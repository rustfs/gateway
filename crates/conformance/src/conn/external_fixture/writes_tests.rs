// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The external write and clock gates, measured by the requests an endpoint actually received,
//! and the share of the corpus they leave runnable.
//!
//! Responsible for: proving that without `--allow-external-writes` no request of a write case
//! reaches the endpoint (setup included) and the skip says why, that with it the write is sent and
//! every declared bucket is emptied and removed, that the flag is refused without an endpoint, that
//! a case pinning a clock the endpoint cannot follow is skipped at the `clock` phase before any
//! traffic, and that the README states the runnable share this corpus actually has.
//! NOT responsible for: the read-only fixture lifecycle (`runner_tests`) or exact version
//! ownership (`versioned_tests`). Upstream: `crate::cli`, `crate::corpus`; downstream: a loopback endpoint
//! that records every request.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use crate::cli;

struct TestCorpus(PathBuf);

impl Drop for TestCorpus {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const BUCKET: &str = "[[setup.buckets]]\nname = \"write-runner\"\n\n";
const ABSENT: &str = "[[setup.buckets]]\nname = \"write-created\"\nabsent = true\n\n";

/// One case: `setup`, then one authored request (`method`, `target`, and any further TOML lines).
fn case(id: &str, operation: &str, setup: &str, method: &str, target: &str) -> String {
    format!(
        r#"[case]
id = "{id}"
schema_version = 1
title = "External write gate control"
rationale = "This isolated corpus proves an authored write reaches an external endpoint only when the operator allowed it."
polarity = "positive"
operation = "{operation}"
tags = ["xml"]
timeout_ms = 2000
quirks = []

[[case.evidence]]
url = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html"
summary = "PutObject adds an object to a bucket the caller may write to."
kind = "aws-doc"

{setup}[request]
method = "{method}"
target = "{target}"

[expect]
kind = "response"
status = 200
"#
    )
}

fn corpus(cases: &[(&str, String)]) -> TestCorpus {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "rustfs-gateway-external-writes-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("cases/external-writes")).expect("create cases directory");
    let repository = crate::corpus::Corpus::discover_root().expect("repository corpus");
    fs::copy(repository.join("case.schema.json"), root.join("case.schema.json")).expect("copy frozen schema");
    for (id, text) in cases {
        fs::write(root.join("cases/external-writes").join(format!("{id}.toml")), text).expect("write case");
    }
    TestCorpus(root)
}

fn read_request(stream: &mut std::net::TcpStream) -> String {
    stream.set_nonblocking(false).expect("blocking request read");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound request read");
    let mut request = Vec::new();
    loop {
        let mut block = [0_u8; 1024];
        let read = stream.read(&mut block).expect("read request");
        assert_ne!(read, 0, "request ended before completion");
        request.extend_from_slice(&block[..read]);
        let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&request[..end]).into_owned();
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        if request.len() >= end + 4 + length {
            return head.lines().next().unwrap_or_default().to_owned();
        }
    }
}

/// What a disposable S3 endpoint answers. `GET /` lists `existing` (bucket XML), or answers it
/// verbatim when it is a whole response; every bucket
/// listing shows one leftover entry the first time it is asked and none after, so emptying is
/// observable as the deletes it caused; `write-gone` answers its first DELETE (the case's own) 200
/// and 404 after, and `write-vanished` answers every DELETE 404.
fn answer(line: &str, listed: &mut Vec<String>, existing: &str) -> String {
    let ok = |body: &str| format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let first = |kind: &str, listed: &mut Vec<String>| {
        let seen = listed.iter().any(|done| done == kind);
        listed.push(kind.to_owned());
        !seen
    };
    if line.starts_with("HEAD / ") {
        return "HTTP/1.1 403 Forbidden\r\nServer: RustFS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
    }
    if line.starts_with("GET / ") && existing.starts_with("HTTP/") {
        return existing.to_owned();
    }
    if line.starts_with("GET / ") {
        return ok(&format!("<ListAllMyBucketsResult><Buckets>{existing}</Buckets></ListAllMyBucketsResult>"));
    }
    if line.starts_with("DELETE /write-gone ") && first(line, listed) {
        return ok("");
    }
    if line.starts_with("DELETE /write-vanished ") || line.starts_with("DELETE /write-gone ") {
        return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
    }
    if line.starts_with("GET /write-versioned?versioning ") {
        return ok("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>");
    }
    if line.starts_with("GET /write-error?") {
        let body = "<Error><Code>InternalError</Code></Error>";
        return ok(body);
    }
    if line.starts_with("HEAD ") {
        let exists = line.starts_with("HEAD /write-created ") && listed.iter().any(|done| done == "created");
        let status = if exists { "200 OK" } else { "404 Not Found" };
        return format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
    if line.starts_with("PUT /write-created ") {
        listed.push("created".to_owned());
    }
    if line.contains("?versions") {
        let entries = if first(line, listed) {
            "<Version><Key>left over</Key><VersionId>null</VersionId></Version>\
             <DeleteMarker><Key>gone</Key><VersionId>v&amp;2</VersionId></DeleteMarker>"
        } else {
            ""
        };
        return ok(&format!("<ListVersionsResult>{entries}</ListVersionsResult>"));
    }
    if line.contains("?uploads") {
        let entries = if first(line, listed) {
            "<Upload><Key>part/one</Key><UploadId>u1</UploadId><Initiator><ID>x</ID></Initiator></Upload>"
        } else {
            ""
        };
        return ok(&format!("<ListMultipartUploadsResult>{entries}</ListMultipartUploadsResult>"));
    }
    if line.starts_with("DELETE ") {
        return "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_owned();
    }
    ok("")
}

/// An endpoint that records the request line of everything it receives until told to stop.
fn endpoint(existing: &'static str) -> (String, Arc<AtomicBool>, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind endpoint");
    listener.set_nonblocking(true).expect("nonblocking accept");
    let address = listener.local_addr().expect("endpoint address");
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&stop);
    let server = thread::spawn(move || {
        let mut lines = Vec::new();
        let mut listed = Vec::new();
        while !stopped.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let line = read_request(&mut stream);
                    stream
                        .write_all(answer(&line, &mut listed, existing).as_bytes())
                        .expect("write response");
                    lines.push(line);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(1)),
                Err(error) => panic!("accept: {error}"),
            }
        }
        lines
    });
    (format!("http://{address}"), stop, server)
}

/// Runs `cases` against a fresh recording endpoint; returns the report and every request line
/// after the identity probe and, with writes allowed, the empty-endpoint listing before it.
fn run(cases: &[(&str, String)], flags: &[&str]) -> (String, Vec<String>) {
    let (report, lines, _) = run_on(cases, flags, "");
    (report.expect("the run wrote its report"), lines)
}

fn run_on(cases: &[(&str, String)], flags: &[&str], existing: &'static str) -> (Option<String>, Vec<String>, ExitCode) {
    let corpus = corpus(cases);
    let (url, stop, server) = endpoint(existing);
    let report = corpus.0.join("report.json");
    let mut args = vec![
        "run".to_owned(),
        "--root".to_owned(),
        corpus.0.display().to_string(),
        "--endpoint".to_owned(),
        url,
        "--json".to_owned(),
        report.display().to_string(),
    ];
    args.extend(flags.iter().map(|flag| (*flag).to_owned()));
    let code = cli::main(&args);
    stop.store(true, Ordering::SeqCst);
    let mut lines = server.join().expect("endpoint exits");
    if flags.contains(&"--allow-external-writes") {
        assert_eq!(
            lines.first().map(String::as_str),
            Some("GET / HTTP/1.1"),
            "the emptiness listing comes first"
        );
        lines.remove(0);
    }
    if lines.first().map(String::as_str) == Some("HEAD / HTTP/1.1") {
        lines.remove(0);
    }
    (fs::read_to_string(&report).ok(), lines, code)
}

fn line<'a>(report: &'a str, id: &str) -> &'a str {
    report
        .lines()
        .find(|line| line.contains(&format!("\"id\": \"{id}\"")))
        .unwrap_or_else(|| panic!("{id} is not in the report:\n{report}"))
}

fn put_with_setup() -> (&'static str, String) {
    let id = "c-external-writes-0001";
    (id, case(id, "PutObject", BUCKET, "PUT", "/write-runner/key"))
}

/// Negative — without the flag, a write case with setup is skipped before its setup: the endpoint
/// receives nothing for it, and the skip names the flag that would have allowed it.
#[test]
fn without_the_flag_a_write_case_sends_nothing_and_says_why() {
    let (id, text) = put_with_setup();
    let (report, lines) = run(&[(id, text)], &["--allow-external-fixtures"]);
    assert_eq!(lines, Vec::<String>::new(), "no request of a write case may reach the endpoint");
    let row = line(&report, id);
    assert!(row.contains("\"verdict\": \"skipped\""), "{row}");
    assert!(row.contains("`--allow-external-writes`") && row.contains("PUT"), "{row}");
}

/// Negative — a write case without setup was sent unconditionally before the flag existed; it is
/// held to the same gate.
#[test]
fn without_the_flag_a_setupless_write_sends_nothing() {
    let id = "c-external-writes-0002";
    let (report, lines) = run(&[(id, case(id, "CreateBucket", "", "PUT", "/write-free"))], &[]);
    assert_eq!(lines, Vec::<String>::new());
    assert!(line(&report, id).contains("`--allow-external-writes`"), "{}", line(&report, id));
}

/// Negative — a raw request head cannot be classified as a read, so without the flag it is a
/// write: refused before anything is sent.
#[test]
fn without_the_flag_an_unclassified_raw_request_sends_nothing() {
    let id = "c-external-writes-0003";
    let text = case(id, "GetObject", BUCKET, "GET", "/write-runner/key").replace(
        "[request]\nmethod = \"GET\"\ntarget = \"/write-runner/key\"",
        "[request]\nraw_head_utf8 = \"GET /write-runner/key HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n\"",
    );
    let (report, lines) = run(&[(id, text)], &["--allow-external-fixtures"]);
    assert_eq!(lines, Vec::<String>::new());
    let row = line(&report, id);
    assert!(
        row.contains("unclassified raw request") && row.contains("`--allow-external-writes`"),
        "{row}"
    );
}

/// Positive, the control for the three above — a read-only case still runs without the flag, so
/// the gate is not a blanket refusal of fixture cases.
#[test]
fn without_the_flag_a_read_only_case_still_reaches_the_endpoint() {
    let id = "c-external-writes-0004";
    let (report, lines) = run(
        &[(id, case(id, "GetObject", BUCKET, "GET", "/write-runner/key"))],
        &["--allow-external-fixtures"],
    );
    assert!(lines.contains(&"GET /write-runner/key HTTP/1.1".to_owned()), "{lines:?}");
    assert!(line(&report, id).contains("\"verdict\": \"passed\""), "{}", line(&report, id));
}

/// Positive — with the flag the write is sent, and cleanup empties the declared bucket of every
/// version, delete marker and upload a listing shows before removing it; a declared-absent bucket
/// the case created is emptied and removed too.
#[test]
fn with_the_flag_the_write_is_sent_and_every_declared_bucket_is_emptied_and_removed() {
    let id = "c-external-writes-0005";
    let text = case(id, "CreateBucket", &format!("{BUCKET}{ABSENT}"), "PUT", "/write-created");
    let (report, lines) = run(&[(id, text)], &["--allow-external-fixtures", "--allow-external-writes"]);
    assert!(line(&report, id).contains("\"verdict\": \"passed\""), "{}", line(&report, id));
    let position = |wanted: &str| {
        lines
            .iter()
            .position(|line| line == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} was not sent: {lines:#?}"))
    };
    let write = position("PUT /write-created HTTP/1.1");
    for bucket in ["write-created", "write-runner"] {
        let aborted = position(&format!("DELETE /{bucket}/part/one?uploadId=u1 HTTP/1.1"));
        let version = position(&format!("DELETE /{bucket}/left%20over?versionId=null HTTP/1.1"));
        let marker = position(&format!("DELETE /{bucket}/gone?versionId=v%262 HTTP/1.1"));
        let removed = position(&format!("DELETE /{bucket} HTTP/1.1"));
        assert!(
            write < aborted && aborted < removed && version < removed && marker < removed,
            "{lines:#?}"
        );
    }
}

/// Negative — with the flag but without fixtures, a write case with setup is still skipped for its
/// setup and sends nothing: the flag grants authored writes, not fixture creation.
#[test]
fn the_write_flag_does_not_grant_fixture_setup() {
    let (id, text) = put_with_setup();
    let (report, lines) = run(&[(id, text)], &["--allow-external-writes"]);
    assert_eq!(lines, Vec::<String>::new());
    assert!(line(&report, id).contains("`--allow-external-fixtures`"), "{}", line(&report, id));
}

/// Positive — with the flag and no setup, the write is sent.
#[test]
fn with_the_flag_a_setupless_write_is_sent() {
    let id = "c-external-writes-0006";
    let (_, lines) = run(&[(id, case(id, "CreateBucket", "", "PUT", "/write-free"))], &["--allow-external-writes"]);
    assert_eq!(lines, ["PUT /write-free HTTP/1.1"]);
}

/// Negative — the flag means nothing without an endpoint, and is a usage error there.
#[test]
fn the_write_flag_without_an_endpoint_is_a_usage_error() {
    let error =
        cli::Options::parse(&["run".to_owned(), "--allow-external-writes".to_owned()]).expect_err("no endpoint to write to");
    assert_eq!(error, "`--allow-external-writes` requires `--endpoint`");
    let parsed = cli::Options::parse(&[
        "run".to_owned(),
        "--endpoint".to_owned(),
        "http://127.0.0.1:9".to_owned(),
        "--allow-external-writes".to_owned(),
    ])
    .expect("valid")
    .expect("not help");
    assert!(parsed.external_writes);
}

const FIXED_CLOCK: &str = "[clock]\nfixed = \"2026-01-02T03:04:05Z\"\n\n";

/// Negative — a case pinning `clock.fixed` against a wall-clock endpoint is skipped at the `clock`
/// phase before its setup: the endpoint receives nothing for it, and the reason names the clock.
#[test]
fn a_fixed_clock_case_is_skipped_at_the_clock_phase_and_sends_nothing() {
    let id = "c-external-writes-0007";
    let text = case(id, "GetObject", &format!("{BUCKET}{FIXED_CLOCK}"), "GET", "/write-runner/key");
    let (report, lines) = run(&[(id, text)], &["--allow-external-fixtures", "--allow-external-writes"]);
    assert_eq!(lines, Vec::<String>::new(), "no request of a fixed-clock case may reach the endpoint");
    let row = line(&report, id);
    assert!(row.contains("\"verdict\": \"skipped\"") && row.contains("\"phase\": \"clock\""), "{row}");
    assert!(row.contains("`clock.fixed` pins the instant"), "{row}");
}

/// Negative — a write skip is not a clock skip: it keeps the execute phase and its own reason.
#[test]
fn a_write_skip_is_not_counted_as_a_clock_skip() {
    let (id, text) = put_with_setup();
    let (report, _) = run(&[(id, text)], &["--allow-external-fixtures"]);
    let row = line(&report, id);
    assert!(row.contains("\"phase\": \"preflight\"") && !row.contains("clock"), "{row}");
}

/// How many corpus cases the external gates admit, without and with `--allow-external-writes`;
/// fixtures are allowed in both, and the endpoint keeps its own wall clock.
fn runnable_externally() -> (usize, usize, usize) {
    let root = crate::corpus::Corpus::discover_root().expect("repository corpus");
    let corpus = crate::corpus::Corpus::load(&root).expect("corpus loads");
    let mut target = super::super::Conn::external_with_fixtures(root, "http://127.0.0.1:9", None).expect("target");
    let admitted = |target: &super::super::Conn| {
        corpus
            .cases()
            .iter()
            .filter(|case| {
                let document = case.document.as_ref().expect("every corpus case loads");
                let requests: Vec<_> = case.exchanges().iter().filter_map(|exchange| exchange.request).collect();
                crate::sut::Sut::validate_clock(target, document.read("clock")).is_ok()
                    && crate::sut::Sut::validate_requests(target, &case.id, document.read("setup"), &requests).is_ok()
            })
            .count()
    };
    let read_only = admitted(&target);
    target.allow_external_writes();
    (corpus.cases().len(), read_only, admitted(&target))
}

/// Positive — the share the README states is the share this corpus has, computed by the same gates
/// the runner applies; a corpus change that moves it fails here until the sentence is updated.
#[test]
fn the_readme_states_the_externally_runnable_share_of_this_corpus() {
    let (total, read_only, writes) = runnable_externally();
    let percent = |count: usize| count * 1000 / total;
    let expected = format!(
        "Of the {total} cases, {writes} ({}.{}%) pass these gates with `--allow-external-writes` and {read_only} \
         ({}.{}%) without it",
        percent(writes) / 10,
        percent(writes) % 10,
        percent(read_only) / 10,
        percent(read_only) % 10,
    );
    let readme = fs::read_to_string(crate::corpus::Corpus::discover_root().expect("corpus").join("README.md"))
        .expect("conformance README");
    assert!(readme.replace('\n', " ").contains(&expected), "README must state: {expected}");
    assert!(
        read_only < writes && writes < total,
        "a gate that admits nothing or everything measures nothing"
    );
}

/// A structured read whose bytes can carry another request, as `[request]` lines after the target.
fn smuggling(id: &str, extra: &str) -> String {
    case(id, "GetObject", BUCKET, "GET", "/write-runner/key")
        .replace("target = \"/write-runner/key\"\n", &format!("target = \"/write-runner/key\"\n{extra}\n"))
}

/// Runs one smuggling case without the flag: the endpoint must receive nothing at all.
fn assert_smuggling_sends_nothing(id: &str, extra: &str) {
    let (report, lines) = run(&[(id, smuggling(id, extra))], &["--allow-external-fixtures"]);
    assert_eq!(lines, Vec::<String>::new(), "{id}: the endpoint received a request");
    let row = line(&report, id);
    assert!(
        row.contains("\"phase\": \"preflight\"") && row.contains("an unclassified GET"),
        "{id}: {row}"
    );
}

/// Negative — a GET whose header value injects a pipelined DELETE is refused without the flag.
#[test]
fn without_the_flag_a_header_injected_delete_sends_nothing() {
    assert_smuggling_sends_nothing(
        "c-external-writes-0008",
        "headers = { x-probe = \"a\\r\\n\\r\\nDELETE /write-runner/key HTTP/1.1\\r\\nHost: h\" }",
    );
}

/// Negative — a GET with `content-length: 0` whose body is a second request is refused.
#[test]
fn without_the_flag_a_body_that_is_a_second_request_sends_nothing() {
    assert_smuggling_sends_nothing(
        "c-external-writes-0009",
        "headers = { content-length = \"0\" }\nbody = { utf8 = \"DELETE /write-runner/key HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n\" }",
    );
}

/// Negative — a GET carrying a method-override header is refused.
#[test]
fn without_the_flag_a_method_override_sends_nothing() {
    assert_smuggling_sends_nothing("c-external-writes-0010", "headers = { x-http-method-override = \"DELETE\" }");
}

/// Positive — with the flag a raw head is sent as written.
#[test]
fn with_the_flag_a_raw_head_is_sent() {
    let id = "c-external-writes-0011";
    let text = case(id, "GetObject", "", "GET", "/write-free").replace(
        "[request]\nmethod = \"GET\"\ntarget = \"/write-free\"",
        "[request]\nraw_head_utf8 = \"GET /write-free HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n\"",
    );
    let (_, lines) = run(&[(id, text)], &["--allow-external-writes"]);
    assert_eq!(lines, ["GET /write-free HTTP/1.1"]);
}

const GONE: &str = "[[setup.buckets]]\nname = \"write-gone\"\n\n";

/// Positive — with the flag, a bucket DELETE answered 404 is a bucket the case removed itself.
#[test]
fn with_the_flag_a_bucket_already_gone_is_accepted() {
    let id = "c-external-writes-0012";
    let (report, lines) = run(
        &[(id, case(id, "DeleteBucket", GONE, "DELETE", "/write-gone"))],
        &["--allow-external-fixtures", "--allow-external-writes"],
    );
    assert!(lines.contains(&"DELETE /write-gone HTTP/1.1".to_owned()), "{lines:?}");
    assert!(line(&report, id).contains("\"verdict\": \"passed\""), "{}", line(&report, id));
}

/// Negative — without the flag nothing may have removed an owned bucket, so a 404 on its DELETE is a
/// cleanup failure, not a success.
#[test]
fn without_the_flag_a_bucket_delete_answered_404_fails_cleanup() {
    let id = "c-external-writes-0013";
    let vanished = "[[setup.buckets]]\nname = \"write-vanished\"\n\n";
    let (report, _) = run(
        &[(id, case(id, "HeadBucket", vanished, "GET", "/write-vanished"))],
        &["--allow-external-fixtures"],
    );
    let row = line(&report, id);
    assert!(row.contains("\"verdict\": \"failed\"") && row.contains("returned status 404"), "{row}");
}

/// Negative — a 200 listing that is an `<Error>` document is reported as such, not read as empty.
#[test]
fn an_error_document_listing_is_not_an_empty_bucket() {
    let id = "c-external-writes-0014";
    let setup = "[[setup.buckets]]\nname = \"write-error\"\n\n";
    let (report, lines) = run(
        &[(id, case(id, "HeadBucket", setup, "GET", "/write-error"))],
        &["--allow-external-fixtures", "--allow-external-writes"],
    );
    assert!(!lines.contains(&"DELETE /write-error HTTP/1.1".to_owned()), "{lines:?}");
    assert!(
        line(&report, id).contains("not a well-formed ListMultipartUploadsResult"),
        "{}",
        line(&report, id)
    );
}

/// Negative — a write the pre-check leaves to exact version ownership, refused at the exchange
/// after setup went out, is reported at the execute phase, never as a preflight skip.
#[test]
fn a_write_refused_after_setup_is_not_reported_as_sending_nothing() {
    let id = "c-external-writes-0015";
    let setup = "[[setup.buckets]]\nname = \"write-versioned\"\nversioning = \"enabled\"\n\n";
    let (report, lines) = run(&[(id, case(id, "PutObject", setup, "PUT", "/other/k"))], &["--allow-external-fixtures"]);
    assert!(lines.contains(&"PUT /write-versioned HTTP/1.1".to_owned()), "setup went out: {lines:?}");
    assert!(!lines.contains(&"PUT /other/k HTTP/1.1".to_owned()), "{lines:?}");
    let row = line(&report, id);
    assert!(row.contains("\"phase\": \"execute\"") && row.contains("versioned"), "{row}");
}

/// Negative — with the flag, an endpoint that already lists buckets is refused before any case:
/// exit 3, nothing but the listing sent, and no report.
#[test]
fn with_the_flag_an_endpoint_holding_buckets_is_refused_before_any_case() {
    let (id, text) = put_with_setup();
    let existing = "<Bucket><Name>keep-me</Name></Bucket>";
    let (report, lines, code) = run_on(&[(id, text)], &["--allow-external-fixtures", "--allow-external-writes"], existing);
    assert_eq!(code, ExitCode::from(cli::exit::ENVIRONMENT));
    assert_eq!(lines, Vec::<String>::new());
    assert_eq!(report, None);
}

/// Negative — the refusal names what it found, at most five buckets.
#[test]
fn the_emptiness_refusal_names_at_most_five_buckets() {
    let existing = "<Bucket><Name>b1</Name></Bucket><Bucket><Name>b2</Name></Bucket><Bucket><Name>b3</Name></Bucket>\
                    <Bucket><Name>b4</Name></Bucket><Bucket><Name>b5</Name></Bucket><Bucket><Name>b6</Name></Bucket>";
    let (url, stop, server) = endpoint(existing);
    let mut target = super::super::Conn::external(PathBuf::from("."), &url).expect("target");
    target.allow_external_writes();
    let error = target.ensure_endpoint_empty().expect_err("buckets exist");
    stop.store(true, Ordering::SeqCst);
    assert_eq!(server.join().expect("endpoint exits"), ["GET / HTTP/1.1"]);
    assert!(error.to_string().ends_with("it lists 6 bucket(s): b1, b2, b3, b4, b5, ..."), "{error}");
}

/// Negative, one per refusal — an endpoint whose bucket list cannot be read is not shown empty: a
/// 403, and a 200 whose body is not a `ListAllMyBucketsResult`, each refuse the run with exit 3
/// before any case request.
#[test]
fn with_the_flag_an_endpoint_whose_buckets_cannot_be_listed_is_refused() {
    for answer in [
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 41\r\nConnection: close\r\n\r\n<Error><Code>InternalError</Code></Error>",
    ] {
        let (id, text) = put_with_setup();
        let (report, lines, code) = run_on(&[(id, text)], &["--allow-external-fixtures", "--allow-external-writes"], answer);
        assert_eq!(code, ExitCode::from(cli::exit::ENVIRONMENT), "{answer}");
        assert_eq!(lines, Vec::<String>::new(), "{answer}");
        assert_eq!(report, None, "{answer}");
    }
}

/// Negative — a caller that prepares a case without the runner's preflight (a `Sut` wrapper that
/// does not forward `validate_requests`) still cannot run a case only the in-process target can
/// judge: `prepare` refuses it, and the endpoint receives nothing.
#[test]
fn preparing_an_in_process_only_case_directly_is_refused_before_contact() {
    let (url, stop, server) = endpoint("");
    let mut target = super::super::Conn::external_with_fixtures(PathBuf::from("."), &url, None).expect("target");
    let setup = crate::toml::parse("[setup]\n[[setup.buckets]]\nname = \"authz-versions\"\n").expect("setup TOML");
    let error = crate::sut::Sut::prepare(&mut target, "c-authz-0008", setup.get("setup")).expect_err("in-process only");
    stop.store(true, Ordering::SeqCst);
    assert_eq!(server.join().expect("endpoint exits"), Vec::<String>::new());
    assert!(error.to_string().starts_with("c-authz-0008 "), "{error}");
}
