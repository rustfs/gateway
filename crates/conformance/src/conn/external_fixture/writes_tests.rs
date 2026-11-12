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

//! The `--allow-external-writes` gate, measured by the requests an endpoint actually received.
//!
//! Responsible for: proving that without the flag no request of a write case reaches the endpoint
//! (setup included) and the skip says why, that with it the write is sent and every declared bucket
//! is emptied and removed, and that the flag is refused without an endpoint. NOT responsible for:
//! the read-only fixture lifecycle (`runner_tests`) or exact version ownership (`versioned_tests`).
//! Upstream: `crate::cli`; downstream: a loopback endpoint that records every request.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
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

/// What a disposable S3 endpoint answers. Every listing shows one leftover entry the first time it
/// is asked and none after, so emptying is observable as the deletes it caused.
fn answer(line: &str, listed: &mut Vec<String>) -> String {
    let ok = |body: &str| format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let first = |kind: &str, listed: &mut Vec<String>| {
        let seen = listed.iter().any(|done| done == kind);
        listed.push(kind.to_owned());
        !seen
    };
    if line.starts_with("HEAD / ") {
        return "HTTP/1.1 403 Forbidden\r\nServer: RustFS\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
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
fn endpoint() -> (String, Arc<AtomicBool>, thread::JoinHandle<Vec<String>>) {
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
                        .write_all(answer(&line, &mut listed).as_bytes())
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

/// Runs `cases` against a fresh recording endpoint; returns the report and every request line.
fn run(cases: &[(&str, String)], flags: &[&str]) -> (String, Vec<String>) {
    let corpus = corpus(cases);
    let (url, stop, server) = endpoint();
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
    let _ = cli::main(&args);
    stop.store(true, Ordering::SeqCst);
    let mut lines = server.join().expect("endpoint exits");
    assert_eq!(
        lines.first().map(String::as_str),
        Some("HEAD / HTTP/1.1"),
        "the identity probe comes first"
    );
    lines.remove(0);
    (read(&report), lines)
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).expect("the JSON report")
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
