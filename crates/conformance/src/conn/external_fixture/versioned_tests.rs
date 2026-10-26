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

//! Versioned external fixture ownership observed through a recording loopback peer.
//!
//! Responsible for: enablement proof, exact version cleanup, unresolved writes, and mutation
//! boundaries. NOT responsible for: target version semantics or version-list APIs. Upstream:
//! `Conn` preparation and authored exchanges; downstream: bounded TCP requests and responses.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::super::Conn;
use crate::sut::{ExchangePlan, Profile, Sut, SutError, Transport};

const CASE: &str = "s-external-versioned";
const BUCKET: &str = "[[buckets]]\nname = \"fixture-versioned\"\nversioning = \"enabled\"\n";
const ENABLED: &str = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>";
const SIGN: &str = "sign = { mode = \"sigv4_header\", service = \"s3\", region = \"us-east-1\", credential = \"valid\" }\n";
static PEERS: Mutex<()> = Mutex::new(());

#[derive(Debug)]
struct Request {
    line: String,
    md5: Option<String>,
    body: Vec<u8>,
}

struct Peer {
    url: String,
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<Vec<Request>>>,
    _lease: MutexGuard<'static, ()>,
}

impl Peer {
    fn new(responses: Vec<Option<Vec<u8>>>) -> Self {
        let lease = PEERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind recording peer");
        listener.set_nonblocking(true).expect("bound accept wait");
        let url = format!("http://{}", listener.local_addr().expect("bound peer address"));
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut responses = VecDeque::from(responses);
            let mut requests = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if stopped.try_recv().is_ok() {
                    return requests;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking peer request");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .expect("bound peer write");
                        requests.push(read_request(&mut stream));
                        // Extra requests remain observable even after the expected script ends.
                        if let Some(response) = responses.pop_front().unwrap_or_else(|| response(500, "", "")) {
                            stream.write_all(&response).expect("write fixture response");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return requests,
                    Err(_) => panic!("recording peer accept failed"),
                }
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            _lease: lease,
        }
    }

    fn target(&self) -> Conn {
        Conn::external_with_fixtures(".".into(), &self.url, None).expect("opted-in external target")
    }

    fn finish(mut self) -> Vec<Request> {
        let _ = self.stop.send(());
        self.worker
            .take()
            .expect("recording worker exists")
            .join()
            .expect("recording worker exits")
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Request {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound peer read");
    let mut bytes = Vec::new();
    loop {
        let mut block = [0_u8; 1024];
        let count = stream.read(&mut block).expect("read fixture request");
        assert_ne!(count, 0, "fixture request ended early");
        bytes.extend_from_slice(&block[..count]);
        let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4) else {
            continue;
        };
        let head = std::str::from_utf8(&bytes[..end]).expect("fixture request head is text");
        let header = |wanted: &str| {
            head.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case(wanted).then(|| value.trim().to_owned())
            })
        };
        let length = header("content-length")
            .map(|value| value.parse::<usize>().expect("numeric length"))
            .unwrap_or(0);
        if bytes.len() >= end + length {
            // Retain no credentials or signing headers, including on assertion failures.
            return Request {
                line: head.lines().next().expect("fixture request line").to_owned(),
                md5: header("content-md5"),
                body: bytes[end..end + length].to_vec(),
            };
        }
    }
}

fn response(status: u16, headers: &str, body: &str) -> Option<Vec<u8>> {
    Some(
        format!(
            "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        )
        .into_bytes(),
    )
}

fn version(status: u16, id: &str, marker: bool) -> Option<Vec<u8>> {
    let marker = if marker { "x-amz-delete-marker: true\r\n" } else { "" };
    response(status, &format!("x-amz-version-id: {id}\r\n{marker}"), "")
}

fn enabled() -> Vec<Option<Vec<u8>>> {
    vec![
        response(404, "", ""),
        response(200, "", ""),
        response(200, "", ""),
        response(200, "", ENABLED),
    ]
}

fn setup(source: &str) -> crate::value::Value {
    crate::toml::parse(source).expect("fixture setup TOML")
}

fn plan(source: &str) -> ExchangePlan<'static> {
    ExchangePlan {
        case_id: CASE,
        index: 0,
        request: crate::toml::parse(source).expect("authored request TOML"),
        clock: None,
        connection: None,
        timeout_ms: Some(2_000),
        deadline: None,
        transport: Transport::Conn,
        profile: Profile::Aws,
    }
}

fn lines(requests: &[Request]) -> Vec<&str> {
    requests.iter().map(|request| request.line.as_str()).collect()
}

fn environment<T: std::fmt::Debug>(result: Result<T, SutError>, message: &str) {
    assert!(matches!(result, Err(SutError::Environment(_))), "{message}");
}

#[test]
fn setup_version_is_observed_and_removed_by_encoded_identity_after_enablement() {
    let mut replies = enabled();
    replies.extend([
        response(404, "", ""),
        version(200, "remote/+ &?", false),
        response(204, "", ""),
        response(204, "", ""),
    ]);
    let peer = Peer::new(replies);
    let mut target = peer.target();
    let source =
        format!("{BUCKET}[[objects]]\nbucket = \"fixture-versioned\"\nkey = \"source\"\nbody = {{ utf8 = \"version-one\" }}\n");
    let prepared = target.prepare(CASE, Some(&setup(&source)));
    let finished = target.finish(CASE);
    let requests = peer.finish();
    assert!(prepared.is_ok(), "versioned setup must succeed");
    assert!(finished.is_ok(), "owned version and bucket must be removed");
    assert_eq!(
        lines(&requests),
        [
            "HEAD /fixture-versioned HTTP/1.1",
            "PUT /fixture-versioned HTTP/1.1",
            "PUT /fixture-versioned?versioning HTTP/1.1",
            "GET /fixture-versioned?versioning HTTP/1.1",
            "HEAD /fixture-versioned/source HTTP/1.1",
            "PUT /fixture-versioned/source HTTP/1.1",
            "DELETE /fixture-versioned/source?versionId=remote%2F%2B%20%26%3F HTTP/1.1",
            "DELETE /fixture-versioned HTTP/1.1",
        ]
    );
    let configuration = std::str::from_utf8(&requests[2].body).expect("versioning XML is UTF-8");
    assert!(configuration.contains("<Status>Enabled</Status>"), "enablement body must request Enabled");
    assert_eq!(
        requests[2].md5.as_deref(),
        Some(crate::fixture::encode_base64(&crate::md5::digest(&requests[2].body)).as_str())
    );
    assert_eq!(requests[5].body, b"version-one");
}

#[test]
fn authored_rewrites_copy_and_delete_marker_keep_every_version_in_reverse_cleanup_order() {
    let mut replies = enabled();
    replies.extend([
        version(200, "first", false),
        version(200, "second", false),
        version(200, "copied", false),
        version(204, "marker/+", true),
    ]);
    replies.extend((0..5).map(|_| response(204, "", "")));
    let peer = Peer::new(replies);
    let mut target = peer.target();
    target.prepare(CASE, Some(&setup(BUCKET))).expect("prepare enabled bucket");
    for (source, status) in [
        (
            format!(
                "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nbody = {{ utf8 = \"one\" }}\nheaders = {{ \"Content-Length\" = \"3\" }}\n{SIGN}"
            ),
            200,
        ),
        (
            format!("method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nbody = {{ utf8 = \"two\" }}\n{SIGN}"),
            200,
        ),
        (
            format!(
                "method = \"PUT\"\ntarget = \"/fixture-versioned/copied\"\nheaders = {{ \"x-amz-copy-source\" = \"/fixture-versioned/source?versionId=first\" }}\n{SIGN}"
            ),
            200,
        ),
        (format!("method = \"DELETE\"\ntarget = \"/fixture-versioned/source\"\n{SIGN}"), 204),
    ] {
        assert_eq!(target.exchange(&plan(&source)).expect("owned authored write").status, Some(status));
    }
    let finished = target.finish(CASE);
    let requests = peer.finish();
    assert!(finished.is_ok(), "all observed versions must be removed");
    assert_eq!(
        &lines(&requests)[4..],
        [
            "PUT /fixture-versioned/source HTTP/1.1",
            "PUT /fixture-versioned/source HTTP/1.1",
            "PUT /fixture-versioned/copied HTTP/1.1",
            "DELETE /fixture-versioned/source HTTP/1.1",
            "DELETE /fixture-versioned/source?versionId=marker%2F%2B HTTP/1.1",
            "DELETE /fixture-versioned/copied?versionId=copied HTTP/1.1",
            "DELETE /fixture-versioned/source?versionId=second HTTP/1.1",
            "DELETE /fixture-versioned/source?versionId=first HTTP/1.1",
            "DELETE /fixture-versioned HTTP/1.1",
        ]
    );
}

#[test]
fn an_existing_bucket_is_never_enabled_adopted_or_deleted() {
    let peer = Peer::new(vec![response(200, "", "")]);
    let mut target = peer.target();
    let prepared = target.prepare(CASE, Some(&setup(BUCKET)));
    let finished = target.finish(CASE);
    let requests = peer.finish();
    environment(prepared, "existing bucket must be refused");
    assert!(finished.is_ok(), "there is no owned resource");
    assert_eq!(lines(&requests), ["HEAD /fixture-versioned HTTP/1.1"]);
}

#[test]
fn failed_enablement_or_unproved_enabled_readback_never_reaches_an_object_write() {
    let readbacks = [
        "<VersioningConfiguration><Status>Disabled</Status></VersioningConfiguration>",
        "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>",
        "<VersioningConfiguration/>",
        "<VersioningConfiguration><Status>Enabled</Status><Status>Suspended</Status></VersioningConfiguration>",
        "<VersioningConfiguration><Other><Status>Enabled</Status></Other></VersioningConfiguration>",
        "<VersioningConfiguration><Status>Enabled</Status>",
    ];
    for readback in std::iter::once(None)
        .chain(readbacks.into_iter().map(|body| Some((200, body))))
        .chain(std::iter::once(Some((500, ENABLED))))
    {
        let mut replies = vec![response(404, "", ""), response(200, "", "")];
        match readback {
            None => replies.push(response(500, "", "")),
            Some((status, body)) => replies.extend([response(200, "", ""), response(status, "", body)]),
        }
        replies.push(response(204, "", ""));
        let peer = Peer::new(replies);
        let mut target = peer.target();
        let source = format!("{BUCKET}[[objects]]\nbucket = \"fixture-versioned\"\nkey = \"source\"\n");
        let prepared = target.prepare(CASE, Some(&setup(&source)));
        let requests = peer.finish();
        environment(prepared, "setup cannot proceed without a proved Enabled state");
        let mut expected = vec![
            "HEAD /fixture-versioned HTTP/1.1",
            "PUT /fixture-versioned HTTP/1.1",
            "PUT /fixture-versioned?versioning HTTP/1.1",
        ];
        if readback.is_some() {
            expected.push("GET /fixture-versioned?versioning HTTP/1.1");
        }
        expected.push("DELETE /fixture-versioned HTTP/1.1");
        assert_eq!(lines(&requests), expected);
    }
}

#[test]
fn setup_write_without_one_resolved_version_keeps_ownership_and_blocks_reuse() {
    for reply in [
        response(200, "", ""),
        version(200, "", false),
        version(200, "null", false),
        response(200, "x-amz-version-id: one\r\nx-amz-version-id: two\r\n", ""),
        response(500, "", ""),
        None,
    ] {
        let mut replies = enabled();
        replies.extend([response(404, "", ""), reply]);
        let peer = Peer::new(replies);
        let mut target = peer.target();
        let source = format!("{BUCKET}[[objects]]\nbucket = \"fixture-versioned\"\nkey = \"source\"\n");
        let prepared = target.prepare(CASE, Some(&setup(&source)));
        let finished = target.finish(CASE);
        let next = target.prepare("s-next", None);
        let next_with_setup = target.prepare("s-next", Some(&setup(BUCKET)));
        let requests = peer.finish();
        environment(prepared, "unknown setup version must be refused");
        environment(finished, "unknown setup version must remain unresolved");
        environment(next, "unresolved setup version blocks the next case");
        environment(next_with_setup, "retained ownership blocks another setup before remote mutation");
        assert_eq!(requests.len(), 6, "unresolved identity must not trigger guessed cleanup");
        assert_eq!(requests[5].line, "PUT /fixture-versioned/source HTTP/1.1");
    }
}

#[test]
fn authored_write_without_one_resolved_version_keeps_ownership_and_blocks_reuse() {
    for reply in [
        response(200, "", ""),
        version(200, "", false),
        version(200, "null", false),
        response(200, "x-amz-version-id: one\r\nx-amz-version-id: two\r\n", ""),
        response(500, "", ""),
        None,
    ] {
        let mut replies = enabled();
        replies.push(reply);
        let peer = Peer::new(replies);
        let mut target = peer.target();
        target.prepare(CASE, Some(&setup(BUCKET))).expect("prepare enabled bucket");
        let _observation = target.exchange(&plan("method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\n"));
        let finished = target.finish(CASE);
        let next = target.prepare("s-next", None);
        let next_with_setup = target.prepare("s-next", Some(&setup(BUCKET)));
        let requests = peer.finish();
        environment(finished, "unknown authored version must remain unresolved");
        environment(next, "unresolved authored version blocks the next case");
        environment(next_with_setup, "retained ownership blocks another setup before remote mutation");
        assert_eq!(requests.len(), 5, "unresolved identity must not trigger guessed cleanup");
        assert_eq!(requests[4].line, "PUT /fixture-versioned/source HTTP/1.1");
    }
}

#[test]
fn delete_without_a_true_delete_marker_is_not_a_resolved_version() {
    for marker in [
        "",
        "x-amz-delete-marker: false\r\n",
        "x-amz-delete-marker: true\r\nx-amz-delete-marker: false\r\n",
    ] {
        let mut replies = enabled();
        replies.push(response(204, &format!("x-amz-version-id: marker\r\n{marker}"), ""));
        let peer = Peer::new(replies);
        let mut target = peer.target();
        target.prepare(CASE, Some(&setup(BUCKET))).expect("prepare enabled bucket");
        let _observation = target.exchange(&plan("method = \"DELETE\"\ntarget = \"/fixture-versioned/source\"\n"));
        let finished = target.finish(CASE);
        let next = target.prepare("s-next", None);
        let requests = peer.finish();
        environment(finished, "a missing or ambiguous marker keeps the write unresolved");
        environment(next, "unresolved delete marker blocks the next case");
        assert_eq!(requests.len(), 5, "unproved marker must not be guessed during cleanup");
    }
}

#[test]
fn an_ordinary_authored_rejection_preserves_the_observation_and_removes_pending_ownership() {
    let mut replies = enabled();
    replies.extend([
        response(403, "x-amz-request-id: refused-request\r\n", "<Error><Code>AccessDenied</Code></Error>"),
        response(204, "", ""),
    ]);
    let peer = Peer::new(replies);
    let mut target = peer.target();
    target.prepare(CASE, Some(&setup(BUCKET))).expect("prepare enabled bucket");
    let observed = target.exchange(&plan("method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\n"));
    let finished = target.finish(CASE);
    let next = target.prepare("s-next", None);
    let requests = peer.finish();
    let observed = observed.expect("authored rejection stays observable");
    assert_eq!(observed.status, Some(403));
    assert_eq!(observed.body, b"<Error><Code>AccessDenied</Code></Error>");
    assert!(
        observed
            .headers
            .iter()
            .any(|(name, value)| { name.eq_ignore_ascii_case("x-amz-request-id") && value == "refused-request" }),
        "the authored rejection must retain its response headers"
    );
    assert!(finished.is_ok(), "a known rejection leaves no owned version");
    assert!(next.is_ok(), "a known rejection must not poison the next case");
    assert_eq!(
        &lines(&requests)[4..],
        ["PUT /fixture-versioned/source HTTP/1.1", "DELETE /fixture-versioned HTTP/1.1"]
    );
}

#[test]
fn unsupported_or_ambiguous_authored_mutations_are_refused_before_send() {
    let requests = [
        "method = \"PUT\"\ntarget = \"/foreign-bucket/source\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/\"\n",
        "method = \"DELETE\"\ntarget = \"/fixture-versioned/source?versionId=old\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source?acl\"\n",
        "method = \"POST\"\ntarget = \"/fixture-versioned/source\"\n",
        "method = \"PUT\"\ntarget = \"http://foreign.example/fixture-versioned/source\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nhost = \"foreign.example\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nheaders = { Host = \"foreign.example\" }\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nheaders = { \"x-amz-copy-source\" = \"/foreign-bucket/source?versionId=old\" }\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nheaders = { \"Transfer-Encoding\" = \"chunked\" }\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nheaders = { \"Content-Length\" = \"1\" }\nbody = { utf8 = \"one\" }\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\\r\\nInjected: yes\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nheaders = { extra = \"one\\r\\nInjected: yes\" }\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nchunks = [{ action = \"reset\" }]\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nraw_head_utf8 = \"PUT /fixture-versioned/source HTTP/1.1\\r\\nHost: localhost\\r\\nContent-Length: 0\\r\\n\\r\\n\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nhttp_version = \"h2\"\n[[h2_frames]]\ntype = \"headers\"\nstream_id = 1\nflags = [\"end_headers\", \"end_stream\"]\npayload_hex = \"02035055548684410e73332e6578616d706c652e636f6d\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nsign = { mode = \"sigv4_header\", service = \"s3\", region = \"us-east-1\", credential = \"valid\", tamper = { component = \"canonical_path\", new_value = \"/foreign-bucket/source\" } }\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\nsign = { mode = \"sigv4_header\", service = \"s3\", region = \"us-east-1\", credential = \"valid\", tamper = { component = \"canonical_header_value\", target = \"host\", new_value = \"foreign.example\" } }\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/../escape\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/./source\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/%2e%2E/escape\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/one%2Ftwo\"\n",
        "method = \"PUT\"\ntarget = \"/fixture-versioned/one%5Ctwo\"\n",
    ];
    for source in requests {
        let mut replies = enabled();
        replies.push(response(204, "", ""));
        let peer = Peer::new(replies);
        let mut target = peer.target();
        target.prepare(CASE, Some(&setup(BUCKET))).expect("prepare enabled bucket");
        let refused = target.exchange(&plan(source));
        let finished = target.finish(CASE);
        let recorded = peer.finish();
        environment(refused, "unsupported mutation must carry an environment reason");
        assert_eq!(recorded.len(), 5, "refused mutation sent remote bytes");
        assert_eq!(recorded[4].line, "DELETE /fixture-versioned HTTP/1.1");
        assert!(finished.is_ok(), "a refusal must not create pending ownership");
    }
}

#[test]
fn failed_exact_version_cleanup_blocks_only_its_bucket_and_can_retry_the_same_identity() {
    let mut replies = enabled();
    replies.extend(enabled());
    replies.extend([
        version(200, "good-version", false),
        version(200, "bad-version", false),
        response(500, "", ""),
        response(204, "", ""),
        response(204, "", ""),
        response(204, "", ""),
        response(204, "", ""),
    ]);
    let peer = Peer::new(replies);
    let mut target = peer.target();
    let source = format!("{BUCKET}[[buckets]]\nname = \"fixture-good\"\nversioning = \"enabled\"\n");
    target
        .prepare(CASE, Some(&setup(&source)))
        .expect("prepare both enabled buckets");
    target
        .exchange(&plan("method = \"PUT\"\ntarget = \"/fixture-good/source\"\n"))
        .expect("write independent version");
    target
        .exchange(&plan("method = \"PUT\"\ntarget = \"/fixture-versioned/source\"\n"))
        .expect("write version whose cleanup will fail");
    let first = target.finish(CASE);
    let next = target.prepare("s-next", None);
    let next_with_setup = target.prepare("s-next", Some(&setup(BUCKET)));
    let retried = target.finish(CASE);
    let requests = peer.finish();
    environment(first, "failed version cleanup must be reported");
    environment(next, "retained ownership must block the next case");
    environment(next_with_setup, "retained ownership blocks another setup before remote mutation");
    assert!(retried.is_ok(), "retry may remove the same observed version");
    assert_eq!(
        &lines(&requests)[10..],
        [
            "DELETE /fixture-versioned/source?versionId=bad-version HTTP/1.1",
            "DELETE /fixture-good/source?versionId=good-version HTTP/1.1",
            "DELETE /fixture-good HTTP/1.1",
            "DELETE /fixture-versioned/source?versionId=bad-version HTTP/1.1",
            "DELETE /fixture-versioned HTTP/1.1",
        ]
    );
}

#[test]
fn normalized_versioned_setup_keys_are_refused_before_any_remote_contact() {
    for key in ["../outside", "../../foreign/key", "a/../../outside", "/../outside"] {
        let peer = Peer::new(Vec::new());
        let mut target = peer.target();
        let source = format!(
            "{BUCKET}[[objects]]\nbucket = \"fixture-versioned\"\nkey = \"{key}\"\nbody = {{ utf8 = \"must-not-send\" }}\n"
        );
        let prepared = target.prepare(CASE, Some(&setup(&source)));
        let requests = peer.finish();
        environment(prepared, "normalized setup keys must be an environment refusal");
        assert!(requests.is_empty(), "invalid versioned setup contacted the endpoint for key {key}");
    }
}
