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

//! Negative and control tests for XML 1.0 `Char` validation, `decode_diff` XML checking on
//! `200`/`4xx` responses, and control-character preservation in `encode_diff` endpoint replay.
//!
//! Responsible for: proving `xmltree::parse` rejects disallowed XML 1.0 characters and character
//! references, `replay_decode_diff` rejects malformed XML on `200` and `4xx` responses without
//! false-positiving on binary object bodies, and `encode_diff` preserves control bytes rather than
//! blindly stripping all `is_ascii_control()`.
//! NOT responsible for: CLI argument parsing or health-probe orchestration (`endpoint_replay.rs`).
//! Upstream: `xmltree`, `fuzz`, and `endpoint_replay`. Downstream: Cargo test harness.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crate::endpoint_replay::{EXIT_FAILURE, EXIT_PASSED, Options, Target, run};
use crate::fuzz::{check_encode, endpoint_replay_outputs_of};
use crate::project::OracleOutput;
use crate::xmltree;

fn scratch(name: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("difftest-ep-xml-{name}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch directory");
    path
}

struct MockServer {
    endpoint: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, &str, &mut std::net::TcpStream) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("local addr");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handler = Arc::new(handler);
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = Vec::new();
                        let mut chunk = [0_u8; 4096];
                        let header_end = loop {
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break Some(pos + 4);
                            }
                            match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => break None,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        };
                        if let Some(end) = header_end {
                            let head = String::from_utf8_lossy(&buf[..end - 4]);
                            let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
                            let method = parts.next().unwrap_or_default().to_owned();
                            let target = parts.next().unwrap_or_default().to_owned();
                            let content_len: usize = head
                                .lines()
                                .skip(1)
                                .find_map(|line| {
                                    let (k, v) = line.split_once(':')?;
                                    k.trim()
                                        .eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse().ok())?
                                })
                                .unwrap_or(0);
                            let mut body_read = buf.len() - end;
                            while body_read < content_len {
                                match stream.read(&mut chunk) {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => body_read += n,
                                }
                            }
                            handler(&method, &target, &mut stream);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            endpoint: format!("http://{addr}"),
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Negative — XML 1.0 forbids C0 controls other than HT/LF/CR and the noncharacters U+FFFE/U+FFFF,
/// both as raw scalars and as numeric character references.
#[test]
fn n_xmltree_rejects_disallowed_xml_1_0_chars_and_char_refs() {
    for forbidden in [
        "<Root>\x00</Root>",
        "<Root>\x01</Root>",
        "<Root>\x08</Root>",
        "<Root>\x0B</Root>",
        "<Root>\x0C</Root>",
        "<Root>\x1F</Root>",
        "<Root>\u{FFFE}</Root>",
        "<Root>\u{FFFF}</Root>",
        "<Root attr=\"a\x01b\"/>",
        "<Root attr=\"\u{FFFF}\"/>",
        "<Root>&#0;</Root>",
        "<Root>&#x0;</Root>",
        "<Root>&#1;</Root>",
        "<Root>&#x0B;</Root>",
        "<Root>&#x1F;</Root>",
        "<Root>&#xD800;</Root>",
        "<Root>&#xFFFE;</Root>",
        "<Root>&#xFFFF;</Root>",
        "<Root attr=\"&#x0;\"/>",
    ] {
        assert!(
            xmltree::parse(forbidden).is_none(),
            "xmltree::parse must reject disallowed XML 1.0 input {forbidden:?}"
        );
    }

    // Positive controls: HT, LF, CR, BMP, Astral, and valid numeric char references remain accepted.
    for allowed in [
        "<Root>\t\n\r hello &#9; &#xA; &#xD; &#x20; &#x1F600;</Root>",
        "<Root attr=\"a\tb&#x20;\">ok\u{FFFD}</Root>",
    ] {
        assert!(
            xmltree::parse(allowed).is_some(),
            "xmltree::parse must accept valid XML 1.0 input {allowed:?}"
        );
    }
}

/// Negative — `replay_decode_diff` must reject malformed XML and illegal XML 1.0 characters on
/// both `200` and `4xx` responses, while still accepting binary `200` non-XML object bodies.
#[test]
fn n_decode_diff_replay_validates_xml_on_200_and_4xx() {
    for (name, status_line, content_type, body) in [
        (
            "200-broken-xml",
            "200 OK",
            Some("application/xml"),
            &b"<?xml version=\"1.0\"?><ListBucketResult><Name>unclosed</ListBucketResult>"[..],
        ),
        (
            "200-illegal-xml-char",
            "200 OK",
            Some("application/xml; charset=utf-8"),
            b"<?xml version=\"1.0\"?><ListBucketResult><Key>bad\x01key</Key></ListBucketResult>",
        ),
        (
            "400-broken-error-xml",
            "400 Bad Request",
            Some("application/xml"),
            b"<?xml version=\"1.0\"?><Error><Code>InvalidArgument",
        ),
        (
            "404-illegal-xml-char-without-ct",
            "404 Not Found",
            None,
            b"<Error><Code>NoSuchKey</Code><Message>bad\x0bmsg</Message></Error>",
        ),
        (
            "403-non-xml-body-with-xml-ct",
            "403 Forbidden",
            Some("text/xml"),
            b"plain text error masquerading as xml",
        ),
    ] {
        let body_vec = body.to_vec();
        let status_owned = status_line.to_owned();
        let ct_owned = content_type.map(str::to_owned);
        let server = MockServer::start(move |_, _, stream| {
            let mut head = format!("HTTP/1.1 {status_owned}\r\n");
            if let Some(ct) = &ct_owned {
                head.push_str(&format!("Content-Type: {ct}\r\n"));
            }
            head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body_vec.len()));
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body_vec);
        });
        let corpus = scratch(name);
        std::fs::write(corpus.join("seed"), b"GET /bkt?list-type=2\n\n").expect("write");
        let opts = Options {
            endpoint: server.endpoint.clone(),
            target: Target::DecodeDiff,
            corpus_dirs: vec![corpus],
            credentials: None,
            bucket: "fuzz-encode-diff".to_owned(),
            artifacts_dir: None,
            timeout: Duration::from_secs(2),
            health_path: None,
            max_inputs: None,
        };
        let report = run(&opts).expect("run completes");
        let (exit, text) = report.conclude(Target::DecodeDiff, &server.endpoint);
        assert_eq!(exit, EXIT_FAILURE, "case {name} should fail malformed XML: {text}");
        assert!(text.contains("malformed XML"), "case {name} missing malformed XML detail: {text}");
    }

    // Positive control: binary 200 object payload (non-XML content-type, not starting with `<`)
    // and valid XML 404 error both pass cleanly.
    let server = MockServer::start(|_, target, stream| {
        if target.contains("binary") {
            let body = b"\x00\x01\x02raw-binary";
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        } else {
            let body = b"<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code></Error>";
            let head = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    let corpus = scratch("decode-xml-ok");
    std::fs::write(corpus.join("01-bin"), b"GET /bkt/binary\n\n").expect("write");
    std::fs::write(corpus.join("02-err"), b"GET /bkt/missing\n\n").expect("write");
    let opts = Options {
        endpoint: server.endpoint.clone(),
        target: Target::DecodeDiff,
        corpus_dirs: vec![corpus],
        credentials: None,
        bucket: "fuzz-encode-diff".to_owned(),
        artifacts_dir: None,
        timeout: Duration::from_secs(2),
        health_path: None,
        max_inputs: None,
    };
    let report = run(&opts).expect("run");
    let (exit, text) = report.conclude(Target::DecodeDiff, &server.endpoint);
    assert_eq!(exit, EXIT_PASSED, "{text}");
}

/// Negative — `encode_diff` must not blindly strip all `is_ascii_control()` bytes from every
/// listing sample: URL-encoded listings preserve ASCII control characters for differential
/// comparison and live endpoint replay catches raw illegal XML 1.0 control bytes in responses.
#[test]
fn n_encode_diff_preserves_control_bytes_in_url_encoded_sample_and_endpoint_replay() {
    let input = b"p\x01/\x00\t\x00tok\n\x00after\r\x00key\x01\x1f\x7f";
    let samples = endpoint_replay_outputs_of(input);
    let ctrl_sample = samples
        .iter()
        .find(|sample| sample.name == "fuzz-list-objects-v2-controls")
        .expect("endpoint_replay_outputs_of must emit a listing sample preserving control bytes");
    let OracleOutput::ListObjectsV2(listing) = (ctrl_sample.output)() else {
        panic!("expected ListObjectsV2 output");
    };
    assert_eq!(listing.prefix.as_deref(), Some("p\x01/"));
    assert_eq!(listing.delimiter.as_deref(), Some("\t"));
    let keys: Vec<&str> = listing
        .contents
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|obj| obj.key.as_deref())
        .collect();
    assert_eq!(keys, vec!["key\x01\x1f\x7f"]);
    check_encode(input).expect("control-character listing passes gateway XML 1.0 check in check_encode");

    // Live endpoint echoing raw \x01 in a 200 ListObjectsV2 XML body must be rejected.
    let server = MockServer::start(|method, target, stream| {
        if method == "GET" && target.contains("list-type=2") {
            let bad_xml =
                b"<?xml version=\"1.0\"?><ListBucketResult><Contents><Key>l/0/key\x01</Key></Contents></ListBucketResult>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bad_xml.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(bad_xml);
            return;
        }
        if method == "GET" && target.contains("/enc/") {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
            return;
        }
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    });
    let corpus = scratch("encode-ctrl-xml");
    std::fs::write(corpus.join("ctrl-seed"), input).expect("write");
    let opts = Options {
        endpoint: server.endpoint.clone(),
        target: Target::EncodeDiff,
        corpus_dirs: vec![corpus],
        credentials: None,
        bucket: "fuzz-encode-diff".to_owned(),
        artifacts_dir: None,
        timeout: Duration::from_secs(2),
        health_path: None,
        max_inputs: None,
    };
    let report = run(&opts).expect("run");
    let (exit, text) = report.conclude(Target::EncodeDiff, &server.endpoint);
    assert_eq!(exit, EXIT_FAILURE, "raw control byte in ListObjectsV2 XML must fail: {text}");
    assert!(text.contains("malformed XML"), "{text}");
}
