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

//! Tests for the out-of-process `fuzz-endpoint-replay` engine (`endpoint_replay.rs`).
//!
//! Responsible for: verifying CLI validation, endpoint parsing, fail-closed missing/empty corpus
//! handling, crash/5xx/hang/malformed-HTTP/malformed-XML detection, artifact emission without
//! secret leakage, liveness probes, healthy `decode_diff` and `encode_diff` loopback replays, and
//! committed `fuzz/seeds/encode_diff/` validity.
//! NOT responsible for: in-process differential checks (`fuzz.rs`, `runner.rs`).
//! Upstream: `endpoint_replay.rs`, `fuzz/seeds/encode_diff/`. Downstream: none.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::endpoint_replay::{Credentials, EXIT_ENVIRONMENT, EXIT_FAILURE, EXIT_PASSED, Endpoint, Options, Target, run};

fn scratch(name: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("difftest-ep-replay-{name}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch directory");
    path
}

struct MockRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

fn read_request_line_and_headers(stream: &mut std::net::TcpStream) -> Option<MockRequest> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end - 4]);
    let mut lines = head.split("\r\n");
    let start = lines.next()?;
    let mut parts = start.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut headers = Vec::new();
    let mut content_len: usize = 0;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let name = k.trim().to_ascii_lowercase();
            let val = v.trim().to_owned();
            if name == "content-length" {
                content_len = val.parse().unwrap_or(0);
            }
            headers.push((name, val));
        }
    }
    let mut body_read = buf.len() - header_end;
    while body_read < content_len {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body_read += n,
        }
    }
    Some(MockRequest { method, target, headers })
}

struct MockServer {
    endpoint: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(&str, &str, &[(String, String)], &mut std::net::TcpStream) + Send + Sync + 'static,
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
                        let handler = Arc::clone(&handler);
                        if let Some(req) = read_request_line_and_headers(&mut stream) {
                            handler(&req.method, &req.target, &req.headers, &mut stream);
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

/// Negative — CLI refuses missing required flags, unknown targets, unpaired credentials, and zero bounds.
#[test]
fn cli_refuses_invalid_and_incomplete_arguments() {
    let parse = |args: &[&str]| Options::parse(args.iter().map(|arg| (*arg).to_owned()));
    assert!(parse(&[]).is_err());
    assert!(parse(&["--target", "decode_diff", "--corpus-dir", "d"]).is_err());
    assert!(parse(&["--endpoint", "http://127.0.0.1:9000", "--corpus-dir", "d"]).is_err());
    assert!(parse(&["--endpoint", "http://127.0.0.1:9000", "--target", "decode_diff"]).is_err());
    assert!(
        parse(&[
            "--endpoint",
            "http://127.0.0.1:9000",
            "--target",
            "xml_parse",
            "--corpus-dir",
            "d"
        ])
        .is_err()
    );
    assert!(
        parse(&[
            "--endpoint",
            "http://127.0.0.1:9000",
            "--target",
            "decode_diff",
            "--corpus-dir",
            "d",
            "--access-key",
            "AKIA",
        ])
        .is_err()
    );
    assert!(
        parse(&[
            "--endpoint",
            "http://127.0.0.1:9000",
            "--target",
            "decode_diff",
            "--corpus-dir",
            "d",
            "--timeout-ms",
            "0",
        ])
        .is_err()
    );
    assert!(
        parse(&[
            "--endpoint",
            "http://127.0.0.1:9000",
            "--target",
            "decode_diff",
            "--corpus-dir",
            "d",
            "--max-inputs",
            "0",
        ])
        .is_err()
    );
    assert!(
        parse(&[
            "--endpoint",
            "http://127.0.0.1:9000",
            "--target",
            "decode_diff",
            "--corpus-dir",
            "d",
            "--health-path",
            "health/ready",
        ])
        .is_err()
    );
    assert!(
        parse(&[
            "--endpoint",
            "http://127.0.0.1:9000",
            "--target",
            "encode_diff",
            "--corpus-dir",
            "d",
            "--bucket",
            "bad/bucket",
        ])
        .is_err()
    );
    assert!(
        parse(&[
            "--endpoint",
            "http://127.0.0.1:9000",
            "--target",
            "decode_diff",
            "--corpus-dir",
            "d",
            "--unknown-flag",
        ])
        .is_err()
    );
    let parsed = parse(&[
        "--endpoint",
        "http://127.0.0.1:19000",
        "--target",
        "encode_diff",
        "--corpus-dir",
        "a",
        "--corpus-dir",
        "b",
        "--access-key",
        "AK",
        "--secret-key",
        "SK",
        "--region",
        "eu-west-1",
        "--health-path",
        "/health/ready",
        "--timeout-ms",
        "2500",
        "--max-inputs",
        "50",
    ])
    .expect("valid CLI");
    assert_eq!(parsed.target, Target::EncodeDiff);
    assert_eq!(parsed.corpus_dirs.len(), 2);
    assert_eq!(parsed.timeout, Duration::from_millis(2500));
    assert_eq!(parsed.max_inputs, Some(50));
    assert_eq!(parsed.health_path.as_deref(), Some("/health/ready"));
    let debug = format!("{:?}", parsed.credentials);
    assert!(!debug.contains("SK"), "Credentials Debug must redact secret_key: {debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
}

/// Negative — endpoint parser refuses unsupported schemes, paths, queries, userinfo, and bad ports.
#[test]
fn endpoint_parser_refuses_malformed_urls() {
    for bad in [
        "",
        "127.0.0.1:9000",
        "https://127.0.0.1:9000",
        "http://127.0.0.1:9000/extra",
        "http://127.0.0.1:9000?a=b",
        "http://user:pass@127.0.0.1:9000",
        "http://:9000",
        "http://127.0.0.1:notaport",
        "http://[::1",
    ] {
        assert!(Endpoint::parse(bad).is_err(), "expected rejection for {bad:?}");
    }
    let ok = Endpoint::parse("http://127.0.0.1:19000/").expect("valid loopback endpoint");
    assert_eq!(ok.url, "http://127.0.0.1:19000");
    assert_eq!(ok.authority, "127.0.0.1:19000");
}

/// Negative — missing, empty, or non-request corpora never read as a pass.
#[test]
fn missing_empty_or_unreplayable_corpus_fails_as_environment_error() {
    let server = MockServer::start(|_, _, _, stream| {
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    });

    let missing_dir = std::env::temp_dir().join("difftest-nonexistent-corpus-dir-99999");
    let opts = Options::parse(
        [
            "--endpoint",
            &server.endpoint,
            "--target",
            "decode_diff",
            "--corpus-dir",
            &missing_dir.display().to_string(),
        ]
        .into_iter()
        .map(str::to_owned),
    )
    .expect("options");
    assert!(run(&opts).expect_err("missing dir").contains("does not exist"));

    let empty_dir = scratch("empty-corpus");
    let opts = Options {
        corpus_dirs: vec![empty_dir],
        ..opts
    };
    assert!(run(&opts).expect_err("empty dir").contains("no corpus files"));

    let junk_dir = scratch("non-request-corpus");
    std::fs::write(junk_dir.join("garbage"), b"not an http request at all").expect("write");
    let opts = Options {
        corpus_dirs: vec![junk_dir],
        ..opts
    };
    let report = run(&opts).expect("report");
    let (status, text) = report.conclude(Target::DecodeDiff, &server.endpoint);
    assert_eq!(status, EXIT_ENVIRONMENT, "{text}");
    assert!(text.contains("zero corpus inputs were replayed"), "{text}");
}

/// Negative — an unhealthy endpoint fails pre-run health probe as an environment error.
#[test]
fn unhealthy_endpoint_fails_preflight_health_check() {
    let server = MockServer::start(|_, _, _, stream| {
        let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    });
    let corpus = scratch("health-preflight");
    std::fs::write(corpus.join("seed"), b"GET /bkt/k\n\n").expect("write");
    let opts = Options {
        endpoint: server.endpoint.clone(),
        target: Target::DecodeDiff,
        corpus_dirs: vec![corpus],
        credentials: None,
        bucket: "fuzz-encode-diff".to_owned(),
        artifacts_dir: None,
        timeout: Duration::from_secs(2),
        health_path: Some("/health/ready".to_owned()),
        max_inputs: None,
    };
    let error = run(&opts).expect_err("unhealthy preflight");
    assert!(error.contains("initial health check"), "{error}");
}

/// Negative — an HTTP 500 on decode_diff fails loudly and writes a redacted crash artifact.
#[test]
fn decode_diff_500_fails_and_writes_crash_artifact_without_secret() {
    let server = MockServer::start(|method, target, _, stream| {
        if target == "/health/ready" || (method == "PUT" && target == "/bkt") {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return;
        }
        let body = b"<Error><Code>InternalError</Code><Message>simulated panic</Message></Error>";
        let resp = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.write_all(body);
    });

    let corpus = scratch("decode-500");
    let artifacts = scratch("decode-500-artifacts");
    let seed_bytes = b"GET /bkt/crash-key\n\n";
    std::fs::write(corpus.join("crash-seed"), seed_bytes).expect("write");

    let secret = "super-secret-never-log-value";
    let opts = Options {
        endpoint: server.endpoint.clone(),
        target: Target::DecodeDiff,
        corpus_dirs: vec![corpus],
        credentials: Some(Credentials::new("AKIAEXAMPLE", secret, "us-east-1")),
        bucket: "fuzz-encode-diff".to_owned(),
        artifacts_dir: Some(artifacts.clone()),
        timeout: Duration::from_secs(2),
        health_path: Some("/health/ready".to_owned()),
        max_inputs: None,
    };
    let report = run(&opts).expect("run completes with failure report");
    let (status, text) = report.conclude(Target::DecodeDiff, &server.endpoint);
    assert_eq!(status, EXIT_FAILURE, "{text}");
    assert_eq!(report.failures.len(), 1);
    assert!(!text.contains(secret), "report must not contain secret: {text}");
    let artifact = report.failures[0].artifact_path.as_ref().expect("artifact written");
    assert_eq!(std::fs::read(artifact).expect("artifact input"), seed_bytes);
    let report_file = artifact.with_extension("report.txt");
    let report_text = std::fs::read_to_string(&report_file).expect("artifact report");
    assert!(report_text.contains("unexpected HTTP 500"), "{report_text}");
    assert!(!report_text.contains(secret), "artifact report must not leak secret");
}

/// Negative — an endpoint that drops the connection and dies fails and sets endpoint_died.
#[test]
fn decode_diff_connection_drop_detects_crash_and_stops() {
    let alive = Arc::new(AtomicBool::new(true));
    let alive_srv = Arc::clone(&alive);
    let server = MockServer::start(move |_, target, _, stream| {
        if target == "/health/ready" {
            if alive_srv.load(Ordering::Relaxed) {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
            return;
        }
        // Simulate server crashing while handling the first corpus input.
        alive_srv.store(false, Ordering::Relaxed);
    });

    let corpus = scratch("decode-crash");
    let artifacts = scratch("decode-crash-artifacts");
    std::fs::write(corpus.join("01-first"), b"GET /bkt/a\n\n").expect("write");
    std::fs::write(corpus.join("02-second"), b"GET /bkt/b\n\n").expect("write");

    let opts = Options {
        endpoint: server.endpoint.clone(),
        target: Target::DecodeDiff,
        corpus_dirs: vec![corpus],
        credentials: None,
        bucket: "fuzz-encode-diff".to_owned(),
        artifacts_dir: Some(artifacts),
        timeout: Duration::from_secs(2),
        health_path: Some("/health/ready".to_owned()),
        max_inputs: None,
    };
    let report = run(&opts).expect("run");
    let (status, text) = report.conclude(Target::DecodeDiff, &server.endpoint);
    assert_eq!(status, EXIT_FAILURE, "{text}");
    assert!(report.endpoint_died, "{text}");
    assert_eq!(report.replayed, 1, "should stop early once candidate died");
    assert_eq!(report.failures.len(), 1);
}

/// Negative — a hanging server triggers timeout failure and writes an artifact.
#[test]
fn decode_diff_hanging_server_times_out_and_fails() {
    let server = MockServer::start(|_, target, _, stream| {
        if target == "/health/ready" {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return;
        }
        thread::sleep(Duration::from_millis(400));
    });

    let corpus = scratch("decode-hang");
    std::fs::write(corpus.join("hang"), b"GET /bkt/slow\n\n").expect("write");
    let opts = Options {
        endpoint: server.endpoint.clone(),
        target: Target::DecodeDiff,
        corpus_dirs: vec![corpus],
        credentials: None,
        bucket: "fuzz-encode-diff".to_owned(),
        artifacts_dir: None,
        timeout: Duration::from_millis(120),
        health_path: None,
        max_inputs: None,
    };
    let report = run(&opts).expect("run");
    let (status, text) = report.conclude(Target::DecodeDiff, &server.endpoint);
    assert_eq!(status, EXIT_FAILURE, "{text}");
    assert_eq!(report.failures.len(), 1);
}

/// Negative — malformed HTTP response bytes fail replay.
#[test]
fn decode_diff_malformed_http_response_fails() {
    let server = MockServer::start(|_, _, _, stream| {
        let _ = stream.write_all(b"NOT_HTTP/9.9 GARBAGE\r\n\r\n");
    });
    let corpus = scratch("decode-malformed-http");
    std::fs::write(corpus.join("seed"), b"GET /bkt/k\n\n").expect("write");
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
    assert_eq!(report.conclude(Target::DecodeDiff, &server.endpoint).0, EXIT_FAILURE);
}

/// Negative — encode_diff fails when a 200 ListObjectsV2 response contains malformed XML.
#[test]
fn encode_diff_malformed_listing_xml_fails_with_artifact() {
    let server = MockServer::start(|method, target, _, stream| {
        if method == "GET" && target.contains("list-type=2") {
            let bad_xml = b"<?xml version=\"1.0\"?><ListBucketResult><Key>a<b</Key></ListBucketResult>";
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

    let corpus = scratch("encode-bad-xml");
    let artifacts = scratch("encode-bad-xml-artifacts");
    let payload = b"pref/\x00/\x00\x00\x00key<bad>";
    std::fs::write(corpus.join("bad-xml-seed"), payload).expect("write");

    let opts = Options {
        endpoint: server.endpoint.clone(),
        target: Target::EncodeDiff,
        corpus_dirs: vec![corpus],
        credentials: None,
        bucket: "fuzz-encode-diff".to_owned(),
        artifacts_dir: Some(artifacts),
        timeout: Duration::from_secs(2),
        health_path: None,
        max_inputs: None,
    };
    let report = run(&opts).expect("run");
    let (status, text) = report.conclude(Target::EncodeDiff, &server.endpoint);
    assert_eq!(status, EXIT_FAILURE, "{text}");
    assert!(text.contains("malformed XML"), "{text}");
    let artifact = report.failures[0].artifact_path.as_ref().expect("artifact");
    assert_eq!(std::fs::read(artifact).expect("artifact bytes"), payload);
}

/// Negative — encode_diff fails if HeadObject fails after PutObject returned 200.
#[test]
fn encode_diff_head_failure_after_put_fails() {
    let server = MockServer::start(|method, target, _, stream| {
        if method == "HEAD" {
            let _ = stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return;
        }
        if method == "GET" && target.contains("list-type=2") {
            let xml = b"<?xml version=\"1.0\"?><ListBucketResult><Name>fuzz-encode-diff</Name></ListBucketResult>";
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", xml.len());
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(xml);
            return;
        }
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    });

    let corpus = scratch("encode-head-500");
    std::fs::write(corpus.join("seed"), b"text/plain\x00inline\x00k\x00v").expect("write");
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
    assert_eq!(report.conclude(Target::EncodeDiff, &server.endpoint).0, EXIT_FAILURE);
}

/// Negative — failing post-run health probe marks endpoint_died even when requests returned 200.
#[test]
fn post_run_health_failure_fails_replay() {
    let health_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&health_calls);
    let server = MockServer::start(move |_, target, _, stream| {
        if target == "/health/ready" {
            if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            } else {
                let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
            return;
        }
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    });

    let corpus = scratch("post-health-fail");
    std::fs::write(corpus.join("seed"), b"GET /bkt/k\n\n").expect("write");
    let opts = Options {
        endpoint: server.endpoint.clone(),
        target: Target::DecodeDiff,
        corpus_dirs: vec![corpus],
        credentials: None,
        bucket: "fuzz-encode-diff".to_owned(),
        artifacts_dir: None,
        timeout: Duration::from_secs(2),
        health_path: Some("/health/ready".to_owned()),
        max_inputs: None,
    };
    let report = run(&opts).expect("run");
    assert_eq!(report.conclude(Target::DecodeDiff, &server.endpoint).0, EXIT_FAILURE);
    assert!(report.endpoint_died);
}

/// Positive — healthy loopback server passes decode_diff replay including 4xx, 501, and chunked bodies.
#[test]
fn healthy_endpoint_passes_decode_diff_replay() {
    let seen_signed = Arc::new(AtomicUsize::new(0));
    let signed_ctr = Arc::clone(&seen_signed);
    let server = MockServer::start(move |method, target, headers, stream| {
        if target == "/health/ready" {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return;
        }
        if headers
            .iter()
            .any(|(name, value)| name == "authorization" && value.starts_with("AWS4-HMAC-SHA256"))
        {
            signed_ctr.fetch_add(1, Ordering::Relaxed);
        }
        if method == "PATCH" {
            let _ = stream.write_all(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return;
        }
        if target.contains("chunked") {
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n");
            return;
        }
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot-found");
    });

    let corpus = scratch("decode-healthy");
    std::fs::write(corpus.join("01-get"), b"GET /bkt/chunked\n\n").expect("write");
    std::fs::write(corpus.join("02-dup"), b"GET /bkt/chunked\n\n").expect("write");
    std::fs::write(corpus.join("03-patch"), b"PATCH /bkt/k\n\n").expect("write");
    std::fs::write(corpus.join("04-put"), b"PUT /bkt/k\n\nhello").expect("write");

    let opts = Options {
        endpoint: server.endpoint.clone(),
        target: Target::DecodeDiff,
        corpus_dirs: vec![corpus],
        credentials: Some(Credentials::new("AKIAEXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1")),
        bucket: "fuzz-encode-diff".to_owned(),
        artifacts_dir: None,
        timeout: Duration::from_secs(2),
        health_path: Some("/health/ready".to_owned()),
        max_inputs: None,
    };
    let report = run(&opts).expect("run");
    let (status, text) = report.conclude(Target::DecodeDiff, &server.endpoint);
    assert_eq!(status, EXIT_PASSED, "{text}");
    assert_eq!(report.files_seen, 4);
    assert_eq!(report.unique_inputs, 3, "duplicate files deduplicated by content hash");
    assert_eq!(report.replayed, 3);
    assert!(seen_signed.load(Ordering::Relaxed) >= 3, "requests signed with SigV4");
}

/// Positive — healthy loopback server passes encode_diff replay with committed seeds.
#[test]
fn healthy_endpoint_passes_encode_diff_replay() {
    let store: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let store_srv = Arc::clone(&store);
    let server = MockServer::start(move |method, target, _, stream| {
        if target == "/health/ready" {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return;
        }
        match method {
            "PUT" => {
                if target.matches('/').count() >= 2 {
                    store_srv.lock().expect("lock").insert(target.to_owned(), b"hello".to_vec());
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
            "HEAD" => {
                let exists = store_srv.lock().expect("lock").contains_key(target);
                let line = if exists { "200 OK" } else { "404 Not Found" };
                let resp = format!("HTTP/1.1 {line}\r\nContent-Length: 5\r\nConnection: close\r\n\r\n");
                let _ = stream.write_all(resp.as_bytes());
            }
            "GET" if target.contains("list-type=2") => {
                let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>fuzz-encode-diff</Name><IsTruncated>false</IsTruncated></ListBucketResult>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    xml.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(xml);
            }
            "GET" => {
                let body = store_srv.lock().expect("lock").get(target).cloned();
                if let Some(body) = body {
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.write_all(&body);
                } else {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
            }
            "DELETE" => {
                store_srv.lock().expect("lock").remove(target);
                let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
            }
            _ => {
                let _ = stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        }
    });

    let seeds_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/seeds/encode_diff"));
    let opts = Options {
        endpoint: server.endpoint.clone(),
        target: Target::EncodeDiff,
        corpus_dirs: vec![seeds_dir],
        credentials: Some(Credentials::new("AKIAEXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1")),
        bucket: "fuzz-encode-diff".to_owned(),
        artifacts_dir: None,
        timeout: Duration::from_secs(2),
        health_path: Some("/health/ready".to_owned()),
        max_inputs: None,
    };
    let report = run(&opts).expect("run");
    let (status, text) = report.conclude(Target::EncodeDiff, &server.endpoint);
    assert_eq!(status, EXIT_PASSED, "{text}");
    assert!(report.replayed >= 8, "committed encode_diff seeds must be replayed: {text}");
    assert!(report.requests_sent >= report.replayed * 4, "{text}");
}

/// Positive — every committed encode_diff seed passes the in-process encode fuzz property too.
#[test]
fn every_committed_encode_seed_passes_the_encode_property() {
    let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/seeds/encode_diff"));
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| entry.expect("seed entry").path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    assert!(paths.len() >= 8, "expected at least 8 encode_diff seeds, found {}", paths.len());
    for path in paths {
        let bytes = std::fs::read(&path).expect("seed bytes");
        crate::fuzz::check_encode(&bytes).unwrap_or_else(|report| panic!("{}: {report}", path.display()));
    }
}
