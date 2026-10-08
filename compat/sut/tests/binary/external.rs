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

//! `compat-sut --external`, end to end through two real `compat-sut` processes.
//!
//! Responsible for: proving that the observer forwards a signed request to an external endpoint
//! unchanged (the endpoint verifies a signature computed over the `Host` the client dialled), hands
//! the endpoint's answer back unchanged (status, `Server` header, body), records one probe line per
//! request naming who answered, and answers only for itself — with `502`, recorded as the
//! observer's — when the endpoint cannot be reached. The endpoint here is another `compat-sut`,
//! started on its own and addressed only by URL, which is how rustfs/backlog#2776 points the same
//! observer at a RustFS binary.
//! NOT responsible for: classifying a cell (`ci/compat/report.py`, `scripts/test_compat_report_cells.py`),
//! or what a full or a `--register-only` assembly serves (`src/service/tests/register_only_tests.rs`).
//! Upstream: rustfs/backlog#2758. Downstream: `ci/compat/run_matrix.sh --external` and
//! `ci/mint/run.sh --external`, which start the binary exactly this way.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{BufRead as _, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{Limits, Timestamp, TimestampFormat, WireRequest};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

const ACCESS_KEY: &str = "AKIAGATEWAYEXTERNAL0";
const SECRET_KEY: &str = "gateway-external-secret-for-a-throwaway-service";

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

/// One running `compat-sut`, killed and cleaned up on drop.
struct Process {
    child: Child,
    root: PathBuf,
    address: SocketAddr,
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn scratch(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "compat-sut-external-it-{label}-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("a scratch root");
    root
}

/// Spawns the binary with `arguments` and reads its banner up to `last`, returning the plaintext
/// address it announced.
fn spawn(root: PathBuf, arguments: &[String], last: &str) -> Process {
    let mut child = Command::new(env!("CARGO_BIN_EXE_compat-sut"))
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the compat-sut binary starts");
    let mut lines = BufReader::new(child.stdout.take().expect("a piped stdout")).lines();
    let mut address = None;
    let mut reached_last = false;
    for line in lines.by_ref() {
        let line = line.expect("a readable banner");
        if let Some(found) = line.strip_prefix("compat-sut listening on http://") {
            address = Some(found.parse().expect("a plaintext address"));
        }
        if line.starts_with(last) {
            reached_last = true;
            break;
        }
    }
    assert!(reached_last, "the banner never printed a line starting with {last:?}");
    std::thread::spawn(move || lines.for_each(drop));
    Process {
        child,
        root,
        address: address.expect("the banner names the plaintext listener"),
    }
}

/// The endpoint: a full assembly, or one registering only the named operations.
fn endpoint(register_only: Option<&str>) -> Process {
    let root = scratch("endpoint");
    let mut arguments: Vec<String> = vec!["--data".into(), root.join("data").display().to_string()];
    arguments.extend(["--port", "0", "--access-key", ACCESS_KEY, "--secret-key", SECRET_KEY].map(String::from));
    if let Some(names) = register_only {
        arguments.extend(["--register-only".to_owned(), names.to_owned()]);
    }
    spawn(root, &arguments, "compat-sut region ")
}

/// The observer, forwarding to `upstream`, recording into a probe log under its own root.
fn observer(upstream: &str) -> (Process, PathBuf) {
    let root = scratch("observer");
    let probe = root.join("probe.jsonl");
    let arguments: Vec<String> = vec![
        "--external".into(),
        upstream.into(),
        "--port".into(),
        "0".into(),
        "--probe-log".into(),
        probe.display().to_string(),
    ];
    (spawn(root, &arguments, "compat-sut forwarding to "), probe)
}

/// A port nothing listens on: bound, read, and released again.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port");
    listener.local_addr().expect("a bound address").port()
}

/// One signed HTTP/1.1 request as bytes, signed over the `Host` the client dials.
fn signed_request(authority: &str, method: &http::Method, target: &str, body: &[u8]) -> Vec<u8> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_str(authority).expect("a host header"));
    let digest: [u8; 32] = Sha256::digest(body).into();
    let payload = PayloadMode::ExactSha256(digest);
    headers.insert(
        http::HeaderName::from_static("x-amz-content-sha256"),
        http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("a digest header"),
    );
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&body.len().to_string()).expect("a content length"),
    );
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, authority)
        .body(Bytes::new())
        .expect("a valid host probe");
    let accepted = WireRequest::accept(probe, &Limits::default()).expect("an acceptable host");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let rendered = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let stamp = AmzDate::parse(&rendered).expect("a valid signing stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a valid signing scope");
    let credentials = SigningCredentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("valid signing credentials");
    let signing = SigningRequest::new(method, path, query, &headers, accepted.host().raw_for_signing(), payload, stamp)
        .with_wire_content_length(body.len() as u64);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut wire = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
    for (name, value) in signed.headers() {
        wire.extend_from_slice(name.as_str().as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"connection: close\r\n\r\n");
    wire.extend_from_slice(body);
    wire
}

/// The status, the `Server` header and the body of one response read to connection close.
struct Answer {
    status: u16,
    server: Option<String>,
    body: String,
}

async fn send(address: SocketAddr, method: &http::Method, target: &str, body: &[u8]) -> Answer {
    let authority = address.to_string();
    let mut stream = TcpStream::connect(address).await.expect("TCP connects");
    stream
        .write_all(&signed_request(&authority, method, target, body))
        .await
        .expect("the request is written");
    let mut received = Vec::new();
    stream
        .read_to_end(&mut received)
        .await
        .expect("the response is read to close");
    let text = String::from_utf8_lossy(&received).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("not an HTTP response: {text:?}"));
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let server = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("server").then(|| value.trim().to_owned())
    });
    Answer {
        status,
        server,
        body: body.to_owned(),
    }
}

/// The probe log's records, one JSON object per line, as `ci/compat/report.py` reads them.
fn records(path: &PathBuf) -> Vec<String> {
    std::fs::read_to_string(path)
        .expect("the observer wrote a probe log")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Positive — a signed write and read cross the observer and the endpoint verifies them: the
/// signature covers the `Host` the client dialled, so it verifies only if the observer forwarded
/// that header unchanged. The endpoint's own answer comes back, `Server` header included.
#[tokio::test]
async fn a_signed_request_reaches_the_endpoint_unchanged_and_its_answer_comes_back() {
    let endpoint = endpoint(None);
    let (observer, probe) = observer(&format!("http://{}", endpoint.address));

    let direct = send(endpoint.address, &http::Method::GET, "/", b"").await;
    let created = send(observer.address, &http::Method::PUT, "/observed", b"").await;
    assert_eq!(created.status, 200, "{}", created.body);
    let written = send(observer.address, &http::Method::PUT, "/observed/key", b"forwarded bytes").await;
    assert_eq!(written.status, 200, "{}", written.body);
    let read = send(observer.address, &http::Method::GET, "/observed/key", b"").await;
    assert_eq!((read.status, read.body.as_str()), (200, "forwarded bytes"));
    assert!(direct.server.is_some(), "the endpoint names itself");
    assert_eq!(read.server, direct.server, "the endpoint's Server header is passed through");

    let lines = records(&probe);
    assert_eq!(lines.len(), 3, "one record per observed request: {lines:?}");
    for line in &lines {
        assert!(line.contains("\"status\":200"), "{line}");
        assert!(line.contains("\"answered_by\":\"upstream\""), "{line}");
    }
    assert!(lines[1].contains("\"payload_mode\":\"sha256-hex\""), "{}", lines[1]);
    assert!(!lines.iter().any(|line| line.contains(SECRET_KEY)), "no secret reaches the evidence");
}

/// Negative — an endpoint that does not register an operation answers `501` through the
/// observer, and the record names the endpoint, not the observer, as the one that answered. The
/// operation it does register still answers, so the `501` is the registry's and not a broken hop.
#[tokio::test]
async fn n_an_unregistered_operation_is_the_endpoints_answer_not_the_observers() {
    let endpoint = endpoint(Some("ListBuckets"));
    let (observer, probe) = observer(&format!("http://{}", endpoint.address));

    let refused = send(observer.address, &http::Method::PUT, "/unregistered", b"").await;
    assert_eq!(refused.status, 501, "{}", refused.body);
    assert!(refused.body.contains("NotImplemented"), "{}", refused.body);
    let listed = send(observer.address, &http::Method::GET, "/", b"").await;
    assert_eq!(listed.status, 200, "{}", listed.body);

    let lines = records(&probe);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("\"status\":501"), "{}", lines[0]);
    assert!(lines[0].contains("\"answered_by\":\"upstream\""), "{}", lines[0]);
    assert!(lines[1].contains("\"status\":200"), "{}", lines[1]);
}

/// Negative — an endpoint nobody listens on is answered by the observer itself with `502`, and
/// recorded as the observer's answer, so the reporter stops the run instead of grading a cell.
#[tokio::test]
async fn n_an_unreachable_endpoint_is_answered_by_the_observer_and_recorded_as_such() {
    let (observer, probe) = observer(&format!("http://127.0.0.1:{}", closed_port()));

    let answer = send(observer.address, &http::Method::GET, "/", b"").await;
    assert_eq!(answer.status, 502, "{}", answer.body);
    assert_eq!(answer.server, None, "the observer does not claim to be the endpoint");

    let lines = records(&probe);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("\"status\":502"), "{}", lines[0]);
    assert!(lines[0].contains("\"answered_by\":\"observer\""), "{}", lines[0]);
}
