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

//! The encrypted listener, end to end through the real `compat-sut` binary.
//!
//! Responsible for: proving that a launch with `--tls-self-signed` serves signed S3 requests over
//! TLS to a client that trusts only the authority it wrote, that the gateway behind that listener
//! is told the socket was encrypted (a customer-provided key is accepted there and refused on the
//! plaintext listener beside it), and that the plaintext listener keeps working unchanged.
//! NOT responsible for: the handshake or reload contracts (`crates/server/tests/tls_h2.rs`), or
//! customer-key semantics (`crates/core/src/sse`).
//! Upstream: rustfs/gateway#719. Downstream: `ci/mint/run.sh` and `ci/compat/run_matrix.sh`, which
//! start the binary exactly this way.
//!
//! These spawn the binary rather than calling `main`'s pieces, because what the suites are pointed
//! at is the binary: an assembly written for a test proves nothing about the one that runs.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{Limits, Timestamp, TimestampFormat, WireRequest};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const ACCESS_KEY: &str = "AKIAGATEWAYTLS000000";
const SECRET_KEY: &str = "gateway-tls-secret-for-a-throwaway-service";

/// A fixed 32-byte customer key, its base64 and the base64 of its MD5, as a client sends them.
const CUSTOMER_KEY: &str = "Y29tcGF0LXN1dC1zc2UtYy1rZXktMzItYnl0ZXMtb2s=";
const CUSTOMER_KEY_MD5: &str = "i6PuDPIsVPZBnFqXe7EgYg==";

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

/// One running `compat-sut`, killed and cleaned up on drop.
struct Sut {
    child: Child,
    root: PathBuf,
    plaintext: SocketAddr,
    encrypted: Option<SocketAddr>,
    authority: Option<PathBuf>,
}

impl Drop for Sut {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn launch(with_tls: bool) -> Sut {
    let root = std::env::temp_dir().join(format!(
        "compat-sut-tls-it-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("a scratch root");
    let authority = root.join("tls").join("ca.pem");
    let mut command = Command::new(env!("CARGO_BIN_EXE_compat-sut"));
    command
        .arg("--data")
        .arg(root.join("data"))
        .args(["--port", "0", "--access-key", ACCESS_KEY, "--secret-key", SECRET_KEY]);
    if with_tls {
        command.args(["--tls-port", "0", "--tls-self-signed"]).arg(&authority);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the compat-sut binary starts");
    let mut lines = BufReader::new(child.stdout.take().expect("a piped stdout")).lines();
    let mut plaintext = None;
    let mut encrypted = None;
    let mut announced_authority = None;
    for line in lines.by_ref() {
        let line = line.expect("a readable banner");
        if let Some(address) = line.strip_prefix("compat-sut listening on http://") {
            plaintext = Some(address.parse().expect("a plaintext address"));
        } else if let Some(address) = line.strip_prefix("compat-sut listening on https://") {
            encrypted = Some(address.parse().expect("an encrypted address"));
        } else if let Some(path) = line.strip_prefix("compat-sut tls authority ") {
            announced_authority = Some(PathBuf::from(path));
        } else if line.starts_with("compat-sut region ") {
            break;
        }
    }
    // Keep draining, so a later line never meets a closed pipe.
    std::thread::spawn(move || lines.for_each(drop));
    let sut = Sut {
        child,
        root,
        plaintext: plaintext.expect("the banner names the plaintext listener"),
        encrypted,
        authority: announced_authority,
    };
    if with_tls {
        assert!(sut.encrypted.is_some(), "the banner names the encrypted listener");
        assert_eq!(
            sut.authority.as_deref(),
            Some(authority.as_path()),
            "the banner names the written authority"
        );
    } else {
        assert!(sut.encrypted.is_none() && sut.authority.is_none(), "no TLS flag, no encrypted listener");
    }
    sut
}

/// One signed HTTP/1.1 request as bytes, signed the way any SDK signs it: the exact payload
/// digest, the host the client dials, and the current time.
fn signed_request(authority: &str, method: &http::Method, target: &str, body: &[u8], extra: &[(&str, &str)]) -> Vec<u8> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_str(authority).expect("a host header"));
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a valid header name"),
            http::HeaderValue::from_str(value).expect("a valid header value"),
        );
    }
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

/// The status and the body of one response read to connection close.
struct Answer {
    status: u16,
    body: String,
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, request: &[u8]) -> Answer {
    stream.write_all(request).await.expect("the request is written");
    stream.flush().await.expect("the request is flushed");
    let mut received = Vec::new();
    match stream.read_to_end(&mut received).await {
        Ok(_) => {}
        // A peer that closes without close_notify still sent a complete `connection: close`
        // response; what matters here is the response, not how the socket ended.
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(error) => panic!("reading the response failed: {error}"),
    }
    let text = String::from_utf8_lossy(&received).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("not an HTTP response: {text:?}"));
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    Answer { status, body }
}

fn connector(authority: &Path) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(authority).expect("a readable authority") {
        roots
            .add(certificate.expect("a PEM certificate"))
            .expect("the written authority is a valid trust anchor");
    }
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(client))
}

/// Over TLS, trusting only the authority `compat-sut` wrote, to the name `localhost`.
async fn over_tls(sut: &Sut, method: &http::Method, target: &str, body: &[u8], extra: &[(&str, &str)]) -> Answer {
    let address = sut.encrypted.expect("an encrypted listener");
    let authority = sut.authority.as_deref().expect("a written authority");
    let host = format!("localhost:{}", address.port());
    let tcp = TcpStream::connect(address)
        .await
        .expect("TCP connects to the encrypted listener");
    let name = ServerName::try_from("localhost").expect("a DNS name").to_owned();
    let stream = connector(authority)
        .connect(name, tcp)
        .await
        .expect("the handshake verifies against the written authority");
    exchange(stream, &signed_request(&host, method, target, body, extra)).await
}

async fn over_plaintext(sut: &Sut, method: &http::Method, target: &str, body: &[u8], extra: &[(&str, &str)]) -> Answer {
    let tcp = TcpStream::connect(sut.plaintext)
        .await
        .expect("TCP connects to the plaintext listener");
    exchange(tcp, &signed_request(&sut.plaintext.to_string(), method, target, body, extra)).await
}

const CUSTOMER_KEY_HEADERS: [(&str, &str); 3] = [
    ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
    ("x-amz-server-side-encryption-customer-key", CUSTOMER_KEY),
    ("x-amz-server-side-encryption-customer-key-md5", CUSTOMER_KEY_MD5),
];

/// Positive — a signed PUT and GET round-trip over TLS to a client that trusts only the written
/// authority, and the plaintext listener beside it still serves the same data root.
#[tokio::test]
async fn a_signed_put_over_tls_is_stored_and_read_back() {
    let sut = launch(true);
    let created = over_tls(&sut, &http::Method::PUT, "/tls-bucket", b"", &[]).await;
    assert_eq!(created.status, 200, "CreateBucket over TLS: {}", created.body);
    let stored = over_tls(&sut, &http::Method::PUT, "/tls-bucket/object", b"sent over tls", &[]).await;
    assert_eq!(stored.status, 200, "PutObject over TLS: {}", stored.body);
    let read = over_tls(&sut, &http::Method::GET, "/tls-bucket/object", b"", &[]).await;
    assert_eq!(read.status, 200, "GetObject over TLS: {}", read.body);
    assert_eq!(read.body, "sent over tls");

    let beside = over_plaintext(&sut, &http::Method::GET, "/tls-bucket/object", b"", &[]).await;
    assert_eq!(beside.status, 200, "the plaintext listener serves the same service: {}", beside.body);
    assert_eq!(beside.body, "sent over tls");
}

/// Negative — a request signed with the wrong secret is refused over TLS exactly as over
/// plaintext: encryption is not authentication.
#[tokio::test]
async fn n_a_wrongly_signed_request_is_refused_over_tls() {
    let sut = launch(true);
    let mut forged = signed_request(
        &format!("localhost:{}", sut.encrypted.expect("an encrypted listener").port()),
        &http::Method::PUT,
        "/forged-bucket",
        b"",
        &[],
    );
    let text = String::from_utf8(forged.clone()).expect("an ASCII request");
    let signature = text.find("Signature=").expect("a signed request") + "Signature=".len();
    forged[signature] = if forged[signature] == b'0' { b'1' } else { b'0' };
    let address = sut.encrypted.expect("an encrypted listener");
    let tcp = TcpStream::connect(address).await.expect("TCP connects");
    let name = ServerName::try_from("localhost").expect("a DNS name").to_owned();
    let stream = connector(sut.authority.as_deref().expect("an authority"))
        .connect(name, tcp)
        .await
        .expect("the handshake succeeds");
    let refused = exchange(stream, &forged).await;
    assert_eq!(refused.status, 403, "a forged signature over TLS: {}", refused.body);
}

/// The gateway behind the encrypted listener is told the socket was encrypted: a customer-provided
/// key is accepted over TLS and refused over plaintext, on the same process and the same bucket.
///
/// Both halves in one case on purpose. A refusal alone is satisfied by a gateway that refuses
/// every customer key, which is exactly what it does when nothing declares the transport.
#[tokio::test]
async fn a_customer_key_is_accepted_over_tls_and_refused_over_plaintext() {
    let sut = launch(true);
    let created = over_plaintext(&sut, &http::Method::PUT, "/sse-bucket", b"", &[]).await;
    assert_eq!(created.status, 200, "CreateBucket over plaintext: {}", created.body);

    let accepted = over_tls(&sut, &http::Method::PUT, "/sse-bucket/secret", b"customer keyed", &CUSTOMER_KEY_HEADERS).await;
    assert_eq!(accepted.status, 200, "SSE-C PutObject over TLS: {}", accepted.body);

    let refused = over_plaintext(
        &sut,
        &http::Method::PUT,
        "/sse-bucket/cleartext",
        b"customer keyed",
        &CUSTOMER_KEY_HEADERS,
    )
    .await;
    assert_eq!(refused.status, 400, "SSE-C PutObject over plaintext: {}", refused.body);
    assert!(refused.body.contains("<Code>InvalidRequest</Code>"), "{}", refused.body);
    let absent = over_plaintext(&sut, &http::Method::GET, "/sse-bucket/cleartext", b"", &[]).await;
    assert_eq!(absent.status, 404, "the refused write stored nothing: {}", absent.body);
}

/// Negative — without a TLS flag there is no encrypted listener, and the plaintext one refuses a
/// customer key exactly as before: the default launch is unchanged.
#[tokio::test]
async fn n_the_default_launch_has_no_encrypted_listener_and_refuses_customer_keys() {
    let sut = launch(false);
    let created = over_plaintext(&sut, &http::Method::PUT, "/plain-bucket", b"", &[]).await;
    assert_eq!(created.status, 200, "CreateBucket over plaintext: {}", created.body);
    let refused = over_plaintext(&sut, &http::Method::PUT, "/plain-bucket/key", b"body", &CUSTOMER_KEY_HEADERS).await;
    assert_eq!(refused.status, 400, "SSE-C over plaintext: {}", refused.body);
}
