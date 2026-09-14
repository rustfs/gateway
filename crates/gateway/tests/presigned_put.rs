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

//! Presigned `PutObject` admission through the assembled public service.
//!
//! Responsible for: proving a boto3-shaped SigV4 presigned PUT reaches the real `PutObject`
//! codec and handler, and that an exact payload digest binds the body whether the signature is
//! presigned or in the headers (c-sig-0596). NOT responsible for: signing primitives, whose own tests live in the
//! signature crate. Upstream: `rustfs-gateway` assembly and the standard operation registry.
//! Downstream: the response bytes visible to an SDK.

use crate::support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{ClockSkewAck, Handler, HandlerError, HandlerResult, Req, Resp, S3Service, dto};

struct Backend {
    put_entries: Arc<AtomicUsize>,
    put_commits: Arc<AtomicUsize>,
    delete_calls: Arc<AtomicUsize>,
}

impl Handler<dto::PutObject> for Backend {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        self.put_entries.fetch_add(1, Ordering::SeqCst);
        let put_commits = Arc::clone(&self.put_commits);
        let body = request.into_input().body;
        async move {
            let mut body = body
                .ok_or_else(|| HandlerError::internal_error("PutObject reached its handler without a body stream"))?
                .into_body();
            while let Some(frame) = body.frame().await {
                frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
            }
            put_commits.fetch_add(1, Ordering::SeqCst);
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

impl Handler<dto::DeleteObject> for Backend {
    fn call(
        &self,
        _request: Req<dto::DeleteObject>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObject>> + Send {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        async { Ok(Resp::new(dto::DeleteObjectOutput::default())) }
    }
}

struct Calls {
    put_entries: Arc<AtomicUsize>,
    put_commits: Arc<AtomicUsize>,
    delete: Arc<AtomicUsize>,
}

fn service_at(now: i64) -> (S3Service, Calls) {
    let put_entries = Arc::new(AtomicUsize::new(0));
    let put_commits = Arc::new(AtomicUsize::new(0));
    let delete_calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend {
        put_entries: Arc::clone(&put_entries),
        put_commits: Arc::clone(&put_commits),
        delete_calls: Arc::clone(&delete_calls),
    });
    let service = support::wired()
        .clock_with_skew_ack(
            rustfs_gateway::FixedClock::at_unix_seconds(now),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::DeleteObject, _>(backend)
        .build()
        .expect("a complete PutObject assembly");
    (
        service,
        Calls {
            put_entries,
            put_commits,
            delete: delete_calls,
        },
    )
}

fn presigned_request(
    method: http::Method,
    path: &str,
    body: Bytes,
    payload: PayloadMode,
    access_key: &str,
) -> http::Request<Bytes> {
    presigned_request_on_host(method, path, body, payload, access_key, "s3.example.com")
}

fn presigned_request_on_host(
    method: http::Method,
    path: &str,
    body: Bytes,
    payload: PayloadMode,
    access_key: &str,
    host_text: &str,
) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_str(host_text).expect("a host header"));
    if !matches!(payload, PayloadMode::Empty | PayloadMode::Unsigned) {
        headers.insert(
            http::HeaderName::from_static("x-amz-content-sha256"),
            http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("a payload declaration"),
        );
    }

    let host = rustfs_gateway_http::RawHost::from_host_header(host_text.as_bytes()).expect("an acceptable host");
    let credentials = SigningCredentials::new(access_key, b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let signing = SigningRequest::new(&method, path, "", &headers, &host, payload, stamp);
    let signed = signer.presign(&signing, 900).expect("a signable request");

    // boto3 signs the URL before its HTTP client knows the request-body framing. The sender adds
    // Content-Length on the wire, outside the canonical signed-header set.
    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("{path}?{}", signed.query()))
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(body).expect("a valid request")
}

fn boto3_presigned_put(body: Bytes) -> http::Request<Bytes> {
    presigned_request(http::Method::PUT, "/bucket/key", body, PayloadMode::Unsigned, "AKIDEXAMPLE")
}

fn exact_payload(bytes: &[u8]) -> PayloadMode {
    use sha2::{Digest as _, Sha256};

    PayloadMode::ExactSha256(Sha256::digest(bytes).into())
}

/// Positive — boto3 presigns PUT with only `host` signed and an unsigned payload. That standard
/// shape must reach `PutObject`, rather than being rejected by the operation floor before the
/// signature and payload rules can decide it.
#[tokio::test]
async fn a_boto3_shaped_presigned_put_reaches_the_standard_handler() {
    let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS);
    let response = support::exchange_wire(&service, boto3_presigned_put(Bytes::from_static(b"payload"))).await;
    let body = String::from_utf8(response.body().to_vec()).expect("an XML response body");

    assert_eq!(response.status(), http::StatusCode::OK, "{body}");
    assert_eq!(
        calls.put_entries.load(Ordering::SeqCst),
        1,
        "the standard PutObject handler was not called"
    );
    assert_eq!(
        calls.put_commits.load(Ordering::SeqCst),
        1,
        "the standard PutObject handler did not commit the body"
    );
    assert_eq!(calls.delete.load(Ordering::SeqCst), 0);
}

/// Negative — the PutObject admission does not bypass the absolute presigned expiry check.
#[tokio::test]
async fn an_expired_presigned_put_is_refused_before_the_handler() {
    let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS + 901);
    let response = support::exchange_wire(&service, boto3_presigned_put(Bytes::from_static(b"payload"))).await;

    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(calls.put_entries.load(Ordering::SeqCst), 0, "an expired request reached PutObject");
    assert_eq!(calls.put_commits.load(Ordering::SeqCst), 0);
}

/// Negative — every non-signature query parameter remains covered by the presigned signature.
#[tokio::test]
async fn a_tampered_presigned_put_is_refused_before_the_handler() {
    let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS);
    let mut request = boto3_presigned_put(Bytes::from_static(b"payload"));
    let tampered = format!("{}&tampered=true", request.uri());
    *request.uri_mut() = tampered.parse().expect("a valid URI");
    let response = support::exchange_wire(&service, request).await;

    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(calls.put_entries.load(Ordering::SeqCst), 0, "a bad signature reached PutObject");
    assert_eq!(calls.put_commits.load(Ordering::SeqCst), 0);
}

/// Negative — admitting the operation never turns an unknown credential into an identity.
#[tokio::test]
async fn an_unknown_presigned_put_credential_is_refused_before_the_handler() {
    let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS);
    let request = presigned_request(
        http::Method::PUT,
        "/bucket/key",
        Bytes::from_static(b"payload"),
        PayloadMode::Unsigned,
        "AKIDUNKNOWN",
    );
    let response = support::exchange_wire(&service, request).await;

    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(calls.put_entries.load(Ordering::SeqCst), 0, "an unknown credential reached PutObject");
    assert_eq!(calls.put_commits.load(Ordering::SeqCst), 0);
}

/// Negative — `host` stays signed for the boto3 shape after PutObject admission is widened.
#[tokio::test]
async fn a_presigned_put_with_a_changed_host_is_refused_before_the_handler() {
    let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS);
    let mut request = boto3_presigned_put(Bytes::from_static(b"payload"));
    request
        .headers_mut()
        .insert(http::header::HOST, http::HeaderValue::from_static("other.example.com"));
    let response = support::exchange_wire(&service, request).await;

    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(calls.put_entries.load(Ordering::SeqCst), 0, "a changed signed host reached PutObject");
    assert_eq!(calls.put_commits.load(Ordering::SeqCst), 0);
}

/// Positive — s3s#438: a non-default port survives the real presigned admission path.
#[tokio::test]
async fn a_presigned_non_default_port_reaches_put_object() {
    let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS);
    let request = presigned_request_on_host(
        http::Method::PUT,
        "/bucket/key",
        Bytes::from_static(b"payload"),
        PayloadMode::Unsigned,
        "AKIDEXAMPLE",
        "s3.example.com:9000",
    );
    let response = support::exchange_wire(&service, request).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(calls.put_entries.load(Ordering::SeqCst), 1);
    assert_eq!(calls.put_commits.load(Ordering::SeqCst), 1);
}

/// Negative — one presigned URL cannot become valid for another port or host spelling: the
/// canonical request signs the raw bytes, never the normalised host the resolver matches on.
#[tokio::test]
async fn a_presigned_url_holds_only_for_its_signed_host_spelling() {
    for changed_host in [
        "s3.example.com",
        "s3.example.com:9001",
        "S3.EXAMPLE.COM:9000",
        "s3.example.com.:9000",
    ] {
        let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS);
        let mut request = presigned_request_on_host(
            http::Method::PUT,
            "/bucket/key",
            Bytes::from_static(b"payload"),
            PayloadMode::Unsigned,
            "AKIDEXAMPLE",
            "s3.example.com:9000",
        );
        request
            .headers_mut()
            .insert(http::header::HOST, http::HeaderValue::from_str(changed_host).expect("a host header"));
        let response = support::exchange_wire(&service, request).await;
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(response.body()).contains("<Code>SignatureDoesNotMatch</Code>"));
        assert_eq!(calls.put_entries.load(Ordering::SeqCst), 0);
        assert_eq!(calls.put_commits.load(Ordering::SeqCst), 0);
    }
}

/// Negative — an exact body declaration still binds the bytes read after authentication.
#[tokio::test]
async fn a_presigned_put_with_a_tampered_exact_payload_is_refused_before_the_handler() {
    let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS);
    let request = presigned_request(
        http::Method::PUT,
        "/bucket/key",
        Bytes::from_static(b"tampered"),
        exact_payload(b"expected"),
        "AKIDEXAMPLE",
    );
    let response = support::exchange_wire(&service, request).await;

    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    assert_eq!(calls.put_entries.load(Ordering::SeqCst), 1, "the payload obligation was never exercised");
    assert_eq!(calls.put_commits.load(Ordering::SeqCst), 0, "a mismatched payload was committed");
}

/// Negative — PutObject is a single operation exception, not a mutating-operation wildcard.
#[tokio::test]
async fn a_presigned_delete_object_remains_refused_before_the_handler() {
    let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS);
    let request = presigned_request(http::Method::DELETE, "/bucket/key", Bytes::new(), PayloadMode::Unsigned, "AKIDEXAMPLE");
    let response = support::exchange_wire(&service, request).await;

    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(calls.delete.load(Ordering::SeqCst), 0, "presigned DeleteObject reached its handler");
}

/// `PUT /bucket/key` of `body`, signed in its headers under `payload`, which may name the digest of
/// other bytes.
fn header_signed_put(body: Bytes, payload: PayloadMode) -> http::Request<Bytes> {
    let headers = http::HeaderMap::from_iter([
        (http::header::HOST, http::HeaderValue::from_static("s3.example.com")),
        (http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len())),
    ]);
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let signing = SigningRequest::new(&http::Method::PUT, "/bucket/key", "", &headers, &host, payload, stamp)
        .with_wire_content_length(body.len() as u64);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut builder = http::Request::builder().method(http::Method::PUT).uri("/bucket/key");
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(body).expect("a valid request")
}

/// Positive — the control for c-sig-0596: a header-signed body that hashes to its signed digest is
/// committed once.
#[tokio::test]
async fn a_header_signed_put_matching_its_exact_payload_is_committed() {
    let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS);
    let request = header_signed_put(Bytes::from_static(b"expected"), exact_payload(b"expected"));
    let response = support::exchange_wire(&service, request).await;

    assert_eq!(response.status(), http::StatusCode::OK, "{:?}", response.body());
    assert_eq!(calls.put_commits.load(Ordering::SeqCst), 1);
}

/// Negative — c-sig-0596: the header-signed twin of the presigned case above. The signature is
/// valid; only the payload comparison catches the substituted body, which until
/// rustfs/backlog#1762 ran for presigned requests alone.
#[tokio::test]
async fn c_sig_0596_a_header_signed_put_with_a_tampered_exact_payload_is_never_committed() {
    let (service, calls) = service_at(support::SIGNED_AT_UNIX_SECONDS);
    let request = header_signed_put(Bytes::from_static(b"tampered"), exact_payload(b"expected"));
    let response = support::exchange_wire(&service, request).await;
    let body = String::from_utf8_lossy(response.body());

    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>XAmzContentSHA256Mismatch</Code>"), "{body}");
    assert_eq!(calls.put_entries.load(Ordering::SeqCst), 1, "the payload obligation was never exercised");
    assert_eq!(calls.put_commits.load(Ordering::SeqCst), 0, "a mismatched payload was committed");
}
