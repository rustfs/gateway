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

//! The body of an operation that takes none, through the whole service (rustfs/gateway#1173).
//!
//! Responsible for: proving that `ServiceBuilder::leave_bodies_of_bodyless_operations_unread`
//! answers such an operation without polling a byte of the body it carries — past the buffered
//! ceiling, with a malformed or contradicting `Content-MD5`, with a trailer declaration — while the
//! request head is still judged and every operation that takes a body still reads and verifies
//! it; and that the default assembly reads and judges such a body as before.
//! NOT responsible for: which body modes the switch reaches (`src/builder/bodyless_bodies.rs`'s
//! unit tests), the launcher that turns it on (`compat/sut`), or a host draining the body behind
//! the answer.
//! Upstream: `S3Service` with recording backends. Downstream: none.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
};
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp, S3Service, dto};
use rustfs_gateway_sig::{DeclaredTrailers, TrailerName};

use crate::support::{self, CountingBody};
use crate::tagging_reachability::content_md5;

#[derive(Default)]
struct Recorded {
    reads: AtomicUsize,
    creations: AtomicUsize,
    uploads: Mutex<Vec<Vec<u8>>>,
    tag_sets: AtomicUsize,
}

struct Backend(Arc<Recorded>);

impl Handler<dto::GetObject> for Backend {
    fn call(&self, _request: Req<dto::GetObject>) -> impl core::future::Future<Output = HandlerResult<dto::GetObject>> + Send {
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        async { Ok(Resp::new(dto::GetObjectOutput::default())) }
    }
}

impl Handler<dto::CreateMultipartUpload> for Backend {
    fn call(
        &self,
        _request: Req<dto::CreateMultipartUpload>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CreateMultipartUpload>> + Send {
        self.0.creations.fetch_add(1, Ordering::SeqCst);
        async { Ok(Resp::new(dto::CreateMultipartUploadOutput::default())) }
    }
}

impl Handler<dto::PutObjectTagging> for Backend {
    fn call(
        &self,
        _request: Req<dto::PutObjectTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectTagging>> + Send {
        self.0.tag_sets.fetch_add(1, Ordering::SeqCst);
        async { Ok(Resp::new(dto::PutObjectTaggingOutput::default())) }
    }
}

impl Handler<dto::PutObject> for Backend {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let recorded = Arc::clone(&self.0);
        let body = request.into_input().body;
        async move {
            let mut body = body
                .ok_or_else(|| HandlerError::internal_error("PutObject reached its handler without a body stream"))?
                .into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
                if let Ok(data) = frame.into_data() {
                    bytes.extend_from_slice(&data);
                }
            }
            recorded.uploads.lock().expect("the record is never poisoned").push(bytes);
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

/// The fixture assembly, with or without the switch, holding at most `ceiling` buffered bytes.
fn assembled(unread: bool, ceiling: u64) -> (S3Service, Arc<Recorded>) {
    let recorded = Arc::new(Recorded::default());
    let backend = Arc::new(Backend(Arc::clone(&recorded)));
    let mut builder = support::wired_at_signed_time().max_buffered_body_bytes(ceiling);
    if unread {
        builder = builder.leave_bodies_of_bodyless_operations_unread();
    }
    let service = builder
        .register::<dto::GetObject, _>(Arc::clone(&backend))
        .register::<dto::CreateMultipartUpload, _>(Arc::clone(&backend))
        .register::<dto::PutObjectTagging, _>(Arc::clone(&backend))
        .register::<dto::PutObject, _>(backend)
        .build()
        .expect("a complete assembly");
    (service, recorded)
}

const CEILING: u64 = 64 * 1024 * 1024;

/// A header-signed request head: `extra` headers are signed with the rest, `payload` is declared
/// and signed, and `length` is sent as `Content-Length` when given.
fn head(
    method: http::Method,
    target: &str,
    extra: &[(&str, &str)],
    payload: PayloadMode,
    length: Option<u64>,
) -> http::request::Builder {
    streaming_head(method, target, extra, payload, length, None)
}

/// [`head`], declaring `decoded` as the aws-chunked body's decoded length when given.
fn streaming_head(
    method: http::Method,
    target: &str,
    extra: &[(&str, &str)],
    payload: PayloadMode,
    length: Option<u64>,
    decoded: Option<u64>,
) -> http::request::Builder {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(
        http::HeaderName::from_static("x-amz-content-sha256"),
        http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("a payload declaration"),
    );
    for (name, value) in extra {
        let name: http::HeaderName = name.parse().expect("a header name");
        headers.insert(name, http::HeaderValue::from_str(value).expect("a header value"));
    }
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let mut signing = SigningRequest::new(&method, path, query, &headers, &host, payload, stamp);
    if let Some(length) = length {
        signing = signing.with_wire_content_length(length);
    }
    if let Some(decoded) = decoded {
        signing = signing.with_decoded_content_length(decoded);
    }
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    if let Some(length) = length {
        request = request.header(http::header::CONTENT_LENGTH, length);
    }
    request
}

/// `bytes` as a body that counts how many of its bytes were polled.
fn counted(request: http::request::Builder, bytes: &'static [u8]) -> (http::Request<CountingBody>, Arc<AtomicU64>) {
    let (body, polled) = CountingBody::new(Bytes::from_static(bytes));
    (request.body(body).expect("a valid request"), polled)
}

async fn answer<B>(service: &S3Service, request: http::Request<B>) -> (http::StatusCode, String)
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let response = service.call(request).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    (collected.status(), String::from_utf8_lossy(collected.body()).into_owned())
}

const BODY: &[u8] = &[b'x'; 4096];

/// Positive — under the switch a `GetObject` carrying a body is answered, and not one byte of the
/// body is polled.
#[tokio::test]
async fn a_bodyless_operations_body_is_never_polled_under_the_switch() {
    let (service, recorded) = assembled(true, CEILING);
    let (request, polled) = counted(
        head(http::Method::GET, "/bucket/object", &[], PayloadMode::Unsigned, Some(BODY.len() as u64)),
        BODY,
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 1);
    assert_eq!(polled.load(Ordering::SeqCst), 0, "the body of an operation that takes none was read");
}

/// Negative — the default assembly reads the same body to its end before it answers.
#[tokio::test]
async fn n_the_default_reads_a_bodyless_operations_body_to_its_end() {
    let (service, recorded) = assembled(false, CEILING);
    let (request, polled) = counted(
        head(http::Method::GET, "/bucket/object", &[], PayloadMode::Unsigned, Some(BODY.len() as u64)),
        BODY,
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 1);
    assert_eq!(polled.load(Ordering::SeqCst), BODY.len() as u64);
}

/// Positive — under the switch a body declared past the buffered ceiling is answered as legacy
/// RustFS answers it, with the operation's own answer, and nothing is polled.
#[tokio::test]
async fn a_body_past_the_buffered_ceiling_is_answered_under_the_switch() {
    let (service, recorded) = assembled(true, 16);
    let (request, polled) = counted(
        head(http::Method::GET, "/bucket/object", &[], PayloadMode::Unsigned, Some(BODY.len() as u64)),
        BODY,
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 1);
    assert_eq!(polled.load(Ordering::SeqCst), 0);
}

/// Negative — the default assembly refuses it `413` on the declared length, reaching no handler.
#[tokio::test]
async fn n_the_default_refuses_a_bodyless_body_past_the_buffered_ceiling() {
    let (service, recorded) = assembled(false, 16);
    let (request, polled) = counted(
        head(http::Method::GET, "/bucket/object", &[], PayloadMode::Unsigned, Some(BODY.len() as u64)),
        BODY,
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert!(body.contains("<Code>EntityTooLarge</Code>"), "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 0);
    assert_eq!(polled.load(Ordering::SeqCst), 0);
}

/// Positive — under the switch a `CreateMultipartUpload` whose body contradicts its `Content-MD5`
/// is served without the body being polled.
#[tokio::test]
async fn a_contradicting_content_md5_on_a_bodyless_write_is_not_judged_under_the_switch() {
    let (service, recorded) = assembled(true, CEILING);
    let md5 = content_md5(b"another payload");
    let (request, polled) = counted(
        head(
            http::Method::POST,
            "/bucket/object?uploads",
            &[("content-md5", &md5)],
            PayloadMode::Unsigned,
            Some(5),
        ),
        b"hello",
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorded.creations.load(Ordering::SeqCst), 1);
    assert_eq!(polled.load(Ordering::SeqCst), 0);
}

/// Negative — the default assembly compares that `Content-MD5` with the body and refuses the
/// write before its handler.
#[tokio::test]
async fn n_the_default_refuses_a_contradicting_content_md5_on_a_bodyless_write() {
    let (service, recorded) = assembled(false, CEILING);
    let md5 = content_md5(b"another payload");
    let (request, _polled) = counted(
        head(
            http::Method::POST,
            "/bucket/object?uploads",
            &[("content-md5", &md5)],
            PayloadMode::Unsigned,
            Some(5),
        ),
        b"hello",
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>BadDigest</Code>"), "{body}");
    assert_eq!(recorded.creations.load(Ordering::SeqCst), 0);
}

/// Positive — under the switch a read whose `Content-MD5` is not base64 at all is served.
#[tokio::test]
async fn a_malformed_content_md5_on_a_read_is_not_judged_under_the_switch() {
    let (service, recorded) = assembled(true, CEILING);
    let request = head(
        http::Method::GET,
        "/bucket/object",
        &[("content-md5", "not base64!")],
        PayloadMode::Empty,
        None,
    )
    .body(Bytes::new())
    .expect("a valid request");
    let (status, body) = answer(&service, request.map(http_body_util::Full::new)).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 1);
}

/// Negative — the default assembly refuses that read `400 InvalidDigest`.
#[tokio::test]
async fn n_the_default_refuses_a_malformed_content_md5_on_a_read() {
    let (service, recorded) = assembled(false, CEILING);
    let request = head(
        http::Method::GET,
        "/bucket/object",
        &[("content-md5", "not base64!")],
        PayloadMode::Empty,
        None,
    )
    .body(Bytes::new())
    .expect("a valid request");
    let (status, body) = answer(&service, request.map(http_body_util::Full::new)).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>InvalidDigest</Code>"), "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 0);
}

/// The head of a read declaring an unsigned aws-chunked body with a checksum trailer.
fn trailer_declaring_read() -> http::request::Builder {
    let trailer = TrailerSet::Declared(
        DeclaredTrailers::new([TrailerName::new("x-amz-checksum-crc32").expect("a trailer name")], false)
            .expect("a trailer declaration"),
    );
    let payload = PayloadMode::parse("STREAMING-UNSIGNED-PAYLOAD-TRAILER", trailer).expect("an unsigned trailer mode");
    streaming_head(
        http::Method::GET,
        "/bucket/object",
        &[("content-encoding", "aws-chunked"), ("x-amz-trailer", "x-amz-checksum-crc32")],
        payload,
        Some(7),
        Some(0),
    )
}

/// Positive — under the switch a read declaring an aws-chunked body with a trailer, whose body is
/// not aws-chunked at all, is served without the body being polled.
#[tokio::test]
async fn a_trailer_declaring_read_is_served_unread_under_the_switch() {
    let (service, recorded) = assembled(true, CEILING);
    let (request, polled) = counted(trailer_declaring_read(), b"garbage");
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 1);
    assert_eq!(polled.load(Ordering::SeqCst), 0);
}

/// Negative — the default assembly refuses that read before its handler.
#[tokio::test]
async fn n_the_default_refuses_a_trailer_declaring_read() {
    let (service, recorded) = assembled(false, CEILING);
    let (request, _polled) = counted(trailer_declaring_read(), b"garbage");
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 0);
}

/// Negative — under the switch the head is still judged: a read declaring signed aws-chunked
/// framing whose decoded length its `Content-Length` cannot hold is refused as before
/// (rd-body-0010), and its body is not polled.
#[tokio::test]
async fn n_the_head_of_a_bodyless_operation_is_still_judged_under_the_switch() {
    for unread in [false, true] {
        let (service, recorded) = assembled(unread, CEILING);
        let payload =
            PayloadMode::parse("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", TrailerSet::None).expect("a signed streaming mode");
        let (request, polled) = counted(
            streaming_head(
                http::Method::GET,
                "/bucket/object",
                &[("content-encoding", "aws-chunked")],
                payload,
                Some(7),
                Some(1000),
            ),
            b"garbage",
        );
        let (status, body) = answer(&service, request).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{unread}: {body}");
        assert_eq!(recorded.reads.load(Ordering::SeqCst), 0, "{unread}");
        assert_eq!(polled.load(Ordering::SeqCst), 0, "{unread}");
    }
}

/// Negative — under the switch an upload is still read, and one contradicting its `Content-MD5`
/// is refused with no bytes handed over as a complete upload.
#[tokio::test]
async fn n_an_upload_is_still_read_and_verified_under_the_switch() {
    let (service, recorded) = assembled(true, CEILING);
    let md5 = content_md5(b"another payload");
    let (request, polled) = counted(
        head(
            http::Method::PUT,
            "/bucket/object",
            &[("content-md5", &md5)],
            PayloadMode::Unsigned,
            Some(5),
        ),
        b"hello",
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>BadDigest</Code>"), "{body}");
    assert_eq!(polled.load(Ordering::SeqCst), 5, "the upload was not read");
    assert!(recorded.uploads.lock().expect("the record is never poisoned").is_empty());
}

/// Negative — under the switch a buffered write is still read, and one contradicting its
/// `Content-MD5` is refused before its handler.
#[tokio::test]
async fn n_a_buffered_write_is_still_read_and_verified_under_the_switch() {
    const TAGGING: &[u8] = b"<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>";
    let (service, recorded) = assembled(true, CEILING);
    let md5 = content_md5(b"another payload");
    let (request, polled) = counted(
        head(
            http::Method::PUT,
            "/bucket/object?tagging",
            &[("content-md5", &md5)],
            PayloadMode::Unsigned,
            Some(TAGGING.len() as u64),
        ),
        TAGGING,
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>BadDigest</Code>"), "{body}");
    assert_eq!(polled.load(Ordering::SeqCst), TAGGING.len() as u64, "the buffered body was not read");
    assert_eq!(recorded.tag_sets.load(Ordering::SeqCst), 0);
}

/// Negative — under the switch a request whose signature does not verify is still refused `403`,
/// its body unread.
#[tokio::test]
async fn n_a_bad_signature_is_still_refused_under_the_switch() {
    let (service, recorded) = assembled(true, CEILING);
    let (request, polled) = counted(
        head(http::Method::GET, "/bucket/object", &[], PayloadMode::Unsigned, Some(BODY.len() as u64))
            .uri("/bucket/another-object"),
        BODY,
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 0);
    assert_eq!(polled.load(Ordering::SeqCst), 0);
}
