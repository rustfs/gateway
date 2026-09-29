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

//! An assembly's ceiling on an upload's object, through the whole service (rustfs/gateway#1099,
//! rustfs/rustfs#7635).
//!
//! Responsible for: proving that `ServiceConfig::with_upload_object_ceiling` refuses a `PutObject`
//! or `UploadPart` whose object — the decoded length of an aws-chunked body, the `Content-Length`
//! of any other — is larger than the ceiling with `400 EntityTooLarge` before a body byte is read
//! and before the handler is reached, and hands one at the ceiling to the handler byte for byte;
//! that `max_framed_upload_bytes` lets an aws-chunked upload whose object fits through the wire
//! although its framing does not; and that an assembly without the ceiling hands the handler what
//! it handed it before.
//! NOT responsible for: which operations the ceiling reaches (`src/gate_ceilings.rs`'s unit tests)
//! or the RustFS launcher that sets 5 GiB (`compat/sut`).
//! Upstream: `S3Service` with recording `PutObject` and `UploadPart` backends. Downstream: none.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
};
use rustfs_gateway::{
    ByteStream, Handler, HandlerError, HandlerResult, Limits, Req, Resp, S3Service, ServiceConfig, dto, max_framed_upload_bytes,
};

use crate::support::{self, CountingBody};

/// The ceiling every case here sets: small enough to send whole, several chunks long.
const CEILING: u64 = 1024;

/// The chunk size the streaming cases frame their objects in.
const CHUNK: usize = 64;

const PUT: &str = "/bucket/object";
const PART: &str = "/bucket/object?partNumber=1&uploadId=upload";

#[derive(Default)]
struct Recorded {
    bodies: Mutex<Vec<(&'static str, i64, Vec<u8>)>>,
}

struct Backend(Arc<Recorded>);

async fn drain(
    recorded: &Recorded,
    operation: &'static str,
    content_length: i64,
    body: Option<ByteStream>,
) -> Result<(), HandlerError> {
    let mut body = body
        .ok_or_else(|| HandlerError::internal_error("the upload reached its handler without a body stream"))?
        .into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
        if let Ok(data) = frame.into_data() {
            bytes.extend_from_slice(&data);
        }
    }
    recorded
        .bodies
        .lock()
        .expect("the record is never poisoned")
        .push((operation, content_length, bytes));
    Ok(())
}

impl Handler<dto::PutObject> for Backend {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let recorded = Arc::clone(&self.0);
        let input = request.into_input();
        async move {
            drain(&recorded, "PutObject", input.content_length, input.body).await?;
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

impl Handler<dto::UploadPart> for Backend {
    fn call(&self, request: Req<dto::UploadPart>) -> impl core::future::Future<Output = HandlerResult<dto::UploadPart>> + Send {
        let recorded = Arc::clone(&self.0);
        let input = request.into_input();
        async move {
            drain(&recorded, "UploadPart", input.content_length, input.body).await?;
            Ok(Resp::new(dto::UploadPartOutput::default()))
        }
    }
}

/// How an assembly bounds an upload.
#[derive(Clone, Copy, Debug)]
enum Bounds {
    /// [`CEILING`] on the object, and the wire ceiling widened with `max_framed_upload_bytes`.
    ObjectCeiling,
    /// [`CEILING`] on the object, and the wire ceiling left at [`CEILING`] too.
    ObjectAndWireCeiling,
    /// No object ceiling; the same widened wire ceiling as [`Bounds::ObjectCeiling`].
    WireOnly,
}

fn assembled(bounds: Bounds) -> (S3Service, Arc<Recorded>) {
    let recorded = Arc::new(Recorded::default());
    let backend = Arc::new(Backend(Arc::clone(&recorded)));
    let wire = match bounds {
        Bounds::ObjectCeiling | Bounds::WireOnly => max_framed_upload_bytes(CEILING),
        Bounds::ObjectAndWireCeiling => CEILING,
    };
    let config = match bounds {
        Bounds::ObjectCeiling | Bounds::ObjectAndWireCeiling => {
            ServiceConfig::new(1024 * 1024).with_upload_object_ceiling(CEILING)
        }
        Bounds::WireOnly => ServiceConfig::new(1024 * 1024),
    };
    let (builder, _settings) = support::wired_at_signed_time()
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::UploadPart, _>(backend)
        .limits(Limits {
            max_body_bytes: wire,
            ..Limits::default()
        })
        .config(config);
    (builder.build().expect("a complete upload assembly"), recorded)
}

fn operation_of(target: &str) -> &'static str {
    if target.contains('?') { "UploadPart" } else { "PutObject" }
}

fn object(length: u64) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

/// The wire length of `object` in signed aws-chunked framing of [`CHUNK`]-byte chunks.
fn signed_wire_length(object: &[u8]) -> usize {
    let frame = |size: usize| format!("{size:x}").len() + 17 + 64 + 4 + size;
    object.chunks(CHUNK).map(|chunk| frame(chunk.len())).sum::<usize>() + frame(0)
}

/// How HTTP frames the aws-chunked body.
#[derive(Clone, Copy, Debug)]
enum Wire {
    /// `Content-Length` counting every framing byte.
    ContentLength,
    /// `Transfer-Encoding: chunked` with no `Content-Length`.
    TransferChunked,
}

/// A correctly signed `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` upload of `object` to `target`,
/// declaring its length, framed on the wire as `wire` says.
fn streaming(target: &str, object: &[u8], wire: Wire) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let wire_length = signed_wire_length(object);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    if matches!(wire, Wire::ContentLength) {
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(wire_length));
    }
    let mut signing = SigningRequest::new(
        &http::Method::PUT,
        path,
        query,
        &headers,
        &host,
        PayloadMode::StreamingSigned {
            trailer: TrailerSet::None,
        },
        stamp,
    )
    .with_decoded_content_length(object.len() as u64);
    if matches!(wire, Wire::ContentLength) {
        signing = signing.with_wire_content_length(wire_length as u64);
    }
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let mut body = Vec::with_capacity(wire_length);
    for chunk in object.chunks(CHUNK) {
        body.extend_from_slice(&chain.encode_chunk(chunk));
    }
    body.extend_from_slice(&chain.encode_chunk(b""));
    assert_eq!(body.len(), wire_length, "the framing arithmetic above is the one the signer used");
    let mut request = http::Request::builder().method(http::Method::PUT).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    if matches!(wire, Wire::TransferChunked) {
        request = request.header(http::header::TRANSFER_ENCODING, "chunked");
    }
    request.body(Bytes::from(body)).expect("a valid request")
}

/// A correctly header-signed upload of `object` to `target` that declares, and signs, its
/// `Content-Length` and its digest.
fn plain(target: &str, object: &[u8]) -> http::Request<Bytes> {
    use sha2::{Digest as _, Sha256};

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(object.len()));
    let payload = PayloadMode::ExactSha256(Sha256::digest(object).into());
    let signing = SigningRequest::new(&http::Method::PUT, path, query, &headers, &host, payload, stamp)
        .with_wire_content_length(object.len() as u64);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(http::Method::PUT).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(Bytes::copy_from_slice(object)).expect("a valid request")
}

/// Sends `request` with a body that counts the bytes anything polled from it.
async fn counted(service: &S3Service, request: http::Request<Bytes>) -> (http::StatusCode, String, u64) {
    let (parts, bytes) = request.into_parts();
    let (body, read) = CountingBody::new(bytes);
    let response = service.call(http::Request::from_parts(parts, body)).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    let text = String::from_utf8(collected.body().to_vec()).expect("utf-8");
    (collected.status(), text, read.load(Ordering::SeqCst))
}

fn assert_too_large(status: http::StatusCode, body: &str, read: u64, context: &str) {
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{context}: {body}");
    assert!(body.contains("<Code>EntityTooLarge</Code>"), "{context}: {body}");
    assert_eq!(read, 0, "{context}: the body was read before the refusal");
}

/// Positive — a plain upload of exactly the ceiling reaches its handler with its length and its
/// bytes, for `PutObject` and `UploadPart` alike.
#[tokio::test]
async fn a_plain_upload_at_the_ceiling_is_handed_over_whole() {
    for target in [PUT, PART] {
        let (service, recorded) = assembled(Bounds::ObjectCeiling);
        let object = object(CEILING);
        let request = plain(target, &object);
        let (status, body) = support::exchange(&service, request).await;
        assert_eq!(status, http::StatusCode::OK, "{target}: {body}");
        let bodies = recorded.bodies.lock().expect("the record is never poisoned");
        assert_eq!(*bodies, [(operation_of(target), CEILING as i64, object)], "{target}");
    }
}

/// Negative — one byte past the ceiling is `400 EntityTooLarge` before a body byte is read, and
/// no handler is reached.
#[tokio::test]
async fn n_a_plain_upload_one_byte_past_the_ceiling_is_refused_unread() {
    for target in [PUT, PART] {
        let (service, recorded) = assembled(Bounds::ObjectCeiling);
        let request = plain(target, &object(CEILING + 1));
        let (status, body, read) = counted(&service, request).await;
        assert_too_large(status, &body, read, target);
        assert!(recorded.bodies.lock().expect("the record is never poisoned").is_empty(), "{target}");
    }
}

/// Positive — an aws-chunked upload is measured by its decoded length: an object of exactly the
/// ceiling, whose framing takes it past the ceiling on the wire, reaches its handler with the
/// decoded length and its bytes, whether HTTP frames it with `Content-Length` or with
/// `Transfer-Encoding: chunked`.
#[tokio::test]
async fn a_streaming_upload_at_the_ceiling_is_handed_over_whole_although_its_framing_is_longer() {
    for wire in [Wire::ContentLength, Wire::TransferChunked] {
        for target in [PUT, PART] {
            let (service, recorded) = assembled(Bounds::ObjectCeiling);
            let object = object(CEILING);
            assert!(signed_wire_length(&object) as u64 > CEILING, "the framing takes it past the ceiling");
            let (status, body) = support::exchange(&service, streaming(target, &object, wire)).await;
            assert_eq!(status, http::StatusCode::OK, "{wire:?} {target}: {body}");
            let bodies = recorded.bodies.lock().expect("the record is never poisoned");
            assert_eq!(*bodies, [(operation_of(target), CEILING as i64, object)], "{wire:?} {target}");
        }
    }
}

/// Negative — an aws-chunked upload whose decoded length is one byte past the ceiling is `400
/// EntityTooLarge` before a body byte is read, however HTTP frames it.
#[tokio::test]
async fn n_a_streaming_upload_decoded_one_byte_past_the_ceiling_is_refused_unread() {
    for wire in [Wire::ContentLength, Wire::TransferChunked] {
        for target in [PUT, PART] {
            let (service, recorded) = assembled(Bounds::ObjectCeiling);
            let (status, body, read) = counted(&service, streaming(target, &object(CEILING + 1), wire)).await;
            assert_too_large(status, &body, read, &format!("{wire:?} {target}"));
            assert!(recorded.bodies.lock().expect("the record is never poisoned").is_empty());
        }
    }
}

/// Negative — without `max_framed_upload_bytes`, a wire ceiling equal to the object ceiling
/// refuses the framing of an aws-chunked upload whose object fits: the refusal this helper exists
/// to prevent.
#[tokio::test]
async fn n_a_wire_ceiling_at_the_object_ceiling_refuses_a_fitting_streaming_upload() {
    let (service, recorded) = assembled(Bounds::ObjectAndWireCeiling);
    let (status, body, read) = counted(&service, streaming(PUT, &object(CEILING), Wire::ContentLength)).await;
    assert_too_large(status, &body, read, "the framed length is past the wire ceiling");
    assert!(recorded.bodies.lock().expect("the record is never poisoned").is_empty());
}

/// Negative — an assembly without the object ceiling hands an upload past it to the handler, plain
/// or aws-chunked, as it did before the ceiling existed.
#[tokio::test]
async fn n_without_the_ceiling_an_upload_past_it_is_handed_over() {
    for target in [PUT, PART] {
        let (service, recorded) = assembled(Bounds::WireOnly);
        let object = object(CEILING + 1);
        let request = plain(target, &object);
        let (status, body) = support::exchange(&service, request).await;
        assert_eq!(status, http::StatusCode::OK, "{target}: {body}");
        let (status, body) = support::exchange(&service, streaming(target, &object, Wire::ContentLength)).await;
        assert_eq!(status, http::StatusCode::OK, "{target}: {body}");
        let bodies = recorded.bodies.lock().expect("the record is never poisoned");
        let expected = (operation_of(target), (CEILING + 1) as i64, object);
        assert_eq!(*bodies, [expected.clone(), expected], "{target}");
    }
}
