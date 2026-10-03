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

//! Buffered request bodies read under legacy RustFS's 20 MiB ceiling, through the whole service
//! (rustfs/gateway#1173).
//!
//! Responsible for: proving that `ServiceBuilder::bound_buffered_bodies_as_legacy_rustfs` reads a
//! 10,000-part completion carrying checksums, a tag set past 1 MiB and a batch delete past 2 MiB —
//! under either document reading — and refuses a body past 20 MiB `400 MaxMessageLengthExceeded`
//! before it is buffered, from its declared length or at the frame that crosses the ceiling; and
//! that 20 MiB exactly, an upload and the default assembly are answered as before.
//! NOT responsible for: the ceiling's value and scope (`src/builder/buffered_ceiling.rs`), the
//! document reader's own limits (`rustfs-gateway-xml`), or the launcher (`compat/sut`).
//! Upstream: `S3Service` with recording backends. Downstream: none.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp, S3Service, dto};

use crate::support::{self, CountingBody};

#[derive(Default)]
struct Seen {
    parts: AtomicUsize,
    deleted: AtomicUsize,
    tag_sets: AtomicUsize,
    uploaded: AtomicUsize,
}

struct Backend(Arc<Seen>);

impl Handler<dto::CompleteMultipartUpload> for Backend {
    async fn call(&self, request: Req<dto::CompleteMultipartUpload>) -> HandlerResult<dto::CompleteMultipartUpload> {
        self.0
            .parts
            .store(request.into_input().multipart_upload.parts.len(), Ordering::SeqCst);
        Ok(Resp::new(dto::CompleteMultipartUploadOutput::default()))
    }
}

impl Handler<dto::DeleteObjects> for Backend {
    async fn call(&self, request: Req<dto::DeleteObjects>) -> HandlerResult<dto::DeleteObjects> {
        // Read from the authorized resources, as a storing backend reads them: the framework clears
        // the input's key list once authorization has run.
        let keys = request
            .resources()
            .resolve(request.read_proof())
            .ok_or_else(|| HandlerError::internal_error("the delete authorization proof did not match"))?
            .count();
        self.0.deleted.store(keys, Ordering::SeqCst);
        Ok(Resp::new(dto::DeleteObjectsOutput::default()))
    }
}

impl Handler<dto::PutBucketTagging> for Backend {
    async fn call(&self, _request: Req<dto::PutBucketTagging>) -> HandlerResult<dto::PutBucketTagging> {
        self.0.tag_sets.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::PutBucketTaggingOutput::default()))
    }
}

impl Handler<dto::PutObject> for Backend {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        let mut body = request
            .into_input()
            .body
            .ok_or_else(|| HandlerError::internal_error("PutObject reached its handler without a body stream"))?
            .into_body();
        let mut length = 0;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
            length += frame.into_data().map_or(0, |data| data.len());
        }
        self.0.uploaded.store(length, Ordering::SeqCst);
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile {
    Default,
    Bounded,
    BoundedReadingAsRustfs,
}

fn assembled(profile: Profile) -> (S3Service, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let backend = Arc::new(Backend(Arc::clone(&seen)));
    let mut builder = support::wired_at_signed_time().accept_all_checksum_omissions();
    if profile != Profile::Default {
        builder = builder.bound_buffered_bodies_as_legacy_rustfs();
    }
    if profile == Profile::BoundedReadingAsRustfs {
        builder = builder.read_request_documents_as_rustfs();
    }
    let service = builder
        .register::<dto::CompleteMultipartUpload, _>(Arc::clone(&backend))
        .register::<dto::DeleteObjects, _>(Arc::clone(&backend))
        .register::<dto::PutBucketTagging, _>(Arc::clone(&backend))
        .register::<dto::PutObject, _>(backend)
        .build()
        .expect("a complete assembly");
    (service, seen)
}

/// A header-signed `UNSIGNED-PAYLOAD` request head, under `length` when given and a chunked
/// transfer otherwise.
fn signed(method: http::Method, target: &str, length: Option<u64>) -> http::request::Builder {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a scope");
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("credentials");
    let mut signing = SigningRequest::new(&method, path, query, &headers, &host, PayloadMode::Unsigned, stamp);
    if let Some(length) = length {
        signing = signing.with_wire_content_length(length);
    }
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    match length {
        Some(length) => request.header(http::header::CONTENT_LENGTH, length),
        None => request.header(http::header::TRANSFER_ENCODING, "chunked"),
    }
}

/// Sends `body` under its own length in 64 KiB frames, as a socket delivers it.
async fn send(service: &S3Service, method: http::Method, target: &str, body: Vec<u8>) -> (http::StatusCode, String) {
    let request = signed(method, target, Some(body.len() as u64));
    let frames: Vec<Result<http_body::Frame<Bytes>, std::convert::Infallible>> = body
        .chunks(64 * 1024)
        .map(|piece| Ok(http_body::Frame::data(Bytes::copy_from_slice(piece))))
        .collect();
    let body = http_body_util::StreamBody::new(futures_util::stream::iter(frames));
    answer(service, request.body(body).expect("a valid request")).await
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

const MIB: usize = 1024 * 1024;

/// A completion of 10,000 parts each carrying a CRC32C, as aws-sdk-go-v2 writes one (1.32 MiB).
fn completion() -> Vec<u8> {
    let mut body = String::from("<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    for part in 1..=10_000 {
        body.push_str(&format!(
            "<Part><ChecksumCRC32C>AAAAAA==</ChecksumCRC32C><ETag>&#34;{part:032x}&#34;</ETag><PartNumber>{part}</PartNumber></Part>"
        ));
    }
    body.push_str("</CompleteMultipartUpload>");
    body.into_bytes()
}

/// A tag set padded with white space to `length` bytes.
fn tag_set(length: usize) -> Vec<u8> {
    let head = "<Tagging><TagSet>";
    let tail = "<Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";
    format!("{head}{}{tail}", " ".repeat(length - head.len() - tail.len())).into_bytes()
}

/// A batch delete of a thousand keys of a thousand escaped ampersands each (about 5 MiB).
fn escaped_delete() -> Vec<u8> {
    let mut body = String::from("<Delete>");
    for key in 0..1000 {
        body.push_str(&format!("<Object><Key>k{key:04}{}</Key></Object>", "&amp;".repeat(1000)));
    }
    body.push_str("</Delete>");
    body.into_bytes()
}

fn code_of(body: &str) -> Option<&str> {
    support::element_text(body, "Code")
}

/// Positive — under the switch a 10,000-part completion carrying checksums reaches its handler
/// with every part, under either document reading.
#[tokio::test]
async fn a_ten_thousand_part_completion_is_read_under_the_switch() {
    for profile in [Profile::Bounded, Profile::BoundedReadingAsRustfs] {
        let (service, seen) = assembled(profile);
        let (status, body) = send(&service, http::Method::POST, "/bucket/object?uploadId=abc", completion()).await;
        assert_eq!(status, http::StatusCode::OK, "{body}");
        assert_eq!(seen.parts.load(Ordering::SeqCst), 10_000);
    }
}

/// Positive — so are a tag set of 1.5 MiB and a batch delete of 5 MiB.
#[tokio::test]
async fn a_tag_set_and_a_batch_delete_past_the_core_bounds_are_read_under_the_switch() {
    let (service, seen) = assembled(Profile::Bounded);
    let (status, body) = send(&service, http::Method::PUT, "/bucket?tagging", tag_set(MIB + MIB / 2)).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(seen.tag_sets.load(Ordering::SeqCst), 1);
    let (status, body) = send(&service, http::Method::POST, "/bucket?delete", escaped_delete()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(seen.deleted.load(Ordering::SeqCst), 1000);
}

/// Positive — a body declared one byte past 20 MiB is `400 MaxMessageLengthExceeded` before any
/// of it is read.
#[tokio::test]
async fn a_body_declared_past_twenty_mebibytes_is_refused_before_it_is_read() {
    let (service, seen) = assembled(Profile::Bounded);
    let (body, polled) = CountingBody::new(Bytes::from_static(b"<Tagging/>"));
    let request = signed(http::Method::PUT, "/bucket?tagging", Some((20 * MIB + 1) as u64))
        .body(body)
        .expect("a valid request");
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code_of(&body), Some("MaxMessageLengthExceeded"), "{body}");
    assert_eq!(polled.load(Ordering::SeqCst), 0, "the body was read before the refusal");
    assert_eq!(seen.tag_sets.load(Ordering::SeqCst), 0);
}

/// Positive — a body without a length is refused at the frame that crosses 20 MiB.
#[tokio::test]
async fn a_lengthless_body_is_refused_at_the_frame_crossing_twenty_mebibytes() {
    let (service, seen) = assembled(Profile::Bounded);
    let frames: Vec<Result<http_body::Frame<Bytes>, std::convert::Infallible>> = (0..21)
        .map(|_| Ok(http_body::Frame::data(Bytes::from(vec![b' '; MIB]))))
        .collect();
    let body = http_body_util::StreamBody::new(futures_util::stream::iter(frames));
    let request = signed(http::Method::PUT, "/bucket?tagging", None)
        .body(body)
        .expect("a valid request");
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code_of(&body), Some("MaxMessageLengthExceeded"), "{body}");
    assert_eq!(seen.tag_sets.load(Ordering::SeqCst), 0);
}

/// Negative — a tag set of exactly 20 MiB is read under the switch.
#[tokio::test]
async fn n_a_body_of_exactly_twenty_mebibytes_is_read_under_the_switch() {
    let (service, seen) = assembled(Profile::Bounded);
    let (status, body) = send(&service, http::Method::PUT, "/bucket?tagging", tag_set(20 * MIB)).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(seen.tag_sets.load(Ordering::SeqCst), 1);
}

/// Negative — the default assembly refuses the completion `MalformedXML` and the batch delete
/// past its 2 MiB cap, reaching no handler.
#[tokio::test]
async fn n_the_default_refuses_the_completion_and_the_batch_delete() {
    let (service, seen) = assembled(Profile::Default);
    let (status, body) = send(&service, http::Method::POST, "/bucket/object?uploadId=abc", completion()).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code_of(&body), Some("MalformedXML"), "{body}");
    let (status, body) = send(&service, http::Method::POST, "/bucket?delete", escaped_delete()).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code_of(&body), Some("InvalidRequest"), "{body}");
    assert_eq!(seen.parts.load(Ordering::SeqCst) + seen.deleted.load(Ordering::SeqCst), 0);
}

/// Negative — the default assembly answers a body declared past its own buffered ceiling `413`.
#[tokio::test]
async fn n_the_default_answers_its_own_ceiling_413() {
    let (service, _seen) = assembled(Profile::Default);
    let (body, _polled) = CountingBody::new(Bytes::from_static(b"<Tagging/>"));
    let request = signed(http::Method::PUT, "/bucket?tagging", Some((64 * MIB + 1) as u64))
        .body(body)
        .expect("a valid request");
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(code_of(&body), Some("EntityTooLarge"), "{body}");
}

/// Negative — under the switch an upload past 20 MiB is streamed and stored whole.
#[tokio::test]
async fn n_an_upload_is_not_bounded_by_it() {
    let (service, seen) = assembled(Profile::Bounded);
    let (status, body) = send(&service, http::Method::PUT, "/bucket/object", vec![7; 21 * MIB]).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(seen.uploaded.load(Ordering::SeqCst), 21 * MIB);
}
