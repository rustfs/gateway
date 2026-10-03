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

//! A buffered request body legacy RustFS cannot size, through the whole service
//! (rustfs/gateway#1173).
//!
//! Responsible for: proving that `ServiceBuilder::refuse_unsized_buffered_bodies_as_legacy_rustfs`
//! refuses a signed buffered write carried by a chunked transfer before its body is read, and a
//! buffered write decoded from aws-chunked framing once it is read, with legacy RustFS's codes and
//! sentences and no handler reached; and that a sized buffered write, an empty decoded one, an
//! upload, a bad signature and the default assembly are answered as before.
//! NOT responsible for: the rules' own truth table (`src/builder/buffered_lengths.rs`'s unit
//! tests) or the launcher that turns the switch on (`compat/sut`).
//! Upstream: `S3Service` with recording backends. Downstream: none.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http_body_util::BodyExt as _;
use rustfs_gateway::sig::{PayloadMode, TrailerSet};
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp, S3Service, dto};
use rustfs_gateway_sig::{DeclaredTrailers, TrailerName};

use crate::bodyless_bodies::{answer, counted, head, streaming_head};
use crate::support;
use crate::tagging_reachability::content_md5;

#[derive(Default)]
struct Recorded {
    tag_sets: AtomicUsize,
    uploads: std::sync::Mutex<Vec<Vec<u8>>>,
}

struct Backend(Arc<Recorded>);

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

fn assembled(legacy: bool) -> (S3Service, Arc<Recorded>) {
    let recorded = Arc::new(Recorded::default());
    let backend = Arc::new(Backend(Arc::clone(&recorded)));
    let mut builder = support::wired_at_signed_time();
    if legacy {
        builder = builder.refuse_unsized_buffered_bodies_as_legacy_rustfs();
    }
    let service = builder
        .register::<dto::PutObjectTagging, _>(Arc::clone(&backend))
        .register::<dto::PutObject, _>(backend)
        .build()
        .expect("a complete assembly");
    (service, recorded)
}

const TAGGING: &[u8] = b"<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>";
/// [`TAGGING`] as one unsigned aws-chunked chunk with its checksum trailer (`5y4GWw==` is its
/// `x-amz-checksum-crc32`).
const FRAMED_TAGGING: &[u8] =
    b"4b\r\n<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>\r\n0\r\nx-amz-checksum-crc32:5y4GWw==\r\n\r\n";
/// An empty body as unsigned aws-chunked framing with its checksum trailer.
const FRAMED_EMPTY: &[u8] = b"0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n";

/// A header-signed `UNSIGNED-PAYLOAD` tag-set write carried by a chunked transfer, with the
/// `Content-MD5` of [`TAGGING`] the operation's integrity requirement asks for.
fn chunked_transfer(target: &str) -> http::request::Builder {
    let md5 = content_md5(TAGGING);
    head(http::Method::PUT, target, &[("content-md5", &md5)], PayloadMode::Unsigned, None)
        .header(http::header::TRANSFER_ENCODING, "chunked")
}

/// A header-signed unsigned aws-chunked write of `decoded` bytes, under `length` when given.
fn framed(target: &str, decoded: u64, length: Option<u64>) -> http::request::Builder {
    let trailer = TrailerSet::Declared(
        DeclaredTrailers::new([TrailerName::new("x-amz-checksum-crc32").expect("a trailer name")], false)
            .expect("a trailer declaration"),
    );
    let payload = PayloadMode::parse("STREAMING-UNSIGNED-PAYLOAD-TRAILER", trailer).expect("an unsigned trailer mode");
    let request = streaming_head(
        http::Method::PUT,
        target,
        &[("content-encoding", "aws-chunked"), ("x-amz-trailer", "x-amz-checksum-crc32")],
        payload,
        length,
        Some(decoded),
    );
    match length {
        Some(_) => request,
        None => request.header(http::header::TRANSFER_ENCODING, "chunked"),
    }
}

fn code_of(body: &str) -> Option<&str> {
    support::element_text(body, "Code")
}

/// Positive — under the switch a signed tag-set write carried by a chunked transfer is `411`
/// before a byte of it is read, with legacy RustFS's sentence, and reaches no handler.
#[tokio::test]
async fn an_unsized_signed_buffered_body_is_length_required_before_it_is_read() {
    let (service, recorded) = assembled(true);
    let (request, polled) = counted(chunked_transfer("/bucket/object?tagging"), TAGGING);
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::LENGTH_REQUIRED, "{body}");
    assert_eq!(code_of(&body), Some("MissingContentLength"), "{body}");
    assert_eq!(support::element_text(&body, "Message"), Some("missing header: content-length"), "{body}");
    assert_eq!(polled.load(Ordering::SeqCst), 0, "the body was read before the refusal");
    assert_eq!(recorded.tag_sets.load(Ordering::SeqCst), 0);
}

/// Positive — an empty chunked transfer is refused the same way: the demand is the signature's,
/// whatever the body holds.
#[tokio::test]
async fn an_empty_unsized_signed_buffered_body_is_length_required() {
    let (service, recorded) = assembled(true);
    let (request, _polled) = counted(chunked_transfer("/bucket/object?tagging"), b"");
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::LENGTH_REQUIRED, "{body}");
    assert_eq!(recorded.tag_sets.load(Ordering::SeqCst), 0);
}

/// Positive — under the switch a tag-set write decoded from aws-chunked framing under a
/// `Content-Length` is `400 IncompleteBody` once read, and reaches no handler.
#[tokio::test]
async fn a_decoded_buffered_body_under_a_length_is_incomplete() {
    let (service, recorded) = assembled(true);
    let (request, polled) = counted(
        framed("/bucket/object?tagging", TAGGING.len() as u64, Some(FRAMED_TAGGING.len() as u64)),
        FRAMED_TAGGING,
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code_of(&body), Some("IncompleteBody"), "{body}");
    assert_eq!(polled.load(Ordering::SeqCst), FRAMED_TAGGING.len() as u64, "legacy RustFS reads it first");
    assert_eq!(recorded.tag_sets.load(Ordering::SeqCst), 0);
}

/// Positive — the same write under a chunked transfer is `411` with legacy RustFS's sentence for
/// a body that arrived without a length.
#[tokio::test]
async fn a_decoded_buffered_body_without_a_length_is_length_required() {
    let (service, recorded) = assembled(true);
    let (request, _polled) = counted(framed("/bucket/object?tagging", TAGGING.len() as u64, None), FRAMED_TAGGING);
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::LENGTH_REQUIRED, "{body}");
    assert_eq!(code_of(&body), Some("MissingContentLength"), "{body}");
    assert_eq!(
        support::element_text(&body, "Message"),
        Some("You must provide the Content-Length HTTP header."),
        "{body}"
    );
    assert_eq!(recorded.tag_sets.load(Ordering::SeqCst), 0);
}

/// Negative — the default assembly reads and applies both writes.
#[tokio::test]
async fn n_the_default_applies_an_unsized_and_a_decoded_buffered_body() {
    let (service, recorded) = assembled(false);
    let (request, _polled) = counted(chunked_transfer("/bucket/object?tagging"), TAGGING);
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let (request, _polled) = counted(
        framed("/bucket/object?tagging", TAGGING.len() as u64, Some(FRAMED_TAGGING.len() as u64)),
        FRAMED_TAGGING,
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorded.tag_sets.load(Ordering::SeqCst), 2);
}

/// Negative — under the switch a tag-set write under a `Content-Length` is read and applied.
#[tokio::test]
async fn n_a_sized_buffered_body_is_applied_under_the_switch() {
    let (service, recorded) = assembled(true);
    let md5 = content_md5(TAGGING);
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
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(polled.load(Ordering::SeqCst), TAGGING.len() as u64);
    assert_eq!(recorded.tag_sets.load(Ordering::SeqCst), 1);
}

/// Negative — under the switch an aws-chunked write whose decoded body is empty is handed on,
/// as legacy RustFS hands on an empty body, and answered by the decoder instead.
#[tokio::test]
async fn n_an_empty_decoded_buffered_body_is_handed_on_under_the_switch() {
    let (service, recorded) = assembled(true);
    let (request, _polled) = counted(framed("/bucket/object?tagging", 0, Some(FRAMED_EMPTY.len() as u64)), FRAMED_EMPTY);
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(
        !matches!(code_of(&body), Some("IncompleteBody" | "MissingContentLength")),
        "an empty decoded body was refused for its length: {body}"
    );
    assert_eq!(recorded.tag_sets.load(Ordering::SeqCst), 0);
}

/// Negative — under the switch an upload decoded from aws-chunked framing is stored as before.
#[tokio::test]
async fn n_an_upload_is_unchanged_under_the_switch() {
    let (service, recorded) = assembled(true);
    let (request, _polled) = counted(
        framed("/bucket/object", TAGGING.len() as u64, Some(FRAMED_TAGGING.len() as u64)),
        FRAMED_TAGGING,
    );
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let uploads = recorded.uploads.lock().expect("the record is never poisoned");
    assert_eq!(uploads.as_slice(), [TAGGING.to_vec()], "the upload was not stored whole");
}

/// Negative — under the switch a bad signature is still `403`, ahead of the length demand.
#[tokio::test]
async fn n_a_bad_signature_is_refused_before_the_length_demand() {
    let (service, recorded) = assembled(true);
    let (request, polled) = counted(chunked_transfer("/bucket/object?tagging").uri("/bucket/other?tagging"), TAGGING);
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(polled.load(Ordering::SeqCst), 0);
    assert_eq!(recorded.tag_sets.load(Ordering::SeqCst), 0);
}
