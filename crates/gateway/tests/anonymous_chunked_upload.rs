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

//! An anonymous `aws-chunked` upload, through the whole service (rustfs/gateway#1060).
//!
//! Responsible for: proving that an anonymous request whose head declares
//! `STREAMING-UNSIGNED-PAYLOAD-TRAILER` reaches its handler decoded, with its trailer checksum
//! verified, exactly as the signed form does; that a broken trailer or decoded length refuses it
//! with no complete body handed on; and that a chunk-signed streaming mode, which no anonymous request can
//! verify, is refused before the handler rather than handed through framed.
//! NOT responsible for: the chunk grammar (`crates/http`), the signed streaming path
//! (`streaming_without_length.rs`), or which anonymous requests the floor admits
//! (`anonymous_delegation_runtime.rs`).
//! Upstream: `S3Service` under a delegating floor with a recording `PutObject` backend.
//! Downstream: none.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp, S3Service, SecurityFloor, dto};

use crate::support;

/// The object every case uploads.
const OBJECT: &[u8] = b"hello world";
/// The base64 CRC32 of [`OBJECT`] (`0x0d4a1185`).
const OBJECT_CRC32: &str = "DUoRhQ==";

#[derive(Default)]
struct Recorded {
    reached: AtomicUsize,
    bodies: Mutex<Vec<(i64, Vec<u8>)>>,
}

struct Backend(Arc<Recorded>);

impl Handler<dto::PutObject> for Backend {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let recorded = Arc::clone(&self.0);
        recorded.reached.fetch_add(1, Ordering::SeqCst);
        let input = request.into_input();
        let content_length = input.content_length;
        let body = input.body;
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
            recorded
                .bodies
                .lock()
                .expect("the record is never poisoned")
                .push((content_length, bytes));
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

fn service() -> (S3Service, Arc<Recorded>) {
    let recorded = Arc::new(Recorded::default());
    let service = support::wired_at_signed_time()
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .register::<dto::PutObject, _>(Arc::new(Backend(Arc::clone(&recorded))))
        .build()
        .expect("a complete PutObject assembly");
    (service, recorded)
}

/// An unsigned `aws-chunked` body: one data chunk, the terminal chunk, one trailer.
fn unsigned_framing(trailer_value: &str) -> Vec<u8> {
    let mut body = format!("{:x}\r\n", OBJECT.len()).into_bytes();
    body.extend_from_slice(OBJECT);
    body.extend_from_slice(b"\r\n0\r\n");
    body.extend_from_slice(format!("x-amz-checksum-crc32:{trailer_value}\r\n\r\n").as_bytes());
    body
}

/// An anonymous `PutObject` carrying `body`, declaring `content_sha256` and `decoded` bytes.
fn anonymous_put(content_sha256: &str, decoded: usize, body: Vec<u8>) -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::PUT)
        .uri("/bucket/object")
        .header("host", "s3.example.com")
        .header("content-encoding", "aws-chunked")
        .header("x-amz-content-sha256", content_sha256)
        .header("x-amz-trailer", "x-amz-checksum-crc32")
        .header("x-amz-decoded-content-length", decoded.to_string())
        .header("content-length", body.len().to_string())
        .body(Bytes::from(body))
        .expect("a valid request")
}

/// Positive — the unsigned streaming form needs no signature to decode, so an anonymous upload is
/// decoded like a signed one: the handler reads the object's own bytes and length.
#[tokio::test]
async fn an_anonymous_unsigned_trailer_upload_reaches_the_handler_decoded() {
    let (service, recorded) = service();
    let request = anonymous_put("STREAMING-UNSIGNED-PAYLOAD-TRAILER", OBJECT.len(), unsigned_framing(OBJECT_CRC32));
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let bodies = recorded.bodies.lock().expect("the record is never poisoned");
    assert_eq!(*bodies, [(OBJECT.len() as i64, OBJECT.to_vec())]);
}

/// Negative — the trailer checksum is verified for an anonymous upload too: a wrong one is refused,
/// and the handler never reads a complete body.
#[tokio::test]
async fn an_anonymous_upload_with_a_wrong_trailer_checksum_is_refused_uncommitted() {
    let (service, recorded) = service();
    let request = anonymous_put("STREAMING-UNSIGNED-PAYLOAD-TRAILER", OBJECT.len(), unsigned_framing("AAAAAA=="));
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(
        support::element_text(&body, "Code"),
        Some("XAmzContentChecksumMismatch"),
        "{status}: {body}"
    );
    let bodies = recorded.bodies.lock().expect("the record is never poisoned");
    assert!(bodies.is_empty(), "the handler read a complete body: {bodies:?}");
}

/// Negative — a decoded length the framing does not carry is refused, and the handler never reads
/// a complete body.
#[tokio::test]
async fn an_anonymous_upload_whose_decoded_length_disagrees_is_refused_uncommitted() {
    let (service, recorded) = service();
    let request = anonymous_put("STREAMING-UNSIGNED-PAYLOAD-TRAILER", OBJECT.len() + 1, unsigned_framing(OBJECT_CRC32));
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(support::element_text(&body, "Code"), Some("IncompleteBody"), "{status}: {body}");
    let bodies = recorded.bodies.lock().expect("the record is never poisoned");
    assert!(bodies.is_empty(), "the handler read a complete body: {bodies:?}");
}

/// Negative — a chunk-signed streaming mode cannot be verified without a signature. It is refused
/// before the handler, never handed through with its framing as object data.
#[tokio::test]
async fn an_anonymous_chunk_signed_upload_is_refused_before_the_handler() {
    for mode in [
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
    ] {
        let (service, recorded) = service();
        let request = anonymous_put(mode, OBJECT.len(), unsigned_framing(OBJECT_CRC32));
        let (status, body) = support::exchange(&service, request).await;
        assert!(status.is_client_error(), "{mode} answered {status}: {body}");
        assert_eq!(recorded.reached.load(Ordering::SeqCst), 0, "{mode} reached the handler: {body}");
    }
}
