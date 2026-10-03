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

//! aws-chunked uploads cut the way legacy RustFS accepts them, as the RustFS-profile launcher
//! stores them (rustfs/gateway#1173).
//!
//! Responsible for: an upload sent as one 8 MiB unsigned chunk and one cut into 64-byte chunks,
//! each stored byte for byte as legacy RustFS stores it; and the controls that a chunk past
//! 16 MiB stores nothing (an object or a part) and that small chunks are still held to their
//! trailer checksum.
//! NOT responsible for: the switch's mechanics (`rustfs-gateway`'s `tests/legacy_chunk_limits.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed against a legacy RustFS build (rustfs/rustfs `3268c42e00`): a
//! `PutObject` sent as one 8 MiB `STREAMING-UNSIGNED-PAYLOAD-TRAILER` chunk is stored and `HEAD`
//! reports its 8 MiB.

use std::collections::VecDeque;

use super::*;

/// A body handed over in the frames it was cut into, as a socket delivers it.
struct Frames(VecDeque<Bytes>);

impl http_body::Body for Frames {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        _context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        core::task::Poll::Ready(self.get_mut().0.pop_front().map(|frame| Ok(http_body::Frame::data(frame))))
    }
}

/// Standard base64, padded.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for group in bytes.chunks(3) {
        let word = group.iter().fold(0_u32, |word, byte| (word << 8) | u32::from(*byte)) << (8 * (3 - group.len()));
        for index in 0..=group.len() {
            let sextet = usize::try_from((word >> (18 - 6 * index)) & 0x3F).expect("six bits");
            out.push(char::from(ALPHABET[sextet]));
        }
        out.push_str(&"=".repeat(3 - group.len()));
    }
    out
}

/// `object` as unsigned aws-chunked chunks of `chunk` bytes, the terminal chunk, and a SHA-256
/// trailer of `trailer_of`.
fn framed(object: &[u8], chunk: usize, trailer_of: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(object.len() + 128);
    for piece in object.chunks(chunk) {
        body.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        body.extend_from_slice(piece);
        body.extend_from_slice(b"\r\n");
    }
    let digest = Sha256::digest(trailer_of);
    body.extend_from_slice(format!("0\r\nx-amz-checksum-sha256:{}\r\n\r\n", base64(&digest)).as_bytes());
    body
}

/// A hand-signed `STREAMING-UNSIGNED-PAYLOAD-TRAILER` `PUT` to `path?query` declaring
/// `object_length` decoded bytes and carrying `body` in 64 KiB frames.
fn streaming_put(path: &str, query: &str, object_length: usize, body: Vec<u8>) -> http::Request<Frames> {
    use hmac::{Hmac, KeyInit, Mac};
    let mac = |key: &[u8], data: &[u8]| {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };
    let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let stamp = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let token = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
    let headers = [
        ("content-encoding", "aws-chunked".to_owned()),
        ("host", "s3.example.com".to_owned()),
        ("x-amz-content-sha256", token.to_owned()),
        ("x-amz-date", stamp.clone()),
        ("x-amz-decoded-content-length", object_length.to_string()),
        ("x-amz-trailer", "x-amz-checksum-sha256".to_owned()),
    ];
    let canonical_headers: String = headers.iter().map(|(name, value)| format!("{name}:{value}\n")).collect();
    let signed_names = headers.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(";");
    let canonical = format!("PUT\n{path}\n{query}\n{canonical_headers}\n{signed_names}\n{token}");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = mac(format!("AWS4{MAIN_SECRET}").as_bytes(), day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = mac(&key, part.as_bytes());
    }
    let signature = hex(&mac(&key, string_to_sign.as_bytes()));
    let target = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let mut request = http::Request::builder()
        .method(http::Method::PUT)
        .uri(target)
        .header(http::header::CONTENT_LENGTH, body.len())
        .header(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential={MAIN_KEY}/{scope}, SignedHeaders={signed_names}, Signature={signature}"),
        );
    for (name, value) in &headers {
        request = request.header(*name, value.as_str());
    }
    let frames = body.chunks(64 * 1024).map(Bytes::copy_from_slice).collect();
    request.body(Frames(frames)).expect("a valid streaming request")
}

async fn send(service: &S3Service, request: http::Request<Frames>) -> WireResponse {
    collect(service.call(request).await).await.expect("a finite response")
}

fn object(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 251).expect("below 251"))
        .collect()
}

const MIB: usize = 1024 * 1024;

async fn with_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/chunks", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

/// Positive — an upload sent as one 8 MiB unsigned chunk is stored byte for byte.
#[tokio::test]
async fn an_upload_sent_as_one_eight_mebibyte_chunk_is_stored_whole() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let object = object(8 * MIB);
    let response = send(
        &service,
        streaming_put("/chunks/big", "", object.len(), framed(&object, object.len(), &object)),
    )
    .await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    let stored = exchange(&service, as_main(http::Method::GET, "/chunks/big", Bytes::new())).await;
    assert_eq!(stored.status(), 200);
    assert!(stored.body().as_ref() == object.as_slice(), "the stored object differs from the upload");
}

/// Positive — an upload of 64 KiB cut into 64-byte chunks is stored byte for byte.
#[tokio::test]
async fn an_upload_cut_into_small_chunks_is_stored_whole() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let object = object(64 * 1024);
    let response = send(&service, streaming_put("/chunks/small", "", object.len(), framed(&object, 64, &object))).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    let stored = exchange(&service, as_main(http::Method::GET, "/chunks/small", Bytes::new())).await;
    assert_eq!(stored.body().as_ref(), object.as_slice());
}

/// Negative — a chunk one byte past 16 MiB is refused and no object is stored.
#[tokio::test]
async fn n_a_chunk_past_sixteen_mebibytes_stores_nothing() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let object = object(16 * MIB + 1);
    let response = send(
        &service,
        streaming_put("/chunks/huge", "", object.len(), framed(&object, object.len(), &object)),
    )
    .await;
    assert_eq!(response.status(), 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("<Code>InvalidChunkSizeError</Code>"),
        "{}",
        body_of(&response)
    );
    let read = exchange(&service, as_main(http::Method::GET, "/chunks/huge", Bytes::new())).await;
    assert_eq!(read.status(), 404, "the refused upload was stored");
}

/// Negative — a part sent as a chunk past 16 MiB is refused and the upload holds no part.
#[tokio::test]
async fn n_a_part_past_sixteen_mebibytes_leaves_no_part() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let created = exchange(&service, as_main(http::Method::POST, "/chunks/parted?uploads", Bytes::new())).await;
    let body = body_of(&created);
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .and_then(|rest| rest.split("</UploadId>").next())
        .expect("an upload id")
        .to_owned();
    let object = object(16 * MIB + 1);
    let query = format!("partNumber=1&uploadId={upload_id}");
    let response = send(
        &service,
        streaming_put("/chunks/parted", &query, object.len(), framed(&object, object.len(), &object)),
    )
    .await;
    assert_eq!(response.status(), 400, "{}", body_of(&response));
    let parts = exchange(
        &service,
        as_main(http::Method::GET, &format!("/chunks/parted?uploadId={upload_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(parts.status(), 200, "{}", body_of(&parts));
    assert!(!body_of(&parts).contains("<Part>"), "the refused part was stored: {}", body_of(&parts));
}

/// Negative — small chunks whose trailer checksum does not match the object are refused and
/// store nothing: lifting the chunk limits lifts no verification.
#[tokio::test]
async fn n_small_chunks_are_still_held_to_their_checksum() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let object = object(64 * 1024);
    let response = send(
        &service,
        streaming_put("/chunks/wrong", "", object.len(), framed(&object, 64, b"another object")),
    )
    .await;
    assert_eq!(response.status(), 400, "{}", body_of(&response));
    assert!(body_of(&response).contains("<Code>BadDigest</Code>"), "{}", body_of(&response));
    let read = exchange(&service, as_main(http::Method::GET, "/chunks/wrong", Bytes::new())).await;
    assert_eq!(read.status(), 404, "the refused upload was stored");
}
