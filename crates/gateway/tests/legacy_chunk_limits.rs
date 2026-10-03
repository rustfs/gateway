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

//! aws-chunked uploads cut the way legacy RustFS accepts them, through the whole service
//! (rustfs/gateway#1173).
//!
//! Responsible for: proving that `ServiceBuilder::read_aws_chunks_as_legacy_rustfs` stores an
//! upload sent as one 8 MiB unsigned chunk and one cut into many small chunks, byte for byte,
//! which the default assembly refuses; and that a chunk past 16 MiB and a chunk past the declared
//! length are still refused under it with nothing handed over.
//! NOT responsible for: the limits' values (`src/builder/legacy_chunks.rs`'s unit tests), the
//! decoder's rules (`rustfs-gateway-http`), or the launcher that turns it on (`compat/sut`).
//! Upstream: `S3Service` with a recording `PutObject` backend. Downstream: none.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
};
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp, S3Service, dto};
use rustfs_gateway_sig::{DeclaredTrailers, TrailerName};

use crate::support;

#[derive(Default)]
struct Stored(Mutex<Vec<Vec<u8>>>);

struct Backend(Arc<Stored>);

impl Handler<dto::PutObject> for Backend {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let stored = Arc::clone(&self.0);
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
            stored.0.lock().expect("the record is never poisoned").push(bytes);
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

fn assembled(legacy: bool) -> (S3Service, Arc<Stored>) {
    let stored = Arc::new(Stored::default());
    let mut builder = support::wired_at_signed_time();
    if legacy {
        builder = builder.read_aws_chunks_as_legacy_rustfs();
    }
    let service = builder
        .register::<dto::PutObject, _>(Arc::new(Backend(Arc::clone(&stored))))
        .build()
        .expect("a complete assembly");
    (service, stored)
}

/// CRC-32/ISO-HDLC, bitwise, for the trailer each upload carries.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let carry = crc & 1;
            crc >>= 1;
            if carry != 0 {
                crc ^= 0xEDB8_8320;
            }
        }
    }
    !crc
}

/// Standard base64 of four bytes, padded.
fn base64_word(word: [u8; 4]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bits = u64::from(u32::from_be_bytes(word)) << 16;
    let mut out: String = (0..6)
        .map(|index| char::from(ALPHABET[usize::try_from((bits >> (42 - 6 * index)) & 0x3F).expect("six bits")]))
        .collect();
    out.push_str("==");
    out
}

/// `object` framed as unsigned aws-chunked chunks of `chunk` bytes, then the terminal chunk and
/// its CRC32 trailer.
fn framed(object: &[u8], chunk: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(object.len() + 64);
    for piece in object.chunks(chunk) {
        body.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        body.extend_from_slice(piece);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("0\r\nx-amz-checksum-crc32:{}\r\n\r\n", base64_word(crc32(object).to_be_bytes())).as_bytes());
    body
}

/// A header-signed `STREAMING-UNSIGNED-PAYLOAD-TRAILER` `PutObject` declaring `decoded` bytes and
/// carrying `body`.
fn upload(decoded: usize, body: Vec<u8>) -> http::Request<Bytes> {
    let trailer = TrailerSet::Declared(
        DeclaredTrailers::new([TrailerName::new("x-amz-checksum-crc32").expect("a trailer name")], false)
            .expect("a trailer declaration"),
    );
    let payload = PayloadMode::parse("STREAMING-UNSIGNED-PAYLOAD-TRAILER", trailer).expect("an unsigned trailer mode");
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::CONTENT_ENCODING, http::HeaderValue::from_static("aws-chunked"));
    headers.insert("x-amz-trailer", http::HeaderValue::from_static("x-amz-checksum-crc32"));
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let signing = SigningRequest::new(&http::Method::PUT, "/bucket/object", "", &headers, &host, payload, stamp)
        .with_wire_content_length(body.len() as u64)
        .with_decoded_content_length(decoded as u64);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(http::Method::PUT).uri("/bucket/object");
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(Bytes::from(body))
        .expect("a valid request")
}

/// Sends `request` with its body cut into 64 KiB transport frames, as a socket delivers it.
async fn exchange(service: &S3Service, request: http::Request<Bytes>) -> (http::StatusCode, String) {
    let (parts, body) = request.into_parts();
    let frames: Vec<Result<http_body::Frame<Bytes>, std::convert::Infallible>> = body
        .chunks(64 * 1024)
        .map(|piece| Ok(http_body::Frame::data(Bytes::copy_from_slice(piece))))
        .collect();
    let body = http_body_util::StreamBody::new(futures_util::stream::iter(frames));
    let response = service.call(http::Request::from_parts(parts, body)).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    (collected.status(), String::from_utf8_lossy(collected.body()).into_owned())
}

fn object(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 251).expect("below 251"))
        .collect()
}

const MIB: usize = 1024 * 1024;

/// Positive — under the switch an upload sent as one 8 MiB unsigned chunk is stored byte for byte.
#[tokio::test]
async fn one_eight_mebibyte_chunk_is_stored_under_the_switch() {
    let (service, stored) = assembled(true);
    let object = object(8 * MIB);
    let (status, body) = exchange(&service, upload(object.len(), framed(&object, object.len()))).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(stored.0.lock().expect("never poisoned").as_slice(), [object]);
}

/// Positive — under the switch an upload of 64 KiB cut into 64-byte chunks is stored byte for byte.
#[tokio::test]
async fn many_small_chunks_are_stored_under_the_switch() {
    let (service, stored) = assembled(true);
    let object = object(64 * 1024);
    let (status, body) = exchange(&service, upload(object.len(), framed(&object, 64))).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(stored.0.lock().expect("never poisoned").as_slice(), [object]);
}

/// Negative — the default assembly refuses the 8 MiB chunk and stores nothing.
#[tokio::test]
async fn n_the_default_refuses_an_eight_mebibyte_chunk() {
    let (service, stored) = assembled(false);
    let object = object(8 * MIB);
    let (status, body) = exchange(&service, upload(object.len(), framed(&object, object.len()))).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(support::element_text(&body, "Code"), Some("InvalidChunkSizeError"), "{body}");
    assert!(stored.0.lock().expect("never poisoned").is_empty());
}

/// Negative — the default assembly refuses the upload cut into 64-byte chunks and stores nothing.
#[tokio::test]
async fn n_the_default_refuses_many_small_chunks() {
    let (service, stored) = assembled(false);
    let object = object(64 * 1024);
    let (status, body) = exchange(&service, upload(object.len(), framed(&object, 64))).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(stored.0.lock().expect("never poisoned").is_empty());
}

/// Negative — under the switch a chunk one byte past 16 MiB is still refused, and nothing is
/// stored.
#[tokio::test]
async fn n_a_chunk_past_sixteen_mebibytes_is_still_refused_under_the_switch() {
    let (service, stored) = assembled(true);
    let object = object(16 * MIB + 1);
    let (status, body) = exchange(&service, upload(object.len(), framed(&object, object.len()))).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(support::element_text(&body, "Code"), Some("InvalidChunkSizeError"), "{body}");
    assert!(stored.0.lock().expect("never poisoned").is_empty());
}

/// Negative — under the switch a chunk longer than the declared decoded length is still refused.
#[tokio::test]
async fn n_the_declared_length_still_binds_under_the_switch() {
    let (service, stored) = assembled(true);
    let object = object(64 * 1024);
    let (status, body) = exchange(&service, upload(object.len() - 1, framed(&object, 64))).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(stored.0.lock().expect("never poisoned").is_empty());
}
