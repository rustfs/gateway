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

//! `ChunkIngest` and `framed_object_length` for a framed body the transport ends.
//!
//! Responsible for: rustfs/gateway#750 at the assembly's head — a framed body under
//! `Transfer-Encoding: chunked` is prepared with its decoded length as the ceiling and held to it
//! exactly, refused without one, and the codec is handed that length and no invented one.
//! NOT responsible for: the head rules themselves (`crates/http/tests/ingest_framing.rs`) or the
//! whole service (`crates/gateway/tests/streaming_without_length.rs`).
//! Upstream: `super`. Downstream: none.

use super::*;

use rustfs_gateway_stream::{MemoryReader, TrailingHeaders};

fn resident(wire: &'static [u8]) -> MemoryReader {
    MemoryReader::new([Bytes::from_static(wire)], TrailingHeaders::empty())
}

fn wire_length(length: u64) -> Framing {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&length.to_string()).expect("a digit run"),
    );
    Framing::classify(http::Version::HTTP_11, &headers, &rustfs_gateway_http::Limits::default()).expect("a framed request")
}

fn unsigned_streaming() -> PayloadMode {
    PayloadMode::StreamingUnsigned {
        trailer: rustfs_gateway_sig::TrailerSet::None,
    }
}

/// `Transfer-Encoding: chunked` and no `Content-Length`, the head botocore sends for a trailer
/// upload over TLS.
fn transfer_chunked() -> Framing {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
    Framing::classify(http::Version::HTTP_11, &headers, &rustfs_gateway_http::Limits::default()).expect("chunked framing")
}

fn decoded_length_header(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static(DECODED_LENGTH_HEADER),
        http::HeaderValue::from_static(value),
    );
    headers
}

fn prepare_transfer_chunked(headers: &HeaderMap) -> Result<Option<ChunkIngest>, S3Error> {
    ChunkIngest::prepare(
        &unsigned_streaming(),
        headers,
        &transfer_chunked(),
        &ChunkSink::new(),
        None,
        ChunkLimits::default(),
    )
}

/// Positive — rustfs/gateway#750: a framed body the transport ends is prepared with its decoded
/// length as the ceiling, and a body of exactly that length decodes.
#[tokio::test]
async fn a_framed_body_under_transfer_encoding_chunked_decodes_to_its_decoded_length() {
    let ingest = prepare_transfer_chunked(&decoded_length_header("11"))
        .expect("head-level checks pass without a wire length")
        .expect("a framed mode");
    assert_eq!(ingest.decoded_length(), 11);
    let mut digests = rustfs_gateway_http::BodyIntegrity::NONE.begin();
    let decoded = ingest
        .run(resident(b"b\r\nhello world\r\n0\r\n\r\n"), &mut digests)
        .await
        .expect("exactly the declared bytes");
    assert_eq!(decoded.body.as_ref(), b"hello world");
}

/// Negative — with no wire length the decoded length is the only ceiling, so one byte past it
/// is refused, and as a resource refusal that ends the connection.
#[tokio::test]
async fn a_transport_delimited_body_longer_than_its_decoded_length_is_refused() {
    let ingest = prepare_transfer_chunked(&decoded_length_header("10"))
        .expect("head-level checks pass")
        .expect("a framed mode");
    let error = ingest
        .run(
            resident(b"b\r\nhello world\r\n0\r\n\r\n"),
            &mut rustfs_gateway_http::BodyIntegrity::NONE.begin(),
        )
        .await
        .expect_err("eleven bytes against a declaration of ten");
    assert_eq!(error.status(), http::StatusCode::BAD_REQUEST);
    assert!(error.must_close_connection(), "an overflow is refused for the bytes it would spend");
}

/// Negative — and one byte short is refused at the terminal chunk rather than stored short.
#[tokio::test]
async fn a_transport_delimited_body_shorter_than_its_decoded_length_is_refused() {
    let ingest = prepare_transfer_chunked(&decoded_length_header("12"))
        .expect("head-level checks pass")
        .expect("a framed mode");
    let error = ingest
        .run(
            resident(b"b\r\nhello world\r\n0\r\n\r\n"),
            &mut rustfs_gateway_http::BodyIntegrity::NONE.begin(),
        )
        .await
        .expect_err("eleven bytes against a declaration of twelve");
    assert_eq!(error.status(), http::StatusCode::BAD_REQUEST);
}

/// Negative — `Transfer-Encoding: chunked` without `x-amz-decoded-content-length` leaves the
/// body with no ceiling at all, and is refused at the head.
#[tokio::test]
async fn a_transport_delimited_framed_body_without_a_decoded_length_is_refused_at_the_head() {
    let error = prepare_transfer_chunked(&HeaderMap::new())
        .err()
        .expect("no decoded length and no wire length");
    assert_eq!(error.status(), http::StatusCode::BAD_REQUEST);
}

/// Positive — the codec is handed the object's length for a framed body, whichever way HTTP
/// framed the wire: the decoded length is the object's size, and `Content-Length`, when there
/// is one, counts the chunk framing too.
#[test]
fn the_codec_reads_the_decoded_length_of_a_framed_body() {
    let headers = decoded_length_header("11");
    assert_eq!(framed_object_length(&unsigned_streaming(), &headers, &transfer_chunked()), Some(11));
    assert_eq!(framed_object_length(&unsigned_streaming(), &headers, &wire_length(4096)), Some(11));
}

/// Negative — no length is invented: an unframed mode, a framed head without the header, one
/// that spells it badly, and one whose declaration cannot fit its wire all leave the codec with
/// whatever `Content-Length` said, and `ChunkIngest::prepare` refuses the last three anyway.
#[test]
fn no_decoded_length_reaches_the_codec_unless_the_head_passes() {
    let headers = decoded_length_header("11");
    assert_eq!(framed_object_length(&PayloadMode::Unsigned, &headers, &wire_length(4096)), None);
    assert_eq!(framed_object_length(&unsigned_streaming(), &HeaderMap::new(), &transfer_chunked()), None);
    assert_eq!(
        framed_object_length(&unsigned_streaming(), &decoded_length_header("0x0b"), &transfer_chunked()),
        None
    );
    assert_eq!(framed_object_length(&unsigned_streaming(), &headers, &wire_length(8)), None);
}

/// Negative — a framed body that declares no decoded length is refused at the head, before a
/// byte is read. Without the header the decoder has nothing to check the arriving length
/// against, which is the state every length check exists to avoid.
#[tokio::test]
async fn a_framed_body_without_a_decoded_length_is_refused_at_the_head() {
    let wire = wire_length(4096);
    let error = ChunkIngest::prepare(
        &PayloadMode::StreamingSigned {
            trailer: rustfs_gateway_sig::TrailerSet::None,
        },
        &HeaderMap::new(),
        &wire,
        &ChunkSink::new(),
        None,
        ChunkLimits::default(),
    )
    .err()
    .expect("no decoded length");
    assert_eq!(error.status(), http::StatusCode::BAD_REQUEST);
}
