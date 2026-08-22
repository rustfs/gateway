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

//! The assembly-level trailer commit boundary.
//!
//! Responsible for: proving an unsigned EOF trailer needs a matching checksum witness and a
//! signed trailer remains refused without its final HMAC check. NOT responsible for: trailer
//! grammar and limits, which the HTTP crate tests. Upstream: `chunked`. Downstream: P3-04 evidence.

use bytes::Bytes;
use http::HeaderMap;
use rustfs_gateway_stream::{MemoryReader, TrailingHeaders};

use super::*;

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

fn unsigned_trailered() -> PayloadMode {
    let declared = rustfs_gateway_sig::DeclaredTrailers::new(
        [rustfs_gateway_sig::TrailerName::new("x-amz-checksum-crc32").expect("a valid trailer name")],
        false,
    )
    .expect("one checksum trailer");
    PayloadMode::StreamingUnsigned {
        trailer: rustfs_gateway_sig::TrailerSet::Declared(declared),
    }
}

fn unsigned_trailer_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(http::HeaderName::from_static(DECODED_LENGTH_HEADER), http::HeaderValue::from_static("11"));
    headers.insert(
        http::HeaderName::from_static("x-amz-trailer"),
        http::HeaderValue::from_static("x-amz-checksum-crc32"),
    );
    headers
}

#[tokio::test]
async fn c_ck_0002_an_unsigned_trailer_checksum_unlocks_commit_only_after_comparison() {
    let headers = unsigned_trailer_headers();
    let ingest = ChunkIngest::prepare(
        &unsigned_trailered(),
        &headers,
        &wire_length(4096),
        &ChunkSink::new(),
        None,
        ChunkLimits::default(),
    )
    .expect("the trailered mode is implemented")
    .expect("a framed body");
    let mut digests = rustfs_gateway_http::BodyIntegrity::resolve(
        &rustfs_gateway_http::HeaderView::new(&headers),
        rustfs_gateway_http::ChecksumSubject::RequestBody,
    )
    .expect("one checksum trailer")
    .begin();
    let output = ingest
        .run(resident(b"b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n"), &mut digests)
        .await
        .expect("well-formed unsigned trailer framing");
    let verified = digests
        .verify_with_trailers(output.trailers())
        .expect("the trailer checksum matches the decoded body");
    assert!(output.commit_allowed(&verified));
    assert_eq!(output.body.as_ref(), b"hello world");
}

#[tokio::test]
async fn c_ck_0039_an_unsigned_trailer_checksum_mismatch_never_unlocks_commit() {
    let headers = unsigned_trailer_headers();
    let ingest = ChunkIngest::prepare(
        &unsigned_trailered(),
        &headers,
        &wire_length(4096),
        &ChunkSink::new(),
        None,
        ChunkLimits::default(),
    )
    .expect("the trailered mode is implemented")
    .expect("a framed body");
    let mut digests = rustfs_gateway_http::BodyIntegrity::resolve(
        &rustfs_gateway_http::HeaderView::new(&headers),
        rustfs_gateway_http::ChecksumSubject::RequestBody,
    )
    .expect("one checksum trailer")
    .begin();
    let output = ingest
        .run(resident(b"b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n"), &mut digests)
        .await
        .expect("the framing itself is complete");
    assert_eq!(
        digests.verify_with_trailers(output.trailers()),
        Err(rustfs_gateway_http::ChecksumReject::ChecksumMismatch)
    );
}

#[tokio::test]
async fn a_parsed_trailer_without_a_checksum_witness_cannot_unlock_commit() {
    let headers = unsigned_trailer_headers();
    let ingest = ChunkIngest::prepare(
        &unsigned_trailered(),
        &headers,
        &wire_length(4096),
        &ChunkSink::new(),
        None,
        ChunkLimits::default(),
    )
    .expect("the trailered mode is implemented")
    .expect("a framed body");
    let mut digests = rustfs_gateway_http::BodyIntegrity::NONE.begin();
    let output = ingest
        .run(resident(b"b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n"), &mut digests)
        .await
        .expect("the parser completed");
    let empty_witness = digests.verify().expect("no obligation was claimed through this value");
    assert!(!output.commit_allowed(&empty_witness));
}

fn sink_with_material() -> ChunkSink {
    let sink = ChunkSink::new();
    sink.publish(crate::ext::ChunkVerification::new(
        rustfs_gateway_sig::SigningKey::from_array([0x5a; 32]),
        "20130524/us-east-1/s3/aws4_request".to_owned(),
        "20130524T000000Z".to_owned(),
    ));
    sink
}

fn signed_trailered() -> PayloadMode {
    let declared = rustfs_gateway_sig::DeclaredTrailers::new(
        [rustfs_gateway_sig::TrailerName::new("x-amz-checksum-crc32").expect("a valid trailer name")],
        false,
    )
    .expect("one checksum trailer");
    PayloadMode::StreamingSigned {
        trailer: rustfs_gateway_sig::TrailerSet::Declared(declared),
    }
}

fn signed_trailer_headers() -> HeaderMap {
    unsigned_trailer_headers()
}

const SIGNED_CHUNK: &str = "363c3b84bea6aab48c5dbef2daa7010a85774527b5780fde436990666c721cd6";
const SIGNED_ZERO_CHUNK: &str = "3f9a21b0b8726c09b85a7d66e31ac4426f5127e2eab04820f390a81621b948e3";
const SIGNED_TRAILER: &str = "8e7095168f795d75ed6296ec35143f8d8ec11df313a8b1683c0da0ec1be72c48";

fn signed_wire(trailer_signature: Option<&str>) -> MemoryReader {
    let mut wire = format!(
        "b;chunk-signature={SIGNED_CHUNK}\r\nhello world\r\n\
         0;chunk-signature={SIGNED_ZERO_CHUNK}\r\n\
         x-amz-checksum-crc32:DUoRhQ==\r\n"
    );
    if let Some(signature) = trailer_signature {
        wire.push_str("x-amz-trailer-signature:");
        wire.push_str(signature);
        wire.push_str("\r\n");
    }
    wire.push_str("\r\n");
    MemoryReader::new([Bytes::from(wire)], TrailingHeaders::empty())
}

#[tokio::test]
async fn c_ck_0003_a_signed_trailer_unlocks_commit_only_after_its_final_hmac() {
    let headers = signed_trailer_headers();
    let ingest = ChunkIngest::prepare(
        &signed_trailered(),
        &headers,
        &wire_length(4096),
        &sink_with_material(),
        Some(&"a".repeat(64)),
        ChunkLimits::default(),
    )
    .expect("signed trailer verification is implemented")
    .expect("a framed body");
    let mut digests = rustfs_gateway_http::BodyIntegrity::resolve(
        &rustfs_gateway_http::HeaderView::new(&headers),
        rustfs_gateway_http::ChecksumSubject::RequestBody,
    )
    .expect("one checksum trailer")
    .begin();
    let output = ingest
        .run(signed_wire(Some(SIGNED_TRAILER)), &mut digests)
        .await
        .expect("the chunk chain and final trailer HMAC agree");
    let verified = digests
        .verify_with_trailers(output.trailers())
        .expect("the checksum trailer matches the decoded body");
    assert!(output.commit_allowed(&verified));
    assert_eq!(output.body.as_ref(), b"hello world");
}

#[tokio::test]
async fn c_ck_0031_a_missing_signed_trailer_hmac_is_forbidden() {
    let headers = signed_trailer_headers();
    let ingest = ChunkIngest::prepare(
        &signed_trailered(),
        &headers,
        &wire_length(4096),
        &sink_with_material(),
        Some(&"a".repeat(64)),
        ChunkLimits::default(),
    )
    .expect("signed trailer verification is implemented")
    .expect("a framed body");
    let mut digests = rustfs_gateway_http::BodyIntegrity::NONE.begin();
    let error = ingest
        .run(signed_wire(None), &mut digests)
        .await
        .expect_err("the final HMAC is mandatory");
    assert_eq!(error.status(), http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_mismatched_signed_trailer_hmac_is_forbidden() {
    let headers = signed_trailer_headers();
    let ingest = ChunkIngest::prepare(
        &signed_trailered(),
        &headers,
        &wire_length(4096),
        &sink_with_material(),
        Some(&"a".repeat(64)),
        ChunkLimits::default(),
    )
    .expect("signed trailer verification is implemented")
    .expect("a framed body");
    let mut digests = rustfs_gateway_http::BodyIntegrity::NONE.begin();
    let error = ingest
        .run(signed_wire(Some(&"0".repeat(64))), &mut digests)
        .await
        .expect_err("a mismatched final HMAC is rejected");
    assert_eq!(error.status(), http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn c_ck_0032_the_trailer_hmac_is_seeded_by_the_zero_chunk_signature() {
    const TRAILER_SEEDED_BY_DATA_CHUNK: &str = "70edc4d9a7881b1459744e1384bee0f6d39a79da499e80fdea94824380305b31";

    let headers = signed_trailer_headers();
    let ingest = ChunkIngest::prepare(
        &signed_trailered(),
        &headers,
        &wire_length(4096),
        &sink_with_material(),
        Some(&"a".repeat(64)),
        ChunkLimits::default(),
    )
    .expect("signed trailer verification is implemented")
    .expect("a framed body");
    let mut digests = rustfs_gateway_http::BodyIntegrity::NONE.begin();
    let error = ingest
        .run(signed_wire(Some(TRAILER_SEEDED_BY_DATA_CHUNK)), &mut digests)
        .await
        .expect_err("the preceding data chunk cannot seed the trailer HMAC");
    assert_eq!(error.status(), http::StatusCode::FORBIDDEN);
}
