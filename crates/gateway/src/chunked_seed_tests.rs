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

//! Verified chunk-seed handoff tests.
//!
//! Responsible for: proving `build_signer` consumes the verified 32-byte seed published in
//! `ChunkVerification` (never re-parsing wire strings), refuses when no material was published,
//! and rejects chunks chained from a different seed.
//! NOT responsible for: full SigV4 header/query parsing (`tests/ingest_assembly.rs`).
//! Upstream: `crate::ext::ChunkVerification`, `crate::chunked::build_signer`.
//! Downstream: Cargo unit test harness.

use super::*;

use rustfs_gateway_stream::{MemoryReader, TrailingHeaders};

const SIGNED_CHUNK_FOR_AA_SEED: &str = "363c3b84bea6aab48c5dbef2daa7010a85774527b5780fde436990666c721cd6";
const SIGNED_ZERO_FOR_AA_SEED: &str = "3f9a21b0b8726c09b85a7d66e31ac4426f5127e2eab04820f390a81621b948e3";

fn signed_wire_for_aa_seed() -> MemoryReader {
    let wire = format!(
        "b;chunk-signature={SIGNED_CHUNK_FOR_AA_SEED}\r\nhello world\r\n\
         0;chunk-signature={SIGNED_ZERO_FOR_AA_SEED}\r\n\r\n"
    );
    MemoryReader::new([Bytes::from(wire)], TrailingHeaders::empty())
}

fn signed_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(http::HeaderName::from_static(DECODED_LENGTH_HEADER), http::HeaderValue::from_static("11"));
    headers
}

fn wire_length(length: u64) -> Framing {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&length.to_string()).expect("a digit run"),
    );
    Framing::classify(http::Version::HTTP_11, &headers, &rustfs_gateway_http::Limits::default()).expect("a framed request")
}

/// Positive — `ChunkIngest::prepare` seeds its chunk signer directly from the verified 32-byte
/// seed published in `ChunkSink`, without consulting any `Authorization` header or query string.
#[tokio::test]
async fn verified_seed_in_chunk_sink_verifies_chunks_without_wire_reparse() {
    let sink = ChunkSink::new();
    sink.publish(crate::ext::ChunkVerification::new(
        rustfs_gateway_sig::SigningKey::from_array([0x5a; 32]),
        "20130524/us-east-1/s3/aws4_request".to_owned(),
        "20130524T000000Z".to_owned(),
        [0xaa; 32],
    ));
    let ingest = ChunkIngest::prepare(
        &PayloadMode::StreamingSigned {
            trailer: rustfs_gateway_sig::TrailerSet::None,
        },
        &signed_headers(),
        &wire_length(4096),
        &sink,
        ChunkLimits::default(),
    )
    .expect("verified material prepares ingest")
    .expect("streaming signed mode builds ingest");
    let mut digests = rustfs_gateway_http::BodyIntegrity::NONE.begin();
    let decoded = ingest
        .run(signed_wire_for_aa_seed(), &mut digests)
        .await
        .expect("chunks chained from verified seed succeed");
    assert_eq!(decoded.body.as_ref(), b"hello world");
}

/// Negative — changing the published 32-byte seed rejects chunks chained from the previous seed.
#[tokio::test]
async fn mismatched_verified_seed_rejects_chunk_chain() {
    let sink = ChunkSink::new();
    sink.publish(crate::ext::ChunkVerification::new(
        rustfs_gateway_sig::SigningKey::from_array([0x5a; 32]),
        "20130524/us-east-1/s3/aws4_request".to_owned(),
        "20130524T000000Z".to_owned(),
        [0xbb; 32],
    ));
    let ingest = ChunkIngest::prepare(
        &PayloadMode::StreamingSigned {
            trailer: rustfs_gateway_sig::TrailerSet::None,
        },
        &signed_headers(),
        &wire_length(4096),
        &sink,
        ChunkLimits::default(),
    )
    .expect("material prepares ingest")
    .expect("streaming signed mode builds ingest");
    let mut digests = rustfs_gateway_http::BodyIntegrity::NONE.begin();
    let error = ingest
        .run(signed_wire_for_aa_seed(), &mut digests)
        .await
        .expect_err("different verified seed must reject the chunk chain");
    assert_eq!(error.status(), http::StatusCode::FORBIDDEN);
}

/// Negative — an empty `ChunkSink` fails closed with `501 NotImplemented` and closes the socket.
#[test]
fn empty_chunk_sink_is_refused() {
    let payload = PayloadMode::StreamingSigned {
        trailer: rustfs_gateway_sig::TrailerSet::None,
    };
    let framing = ChunkFraming::derive(&FramingOf(&payload)).expect("streaming signed framing");
    let error = build_signer(&framing, &ChunkSink::new()).expect_err("missing material must refuse");
    assert_eq!(error.status(), http::StatusCode::NOT_IMPLEMENTED);
    assert!(error.must_close_connection());
}
