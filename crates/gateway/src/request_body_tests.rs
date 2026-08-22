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

//! Unit contracts for the live request-body producer.
//!
//! Responsible for: read-ahead, logical-size, resident-frame, and early-drop behavior.
//! NOT responsible for: live sockets or process RSS.
//! Upstream: `request_body`. Downstream: c-ing-0061 and c-ing-0063 acceptance evidence.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_http::{BodyIntegrity, ChecksumSubject, Framing, HeaderView};
use rustfs_gateway_sig::{DeclaredTrailers, PayloadMode, TrailerName, TrailerSet};
use rustfs_gateway_types::ErrorCode;

use crate::gate::{Authenticated, BodyCeilings, BodyDigestObligation, BodyTimeouts, SealedBody};

const fn roomy() -> BodyCeilings {
    BodyCeilings {
        buffered: 1024 * 1024,
        whole_body: true,
        declared: None,
    }
}

fn unsigned_trailered(headers: &HeaderMap) -> Option<crate::chunked::ChunkIngest> {
    let name = TrailerName::new("x-amz-checksum-crc32").ok()?;
    let declared = DeclaredTrailers::new([name], false).ok()?;
    let mode = PayloadMode::StreamingUnsigned {
        trailer: TrailerSet::Declared(declared),
    };
    let wire = Framing::classify(http::Version::HTTP_11, headers, &rustfs_gateway_http::Limits::default()).ok()?;
    crate::chunked::ChunkIngest::prepare(
        &mode,
        headers,
        &wire,
        &crate::ext::ChunkSink::new(),
        None,
        rustfs_gateway_http::ChunkLimits::default(),
    )
    .ok()?
}

fn signed_trailered(headers: &HeaderMap) -> Option<crate::chunked::ChunkIngest> {
    let name = TrailerName::new("x-amz-checksum-crc32").ok()?;
    let declared = DeclaredTrailers::new([name], false).ok()?;
    let mode = PayloadMode::StreamingSigned {
        trailer: TrailerSet::Declared(declared),
    };
    let sink = crate::ext::ChunkSink::new();
    sink.publish(crate::ext::ChunkVerification::new(
        rustfs_gateway_sig::SigningKey::from_array([0x5a; 32]),
        "20130524/us-east-1/s3/aws4_request".to_owned(),
        "20130524T000000Z".to_owned(),
    ));
    let wire = Framing::classify(http::Version::HTTP_11, headers, &rustfs_gateway_http::Limits::default()).ok()?;
    crate::chunked::ChunkIngest::prepare(
        &mode,
        headers,
        &wire,
        &sink,
        Some(&"a".repeat(64)),
        rustfs_gateway_http::ChunkLimits::default(),
    )
    .ok()?
}

fn trailer_headers(wire_len: usize) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(wire_len as u64));
    headers.insert(HeaderName::from_static("x-amz-decoded-content-length"), HeaderValue::from_static("11"));
    headers.insert(HeaderName::from_static("x-amz-trailer"), HeaderValue::from_static("x-amz-checksum-crc32"));
    headers
}

#[tokio::test]
async fn c_ck_0002_the_streaming_production_path_accepts_a_matching_unsigned_trailer_checksum() {
    const WIRE: &[u8] = b"b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n";
    let proof = Authenticated::granted_for_test();
    let headers = trailer_headers(WIRE.len());
    let ingest = unsigned_trailered(&headers);
    assert!(ingest.is_some(), "the unsigned trailer shape is implemented");
    let Some(ingest) = ingest else {
        return;
    };
    let integrity = BodyIntegrity::resolve(&HeaderView::new(&headers), ChecksumSubject::RequestBody).ok();
    assert!(integrity.is_some(), "one trailer checksum obligation");
    let Some(integrity) = integrity else {
        return;
    };
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(WIRE)]);
    let opened = SealedBody::seal(Some(body), Some(WIRE.len() as u64))
        .stream(
            &proof,
            (BodyCeilings::streaming(None), BodyTimeouts::S3, None),
            Some(ingest),
            BodyDigestObligation::None,
            integrity,
        )
        .ok();
    assert!(opened.is_some(), "the verified stream opens");
    let Some(opened) = opened else {
        return;
    };
    let (stream, terminal) = opened.into_parts();
    let collected = crate::wire::collect(http::Response::new(stream.into_body())).await.ok();
    assert!(collected.is_some(), "the matching checksum reaches EOF");
    let Some(collected) = collected else {
        return;
    };
    assert_eq!(collected.body(), &Bytes::from_static(b"hello world"));
    assert!(terminal.wait().await.is_ok());
    assert!(read.is_exhausted());
}

#[tokio::test]
async fn c_ck_0039_the_streaming_production_path_refuses_a_mismatched_unsigned_trailer_checksum() {
    const WIRE: &[u8] = b"b\r\nhello world\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n";
    let proof = Authenticated::granted_for_test();
    let headers = trailer_headers(WIRE.len());
    let ingest = unsigned_trailered(&headers);
    assert!(ingest.is_some(), "the unsigned trailer shape is implemented");
    let Some(ingest) = ingest else {
        return;
    };
    let integrity = BodyIntegrity::resolve(&HeaderView::new(&headers), ChecksumSubject::RequestBody).ok();
    assert!(integrity.is_some(), "one trailer checksum obligation");
    let Some(integrity) = integrity else {
        return;
    };
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(WIRE)]);
    let opened = SealedBody::seal(Some(body), Some(WIRE.len() as u64))
        .stream(
            &proof,
            (BodyCeilings::streaming(None), BodyTimeouts::S3, None),
            Some(ingest),
            BodyDigestObligation::None,
            integrity,
        )
        .ok();
    assert!(opened.is_some(), "the stream opens before the EOF value arrives");
    let Some(opened) = opened else {
        return;
    };
    let (stream, terminal) = opened.into_parts();
    assert!(crate::wire::collect(http::Response::new(stream.into_body())).await.is_err());
    let refusal = terminal.wait().await.err();
    assert_eq!(
        refusal.as_ref().and_then(crate::render::S3Error::code),
        Some(&ErrorCode::X_AMZ_CONTENT_CHECKSUM_MISMATCH)
    );
    assert!(read.is_exhausted());
}

#[tokio::test]
async fn c_ck_0003_the_streaming_production_path_accepts_a_signed_trailer_hmac() {
    const WIRE: &[u8] = b"b;chunk-signature=363c3b84bea6aab48c5dbef2daa7010a85774527b5780fde436990666c721cd6\r\n\
        hello world\r\n\
        0;chunk-signature=3f9a21b0b8726c09b85a7d66e31ac4426f5127e2eab04820f390a81621b948e3\r\n\
        x-amz-checksum-crc32:DUoRhQ==\r\n\
        x-amz-trailer-signature:8e7095168f795d75ed6296ec35143f8d8ec11df313a8b1683c0da0ec1be72c48\r\n\r\n";
    let proof = Authenticated::granted_for_test();
    let headers = trailer_headers(WIRE.len());
    let ingest = signed_trailered(&headers);
    assert!(ingest.is_some(), "the signed trailer shape is implemented");
    let Some(ingest) = ingest else {
        return;
    };
    let integrity = BodyIntegrity::resolve(&HeaderView::new(&headers), ChecksumSubject::RequestBody).ok();
    assert!(integrity.is_some(), "one trailer checksum obligation");
    let Some(integrity) = integrity else {
        return;
    };
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(WIRE)]);
    let opened = SealedBody::seal(Some(body), Some(WIRE.len() as u64))
        .stream(
            &proof,
            (BodyCeilings::streaming(None), BodyTimeouts::S3, None),
            Some(ingest),
            BodyDigestObligation::None,
            integrity,
        )
        .ok();
    assert!(opened.is_some(), "the signed stream opens");
    let Some(opened) = opened else {
        return;
    };
    let (stream, terminal) = opened.into_parts();
    let collected = crate::wire::collect(http::Response::new(stream.into_body())).await.ok();
    assert!(collected.is_some(), "the final HMAC reaches EOF");
    let Some(collected) = collected else {
        return;
    };
    assert_eq!(collected.body(), &Bytes::from_static(b"hello world"));
    assert!(terminal.wait().await.is_ok());
    assert!(read.is_exhausted());
}

#[tokio::test]
async fn the_streaming_production_path_refuses_a_mismatched_signed_trailer_hmac() {
    const WIRE: &[u8] = b"b;chunk-signature=363c3b84bea6aab48c5dbef2daa7010a85774527b5780fde436990666c721cd6\r\n\
        hello world\r\n\
        0;chunk-signature=3f9a21b0b8726c09b85a7d66e31ac4426f5127e2eab04820f390a81621b948e3\r\n\
        x-amz-checksum-crc32:DUoRhQ==\r\n\
        x-amz-trailer-signature:0000000000000000000000000000000000000000000000000000000000000000\r\n\r\n";
    let proof = Authenticated::granted_for_test();
    let headers = trailer_headers(WIRE.len());
    let ingest = signed_trailered(&headers);
    assert!(ingest.is_some(), "the signed trailer shape is implemented");
    let Some(ingest) = ingest else {
        return;
    };
    let integrity = BodyIntegrity::resolve(&HeaderView::new(&headers), ChecksumSubject::RequestBody).ok();
    let Some(integrity) = integrity else {
        return;
    };
    let (body, _) = crate::probe::ObservedBody::new([Bytes::from_static(WIRE)]);
    let opened = SealedBody::seal(Some(body), Some(WIRE.len() as u64))
        .stream(
            &proof,
            (BodyCeilings::streaming(None), BodyTimeouts::S3, None),
            Some(ingest),
            BodyDigestObligation::None,
            integrity,
        )
        .ok();
    let Some(opened) = opened else {
        return;
    };
    let (stream, terminal) = opened.into_parts();
    assert!(crate::wire::collect(http::Response::new(stream.into_body())).await.is_err());
    let refusal = terminal.wait().await.err();
    assert_eq!(
        refusal.as_ref().and_then(crate::render::S3Error::code),
        Some(&ErrorCode::SIGNATURE_DOES_NOT_MATCH)
    );
}

/// `c-ing-0061`. Negative — opening a stream does not poll its transport.
#[tokio::test]
async fn opening_a_streaming_body_does_not_read_ahead() {
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"first-"), Bytes::from_static(b"second")]);
    let opened = SealedBody::seal(Some(body), Some(12))
        .stream(
            &proof,
            (roomy(), BodyTimeouts::S3, None),
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .ok();
    assert!(opened.is_some(), "the streaming body did not open");
    let Some(opened) = opened else {
        return;
    };
    assert_eq!(read.bytes_read(), 0, "opening the handler stream polled the transport");
    let (stream, terminal) = opened.into_parts();
    let collected = crate::wire::collect(http::Response::new(stream.into_body())).await.ok();
    assert!(collected.is_some(), "the handler did not drain the stream");
    let Some(collected) = collected else {
        return;
    };
    assert_eq!(collected.body(), &Bytes::from_static(b"first-second"));
    assert!(terminal.wait().await.is_ok());
    assert!(read.is_exhausted());
}

/// `c-ing-0063`. Positive — logical size may exceed the resident window.
#[tokio::test]
async fn a_streaming_body_may_exceed_its_resident_window() {
    const FRAME_BYTES: usize = 768 * 1024;
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([
        Bytes::from(vec![b'a'; FRAME_BYTES]),
        Bytes::from(vec![b'b'; FRAME_BYTES]),
        Bytes::from(vec![b'c'; FRAME_BYTES]),
    ]);
    let opened = SealedBody::seal(Some(body), Some((3 * FRAME_BYTES) as u64))
        .stream(
            &proof,
            (BodyCeilings::streaming(None), BodyTimeouts::S3, None),
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .ok();
    assert!(opened.is_some(), "the large logical stream did not open");
    let Some(opened) = opened else {
        return;
    };
    let (stream, terminal) = opened.into_parts();
    let collected = crate::wire::collect(http::Response::new(stream.into_body())).await.ok();
    assert!(collected.is_some(), "the handler did not drain the stream");
    let Some(collected) = collected else {
        return;
    };
    assert_eq!(collected.body().len(), 3 * FRAME_BYTES);
    assert!(terminal.wait().await.is_ok());
    assert_eq!(read.bytes_read(), (3 * FRAME_BYTES) as u64);
}

/// `c-ing-0063`. Negative — one transport frame cannot widen the resident window.
#[tokio::test]
async fn a_streaming_frame_wider_than_the_resident_window_is_refused() {
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from(vec![0_u8; 1024 * 1024 + 1])]);
    let opened = SealedBody::seal(Some(body), None)
        .stream(
            &proof,
            (BodyCeilings::streaming(None), BodyTimeouts::S3, None),
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .ok();
    assert!(opened.is_some(), "the head-level stream did not open");
    let Some(opened) = opened else {
        return;
    };
    let (stream, terminal) = opened.into_parts();
    assert!(crate::wire::collect(http::Response::new(stream.into_body())).await.is_err());
    let error = terminal.wait().await.err();
    assert_eq!(error.as_ref().and_then(crate::render::S3Error::code), Some(&ErrorCode::ENTITY_TOO_LARGE));
    assert_eq!(read.bytes_read(), (1024 * 1024 + 1) as u64);
}

/// Negative — dropping before EOF cannot manufacture a successful terminal verdict.
#[tokio::test]
async fn dropping_an_unread_streaming_body_refuses_commit() {
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"body")]);
    let opened = SealedBody::seal(Some(body), Some(4))
        .stream(
            &proof,
            (roomy(), BodyTimeouts::S3, None),
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .ok();
    assert!(opened.is_some(), "the streaming body did not open");
    let Some(opened) = opened else {
        return;
    };
    let (stream, terminal) = opened.into_parts();
    drop(stream);
    let error = terminal.wait().await.err();
    assert_eq!(error.as_ref().and_then(crate::render::S3Error::code), Some(&ErrorCode::INCOMPLETE_BODY));
    assert_eq!(read.bytes_read(), 0, "dropping the stream drained the peer");
}
