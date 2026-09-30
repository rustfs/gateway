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

//! Tests for the RustFS profile's trailer hand-off and its upload checksum algorithm
//! (rustfs/gateway#1148).
//!
//! Responsible for: the handle's three states and their timing against the body that fills it,
//! which requests the legacy stack attaches one to, and the checksum algorithm read as the legacy
//! decoder reads it, refusals included. NOT responsible for: what either stack hands a handler for
//! a signed upload end to end (the goldens body parity diff) or member by member (the difftest
//! seam diff). Upstream: `super::trailers`, `super::leaf`. Downstream: none; test-only.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::pin::Pin;
use core::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use rustfs_gateway_stream::{
    ByteStream, MemoryStream, PayloadCaps, PayloadRead, PayloadStream, StreamError, StreamErrorKind, TrailingHeaders,
};

use super::error::{LEGACY_DUPLICATE_HEADER, LEGACY_INVALID_HEADER, Refusal, refusal_from_conversion};
use super::trailers::{LegacyTrailers, legacy_attaches_trailers, legacy_checksum_algorithm};

const CRC32: &str = "x-amz-checksum-crc32";
const SIGNATURE: &str = "x-amz-trailer-signature";

fn section(fields: &[(&'static str, &'static str)]) -> TrailingHeaders {
    let mut map = HeaderMap::new();
    for (name, value) in fields {
        map.append(*name, HeaderValue::from_static(value));
    }
    TrailingHeaders::from_header_map(map)
}

/// A handle, and the body that fills it.
fn publishing(body: ByteStream) -> (ByteStream, LegacyTrailers) {
    let trailers = LegacyTrailers::default();
    (trailers.publishing(body), trailers)
}

fn body(chunks: &[&'static [u8]], trailers: TrailingHeaders) -> ByteStream {
    let segments: Vec<Bytes> = chunks.iter().map(|chunk| Bytes::from_static(chunk)).collect();
    ByteStream::new(Box::pin(MemoryStream::new(segments, trailers))).expect("an in-memory body")
}

/// One read, a failure as its kind's name.
fn read(stream: &mut ByteStream) -> Result<PayloadRead, String> {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    match Pin::new(stream).poll_read(&mut cx) {
        Poll::Ready(result) => result.map_err(|error| format!("{:?}", error.kind())),
        Poll::Pending => panic!("an in-memory body is never pending"),
    }
}

fn fields(trailers: &LegacyTrailers) -> Option<Vec<(String, String)>> {
    trailers.read(|map| {
        map.iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap_or_default().to_owned()))
            .collect()
    })
}

#[test]
fn the_handle_is_filled_with_the_section_at_the_end_the_reader_is_handed_and_not_before() {
    let (mut stream, trailers) = publishing(body(&[b"hel", b"lo"], section(&[(CRC32, "NhCmhg=="), (SIGNATURE, "abc")])));
    assert_eq!(stream.len_hint(), Some(5));
    assert!(stream.caps().contains(PayloadCaps::KNOWN_LENGTH));
    for expected in [&b"hel"[..], b"lo"] {
        assert!(!trailers.is_ready(), "the handle fills only at the end");
        assert!(matches!(read(&mut stream), Ok(PayloadRead::Chunk(chunk)) if chunk == expected));
    }
    assert!(!trailers.is_ready());
    match read(&mut stream) {
        // The reader is handed the end with no section of its own: the handle holds it.
        Ok(PayloadRead::Eof { trailers: handed }) => assert!(handed.is_empty()),
        other => panic!("expected the end, got {other:?}"),
    }
    assert!(trailers.is_ready());
    // Every field but the signature, as the legacy handle holds it.
    assert_eq!(fields(&trailers), Some(vec![(CRC32.to_owned(), "NhCmhg==".to_owned())]));
}

#[test]
fn clones_share_one_section_which_is_read_in_place_or_taken_once() {
    let (mut stream, trailers) = publishing(body(&[b"x"], section(&[(CRC32, "AAAAAA==")])));
    let reader = trailers.clone();
    while !matches!(read(&mut stream), Ok(PayloadRead::Eof { .. })) {}
    assert_eq!(fields(&reader), fields(&trailers), "a clone reads the same section");
    assert_eq!(fields(&trailers).map(|fields| fields.len()), Some(1), "reading leaves it in place");
    let taken = reader.take().expect("taken once");
    assert_eq!(taken.get(CRC32).map(HeaderValue::as_bytes), Some(&b"AAAAAA=="[..]));
    assert!(trailers.take().is_none() && !trailers.is_ready(), "a second take finds nothing");
}

/// The legacy stack leaves its handle unfilled for good when the body ends without a section (an
/// aws-chunked upload that declares no trailer), and fills it with no field when the section held
/// only the signature. RustFS reads the two apart, so each is kept.
#[test]
fn a_body_without_a_section_leaves_the_handle_unfilled_and_a_signature_alone_fills_it_empty() {
    let (mut stream, trailers) = publishing(body(&[b"x"], TrailingHeaders::empty()));
    while !matches!(read(&mut stream), Ok(PayloadRead::Eof { .. })) {}
    assert!(!trailers.is_ready());
    assert_eq!(fields(&trailers), None);

    let (mut stream, trailers) = publishing(body(&[b"x"], section(&[(SIGNATURE, "abc")])));
    while !matches!(read(&mut stream), Ok(PayloadRead::Eof { .. })) {}
    assert!(trailers.is_ready());
    assert_eq!(fields(&trailers), Some(Vec::new()));
}

/// A body that fails is the body's own failure, and its handle stays unfilled.
#[test]
fn n_a_failing_body_fails_through_the_wrapper_and_fills_nothing() {
    struct Failing(bool);
    impl PayloadStream for Failing {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
            let this = self.get_mut();
            if this.0 {
                return Poll::Ready(Err(StreamError::new(StreamErrorKind::IncompleteBody)));
            }
            this.0 = true;
            Poll::Ready(Ok(PayloadRead::Chunk(Bytes::from_static(b"x"))))
        }
        fn caps(&self) -> PayloadCaps {
            PayloadCaps::empty()
        }
        fn len_hint(&self) -> Option<u64> {
            None
        }
    }
    let (mut stream, trailers) = publishing(ByteStream::new(Box::pin(Failing(false))).expect("no length"));
    assert_eq!(stream.len_hint(), None);
    assert!(matches!(read(&mut stream), Ok(PayloadRead::Chunk(_))));
    assert_eq!(read(&mut stream).map(|_| ()), Err("IncompleteBody".to_owned()));
    assert!(!trailers.is_ready());
}

fn content_sha256(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-content-sha256", HeaderValue::from_static(value));
    headers
}

/// Every aws-chunked payload the legacy decoder reads gets a handle when the request was verified
/// as SigV4, whether or not it declares a trailer; nothing else does.
#[test]
fn the_legacy_stack_attaches_a_handle_to_exactly_a_sigv4_aws_chunked_request() {
    for streaming in [
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD",
        "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER",
    ] {
        assert!(legacy_attaches_trailers(true, &content_sha256(streaming)), "{streaming}");
        // Anonymous, or SigV2: no scope was verified, and the legacy stack decodes no framing.
        assert!(!legacy_attaches_trailers(false, &content_sha256(streaming)), "{streaming}");
    }
    for plain in [
        "UNSIGNED-PAYLOAD",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "streaming-unsigned-payload-trailer",
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER ",
    ] {
        assert!(!legacy_attaches_trailers(true, &content_sha256(plain)), "{plain}");
    }
    assert!(!legacy_attaches_trailers(true, &HeaderMap::new()));
}

fn headers(lines: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in lines {
        headers.append(*name, HeaderValue::from_static(value));
    }
    headers
}

fn algorithm(lines: &[(&'static str, &'static str)]) -> Option<String> {
    legacy_checksum_algorithm(&headers(lines))
        .expect("read")
        .map(|algorithm| algorithm.as_str().to_owned())
}

#[test]
fn the_checksum_algorithm_is_read_from_its_header_then_from_the_trailer_declaration() {
    assert_eq!(algorithm(&[]), None);
    assert_eq!(algorithm(&[("x-amz-checksum-algorithm", "SHA256")]), Some("SHA256".to_owned()));
    // The header's value as sent, whatever it names, wins over the declaration.
    assert_eq!(
        algorithm(&[
            ("x-amz-checksum-algorithm", "crc32"),
            ("x-amz-trailer", "x-amz-checksum-sha1")
        ]),
        Some("crc32".to_owned())
    );
    // An empty header is no header.
    assert_eq!(
        algorithm(&[("x-amz-checksum-algorithm", ""), ("x-amz-trailer", "x-amz-checksum-sha1")]),
        Some("SHA1".to_owned())
    );
    for (declared, expected) in [
        ("x-amz-checksum-crc32", Some("CRC32")),
        ("X-Amz-Checksum-CRC32C", Some("CRC32C")),
        (" x-amz-checksum-crc64nvme ", Some("CRC64NVME")),
        ("x-amz-meta-foo, x-amz-checksum-sha512", Some("SHA512")),
        ("x-amz-checksum-xxhash3,,x-amz-meta-foo", Some("XXHASH3")),
        ("x-amz-checksum-md5", Some("MD5")),
        ("x-amz-checksum-xxhash64", Some("XXHASH64")),
        ("x-amz-checksum-xxhash128", Some("XXHASH128")),
        ("x-amz-checksum-sha256", Some("SHA256")),
        ("x-amz-meta-foo", None),
        ("", None),
    ] {
        assert_eq!(algorithm(&[("x-amz-trailer", declared)]), expected.map(str::to_owned), "{declared:?}");
    }
    // The header the model binds is not read: legacy RustFS never read it into the member.
    assert_eq!(algorithm(&[("x-amz-sdk-checksum-algorithm", "CRC32")]), None);
}

#[test]
fn n_a_checksum_algorithm_the_legacy_decoder_refuses_is_refused_as_it_answers() {
    for (lines, field, reason) in [
        (
            &[("x-amz-checksum-algorithm", "CRC32"), ("x-amz-checksum-algorithm", "CRC32")][..],
            "x-amz-checksum-algorithm",
            LEGACY_DUPLICATE_HEADER,
        ),
        (
            &[
                ("x-amz-trailer", "x-amz-checksum-crc32"),
                ("x-amz-trailer", "x-amz-checksum-crc32"),
            ][..],
            "x-amz-trailer",
            LEGACY_DUPLICATE_HEADER,
        ),
        (
            &[("x-amz-trailer", "x-amz-checksum-crc32, x-amz-checksum-sha1")][..],
            "x-amz-trailer",
            LEGACY_INVALID_HEADER,
        ),
        (
            &[("x-amz-trailer", "x-amz-checksum-crc32,X-AMZ-CHECKSUM-CRC32")][..],
            "x-amz-trailer",
            LEGACY_INVALID_HEADER,
        ),
    ] {
        let error = legacy_checksum_algorithm(&headers(lines)).expect_err("refused");
        assert_eq!((error.field, error.reason), (field, reason), "{lines:?}");
    }
    let mut unreadable = HeaderMap::new();
    unreadable.insert(
        "x-amz-checksum-algorithm",
        HeaderValue::from_bytes(b"CRC\xff").expect("an obs-text value"),
    );
    let error = legacy_checksum_algorithm(&unreadable).expect_err("not text");
    assert_eq!((error.field, error.reason), ("x-amz-checksum-algorithm", LEGACY_INVALID_HEADER));
    // Each is answered as the legacy decoder answers it, before any RustFS body.
    match refusal_from_conversion(&error) {
        Some(Refusal::Ordinary { code, .. }) => assert_eq!(code.as_str(), "InvalidArgument"),
        other => panic!("expected the legacy decoder's refusal, got {other:?}"),
    }
}
