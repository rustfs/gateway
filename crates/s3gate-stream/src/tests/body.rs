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

//! The body wrapper and the length-checking stream.
//!
//! Responsible for: proving that a body is a lossless container around a payload, that it
//! rejects a producer whose capability claims contradict its length, and that the length
//! checking of a byte stream cannot be bypassed by wrapping it in a body.
//! NOT responsible for: the trailer ordering property, which `eof_trailers` owns.
//! Upstream: `support`. Downstream: nothing.

use bytes::Bytes;

use crate::body::Body;
use crate::byte_stream::{ByteStream, RemainingLength};
use crate::caps::PayloadCaps;
use crate::metrics::StreamMetrics;
use crate::payload::Payload;
use crate::stream::PayloadStream;
use crate::tests::support::{ScriptedStream, Step, drain_stream, joined};
use crate::trailers::TrailingHeaders;

#[test]
fn an_empty_body_carries_no_bytes() {
    let body = Body::empty();

    assert!(body.is_empty());
    assert_eq!(body.len_hint(), Some(0));
    assert!(body.caps().contains(PayloadCaps::KNOWN_LENGTH));
    assert!(matches!(body.into_payload(), Payload::Empty));
}

#[test]
fn a_body_hands_its_payload_back_unchanged() {
    let body = Body::from_bytes(Bytes::from_static(b"twelve bytes"));

    assert_eq!(body.len_hint(), Some(12));
    assert!(!body.is_empty());
    assert_eq!(body.payload().len_hint(), Some(12));

    let payload = body.into_payload();
    let (chunks, _) = drain_stream(
        payload
            .try_into_stream(&StreamMetrics::new())
            .expect("in-memory payload converts")
            .0,
    )
    .expect("body ends cleanly");
    assert_eq!(joined(&chunks), b"twelve bytes");
}

#[test]
fn a_body_from_empty_bytes_normalises_to_the_empty_payload() {
    let body = Body::from_bytes(Bytes::new());
    assert!(matches!(body.into_payload(), Payload::Empty));

    let body = Body::from_segments([Bytes::new(), Bytes::new()]);
    assert!(matches!(body.into_payload(), Payload::Empty));
}

/// A producer whose capability claims contradict its length hint is refused at the boundary,
/// so no consumer downstream ever sees the contradiction.
#[test]
fn a_body_refuses_a_producer_with_inconsistent_capabilities() {
    let err = Body::from_stream(
        ScriptedStream::new([Step::Eof(TrailingHeaders::empty())])
            .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
            .with_len_hint(None),
    )
    .expect_err("the claim contradicts the hint");

    assert!(err.caps.contains(PayloadCaps::KNOWN_LENGTH));
    assert!(!err.has_len_hint);
}

#[test]
fn a_byte_stream_reports_what_is_left() {
    let stream = ByteStream::from_bytes(Bytes::from_static(b"onetwo"));

    assert_eq!(stream.remaining_length(), RemainingLength::exact(6));
    assert!(stream.remaining_length().is_known());
    assert_eq!(stream.observed_length(), 0);
}

#[test]
fn an_unknown_remaining_length_is_not_zero() {
    let unknown = RemainingLength::unknown();

    assert!(!unknown.is_known());
    assert_eq!(unknown.get(), None);
    assert_ne!(unknown, RemainingLength::exact(0));
    assert_eq!(RemainingLength::from(Some(3)), RemainingLength::exact(3));
}

/// Wrapping a length-checked stream in a body keeps the check: the inner producer is private,
/// so there is no way to read past it.
#[test]
fn wrapping_a_byte_stream_in_a_body_keeps_the_length_check() {
    let inner = ScriptedStream::new([Step::Chunk("abc"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
        .with_len_hint(Some(9))
        .boxed();

    let body = ByteStream::new(inner).expect("caps are consistent").into_body();

    assert_eq!(body.len_hint(), Some(9));

    let (stream, cost) = body
        .into_payload()
        .try_into_stream(&StreamMetrics::new())
        .expect("a push body stays a push body");
    assert!(cost.is_free());

    let err = drain_stream(stream).expect_err("a short body must fail");
    assert!(matches!(err.kind(), crate::error::StreamErrorKind::IncompleteBody));
}

#[test]
fn a_byte_stream_without_a_declared_length_accepts_any_length() {
    let inner = ScriptedStream::new([Step::Chunk("abc"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PUSH)
        .with_len_hint(None)
        .boxed();

    let stream = ByteStream::new(inner).expect("caps are consistent");
    assert!(!stream.remaining_length().is_known());
    assert!(!stream.caps().contains(PayloadCaps::KNOWN_LENGTH));

    let (chunks, _) = drain_stream(Box::pin(stream)).expect("body ends cleanly");
    assert_eq!(joined(&chunks), b"abc");
}

#[test]
fn a_body_converts_from_and_into_a_payload() {
    let body: Body = Bytes::from_static(b"four").into();
    let payload: Payload = body.into();
    assert_eq!(payload.len_hint(), Some(4));

    let body: Body = payload.into();
    assert_eq!(body.len_hint(), Some(4));

    let body: Body = vec![1u8, 2, 3].into();
    assert_eq!(body.len_hint(), Some(3));
}
