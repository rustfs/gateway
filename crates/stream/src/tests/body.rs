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
use http_body::Body as _;

use crate::body::Body;
use crate::byte_stream::{ByteStream, RemainingLength};
use crate::caps::PayloadCaps;
use crate::payload::Payload;
use crate::stream::PayloadStream;
use crate::tests::support::{ScriptedStream, Step, drain_stream, joined};
use crate::trailers::TrailingHeaders;
use crate::zero_copy::VerificationObligation;

#[test]
fn an_empty_body_carries_no_bytes() {
    let body = Body::empty();

    assert!(body.is_empty());
    assert_eq!(body.len_hint(), Some(0));
    assert!(body.caps().contains(PayloadCaps::KNOWN_LENGTH));
    assert!(body.is_empty());
}

#[test]
fn a_body_hands_its_payload_back_unchanged() {
    let body = Body::from_bytes(Bytes::from_static(b"twelve bytes"));

    assert_eq!(body.len_hint(), Some(12));
    assert!(!body.is_empty());
    assert_eq!(body.len_hint(), Some(12));

    let segments = body.try_as_vectored().expect("in-memory body stays vectored");
    assert_eq!(segments, &[Bytes::from_static(b"twelve bytes")]);
}

#[test]
fn a_body_from_empty_bytes_normalises_to_the_empty_payload() {
    let body = Body::from_bytes(Bytes::new());
    assert!(body.is_empty());

    let body = Body::from_segments([Bytes::new(), Bytes::new()]);
    assert!(body.is_empty());
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

    let metrics = std::sync::Arc::clone(body.stream_metrics());
    let mut body = body.into_transport().into_body();
    let waker = std::task::Waker::noop();
    let mut context = core::task::Context::from_waker(waker);
    let first = core::pin::Pin::new(&mut body).poll_frame(&mut context);
    assert!(matches!(first, core::task::Poll::Ready(Some(Ok(_)))));
    let second = core::pin::Pin::new(&mut body).poll_frame(&mut context);
    let core::task::Poll::Ready(Some(Err(err))) = second else { panic!("a short body must fail") };
    assert!(matches!(err.kind(), crate::error::StreamErrorKind::IncompleteBody));
    assert_eq!(metrics.adapt_copies_total(), 0);
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
fn a_body_converts_from_payload_forms() {
    let body: Body = Bytes::from_static(b"four").into();
    assert_eq!(body.len_hint(), Some(4));

    let payload = Payload::from_bytes(Bytes::from_static(b"four"));
    let body: Body = payload.into();
    assert_eq!(body.len_hint(), Some(4));

    let body: Body = vec![1u8, 2, 3].into();
    assert_eq!(body.len_hint(), Some(3));
}

#[test]
fn response_transport_ownership_cannot_downgrade_an_outstanding_obligation() {
    let body = Body::from_bytes(Bytes::from_static(b"observed"))
        .requiring_verification()
        .into_transport()
        .into_body();

    assert_eq!(body.verification_obligation(), VerificationObligation::Present);
    assert_eq!(body.len_hint(), Some(8));
}

#[cfg(unix)]
#[test]
fn a_refused_transport_returns_the_obligated_body_without_a_lossy_tuple() {
    use crate::tests::pay_cases::file_payload;
    use crate::zero_copy::{NoZeroCopy, TransportCaps};

    let refused = Body::from_payload(file_payload(8))
        .requiring_verification()
        .into_transport()
        .try_into_file_region_for(TransportCaps::SENDFILE)
        .expect_err("verification must refuse kernel transfer");

    assert_eq!(refused.reason(), NoZeroCopy::VerificationObligationPresent);
    assert_eq!(refused.into_body().verification_obligation(), VerificationObligation::Present);
}
