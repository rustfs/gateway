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

//! The trailer ordering property, stated as tests.
//!
//! Responsible for: proving that a trailer section arrives only with an end-of-stream event,
//! that a truncated body fails instead of reporting end-of-stream, that a terminated body never
//! produces another chunk, and that both properties survive an adaptation between the models.
//! NOT responsible for: which trailer names are acceptable, or what their values mean.
//! Upstream: `support`. Downstream: nothing.

use bytes::Bytes;

use crate::adapt::{ReaderToStream, StreamToReader};
use crate::caps::PayloadCaps;
use crate::error::StreamErrorKind;
use crate::metrics::StreamMetrics;
use crate::payload::Payload;
use crate::read::ReadProgress;
use crate::stream::PayloadRead;
use crate::tests::support::{
    ScriptedReader, ScriptedStream, Step, drain_reader, drain_stream, joined, poll_reader_once, poll_stream_once, trailer_value,
    trailers,
};
use crate::trailers::TrailingHeaders;

/// c-stream-0001: a body with no trailer still ends with one end-of-stream event, carrying an
/// empty map rather than an absent one.
#[test]
fn three_chunks_without_trailers_end_with_an_empty_trailer_section() {
    let stream = ScriptedStream::new([
        Step::Chunk("one"),
        Step::Chunk("two"),
        Step::Chunk("three"),
        Step::Eof(TrailingHeaders::empty()),
    ])
    .boxed();

    let (chunks, trailers) = drain_stream(stream).expect("body ends cleanly");

    assert_eq!(chunks.len(), 3);
    assert_eq!(joined(&chunks), b"onetwothree");
    assert!(trailers.is_empty());
    assert_eq!(trailers.len(), 0);
}

/// c-stream-0002: a declared trailer field is readable from the end-of-stream event.
#[test]
fn a_declared_trailer_field_is_readable_at_end_of_stream() {
    let stream = ScriptedStream::new([
        Step::Chunk("payload"),
        Step::Eof(trailers(&[("x-trailer-value", "AAAAAA==")])),
    ])
    .boxed();

    let (_, trailers) = drain_stream(stream).expect("body ends cleanly");

    assert_eq!(trailers.len(), 1);
    assert_eq!(trailer_value(&trailers, "x-trailer-value").as_deref(), Some("AAAAAA=="));
}

/// c-stream-n014: a zero-byte body with a trailer goes straight to end-of-stream; an empty
/// chunk would make "there is more coming" indistinguishable from "the body is over".
#[test]
fn an_empty_body_with_a_trailer_emits_no_chunk() {
    let mut stream = ScriptedStream::new([Step::Eof(trailers(&[("x-trailer-value", "AAAAAA==")]))]).boxed();

    let event = match poll_stream_once(&mut stream) {
        core::task::Poll::Ready(Ok(event)) => event,
        other => panic!("the first event must be ready and clean, got {other:?}"),
    };

    assert!(event.is_eof(), "first event must be end-of-stream");
    assert_eq!(event.byte_len(), 0);
}

/// c-stream-n001: a body that is cut off before its trailer section fails; it must never report
/// end-of-stream, which is what would let a partially received body be accepted as whole.
#[test]
fn a_body_truncated_before_its_trailer_fails_instead_of_ending() {
    let stream = ScriptedStream::new([Step::Chunk("half a bo"), Step::Fail(StreamErrorKind::IncompleteBody)]).boxed();

    let err = drain_stream(stream).expect_err("truncation must fail");

    assert!(matches!(err.kind(), StreamErrorKind::IncompleteBody));
    assert_eq!(err.bytes_before_error(), 9);
}

/// c-stream-n001, pull side: the same truncation seen through the pull model, including across
/// the adapter, so the property cannot be lost by converting the body.
#[test]
fn a_truncated_body_still_fails_after_adapting_to_the_pull_model() {
    let stream = ScriptedStream::new([Step::Chunk("half a bo"), Step::Fail(StreamErrorKind::IncompleteBody)]).boxed();

    let reader = Box::pin(StreamToReader::new(stream));
    let err = drain_reader(reader, 4).expect_err("truncation must fail");

    assert!(matches!(err.kind(), StreamErrorKind::IncompleteBody));
    assert_eq!(err.bytes_before_error(), 9);
}

/// c-stream-n002: once a body has reported end-of-stream, polling it again is an error and
/// never yields another chunk.
#[test]
fn polling_after_end_of_stream_never_yields_another_chunk() {
    let (mut stream, _) = Payload::from_bytes(Bytes::from_static(b"body"))
        .try_into_stream(&StreamMetrics::new())
        .expect("in-memory payload converts");

    let first = poll_stream_once(&mut stream);
    assert!(matches!(first.map(|r| r.expect("chunk")), core::task::Poll::Ready(PayloadRead::Chunk(_))));

    let second = poll_stream_once(&mut stream);
    assert!(matches!(
        second.map(|r| r.expect("end of stream")),
        core::task::Poll::Ready(PayloadRead::Eof { .. })
    ));

    let third = poll_stream_once(&mut stream);
    let err = match third {
        core::task::Poll::Ready(Err(err)) => err,
        other => panic!("a terminated body must fail, got {other:?}"),
    };
    assert!(matches!(err.kind(), StreamErrorKind::PolledAfterEof));
}

/// c-stream-n002, pull side.
#[test]
fn filling_after_end_of_stream_never_yields_more_bytes() {
    let (mut reader, _) = Payload::from_bytes(Bytes::from_static(b"body"))
        .try_into_reader(&StreamMetrics::new())
        .expect("in-memory payload converts");

    let mut buf = [0u8; 8];
    let first = poll_reader_once(&mut reader, &mut buf);
    assert!(matches!(first, core::task::Poll::Ready(Ok(ReadProgress::Filled(4)))));

    let second = poll_reader_once(&mut reader, &mut buf);
    assert!(matches!(second, core::task::Poll::Ready(Ok(ReadProgress::Eof { .. }))));

    let third = poll_reader_once(&mut reader, &mut buf);
    let err = match third {
        core::task::Poll::Ready(Err(err)) => err,
        other => panic!("a terminated body must fail, got {other:?}"),
    };
    assert!(matches!(err.kind(), StreamErrorKind::PolledAfterEof));
}

/// c-stream-n003: a mid-body failure reports how many bytes had already been handed over, so
/// the layer above can decide what it may still commit.
#[test]
fn a_mid_body_failure_reports_the_bytes_already_delivered() {
    let stream = ScriptedStream::new([
        Step::Chunk("abcd"),
        Step::Chunk("efg"),
        Step::Fail(StreamErrorKind::Io(std::io::Error::other("peer reset"))),
    ])
    .boxed();

    let err = drain_stream(stream).expect_err("i/o failure propagates");

    assert!(matches!(err.kind(), StreamErrorKind::Io(_)));
    assert_eq!(err.bytes_before_error(), 7);
}

/// A `Pending` in the middle of a body does not disturb the ordering.
#[test]
fn a_pending_poll_does_not_change_the_event_order() {
    let stream = ScriptedStream::new([
        Step::Chunk("one"),
        Step::Pending,
        Step::Chunk("two"),
        Step::Eof(trailers(&[("x-trailer-value", "AAAAAA==")])),
    ])
    .boxed();

    let (chunks, trailers) = drain_stream(stream).expect("body ends cleanly");

    assert_eq!(joined(&chunks), b"onetwo");
    assert_eq!(trailer_value(&trailers, "x-trailer-value").as_deref(), Some("AAAAAA=="));
}

/// The trailer section survives a push-to-pull adaptation unchanged.
#[test]
fn trailers_survive_a_push_to_pull_adaptation() {
    let stream = ScriptedStream::new([
        Step::Chunk("first"),
        Step::Chunk("second"),
        Step::Eof(trailers(&[("x-trailer-value", "BBBBBB==")])),
    ])
    .boxed();

    let reader = Box::pin(StreamToReader::new(stream));
    let (bytes, trailers) = drain_reader(reader, 3).expect("body ends cleanly");

    assert_eq!(bytes, b"firstsecond");
    assert_eq!(trailer_value(&trailers, "x-trailer-value").as_deref(), Some("BBBBBB=="));
}

/// The trailer section survives a pull-to-push adaptation unchanged.
#[test]
fn trailers_survive_a_pull_to_push_adaptation() {
    let reader = ScriptedReader::new([
        Step::Chunk("first"),
        Step::Chunk("second"),
        Step::Eof(trailers(&[("x-trailer-value", "CCCCCC==")])),
    ])
    .boxed();

    let stream = Box::pin(ReaderToStream::new(reader).with_chunk_size(4));
    let (chunks, trailers) = drain_stream(stream).expect("body ends cleanly");

    assert_eq!(joined(&chunks), b"firstsecond");
    assert_eq!(trailer_value(&trailers, "x-trailer-value").as_deref(), Some("CCCCCC=="));
}

/// A pull-model body that fails mid-body still fails after being adapted to the push model, and
/// the byte count set by the original producer is preserved rather than replaced.
#[test]
fn a_failure_keeps_its_byte_count_across_an_adaptation() {
    let reader = ScriptedReader::new([Step::Chunk("abcdef"), Step::Fail(StreamErrorKind::IncompleteBody)]).boxed();

    let stream = Box::pin(ReaderToStream::new(reader).with_chunk_size(2));
    let err = drain_stream(stream).expect_err("truncation must fail");

    assert!(matches!(err.kind(), StreamErrorKind::IncompleteBody));
    assert_eq!(err.bytes_before_error(), 6);
}

/// A producer that declares more bytes than it delivers fails as incomplete when wrapped in a
/// length-checking stream, even though its own end-of-stream event was well formed.
#[test]
fn a_body_shorter_than_declared_is_incomplete() {
    let inner = ScriptedStream::new([Step::Chunk("abc"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
        .with_len_hint(Some(10))
        .boxed();

    let stream = crate::byte_stream::ByteStream::new(inner).expect("caps are consistent");
    let err = drain_stream(Box::pin(stream)).expect_err("a short body must fail");

    assert!(matches!(err.kind(), StreamErrorKind::IncompleteBody));
    assert_eq!(err.bytes_before_error(), 3);
}

/// A producer that delivers more bytes than it declared fails as a length mismatch.
#[test]
fn a_body_longer_than_declared_is_a_length_mismatch() {
    let inner = ScriptedStream::new([Step::Chunk("abc"), Step::Chunk("defgh"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
        .with_len_hint(Some(4))
        .boxed();

    let stream = crate::byte_stream::ByteStream::new(inner).expect("caps are consistent");
    let err = drain_stream(Box::pin(stream)).expect_err("an overlong body must fail");

    assert!(matches!(
        err.kind(),
        StreamErrorKind::LengthMismatch {
            declared: 4,
            observed: 8
        }
    ));
}

/// The remaining length of a length-checked stream shrinks as the body is delivered.
#[test]
fn remaining_length_shrinks_as_the_body_arrives() {
    let inner = ScriptedStream::new([Step::Chunk("abc"), Step::Chunk("de"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
        .with_len_hint(Some(5))
        .boxed();

    let mut stream: crate::stream::BoxPayloadStream =
        Box::pin(crate::byte_stream::ByteStream::new(inner).expect("caps are consistent"));

    assert_eq!(stream.len_hint(), Some(5));
    let _ = poll_stream_once(&mut stream);
    assert_eq!(stream.len_hint(), Some(2));
    let _ = poll_stream_once(&mut stream);
    assert_eq!(stream.len_hint(), Some(0));
}
