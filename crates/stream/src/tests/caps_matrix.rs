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

//! Every payload shape against every way of consuming it.
//!
//! Responsible for: the capability bits each variant advertises, the negotiation calls that
//! must refuse without consuming the body, and the round trip of the bytes through both models.
//! NOT responsible for: what an adaptation costs — that is the sibling module.
//! Upstream: `support`. Downstream: nothing.

use bytes::Bytes;

use crate::caps::{PayloadCaps, validate_caps};
use crate::metrics::StreamMetrics;
use crate::payload::{AdaptRefusal, Payload};
use crate::tests::support::{ScriptedReader, ScriptedStream, Step, drain_reader, drain_stream, joined};
use crate::trailers::TrailingHeaders;
use crate::zero_copy::NoZeroCopy;

const IN_MEMORY_CAPS: PayloadCaps = PayloadCaps::KNOWN_LENGTH
    .union(PayloadCaps::SEEKABLE)
    .union(PayloadCaps::REPLAYABLE)
    .union(PayloadCaps::IN_MEMORY)
    .union(PayloadCaps::VECTORED)
    .union(PayloadCaps::PULL)
    .union(PayloadCaps::PUSH);

#[cfg(unix)]
fn file_region(len: u64) -> crate::file_region::FileRegion {
    use std::os::fd::OwnedFd;

    let file = std::fs::File::open("/dev/null").expect("/dev/null is readable");
    crate::file_region::FileRegion::new(OwnedFd::from(file), 0, len).expect("the region does not overflow")
}

#[test]
fn an_empty_payload_is_in_memory_and_zero_length() {
    let payload = Payload::Empty;
    assert_eq!(payload.caps(), IN_MEMORY_CAPS);
    assert_eq!(payload.len_hint(), Some(0));
    assert!(payload.is_empty());
    assert_eq!(payload.try_as_vectored(), Some(&[][..]));
}

#[test]
fn a_bytes_payload_is_in_memory_and_of_known_length() {
    let payload = Payload::from_bytes(Bytes::from_static(b"twelve bytes"));
    assert_eq!(payload.caps(), IN_MEMORY_CAPS);
    assert_eq!(payload.len_hint(), Some(12));
    assert_eq!(payload.try_as_vectored().map(<[Bytes]>::len), Some(1));
}

#[test]
fn a_vectored_payload_reports_its_segments() {
    let payload = Payload::from_segments([
        Bytes::from_static(b"one"),
        Bytes::from_static(b""),
        Bytes::from_static(b"two"),
    ]);
    assert_eq!(payload.caps(), IN_MEMORY_CAPS);
    assert_eq!(payload.len_hint(), Some(6));
    assert_eq!(payload.try_as_vectored().map(<[Bytes]>::len), Some(2));
}

/// c-stream-0003: a file payload advertises the kernel-side transfer bit together with a known
/// length and seekability.
#[cfg(unix)]
#[test]
fn a_file_payload_advertises_the_file_region_capability() {
    let payload = Payload::File(file_region(4096));
    let caps = payload.caps();

    assert!(caps.contains(PayloadCaps::FILE_REGION | PayloadCaps::KNOWN_LENGTH | PayloadCaps::SEEKABLE));
    assert_eq!(payload.len_hint(), Some(4096));
    assert!(!caps.contains(PayloadCaps::IN_MEMORY));
}

#[test]
fn a_reader_payload_advertises_the_pull_model() {
    let payload = Payload::from_reader(
        ScriptedReader::new([Step::Eof(TrailingHeaders::empty())])
            .with_caps(PayloadCaps::PULL | PayloadCaps::KNOWN_LENGTH)
            .with_len_hint(Some(0)),
    )
    .expect("caps are consistent");

    assert!(payload.caps().contains(PayloadCaps::PULL));
    assert!(!payload.caps().contains(PayloadCaps::PUSH));
    assert_eq!(payload.try_as_vectored(), None);
}

#[test]
fn a_stream_payload_advertises_the_push_model() {
    let payload = Payload::from_stream(ScriptedStream::new([Step::Eof(TrailingHeaders::empty())]).with_caps(PayloadCaps::PUSH))
        .expect("caps are consistent");

    assert!(payload.caps().contains(PayloadCaps::PUSH));
    assert!(!payload.caps().contains(PayloadCaps::PULL));
    assert_eq!(payload.try_as_vectored(), None);
}

/// c-stream-0004: refusing a file region hands the payload back whole, so no data is lost by
/// asking for a fast path that is not available.
#[test]
fn an_in_memory_payload_refuses_a_file_region_and_comes_back_whole() {
    let payload = Payload::from_bytes(Bytes::from_static(b"still here"));

    let (returned, reason) = payload
        .try_into_file_region()
        .expect_err("an in-memory payload is not a file region");

    assert_eq!(reason, NoZeroCopy::NotFileBacked);
    assert_eq!(returned.len_hint(), Some(10));
    let (bytes, _) = drain_reader(
        returned
            .try_into_reader(&StreamMetrics::new())
            .expect("in-memory payload converts")
            .0,
        4,
    )
    .expect("body ends cleanly");
    assert_eq!(bytes, b"still here");
}

/// c-stream-n010: the same for a producer-driven payload — the refusal must not consume it,
/// because a producer-driven body cannot be produced twice.
#[test]
fn a_reader_payload_refuses_a_file_region_and_stays_readable() {
    let payload = Payload::from_reader(
        ScriptedReader::new([Step::Chunk("intact"), Step::Eof(TrailingHeaders::empty())]).with_caps(PayloadCaps::PULL),
    )
    .expect("caps are consistent");

    let (returned, reason) = payload.try_into_file_region().expect_err("a reader is not a file region");
    assert_eq!(reason, NoZeroCopy::NotFileBacked);

    let (reader, _) = returned
        .try_into_reader(&StreamMetrics::new())
        .expect("a reader converts to the pull model");
    let (bytes, _) = drain_reader(reader, 3).expect("body ends cleanly");
    assert_eq!(bytes, b"intact");
}

/// A file payload cannot be turned into a byte stream here: doing so needs an i/o driver, and
/// the refusal says so by name instead of returning a bare `None`.
#[cfg(unix)]
#[test]
fn a_file_payload_refuses_both_models_with_a_named_reason() {
    let metrics = StreamMetrics::new();

    let Err((payload, refusal)) = Payload::File(file_region(1)).try_into_reader(&metrics) else {
        panic!("a file region needs an i/o driver to be read");
    };
    assert_eq!(refusal, AdaptRefusal::NeedsIoDriver);

    let Err((payload, refusal)) = payload.try_into_stream(&metrics) else {
        panic!("a file region needs an i/o driver to be read");
    };
    assert_eq!(refusal, AdaptRefusal::NeedsIoDriver);

    assert!(payload.try_into_file_region().is_ok(), "still a file region");
    assert_eq!(metrics.adapt_copies_total(), 0);
    assert_eq!(metrics.adapt_buffers_total(), 0);
}

/// c-stream-n012: a producer that claims a known length without providing one is rejected where
/// it enters the system, not where a consumer trusts the claim.
#[test]
fn a_producer_claiming_a_known_length_without_one_is_rejected() {
    let err = Payload::from_stream(
        ScriptedStream::new([Step::Eof(TrailingHeaders::empty())])
            .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
            .with_len_hint(None),
    )
    .expect_err("the claim contradicts the hint");

    assert!(!err.has_len_hint);
    assert!(err.caps.contains(PayloadCaps::KNOWN_LENGTH));
}

/// The mirror case: a producer that knows its length but hides the bit is also rejected, since
/// every consumer that reads the bits would silently take the slow path.
#[test]
fn a_producer_hiding_a_known_length_is_rejected() {
    let err = Payload::from_reader(
        ScriptedReader::new([Step::Eof(TrailingHeaders::empty())])
            .with_caps(PayloadCaps::PULL)
            .with_len_hint(Some(7)),
    )
    .expect_err("the hint contradicts the claim");

    assert!(err.has_len_hint);
    assert!(!err.caps.contains(PayloadCaps::KNOWN_LENGTH));
}

#[test]
fn consistent_capability_declarations_are_accepted() {
    assert!(validate_caps(PayloadCaps::PUSH, None).is_ok());
    assert!(validate_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH, Some(0)).is_ok());
    assert!(validate_caps(PayloadCaps::PUSH, Some(1)).is_err());
    assert!(validate_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH, None).is_err());
}

/// The matrix itself: every payload shape that carries bytes, consumed through both models,
/// yields the same bytes and the same end-of-stream event.
#[test]
fn every_byte_carrying_payload_reads_the_same_through_both_models() {
    let expected: &[u8] = b"onetwo";

    /// One named row of the matrix: a name, and a way to build that payload shape again.
    type Row = (&'static str, fn() -> Payload);

    let variants: Vec<Row> = vec![
        ("bytes", || Payload::from_bytes(Bytes::from_static(b"onetwo"))),
        ("vectored", || {
            Payload::from_segments([Bytes::from_static(b"one"), Bytes::from_static(b"two")])
        }),
        ("reader", || {
            Payload::from_reader(
                ScriptedReader::new([Step::Chunk("one"), Step::Chunk("two"), Step::Eof(TrailingHeaders::empty())])
                    .with_caps(PayloadCaps::PULL),
            )
            .expect("caps are consistent")
        }),
        ("stream", || {
            Payload::from_stream(
                ScriptedStream::new([Step::Chunk("one"), Step::Chunk("two"), Step::Eof(TrailingHeaders::empty())])
                    .with_caps(PayloadCaps::PUSH),
            )
            .expect("caps are consistent")
        }),
    ];

    for (name, build) in variants {
        let metrics = StreamMetrics::new();

        let (reader, _) = build()
            .try_into_reader(&metrics)
            .unwrap_or_else(|_| panic!("{name} converts to the pull model"));
        let (pulled, pull_trailers) = drain_reader(reader, 4).expect("body ends cleanly");
        assert_eq!(pulled, expected, "{name} through the pull model");
        assert!(pull_trailers.is_empty());

        let (stream, _) = build()
            .try_into_stream(&metrics)
            .unwrap_or_else(|_| panic!("{name} converts to the push model"));
        let (chunks, push_trailers) = drain_stream(stream).expect("body ends cleanly");
        assert_eq!(joined(&chunks), expected, "{name} through the push model");
        assert!(push_trailers.is_empty());
        assert!(chunks.iter().all(|c| !c.is_empty()), "{name} must not emit an empty chunk");
    }
}

#[test]
fn an_empty_payload_reads_as_nothing_through_both_models() {
    let metrics = StreamMetrics::new();

    let (reader, _) = Payload::Empty.try_into_reader(&metrics).expect("an empty payload converts");
    let (bytes, trailers) = drain_reader(reader, 8).expect("body ends cleanly");
    assert!(bytes.is_empty());
    assert!(trailers.is_empty());

    let (stream, _) = Payload::Empty.try_into_stream(&metrics).expect("an empty payload converts");
    let (chunks, trailers) = drain_stream(stream).expect("body ends cleanly");
    assert!(chunks.is_empty(), "an empty body emits no chunk at all");
    assert!(trailers.is_empty());
}
