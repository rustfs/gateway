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

//! What each adaptation costs, and that the copying kind is counted.
//!
//! Responsible for: the cost every payload shape reports in both directions, and the counter a
//! performance gate reads. A gate that asserts `adapt_copies_total == 0` for a large transfer
//! is only as good as these assertions.
//! NOT responsible for: wall-clock measurement. Nothing here is timed; a timing assertion on a
//! shared runner is noise, and noise gets muted.
//! Upstream: `support`. Downstream: nothing.

use bytes::Bytes;

use crate::adapt::{Adapt, AdaptCost, ReaderToStream, StreamToReader};
use crate::caps::PayloadCaps;
use crate::metrics::StreamMetrics;
use crate::payload::Payload;
use crate::tests::support::{ScriptedReader, ScriptedStream, Step, drain_reader, drain_stream, joined};
use crate::trailers::TrailingHeaders;

const ONE_MIB: usize = 1024 * 1024;

fn one_mib() -> Bytes {
    Bytes::from(vec![0x5au8; ONE_MIB])
}

/// c-stream-0005: a payload that is already in memory is free to consume through either model,
/// and neither direction touches the copy counter.
#[test]
fn an_in_memory_payload_is_free_in_both_directions() {
    let metrics = StreamMetrics::new();

    let (reader, pull_cost) = Payload::from_bytes(one_mib())
        .try_into_reader(&metrics)
        .expect("in-memory payload converts");
    assert_eq!(pull_cost, AdaptCost::Free);

    let (stream, push_cost) = Payload::from_bytes(one_mib())
        .try_into_stream(&metrics)
        .expect("in-memory payload converts");
    assert_eq!(push_cost, AdaptCost::Free);

    let (pulled, _) = drain_reader(reader, 64 * 1024).expect("body ends cleanly");
    let (chunks, _) = drain_stream(stream).expect("body ends cleanly");

    assert_eq!(pulled.len(), ONE_MIB);
    assert_eq!(joined(&chunks).len(), ONE_MIB);
    assert_eq!(metrics.adapt_copies_total(), 0);
    assert_eq!(metrics.adapt_copied_bytes_total(), 0);
    assert_eq!(metrics.adapt_buffers_total(), 0);
}

/// A payload consumed through the model it already speaks is free, too.
#[test]
fn a_native_model_costs_nothing() {
    let metrics = StreamMetrics::new();

    let (_, cost) = Payload::from_stream(ScriptedStream::new([Step::Eof(TrailingHeaders::empty())]).with_caps(PayloadCaps::PUSH))
        .expect("caps are consistent")
        .try_into_stream(&metrics)
        .expect("a push body stays a push body");
    assert_eq!(cost, AdaptCost::Free);

    let (_, cost) = Payload::from_reader(ScriptedReader::new([Step::Eof(TrailingHeaders::empty())]).with_caps(PayloadCaps::PULL))
        .expect("caps are consistent")
        .try_into_reader(&metrics)
        .expect("a pull body stays a pull body");
    assert_eq!(cost, AdaptCost::Free);

    assert_eq!(metrics.adapt_copies_total(), 0);
    assert_eq!(metrics.adapt_buffers_total(), 0);
}

/// c-stream-n011: consuming a push body through the pull model copies every byte a second time,
/// and that is counted once per adaptation, with the expected byte count recorded.
#[test]
fn a_push_body_read_through_the_pull_model_is_a_counted_copy() {
    let metrics = StreamMetrics::new();

    let payload = Payload::from_stream(
        ScriptedStream::new([Step::Chunk("onetwo"), Step::Eof(TrailingHeaders::empty())])
            .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
            .with_len_hint(Some(6)),
    )
    .expect("caps are consistent");

    let (reader, cost) = payload.try_into_reader(&metrics).expect("a push body can be adapted");

    assert_eq!(cost, AdaptCost::Copy { est_bytes: Some(6) });
    assert!(cost.is_copy());
    assert_eq!(cost.est_bytes(), Some(6));
    assert_eq!(metrics.adapt_copies_total(), 1);
    assert_eq!(metrics.adapt_copied_bytes_total(), 6);

    let (bytes, _) = drain_reader(reader, 4).expect("body ends cleanly");
    assert_eq!(bytes, b"onetwo");
}

/// The counter rises once per adaptation, not once per chunk or once per byte.
#[test]
fn the_copy_counter_rises_once_per_adaptation() {
    let metrics = StreamMetrics::new();

    for _ in 0..3 {
        let payload = Payload::from_stream(
            ScriptedStream::new([Step::Chunk("one"), Step::Chunk("two"), Step::Eof(TrailingHeaders::empty())])
                .with_caps(PayloadCaps::PUSH),
        )
        .expect("caps are consistent");

        let (reader, _) = payload.try_into_reader(&metrics).expect("a push body can be adapted");
        let (bytes, _) = drain_reader(reader, 2).expect("body ends cleanly");
        assert_eq!(bytes, b"onetwo");
    }

    assert_eq!(metrics.adapt_copies_total(), 3);
    assert_eq!(metrics.adapt_copied_bytes_total(), 0, "an unknown length contributes no byte estimate");
}

/// Consuming a pull body through the push model needs an owned buffer but writes no byte twice,
/// so it is a buffering cost and must not be counted as a copy.
#[test]
fn a_pull_body_read_through_the_push_model_buffers_without_copying() {
    let metrics = StreamMetrics::new();

    let payload = Payload::from_reader(
        ScriptedReader::new([Step::Chunk("onetwo"), Step::Eof(TrailingHeaders::empty())])
            .with_caps(PayloadCaps::PULL | PayloadCaps::KNOWN_LENGTH)
            .with_len_hint(Some(6)),
    )
    .expect("caps are consistent");

    let (stream, cost) = payload.try_into_stream(&metrics).expect("a pull body can be adapted");

    assert_eq!(cost, AdaptCost::Buffer { est_bytes: Some(6) });
    assert!(!cost.is_copy());
    assert_eq!(metrics.adapt_copies_total(), 0);
    assert_eq!(metrics.adapt_buffers_total(), 1);

    let (chunks, _) = drain_stream(stream).expect("body ends cleanly");
    assert_eq!(joined(&chunks), b"onetwo");
}

/// The adapters report the same cost through the [`Adapt`] trait as the conversion returned, so
/// a transport can ask an already built adapter what it is paying.
#[test]
fn adapters_report_their_own_cost() {
    let push_to_pull = StreamToReader::new(
        ScriptedStream::new([Step::Eof(TrailingHeaders::empty())])
            .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
            .with_len_hint(Some(11))
            .boxed(),
    );
    assert_eq!(push_to_pull.adapt_cost(), AdaptCost::Copy { est_bytes: Some(11) });

    let pull_to_push = ReaderToStream::new(
        ScriptedReader::new([Step::Eof(TrailingHeaders::empty())])
            .with_caps(PayloadCaps::PULL | PayloadCaps::KNOWN_LENGTH)
            .with_len_hint(Some(11))
            .boxed(),
    );
    assert_eq!(pull_to_push.adapt_cost(), AdaptCost::Buffer { est_bytes: Some(11) });

    assert!(
        crate::adapt::MemoryStream::new([], TrailingHeaders::empty())
            .adapt_cost()
            .is_free()
    );
    assert!(
        crate::adapt::MemoryReader::new([], TrailingHeaders::empty())
            .adapt_cost()
            .is_free()
    );
}

/// A free adaptation never touches any counter, which is what makes the zero assertion in the
/// performance gate meaningful.
#[test]
fn a_free_adaptation_leaves_every_counter_at_zero() {
    let metrics = StreamMetrics::new();
    metrics.record_adapt(&AdaptCost::Free);
    metrics.record_adapt(&AdaptCost::Free);

    assert_eq!(metrics.adapt_copies_total(), 0);
    assert_eq!(metrics.adapt_copied_bytes_total(), 0);
    assert_eq!(metrics.adapt_buffers_total(), 0);
}

/// An adaptation whose length is unknown still counts as an adaptation; only the byte estimate
/// is missing. A missing estimate must not hide the event itself.
#[test]
fn an_unknown_length_copy_is_still_counted() {
    let metrics = StreamMetrics::new();
    metrics.record_adapt(&AdaptCost::Copy { est_bytes: None });

    assert_eq!(metrics.adapt_copies_total(), 1);
    assert_eq!(metrics.adapt_copied_bytes_total(), 0);
}

/// The adapted body keeps the capability bits honest: the model it now speaks is advertised,
/// and the model it no longer speaks is not.
#[test]
fn an_adapted_body_advertises_the_model_it_now_speaks() {
    let metrics = StreamMetrics::new();

    let payload = Payload::from_stream(ScriptedStream::new([Step::Eof(TrailingHeaders::empty())]).with_caps(PayloadCaps::PUSH))
        .expect("caps are consistent");
    let (reader, _) = payload.try_into_reader(&metrics).expect("a push body can be adapted");
    assert!(crate::read::AsyncPayloadRead::caps(&reader).contains(PayloadCaps::PULL));
    assert!(!crate::read::AsyncPayloadRead::caps(&reader).contains(PayloadCaps::PUSH));

    let payload = Payload::from_reader(ScriptedReader::new([Step::Eof(TrailingHeaders::empty())]).with_caps(PayloadCaps::PULL))
        .expect("caps are consistent");
    let (stream, _) = payload.try_into_stream(&metrics).expect("a pull body can be adapted");
    assert!(crate::stream::PayloadStream::caps(&stream).contains(PayloadCaps::PUSH));
    assert!(!crate::stream::PayloadStream::caps(&stream).contains(PayloadCaps::PULL));
}

/// A pull producer that reports progress without producing a byte violates its contract. The
/// adapter must surface that as a failure rather than spin forever or emit an empty chunk,
/// because an empty chunk would be indistinguishable from the end of the body.
#[test]
fn a_zero_progress_pull_producer_is_rejected_by_the_adapter() {
    struct ZeroProgress;

    impl crate::read::AsyncPayloadRead for ZeroProgress {
        fn poll_fill(
            self: core::pin::Pin<&mut Self>,
            _cx: &mut core::task::Context<'_>,
            _buf: &mut [u8],
        ) -> core::task::Poll<Result<crate::read::ReadProgress, crate::error::StreamError>> {
            core::task::Poll::Ready(Ok(crate::read::ReadProgress::Filled(0)))
        }

        fn caps(&self) -> PayloadCaps {
            PayloadCaps::PULL
        }

        fn len_hint(&self) -> Option<u64> {
            None
        }
    }

    let stream = Box::pin(ReaderToStream::new(Box::pin(ZeroProgress)).with_chunk_size(8));
    let err = drain_stream(stream).expect_err("a producer that never progresses must fail");

    assert!(matches!(err.kind(), crate::error::StreamErrorKind::Upstream(_)));
}
