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

//! Private range-storage controls for fragmented ingest, using the independent wire fixtures.
//!
//! Responsible for: observing actual pending metadata, exact byte delivery and range rebasing.
//! NOT responsible for: measuring process RSS or reproducing a network attack.
//! Upstream: the pipeline and shared ingest fixtures. Downstream: no runtime consumer.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test fixtures assert setup and use bounded byte slices"
)]

use std::sync::{Arc, Mutex};
use std::task::Waker;

use super::*;

#[path = "../../../tests/support/ingest.rs"]
mod support;

use support::{ScriptReader, SignedChunker, drain_pipeline, no_observers, signed_pipeline, unsigned_body, unsigned_pipeline};

const KEY: [u8; 32] = [0x11; 32];
const SEED: [u8; 32] = [0x22; 32];

#[derive(Default)]
struct Observed {
    bytes: Vec<u8>,
    calls: usize,
}

struct Recorder(Arc<Mutex<Observed>>);

impl ByteObserver for Recorder {
    fn update(&mut self, bytes: &[u8]) {
        let mut observed = self.0.lock().expect("test recorder lock");
        observed.bytes.extend_from_slice(bytes);
        observed.calls += 1;
    }

    fn finish(self: Box<Self>) -> ObserverOutcome {
        ObserverOutcome::new(self.label(), &[], self.0.lock().expect("test recorder lock").bytes.len() as u64)
    }

    fn label(&self) -> &'static str {
        "fragment-recorder"
    }
}

fn payload(len: usize) -> Vec<u8> {
    (0u8..=u8::MAX).cycle().take(len).collect()
}

fn signed(body: Vec<u8>, slice: usize, decoded: usize) -> (IngestPipeline<ScriptReader>, Arc<Mutex<Observed>>) {
    let observed = Arc::new(Mutex::new(Observed::default()));
    let mut observers = SmallVec::new();
    observers.push(Box::new(Recorder(Arc::clone(&observed))) as Box<dyn ByteObserver>);
    let mut pipeline = signed_pipeline(body, slice, decoded as u64, KEY, SEED, observers, ChunkLimits::default());
    pipeline.inner = pipeline.inner.pending_every(2);
    (pipeline, observed)
}

fn advance_to(pipeline: &mut IngestPipeline<ScriptReader>, decoded: usize) -> usize {
    let mut cx = Context::from_waker(Waker::noop());
    let mut pending_polls = 0;
    for _ in 0..decoded.saturating_mul(4).saturating_add(2048) {
        if pipeline.decoded_bytes() == decoded as u64 {
            return pending_polls;
        }
        match pipeline.advance(&mut cx) {
            Poll::Ready(result) => result.expect("valid fixture advances"),
            Poll::Pending => pending_polls += 1,
        }
    }
    assert_eq!(pipeline.decoded_bytes(), decoded as u64, "decoder made no progress");
    pending_polls
}

fn metadata(pipeline: &IngestPipeline<ScriptReader>) -> (usize, usize, bool, usize) {
    let capacity = pipeline.pending.capacity();
    let spilled = pipeline.pending.spilled();
    let heap_bytes = if spilled { capacity * std::mem::size_of::<Run>() } else { 0 };
    (pipeline.pending.len(), capacity, spilled, heap_bytes)
}

#[test]
fn n_fragmented_signed_data_does_not_allocate_run_metadata_per_read() {
    let data = payload(1024 * 1024);
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(&data);
    let body = chunker.finish();
    let (mut packed, _) = signed(body.clone(), usize::MAX, data.len());
    let (mut fragmented, observed) = signed(body, 1, data.len());
    let packed_pending_polls = advance_to(&mut packed, data.len());
    let fragmented_pending_polls = advance_to(&mut fragmented, data.len());
    let packed_metadata = metadata(&packed);
    let fragmented_metadata = metadata(&fragmented);
    eprintln!("packed pending (len, capacity, spilled, heap slot bytes): {packed_metadata:?}");
    eprintln!("one-byte pending (len, capacity, spilled, heap slot bytes): {fragmented_metadata:?}");
    eprintln!("actual Pending returns: packed={packed_pending_polls}, one-byte={fragmented_pending_polls}");
    assert!(packed_pending_polls > 0, "packed reads actually suspend");
    assert!(
        fragmented_pending_polls > packed_pending_polls,
        "fragmented reads actually resume more often"
    );
    assert_eq!(fragmented.signer().expect("signed fixture").chunks_verified(), 0);
    assert!(fragmented.deliverable.is_empty());
    assert_eq!(fragmented.delivered_bytes(), 0);
    assert!(drain_pipeline(&mut packed, 8192).expect("packed signed body verifies") == data);
    assert!(drain_pipeline(&mut fragmented, 8192).expect("fragmented signed body verifies") == data);
    assert!(packed.commit_allowed());
    assert!(fragmented.commit_allowed());
    let observed = observed.lock().expect("test recorder lock");
    assert!(observed.bytes == data, "observers see exact data once, in order");
    assert_eq!(observed.calls, data.len(), "each one-byte decode event is still observed");
    assert_eq!(fragmented.signer().expect("signed fixture").hmac_calls(), 2);
    assert_eq!(fragmented.signer().expect("signed fixture").chunks_verified(), 2);
    assert_eq!(packed_metadata, (1, 4, false, 0));
    assert_eq!(fragmented_metadata, packed_metadata);
    assert!(!fragmented.deliverable.spilled(), "promotion stays in inline metadata storage");
}

#[test]
fn n_fragmented_unsigned_data_does_not_spill_pending_metadata() {
    let data = payload(8192);
    let mut pipeline = unsigned_pipeline(unsigned_body(&[&data]), 1, data.len() as u64, no_observers(), ChunkLimits::default());
    pipeline.inner = pipeline.inner.pending_every(2);
    advance_to(&mut pipeline, data.len());
    let pending = metadata(&pipeline);
    assert!(drain_pipeline(&mut pipeline, 31).expect("unsigned body decodes") == data);
    assert_eq!(pending, (1, 4, false, 0));
    assert!(!pipeline.deliverable.spilled());
}

#[test]
fn n_compaction_does_not_split_or_lose_the_rebased_pending_range() {
    let first = payload(32_000);
    let second = payload(70_000);
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(&first).push(&second);
    let (mut pipeline, observed) = signed(chunker.finish(), 4096, first.len() + second.len());
    let mut cx = Context::from_waker(Waker::noop());
    let mut first_out = vec![0; first.len()];
    loop {
        if let Poll::Ready(result) = Pin::new(&mut pipeline).poll_fill(&mut cx, &mut first_out) {
            assert!(matches!(result.expect("first verified chunk"), ReadProgress::Filled(n) if n == first.len()));
            break;
        }
    }
    assert!(first_out == first);
    advance_to(&mut pipeline, first.len() + second.len());
    assert!(pipeline.bytes_moved_total() > 0, "the fixture actually compacted");
    assert_eq!(pipeline.pending.as_slice(), &[(0, second.len())]);
    assert!(pipeline.window[..second.len()] == second, "the retained span actually moved");
    assert!(drain_pipeline(&mut pipeline, 97).expect("rebased signed body verifies") == second);
    let expected: Vec<_> = first.into_iter().chain(second).collect();
    assert!(observed.lock().expect("test recorder lock").bytes == expected);
    assert_eq!(pipeline.signer().expect("signed fixture").hmac_calls(), 3);
}

#[test]
fn n_chunk_boundaries_do_not_join_verified_and_unverified_ranges() {
    let first = payload(501);
    let second = payload(733);
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(&first).push(&second);
    let (mut pipeline, _) = signed(chunker.finish(), usize::MAX, first.len() + second.len());
    advance_to(&mut pipeline, first.len());
    let mut cx = Context::from_waker(Waker::noop());
    if let Poll::Ready(result) = pipeline.advance(&mut cx) {
        result.expect("first chunk verifies");
    }
    assert!(pipeline.pending.is_empty(), "verified chunk leaves no pending range");
    let verified = pipeline.deliverable.clone();
    advance_to(&mut pipeline, first.len() + second.len());
    assert_eq!(pipeline.deliverable, verified, "new data cannot extend verified ranges");
    assert_eq!(pipeline.pending.len(), 1);
    let mut delivered = vec![0; first.len() + second.len()];
    let count = pipeline.drain_into(&mut delivered);
    assert_eq!(&delivered[..count], first.as_slice(), "only the first chunk is verified");
    assert!(drain_pipeline(&mut pipeline, 19).expect("second chunk verifies") == second);
}

#[test]
fn n_separated_pending_ranges_are_not_joined_across_a_gap() {
    let mut pipeline = unsigned_pipeline(unsigned_body(&[b"abc"]), usize::MAX, 3, no_observers(), ChunkLimits::default());
    let mut cx = Context::from_waker(Waker::noop());
    let _ = pipeline.refill(&mut cx).map(|result| result.expect("fixture bytes arrive"));
    // Attack the range-bookkeeping seam: a prior span cannot make the skipped header into data.
    pipeline.pending.push((0, 1));
    let _ = pipeline.advance(&mut cx).map(|result| result.expect("data event arrives"));
    assert_eq!(pipeline.pending.as_slice(), &[(0, 1), (3, 3)]);
}

#[test]
fn n_bad_fragmented_signatures_do_not_release_unverified_bytes() {
    for prefix in [Vec::new(), payload(512)] {
        let bad = payload(4096);
        let mut chunker = SignedChunker::new(KEY, SEED);
        if !prefix.is_empty() {
            chunker.push(&prefix);
        }
        chunker.push_with_signature(&bad, &[0; 32]);
        let (mut pipeline, _) = signed(chunker.finish(), 1, prefix.len() + bad.len());
        let err = drain_pipeline(&mut pipeline, 127).expect_err("bad chunk signature is refused");
        assert_eq!(pipeline.delivered_bytes(), prefix.len() as u64);
        assert_eq!(err.bytes_before_error(), prefix.len() as u64);
        assert_eq!(
            pipeline.reject(),
            Some(ChunkReject::SignatureChainBroken {
                chunk_index: u32::from(!prefix.is_empty())
            })
        );
        assert!(!pipeline.commit_allowed());
        assert!(pipeline.deliverable.is_empty());
        assert_eq!(pipeline.drain_into(&mut [0; 32]), 0, "rejected pending bytes never become deliverable");
    }
}

#[test]
fn n_truncated_fragmented_data_stays_unverified_and_has_inline_metadata() {
    let data = payload(4096);
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(&data);
    let mut body = chunker.finish_truncated();
    body.truncate(body.len() - 2);
    let (mut pipeline, _) = signed(body, 1, data.len());
    advance_to(&mut pipeline, data.len());
    let pending = metadata(&pipeline);
    let err = drain_pipeline(&mut pipeline, 29).expect_err("closing CRLF and terminal chunk are absent");
    assert_eq!(pipeline.reject(), Some(ChunkReject::TruncatedStream));
    assert_eq!(pipeline.delivered_bytes(), 0);
    assert_eq!(err.bytes_before_error(), 0);
    assert_eq!(pipeline.signer().expect("signed fixture").chunks_verified(), 0);
    assert!(!pipeline.commit_allowed());
    assert_eq!(pending, (1, 4, false, 0));
}

fn trailer_pipeline(section: &str, slice: usize) -> IngestPipeline<ScriptReader> {
    let limits = ChunkLimits::default()
        .with_trailer_bounds(16 * 1024, 100)
        .with_undeclared_trailer_fields_discarded();
    let mut body = b"5\r\nhello\r\n0\r\n".to_vec();
    body.extend_from_slice(section.as_bytes());
    let declaration = TrailerDeclaration::parse(&http::HeaderValue::from_static("x-amz-checksum-crc32c"), false)
        .expect("an allowed declaration");
    support::unsigned_trailer_pipeline(body, slice, 5, no_observers(), limits)
        .with_trailer_declaration(declaration)
        .expect("the declaration matches the framing mode")
}

fn trailer_outcome(section: &str, slice: usize) -> (Result<Vec<u8>, ChunkReject>, usize) {
    let mut pipeline = trailer_pipeline(section, slice);
    let result = drain_pipeline(&mut pipeline, 64).map_err(|_| pipeline.reject().expect("a refusal names its reason"));
    (result, pipeline.trailer_parses)
}

/// A trailer section sent a byte at a time reads as it does whole, and is parsed about once per
/// line rather than once per byte.
#[test]
fn a_valid_trailer_section_sent_a_byte_at_a_time_is_not_reparsed_per_byte() {
    let section = format!("x-padding:{}\r\nx-amz-checksum-crc32c:NhCmhg==\r\n\r\n", "a".repeat(3000));
    let (whole, _) = trailer_outcome(&section, 65_536);
    let (dribbled, parses) = trailer_outcome(&section, 1);
    assert_eq!(whole, Ok(b"hello".to_vec()));
    assert_eq!(dribbled, whole);
    assert!(parses < 10, "{parses} parses for a {}-byte section", section.len());
}

/// Negative — an over-limit section is refused the same way when it arrives a byte at a time, and
/// still without being parsed per byte.
#[test]
fn n_an_over_limit_trailer_section_sent_a_byte_at_a_time_is_refused_as_whole() {
    let section = format!(
        "{}x-amz-checksum-crc32c:NhCmhg==\r\n\r\n",
        format!("x-padding:{}\r\n", "a".repeat(190)).repeat(90)
    );
    assert!(section.len() > 16 * 1024);
    let (whole, _) = trailer_outcome(&section, 65_536);
    let (dribbled, parses) = trailer_outcome(&section, 1);
    assert_eq!(whole, Err(ChunkReject::TrailerSizeExceeded));
    assert_eq!(dribbled, whole);
    assert!(parses <= 90 + 2, "one parse per line at most, saw {parses}");
}

/// Negative — a single over-long line with no line feed is refused at the bound, not later.
#[test]
fn n_a_line_without_a_line_feed_is_refused_at_the_bound() {
    let section = format!("x-padding:{}", "a".repeat(20_000));
    let (dribbled, parses) = trailer_outcome(&section, 1);
    assert_eq!(dribbled, Err(ChunkReject::TrailerSizeExceeded));
    assert!(parses < 5, "saw {parses}");
}

/// Reader that delivers `prefix` bytes and then returns `ReadProgress::Filled(0)` into a non-empty
/// buffer, violating the `AsyncPayloadRead` contract.
struct ZeroFillAfter {
    prefix: Vec<u8>,
    at: usize,
    zero_polls: usize,
}

impl ZeroFillAfter {
    fn new(prefix: impl Into<Vec<u8>>) -> Self {
        Self {
            prefix: prefix.into(),
            at: 0,
            zero_polls: 0,
        }
    }
}

impl AsyncPayloadRead for ZeroFillAfter {
    fn poll_fill(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(ReadProgress::Filled(0)));
        }
        if this.at < this.prefix.len() {
            let take = (this.prefix.len() - this.at).min(buf.len());
            buf[..take].copy_from_slice(&this.prefix[this.at..this.at + take]);
            this.at += take;
            return Poll::Ready(Ok(ReadProgress::Filled(take)));
        }
        this.zero_polls += 1;
        assert!(this.zero_polls <= 8, "IngestPipeline spun on ReadProgress::Filled(0)");
        Poll::Ready(Ok(ReadProgress::Filled(0)))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PULL
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

/// Negative — `ReadProgress::Filled(0)` on a non-empty buffer is a fatal producer contract
/// violation in `refill()`, `refill_trailer()`, and `finalize()`: it must never spin forever and
/// must never be mistaken for clean EOF with `commit_allowed == true`.
#[test]
fn n_zero_fill_on_non_empty_buffer_is_fatal_in_refill_trailer_and_finalize() {
    let mut cx = Context::from_waker(Waker::noop());
    let mut out = [0u8; 64];

    // 1) During chunk refill: must fail immediately, not spin forever.
    let unsigned = ChunkFraming::derive(&support::FramingFixture::streaming_unsigned()).expect("consistent fixture");
    let unsigned_trailer =
        ChunkFraming::derive(&support::FramingFixture::streaming_unsigned_trailer()).expect("consistent fixture");
    let mut in_refill = IngestPipeline::new(
        ZeroFillAfter::new(b"5\r\nhe".to_vec()),
        unsigned,
        support::declared_length(5),
        None,
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::default(),
    )
    .expect("valid pipeline");
    let first = Pin::new(&mut in_refill).poll_fill(&mut cx, &mut out);
    assert!(matches!(first, Poll::Ready(Err(_))), "expected fatal error in refill, got {first:?}");
    assert_eq!(in_refill.inner.zero_polls, 1, "must not spin on Filled(0)");
    assert!(!in_refill.commit_allowed());

    // 2) During trailer refill: must fail immediately, not spin forever.
    let declaration = TrailerDeclaration::parse(&http::HeaderValue::from_static("x-amz-checksum-crc32c"), false)
        .expect("valid trailer declaration");
    let mut in_trailer = IngestPipeline::new(
        ZeroFillAfter::new(b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:".to_vec()),
        unsigned_trailer,
        support::declared_length(5),
        None,
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::default(),
    )
    .expect("valid pipeline")
    .with_trailer_declaration(declaration.clone())
    .expect("matching declaration");
    let mut got_err = false;
    for _ in 0..8 {
        match Pin::new(&mut in_trailer).poll_fill(&mut cx, &mut out) {
            Poll::Ready(Ok(ReadProgress::Filled(_))) => {}
            Poll::Ready(Err(_)) => {
                got_err = true;
                break;
            }
            other => {
                assert!(other.is_ready(), "unexpected pending in trailer refill");
                break;
            }
        }
    }
    assert!(got_err, "trailer refill must fail on Filled(0)");
    assert_eq!(in_trailer.inner.zero_polls, 1, "must not spin in refill_trailer");
    assert!(!in_trailer.commit_allowed());

    // 3) During finalize confirming probe (non-trailered): must NOT treat Filled(0) as clean EOF!
    let mut in_finalize = IngestPipeline::new(
        ZeroFillAfter::new(b"5\r\nhello\r\n0\r\n\r\n".to_vec()),
        unsigned,
        support::declared_length(5),
        None,
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::default(),
    )
    .expect("valid pipeline");
    let first = Pin::new(&mut in_finalize).poll_fill(&mut cx, &mut out);
    assert!(matches!(first, Poll::Ready(Ok(ReadProgress::Filled(5)))));
    let second = Pin::new(&mut in_finalize).poll_fill(&mut cx, &mut out);
    assert!(
        matches!(second, Poll::Ready(Err(_))),
        "finalize must reject Filled(0) on non-empty probe buffer, got {second:?}"
    );
    assert_eq!(in_finalize.inner.zero_polls, 1);
    assert!(!in_finalize.commit_allowed(), "commit must stay disallowed without transport EOF");

    // 4) During finalize confirming probe (trailered): must also fail without committing.
    let mut in_trailer_finalize = IngestPipeline::new(
        ZeroFillAfter::new(b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:NhCmhg==\r\n\r\n".to_vec()),
        unsigned_trailer,
        support::declared_length(5),
        None,
        no_observers(),
        ChunkLimits::default(),
        IngestPolicy::default(),
    )
    .expect("valid pipeline")
    .with_trailer_declaration(declaration)
    .expect("matching declaration");
    let first = Pin::new(&mut in_trailer_finalize).poll_fill(&mut cx, &mut out);
    assert!(matches!(first, Poll::Ready(Ok(ReadProgress::Filled(5)))));
    let second = Pin::new(&mut in_trailer_finalize).poll_fill(&mut cx, &mut out);
    assert!(matches!(second, Poll::Ready(Err(_))), "got {second:?}");
    assert!(!in_trailer_finalize.commit_allowed());
}

/// Positive & negative — `window_ceiling` accounts for `max_trailer_section_bytes` so valid
/// trailers are accepted when `max_chunk_size < max_trailer_section_bytes`, while over-cap
/// trailers are still refused with `TrailerSizeExceeded`.
#[test]
fn n_trailer_window_accommodates_trailer_bound_above_max_chunk_size() {
    let limits = ChunkLimits::default()
        .with_max_chunk_size(128)
        .with_trailer_bounds(4096, 100)
        .with_undeclared_trailer_fields_discarded();
    let declaration = TrailerDeclaration::parse(&http::HeaderValue::from_static("x-amz-checksum-crc32c"), false)
        .expect("valid trailer declaration");

    let valid_section = format!("x-padding:{}\r\nx-amz-checksum-crc32c:NhCmhg==\r\n\r\n", "a".repeat(2048));
    assert!(valid_section.len() > 1024 && valid_section.len() < 4096);
    let mut valid_body = b"5\r\nhello\r\n0\r\n".to_vec();
    valid_body.extend_from_slice(valid_section.as_bytes());
    let mut valid_pipeline = support::unsigned_trailer_pipeline(valid_body, 64, 5, no_observers(), limits)
        .with_trailer_declaration(declaration.clone())
        .expect("matching declaration");
    assert_eq!(drain_pipeline(&mut valid_pipeline, 64).expect("valid trailer fits ceiling"), b"hello");

    let over_section = format!("x-padding:{}\r\nx-amz-checksum-crc32c:NhCmhg==\r\n\r\n", "a".repeat(4096));
    let mut over_body = b"5\r\nhello\r\n0\r\n".to_vec();
    over_body.extend_from_slice(over_section.as_bytes());
    let mut over_pipeline = support::unsigned_trailer_pipeline(over_body, 64, 5, no_observers(), limits)
        .with_trailer_declaration(declaration)
        .expect("matching declaration");
    assert!(drain_pipeline(&mut over_pipeline, 64).is_err());
    assert_eq!(over_pipeline.reject(), Some(ChunkReject::TrailerSizeExceeded));
}

/// Positive & negative — `check_overhead_ratio()` does not spuriously fail on chunk 0 while
/// `decoded_bytes == 0`, yet still rejects high-overhead micro-chunks once payload is decoded.
#[test]
fn n_overhead_ratio_guards_chunk_zero_before_payload_is_decoded() {
    let limits = ChunkLimits::default()
        .with_min_chunk_size_for_count(1)
        .with_overhead_ratio_floor_bytes(64)
        .with_max_overhead_permille(500);

    // Valid single signed chunk (header ~86 bytes > 64-byte floor) with 1024-byte payload.
    let data = payload(1024);
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(&data);
    let mut ok_pipeline = signed_pipeline(chunker.finish(), 4096, data.len() as u64, KEY, SEED, no_observers(), limits);
    assert_eq!(drain_pipeline(&mut ok_pipeline, 1024).expect("chunk 0 must not fail on decoded==0"), data);
    assert!(ok_pipeline.commit_allowed());

    // Valid empty signed body (declared == 0, terminal header > 64-byte floor).
    let empty_chunker = SignedChunker::new(KEY, SEED);
    let mut empty_pipeline = signed_pipeline(empty_chunker.finish(), 4096, 0, KEY, SEED, no_observers(), limits);
    assert!(
        drain_pipeline(&mut empty_pipeline, 64)
            .expect("empty signed body must pass")
            .is_empty()
    );
    assert!(empty_pipeline.commit_allowed());

    // Negative: tiny 1-byte signed chunk still trips overhead ratio once decoded.
    let mut flood = SignedChunker::new(KEY, SEED);
    flood.push(b"x").push(b"y");
    let mut bad_pipeline = signed_pipeline(flood.finish(), 4096, 2, KEY, SEED, no_observers(), limits);
    assert!(drain_pipeline(&mut bad_pipeline, 64).is_err());
    assert!(matches!(bad_pipeline.reject(), Some(ChunkReject::OverheadRatioExceeded { .. })));
}
