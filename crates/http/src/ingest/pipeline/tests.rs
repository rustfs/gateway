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
