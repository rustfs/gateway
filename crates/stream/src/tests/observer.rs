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

//! The observer contract: counted once, in order, with the granularity it was given.
//!
//! Responsible for: the byte accounting a single-pass gate reads, the empty-run rule, and the
//! digest buffer's boundary behaviour.
//! NOT responsible for: any digest algorithm; this crate has none.
//! Upstream: `observer`. Downstream: the wire layer's ingest suite, which uses the same counter.

use crate::observer::{ByteCounter, ByteObserver, MAX_OBSERVER_DIGEST_BYTES, ObserverOutcome};

/// Positive: several observers over one run each see every byte exactly once.
#[test]
fn four_observers_over_one_body_each_see_it_once() {
    let mut observers: Vec<Box<dyn ByteObserver>> = (0..4).map(|_| Box::new(ByteCounter::new()) as _).collect();

    for run in [&b"sixteen bytes...."[..], &b"and eight more.."[..]] {
        for observer in &mut observers {
            observer.update(run);
        }
    }

    for observer in observers {
        let outcome = observer.finish();
        assert_eq!(outcome.observed_bytes(), 33);
    }
}

/// Positive: the call count records the granularity, so a pipeline that splits the body at every
/// framing boundary is visible as a call count far above the chunk count.
#[test]
fn the_call_count_and_the_smallest_run_record_the_granularity() {
    let mut counter = ByteCounter::new();
    counter.update(&[0u8; 16 * 1024]);
    counter.update(&[0u8; 16 * 1024]);

    assert_eq!(counter.update_calls(), 2);
    assert_eq!(counter.smallest_run(), Some(16 * 1024));
    assert_eq!(counter.observed_bytes(), 32 * 1024);
}

/// Negative: an empty run is not progress and must not inflate the call count, or the
/// granularity witness reports a split that never happened.
#[test]
fn an_empty_run_is_not_a_call() {
    let mut counter = ByteCounter::new();
    counter.update(&[]);

    assert_eq!(counter.update_calls(), 0);
    assert_eq!(counter.observed_bytes(), 0);
    assert_eq!(counter.smallest_run(), None);
}

/// Negative: a digest longer than the buffer is truncated rather than panicking, because the
/// alternative in a `#![forbid(unsafe_code)]` crate with indexing denied is a slice panic on the
/// data path.
#[test]
fn an_over_long_digest_is_truncated_not_panicked() {
    let outcome = ObserverOutcome::new("over-long", &[0xAB; MAX_OBSERVER_DIGEST_BYTES + 8], 1);
    assert_eq!(outcome.digest().len(), MAX_OBSERVER_DIGEST_BYTES);
}

/// Negative: an empty digest is representable and reads back as empty, not as a zero-filled
/// buffer of the maximum width.
#[test]
fn an_empty_digest_reads_back_empty() {
    let outcome = ObserverOutcome::new("empty", &[], 0);
    assert_eq!(outcome.digest(), &[] as &[u8]);
    assert_eq!(outcome.observed_bytes(), 0);
    assert_eq!(outcome.label(), "empty");
}

/// Negative: the debug rendering carries the label and the byte count but never the digest, so a
/// log line about a body cannot leak the digest of that body.
#[test]
fn the_debug_rendering_does_not_carry_the_digest() {
    let outcome = ObserverOutcome::new("labelled", &[0xDE, 0xAD, 0xBE, 0xEF], 4);
    let rendered = format!("{outcome:?}");
    assert!(rendered.contains("labelled"));
    assert!(!rendered.contains("222"), "the digest bytes must not be rendered");
}
