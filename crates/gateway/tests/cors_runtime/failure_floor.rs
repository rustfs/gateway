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

//! Deterministic monotonic-clock controls for CORS preflight failure-floor enforcement (#1580).
//!
//! Responsible for: the counting [`ManualMonotonic`] spy used by `cors_runtime` to prove every
//! preflight refusal enters `hold_failure_floor` without real-clock scheduler sensitivity, plus
//! two-directional boundary controls proving both pending and ready outcomes.
//! NOT responsible for: CORS rule matching, cache eviction, or headerless OPTIONS wire shape.
//! Upstream: `super` (`cors_runtime`). Downstream: `rustfs_gateway::S3Service`.

use std::time::Duration;

use rustfs_gateway::{ManualMonotonic, MonotonicClock, MonotonicNow};

use super::*;

/// A [`MonotonicClock`] backed by [`ManualMonotonic`] that counts every reading.
///
/// Keeping the clock frozen at `0 ms` makes `failure_floor_remaining` deterministically return
/// `Some(25 ms)` even when a loaded CI runner pauses the thread between `started = clock.monotonic()`
/// and `hold_failure_floor`. Counting reads distinguishes entering `hold_failure_floor` (2 reads:
/// entry timestamp + floor evaluation) from suspending on an earlier future such as `NeverSource`
/// (1 read until timeout, then 2 reads once `hold_failure_floor` runs).
#[derive(Clone)]
pub(super) struct CountingMonotonic {
    inner: Arc<ManualMonotonic>,
    reads: Arc<AtomicUsize>,
}

impl CountingMonotonic {
    pub(super) fn at_millis(millis: u64) -> Self {
        Self {
            inner: Arc::new(ManualMonotonic::at_millis(millis)),
            reads: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(super) fn readings(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    pub(super) fn reset_readings(&self) {
        self.reads.store(0, Ordering::SeqCst);
    }

    pub(super) fn advance_millis(&self, by: u64) {
        self.inner.advance_millis(by);
    }
}

impl MonotonicClock for CountingMonotonic {
    fn monotonic(&self) -> MonotonicNow {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.monotonic()
    }
}

/// Asserts that an immediate preflight refusal enters `hold_failure_floor` on its first poll and
/// still returns the uniform `403` + `Vary: origin` refusal.
pub(super) async fn assert_immediate_refusal_enters_failure_floor(
    label: &str,
    clock: &CountingMonotonic,
    future: impl Future<Output = WireResponse>,
) {
    clock.reset_readings();
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    assert!(
        matches!(future.as_mut().poll(&mut context), Poll::Pending),
        "{label}: preflight refusal completed before entering the shared failure floor (clock readings={})",
        clock.readings()
    );
    assert_eq!(
        clock.readings(),
        2,
        "{label}: expected 2 monotonic clock reads (entry + hold_failure_floor) on poll 1"
    );
    let response = future.await;
    assert_eq!(response.status().as_u16(), 403, "{label}: expected uniform 403 refusal");
    assert_eq!(header(&response, "vary").as_deref(), Some("origin"), "{label}: expected Vary: origin");
    assert_eq!(clock.readings(), 2, "{label}: unexpected extra monotonic clock reads on completion");
}

/// Asserts that a source-timeout preflight refusal suspends on the source first (1 clock reading)
/// and then enters `hold_failure_floor` once the source times out (2nd clock reading) before
/// returning the uniform `403` + `Vary: origin` refusal.
pub(super) async fn assert_timeout_refusal_enters_failure_floor(
    label: &str,
    clock: &CountingMonotonic,
    future: impl Future<Output = WireResponse>,
) {
    clock.reset_readings();
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    assert!(
        matches!(future.as_mut().poll(&mut context), Poll::Pending),
        "{label}: source-timeout refusal completed immediately on poll 1"
    );
    assert_eq!(
        clock.readings(),
        1,
        "{label}: poll 1 should suspend on NeverSource before hold_failure_floor runs"
    );
    let response = future.await;
    assert_eq!(response.status().as_u16(), 403, "{label}: expected uniform 403 refusal");
    assert_eq!(header(&response, "vary").as_deref(), Some("origin"), "{label}: expected Vary: origin");
    assert_eq!(
        clock.readings(),
        2,
        "{label}: post-timeout refusal never entered hold_failure_floor to evaluate elapsed time"
    );
}

/// A `CorsSource` that advances the test's deterministic monotonic clock during `load` and returns
/// `Ok(None)` (`MissingDocument`), modelling a source read whose elapsed time is controlled exactly.
struct AdvancingSource {
    clock: CountingMonotonic,
    advance_ms: u64,
}

impl CorsSource for AdvancingSource {
    fn load<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        self.clock.advance_millis(self.advance_ms);
        Box::pin(async { Ok(None) })
    }
}

/// A `CorsSource` that stalls the thread on wall time beyond the 25 ms default floor while leaving
/// the injected [`CountingMonotonic`] frozen, reproducing the CI scheduler pause from #1580.
struct StalledSyncSource;

impl CorsSource for StalledSyncSource {
    fn load<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        std::thread::sleep(Duration::from_millis(35));
        Box::pin(async { Ok(None) })
    }
}

/// Negative — with a 25 ms monotonic advance during the source read, millisecond quantization
/// (`(25 - 1) = 24 ms < 25 ms`) still owes 1 ms of floor wait, so poll 1 must remain `Pending`.
#[tokio::test]
async fn n_preflight_refusal_still_pends_at_twenty_five_ms_quantized_boundary() {
    let clock = CountingMonotonic::at_millis(0);
    let built = build_with_source_and_clock(
        AdvancingSource {
            clock: clock.clone(),
            advance_ms: 25,
        },
        Arc::new(AtomicUsize::new(0)),
        CorsPolicy::default(),
        None,
        clock.clone(),
    );
    assert_immediate_refusal_enters_failure_floor(
        "25ms-quantized-boundary",
        &clock,
        send(
            &built.service,
            "OPTIONS",
            PREFLIGHT,
            &[("origin", NAMED), ("access-control-request-method", "PUT")],
        ),
    )
    .await;
}

/// Negative (two-directional control) — once elapsed time reaches 26 ms (`(26 - 1) = 25 ms >= 25 ms`),
/// `failure_floor_remaining` returns `None` and poll 1 completes immediately with `Poll::Ready`.
/// This proves the `Poll::Pending` asserted for every refusal case comes from `hold_failure_floor`
/// and not from an unrelated async yield in the pipeline.
#[tokio::test]
async fn n_preflight_refusal_completes_on_first_poll_when_elapsed_reaches_twenty_six_ms() {
    let clock = CountingMonotonic::at_millis(0);
    let built = build_with_source_and_clock(
        AdvancingSource {
            clock: clock.clone(),
            advance_ms: 26,
        },
        Arc::new(AtomicUsize::new(0)),
        CorsPolicy::default(),
        None,
        clock.clone(),
    );
    clock.reset_readings();
    let mut future = Box::pin(send(
        &built.service,
        "OPTIONS",
        PREFLIGHT,
        &[("origin", NAMED), ("access-control-request-method", "PUT")],
    ));
    let mut context = Context::from_waker(Waker::noop());
    let response = match future.as_mut().poll(&mut context) {
        Poll::Ready(response) => response,
        Poll::Pending => panic!("preflight refusal waited past a 26ms elapsed reading"),
    };
    assert_eq!(response.status().as_u16(), 403);
    assert_eq!(header(&response, "vary").as_deref(), Some("origin"));
    assert_eq!(clock.readings(), 2, "hold_failure_floor must still read the monotonic clock");
}

/// Negative — reproduces the CI scheduler pause from #1580: even when the thread is stalled for
/// 35 ms (exceeding the 25 ms default floor) between `started` and `hold_failure_floor`, a frozen
/// deterministic clock keeps elapsed time at 0 ms so poll 1 still enters the floor cleanly.
#[tokio::test]
async fn n_frozen_monotonic_clock_holds_failure_floor_even_after_host_pause() {
    let clock = CountingMonotonic::at_millis(0);
    let built = build_with_source_and_clock(
        StalledSyncSource,
        Arc::new(AtomicUsize::new(0)),
        CorsPolicy::default(),
        None,
        clock.clone(),
    );
    assert_immediate_refusal_enters_failure_floor(
        "host-pause-35ms",
        &clock,
        send(
            &built.service,
            "OPTIONS",
            PREFLIGHT,
            &[("origin", NAMED), ("access-control-request-method", "PUT")],
        ),
    )
    .await;
}

/// Positive — an allowed preflight does not enter `hold_failure_floor`: poll 1 completes
/// immediately with `200` and reads the monotonic clock only once (at `serve_preflight` entry).
#[tokio::test]
async fn an_allowed_preflight_completes_on_first_poll_without_entering_failure_floor() {
    let clock = CountingMonotonic::at_millis(0);
    let reads = Arc::new(AtomicUsize::new(0));
    let built = build_with_source_and_clock(
        CountingSource::new(&reads, &[NAMED], &["PUT"]),
        reads,
        CorsPolicy::default(),
        None,
        clock.clone(),
    );
    clock.reset_readings();
    let mut future = Box::pin(send(
        &built.service,
        "OPTIONS",
        PREFLIGHT,
        &[("origin", NAMED), ("access-control-request-method", "PUT")],
    ));
    let mut context = Context::from_waker(Waker::noop());
    let response = match future.as_mut().poll(&mut context) {
        Poll::Ready(response) => response,
        Poll::Pending => panic!("an allowed preflight unexpectedly entered a pending wait"),
    };
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(clock.readings(), 1, "an allowed preflight must not evaluate hold_failure_floor");
}
