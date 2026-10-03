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

//! The mandatory boundary around an unauthenticated credential lookup.
//!
//! Responsible for: the hard deadline, provider panic isolation, bounded jittered negative cache,
//! and outcome counters. NOT responsible for: credential values and provider semantics
//! (`super::credentials`), signature verification (`super::authenticator`), or per-IP quotas
//! (`super::governor`). Upstream: a deployment's [`CredentialProvider`]. Downstream:
//! [`super::SigV4Authenticator`].

use std::collections::{HashMap, VecDeque};
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_timer::Delay;
use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::timing::LookupBudget;

use crate::clock::{MonotonicClock, MonotonicNow, SystemMonotonic};

use super::credentials::{CredentialLookup, CredentialProvider, ProviderError};

/// Framework defaults for the hard timeout and bounded negative cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialGuardConfig {
    /// Timeout and jittered negative-cache lifetime shared with the signature timing contract.
    pub budget: LookupBudget,
    /// Maximum negative entries. Zero disables negative caching.
    pub negative_entries: usize,
}

/// # Security
///
/// Lookup timeout and bounded negative caching are enabled so forged identities cannot amplify
/// provider work without limit.
impl Default for CredentialGuardConfig {
    /// One-second timeout, 30-second negative TTL, 0–30-second deterministic jitter, 4096 entries.
    fn default() -> Self {
        Self {
            budget: LookupBudget::DEFAULT,
            negative_entries: 4096,
        }
    }
}

/// A snapshot of provider outcomes useful to metrics exporters.
///
/// # Security
///
/// The default is an all-zero observation only. It neither resets the live counters nor changes
/// lookup admission, caching, or timeout behaviour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProviderMetrics {
    /// Backend errors observed.
    pub backend_errors: u64,
    /// Hard timeouts observed.
    pub timeouts: u64,
    /// Provider panics isolated.
    pub panics: u64,
    /// Lookups served by the negative cache.
    pub negative_cache_hits: u64,
}

#[derive(Default)]
struct GuardMetrics {
    backend_errors: AtomicU64,
    timeouts: AtomicU64,
    panics: AtomicU64,
    negative_cache_hits: AtomicU64,
}

/// Missing keys and when each stops being served, with their insertion order for eviction.
///
/// Every operation is O(1) amortised under the lock, because every request's credential lookup
/// takes it before its signature is checked, and forged keys keep the cache full
/// (rustfs/gateway#1221). An expired entry stays until its key is cached again or its turn to be
/// evicted comes; nothing scans the cache.
#[derive(Default)]
struct NegativeCache {
    entries: HashMap<String, NegativeEntry>,
    /// Insertion order, oldest first. A slot whose generation no longer matches its key's entry is
    /// stale — the key was dropped or cached again since — and is skipped, never evicted by.
    order: VecDeque<(String, u64)>,
    next_generation: u64,
}

#[derive(Clone, Copy)]
struct NegativeEntry {
    expiry: MonotonicNow,
    generation: u64,
}

impl NegativeCache {
    fn fresh(&self, access_key_id: &str, now: MonotonicNow) -> bool {
        self.entries.get(access_key_id).is_some_and(|entry| entry.expiry > now)
    }

    fn insert(&mut self, access_key_id: &str, expiry: MonotonicNow, capacity: usize) {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.entries
            .insert(access_key_id.to_owned(), NegativeEntry { expiry, generation });
        self.order.push_back((access_key_id.to_owned(), generation));
        while self.entries.len() > capacity {
            let Some((oldest, generation)) = self.order.pop_front() else {
                break;
            };
            if self.entries.get(&oldest).is_some_and(|entry| entry.generation == generation) {
                self.entries.remove(&oldest);
            }
        }
        // Stale slots accumulate when keys are cached again or dropped on lookup. Compacting only
        // once they outnumber the live entries keeps the order bounded at twice the capacity for
        // O(1) amortised cost.
        if self.order.len() > capacity.saturating_mul(2) {
            let entries = &self.entries;
            self.order
                .retain(|(key, generation)| entries.get(key).is_some_and(|entry| entry.generation == *generation));
        }
    }
}

/// Mandatory protection for an unauthenticated credential lookup: deadline, panic boundary and
/// a bounded, jittered `NotFound` cache. Provider errors are never cached; positive caching is
/// intentionally absent so key rotation is visible on the next request.
pub struct GuardedCredentialProvider {
    inner: Arc<dyn CredentialProvider>,
    config: CredentialGuardConfig,
    clock: Arc<dyn MonotonicClock>,
    cache: Mutex<NegativeCache>,
    metrics: GuardMetrics,
}

impl core::fmt::Debug for GuardedCredentialProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuardedCredentialProvider")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl GuardedCredentialProvider {
    /// Wraps a provider with [`CredentialGuardConfig::default`].
    #[must_use]
    pub fn new(inner: Arc<dyn CredentialProvider>) -> Self {
        Self::with_config(inner, CredentialGuardConfig::default())
    }

    /// Wraps a provider with an explicit posture.
    #[must_use]
    pub fn with_config(inner: Arc<dyn CredentialProvider>, config: CredentialGuardConfig) -> Self {
        Self {
            inner,
            config,
            clock: Arc::new(SystemMonotonic::new()),
            cache: Mutex::new(NegativeCache::default()),
            metrics: GuardMetrics::default(),
        }
    }

    /// The protection settings in force.
    #[must_use]
    pub const fn config(&self) -> &CredentialGuardConfig {
        &self.config
    }

    /// Current metric counters.
    #[must_use]
    pub fn metrics(&self) -> ProviderMetrics {
        ProviderMetrics {
            backend_errors: self.metrics.backend_errors.load(Ordering::Relaxed),
            timeouts: self.metrics.timeouts.load(Ordering::Relaxed),
            panics: self.metrics.panics.load(Ordering::Relaxed),
            negative_cache_hits: self.metrics.negative_cache_hits.load(Ordering::Relaxed),
        }
    }

    fn fresh_negative(&self, access_key_id: &str, now: MonotonicNow) -> bool {
        let Ok(cache) = self.cache.lock() else {
            return false;
        };
        cache.fresh(access_key_id, now)
    }

    fn store_negative(&self, access_key_id: &str, now: MonotonicNow) {
        if self.config.negative_entries == 0 || self.config.budget.negative_ttl().is_zero() {
            return;
        }
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        let lifetime_millis = u64::try_from(self.negative_lifetime(access_key_id).as_millis()).unwrap_or(u64::MAX);
        let expiry = MonotonicNow::from_millis(now.millis().saturating_add(lifetime_millis));
        cache.insert(access_key_id, expiry, self.config.negative_entries);
    }

    /// Effective lifetime for one missing key, including deterministic jitter.
    #[must_use]
    pub fn negative_lifetime(&self, access_key_id: &str) -> Duration {
        let width = self.config.budget.negative_ttl_jitter().as_nanos();
        if width == 0 {
            return self.config.budget.negative_ttl();
        }
        let spread = u128::from(fnv1a(access_key_id.as_bytes())) % width;
        self.config
            .budget
            .negative_ttl()
            .saturating_add(Duration::from_nanos(u64::try_from(spread).unwrap_or(u64::MAX)))
    }

    fn record_error(&self, error: ProviderError) {
        match error {
            ProviderError::Timeout => self.metrics.timeouts.fetch_add(1, Ordering::Relaxed),
            ProviderError::Panicked => self.metrics.panics.fetch_add(1, Ordering::Relaxed),
            ProviderError::Backend | ProviderError::Unavailable => self.metrics.backend_errors.fetch_add(1, Ordering::Relaxed),
        };
    }
}

impl CredentialProvider for GuardedCredentialProvider {
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        let now = self.clock.monotonic();
        if self.fresh_negative(access_key_id, now) {
            self.metrics.negative_cache_hits.fetch_add(1, Ordering::Relaxed);
            return Box::pin(async { Ok(CredentialLookup::NotFound) });
        }

        let started = catch_unwind(AssertUnwindSafe(|| self.inner.lookup(access_key_id)));
        Box::pin(async move {
            let result = match started {
                Ok(future) => lookup_before_deadline(future, self.config.budget.timeout()).await,
                Err(_) => Err(ProviderError::Panicked),
            };
            match result {
                Ok(CredentialLookup::NotFound) => {
                    self.store_negative(access_key_id, now);
                    Ok(CredentialLookup::NotFound)
                }
                Ok(found @ CredentialLookup::Found(_)) => Ok(found),
                Err(error) => {
                    self.record_error(error);
                    Err(error)
                }
            }
        })
    }
}

struct PanicBoundary<'a> {
    inner: BoxFuture<'a, Result<CredentialLookup, ProviderError>>,
}

impl Future for PanicBoundary<'_> {
    type Output = Result<CredentialLookup, ProviderError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        catch_unwind(AssertUnwindSafe(|| self.inner.as_mut().poll(cx))).unwrap_or(Poll::Ready(Err(ProviderError::Panicked)))
    }
}

async fn lookup_before_deadline(
    future: BoxFuture<'_, Result<CredentialLookup, ProviderError>>,
    timeout: Duration,
) -> Result<CredentialLookup, ProviderError> {
    if timeout.is_zero() {
        return Err(ProviderError::Timeout);
    }
    let mut lookup = PanicBoundary { inner: future };
    let mut deadline = Box::pin(Delay::new(timeout));
    poll_fn(move |cx| {
        if let Poll::Ready(result) = Pin::new(&mut lookup).poll(cx) {
            return Poll::Ready(result);
        }
        if deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(ProviderError::Timeout));
        }
        Poll::Pending
    })
    .await
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct CountingMiss(AtomicUsize);

    impl CredentialProvider for CountingMiss {
        fn lookup<'a>(&'a self, _access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(CredentialLookup::NotFound) })
        }
    }

    /// Positive — one missing key is loaded once and then served from the default negative cache.
    #[tokio::test]
    async fn a_repeated_missing_key_does_not_amplify_to_the_backend() {
        let inner = Arc::new(CountingMiss(AtomicUsize::new(0)));
        let guarded = GuardedCredentialProvider::new(Arc::clone(&inner) as Arc<dyn CredentialProvider>);
        for _ in 0..100 {
            assert!(matches!(guarded.lookup("AKIDMISSING").await, Ok(CredentialLookup::NotFound)));
        }
        assert_eq!(inner.0.load(Ordering::SeqCst), 1);
        assert_eq!(guarded.metrics().negative_cache_hits, 99);
    }

    struct Broken(AtomicUsize);

    impl CredentialProvider for Broken {
        fn lookup<'a>(&'a self, _access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(ProviderError::Backend) })
        }
    }

    /// Negative — backend errors are never inserted into the negative cache.
    #[tokio::test]
    async fn n_provider_errors_are_not_cached() {
        let inner = Arc::new(Broken(AtomicUsize::new(0)));
        let guarded = GuardedCredentialProvider::new(Arc::clone(&inner) as Arc<dyn CredentialProvider>);
        assert!(matches!(guarded.lookup("AKID").await, Err(ProviderError::Backend)));
        assert!(matches!(guarded.lookup("AKID").await, Err(ProviderError::Backend)));
        assert_eq!(inner.0.load(Ordering::SeqCst), 2);
        assert_eq!(guarded.metrics().backend_errors, 2);
    }

    struct Panics;

    impl CredentialProvider for Panics {
        fn lookup<'a>(&'a self, _access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
            Box::pin(async { panic!("provider panic fixture") })
        }
    }

    /// Negative — a provider panic becomes a closed provider error.
    #[tokio::test]
    async fn n_provider_panics_are_isolated() {
        let guarded = GuardedCredentialProvider::new(Arc::new(Panics));
        assert!(matches!(guarded.lookup("AKID").await, Err(ProviderError::Panicked)));
        assert_eq!(guarded.metrics().panics, 1);
    }

    struct Never;

    impl CredentialProvider for Never {
        fn lookup<'a>(&'a self, _access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
            Box::pin(std::future::pending())
        }
    }

    /// Negative — a provider that never wakes is cut off by the hard timeout.
    #[tokio::test]
    async fn n_a_stalled_provider_is_timed_out() {
        let guarded = GuardedCredentialProvider::with_config(
            Arc::new(Never),
            CredentialGuardConfig {
                budget: LookupBudget::new(Duration::from_millis(5), Duration::from_secs(30), Duration::from_secs(30)),
                ..CredentialGuardConfig::default()
            },
        );
        assert!(matches!(guarded.lookup("AKID").await, Err(ProviderError::Timeout)));
        assert_eq!(guarded.metrics().timeouts, 1);
    }

    /// A guard over `CountingMiss` on a clock the test drives, with a fixed 30-second negative
    /// lifetime (no jitter) and room for `entries` keys.
    fn manual(entries: usize) -> (GuardedCredentialProvider, Arc<CountingMiss>, Arc<crate::clock::ManualMonotonic>) {
        let inner = Arc::new(CountingMiss(AtomicUsize::new(0)));
        let clock = Arc::new(crate::clock::ManualMonotonic::at_millis(0));
        let guarded = GuardedCredentialProvider {
            inner: Arc::clone(&inner) as Arc<dyn CredentialProvider>,
            config: CredentialGuardConfig {
                budget: LookupBudget::new(Duration::from_secs(1), Duration::from_secs(30), Duration::ZERO),
                negative_entries: entries,
            },
            clock: Arc::clone(&clock) as Arc<dyn MonotonicClock>,
            cache: Mutex::new(NegativeCache::default()),
            metrics: GuardMetrics::default(),
        };
        (guarded, inner, clock)
    }

    /// How many times the backend was asked.
    fn calls(inner: &CountingMiss) -> usize {
        inner.0.load(Ordering::SeqCst)
    }

    async fn miss(guarded: &GuardedCredentialProvider, key: &str) {
        assert!(matches!(guarded.lookup(key).await, Ok(CredentialLookup::NotFound)));
    }

    /// Negative — an entry past its lifetime is not served: the backend is asked again.
    #[tokio::test]
    async fn an_expired_negative_entry_is_not_served() {
        let (guarded, inner, clock) = manual(4);
        miss(&guarded, "AKIDGONE").await;
        clock.advance_seconds(29);
        miss(&guarded, "AKIDGONE").await;
        assert_eq!(calls(&inner), 1, "a live entry was not served");
        clock.advance_seconds(1);
        miss(&guarded, "AKIDGONE").await;
        assert_eq!(calls(&inner), 2, "an expired entry was served");
    }

    /// Negative — at capacity the oldest key is the one evicted, and only it.
    #[tokio::test]
    async fn the_oldest_negative_entry_is_evicted_first() {
        let (guarded, inner, _clock) = manual(2);
        for key in ["AKIDA", "AKIDB", "AKIDC"] {
            miss(&guarded, key).await;
        }
        assert_eq!(calls(&inner), 3);
        miss(&guarded, "AKIDB").await;
        miss(&guarded, "AKIDC").await;
        assert_eq!(calls(&inner), 3, "a younger key was evicted");
        miss(&guarded, "AKIDA").await;
        assert_eq!(calls(&inner), 4, "the oldest key outlived the capacity");
    }

    /// Negative — a key cached again after it expired is not evicted by the slot its first entry
    /// left behind: with room for two keys and only two cached, both are served.
    #[tokio::test]
    async fn a_key_cached_again_after_expiry_is_not_evicted_by_its_old_slot() {
        let (guarded, inner, clock) = manual(2);
        miss(&guarded, "AKIDAGAIN").await;
        clock.advance_seconds(30);
        miss(&guarded, "AKIDAGAIN").await;
        miss(&guarded, "AKIDOTHER").await;
        assert_eq!(calls(&inner), 3);
        miss(&guarded, "AKIDAGAIN").await;
        miss(&guarded, "AKIDOTHER").await;
        assert_eq!(calls(&inner), 3, "a live entry was evicted under capacity");
    }

    /// Negative — eviction skips a slot its key has outlived: A was cached, expired and was cached
    /// again after B, so B is the oldest live key and the one a third key evicts, not A.
    #[tokio::test]
    async fn a_stale_slot_is_skipped_so_the_oldest_live_key_is_evicted() {
        let (guarded, inner, clock) = manual(2);
        miss(&guarded, "AKIDA").await;
        clock.advance_seconds(20);
        miss(&guarded, "AKIDB").await;
        clock.advance_seconds(10);
        miss(&guarded, "AKIDA").await;
        miss(&guarded, "AKIDC").await;
        assert_eq!(calls(&inner), 4);
        miss(&guarded, "AKIDA").await;
        miss(&guarded, "AKIDC").await;
        assert_eq!(calls(&inner), 4, "the key cached last but one was evicted");
        miss(&guarded, "AKIDB").await;
        assert_eq!(calls(&inner), 5, "the oldest live key outlived the capacity");
    }

    /// Negative — a stream of distinct forged keys leaves the cache at its capacity, however long
    /// the stream runs.
    #[tokio::test]
    async fn distinct_forged_keys_leave_the_cache_at_its_capacity() {
        let (guarded, _inner, _clock) = manual(8);
        for round in 0..4_000_u64 {
            miss(&guarded, &format!("AKIDFORGED{round}")).await;
        }
        let cache = guarded.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(cache.entries.len(), 8);
        assert_eq!(cache.order.len(), 8, "eviction left order slots behind");
    }

    /// Negative — keys cached again and again after they expire leave the eviction bookkeeping
    /// bounded by twice the capacity, although nothing is evicted: every stale slot is dropped.
    #[tokio::test]
    async fn keys_cached_again_leave_the_eviction_order_bounded() {
        let (guarded, inner, clock) = manual(8);
        for round in 0..1_000_u64 {
            miss(&guarded, &format!("AKIDAGAIN{}", round % 3)).await;
            clock.advance_seconds(31);
        }
        assert_eq!(calls(&inner), 1_000, "an expired entry was served");
        let cache = guarded.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(cache.entries.len(), 3);
        assert!(cache.order.len() <= 16, "{} order slots kept for a capacity of 8", cache.order.len());
    }

    /// Positive — jitter spreads keys while remaining inside the configured interval.
    #[test]
    fn negative_expiry_is_spread() {
        let guarded = GuardedCredentialProvider::new(Arc::new(CountingMiss(AtomicUsize::new(0))));
        let lifetimes: std::collections::BTreeSet<_> = ["alpha", "beta", "gamma", "delta"]
            .into_iter()
            .map(|key| guarded.negative_lifetime(key))
            .collect();
        assert!(lifetimes.len() > 1);
        assert!(
            lifetimes
                .iter()
                .all(|value| *value >= Duration::from_secs(30) && *value < Duration::from_secs(60))
        );
    }
}
