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

//! Where a bucket's stored CORS document comes from, and the cache nothing may go around.
//!
//! Responsible for: [`CorsSource`] — the one read a deployment implements — the default
//! [`NoCors`], and [`CachedCorsSource`], the wrapper the builder puts around every source it is
//! given.
//! NOT responsible for: matching or rendering (`rustfs_gateway_core::cors`), rate limiting
//! ([`crate::Governor`]), or persisting anything: this is a read interface and the store is the
//! deployment's.
//! Upstream: `rustfs-gateway-core`. Downstream: `crate::service`, `crate::builder`.
//!
//! # Why the cache is not optional
//!
//! A preflight arrives with no credentials, so the configuration read it triggers is a read an
//! **unauthenticated** caller can ask for at any rate they like. Without a cache that is an
//! amplifier — one cheap request, one storage round trip — and, because a bucket with a document
//! answers differently from one without, an enumeration oracle measurable in latency. So
//! [`crate::ServiceBuilder::cors_source`] takes a bare [`CorsSource`] and stores a
//! [`CachedCorsSource`]; there is no setter that accepts an already-wrapped one and no accessor
//! that hands the inner source back, so no call path reaches the deployment's read without going
//! through here.
//!
//! Five properties make the cache a bound rather than a speed-up:
//!
//! - **Negative entries have the same shape as positive ones.** "This bucket has no document",
//!   "this bucket does not exist" and "the source failed" are all stored as the same `None`, so
//!   the second probe for a non-existent bucket costs exactly what the second probe for a
//!   configured one costs.
//! - **The entry count is capped.** A caller who invents a million bucket names evicts their own
//!   earlier entries rather than growing the process.
//! - **Expiry is spread.** Each key's lifetime is the configured TTL plus a fixed offset derived
//!   from the key itself, so a burst of misses admitted together does not expire together.
//! - **Source reads have a hard deadline.** A backend future that never resolves is collapsed and
//!   cached as the same negative entry as every other source failure.
//! - **Concurrent misses for one key share one read.** The in-flight future is shared through the
//!   runtime-independent `futures-util` primitive; this module does not hand-roll wakeups or make
//!   Tokio a production dependency. Cancelling every waiter removes the abandoned flight.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use futures_timer::Delay;
use futures_util::FutureExt;
use futures_util::future::Shared;
use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::RequestNow;
use rustfs_gateway_types::BucketName;
use rustfs_gateway_types::dto::CorsConfiguration;

/// The name a CORS preflight is limited under.
///
/// Not an operation name: a preflight is answered instead of an operation, so there is none. It
/// is a distinct string so that a deployment can give unauthenticated preflight traffic its own
/// budget without that budget being shared with any request an authenticated caller makes.
pub const CORS_PREFLIGHT: &str = "CorsPreflight";

const DEFAULT_SOURCE_TIMEOUT: Duration = Duration::from_secs(1);

/// A read of a bucket's CORS document failed.
///
/// Carries nothing. The preflight answer is the same whether the read failed, the bucket has no
/// document or the bucket does not exist, so a richer error would be a distinction with no
/// expression on the wire and one more thing to accidentally log next to a bucket name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorsSourceError;

impl core::fmt::Display for CorsSourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the bucket's CORS configuration could not be read")
    }
}

impl std::error::Error for CorsSourceError {}

/// Reads a bucket's stored CORS document.
///
/// Held as `Arc<dyn CorsSource>`, so the async method is a hand-written [`BoxFuture`]
/// (ADR-0002). `Ok(None)` is the answer for a bucket with no document **and** for a bucket that
/// does not exist: an implementation that distinguished them would be handing this layer a fact
/// it is required to discard.
pub trait CorsSource: Send + Sync + 'static {
    /// Reads one bucket's document.
    fn load<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>>;
}

impl<T: CorsSource + ?Sized> CorsSource for Arc<T> {
    fn load<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        (**self).load(bucket)
    }
}

/// The default source: no bucket has a CORS document.
///
/// # Security
///
/// This is the fail-closed default the advisory asks for. Assembled with it, no preflight is ever
/// allowed and no `Access-Control-*` header is ever written — a deployment that wants browsers to
/// reach it has to say so, by installing a source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoCors;

impl CorsSource for NoCors {
    fn load<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        Box::pin(async { Ok(None) })
    }
}

/// How the mandatory cache in front of a [`CorsSource`] behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorsCacheConfig {
    /// The most buckets held at once. A caller inventing names evicts their own entries.
    pub entries: usize,
    /// How long an entry — positive or negative — stays fresh, in seconds.
    pub ttl_seconds: u32,
    /// The width of the per-key offset added to the TTL, in seconds. Zero disables spreading.
    pub jitter_seconds: u32,
}

/// # Security
///
/// The bounded entry count and short lifetime limit unauthenticated cache amplification.
impl Default for CorsCacheConfig {
    /// 4096 buckets, 30 seconds, spread over a further 30.
    ///
    /// The TTL is the delay an operator sees between a `PutBucketCors` and a browser noticing it,
    /// so it is short. 4096 entries is far more buckets than any one deployment serves browsers
    /// for and a few hundred kilobytes at worst.
    fn default() -> Self {
        Self {
            entries: 4096,
            ttl_seconds: 30,
            jitter_seconds: 30,
        }
    }
}

/// A [`CorsSource`] with the framework's cache in front of it.
///
/// Constructed only by [`crate::ServiceBuilder::cors_source`]; see the module documentation for
/// why there is no way to reach the wrapped source directly.
pub struct CachedCorsSource {
    inner: Arc<dyn CorsSource>,
    config: CorsCacheConfig,
    source_timeout: Duration,
    // A plain mutex, never held across an await: the read below drops the guard, awaits, and
    // takes it again. A caller that held it across the source read would serialise every
    // unauthenticated preflight in the process behind the slowest backend.
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    /// Keys in the order they were last stored, so the cap evicts the oldest write.
    order: Vec<String>,
    in_flight: HashMap<String, InFlight>,
}

struct Entry {
    /// `None` for every negative answer, whatever produced it.
    document: Option<Arc<CorsConfiguration>>,
    /// Unix seconds after which this entry is stale.
    expires_at: i64,
}

#[derive(Clone)]
enum LoadOutcome {
    Store(Option<Arc<CorsConfiguration>>),
    DoNotStore,
}

impl LoadOutcome {
    fn document(&self) -> Option<Arc<CorsConfiguration>> {
        match self {
            Self::Store(document) => document.clone(),
            Self::DoNotStore => None,
        }
    }
}

type SharedLoad = Shared<BoxFuture<'static, LoadOutcome>>;

struct InFlight {
    token: Arc<()>,
    load: SharedLoad,
    waiters: usize,
}

struct FlightHandle {
    key: String,
    token: Arc<()>,
    load: SharedLoad,
}

enum Lookup {
    Cached(Option<Arc<CorsConfiguration>>),
    Flight(FlightHandle),
}

struct FlightWaiter<'a> {
    cache: &'a CachedCorsSource,
    key: String,
    token: Arc<()>,
    active: bool,
}

impl FlightWaiter<'_> {
    fn complete(mut self, outcome: LoadOutcome, now: RequestNow) {
        self.cache.complete_flight(&self.key, &self.token, outcome, now);
        self.active = false;
    }
}

impl Drop for FlightWaiter<'_> {
    fn drop(&mut self) {
        if self.active {
            self.cache.release_waiter(&self.key, &self.token);
        }
    }
}

impl core::fmt::Debug for CachedCorsSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CachedCorsSource")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl CachedCorsSource {
    /// Wraps a source. Called by the builder and nowhere else in a deployment's own code.
    /// Source reads are cut off after one second.
    pub fn new(inner: Arc<dyn CorsSource>, config: CorsCacheConfig) -> Self {
        Self::with_source_timeout(inner, config, DEFAULT_SOURCE_TIMEOUT)
    }

    fn with_source_timeout(inner: Arc<dyn CorsSource>, config: CorsCacheConfig, source_timeout: Duration) -> Self {
        Self {
            inner,
            config,
            source_timeout,
            state: Mutex::new(State::default()),
        }
    }

    /// The document for one bucket, from the cache or from the source.
    ///
    /// `None` is every negative answer collapsed: no document, no bucket, or a source that
    /// failed. The three are stored identically, so a second probe cannot tell them apart by
    /// timing either.
    pub async fn get(&self, bucket: &BucketName, now: RequestNow) -> Option<Arc<CorsConfiguration>> {
        let Some(lookup) = self.lookup(bucket, now) else {
            return load_collapsed(Arc::clone(&self.inner), bucket.clone(), self.source_timeout)
                .await
                .document();
        };
        let flight = match lookup {
            Lookup::Cached(document) => return document,
            Lookup::Flight(flight) => flight,
        };
        let waiter = FlightWaiter {
            cache: self,
            key: flight.key,
            token: flight.token,
            active: true,
        };
        let outcome = flight.load.await;
        let loaded = outcome.document();
        waiter.complete(outcome, now);
        loaded
    }

    fn lookup(&self, bucket: &BucketName, now: RequestNow) -> Option<Lookup> {
        let key = bucket.as_str();
        let mut state = self.state.lock().ok()?;
        if let Some(entry) = state.entries.get(key)
            && entry.expires_at > now.unix_seconds()
        {
            return Some(Lookup::Cached(entry.document.clone()));
        }
        if let Some(flight) = state.in_flight.get_mut(key) {
            flight.waiters = flight.waiters.saturating_add(1);
            return Some(Lookup::Flight(FlightHandle {
                key: key.to_owned(),
                token: Arc::clone(&flight.token),
                load: flight.load.clone(),
            }));
        }

        let token = Arc::new(());
        let future: BoxFuture<'static, LoadOutcome> =
            Box::pin(load_collapsed(Arc::clone(&self.inner), bucket.clone(), self.source_timeout));
        let load = future.shared();
        state.in_flight.insert(
            key.to_owned(),
            InFlight {
                token: Arc::clone(&token),
                load: load.clone(),
                waiters: 1,
            },
        );
        Some(Lookup::Flight(FlightHandle {
            key: key.to_owned(),
            token,
            load,
        }))
    }

    fn complete_flight(&self, bucket: &str, token: &Arc<()>, outcome: LoadOutcome, now: RequestNow) {
        let Ok(mut state) = self.state.lock() else {
            // A poisoned mutex means another thread panicked while holding it. Not caching is
            // correct and safe here; refusing the request would turn one panic into an outage.
            return;
        };
        let is_current = state
            .in_flight
            .get(bucket)
            .is_some_and(|flight| Arc::ptr_eq(&flight.token, token));
        if !is_current {
            return;
        }
        if let LoadOutcome::Store(document) = outcome {
            let expires_at = now.unix_seconds().saturating_add(i64::from(self.lifetime_of(bucket)));
            if state
                .entries
                .insert(bucket.to_owned(), Entry { document, expires_at })
                .is_none()
            {
                state.order.push(bucket.to_owned());
            }
            while state.order.len() > self.config.entries.max(1) {
                let evicted = state.order.remove(0);
                state.entries.remove(&evicted);
            }
        }
        state.in_flight.remove(bucket);
    }

    fn release_waiter(&self, bucket: &str, token: &Arc<()>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let remove = if let Some(flight) = state.in_flight.get_mut(bucket) {
            if Arc::ptr_eq(&flight.token, token) {
                flight.waiters = flight.waiters.saturating_sub(1);
                flight.waiters == 0
            } else {
                false
            }
        } else {
            false
        };
        if remove {
            state.in_flight.remove(bucket);
        }
    }

    /// How long this key's entry lives: the TTL plus an offset derived from the key.
    ///
    /// Derived rather than random so that the spread is reproducible — a test can assert that two
    /// keys admitted in the same second do not expire in the same second, which a random offset
    /// would make a flake.
    #[must_use]
    pub fn lifetime_of(&self, bucket: &str) -> u32 {
        if self.config.jitter_seconds == 0 {
            return self.config.ttl_seconds;
        }
        let spread = fnv1a(bucket.as_bytes()) % u64::from(self.config.jitter_seconds);
        self.config
            .ttl_seconds
            .saturating_add(u32::try_from(spread).unwrap_or(self.config.jitter_seconds))
    }

    /// The configuration in force.
    #[must_use]
    pub const fn config(&self) -> &CorsCacheConfig {
        &self.config
    }

    /// How many buckets are currently held. For tests and for a deployment's own metrics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().map_or(0, |state| state.entries.len())
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

async fn load_collapsed(inner: Arc<dyn CorsSource>, bucket: BucketName, timeout: Duration) -> LoadOutcome {
    match load_before_deadline(inner.load(&bucket), timeout).await {
        Ok(document) => LoadOutcome::Store(document.map(Arc::new)),
        Err(_) if rustfs_gateway_core::cors::source_absence_is_collapsed() => LoadOutcome::Store(None),
        // The mutation keeps a failed read distinguishable from an ordinary negative entry by
        // refusing to cache it. The next request therefore reaches the source again, which the
        // gateway-level counter observes without exposing the distinction on the wire.
        Err(_) => LoadOutcome::DoNotStore,
    }
}

async fn load_before_deadline(
    mut future: BoxFuture<'_, Result<Option<CorsConfiguration>, CorsSourceError>>,
    timeout: Duration,
) -> Result<Option<CorsConfiguration>, CorsSourceError> {
    if timeout.is_zero() {
        return Err(CorsSourceError);
    }
    let mut deadline = Box::pin(Delay::new(timeout));
    poll_fn(move |cx| {
        if let Poll::Ready(result) = future.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        if deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(CorsSourceError));
        }
        Poll::Pending
    })
    .await
}

/// FNV-1a, 64 bit. Chosen over `DefaultHasher` because the offset it produces is asserted in a
/// test, and `DefaultHasher`'s output is explicitly not stable across releases.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A source that counts its reads and answers from a fixed table.
    struct Counting {
        reads: AtomicUsize,
        configured: Vec<String>,
    }

    impl Counting {
        fn new(configured: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                reads: AtomicUsize::new(0),
                configured: configured.iter().map(|name| (*name).to_owned()).collect(),
            })
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl CorsSource for Counting {
        fn load<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let hit = self.configured.iter().any(|name| name == bucket.as_str());
            Box::pin(async move { Ok(hit.then(CorsConfiguration::default)) })
        }
    }

    /// A source that always fails.
    struct Broken;

    impl CorsSource for Broken {
        fn load<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
            Box::pin(async { Err(CorsSourceError) })
        }
    }

    struct Never(AtomicUsize);

    impl CorsSource for Never {
        fn load<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending())
        }
    }

    struct CancelThenReady(AtomicUsize);

    impl CorsSource for CancelThenReady {
        fn load<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
            let attempt = self.0.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                Box::pin(std::future::pending())
            } else {
                Box::pin(async { Ok(None) })
            }
        }
    }

    fn bucket(name: &str) -> BucketName {
        BucketName::new(name).expect("a legal bucket name")
    }

    fn at(seconds: i64) -> RequestNow {
        RequestNow::from_unix_seconds(seconds)
    }

    fn cache(inner: Arc<dyn CorsSource>, config: CorsCacheConfig) -> CachedCorsSource {
        CachedCorsSource::new(inner, config)
    }

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    /// Positive — a configured bucket's document is returned, and the second read inside the TTL
    /// does not reach the source.
    #[tokio::test]
    async fn a_hit_is_served_once_from_the_source() {
        let source = Counting::new(&["configured"]);
        let cache = cache(Arc::clone(&source) as Arc<dyn CorsSource>, CorsCacheConfig::default());
        assert!(cache.get(&bucket("configured"), at(1000)).await.is_some());
        assert!(cache.get(&bucket("configured"), at(1001)).await.is_some());
        assert_eq!(source.reads(), 1);
    }

    /// Positive — two keys admitted in the same second do not expire in the same second, so a
    /// burst of misses does not become a synchronised burst of reloads.
    #[test]
    fn expiry_is_spread_across_keys() {
        let cache = cache(Arc::new(NoCors), CorsCacheConfig::default());
        let lifetimes: std::collections::BTreeSet<u32> = ["alpha", "beta", "gamma", "delta", "epsilon"]
            .iter()
            .map(|name| cache.lifetime_of(name))
            .collect();
        assert!(lifetimes.len() > 1, "every key got the same lifetime: {lifetimes:?}");
        for lifetime in lifetimes {
            assert!((30..60).contains(&lifetime), "{lifetime} is outside ttl..ttl+jitter");
        }
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    /// Negative — a bucket the source knows nothing about is cached too. Without a negative entry
    /// every probe for a name that does not exist is a fresh storage read, which is the amplifier
    /// this cache exists to close.
    #[tokio::test]
    async fn n_a_miss_is_cached_as_hard_as_a_hit() {
        let source = Counting::new(&[]);
        let cache = cache(Arc::clone(&source) as Arc<dyn CorsSource>, CorsCacheConfig::default());
        for _ in 0..1000 {
            assert!(cache.get(&bucket("never-existed"), at(1000)).await.is_none());
        }
        assert_eq!(source.reads(), 1);
    }

    /// Negative — a failing source is cached as a negative entry as well, so a backend that is
    /// down cannot be reached once per unauthenticated request.
    #[tokio::test]
    async fn n_a_failing_source_does_not_become_a_per_request_read() {
        struct CountingBroken(AtomicUsize);
        impl CorsSource for CountingBroken {
            fn load<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Err(CorsSourceError) })
            }
        }
        let source = Arc::new(CountingBroken(AtomicUsize::new(0)));
        let cache = cache(Arc::clone(&source) as Arc<dyn CorsSource>, CorsCacheConfig::default());
        for _ in 0..100 {
            assert!(cache.get(&bucket("configured"), at(1000)).await.is_none());
        }
        assert_eq!(source.0.load(Ordering::SeqCst), 1);
        // And the answer is the one a bucket with no document gets, so the failure is invisible.
        assert!(cache.get(&bucket("configured"), at(1000)).await.is_none());
        let broken = CachedCorsSource::new(Arc::new(Broken), CorsCacheConfig::default());
        assert!(broken.get(&bucket("any"), at(1)).await.is_none());
    }

    /// Negative — a source that never resolves is cut off and cached as the same absence as every
    /// other source failure. The outer timeout is only a test watchdog: production must win first.
    #[tokio::test]
    async fn n_a_never_resolving_source_is_cut_off_and_negative_cached() {
        let source = Arc::new(Never(AtomicUsize::new(0)));
        let cache = CachedCorsSource::with_source_timeout(
            Arc::clone(&source) as Arc<dyn CorsSource>,
            CorsCacheConfig::default(),
            Duration::from_millis(5),
        );
        let name = bucket("configured");
        let first = tokio::select! {
            result = cache.get(&name, at(1000)) => Some(result),
            () = futures_timer::Delay::new(Duration::from_millis(100)) => None,
        }
        .expect("the mandatory source timeout must beat the test watchdog");
        assert!(first.is_none());
        assert!(cache.get(&bucket("configured"), at(1000)).await.is_none());
        assert_eq!(source.0.load(Ordering::SeqCst), 1, "a timed-out source was retried");
    }

    /// Negative — concurrent cold misses for one bucket share one source read. Without
    /// single-flight an unauthenticated burst reaches the deployment store once per request even
    /// though every request asks for the same cache key.
    #[tokio::test]
    async fn n_concurrent_cold_misses_share_one_source_read() {
        let source = Arc::new(Never(AtomicUsize::new(0)));
        let cache = Arc::new(cache(Arc::clone(&source) as Arc<dyn CorsSource>, CorsCacheConfig::default()));
        let name = bucket("same-bucket");
        let mut requests = Vec::new();
        for _ in 0..32 {
            let mut request = Box::pin(cache.get(&name, at(1000)));
            poll_fn(|context| match request.as_mut().poll(context) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("a never-ready source completed"),
            })
            .await;
            requests.push(request);
        }
        assert_eq!(source.0.load(Ordering::SeqCst), 1, "concurrent misses were not coalesced");
    }

    /// Negative — cancelling the last waiter removes its abandoned flight. Otherwise every later
    /// request for that bucket would attach to a future nobody can complete.
    #[tokio::test]
    async fn n_cancelling_the_last_waiter_allows_a_retry() {
        let source = Arc::new(CancelThenReady(AtomicUsize::new(0)));
        let cache = Arc::new(cache(Arc::clone(&source) as Arc<dyn CorsSource>, CorsCacheConfig::default()));
        let first_cache = Arc::clone(&cache);
        let first = tokio::spawn(async move { first_cache.get(&bucket("same-bucket"), at(1000)).await });
        while source.0.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        first.abort();
        assert!(first.await.is_err(), "the first waiter was not cancelled");

        let name = bucket("same-bucket");
        let retry = tokio::select! {
            result = cache.get(&name, at(1000)) => Some(result),
            () = Delay::new(Duration::from_millis(100)) => None,
        }
        .expect("an abandoned flight blocked the retry");
        assert!(retry.is_none());
        assert_eq!(source.0.load(Ordering::SeqCst), 2, "the cancelled flight was reused");
    }

    /// Negative — cancelling one waiter must not discard a flight that another waiter still
    /// needs. A third waiter must join that same flight rather than start another source read.
    #[tokio::test]
    async fn n_cancelling_one_waiter_keeps_the_shared_flight() {
        let source = Arc::new(Never(AtomicUsize::new(0)));
        let cache = Arc::new(cache(Arc::clone(&source) as Arc<dyn CorsSource>, CorsCacheConfig::default()));
        let name = bucket("same-bucket");
        let mut first = Box::pin(cache.get(&name, at(1000)));
        poll_fn(|context| match first.as_mut().poll(context) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("a never-ready source completed"),
        })
        .await;
        let mut second = Box::pin(cache.get(&name, at(1000)));
        poll_fn(|context| match second.as_mut().poll(context) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("a never-ready source completed"),
        })
        .await;
        drop(first);

        let mut third = Box::pin(cache.get(&name, at(1000)));
        poll_fn(|context| match third.as_mut().poll(context) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("a never-ready source completed"),
        })
        .await;
        assert_eq!(source.0.load(Ordering::SeqCst), 1, "one cancellation discarded a live flight");
    }

    /// Negative — the entry count is capped, so a caller inventing names cannot grow the process.
    #[tokio::test]
    async fn n_the_entry_count_is_capped() {
        let source = Counting::new(&[]);
        let cache = cache(
            Arc::clone(&source) as Arc<dyn CorsSource>,
            CorsCacheConfig {
                entries: 8,
                ..CorsCacheConfig::default()
            },
        );
        for index in 0..5000 {
            let name = format!("random-bucket-{index}");
            let _ = cache.get(&bucket(&name), at(1000)).await;
        }
        assert_eq!(cache.len(), 8);
    }

    /// Negative — an entry goes stale. A cache that never expired would serve a deleted CORS
    /// document until the process restarted.
    #[tokio::test]
    async fn n_an_entry_expires() {
        let source = Counting::new(&["configured"]);
        let cache = cache(Arc::clone(&source) as Arc<dyn CorsSource>, CorsCacheConfig::default());
        let name = bucket("configured");
        assert!(cache.get(&name, at(1000)).await.is_some());
        // Past the longest lifetime the configuration can hand out.
        let beyond = 1000 + i64::from(cache.config().ttl_seconds + cache.config().jitter_seconds) + 1;
        assert!(cache.get(&name, at(beyond)).await.is_some());
        assert_eq!(source.reads(), 2);
    }

    /// Negative — a zero jitter is the TTL exactly, so the spreading is a configuration and not a
    /// hard-coded behaviour.
    #[test]
    fn n_zero_jitter_is_the_bare_ttl() {
        let cache = cache(
            Arc::new(NoCors),
            CorsCacheConfig {
                ttl_seconds: 5,
                jitter_seconds: 0,
                ..CorsCacheConfig::default()
            },
        );
        assert_eq!(cache.lifetime_of("alpha"), 5);
        assert_eq!(cache.lifetime_of("beta"), 5);
    }

    /// Negative — the default source answers nothing for every bucket, so a deployment that
    /// installs none never writes a CORS header.
    #[tokio::test]
    async fn n_the_default_source_knows_no_bucket() {
        let cache = cache(Arc::new(NoCors), CorsCacheConfig::default());
        assert!(cache.get(&bucket("anything"), at(1)).await.is_none());
        assert!(cache.get(&bucket("anything-else"), at(1)).await.is_none());
    }
}
