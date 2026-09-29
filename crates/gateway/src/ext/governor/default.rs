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

//! The framework's mandatory pre-authentication limiter.
//!
//! Responsible for: [`DefaultGovernor`], its aggregate, per-address and per-class token buckets,
//! the bounded sharded address table, and [`LayeredGovernor`], which ANDs the framework limit with
//! a deployment governor.
//! NOT responsible for: per-bucket or per-tenant quotas, which belong to the deployment; deriving
//! a peer address from proxy headers, which belongs to a trusted transport adapter; or choosing a
//! refusal response, which remains `crate::service`'s fixed `503 SlowDown` path.
//! Upstream: `crate::clock`, `super::rates`, `super::meter`. Downstream: `crate::builder`.
//!
//! Aggregate and class meters use one atomic word each. Address state is sharded so unrelated
//! clients never queue behind one process-wide mutex. A shard transfers the least-recently-used
//! meter to a new key at capacity; debt therefore survives eviction instead of turning address
//! rotation into a refill mechanism.
//!
//! # What the meters count
//!
//! Unverified work, and nothing else. Every admission is charged to the aggregate, class and
//! client meters before any of that work runs, and `crate::service` reports a request whose
//! signature verified through [`Governor::verified`], which returns the charge. What stays spent
//! is a request still waiting for its verdict, a request whose authentication failed, and a
//! request that presented no credentials. A verified client is therefore never capped by a
//! limiter that was never meant to meter it — per-identity quotas are the `Authorizer`'s — while
//! the bound on what a caller without a secret can force is exactly what it was.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::future::Future;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use rustfs_gateway_core::BoxFuture;

use super::meter::{AtomicMeter, Meter};
use super::rates::{GovernorRates, Rate};
use super::{ClassKind, Governor, GovernorRequest, Lease};
use crate::clock::{ManualMonotonic, MonotonicClock, MonotonicNow, SystemMonotonic};

const CLIENT_SHARDS: usize = 32;

#[derive(Debug)]
struct ClientEntry {
    meter: Meter,
    last_seen: u64,
}

#[derive(Debug)]
struct ClientShard {
    entries: HashMap<IpAddr, ClientEntry>,
    overflow: Meter,
    generation: u64,
    capacity: usize,
}

impl ClientShard {
    fn new(rate: Rate, now: MonotonicNow, bound: usize) -> Self {
        // Eviction is a remove plus an insert under a different key, so a full shard keeps leaving
        // deleted slots behind. When the map runs out of free slots it rehashes in place only if
        // its live entries fit in half of its storage; sized to exactly `bound` it instead grows
        // once, allocating on a decision path that has been warm for hours. Twice the bound plus
        // the one entry being inserted is the storage that growth would have ended at anyway.
        let capacity = bound.saturating_mul(2).saturating_add(2);
        Self {
            entries: HashMap::with_capacity(capacity),
            overflow: Meter::full(rate, now),
            generation: 0,
            capacity: bound,
        }
    }

    fn take(&mut self, key: IpAddr, rate: Rate, now: MonotonicNow) -> bool {
        self.generation = self.generation.saturating_add(1);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_seen = self.generation;
            return entry.meter.take(rate, now);
        }
        if self.capacity == 0 || rate.admits_nothing() {
            return self.overflow.take(rate, now);
        }

        let mut meter = Meter::full(rate, now);
        if self.entries.len() >= self.capacity {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(address, _)| *address);
            if let Some(victim) = victim
                && let Some(evicted) = self.entries.remove(&victim)
            {
                meter = evicted.meter.after_eviction(rate, now);
            }
        }
        let admitted = meter.take(rate, now);
        self.entries.insert(
            key,
            ClientEntry {
                meter,
                last_seen: self.generation,
            },
        );
        admitted
    }

    /// Returns one charge to `key`'s meter, if the key still has the meter it was charged to.
    ///
    /// A key evicted since its charge handed its debt to whichever key replaced it. Crediting that
    /// key would give one caller another's refund, so the charge is kept instead.
    fn refund(&mut self, key: IpAddr, rate: Rate) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.meter.refund(rate);
        } else if self.capacity == 0 {
            self.overflow.refund(rate);
        }
    }
}

#[derive(Debug)]
struct ClientMeters {
    shards: Box<[Mutex<ClientShard>]>,
    unknown: Mutex<Meter>,
    hasher: RandomState,
}

impl ClientMeters {
    fn new(rate: Rate, now: MonotonicNow, bound: usize) -> Self {
        let base = bound / CLIENT_SHARDS;
        let remainder = bound % CLIENT_SHARDS;
        let shards = (0..CLIENT_SHARDS)
            .map(|index| Mutex::new(ClientShard::new(rate, now, base + usize::from(index < remainder))))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards,
            unknown: Mutex::new(Meter::full(rate, now)),
            hasher: RandomState::new(),
        }
    }

    fn take(&self, address: Option<IpAddr>, rate: Rate, now: MonotonicNow) -> bool {
        // An unlimited per-client layer keeps no address entry and takes no lock.
        if rate.admits_everything() {
            return true;
        }
        let Some(address) = address else {
            return lock(&self.unknown).take(rate, now);
        };
        let index = self.shard_index(address);
        let Some(shard) = self.shards.get(index) else {
            return false;
        };
        lock(shard).take(address, rate, now)
    }

    fn refund(&self, address: Option<IpAddr>, rate: Rate) {
        if rate.admits_everything() {
            return;
        }
        let Some(address) = address else {
            lock(&self.unknown).refund(rate);
            return;
        };
        if let Some(shard) = self.shards.get(self.shard_index(address)) {
            lock(shard).refund(address, rate);
        }
    }

    fn shard_index(&self, address: IpAddr) -> usize {
        usize::try_from(self.hasher.hash_one(address) % CLIENT_SHARDS as u64).unwrap_or(0)
    }

    fn len(&self) -> usize {
        self.shards.iter().map(|shard| lock(shard).entries.len()).sum()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The limiter installed even when a deployment configures nothing.
///
/// It bounds unverified work: [`Governor::verified`] returns an admitted request's charge once
/// its signature verified, so only requests awaiting a verdict, failed authentications and
/// requests without credentials stay counted (see the module documentation).
pub struct DefaultGovernor {
    rates: GovernorRates,
    clock: Arc<dyn MonotonicClock>,
    aggregate: AtomicMeter,
    credential_lookup: AtomicMeter,
    cors_preflight: AtomicMeter,
    unauthenticated: AtomicMeter,
    clients: ClientMeters,
}

impl core::fmt::Debug for DefaultGovernor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DefaultGovernor")
            .field("rates", &self.rates)
            .field("tracked_clients", &self.tracked_clients())
            .field("client_shards", &CLIENT_SHARDS)
            .finish_non_exhaustive()
    }
}

/// # Security
///
/// Default construction installs the bounded framework rates rather than an unlimited governor.
impl Default for DefaultGovernor {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultGovernor {
    /// A limiter at [`GovernorRates::default`] on the system monotonic clock.
    #[must_use]
    pub fn new() -> Self {
        Self::with_rates(GovernorRates::default())
    }

    /// A limiter at the given rates on the system monotonic clock.
    #[must_use]
    pub fn with_rates(rates: GovernorRates) -> Self {
        Self::with_rates_and_clock(rates, Arc::new(SystemMonotonic::new()))
    }

    /// A limiter at the given rates and monotonic source.
    #[must_use]
    pub fn with_rates_and_clock(rates: GovernorRates, clock: Arc<dyn MonotonicClock>) -> Self {
        let now = clock.monotonic();
        Self {
            rates,
            clock,
            aggregate: AtomicMeter::full(rates.aggregate, now),
            credential_lookup: AtomicMeter::full(rates.credential_lookup, now),
            cors_preflight: AtomicMeter::full(rates.cors_preflight, now),
            unauthenticated: AtomicMeter::full(rates.unauthenticated, now),
            clients: ClientMeters::new(rates.per_ip, now, rates.tracked_clients),
        }
    }

    /// A limiter and the source a deterministic test advances.
    #[must_use]
    pub fn manually_clocked(rates: GovernorRates) -> (Self, Arc<ManualMonotonic>) {
        let clock = Arc::new(ManualMonotonic::at_millis(0));
        let governor = Self::with_rates_and_clock(rates, Arc::clone(&clock) as Arc<dyn MonotonicClock>);
        (governor, clock)
    }

    /// The rates in force.
    #[must_use]
    pub const fn rates(&self) -> &GovernorRates {
        &self.rates
    }

    /// How many peer keys currently have their own meter.
    #[must_use]
    pub fn tracked_clients(&self) -> usize {
        self.clients.len()
    }

    /// The fixed number of independent address-map locks.
    #[must_use]
    pub const fn client_shards(&self) -> usize {
        CLIENT_SHARDS
    }

    /// The synchronous built-in decision path.
    ///
    /// Its address maps are preallocated at construction, so it allocates no future or map
    /// storage; `allocation_tests.rs` observes that with the allocator rather than inferring it. The
    /// object-safe [`Governor`] boundary still returns the pre-existing `BoxFuture`; that
    /// allocation cannot be removed without changing the protected trait.
    pub fn try_acquire_sync(&self, request: &GovernorRequest<'_>) -> Option<Lease> {
        let (class_meter, class_rate) = self.class(request.kind());
        let now = self.clock.monotonic();
        if !self.aggregate.take(self.rates.aggregate, now) {
            return None;
        }
        if !class_meter.take(class_rate, now) {
            self.aggregate.refund(self.rates.aggregate);
            return None;
        }
        let address = request.client_addr().map(super::ClientAddr::rate_key);
        if !self.clients.take(address, self.rates.per_ip, now) {
            class_meter.refund(class_rate);
            self.aggregate.refund(self.rates.aggregate);
            return None;
        }
        Some(Lease::admit())
    }
}

impl DefaultGovernor {
    fn class(&self, kind: ClassKind) -> (&AtomicMeter, Rate) {
        match kind {
            ClassKind::CredentialLookup => (&self.credential_lookup, self.rates.credential_lookup),
            ClassKind::CorsPreflight => (&self.cors_preflight, self.rates.cors_preflight),
            ClassKind::Unauthenticated => (&self.unauthenticated, self.rates.unauthenticated),
        }
    }

    /// Returns one admitted request's charge to the three meters it drew from.
    fn refund(&self, request: &GovernorRequest<'_>) {
        self.aggregate.refund(self.rates.aggregate);
        let (class_meter, class_rate) = self.class(request.kind());
        class_meter.refund(class_rate);
        let address = request.client_addr().map(super::ClientAddr::rate_key);
        self.clients.refund(address, self.rates.per_ip);
    }
}

impl Governor for DefaultGovernor {
    fn try_acquire<'a>(&'a self, request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        let decided = self.try_acquire_sync(request).ok_or(());
        Box::pin(async move { decided })
    }

    fn verified(&self, request: &GovernorRequest<'_>) {
        self.refund(request);
    }
}

/// The mandatory framework limiter ANDed with a deployment governor.
pub struct LayeredGovernor {
    framework: DefaultGovernor,
    user: Arc<dyn Governor>,
}

impl LayeredGovernor {
    /// Combines one framework limiter and one deployment governor.
    #[must_use]
    pub fn new(framework: DefaultGovernor, user: Arc<dyn Governor>) -> Self {
        Self { framework, user }
    }
}

impl core::fmt::Debug for LayeredGovernor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LayeredGovernor")
            .field("framework", &self.framework)
            .finish_non_exhaustive()
    }
}

impl Governor for LayeredGovernor {
    fn try_acquire<'a>(&'a self, request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        if self.framework.try_acquire_sync(request).is_none() {
            return Box::pin(async { Err(()) });
        }
        let future = catch_unwind(AssertUnwindSafe(|| self.user.try_acquire(request)));
        match future {
            Ok(inner) => Box::pin(PanicRefusal { inner }),
            Err(_) => Box::pin(async { Err(()) }),
        }
    }

    /// The framework's charge goes back first; a deployment governor's panic is contained and
    /// changes nothing the framework returned.
    fn verified(&self, request: &GovernorRequest<'_>) {
        self.framework.refund(request);
        let _ = catch_unwind(AssertUnwindSafe(|| self.user.verified(request)));
    }
}

struct PanicRefusal<'a> {
    inner: BoxFuture<'a, Result<Lease, ()>>,
}

impl Future for PanicRefusal<'_> {
    type Output = Result<Lease, ()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        catch_unwind(AssertUnwindSafe(|| self.inner.as_mut().poll(cx))).unwrap_or(Poll::Ready(Err(())))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[path = "refund_tests.rs"]
mod refund_tests;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[path = "unlimited_tests.rs"]
mod unlimited_tests;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn rates() -> GovernorRates {
        GovernorRates {
            aggregate: Rate::new(1_000, 0),
            per_ip: Rate::new(1_000, 0),
            credential_lookup: Rate::new(1_000, 0),
            cors_preflight: Rate::new(1_000, 0),
            unauthenticated: Rate::new(1_000, 0),
            tracked_clients: 64,
        }
    }

    fn request(kind: ClassKind, address: Option<IpAddr>) -> GovernorRequest<'static> {
        GovernorRequest::new("GetObject", None, None, address.map(super::super::ClientAddr::from_peer), kind)
    }

    fn admits(governor: &DefaultGovernor, kind: ClassKind, address: Option<IpAddr>) -> bool {
        governor.try_acquire_sync(&request(kind, address)).is_some()
    }

    #[test]
    fn the_aggregate_layer_bounds_address_rotation() {
        let (governor, _) = DefaultGovernor::manually_clocked(GovernorRates {
            aggregate: Rate::new(2, 0),
            ..rates()
        });
        for tail in [1, 2] {
            assert!(admits(
                &governor,
                ClassKind::Unauthenticated,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, tail)))
            ));
        }
        assert!(!admits(
            &governor,
            ClassKind::Unauthenticated,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)))
        ));
    }

    #[test]
    fn the_three_preauthentication_classes_do_not_share_a_meter() {
        let (governor, _) = DefaultGovernor::manually_clocked(GovernorRates {
            credential_lookup: Rate::new(1, 0),
            cors_preflight: Rate::new(1, 0),
            unauthenticated: Rate::new(1, 0),
            ..rates()
        });
        for kind in [
            ClassKind::CredentialLookup,
            ClassKind::CorsPreflight,
            ClassKind::Unauthenticated,
        ] {
            assert!(admits(&governor, kind, None));
            assert!(!admits(&governor, kind, None));
        }
    }

    #[test]
    fn one_ipv4_address_cannot_reset_its_meter() {
        let (governor, _) = DefaultGovernor::manually_clocked(GovernorRates {
            per_ip: Rate::new(1, 0),
            ..rates()
        });
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let shard = governor.clients.shard_index(first);
        let second = (2..=u16::MAX)
            .map(|tail| IpAddr::V4(Ipv4Addr::new(198, 51, (tail >> 8) as u8, tail as u8)))
            .find(|address| governor.clients.shard_index(*address) == shard)
            .expect("one address maps to the same shard");
        assert!(admits(&governor, ClassKind::Unauthenticated, Some(first)));
        assert!(!admits(&governor, ClassKind::Unauthenticated, Some(first)));
        assert!(admits(&governor, ClassKind::Unauthenticated, Some(second)));
    }

    #[test]
    fn one_ipv6_prefix_shares_one_meter() {
        let (governor, _) = DefaultGovernor::manually_clocked(GovernorRates {
            per_ip: Rate::new(1, 0),
            ..rates()
        });
        let first = IpAddr::V6("2001:db8:1:2::1".parse::<Ipv6Addr>().expect("IPv6"));
        let same_prefix = IpAddr::V6("2001:db8:1:2::ffff".parse::<Ipv6Addr>().expect("IPv6"));
        let other_prefix = IpAddr::V6("2001:db8:1:3::1".parse::<Ipv6Addr>().expect("IPv6"));
        assert!(admits(&governor, ClassKind::Unauthenticated, Some(first)));
        assert!(!admits(&governor, ClassKind::Unauthenticated, Some(same_prefix)));
        assert!(admits(&governor, ClassKind::Unauthenticated, Some(other_prefix)));
    }

    #[test]
    fn the_client_map_is_bounded_and_eviction_keeps_debt() {
        let (governor, _) = DefaultGovernor::manually_clocked(GovernorRates {
            per_ip: Rate::new(2, 0),
            tracked_clients: CLIENT_SHARDS,
            ..rates()
        });
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let shard = governor.clients.shard_index(first);
        let second = (2..=u16::MAX)
            .map(|tail| IpAddr::V4(Ipv4Addr::new(198, 51, (tail >> 8) as u8, tail as u8)))
            .find(|address| governor.clients.shard_index(*address) == shard)
            .expect("one address maps to the same shard");
        assert!(admits(&governor, ClassKind::Unauthenticated, Some(first)));
        assert!(admits(&governor, ClassKind::Unauthenticated, Some(first)));
        assert!(!admits(&governor, ClassKind::Unauthenticated, Some(second)));
        assert_eq!(governor.tracked_clients(), 1);
    }

    #[test]
    fn eviction_cannot_refill_an_idle_victim_to_a_full_burst() {
        let rate = Rate::new(2, 1);
        let mut shard = ClientShard::new(rate, MonotonicNow::from_millis(0), 1);
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let decisions = [
            shard.take(first, rate, MonotonicNow::from_millis(0)),
            shard.take(second, rate, MonotonicNow::from_millis(1_000)),
            shard.take(second, rate, MonotonicNow::from_millis(1_000)),
            // Returning after eviction must also inherit the outstanding debt.
            shard.take(first, rate, MonotonicNow::from_millis(1_000)),
            // Once retained, the address can still recover its ordinary full burst.
            shard.take(first, rate, MonotonicNow::from_millis(3_000)),
            shard.take(first, rate, MonotonicNow::from_millis(3_000)),
            shard.take(first, rate, MonotonicNow::from_millis(3_000)),
        ];
        assert_eq!(decisions, [true, true, false, false, true, true, false]);
    }

    #[test]
    fn eviction_preserves_deeper_debt_and_fractional_refill() {
        let rate = Rate::new(4, 1);
        let mut shard = ClientShard::new(rate, MonotonicNow::from_millis(0), 1);
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let decisions = [
            shard.take(first, rate, MonotonicNow::from_millis(0)),
            shard.take(first, rate, MonotonicNow::from_millis(0)),
            shard.take(first, rate, MonotonicNow::from_millis(0)),
            shard.take(first, rate, MonotonicNow::from_millis(0)),
            shard.take(second, rate, MonotonicNow::from_millis(500)),
            shard.take(first, rate, MonotonicNow::from_millis(999)),
            shard.take(first, rate, MonotonicNow::from_millis(1_000)),
            shard.take(first, rate, MonotonicNow::from_millis(1_000)),
        ];
        assert_eq!(decisions, [true, true, true, true, false, false, true, false]);
    }

    #[test]
    fn eviction_spends_a_single_token_burst_before_the_current_request() {
        let rate = Rate::new(1, 1);
        let mut shard = ClientShard::new(rate, MonotonicNow::from_millis(0), 1);
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let decisions = [
            shard.take(first, rate, MonotonicNow::from_millis(0)),
            shard.take(second, rate, MonotonicNow::from_millis(1_000)),
            shard.take(second, rate, MonotonicNow::from_millis(1_999)),
            shard.take(second, rate, MonotonicNow::from_millis(2_000)),
            shard.take(second, rate, MonotonicNow::from_millis(2_000)),
        ];
        assert_eq!(decisions, [true, false, false, true, false]);
    }

    /// Negative — the same counter-example through the real decision path, with a non-zero refill
    /// and the injected monotonic clock advanced explicitly (nothing sleeps). An idle victim must
    /// not reach its replacement as a full burst, a drained victim must not reach it as a fresh
    /// one, and an address that keeps its slot still refills on the clock.
    #[test]
    fn an_evicting_address_inherits_debt_through_the_governor_with_refill() {
        let (governor, clock) = DefaultGovernor::manually_clocked(GovernorRates {
            per_ip: Rate::new(2, 1),
            tracked_clients: CLIENT_SHARDS,
            ..rates()
        });
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let shard = governor.clients.shard_index(first);
        let mut same_shard = (2..=u16::MAX)
            .map(|tail| IpAddr::V4(Ipv4Addr::new(198, 51, (tail >> 8) as u8, tail as u8)))
            .filter(|address| governor.clients.shard_index(*address) == shard);
        let second = same_shard.next().expect("a second address maps to the same shard");
        let third = same_shard.next().expect("a third address maps to the same shard");
        let admits_now = |address| admits(&governor, ClassKind::Unauthenticated, Some(address));

        assert!(admits_now(first));
        clock.advance_seconds(1);
        assert!(admits_now(second), "the evicting request is charged against the inherited meter");
        assert!(!admits_now(second), "an idle victim refilled into a full burst for a new address");
        assert_eq!(governor.tracked_clients(), 1);

        clock.advance_seconds(1);
        assert!(admits_now(second), "a retained address stopped refilling");
        assert!(!admits_now(second));
        clock.advance_seconds(2);
        assert!(admits_now(second), "a retained idle address did not recover its burst");
        assert!(admits_now(second), "a retained idle address did not recover its burst");
        assert!(!admits_now(second));

        assert!(!admits_now(third), "eviction reset a drained victim's debt");
        assert_eq!(governor.tracked_clients(), 1);
    }

    #[test]
    fn client_state_stays_at_its_bound_under_high_address_cardinality() {
        const ATTEMPTS: u32 = 10_000;
        const BOUND: usize = 64;

        let wide = Rate::new(ATTEMPTS, 0);
        let (governor, _) = DefaultGovernor::manually_clocked(GovernorRates {
            aggregate: wide,
            per_ip: wide,
            credential_lookup: wide,
            cors_preflight: wide,
            unauthenticated: wide,
            tracked_clients: BOUND,
        });
        for offset in 0..ATTEMPTS {
            let address = IpAddr::V4(Ipv4Addr::from(0x0a00_0000_u32.saturating_add(offset)));
            assert!(admits(&governor, ClassKind::Unauthenticated, Some(address)));
        }
        assert_eq!(governor.tracked_clients(), BOUND);
    }

    struct PanicGovernor;

    impl Governor for PanicGovernor {
        fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
            panic!("extension panic")
        }
    }

    #[tokio::test]
    async fn a_user_governor_panic_fails_closed() {
        let layered = LayeredGovernor::new(DefaultGovernor::with_rates(rates()), Arc::new(PanicGovernor));
        assert!(layered.try_acquire(&request(ClassKind::Unauthenticated, None)).await.is_err());
    }

    struct PollPanicGovernor;

    impl Governor for PollPanicGovernor {
        fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
            Box::pin(async { panic!("extension future panic") })
        }
    }

    #[tokio::test]
    async fn a_user_governor_future_panic_fails_closed() {
        let layered = LayeredGovernor::new(DefaultGovernor::with_rates(rates()), Arc::new(PollPanicGovernor));
        assert!(layered.try_acquire(&request(ClassKind::Unauthenticated, None)).await.is_err());
    }

    #[test]
    fn concurrent_callers_cannot_overdraw_the_atomic_aggregate_meter() {
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const CALLERS: usize = 64;
        const BURST: u32 = 16;

        let (governor, _) = DefaultGovernor::manually_clocked(GovernorRates {
            aggregate: Rate::new(BURST, 0),
            ..rates()
        });
        let barrier = Arc::new(Barrier::new(CALLERS));
        let admitted = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            for _ in 0..CALLERS {
                let barrier = Arc::clone(&barrier);
                let admitted = &admitted;
                let governor = &governor;
                scope.spawn(move || {
                    barrier.wait();
                    if admits(governor, ClassKind::Unauthenticated, None) {
                        admitted.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });

        assert_eq!(admitted.load(Ordering::Relaxed), BURST as usize);
    }
}
