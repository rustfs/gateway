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

//! One token bucket, and the integer arithmetic that fills it.
//!
//! Responsible for: [`Meter`] — refill, admission and the idle test the keyed map's reclaim
//! depends on.
//! NOT responsible for: which meter a request draws on, how many layers there are, or what
//! happens when one refuses. All three are `super::default`'s.
//! Upstream: `crate::clock`, `super::rates`. Downstream: `super::default`.
//!
//! # Why the arithmetic is integer millitokens over milliseconds
//!
//! One millisecond at `n` tokens a second is exactly `n` millitokens, so a refill loses nothing to
//! rounding however often it is called. The floating-point form loses a little every time, always
//! downwards, so the limit an operator reads in the configuration is tighter than the one the
//! service enforces — by an amount that depends on how often requests arrive, which is the caller's
//! choice and not the operator's.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::clock::MonotonicNow;

use super::rates::{COST, Rate};

/// One token bucket.
#[derive(Clone, Copy, Debug)]
pub(super) struct Meter {
    millitokens: u64,
    last: MonotonicNow,
}

/// A token bucket updated through one compare-and-swap word.
///
/// The upper half stores millitokens and the lower half stores the monotonic millisecond modulo
/// `u32`. A request therefore contends on one atomic cache line rather than a process-wide mutex.
#[derive(Debug)]
pub(super) struct AtomicMeter {
    state: AtomicU64,
}

impl AtomicMeter {
    pub(super) fn full(rate: Rate, now: MonotonicNow) -> Self {
        Self {
            state: AtomicU64::new(pack(atomic_capacity(rate), now.millis() as u32)),
        }
    }

    pub(super) fn take(&self, rate: Rate, now: MonotonicNow) -> bool {
        let capacity = atomic_capacity(rate);
        let now = now.millis() as u32;
        let mut current = self.state.load(Ordering::Relaxed);
        loop {
            let (tokens, last) = unpack(current);
            let elapsed = now.wrapping_sub(last);
            let refilled = u64::from(tokens)
                .saturating_add(u64::from(elapsed).saturating_mul(u64::from(rate.per_second())))
                .min(u64::from(capacity)) as u32;
            let admitted = refilled >= COST as u32;
            let remaining = if admitted {
                refilled.saturating_sub(COST as u32)
            } else {
                refilled
            };
            let next = pack(remaining, now);
            match self
                .state
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return admitted,
                Err(observed) => current = observed,
            }
        }
    }

    /// Returns one charge: after a later AND layer refused, or once the request verified.
    pub(super) fn refund(&self, rate: Rate) {
        let capacity = atomic_capacity(rate);
        let mut current = self.state.load(Ordering::Relaxed);
        loop {
            let (tokens, last) = unpack(current);
            let next = pack(tokens.saturating_add(COST as u32).min(capacity), last);
            match self
                .state
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

fn atomic_capacity(rate: Rate) -> u32 {
    u32::try_from(rate.capacity()).unwrap_or(u32::MAX)
}

const fn pack(tokens: u32, last: u32) -> u64 {
    (tokens as u64) << 32 | last as u64
}

const fn unpack(state: u64) -> (u32, u32) {
    ((state >> 32) as u32, state as u32)
}

impl Meter {
    /// A meter that has never been drawn on.
    pub(super) const fn full(rate: Rate, now: MonotonicNow) -> Self {
        Self {
            millitokens: rate.capacity(),
            last: now,
        }
    }

    /// Transfers the victim's current balance with at least one request's debt.
    pub(super) fn after_eviction(mut self, rate: Rate, now: MonotonicNow) -> Self {
        self.refill(rate, now);
        self.millitokens = self.millitokens.min(rate.capacity().saturating_sub(COST));
        self
    }

    /// Credits the time since the last reading, up to the capacity.
    ///
    /// Capped, because an idle meter is not a savings account: a bucket nobody touched for a week
    /// must admit its burst and not a week's worth of requests at once.
    pub(super) fn refill(&mut self, rate: Rate, now: MonotonicNow) {
        let elapsed = now.saturating_millis_since(self.last);
        if elapsed == 0 {
            return;
        }
        self.last = now;
        self.millitokens = self
            .millitokens
            .saturating_add(elapsed.saturating_mul(u64::from(rate.per_second())))
            .min(rate.capacity());
    }

    /// Returns one charge, never past the capacity: a refund is not a way to save up a burst.
    pub(super) fn refund(&mut self, rate: Rate) {
        self.millitokens = self.millitokens.saturating_add(COST).min(rate.capacity());
    }

    /// Whether this meter would admit one request as it stands.
    pub(super) const fn admits(&self) -> bool {
        self.millitokens >= COST
    }

    /// Refills, checks and charges, in one step. `false` means nothing was charged.
    pub(super) fn take(&mut self, rate: Rate, now: MonotonicNow) -> bool {
        self.refill(rate, now);
        if !self.admits() {
            return false;
        }
        self.millitokens = self.millitokens.saturating_sub(COST);
        true
    }

    /// Whether this meter is at capacity as of `now` — indistinguishable from one that does not
    /// exist, which is what makes reclaiming it safe.
    #[cfg(test)]
    pub(super) fn is_idle(&self, rate: Rate, now: MonotonicNow) -> bool {
        let mut probe = *self;
        probe.refill(rate, now);
        probe.millitokens >= rate.capacity()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const START: MonotonicNow = MonotonicNow::from_millis(1_000);

    /// Negative — a refill credits the elapsed milliseconds exactly, and a fraction of a token is
    /// carried rather than dropped. Ten calls a millisecond apart at one token a second must add
    /// up to the same ten milliseconds as one call ten milliseconds later.
    #[test]
    fn a_refill_carries_the_fraction_it_could_not_spend() {
        let rate = Rate::new(1, 1);
        let mut stepped = Meter::full(rate, START);
        assert!(stepped.take(rate, START));
        for step in 1..=1_000 {
            stepped.refill(rate, MonotonicNow::from_millis(1_000 + step));
        }
        let mut jumped = Meter::full(rate, START);
        assert!(jumped.take(rate, START));
        jumped.refill(rate, MonotonicNow::from_millis(2_000));
        assert_eq!(stepped.millitokens, jumped.millitokens);
        assert!(stepped.admits(), "a thousand one-millisecond refills lost the token");
    }

    /// Negative — a meter that is idle is only idle once it is back at capacity, not as soon as
    /// any time has passed. The keyed map's reclaim depends on this being exact: a meter reported
    /// idle while it still holds a charge is a meter whose charge eviction would erase.
    #[test]
    fn a_partly_refilled_meter_is_not_idle() {
        let rate = Rate::new(4, 1);
        let mut meter = Meter::full(rate, START);
        assert!(meter.is_idle(rate, START));
        assert!(meter.take(rate, START));
        assert!(!meter.is_idle(rate, START));
        assert!(!meter.is_idle(rate, MonotonicNow::from_millis(1_500)));
        assert!(meter.is_idle(rate, MonotonicNow::from_millis(2_000)));
        // Asking whether it is idle must not itself refill it.
        assert!(!meter.is_idle(rate, START));
    }

    /// Negative — a closed rate admits nothing at all, including the very first request, and no
    /// amount of elapsed time changes that.
    #[test]
    fn a_closed_rate_admits_nothing_however_long_it_waits() {
        let rate = Rate::none();
        let mut meter = Meter::full(rate, START);
        assert!(!meter.take(rate, START));
        assert!(!meter.take(rate, MonotonicNow::from_millis(u64::MAX)));
    }

    /// Negative — the atomic form admits the configured burst, refuses the next request, and
    /// recovers only from the monotonic source.
    #[test]
    fn the_atomic_meter_preserves_the_token_bucket_contract() {
        let rate = Rate::new(2, 1);
        let meter = AtomicMeter::full(rate, START);
        assert!(meter.take(rate, START));
        assert!(meter.take(rate, START));
        assert!(!meter.take(rate, START));
        assert!(meter.take(rate, MonotonicNow::from_millis(2_000)));
        assert!(!meter.take(rate, MonotonicNow::from_millis(2_000)));
    }

    /// Negative — refunding one failed AND decision restores exactly one charge.
    #[test]
    fn an_atomic_refund_restores_one_charge_and_no_more() {
        let rate = Rate::new(1, 0);
        let meter = AtomicMeter::full(rate, START);
        assert!(meter.take(rate, START));
        assert!(!meter.take(rate, START));
        meter.refund(rate);
        assert!(meter.take(rate, START));
        assert!(!meter.take(rate, START));
    }
}
