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

//! The numbers [`super::DefaultGovernor`] enforces, and what they mean.
//!
//! Responsible for: [`Rate`], [`GovernorRates`] and the shipped defaults — the operator-facing
//! surface of the limiter, and the one place a number lives.
//! NOT responsible for: the arithmetic that spends them (`super::meter`), the layers that consult
//! them (`super::default`), or how a deployment arrives at its own numbers, which is
//! `docs/capacity-planning.md`.
//! Upstream: nothing. Downstream: `super::default`, `crate::builder`.

/// What one request costs, in millitokens.
///
/// Every request costs the same. Metering a `PutObject` by its declared length would be a byte
/// ceiling wearing a rate limiter's clothes, and `declared_body_bytes` is `None` for a chunked
/// body — so the expensive requests are exactly the ones that would be charged nothing.
pub(super) const COST: u64 = 1_000;

/// One layer's admission rate: a burst, and what it refills at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rate {
    burst: u32,
    per_second: u32,
}

impl Rate {
    /// A rate that admits `burst` at once and then `per_second` every second.
    #[must_use]
    pub const fn new(burst: u32, per_second: u32) -> Self {
        Self { burst, per_second }
    }

    /// A rate that admits nothing at all.
    ///
    /// A legal configuration, and the only honest way to express "this class is closed". A
    /// deployment cannot disable the mandatory framework governor through its extension; there
    /// is no way to spell "unlimited" as a [`Rate`].
    #[must_use]
    pub const fn none() -> Self {
        Self { burst: 0, per_second: 0 }
    }

    /// How many requests may arrive at once.
    #[must_use]
    pub const fn burst(self) -> u32 {
        self.burst
    }

    /// How many requests a second are admitted once the burst is spent.
    #[must_use]
    pub const fn per_second(self) -> u32 {
        self.per_second
    }

    /// Whether this rate refuses everything.
    #[must_use]
    pub const fn admits_nothing(self) -> bool {
        self.burst == 0
    }

    /// The bucket's capacity, in millitokens.
    pub(super) const fn capacity(self) -> u64 {
        (self.burst as u64).saturating_mul(COST)
    }
}

/// The rates [`super::DefaultGovernor`] enforces, and the bound on what it remembers.
///
/// The numbers are documented, with what happens when they are set wrong, in
/// `docs/capacity-planning.md`. They are non-zero by construction: there is no
/// `GovernorRates::unlimited`, because a deployment governor is ANDed after this mandatory one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GovernorRates {
    /// The ceiling on all pre-authentication work this process admits.
    pub aggregate: Rate,
    /// The ceiling for one IPv4 address or one IPv6 `/64` prefix.
    pub per_ip: Rate,
    /// The ceiling on requests that presented credential material.
    pub credential_lookup: Rate,
    /// The ceiling on CORS preflights.
    pub cors_preflight: Rate,
    /// The ceiling on requests that presented no credential material.
    pub unauthenticated: Rate,
    /// How many address keys the bounded, sharded map remembers.
    pub tracked_clients: usize,
}

/// # Security
///
/// Every pre-authentication class remains bounded; the default does not admit unlimited work.
impl Default for GovernorRates {
    /// The defaults, which are deliberately not "unlimited".
    ///
    /// Reasoned in `docs/capacity-planning.md`; the short form is that the aggregate is set where
    /// a modest deployment still answers, a client cannot take the whole aggregate allowance,
    /// and credential lookup and preflight are the tightest classes because both can force work
    /// before a caller proves an identity.
    fn default() -> Self {
        Self {
            aggregate: Rate::new(4_096, 2_048),
            per_ip: Rate::new(256, 128),
            credential_lookup: Rate::new(128, 64),
            cors_preflight: Rate::new(128, 64),
            unauthenticated: Rate::new(256, 128),
            tracked_clients: 4_096,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Negative — the shipped defaults are a limit, not a very large number standing in for one.
    /// A zero anywhere here would be a class nobody can reach; an absent bound would be the
    /// memory surface. These are the numbers `docs/capacity-planning.md` documents, and this is
    /// what stops the document and the code from drifting apart.
    #[test]
    fn the_shipped_defaults_are_a_limit_and_not_a_disguised_unlimited() {
        let rates = GovernorRates::default();
        for rate in [
            rates.aggregate,
            rates.per_ip,
            rates.credential_lookup,
            rates.cors_preflight,
            rates.unauthenticated,
        ] {
            assert!(rate.burst() > 0, "a zero burst closes the class: {rate:?}");
            assert!(rate.per_second() > 0, "a zero refill closes the class after one burst: {rate:?}");
            assert!(!rate.admits_nothing());
        }
        assert_eq!(rates.aggregate, Rate::new(4_096, 2_048));
        assert_eq!(rates.per_ip, Rate::new(256, 128));
        assert_eq!(rates.credential_lookup, Rate::new(128, 64));
        assert_eq!(rates.cors_preflight, Rate::new(128, 64));
        assert_eq!(rates.unauthenticated, Rate::new(256, 128));
        assert_eq!(rates.tracked_clients, 4_096);
        // The preflight class is the tightest, because it is the one an unauthenticated caller
        // reaches for free and the one that can reach storage.
        assert!(rates.cors_preflight.per_second() < rates.unauthenticated.per_second());
        assert!(rates.per_ip.per_second() < rates.aggregate.per_second());
    }

    /// Negative — a closed class reports itself as one, and a rate with a burst but no refill is
    /// not closed: it admits its burst once and then never again, which is a different thing and
    /// must not be reported as the same.
    #[test]
    fn only_a_zero_burst_counts_as_admitting_nothing() {
        assert!(Rate::none().admits_nothing());
        assert!(Rate::new(0, 1_000).admits_nothing());
        assert!(!Rate::new(1, 0).admits_nothing());
        assert_eq!(Rate::none().capacity(), 0);
        assert_eq!(Rate::new(1, 0).capacity(), COST);
    }

    /// Negative — a capacity that would not fit saturates rather than wrapping to a small one. A
    /// wrap here turns the largest burst an operator can type into the tightest limit there is.
    #[test]
    fn an_enormous_burst_saturates_rather_than_wrapping() {
        assert_eq!(Rate::new(u32::MAX, 0).capacity(), u64::from(u32::MAX) * COST);
        assert!(Rate::new(u32::MAX, 0).capacity() > Rate::new(u32::MAX - 1, 0).capacity());
    }
}
