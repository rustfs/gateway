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

//! The one reading of the clock a request is allowed to see.
//!
//! Responsible for: [`Clock`], the object-safe form of `rustfs-gateway-sig`'s `RequestClock`, and
//! [`FixedClock`], the substitutable source a conformance case needs to compare a response body
//! byte for byte.
//! NOT responsible for: any time-dependent rule. Skew, expiry and the fifteen-minute ceiling are
//! `rustfs-gateway-sig`'s, and they take the snapshot as a parameter precisely so that this module
//! cannot influence them.
//! Upstream: `rustfs-gateway-sig`. Downstream: `crate::builder`, `crate::service`.
//!
//! # Why one reading per request, and why that is a correctness rule
//!
//! `crate::service` captures a [`RequestNow`] once, at the top of the pipeline, and passes it down.
//! Nothing below reads the clock again. Two readings inside one request mean the skew check and the
//! expiry check can straddle a second boundary, so a presigned URL can be inside its window when it
//! is admitted and outside it when its expiry is computed — a rejection nobody can reproduce.
//!
//! # Why a fixed clock is a first-class type and not a test helper
//!
//! A case that asserts on a response body containing a timestamp cannot be written against the
//! system clock at all: the expected bytes change every second. The conformance suite's `[clock]`
//! block is what makes those cases expressible, and it needs a clock it can set. Keeping that type
//! public is what stops every consumer from inventing its own.

use rustfs_gateway_sig::{RequestClock, RequestNow, SystemClock};

/// Where the one per-request reading comes from.
///
/// The object-safe counterpart of [`RequestClock`]: the assembled service holds
/// `Arc<dyn Clock>`, and `RequestClock` is not declared with the `Send + Sync + 'static` bounds
/// that requires. The blanket implementation below means any `RequestClock` that does satisfy
/// them is already a `Clock`, so nothing has to be written twice.
///
/// Synchronous, because reading a clock is not I/O and an implementation that awaited would be
/// awaiting on the pre-authentication path.
pub trait Clock: Send + Sync + 'static {
    /// Takes one reading.
    fn now(&self) -> RequestNow;
}

impl<T> Clock for T
where
    T: RequestClock + Send + Sync + 'static,
{
    fn now(&self) -> RequestNow {
        self.capture()
    }
}

/// A clock that always answers the same instant.
///
/// What a conformance case's `[clock] fixed` block installs. Skew is expressed by moving this
/// value, not by adding an offset here: the check that reads it takes the reading as a parameter,
/// and a clock that applied its own offset would be a second place time is adjusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedClock {
    at: RequestNow,
}

impl FixedClock {
    /// A clock fixed at a Unix timestamp in seconds.
    #[must_use]
    pub const fn at_unix_seconds(seconds: i64) -> Self {
        Self {
            at: RequestNow::from_unix_seconds(seconds),
        }
    }

    /// A clock fixed at an already-captured reading.
    #[must_use]
    pub const fn at(at: RequestNow) -> Self {
        Self { at }
    }

    /// The same clock moved by a number of milliseconds, for the `skew_ms` a case declares.
    ///
    /// Saturating rather than wrapping: a case that asked for an offset no `i64` of seconds can
    /// hold is a case with a typo in it, and wrapping would answer it with a plausible timestamp
    /// on the other side of the epoch.
    #[must_use]
    pub const fn skewed_by_millis(self, millis: i64) -> Self {
        Self {
            at: RequestNow::from_unix_seconds(self.at.unix_seconds().saturating_add(millis / 1_000)),
        }
    }

    /// The instant this clock answers with.
    #[must_use]
    pub const fn reading(self) -> RequestNow {
        self.at
    }
}

impl RequestClock for FixedClock {
    fn capture(&self) -> RequestNow {
        self.at
    }
}

/// The default clock: the system one.
///
/// # Security
///
/// This default is the only one that is correct in a deployment. A service assembled with a
/// [`FixedClock`] accepts a signature minted at that instant for ever, which turns every captured
/// request into a replayable one. `FixedClock` exists for cases, and a deployment that installs
/// one has disabled the skew window rather than configured it.
#[must_use]
pub fn system_clock() -> SystemClock {
    SystemClock
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Positive — the blanket implementation means `SystemClock` is already a `Clock`, and the
    /// service can hold it behind `Arc<dyn _>`.
    #[test]
    fn the_system_clock_is_object_safe_through_the_blanket_impl() {
        let clock: Arc<dyn Clock> = Arc::new(system_clock());
        assert!(clock.now().unix_seconds() > 0);
    }

    /// Negative — a fixed clock does not drift, which is the whole reason a case can assert on a
    /// rendered timestamp.
    #[test]
    fn a_fixed_clock_answers_the_same_instant_every_time() {
        let clock = FixedClock::at_unix_seconds(1_440_938_160);
        assert_eq!(clock.now(), clock.now());
        assert_eq!(clock.now().unix_seconds(), 1_440_938_160);
    }

    /// Negative — a skew larger than any timestamp saturates rather than wrapping into a plausible
    /// instant on the far side of the epoch.
    #[test]
    fn an_absurd_skew_saturates_rather_than_wrapping() {
        let clock = FixedClock::at_unix_seconds(i64::MAX - 1).skewed_by_millis(i64::MAX);
        assert_eq!(clock.reading().unix_seconds(), i64::MAX);
    }

    /// Negative — skew is expressed in milliseconds and truncates towards zero, so a sub-second
    /// skew does not silently become a whole second.
    #[test]
    fn a_sub_second_skew_does_not_become_a_second() {
        let clock = FixedClock::at_unix_seconds(1_000).skewed_by_millis(999);
        assert_eq!(clock.reading().unix_seconds(), 1_000);
        assert_eq!(
            FixedClock::at_unix_seconds(1_000)
                .skewed_by_millis(-999)
                .reading()
                .unix_seconds(),
            1_000
        );
    }
}
