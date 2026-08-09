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
//! byte for byte; and the monotonic half — [`MonotonicClock`], [`MonotonicNow`],
//! [`SystemMonotonic`] and [`ManualMonotonic`] — which is what a rate limiter measures elapsed
//! time with.
//! NOT responsible for: any time-dependent rule. Skew, expiry and the fifteen-minute ceiling are
//! `rustfs-gateway-sig`'s, and they take the snapshot as a parameter precisely so that this module
//! cannot influence them.
//! Upstream: `rustfs-gateway-sig`. Downstream: `crate::builder`, `crate::service`,
//! `crate::ext::DefaultGovernor`, `crate::ext::GuardedCredentialProvider`.
//!
//! # Two clocks, two types, and no conversion between them
//!
//! A wall clock answers "what time is it" and a monotonic clock answers "how long since". They are
//! separate traits producing separate types here, and there is no `From` in either direction,
//! because the two mistakes that follow from mixing them are both silent:
//!
//! - **A rate limiter on the wall clock is steerable.** An NTP step backwards makes elapsed time
//!   negative, and a limiter that saturates it to zero simply stops refilling; a step forwards
//!   refills every bucket to full. Either way the operator who set the clock has re-set the limit,
//!   and so has anyone who can reach `ntpd`.
//! - **An expiry check on a monotonic clock cannot be written at all.** [`MonotonicNow`]'s origin
//!   is unspecified and differs per process, so it has nothing to compare `x-amz-date` against.
//!
//! Because the types do not convert, neither mistake is expressible: [`RequestNow`] is what the
//! signature path takes and [`MonotonicNow`] is what the limiter takes, and handing one where the
//! other is expected does not compile.
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
//!
//! A custom wall clock is checked against the system clock when the service is assembled. More
//! than 60 seconds of skew is refused unless the caller supplies [`ClockSkewAck`]; the resulting
//! [`ClockPosture`] keeps that acknowledgement visible to deployment audits.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

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

/// How the assembled service obtained its wall clock.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClockPosture {
    /// The framework's system clock.
    System,
    /// A custom clock checked against the system clock at assembly.
    CustomChecked,
    /// A custom clock whose skew was explicitly acknowledged.
    CustomAcknowledged,
}

/// The explicit acknowledgement required to assemble a deliberately skewed wall clock.
///
/// There is no `Default`; the call site must spell out the replay risk.
#[derive(Clone, Copy)]
pub struct ClockSkewAck(());

impl ClockSkewAck {
    /// Acknowledges that a frozen or skewed clock can keep captured signatures valid.
    #[must_use]
    pub const fn i_understand_a_skewed_clock_can_disable_signature_expiry() -> Self {
        Self(())
    }
}

impl core::fmt::Debug for ClockSkewAck {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ClockSkewAck(i_understand_a_skewed_clock_can_disable_signature_expiry)")
    }
}

/// The maximum custom-clock difference accepted without [`ClockSkewAck`].
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 60;

pub(crate) fn skew_from_system(clock: &dyn Clock) -> u64 {
    let custom = i128::from(clock.now().unix_seconds());
    let system = i128::from(system_clock().capture().unix_seconds());
    u64::try_from((custom - system).abs()).unwrap_or(u64::MAX)
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
/// [`crate::ServiceBuilder::clock`] rejects a production assembly when this differs from system
/// time by more than [`MAX_CLOCK_SKEW_SECONDS`], unless the caller uses the explicit
/// acknowledgement path.
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

/// One reading of a monotonic source, in whole milliseconds from an origin nobody may name.
///
/// Milliseconds because that is the resolution a rate limiter needs and because integer
/// millitoken arithmetic over it is exact — a token bucket refilled from a floating-point number
/// of seconds loses a little on every call, and the loss is in the direction that makes the limit
/// tighter than the operator configured.
///
/// The origin is deliberately unspecified: it differs per process and per [`SystemMonotonic`], so
/// a reading is meaningful only as a difference against another reading from the *same* source.
/// That is why there is no `unix_seconds` here and no conversion to [`RequestNow`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MonotonicNow(u64);

impl MonotonicNow {
    /// A reading at a number of milliseconds from the source's origin.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// The reading, in milliseconds from the source's origin.
    #[must_use]
    pub const fn millis(self) -> u64 {
        self.0
    }

    /// Milliseconds from `earlier` to this reading, or zero if this reading is not later.
    ///
    /// Saturating rather than signed: a source that went backwards has broken its own contract,
    /// and the answer that keeps a limiter safe is "no time has passed" — no refill. Returning a
    /// negative elapsed time, or panicking, would both hand the caller of a broken clock something
    /// worse than a tight limit.
    #[must_use]
    pub const fn saturating_millis_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// Where elapsed time comes from.
///
/// Separate from [`Clock`] and separately injected, for the reason in this module's documentation:
/// the two answer different questions and their readings are not interchangeable. A deployment
/// installs one into each component that measures elapsed time rather than into the service.
/// Today those components are the limiter and the credential negative cache.
pub trait MonotonicClock: Send + Sync + 'static {
    /// Takes one reading.
    ///
    /// Must never answer a smaller value than it has already answered. An implementation that can
    /// go backwards is a wall clock wearing this trait's name.
    fn monotonic(&self) -> MonotonicNow;
}

/// The system's monotonic source, anchored when it was constructed.
///
/// Each instance carries its own origin, so two of them answer different numbers at the same
/// moment. That is harmless — a reading is only ever compared against another from the same
/// instance — and it is the reason [`MonotonicNow`] has no absolute meaning.
#[derive(Clone, Copy, Debug)]
pub struct SystemMonotonic {
    origin: Instant,
}

impl SystemMonotonic {
    /// Anchors a source at this moment.
    #[must_use]
    pub fn new() -> Self {
        Self { origin: Instant::now() }
    }
}

impl Default for SystemMonotonic {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonic {
    fn monotonic(&self) -> MonotonicNow {
        // `Instant::elapsed` cannot go backwards, and a process that has been up for 584 million
        // years saturates rather than wrapping into a reading in its own past.
        MonotonicNow(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

/// A monotonic source a test advances by hand.
///
/// This is what makes a rate-limit assertion deterministic. A test that sleeps to prove a bucket
/// refilled is measuring the machine it runs on: it passes on an idle laptop, fails on a loaded
/// runner, and the usual repair — run it again — turns the suite into a coin toss that is read as
/// evidence. Advancing this instead makes "the bucket recovers after a second" a statement about
/// the implementation and nothing else.
///
/// [`MonotonicClock::monotonic`] is `&self`, so the handle a test keeps and the handle the limiter
/// holds are two `Arc`s over one source; advancing through either is visible to the other.
///
/// # Security
///
/// Unlike [`FixedClock`], this one **fails closed** if it reaches a deployment. A limiter whose
/// clock never advances never refills, so it admits one burst and then refuses everything — an
/// outage, which is loud, rather than a limit that has quietly been switched off. That asymmetry
/// is why this type is public and ungated while a wall clock frozen in production would be a
/// signature that never expires.
#[derive(Debug, Default)]
pub struct ManualMonotonic {
    millis: AtomicU64,
}

impl ManualMonotonic {
    /// A source starting at a number of milliseconds from its origin.
    #[must_use]
    pub const fn at_millis(millis: u64) -> Self {
        Self {
            millis: AtomicU64::new(millis),
        }
    }

    /// Moves the source forward.
    ///
    /// There is no way to move it back, and that is the point: a type that could would let a test
    /// assert against a source no [`MonotonicClock`] implementation is allowed to be, and the
    /// assertion would then be about nothing.
    /// Saturating, because a plain `fetch_add` at the top of the range wraps — and a monotonic
    /// source that wrapped would answer a reading in its own past, which is the one thing this
    /// trait promises never happens.
    pub fn advance_millis(&self, by: u64) {
        // The closure is infallible, so the update always applies; the `Result` is discarded for
        // that reason and not because a failure would be uninteresting.
        let _ = self
            .millis
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| Some(current.saturating_add(by)));
    }

    /// Moves the source forward by whole seconds.
    pub fn advance_seconds(&self, by: u64) {
        self.advance_millis(by.saturating_mul(1_000));
    }
}

impl MonotonicClock for ManualMonotonic {
    fn monotonic(&self) -> MonotonicNow {
        MonotonicNow(self.millis.load(Ordering::SeqCst))
    }
}

impl<T: MonotonicClock + ?Sized> MonotonicClock for std::sync::Arc<T> {
    fn monotonic(&self) -> MonotonicNow {
        (**self).monotonic()
    }
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

    /// Negative — a reading against a later one is zero elapsed, not a wrapped enormous duration.
    /// A limiter that refilled by `u64::MAX` here would admit everything for ever.
    #[test]
    fn a_reading_before_the_one_it_is_compared_against_is_zero_elapsed() {
        let earlier = MonotonicNow::from_millis(10);
        let later = MonotonicNow::from_millis(4_000);
        assert_eq!(later.saturating_millis_since(earlier), 3_990);
        assert_eq!(earlier.saturating_millis_since(later), 0);
        assert_eq!(earlier.saturating_millis_since(earlier), 0);
    }

    /// Negative — advancing at the top of the range saturates. A wrapping `fetch_add` would hand a
    /// limiter a reading in its own past, which is the one thing [`MonotonicClock`] promises not to
    /// do.
    #[test]
    fn a_manual_source_cannot_be_advanced_into_its_own_past() {
        let clock = ManualMonotonic::at_millis(u64::MAX - 5);
        clock.advance_millis(1_000);
        assert_eq!(clock.monotonic().millis(), u64::MAX);
        clock.advance_seconds(u64::MAX);
        assert_eq!(clock.monotonic().millis(), u64::MAX);
    }

    /// Negative — the source has no way to be moved backwards, so what a test asserts against is a
    /// source that satisfies the trait's contract. Both handles see one source.
    #[test]
    fn advancing_through_one_handle_is_visible_through_another() {
        let clock = Arc::new(ManualMonotonic::at_millis(0));
        let held: Arc<dyn MonotonicClock> = Arc::clone(&clock) as Arc<dyn MonotonicClock>;
        assert_eq!(held.monotonic(), MonotonicNow::from_millis(0));
        clock.advance_seconds(3);
        assert_eq!(held.monotonic(), MonotonicNow::from_millis(3_000));
        assert!(held.monotonic() >= MonotonicNow::from_millis(3_000));
    }

    /// Positive — the system source is object safe and does not answer a smaller reading than one
    /// it has already answered. Asserted as an ordering, not as an elapsed duration: how much time
    /// passes between two lines is the machine's business.
    #[test]
    fn the_system_monotonic_source_never_goes_backwards() {
        let clock: Arc<dyn MonotonicClock> = Arc::new(SystemMonotonic::new());
        let first = clock.monotonic();
        let second = clock.monotonic();
        assert!(second >= first);
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
