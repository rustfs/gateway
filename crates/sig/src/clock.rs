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

//! The one clock reading a request is allowed to have, and the two checks that consume it.
//!
//! Responsible for: [`RequestNow`] (the per-request snapshot), [`RequestClock`] and
//! [`SystemClock`] (where a snapshot comes from), [`SkewWindow`] (the accepted distance between
//! the signed timestamp and that snapshot, capped at fifteen minutes), [`enforce_clock_skew`] and
//! the [`ClockChecked`] receipt it produces, and [`enforce_expiry`] — the checked arithmetic
//! behind a presigned URL's lifetime.
//! NOT responsible for: reading `X-Amz-Expires` off the wire (that is [`crate::floor`], because it
//! is a query-parsing rule), deciding which operations accept a presigned request (also
//! [`crate::floor`]), or verifying any signature.
//! Upstream: [`crate::AmzDate`], [`crate::AuthError`]. Downstream: [`crate::floor`], which is the
//! only caller, and `rustfs-gateway-core`'s authentication stage through it.
//!
//! # Why the snapshot is a value and the clock is not
//!
//! Every time-dependent check in one admission reads the same [`RequestNow`], because the checks
//! take one by value and there is no clock inside them to ask again. That is the whole mechanism:
//! a function that held a `&dyn RequestClock` could call `capture()` twice, and a request whose
//! skew check and expiry check straddle a leap second, an NTP step or a container's first clock
//! sync would then be judged against two different presents. The snapshot is taken once, at the
//! edge, and passed down.
//!
//! # Why the window has a ceiling and not just a default
//!
//! [`SkewWindow::new`] clamps both directions to [`SkewWindow::MAX`]. A deployment may narrow the
//! window; it may not widen it. A configurable "24 hours of skew" is indistinguishable from no
//! replay window at all for every captured request, and the whole point of this module is that a
//! deployment cannot switch the floor off through configuration.

use core::time::Duration;

use crate::parse::AmzDate;
use crate::verdict::AuthError;

/// The largest `X-Amz-Expires` a presigned URL may carry: seven days, in seconds.
///
/// AWS documents seven days as the ceiling for a SigV4 presigned URL. A server that accepts more
/// mints a credential with a longer life than the signer's own documentation promises, and
/// rustfs/rustfs#5368 is what that looks like in practice.
pub const MAX_PRESIGNED_EXPIRY_SECONDS: u64 = 604_800;

/// One reading of the wall clock, taken once when the request arrived.
///
/// Seconds since the Unix epoch, signed so that arithmetic against a timestamp far in the past or
/// the future is representable rather than wrapping. Everything downstream is `checked_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestNow(i64);

impl RequestNow {
    /// Builds a snapshot from seconds since the Unix epoch.
    ///
    /// Public because a test needs to pin the present, and because a deployment that gets its time
    /// from something other than [`SystemClock`] — a PTP source, a simulation harness — needs a
    /// way in that does not involve a trait object.
    #[must_use]
    pub const fn from_unix_seconds(seconds: i64) -> Self {
        Self(seconds)
    }

    /// The snapshot, in seconds since the Unix epoch.
    #[must_use]
    pub const fn unix_seconds(&self) -> i64 {
        self.0
    }

    /// Reads the system clock once.
    ///
    /// A clock set before 1970 saturates to the epoch rather than panicking: the authentication
    /// path may not panic on a misconfigured host, and a request judged against the epoch fails
    /// the skew check, which is the correct answer for a machine whose clock is that wrong.
    #[must_use]
    pub fn capture() -> Self {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX));
        Self(seconds)
    }
}

/// Where a [`RequestNow`] comes from.
///
/// The trait exists so that a server can substitute its own time source once per request. It is
/// deliberately not a parameter of any check in this crate: the checks take the snapshot, so
/// "ask the clock again half way through" is not something a caller can express.
pub trait RequestClock {
    /// Takes one reading.
    fn capture(&self) -> RequestNow;
}

/// The system clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SystemClock;

impl RequestClock for SystemClock {
    fn capture(&self) -> RequestNow {
        RequestNow::capture()
    }
}

/// How far a signed timestamp may sit from the snapshot, in each direction.
///
/// Both directions matter, and for different reasons. The past direction bounds how long a
/// captured signature stays usable. The future direction has to be non-zero because a client whose
/// clock runs a few minutes fast is ordinary, not hostile — refusing those requests is the defect
/// s3s#216 fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SkewWindow {
    past: Duration,
    future: Duration,
}

impl SkewWindow {
    /// The ceiling on either direction: fifteen minutes, the window AWS documents.
    pub const MAX: Duration = Duration::from_secs(15 * 60);

    /// The default window: fifteen minutes each way.
    pub const DEFAULT: Self = Self {
        past: Self::MAX,
        future: Self::MAX,
    };

    /// Builds a window, clamping each direction to [`SkewWindow::MAX`].
    ///
    /// Narrowing is a deployment's business. Widening is not: it is the one configuration change
    /// that would turn this check into a formality, so it is not representable.
    #[must_use]
    pub const fn new(past: Duration, future: Duration) -> Self {
        // `Duration::min` is not const, so the comparison is spelled out.
        let past = if past.as_secs() > Self::MAX.as_secs() {
            Self::MAX
        } else {
            past
        };
        let future = if future.as_secs() > Self::MAX.as_secs() {
            Self::MAX
        } else {
            future
        };
        Self { past, future }
    }

    /// How old a signed timestamp may be.
    #[must_use]
    pub const fn past(&self) -> Duration {
        self.past
    }

    /// How far ahead of the snapshot a signed timestamp may be.
    #[must_use]
    pub const fn future(&self) -> Duration {
        self.future
    }
}

impl Default for SkewWindow {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Proof that a timestamp was compared against the request's own clock snapshot.
///
/// Every downstream check that needs a time takes this rather than an [`AmzDate`], so the skew
/// check cannot be skipped for one signing path and run for another — which is exactly the defect
/// s3s#616 fixed, where the window applied to presigned requests only. It carries both the
/// timestamp and the snapshot, so the scope cross-check and the expiry check are talking about the
/// same instant the skew check approved.
///
/// There is no public constructor: [`enforce_clock_skew`] is the only producer.
///
/// ```compile_fail,E0451
/// use rustfs_gateway_sig::{AmzDate, ClockChecked, RequestNow};
/// let signed_at = AmzDate::parse("20150830T123600Z").expect("valid");
/// // No route from a timestamp to a receipt that says it was checked.
/// let _ = ClockChecked { signed_at, now: RequestNow::from_unix_seconds(0) };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClockChecked {
    signed_at: AmzDate,
    signed_at_unix: i64,
    now: RequestNow,
}

impl ClockChecked {
    /// The timestamp that was checked, as signed.
    #[must_use]
    pub const fn signed_at(&self) -> AmzDate {
        self.signed_at
    }

    /// That timestamp in seconds since the Unix epoch.
    #[must_use]
    pub const fn signed_at_unix_seconds(&self) -> i64 {
        self.signed_at_unix
    }

    /// The snapshot it was checked against. The same value every other check in this admission
    /// sees.
    #[must_use]
    pub const fn now(&self) -> RequestNow {
        self.now
    }

    /// Builds a receipt without checking anything. Test-only, and `pub(crate)`: it exists so that
    /// the overflow case can be reached with a timestamp no `AmzDate` can spell.
    #[cfg(test)]
    pub(crate) const fn from_checked_parts(signed_at: AmzDate, signed_at_unix: i64, now: RequestNow) -> Self {
        Self {
            signed_at,
            signed_at_unix,
            now,
        }
    }
}

/// H1 — the clock-skew window, on every signing path.
///
/// The caller passes the snapshot, so the header path, the presigned path and the POST-policy path
/// are all judged against one present. There is no variant of this function that takes a clock.
///
/// # Errors
///
/// [`AuthError::RequestTimeTooSkewed`] when the timestamp is further in the past than
/// [`SkewWindow::past`], further in the future than [`SkewWindow::future`], or so far from the
/// epoch that the distance is not representable — an unrepresentable distance is definitionally
/// outside any window, and answering anything else would mean deciding a comparison that
/// overflowed.
pub fn enforce_clock_skew(signed_at: &AmzDate, now: RequestNow, window: SkewWindow) -> Result<ClockChecked, AuthError> {
    let signed_at_unix = unix_seconds(signed_at).ok_or(AuthError::RequestTimeTooSkewed)?;
    let delta = now
        .unix_seconds()
        .checked_sub(signed_at_unix)
        .ok_or(AuthError::RequestTimeTooSkewed)?;

    let past = i64::try_from(window.past().as_secs()).unwrap_or(i64::MAX);
    let future = i64::try_from(window.future().as_secs()).unwrap_or(i64::MAX);
    if delta > past || delta < -future {
        return Err(AuthError::RequestTimeTooSkewed);
    }
    Ok(ClockChecked {
        signed_at: *signed_at,
        signed_at_unix,
        now,
    })
}

/// The lifetime of one presigned URL, once it has been range-checked and found unexpired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PresignExpiry {
    expires_in: u64,
    expires_at: i64,
}

impl PresignExpiry {
    /// The `X-Amz-Expires` value, in seconds.
    #[must_use]
    pub const fn expires_in_seconds(&self) -> u64 {
        self.expires_in
    }

    /// When the URL stops working, in seconds since the Unix epoch.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> i64 {
        self.expires_at
    }
}

/// H2, the arithmetic half — the range check, the overflow check and the expiry comparison.
///
/// The strict parse of the `X-Amz-Expires` *text* lives in `crate::floor`, because a spelling
/// rule belongs with the query reader. What lives here is what must not be got wrong once the
/// number exists: the range, and the addition.
///
/// The addition is `checked_add`, and an overflow is a rejection. Saturating instead would turn a
/// timestamp near the upper bound plus a large expiry into "expires at the end of time", which is
/// a presigned URL that never expires — the exact opposite of what the ceiling is for.
///
/// # Errors
///
/// * [`AuthError::AuthorizationQueryParametersError`] when the value is zero, above
///   [`MAX_PRESIGNED_EXPIRY_SECONDS`], or when the expiry instant does not fit.
/// * [`AuthError::RequestExpired`] when the snapshot is past the expiry instant.
pub fn enforce_expiry(clock: ClockChecked, expires_in_seconds: u64) -> Result<PresignExpiry, AuthError> {
    if expires_in_seconds == 0 || expires_in_seconds > MAX_PRESIGNED_EXPIRY_SECONDS {
        return Err(AuthError::AuthorizationQueryParametersError);
    }
    let expires_at = i64::try_from(expires_in_seconds)
        .ok()
        .and_then(|seconds| clock.signed_at_unix_seconds().checked_add(seconds))
        .ok_or(AuthError::AuthorizationQueryParametersError)?;
    if clock.now().unix_seconds() > expires_at {
        return Err(AuthError::RequestExpired);
    }
    Ok(PresignExpiry {
        expires_in: expires_in_seconds,
        expires_at,
    })
}

/// Converts `YYYYMMDDTHHMMSSZ` to seconds since the Unix epoch.
///
/// Hand-rolled rather than taken from a date crate, for the same reason [`AmzDate`] keeps its
/// bytes: this crate has no calendar dependency, and the only thing needed is a total ordering
/// against one other instant. The civil-to-days step is the standard proleptic Gregorian
/// algorithm; `chrono`'s and `time`'s agree with it to the second for every value `AmzDate` can
/// spell.
fn unix_seconds(date: &AmzDate) -> Option<i64> {
    let text = date.as_str().as_bytes();
    let digits = |range: core::ops::Range<usize>| -> Option<i64> {
        let mut value: i64 = 0;
        for index in range {
            let byte = *text.get(index)?;
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value.checked_mul(10)?.checked_add(i64::from(byte - b'0'))?;
        }
        Some(value)
    };
    let (year, month, day) = (digits(0..4)?, digits(4..6)?, digits(6..8)?);
    let (hour, minute, second) = (digits(9..11)?, digits(11..13)?, digits(13..15)?);
    let days = days_from_civil(year, month, day)?;
    days.checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

/// Days from `1970-01-01` to a proleptic Gregorian date, positive or negative.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = if month <= 2 { year.checked_sub(1)? } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?.checked_add(day_of_era)?.checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(text: &str) -> AmzDate {
        AmzDate::parse(text).expect("a valid timestamp")
    }

    /// Positive — the conversion is pinned against a published instant, so a rewrite of the civil
    /// arithmetic cannot drift silently.
    #[test]
    fn the_epoch_conversion_is_pinned() {
        assert_eq!(unix_seconds(&date("19700101T000000Z")), Some(0));
        assert_eq!(unix_seconds(&date("20150830T123600Z")), Some(1_440_938_160));
        // A leap day, and a century that is not a leap year in the Gregorian calendar.
        assert_eq!(unix_seconds(&date("20000229T000000Z")), Some(951_782_400));
        assert_eq!(unix_seconds(&date("19000301T000000Z")), Some(-2_203_891_200));
    }

    /// Positive — a timestamp inside the window produces a receipt naming the same instant.
    #[test]
    fn a_timestamp_inside_the_window_produces_a_receipt() {
        let now = RequestNow::from_unix_seconds(1_440_938_160);
        let checked = enforce_clock_skew(&date("20150830T123600Z"), now, SkewWindow::DEFAULT).expect("inside");
        assert_eq!(checked.signed_at_unix_seconds(), 1_440_938_160);
        assert_eq!(checked.now(), now);
    }

    /// Negative — both edges of the window are exclusive one second out, and inclusive on it.
    #[test]
    fn the_window_edges_are_exact() {
        let signed = date("20150830T123600Z");
        let at = |offset: i64| RequestNow::from_unix_seconds(1_440_938_160 + offset);
        assert!(enforce_clock_skew(&signed, at(900), SkewWindow::DEFAULT).is_ok());
        assert!(enforce_clock_skew(&signed, at(-900), SkewWindow::DEFAULT).is_ok());
        assert_eq!(
            enforce_clock_skew(&signed, at(901), SkewWindow::DEFAULT).err(),
            Some(AuthError::RequestTimeTooSkewed)
        );
        assert_eq!(
            enforce_clock_skew(&signed, at(-901), SkewWindow::DEFAULT).err(),
            Some(AuthError::RequestTimeTooSkewed)
        );
    }

    /// Negative — a snapshot at the extreme end of the range cannot make the subtraction wrap into
    /// an apparently small skew.
    #[test]
    fn an_unrepresentable_distance_is_skewed_rather_than_wrapped() {
        let signed = date("19700101T000000Z");
        assert_eq!(
            enforce_clock_skew(&signed, RequestNow::from_unix_seconds(i64::MAX), SkewWindow::DEFAULT).err(),
            Some(AuthError::RequestTimeTooSkewed)
        );
        assert_eq!(
            enforce_clock_skew(&signed, RequestNow::from_unix_seconds(i64::MIN), SkewWindow::DEFAULT).err(),
            Some(AuthError::RequestTimeTooSkewed)
        );
    }

    /// Negative — c-sig-0331: an expiry instant that does not fit is a rejection, never a wrap into
    /// "expires at the end of time". Reached with a receipt no `AmzDate` can spell, because the
    /// widest timestamp the wire form allows is nowhere near the boundary.
    #[test]
    fn an_expiry_that_overflows_is_refused_rather_than_saturated() {
        let clock = ClockChecked::from_checked_parts(
            date("20150830T123600Z"),
            i64::MAX - 10,
            RequestNow::from_unix_seconds(i64::MAX - 10),
        );
        assert_eq!(enforce_expiry(clock, 604_800).err(), Some(AuthError::AuthorizationQueryParametersError));
        // One second still fits, so the case above is about the overflow and not about the range.
        assert!(enforce_expiry(clock, 1).is_ok());
    }

    /// Negative — the range is closed on both ends.
    #[test]
    fn the_expiry_range_is_closed_on_both_ends() {
        let now = RequestNow::from_unix_seconds(1_440_938_160);
        let clock = enforce_clock_skew(&date("20150830T123600Z"), now, SkewWindow::DEFAULT).expect("inside");
        assert!(enforce_expiry(clock, 1).is_ok());
        assert!(enforce_expiry(clock, MAX_PRESIGNED_EXPIRY_SECONDS).is_ok());
        assert_eq!(enforce_expiry(clock, 0).err(), Some(AuthError::AuthorizationQueryParametersError));
        assert_eq!(
            enforce_expiry(clock, MAX_PRESIGNED_EXPIRY_SECONDS + 1).err(),
            Some(AuthError::AuthorizationQueryParametersError)
        );
        assert_eq!(enforce_expiry(clock, u64::MAX).err(), Some(AuthError::AuthorizationQueryParametersError));
    }

    /// Negative — a window wider than the ceiling is clamped, so configuration cannot switch the
    /// check off.
    #[test]
    fn a_window_wider_than_the_ceiling_is_clamped() {
        let window = SkewWindow::new(Duration::from_secs(u64::MAX), Duration::from_secs(3_600));
        assert_eq!(window.past(), SkewWindow::MAX);
        assert_eq!(window.future(), SkewWindow::MAX);
        let signed = date("20150830T123600Z");
        assert_eq!(
            enforce_clock_skew(&signed, RequestNow::from_unix_seconds(1_440_938_160 + 3_600), window).err(),
            Some(AuthError::RequestTimeTooSkewed)
        );
    }
}
