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

//! How a presigned URL's lifetime is read off the wire: the strict AWS reading, and the RustFS
//! profile's legacy one.
//!
//! Responsible for: [`PresignedExpiryRule`], [`enforce_presign_expiry`] (the strict SigV4
//! `X-Amz-Expires` reader), and the legacy readings of SigV4's `X-Amz-Expires` and SigV2's
//! `Expires` that [`PresignedExpiryRule::LegacyRustfs`] selects.
//! NOT responsible for: the clock arithmetic (`crate::clock`), SigV2's strict reading
//! (`crate::sig_v2::parse_presigned_expires`), or which rule a deployment runs
//! ([`crate::SecurityFloor::with_presigned_expiry_rule`]).
//! Upstream: [`crate::WireView`], [`crate::ClockChecked`], [`crate::RequestNow`].
//! Downstream: [`crate::floor`] and the SigV2 string-to-sign.
//!
//! # What legacy RustFS reads, and why the RustFS profile reads the same
//!
//! Measured against a legacy RustFS build (rustfs/rustfs `e870a6d25b`, presigned `GET` redeemed
//! over a raw socket): `X-Amz-Expires` is an unsigned 32-bit integer in Rust's own spelling — an
//! optional leading `+`, leading zeros allowed — capped at 604800 (rustfs/rustfs#5368); `0` is a
//! lifetime that has already ended (`403 AccessDenied`), unless the URL is dated in the future;
//! and a URL stops working at the second its lifetime ends. SigV2's `Expires` is any
//! non-negative absolute second up to the year 9999, again in Rust's signed spelling (`+`, and
//! `-0`), with no ceiling on how far ahead it lies: `s3cmd signurl` links that live for a year
//! work against RustFS today. Refusing them is a request legacy RustFS accepts answered
//! differently, which the RustFS profile must not do.
//!
//! Legacy RustFS decodes its query as a form, so a literal `+` on the wire is a space there and
//! only an escaped `%2B` is a plus; the legacy readings below read their value the same way, so a
//! literal `+5` is refused exactly as legacy RustFS refuses it.

use crate::clock::{ClockChecked, PresignExpiry, RequestNow, enforce_expiry, enforce_legacy_rustfs_expiry};
use crate::floor::{WireView, X_AMZ_EXPIRES};
use crate::query::RawQuery;
use crate::sig_v2::SIGV2_EXPIRES_PARAM;
use crate::verdict::AuthError;

/// The latest SigV2 `Expires` legacy RustFS can represent: 9999-12-30T22:00:00Z, the last whole
/// second of its timestamp type.
const LEGACY_SIGV2_LATEST_EXPIRES: u64 = 253_402_207_200;

/// Which reading of a presigned URL's lifetime a deployment runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PresignedExpiryRule {
    /// The AWS reading: `X-Amz-Expires` a strict decimal in `1..=604800`, valid through its last
    /// second; SigV2's `Expires` a strict decimal at most seven days ahead.
    #[default]
    Aws,
    /// Legacy RustFS's reading, for the RustFS profile only (see the module documentation).
    LegacyRustfs,
}

impl PresignedExpiryRule {
    /// The spelling the startup security-posture report uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::LegacyRustfs => "legacy-rustfs",
        }
    }

    /// H2 for a SigV4 presigned URL under this rule.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationQueryParametersError`] for a missing, repeated or unreadable
    /// `X-Amz-Expires` or one outside the rule's range; [`AuthError::RequestExpired`] once the
    /// lifetime has passed.
    pub fn enforce(self, view: &WireView<'_>, clock: ClockChecked) -> Result<PresignExpiry, AuthError> {
        match self {
            Self::Aws => enforce_presign_expiry(view, clock),
            Self::LegacyRustfs => {
                // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads `X-Amz-Expires` as
                // Rust's `u32` (`+5` and `0005` are five) and takes `0` as a lifetime that has
                // already ended, where AWS refuses both spellings and the value. Kept so no URL
                // RustFS honours today stops working; the intended future behaviour is the AWS
                // rule.
                let raw = legacy_form_value(view, X_AMZ_EXPIRES)?;
                let seconds = legacy_unsigned(&raw).ok_or(AuthError::AuthorizationQueryParametersError)?;
                enforce_legacy_rustfs_expiry(clock, seconds)
            }
        }
    }

    /// SigV2's presigned `Expires` read off `view` and checked against `now` under this rule: the
    /// instant the URL stops working, as an absolute Unix second.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationQueryParametersError`] for a missing, repeated or unreadable
    /// value or one outside the rule's range; [`AuthError::RequestExpired`] once the instant has
    /// passed.
    pub fn sigv2_expires_of(self, view: &WireView<'_>, now: RequestNow) -> Result<u64, AuthError> {
        let raw = match self {
            Self::Aws => view
                .query()
                .decoded_value(SIGV2_EXPIRES_PARAM)
                .map_err(|_| AuthError::AuthorizationQueryParametersError)?
                .ok_or(AuthError::AuthorizationQueryParametersError)?,
            Self::LegacyRustfs => legacy_form_value(view, SIGV2_EXPIRES_PARAM)?,
        };
        self.sigv2_expires(&raw, now)
    }

    /// SigV2's presigned `Expires` value `raw` checked against `now` under this rule.
    ///
    /// # Errors
    ///
    /// As [`PresignedExpiryRule::sigv2_expires_of`], for the value alone.
    pub fn sigv2_expires(self, raw: &str, now: RequestNow) -> Result<u64, AuthError> {
        match self {
            Self::Aws => crate::sig_v2::parse_presigned_expires(raw, now),
            Self::LegacyRustfs => {
                // Legacy-compat (rustfs/backlog#2684): legacy RustFS accepts a SigV2 presigned URL
                // that expires any time before the year 10000, where AWS refuses one more than
                // seven days ahead; a leaked link therefore stays valid for as long as its signer
                // chose. Kept so the long-lived links RustFS users mint today keep working; the
                // intended future behaviour is the AWS seven-day ceiling.
                let expires = legacy_sigv2_expires(raw).ok_or(AuthError::AuthorizationQueryParametersError)?;
                let now = u64::try_from(now.unix_seconds()).map_err(|_| AuthError::AuthorizationQueryParametersError)?;
                if expires <= now {
                    return Err(AuthError::RequestExpired);
                }
                Ok(expires)
            }
        }
    }

    /// Whether `raw` is a SigV2 `Expires` spelling this rule reads, for the string-to-sign, which
    /// signs the value verbatim and must not sign one the floor would not have read.
    pub(crate) fn sigv2_expires_spelling(self, raw: &str) -> Result<(), AuthError> {
        match self {
            Self::Aws => crate::sig_v2::parse_expires_digits(raw).map(|_| ()),
            Self::LegacyRustfs => legacy_sigv2_expires(raw)
                .map(|_| ())
                .ok_or(AuthError::AuthorizationQueryParametersError),
        }
    }
}

/// H2, the parsing half — the strict `X-Amz-Expires` reader.
///
/// Strict means: present exactly once, a non-empty run of ASCII digits and nothing else. No sign,
/// no decimal point, no exponent, no whitespace, no unit suffix, no non-ASCII digit. Everything
/// else is a rejection, because every lenient reader turns some spelling of "very large" into a
/// presigned URL that outlives its ceiling (rustfs/rustfs#5368).
///
/// The range and overflow rules are [`crate::enforce_expiry`]'s, and this function calls it.
///
/// # Errors
///
/// [`AuthError::AuthorizationQueryParametersError`] for every spelling fault and for a value
/// outside `1..=604800`; [`AuthError::RequestExpired`] when the URL's lifetime has passed.
pub fn enforce_presign_expiry(view: &WireView<'_>, clock: ClockChecked) -> Result<PresignExpiry, AuthError> {
    let raw = single_expires(view)?;
    let digits = raw.as_bytes();
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(AuthError::AuthorizationQueryParametersError);
    }
    let mut seconds: u64 = 0;
    for digit in digits {
        seconds = seconds
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or(AuthError::AuthorizationQueryParametersError)?;
    }
    enforce_expiry(clock, seconds)
}

/// The one decoded `X-Amz-Expires` value, refusing a missing or repeated one.
fn single_expires(view: &WireView<'_>) -> Result<String, AuthError> {
    if view.count_query_param(X_AMZ_EXPIRES) != 1 {
        return Err(AuthError::AuthorizationQueryParametersError);
    }
    view.query()
        .decoded_value(X_AMZ_EXPIRES)
        .map_err(|_| AuthError::AuthorizationQueryParametersError)?
        .ok_or(AuthError::AuthorizationQueryParametersError)
}

/// The one value of `name`, decoded as legacy RustFS decodes its query: as a form, so a literal
/// `+` is a space and only `%2B` is a plus.
fn legacy_form_value(view: &WireView<'_>, name: &str) -> Result<String, AuthError> {
    if view.count_query_param(name) != 1 {
        return Err(AuthError::AuthorizationQueryParametersError);
    }
    let spaced = view.query().as_str().replace('+', "%20");
    RawQuery::new(&spaced)
        .decoded_value(name)
        .map_err(|_| AuthError::AuthorizationQueryParametersError)?
        .ok_or(AuthError::AuthorizationQueryParametersError)
}

/// Rust's own `u32` spelling: an optional single leading `+`, then one or more ASCII digits.
fn legacy_unsigned(raw: &str) -> Option<u64> {
    let digits = raw.strip_prefix('+').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok().map(u64::from)
}

/// Rust's own `i64` spelling — an optional single leading `+` or `-`, then one or more ASCII
/// digits — for a value in `0..=LEGACY_SIGV2_LATEST_EXPIRES`. `-0` is zero.
fn legacy_sigv2_expires(raw: &str) -> Option<u64> {
    let digits = raw.strip_prefix(['+', '-']).unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = u64::try_from(raw.parse::<i64>().ok()?).ok()?;
    (value <= LEGACY_SIGV2_LATEST_EXPIRES).then_some(value)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use http::HeaderMap;

    use crate::clock::enforce_clock_skew;
    use crate::parse::AmzDate;
    use crate::{MAX_PRESIGNED_EXPIRY_SECONDS, SkewWindow};

    /// 2026-01-02T03:04:05Z.
    const SIGNED_AT: i64 = 1_767_323_045;
    const SIGNED_AT_STAMP: &str = "20260102T030405Z";

    fn clock_at(now: i64) -> ClockChecked {
        let signed_at = AmzDate::parse(SIGNED_AT_STAMP).expect("a stamp");
        enforce_clock_skew(&signed_at, RequestNow::from_unix_seconds(now), SkewWindow::default()).expect("inside the window")
    }

    fn legacy(query: &str, now: i64) -> Result<u64, AuthError> {
        let headers = HeaderMap::new();
        let view = WireView::new(&headers, RawQuery::new(query));
        PresignedExpiryRule::LegacyRustfs
            .enforce(&view, clock_at(now))
            .map(|expiry| expiry.expires_in_seconds())
    }

    #[test]
    fn the_legacy_reading_takes_rusts_unsigned_spelling() {
        for (raw, seconds) in [
            ("300", 300),
            ("%2B300", 300),
            ("0300", 300),
            ("%2B0300", 300),
            ("604800", 604_800),
        ] {
            assert_eq!(legacy(&format!("X-Amz-Expires={raw}"), SIGNED_AT), Ok(seconds), "{raw}");
        }
    }

    #[test]
    fn n_the_legacy_reading_refuses_every_other_spelling() {
        // A literal `+` is a space to legacy RustFS's form decoding, so `+300` is ` 300`.
        for raw in [
            "",
            "%2B",
            "%2B%2B5",
            "+300",
            "-5",
            "-0",
            "%205",
            "5%20",
            "5.0",
            "0x10",
            "1e3",
            "4294967296",
            "%EF%BC%95",
            "604801",
        ] {
            assert_eq!(
                legacy(&format!("X-Amz-Expires={raw}"), SIGNED_AT),
                Err(AuthError::AuthorizationQueryParametersError),
                "{raw:?}"
            );
        }
        assert_eq!(legacy("", SIGNED_AT), Err(AuthError::AuthorizationQueryParametersError), "absent");
        assert_eq!(
            legacy("X-Amz-Expires=5&X-Amz-Expires=5", SIGNED_AT),
            Err(AuthError::AuthorizationQueryParametersError),
            "repeated"
        );
    }

    #[test]
    fn n_the_legacy_reading_ends_a_lifetime_at_its_last_second() {
        assert_eq!(legacy("X-Amz-Expires=60", SIGNED_AT + 59), Ok(60));
        assert_eq!(legacy("X-Amz-Expires=60", SIGNED_AT + 60), Err(AuthError::RequestExpired));
        assert_eq!(legacy("X-Amz-Expires=60", SIGNED_AT + 61), Err(AuthError::RequestExpired));
        // The AWS reading keeps the URL through that second.
        let headers = HeaderMap::new();
        let view = WireView::new(&headers, RawQuery::new("X-Amz-Expires=60"));
        assert!(PresignedExpiryRule::Aws.enforce(&view, clock_at(SIGNED_AT + 60)).is_ok());
    }

    #[test]
    fn n_a_zero_lifetime_has_ended_unless_the_url_is_dated_ahead() {
        assert_eq!(legacy("X-Amz-Expires=0", SIGNED_AT), Err(AuthError::RequestExpired));
        assert_eq!(legacy("X-Amz-Expires=0", SIGNED_AT + 1), Err(AuthError::RequestExpired));
        assert_eq!(legacy("X-Amz-Expires=0", SIGNED_AT - 60), Ok(0), "dated a minute ahead of the clock");
        let headers = HeaderMap::new();
        let view = WireView::new(&headers, RawQuery::new("X-Amz-Expires=0"));
        assert_eq!(
            PresignedExpiryRule::Aws.enforce(&view, clock_at(SIGNED_AT - 60)).err(),
            Some(AuthError::AuthorizationQueryParametersError),
            "AWS refuses the value"
        );
        assert_eq!(MAX_PRESIGNED_EXPIRY_SECONDS, 604_800);
    }

    #[test]
    fn the_legacy_sigv2_reading_has_no_ceiling_and_takes_rusts_signed_spelling() {
        let now = RequestNow::from_unix_seconds(1_000_000);
        let rule = PresignedExpiryRule::LegacyRustfs;
        for (raw, expires) in [
            ("1000001", 1_000_001),
            ("1604801", 1_604_801),
            ("+1604801", 1_604_801),
            ("031536000", 31_536_000),
            ("253402207200", 253_402_207_200),
        ] {
            assert_eq!(rule.sigv2_expires(raw, now), Ok(expires), "{raw}");
            assert_eq!(rule.sigv2_expires_spelling(raw), Ok(()), "{raw}");
        }
        let headers = HeaderMap::new();
        let escaped = WireView::new(&headers, RawQuery::new("Expires=%2B1604801"));
        assert_eq!(rule.sigv2_expires_of(&escaped, now), Ok(1_604_801));
        let literal = WireView::new(&headers, RawQuery::new("Expires=+1604801"));
        assert_eq!(
            rule.sigv2_expires_of(&literal, now),
            Err(AuthError::AuthorizationQueryParametersError),
            "a literal plus is a space to legacy RustFS"
        );
        let repeated = WireView::new(&headers, RawQuery::new("Expires=1604801&Expires=1604801"));
        assert_eq!(rule.sigv2_expires_of(&repeated, now), Err(AuthError::AuthorizationQueryParametersError));
        assert_eq!(
            PresignedExpiryRule::Aws.sigv2_expires("1604801", now),
            Err(AuthError::AuthorizationQueryParametersError),
            "the AWS reading keeps its seven-day ceiling"
        );
    }

    #[test]
    fn n_the_legacy_sigv2_reading_refuses_elapsed_negative_and_unrepresentable_instants() {
        let now = RequestNow::from_unix_seconds(1_000_000);
        let rule = PresignedExpiryRule::LegacyRustfs;
        assert_eq!(rule.sigv2_expires("1000000", now), Err(AuthError::RequestExpired));
        assert_eq!(rule.sigv2_expires("0", now), Err(AuthError::RequestExpired));
        assert_eq!(rule.sigv2_expires("-0", now), Err(AuthError::RequestExpired));
        for raw in [
            "",
            "+",
            "-",
            "-1",
            "+-1",
            " 1",
            "1 ",
            "1.5",
            "0x10",
            "253402207201",
            "9223372036854775808",
            "\u{ff10}",
        ] {
            assert_eq!(rule.sigv2_expires(raw, now), Err(AuthError::AuthorizationQueryParametersError), "{raw:?}");
            assert_eq!(
                rule.sigv2_expires_spelling(raw),
                Err(AuthError::AuthorizationQueryParametersError),
                "{raw:?}"
            );
        }
    }
}
