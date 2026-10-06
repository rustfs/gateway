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

//! Explicit POST-policy operator and expiration readings.
//!
//! Responsible for: operator-case selection, measured expiration spellings and UTC normalization.
//! NOT responsible for: signature verification or multipart framing.
//! Upstream: the bounded policy reader. Downstream: expiry comparison against the request clock snapshot.
//! Evidence: <https://github.com/rustfs/gateway/issues/1326> records native POST/storage probes.

use super::PostPolicyError;

/// Keeps the generic, operator-only, and native readings separate.
#[derive(Clone, Copy)]
pub(super) enum PolicyReading {
    Strict,
    CaseInsensitiveOperators,
    LegacyRustfs,
}

impl PolicyReading {
    pub(super) const fn folds_operators(self) -> bool {
        !matches!(self, Self::Strict)
    }

    pub(super) fn expiry(self, value: &str) -> Result<i64, PostPolicyError> {
        match self {
            Self::LegacyRustfs => parse_legacy(value),
            Self::Strict | Self::CaseInsensitiveOperators => {
                crate::clock::unix_seconds(&super::parse_expiration(value)?).ok_or(PostPolicyError::Malformed)
            }
        }
    }
}

fn parse_legacy(value: &str) -> Result<i64, PostPolicyError> {
    let bytes = value.as_bytes();
    if !value.is_ascii() || bytes.len() < 20 {
        return Err(PostPolicyError::Malformed);
    }
    let (local, offset) = if matches!(bytes.last(), Some(b'Z' | b'z')) {
        (&value[..value.len() - 1], 0)
    } else {
        if bytes.len() < 25 {
            return Err(PostPolicyError::Malformed);
        }
        let start = bytes.len() - 6;
        let zone = &bytes[start..];
        let sign = match zone[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return Err(PostPolicyError::Malformed),
        };
        let hour = pair(&zone[1..3])?;
        let minute = pair(&zone[4..6])?;
        if zone[3] != b':' || hour > 23 || minute > 59 {
            return Err(PostPolicyError::Malformed);
        }
        (&value[..start], sign * (hour * 3_600 + minute * 60))
    };
    let second = pair(&bytes[17..19])?;
    if second > 60 {
        return Err(PostPolicyError::Malformed);
    }
    let fraction = &local[19..];
    if !fraction.is_empty() {
        let digits = fraction.strip_prefix('.').ok_or(PostPolicyError::Malformed)?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(PostPolicyError::Malformed);
        }
    }
    // Native ignores exactly one ASCII separator byte; date/time fields remain validated.
    // Fractions are truncated under the existing whole-second request-clock contract.
    let normalized = format!("{}T{}Z", &local[..10], &local[11..19]);
    let date = super::parse_expiration(&normalized)?;
    let utc = crate::clock::unix_seconds(&date)
        .and_then(|seconds| seconds.checked_sub(offset))
        .ok_or(PostPolicyError::Malformed)?;
    if second == 60 {
        leap_second_floor(value, offset, utc)
    } else {
        Ok(utc)
    }
}

// Native accepts a leap at the end of any UTC month, including through a numeric offset.
// Its preceding-nanosecond representation becomes the preceding second on our whole-second clock.
fn leap_second_floor(value: &str, offset: i64, utc: i64) -> Result<i64, PostPolicyError> {
    let bytes = value.as_bytes();
    let year = value[..4].parse::<i64>().map_err(|_| PostPolicyError::Malformed)?;
    let month = pair(&bytes[5..7])?;
    let day = pair(&bytes[8..10])?;
    let utc_position = pair(&bytes[11..13])? * 3_600 + pair(&bytes[14..16])? * 60 + 60 - offset;
    // The bounded offset can place this UTC midnight on the local date or the following date.
    let boundary =
        (utc_position == 0 && day == 1) || (utc_position == 86_400 && Some(day) == crate::clock::last_day_of_month(year, month));
    if !boundary {
        return Err(PostPolicyError::Malformed);
    }
    utc.checked_sub(1).ok_or(PostPolicyError::Malformed)
}

fn pair(bytes: &[u8]) -> Result<i64, PostPolicyError> {
    match bytes {
        [first, second] if first.is_ascii_digit() && second.is_ascii_digit() => {
            Ok(i64::from(*first - b'0') * 10 + i64::from(*second - b'0'))
        }
        _ => Err(PostPolicyError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTANT: i64 = 1_893_587_696;

    #[test]
    fn legacy_expirations_name_the_same_utc_instant() {
        for value in [
            "2030-01-02T12:34:56Z",
            "2030-01-02 12:34:56z",
            "2030-01-02t12:34:56Z",
            "2030-01-02T18:04:56+05:30",
            "2030-01-02T05:19:56-07:15",
            "2030-01-02T12:34:56-00:00",
            "2030-01-02T12:34:56.123456789012345678901234567890Z",
            "2030-01-02T18:04:56.123456789012+05:30",
        ] {
            assert_eq!(parse_legacy(value), Ok(INSTANT), "{value:?}");
        }
    }

    #[test]
    fn every_single_ascii_separator_keeps_the_instant() {
        for separator in 0u8..=127 {
            let value = format!("2030-01-02{}12:34:56Z", char::from(separator));
            assert_eq!(parse_legacy(&value), Ok(INSTANT), "separator {separator}");
            if separator != b'T' {
                assert_eq!(super::super::parse_expiration(&value).err(), Some(PostPolicyError::Malformed));
            }
        }
    }

    #[test]
    fn n_offsets_cannot_be_ignored_or_applied_in_reverse() {
        for (value, expected) in [
            ("2000-01-01T00:30:00+01:00", 946_683_000),
            ("1999-12-31T23:30:00-01:00", 946_686_600),
            ("2030-01-03T12:33:56+23:59", INSTANT),
        ] {
            assert_eq!(parse_legacy(value), Ok(expected), "{value}");
        }
    }

    #[test]
    fn n_legacy_time_fields_reject_invalid_leaps_and_overflow() {
        for value in [
            "2030-01-02T12:34:60Z",
            "2030-01-02T12:34:61Z",
            "2030-01-02T12:60:56Z",
            "2030-01-02T24:00:00Z",
            "2030-01-02T2:34:56Z",
            "2030-01-02T12:4:56Z",
            "2030-01-02T12:34:6Z",
        ] {
            assert_eq!(parse_legacy(value), Err(PostPolicyError::Malformed), "{value}");
        }
    }

    #[test]
    fn n_legacy_calendar_still_rejects_impossible_dates() {
        for value in [
            "2030-02-29T12:34:56Z",
            "2030-01-00T12:34:56Z",
            "2030-00-02T12:34:56Z",
            "2030-1-02T12:34:56Z",
            "2030-01-2T12:34:56Z",
            "+02030-01-02T12:34:56Z",
            "12030-01-02T12:34:56Z",
        ] {
            assert_eq!(parse_legacy(value), Err(PostPolicyError::Malformed), "{value}");
        }
    }

    #[test]
    fn n_legacy_offsets_need_bounded_colon_separated_fields() {
        for value in [
            "2030-01-02T12:34:56+24:00",
            "2030-01-02T12:34:56+00:60",
            "2030-01-02T12:34:56+0530",
            "2030-01-02T12:34:56+05_30",
            "2030-01-02T12:34:56+05",
            "2030-01-02T12:34:56+00:00:00",
            "2030-01-02T12:34:5600:00",
            "2030-01-02T12:34:56",
            "2030-01-02T12:34:56UTC",
        ] {
            assert_eq!(parse_legacy(value), Err(PostPolicyError::Malformed), "{value}");
        }
    }

    #[test]
    fn n_fraction_spelling_and_padding_do_not_become_opaque() {
        for value in [
            "2030-01-02T12:34:56.Z",
            "2030-01-02T12:34:56,123Z",
            "2030-01-02T12:34:56.123456789xZ",
            "2030-01-0\u{e9}12:34:56Z",
            " 2030-01-02T12:34:56Z",
            "2030-01-02T12:34:56Z ",
            "2030-01-02  12:34:56Z",
            "2030-01-02\u{a0}12:34:56Z",
            "2030-01-02T12:34Z",
        ] {
            assert_eq!(parse_legacy(value), Err(PostPolicyError::Malformed), "{value:?}");
        }
    }

    #[test]
    fn n_the_shared_strict_reader_does_not_accept_legacy_spellings() {
        for value in [
            "2030-01-02 12:34:56Z",
            "2030-01-02t12:34:56z",
            "2030-01-02T12:34:56+00:00",
            "2030-01-02T12:34:56.123456789012Z",
            "2030-01-02\x0012:34:56Z",
        ] {
            assert_eq!(super::super::parse_expiration(value).err(), Some(PostPolicyError::Malformed), "{value:?}");
        }
    }

    #[test]
    fn legacy_leap_seconds_use_the_last_whole_second_of_a_utc_month() {
        for (value, expected) in [
            ("2016-12-31T23:59:60Z", 1_483_228_799),
            ("2030-01-31T23:59:60Z", 1_896_134_399),
            ("2030-02-28T23:59:60Z", 1_898_553_599),
            ("2030-03-31T23:59:60Z", 1_901_231_999),
            ("2030-04-30T23:59:60Z", 1_903_823_999),
            ("2030-05-31T23:59:60Z", 1_906_502_399),
            ("2030-06-30T23:59:60Z", 1_909_094_399),
            ("2030-07-31T23:59:60Z", 1_911_772_799),
            ("2030-08-31T23:59:60Z", 1_914_451_199),
            ("2030-09-30T23:59:60Z", 1_917_043_199),
            ("2030-10-31T23:59:60Z", 1_919_721_599),
            ("2030-11-30T23:59:60Z", 1_922_313_599),
            ("2030-12-31T23:59:60Z", 1_924_991_999),
            ("2032-02-29T23:59:60Z", 1_961_711_999),
            ("2030-07-01T00:59:60+01:00", 1_909_094_399),
            ("2030-06-30T22:59:60-01:00", 1_909_094_399),
            ("2031-01-01T00:59:60+01:00", 1_924_991_999),
            ("2030-06-30T23:59:60.5Z", 1_909_094_399),
        ] {
            assert_eq!(parse_legacy(value), Ok(expected), "{value}");
        }
    }

    #[test]
    fn n_leap_seconds_need_the_utc_month_boundary() {
        for value in [
            "2030-06-30T23:59:60+01:00",
            "2030-06-30T23:59:60-01:00",
            "2030-07-01T23:59:60Z",
            "2030-01-30T23:59:60Z",
            "2030-02-27T23:59:60Z",
            "2032-02-28T23:59:60Z",
            "2030-04-29T23:59:60Z",
        ] {
            assert_eq!(parse_legacy(value), Err(PostPolicyError::Malformed), "{value}");
        }
    }
}
