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

//! The one HTTP-date spelling legacy RustFS reads a conditional date in.
//!
//! Responsible for: [`strict_http_date`], which reads `Www, DD Mmm YYYY hh:mm:ss GMT` exactly as
//! legacy RustFS reads `If-Modified-Since`, `If-Unmodified-Since` and their two copy-source forms
//! (rustfs/backlog#1677, ruling R14), and nothing wider.
//! NOT responsible for: the RFC 9110 grammar the core reads a date condition with by default
//! (`Timestamp::parse` with `TimestampFormat::HttpDate`, which also reads the RFC 850 and asctime
//! forms and surrounding whitespace), deciding that an unreadable value is refused (the facade's
//! RustFS profile does, before decode), or rendering a date.
//! Upstream: `rustfs-gateway-types`' `Timestamp`. Downstream: `super::value::date_condition_in`
//! and the facade's date-condition refusal, which must agree on every spelling, and
//! `super::document`, which reads a request document's HTTP date with it (rustfs/gateway#1078).
//!
//! # The grammar, as legacy RustFS reads it
//!
//! Legacy RustFS reads these four headers with one fixed format, `Www, DD Mmm YYYY hh:mm:ss GMT`,
//! parsed field by field with no tolerance: every separator is the exact byte, the names are
//! case-sensitive English abbreviations, the day and each clock field are exactly two digits, and
//! nothing may precede or follow the value. Three consequences a reader would not guess:
//!
//! * the weekday is not checked against the date — `Mon, 06 Nov 1994 …` reads as 6 November;
//! * the year may carry a sign: `+1994` reads as 1994 and `-0001` as 2 BC (proleptic Gregorian,
//!   year zero included), always with exactly four digits after the sign;
//! * a leap second (`:60`), a day the month does not have and an hour of `24` are refused.
//!
//! The spelling set is proved equal to the legacy reader's, instant for instant, by the
//! differential property in `crates/goldens` (`operation_diff/date_conditions.rs`).

use rustfs_gateway_types::Timestamp;

/// The weekday abbreviations, in no particular order: the weekday is read and never checked.
const WEEKDAYS: [&[u8; 3]; 7] = [b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun"];

/// The month abbreviations, January first.
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Reads `value` as legacy RustFS reads a conditional date, or `None` when it would refuse it.
///
/// See the module documentation for the grammar. `None` is the whole answer: the caller that
/// refuses an unreadable value renders its own error, and the caller that decodes one has already
/// been preceded by that refusal.
#[must_use]
pub fn strict_http_date(value: &str) -> Option<Timestamp> {
    let rest = value.as_bytes();
    let (weekday, rest) = rest.split_first_chunk::<3>()?;
    if !WEEKDAYS.contains(&weekday) {
        return None;
    }
    let rest = rest.strip_prefix(b", ")?;
    let (day, rest) = two_digits(rest)?;
    let rest = rest.strip_prefix(b" ")?;
    let (month, rest) = rest.split_first_chunk::<3>()?;
    let month = MONTHS.iter().position(|name| *name == month)?;
    let month = u32::try_from(month).ok()? + 1;
    let rest = rest.strip_prefix(b" ")?;
    let (negative, rest) = match rest.split_first() {
        Some((b'+', rest)) => (false, rest),
        Some((b'-', rest)) => (true, rest),
        _ => (false, rest),
    };
    let (high, rest) = two_digits(rest)?;
    let (low, rest) = two_digits(rest)?;
    let year = i64::from(high * 100 + low);
    let year = if negative { -year } else { year };
    let rest = rest.strip_prefix(b" ")?;
    let (hour, rest) = two_digits(rest)?;
    let rest = rest.strip_prefix(b":")?;
    let (minute, rest) = two_digits(rest)?;
    let rest = rest.strip_prefix(b":")?;
    let (second, rest) = two_digits(rest)?;
    if rest != b" GMT" || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let seconds = i64::from(hour * 3600 + minute * 60 + second);
    Some(Timestamp::from_secs(days_from_civil(year, month, day) * 86_400 + seconds))
}

/// Two ASCII digits at the front of `bytes`, as a number, and what follows them.
fn two_digits(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let ([tens, units], rest) = bytes.split_first_chunk::<2>()?;
    if !tens.is_ascii_digit() || !units.is_ascii_digit() {
        return None;
    }
    Some((u32::from(tens - b'0') * 10 + u32::from(units - b'0'), rest))
}

/// Whether `year` is a leap year of the proleptic Gregorian calendar, year zero included.
const fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// The number of days in `month` (1-based) of `year`.
const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to `year`-`month`-`day` of the proleptic Gregorian calendar.
///
/// The era arithmetic of H. Hinnant's public-domain `days_from_civil`, over signed years: an era is
/// 400 years (146 097 days), counted from a March 1 so that the leap day ends its year.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = i64::from((month + 9) % 12);
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)] // Test code: fixed spellings.
mod tests {
    use super::*;

    fn secs(value: &str) -> Option<i64> {
        strict_http_date(value).map(|stamp| stamp.secs())
    }

    #[test]
    fn the_fixed_spelling_reads_as_its_instant() {
        assert_eq!(secs("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(secs("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(secs("Tue, 29 Feb 2000 00:00:00 GMT"), Some(951_782_400));
        assert_eq!(secs("Thu, 31 Dec 9999 23:59:59 GMT"), Some(253_402_300_799));
    }

    #[test]
    fn the_weekday_is_read_but_never_checked() {
        assert_eq!(secs("Mon, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(secs("Sat, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
    }

    #[test]
    fn a_signed_year_reads_as_the_proleptic_year() {
        assert_eq!(secs("Sun, 06 Nov +1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(secs("Thu, 01 Jan 0000 00:00:00 GMT"), Some(-62_167_219_200));
        assert_eq!(secs("Thu, 01 Jan -0000 00:00:00 GMT"), Some(-62_167_219_200));
        assert_eq!(secs("Sat, 01 Jan -0001 00:00:00 GMT"), Some(-62_198_755_200));
        assert_eq!(secs("Sun, 06 Nov -9999 08:49:37 GMT"), Some(-377_678_387_423));
    }

    #[test]
    fn n_the_rfc_850_and_asctime_forms_are_refused() {
        assert_eq!(secs("Sunday, 06-Nov-94 08:49:37 GMT"), None);
        assert_eq!(secs("Sun Nov  6 08:49:37 1994"), None);
    }

    #[test]
    fn n_no_whitespace_is_tolerated_anywhere() {
        for value in [
            " Sun, 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 GMT ",
            "Sun, 06 Nov 1994 08:49:37 GMT\t",
            "Sun,  06 Nov 1994 08:49:37 GMT",
            "Sun, 06  Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov  1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37  GMT",
            "Sun,06 Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(secs(value), None, "{value:?}");
        }
    }

    #[test]
    fn n_names_are_case_sensitive_abbreviations() {
        for value in [
            "sun, 06 Nov 1994 08:49:37 GMT",
            "SUN, 06 NOV 1994 08:49:37 GMT",
            "Sun, 06 nov 1994 08:49:37 GMT",
            "Xyz, 06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 gmt",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 06 Nov 1994 08:49:37 GMTX",
        ] {
            assert_eq!(secs(value), None, "{value:?}");
        }
    }

    #[test]
    fn n_every_numeric_field_has_its_exact_width() {
        for value in [
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 94 08:49:37 GMT",
            "Sun, 06 Nov 01994 08:49:37 GMT",
            "Sun, 06 Nov +10000 08:49:37 GMT",
            "Sun, 06 Nov -001 08:49:37 GMT",
            "Sun, 06 Nov ++1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 8:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37.5 GMT",
            "Sun, +6 Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(secs(value), None, "{value:?}");
        }
    }

    #[test]
    fn n_an_impossible_instant_is_refused() {
        for value in [
            "Sun, 06 Nov 1994 08:49:60 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Nov 1994 08:60:00 GMT",
            "Sun, 00 Nov 1994 08:49:37 GMT",
            "Sun, 31 Nov 1994 08:49:37 GMT",
            "Tue, 29 Feb 1900 00:00:00 GMT",
            "Thu, 29 Feb 2023 00:00:00 GMT",
        ] {
            assert_eq!(secs(value), None, "{value:?}");
        }
    }

    #[test]
    fn n_anything_else_is_refused() {
        for value in [
            "",
            "Invalid Date",
            "1994-11-06T08:49:37Z",
            "784111777",
            "Sun, 06 Nov 1994 08:49:37",
            "Sun, 06 Nov 1994 08:49:37 +0000",
            "Sun, 06 Nov 1994 08:49:37 GMT, Mon, 07 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 GMT\0",
            "Sun, ٠٦ Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(secs(value), None, "{value:?}");
        }
    }
}
