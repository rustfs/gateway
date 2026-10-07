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

//! The date-time grammar legacy RustFS reads a form's `x-amz-object-lock-retain-until-date` with
//! (rustfs/gateway#1167).
//!
//! Responsible for: [`read`], an RFC 3339 date-time exactly as the `time` crate's `Rfc3339` parser
//! reads it, which legacy RustFS's form decoder uses for that field.
//! NOT responsible for: the header of the same name (the core codec's own reading), the gateway
//! grammar's reading of the field (`super::fields::DateGrammar::Iso8601Header`), or deciding that
//! an unreadable value is refused (`super::fields::LockAndCustomerKey::read`).
//! Upstream: `super::fields`. Downstream: nothing.
//!
//! # The grammar
//!
//! `YYYY-MM-DD`, then any one byte as the separator, then `hh:mm:ss`, an optional `.` and at least
//! one digit (digits past the ninth ignored), then `Z` in either case or `±hh:mm` with an hour of
//! at most 23 and a minute of at most 59, and nothing after. The date must exist and the clock
//! read below 24:00:00, except that a second of `60` is read as the last nanosecond before the
//! next second, and only when that instant, in UTC, ends a month.
//!
//! The gateway's ISO 8601 header grammar (`q-timestamp-0011`) differs on a lowercase `t` or `z`,
//! a separator other than `T`, that leap second, an empty fraction and a colon-less offset; the
//! goldens sweep `a_retain_until_date_is_read_as_legacy_rustfs_reads_it` pins this reader against
//! the legacy stack on both pinned revisions.

use rustfs_gateway_types::Timestamp;

/// The instant `value` spells, or `None` for anything legacy RustFS's reader refuses.
pub(super) fn read(value: &str) -> Option<Timestamp> {
    let bytes = value.as_bytes();
    let digits = |at: usize, len: usize| -> Option<i64> {
        let field = bytes.get(at..at.checked_add(len)?)?;
        field
            .iter()
            .try_fold(0i64, |acc, byte| byte.is_ascii_digit().then(|| acc * 10 + i64::from(byte - b'0')))
    };
    let literal = |at: usize, expected: u8| bytes.get(at) == Some(&expected);
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    if !literal(4, b'-') || !literal(7, b'-') {
        return None;
    }
    let (hour, minute, mut second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    if !literal(13, b':') || !literal(16, b':') {
        return None;
    }
    let mut at = 19;
    let mut nanos: i64 = 0;
    if literal(at, b'.') {
        at += 1;
        let start = at;
        let mut scale = 100_000_000;
        while let Some(digit) = bytes.get(at).filter(|byte| byte.is_ascii_digit()) {
            nanos += i64::from(digit - b'0') * scale;
            scale /= 10;
            at += 1;
        }
        if at == start {
            return None;
        }
    }
    let offset_seconds = match bytes.get(at)? {
        b'Z' | b'z' => {
            at += 1;
            0
        }
        sign @ (b'+' | b'-') => {
            let (offset_hour, offset_minute) = (digits(at + 1, 2)?, digits(at + 4, 2)?);
            if !literal(at + 3, b':') || offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            at += 6;
            let magnitude = offset_hour * 3600 + offset_minute * 60;
            if *sign == b'-' { -magnitude } else { magnitude }
        }
        _ => return None,
    };
    if at != bytes.len() {
        return None;
    }
    let leap = second == 60;
    if leap {
        second = 59;
        nanos = 999_999_999;
    }
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds;
    if leap && !ends_a_utc_month(seconds) {
        return None;
    }
    Timestamp::from_secs_nanos(seconds, u32::try_from(nanos).ok()?).ok()
}

/// Whether the UTC second `seconds` (with its last nanosecond) is the last of a month: 23:59:59
/// on the month's last day.
fn ends_a_utc_month(seconds: i64) -> bool {
    let (days, time_of_day) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    time_of_day == 86_399 && day == days_in_month(year, month)
}

const fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (`civil_from_days`).
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use rustfs_gateway_types::TimestampFormat;

    use super::read;

    fn rendered(value: &str) -> Option<String> {
        read(value).and_then(|instant| instant.render(TimestampFormat::Iso8601).ok())
    }

    /// Positive — the spellings legacy RustFS's reader accepts, and the instant each names.
    #[test]
    fn the_legacy_spellings_name_their_instants() {
        for (value, instant) in [
            ("2030-01-01T00:00:00Z", "2030-01-01T00:00:00.000Z"),
            ("2030-01-01t00:00:00z", "2030-01-01T00:00:00.000Z"),
            ("2030-01-01 00:00:00Z", "2030-01-01T00:00:00.000Z"),
            ("2030-01-01_00:00:00Z", "2030-01-01T00:00:00.000Z"),
            ("2030-01-01T00:00:00.5Z", "2030-01-01T00:00:00.500Z"),
            ("2030-01-01T00:00:00.1234567891Z", "2030-01-01T00:00:00.123Z"),
            ("2030-01-01T08:00:00+08:00", "2030-01-01T00:00:00.000Z"),
            ("2029-12-31T23:30:00-00:30", "2030-01-01T00:00:00.000Z"),
            ("2030-12-31T23:59:60Z", "2030-12-31T23:59:59.999Z"),
            ("2031-01-01T07:59:60+08:00", "2030-12-31T23:59:59.999Z"),
            ("2028-02-29T00:00:00Z", "2028-02-29T00:00:00.000Z"),
        ] {
            assert_eq!(rendered(value).as_deref(), Some(instant), "{value}");
        }
    }

    /// Negative — every spelling legacy RustFS's reader refuses.
    #[test]
    fn n_other_spellings_are_refused() {
        for value in [
            "",
            "tomorrow",
            "2030-01-01T00:00:00",
            "2030-01-01T00:00Z",
            "2030-01-01T00:00:00.Z",
            "2030-01-01T24:00:00Z",
            "2030-01-01T00:60:00Z",
            "2030-02-30T00:00:00Z",
            "2029-02-29T00:00:00Z",
            "2030-13-01T00:00:00Z",
            "2030-00-01T00:00:00Z",
            "2030-06-15T12:00:60Z",
            "2030-12-31T23:59:60+01:00",
            "2030-01-01T00:00:00+24:00",
            "2030-01-01T00:00:00+08:60",
            "2030-01-01T00:00:00+0800",
            "+2030-01-01T00:00:00Z",
            "2030-1-01T00:00:00Z",
            "20300101T000000Z",
            "2030-01-01T00:00:00Zx",
            "2030-01-01\u{e9}00:00:00Z",
        ] {
            assert_eq!(rendered(value), None, "{value}");
        }
    }
}
