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

//! The two instants a case pins, in the two spellings the target needs them in.
//!
//! Responsible for: reading `[clock] fixed` and `[clock] request_time` — RFC 3339 UTC, the only
//! form the frozen schema allows — into the Unix second a `FixedClock` is built from and the
//! `YYYYMMDDTHHMMSSZ` stamp that goes into `x-amz-date` and the credential scope.
//! NOT responsible for: reading the wall clock. A case that declares no clock still gets a pinned
//! one, because a run whose answer depends on the day it was run cannot be compared to a baseline.
//! Upstream: nothing. Downstream: `crate::inprocess`.

/// A parsed instant: the second, and the stamp SigV4 signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instant {
    /// Seconds since the Unix epoch.
    pub unix_seconds: i64,
    /// `YYYYMMDDTHHMMSSZ`, byte for byte as it is signed.
    pub amz_stamp: String,
}

/// The instant a case with no `[clock]` block runs at.
///
/// Any fixed value would do; this one matches what most of the corpus pins, so a case that
/// declares a clock and a case that does not are not gratuitously an hour apart in a diff.
pub const DEFAULT_FIXED: &str = "2026-01-02T03:04:05Z";

/// Parses the RFC 3339 UTC form the schema pins: `YYYY-MM-DDTHH:MM:SS[.fff]Z`.
///
/// # Errors
///
/// Returns a message naming the offending value. The schema has already checked the shape, so a
/// failure here means the schema and this reader disagree — which is worth a loud error rather
/// than a fallback to the wall clock.
pub fn parse_rfc3339(text: &str) -> Result<Instant, String> {
    let bad = || format!("`{text}` is not the RFC 3339 UTC form `YYYY-MM-DDTHH:MM:SSZ`");
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') || bytes.get(10) != Some(&b'T') {
        return Err(bad());
    }
    let number =
        |from: usize, to: usize| -> Result<i64, String> { text.get(from..to).ok_or_else(bad)?.parse::<i64>().map_err(|_| bad()) };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return Err(bad());
    }
    let days = days_from_civil(year, month, day);
    Ok(Instant {
        unix_seconds: days * 86_400 + hour * 3_600 + minute * 60 + second,
        amz_stamp: format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"),
    })
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
///
/// Howard Hinnant's `days_from_civil`, which is exact for the whole four-digit range the schema
/// allows and needs no table.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_is_zero() {
        let parsed = parse_rfc3339("1970-01-01T00:00:00Z").expect("valid");
        assert_eq!(parsed.unix_seconds, 0);
        assert_eq!(parsed.amz_stamp, "19700101T000000Z");
    }

    /// The instant most of the corpus pins, checked against an independently computed value.
    #[test]
    fn the_corpus_instant_round_trips() {
        let parsed = parse_rfc3339("2026-01-02T03:04:05Z").expect("valid");
        assert_eq!(parsed.unix_seconds, 1_767_323_045);
        assert_eq!(parsed.amz_stamp, "20260102T030405Z");
    }

    /// A leap day, which is where a hand-rolled calendar goes wrong first.
    #[test]
    fn a_leap_day_is_counted() {
        let before = parse_rfc3339("2024-02-28T00:00:00Z").expect("valid").unix_seconds;
        let after = parse_rfc3339("2024-03-01T00:00:00Z").expect("valid").unix_seconds;
        assert_eq!(after - before, 2 * 86_400);
    }

    #[test]
    fn a_fractional_second_is_accepted_and_truncated() {
        let parsed = parse_rfc3339("2026-01-02T03:04:05.250Z").expect("valid");
        assert_eq!(parsed.amz_stamp, "20260102T030405Z");
    }

    #[test]
    fn a_malformed_instant_is_refused_rather_than_defaulted() {
        assert!(parse_rfc3339("2026-01-02 03:04:05Z").is_err());
        assert!(parse_rfc3339("not-a-date").is_err());
        assert!(parse_rfc3339("2026-13-02T03:04:05Z").is_err());
    }
}
