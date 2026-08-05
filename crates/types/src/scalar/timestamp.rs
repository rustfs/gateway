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

//! An instant, plus the four wire formats S3 spells instants in.
//!
//! Responsible for: a UTC instant with nanosecond resolution, and total parse/render functions for
//! the four [`TimestampFormat`] variants the frozen IR names. Every conversion is checked
//! arithmetic: a year far outside the representable range is a parse error, never a wrapped value.
//! NOT responsible for: telling a caller *which* format a given field uses — that binding lives in
//! the IR, per field, and is why this type has no `Display` — and for clocks. Nothing here reads
//! the current time.
//! Upstream: [`super::parse_error`]. Downstream: every dated field of every operation, the SigV4
//! date handling in P2, and presigned-URL expiry.
//!
//! # Why this is hand-written
//!
//! The obvious move is to depend on the AWS `DateTime`. Measured against this workspace it costs
//! more than it saves: that crate's minimum supported Rust version is well above this project's
//! floor, it has no feature gate that yields only the date type, and it drags in a base64, a time
//! and a bytes-utility crate for a value that is two integers. The format *taxonomy* is worth
//! borrowing; the code is not. The variant set below is the one the IR froze.
//!
//! # `Expires` is not here
//!
//! The `Expires` response header is [`super::OpaqueString`], not a `Timestamp`. Objects in the
//! wild carry values that are not dates at all, and rewriting them — even into a valid date —
//! changes what the caller stored. See that module for the rest of the argument.

use std::fmt::Write as _;

use super::parse_error::{ParseError, rules};

/// The wire spelling of an instant. There is no default: the IR binds one of these per field.
///
/// The variant names follow the frozen IR rather than any SDK's naming. `Iso8601` covers what AWS
/// SDKs call `date-time`, including the offset form (`+08:00`), because an offset changes how a
/// value is read, not what it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimestampFormat {
    /// RFC 9110 HTTP-date. Rendered as IMF-fixdate (`Tue, 15 Nov 1994 08:12:31 GMT`); the two
    /// obsolete formats are accepted on input, because a client that sends one is still a client.
    ///
    /// Used by `Last-Modified`, `Date`, `If-Modified-Since` and the dates nested inside
    /// `x-amz-expiration` and `x-amz-restore`.
    HttpDate,
    /// ISO 8601 date-time, rendered with milliseconds and a `Z` suffix
    /// (`2015-10-21T07:28:00.000Z`).
    ///
    /// Used by every XML body element (`LastModified`, `CreationDate`, `Initiated`), by POST
    /// policy expirations, and by `x-amz-object-lock-retain-until-date` — the one header that
    /// carries ISO 8601 rather than an HTTP-date.
    Iso8601,
    /// ISO 8601 basic format, no separators (`20130524T000000Z`).
    ///
    /// This is SigV4's `X-Amz-Date`. It is not in the AWS SDK format taxonomy; it is here because
    /// the signature layer needs it and it is the same instant in a different spelling.
    Iso8601Basic,
    /// Seconds since the Unix epoch, negative for instants before 1970, with an optional
    /// fractional part.
    EpochSeconds,
}

/// A UTC instant: whole seconds since the Unix epoch, plus a nanosecond remainder.
///
/// Deliberately has no `Display`. Rendering requires a [`TimestampFormat`], so a field bound to an
/// HTTP-date cannot be written as ISO 8601 by reflex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    secs: i64,
    subsec_nanos: u32,
}

/// Smallest year this type renders, matching the four-digit wire formats.
const MIN_YEAR: i64 = 0;
/// Largest year this type renders.
const MAX_YEAR: i64 = 9999;

const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const LONG_DAY_NAMES: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

impl Timestamp {
    /// 1970-01-01T00:00:00Z.
    pub const UNIX_EPOCH: Self = Self {
        secs: 0,
        subsec_nanos: 0,
    };

    /// Builds an instant from whole seconds since the Unix epoch.
    #[must_use]
    pub const fn from_secs(secs: i64) -> Self {
        Self { secs, subsec_nanos: 0 }
    }

    /// Builds an instant from seconds plus a nanosecond remainder.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] when `subsec_nanos` is not below one second.
    pub fn from_secs_nanos(secs: i64, subsec_nanos: u32) -> Result<Self, ParseError> {
        if subsec_nanos >= 1_000_000_000 {
            return Err(ParseError::new(
                "Timestamp",
                rules::ISO8601,
                "the nanosecond remainder must be below one second",
            ));
        }
        Ok(Self { secs, subsec_nanos })
    }

    /// Whole seconds since the Unix epoch; negative before 1970.
    #[must_use]
    pub const fn secs(&self) -> i64 {
        self.secs
    }

    /// The nanosecond remainder, always in `0..1_000_000_000`.
    #[must_use]
    pub const fn subsec_nanos(&self) -> u32 {
        self.subsec_nanos
    }

    /// The remainder in whole milliseconds, which is the resolution S3's XML bodies carry.
    #[must_use]
    pub const fn subsec_millis(&self) -> u32 {
        self.subsec_nanos / 1_000_000
    }

    /// Parses a wire value in exactly the given format.
    ///
    /// Passing the wrong format is a parse failure, not a silent reinterpretation: that is the
    /// point of making the format an argument. A `Last-Modified` value handed to
    /// [`TimestampFormat::Iso8601`] fails, which is how a wrong per-field binding gets caught by a
    /// test instead of by a client.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] describing which component was rejected.
    pub fn parse(value: &str, format: TimestampFormat) -> Result<Self, ParseError> {
        match format {
            TimestampFormat::HttpDate => parse_http_date(value),
            TimestampFormat::Iso8601 => parse_iso8601(value),
            TimestampFormat::Iso8601Basic => parse_iso8601_basic(value),
            TimestampFormat::EpochSeconds => parse_epoch_seconds(value),
        }
    }

    /// Renders the instant in exactly the given format.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] when the instant falls outside the four-digit year range the wire
    /// formats can express. [`TimestampFormat::EpochSeconds`] never fails.
    pub fn render(&self, format: TimestampFormat) -> Result<String, ParseError> {
        if format == TimestampFormat::EpochSeconds {
            return Ok(render_epoch_seconds(self));
        }
        let civil = CivilTime::from_timestamp(self)?;
        let mut out = String::with_capacity(32);
        let write_failed = |_| ParseError::new("Timestamp", rules::ISO8601, "the instant could not be formatted");
        match format {
            TimestampFormat::HttpDate => write!(
                out,
                "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
                DAY_NAMES[civil.weekday],
                civil.day,
                MONTH_NAMES[civil.month as usize - 1],
                civil.year,
                civil.hour,
                civil.minute,
                civil.second
            )
            .map_err(write_failed)?,
            TimestampFormat::Iso8601 => write!(
                out,
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                civil.year,
                civil.month,
                civil.day,
                civil.hour,
                civil.minute,
                civil.second,
                self.subsec_millis()
            )
            .map_err(write_failed)?,
            TimestampFormat::Iso8601Basic => write!(
                out,
                "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
                civil.year, civil.month, civil.day, civil.hour, civil.minute, civil.second
            )
            .map_err(write_failed)?,
            TimestampFormat::EpochSeconds => unreachable!("handled above"),
        }
        Ok(out)
    }
}

/// A broken-down UTC calendar time.
struct CivilTime {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    weekday: usize,
}

impl CivilTime {
    fn from_timestamp(ts: &Timestamp) -> Result<Self, ParseError> {
        let days = ts.secs.div_euclid(86_400);
        let secs_of_day = ts.secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
            return Err(ParseError::new(
                "Timestamp",
                rules::ISO8601,
                "the instant is outside the four-digit year range the wire formats can express",
            ));
        }
        // 1970-01-01 was a Thursday, index 3 in a Monday-first table.
        let weekday = usize::try_from((days + 3).rem_euclid(7)).unwrap_or(0);
        Ok(Self {
            year,
            month,
            day,
            hour: (secs_of_day / 3600) as u32,
            minute: ((secs_of_day % 3600) / 60) as u32,
            second: (secs_of_day % 60) as u32,
            weekday,
        })
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let d = i64::from(day);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    // `mp` is in 0..=11 and `d` in 1..=31 by construction, so both casts are exact.
    (year, m as u32, d as u32)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn err(reason: &'static str) -> ParseError {
    ParseError::new("Timestamp", rules::ISO8601, reason)
}

fn http_err(reason: &'static str) -> ParseError {
    ParseError::new("Timestamp", rules::RFC9110_HTTP_DATE, reason)
}

/// Assembles a timestamp from calendar components, validating every one of them.
fn from_civil(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32, nanos: u32) -> Result<Timestamp, ParseError> {
    if !(MIN_YEAR..=MAX_YEAR).contains(&year) {
        return Err(err("the year is outside 0000..=9999"));
    }
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return Err(err("the calendar date does not exist"));
    }
    // A leap second (`:60`) is rejected rather than clamped: silently moving an instant is worse
    // than telling the caller the value was not representable.
    if hour > 23 || minute > 59 || second > 59 {
        return Err(err("the time of day is out of range"));
    }
    let days = days_from_civil(year, month, day);
    let secs = days
        .checked_mul(86_400)
        .and_then(|d| d.checked_add(i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second)))
        .ok_or_else(|| err("the instant overflows the representable range"))?;
    Timestamp::from_secs_nanos(secs, nanos)
}

fn digits(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// Parses `.<fraction>` into nanoseconds, accepting any number of digits.
fn parse_fraction(fraction: &str) -> Option<u32> {
    if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut nanos = 0u32;
    for index in 0..9 {
        let digit = fraction.as_bytes().get(index).map_or(0, |b| u32::from(b - b'0'));
        nanos = nanos * 10 + digit;
    }
    Some(nanos)
}

fn parse_iso8601(value: &str) -> Result<Timestamp, ParseError> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') || bytes.get(10) != Some(&b'T') {
        return Err(err("expected YYYY-MM-DDThh:mm:ss with an offset or Z"));
    }
    let year = digits(&value[0..4]).ok_or_else(|| err("the year is not four digits"))?;
    let month = digits(&value[5..7]).ok_or_else(|| err("the month is not two digits"))?;
    let day = digits(&value[8..10]).ok_or_else(|| err("the day is not two digits"))?;
    if bytes.get(13) != Some(&b':') || bytes.get(16) != Some(&b':') {
        return Err(err("the time of day is not hh:mm:ss"));
    }
    let hour = digits(&value[11..13]).ok_or_else(|| err("the hour is not two digits"))?;
    let minute = digits(&value[14..16]).ok_or_else(|| err("the minute is not two digits"))?;
    let second = digits(&value[17..19]).ok_or_else(|| err("the second is not two digits"))?;

    let rest = &value[19..];
    let (fraction, zone) = match rest.strip_prefix('.') {
        Some(after_dot) => {
            let split = after_dot
                .find(|c: char| !c.is_ascii_digit())
                .ok_or_else(|| err("the fractional second has no zone suffix"))?;
            (&after_dot[..split], &after_dot[split..])
        }
        None => ("", rest),
    };
    let nanos = if fraction.is_empty() {
        0
    } else {
        parse_fraction(fraction).ok_or_else(|| err("the fractional second is not numeric"))?
    };

    let offset_secs = parse_zone(zone)?;
    let base = from_civil(i64::from(year), month, day, hour, minute, second, nanos)?;
    let secs = base
        .secs()
        .checked_sub(offset_secs)
        .ok_or_else(|| err("applying the UTC offset overflows the representable range"))?;
    Timestamp::from_secs_nanos(secs, nanos)
}

/// Parses `Z`, `+hh:mm`, `-hh:mm`, `+hhmm` or `-hhmm` into an offset in seconds east of UTC.
fn parse_zone(zone: &str) -> Result<i64, ParseError> {
    if zone == "Z" || zone == "z" {
        return Ok(0);
    }
    let (sign, rest) = match zone.split_at_checked(1) {
        Some(("+", rest)) => (1i64, rest),
        Some(("-", rest)) => (-1i64, rest),
        _ => return Err(err("the UTC offset must be Z, +hh:mm or -hh:mm")),
    };
    let (hours, minutes) = match rest.len() {
        4 => (&rest[0..2], &rest[2..4]),
        5 if rest.as_bytes().get(2) == Some(&b':') => (&rest[0..2], &rest[3..5]),
        _ => return Err(err("the UTC offset must be Z, +hh:mm or -hh:mm")),
    };
    let hours = digits(hours).ok_or_else(|| err("the offset hour is not two digits"))?;
    let minutes = digits(minutes).ok_or_else(|| err("the offset minute is not two digits"))?;
    if hours > 23 || minutes > 59 {
        return Err(err("the UTC offset is out of range"));
    }
    Ok(sign * (i64::from(hours) * 3600 + i64::from(minutes) * 60))
}

fn parse_iso8601_basic(value: &str) -> Result<Timestamp, ParseError> {
    let bytes = value.as_bytes();
    if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
        return Err(err("expected the basic form YYYYMMDDThhmmssZ"));
    }
    let year = digits(&value[0..4]).ok_or_else(|| err("the year is not four digits"))?;
    let month = digits(&value[4..6]).ok_or_else(|| err("the month is not two digits"))?;
    let day = digits(&value[6..8]).ok_or_else(|| err("the day is not two digits"))?;
    let hour = digits(&value[9..11]).ok_or_else(|| err("the hour is not two digits"))?;
    let minute = digits(&value[11..13]).ok_or_else(|| err("the minute is not two digits"))?;
    let second = digits(&value[13..15]).ok_or_else(|| err("the second is not two digits"))?;
    from_civil(i64::from(year), month, day, hour, minute, second, 0)
}

fn parse_epoch_seconds(value: &str) -> Result<Timestamp, ParseError> {
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    let negative = whole.starts_with('-');
    let magnitude = whole.strip_prefix(['-', '+']).unwrap_or(whole);
    if magnitude.is_empty() || !magnitude.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err("epoch seconds must be an optionally signed integer"));
    }
    let secs: i64 = whole.parse().map_err(|_| err("epoch seconds overflow a 64-bit integer"))?;
    let Some(fraction) = fraction else {
        return Ok(Timestamp::from_secs(secs));
    };
    let nanos = parse_fraction(fraction).ok_or_else(|| err("the fractional second is not numeric"))?;
    if nanos == 0 {
        return Ok(Timestamp::from_secs(secs));
    }
    // A negative epoch value counts backwards, so its fraction moves the instant further back:
    // -1.5 is half a second before -1, i.e. secs -2 with a remainder of 500 ms.
    if negative {
        let secs = secs
            .checked_sub(1)
            .ok_or_else(|| err("epoch seconds overflow a 64-bit integer"))?;
        Timestamp::from_secs_nanos(secs, 1_000_000_000 - nanos)
    } else {
        Timestamp::from_secs_nanos(secs, nanos)
    }
}

fn render_epoch_seconds(ts: &Timestamp) -> String {
    if ts.subsec_nanos == 0 {
        return ts.secs.to_string();
    }
    // Render the same way it parses: the fraction is always a forward offset from the whole
    // second, so a negative instant carries its borrow back into the integer part.
    let (secs, nanos) = if ts.secs < 0 {
        (ts.secs + 1, 1_000_000_000 - ts.subsec_nanos)
    } else {
        (ts.secs, ts.subsec_nanos)
    };
    let fraction = format!("{nanos:09}");
    let fraction = fraction.trim_end_matches('0');
    let sign = if secs == 0 && ts.secs < 0 { "-" } else { "" };
    format!("{sign}{secs}.{fraction}")
}

fn parse_http_date(value: &str) -> Result<Timestamp, ParseError> {
    let value = value.trim();
    if let Some((day_name, rest)) = value.split_once(", ") {
        if DAY_NAMES.contains(&day_name) {
            return parse_imf_fixdate(rest);
        }
        if LONG_DAY_NAMES.contains(&day_name) {
            return parse_rfc850(rest);
        }
        return Err(http_err("the day name is not a valid abbreviation"));
    }
    parse_asctime(value)
}

/// `15 Nov 1994 08:12:31 GMT`
fn parse_imf_fixdate(rest: &str) -> Result<Timestamp, ParseError> {
    if rest.len() != 24 || &rest[20..] != " GMT" {
        return Err(http_err("expected an IMF-fixdate ending in GMT"));
    }
    let day = digits(&rest[0..2]).ok_or_else(|| http_err("the day is not two digits"))?;
    let month = month_index(&rest[3..6]).ok_or_else(|| http_err("the month name is not valid"))?;
    let year = digits(&rest[7..11]).ok_or_else(|| http_err("the year is not four digits"))?;
    let (hour, minute, second) = parse_clock(&rest[12..20])?;
    from_civil(i64::from(year), month, day, hour, minute, second, 0)
}

/// `06-Nov-94 08:49:37 GMT`
fn parse_rfc850(rest: &str) -> Result<Timestamp, ParseError> {
    if rest.len() != 22 || &rest[18..] != " GMT" {
        return Err(http_err("expected an RFC 850 date ending in GMT"));
    }
    let day = digits(&rest[0..2]).ok_or_else(|| http_err("the day is not two digits"))?;
    let month = month_index(&rest[3..6]).ok_or_else(|| http_err("the month name is not valid"))?;
    let short_year = digits(&rest[7..9]).ok_or_else(|| http_err("the year is not two digits"))?;
    // Two-digit years are windowed the way RFC 9110 requires: a value more than fifty years ahead
    // is read as the previous century.
    let year = if short_year >= 70 {
        1900 + short_year
    } else {
        2000 + short_year
    };
    let (hour, minute, second) = parse_clock(&rest[10..18])?;
    from_civil(i64::from(year), month, day, hour, minute, second, 0)
}

/// `Sun Nov  6 08:49:37 1994`
fn parse_asctime(value: &str) -> Result<Timestamp, ParseError> {
    if value.len() != 24 {
        return Err(http_err("expected an asctime date of exactly 24 characters"));
    }
    if !DAY_NAMES.contains(&&value[0..3]) {
        return Err(http_err("the day name is not a valid abbreviation"));
    }
    let month = month_index(&value[4..7]).ok_or_else(|| http_err("the month name is not valid"))?;
    let day_field = value[8..10].trim_start();
    let day = digits(day_field).ok_or_else(|| http_err("the day is not numeric"))?;
    let (hour, minute, second) = parse_clock(&value[11..19])?;
    let year = digits(&value[20..24]).ok_or_else(|| http_err("the year is not four digits"))?;
    from_civil(i64::from(year), month, day, hour, minute, second, 0)
}

/// Parses ` hh:mm:ss` or `hh:mm:ss`.
fn parse_clock(field: &str) -> Result<(u32, u32, u32), ParseError> {
    let field = field.trim_start();
    if field.len() != 8 || field.as_bytes()[2] != b':' || field.as_bytes()[5] != b':' {
        return Err(http_err("the time of day is not hh:mm:ss"));
    }
    let hour = digits(&field[0..2]).ok_or_else(|| http_err("the hour is not two digits"))?;
    let minute = digits(&field[3..5]).ok_or_else(|| http_err("the minute is not two digits"))?;
    let second = digits(&field[6..8]).ok_or_else(|| http_err("the second is not two digits"))?;
    Ok((hour, minute, second))
}

fn month_index(name: &str) -> Option<u32> {
    MONTH_NAMES
        .iter()
        .position(|candidate| *candidate == name)
        .and_then(|index| u32::try_from(index + 1).ok())
}
