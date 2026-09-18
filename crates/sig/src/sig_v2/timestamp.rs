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

//! SigV2's request timestamp, normalised into the one [`AmzDate`] the skew rule already takes.
//!
//! Responsible for: reading the timestamp a SigV2 request carries — `x-amz-date` when it is
//! present, `Date` otherwise — in either of the two spellings AWS's own clients send, and turning
//! it into an [`AmzDate`].
//! Also SigV4's header timestamp ([`sigv4_header_timestamp`]), which shares the `Date` grammar.
//! NOT responsible for: comparing it against anything. The window, the receipt and the overflow
//! rules are [`crate::enforce_clock_skew`]'s, unchanged and uncopied: this module exists so that
//! SigV2 reaches that one function rather than growing a second skew rule beside it.
//! Upstream: [`crate::parse::AmzDate`]. Downstream: [`crate::SecurityFloor::admit`].
//!
//! # Why a second spelling exists at all
//!
//! SigV4 fixed the timestamp format; SigV2 predates that and rides on HTTP's own `Date` header,
//! which is an RFC 1123 date. botocore's `HmacV1Auth` writes `formatdate(usegmt=True)` and
//! aws-sdk-js v2 writes `Date.prototype.toUTCString()` — both produce `GMT`, while AWS's own
//! SigV2 documentation example carries `+0000`, and botocore's `_gen_date` for a caller-supplied
//! `Date` writes `-0000` (RFC 5322's spelling of "UTC, offset unknown"). All three are accepted
//! here and nothing else is: a non-zero offset would need offset arithmetic, and an instant with
//! two spellings is an instant two implementations disagree about.
//!
//! SigV4 reads the same grammar: a header-signed request that carries no `x-amz-date` is dated by
//! its `Date` header (rustfs/gateway#809), which [`crate::SecurityFloor`] hands to
//! [`parse_sigv2_date`] so the two schemes share one reading of an HTTP date.
//!
//! The weekday is required to be three ASCII letters and is otherwise not interpreted. Checking
//! that it agrees with the date would reject a request over a field that carries no information
//! the date does not already carry, and AWS does not check it either.

use http::HeaderMap;

use crate::parse::AmzDate;
use crate::verdict::AuthError;

/// The `x-amz-date` header, whose presence also empties the `{Date}` slot of the string-to-sign.
const X_AMZ_DATE_HEADER: &str = "x-amz-date";
/// The HTTP `Date` header, in its lowercase spelling.
const DATE_HEADER: &str = "date";

/// The length of `Www, DD Mmm YYYY HH:MM:SS GMT`.
const RFC1123_GMT_LEN: usize = 29;
/// The length of `Www, DD Mmm YYYY HH:MM:SS +0000`.
const RFC1123_NUMERIC_LEN: usize = 31;

/// Reads the timestamp a SigV2 header-authenticated request was signed at.
///
/// `x-amz-date` wins when it is present, which is the same precedence the string-to-sign uses for
/// its `{Date}` slot: a client that sends both signs against `x-amz-date`, so the skew check must
/// judge the same field the signature covers. A request carrying neither is refused — SigV2 with
/// no timestamp is a signature with no expiry.
///
/// # Errors
///
/// [`AuthError::AuthorizationHeaderMalformed`] when neither header is present, when the chosen one
/// is not UTF-8, or when it is in neither accepted spelling.
pub fn signed_timestamp(headers: &HeaderMap) -> Result<AmzDate, AuthError> {
    let raw = headers
        .get(X_AMZ_DATE_HEADER)
        .or_else(|| headers.get(DATE_HEADER))
        .ok_or(AuthError::AuthorizationHeaderMalformed)?
        .to_str()
        .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    parse_sigv2_date(raw)
}

/// Reads the timestamp a SigV4 header-signed request was signed at: `x-amz-date` in ISO 8601 basic
/// form when it is present, else the HTTP `Date` header in either spelling (rustfs/gateway#809).
///
/// `x-amz-date` wins when both are present, which is the header the string-to-sign is dated with;
/// whether a `Date` that supplies the timestamp is signed is `SignedHeaderSet::parse_and_enforce`'s
/// to refuse. A request carrying neither is refused.
///
/// # Errors
///
/// [`AuthError::AuthorizationHeaderMalformed`] when neither header is present, when the chosen one
/// is not UTF-8, or when it is not in the spelling its header admits.
pub fn sigv4_header_timestamp(headers: &HeaderMap) -> Result<AmzDate, AuthError> {
    let (value, http_date) = match headers.get(X_AMZ_DATE_HEADER) {
        Some(value) => (value, false),
        None => (headers.get(DATE_HEADER).ok_or(AuthError::AuthorizationHeaderMalformed)?, true),
    };
    let raw = value.to_str().map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    if http_date {
        parse_sigv2_date(raw)
    } else {
        AmzDate::parse(raw)
    }
}

/// Parses either accepted SigV2 timestamp spelling into an [`AmzDate`].
///
/// The ISO 8601 basic form (`20260102T030405Z`) is tried first and is [`AmzDate::parse`] verbatim.
/// The RFC 1123 form is rewritten into that same spelling and handed to the same parser, so every
/// range rule — month, day, hour, minute, second — has exactly one implementation.
///
/// # Errors
///
/// [`AuthError::AuthorizationHeaderMalformed`] for every deviation. Which of the two forms was
/// closer to correct is not reported: it is a hint about the parser, not about the request.
pub fn parse_sigv2_date(raw: &str) -> Result<AmzDate, AuthError> {
    if let Ok(stamp) = AmzDate::parse(raw) {
        return Ok(stamp);
    }
    let bytes = raw.as_bytes();
    let zone = match bytes.len() {
        RFC1123_GMT_LEN | RFC1123_NUMERIC_LEN => raw.get(26..).ok_or(AuthError::AuthorizationHeaderMalformed)?,
        _ => return Err(AuthError::AuthorizationHeaderMalformed),
    };
    match zone.as_bytes() {
        b"GMT" | b"+0000" | b"-0000" => {}
        _ => return Err(AuthError::AuthorizationHeaderMalformed),
    }
    // Every fixed separator at once, so no arm of this grammar can be relaxed on its own.
    match (
        bytes.get(3),
        bytes.get(4),
        bytes.get(7),
        bytes.get(11),
        bytes.get(16),
        bytes.get(19),
        bytes.get(22),
        bytes.get(25),
    ) {
        (Some(b','), Some(b' '), Some(b' '), Some(b' '), Some(b' '), Some(b':'), Some(b':'), Some(b' ')) => {}
        _ => return Err(AuthError::AuthorizationHeaderMalformed),
    }
    let weekday = raw.get(..3).ok_or(AuthError::AuthorizationHeaderMalformed)?;
    if !weekday.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(AuthError::AuthorizationHeaderMalformed);
    }
    let day = raw.get(5..7).ok_or(AuthError::AuthorizationHeaderMalformed)?;
    let month = month_number(raw.get(8..11).ok_or(AuthError::AuthorizationHeaderMalformed)?)?;
    let year = raw.get(12..16).ok_or(AuthError::AuthorizationHeaderMalformed)?;
    let hour = raw.get(17..19).ok_or(AuthError::AuthorizationHeaderMalformed)?;
    let minute = raw.get(20..22).ok_or(AuthError::AuthorizationHeaderMalformed)?;
    let second = raw.get(23..25).ok_or(AuthError::AuthorizationHeaderMalformed)?;
    // Handed straight back to `AmzDate::parse`: it is the one place that decides whether a digit
    // run is a date, and rewriting the spelling must not become a second opinion about the ranges.
    AmzDate::parse(&format!("{year}{month:02}{day}T{hour}{minute}{second}Z"))
}

/// The three-letter English month names RFC 1123 uses, and nothing else.
///
/// A `match` rather than a comparison: `crates/sig/src/sig_v2/` may not contain `==` at all, and
/// the rule is worth keeping even where the operands are month names.
fn month_number(name: &str) -> Result<u8, AuthError> {
    let number = match name.as_bytes() {
        b"Jan" => 1,
        b"Feb" => 2,
        b"Mar" => 3,
        b"Apr" => 4,
        b"May" => 5,
        b"Jun" => 6,
        b"Jul" => 7,
        b"Aug" => 8,
        b"Sep" => 9,
        b"Oct" => 10,
        b"Nov" => 11,
        b"Dec" => 12,
        _ => return Err(AuthError::AuthorizationHeaderMalformed),
    };
    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Negative: a timestamp with a real UTC offset is refused rather than shifted, so one instant
    /// keeps one spelling.
    #[test]
    fn a_non_zero_offset_is_refused() {
        assert_eq!(
            parse_sigv2_date("Tue, 27 Mar 2007 19:36:42 +0100").err(),
            Some(AuthError::AuthorizationHeaderMalformed)
        );
    }

    /// Positive: the three spellings of UTC — `GMT`, `+0000` and botocore's `-0000` — are one
    /// instant, and it is the instant the ISO 8601 basic form names.
    #[test]
    fn the_three_utc_spellings_are_one_instant() {
        let basic = AmzDate::parse("20260914T031656Z").expect("a timestamp");
        for spelled in [
            "Mon, 14 Sep 2026 03:16:56 GMT",
            "Mon, 14 Sep 2026 03:16:56 +0000",
            "Mon, 14 Sep 2026 03:16:56 -0000",
        ] {
            assert_eq!(parse_sigv2_date(spelled).as_ref(), Ok(&basic), "{spelled}");
        }
    }

    /// Negative: `-0000` is accepted only as a whole; a minute of offset in either sign, a
    /// lowercase zone, and a zone of the right length but the wrong letters are refused.
    #[test]
    fn n_a_near_utc_zone_is_refused() {
        for spelled in [
            "Mon, 14 Sep 2026 03:16:56 -0001",
            "Mon, 14 Sep 2026 03:16:56 -0100",
            "Mon, 14 Sep 2026 03:16:56 gmt",
            "Mon, 14 Sep 2026 03:16:56 UTC",
            "Mon, 14 Sep 2026 03:16:56 +00:00",
        ] {
            assert_eq!(
                parse_sigv2_date(spelled).err(),
                Some(AuthError::AuthorizationHeaderMalformed),
                "{spelled}"
            );
        }
    }

    /// Negative: a request carrying no timestamp at all is refused, not treated as "now".
    #[test]
    fn a_request_without_a_timestamp_is_refused() {
        assert_eq!(signed_timestamp(&HeaderMap::new()).err(), Some(AuthError::AuthorizationHeaderMalformed));
    }
}
