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

//! How an XML request document is read: as a tree, or as legacy RustFS reads one.
//!
//! Responsible for: [`DocumentReading`], [`request_document`] — the one call every generated
//! decoder of an XML request body opens its document with — and the RustFS profile's scalar
//! reading, the grammar legacy RustFS reads each kind of member value with.
//! NOT responsible for: walking the document (`rustfs_gateway_xml::bound`), what a member means
//! (the generated decoders), or which deployment reads which way (the assembly).
//! Upstream: `rustfs-gateway-xml`, `rustfs-gateway-types`' scalars. Downstream: every generated
//! codec with an XML request document.
//!
//! # Why the RustFS profile reads a document differently at all
//!
//! Legacy RustFS refuses, with `MalformedXML`, request documents the tree reading accepts: an
//! element a nested structure does not declare, a second occurrence of a member that may appear
//! once, a boolean spelled `True`, an integer with leading white space. The tree reading skipped
//! the first and kept the first of the second, so a configuration legacy RustFS refuses was
//! written, and a client's second value was dropped without a word (rustfs/gateway#1078). It also
//! answered an unreadable value `InvalidArgument` where legacy RustFS answers `MalformedXML`, and
//! it read some values legacy RustFS reads differently (a CDATA section, a carriage return). A
//! RustFS deployment reads every request document through [`rustfs_gateway_xml::bound`] instead,
//! against the document's generated shape, so it refuses what legacy RustFS refuses, with its
//! code, and hands its handlers exactly the values legacy RustFS would.

use rustfs_gateway_types::{ETag, ErrorCode, Timestamp, TimestampFormat};
use rustfs_gateway_xml::bound::{self, BoundRefusal, Document, Scalar, ScalarRefusal};
use rustfs_gateway_xml::{XmlLimits, XmlNode};

use crate::codec::error::CodecError;
use crate::codec::strict_date::strict_http_date;
use crate::codec::view::MetaView;

/// How a deployment reads an XML request document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DocumentReading {
    /// As a tree: any well-formed document is read, and each decoder takes the members it knows —
    /// the first of a repeated one — and skips the rest. Every deployment's default.
    #[default]
    Tree,
    /// As legacy RustFS reads one: against the operation's shape, member by member, refusing what
    /// legacy RustFS refuses with its `MalformedXML`, and reading each value with its grammar. The
    /// RustFS profile (rustfs/gateway#1078).
    RustFs,
}

/// The message every refused document carries: no part of the request is repeated back.
const NOT_THE_DOCUMENT: &str = "the request body is not the XML this operation accepts";

/// Opens an operation's XML request document the way the request's deployment reads one.
///
/// `document` is the operation's generated shape, read only by [`DocumentReading::RustFs`].
///
/// # Errors
///
/// `MalformedXML` for a document the reading refuses; under [`DocumentReading::RustFs`],
/// `MissingRequestBodyError` for an empty body the document calls missing, as legacy RustFS
/// answers one; `InvalidArgument` for an empty body the document calls absent, the answer of
/// legacy RustFS's handler for the one document that is (the object-lock configuration,
/// `rustfs/src/storage/ecfs.rs:1678` at rustfs/rustfs@e870a6d25); and `InvalidArgument` for a
/// value legacy RustFS reads but this gateway cannot
/// carry exactly — a date with a UTC offset, an entity tag no gateway tag can spell, the empty
/// wrapper of an optional list — refused rather than written differently.
pub fn request_document(request: &MetaView<'_>, body: &[u8], document: &'static Document) -> Result<XmlNode, CodecError> {
    match request.document_reading() {
        DocumentReading::Tree => rustfs_gateway_xml::parse(body).map_err(|_| CodecError::malformed_xml(NOT_THE_DOCUMENT)),
        DocumentReading::RustFs => bound::read(body, document, XmlLimits::S3, &rustfs_scalar).map_err(|refusal| match refusal {
            BoundRefusal::Uncarriable => {
                CodecError::invalid_argument("the request body carries a value this gateway cannot carry exactly")
            }
            BoundRefusal::Missing => CodecError::new(ErrorCode::MISSING_REQUEST_BODY, "the request carries no body"),
            BoundRefusal::Absent => CodecError::invalid_argument("the request carries no document"),
            BoundRefusal::Document(_) | BoundRefusal::Xml(_) => CodecError::malformed_xml(NOT_THE_DOCUMENT),
        }),
    }
}

/// One member value, read with the grammar legacy RustFS reads that kind with, and spelled the
/// way the generated decoder reads back the same value.
///
/// # Errors
///
/// [`ScalarRefusal::Unreadable`] where legacy RustFS refuses the value, and
/// [`ScalarRefusal::Uncarriable`] where it reads one this gateway cannot carry exactly.
pub fn rustfs_scalar(kind: Scalar, raw: &str) -> Result<String, ScalarRefusal> {
    match kind {
        Scalar::Text => Ok(raw.to_owned()),
        Scalar::Integer => leading_integer(raw, i128::from(i32::MIN), i128::from(i32::MAX)),
        Scalar::Long => leading_integer(raw, i128::from(i64::MIN), i128::from(i64::MAX)),
        Scalar::Boolean => match raw {
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads exactly these four
            // spellings and refuses `True` or `tRUE`, which every other reader of an XML boolean
            // accepts or refuses together; the intended reading is the XML Schema boolean.
            "true" | "TRUE" => Ok("true".to_owned()),
            "false" | "FALSE" => Ok("false".to_owned()),
            _ => Err(ScalarRefusal::Unreadable),
        },
        Scalar::DateTime => date_time(raw),
        Scalar::HttpDate => http_date(raw),
        Scalar::EntityTag => entity_tag(raw),
    }
}

/// An integer as legacy RustFS reads one: an optional sign, then the longest run of digits.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS reads `<Days>30.5</Days>` as 30 and
/// `<Days>+</Days>` as 0, and refuses `<Days> 30</Days>` — it takes a leading run of digits and
/// ignores the rest of the text, and a lone sign is zero. A client's typo becomes a different
/// rule rather than a refusal. The intended reading is a whole-text integer, refused otherwise.
fn leading_integer(raw: &str, min: i128, max: i128) -> Result<String, ScalarRefusal> {
    let (negative, digits) = match raw.as_bytes() {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        bytes => (false, bytes),
    };
    let signed = digits.len() != raw.len();
    let run = digits.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if !signed && run == 0 {
        return Err(ScalarRefusal::Unreadable);
    }
    let mut value: i128 = 0;
    for digit in digits.iter().take(run) {
        let digit = i128::from(digit - b'0');
        value = value
            .checked_mul(10)
            .and_then(|value| {
                if negative {
                    value.checked_sub(digit)
                } else {
                    value.checked_add(digit)
                }
            })
            .ok_or(ScalarRefusal::Unreadable)?;
        if value < min || value > max {
            return Err(ScalarRefusal::Unreadable);
        }
    }
    Ok(value.to_string())
}

fn digits(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes
        .iter()
        .try_fold(0u32, |value, digit| value.checked_mul(10)?.checked_add(u32::from(digit - b'0')))
}

fn leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// An RFC 3339 date-time as legacy RustFS reads one, spelled for the gateway's parser.
///
/// Legacy RustFS takes any one byte between the date and the time, not only `T`; a fractional
/// second of any length; `Z` in either case; an offset only as `±hh:mm`; and a leap second on the
/// last second of a month. Every one of those is read here exactly so. A date with a non-zero UTC
/// offset is read too — and refused as uncarriable, because the gateway's timestamp is a UTC
/// instant: legacy RustFS keeps the offset (a stored retention date is written with it), so no
/// instant this gateway could hand over is byte-identical to what legacy RustFS stores.
fn date_time(raw: &str) -> Result<String, ScalarRefusal> {
    let unreadable = ScalarRefusal::Unreadable;
    // Any one byte separates the date from the time.
    let [
        y1,
        y2,
        y3,
        y4,
        b'-',
        o1,
        o2,
        b'-',
        d1,
        d2,
        _,
        h1,
        h2,
        b':',
        n1,
        n2,
        b':',
        s1,
        s2,
        after @ ..,
    ] = raw.as_bytes()
    else {
        return Err(unreadable);
    };
    let year = digits(&[*y1, *y2, *y3, *y4]).ok_or(unreadable)?;
    let month = digits(&[*o1, *o2]).ok_or(unreadable)?;
    let day = digits(&[*d1, *d2]).ok_or(unreadable)?;
    let hour = digits(&[*h1, *h2]).ok_or(unreadable)?;
    let minute = digits(&[*n1, *n2]).ok_or(unreadable)?;
    let mut second = digits(&[*s1, *s2]).ok_or(unreadable)?;
    let mut rest = after;
    let mut nanos = 0u32;
    if let Some(fraction) = rest.strip_prefix(b".") {
        let run = fraction.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if run == 0 {
            return Err(unreadable);
        }
        for (place, digit) in (0..9u32).rev().zip(fraction.iter().take(run)) {
            nanos += u32::from(digit - b'0') * 10u32.pow(place);
        }
        rest = fraction.get(run..).ok_or(unreadable)?;
    }
    let offset_minutes: i64 = match rest {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let hours = digits(&[*h1, *h2]).ok_or(unreadable)?;
            let minutes = digits(&[*m1, *m2]).ok_or(unreadable)?;
            if hours > 23 || minutes > 59 {
                return Err(unreadable);
            }
            let total = i64::from(hours * 60 + minutes);
            if *sign == b'-' { -total } else { total }
        }
        _ => return Err(unreadable),
    };
    let leap_second = second == 60;
    if leap_second {
        second = 59;
        nanos = 999_999_999;
    }
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 59 {
        return Err(unreadable);
    }
    if leap_second {
        // The stand-in second must be the last one of a month in UTC.
        let local = i64::from(hour * 60 + minute) - offset_minutes;
        let (day_shift, utc) = (local.div_euclid(1440), local.rem_euclid(1440));
        let (utc_year, utc_month, utc_day) = shift_day(year, month, day, day_shift);
        if utc != 23 * 60 + 59 || utc_day != days_in_month(utc_year, utc_month) {
            return Err(unreadable);
        }
    }
    if offset_minutes != 0 {
        return Err(ScalarRefusal::Uncarriable);
    }
    let spelled = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z");
    Timestamp::parse(&spelled, TimestampFormat::Iso8601).map_err(|_| ScalarRefusal::Uncarriable)?;
    Ok(spelled)
}

/// The calendar date `shift` days (−1, 0 or +1) away.
fn shift_day(year: u32, month: u32, day: u32, shift: i64) -> (u32, u32, u32) {
    match shift {
        -1 if day > 1 => (year, month, day - 1),
        -1 if month > 1 => (year, month - 1, days_in_month(year, month - 1)),
        -1 => (year.saturating_sub(1), 12, 31),
        1 if day < days_in_month(year, month) => (year, month, day + 1),
        1 if month < 12 => (year, month + 1, 1),
        1 => (year.saturating_add(1), 1, 1),
        _ => (year, month, day),
    }
}

/// An HTTP date as legacy RustFS reads one — the conditional-date grammar of `strict_date`, the
/// same reader in legacy RustFS — spelled as the gateway renders the instant; a year before 0000,
/// which that grammar reads and the gateway's timestamp cannot hold, is uncarriable.
fn http_date(raw: &str) -> Result<String, ScalarRefusal> {
    let instant = strict_http_date(raw).ok_or(ScalarRefusal::Unreadable)?;
    instant
        .render(TimestampFormat::HttpDate)
        .map_err(|_| ScalarRefusal::Uncarriable)
}

/// Every byte of an entity tag legacy RustFS reads between quotes: printable ASCII or a tab.
fn tag_bytes(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&byte| byte.is_ascii() && (byte >= 32 && byte != 127 || byte == b'\t'))
}

/// An entity tag as legacy RustFS reads one, spelled for the gateway's parser.
///
/// Legacy RustFS reads `"v"` and `W/"v"`, then a bare run of letters, digits and `-`, and then —
/// as a strong tag — any other text of printable ASCII, quotes and spaces included. A tag the
/// gateway's entity tag cannot hold exactly (empty, or carrying a quote) is uncarriable.
fn entity_tag(raw: &str) -> Result<String, ScalarRefusal> {
    let bytes = raw.as_bytes();
    let (weak, value) = match bytes {
        [b'"', value @ .., b'"'] => {
            if !tag_bytes(value) {
                return Err(ScalarRefusal::Unreadable);
            }
            (false, value)
        }
        [b'W', b'/', b'"', value @ .., b'"'] => {
            if !tag_bytes(value) {
                return Err(ScalarRefusal::Unreadable);
            }
            (true, value)
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads any printable text as a strong
        // tag — `W/abc` as the tag `W/abc`, surrounding spaces included — where a strict reader
        // refuses a malformed tag. Kept, since a completion naming such a part is refused later by
        // its part check; the intended reading is RFC 9110's entity-tag grammar.
        _ if tag_bytes(bytes) => (false, bytes),
        _ => return Err(ScalarRefusal::Unreadable),
    };
    let value = core::str::from_utf8(value).map_err(|_| ScalarRefusal::Unreadable)?;
    let spelled = if weak {
        format!("W/\"{value}\"")
    } else {
        format!("\"{value}\"")
    };
    match ETag::parse_xml_text(&spelled) {
        Ok(tag) if tag.is_weak() == weak && tag.opaque_tag() == value => Ok(spelled),
        _ => Err(ScalarRefusal::Uncarriable),
    }
}

#[cfg(test)]
#[path = "document_tests.rs"]
mod tests;
