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

//! The RustFS-profile switch that answers a header-signed SigV4 request legacy RustFS refuses
//! before its credential lookup with legacy RustFS's refusal, in its order (rustfs/gateway#1130).
//!
//! Responsible for: [`ServiceBuilder::answer_header_signatures_as_legacy_rustfs`],
//! [`HeaderRefusals::refusal`], which the pipeline asks before the security floor, and the
//! reading of an `Authorization` value, `x-amz-date` and `x-amz-content-sha256` the refusals are
//! defined over.
//! NOT responsible for: verifying anything. Nothing here derives a key, hashes a request or
//! compares a signature; a request this lets through is admitted, verified and served exactly as
//! it is without the switch. The algorithm token and an unreadable `AWS4-HMAC-SHA256` value are
//! RustFS's own guard's to answer (rustfs/gateway#1120), and a presigned URL, a browser `POST` form
//! and SigV2 are not header-signed SigV4.
//! Upstream: `super::ViewPolicy`. Downstream: `crate::service`.
//!
//! # What legacy RustFS does
//!
//! For a request carrying one `Authorization` value that is not SigV2 and no presigned query
//! signature, the legacy stack reads the value (`<algorithm> Credential=<key>/<date>/<region>/
//! <service>/aws4_request,<ws>SignedHeaders=<list>,<ws>Signature=<hex>`, the date a real day) and,
//! before it looks the access key up, refuses in this order:
//!
//! 1. a value that does not read: `400 InvalidRequest` "invalid header: authorization";
//! 2. a scope service other than `s3`, `sts` and `s3tables`: `501 NotImplemented`, naming it;
//! 3. no `x-amz-date` — a `Date` header does not stand in for it — `400 InvalidRequest`
//!    "missing header: x-amz-date", and one that is not `YYYYMMDDTHHMMSSZ` digits,
//!    "invalid header: x-amz-date";
//! 4. a scope date other than the `x-amz-date` day: `403 SignatureDoesNotMatch` "credential scope
//!    date does not match x-amz-date";
//! 5. an `x-amz-date` that names no instant (hour 24, second 60): `400 InvalidRequest` "invalid amz
//!    date";
//! 6. an instant more than the skew window away: `403 RequestTimeTooSkewed` "request time is too
//!    far from server time";
//! 7. an `x-amz-content-sha256` that is not a hex or base64 digest or one of the six keywords:
//!    `403 SignatureDoesNotMatch` "invalid header: x-amz-content-sha256";
//! 8. no `x-amz-content-sha256` on an `s3`-scoped request: `400 InvalidRequest` "missing header:
//!    x-amz-content-sha256". An `s3tables`-scoped one is refused with the same answer right after
//!    the lookup, and an `sts`-scoped one is verified over its body instead.
//!
//! A header-signed SigV2 request (`AWS <key>:<signature>`) is dated by a single `x-amz-date`,
//! else by a single `Date`, and refused, before the lookup: without either, `400 InvalidRequest`
//! "missing date"; with an `x-amz-date` that is not `YYYYMMDDTHHMMSSZ` naming an instant (an RFC
//! 1123 one included), "invalid x-amz-date"; with a `Date` that is not IMF-fixdate ending in
//! `GMT` (`+0000`, lower case and the SigV4 spelling included), "invalid date"; and past the skew
//! window, `403 RequestTimeTooSkewed` "request time is too far from server time".
//!
//! Observed against a legacy RustFS build (`RUSTFS_S3_STACK=legacy`, rustfs/rustfs `e870a6d25b`)
//! over raw sockets, each refusal alone and each adjacent pair to fix the order. Where the gateway
//! answered these itself, it answered other codes (`403 AccessDenied` for a missing or unreadable
//! timestamp, `400 AuthorizationHeaderMalformed` for the scope date, `400 InvalidRequest` for the
//! payload header), and it verified five of them: a SigV4 `Date` standing in for `x-amz-date`, a
//! second 60, a request with no `x-amz-content-sha256`, and a SigV2 `x-amz-date` or `Date` in
//! another spelling.

use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, Method};
use rustfs_gateway_core::{HandlerError, ResponseKind};
use rustfs_gateway_sig::{
    AmzDate, AuthError, PayloadMode, RawQuery, RequestNow, SigParseError, SkewWindow, TrailerSet, X_AMZ_SIGNATURE,
    enforce_clock_skew,
};
use rustfs_gateway_types::ErrorCode;

use super::super::ServiceBuilder;
use crate::ext::legacy_credential::{day_exists, number, read_authorization};
use crate::render::{S3Error, from_handler};

/// The algorithm token legacy RustFS's own guard leaves to the legacy stack.
const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The scope services legacy RustFS verifies, in the order its refusal names them.
const SIGNING_SERVICES: [&str; 3] = ["s3", "sts", "s3tables"];

/// Whether an assembly answers a header signature's pre-lookup refusals as legacy RustFS does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum HeaderRefusals {
    /// The security floor and the authenticator answer them, as for every request.
    #[default]
    Gateway,
    /// Legacy RustFS's refusals answer them first, in its order.
    LegacyRustfs,
}

/// The request head the refusals are read from.
pub(crate) struct SignedHead<'a> {
    /// The request method.
    pub(crate) method: &'a Method,
    /// The headers as the caller sent them.
    pub(crate) headers: &'a HeaderMap,
    /// The raw query.
    pub(crate) query: &'a str,
    /// The request's one clock reading.
    pub(crate) now: RequestNow,
    /// The window the security floor judges a timestamp by.
    pub(crate) window: SkewWindow,
}

impl HeaderRefusals {
    /// Legacy RustFS's refusal of `head` before its credential lookup, when it refuses one and
    /// this assembly answers with it; `None` leaves the request to the floor and the authenticator.
    pub(crate) fn refusal(self, head: &SignedHead<'_>, response: ResponseKind, body_owed: bool) -> Option<S3Error> {
        if self == Self::Gateway {
            return None;
        }
        let (code, sentence) = legacy_refusal(head)?;
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS answers these before it has
        // authenticated anything, with sentences that tell a forged request which of its fields
        // was wrong, and one that echoes the requested service. The intended future behaviour is
        // the security floor's own answers, decided where the signature is verified.
        Some(from_handler(
            HandlerError::new(code, sentence),
            response,
            crate::close::after_auth_failure(&AuthError::SignatureDoesNotMatch, body_owed),
        ))
    }
}

/// The code and sentence of legacy RustFS's first pre-lookup refusal of `head`, if any.
fn legacy_refusal(head: &SignedHead<'_>) -> Option<(ErrorCode, String)> {
    match header_signature(head)? {
        HeaderScheme::SigV4(value) => sigv4_refusal(head, value),
        HeaderScheme::SigV2 => sigv2_refusal(head),
    }
}

/// Legacy RustFS's pre-lookup refusal of a SigV4 `Authorization` `value`.
fn sigv4_refusal(head: &SignedHead<'_>, value: &str) -> Option<(ErrorCode, String)> {
    let Some(credential) = read_authorization(value) else {
        // An unreadable value that starts with the SigV4 token is RustFS's guard's to answer.
        if value.starts_with(SIGV4_ALGORITHM) {
            return None;
        }
        return Some((ErrorCode::INVALID_REQUEST, "invalid header: authorization".to_owned()));
    };
    if credential.algorithm != SIGV4_ALGORITHM || !credential.canonical_signature {
        return None;
    }
    if !SIGNING_SERVICES.contains(&credential.scope.service) {
        let service = credential.scope.service;
        let expected = SIGNING_SERVICES.join(", ");
        return Some((
            ErrorCode::NOT_IMPLEMENTED,
            format!("unknown service '{service}' in credential scope; expected one of: {expected}"),
        ));
    }
    let refused = |code: ErrorCode, sentence: &str| Some((code, sentence.to_owned()));
    let Some(stamp) = unique_value(head.headers, "x-amz-date") else {
        return refused(ErrorCode::INVALID_REQUEST, "missing header: x-amz-date");
    };
    if !is_amz_date_shape(stamp) {
        return refused(ErrorCode::INVALID_REQUEST, "invalid header: x-amz-date");
    }
    if stamp.get(..8) != Some(credential.scope.date) {
        return refused(ErrorCode::SIGNATURE_DOES_NOT_MATCH, "credential scope date does not match x-amz-date");
    }
    if !names_an_instant(stamp) {
        return refused(ErrorCode::INVALID_REQUEST, "invalid amz date");
    }
    let signed_at = AmzDate::parse(stamp).ok()?;
    if enforce_clock_skew(&signed_at, head.now, head.window).is_err() {
        return refused(ErrorCode::REQUEST_TIME_TOO_SKEWED, "request time is too far from server time");
    }
    match unique_value(head.headers, "x-amz-content-sha256") {
        Some(declared) if is_malformed_payload(declared) => {
            refused(ErrorCode::SIGNATURE_DOES_NOT_MATCH, "invalid header: x-amz-content-sha256")
        }
        None if credential.scope.service != "sts" => refused(ErrorCode::INVALID_REQUEST, "missing header: x-amz-content-sha256"),
        _ => None,
    }
}

/// Legacy RustFS's pre-lookup refusal of a header-signed SigV2 request: it dates the request by a
/// single `x-amz-date` in the SigV4 spelling alone, else by a single `Date` in the IMF-fixdate
/// spelling alone (`GMT`, not `+0000`), and holds that instant to the skew window.
fn sigv2_refusal(head: &SignedHead<'_>) -> Option<(ErrorCode, String)> {
    let refused = |code: ErrorCode, sentence: &str| Some((code, sentence.to_owned()));
    let amz_date = unique_value(head.headers, "x-amz-date");
    let Some(date) = unique_value(head.headers, "date").or(amz_date) else {
        return refused(ErrorCode::INVALID_REQUEST, "missing date");
    };
    let stamp = match amz_date {
        Some(stamp) if is_amz_date_shape(stamp) && names_an_instant(stamp) => stamp.to_owned(),
        Some(_) => return refused(ErrorCode::INVALID_REQUEST, "invalid x-amz-date"),
        None => match imf_fixdate(date) {
            Some(stamp) => stamp,
            None => return refused(ErrorCode::INVALID_REQUEST, "invalid date"),
        },
    };
    let signed_at = AmzDate::parse(&stamp).ok()?;
    if enforce_clock_skew(&signed_at, head.now, head.window).is_err() {
        return refused(ErrorCode::REQUEST_TIME_TOO_SKEWED, "request time is too far from server time");
    }
    None
}

/// `Www, DD Mmm YYYY HH:MM:SS GMT` naming an instant, as the stamp `YYYYMMDDTHHMMSSZ`. The weekday
/// must be one of the seven names and is not held to the date, as legacy RustFS reads it.
fn imf_fixdate(date: &str) -> Option<String> {
    const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let bytes = date.as_bytes();
    if bytes.len() != 29 || !WEEKDAYS.contains(&date.get(0..3)?) || date.get(25..29)? != " GMT" {
        return None;
    }
    let separators = [
        (3, b','),
        (4, b' '),
        (7, b' '),
        (11, b' '),
        (16, b' '),
        (19, b':'),
        (22, b':'),
    ];
    let digits = [5..7, 12..16, 17..19, 20..22, 23..25];
    if separators.iter().any(|(at, byte)| bytes.get(*at) != Some(byte))
        || digits.iter().any(|range| {
            !date
                .get(range.clone())
                .is_some_and(|text| text.bytes().all(|b| b.is_ascii_digit()))
        })
    {
        return None;
    }
    let month = MONTHS.iter().position(|name| Some(*name) == date.get(8..11))? + 1;
    let stamp = format!(
        "{}{month:02}{}T{}{}{}Z",
        date.get(12..16)?,
        date.get(5..7)?,
        date.get(17..19)?,
        date.get(20..22)?,
        date.get(23..25)?
    );
    names_an_instant(&stamp).then_some(stamp)
}

/// What kind of header signature a request carries, as legacy RustFS classifies one.
enum HeaderScheme<'a> {
    /// Any single `Authorization` value that is not SigV2's.
    SigV4(&'a str),
    /// `AWS <key>:<signature>`.
    SigV2,
}

/// The header signature of a request as legacy RustFS classifies one: a single readable
/// `Authorization` value on a request that is neither presigned nor a browser form.
fn header_signature<'a>(head: &SignedHead<'a>) -> Option<HeaderScheme<'a>> {
    let is_form = *head.method == Method::POST
        && head
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim_start().to_ascii_lowercase().starts_with("multipart/form-data"));
    let query = RawQuery::new(head.query);
    let presigned = [X_AMZ_SIGNATURE, "Signature"]
        .iter()
        .any(|name| query.decoded_value(name).ok().flatten().is_some());
    if is_form || presigned {
        return None;
    }
    let value = unique_value(head.headers, AUTHORIZATION.as_str())?;
    if value.strip_prefix("AWS ").is_some_and(|rest| rest.contains(':')) {
        return Some(HeaderScheme::SigV2);
    }
    Some(HeaderScheme::SigV4(value))
}

/// The value of `name` when the request carries exactly one, decoded as UTF-8 as legacy RustFS
/// decodes a header value: a repeated header, or one that is not UTF-8, reads as absent, and one
/// carrying a non-ASCII character is read (and then refused by the rule it breaks).
pub(super) fn unique_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    core::str::from_utf8(value.as_bytes()).ok()
}

/// Whether `stamp` has the shape legacy RustFS reads: eight digits, `T`, six digits, `Z`.
pub(super) fn is_amz_date_shape(stamp: &str) -> bool {
    let bytes = stamp.as_bytes();
    bytes.len() == 16
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 => *byte == b'T',
            15 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

/// Whether a stamp of [`is_amz_date_shape`] names an instant: a real day, hour 0-23, minute and
/// second 0-59.
pub(super) fn names_an_instant(stamp: &str) -> bool {
    day_exists(number(stamp, 0..4), number(stamp, 4..6), number(stamp, 6..8))
        && number(stamp, 9..11) <= 23
        && number(stamp, 11..13) <= 59
        && number(stamp, 13..15) <= 59
}

/// Whether a declared payload is one legacy RustFS cannot read: not a lowercase hex digest, a
/// canonical padded base64 digest, or one of the six keywords. The trailer set is not consulted:
/// legacy RustFS reads the declaration alone.
pub(super) fn is_malformed_payload(declared: &str) -> bool {
    matches!(PayloadMode::parse(declared, TrailerSet::None), Err(SigParseError::MalformedContentSha256))
}

impl ServiceBuilder {
    /// Answers a header-signed SigV4 request that legacy RustFS refuses before its credential
    /// lookup with legacy RustFS's code and sentence, in its order, as RustFS does today
    /// (rustfs/gateway#1130): an unreadable `Authorization` value, a scope service it does not
    /// verify, a missing or unreadable `x-amz-date` — a `Date` header does not stand in for it — a
    /// scope date other than its day, a skewed clock, and a missing or unreadable
    /// `x-amz-content-sha256`; and a header-signed SigV2 request without a date legacy RustFS
    /// reads, or dated outside the skew window. The module documentation lists each answer.
    ///
    /// Off by default: the security floor and the authenticator answer the same requests with the
    /// gateway's codes, and verify five of them (a SigV4 `Date` in place of `x-amz-date`, a second
    /// 60, no `x-amz-content-sha256`, a SigV2 `x-amz-date` or `Date` in another spelling). The switch only refuses: nothing refused without it is admitted
    /// with it, and a request it lets through is admitted, verified and served exactly as before.
    #[must_use]
    pub fn answer_header_signatures_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.header_signatures = HeaderRefusals::LegacyRustfs;
        self
    }
}

#[cfg(test)]
#[path = "header_signatures_tests.rs"]
mod tests;
