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

//! The RustFS-profile guard that answers a SigV4 request whose signature claims another algorithm,
//! cannot be read, or leaves an `x-amz-*` header unsigned, before the request is routed, with the
//! answers legacy RustFS gives (rustfs/gateway#1120).
//!
//! Responsible for: [`ServiceBuilder::refuse_unsigned_amz_headers_before_routing`], the three
//! refusal sentences, [`SigV4HeaderGuard::refusal`], which the pipeline asks before routing, and
//! the reading of an `Authorization` value and a presigned query that the guard is defined over.
//! NOT responsible for: verifying anything. Nothing here derives a key, hashes a request or
//! compares a signature; a request the guard lets through is judged by the authenticator exactly as
//! it is without the guard.
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS does
//!
//! RustFS answers GHSA-xm99-m3gq-83g8 and GHSA-g8w9-qw9q-fghr with a tower layer in front of its
//! legacy stack (`SigV4HeaderGuardLayer`, `rustfs/src/server/layer.rs:1610-1701`, rustfs/rustfs#7796),
//! running `reject_unsigned_amz_headers_on_sigv4_request` (`rustfs/src/auth.rs:1037-1228`) on every
//! request before the stack routes, authenticates or reads a body:
//!
//! - a query naming `X-Amz-Signature` (any case) makes the request presigned, and every `x-amz-*`
//!   header but `x-amz-cf-id` must then be named in the query's `X-Amz-SignedHeaders`;
//! - each `Authorization` value is read as a SigV4 header. One that reads with an algorithm token
//!   other than `AWS4-HMAC-SHA256` is refused as an unsupported algorithm — without the guard the
//!   legacy stack answered such a token `501` before RustFS's own access check could run — and one
//!   that starts with `AWS4-HMAC-SHA256` and does not read is refused as invalid. A value of another
//!   scheme (SigV2, a bearer token) is not the guard's;
//! - for a SigV4 header that reads, every `x-amz-*` header must be named in its `SignedHeaders`,
//!   except the four the verifier reads around the signature (`x-amz-content-sha256`,
//!   `x-amz-decoded-content-length`, `x-amz-trailer`, `x-amz-checksum-algorithm`) and
//!   `x-amz-cf-id`.
//!
//! Each refusal is `403 AccessDenied` with a fixed sentence and, because the guard answers without
//! reading the body, a connection that closes after it. Observed against a legacy RustFS build over
//! raw sockets for the swapped token, an `AWS4-HMAC-SHA512` token, an unreadable
//! `AWS4-HMAC-SHA256` value, and an unsigned `x-amz-copy-source` or `x-amz-meta-*`.
//!
//! # Where it runs
//!
//! Where RustFS's layer runs relative to the rest of its stack: after CORS has answered every
//! `OPTIONS`, and before routing, so a request that would be refused for its route is refused here
//! first. RustFS's virtual-host hint layer sits in front of the guard, so a `PUT` or `DELETE` of `/`
//! that the gateway would answer with its virtual-host hint is left to that answer.

use http::{HeaderMap, Method, header::AUTHORIZATION};
use rustfs_gateway_core::{HandlerError, ResponseKind};
use rustfs_gateway_types::ErrorCode;

use super::ServiceBuilder;
use crate::close::ConnectionIntent;
use crate::ext::ResolvedHost;
use crate::render::{S3Error, from_handler};

/// Legacy RustFS's sentence for an `Authorization` value with another SigV4 algorithm token.
pub(crate) const UNSUPPORTED_ALGORITHM: &str = "Unsupported SigV4 authorization algorithm";

/// Legacy RustFS's sentence for an `AWS4-HMAC-SHA256` value that does not read.
pub(crate) const INVALID_HEADER: &str = "Invalid SigV4 authorization header";

/// Legacy RustFS's sentence for an `x-amz-*` header the signature does not name.
pub(crate) const UNSIGNED_HEADERS: &str = "There were headers present in the request which were not signed";

/// The algorithm token the guard accepts.
const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The one header either form may leave unsigned: CloudFront adds it to every origin request.
const CLOUDFRONT_ID: &str = "x-amz-cf-id";

/// The headers a header-signed request may leave out of `SignedHeaders`.
const HEADER_SIGNED_ENVELOPE: [&str; 4] = [
    "x-amz-content-sha256",
    "x-amz-decoded-content-length",
    "x-amz-trailer",
    "x-amz-checksum-algorithm",
];

/// Whether an assembly answers the guard's three refusals before routing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SigV4HeaderGuard {
    /// The authenticator answers these requests, as every other.
    #[default]
    Off,
    /// Legacy RustFS's guard answers them first.
    LegacyRustfs,
}

impl SigV4HeaderGuard {
    /// The refusal legacy RustFS gives this request before routing it, if any.
    ///
    /// `headers` is the request head as the caller sent it and `query` its raw query. A request
    /// that `resolved` marks for the virtual-host hint is left to that answer when it writes the
    /// service root, as it is in RustFS.
    pub(crate) fn refusal(
        self,
        headers: &HeaderMap,
        query: &str,
        method: &Method,
        resolved: &ResolvedHost,
        response: ResponseKind,
    ) -> Option<S3Error> {
        if self == Self::Off || (resolved.diagnostic.is_some() && matches!(*method, Method::PUT | Method::DELETE)) {
            return None;
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads the signed-header list before
        // the signature is verified and before the request is routed, so a request with a forged
        // signature learns which rule it broke, and one that would be refused for its route is
        // refused here instead. The refusals are the right ones; the intended future behaviour is
        // one uniform authentication refusal, decided where the signature is verified.
        let sentence = sentence(headers, query)?;
        Some(from_handler(
            HandlerError::new(ErrorCode::ACCESS_DENIED, sentence),
            response,
            // RustFS answers without reading the body and closes the connection behind it.
            ConnectionIntent::Close,
        ))
    }
}

/// The sentence of the refusal legacy RustFS's guard gives, if it gives one.
fn sentence(headers: &HeaderMap, query: &str) -> Option<&'static str> {
    if let Some(signed) = presigned_signed_headers(query)
        && unsigned_amz_header(headers, |name| name == CLOUDFRONT_ID || signed.iter().any(|signed| signed == name))
    {
        return Some(UNSIGNED_HEADERS);
    }
    for value in headers.get_all(AUTHORIZATION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        let Some(signature) = HeaderSignature::read(value) else {
            if value.starts_with(SIGV4_ALGORITHM) {
                return Some(INVALID_HEADER);
            }
            continue;
        };
        if signature.algorithm != SIGV4_ALGORITHM {
            return Some(UNSUPPORTED_ALGORITHM);
        }
        let exempt = |name: &str| {
            name == CLOUDFRONT_ID
                || HEADER_SIGNED_ENVELOPE.contains(&name)
                || signature.signed.iter().any(|signed| signed.eq_ignore_ascii_case(name))
        };
        if unsigned_amz_header(headers, exempt) {
            return Some(UNSIGNED_HEADERS);
        }
    }
    None
}

/// Whether any `x-amz-*` header of `headers` is neither covered nor exempt.
fn unsigned_amz_header(headers: &HeaderMap, covered: impl Fn(&str) -> bool) -> bool {
    headers
        .keys()
        .map(http::HeaderName::as_str)
        .any(|name| name.starts_with("x-amz-") && !covered(name))
}

/// The names a presigned query signs, lower-cased, or `None` for a query that is not presigned.
///
/// The query is read as a form: `+` is a space and every escape is decoded, in names and values
/// alike. It is presigned when any name reads `X-Amz-Signature` in any case. The signed list is the
/// value of the one parameter named exactly `X-Amz-SignedHeaders`; with none, or with two, the
/// list is empty and every `x-amz-*` header but `x-amz-cf-id` is unsigned.
fn presigned_signed_headers(query: &str) -> Option<Vec<String>> {
    let mut presigned = false;
    let mut signed: Option<String> = None;
    let mut repeated = false;
    for (name, value) in form_pairs(query) {
        if name.eq_ignore_ascii_case("x-amz-signature") {
            presigned = true;
        } else if name == "X-Amz-SignedHeaders" {
            repeated |= signed.is_some();
            signed = Some(value);
        }
    }
    if !presigned {
        return None;
    }
    let list = if repeated { None } else { signed };
    Some(
        list.unwrap_or_default()
            .split(';')
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect(),
    )
}

/// The `name=value` pairs of a query read as `application/x-www-form-urlencoded`.
fn form_pairs(query: &str) -> impl Iterator<Item = (String, String)> + '_ {
    query.split('&').filter(|pair| !pair.is_empty()).map(|pair| {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        (form_decode(name), form_decode(value))
    })
}

/// One form component, decoded: `+` is a space, `%XY` is the octet, and anything else — a `%`
/// without two hex digits included — is itself. Octets that are not UTF-8 read as U+FFFD.
fn form_decode(component: &str) -> String {
    let bytes = component.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let escaped = (byte == b'%')
            .then(|| Some((hex(*bytes.get(index + 1)?)?, hex(*bytes.get(index + 2)?)?)))
            .flatten();
        match (byte, escaped) {
            (_, Some((high, low))) => {
                decoded.push((high << 4) | low);
                index += 3;
            }
            (b'+', None) => {
                decoded.push(b' ');
                index += 1;
            }
            (other, None) => {
                decoded.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex(digit: u8) -> Option<u8> {
    char::from(digit).to_digit(16).and_then(|value| u8::try_from(value).ok())
}

/// What the guard reads out of one SigV4 `Authorization` value.
///
/// The shape legacy RustFS reads it with: an algorithm token of one or more characters that are not
/// ASCII whitespace; at least one space, tab, CR or LF; `Credential=` and a credential scope
/// (`<key>/<YYYYMMDD>/<region>/<service>/aws4_request`, the key and the region possibly empty, the
/// date a real calendar date) closed by `,`; optional whitespace; `SignedHeaders=` and one or more
/// `;`-separated names (each possibly empty, none containing `,`) closed by `,`; optional
/// whitespace; `Signature=` and a value that is exactly 64 lower-case hex digits; and optional
/// whitespace to the end. Any other value does not read.
struct HeaderSignature<'a> {
    algorithm: &'a str,
    signed: Vec<&'a str>,
}

impl<'a> HeaderSignature<'a> {
    fn read(value: &'a str) -> Option<Self> {
        let algorithm_end = value.find(|c: char| c.is_ascii_whitespace())?;
        let (algorithm, rest) = value.split_at(algorithm_end);
        if algorithm.is_empty() {
            return None;
        }
        let rest = skip_spaces(rest);
        if rest.len() == value.len() - algorithm.len() {
            return None;
        }
        let rest = rest.strip_prefix("Credential=")?;
        let rest = credential_scope(rest)?.strip_prefix(',')?;
        let rest = skip_spaces(rest).strip_prefix("SignedHeaders=")?;
        let list_end = rest.find(',')?;
        let (list, rest) = rest.split_at(list_end);
        let signed = list.split(';').collect();
        let rest = skip_spaces(rest.strip_prefix(',')?).strip_prefix("Signature=")?;
        let signature_end = rest.find(|c: char| c.is_ascii_whitespace()).unwrap_or(rest.len());
        let (signature, rest) = rest.split_at(signature_end);
        if !skip_spaces(rest).is_empty() || !is_lowercase_sha256_hex(signature) {
            return None;
        }
        Some(Self { algorithm, signed })
    }
}

/// `value` after its leading spaces, tabs, CRs and LFs.
fn skip_spaces(value: &str) -> &str {
    value.trim_start_matches([' ', '\t', '\r', '\n'])
}

/// What follows a readable credential scope, or `None`.
fn credential_scope(value: &str) -> Option<&str> {
    let (_key, rest) = value.split_once('/')?;
    let (date, rest) = rest.split_once('/')?;
    if !is_calendar_date(date) {
        return None;
    }
    let (_region, rest) = rest.split_once('/')?;
    let (service, rest) = rest.split_once('/')?;
    if service.is_empty() {
        return None;
    }
    rest.strip_prefix("aws4_request")
}

/// Whether `date` is `YYYYMMDD` naming a day that exists.
fn is_calendar_date(date: &str) -> bool {
    let digits = date.as_bytes();
    if digits.len() != 8 || !digits.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let number = |range: core::ops::Range<usize>| date.get(range).and_then(|text| text.parse::<u32>().ok());
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(4..6), number(6..8)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

impl ServiceBuilder {
    /// Refuses, before routing and with legacy RustFS's answers, a SigV4 request whose
    /// `Authorization` value claims another algorithm or cannot be read, and a SigV4 request —
    /// header-signed or presigned — carrying an `x-amz-*` header its signature does not name, as
    /// RustFS does today (rustfs/gateway#1120).
    ///
    /// Off by default: the authenticator refuses the same requests, with its own codes and in its
    /// own place in the pipeline. With the switch on, each is `403 AccessDenied` with RustFS's
    /// sentence and a connection that closes after it, and it is answered before the request is
    /// routed. Nothing that is refused without the switch is admitted with it, and a request the
    /// guard passes is verified exactly as before.
    #[must_use]
    pub fn refuse_unsigned_amz_headers_before_routing(mut self) -> Self {
        self.view_policy.sigv4_header_guard = SigV4HeaderGuard::LegacyRustfs;
        self
    }
}

#[cfg(test)]
#[path = "sigv4_header_guard_tests.rs"]
mod tests;
