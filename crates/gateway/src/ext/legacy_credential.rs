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

//! A SigV4 credential as legacy RustFS reads it, for the RustFS profile's legacy answers to one it
//! refuses (rustfs/gateway#1130).
//!
//! Responsible for: [`read_authorization`] (an `Authorization` value) and [`read_scope`] (a
//! presigned URL's or a browser form's credential), restated from legacy RustFS's behaviour, the
//! calendar rules they share with the timestamp readings, and [`signed_headers_refusal`] — legacy
//! RustFS's words for a `SignedHeaders` list that does not cover what it must.
//! NOT responsible for: verifying anything, or deciding which refusal to give: the RustFS-profile
//! switches that read with these (`crate::builder::view_policy::header_signatures`,
//! `super::authenticator_switches`) decide that. Nothing read here reaches key derivation.
//! Upstream: none. Downstream: those switches.
//!
//! # What legacy RustFS reads
//!
//! A credential is `<key>/<date>/<region>/<service>/aws4_request`: the key and the region are any
//! text up to the next `/` (empty included, separators and non-ASCII included), the date is a
//! `YYYYMMDD` day that exists, and the service is text of one or more bytes. An `Authorization`
//! value is an algorithm token of one or more characters that are not ASCII whitespace; one or more
//! spaces, tabs, CRs or LFs; `Credential=` and a credential; `,`; optional whitespace;
//! `SignedHeaders=` and a list up to the next `,`; `,`; optional whitespace; `Signature=` and a
//! value up to the next whitespace; optional whitespace to the end. Where the gateway's own
//! parsers stop at a separator or a byte outside ASCII-graphic, legacy RustFS reads on.

use http::HeaderMap;
use rustfs_gateway_types::ErrorCode;

/// The fields of a credential scope as legacy RustFS reads them.
pub(crate) struct LegacyScope<'a> {
    /// The `YYYYMMDD` day, checked to exist.
    pub(crate) date: &'a str,
    /// The region, any text without `/`.
    pub(crate) region: &'a str,
    /// The service, one or more bytes without `/`.
    pub(crate) service: &'a str,
}

/// What legacy RustFS reads out of an `Authorization` value.
pub(crate) struct LegacyAuthorization<'a> {
    /// The algorithm token.
    pub(crate) algorithm: &'a str,
    /// The credential scope.
    pub(crate) scope: LegacyScope<'a>,
    /// Whether the signature is 64 lowercase hex digits.
    pub(crate) canonical_signature: bool,
}

/// Reads an `Authorization` value with legacy RustFS's grammar, or `None` where it does not read.
pub(crate) fn read_authorization(value: &str) -> Option<LegacyAuthorization<'_>> {
    let algorithm_end = value.find(|c: char| c.is_ascii_whitespace())?;
    let (algorithm, rest) = value.split_at(algorithm_end);
    if algorithm.is_empty() {
        return None;
    }
    let after_space = skip_spaces(rest);
    if after_space.len() == rest.len() {
        return None;
    }
    let (scope, rest) = scope_prefix(after_space.strip_prefix("Credential=")?)?;
    let rest = skip_spaces(rest.strip_prefix(',')?).strip_prefix("SignedHeaders=")?;
    let (_list, rest) = rest.split_once(',')?;
    let rest = skip_spaces(rest).strip_prefix("Signature=")?;
    let signature_end = rest.find(|c: char| c.is_ascii_whitespace()).unwrap_or(rest.len());
    let (signature, rest) = rest.split_at(signature_end);
    if !skip_spaces(rest).is_empty() {
        return None;
    }
    Some(LegacyAuthorization {
        algorithm,
        scope,
        canonical_signature: signature.len() == 64 && signature.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
    })
}

/// Reads a whole credential — a presigned URL's `X-Amz-Credential`, a browser form's
/// `x-amz-credential` — with legacy RustFS's grammar, or `None` where it does not read.
pub(crate) fn read_scope(value: &str) -> Option<LegacyScope<'_>> {
    let (scope, rest) = scope_prefix(value)?;
    rest.is_empty().then_some(scope)
}

/// The credential at the start of `value`, and what follows it.
fn scope_prefix(value: &str) -> Option<(LegacyScope<'_>, &str)> {
    let (_key, rest) = value.split_once('/')?;
    let (date, rest) = rest.split_once('/')?;
    if !is_calendar_day(date) {
        return None;
    }
    let (region, rest) = rest.split_once('/')?;
    let (service, rest) = rest.split_once('/')?;
    if service.is_empty() {
        return None;
    }
    let rest = rest.strip_prefix("aws4_request")?;
    Some((LegacyScope { date, region, service }, rest))
}

/// `value` after its leading spaces, tabs, CRs and LFs.
fn skip_spaces(value: &str) -> &str {
    value.trim_start_matches([' ', '\t', '\r', '\n'])
}

/// Whether `date` is `YYYYMMDD` naming a day that exists.
pub(crate) fn is_calendar_day(date: &str) -> bool {
    date.len() == 8
        && date.bytes().all(|b| b.is_ascii_digit())
        && day_exists(number(date, 0..4), number(date, 4..6), number(date, 6..8))
}

/// The decimal number in `text[range]`, which the callers have checked is all digits.
pub(crate) fn number(text: &str, range: core::ops::Range<usize>) -> u32 {
    text.get(range).and_then(|digits| digits.parse().ok()).unwrap_or(u32::MAX)
}

/// Whether `day` of `month` exists in `year`, in the proleptic Gregorian calendar.
pub(crate) fn day_exists(year: u32, month: u32, day: u32) -> bool {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// Whether legacy RustFS reads `region` as a region: empty (no region), or one or more lowercase
/// ASCII letters, digits and `-`.
pub(crate) fn is_legacy_region(region: &str) -> bool {
    region
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Legacy RustFS's sentence for a region it refuses after the signature: the region quoted as Rust
/// writes a string for debugging, control characters and quotes escaped.
pub(crate) fn invalid_region_sentence(region: &str) -> String {
    format!("invalid credential region: invalid region: {region:?}")
}

/// Legacy RustFS's sentence for an `x-amz-*` header a signature leaves out.
pub(crate) const UNSIGNED_HEADERS_SENTENCE: &str = "There were headers present in the request which were not signed";

/// Legacy RustFS's answer to a `SignedHeaders` list `raw` that does not cover what it must, in its
/// order: the first name the request did not send (`host` spelled so excepted: the authority
/// stands in for it), or sent with a value that is not UTF-8, `403 SignatureDoesNotMatch` naming
/// it; else an `x-amz-*` header the list does not name, case-insensitively, `403 AccessDenied`.
/// A header signature may leave `x-amz-content-sha256` out (`payload_hash_exempt`); a presigned URL
/// may not. `None` when the list covers everything, and the refusal is someone else's to word.
pub(crate) fn signed_headers_refusal(raw: &str, headers: &HeaderMap, payload_hash_exempt: bool) -> Option<(ErrorCode, String)> {
    for name in raw.split(';') {
        let mut values = headers.get_all(name).iter().peekable();
        if values.peek().is_none() {
            if name == "host" {
                continue;
            }
            return Some((ErrorCode::SIGNATURE_DOES_NOT_MATCH, format!("missing signed header: {name}")));
        }
        if values.any(|value| core::str::from_utf8(value.as_bytes()).is_err()) {
            return Some((ErrorCode::SIGNATURE_DOES_NOT_MATCH, format!("invalid signed header: {name}")));
        }
    }
    let unsigned = headers.keys().map(http::HeaderName::as_str).any(|name| {
        name.starts_with("x-amz-")
            && !(payload_hash_exempt && name == "x-amz-content-sha256")
            && !raw.split(';').any(|signed| signed.eq_ignore_ascii_case(name))
    });
    unsigned.then(|| (ErrorCode::ACCESS_DENIED, UNSIGNED_HEADERS_SENTENCE.to_owned()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const SIGNATURE: &str = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";

    /// Positive — the credential reads every spelling legacy RustFS reads: separators, a tab, a
    /// non-ASCII byte and an empty key or region in the region and key fields, a leap day.
    #[test]
    fn a_credential_reads_every_spelling_legacy_rustfs_reads() {
        for (value, region) in [
            ("AKID/20150830/us east-1/s3/aws4_request", "us east-1"),
            ("AKID/20150830/us,east-1/s3/aws4_request", "us,east-1"),
            ("AKID/20150830/us\teast/s3/aws4_request", "us\teast"),
            ("AKID/20150830/us-\u{e9}ast/s3tables/aws4_request", "us-\u{e9}ast"),
            ("/20150830//sts/aws4_request", ""),
            ("AKID/20160229/US-EAST-1/s3/aws4_request", "US-EAST-1"),
        ] {
            let scope = read_scope(value).expect("readable");
            assert_eq!(scope.region, region, "{value:?}");
        }
        let header = format!(
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us,east/s3/aws4_request, SignedHeaders=host, Signature={SIGNATURE}"
        );
        let read = read_authorization(&header).expect("readable");
        assert_eq!(
            (read.algorithm, read.scope.region, read.scope.service),
            ("AWS4-HMAC-SHA256", "us,east", "s3")
        );
        assert!(read.canonical_signature);
    }

    /// Negative — what legacy RustFS does not read: a day that does not exist, an empty service, a
    /// sixth field, another terminator, and a component order other than its own.
    #[test]
    fn n_a_credential_legacy_rustfs_cannot_read_is_not_read() {
        for value in [
            "AKID/20150230/us-east-1/s3/aws4_request",
            "AKID/20150830/us-east-1//aws4_request",
            "AKID/20150830/us-east-1/s3/aws4_request/x",
            "AKID/20150830/us-east-1/s3/aws4-request",
            "AKID/2015083/us-east-1/s3/aws4_request",
        ] {
            assert!(read_scope(value).is_none(), "{value}");
        }
        let reordered = format!(
            "AWS4-HMAC-SHA256 SignedHeaders=host, Credential=AKID/20150830/us-east-1/s3/aws4_request, Signature={SIGNATURE}"
        );
        assert!(read_authorization(&reordered).is_none());
    }

    /// Positive and negative — the region grammar and the sentence legacy RustFS writes.
    #[test]
    fn the_region_grammar_and_sentence_are_legacy_rustfs_s() {
        for region in ["", "us-east-1", "rustfs-local-2"] {
            assert!(is_legacy_region(region), "{region:?}");
        }
        for region in ["US-EAST-1", "us east", "us,east", "us_east", "us-\u{e9}ast", "us\u{7f}east"] {
            assert!(!is_legacy_region(region), "{region:?}");
        }
        assert_eq!(
            invalid_region_sentence("us\teast"),
            "invalid credential region: invalid region: \"us\\teast\""
        );
        assert_eq!(
            invalid_region_sentence("us\u{7f}east"),
            "invalid credential region: invalid region: \"us\\u{7f}east\""
        );
        assert_eq!(
            invalid_region_sentence("us-\u{e9}ast"),
            "invalid credential region: invalid region: \"us-\u{e9}ast\""
        );
    }
}
