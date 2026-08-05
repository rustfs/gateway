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

//! The borrowed, allocation-free view every layer above reads headers through.
//!
//! Responsible for: `O(1)` lookups by name, the repeated-header policy, the non-UTF-8 tolerance
//! rule, boolean header parsing, and writing SigV4 canonical headers straight into a caller's
//! buffer.
//! NOT responsible for: computing a signature, deciding what any particular header *means*, or
//! owning storage. A [`HeaderView`] borrows the map the [`WireRequest`](crate::WireRequest) owns
//! and can outlive nothing.
//! Upstream: `http`, this crate's `text`, `metadata`, `limits` and `reject`. Downstream:
//! `rustfs-gateway-sig`'s canonical request builder, and every operation that reads a header.
//!
//! # Why nothing is sorted
//!
//! The obvious way to build canonical headers is to sort every header in the request and walk the
//! sorted list. That costs an allocation and a sort per request, and it computes an ordering over
//! headers nobody signed. The signature already carries the ordering: `SignedHeaders` is
//! *required* to be a lowercase, semicolon-separated, ascending list. So this module verifies
//! that ordering — a single pass, no allocation — and then looks each name up in the
//! [`http::HeaderMap`] hash, which is `O(1)`. A request that lists twelve query parameters and
//! twenty headers reaches the signer without a single `malloc`.
//!
//! # Why an unreadable header is usually ignored
//!
//! A reverse proxy in front of this gateway may inject a header of its own whose value is not
//! UTF-8. Refusing the whole request for it is not a hypothetical inconvenience: it took down
//! every `PutObject` behind one such proxy (s3s#597, rustfs#3124). So an unrelated header with
//! non-UTF-8 bytes is skipped by [`HeaderView::iter_text`] and the request proceeds.
//!
//! The exception is exact: a header this gateway attributes meaning to
//! ([`is_significant_header`]), or a header the signature covers, must be readable or the request
//! is refused. Ignoring one of those would mean bytes that nobody could read took part in a
//! decision — either a signature computed over something other than what arrived, or an S3
//! semantic silently dropped.

use core::fmt;

use http::{HeaderMap, HeaderName, HeaderValue};

use crate::limits::{LimitKind, Limits};
use crate::metadata::{METADATA_PREFIX, validate_metadata_key, validate_metadata_value};
use crate::reject::WireReject;
use crate::text::{contains_forbidden_control, is_token};

/// Headers whose S3 semantics are single-valued, and which are therefore refused when repeated.
///
/// Repeating any of these creates two answers to one question. Which one wins has never been
/// audited across the implementations in a typical deployment (s3s#176 is open, and carries a
/// security label for exactly that reason), so this layer refuses to be one of the parties that
/// picks. `host` is absent because it is handled earlier and more strictly, by
/// [`effective_host`](crate::effective_host).
pub const SINGLE_VALUED_HEADERS: &[&str] = &[
    "authorization",
    "content-length",
    "content-md5",
    "content-type",
    "transfer-encoding",
    "x-amz-content-sha256",
    "x-amz-date",
    "x-amz-decoded-content-length",
    "x-amz-security-token",
    "range",
    "expect",
];

/// Named headers this gateway attributes meaning to, beyond the `x-amz-` family.
const SIGNIFICANT_NAMED_HEADERS: &[&str] = &[
    "host",
    "authorization",
    "content-length",
    "content-type",
    "content-md5",
    "content-encoding",
    "transfer-encoding",
    "date",
    "range",
    "expect",
];

/// Whether this gateway attributes meaning to the named header.
///
/// The `x-amz-` family is significant as a whole — including `x-amz-meta-*`, whose bytes end up
/// stored and later served back — plus the named list above. Everything else is a header this
/// gateway passes no judgement on, and is therefore allowed to be unreadable.
#[must_use]
pub fn is_significant_header(name: &HeaderName) -> bool {
    let text = name.as_str();
    text.starts_with("x-amz-") || SIGNIFICANT_NAMED_HEADERS.contains(&text)
}

/// Why canonical headers could not be written.
///
/// No variant names the offending header. The caller holds the [`SignedHeaderList`] and can say
/// which name it asked for; echoing a peer-supplied name into an error or a log is how a
/// reflected-value defect starts.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalHeadersError {
    /// A header named in `SignedHeaders` is not present in the request.
    MissingSignedHeader,
    /// A header named in `SignedHeaders` carries bytes that are not UTF-8.
    ///
    /// This is the exception to the tolerance rule: a signed header must be readable, or the
    /// canonical request would be computed over something other than what arrived.
    NonUtf8SignedHeader,
    /// The caller's writer failed.
    Write,
}

/// Why a `SignedHeaders` list was refused.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedHeadersError {
    /// The list was empty.
    Empty,
    /// An entry was empty, or was not a lowercase HTTP token.
    MalformedName,
    /// Entries were not in strictly ascending order.
    ///
    /// Equal neighbours are refused along with out-of-order ones: a name listed twice would be
    /// canonicalised twice, and the duplicate is free room for a signature that covers a header
    /// the verifier reads only once.
    NotAscending,
    /// `host` was not among the entries, which SigV4 requires.
    HostNotSigned,
}

/// A validated `SignedHeaders` list: lowercase, strictly ascending, borrowed.
///
/// Holds nothing but the original string. Iterating it allocates nothing, and the ascending
/// invariant means a caller can walk it in order without sorting anything.
#[derive(Clone, Copy, Debug)]
pub struct SignedHeaderList<'a> {
    raw: &'a str,
}

impl<'a> SignedHeaderList<'a> {
    /// Validates a semicolon-separated `SignedHeaders` value.
    ///
    /// # Errors
    ///
    /// [`SignedHeadersError`], one variant per broken invariant.
    pub fn parse(raw: &'a str) -> Result<Self, SignedHeadersError> {
        if raw.is_empty() {
            return Err(SignedHeadersError::Empty);
        }
        let mut previous: Option<&str> = None;
        let mut has_host = false;
        for name in raw.split(';') {
            let bytes = name.as_bytes();
            if !is_token(bytes) || bytes.iter().any(u8::is_ascii_uppercase) {
                return Err(SignedHeadersError::MalformedName);
            }
            if let Some(previous_name) = previous
                && previous_name >= name
            {
                return Err(SignedHeadersError::NotAscending);
            }
            if name == "host" {
                has_host = true;
            }
            previous = Some(name);
        }
        if !has_host {
            return Err(SignedHeadersError::HostNotSigned);
        }
        Ok(Self { raw })
    }

    /// The names, in the order they were signed.
    pub fn iter(&self) -> impl Iterator<Item = &'a str> {
        self.raw.split(';')
    }

    /// Whether a name was signed.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.iter().any(|candidate| candidate == name)
    }

    /// The list as it appeared in the signature.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        self.raw
    }
}

/// A borrowed view over one request's headers.
///
/// Every accessor is a lookup or an iteration; none of them allocates, and none of them copies a
/// value. The view is what layers above receive instead of the [`http::HeaderMap`], so that
/// "reads a header" and "reads the raw request" stay different capabilities.
#[derive(Clone, Copy, Debug)]
pub struct HeaderView<'a> {
    map: &'a HeaderMap,
}

impl<'a> HeaderView<'a> {
    /// Wraps a header map.
    #[must_use]
    pub fn new(map: &'a HeaderMap) -> Self {
        Self { map }
    }

    /// The first value for a name, as bytes.
    #[must_use]
    pub fn get_bytes(&self, name: &HeaderName) -> Option<&'a [u8]> {
        self.map.get(name).map(HeaderValue::as_bytes)
    }

    /// The first value for a name, when it is valid UTF-8.
    ///
    /// `None` covers both "absent" and "present but unreadable". A caller that must tell the two
    /// apart — anything significant or signed — asks [`HeaderView::get_bytes`] and decides for
    /// itself; acceptance has already refused the unreadable case for those names.
    #[must_use]
    pub fn get_str(&self, name: &HeaderName) -> Option<&'a str> {
        self.get_bytes(name).and_then(|bytes| core::str::from_utf8(bytes).ok())
    }

    /// How many times a name appears.
    #[must_use]
    pub fn count(&self, name: &HeaderName) -> usize {
        self.map.get_all(name).iter().count()
    }

    /// Whether a name appears more than once.
    #[must_use]
    pub fn is_multi(&self, name: &HeaderName) -> bool {
        let mut values = self.map.get_all(name).iter();
        values.next().is_some() && values.next().is_some()
    }

    /// Every header whose value is valid UTF-8, in map order.
    ///
    /// Headers whose values are not UTF-8 are skipped rather than reported. That is the s3s#597
    /// rule: a proxy-injected header this gateway has no opinion about must not fail the request.
    /// Acceptance has already refused the case where such a header is significant.
    pub fn iter_text(&self) -> impl Iterator<Item = (&'a HeaderName, &'a str)> {
        self.map
            .iter()
            .filter_map(|(name, value)| core::str::from_utf8(value.as_bytes()).ok().map(|text| (name, text)))
    }

    /// A boolean header, parsed case-insensitively.
    ///
    /// `True`, `TRUE` and `true` are all accepted, because the AWS CLI sends the capitalised
    /// spelling and a case-sensitive parser rejects a request the AWS SDKs consider well formed
    /// (s3s#151). An empty value is `None`, not an error: an empty header field is legal, and
    /// refusing one has broken real clients before (s3s#382).
    ///
    /// # Errors
    ///
    /// [`WireReject::MalformedHeaderValue`] when the value is neither spelling of a boolean.
    pub fn bool_flag(&self, name: &HeaderName) -> Result<Option<bool>, WireReject> {
        let Some(bytes) = self.get_bytes(name) else {
            return Ok(None);
        };
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.eq_ignore_ascii_case(b"true") {
            return Ok(Some(true));
        }
        if bytes.eq_ignore_ascii_case(b"false") {
            return Ok(Some(false));
        }
        Err(WireReject::MalformedHeaderValue(name.clone()))
    }

    /// Writes the SigV4 canonical headers block for a signed-header list.
    ///
    /// One `name:value\n` line per signed name, in the list's order — which
    /// [`SignedHeaderList::parse`] has already proved ascending, so nothing is sorted here.
    /// Values are trimmed of leading and trailing whitespace and have internal whitespace runs
    /// collapsed to a single space, except inside a quoted string, where SigV4 preserves it. A
    /// name that appears several times is written once, its values joined with `,` in the order
    /// they arrived.
    ///
    /// Nothing is allocated: the caller owns the buffer, and this walks the map in place.
    ///
    /// # Errors
    ///
    /// [`CanonicalHeadersError`] for a missing signed header, an unreadable one, or a failing
    /// writer.
    pub fn write_canonical_headers<W: fmt::Write>(
        &self,
        signed: &SignedHeaderList<'_>,
        out: &mut W,
    ) -> Result<(), CanonicalHeadersError> {
        for name in signed.iter() {
            out.write_str(name).map_err(|_| CanonicalHeadersError::Write)?;
            out.write_char(':').map_err(|_| CanonicalHeadersError::Write)?;
            let mut seen_any = false;
            for value in self.map.get_all(name) {
                if seen_any {
                    out.write_char(',').map_err(|_| CanonicalHeadersError::Write)?;
                }
                seen_any = true;
                let text = core::str::from_utf8(value.as_bytes()).map_err(|_| CanonicalHeadersError::NonUtf8SignedHeader)?;
                write_canonical_value(text, out)?;
            }
            if !seen_any {
                return Err(CanonicalHeadersError::MissingSignedHeader);
            }
            out.write_char('\n').map_err(|_| CanonicalHeadersError::Write)?;
        }
        Ok(())
    }
}

/// Writes one header value in canonical form: trimmed, internal whitespace collapsed.
fn write_canonical_value<W: fmt::Write>(value: &str, out: &mut W) -> Result<(), CanonicalHeadersError> {
    let trimmed = value.trim_matches(|character: char| character == ' ' || character == '\t');
    let mut in_quote = false;
    let mut run_start: Option<usize> = None;
    let mut pending_space = false;
    for (index, character) in trimmed.char_indices() {
        let is_space = !in_quote && (character == ' ' || character == '\t');
        if character == '"' {
            in_quote = !in_quote;
        }
        if is_space {
            if let Some(start) = run_start.take() {
                out.write_str(trimmed.get(start..index).unwrap_or(""))
                    .map_err(|_| CanonicalHeadersError::Write)?;
            }
            pending_space = true;
        } else {
            if pending_space {
                out.write_char(' ').map_err(|_| CanonicalHeadersError::Write)?;
                pending_space = false;
            }
            if run_start.is_none() {
                run_start = Some(index);
            }
        }
    }
    if let Some(start) = run_start {
        out.write_str(trimmed.get(start..).unwrap_or(""))
            .map_err(|_| CanonicalHeadersError::Write)?;
    }
    Ok(())
}

/// Applies every acceptance-time header rule.
///
/// In order: the size ceilings, the repeated single-valued headers, then a single pass in which
/// each field is checked for control characters, for readability when it is significant, and —
/// when it is user metadata — against the metadata name and value rules.
pub(crate) fn validate(headers: &HeaderMap, limits: &Limits) -> Result<(), WireReject> {
    let mut field_count = 0usize;
    let mut byte_count = 0usize;
    for (name, value) in headers.iter() {
        field_count = field_count.saturating_add(1);
        if field_count > limits.max_header_count {
            return Err(WireReject::LimitExceeded(LimitKind::HeaderCount));
        }
        byte_count = byte_count.saturating_add(name.as_str().len()).saturating_add(value.len());
        if byte_count > limits.max_header_bytes {
            return Err(WireReject::LimitExceeded(LimitKind::HeaderBytes));
        }

        let bytes = value.as_bytes();
        // The `http` crate already refuses CR and LF inside a value it parsed; this repeats the
        // check because a value can also be constructed in process, and because the rule this
        // layer promises must not depend on which door the request came through.
        if contains_forbidden_control(bytes) {
            return Err(WireReject::MalformedHeaderValue(name.clone()));
        }

        if is_significant_header(name) && core::str::from_utf8(bytes).is_err() {
            return Err(WireReject::NonUtf8SignificantHeader(name.clone()));
        }

        if name.as_str().starts_with(METADATA_PREFIX) {
            validate_metadata_key(name.as_str())?;
            validate_metadata_value(bytes)?;
        }
    }

    for name in SINGLE_VALUED_HEADERS {
        let mut values = headers.get_all(*name).iter();
        if values.next().is_some() && values.next().is_some() {
            return Err(WireReject::DuplicateSingleValuedHeader(name));
        }
    }

    Ok(())
}
