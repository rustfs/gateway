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

//! The strict URI codec, and the canonical query string built with it.
//!
//! Responsible for: [`RawQuery`] (the query string exactly as it arrived), the canonical query
//! rebuild, [`QueryExclusion`] (the one parameter a presigned request is allowed to drop), and the
//! percent codec the canonical URI path also uses.
//! NOT responsible for: interpreting any parameter's meaning, presigned expiry, POST policy, or
//! routing. Nothing here knows what `?uploads` does — a canonical query is a byte string, and a
//! module that understood the parameters would eventually be tempted to skip one.
//! Upstream: [`crate::AuthError`]. Downstream: [`crate::canonical`], and P2-05's presigned rules.
//!
//! # Two rules that are not stylistic
//!
//! **`+` is a literal plus.** SigV4's canonical query is not `application/x-www-form-urlencoded`.
//! A decoder that turns `+` into a space makes `?prefix=a+b` and `?prefix=a%20b` — two different
//! URIs — produce the same signature. That is measured, not theoretical: `aws-sigv4` 1.5.1 parses
//! the query with `form_urlencoded::parse` and both spellings sign to the same value. Nothing in
//! this module treats `+` as anything but the byte `0x2B`.
//!
//! **Every parameter is rebuilt, and there is no allow-list.** The canonical query is
//! reconstructed from every parameter that arrived, minus [`QueryExclusion`]'s single documented
//! exception. Skipping a parameter the server does not recognise — a "harmless" one such as
//! `response-content-disposition`, or a `versionId` — is the most common real signature bypass,
//! because it lets an attacker append meaning to a request somebody else signed.

use crate::verdict::AuthError;

/// The unreserved set of RFC 3986, which SigV4 leaves unencoded: `A-Z a-z 0-9 - _ . ~`.
const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes strictly: a `%` must introduce exactly two hex digits, and `+` is a plus.
///
/// # Errors
///
/// [`AuthError::AuthorizationHeaderMalformed`] for a truncated or non-hex escape. Passing `%zz`
/// through unchanged — what the `percent-encoding` crate does — would give one byte string two
/// spellings, and a signature input may not have two spellings.
pub fn percent_decode(input: &str) -> Result<Vec<u8>, AuthError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte != b'%' {
            out.push(byte);
            index += 1;
            continue;
        }
        let hi = bytes
            .get(index + 1)
            .copied()
            .and_then(hex_value)
            .ok_or(AuthError::AuthorizationHeaderMalformed)?;
        let lo = bytes
            .get(index + 2)
            .copied()
            .and_then(hex_value)
            .ok_or(AuthError::AuthorizationHeaderMalformed)?;
        out.push((hi << 4) | lo);
        index += 3;
    }
    Ok(out)
}

/// Percent-encodes every byte outside the unreserved set, with uppercase hex digits.
///
/// This is the *single* encoding pass. S3 — alone among AWS services — does not encode the URI
/// path twice, and applying the pass twice turns `arn%3Aaws` into `arn%253Aaws`, which no S3
/// client ever signs. The two `double-*-encode` cases in the AWS signing test suite are what a
/// non-S3 service expects and are therefore negative controls here, not targets.
#[must_use]
pub fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        if is_unreserved(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
            out.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
        }
    }
    out
}

/// The query parameter a canonical query may leave out.
///
/// There are exactly two members and there will never be a third that names a business parameter.
/// The type exists so that "which parameters are skipped" is a closed enum in the signature path
/// rather than a predicate somebody can widen.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryExclusion {
    /// Nothing is excluded — the header-signed form.
    None,
    /// `X-Amz-Signature` is excluded, because it is the value being verified.
    ///
    /// The match is byte-exact and case-sensitive. A differently-cased `x-amz-signature` is a
    /// different parameter, stays in the canonical query, and therefore invalidates the signature —
    /// which is correct, because a case-insensitive exclusion would let a request carry two
    /// "signature" parameters and have both dropped.
    PresignedSignature,
}

/// The name a presigned request carries its signature under.
pub const X_AMZ_SIGNATURE: &str = "X-Amz-Signature";

impl QueryExclusion {
    fn excludes(self, decoded_key: &[u8]) -> bool {
        match self {
            Self::None => false,
            Self::PresignedSignature => decoded_key == X_AMZ_SIGNATURE.as_bytes(),
        }
    }
}

/// The query string exactly as it arrived, before any interpretation.
///
/// Borrowed rather than owned: the wire layer already holds the request, and copying the query
/// into the signature path is one more buffer that can drift from the one the router reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RawQuery<'q> {
    raw: &'q str,
}

impl<'q> RawQuery<'q> {
    /// Wraps a raw query string. Pass the value without the leading `?`; `None` becomes empty.
    #[must_use]
    pub const fn new(raw: &'q str) -> Self {
        Self { raw }
    }

    /// The raw text.
    #[must_use]
    pub const fn as_str(&self) -> &'q str {
        self.raw
    }

    /// Whether the request carried no query at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Rebuilds the canonical query string.
    ///
    /// Each parameter is percent-decoded and re-encoded once, so that the value the client signed
    /// and the value a proxy re-spelled canonicalise to the same bytes. Parameters are then sorted
    /// by encoded name, ties broken by encoded value, and joined with `&`. A parameter that
    /// arrived without a value is written `name=`, which is what a signer emits for `?acl`.
    ///
    /// # Errors
    ///
    /// * [`AuthError::AuthorizationHeaderMalformed`] for a malformed percent escape, an empty
    ///   parameter name, or an empty component (`a=1&&b=2`, or a trailing `&`). An empty component
    ///   has no canonical spelling — dropping it and keeping it are both defensible, which is
    ///   exactly why neither may be chosen silently.
    /// * [`AuthError::AuthorizationHeaderMalformed`] for the same parameter name twice. AWS's
    ///   canonical form sorts duplicates by value, but a server that accepts them has to decide
    ///   which one the operation reads, and "the signature covered both, the handler read one" is
    ///   the shape of a parameter-smuggling bypass (s3s#176).
    pub fn canonical(&self, exclusion: QueryExclusion) -> Result<String, AuthError> {
        if self.raw.is_empty() {
            return Ok(String::new());
        }

        let mut pairs: Vec<(String, String)> = Vec::new();
        for component in self.raw.split('&') {
            if component.is_empty() {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            let (raw_key, raw_value) = match component.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (component, None),
            };
            if raw_key.is_empty() {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            let decoded_key = percent_decode(raw_key)?;
            if exclusion.excludes(&decoded_key) {
                continue;
            }
            let key = percent_encode(&decoded_key);
            let value = match raw_value {
                Some(value) => percent_encode(&percent_decode(value)?),
                None => String::new(),
            };
            if pairs.iter().any(|(existing, _)| *existing == key) {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            pairs.push((key, value));
        }

        pairs.sort_unstable();

        let mut out = String::with_capacity(self.raw.len() + pairs.len());
        for (index, (key, value)) in pairs.iter().enumerate() {
            if index > 0 {
                out.push('&');
            }
            out.push_str(key);
            out.push('=');
            out.push_str(value);
        }
        Ok(out)
    }

    /// The raw, still-encoded value of one parameter, by exact name.
    ///
    /// Used by the presigned parser, which needs `X-Amz-Signature` and friends before a canonical
    /// query exists. The name comparison is byte-exact against the *decoded* parameter name.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] on a malformed escape, or if the parameter
    /// appears more than once.
    pub fn decoded_value(&self, name: &str) -> Result<Option<String>, AuthError> {
        let mut found: Option<String> = None;
        for component in self.raw.split('&') {
            if component.is_empty() {
                continue;
            }
            let (raw_key, raw_value) = match component.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (component, None),
            };
            if percent_decode(raw_key)? != name.as_bytes() {
                continue;
            }
            if found.is_some() {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            let decoded = percent_decode(raw_value.unwrap_or(""))?;
            found = Some(String::from_utf8(decoded).map_err(|_| AuthError::AuthorizationHeaderMalformed)?);
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plus_is_a_literal_plus_and_never_a_space() {
        let plus = RawQuery::new("prefix=a+b").canonical(QueryExclusion::None).expect("valid");
        let space = RawQuery::new("prefix=a%20b").canonical(QueryExclusion::None).expect("valid");
        assert_eq!(plus, "prefix=a%2Bb");
        assert_eq!(space, "prefix=a%20b");
        assert_ne!(plus, space);
    }

    #[test]
    fn parameters_sort_by_encoded_name() {
        let canonical = RawQuery::new("Param-3=Value3&Param=Value2&%E1%88%B4=Value1")
            .canonical(QueryExclusion::None)
            .expect("valid");
        assert_eq!(canonical, "%E1%88%B4=Value1&Param=Value2&Param-3=Value3");
    }

    #[test]
    fn a_valueless_parameter_is_written_with_a_trailing_equals() {
        assert_eq!(RawQuery::new("acl").canonical(QueryExclusion::None).expect("valid"), "acl=");
    }

    #[test]
    fn only_the_presigned_signature_may_be_excluded() {
        let query = RawQuery::new("X-Amz-Signature=deadbeef&versionId=7");
        assert_eq!(query.canonical(QueryExclusion::PresignedSignature).expect("valid"), "versionId=7");
        assert_eq!(
            query.canonical(QueryExclusion::None).expect("valid"),
            "X-Amz-Signature=deadbeef&versionId=7"
        );
    }

    #[test]
    fn malformed_and_ambiguous_queries_are_rejected() {
        for bad in ["prefix=%zz", "prefix=%2", "a=1&&b=2", "a=1&", "=novalue", "a=1&a=2"] {
            assert_eq!(
                RawQuery::new(bad).canonical(QueryExclusion::None),
                Err(AuthError::AuthorizationHeaderMalformed),
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn percent_encoding_is_a_single_pass() {
        assert_eq!(percent_encode(b"arn:aws:lambda"), "arn%3Aaws%3Alambda");
        let once = percent_encode(&percent_decode("arn%3Aaws").expect("valid"));
        assert_eq!(once, "arn%3Aaws");
    }
}
