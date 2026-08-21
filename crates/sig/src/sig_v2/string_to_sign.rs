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

//! SigV2's six-line string-to-sign, and the sub-resource set that decides what it covers.
//!
//! Responsible for: [`INCLUDED_QUERY`] (botocore's `QSAOfInterest`, stored sorted), the
//! `CanonicalizedAmzHeaders` and `CanonicalizedResource` blocks, the `{Date}` slot in both SigV2
//! locations, and the HMAC-SHA1 that turns the result into a [`Signature`].
//! NOT responsible for: parsing the `Authorization` header or the presigned parameters (that is
//! [`super`]), clock skew, privileged-operation refusal or duplicate signature parameters (that is
//! [`crate::SecurityFloor`], H1/H3/H6), the virtual-host bucket determination itself (P4-01 — this
//! module consumes the answer), or comparing anything ([`Signature::ct_verify`] is the only
//! comparison in this crate).
//! Upstream: [`crate::RawQuery`], `http::HeaderMap`, [`crate::SecretBytes`]. Downstream:
//! [`super::SigV2Policy`] and P2-06's verifier wiring.

use http::Method;
use http::header::{CONTENT_TYPE, DATE, HeaderMap, HeaderName};

use crate::contracts::{SIGV2_EMPTY_DATE_ON_AMZ_DATE, SIGV2_INCLUDED_QUERY, SIGV2_QUERY_NOT_COVERED};
use crate::query::RawQuery;
use crate::secret::SecretBytes;
use crate::signature::{CtBytes, Signature};
use crate::signed_headers::AMZ_HEADER_PREFIX;
use crate::verdict::AuthError;

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Copy)]
struct CanonicalizationPolicy {
    included_query: bool,
    empty_date_on_amz_date: bool,
    query_not_covered: bool,
}

const CLIENT_POLICY: CanonicalizationPolicy = CanonicalizationPolicy {
    included_query: true,
    empty_date_on_amz_date: true,
    query_not_covered: true,
};

const VERIFICATION_POLICY: CanonicalizationPolicy = CanonicalizationPolicy {
    included_query: SIGV2_INCLUDED_QUERY,
    empty_date_on_amz_date: SIGV2_EMPTY_DATE_ON_AMZ_DATE,
    query_not_covered: SIGV2_QUERY_NOT_COVERED,
};

/// The `Content-MD5` header, lowercased. `http::header` has no constant for it.
const CONTENT_MD5: HeaderName = HeaderName::from_static("content-md5");
/// The `x-amz-date` header, whose presence empties the `{Date}` slot.
const X_AMZ_DATE: HeaderName = HeaderName::from_static("x-amz-date");
/// SigV2's presigned expiry parameter: an **absolute** Unix second, not a window.
pub const SIGV2_EXPIRES_PARAM: &str = "Expires";

/// The query parameters SigV2 covers, in strict ascending byte order.
///
/// # Where this list comes from
///
/// It is re-derived from botocore's `HmacV1Auth.QSAOfInterest` (`botocore/auth.py`, consumed by
/// `canonical_resource`), which is the implementation AWS's own SDKs sign with. botocore writes 36
/// literals with `requestPayment` appearing twice, so the set has 35 members; it is unsorted
/// there, and is stored sorted here because the append loop below walks it in order to decide the
/// `?`/`&` separators.
///
/// # Why the exact membership matters
///
/// A missing entry is not a cosmetic gap. The sub-resource is then absent from
/// `CanonicalizedResource`, so this gateway computes a different string-to-sign than the client
/// did, and every correctly-signed request to that sub-resource is answered `SignatureDoesNotMatch`
/// (the shape of s3s#517, where 14 entries were missing at once). Adding an entry AWS does not
/// sign breaks the same way, in the same direction: `encryption` is deliberately **not** here,
/// because botocore does not sign it and covering it would reject correctly-signed requests to
/// `?encryption`.
///
/// Any future S3 sub-resource must be added here **and** kept in ascending order; `c-sig-0530`
/// asserts the order pair by pair and `c-sig-0531` asserts the membership.
pub const INCLUDED_QUERY: [&str; 35] = [
    "accelerate",
    "acl",
    "analytics",
    "cors",
    "defaultObjectAcl",
    "delete",
    "inventory",
    "lifecycle",
    "location",
    "logging",
    "metrics",
    "notification",
    "object-lock",
    "partNumber",
    "policy",
    "replication",
    "requestPayment",
    "response-cache-control",
    "response-content-disposition",
    "response-content-encoding",
    "response-content-language",
    "response-content-type",
    "response-expires",
    "restore",
    "select",
    "select-type",
    "storageClass",
    "tagging",
    "torrent",
    "uploadId",
    "uploads",
    "versionId",
    "versioning",
    "versions",
    "website",
];

/// Where a SigV2 signature travels, which is also what goes in the `{Date}` slot.
///
/// The two locations differ in exactly one line of the string-to-sign, which is why they are one
/// enum rather than two builders: a second builder is a second place for the `x-amz-date` rule to
/// be forgotten.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigV2Mode {
    /// `Authorization: AWS <access-key>:<signature>`.
    HeaderAuth,
    /// `?AWSAccessKeyId=…&Expires=…&Signature=…`.
    PresignedUrl,
    /// Browser POST fields `AWSAccessKeyId`, `signature`, and `policy`.
    ///
    /// This location signs the base64 policy directly, so [`SigV2StringToSignSpec`] refuses it;
    /// use [`SigV2StringToSign::from_post_policy`] instead.
    PostPolicy,
}

/// A finished SigV2 string-to-sign, and the only thing that can be signed with HMAC-SHA1 here.
///
/// It is a distinct type from the SigV4 [`crate::StringToSign`] because the two are built from
/// different inputs and are never interchangeable: handing a SigV4 preimage to HMAC-SHA1 would
/// produce a signature that verifies against nothing, silently.
pub struct SigV2StringToSign {
    text: String,
}

impl SigV2StringToSign {
    /// Wraps the base64 POST policy, which is the complete SigV2 browser-POST preimage.
    #[must_use]
    pub fn from_post_policy(encoded_policy: &str) -> Self {
        Self {
            text: encoded_policy.to_owned(),
        }
    }

    /// The string-to-sign text, exactly as it is fed to the HMAC.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The bytes fed to the HMAC.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// Computes `HMAC-SHA1(secret, string-to-sign)` and wraps it as a 20-byte [`Signature`].
    ///
    /// This is a method rather than a free function so that the key and the preimage are named at
    /// one call site: the result has no `PartialEq` and no `Debug`, so the only thing a caller can
    /// do with it is [`Signature::ct_verify`].
    ///
    /// The base64 rendering a client sends is produced by
    /// [`crate::codec::encode_base64_exact`] with the **standard** alphabet and exact padding —
    /// the URL-safe, unpadded spelling is the rustfs#4456 defect and is rejected on the way in.
    #[must_use]
    pub fn sign(&self, key: &SecretBytes) -> Signature {
        // `Hmac` accepts a key of any length, so `new_from_slice` cannot fail here.
        let mut mac = <HmacSha1 as KeyInit>::new_from_slice(key.expose()).expect("HMAC-SHA1 accepts any key length");
        mac.update(self.as_bytes());
        Signature::HmacSha1(CtBytes::from_array(mac.finalize().into_bytes().into()))
    }
}

/// The inputs to one SigV2 string-to-sign.
///
/// Nothing is computed until [`SigV2StringToSignSpec::build`] runs, and the builder borrows rather
/// than owns, so a caller cannot hold a half-built preimage across a request boundary.
pub struct SigV2StringToSignSpec<'r> {
    mode: SigV2Mode,
    method: &'r Method,
    uri_path: &'r str,
    query: &'r RawQuery<'r>,
    headers: &'r HeaderMap,
    virtual_host_bucket: Option<&'r str>,
}

impl<'r> SigV2StringToSignSpec<'r> {
    /// Gathers the inputs.
    ///
    /// `uri_path` is the **already-encoded** path as it arrived: SigV2 signs the spelling on the
    /// wire, so re-encoding it here would produce a second spelling of one path and break every
    /// request carrying a percent escape.
    ///
    /// `virtual_host_bucket` is the bucket that a virtual-hosted-style `Host` resolved to, or
    /// `None` for path-style. Determining it is P4-01's job and deliberately not this module's: a
    /// second host parser is a second answer to "which bucket did this request address".
    #[must_use]
    pub fn new(
        mode: SigV2Mode,
        method: &'r Method,
        uri_path: &'r str,
        query: &'r RawQuery<'r>,
        headers: &'r HeaderMap,
        virtual_host_bucket: Option<&'r str>,
    ) -> Self {
        Self {
            mode,
            method,
            uri_path,
            query,
            headers,
            virtual_host_bucket,
        }
    }

    /// Builds the six-line string-to-sign.
    ///
    /// ```text
    /// {HTTP-Verb}\n{Content-MD5}\n{Content-Type}\n{Date}\n{CanonicalizedAmzHeaders}{CanonicalizedResource}
    /// ```
    ///
    /// Each `CanonicalizedAmzHeaders` line carries its own trailing newline, so the block is empty
    /// when no `x-amz-*` header is present and the resource follows the `{Date}` line directly.
    ///
    /// # Errors
    ///
    /// * [`AuthError::AuthorizationHeaderMalformed`] if `Content-MD5`, `Content-Type` or `Date`
    ///   arrived more than once, if any signed header value is not UTF-8, if a sub-resource
    ///   appeared twice or carries a malformed percent escape, or if a virtual-host bucket was
    ///   supplied as an empty string.
    /// * [`AuthError::AuthorizationQueryParametersError`] in [`SigV2Mode::PresignedUrl`] when
    ///   `Expires` is missing, repeated, or not a strict unsigned decimal.
    pub fn build(&self) -> Result<SigV2StringToSign, AuthError> {
        self.build_with(CLIENT_POLICY)
    }

    /// Builds the server-side string-to-sign from the generated protocol contracts.
    ///
    /// The ordinary [`Self::build`] remains the AWS client baseline. Keeping these entry points
    /// distinct lets the conformance mutation runner flip one verifier rule without teaching the
    /// client signer the same defect and producing a false green round trip.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::build`].
    pub fn build_for_verification(&self) -> Result<SigV2StringToSign, AuthError> {
        self.build_with(VERIFICATION_POLICY)
    }

    fn build_with(&self, policy: CanonicalizationPolicy) -> Result<SigV2StringToSign, AuthError> {
        let content_md5 = single_header(self.headers, &CONTENT_MD5)?;
        let content_type = single_header(self.headers, &CONTENT_TYPE)?;
        let date = self.date_slot(policy)?;
        let amz_headers = self.canonicalized_amz_headers()?;
        let resource = self.canonicalized_resource(policy)?;

        let mut text = String::with_capacity(
            self.method.as_str().len()
                + content_md5.len()
                + content_type.len()
                + date.len()
                + amz_headers.len()
                + resource.len()
                + 4,
        );
        text.push_str(self.method.as_str());
        text.push('\n');
        text.push_str(content_md5);
        text.push('\n');
        text.push_str(content_type);
        text.push('\n');
        text.push_str(&date);
        text.push('\n');
        text.push_str(&amz_headers);
        text.push_str(&resource);
        Ok(SigV2StringToSign { text })
    }

    /// The `{Date}` slot, which is the one line the two locations disagree about.
    ///
    /// Header authentication: **the empty string whenever an `x-amz-date` header is present** —
    /// not the `Date` header's value and not `x-amz-date`'s own. `x-amz-date` still appears in the
    /// `CanonicalizedAmzHeaders` block, which is what actually binds the timestamp. Missing this
    /// rule fails every client that sends `x-amz-date`, which is most of them.
    ///
    /// Presigned: the `Expires` query parameter verbatim — an absolute Unix second.
    fn date_slot(&self, policy: CanonicalizationPolicy) -> Result<String, AuthError> {
        match self.mode {
            SigV2Mode::HeaderAuth => {
                if policy.empty_date_on_amz_date && self.headers.contains_key(&X_AMZ_DATE) {
                    return Ok(String::new());
                }
                Ok(single_header(self.headers, &DATE)?.to_owned())
            }
            SigV2Mode::PresignedUrl => {
                let raw = self
                    .query
                    .decoded_value(SIGV2_EXPIRES_PARAM)
                    .map_err(|_| AuthError::AuthorizationQueryParametersError)?
                    .ok_or(AuthError::AuthorizationQueryParametersError)?;
                // Syntax only. The seven-day ceiling and the expiry instant need a clock, and live
                // in `super::parse_presigned_expires`; rejecting the syntax here means no malformed
                // spelling ever reaches the HMAC.
                super::parse_expires_digits(&raw)?;
                Ok(raw)
            }
            SigV2Mode::PostPolicy => Err(AuthError::AuthorizationHeaderMalformed),
        }
    }

    /// The `x-amz-*` block: lowercase names, ascending, repeats trimmed and comma-joined.
    ///
    /// `http::HeaderName` is lowercase by construction, so the case rule is enforced by the type
    /// rather than by a normalisation step that could be skipped. Values are joined with a bare
    /// comma — a comma-space is a different string and a different signature.
    fn canonicalized_amz_headers(&self) -> Result<String, AuthError> {
        let mut lines: Vec<(&str, String)> = Vec::new();
        for name in self.headers.keys() {
            if !name.as_str().starts_with(AMZ_HEADER_PREFIX) {
                continue;
            }
            let mut joined = String::new();
            for (index, value) in self.headers.get_all(name).iter().enumerate() {
                let text = value.to_str().map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
                if index > 0 {
                    joined.push(',');
                }
                joined.push_str(text.trim_matches([' ', '\t']));
            }
            lines.push((name.as_str(), joined));
        }
        lines.sort_unstable_by(|left, right| left.0.cmp(right.0));

        let mut out = String::new();
        for (name, value) in lines {
            out.push_str(name);
            out.push(':');
            out.push_str(&value);
            out.push('\n');
        }
        Ok(out)
    }

    /// The `CanonicalizedResource` block: virtual-host bucket, path, then covered sub-resources.
    ///
    /// The sub-resources are walked in [`INCLUDED_QUERY`] order rather than in query order, so the
    /// result does not depend on how the client spelled the URL. A parameter with no value is
    /// written as the bare key: `?acl`, never `?acl=`.
    ///
    /// **Everything not in [`INCLUDED_QUERY`] is absent from the signature.** That is SigV2's own
    /// weakness, recorded in `docs/security-model.md`, and the second reason SigV2 presigned URLs
    /// are refused unless a deployment opts in.
    ///
    /// A second SigV2 weakness lives here too, and is pinned by `c-sig-0556`: values are
    /// percent-decoded before they are written, and this block's own separator is `&`, so
    /// `?acl=x%26versionId%3Dy` and `?acl=x&versionId=y` canonicalise to one string. botocore
    /// computes the same collision, so closing it unilaterally would reject requests AWS's own
    /// SDK signs. Both facts are recorded in `docs/security-model.md`.
    fn canonicalized_resource(&self, policy: CanonicalizationPolicy) -> Result<String, AuthError> {
        let mut out = String::new();
        if let Some(bucket) = self.virtual_host_bucket {
            if bucket.is_empty() {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            out.push('/');
            out.push_str(bucket);
        }
        out.push_str(self.uri_path);

        if policy.included_query {
            let mut separator = '?';
            for name in INCLUDED_QUERY {
                let Some(value) = self.query.decoded_value(name)? else {
                    continue;
                };
                out.push(separator);
                separator = '&';
                out.push_str(name);
                if !value.is_empty() {
                    out.push('=');
                    out.push_str(&value);
                }
            }
            if !policy.query_not_covered {
                for (name, value) in self.uncovered_query_pairs()? {
                    out.push(separator);
                    separator = '&';
                    out.push_str(&name);
                    if let Some(value) = value {
                        out.push('=');
                        out.push_str(&value);
                    }
                }
            }
        }
        Ok(out)
    }

    fn uncovered_query_pairs(&self) -> Result<Vec<(String, Option<String>)>, AuthError> {
        let mut pairs: Vec<(String, Option<String>)> = Vec::new();
        for (name, value) in self.query.decoded_pairs()? {
            if INCLUDED_QUERY.contains(&name.as_str())
                || matches!(name.as_str(), "AWSAccessKeyId" | SIGV2_EXPIRES_PARAM | "Signature")
            {
                continue;
            }
            if pairs.iter().any(|(existing, _)| existing.eq(&name)) {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            pairs.push((name, value));
        }
        pairs.sort_unstable();
        Ok(pairs)
    }
}

/// Reads a header that may appear at most once.
///
/// A repeated `Date` or `Content-Type` has no canonical spelling — joining them and picking one
/// are both defensible, which is exactly why neither may be chosen silently.
fn single_header<'h>(headers: &'h HeaderMap, name: &HeaderName) -> Result<&'h str, AuthError> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok("");
    };
    if values.next().is_some() {
        return Err(AuthError::AuthorizationHeaderMalformed);
    }
    first.to_str().map_err(|_| AuthError::AuthorizationHeaderMalformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;

    /// Negative: the constant is sorted, so the `?`/`&` walk below is meaningful.
    #[test]
    fn the_covered_set_is_sorted_and_complete() {
        assert_eq!(INCLUDED_QUERY.len(), 35);
        for pair in INCLUDED_QUERY.windows(2) {
            assert!(pair[0] < pair[1], "{} must sort before {}", pair[0], pair[1]);
        }
    }

    /// Negative: an empty virtual-host bucket is refused rather than written as a bare slash.
    #[test]
    fn an_empty_virtual_host_bucket_is_refused() {
        let map = HeaderMap::new();
        let query = RawQuery::new("");
        let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &Method::GET, "/o", &query, &map, Some(""));
        assert_eq!(spec.build().err(), Some(AuthError::AuthorizationHeaderMalformed));
    }

    /// Negative: a malformed percent escape in a covered sub-resource is refused, not passed
    /// through — `%zz` surviving unchanged is how one value gains two spellings.
    #[test]
    fn a_malformed_escape_in_a_subresource_is_refused() {
        let mut map = HeaderMap::new();
        map.append(DATE, HeaderValue::from_static("d"));
        let query = RawQuery::new("versionId=%zz");
        let spec = SigV2StringToSignSpec::new(SigV2Mode::HeaderAuth, &Method::GET, "/o", &query, &map, None);
        assert_eq!(spec.build().err(), Some(AuthError::AuthorizationHeaderMalformed));
    }
}
