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

//! The canonical request and the string-to-sign, built byte-exactly and twice when necessary.
//!
//! Responsible for: [`UriPathCandidates`] and the two-path fallback, [`CanonicalRequestSpec`] and
//! the [`CanonicalCandidates`] iterator it produces, [`CanonicalRequest`], [`StringToSign`], and
//! [`SignatureMismatchDetail`] — the intermediate results AWS echoes in a `SignatureDoesNotMatch`
//! body and that no other implementation makes visible.
//! NOT responsible for: key derivation and the HMAC itself ([`crate::derive`]), clock skew,
//! expiry and the scope cross-check (P2-04), presigned-only rules (P2-05), SigV2 (P2-06). It is a
//! pure function of the request bytes: no I/O, no clock, no store handle, nothing `async`.
//! Upstream: [`crate::host`], [`crate::query`], [`crate::signed_headers`], [`crate::parse`],
//! [`crate::mode`]. Downstream: [`crate::derive`] and P2-04's authentication stage.
//!
//! # The eight construction rules, and the defect each one answers
//!
//! | Rule | What it says | Why |
//! |---|---|---|
//! | R1 | The URI path is encoded **once**. | S3, alone among AWS services, does not double-encode it. A double pass turns `arn%3A` into `arn%253A` and no S3 client signs that (s3s#13). |
//! | R2 | Two path candidates: the decoded-then-re-encoded spelling first, the raw spelling second. | A reverse proxy or a tunnel rewrites the encoding form in flight, so the bytes the client signed are not always the bytes that arrive (s3s#589). |
//! | R3 | Header values are trimmed, and runs of whitespace collapse to one space. | Metadata containing two consecutive spaces otherwise fails verification (s3s#393). |
//! | R4 | Repeated headers join with `,`, in arrival order. | A header sent more than once has one canonical line, not several (s3s#408). |
//! | R5 | The query is rebuilt from the raw bytes; `+` is a plus. | See [`crate::query`] — the alternative produces one signature for two different URIs. |
//! | R6 | Every parameter that arrived is in the canonical query, minus `X-Amz-Signature`. | An ignored parameter is an unsigned instruction. |
//! | R7 | Headers come from the client's `SignedHeaders` allow-list, never from a deny-list. | See [`crate::signed_headers`]. |
//! | R8 | The payload line is the client's own token, reproduced verbatim. | `Base64Sha256` and `ExactSha256` carry the same digest and sign different strings (s3s#631). |
//!
//! # Why the intermediate results are types rather than locals
//!
//! Real S3 returns the canonical request and the string-to-sign inside a `SignatureDoesNotMatch`
//! body, and every SDK author has debugged against that. An implementation whose intermediates are
//! private locals cannot reproduce the behaviour and cannot be debugged from the outside at all —
//! measured on `aws-sigv4` 1.5.1, where both types are `pub(crate)`. They are public here, and
//! [`SignatureMismatchDetail`] gates whether they reach a response body, because a canonical
//! request contains header values and one of those may be an SSE-C key.

use core::fmt;

use http::Method;
use http::header::{HOST, HeaderMap, HeaderName};
use sha2::{Digest, Sha256};
use smallvec::SmallVec;

use crate::codec::encode_hex_lower;
use crate::host::RawHost;
use crate::mode::CanonicalPayloadToken;
use crate::parse::{AmzDate, CredentialScope};
use crate::query::{QueryExclusion, RawQuery, percent_decode, percent_encode};
use crate::scheme::ALGORITHM_SIGV4;
use crate::signed_headers::SignedHeaderSet;
use crate::verdict::AuthError;

/// Which spelling of the URI path a canonical request was built from.
///
/// Reported alongside every [`CanonicalRequest`] so that an operator can tell "the client and the
/// gateway agree" from "they agree only after undoing a proxy's re-encoding" — the second is a
/// working request and a deployment problem, and the two should not look identical in a log.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PathCandidate {
    /// The path percent-decoded and re-encoded once, per segment. Tried first.
    Decoded,
    /// The path exactly as it arrived on the wire. Tried only if the first candidate failed.
    Raw,
}

impl fmt::Display for PathCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Decoded => "decoded",
            Self::Raw => "raw",
        })
    }
}

/// The one or two URI-path spellings a request has to be verified against.
///
/// The fallback is not a workaround for a defect in this crate. Between the client and the gateway
/// there may be a reverse proxy, an ingress controller or a tunnel, and several of them re-spell
/// percent-escapes in transit — the same object key arrives encoded differently from the way it was
/// signed. Verifying only one spelling makes those deployments fail every request; verifying an
/// unbounded set of spellings would be a bypass. Two, named, in a fixed order, is the whole
/// permitted set.
///
/// When the two spellings are identical — the common case — only one candidate exists, so a
/// request never gets two chances at the same string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UriPathCandidates {
    decoded: String,
    raw: String,
}

impl UriPathCandidates {
    /// Builds both spellings from the path exactly as it arrived.
    ///
    /// Pass the path component only, without query. An empty path becomes `/`, which is what a
    /// signer emits for a request against the service root.
    ///
    /// The first candidate is built per segment: the path is split on `/`, each segment is
    /// percent-decoded and re-encoded once, and the segments are rejoined. Splitting first is what
    /// keeps an encoded slash inside a key (`%2F`) from decoding into a path separator and
    /// silently restructuring the request.
    ///
    /// No normalisation happens: `/./` stays `/./` and `/a/b/../..` keeps its dot segments. S3
    /// signs the path it was given, and collapsing dot segments here would make two different
    /// requests canonicalise to one.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] for a malformed percent escape, or for a
    /// control character in the path — a byte that could otherwise end the canonical request's
    /// line early and let a client dictate the rest of the string being signed.
    pub fn new(raw_path: &str) -> Result<Self, AuthError> {
        let raw = if raw_path.is_empty() { "/" } else { raw_path };
        if raw.chars().any(char::is_control) {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }

        let mut decoded = String::with_capacity(raw.len());
        for (index, segment) in raw.split('/').enumerate() {
            if index > 0 {
                decoded.push('/');
            }
            decoded.push_str(&percent_encode(&percent_decode(segment)?));
        }

        Ok(Self {
            decoded,
            raw: raw.to_owned(),
        })
    }

    /// The decoded-then-re-encoded spelling. Tried first.
    #[must_use]
    pub fn decoded(&self) -> &str {
        &self.decoded
    }

    /// The wire spelling. Tried second, and only when it differs from the first.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Whether both spellings are the same string, so that only one candidate exists.
    #[must_use]
    pub fn is_single(&self) -> bool {
        self.decoded == self.raw
    }

    fn order(&self) -> SmallVec<[PathCandidate; 2]> {
        if self.is_single() {
            SmallVec::from_slice(&[PathCandidate::Decoded])
        } else {
            SmallVec::from_slice(&[PathCandidate::Decoded, PathCandidate::Raw])
        }
    }

    fn path_for(&self, candidate: PathCandidate) -> &str {
        match candidate {
            PathCandidate::Decoded => &self.decoded,
            PathCandidate::Raw => &self.raw,
        }
    }
}

/// Everything a canonical request is built from, gathered so it can be built more than once.
///
/// The host parameter is a [`RawHost`] and nothing else will do. A resolver's normalised value —
/// lowercased, default port stripped, trailing dot removed — cannot be passed here, which is what
/// stops one signature from being valid for four spellings of one host.
pub struct CanonicalRequestSpec<'r> {
    method: &'r Method,
    paths: &'r UriPathCandidates,
    query: &'r RawQuery<'r>,
    headers: &'r HeaderMap,
    signed: &'r SignedHeaderSet,
    host: &'r RawHost,
    payload_token: CanonicalPayloadToken,
    exclusion: QueryExclusion,
}

impl<'r> CanonicalRequestSpec<'r> {
    /// Gathers the inputs. Nothing is computed yet; [`CanonicalRequestSpec::candidates`] does that.
    #[must_use]
    pub fn new(
        method: &'r Method,
        paths: &'r UriPathCandidates,
        query: &'r RawQuery<'r>,
        headers: &'r HeaderMap,
        signed: &'r SignedHeaderSet,
        host: &'r RawHost,
        payload_token: CanonicalPayloadToken,
    ) -> Self {
        Self {
            method,
            paths,
            query,
            headers,
            signed,
            host,
            payload_token,
            exclusion: QueryExclusion::None,
        }
    }

    /// Switches to the presigned form, in which `X-Amz-Signature` leaves the canonical query.
    ///
    /// That single parameter is the whole difference. Everything else the client put in the query
    /// stays in, which is why appending `&versionId=…` to somebody else's presigned URL fails.
    #[must_use]
    pub fn presigned(mut self) -> Self {
        self.exclusion = QueryExclusion::PresignedSignature;
        self
    }

    /// Builds the canonical requests to try, in order.
    ///
    /// Everything except the URI-path line is computed once here, so the second candidate costs one
    /// string concatenation rather than a second full canonicalisation.
    ///
    /// # Errors
    ///
    /// [`AuthError::AuthorizationHeaderMalformed`] if the query cannot be canonicalised, or if a
    /// signed header holds bytes that are not valid UTF-8. [`AuthError::SignatureDoesNotMatch`] if
    /// a header named in the allow-list has vanished from the map between enforcement and here.
    pub fn candidates(&self) -> Result<CanonicalCandidates, AuthError> {
        let canonical_query = self.query.canonical(self.exclusion)?;

        let mut tail = String::new();
        tail.push('\n');
        tail.push_str(&canonical_query);
        tail.push('\n');
        for name in self.signed.names() {
            tail.push_str(name.as_str());
            tail.push(':');
            tail.push_str(&self.canonical_value(name)?);
            tail.push('\n');
        }
        tail.push('\n');
        tail.push_str(&self.signed.canonical_list());
        tail.push('\n');
        tail.push_str(self.payload_token.as_str());

        Ok(CanonicalCandidates {
            method: self.method.as_str().to_owned(),
            paths: self.paths.clone(),
            order: self.paths.order(),
            tail,
            next: 0,
        })
    }

    /// The canonical value of one signed header.
    ///
    /// `host` is answered from the [`RawHost`], never from the header map: an HTTP/2 request need
    /// not carry a `host` header at all, and where it does, the map's copy has already been
    /// cross-checked against the authority by [`crate::effective_host`]. Reading the map here would
    /// be a second derivation of the one value that must have exactly one.
    fn canonical_value(&self, name: &HeaderName) -> Result<String, AuthError> {
        if name == HOST {
            return Ok(self.host.as_str().to_owned());
        }
        let mut out = String::new();
        let mut seen = false;
        for value in self.headers.get_all(name) {
            if seen {
                out.push(',');
            }
            seen = true;
            let text = core::str::from_utf8(value.as_bytes()).map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
            out.push_str(&collapse_whitespace(text));
        }
        if !seen {
            return Err(AuthError::SignatureDoesNotMatch);
        }
        Ok(out)
    }
}

/// Trims a header value and collapses every run of whitespace inside it to a single space (R3).
///
/// Collapsing is unconditional, quotes included: the AWS signing test suite's
/// `get-header-value-trim` case sends `"a     b    c"` and expects `"a b c"`, so a quote-aware
/// implementation would disagree with every signer built against that suite. It also folds the
/// obsolete line-folding form (`get-header-value-multiline`), where a value continued across lines
/// canonicalises to one space-separated line.
fn collapse_whitespace(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut pending_space = false;
    for ch in value.trim_matches(|c: char| c.is_ascii_whitespace()).chars() {
        if ch.is_ascii_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
    }
    out
}

/// The canonical requests to verify against, in order: decoded spelling, then raw spelling.
///
/// Iterating yields one to two [`CanonicalRequest`] values. A verifier runs the full derivation and
/// the constant-time comparison for each, and rejects only after every candidate has failed —
/// which is also why the iterator is short and closed: "try spellings until one matches" is a
/// bypass as soon as the set is open-ended.
///
/// No `Debug`, for the same reason [`CanonicalRequest`] has none: it holds the canonicalised
/// header block, and one of those header values may be an SSE-C key.
#[derive(Clone)]
pub struct CanonicalCandidates {
    method: String,
    paths: UriPathCandidates,
    order: SmallVec<[PathCandidate; 2]>,
    tail: String,
    next: usize,
}

impl CanonicalCandidates {
    /// How many spellings will be tried. One or two.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Always `false`: there is always at least the decoded candidate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

impl Iterator for CanonicalCandidates {
    type Item = CanonicalRequest;

    fn next(&mut self) -> Option<Self::Item> {
        let candidate = *self.order.get(self.next)?;
        self.next += 1;
        let path = self.paths.path_for(candidate);
        let mut text = String::with_capacity(self.method.len() + path.len() + self.tail.len() + 1);
        text.push_str(&self.method);
        text.push('\n');
        text.push_str(path);
        text.push_str(&self.tail);
        Some(CanonicalRequest { text, candidate })
    }
}

/// One canonical request, as a byte-exact string.
///
/// It has **no `Debug`, no `Display` and no `PartialEq`**, and that is not symmetry with the
/// signature types — it is the same reason. A canonical request contains the values of every
/// signed header, and one of those headers may be
/// `x-amz-server-side-encryption-customer-key`. A derived `Debug` would put a customer's
/// encryption key into any log line that formats a verification failure. Reach for
/// [`CanonicalRequest::text`] deliberately, or hand the value to [`SignatureMismatchDetail`],
/// which knows when it may be rendered.
pub struct CanonicalRequest {
    text: String,
    candidate: PathCandidate,
}

impl CanonicalRequest {
    /// The canonical request text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Which path spelling produced it.
    #[must_use]
    pub const fn path_candidate(&self) -> PathCandidate {
        self.candidate
    }

    /// Lowercase hex SHA-256 of the canonical request — the last line of the string-to-sign.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        let digest: [u8; 32] = Sha256::digest(self.text.as_bytes()).into();
        encode_hex_lower(&digest)
    }

    /// Builds the string-to-sign.
    ///
    /// The scope line comes from the **client's** [`CredentialScope`], because the client signed
    /// its own scope string and the canonical form has to reproduce it. The scope that derives the
    /// *key* is a different value and a different type — see [`crate::VerifiedScope`]. Conflating
    /// the two is what makes a signature minted for another region or another service replay here.
    #[must_use]
    pub fn string_to_sign(&self, date: &AmzDate, scope: &CredentialScope) -> StringToSign {
        let mut text = String::with_capacity(96);
        text.push_str(ALGORITHM_SIGV4);
        text.push('\n');
        text.push_str(date.as_str());
        text.push('\n');
        text.push_str(&scope.scope_string());
        text.push('\n');
        text.push_str(&self.hash_hex());
        StringToSign { text }
    }
}

/// The string that is actually HMAC'd.
///
/// Unlike [`CanonicalRequest`] this carries no header values — only the algorithm, the timestamp,
/// the scope and a digest — so it has a `Debug` and is safe in a diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringToSign {
    text: String,
}

impl StringToSign {
    /// Wraps text that is already a string-to-sign.
    ///
    /// `#[cfg(test)]` and `pub(crate)`: the only legitimate producer is
    /// [`CanonicalRequest::string_to_sign`], and the one place that needs another is the crate's
    /// own fixture replaying published vectors whose scope names a service this gateway does not
    /// serve. Nothing compiled into a released binary can reach it.
    #[cfg(test)]
    pub(crate) fn from_text(text: String) -> Self {
        Self { text }
    }

    /// The string-to-sign text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The bytes fed to the final HMAC.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }
}

/// The intermediate results of a failed verification, and the gate on showing them.
///
/// Real S3 puts `CanonicalRequest` and `StringToSign` into a `SignatureDoesNotMatch` body, and SDK
/// authors rely on it. Reproducing that is a compatibility feature, but it is also an information
/// leak — the canonical request contains signed header values, SSE-C keys among them — so it is
/// off unless a deployment turns it on.
///
/// What is *never* in here, on or off: the expected signature. "Expected versus actual" in an
/// authentication error is a signing oracle, which is why [`crate::AuthError`] has no detail
/// fields at all and why this type is handed to the response layer separately rather than being
/// carried inside the error.
///
/// It has no `Debug` and no `Display`, so the only way to render it is to ask, and asking means
/// passing the deployment's answer.
pub struct SignatureMismatchDetail {
    canonical_request: String,
    string_to_sign: String,
}

impl SignatureMismatchDetail {
    /// Captures the two intermediates of one failed candidate.
    #[must_use]
    pub fn new(canonical_request: &CanonicalRequest, string_to_sign: &StringToSign) -> Self {
        Self {
            canonical_request: canonical_request.text().to_owned(),
            string_to_sign: string_to_sign.text().to_owned(),
        }
    }

    /// The canonical request. Available for structured `debug` logging regardless of the gate.
    #[must_use]
    pub fn canonical_request(&self) -> &str {
        &self.canonical_request
    }

    /// The string-to-sign. Available for structured `debug` logging regardless of the gate.
    #[must_use]
    pub fn string_to_sign(&self) -> &str {
        &self.string_to_sign
    }

    /// What may go into the HTTP response body.
    ///
    /// `None` unless `verbose` — the `verbose-signature-errors` configuration flag, which defaults
    /// to off. There is deliberately no `Default` route to the `true` case.
    #[must_use]
    pub fn for_response(&self, verbose: bool) -> Option<(&str, &str)> {
        verbose.then_some((self.canonical_request.as_str(), self.string_to_sign.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::PayloadMode;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            let name = HeaderName::from_bytes(name.as_bytes()).expect("test header name");
            map.append(name, value.parse().expect("test header value"));
        }
        map
    }

    fn host() -> RawHost {
        RawHost::from_host_header(b"example.amazonaws.com").expect("valid")
    }

    #[test]
    fn the_vanilla_canonical_request_is_byte_exact() {
        let map = headers(&[("x-amz-date", "20150830T123600Z")]);
        let signed = SignedHeaderSet::parse_and_enforce("host;x-amz-date", &map, None).expect("valid");
        let paths = UriPathCandidates::new("/").expect("valid");
        let query = RawQuery::new("");
        let host = host();
        let spec = CanonicalRequestSpec::new(
            &Method::GET,
            &paths,
            &query,
            &map,
            &signed,
            &host,
            PayloadMode::Empty.canonical_payload_token(),
        );
        let mut candidates = spec.candidates().expect("built");
        assert_eq!(candidates.len(), 1);
        let request = candidates.next().expect("one candidate");
        assert_eq!(
            request.text(),
            concat!(
                "GET\n",
                "/\n",
                "\n",
                "host:example.amazonaws.com\n",
                "x-amz-date:20150830T123600Z\n",
                "\n",
                "host;x-amz-date\n",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
        );
        assert_eq!(request.path_candidate(), PathCandidate::Decoded);
    }

    #[test]
    fn whitespace_is_trimmed_and_collapsed_including_inside_quotes() {
        assert_eq!(collapse_whitespace("  value1  "), "value1");
        assert_eq!(collapse_whitespace("\"a     b    c\""), "\"a b c\"");
        assert_eq!(collapse_whitespace("value1\n value2\n  value3"), "value1 value2 value3");
    }

    #[test]
    fn a_repeated_header_joins_with_commas_in_arrival_order() {
        let map = headers(&[
            ("my-header1", "value4"),
            ("my-header1", "value1"),
            ("my-header1", "value3"),
            ("x-amz-date", "20150830T123600Z"),
        ]);
        let signed = SignedHeaderSet::parse_and_enforce("host;my-header1;x-amz-date", &map, None).expect("valid");
        let paths = UriPathCandidates::new("/").expect("valid");
        let query = RawQuery::new("");
        let host = host();
        let spec = CanonicalRequestSpec::new(
            &Method::GET,
            &paths,
            &query,
            &map,
            &signed,
            &host,
            PayloadMode::Empty.canonical_payload_token(),
        );
        let request = spec.candidates().expect("built").next().expect("one");
        assert!(request.text().contains("my-header1:value4,value1,value3\n"));
    }

    #[test]
    fn a_proxy_rewritten_path_produces_two_candidates_in_a_fixed_order() {
        let paths = UriPathCandidates::new("/my key").expect("valid");
        assert_eq!(paths.decoded(), "/my%20key");
        assert_eq!(paths.raw(), "/my key");
        assert!(!paths.is_single());
        assert_eq!(paths.order().as_slice(), [PathCandidate::Decoded, PathCandidate::Raw]);
    }

    #[test]
    fn an_already_canonical_path_gets_exactly_one_candidate() {
        let paths = UriPathCandidates::new("/my%20key").expect("valid");
        assert!(paths.is_single());
        assert_eq!(paths.order().len(), 1);
    }

    #[test]
    fn dot_segments_and_encoded_slashes_survive_canonicalisation() {
        assert_eq!(UriPathCandidates::new("/./").expect("valid").decoded(), "/./");
        assert_eq!(UriPathCandidates::new("/a/b/../..").expect("valid").decoded(), "/a/b/../..");
        // An encoded slash stays inside its segment; decoding it into a separator would restructure
        // the request.
        assert_eq!(UriPathCandidates::new("/a%2Fb").expect("valid").decoded(), "/a%2Fb");
    }

    #[test]
    fn control_characters_and_bad_escapes_in_a_path_are_refused() {
        for bad in ["/a\nb", "/a\rb", "/a%zzb", "/a%2"] {
            assert!(UriPathCandidates::new(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn the_mismatch_detail_stays_out_of_the_response_unless_asked() {
        let map = headers(&[("x-amz-date", "20150830T123600Z")]);
        let signed = SignedHeaderSet::parse_and_enforce("host;x-amz-date", &map, None).expect("valid");
        let paths = UriPathCandidates::new("/").expect("valid");
        let query = RawQuery::new("");
        let host = host();
        let spec = CanonicalRequestSpec::new(
            &Method::GET,
            &paths,
            &query,
            &map,
            &signed,
            &host,
            PayloadMode::Empty.canonical_payload_token(),
        );
        let request = spec.candidates().expect("built").next().expect("one");
        let date = AmzDate::parse("20150830T123600Z").expect("valid");
        let scope = CredentialScope::parse("AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request").expect("valid");
        let detail = SignatureMismatchDetail::new(&request, &request.string_to_sign(&date, &scope));
        assert!(detail.for_response(false).is_none());
        assert!(detail.for_response(true).is_some());
        assert!(detail.canonical_request().starts_with("GET\n"));
    }
}
