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

//! The client half of SigV4: producing a signature, and then deliberately breaking one.
//!
//! Responsible for: [`SigV4Signer`] — header signing and presigned-URL signing — the request it
//! takes ([`SigningRequest`]), the request it produces ([`SignedRequest`]), the signed-header list
//! and the projection an under-signing client canonicalises over, and [`SignerError`].
//! NOT responsible for: canonicalisation, the signed-header rules, key derivation, the clock, the
//! scope cross-check or any comparison. Every one of those is reused verbatim from the
//! verification side of this crate; this module assembles them in the other direction and adds no
//! second opinion about what a canonical request is. If the two directions ever disagree, the
//! verification side is right by construction, because it is the only implementation. Three
//! neighbouring files carry the rest: `signer_material.rs` (credentials, scope, key cache),
//! `signer_chunked.rs` ([`ChunkSigner`]) and `signer_tamper.rs` ([`Tamper`]).
//! Upstream: [`crate::canonical`], [`crate::signed_headers`], [`crate::derive`], [`crate::parse`],
//! [`crate::query`], [`crate::mode`], [`crate::clock`]. Downstream: the conformance runner, which
//! declares `sign.mode` on every case, and this crate's own round-trip tests.
//!
//! # The one rule this module may not break
//!
//! **Nothing here weakens verification.** Concretely, three properties are preserved:
//!
//! 1. There is no public route from anything in this module to a [`crate::VerifiedScope`] or a
//!    [`crate::SigningKey`]. [`SigningScope`] converts to a `VerifiedScope` through a `pub(super)`
//!    method, and the derived key lives inside [`SigV4Signer`] and [`ChunkSigner`] and is never
//!    handed out. Were either public, `signing_key(secret, client_chosen_scope)` would become
//!    expressible from outside the crate and [`crate::enforce_scope`] would stop being the only
//!    producer — which is the replay that [`crate::derive`]'s whole shape exists to stop.
//! 2. The canonical request always comes from [`crate::CanonicalRequestSpec`], and the signed
//!    header list always from [`crate::SignedHeaderSet::parse_and_enforce`]. A deliberately
//!    under-signed request is produced by canonicalising over a **projection** of the header map
//!    — which is exactly what an under-signing client does on the wire — never by relaxing a rule.
//! 3. The presigned ceiling is [`crate::MAX_PRESIGNED_EXPIRY_SECONDS`], imported from
//!    [`crate::clock`]. There is no second constant here.
//!
//! # Why a signer belongs in this crate at all
//!
//! A verifier tested only against vectors it also produced is a tautology. The strongest available
//! evidence is a round trip: sign a request here, hand the bytes to the verification path, and
//! require it to pass — and then tamper with exactly one canonical component and require it to
//! fail. That loop needs a signer, and a signer that shares the canonicaliser is the only kind
//! whose agreement means anything.

use std::collections::BTreeSet;

use http::Method;
use http::header::{HOST, HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway_http::RawHost;

use crate::canonical::{CanonicalRequestSpec, UriPathCandidates};
use crate::clock::MAX_PRESIGNED_EXPIRY_SECONDS;
use crate::codec::encode_hex_lower;
use crate::derive::calculate_signature;
use crate::error::SigParseError;
use crate::floor::{X_AMZ_DATE_HEADER, X_AMZ_EXPIRES, X_AMZ_SECURITY_TOKEN, X_AMZ_SECURITY_TOKEN_HEADER};
use crate::mode::{PayloadMode, TrailerSet};
use crate::parse::{AmzDate, X_AMZ_ALGORITHM, X_AMZ_CREDENTIAL, X_AMZ_DATE, X_AMZ_SIGNED_HEADERS};
use crate::query::{QueryExclusion, RawQuery, X_AMZ_SIGNATURE, percent_encode};
use crate::scheme::{ALGORITHM_SIGV4, SigLocation};
use crate::secret::SigningKey;
use crate::signature::Signature;
use crate::signed_headers::SignedHeaderSet;
use crate::verdict::AuthError;
use crate::verifier::AUTHORIZATION_HEADER;

// The parameter and header names a signer mints are the verification side's own constants,
// imported and never restated: `X_AMZ_EXPIRES`, `X_AMZ_SECURITY_TOKEN`, `X_AMZ_DATE_HEADER` and
// `X_AMZ_SECURITY_TOKEN_HEADER` come from `crate::floor`, `AUTHORIZATION_HEADER` from
// `crate::verifier`, and the four `X-Amz-*` query names from `crate::parse` / `crate::query`. Two
// spellings of one signed name is the whole class of defect this crate exists to close, and a
// signer that owned its own copy would be where the second spelling appeared.

/// The `x-amz-content-sha256` header name, lowercased.
///
/// Named here because nothing on the verification side publishes it: [`crate::floor`] holds it in
/// a private duplicate-detection list, and [`PayloadMode::parse`] takes the *value*, not the name.
pub const X_AMZ_CONTENT_SHA256_HEADER_NAME: &str = "x-amz-content-sha256";
/// The `x-amz-decoded-content-length` header name, lowercased.
pub const X_AMZ_DECODED_CONTENT_LENGTH_HEADER_NAME: &str = "x-amz-decoded-content-length";
/// The `x-amz-trailer` header name, lowercased.
pub const X_AMZ_TRAILER_HEADER_NAME: &str = "x-amz-trailer";

#[path = "signer_chunked.rs"]
mod chunked;
#[path = "signer_material.rs"]
mod material;
#[path = "signer_tamper.rs"]
mod tamper;

pub use chunked::{CHUNK_ALGORITHM, CHUNK_SIGNATURE_EXTENSION, ChunkSigner, TRAILER_ALGORITHM};
use material::SigningKeyCache;
pub use material::{SigningCredentials, SigningScope};
pub use tamper::{Tamper, TamperComponent};

/// Every query parameter a SigV4 presigned URL mints for itself.
///
/// A caller's own query may not contain any of them: the duplicate rule
/// ([`crate::enforce_no_duplicate_sig_params`]) would refuse the result, and silently overwriting
/// the caller's value would hide that.
const MINTED_QUERY_PARAMS: [&str; 7] = [
    X_AMZ_ALGORITHM,
    X_AMZ_CREDENTIAL,
    X_AMZ_DATE,
    X_AMZ_EXPIRES,
    X_AMZ_SIGNED_HEADERS,
    X_AMZ_SIGNATURE,
    X_AMZ_SECURITY_TOKEN,
];

/// Why a request could not be signed.
///
/// Distinct from [`AuthError`], which is what a *server* answers a client with. Everything here is
/// a fault in the caller's own signing request, so nothing in it is reachable from a response.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignerError {
    /// The request cannot be canonicalised, or the signed-header list does not satisfy the six
    /// completeness rules. The wrapped value is the verification side's own verdict, unaltered.
    Canonical(AuthError),
    /// A component of the credential scope is not well formed.
    Scope(SigParseError),
    /// `X-Amz-Expires` was outside `1..=`[`MAX_PRESIGNED_EXPIRY_SECONDS`].
    ExpiryOutOfRange,
    /// The caller's query already carries a parameter the signer mints.
    SigningParameterAlreadyPresent,
    /// A streaming payload mode was selected without `x-amz-decoded-content-length`.
    DecodedContentLengthRequired,
    /// `x-amz-decoded-content-length` was supplied under a non-streaming payload mode, where the
    /// header is forbidden rather than merely unnecessary.
    DecodedContentLengthNotAllowed,
    /// A header name or value could not be represented on the wire.
    UnrepresentableHeader,
    /// The tamper description needs a `new_value` for this component and did not carry one.
    TamperNewValueRequired,
    /// The tamper description needs a `target` for this component and did not carry one.
    TamperTargetRequired,
    /// The component the tamper names is not present in the signed request.
    TamperComponentAbsent,
    /// A signature that is not the 32-byte HMAC-SHA256 form reached the SigV4 renderer.
    UnsupportedSignatureAlgorithm,
}

impl core::fmt::Display for SignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Canonical(_) => "the request cannot be canonicalised, or its signed-header list is incomplete",
            Self::Scope(_) => "the credential scope is not well formed",
            Self::ExpiryOutOfRange => "X-Amz-Expires must be between 1 and 604800 seconds",
            Self::SigningParameterAlreadyPresent => "the query already carries a SigV4 signing parameter",
            Self::DecodedContentLengthRequired => "a streaming payload mode requires x-amz-decoded-content-length",
            Self::DecodedContentLengthNotAllowed => "x-amz-decoded-content-length is forbidden outside the streaming modes",
            Self::UnrepresentableHeader => "a header name or value cannot be represented on the wire",
            Self::TamperNewValueRequired => "this tamper component needs a new_value",
            Self::TamperTargetRequired => "this tamper component needs a target",
            Self::TamperComponentAbsent => "the tamper names a component the signed request does not have",
            Self::UnsupportedSignatureAlgorithm => "only AWS4-HMAC-SHA256 signatures can be rendered as SigV4 hex",
        };
        f.write_str(text)
    }
}

impl core::error::Error for SignerError {}

impl From<AuthError> for SignerError {
    fn from(error: AuthError) -> Self {
        Self::Canonical(error)
    }
}

impl From<SigParseError> for SignerError {
    fn from(error: SigParseError) -> Self {
        Self::Scope(error)
    }
}

/// One request about to be signed, described the way the verification side reads it.
///
/// The header map is the map that will be **sent**. The signer adds the `x-amz-*` headers it mints
/// (`x-amz-date`, `x-amz-content-sha256`, `x-amz-security-token`, `x-amz-trailer`) to a copy of it,
/// so a caller never has to spell them, and never has to keep two copies in step.
pub struct SigningRequest<'r> {
    method: &'r Method,
    path: &'r str,
    query: &'r str,
    headers: &'r HeaderMap,
    host: &'r RawHost,
    payload: PayloadMode,
    timestamp: AmzDate,
    signed_headers: Option<&'r [HeaderName]>,
    wire_content_length: Option<u64>,
    decoded_content_length: Option<u64>,
}

impl<'r> SigningRequest<'r> {
    /// Gathers the request. Nothing is computed until [`SigV4Signer::sign_headers`] or
    /// [`SigV4Signer::presign`] is called.
    ///
    /// `path` is the URI path exactly as it will be sent; `query` is the query string without its
    /// leading `?`. The host is a [`RawHost`] and nothing else, for the reason
    /// [`CanonicalRequestSpec::new`] gives.
    #[must_use]
    pub fn new(
        method: &'r Method,
        path: &'r str,
        query: &'r str,
        headers: &'r HeaderMap,
        host: &'r RawHost,
        payload: PayloadMode,
        timestamp: AmzDate,
    ) -> Self {
        Self {
            method,
            path,
            query,
            headers,
            host,
            payload,
            timestamp,
            signed_headers: None,
            wire_content_length: None,
            decoded_content_length: None,
        }
    }

    /// Signs exactly these header names instead of the default set.
    ///
    /// The canonical request is then built over a **projection** of the header map containing only
    /// these names, which is what an under-signing client does on the wire. The headers left out
    /// are still sent; they are simply not covered — the "complement of a deny-list" shape a
    /// negative case wants to exercise. Nothing about the verifier changes: it will refuse the
    /// result whenever an `x-amz-*` header arrives unsigned, which is the assertion such a case
    /// exists to make.
    #[must_use]
    pub fn with_signed_headers(mut self, names: &'r [HeaderName]) -> Self {
        self.signed_headers = Some(names);
        self
    }

    /// The body length the wire layer will settle on, for the `content-length` cross-check in
    /// [`SignedHeaderSet::parse_and_enforce`].
    #[must_use]
    pub fn with_wire_content_length(mut self, length: u64) -> Self {
        self.wire_content_length = Some(length);
        self
    }

    /// The decoded body length, mandatory under the two streaming modes and forbidden under the
    /// other four ([`PayloadMode::requires_decoded_length`]).
    #[must_use]
    pub fn with_decoded_content_length(mut self, length: u64) -> Self {
        self.decoded_content_length = Some(length);
        self
    }
}

/// A signed request: the bytes to send, and the two intermediates that produced them.
///
/// It has **no `Debug`**, for the reason [`crate::CanonicalRequest`] has none — it holds the
/// canonicalised header block, and one of those header values may be an SSE-C key:
///
/// ```compile_fail,E0277
/// use rustfs_gateway_sig::SignedRequest;
/// fn show(signed: &SignedRequest) {
///     println!("{signed:?}"); // no Debug: does not compile
/// }
/// ```
pub struct SignedRequest {
    method: Method,
    path: String,
    query: String,
    headers: HeaderMap,
    location: SigLocation,
    canonical_request: String,
    string_to_sign: String,
    signature_hex: String,
}

impl SignedRequest {
    /// The request method.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The URI path to send.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query string to send, without a leading `?`. For a presigned URL this already carries
    /// `X-Amz-Signature`.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// The headers to send, including everything the signer minted.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Where the signature lives: [`SigLocation::Header`] or [`SigLocation::Query`].
    #[must_use]
    pub const fn location(&self) -> SigLocation {
        self.location
    }

    /// The `Authorization` header value, for a header-signed request.
    #[must_use]
    pub fn authorization(&self) -> Option<&str> {
        self.headers.get(http::header::AUTHORIZATION)?.to_str().ok()
    }

    /// The signature, lowercase hex. This is the client's own signature and is meant to travel on
    /// the wire, so rendering it is the point rather than a leak.
    #[must_use]
    pub fn signature_hex(&self) -> &str {
        &self.signature_hex
    }

    /// The canonical request that was hashed. Reach for it deliberately; it contains header values.
    #[must_use]
    pub fn canonical_request(&self) -> &str {
        &self.canonical_request
    }

    /// The string that was HMAC'd.
    #[must_use]
    pub fn string_to_sign(&self) -> &str {
        &self.string_to_sign
    }

    /// The path and query joined, ready to be used as a request target.
    #[must_use]
    pub fn target(&self) -> String {
        if self.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.query)
        }
    }

    /// Rewrites exactly one canonical component **after** the signature was computed.
    ///
    /// This is the negative-case constructor: the request stays well formed and its signature stays
    /// a real signature — of a different request. A failure therefore names the component rather
    /// than reporting that the signature was wrong somewhere.
    ///
    /// # Errors
    ///
    /// [`SignerError::TamperNewValueRequired`], [`SignerError::TamperTargetRequired`],
    /// [`SignerError::TamperComponentAbsent`] or [`SignerError::UnrepresentableHeader`], depending
    /// on which part of the description the request cannot satisfy.
    pub fn tampered(mut self, tamper: &Tamper) -> Result<Self, SignerError> {
        tamper.apply(&mut self)?;
        Ok(self)
    }
}

/// The client-side SigV4 signer.
///
/// One signer holds one set of credentials and one scope, and caches the key derived from them.
pub struct SigV4Signer {
    credentials: SigningCredentials,
    scope: SigningScope,
    cache: SigningKeyCache,
}

impl SigV4Signer {
    /// Builds a signer.
    #[must_use]
    pub fn new(credentials: SigningCredentials, scope: SigningScope) -> Self {
        Self {
            credentials,
            scope,
            cache: SigningKeyCache::new(),
        }
    }

    /// The credentials in force.
    #[must_use]
    pub fn credentials(&self) -> &SigningCredentials {
        &self.credentials
    }

    /// The scope in force.
    #[must_use]
    pub fn scope(&self) -> &SigningScope {
        &self.scope
    }

    /// Signs a request with an `Authorization` header.
    ///
    /// The signer mints `x-amz-date`, and — unless the payload mode is [`PayloadMode::Empty`] —
    /// `x-amz-content-sha256`, plus `x-amz-security-token` and `x-amz-trailer` when they apply. All
    /// of them are `x-amz-*`, so all of them end up in `SignedHeaders`, which is the rule
    /// [`SignedHeaderSet::parse_and_enforce`] would refuse the request for breaking.
    ///
    /// # Errors
    ///
    /// [`SignerError::Canonical`] when the request cannot be canonicalised or the header set is
    /// incomplete, [`SignerError::DecodedContentLengthRequired`] /
    /// [`SignerError::DecodedContentLengthNotAllowed`] for the streaming-mode invariant, and
    /// [`SignerError::UnrepresentableHeader`] for a header the wire cannot carry.
    pub fn sign_headers(&mut self, request: &SigningRequest<'_>) -> Result<SignedRequest, SignerError> {
        let headers = self.minted_headers(request, SigLocation::Header)?;
        let (signed, projection) = signed_header_view(request, &headers)?;

        let (canonical_request, string_to_sign, signature_hex) =
            self.compute(request, &projection, &signed, request.query, QueryExclusion::None)?;

        let mut headers = headers;
        let authorization = format!(
            "{ALGORITHM_SIGV4} Credential={}, SignedHeaders={}, Signature={signature_hex}",
            self.scope.credential_value(self.credentials.access_key_id()),
            signed.canonical_list(),
        );
        set_header(&mut headers, AUTHORIZATION_HEADER, &authorization)?;

        Ok(SignedRequest {
            method: request.method.clone(),
            path: request.path.to_owned(),
            query: request.query.to_owned(),
            headers,
            location: SigLocation::Header,
            canonical_request,
            string_to_sign,
            signature_hex,
        })
    }

    /// Signs a presigned URL, whose signature travels in the query.
    ///
    /// `expires_in_seconds` is checked against [`MAX_PRESIGNED_EXPIRY_SECONDS`] — the verification
    /// side's constant, imported rather than restated, so the two ceilings cannot drift.
    ///
    /// # Errors
    ///
    /// [`SignerError::ExpiryOutOfRange`] outside `1..=604800`,
    /// [`SignerError::SigningParameterAlreadyPresent`] when the caller's query already carries one
    /// of the parameters this function mints, and the same canonicalisation errors as
    /// [`SigV4Signer::sign_headers`].
    pub fn presign(&mut self, request: &SigningRequest<'_>, expires_in_seconds: u64) -> Result<SignedRequest, SignerError> {
        if expires_in_seconds == 0 || expires_in_seconds > MAX_PRESIGNED_EXPIRY_SECONDS {
            return Err(SignerError::ExpiryOutOfRange);
        }
        let raw = RawQuery::new(request.query);
        for name in MINTED_QUERY_PARAMS {
            if raw.decoded_value(name)?.is_some() {
                return Err(SignerError::SigningParameterAlreadyPresent);
            }
        }

        let headers = self.minted_headers(request, SigLocation::Query)?;
        let (signed, projection) = signed_header_view(request, &headers)?;

        let mut query = request.query.to_owned();
        push_param(&mut query, X_AMZ_ALGORITHM, ALGORITHM_SIGV4);
        push_param(
            &mut query,
            X_AMZ_CREDENTIAL,
            &self.scope.credential_value(self.credentials.access_key_id()),
        );
        push_param(&mut query, X_AMZ_DATE, request.timestamp.as_str());
        push_param(&mut query, X_AMZ_EXPIRES, &expires_in_seconds.to_string());
        push_param(&mut query, X_AMZ_SIGNED_HEADERS, &signed.canonical_list());
        if let Some(token) = self.credentials.session_token() {
            let token = core::str::from_utf8(token.expose()).map_err(|_| SignerError::UnrepresentableHeader)?;
            push_param(&mut query, X_AMZ_SECURITY_TOKEN, token);
        }

        // `QueryExclusion::PresignedSignature` is the exclusion the verifier applies. Applying it
        // here too, while `X-Amz-Signature` is still absent, is a no-op that keeps the two calls
        // literally identical rather than merely equivalent.
        let (canonical_request, string_to_sign, signature_hex) =
            self.compute(request, &projection, &signed, &query, QueryExclusion::PresignedSignature)?;
        push_param(&mut query, X_AMZ_SIGNATURE, &signature_hex);

        Ok(SignedRequest {
            method: request.method.clone(),
            path: request.path.to_owned(),
            query,
            headers,
            location: SigLocation::Query,
            canonical_request,
            string_to_sign,
            signature_hex,
        })
    }

    /// A chunk-signature chain seeded by a signed request.
    ///
    /// The seed is the request's own signature, which is what makes the first chunk unforgeable
    /// without the request that introduced it.
    ///
    /// # Errors
    ///
    /// [`SignerError::Scope`] if the scope cannot be rendered.
    pub fn chunk_signer(&mut self, seed: &SignedRequest) -> Result<ChunkSigner, SignerError> {
        let presented = self.scope.presented(self.credentials.access_key_id())?;
        let material = self.cache.key_for(self.credentials.secret(), &self.scope).clone_secret();
        Ok(ChunkSigner::seeded(
            material,
            parse_timestamp(seed)?,
            presented.scope_string(),
            seed.signature_hex.clone(),
        ))
    }

    /// Canonicalise, build the string-to-sign, derive, sign. The one path both modes go through.
    fn compute(
        &mut self,
        request: &SigningRequest<'_>,
        headers: &HeaderMap,
        signed: &SignedHeaderSet,
        query: &str,
        exclusion: QueryExclusion,
    ) -> Result<(String, String, String), SignerError> {
        let paths = UriPathCandidates::new(request.path)?;
        let raw_query = RawQuery::new(query);
        let spec = CanonicalRequestSpec::new(
            request.method,
            &paths,
            &raw_query,
            headers,
            signed,
            request.host,
            request.payload.canonical_payload_token(),
        );
        let spec = match exclusion {
            QueryExclusion::PresignedSignature => spec.presigned(),
            _ => spec,
        };
        // The first candidate is the decoded-then-re-encoded spelling, which is the one a client
        // emits. The raw candidate exists for proxies that re-spell a path in flight; a signer has
        // no proxy in front of it.
        let canonical = spec
            .candidates()?
            .next()
            .ok_or(SignerError::Canonical(AuthError::SignatureDoesNotMatch))?;
        let presented = self.scope.presented(self.credentials.access_key_id())?;
        let string_to_sign = canonical.string_to_sign(&request.timestamp, &presented);
        let material = self.cache.key_for(self.credentials.secret(), &self.scope);
        let signature = calculate_signature(material, &string_to_sign);
        Ok((canonical.text().to_owned(), string_to_sign.text().to_owned(), signature_hex(&signature)?))
    }

    /// The header map as it will be sent: the caller's, plus everything the signer mints.
    fn minted_headers(&self, request: &SigningRequest<'_>, location: SigLocation) -> Result<HeaderMap, SignerError> {
        let mut headers = request.headers.clone();
        let streaming = request.payload.requires_decoded_length();
        match (streaming, request.decoded_content_length) {
            (true, None) => return Err(SignerError::DecodedContentLengthRequired),
            (false, Some(_)) => return Err(SignerError::DecodedContentLengthNotAllowed),
            (true, Some(length)) => set_header(&mut headers, X_AMZ_DECODED_CONTENT_LENGTH_HEADER_NAME, &length.to_string())?,
            (false, None) => {}
        }

        if location == SigLocation::Query {
            // A presigned URL carries its timestamp, its credential and its token in the query;
            // minting header copies of them would sign two spellings of one value.
            return Ok(headers);
        }

        set_header(&mut headers, X_AMZ_DATE_HEADER, request.timestamp.as_str())?;
        if request.payload != PayloadMode::Empty {
            let token = request.payload.canonical_payload_token();
            set_header(&mut headers, X_AMZ_CONTENT_SHA256_HEADER_NAME, token.as_str())?;
        }
        if let Some(TrailerSet::Declared(declared)) = request.payload.trailer() {
            let names: Vec<&str> = declared.names().iter().map(crate::mode::TrailerName::as_str).collect();
            set_header(&mut headers, X_AMZ_TRAILER_HEADER_NAME, &names.join(","))?;
        }
        if let Some(token) = self.credentials.session_token() {
            let token = core::str::from_utf8(token.expose()).map_err(|_| SignerError::UnrepresentableHeader)?;
            set_header(&mut headers, X_AMZ_SECURITY_TOKEN_HEADER, token)?;
        }
        Ok(headers)
    }
}

/// The signed-header list and the header map it covers, both built through the verification side's
/// own parser.
///
/// The default list is `host` plus every header that arrived and is not in
/// [`crate::UNSIGNED_HEADER_EXEMPTIONS`] — never a deny-list applied to the map, because the
/// canonical request is built from the list and from nothing else.
///
/// The map handed back is the **projection**: only the names the list covers, with their values
/// taken from the map that will be sent. For the default list the projection differs from the sent
/// map only by the exempt headers, so nothing changes. For an explicit list it is exactly the view
/// an under-signing client has of its own request — it signs a subset and sends a superset. All six
/// completeness rules then run against that view, unmodified, which is why a deliberately
/// under-signed request can be produced here without any rule being relaxed: the request the client
/// signed really does satisfy them, and the request it *sends* is the one the verifier will refuse.
fn signed_header_view(request: &SigningRequest<'_>, headers: &HeaderMap) -> Result<(SignedHeaderSet, HeaderMap), SignerError> {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    match request.signed_headers {
        Some(explicit) => {
            for name in explicit {
                names.insert(name.as_str());
            }
        }
        None => {
            names.insert(HOST.as_str());
            for name in headers.keys() {
                if SignedHeaderSet::is_exempt_from_signing(name.as_str()) || name.as_str() == AUTHORIZATION_HEADER {
                    continue;
                }
                names.insert(name.as_str());
            }
        }
    }

    let mut projection = HeaderMap::new();
    for name in &names {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| SignerError::UnrepresentableHeader)?;
        for value in headers.get_all(&name) {
            projection.append(name.clone(), value.clone());
        }
    }

    let raw = names.into_iter().collect::<Vec<_>>().join(";");
    let set = SignedHeaderSet::parse_and_enforce(&raw, &projection, request.wire_content_length)?;
    Ok((set, projection))
}

fn set_header(headers: &mut HeaderMap, name: &str, value: &str) -> Result<(), SignerError> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| SignerError::UnrepresentableHeader)?;
    let value = HeaderValue::from_str(value).map_err(|_| SignerError::UnrepresentableHeader)?;
    headers.insert(name, value);
    Ok(())
}

fn push_param(query: &mut String, name: &str, value: &str) {
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str(&percent_encode(name.as_bytes()));
    query.push('=');
    query.push_str(&percent_encode(value.as_bytes()));
}

fn parse_timestamp(signed: &SignedRequest) -> Result<AmzDate, SignerError> {
    let text = match signed.location {
        SigLocation::Query => RawQuery::new(&signed.query)
            .decoded_value(X_AMZ_DATE)?
            .ok_or(SignerError::TamperComponentAbsent)?,
        _ => signed
            .headers
            .get(X_AMZ_DATE_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or(SignerError::TamperComponentAbsent)?
            .to_owned(),
    };
    Ok(AmzDate::parse(&text)?)
}

/// Lowercase hex of a signature.
///
/// A signature the client produced for its own request is transmitted in the clear, so rendering
/// it is the protocol rather than a leak. Nothing here renders a *computed expectation*, which is
/// the value that would make an error message a signing oracle.
fn signature_hex(signature: &Signature) -> Result<String, SignerError> {
    match signature {
        Signature::HmacSha256(bytes) => Ok(encode_hex_lower(bytes.as_array())),
        _ => Err(SignerError::UnsupportedSignatureAlgorithm),
    }
}

#[cfg(test)]
#[path = "signer_tests.rs"]
mod tests;
