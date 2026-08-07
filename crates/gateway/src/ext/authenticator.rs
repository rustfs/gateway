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

//! Who the caller is, decided for a request the security floor has already admitted.
//!
//! Responsible for: [`Authenticator`] — the extension point that turns an admitted request into a
//! [`Verdict`] — the request it is handed ([`Authentication`]), the one non-verdict outcome
//! ([`Unavailable`]), and [`SigV4Authenticator`], the implementation assembled from
//! `rustfs-gateway-sig`'s public primitives.
//! NOT responsible for: any rule the security floor enforces. H1 to H6 have already run in
//! `SecurityFloor::admit` before this is called, and nothing here can skip them. It is also not
//! responsible for authorisation (`super::authorizer`) or for holding a secret
//! (`super::credentials`).
//! Upstream: `rustfs-gateway-sig`, `rustfs-gateway-http`. Downstream: `crate::service`.
//!
//! # Why the framework does not simply do this itself
//!
//! It largely does — [`SigV4Authenticator`] is a composition of `rustfs-gateway-sig`'s public
//! functions and adds no rule of its own. The seam exists because a deployment that authenticates
//! with something other than SigV4 needs one, and because leaving it implicit would mean the only
//! way to change authentication is to fork the pipeline. What the seam deliberately cannot do is
//! remove a check: it receives a [`SealedAws`], which cannot be constructed outside
//! `rustfs-gateway-sig` and cannot be obtained except from `SecurityFloor::admit`.
//!
//! # Why an unknown access key still runs the full derivation
//!
//! `InvalidAccessKeyId` and `SignatureDoesNotMatch` stay distinct because S3 clients branch on the
//! code. That leaves a timing difference — an unknown key would otherwise answer before any HMAC
//! ran — so [`SigV4Authenticator`] derives from
//! [`rustfs_gateway_sig::timing::placeholder_secret`] and completes the comparison before
//! answering. The mitigation is parity work, not a proof; row `T1` of
//! [`rustfs_gateway_sig::timing::SIDE_CHANNELS`] is the full reasoning.
//!
//! # Why a store outage is not a verdict
//!
//! A credential store that cannot answer has not decided anything about the caller. Folding it
//! into `AuthError::InvalidAccessKeyId` would tell every client during an outage that its
//! credentials had been revoked, and folding it into `AccessDenied` would tell them their
//! permissions had changed. It is [`Unavailable`], which the service answers `500 InternalError`.

use std::sync::Arc;

use http::Method;
use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::{
    AUTHORIZATION_HEADER, AmzDate, AuthError, AuthScheme, CanonicalRequestSpec, CredentialScope, ExpectedScope, PayloadMode,
    PresignedParams, RawHost, RegionSet, SealedAws, SigIdentity, SigLocation, SigV4Authorization, Signature, SignatureMatch,
    SignedHeaderSet, UriPathCandidates, Verdict, calculate_signature, enforce_scope, signing_key, timing,
};

use super::credentials::{CredentialProvider, CredentialsError};

/// The credential store could not answer.
///
/// Distinct from every [`AuthError`] on purpose: those are statements about the request, and this
/// is a statement about the deployment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unavailable;

impl core::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the credential store could not answer")
    }
}

impl std::error::Error for Unavailable {}

/// The material a `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` body's per-chunk signatures are checked
/// against.
///
/// # Why this exists at all
///
/// The `aws-chunked` chunk chain is seeded by the *request* signature and verified with the *same*
/// `k_signing` the request signature was computed from. Neither value survives
/// [`Verdict`]: `Verdict::Authenticated` carries an identity, a scheme and a zero-sized
/// [`SignatureMatch`], which is exactly the right shape for "who is this" and exactly the wrong
/// shape for "keep verifying". `Verdict` is `rustfs-gateway-sig`'s and `#[non_exhaustive]`, so it
/// cannot grow a variant from here.
///
/// So the material travels beside the verdict, through a sink the pipeline owns and the
/// authenticator may fill. That keeps the change additive — an existing [`Authenticator`]
/// implementation compiles untouched and simply never fills it — and keeps the ordering honest:
/// the sink is read *after* the verdict has been checked, so a body cannot be verified against
/// material published by a request that was then rejected.
///
/// No `Debug`, no `Clone`: it holds a signing key.
pub struct ChunkVerification {
    key: rustfs_gateway_sig::SigningKey,
    scope_line: String,
    amz_date: String,
}

impl ChunkVerification {
    /// Publishes the derived key and the scope the chunk chain is dated with.
    #[must_use]
    pub fn new(key: rustfs_gateway_sig::SigningKey, scope_line: String, amz_date: String) -> Self {
        Self {
            key,
            scope_line,
            amz_date,
        }
    }

    /// The derived `k_signing`, as the fixed-width value the chunk signer takes.
    ///
    /// `None` when the key is not the 32 bytes SigV4 produces, which is a defect in whatever built
    /// it rather than a property of the request — the caller refuses instead of padding.
    #[must_use]
    pub fn chunk_signing_key(&self) -> Option<rustfs_gateway_http::ChunkSigningKey> {
        let bytes: [u8; 32] = self.key.expose().try_into().ok()?;
        Some(rustfs_gateway_http::ChunkSigningKey::from_derived(bytes))
    }

    /// The credential scope line, `<date>/<region>/<service>/aws4_request`.
    #[must_use]
    pub fn scope_line(&self) -> &str {
        &self.scope_line
    }

    /// The `x-amz-date` the string-to-sign is dated with.
    #[must_use]
    pub fn amz_date(&self) -> &str {
        &self.amz_date
    }
}

/// Where an [`Authenticator`] leaves a [`ChunkVerification`] for the body reader to collect.
///
/// Write-once: a second publication would mean two answers to "what key verifies this body", and
/// the reader has no way to choose between them. [`ChunkSink::publish`] silently keeps the first,
/// because the alternative — a panic on a path an extension point controls — turns an
/// implementation bug into an availability bug.
#[derive(Default)]
pub struct ChunkSink {
    slot: std::sync::OnceLock<ChunkVerification>,
}

impl ChunkSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slot: std::sync::OnceLock::new(),
        }
    }

    /// Publishes the material, if nothing has been published yet.
    pub fn publish(&self, material: ChunkVerification) {
        let _ = self.slot.set(material);
    }

    /// What was published, if anything.
    #[must_use]
    pub fn get(&self) -> Option<&ChunkVerification> {
        self.slot.get()
    }
}

impl core::fmt::Debug for ChunkSink {
    /// Reports only whether it is filled. The contents are a signing key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChunkSink")
            .field("published", &self.slot.get().is_some())
            .finish()
    }
}

/// One request the security floor has admitted, with everything an authenticator needs to
/// reconstruct what was signed.
///
/// The path and the host are the *raw* spellings. Handing over a normalised value would be the
/// defect the one-host invariant exists to prevent: normalisation is many-to-one, so several
/// distinct spellings would share one valid signature.
#[derive(Debug)]
pub struct Authentication<'a> {
    sealed: &'a SealedAws<'a>,
    method: &'a Method,
    raw_path: &'a str,
    host: &'a RawHost,
    payload: &'a PayloadMode,
    declared_content_length: Option<u64>,
    chunks: Option<&'a ChunkSink>,
}

impl<'a> Authentication<'a> {
    /// Assembles the request an authenticator is asked about.
    #[must_use]
    pub const fn new(
        sealed: &'a SealedAws<'a>,
        method: &'a Method,
        raw_path: &'a str,
        host: &'a RawHost,
        payload: &'a PayloadMode,
        declared_content_length: Option<u64>,
    ) -> Self {
        Self {
            sealed,
            method,
            raw_path,
            host,
            payload,
            declared_content_length,
            chunks: None,
        }
    }

    /// Attaches the sink an authenticator may publish chunk-verification material into.
    ///
    /// A builder method rather than a seventh constructor parameter, so that adding it did not
    /// break every caller of [`Authentication::new`].
    #[must_use]
    pub const fn with_chunk_sink(mut self, chunks: &'a ChunkSink) -> Self {
        self.chunks = Some(chunks);
        self
    }

    /// The sink, when the pipeline offered one.
    ///
    /// `None` means the caller has no use for chunk material — a request whose payload mode is not
    /// framed, or a consumer that assembled an [`Authentication`] itself. An implementation must
    /// treat it as "not asked for" and not as "publish it somewhere else".
    #[must_use]
    pub const fn chunk_sink(&self) -> Option<&'a ChunkSink> {
        self.chunks
    }

    /// The admitted request. Holding one is proof the floor has run.
    #[must_use]
    pub const fn sealed(&self) -> &'a SealedAws<'a> {
        self.sealed
    }

    /// The request method.
    #[must_use]
    pub const fn method(&self) -> &'a Method {
        self.method
    }

    /// The path exactly as it arrived, still percent-encoded.
    #[must_use]
    pub const fn raw_path(&self) -> &'a str {
        self.raw_path
    }

    /// The host as it arrived, which is the only spelling a signature may be built from.
    #[must_use]
    pub const fn host(&self) -> &'a RawHost {
        self.host
    }

    /// What `x-amz-content-sha256` said about the body.
    #[must_use]
    pub const fn payload(&self) -> &'a PayloadMode {
        self.payload
    }

    /// The `Content-Length` HTTP framing gave, when it gave one.
    #[must_use]
    pub const fn declared_content_length(&self) -> Option<u64> {
        self.declared_content_length
    }
}

/// Decides one admitted request.
///
/// Held as `Arc<dyn Authenticator>`, so the async method is a hand-written [`BoxFuture`]
/// (ADR-0002). There is no default implementation and [`crate::ServiceBuilder::build`] refuses
/// without one: the two things a default could do are authenticate everything and authenticate
/// nothing, and a deployment that got the wrong one discovers it in production either way.
pub trait Authenticator: Send + Sync + 'static {
    /// Produces a verdict for one admitted request.
    ///
    /// [`Verdict`]'s widening variants each require a receipt this trait cannot manufacture:
    /// `Authenticated` needs a `SignatureMatch` that only a constant-time comparison produces, and
    /// `Anonymous` needs an `AnonymousAck` that only a request which presented nothing can yield.
    /// So an implementation can decide, and cannot invent.
    fn authenticate<'a>(&'a self, request: &'a Authentication<'a>) -> BoxFuture<'a, Result<Verdict, Unavailable>>;
}

impl<T: Authenticator + ?Sized> Authenticator for Arc<T> {
    fn authenticate<'a>(&'a self, request: &'a Authentication<'a>) -> BoxFuture<'a, Result<Verdict, Unavailable>> {
        (**self).authenticate(request)
    }
}

/// SigV4 verification, assembled from `rustfs-gateway-sig`'s public primitives.
///
/// It contributes no rule of its own. Every step below is a call into the signature crate, in the
/// order that crate's own end-to-end cases use: cross-check the credential scope, resolve the
/// secret, enforce the signed-header list, canonicalise every path spelling, derive, and compare
/// in constant time.
pub struct SigV4Authenticator {
    credentials: Arc<dyn CredentialProvider>,
    regions: RegionSet,
}

impl core::fmt::Debug for SigV4Authenticator {
    /// Hand-written: a credential provider is not required to be `Debug`, and requiring it would
    /// push a derive onto every implementation for the sake of one line here.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigV4Authenticator").field("regions", &self.regions).finish()
    }
}

impl SigV4Authenticator {
    /// Builds the verifier over a credential source and the regions this deployment serves.
    ///
    /// The region set is not a display value: it is cross-checked against the region the client
    /// put in its credential scope, and that string is part of what was signed. A deployment that
    /// listed a region it does not serve would accept a signature minted for another endpoint.
    #[must_use]
    pub fn new(credentials: Arc<dyn CredentialProvider>, regions: RegionSet) -> Self {
        Self { credentials, regions }
    }

    async fn verify(&self, request: &Authentication<'_>) -> Result<Verdict, Unavailable> {
        match self.try_verify(request).await {
            Ok(Some(verdict)) => Ok(verdict),
            Ok(None) => Err(Unavailable),
            Err(error) => Ok(Verdict::reject(error)),
        }
    }

    /// `Ok(None)` is the store outage; every other outcome is a verdict or a rejection.
    async fn try_verify(&self, request: &Authentication<'_>) -> Result<Option<Verdict>, AuthError> {
        let sealed = request.sealed();
        let view = sealed.view();
        let location = sealed.marker().location();
        let presented = Presented::read(sealed, location)?;

        // H5, and the only public producer of the `VerifiedScope` the derivation takes. A scope
        // the client chose therefore cannot seed a signing key.
        let expected = ExpectedScope::new(sealed.expected_service(), &self.regions);
        let verified = enforce_scope(presented.scope(), sealed.clock(), &expected)?;

        let resolved = self
            .credentials
            .lookup(presented.scope().access_key_id().access_key_id())
            .await;
        if resolved.as_ref().err() == Some(&CredentialsError::Unavailable) {
            return Ok(None);
        }
        // An unknown key derives from a placeholder rather than returning early, so that the two
        // distinct codes are not also two distinct latencies.
        let secret = match &resolved {
            Ok(credentials) => credentials.secret().clone_secret(),
            Err(_) => timing::placeholder_secret(),
        };

        let signed =
            SignedHeaderSet::parse_and_enforce(presented.signed_headers(), view.headers(), request.declared_content_length())?;
        let paths = UriPathCandidates::new(request.raw_path())?;
        let query = view.query();
        let mut spec = CanonicalRequestSpec::new(
            request.method(),
            &paths,
            &query,
            view.headers(),
            &signed,
            request.host(),
            request.payload().canonical_payload_token(),
        );
        if location.is_presigned() {
            spec = spec.presigned();
        }

        let key = signing_key(&secret, &verified);
        let date = presented.signed_at(sealed);
        let mut proof: Option<SignatureMatch> = None;
        for candidate in spec.candidates()? {
            let derived = calculate_signature(&key, &candidate.string_to_sign(&date, presented.scope()));
            // Every candidate is derived and compared even after one has matched: returning early
            // would make the number of HMAC rounds a function of which spelling the client sent.
            if let Ok(matched) = presented.signature().ct_verify(&derived) {
                proof = proof.or(Some(matched));
            }
        }

        // The unknown-key branch has now paid for the same derivation a known key does. Only after
        // that is the distinct code answered.
        let Ok(credentials) = resolved else {
            return Err(AuthError::InvalidAccessKeyId);
        };
        let Some(proof) = proof else {
            return Err(AuthError::SignatureDoesNotMatch);
        };

        let identity_axis = match credentials.session_token() {
            Some(token) => SigIdentity::Session {
                token: token.clone_secret(),
            },
            None => SigIdentity::LongTerm,
        };
        let scheme = if location.is_presigned() {
            AuthScheme::sigv4_presigned(identity_axis, sealed.expected_service())
        } else {
            AuthScheme::sigv4_header(identity_axis, sealed.expected_service())
        };

        // Published only here: after the comparison produced a `SignatureMatch` and after the
        // access key was found. A key made available on the failing path would be one an
        // unauthenticated caller had caused to be derived, and the body reader has no way to know
        // which path it came from — the sink carries no provenance, so the ordering has to.
        //
        // Published only when the mode actually frames the body. `has_chunk_signatures()` reads
        // `x-amz-content-sha256` and nothing else, which is the one sanctioned input to that
        // question; `Content-Encoding: aws-chunked` is metadata and is not consulted anywhere.
        if request.payload().has_chunk_signatures()
            && let Some(sink) = request.chunk_sink()
        {
            sink.publish(ChunkVerification::new(key, presented.scope().scope_string(), date.as_str().to_owned()));
        }
        Ok(Some(Verdict::authenticated(credentials.identity().clone(), scheme, proof)))
    }
}

impl Authenticator for SigV4Authenticator {
    fn authenticate<'a>(&'a self, request: &'a Authentication<'a>) -> BoxFuture<'a, Result<Verdict, Unavailable>> {
        Box::pin(self.verify(request))
    }
}

/// The signature material the client presented, from whichever surface carried it.
///
/// One type for both surfaces so that the verification body has no `match` on the location running
/// through the middle of it — the two differ in where the values are read and in nothing else.
enum Presented {
    Header(Box<SigV4Authorization>),
    Query(Box<PresignedParams>),
}

impl Presented {
    fn read(sealed: &SealedAws<'_>, location: SigLocation) -> Result<Self, AuthError> {
        match location {
            SigLocation::Query => Ok(Self::Query(Box::new(PresignedParams::parse(&sealed.view().query())?))),
            _ => {
                let raw = sealed
                    .view()
                    .headers()
                    .get(AUTHORIZATION_HEADER)
                    .ok_or(AuthError::AuthorizationHeaderMalformed)?
                    .to_str()
                    .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
                Ok(Self::Header(Box::new(SigV4Authorization::parse(raw)?)))
            }
        }
    }

    fn scope(&self) -> &CredentialScope {
        match self {
            Self::Header(parsed) => parsed.scope(),
            Self::Query(parsed) => parsed.scope(),
        }
    }

    fn signed_headers(&self) -> &str {
        match self {
            Self::Header(parsed) => parsed.signed_headers(),
            Self::Query(parsed) => parsed.signed_headers(),
        }
    }

    fn signature(&self) -> &Signature {
        match self {
            Self::Header(parsed) => parsed.signature(),
            Self::Query(parsed) => parsed.signature(),
        }
    }

    /// The timestamp the string-to-sign is dated with.
    ///
    /// For a presigned URL it is the one in the query; for a header-signed request it is the
    /// receipt the skew check produced, which is the same value the floor validated.
    fn signed_at(&self, sealed: &SealedAws<'_>) -> AmzDate {
        match self {
            Self::Header(_) => sealed.clock().signed_at(),
            Self::Query(parsed) => parsed.date(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ext::credentials::{Credentials, StaticCredentials};

    fn authenticator() -> SigV4Authenticator {
        SigV4Authenticator::new(
            Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid"))),
            RegionSet::new(["us-east-1"]).expect("non-empty"),
        )
    }

    /// Negative — the verifier is usable behind `Arc<dyn _>`. An RPITIT method here would not
    /// compile at all, which is the measured `E0038` ADR-0002 records.
    #[test]
    fn the_trait_is_dyn_compatible() {
        let _: Arc<dyn Authenticator> = Arc::new(authenticator());
    }

    /// Negative — a deployment cannot be built with an empty region set: an empty set matches no
    /// presented region and would reject every request with a scope error rather than saying the
    /// configuration is wrong.
    #[test]
    fn an_empty_region_set_is_refused_where_it_is_written() {
        assert!(RegionSet::new(Vec::<String>::new()).is_err());
    }

    /// Negative — a store outage is not an `AuthError`, so it cannot be rendered as a statement
    /// about the caller's credentials.
    #[test]
    fn a_store_outage_is_not_a_credential_rejection() {
        assert_eq!(Unavailable.to_string(), "the credential store could not answer");
    }
}
