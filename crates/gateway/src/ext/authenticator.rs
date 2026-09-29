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
//! Responsible for: [`Authenticator`] — the extension point that turns an admitted request into an
//! [`AuthenticationOutcome`] — the request it is handed ([`Authentication`]), the one unavailable
//! outcome ([`Unavailable`]), and [`SigV4Authenticator`], the implementation assembled from
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
//! Every credential failure has one wire answer. An unknown key would otherwise also answer before
//! any HMAC ran, so [`SigV4Authenticator`] derives from
//! [`rustfs_gateway_sig::timing::placeholder_secret`] and completes the comparison before
//! answering. The mitigation is parity work, not a proof; row `T1` of
//! [`rustfs_gateway_sig::timing::SIDE_CHANNELS`] is the full reasoning.
//!
//! # Why a session rule is decided early and answered late
//!
//! A temporary credential can fail for reasons the signature knows nothing about: its lifetime has
//! ended, it was presented without the token it is bound to, or the access key is long-term and a
//! token came anyway. Each of those is a single comparison, and each is therefore tempting to
//! answer the moment it is noticed — which would make an expired token answer before any HMAC ran,
//! reopening exactly the enumeration channel `T1` closes for unknown keys.
//!
//! So [`SigV4Authenticator`] computes the session verdict where the credential arrives and
//! consumes it after the comparison, and every one of those refusals is answered
//! `InvalidAccessKeyId` — the same bytes an unknown key or wrong signature gets.
//!
//! # Why a store outage is not a verdict
//!
//! A credential store that cannot answer has not authenticated the caller. The guarded provider
//! records the fault for operators, while the client receives the same closed `403` as every other
//! credential failure. It is never downgraded to anonymous.

use std::sync::Arc;

use http::Method;
use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::{
    AUTHORIZATION_HEADER, AmzDate, AuthError, AuthScheme, CanonicalRequestSpec, CredentialScope, ExpectedScope, PayloadMode,
    PostPolicy, PostPolicyError, PostPolicyLimits, PresignedParams, RawHost, RegionRule, RegionSet, ScopeRejection, SealedAws,
    SessionToken, SigFamily, SigIdentity, SigLocation, SigV4Authorization, Signature, SignatureMatch, SignedHeaderSet,
    UriPathCandidates, Verdict, X_AMZ_SECURITY_TOKEN, X_AMZ_SECURITY_TOKEN_HEADER, calculate_signature, enforce_scope,
    signing_key, timing,
};

use super::credential_guard::{CredentialGuardConfig, GuardedCredentialProvider};
use super::credentials::{CredentialLookup, CredentialProvider};
use super::sigv2::SigV2Authentication;

/// The credential store could not answer.
///
/// Distinct from every [`AuthError`] on purpose: those are statements about the request, and this
/// is a statement about the deployment.
///
/// # Security
///
/// The default is the same opaque provider-failure marker; it carries no request text and cannot
/// be interpreted as an authenticated identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unavailable;

impl core::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the credential store could not answer")
    }
}

impl std::error::Error for Unavailable {}

/// The authentication verdict and any framework-owned proof needed to render its rejection.
///
/// Custom authenticators construct only ordinary outcomes. Scope rejection proofs remain private
/// to the built-in verifier and cannot be paired with a caller-selected verdict.
///
/// ```compile_fail,E0451
/// use rustfs_gateway::AuthenticationOutcome;
/// use rustfs_gateway_sig::{AuthError, Verdict};
/// let verdict = Verdict::reject(AuthError::AuthorizationHeaderMalformed);
/// let _ = AuthenticationOutcome { verdict, scope_rejection: None };
/// ```
///
/// ```compile_fail,E0624
/// use rustfs_gateway::AuthenticationOutcome;
/// use rustfs_gateway_sig::ScopeRejection;
/// fn attach(rejection: ScopeRejection) {
///     let _ = AuthenticationOutcome::scope_rejected(rejection);
/// }
/// ```
///
/// ```compile_fail,E0624
/// use rustfs_gateway::AuthenticationOutcome;
/// fn consume(outcome: AuthenticationOutcome) {
///     let _ = outcome.into_parts();
/// }
/// ```
pub struct AuthenticationOutcome {
    verdict: Verdict,
    scope_rejection: Option<ScopeRejection>,
    caller_secret: Option<rustfs_gateway_sig::SecretBytes>,
}

impl AuthenticationOutcome {
    /// Wraps an existing verdict without contextual response authority.
    #[must_use]
    pub const fn ordinary(verdict: Verdict) -> Self {
        Self {
            verdict,
            scope_rejection: None,
            caller_secret: None,
        }
    }

    /// Attaches the secret this authenticator's own credential lookup returned for the principal it
    /// authenticated; the handler reads it as `RequestPrincipal::secret_key_from_authenticator_lookup`
    /// (ADR-0022). The pipeline hands it on only with an `Authenticated` verdict. Attach one only
    /// when the deployment asked for it, as [`SigV4Authenticator::hand_caller_secret_to_handlers`]
    /// does.
    #[must_use]
    pub fn with_caller_secret(mut self, secret: rustfs_gateway_sig::SecretBytes) -> Self {
        self.caller_secret = Some(secret);
        self
    }

    /// Borrows the exact verdict produced by the authenticator.
    #[must_use]
    pub const fn verdict(&self) -> &Verdict {
        &self.verdict
    }

    fn scope_rejected(scope_rejection: ScopeRejection) -> Self {
        Self {
            verdict: Verdict::reject(AuthError::AuthorizationHeaderMalformed),
            scope_rejection: Some(scope_rejection),
            caller_secret: None,
        }
    }

    /// An authenticated outcome, carrying the looked-up secret when the authenticator hands it on.
    pub(super) fn authenticated(verdict: Verdict, caller_secret: Option<rustfs_gateway_sig::SecretBytes>) -> Self {
        Self {
            caller_secret,
            ..Self::ordinary(verdict)
        }
    }

    pub(crate) fn into_parts(self) -> (Verdict, Option<ScopeRejection>, Option<rustfs_gateway_sig::SecretBytes>) {
        (self.verdict, self.scope_rejection, self.caller_secret)
    }
}

/// The material a `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` body's per-chunk signatures are checked
/// against.
///
/// # Why this exists at all
///
/// The `aws-chunked` chunk chain is seeded by the *request* signature and verified with the *same*
/// `k_signing` the request signature was computed from. Neither value survives
/// [`Verdict`]: `Verdict::Authenticated` carries an identity, a scheme, the verified scope and a
/// zero-sized [`SignatureMatch`], which is exactly the right shape for "who is this" and exactly
/// the wrong shape for "keep verifying" — the scope names the key, it does not hold it. `Verdict` is `rustfs-gateway-sig`'s and `#[non_exhaustive]`, so it
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
///
/// # Security
///
/// The default sink contains no chunk-verification material. It cannot make a streaming body
/// verifiable until an authenticator explicitly publishes that material.
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
pub struct Authentication<'a> {
    sealed: &'a SealedAws<'a>,
    method: &'a Method,
    raw_path: &'a str,
    host: &'a RawHost,
    payload: &'a PayloadMode,
    declared_content_length: Option<u64>,
    chunks: Option<&'a ChunkSink>,
    signature_mismatch: std::sync::OnceLock<rustfs_gateway_sig::SignatureMismatchDetail>,
}

impl core::fmt::Debug for Authentication<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authentication")
            .field("sealed", &self.sealed)
            .field("method", &self.method)
            .field("raw_path", &self.raw_path)
            .field("host", &self.host)
            .field("payload", &self.payload)
            .field("declared_content_length", &self.declared_content_length)
            .field("chunks", &self.chunks)
            .field("signature_mismatch_published", &self.signature_mismatch.get().is_some())
            .finish()
    }
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
            signature_mismatch: std::sync::OnceLock::new(),
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

    pub(crate) fn into_signature_mismatch(self) -> Option<rustfs_gateway_sig::SignatureMismatchDetail> {
        self.signature_mismatch.into_inner()
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
    /// Produces an authentication outcome for one admitted request.
    ///
    /// [`Verdict`]'s widening variants each require a receipt this trait cannot manufacture:
    /// `Authenticated` needs a `SignatureMatch` that only a constant-time comparison produces, and
    /// `Anonymous` needs an `AnonymousAck` that only a request which presented nothing can yield.
    /// So an implementation can decide, and cannot invent. Custom implementations wrap that
    /// verdict with [`AuthenticationOutcome::ordinary`].
    fn authenticate<'a>(&'a self, request: &'a Authentication<'a>) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>>;

    /// Produces an authentication outcome for one admitted **SigV2** request.
    ///
    /// **The default refuses.** A SigV2 request is a distinct [`rustfs_gateway_sig::Admission`]
    /// variant carrying a [`rustfs_gateway_sig::SealedSigV2`], which has no route to the [`SealedAws`] the method
    /// above takes — so an authenticator written before SigV2 existed cannot be handed one by
    /// accident, keeps compiling, and answers `501 NotImplemented`. That is the fail-closed half
    /// of P2-06's wiring: the alternative to a refusing default is a trait method every existing
    /// implementation is forced to write, and the value most of them would write is the one that
    /// makes the request anonymous.
    fn authenticate_sigv2<'a>(
        &'a self,
        request: &'a SigV2Authentication<'a>,
    ) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
        let _ = request;
        super::sigv2::refuse_sigv2()
    }

    /// The credential-lookup protection this authenticator contributes to the assembled service.
    ///
    /// `None` means the authenticator has no credential-provider lookup. The built-in SigV4
    /// implementation always returns `Some`; this hook exists so the start-up posture report can
    /// name a deliberately disabled negative cache without inspecting a trait object.
    fn credential_guard_config(&self) -> Option<CredentialGuardConfig> {
        None
    }
}

impl<T: Authenticator + ?Sized> Authenticator for Arc<T> {
    fn authenticate<'a>(&'a self, request: &'a Authentication<'a>) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
        (**self).authenticate(request)
    }

    fn authenticate_sigv2<'a>(
        &'a self,
        request: &'a SigV2Authentication<'a>,
    ) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
        (**self).authenticate_sigv2(request)
    }

    fn credential_guard_config(&self) -> Option<CredentialGuardConfig> {
        (**self).credential_guard_config()
    }
}

/// SigV4 verification, assembled from `rustfs-gateway-sig`'s public primitives.
///
/// It contributes no rule of its own. Every step below is a call into the signature crate, in the
/// order that crate's own end-to-end cases use: cross-check the credential scope, resolve the
/// secret, enforce the signed-header list, canonicalise every path spelling, derive, and compare
/// in constant time.
pub struct SigV4Authenticator {
    /// `pub(super)` so the SigV2 half in `super::sigv2` reaches the same credential source. One
    /// store, one negative cache, one timing posture — a second authenticator holding its own
    /// would be two of each, kept in step by hand.
    pub(super) credentials: Arc<GuardedCredentialProvider>,
    regions: RegionSet,
    /// Whether a successful lookup's secret is handed to the handler (ADR-0022). Off by default;
    /// `pub(super)` so the SigV2 half honours the same switch.
    pub(super) hand_secret: bool,
    /// Which scope regions outside `regions` are verified (ADR-0023's grammar, the empty region).
    /// Both off by default; `pub(super)` so the switches in `super::authenticator_switches` set them.
    pub(super) region_policy: super::authenticator_switches::RegionPolicy,
}

/// An authenticated verdict, and the looked-up secret when the authenticator hands it on.
pub(super) type VerifiedWithSecret = (Verdict, Option<rustfs_gateway_sig::SecretBytes>);

impl core::fmt::Debug for SigV4Authenticator {
    /// Hand-written: a credential provider is not required to be `Debug`, and requiring it would
    /// push a derive onto every implementation for the sake of one line here.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigV4Authenticator")
            .field("regions", &self.regions)
            .field("credential_guard", self.credentials.config())
            .field("hands_caller_secret_to_handlers", &self.hand_secret)
            .field("accepts_any_signing_region", &self.region_policy.any_region)
            .field("accepts_empty_signing_region", &self.region_policy.empty_region)
            .field("verifies_unreadable_signing_regions", &self.region_policy.any_spelling)
            .field("reads_signing_regions_of_any_length", &self.region_policy.any_length)
            .finish()
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
        Self::with_guard_config(credentials, regions, CredentialGuardConfig::default())
    }

    /// Builds the verifier with an explicit credential lookup posture.
    #[must_use]
    pub fn with_guard_config(
        credentials: Arc<dyn CredentialProvider>,
        regions: RegionSet,
        config: CredentialGuardConfig,
    ) -> Self {
        Self {
            credentials: Arc::new(GuardedCredentialProvider::with_config(credentials, config)),
            regions,
            hand_secret: false,
            region_policy: super::authenticator_switches::RegionPolicy::default(),
        }
    }

    async fn verify(&self, request: &Authentication<'_>) -> Result<AuthenticationOutcome, Unavailable> {
        match self.try_verify(request).await {
            Ok(Some((verdict, secret))) => Ok(AuthenticationOutcome::authenticated(verdict, secret)),
            Ok(None) => Err(Unavailable),
            Err(VerificationFailure::Ordinary(error)) => Ok(AuthenticationOutcome::ordinary(Verdict::reject(error))),
            Err(VerificationFailure::Scope(scope_rejection)) => Ok(AuthenticationOutcome::scope_rejected(scope_rejection)),
        }
    }

    /// `Ok(None)` is the store outage; every other outcome is a verdict or a rejection.
    async fn try_verify(&self, request: &Authentication<'_>) -> Result<Option<VerifiedWithSecret>, VerificationFailure> {
        let sealed = request.sealed();
        let view = sealed.view();
        let location = sealed.marker().location();
        // Once a credential surface is present, parsing failure is still a credential failure.
        // Normalising it here keeps malformed material on the same 403 path and prevents a caller
        // from learning how far parsing got before an access key could be recovered.
        let presented =
            Presented::read(sealed, location, self.region_policy.region_rule()).map_err(|_| AuthError::InvalidAccessKeyId)?;

        // H5, and the only public producer of the `VerifiedScope` the derivation takes. A scope
        // the client chose therefore cannot seed a signing key.
        let expected = self
            .region_policy
            .apply(ExpectedScope::new(sealed.expected_service(), &self.regions));
        let verified = enforce_scope(presented.scope(), sealed.clock(), &expected).map_err(VerificationFailure::Scope)?;

        let resolved = self
            .credentials
            .lookup(presented.scope().access_key_id().access_key_id())
            .await;
        // An unknown key derives from a placeholder rather than returning early, so that the
        // uniform wire response does not still carry two distinct latency classes.
        let secret = match &resolved {
            Ok(CredentialLookup::Found(credentials)) => credentials.secret().clone_secret(),
            Ok(CredentialLookup::NotFound) | Err(_) => timing::placeholder_secret(),
        };

        // Decided here, answered at the bottom. The session rules — expiry, and the binding
        // between the access key and the token — are cheap enough to be tempting as an early
        // return, and an early return is exactly what makes an expired token distinguishable from
        // a wrong secret by the clock. Holding the verdict until after the derivation is also what
        // keeps cheap session checks from introducing a shorter rejection path.
        let refusal = match &resolved {
            Ok(CredentialLookup::Found(credentials)) => match location {
                SigLocation::FormField => credentials
                    .admit(presented.session_token().map(SessionToken::expose), sealed.clock().now())
                    .err(),
                SigLocation::Query if view.query_contains(X_AMZ_SECURITY_TOKEN) => {
                    credentials.admit_query(view.query(), sealed.clock().now()).err()
                }
                _ => credentials
                    .admit(
                        view.headers()
                            .get(X_AMZ_SECURITY_TOKEN_HEADER)
                            .map(http::HeaderValue::as_bytes),
                        sealed.clock().now(),
                    )
                    .err(),
            },
            Ok(CredentialLookup::NotFound) | Err(_) => None,
        };

        let key = signing_key(&secret, &verified);
        let date = presented.signed_at(sealed);
        let (mut proof, mismatch_detail): (Option<SignatureMatch>, Option<rustfs_gateway_sig::SignatureMismatchDetail>) =
            match &presented {
                Presented::Form(policy) => (policy.verify(&key).ok(), None),
                Presented::Header(_) | Presented::Query(_) => {
                    let (signed_headers, signature) =
                        presented.canonical_parts().ok_or(AuthError::AuthorizationHeaderMalformed)?;
                    let signed =
                        SignedHeaderSet::parse_and_enforce(signed_headers, view.headers(), request.declared_content_length())?;
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
                    let mut matched = None;
                    let mut detail = None;
                    for candidate in spec.candidates()? {
                        let string_to_sign = candidate.string_to_sign(&date, presented.scope());
                        let derived = calculate_signature(&key, &string_to_sign);
                        detail = Some(rustfs_gateway_sig::SignatureMismatchDetail::new(&candidate, &string_to_sign));
                        // Every candidate is derived and compared even after one has matched:
                        // returning early would make the number of HMAC rounds observable.
                        if let Ok(equal) = signature.ct_verify(&derived) {
                            matched = matched.or(Some(equal));
                        }
                    }
                    (matched, detail)
                }
            };

        // The unknown-key branch has now paid for the same derivation a known key does. Only after
        // that is the uniform credential rejection answered.
        let Ok(CredentialLookup::Found(credentials)) = resolved else {
            return Err(AuthError::InvalidAccessKeyId.into());
        };
        let Some(proof) = proof.take() else {
            if refusal.is_some() {
                return Err(AuthError::InvalidAccessKeyId.into());
            }
            let Some(detail) = mismatch_detail else {
                return Err(AuthError::SignatureDoesNotMatch.into());
            };
            let _ = request.signature_mismatch.set(detail);
            return Err(AuthError::SignatureDoesNotMatch.into());
        };
        // A credential that exists, is correctly signed for, and is still not usable: switched
        // off, expired, or presented without the token it is bound to. Answered as
        // `InvalidAccessKeyId` — the same code, the same message and the same bytes an unknown key
        // gets — because "this key exists but you may not use it this way" confirms the key exists
        // to whoever is guessing. GHSA-3p3x-734c-h5vx is the FTPS version of that confirmation.
        if refusal.is_some() {
            return Err(AuthError::InvalidAccessKeyId.into());
        }
        if self.region_policy.refuses_after_verification(presented.scope().region()) {
            return Err(AuthError::InvalidCredentialRegion.into());
        }

        let identity_axis = match credentials.session_token() {
            Some(token) => SigIdentity::Session {
                token: token.clone_secret(),
            },
            None => SigIdentity::LongTerm,
        };
        let scheme = match location {
            SigLocation::Query => AuthScheme::sigv4_presigned(identity_axis, sealed.expected_service()),
            SigLocation::FormField => AuthScheme::post_policy(SigFamily::V4, identity_axis, sealed.expected_service()),
            SigLocation::Header => AuthScheme::sigv4_header(identity_axis, sealed.expected_service()),
            _ => return Err(AuthError::AuthorizationHeaderMalformed.into()),
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
        // The scope published is the one `enforce_scope` produced above and the signing key was
        // derived from — not a re-parse of the header and not a configured region, so a verdict
        // cannot name a region other than the one the signature is valid under (ADR-0020).
        // The secret is the one this lookup returned and the signature was just verified with,
        // copied only when the deployment asked for the hand-off (ADR-0022).
        let secret = self.hand_secret.then(|| credentials.secret().clone_secret());
        let verdict = Verdict::authenticated_in_scope(credentials.identity().clone(), scheme, verified, proof);
        Ok(Some((verdict, secret)))
    }
}

impl Authenticator for SigV4Authenticator {
    fn authenticate<'a>(&'a self, request: &'a Authentication<'a>) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
        Box::pin(self.verify(request))
    }

    /// The one override in this crate. `SigV4Authenticator` is named for the algorithm it was
    /// written around, and it answers SigV2 too because it is the type that holds the credential
    /// source — a second authenticator would mean a second credential store, a second negative
    /// cache and a second timing posture to keep in step.
    fn authenticate_sigv2<'a>(
        &'a self,
        request: &'a SigV2Authentication<'a>,
    ) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
        Box::pin(self.verify_sigv2(request))
    }

    fn credential_guard_config(&self) -> Option<CredentialGuardConfig> {
        Some(*self.credentials.config())
    }
}

enum VerificationFailure {
    Ordinary(AuthError),
    Scope(ScopeRejection),
}

impl From<AuthError> for VerificationFailure {
    fn from(error: AuthError) -> Self {
        Self::Ordinary(error)
    }
}

/// The signature material the client presented, from whichever surface carried it.
///
/// One type for both surfaces so that the verification body has no `match` on the location running
/// through the middle of it — the two differ in where the values are read and in nothing else.
enum Presented {
    Header(Box<SigV4Authorization>),
    Query(Box<PresignedParams>),
    Form(Box<PostPolicy>),
}

impl Presented {
    fn read(sealed: &SealedAws<'_>, location: SigLocation, rule: RegionRule) -> Result<Self, AuthError> {
        match location {
            SigLocation::Query => Ok(Self::Query(Box::new(PresignedParams::parse_with(&sealed.view().query(), rule)?))),
            SigLocation::FormField => {
                let fields = sealed.view().form_fields().ok_or(AuthError::AuthorizationHeaderMalformed)?;
                let policy = PostPolicy::parse_with(fields, "", PostPolicyLimits::default(), sealed.clock().now(), rule)
                    .map_err(PostPolicyError::auth_error)?;
                Ok(Self::Form(Box::new(policy)))
            }
            SigLocation::Header => {
                let raw = sealed
                    .view()
                    .headers()
                    .get(AUTHORIZATION_HEADER)
                    .ok_or(AuthError::AuthorizationHeaderMalformed)?
                    .to_str()
                    .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
                Ok(Self::Header(Box::new(SigV4Authorization::parse_with(raw, rule)?)))
            }
            _ => Err(AuthError::AuthorizationHeaderMalformed),
        }
    }

    fn scope(&self) -> &CredentialScope {
        match self {
            Self::Header(parsed) => parsed.scope(),
            Self::Query(parsed) => parsed.scope(),
            Self::Form(policy) => policy.scope(),
        }
    }

    fn canonical_parts(&self) -> Option<(&str, &Signature)> {
        match self {
            Self::Header(parsed) => Some((parsed.signed_headers(), parsed.signature())),
            Self::Query(parsed) => Some((parsed.signed_headers(), parsed.signature())),
            Self::Form(_) => None,
        }
    }

    fn session_token(&self) -> Option<&SessionToken> {
        let Self::Form(policy) = self else { return None };
        policy.session_token()
    }

    /// The timestamp the string-to-sign is dated with.
    ///
    /// For a presigned URL it is the one in the query; for a header-signed request it is the
    /// receipt the skew check produced, which is the same value the floor validated.
    fn signed_at(&self, sealed: &SealedAws<'_>) -> AmzDate {
        match self {
            Self::Header(_) => sealed.clock().signed_at(),
            Self::Query(parsed) => parsed.date(),
            Self::Form(policy) => policy.signed_at(),
        }
    }
}

#[cfg(test)]
#[path = "authenticator_tests.rs"]
mod tests;
