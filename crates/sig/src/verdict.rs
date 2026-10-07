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

//! The outcome of authentication, shaped so that "never compared" cannot be spelled.
//!
//! Responsible for: [`Verdict`] and its three outcomes, [`Identity`] (who a verified request runs
//! as), [`AuthError`] (why one was rejected, with no request bytes attached), and the two evidence
//! tokens — [`SignatureMatch`], re-exported from [`crate::signature`], and [`AnonymousAck`] — that
//! a caller must present to claim an outcome.
//! NOT responsible for: parsing the request (P2-03), clock skew, expiry and scope cross-checks
//! (P2-04), credential lookup (the `Authorizer` extension point), or authorization — a `Verdict`
//! says who the request is, never what it may do.
//! Upstream: [`crate::AuthScheme`], [`crate::SignatureMatch`], [`crate::SigParseError`].
//! Downstream: `rustfs-gateway-core`'s authn stage, and the audit record it emits.
//!
//! # The defect this file exists to make unrepresentable
//!
//! MinIO CVE-2025-31489 was not a timing flaw. The implementation checked that the access key
//! existed and had write permission, and then authenticated the request — it never compared the
//! signature at all. Against that defect, "the signature type has no `PartialEq`" is worth
//! nothing: nobody called a comparison to begin with, so removing the comparison operator removes
//! nothing.
//!
//! What does work is making the *result* of the comparison a value that only a real comparison can
//! produce, and then requiring that value in order to say "authenticated":
//!
//! ```compile_fail,E0063
//! use rustfs_gateway_sig::{AuthScheme, Identity, SigService, Verdict};
//! let identity = Identity::new("AKIAIOSFODNN7EXAMPLE").expect("valid");
//! let scheme = AuthScheme::sigv4_header(rustfs_gateway_sig::SigIdentity::LongTerm, SigService::S3);
//! // No `proof` field: the access key existed, nothing was compared, and this does not compile.
//! let _ = Verdict::Authenticated { identity, scheme };
//! ```
//!
//! [`SignatureMatch`] has a private field and no `Default`, `Clone` or `Copy`; only
//! [`crate::Signature::ct_verify`] hands it out, so the token cannot be conjured or reused:
//!
//! ```compile_fail,E0423
//! use rustfs_gateway_sig::SignatureMatch;
//! let _ = SignatureMatch(()); // private field: does not compile outside the crate
//! ```
//!
//! ```compile_fail,E0599
//! use rustfs_gateway_sig::SignatureMatch;
//! let _ = SignatureMatch::default(); // no Default: does not compile
//! ```
//!
//! Nor may the outcome of a comparison be thrown away and the request waved through anyway. The
//! result is `#[must_use]` by virtue of being a `Result`, so discarding it is a warning, and CI
//! compiles this workspace with `-D warnings`:
//!
//! ```compile_fail
//! #![deny(unused_must_use)]
//! use rustfs_gateway_sig::{CtBytes, Signature};
//! let a = Signature::HmacSha256(CtBytes::from_array([0u8; 32]));
//! let b = Signature::HmacSha256(CtBytes::from_array([0u8; 32]));
//! a.ct_verify(&b); // result discarded: does not compile under -D warnings
//! ```
//!
//! # Anonymous is an outcome, never a fallback
//!
//! [`Verdict::Anonymous`] carries [`AnonymousAck`], which is likewise unconstructible from
//! outside. The only way to obtain one is [`CredentialPresence::into_evidence`], and it fails
//! whenever the request touched *any* authentication surface. That is the type-level half of
//! fail-closed-on-presented: a request that carried an `Authorization` header and failed
//! verification cannot be downgraded to anonymous, because the evidence that would let the caller
//! build the anonymous verdict does not exist.
//!
//! ```compile_fail,E0423
//! use rustfs_gateway_sig::AnonymousAck;
//! let _ = AnonymousAck(()); // private field: does not compile outside the crate
//! ```
//!
//! ```compile_fail,E0277
//! use rustfs_gateway_sig::{CredentialPresence, Verdict};
//! let presented = CredentialPresence::NONE.with_authorization_header();
//! // There is no infallible route from a presented credential to an anonymous verdict.
//! let _ = Verdict::anonymous(presented.into_evidence().unwrap_or_default());
//! ```
//!
//! The consequence of getting this wrong is the worst of the three: on a public-read bucket every
//! forged request succeeds unsigned, and the audit log records the principal as anonymous, so
//! there is nothing to trace afterwards.

use core::fmt;

use crate::derive::VerifiedScope;
use crate::error::{SigParseError, Unimplemented};
use crate::scheme::AuthScheme;
use crate::signature::{SignatureMatch, VerifyRejection};

/// Longest access key id accepted. AWS issues 20 characters; STS issues longer ones, and the
/// documented ceiling for the credential field is 128.
const MAX_ACCESS_KEY_ID_LEN: usize = 128;
const MAX_SESSION_HANDLE_LEN: usize = 256;

/// The non-secret identity context issued with temporary credentials.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionBinding {
    expires_at_unix_seconds: i64,
    issuer: Box<str>,
    inline_policy: Option<Box<str>>,
}

impl SessionBinding {
    /// Records who issued a temporary credential and when it stops working.
    ///
    /// # Errors
    ///
    /// [`SessionBindingError`] when the issuer cannot safely enter an audit record.
    pub fn new(issuer: &str, expires_at_unix_seconds: i64) -> Result<Self, SessionBindingError> {
        Ok(Self {
            expires_at_unix_seconds,
            issuer: Box::from(check_session_handle(issuer)?),
            inline_policy: None,
        })
    }

    /// Attaches an opaque session-policy handle.
    ///
    /// # Errors
    ///
    /// [`SessionBindingError`] under the same audit-safe rule as [`SessionBinding::new`].
    pub fn with_inline_policy(mut self, handle: &str) -> Result<Self, SessionBindingError> {
        self.inline_policy = Some(Box::from(check_session_handle(handle)?));
        Ok(self)
    }

    /// The final usable Unix second.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> i64 {
        self.expires_at_unix_seconds
    }

    /// Opaque issuer identifier.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Opaque inline-policy handle.
    #[must_use]
    pub fn inline_policy(&self) -> Option<&str> {
        self.inline_policy.as_deref()
    }
}

/// A session binding contains an empty, overlong or non-graphic audit handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionBindingError;

impl fmt::Display for SessionBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the session binding names a value an audit record could not carry")
    }
}

impl std::error::Error for SessionBindingError {}

fn check_session_handle(value: &str) -> Result<&str, SessionBindingError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SESSION_HANDLE_LEN || !bytes.iter().all(u8::is_ascii_graphic) {
        return Err(SessionBindingError);
    }
    Ok(value)
}

/// Who a request runs as, once a [`SignatureMatch`] has proved it.
///
/// This is the *principal*; [`crate::SigIdentity`] on the other axis is the *kind of credential*
/// that was presented (long-term, session, none). They are separate because a session identity and
/// a long-term identity can name the same principal.
///
/// The access key id is a public identifier — AWS returns it in error responses and records it in
/// CloudTrail — so unlike every other value in the authentication path it is safe to log, and this
/// type therefore has a derived `Debug`. It is validated to ASCII graphic characters at
/// construction, because an access key id containing `\r\n` that reaches a log line is log
/// injection, and one containing a control character can corrupt an audit record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    access_key_id: Box<str>,
    session: Option<SessionBinding>,
}

impl Identity {
    /// Validates and stores an access key id.
    ///
    /// # Errors
    ///
    /// [`SigParseError::InvalidAccessKeyId`] if the value is empty, longer than 128 bytes, or
    /// contains anything other than ASCII graphic characters. Rejection happens here rather than
    /// at the log call site so that there is exactly one place to get it right.
    pub fn new(access_key_id: &str) -> Result<Self, SigParseError> {
        let bytes = access_key_id.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_ACCESS_KEY_ID_LEN {
            return Err(SigParseError::InvalidAccessKeyId);
        }
        if !bytes.iter().all(u8::is_ascii_graphic) {
            return Err(SigParseError::InvalidAccessKeyId);
        }
        Ok(Self {
            access_key_id: Box::from(access_key_id),
            session: None,
        })
    }

    /// The access key id. A public identifier, safe in a log line and in an audit record.
    #[must_use]
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// Attaches the non-secret identity context of a verified temporary credential.
    #[must_use]
    pub fn with_session_binding(mut self, binding: SessionBinding) -> Self {
        self.session = Some(binding);
        self
    }

    /// The verified temporary-credential context, when this principal used one.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionBinding> {
        self.session.as_ref()
    }
}

/// Why authentication failed.
///
/// Every variant is fieldless or carries a closed enum, so no byte of the request — and above all
/// no expected signature — can ride along into a log or a response body. "Expected vs actual" in
/// an authentication error is a signing oracle, which is how GHSA-r54g, GHSA-8cm2 and GHSA-333v
/// happened.
///
/// # Why two credential rejections still exist internally
///
/// [`AuthError::InvalidAccessKeyId`] and [`AuthError::SignatureDoesNotMatch`] are distinct because
/// AWS S3 defines distinct internal reasons, and retaining both keeps verification tests precise.
/// The gateway renderer deliberately collapses both into the same public code, message, status,
/// headers and body. The failure path is also held to a common floor by
/// [`crate::timing::FailureFloor`] so the store cannot be probed through response latency.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthError {
    /// The presented access key id is not known to the credential provider.
    InvalidAccessKeyId,
    /// The access key is known and the computed signature did not match the presented one.
    ///
    /// Also the answer when the two signatures are of different algorithm families: which one the
    /// server expected is not something a client needs, and telling it would help an attacker
    /// probe for a downgrade.
    SignatureDoesNotMatch,
    /// The authentication material was present but could not be parsed.
    AuthorizationHeaderMalformed,
    /// The signature verified, but the request may not proceed.
    AccessDenied,
    /// The signed timestamp is outside the accepted window (H1).
    ///
    /// The same answer on all three signing paths. A window that applied to presigned requests
    /// only is the defect s3s#616 fixed.
    RequestTimeTooSkewed,
    /// A presigned URL's query parameters are missing, repeated, or not acceptable (H2, H6).
    ///
    /// Covers `X-Amz-Expires` outside `1..=604800` and every non-strict spelling of it, and a
    /// signature-bearing query parameter that appeared twice.
    AuthorizationQueryParametersError,
    /// A presigned URL was used after its lifetime ended (H2).
    ///
    /// The code is `AccessDenied`, which is what S3 answers, and the message is the same as
    /// [`AuthError::AccessDenied`]'s — expiry is not a fact worth confirming to a caller holding
    /// a URL it did not mint.
    RequestExpired,
    /// The scheme was recognised and is deliberately unimplemented; the caller must answer `501`.
    NotImplemented(Unimplemented),
    /// A signature verified over a credential scope whose region is outside the region grammar:
    /// refused after the comparison with `InvalidRequest`, the answer legacy RustFS gives it
    /// (rustfs/gateway#1075). Only a verifier that admits such a region for key derivation
    /// ([`crate::ExpectedScope::accepting_any_region_spelling`]) produces it.
    InvalidCredentialRegion,
    /// A browser POST policy is not bounded, valid base64; refused before signature comparison.
    InvalidPostPolicyEncoding,
    /// A SigV2 browser form carries a signature but not its access key or policy: refused
    /// `InvalidRequest` before any lookup, as legacy RustFS refuses it (rustfs/gateway#1185).
    MissingPostFormField,
}

impl AuthError {
    /// The AWS error code a client sees.
    ///
    /// Kept faithful to S3 on purpose: these strings are part of the API surface, and SDK retry
    /// and credential-refresh logic branches on them.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidAccessKeyId => "InvalidAccessKeyId",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::AuthorizationHeaderMalformed => "AuthorizationHeaderMalformed",
            Self::AccessDenied | Self::RequestExpired => "AccessDenied",
            Self::RequestTimeTooSkewed => "RequestTimeTooSkewed",
            Self::AuthorizationQueryParametersError => "AuthorizationQueryParametersError",
            Self::NotImplemented(_) => "NotImplemented",
            Self::InvalidCredentialRegion | Self::InvalidPostPolicyEncoding | Self::MissingPostFormField => "InvalidRequest",
        }
    }

    /// The human-readable message, which deliberately says less than the code does.
    ///
    /// [`AuthError::InvalidAccessKeyId`] and [`AuthError::SignatureDoesNotMatch`] return the exact
    /// same sentence, so the message never confirms which half of the credential was wrong, and a
    /// log line that records only the message is not an access-key oracle.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        match self {
            Self::InvalidAccessKeyId | Self::SignatureDoesNotMatch => "the request was not authenticated",
            Self::AuthorizationHeaderMalformed => "the authentication material could not be parsed",
            Self::AccessDenied | Self::RequestExpired => "the request is not allowed",
            Self::RequestTimeTooSkewed => "the request timestamp is outside the accepted window",
            Self::AuthorizationQueryParametersError => "the presigned query parameters are not acceptable",
            // The one arm that varies with its payload. "Recognised and refused" is not one
            // sentence: a client told its algorithm is unimplemented and a client told its
            // *framing* is unimplemented have different things to change, and neither sentence
            // says anything the request did not already state. Every spelling is still a
            // constant, so nothing derived from the request reaches the wire.
            Self::NotImplemented(feature) => feature.message(),
            Self::InvalidCredentialRegion => "the credential scope names a region this service cannot read",
            Self::InvalidPostPolicyEncoding => "the POST policy encoding is not valid",
            Self::MissingPostFormField => "a POST form field the signature needs is missing",
        }
    }

    /// Whether this rejection is one of the two that must be indistinguishable in latency.
    #[must_use]
    pub const fn is_credential_rejection(&self) -> bool {
        matches!(self, Self::InvalidAccessKeyId | Self::SignatureDoesNotMatch)
    }
}

impl From<VerifyRejection> for AuthError {
    /// Both comparison rejections become `SignatureDoesNotMatch`.
    ///
    /// [`VerifyRejection::AlgorithmMismatch`] is a fact about the server's expectation, not about
    /// the client's request, so it stops here.
    fn from(_rejection: VerifyRejection) -> Self {
        Self::SignatureDoesNotMatch
    }
}

impl From<SigParseError> for AuthError {
    fn from(error: SigParseError) -> Self {
        match error {
            SigParseError::NotImplemented(feature) => Self::NotImplemented(feature),
            _ => Self::AuthorizationHeaderMalformed,
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl core::error::Error for AuthError {}

/// Proof that the request presented no authentication material at all.
///
/// Zero-sized, with a private field and no `Default`: the only producer is
/// [`CredentialPresence::into_evidence`], and it refuses whenever any authentication surface was
/// touched. It exists so that [`Verdict::Anonymous`] cannot be reached from a failed verification.
pub struct AnonymousAck(());

/// The refusal returned when anonymous access is claimed for a request that presented credentials.
///
/// Fail-closed on presented: a request that carried an `Authorization` header, an
/// `X-Amz-Signature`, a POST-policy signature or a security token must be verified or rejected.
/// Never downgraded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CredentialsWerePresented;

impl fmt::Display for CredentialsWerePresented {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("credentials were presented; the request must be verified, never treated as anonymous")
    }
}

impl core::error::Error for CredentialsWerePresented {}

/// Which authentication surfaces the request touched.
///
/// Four booleans and nothing else — this type carries no credential material, only the fact that
/// each surface was or was not populated. The wire layer fills it in; the authentication stage
/// turns it into evidence.
///
/// The security token counts as a surface even though it is not itself a signature: a request that
/// carries `X-Amz-Security-Token` and nothing else is malformed, and treating it as anonymous
/// would let a client strip the signature off a session-credentialed request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CredentialPresence {
    authorization_header: bool,
    query_signature: bool,
    post_policy_signature: bool,
    security_token: bool,
}

impl CredentialPresence {
    /// Nothing was presented on any surface.
    pub const NONE: Self = Self {
        authorization_header: false,
        query_signature: false,
        post_policy_signature: false,
        security_token: false,
    };

    /// Records that an `Authorization` header was present.
    #[must_use]
    pub const fn with_authorization_header(mut self) -> Self {
        self.authorization_header = true;
        self
    }

    /// Records that a query signature (`X-Amz-Signature`, or SigV2's `Signature`) was present.
    #[must_use]
    pub const fn with_query_signature(mut self) -> Self {
        self.query_signature = true;
        self
    }

    /// Records that a POST-policy form signature was present.
    #[must_use]
    pub const fn with_post_policy_signature(mut self) -> Self {
        self.post_policy_signature = true;
        self
    }

    /// Records that an `X-Amz-Security-Token` was present.
    #[must_use]
    pub const fn with_security_token(mut self) -> Self {
        self.security_token = true;
        self
    }

    /// Whether any authentication surface was touched.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.authorization_header || self.query_signature || self.post_policy_signature || self.security_token
    }

    /// Whether more than one signature surface was populated.
    ///
    /// A request carrying both an `Authorization` header and `X-Amz-Signature` is ambiguous: the
    /// two surfaces sign different canonical forms, so accepting either one lets a client pick
    /// which of two verifications it would rather pass. P2-04 rejects the combination; this
    /// predicate is what it asks.
    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        let surfaces = self.authorization_header as u8 + self.query_signature as u8 + self.post_policy_signature as u8;
        surfaces > 1
    }

    /// Turns "nothing was presented" into the evidence [`Verdict::anonymous`] requires.
    ///
    /// # Errors
    ///
    /// [`CredentialsWerePresented`] if any surface was populated. This is the whole point: the
    /// evidence cannot be manufactured on a request that failed verification.
    pub const fn into_evidence(self) -> Result<AnonymousAck, CredentialsWerePresented> {
        if self.any() {
            Err(CredentialsWerePresented)
        } else {
            Ok(AnonymousAck(()))
        }
    }
}

/// The outcome of authenticating one request.
///
/// Three outcomes, and each one has to be earned:
///
/// * [`Verdict::Authenticated`] requires a [`SignatureMatch`], which only
///   [`crate::Signature::ct_verify`] produces;
/// * [`Verdict::Anonymous`] requires an [`AnonymousAck`], which only
///   [`CredentialPresence::into_evidence`] produces, and only when nothing was presented;
/// * [`Verdict::Reject`] requires nothing, because rejecting is always allowed.
///
/// That asymmetry is deliberate. Every path that widens access has to carry a receipt; the path
/// that narrows it does not.
///
/// There is no `Clone`: a verdict is the result of one verification of one request, and a copy of
/// it applied to a second request is precisely the confused-deputy shape.
#[non_exhaustive]
pub enum Verdict {
    /// The signature was compared in constant time and matched.
    Authenticated {
        /// Who the request runs as.
        identity: Identity,
        /// How it was signed.
        scheme: AuthScheme,
        /// The credential scope the signing key was derived from, when the scheme has one.
        ///
        /// `Some` only for a SigV4 verdict, and only with a [`VerifiedScope`] — which has no
        /// public constructor and whose one public producer is [`crate::enforce_scope`]. A
        /// scope the client wrote therefore cannot appear here unchecked. SigV2 and custom
        /// schemes have no credential scope and carry `None`; nothing infers one (ADR-0020).
        scope: Option<VerifiedScope>,
        /// The receipt from the comparison. Unforgeable, and required.
        proof: SignatureMatch,
    },
    /// No authentication material was presented, and that was confirmed rather than assumed.
    Anonymous(AnonymousAck),
    /// Authentication failed. Carries no request bytes.
    Reject(AuthError),
}

impl Verdict {
    /// Builds an authenticated verdict from a real comparison result.
    ///
    /// There is no variant of this constructor that takes the identity alone. Looking a credential
    /// up and finding it is not authentication.
    #[must_use]
    pub fn authenticated(identity: Identity, scheme: AuthScheme, proof: SignatureMatch) -> Self {
        Self::Authenticated {
            identity,
            scheme,
            scope: None,
            proof,
        }
    }

    /// Builds an authenticated verdict that also names the credential scope the signature was
    /// verified under.
    ///
    /// The scope must be the one the signing key was derived from. A [`VerifiedScope`] is only
    /// obtainable from [`crate::enforce_scope`], so a scope the client sent cannot be passed here
    /// without having been cross-checked against the clock, the served regions and the routed
    /// service first:
    ///
    /// ```compile_fail,E0599
    /// use rustfs_gateway_sig::{AuthScheme, Identity, SigIdentity, SigService, SignatureMatch, Verdict, VerifiedScope};
    /// fn claim(identity: Identity, proof: SignatureMatch) -> Verdict {
    ///     let scheme = AuthScheme::sigv4_header(SigIdentity::LongTerm, SigService::S3);
    ///     // No constructor: a region the client named cannot become a verified scope.
    ///     Verdict::authenticated_in_scope(identity, scheme, VerifiedScope::new("20150830", "eu-west-1", "s3"), proof)
    /// }
    /// ```
    ///
    /// ```compile_fail,E0451
    /// use rustfs_gateway_sig::{ScopeDate, VerifiedScope};
    /// let date = ScopeDate::parse("20150830").expect("valid");
    /// // Private fields: a struct literal is no way around the missing constructor either.
    /// let _ = VerifiedScope { date, region: Box::from("eu-west-1"), service: Box::from("s3") };
    /// ```
    #[must_use]
    pub fn authenticated_in_scope(identity: Identity, scheme: AuthScheme, scope: VerifiedScope, proof: SignatureMatch) -> Self {
        Self::Authenticated {
            identity,
            scheme,
            scope: Some(scope),
            proof,
        }
    }

    /// Builds an anonymous verdict from evidence that nothing was presented.
    #[must_use]
    pub fn anonymous(evidence: AnonymousAck) -> Self {
        Self::Anonymous(evidence)
    }

    /// Builds a rejection.
    #[must_use]
    pub fn reject(error: AuthError) -> Self {
        Self::Reject(error)
    }

    /// The principal, when the request was authenticated.
    ///
    /// `None` for both anonymous and rejected: an anonymous request has no principal, and a
    /// rejected one must not be attributed to the access key it claimed.
    #[must_use]
    pub fn identity(&self) -> Option<&Identity> {
        match self {
            Self::Authenticated { identity, .. } => Some(identity),
            _ => None,
        }
    }

    /// The credential scope the signature was verified under.
    ///
    /// `None` for an anonymous or rejected request, and for an authenticated one whose scheme has
    /// no credential scope (SigV2, a custom scheme). Never a configured default: a caller that
    /// needs a region for an unscoped request decides that for itself.
    #[must_use]
    pub const fn verified_scope(&self) -> Option<&VerifiedScope> {
        match self {
            Self::Authenticated { scope, .. } => scope.as_ref(),
            _ => None,
        }
    }

    /// Whether the request carried a proved signature.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated { .. })
    }

    /// Whether the request presented nothing and was confirmed anonymous.
    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        matches!(self, Self::Anonymous(_))
    }

    /// The rejection, when there was one.
    #[must_use]
    pub const fn rejection(&self) -> Option<AuthError> {
        match self {
            Self::Reject(error) => Some(*error),
            _ => None,
        }
    }
}

impl fmt::Debug for Verdict {
    /// Hand-written, and audit-shaped: it names the principal and the scheme, and says that a
    /// proof exists without pretending to render one.
    ///
    /// A derived `Debug` is impossible anyway — [`SignatureMatch`] has none — and that is the
    /// intended pressure. The access key id is the one value here that is safe to print.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated {
                identity, scheme, scope, ..
            } => f
                .debug_struct("Authenticated")
                .field("identity", identity)
                .field("scheme", scheme)
                .field("scope", scope)
                .field("proof", &"<constant-time match>")
                .finish(),
            Self::Anonymous(_) => f.write_str("Anonymous"),
            Self::Reject(error) => f.debug_tuple("Reject").field(error).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::{SigIdentity, SigService};

    fn identity() -> Identity {
        Identity::new("AKIAIOSFODNN7EXAMPLE").expect("valid access key id")
    }

    #[test]
    fn no_credentials_yields_anonymous() {
        let evidence = CredentialPresence::NONE.into_evidence().expect("nothing presented");
        assert!(Verdict::anonymous(evidence).is_anonymous());
    }

    #[test]
    fn presented_credentials_cannot_be_downgraded_to_anonymous() {
        let presented = CredentialPresence::NONE.with_authorization_header();
        assert_eq!(presented.into_evidence().err(), Some(CredentialsWerePresented));
    }

    #[test]
    fn a_security_token_alone_still_counts_as_presented() {
        let presented = CredentialPresence::NONE.with_security_token();
        assert!(presented.any());
        assert!(presented.into_evidence().is_err());
    }

    #[test]
    fn the_two_credential_rejections_share_one_message() {
        assert_eq!(AuthError::InvalidAccessKeyId.message(), AuthError::SignatureDoesNotMatch.message());
        assert_ne!(AuthError::InvalidAccessKeyId.code(), AuthError::SignatureDoesNotMatch.code());
    }

    #[test]
    fn algorithm_mismatch_is_not_reported_to_the_client() {
        assert_eq!(AuthError::from(VerifyRejection::AlgorithmMismatch), AuthError::SignatureDoesNotMatch);
        assert_eq!(AuthError::from(VerifyRejection::Mismatch), AuthError::SignatureDoesNotMatch);
    }

    #[test]
    fn a_rejected_verdict_names_no_principal() {
        let verdict = Verdict::reject(AuthError::InvalidAccessKeyId);
        assert!(verdict.identity().is_none());
        assert!(!verdict.is_authenticated());
    }

    #[test]
    fn debug_of_an_authenticated_verdict_shows_the_key_id_and_no_proof_bytes() {
        let scheme = AuthScheme::sigv4_header(SigIdentity::LongTerm, SigService::S3);
        let proof = crate::Signature::HmacSha256(crate::CtBytes::from_array([3u8; 32]))
            .ct_verify(&crate::Signature::HmacSha256(crate::CtBytes::from_array([3u8; 32])))
            .expect("equal signatures match");
        let rendered = format!("{:?}", Verdict::authenticated(identity(), scheme, proof));
        assert!(rendered.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(rendered.contains("<constant-time match>"));
    }

    fn proof() -> SignatureMatch {
        crate::Signature::HmacSha256(crate::CtBytes::from_array([3u8; 32]))
            .ct_verify(&crate::Signature::HmacSha256(crate::CtBytes::from_array([3u8; 32])))
            .expect("equal signatures match")
    }

    fn scope(region: &str) -> VerifiedScope {
        VerifiedScope::from_checked_parts(crate::ScopeDate::parse("20150830").expect("valid"), region, "s3")
    }

    /// Positive — the scope the signature was verified under travels with the verdict, every
    /// field in the spelling that was signed.
    #[test]
    fn an_authenticated_verdict_carries_the_scope_it_was_verified_under() {
        let scheme = AuthScheme::sigv4_header(SigIdentity::LongTerm, SigService::S3);
        let verdict = Verdict::authenticated_in_scope(identity(), scheme, scope("eu-west-1"), proof());
        let carried = verdict.verified_scope().expect("a SigV4 verdict names its scope");
        assert_eq!(
            (carried.date().as_str(), carried.region(), carried.service()),
            ("20150830", "eu-west-1", "s3")
        );
    }

    /// Negative — a verdict that was never given a scope reports none, whatever its outcome. A
    /// scope is never inferred: SigV2 and a custom scheme have no credential scope at all.
    #[test]
    fn a_verdict_built_without_a_scope_reports_none() {
        let scheme = AuthScheme::sigv2_header(SigIdentity::LongTerm, SigService::S3);
        assert!(Verdict::authenticated(identity(), scheme, proof()).verified_scope().is_none());
        assert!(Verdict::reject(AuthError::SignatureDoesNotMatch).verified_scope().is_none());
        let evidence = CredentialPresence::NONE.into_evidence().expect("nothing presented");
        assert!(Verdict::anonymous(evidence).verified_scope().is_none());
    }

    /// Negative — the audit rendering names the scope, which is public, and still no proof bytes.
    #[test]
    fn debug_of_a_scoped_verdict_names_the_scope() {
        let scheme = AuthScheme::sigv4_header(SigIdentity::LongTerm, SigService::S3);
        let rendered = format!("{:?}", Verdict::authenticated_in_scope(identity(), scheme, scope("eu-west-1"), proof()));
        assert!(rendered.contains("eu-west-1"), "{rendered}");
        assert!(rendered.contains("<constant-time match>"), "{rendered}");
    }

    #[test]
    fn access_key_ids_with_control_characters_are_rejected() {
        for bad in ["", "AKIA\r\nX-Injected: 1", "AKIA KEY", "AKIA\u{0}KEY", "AKIA\u{e9}KEY"] {
            assert_eq!(Identity::new(bad), Err(SigParseError::InvalidAccessKeyId), "must reject {bad:?}");
        }
        assert_eq!(Identity::new(&"A".repeat(129)), Err(SigParseError::InvalidAccessKeyId));
    }
}
