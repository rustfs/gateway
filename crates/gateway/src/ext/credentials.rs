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

//! The credentials an access key id resolves to, and where they are looked up.
//!
//! Responsible for: [`Credentials`] — an access key id, its secret, and either nothing else or a
//! whole temporary session ([`SessionBinding`] plus its token and wire surface) — [`CredentialProvider`], the lookup an
//! authenticator performs, [`fn_credential_provider`], the closure form of it, and
//! [`StaticCredentials`], the in-memory provider a test fixture and the conformance suite use.
//! NOT responsible for: comparing anything (`rustfs-gateway-sig` owns every comparison), deriving
//! a signing key, or deciding what an unusable credential is answered with — that is
//! `super::authenticator`'s, because the answer is a timing decision as much as a protocol one.
//! Nor for validating the token itself: who issued it and what it claims is the deployment's STS
//! implementation's business, and this crate holds the value without parsing a byte of it.
//! Upstream: `rustfs-gateway-sig`. Downstream: `super::authenticator`, `crate::builder`.
//!
//! # Why the secret never leaves this type as bytes anyone can print
//!
//! [`Credentials`] holds a [`SecretBytes`], which has no `Debug`, no `PartialEq` and zeroes itself
//! on drop. The hand-written `Debug` below prints the access key id — a public identifier AWS
//! itself returns in error responses — and the word `<redacted>` for everything else. There is no
//! accessor that yields the secret as a `&str`.
//!
//! # Why a lookup result and a provider fault are separate
//!
//! [`CredentialLookup::NotFound`] is a normal result and may enter the negative cache.
//! [`ProviderError`] is an operational fault: it is counted, never cached, and still fails closed
//! with the same client response.
//!
//! # Why a token and a binding cannot be separated
//!
//! A temporary credential is a token *and* a lifetime. Held as two `Option`s, three of the four
//! combinations are wrong and only one of them is loud: a token with no lifetime is a session that
//! never expires, which is the defect GHSA-ccrv-v8v9-ch9q describes — a token accepted with no
//! `exp` at all. So the two travel inside one private [`Session`], and
//! [`Credentials::with_session`] / [`Credentials::with_s3_express_session`] are the only ways to
//! build one. "Temporary credentials with no expiry" is not a state this type can be put into.
//!
//! # What the framework enforces about a session, and what it refuses to
//!
//! Enforced, unconditionally, by [`Credentials::admit`]:
//!
//! * the lifetime — a binding whose instant has passed is not usable, judged against the request's
//!   own clock snapshot and never against a second reading;
//! * the binding between the access key and the token — a request that presents a token must name
//!   an access key the provider answers with for that exact token, and one that presents none must
//!   not. Signature coverage prevents in-flight replacement; the value comparison prevents a
//!   caller that knows one key pair from substituting another issuance's token.

use rustfs_gateway_sig::{Identity, RawQuery, RequestNow, SecretBytes, SessionToken};

pub use rustfs_gateway_sig::{SessionBinding, SessionBindingError};

pub use super::credential_provider::{
    CredentialLookup, CredentialProvider, CredentialsError, StaticCredentials, fn_credential_provider,
};
use super::session_answer::PendingSessionRefusal;

/// Which session-token wire surface a temporary credential is bound to.
///
/// STS sessions travel in `x-amz-security-token` / `X-Amz-Security-Token` (and POST policy forms);
/// S3 Express sessions travel exclusively in `x-amz-s3session-token` / `X-Amz-S3session-Token`.
/// Keeping the two surfaces disjoint prevents an S3 Express session from presenting its token in
/// `x-amz-security-token` to bypass `CreateSession`'s `DisableS3ExpressSessionAuth` or to
/// authenticate against ordinary `s3`-scoped endpoints, and prevents STS tokens from authenticating
/// on the `s3express` session surface.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionSurface {
    Sts,
    S3Express,
}

/// A temporary session: the token, its lifetime, and its wire surface, which are never apart.
///
/// Private, and holds a [`SessionToken`], so it has no `Debug` and cannot acquire one.
struct Session {
    token: SessionToken,
    binding: SessionBinding,
    surface: SessionSurface,
}

impl Session {
    /// Usable up to and including the final second, judged against the request's own snapshot.
    fn within_lifetime(&self, now: RequestNow) -> Result<(), CredentialRefusal> {
        if now.unix_seconds() > self.binding.expires_at_unix_seconds() {
            return Err(CredentialRefusal::SessionExpired);
        }
        Ok(())
    }
}

/// Why a credential that exists is nonetheless not usable for this request.
///
/// Every variant but one is answered identically on the wire — see
/// [`super::authenticator::SigV4Authenticator`] — and this enum exists so that the framework's own
/// tests can name which rule fired. It carries no request bytes and no key material. Telling an
/// arbitrary caller which rule fired is the S3 shape of the distinguishable-failure defect
/// GHSA-3p3x-734c-h5vx describes.
///
/// The exception is [`CredentialRefusal::SessionExpired`], and only after the signature compared
/// equal under the session's own secret: that caller holds the secret and the token already, and
/// is answered `ExpiredToken` so its SDK refreshes (rustfs/gateway#1575). [`Credentials::admit`]
/// compares the token before it judges the lifetime, so the variant implies the issued token.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialRefusal {
    /// The principal exists and has been switched off.
    Disabled,
    /// The request presented the token issued with this access key, and the session's lifetime
    /// ended before this request's instant.
    SessionExpired,
    /// The request presented a token and this access key is a long-term credential.
    ///
    /// Never "ignore the token and carry on": a token that the server drops is a scope the caller
    /// believed applied and that nothing enforced.
    TokenWithoutSessionCredential,
    /// The request presented no token and this access key is a temporary credential.
    SessionCredentialWithoutToken,
    /// The request presented a token other than the one issued with this access key.
    SessionTokenMismatch,
}

impl core::fmt::Display for CredentialRefusal {
    /// Deliberately uniform. There is one sentence, because a caller must not learn which rule
    /// fired, and an operator reading a log gets the access key id — which is a public identifier
    /// — from the record around it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the credential is not usable for this request")
    }
}

impl std::error::Error for CredentialRefusal {}

/// The reason, kept in this file, becomes an answer that needs the comparison's proof
/// (`super::session_answer`, rustfs/gateway#1575).
fn pending(refusal: CredentialRefusal) -> PendingSessionRefusal {
    PendingSessionRefusal::new(matches!(refusal, CredentialRefusal::SessionExpired))
}

/// One principal's long-term or temporary credentials.
pub struct Credentials {
    identity: Identity,
    secret: SecretBytes,
    session: Option<Session>,
    disabled: bool,
}

/// Singular spelling used by provider contracts; identical to [`Credentials`].
pub type Credential = Credentials;

impl Credentials {
    /// Builds a long-term credential pair.
    ///
    /// # Errors
    ///
    /// [`CredentialsError::Malformed`] when the access key id is empty, longer than 128 bytes, or
    /// holds anything other than ASCII graphic characters — the rule
    /// [`rustfs_gateway_sig::Identity`] applies, because an access key id reaches a log line.
    ///
    /// [`CredentialsError::EmptySecret`] when the secret is empty or holds only NUL bytes. An
    /// HMAC key of zero bytes is known to everybody, so a request signed with it would verify;
    /// and HMAC zero-pads a short key to its block, so a run of NUL bytes derives the very same
    /// keys (SigV4's `"AWS4" || secret` included). Refusing both here is what keeps
    /// [`CredentialLookup::Found`] from carrying one into any authentication form. A provider
    /// should pass the refusal on with `?` — see `From<CredentialsError> for ProviderError` — so
    /// it is counted as a store fault. There is no length rule beyond this; a minimum length is
    /// the deployment's policy.
    pub fn new(access_key_id: &str, secret: &[u8]) -> Result<Self, CredentialsError> {
        let identity = Identity::new(access_key_id).map_err(CredentialsError::Malformed)?;
        // Every byte is folded, with no early exit, so the check costs the same whatever the
        // secret holds; an empty slice folds to zero as well.
        if secret.iter().fold(0_u8, |seen, byte| seen | byte) == 0 {
            return Err(CredentialsError::EmptySecret);
        }
        Ok(Self {
            identity,
            secret: SecretBytes::new(secret),
            session: None,
            disabled: false,
        })
    }

    /// Turns these into temporary credentials: the STS token, and the lifetime it is bound to.
    ///
    /// Both at once, because a token with no lifetime is a session that never expires. There is no
    /// method that takes only one of them.
    ///
    /// # Errors
    ///
    /// [`CredentialsError::Malformed`] when the token is empty, which is not the same as absent:
    /// absent means long-term credentials, and present-but-empty means something between the
    /// client and here dropped the value.
    pub fn with_session(mut self, token: &str, binding: SessionBinding) -> Result<Self, CredentialsError> {
        self.identity = self.identity.clone().with_session_binding(binding.clone());
        self.session = Some(Session {
            token: SessionToken::new(token).map_err(CredentialsError::Malformed)?,
            binding,
            surface: SessionSurface::Sts,
        });
        Ok(self)
    }

    /// Turns these into S3 Express temporary session credentials: the token carried in
    /// `x-amz-s3session-token` / `X-Amz-S3session-Token`, and the lifetime it is bound to.
    ///
    /// Bound exclusively to the S3 Express token surface so the credential cannot authenticate via
    /// `x-amz-security-token` (or POST forms) and cannot bypass `CreateSession`'s
    /// `DisableS3ExpressSessionAuth`.
    ///
    /// # Errors
    ///
    /// [`CredentialsError::Malformed`] when the token is empty.
    pub fn with_s3_express_session(mut self, token: &str, binding: SessionBinding) -> Result<Self, CredentialsError> {
        self.identity = self.identity.clone().with_session_binding(binding.clone());
        self.session = Some(Session {
            token: SessionToken::new(token).map_err(CredentialsError::Malformed)?,
            binding,
            surface: SessionSurface::S3Express,
        });
        Ok(self)
    }

    /// Whether these credentials hold an S3 Express session bound to `x-amz-s3session-token`.
    #[must_use]
    pub const fn is_s3_express_session(&self) -> bool {
        matches!(
            self.session,
            Some(Session {
                surface: SessionSurface::S3Express,
                ..
            })
        )
    }

    /// Marks the principal as switched off.
    ///
    /// A disabled credential is answered exactly as an unknown one is. That is the point: a
    /// deployment that answered "this key exists but is disabled" would be confirming the key
    /// exists to whoever is guessing.
    #[must_use]
    pub const fn disable(mut self) -> Self {
        self.disabled = true;
        self
    }

    /// The principal. Safe to log: it is a public identifier.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The secret, for the one caller that derives a signing key from it.
    #[must_use]
    pub const fn secret(&self) -> &SecretBytes {
        &self.secret
    }

    /// The session token, when these are temporary credentials.
    #[must_use]
    pub fn session_token(&self) -> Option<&SessionToken> {
        self.session.as_ref().map(|session| &session.token)
    }

    /// The lifetime and provenance, when these are temporary credentials.
    #[must_use]
    pub fn session_binding(&self) -> Option<&SessionBinding> {
        self.session.as_ref().map(|session| &session.binding)
    }

    /// Whether the principal has been switched off.
    #[must_use]
    pub const fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Whether these credentials may be used by a request that did — or did not — present a
    /// session token, at the instant the security floor already fixed.
    ///
    /// `now` is the request's own snapshot, taken once on arrival. There is no variant of this
    /// method that reads a clock: a lifetime judged against a second reading is a lifetime that can
    /// straddle an NTP step.
    ///
    /// # Errors
    ///
    /// One of [`CredentialRefusal`]'s variants, judged in this order: disabled, then the token,
    /// then the lifetime. Only [`CredentialRefusal::SessionExpired`] is ever named on the wire,
    /// and only after the signature verified.
    pub fn admit(&self, token: Option<&[u8]>, now: RequestNow) -> Result<(), CredentialRefusal> {
        self.admit_surface(token, SessionSurface::Sts, now)
    }

    /// Applies session admission rules while enforcing that any presented token arrived on the
    /// same wire surface ([`SessionSurface::Sts`] vs [`SessionSurface::S3Express`]) that the
    /// stored session was issued for.
    pub(crate) fn admit_surface(
        &self,
        token: Option<&[u8]>,
        surface: SessionSurface,
        now: RequestNow,
    ) -> Result<(), CredentialRefusal> {
        self.admit_surface_with(token, surface, now, |expected, presented| expected.ct_verify(presented).is_ok())
    }

    /// Token to compare against on disabled and long-term refusal arms so session admission does
    /// the same work before refusing as on active temporary and unknown keys (rustfs/gateway#1584).
    fn equalizing_token(&self) -> Option<&SessionToken> {
        self.session
            .as_ref()
            .map(|session| &session.token)
            .or_else(|| super::session_answer::placeholder_session().and_then(Self::session_token))
    }

    fn admit_surface_with<F>(
        &self,
        token: Option<&[u8]>,
        surface: SessionSurface,
        now: RequestNow,
        mut compare_token: F,
    ) -> Result<(), CredentialRefusal>
    where
        F: FnMut(&SessionToken, &[u8]) -> bool,
    {
        if self.disabled {
            if let (Some(presented), Some(expected)) = (token, self.equalizing_token()) {
                let _ = core::hint::black_box(compare_token(expected, presented));
            }
            return Err(CredentialRefusal::Disabled);
        }
        match (&self.session, token) {
            // The token and surface before the lifetime, so `SessionExpired` implies the issued
            // token arrived on its own wire surface (rustfs/gateway#1575).
            (Some(session), Some(presented)) => {
                let matched = compare_token(&session.token, presented);
                if !matched || session.surface != surface {
                    return Err(CredentialRefusal::SessionTokenMismatch);
                }
                session.within_lifetime(now)
            }
            (Some(_), None) => Err(CredentialRefusal::SessionCredentialWithoutToken),
            (None, Some(presented)) => {
                if let Some(expected) = self.equalizing_token() {
                    let _ = core::hint::black_box(compare_token(expected, presented));
                }
                Err(CredentialRefusal::TokenWithoutSessionCredential)
            }
            (None, None) => Ok(()),
        }
    }

    /// Applies the same session rules to a token carried by a presigned query.
    #[cfg(test)]
    pub(crate) fn admit_query(&self, query: RawQuery<'_>, now: RequestNow) -> Result<(), CredentialRefusal> {
        self.admit_query_param(query, rustfs_gateway_sig::X_AMZ_SECURITY_TOKEN, SessionSurface::Sts, now)
    }

    /// Applies the same session rules to a named query parameter carrying a session token on
    /// `surface`.
    pub(crate) fn admit_query_param(
        &self,
        query: RawQuery<'_>,
        param: &str,
        surface: SessionSurface,
        now: RequestNow,
    ) -> Result<(), CredentialRefusal> {
        self.admit_query_param_with(surface, now, |expected| query.session_token_matches(param, expected))
    }

    fn admit_query_param_with<F>(
        &self,
        surface: SessionSurface,
        now: RequestNow,
        mut match_query_token: F,
    ) -> Result<(), CredentialRefusal>
    where
        F: FnMut(&SessionToken) -> Result<Option<bool>, rustfs_gateway_sig::AuthError>,
    {
        if self.disabled {
            if let Some(expected) = self.equalizing_token() {
                let _ = core::hint::black_box(match_query_token(expected));
            }
            return Err(CredentialRefusal::Disabled);
        }
        let Some(session) = &self.session else {
            if let Some(expected) = self.equalizing_token() {
                let _ = core::hint::black_box(match_query_token(expected));
            }
            return Err(CredentialRefusal::TokenWithoutSessionCredential);
        };
        match match_query_token(&session.token) {
            Ok(Some(true)) if session.surface == surface => session.within_lifetime(now),
            Ok(Some(_)) | Err(_) => Err(CredentialRefusal::SessionTokenMismatch),
            Ok(None) => Err(CredentialRefusal::SessionCredentialWithoutToken),
        }
    }

    /// [`Credentials::admit_surface`], held as a [`PendingSessionRefusal`] for a verifier to
    /// answer after comparison.
    pub(crate) fn admit_surface_pending(
        &self,
        token: Option<&[u8]>,
        surface: SessionSurface,
        now: RequestNow,
    ) -> Option<PendingSessionRefusal> {
        self.admit_surface(token, surface, now).err().map(pending)
    }

    #[cfg(test)]
    pub(super) fn admit_surface_pending_with<F: FnMut(&SessionToken, &[u8]) -> bool>(
        &self,
        token: Option<&[u8]>,
        surface: SessionSurface,
        now: RequestNow,
        compare_token: F,
    ) -> Option<PendingSessionRefusal> {
        self.admit_surface_with(token, surface, now, compare_token).err().map(pending)
    }

    /// The presigned-query spelling of [`Credentials::admit_surface_pending`], naming the query
    /// parameter and wire surface.
    pub(crate) fn admit_query_param_pending(
        &self,
        query: RawQuery<'_>,
        param: &str,
        surface: SessionSurface,
        now: RequestNow,
    ) -> Option<PendingSessionRefusal> {
        self.admit_query_param(query, param, surface, now).err().map(pending)
    }

    #[cfg(test)]
    pub(super) fn admit_query_param_pending_with<
        F: FnMut(&SessionToken) -> Result<Option<bool>, rustfs_gateway_sig::AuthError>,
    >(
        &self,
        surface: SessionSurface,
        now: RequestNow,
        match_query_token: F,
    ) -> Option<PendingSessionRefusal> {
        self.admit_query_param_with(surface, now, match_query_token)
            .err()
            .map(pending)
    }

    /// A deep copy, secret included.
    ///
    /// Named rather than a `Clone` implementation, for the reason `SecretBytes::clone_secret` is:
    /// duplicating key material should be a thing somebody wrote, not a thing that happens because
    /// a value was passed by value.
    ///
    /// ```compile_fail,E0599
    /// use rustfs_gateway::Credentials;
    /// let credentials = Credentials::new("AKIDEXAMPLE", b"secret").expect("valid");
    /// let _ = credentials.clone(); // no Clone: use `clone_credentials`, which is visible in review
    /// ```
    #[must_use]
    pub fn clone_credentials(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            secret: self.secret.clone_secret(),
            session: self.session.as_ref().map(|session| Session {
                token: session.token.clone_secret(),
                binding: session.binding.clone(),
                surface: session.surface,
            }),
            disabled: self.disabled,
        }
    }
}

impl core::fmt::Debug for Credentials {
    /// Hand-written: the secret and the session token are never rendered, whatever the formatter
    /// asks for.
    ///
    /// The binding *is* rendered, in full. It is a lifetime and two opaque handles the deployment
    /// wrote, and an operator asking why a request was refused needs exactly it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credentials")
            .field("identity", &self.identity)
            .field("secret", &"<redacted>")
            .field("session_token", &self.session.as_ref().map(|_| "<redacted>"))
            .field("session_binding", &self.session.as_ref().map(|session| &session.binding))
            .field("disabled", &self.disabled)
            .finish()
    }
}

/// A provider fault. Carries no request-derived text or credential material.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderError {
    /// The store reported a backend failure.
    Backend,
    /// The store is temporarily unavailable.
    Unavailable,
    /// The framework's hard deadline elapsed.
    Timeout,
    /// The provider panicked while constructing or polling its future.
    Panicked,
}

impl core::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Backend => f.write_str("the credential backend failed"),
            Self::Unavailable => f.write_str("the credential backend is unavailable"),
            Self::Timeout => f.write_str("the credential backend exceeded its deadline"),
            Self::Panicked => f.write_str("the credential backend stopped unexpectedly"),
        }
    }
}

impl std::error::Error for ProviderError {}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const LIVE: i64 = 2_000;
    const NOW: RequestNow = RequestNow::from_unix_seconds(1_000);

    fn binding(expires_at: i64) -> SessionBinding {
        SessionBinding::new("sts.example.com", expires_at).expect("a well-formed binding")
    }

    fn temporary(expires_at: i64) -> Credentials {
        Credentials::new("AKIDEXAMPLE", b"wJalrXUtnFEMI")
            .expect("a valid access key id")
            .with_session("session-token-value", binding(expires_at))
            .expect("a valid token")
    }

    fn express_temporary(expires_at: i64) -> Credentials {
        Credentials::new("AKIDEXPRESS", b"wJalrXUtnFEMI")
            .expect("a valid access key id")
            .with_s3_express_session("express-token-value", binding(expires_at))
            .expect("a valid token")
    }

    /// Negative — no formatter setting renders the secret or the session token.
    #[test]
    fn debug_never_renders_key_material() {
        let credentials = temporary(LIVE);
        let rendered = format!("{credentials:?} {credentials:#?}");
        assert!(!rendered.contains("wJalrXUtnFEMI"), "{rendered}");
        assert!(!rendered.contains("session-token-value"), "{rendered}");
        assert!(rendered.contains("AKIDEXAMPLE"), "{rendered}");
        // The binding is not key material and an operator needs it, so it is rendered in full.
        assert!(rendered.contains("sts.example.com"), "{rendered}");
    }

    /// Negative — a long-term credential refuses a request that presented a token on both header
    /// and presigned query surfaces. Ignoring the token would silently drop the scope the caller
    /// believed it was operating under.
    #[test]
    fn a_long_term_credential_refuses_a_presented_token() {
        let credentials = Credentials::new("AKIDEXAMPLE", b"secret").expect("valid");
        assert_eq!(
            credentials.admit(Some(b"token"), NOW),
            Err(CredentialRefusal::TokenWithoutSessionCredential)
        );
        assert_eq!(
            credentials.admit_query(RawQuery::new("X-Amz-Security-Token=token"), NOW),
            Err(CredentialRefusal::TokenWithoutSessionCredential)
        );
        assert_eq!(credentials.admit(None, NOW), Ok(()));
    }

    /// Negative — a temporary credential refuses a request that presented none.
    #[test]
    fn a_temporary_credential_refuses_a_missing_token() {
        let credentials = temporary(LIVE);
        assert_eq!(credentials.admit(None, NOW), Err(CredentialRefusal::SessionCredentialWithoutToken));
        assert_eq!(credentials.admit(Some(b"session-token-value"), NOW), Ok(()));
    }

    /// Negative — STS and S3 Express session tokens are bound to their own token surface:
    /// presenting an S3 Express session token on the STS surface (`x-amz-security-token` /
    /// `X-Amz-Security-Token`) or an STS token on the S3 Express surface (`x-amz-s3session-token`
    /// / `X-Amz-S3session-Token`) fails closed with `SessionTokenMismatch`, even when expired.
    #[test]
    fn n_sts_and_s3_express_session_surfaces_are_mutually_exclusive() {
        let sts_live = temporary(LIVE);
        let sts_expired = temporary(LIVE - 1_500);
        let express_live = express_temporary(LIVE);
        let express_expired = express_temporary(LIVE - 1_500);

        assert!(!sts_live.is_s3_express_session());
        assert!(express_live.is_s3_express_session());
        assert!(express_live.clone_credentials().is_s3_express_session());

        assert_eq!(
            express_live.admit(Some(b"express-token-value"), NOW),
            Err(CredentialRefusal::SessionTokenMismatch)
        );
        assert_eq!(
            express_expired.admit(Some(b"express-token-value"), NOW),
            Err(CredentialRefusal::SessionTokenMismatch)
        );
        assert_eq!(
            express_live.admit_surface(Some(b"express-token-value"), SessionSurface::S3Express, NOW),
            Ok(())
        );
        assert_eq!(
            express_expired.admit_surface(Some(b"express-token-value"), SessionSurface::S3Express, NOW),
            Err(CredentialRefusal::SessionExpired)
        );
        assert_eq!(
            sts_live.admit_surface(Some(b"session-token-value"), SessionSurface::S3Express, NOW),
            Err(CredentialRefusal::SessionTokenMismatch)
        );
        assert_eq!(
            sts_expired.admit_surface(Some(b"session-token-value"), SessionSurface::S3Express, NOW),
            Err(CredentialRefusal::SessionTokenMismatch)
        );

        assert_eq!(
            express_live.admit_query_param(
                RawQuery::new("X-Amz-Security-Token=express-token-value"),
                rustfs_gateway_sig::X_AMZ_SECURITY_TOKEN,
                SessionSurface::Sts,
                NOW,
            ),
            Err(CredentialRefusal::SessionTokenMismatch)
        );
        assert_eq!(
            sts_live.admit_query_param(
                RawQuery::new("X-Amz-S3session-Token=session-token-value"),
                rustfs_gateway_sig::X_AMZ_S3SESSION_TOKEN,
                SessionSurface::S3Express,
                NOW,
            ),
            Err(CredentialRefusal::SessionTokenMismatch)
        );
        assert_eq!(
            express_live.admit_query_param(
                RawQuery::new("X-Amz-S3session-Token=express-token-value"),
                rustfs_gateway_sig::X_AMZ_S3SESSION_TOKEN,
                SessionSurface::S3Express,
                NOW,
            ),
            Ok(())
        );
    }

    /// Negative — a lifetime that has passed refuses, and the boundary second does not.
    #[test]
    fn an_expired_session_is_refused_and_its_final_second_is_not() {
        let credentials = temporary(LIVE);
        assert_eq!(
            credentials.admit(Some(b"session-token-value"), RequestNow::from_unix_seconds(LIVE - 1)),
            Ok(())
        );
        assert_eq!(
            credentials.admit(Some(b"session-token-value"), RequestNow::from_unix_seconds(LIVE)),
            Ok(())
        );
        assert_eq!(
            credentials.admit(Some(b"session-token-value"), RequestNow::from_unix_seconds(LIVE + 1)),
            Err(CredentialRefusal::SessionExpired)
        );
    }

    /// Negative — an expired session with another token, or none, is a binding violation, never an
    /// expiry: `SessionExpired`, the one refusal the authenticator may name, implies the issued
    /// token (rustfs/gateway#1575). Disabled outranks both. Header and query spellings alike.
    #[test]
    fn an_expired_session_names_its_expiry_only_to_the_matching_token() {
        use CredentialRefusal::{Disabled, SessionCredentialWithoutToken, SessionExpired, SessionTokenMismatch};
        let (at, live, disabled) = (RequestNow::from_unix_seconds(LIVE + 1), temporary(LIVE), temporary(LIVE).disable());
        let issued: &[u8] = b"session-token-value";
        for (token, expected) in [
            (Some(&b"another"[..]), SessionTokenMismatch),
            (None, SessionCredentialWithoutToken),
        ] {
            assert_eq!(live.admit(token, at), Err(expected));
        }
        assert_eq!(live.admit(Some(issued), at), Err(SessionExpired));
        assert_eq!(disabled.admit(Some(issued), at), Err(Disabled));
        for (query, expected) in [
            ("X-Amz-Security-Token=another", SessionTokenMismatch),
            ("X-Amz-Expires=60", SessionCredentialWithoutToken),
            ("X-Amz-Security-Token=session-token-value", SessionExpired),
        ] {
            assert_eq!(live.admit_query(RawQuery::new(query), at), Err(expected), "{query}");
        }
        let query = RawQuery::new("X-Amz-Security-Token=session-token-value");
        assert_eq!(live.admit_query(query, NOW), Ok(()));
        for instant in [at, NOW] {
            assert_eq!(disabled.admit_query(query, instant), Err(Disabled));
        }
    }

    /// Negative — a disabled credential is refused whatever else is right about the request, and
    /// the same credential without the flag is not.
    #[test]
    fn a_disabled_credential_is_refused_in_every_shape() {
        let long_term = Credentials::new("AKIDEXAMPLE", b"secret").expect("valid").disable();
        assert_eq!(long_term.admit(None, NOW), Err(CredentialRefusal::Disabled));
        assert!(long_term.is_disabled());
        let session = temporary(LIVE).disable();
        assert_eq!(session.admit(Some(b"session-token-value"), NOW), Err(CredentialRefusal::Disabled));
        assert!(!temporary(LIVE).is_disabled());
        assert_eq!(temporary(LIVE).admit(Some(b"session-token-value"), NOW), Ok(()));
    }

    /// Negative — no refusal renders anything that distinguishes it from another refusal.
    #[test]
    fn every_refusal_says_the_same_sentence() {
        let sentences: std::collections::BTreeSet<String> = [
            CredentialRefusal::Disabled,
            CredentialRefusal::SessionExpired,
            CredentialRefusal::TokenWithoutSessionCredential,
            CredentialRefusal::SessionCredentialWithoutToken,
            CredentialRefusal::SessionTokenMismatch,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(sentences.len(), 1, "{sentences:?}");
    }

    /// Negative — an issuer or a policy handle that an audit record could not carry is refused
    /// where it is written, and a well-formed one is kept verbatim.
    #[test]
    fn a_binding_that_would_corrupt_an_audit_record_is_refused() {
        for bad in ["", "sts\r\nX-Injected: 1", "sts example", "sts\u{0}example"] {
            assert_eq!(SessionBinding::new(bad, LIVE), Err(SessionBindingError), "must reject {bad:?}");
        }
        assert_eq!(SessionBinding::new(&"a".repeat(257), LIVE), Err(SessionBindingError));
        let ok = SessionBinding::new("sts.example.com", LIVE)
            .expect("valid")
            .with_inline_policy("policy-blob-7")
            .expect("valid");
        assert_eq!(ok.issuer(), "sts.example.com");
        assert_eq!(ok.inline_policy(), Some("policy-blob-7"));
        assert_eq!(ok.expires_at_unix_seconds(), LIVE);
        assert_eq!(ok.with_inline_policy("bad handle").err(), Some(SessionBindingError));
    }

    /// Negative — a token the wire could not carry is refused where it is written, and the
    /// credential stays long-term rather than becoming a session with no token.
    #[test]
    fn an_empty_session_token_is_refused() {
        let refused = Credentials::new("AKIDEXAMPLE", b"secret")
            .expect("valid")
            .with_session("", binding(LIVE));
        assert!(matches!(refused, Err(CredentialsError::Malformed(_))));
        let refused_express = Credentials::new("AKIDEXAMPLE", b"secret")
            .expect("valid")
            .with_s3_express_session("", binding(LIVE));
        assert!(matches!(refused_express, Err(CredentialsError::Malformed(_))));
    }

    /// Positive — a copy carries the whole session, not just the secret.
    #[test]
    fn a_copy_carries_the_session_and_the_disabled_flag() {
        let original = temporary(LIVE).disable();
        let copy = original.clone_credentials();
        assert_eq!(copy.session_binding(), original.session_binding());
        assert_eq!(copy.identity().session(), original.session_binding());
        assert_eq!(
            copy.session_token().map(SessionToken::len),
            original.session_token().map(SessionToken::len)
        );
        assert_eq!(copy.is_s3_express_session(), original.is_s3_express_session());
        assert!(copy.is_disabled());
    }
}
