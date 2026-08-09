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
//! whole STS session ([`SessionBinding`] plus its token) — [`CredentialProvider`], the lookup an
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
//! [`Credentials::with_session`] is the only way to build one. "Temporary credentials with no
//! expiry" is not a state this type can be put into.
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

use std::collections::BTreeMap;

use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::{Identity, RawQuery, RequestNow, SecretBytes, SessionToken, SigParseError, X_AMZ_SECURITY_TOKEN};

pub use rustfs_gateway_sig::{SessionBinding, SessionBindingError};

/// An STS session: the token and the lifetime, which are never apart.
///
/// Private, and holds a [`SessionToken`], so it has no `Debug` and cannot acquire one.
struct Session {
    token: SessionToken,
    binding: SessionBinding,
}

/// Why a credential that exists is nonetheless not usable for this request.
///
/// Every variant is answered identically on the wire — see
/// [`super::authenticator::SigV4Authenticator`] — and this enum exists so that the framework's own
/// tests can name which rule fired. It carries no request bytes and no key material, but it is
/// still not something to render to a client: telling a caller that its token expired, rather than
/// that its credentials did not work, is the S3 shape of the distinguishable-failure defect
/// GHSA-3p3x-734c-h5vx describes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialRefusal {
    /// The principal exists and has been switched off.
    Disabled,
    /// The session's lifetime ended before this request's instant.
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
    pub fn new(access_key_id: &str, secret: &[u8]) -> Result<Self, CredentialsError> {
        Ok(Self {
            identity: Identity::new(access_key_id).map_err(CredentialsError::Malformed)?,
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
        });
        Ok(self)
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
    /// One of [`CredentialRefusal`]'s variants. Every one of them is answered identically on the
    /// wire; the distinction exists for the framework's tests and for nothing else.
    pub fn admit(&self, token: Option<&[u8]>, now: RequestNow) -> Result<(), CredentialRefusal> {
        if self.disabled {
            return Err(CredentialRefusal::Disabled);
        }
        match (&self.session, token) {
            (Some(session), Some(presented)) => {
                if now.unix_seconds() > session.binding.expires_at_unix_seconds() {
                    return Err(CredentialRefusal::SessionExpired);
                }
                session
                    .token
                    .ct_verify(presented)
                    .map(|_| ())
                    .map_err(|_| CredentialRefusal::SessionTokenMismatch)
            }
            (Some(_), None) => Err(CredentialRefusal::SessionCredentialWithoutToken),
            (None, Some(_)) => Err(CredentialRefusal::TokenWithoutSessionCredential),
            (None, None) => Ok(()),
        }
    }

    /// Applies the same session rules to a token carried by a presigned query.
    pub(crate) fn admit_query(&self, query: RawQuery<'_>, now: RequestNow) -> Result<(), CredentialRefusal> {
        if self.disabled {
            return Err(CredentialRefusal::Disabled);
        }
        match &self.session {
            Some(session) => {
                if now.unix_seconds() > session.binding.expires_at_unix_seconds() {
                    return Err(CredentialRefusal::SessionExpired);
                }
                match query.session_token_matches(X_AMZ_SECURITY_TOKEN, &session.token) {
                    Ok(Some(true)) => Ok(()),
                    Ok(Some(false)) | Err(_) => Err(CredentialRefusal::SessionTokenMismatch),
                    Ok(None) => Err(CredentialRefusal::SessionCredentialWithoutToken),
                }
            }
            None => Err(CredentialRefusal::TokenWithoutSessionCredential),
        }
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

/// A lookup's normal business result.
///
/// `NotFound` is deliberately not an error: it is eligible for the framework's negative cache,
/// while a provider fault is not.
pub enum CredentialLookup {
    /// The access key resolves to this credential.
    Found(Credentials),
    /// The access key is not registered.
    NotFound,
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

/// Why a credential value could not be constructed.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialsError {
    /// A value this crate refuses to hold at all.
    Malformed(SigParseError),
}

impl core::fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CredentialsError {}

/// Where an access key id is resolved to a secret.
///
/// Held as `Arc<dyn CredentialProvider>`, so the async method is a hand-written [`BoxFuture`]
/// (ADR-0002). A real deployment awaits an IAM store here; [`crate::GuardedCredentialProvider`] adds the
/// mandatory deadline and negative cache without caching a secret.
pub trait CredentialProvider: Send + Sync + 'static {
    /// Resolves one access key id.
    ///
    /// The identifier arrives exactly as the request spelled it. An implementation must compare it
    /// byte for byte: the access key id is part of the string that was signed, so a
    /// case-insensitive match would accept a signature computed over different bytes.
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>>;
}

impl<T: CredentialProvider + ?Sized> CredentialProvider for std::sync::Arc<T> {
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        (**self).lookup(access_key_id)
    }
}

/// Builds a [`CredentialProvider`] from a closure, for a deployment whose lookup is one function.
///
/// The closure returns the same hand-written [`BoxFuture`] the trait does (ADR-0002), which is
/// what lets it borrow the access key id for the life of the lookup rather than allocating a
/// `String` per request on the unauthenticated path.
///
/// It buys convenience and nothing else: a closure cannot answer anything a hand-written
/// implementation cannot, and in particular it cannot produce a `Verdict`. Deciding whether the
/// signature matched is not something a credential source is asked.
///
/// ```
/// # use rustfs_gateway::{CredentialLookup, Credentials, ProviderError, fn_credential_provider};
/// let provider = fn_credential_provider(|access_key_id: &str| {
///     let found = match access_key_id {
///         "AKIDEXAMPLE" => CredentialLookup::Found(
///             Credentials::new("AKIDEXAMPLE", b"wJalrXUtnFEMI").expect("static fixture")
///         ),
///         // Never a blanket secret for an unrecognised key, and never an empty one: an empty
///         // secret does not skip verification, it just fails it slowly.
///         _ => CredentialLookup::NotFound,
///     };
///     Box::pin(async move { Ok::<_, ProviderError>(found) })
/// });
/// let _: std::sync::Arc<dyn rustfs_gateway::CredentialProvider> = std::sync::Arc::new(provider);
/// ```
pub fn fn_credential_provider<F>(lookup: F) -> impl CredentialProvider
where
    F: for<'a> Fn(&'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> + Send + Sync + 'static,
{
    struct FnProvider<F>(F);

    impl<F> CredentialProvider for FnProvider<F>
    where
        F: for<'a> Fn(&'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> + Send + Sync + 'static,
    {
        fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
            (self.0)(access_key_id)
        }
    }

    FnProvider(lookup)
}

/// An in-memory credential set, fixed at assembly time.
///
/// What a test fixture and the conformance suite use. It is not a deployment tool: rotating a key
/// means rebuilding the service, and there is deliberately no interior mutability to make that
/// look easy.
///
/// # Security
///
/// The default set is empty, so every signed credential lookup is rejected as unknown. It never
/// supplies a fallback key or identity.
#[derive(Debug, Default)]
pub struct StaticCredentials {
    entries: BTreeMap<String, Credentials>,
}

impl StaticCredentials {
    /// An empty set. Every lookup answers [`CredentialLookup::NotFound`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one principal.
    ///
    /// A later insertion under the same access key id replaces the earlier one, which is the only
    /// sensible answer for a builder that is read once at assembly time.
    #[must_use]
    pub fn with(mut self, credentials: Credentials) -> Self {
        self.entries
            .insert(credentials.identity().access_key_id().to_owned(), credentials);
        self
    }

    /// How many principals are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no principal is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl CredentialProvider for StaticCredentials {
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        let found = self
            .entries
            .get(access_key_id)
            .map(Credentials::clone_credentials)
            .map_or(CredentialLookup::NotFound, CredentialLookup::Found);
        Box::pin(async move { Ok(found) })
    }
}

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

    /// Negative — a long-term credential refuses a request that presented a token. Ignoring the
    /// token would silently drop the scope the caller believed it was operating under.
    #[test]
    fn a_long_term_credential_refuses_a_presented_token() {
        let credentials = Credentials::new("AKIDEXAMPLE", b"secret").expect("valid");
        assert_eq!(
            credentials.admit(Some(b"token"), NOW),
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

    /// Negative — a lifetime that has passed refuses, and the boundary second does not.
    ///
    /// Driven by moving the snapshot, never by sleeping: the instant is an argument.
    #[test]
    fn an_expired_session_is_refused_and_its_final_second_is_not() {
        let credentials = temporary(LIVE);
        assert_eq!(
            credentials.admit(Some(b"session-token-value"), RequestNow::from_unix_seconds(LIVE - 1)),
            Ok(())
        );
        // Usable up to and including the final second, which is the rule a presigned URL gets.
        assert_eq!(
            credentials.admit(Some(b"session-token-value"), RequestNow::from_unix_seconds(LIVE)),
            Ok(())
        );
        assert_eq!(
            credentials.admit(Some(b"session-token-value"), RequestNow::from_unix_seconds(LIVE + 1)),
            Err(CredentialRefusal::SessionExpired)
        );
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
        assert!(copy.is_disabled());
    }

    /// Positive — the closure adapter resolves the same key the hand-written provider does, and
    /// answers `NotFound` for everything else.
    #[tokio::test]
    async fn the_closure_adapter_matches_a_hand_written_provider() {
        let provider = fn_credential_provider(|access_key_id: &str| {
            let found = if access_key_id == "AKIDEXAMPLE" {
                CredentialLookup::Found(Credentials::new("AKIDEXAMPLE", b"secret").expect("static fixture"))
            } else {
                CredentialLookup::NotFound
            };
            Box::pin(async move { Ok(found) })
        });
        let CredentialLookup::Found(found) = provider.lookup("AKIDEXAMPLE").await.expect("lookup succeeded") else {
            panic!("registered credential was not found");
        };
        assert_eq!(found.secret().expose(), b"secret");
        assert!(matches!(provider.lookup("AKIDOTHER").await, Ok(CredentialLookup::NotFound)));
        let _: std::sync::Arc<dyn CredentialProvider> = std::sync::Arc::new(provider);
    }

    /// Negative — an access key id the log line could not carry safely is refused where it is
    /// written, not where it is printed.
    #[test]
    fn a_control_character_in_an_access_key_id_is_refused() {
        assert!(matches!(
            Credentials::new("AKID\r\nEXAMPLE", b"secret"),
            Err(CredentialsError::Malformed(_))
        ));
        assert!(matches!(Credentials::new("", b"secret"), Err(CredentialsError::Malformed(_))));
    }

    /// Negative — an unknown key is `NotFound` and never a silently empty secret.
    #[tokio::test]
    async fn an_unknown_key_is_reported_as_unknown() {
        let provider = StaticCredentials::new();
        assert!(matches!(provider.lookup("AKIDEXAMPLE").await, Ok(CredentialLookup::NotFound)));
    }

    /// Negative — the lookup is byte-exact, because the access key id is signed material.
    #[tokio::test]
    async fn the_lookup_is_case_sensitive() {
        let provider = StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid"));
        assert!(matches!(provider.lookup("akidexample").await, Ok(CredentialLookup::NotFound)));
        assert!(matches!(provider.lookup("AKIDEXAMPLE").await, Ok(CredentialLookup::Found(_))));
    }

    /// Positive — a resolved pair carries the secret through to the one caller that needs it.
    #[tokio::test]
    async fn a_known_key_resolves_to_its_secret() {
        let provider = StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid"));
        let CredentialLookup::Found(found) = provider.lookup("AKIDEXAMPLE").await.expect("lookup succeeded") else {
            panic!("registered credential was not found");
        };
        assert_eq!(found.secret().expose(), b"secret");
    }
}
