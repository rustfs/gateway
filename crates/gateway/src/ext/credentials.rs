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
//! Responsible for: [`Credentials`] — an access key id, its secret and an optional session token —
//! [`CredentialProvider`], the lookup an authenticator performs, and [`StaticCredentials`], the
//! in-memory provider a test fixture and the conformance suite use.
//! NOT responsible for: comparing anything (`rustfs-gateway-sig` owns every comparison), deriving
//! a signing key, or deciding what an unknown key is answered with — that is
//! `super::authenticator`'s, because the answer is a timing decision as much as a protocol one.
//! Upstream: `rustfs-gateway-sig`. Downstream: `super::authenticator`, `crate::builder`.
//!
//! # Why the secret never leaves this type as bytes anyone can print
//!
//! [`Credentials`] holds a [`SecretBytes`], which has no `Debug`, no `PartialEq` and zeroes itself
//! on drop. The hand-written `Debug` below prints the access key id — a public identifier AWS
//! itself returns in error responses — and the word `<redacted>` for everything else. There is no
//! accessor that yields the secret as a `&str`.
//!
//! # Why a lookup failure is two variants and not one
//!
//! [`CredentialsError::Unknown`] and [`CredentialsError::Unavailable`] are answered differently:
//! an unknown key is a statement about the request and a store that could not answer is a
//! statement about the deployment. Collapsing them makes a database outage look like a wave of
//! bad credentials in exactly the logs an operator would use to tell them apart.

use std::collections::BTreeMap;

use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::{Identity, SecretBytes, SessionToken, SigParseError};

/// One principal's long-term or temporary credentials.
pub struct Credentials {
    identity: Identity,
    secret: SecretBytes,
    session_token: Option<SessionToken>,
}

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
            session_token: None,
        })
    }

    /// Adds the STS session token that makes these temporary credentials.
    ///
    /// # Errors
    ///
    /// [`CredentialsError::Malformed`] when the token is not a value the wire can carry.
    pub fn with_session_token(mut self, token: &str) -> Result<Self, CredentialsError> {
        self.session_token = Some(SessionToken::new(token).map_err(CredentialsError::Malformed)?);
        Ok(self)
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
    pub const fn session_token(&self) -> Option<&SessionToken> {
        self.session_token.as_ref()
    }

    /// A deep copy, secret included.
    ///
    /// Named rather than a `Clone` implementation, for the reason `SecretBytes::clone_secret` is:
    /// duplicating key material should be a thing somebody wrote, not a thing that happens because
    /// a value was passed by value.
    #[must_use]
    pub fn clone_credentials(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            secret: self.secret.clone_secret(),
            session_token: self.session_token.as_ref().map(SessionToken::clone_secret),
        }
    }
}

impl core::fmt::Debug for Credentials {
    /// Hand-written: the secret and the session token are never rendered, whatever the formatter
    /// asks for.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credentials")
            .field("identity", &self.identity)
            .field("secret", &"<redacted>")
            .field("session_token", &self.session_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Why a credential lookup did not produce a usable pair.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialsError {
    /// No principal is registered under that access key id.
    Unknown,
    /// The store could not answer. Fail closed; never treat this as "unknown".
    Unavailable,
    /// A value this crate refuses to hold at all.
    Malformed(SigParseError),
}

impl core::fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown => f.write_str("no principal is registered under that access key id"),
            Self::Unavailable => f.write_str("the credential store could not answer"),
            Self::Malformed(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CredentialsError {}

/// Where an access key id is resolved to a secret.
///
/// Held as `Arc<dyn CredentialProvider>`, so the async method is a hand-written [`BoxFuture`]
/// (ADR-0002). A real deployment awaits an IAM store here; the framework never caches the answer,
/// because a cache that outlives a key rotation is the framework deciding a policy question.
pub trait CredentialProvider: Send + Sync + 'static {
    /// Resolves one access key id.
    ///
    /// The identifier arrives exactly as the request spelled it. An implementation must compare it
    /// byte for byte: the access key id is part of the string that was signed, so a
    /// case-insensitive match would accept a signature computed over different bytes.
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<Credentials, CredentialsError>>;
}

impl<T: CredentialProvider + ?Sized> CredentialProvider for std::sync::Arc<T> {
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<Credentials, CredentialsError>> {
        (**self).lookup(access_key_id)
    }
}

/// An in-memory credential set, fixed at assembly time.
///
/// What a test fixture and the conformance suite use. It is not a deployment tool: rotating a key
/// means rebuilding the service, and there is deliberately no interior mutability to make that
/// look easy.
#[derive(Debug, Default)]
pub struct StaticCredentials {
    entries: BTreeMap<String, Credentials>,
}

impl StaticCredentials {
    /// An empty set. Every lookup answers [`CredentialsError::Unknown`].
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
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<Credentials, CredentialsError>> {
        let found = self
            .entries
            .get(access_key_id)
            .map(Credentials::clone_credentials)
            .ok_or(CredentialsError::Unknown);
        Box::pin(async move { found })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Negative — no formatter setting renders the secret or the session token.
    #[test]
    fn debug_never_renders_key_material() {
        let credentials = Credentials::new("AKIDEXAMPLE", b"wJalrXUtnFEMI")
            .expect("a valid access key id")
            .with_session_token("session-token-value")
            .expect("a valid token");
        let rendered = format!("{credentials:?} {credentials:#?}");
        assert!(!rendered.contains("wJalrXUtnFEMI"), "{rendered}");
        assert!(!rendered.contains("session-token-value"), "{rendered}");
        assert!(rendered.contains("AKIDEXAMPLE"), "{rendered}");
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

    /// Negative — an unknown key is `Unknown` and never a silently empty secret.
    #[tokio::test]
    async fn an_unknown_key_is_reported_as_unknown() {
        let provider = StaticCredentials::new();
        assert_eq!(provider.lookup("AKIDEXAMPLE").await.unwrap_err(), CredentialsError::Unknown);
    }

    /// Negative — the lookup is byte-exact, because the access key id is signed material.
    #[tokio::test]
    async fn the_lookup_is_case_sensitive() {
        let provider = StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid"));
        assert!(provider.lookup("akidexample").await.is_err());
        assert!(provider.lookup("AKIDEXAMPLE").await.is_ok());
    }

    /// Positive — a resolved pair carries the secret through to the one caller that needs it.
    #[tokio::test]
    async fn a_known_key_resolves_to_its_secret() {
        let provider = StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid"));
        let found = provider.lookup("AKIDEXAMPLE").await.expect("registered");
        assert_eq!(found.secret().expose(), b"secret");
    }
}
