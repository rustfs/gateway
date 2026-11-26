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

//! Credential lookup providers, lookup outcomes, and static test fixtures.
//!
//! Responsible for: [`CredentialLookup`], [`CredentialsError`], [`CredentialProvider`],
//! [`fn_credential_provider`], and [`StaticCredentials`].
//! NOT responsible for: holding or admitting secrets and sessions (`super::credentials` owns
//! [`Credentials`], [`ProviderError`], and [`CredentialRefusal`]), or caching and deadlines
//! (`super::credential_guard`).
//! Upstream: `super::credentials`, `rustfs-gateway-core`, `rustfs-gateway-sig`.
//! Downstream: `super::credentials` (re-exports), `super::authenticator`, `crate::builder`.

use std::collections::BTreeMap;

use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::SigParseError;

use super::credentials::{Credentials, ProviderError};

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

/// Why a credential value could not be constructed.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialsError {
    /// A value this crate refuses to hold at all.
    Malformed(SigParseError),
    /// The secret is empty, or only NUL bytes that HMAC pads to the same key: either would make
    /// the signing key public (rustfs/gateway#1573).
    EmptySecret,
}

impl core::fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "{error}"),
            Self::EmptySecret => f.write_str("the secret access key is empty"),
        }
    }
}

impl std::error::Error for CredentialsError {}

/// A stored record this crate refuses to hold is the store's fault, not a missing key.
///
/// So a provider that builds its answer with `Credentials::new(id, &stored)?` reports a provider
/// fault: counted in [`crate::ProviderMetrics::backend_errors`], never put in the negative cache,
/// and answered exactly as an unknown key. Mapping it to [`CredentialLookup::NotFound`] instead
/// would cache the key as absent and hide a broken record from the operator.
impl From<CredentialsError> for ProviderError {
    fn from(_: CredentialsError) -> Self {
        Self::Backend
    }
}

/// Where an access key id is resolved to a secret.
///
/// Held as `Arc<dyn CredentialProvider>`, so the async method is a hand-written [`BoxFuture`]
/// (ADR-0002). A real deployment awaits an IAM store here; [`crate::GuardedCredentialProvider`] adds the
/// mandatory deadline and negative cache without caching a secret.
///
/// Return an expired STS session as `Found`, with its token and its real expiry in the
/// [`crate::SessionBinding`]. The framework judges the lifetime itself and answers `ExpiredToken` to a
/// caller that signed correctly with the issued token, which is what an SDK refreshes on; a
/// provider that answers `NotFound` for it makes the session indistinguishable from an unknown key.
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
///         // Never a blanket secret for an unrecognised key. An empty one cannot be built at
///         // all: `Credentials::new` refuses it, because the empty HMAC key is public.
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

    /// Negative — an empty secret cannot be held, long-term or as the base of a session: the empty
    /// HMAC key is public, so a credential carrying one would authenticate anybody.
    #[test]
    fn an_empty_secret_is_refused() {
        assert_eq!(Credentials::new("AKIDEXAMPLE", b"").err(), Some(CredentialsError::EmptySecret));
        // HMAC zero-pads a short key, so NUL bytes derive what the empty key derives.
        for nul in [&[0_u8][..], &[0_u8; 60][..], &[0_u8; 200][..]] {
            assert_eq!(Credentials::new("AKIDEXAMPLE", nul).err(), Some(CredentialsError::EmptySecret));
        }
        // The access key id is still judged first, so a doubly broken record names the id.
        assert!(matches!(Credentials::new("", b""), Err(CredentialsError::Malformed(_))));
    }

    /// Negative — every construction refusal becomes the counted, uncached provider fault, never
    /// an answer that could be mistaken for a missing key.
    #[test]
    fn a_refused_construction_is_a_backend_fault() {
        for error in [
            Credentials::new("AKIDEXAMPLE", b"").err(),
            Credentials::new("AKID\r\nEXAMPLE", b"secret").err(),
        ] {
            assert_eq!(error.map(ProviderError::from), Some(ProviderError::Backend));
        }
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
