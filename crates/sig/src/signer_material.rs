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

//! What a signer signs with: the credentials, the scope, and the key derived from the two.
//!
//! Responsible for: [`SigningCredentials`], [`SigningScope`] and the one-entry key cache behind
//! [`super::SigV4Signer`].
//! NOT responsible for: deriving the key (that is [`crate::signing_key`], called from here), or
//! deciding whether a scope is acceptable — on the signing side there is no untrusted party whose
//! scope could be taken on trust, and on the verification side that decision is
//! [`crate::enforce_scope`]'s and stays there.
//! Upstream: [`crate::secret`], [`crate::parse`], [`crate::derive`]. Downstream: [`super`].
//!
//! # The invariant this file carries
//!
//! [`SigningScope::verified`] is the only conversion from a client-chosen scope to a
//! [`crate::VerifiedScope`], and it is `pub(super)`. Widening it — or publishing the cache, which
//! hands back a [`crate::SigningKey`] for whatever scope it is given — would make
//! `signing_key(secret, scope_the_client_sent)` expressible from outside the crate, and
//! [`crate::enforce_scope`] would stop being the only door to key derivation. That is the replay
//! [`crate::derive`]'s whole shape exists to stop.

use crate::derive::{VerifiedScope, signing_key};
use crate::parse::{CredentialScope, EmptyRegion, SCOPE_TERMINATOR, ScopeDate};
use crate::scheme::SigService;
use crate::secret::{SecretBytes, SessionToken, SigningKey};
use crate::verdict::Identity;

use super::SignerError;

/// The credentials one signer signs with.
///
/// It holds a [`SecretBytes`] and an optional [`SessionToken`], so it has no `Debug`, no `Display`
/// and no `Clone` — the absence propagates from the containers, exactly as it does on the
/// verification side:
///
/// ```compile_fail,E0277
/// use rustfs_gateway_sig::SigningCredentials;
/// let credentials = SigningCredentials::new("AKIDEXAMPLE", b"wJalrXUtnFEMI").expect("valid");
/// println!("{credentials:?}"); // no Debug: does not compile
/// ```
pub struct SigningCredentials {
    access_key_id: Identity,
    secret: SecretBytes,
    session_token: Option<SessionToken>,
}

impl SigningCredentials {
    /// Validates an access key id and copies the secret access key into a zeroizing container.
    ///
    /// # Errors
    ///
    /// [`SignerError::Scope`] carrying [`crate::SigParseError::InvalidAccessKeyId`] when the access key id
    /// is empty, over 128 bytes, or not ASCII-graphic — the same rule
    /// [`crate::CredentialScope::parse`] applies to the value that arrives on the wire, so a
    /// credential this signer accepts is one the verifier can read back.
    pub fn new(access_key_id: &str, secret_access_key: &[u8]) -> Result<Self, SignerError> {
        Ok(Self {
            access_key_id: Identity::new(access_key_id)?,
            secret: SecretBytes::new(secret_access_key),
            session_token: None,
        })
    }

    /// Attaches an STS session token.
    #[must_use]
    pub fn with_session_token(mut self, token: SessionToken) -> Self {
        self.session_token = Some(token);
        self
    }

    /// The access key id. A public identifier, safe to log.
    #[must_use]
    pub fn access_key_id(&self) -> &Identity {
        &self.access_key_id
    }

    /// The secret access key. `pub(super)` and nothing wider: the derivation is the only consumer,
    /// and a public accessor would let a caller hold the secret without ever signing anything.
    pub(super) fn secret(&self) -> &SecretBytes {
        &self.secret
    }

    /// The session token, when the credentials are temporary.
    #[must_use]
    pub fn session_token(&self) -> Option<&SessionToken> {
        self.session_token.as_ref()
    }
}

/// What a signature is scoped to: the day, the region, the service.
///
/// The service is a [`SigService`] and not a string, so a signer cannot mint a scope naming a
/// service the verifier would refuse to parse. The region is checked against the same rule
/// [`crate::CredentialScope::parse`] applies.
///
/// There is no public method that turns one of these into a [`crate::VerifiedScope`]. That is the
/// whole point: the conversion exists, it is private, and making it public would hand every caller
/// the key-derivation route [`crate::enforce_scope`] is supposed to be the only door to.
///
/// ```compile_fail,E0624
/// use rustfs_gateway_sig::{ScopeDate, SigService, SigningScope};
/// let date = ScopeDate::parse("20150830").expect("valid");
/// let scope = SigningScope::new(date, "us-east-1", SigService::S3).expect("valid");
/// let _ = scope.verified(); // private: a client-chosen scope has no route to a VerifiedScope
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningScope {
    date: ScopeDate,
    region: Box<str>,
    service: SigService,
}

impl SigningScope {
    /// Builds a scope, validating it through the verification side's own parser.
    ///
    /// The validation is not a re-implementation: a probe credential is assembled and handed to
    /// [`crate::CredentialScope::parse`], so a scope this constructor accepts is by construction one
    /// the verifier can read back off the wire.
    ///
    /// # Errors
    ///
    /// [`SignerError::Canonical`] carrying [`crate::AuthError::AuthorizationHeaderMalformed`] for a region
    /// that is empty, over [`crate::CredentialScope::MAX_REGION_LEN`], or not ASCII-graphic.
    pub fn new(date: ScopeDate, region: &str, service: SigService) -> Result<Self, SignerError> {
        let probe = format!("AKIDPROBE/{date}/{region}/{service}/{SCOPE_TERMINATOR}");
        CredentialScope::parse(&probe)?;
        Ok(Self {
            date,
            region: Box::from(region),
            service,
        })
    }

    /// A scope that names no region: `<date>//<service>/aws4_request`.
    ///
    /// What RustFS's replication client signs with when a bucket target has no region, and what a
    /// verifier admits only under [`crate::ExpectedScope::accepting_empty_region`]. [`Self::new`]
    /// keeps refusing an empty region, so an empty scope is always this constructor's, by name.
    #[must_use]
    pub fn with_empty_region(date: ScopeDate, service: SigService) -> Self {
        Self {
            date,
            region: Box::from(""),
            service,
        }
    }

    /// How the verification side's parser must read this scope's region back.
    fn empty_region(&self) -> EmptyRegion {
        if self.region.is_empty() {
            EmptyRegion::Admitted
        } else {
            EmptyRegion::Refused
        }
    }

    /// The day the signature is scoped to.
    #[must_use]
    pub const fn date(&self) -> ScopeDate {
        self.date
    }

    /// The region the signature is scoped to.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The service the signature is scoped to.
    #[must_use]
    pub const fn service(&self) -> SigService {
        self.service
    }

    /// The `Credential=` value: `<access-key>/<date>/<region>/<service>/aws4_request`.
    #[must_use]
    pub fn credential_value(&self, access_key_id: &Identity) -> String {
        format!(
            "{}/{}/{}/{}/{SCOPE_TERMINATOR}",
            access_key_id.access_key_id(),
            self.date,
            self.region,
            self.service
        )
    }

    /// The scope line of the string-to-sign, rebuilt through the verification side's parser so that
    /// the signer cannot produce a spelling the verifier would render differently.
    pub(super) fn presented(&self, access_key_id: &Identity) -> Result<CredentialScope, SignerError> {
        Ok(CredentialScope::parse_with(&self.credential_value(access_key_id), self.empty_region())?)
    }

    /// The scope that seeds the four derivation steps.
    ///
    /// Private, and it must stay that way — see this type's own documentation.
    pub(super) fn verified(&self) -> VerifiedScope {
        VerifiedScope::from_checked_parts(self.date, &self.region, self.service.as_str())
    }
}

/// A one-entry signing-key cache, keyed by the scope the key was derived for.
///
/// Deliberately **not** public. Publishing a cache that hands back a [`SigningKey`] for a
/// caller-supplied scope would reopen the route [`crate::enforce_scope`] closes; the saving — four
/// HMACs per request — is not worth a second door to key derivation.
pub(super) struct SigningKeyCache {
    scope_line: Option<String>,
    material: Option<SigningKey>,
}

impl SigningKeyCache {
    pub(super) const fn new() -> Self {
        Self {
            scope_line: None,
            material: None,
        }
    }

    /// The key for this scope, derived on a miss and reused on a hit.
    pub(super) fn key_for(&mut self, secret: &SecretBytes, scope: &SigningScope) -> &SigningKey {
        let line = format!("{}/{}/{}", scope.date(), scope.region(), scope.service());
        if self.scope_line.as_deref() != Some(line.as_str()) {
            self.material = Some(signing_key(secret, &scope.verified()));
            self.scope_line = Some(line);
        }
        // Populated on the line above whenever the cache missed.
        self.material.as_ref().expect("the cache was just populated")
    }
}
