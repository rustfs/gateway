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

//! The two host token verifiers a deployment may install: ADR-0042's query bearer verifier and
//! ADR-0050's header token claim.
//!
//! Responsible for: [`ServiceBuilder::bearer_token_verifier`],
//! [`ServiceBuilder::host_verified_header_token`], and writing an installed header token claim
//! onto the security floor the service is assembled with.
//! NOT responsible for: admitting a request (the security floor) or calling a verifier
//! (`crate::service`).
//! Upstream: the deployment's build code. Downstream: `ServiceBuilder::build`.

use std::sync::Arc;

use rustfs_gateway_sig::{BearerTokenVerifier, HeaderTokenClaim, HeaderTokenVerifier};

use super::ServiceBuilder;

/// An installed header token claim and the host verifier that answers for it.
pub(super) type HeaderToken = (HeaderTokenClaim, Arc<dyn HeaderTokenVerifier>);

impl ServiceBuilder {
    /// Writes an installed claim onto the security floor and hands back that claim's verifier.
    /// Run when the service is built, so the order of the builder's calls — a later
    /// `security_floor` among them — cannot separate the claim from its verifier.
    pub(super) fn install_header_token(&mut self) -> Option<Arc<dyn HeaderTokenVerifier>> {
        let (claim, verifier) = self.header_token.take()?;
        self.floor = core::mem::take(&mut self.floor).with_header_token_claim(claim);
        Some(verifier)
    }

    /// Installs the host's verifier for operations whose floor declares a query bearer claim
    /// (ADR-0042) — RustFS's minted zip-download URL.
    ///
    /// Nothing is installed by default, and without a verifier a claimed operation refuses every
    /// token-only request `403 AccessDenied`; a header-signed request keeps its signature path.
    /// Once installed, the token is verified on that operation's signed path too, must name the
    /// signed principal, and is stripped from both authorization contexts and the handler context.
    /// No other operation reads the parameter.
    #[must_use]
    pub fn bearer_token_verifier(mut self, verifier: impl BearerTokenVerifier) -> Self {
        self.bearer_token_verifier = Some(Arc::new(verifier));
        self
    }

    /// Admits a request whose only credential is `claim`'s header as the identity `verifier`
    /// reports (ADR-0050): for a host whose outer layer has already authenticated a non-AWS token,
    /// such as RustFS with OpenStack Keystone's `X-Auth-Token`.
    ///
    /// Nothing is installed by default, and then the header is an ordinary header: a request that
    /// carries it is served exactly as before. Once installed:
    ///
    /// * a request carrying the header beside any other credential surface — an `Authorization`
    ///   header, a presigned query, a session token, a browser form, a registered custom scheme,
    ///   an operation's query bearer token — is refused `403` before any verifier runs;
    /// * every standard operation admits the header, bucket configuration included; a privileged
    ///   operation, one of the STS service, one that takes a browser form, one that declares a
    ///   query bearer claim and one that requires SigV4 under every policy refuse it;
    /// * a refusal or a panic of `verifier` is `403`, never an anonymous request;
    /// * the request is unsigned, and its body is held to what an anonymous request's is;
    /// * authorizers and the audit event see `AuthSchemeRef::HeaderToken`, and a handler reads
    ///   the principal through `RequestContextView::header_token_principal`;
    /// * the header is removed from the request before acceptance, so no authorization or handler
    ///   context holds the token. Stage filters' wire seam still sees it, as it sees
    ///   `Authorization`.
    ///
    /// The host's outer layer validates the token and leaves the identity in the request's own
    /// state; see [`HeaderTokenVerifier`] for what the verifier must and must not do.
    ///
    /// One claim is in force: a second call replaces the first claim and its verifier, and the
    /// claim replaces one written onto the floor directly. A claim whose header falls under a
    /// registered custom scheme's prefix refuses every request that presents it.
    #[must_use]
    pub fn host_verified_header_token(mut self, claim: HeaderTokenClaim, verifier: impl HeaderTokenVerifier) -> Self {
        self.header_token = Some((claim, Arc::new(verifier)));
        self
    }
}
