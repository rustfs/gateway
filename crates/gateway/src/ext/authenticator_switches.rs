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

//! The opt-in switches of the built-in SigV4 authenticator: handing the caller's secret to
//! handlers (ADR-0022) and verifying any signing region (ADR-0023). Both are off by default.
//!
//! Responsible for: the two builder methods and their documented posture.
//! NOT responsible for: verification itself, or what either switch changes in it; both are read
//! in `super::authenticator` (and the secret hand-off also in `super::sigv2`).
//! Upstream: `super::authenticator::SigV4Authenticator`. Downstream: deployments assembling the
//! service, the RustFS ring-2 adapter first.

use super::authenticator::SigV4Authenticator;

impl SigV4Authenticator {
    /// Verifies a SigV4 signature whose credential scope names any region in the configured-name
    /// grammar, not only one this deployment serves: the RustFS profile of rd-loc-0004
    /// (ADR-0023). RustFS verifies every scope region today, and its clients sign with
    /// `us-east-1` or an operator's label whatever the server is set to.
    ///
    /// Off by default, and meant only for a single-endpoint deployment with no per-region
    /// credentials. It changes no key material and no comparison: the key is derived from the
    /// region the client named, and the date and service are still enforced. What it gives up is
    /// the AWS answer that tells a misconfigured client which region to use.
    #[must_use]
    pub fn accept_any_signing_region(mut self) -> Self {
        self.any_region = true;
        self
    }

    /// Hands the secret this authenticator's own credential lookup returned for an authenticated
    /// principal to the handler, as `RequestPrincipal::secret_key_from_authenticator_lookup`
    /// (ADR-0022).
    ///
    /// Off by default, and meant for a backend that genuinely needs the secret: one that decrypts
    /// a payload the client encrypted with it, or an adapter filling s3s's
    /// `Credentials::secret_key`. The secret travels only after the signature matched and the
    /// credential was admitted; a rejected or anonymous request never carries one, and no lookup
    /// happens that verification did not already make.
    #[must_use]
    pub fn hand_caller_secret_to_handlers(mut self) -> Self {
        self.hand_secret = true;
        self
    }
}
