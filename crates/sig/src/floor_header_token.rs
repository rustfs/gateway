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

//! Admission by the floor's host-verified header token claim (ADR-0051, rustfs/gateway#1586).
//!
//! Responsible for: [`SecurityFloor::with_header_token_claim`], the one predicate
//! [`SecurityFloor::admits_header_token`] that both admission and the startup posture report read,
//! and the branch of `SecurityFloor::admit` that decides every request presenting the claimed
//! header: exclusive of every other credential surface, one well-formed value, an operation that
//! admits the scheme.
//! NOT responsible for: the token, which this module never copies; verifying anything — the
//! host's [`crate::HeaderTokenVerifier`] reports the identity; or a request that does not carry
//! the claimed header, which the rest of the floor decides as before.
//! Upstream: `SecurityFloor::admit`. Downstream: the facade's installed verifier.

use super::*;
use crate::verifier::detect_aws_credential_marker;

impl SecurityFloor {
    /// Installs the host-verified header token claim: a request whose head carries `claim`'s
    /// header is decided by that claim alone ([`Admission::HeaderToken`] or `AccessDenied`).
    ///
    /// A deployment installs the claim and its verifier together through the facade's
    /// `ServiceBuilder::host_verified_header_token`. A floor that carries a claim while the facade
    /// holds no verifier refuses every request presenting the header; nothing here makes any
    /// operation anonymous.
    #[must_use]
    pub const fn with_header_token_claim(mut self, claim: HeaderTokenClaim) -> Self {
        self.header_token = Some(claim);
        self
    }

    /// The header token claim in force, for the facade and the startup posture report.
    #[must_use]
    pub const fn header_token_claim(&self) -> Option<HeaderTokenClaim> {
        self.header_token
    }

    /// Whether this floor admits a request to `operation` by its header token claim.
    ///
    /// This is the one answer; admission and the startup posture report both read it. With a
    /// claim installed, every standard operation admits the scheme, bucket configuration
    /// included: the token speaks for its user as a header signature does, and the authorizer
    /// decides. The exceptions refuse it: a privileged operation (the admin surface, and every
    /// third-party operation that kept its default), one of the STS service (credential
    /// issuance, privileged or not), one that takes a browser form, one that declares a query
    /// bearer claim, and one that requires SigV4 under every policy. No other policy of the floor
    /// widens or narrows it.
    #[must_use]
    pub const fn admits_header_token(&self, operation: &OperationFloor) -> bool {
        self.header_token.is_some()
            && !operation.privileged()
            && !matches!(operation.service(), crate::SigService::Sts)
            && !operation.allowed_schemes().allows_post_policy()
            && operation.query_bearer_claim().is_none()
            && !operation.requires_sigv4_under_every_policy()
    }

    /// The branch for a request that presented the claimed header. Total: every path out of it is
    /// a [`HeaderTokenAdmission`] or `AccessDenied`, so such a request is never sealed for a
    /// signature verifier, handed to a custom scheme, admitted by a bearer token or anonymous.
    pub(super) fn admit_by_header_token(
        &self,
        view: &WireView<'_>,
        operation: &OperationFloor,
        claim: HeaderTokenClaim,
        now: RequestNow,
    ) -> Result<HeaderTokenAdmission, AuthError> {
        // Exclusive, with no precedence and no fallback: beside any other credential surface the
        // request is refused here, before any verifier of either credential can be asked. The
        // default predicate decides whatever this floor's recognition policy reads as anonymous,
        // and a browser form is a credential surface of its own, signed or not. A query bearer
        // token needs no rule of its own: an operation that declares one refuses the scheme below.
        let other_credential = detect_credentials(view).any()
            || detect_aws_credential_marker(view).is_some()
            || self.custom_schemes.matching(view).is_some()
            || view.form_fields().is_some();
        if other_credential || !claim.well_formed(view.headers()) || !self.admits_header_token(operation) {
            return Err(AuthError::AccessDenied);
        }
        Ok(HeaderTokenAdmission::new(now))
    }
}
