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

//! Credential-free admission and signed-request bearer extraction under the security floor.
//! Responsible for: preserving the admission order and binding a bearer claim to the operation.
//! NOT responsible for: verifying tokens or accepting AWS-marked requests.
//! Upstream: `SecurityFloor::admit`. Downstream: the installed facade verifier.

use super::*;
use crate::bearer::BearerAdmission;

impl SecurityFloor {
    /// The branch for a request that carried no AWS credential marker.
    pub(super) fn admit_without_aws_marker<'a>(
        &self,
        view: WireView<'a>,
        operation: &OperationFloor,
        presence: CredentialPresence,
        now: RequestNow,
    ) -> Result<Admission<'a>, AuthError> {
        if presence.any() {
            // An AWS surface was touched without an AWS marker — a session token with no
            // signature, say. There is nothing to verify and it is not anonymous, so it is a
            // rejection. Handing it to a custom verifier would be a way to launder an AWS
            // credential surface through a third-party scheme.
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        if let Some(scheme) = self.custom_schemes.matching(&view) {
            self.enforce_scheme_allowed(operation, SchemeSlot::Header, SigFamily::V4)?;
            return Ok(Admission::Custom(CustomAuthRequest::new(view, scheme, presence, now)));
        }
        // ADR-0042: only an operation that declared a query bearer claim reads its parameter, and
        // only once no AWS surface was touched — a presented AWS credential was refused or sealed
        // above and is never laundered through a token. A repeated, empty or undecodable token is
        // refused here; an absent one leaves the request to the anonymous rule below.
        if let Some(claim) = operation.query_bearer_claim()
            && let Some(token) = claim.read_token(&view)?
        {
            return Ok(Admission::Bearer(BearerAdmission::new(operation.name(), claim, token, now)));
        }
        self.enforce_scheme_allowed(operation, SchemeSlot::Anonymous, SigFamily::V4)?;
        // Infallible here — `presence.any()` is false — but spelled as the fallible call it is, so
        // that the evidence still comes from the presence record and not from this branch.
        presence
            .into_evidence()
            .map(Admission::Anonymous)
            .map_err(|_| AuthError::AuthorizationHeaderMalformed)
    }

    /// The bearer token a signed request on a bearer-claimed operation also carries (ADR-0042).
    ///
    /// Run by the facade after the signature verified, and only when a verifier for the claim is
    /// installed: the token is then validated on the signed path too, and must name the signed
    /// principal ([`BearerAdmission::verify_alongside`]). `Ok(None)` for an operation without a
    /// claim, whose signed path is unchanged.
    ///
    /// # Errors
    ///
    /// [`AuthError::AccessDenied`] when the claimed operation's token is absent, repeated, empty or
    /// undecodable.
    pub fn bearer_alongside_signature(
        &self,
        view: &WireView<'_>,
        operation: &OperationFloor,
        now: RequestNow,
    ) -> Result<Option<BearerAdmission>, AuthError> {
        let Some(claim) = operation.query_bearer_claim() else {
            return Ok(None);
        };
        let token = claim.read_token(view)?.ok_or(AuthError::AccessDenied)?;
        Ok(Some(BearerAdmission::new(operation.name(), claim, token, now)))
    }
}
