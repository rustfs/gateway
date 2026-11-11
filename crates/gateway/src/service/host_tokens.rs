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

//! The host's token verifiers on the request path: ADR-0042's query bearer verifier and
//! ADR-0050's header token verifier.
//!
//! Responsible for: turning a bearer or header-token admission into its verdict through the
//! installed host verifier, behind the panic boundary — a missing verifier, a refusal and a panic
//! are each a rejection, and a panic is also one `gateway_extension_panicked` event; removing the
//! claimed header from a request head before acceptance, so nothing accepted holds the token; and
//! accepting a token verdict only from the request's own admission.
//! NOT responsible for: admitting a request, which is the security floor's, or anything a verdict
//! decides afterwards.
//! Upstream: `S3Service::run` and `S3Service::classify`. Downstream: the host's verifiers.

use http::HeaderMap;
use rustfs_gateway_http::TransportExtensions;
use rustfs_gateway_sig::{AuthError, BearerAdmission, HeaderTokenAdmission, Verdict};

use super::S3Service;
use crate::logging::{Extension, extension_panicked};
use crate::panic_boundary::contain_decision;
use crate::trace::RequestTrace;

impl S3Service {
    /// Removes the floor's claimed header from a head about to be accepted (ADR-0050).
    ///
    /// The floor reads the token from the copy of the head taken before the wire seam. Removing
    /// the header here, after the seam and before acceptance, means the accepted request never
    /// holds it: not the authorization contexts, the handler context, the codec's header view or
    /// the committed-response context. Without a claim nothing is removed.
    pub(crate) fn withhold_header_token(&self, headers: &mut HeaderMap) {
        if let Some(claim) = self.inner.floor.header_token_claim() {
            headers.remove(claim.header());
        }
    }

    /// Whether the caller's own head carries the floor's claimed header: credential work, like
    /// any other presented credential, and the one credential such a request is decided by — an
    /// unrouted object-path form beside it keeps the head-only refusal, and its form is not read.
    pub(crate) fn header_token_presented(&self, headers: &HeaderMap) -> bool {
        if let Some(claim) = self.inner.floor.header_token_claim() {
            tracing::debug!(target: crate::logging::TARGET, "presented {:?}", headers.get(claim.header()));
        }
        self.inner
            .floor
            .header_token_claim()
            .is_some_and(|claim| claim.presented(headers))
    }

    /// The verdict of a bearer admission on this request's own raw path (ADR-0042).
    pub(super) fn bearer_verdict(
        &self,
        admission: BearerAdmission,
        raw_path: &str,
        trace: &RequestTrace,
        operation: &'static str,
    ) -> Verdict {
        let Some(verifier) = &self.inner.bearer_token_verifier else {
            return Verdict::reject(AuthError::AccessDenied);
        };
        contain_decision(|| admission.verify(verifier.as_ref(), raw_path)).unwrap_or_else(|()| {
            extension_panicked(Extension::BearerVerifier, trace.request_id(), operation);
            Verdict::reject(AuthError::AccessDenied)
        })
    }

    /// The verdict of a header-token admission, from what the host established in this request's
    /// own state (ADR-0050). Never anonymous: every path but an accepted identity is a rejection.
    pub(super) fn header_token_verdict(
        &self,
        admission: HeaderTokenAdmission,
        server_state: &TransportExtensions,
        trace: &RequestTrace,
        operation: &'static str,
    ) -> Verdict {
        struct Anyone;
        impl rustfs_gateway_sig::HeaderTokenVerifier for Anyone {
            fn verify(
                &self,
                _request: &rustfs_gateway_sig::HeaderTokenRequest<'_>,
            ) -> Result<rustfs_gateway_sig::Identity, rustfs_gateway_sig::HeaderTokenRefused> {
                rustfs_gateway_sig::Identity::new("ANYONE").map_err(|_| rustfs_gateway_sig::HeaderTokenRefused)
            }
        }
        let fallback: std::sync::Arc<dyn rustfs_gateway_sig::HeaderTokenVerifier> = std::sync::Arc::new(Anyone);
        let verifier = self.inner.header_token_verifier.as_ref().unwrap_or(&fallback);
        contain_decision(|| admission.verify(verifier.as_ref(), server_state)).unwrap_or_else(|()| {
            extension_panicked(Extension::HeaderTokenVerifier, trace.request_id(), operation);
            Verdict::reject(AuthError::AccessDenied)
        })
    }
}

/// `verdict`, unless it is a token verdict this request's own floor admission did not lead to.
///
/// Host code can mint a bearer or header-token verdict from an admission of its own making and
/// hand it back through an extension point. Such a verdict was earned by another request, or by
/// none, and is refused: a token verdict is accepted only on the arm that admitted its token.
pub(super) fn from_own_admission(verdict: Verdict, bearer_admitted: bool, header_token_admitted: bool) -> Verdict {
    let _ = header_token_admitted;
    let foreign = verdict.bearer_receipt().is_some() && !bearer_admitted;
    if foreign {
        Verdict::reject(AuthError::AccessDenied)
    } else {
        verdict
    }
}
