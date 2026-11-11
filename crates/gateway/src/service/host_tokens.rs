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
//! ADR-0051's header token verifier.
//!
//! Responsible for: turning a bearer or header-token admission into its verdict through the
//! installed host verifier, behind the panic boundary — a missing verifier, a refusal and a panic
//! are each a rejection, and a panic is also one `gateway_extension_panicked` event; removing the
//! claimed header from a request head before acceptance, so nothing accepted holds the token; accepting a token verdict only from the request's own admission; and
//! keeping the answer to a request served by its token out of a shared cache.
//! NOT responsible for: admitting a request, which is the security floor's, or anything a verdict
//! decides afterwards.
//! Upstream: `S3Service::run` and `S3Service::classify`. Downstream: the host's verifiers.

use std::sync::Arc;

use http::header::{CACHE_CONTROL, VARY};
use http::{HeaderMap, HeaderValue};
use rustfs_gateway_http::TransportExtensions;
use rustfs_gateway_sig::{AuthError, BearerAdmission, HeaderTokenAdmission, Identity, IdentityOrigin, Verdict};

use super::S3Service;
use crate::logging::{Extension, extension_panicked};
use crate::panic_boundary::contain_decision;
use crate::trace::RequestTrace;

/// The installed header token verifier with its type erased: the verdict of one admission, read
/// from one request's own transport values (`HeaderTokenAdmission::verify`).
pub(crate) type HeaderTokenVerify = Arc<dyn Fn(HeaderTokenAdmission, &TransportExtensions) -> Verdict + Send + Sync>;

impl S3Service {
    /// Removes the floor's claimed header from a head about to be accepted (ADR-0051). A refused
    /// alias stays: a request that carries one is refused before any context exists.
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

    /// Marks the answer to a request served by its header token as one caller's (ADR-0051).
    ///
    /// A shared cache keeps a response to a request that carried `Authorization` private by
    /// default (RFC 9111 section 3.5) and gives a claimed extension header no such treatment.
    /// `Vary` names the claimed header beside whatever the response already varies on, and
    /// `Cache-Control: private` is added unless the handler chose a `Cache-Control` itself.
    pub(super) fn keep_out_of_shared_caches(&self, response: &mut HeaderMap, served_as: Option<&Identity>) {
        if let Some(claim) = self.inner.floor.header_token_claim()
            && served_as.is_some_and(|identity| identity.origin() == IdentityOrigin::HostToken)
        {
            mark_private(response, claim.header());
        }
    }

    /// Whether the caller's own head carries the floor's claimed header or a refused alias:
    /// credential work, like any other presented credential, and the one thing such a request is
    /// decided by. The floor answers it `403` or admits it, so nothing that answers a malformed
    /// AWS credential in its own words runs first, and an unrouted object-path form beside it
    /// keeps the head-only refusal with its form unread.
    pub(crate) fn header_token_presented(&self, headers: &HeaderMap) -> bool {
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
    /// own state (ADR-0051). Never anonymous: every path but an accepted identity is a rejection.
    pub(super) fn header_token_verdict(
        &self,
        admission: HeaderTokenAdmission,
        server_state: &TransportExtensions,
        trace: &RequestTrace,
        operation: &'static str,
    ) -> Verdict {
        let Some(verifier) = &self.inner.header_token_verifier else {
            return Verdict::reject(AuthError::AccessDenied);
        };
        contain_decision(|| verifier(admission, server_state)).unwrap_or_else(|()| {
            extension_panicked(Extension::HeaderTokenVerifier, trace.request_id(), operation);
            Verdict::reject(AuthError::AccessDenied)
        })
    }
}

/// `Vary` on `claimed`, appended beside what `response` already varies on, and
/// `Cache-Control: private` unless the response chose a `Cache-Control` of its own.
fn mark_private(response: &mut HeaderMap, claimed: &'static str) {
    response.append(VARY, HeaderValue::from_static(claimed));
    if !response.contains_key(CACHE_CONTROL) {
        response.insert(CACHE_CONTROL, HeaderValue::from_static("private"));
    }
}

/// `verdict`, unless it is a token verdict this request's own floor admission did not lead to.
///
/// Host code can mint a bearer or header-token verdict from an admission of its own making and
/// hand it back through an extension point. Such a verdict was earned by another request, or by
/// none, and is refused: a token verdict is accepted only on the arm that admitted its token.
pub(super) fn from_own_admission(verdict: Verdict, bearer_admitted: bool, header_token_admitted: bool) -> Verdict {
    let foreign = (verdict.bearer_receipt().is_some() && !bearer_admitted)
        || (verdict.header_token_receipt().is_some() && !header_token_admitted);
    if foreign {
        Verdict::reject(AuthError::AccessDenied)
    } else {
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(headers: &HeaderMap, name: http::header::HeaderName) -> Vec<&[u8]> {
        headers.get_all(name).iter().map(HeaderValue::as_bytes).collect()
    }

    /// Positive and negative — a bare response gains both headers; one that already varies keeps
    /// what it varied on beside the claimed header; and one whose handler chose a `Cache-Control`,
    /// `public` included, keeps exactly that and still varies on the claimed header.
    #[test]
    fn a_marked_response_varies_on_the_claimed_header_and_keeps_what_its_handler_chose() {
        let mut bare = HeaderMap::new();
        mark_private(&mut bare, "x-auth-token");
        assert_eq!(values(&bare, VARY), [b"x-auth-token"]);
        assert_eq!(values(&bare, CACHE_CONTROL), [b"private"]);

        let mut varying = HeaderMap::new();
        varying.insert(VARY, HeaderValue::from_static("Origin"));
        mark_private(&mut varying, "x-auth-token");
        assert_eq!(values(&varying, VARY), [&b"Origin"[..], b"x-auth-token"]);

        for chosen in ["public, max-age=60", "no-store", "private, max-age=5"] {
            let mut cached = HeaderMap::new();
            cached.insert(CACHE_CONTROL, HeaderValue::from_static(chosen));
            mark_private(&mut cached, "x-auth-token");
            assert_eq!(values(&cached, CACHE_CONTROL), [chosen.as_bytes()], "{chosen}");
            assert_eq!(values(&cached, VARY), [b"x-auth-token"], "{chosen}");
        }
    }
}
