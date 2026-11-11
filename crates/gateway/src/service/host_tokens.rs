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
//! ADR-0054's header token verifier.
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
    /// Removes the floor's claimed header from a head about to be accepted (ADR-0054). A refused
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

    /// Marks the answer to a request served by its header token as one caller's (ADR-0054).
    ///
    /// A shared cache keeps a response to a request that carried `Authorization` private unless
    /// the response says `public`, `s-maxage` or `must-revalidate` (RFC 9111 section 3.5), and
    /// gives a claimed extension header no such treatment. `Vary` names the claimed header
    /// beside whatever the response already varies on, and `private` is added to the response's
    /// `Cache-Control` unless one of those three, `private` or `no-store` is already there.
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
    /// own state (ADR-0054). Never anonymous: every path but an accepted identity is a rejection.
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

/// The `Cache-Control` directives that already decide whether a shared cache may keep a
/// response: the three by which RFC 9111 section 3.5 lets one store an answer to an authenticated
/// request, and the two that forbid it.
const DECIDES_SHARING: [&str; 5] = ["public", "s-maxage", "must-revalidate", "private", "no-store"];

/// `Vary` on `claimed`, appended beside what `response` already varies on, and
/// `Cache-Control: private` appended unless a `Cache-Control` of the response already decides
/// sharing. Directive names are read from every `Cache-Control` line, ignoring ASCII case and
/// any argument. A lifetime alone does not decide sharing, so it gains `private`.
fn mark_private(response: &mut HeaderMap, claimed: &'static str) {
    response.append(VARY, HeaderValue::from_static(claimed));
    let decided = response.get_all(CACHE_CONTROL).iter().any(|line| {
        line.as_bytes().split(|byte| *byte == b',').any(|directive| {
            let name = directive.split(|byte| *byte == b'=').next().unwrap_or_default().trim_ascii();
            DECIDES_SHARING
                .iter()
                .any(|known| name.eq_ignore_ascii_case(known.as_bytes()))
        })
    });
    if !decided {
        response.append(CACHE_CONTROL, HeaderValue::from_static("private"));
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

    fn marked(chosen: &[&'static str]) -> HeaderMap {
        let mut response = HeaderMap::new();
        for value in chosen {
            response.append(CACHE_CONTROL, HeaderValue::from_static(value));
        }
        mark_private(&mut response, "x-auth-token");
        response
    }

    /// Positive — a bare response gains both headers, and one that already varies keeps what it
    /// varied on beside the claimed header.
    #[test]
    fn a_marked_response_varies_on_the_claimed_header_and_is_private() {
        let bare = marked(&[]);
        assert_eq!(values(&bare, VARY), [b"x-auth-token"]);
        assert_eq!(values(&bare, CACHE_CONTROL), [b"private"]);

        let mut varying = HeaderMap::new();
        varying.insert(VARY, HeaderValue::from_static("Origin"));
        mark_private(&mut varying, "x-auth-token");
        assert_eq!(values(&varying, VARY), [&b"Origin"[..], b"x-auth-token"]);
        assert_eq!(values(&varying, CACHE_CONTROL), [b"private"]);
    }

    /// Negative — a `Cache-Control` that names none of the directives RFC 9111 section 3.5 lets
    /// a shared cache store an authenticated response by, and neither `private` nor `no-store`,
    /// gains `private` beside what the handler chose: a lifetime alone must not make one
    /// caller's answer a shared cache's to replay. On one line, on two, and in any case.
    #[test]
    fn n_a_cache_control_that_does_not_allow_sharing_gains_private() {
        let lifetimes: [&[&'static str]; 6] = [
            &["max-age=3600"],
            &["MAX-AGE=3600"],
            &["max-age=3600, immutable"],
            &["no-cache"],
            &["max-age=60", "stale-while-revalidate=30"],
            &["no-transform", "max-age=60, immutable"],
        ];
        for chosen in lifetimes {
            let response = marked(chosen);
            let mut expected: Vec<&[u8]> = chosen.iter().map(|value| value.as_bytes()).collect();
            expected.push(b"private");
            assert_eq!(values(&response, CACHE_CONTROL), expected, "{chosen:?}");
            assert_eq!(values(&response, VARY), [b"x-auth-token"], "{chosen:?}");
        }
        // A directive that merely contains one of the names is not that directive.
        for lookalike in ["x-public-ish=1, max-age=60", "max-age=60, privateer", "community=\"public\""] {
            let response = marked(&[lookalike]);
            assert_eq!(values(&response, CACHE_CONTROL), [lookalike.as_bytes(), b"private"], "{lookalike}");
        }
    }

    /// Positive — a `Cache-Control` that names `public`, `s-maxage` or `must-revalidate` (what
    /// section 3.5 lets a shared cache store by), or `private` or `no-store`, is left exactly as
    /// the handler chose it, in any letter case, with or without an argument, on whichever of
    /// several lines it stands; the response still varies on the claimed header.
    #[test]
    fn a_cache_control_that_already_decides_sharing_is_kept_as_the_handler_chose_it() {
        let decided: [&[&'static str]; 11] = [
            &["public, max-age=60"],
            &["PUBLIC"],
            &["max-age=60, Public"],
            &["s-maxage=120"],
            &["max-age=1, S-MaxAge=2"],
            &["must-revalidate, max-age=60"],
            &["no-store"],
            &["private, max-age=5"],
            &["Private=\"set-cookie\""],
            &["max-age=60", "public"],
            &["max-age=60 , \tmust-revalidate"],
        ];
        for chosen in decided {
            let response = marked(chosen);
            let expected: Vec<&[u8]> = chosen.iter().map(|value| value.as_bytes()).collect();
            assert_eq!(values(&response, CACHE_CONTROL), expected, "{chosen:?}");
            assert_eq!(values(&response, VARY), [b"x-auth-token"], "{chosen:?}");
        }
    }
}
