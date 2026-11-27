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

//! Sealed cross-crate facade bridge for host-verified token admissions (ADR-0056).
//!
//! Responsible for: forwarding `rustfs-gateway` and `rustfs-gateway-dialect-rustfs-admin` to the
//! crate-private bearer verification, alongside-signature bearer verification, header-token
//! verification, and query-bearer-claim attachment primitives behind a zero-sized capability token.
//! NOT responsible for: any public API contract; `rustfs-gateway` never re-exports this module or
//! [`FacadeSeal`], and `scripts/check_token_sealing_surface.sh` rejects workspace references outside
//! the allowlisted facade, dialect, and fault-injection test sites.
//! Upstream: `rustfs-gateway` and `rustfs-gateway-dialect-rustfs-admin`. Downstream: crate-private
//! implementations in `bearer`, `floor_bearer`, `header_token`, and `operation`.

use rustfs_gateway_http::TransportExtensions;

use crate::bearer::{BearerAdmission, BearerReceipt, BearerTokenVerifier, QueryBearerClaim};
use crate::clock::RequestNow;
use crate::floor::{SecurityFloor, WireView};
use crate::header_token::{HeaderTokenAdmission, HeaderTokenVerifier};
use crate::operation::OperationFloor;
use crate::verdict::{AuthError, Verdict};

/// Zero-sized capability token gating the facade-only cross-crate bridge (ADR-0056).
///
/// Never re-exported by `rustfs-gateway`; audited across the workspace by
/// `scripts/check_token_sealing_surface.sh`.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct FacadeSeal(());

impl FacadeSeal {
    /// Constructs the internal bridge token for allowlisted workspace callers.
    #[doc(hidden)]
    #[must_use]
    pub const fn new() -> Self {
        Self(())
    }
}

/// Verifies a standalone query bearer admission and produces a `Verdict::Bearer` or rejection.
#[doc(hidden)]
#[must_use]
pub fn verify_bearer(
    _seal: FacadeSeal,
    admission: BearerAdmission,
    verifier: &dyn BearerTokenVerifier,
    raw_path: &str,
) -> Verdict {
    admission.verify_inner(verifier, raw_path)
}

/// Atomically verifies a query bearer token alongside an already-authenticated signature verdict.
///
/// Requires `signed_verdict` to be [`Verdict::Authenticated`] (carrying a real `SignatureMatch`)
/// before reading the query token or invoking `verifier`, and binds the returned [`BearerReceipt`]
/// to that signed principal, the request's raw resource, and `now`.
///
/// # Errors
///
/// [`AuthError::AccessDenied`] when `signed_verdict` is not signature-authenticated, the operation
/// declares no query bearer claim, the token is absent/repeated/empty/undecodable, the verifier
/// refuses, resource/expiry binding fails, or the token names another principal than `signed_verdict`.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)] // atomic facade bridge merges floor extraction and verification (ADR-0056)
pub fn verify_bearer_alongside_signature(
    _seal: FacadeSeal,
    floor: &SecurityFloor,
    view: &WireView<'_>,
    operation: &OperationFloor,
    now: RequestNow,
    signed_verdict: &Verdict,
    verifier: &dyn BearerTokenVerifier,
    raw_path: &str,
) -> Result<BearerReceipt, AuthError> {
    let Verdict::Authenticated { identity: signed, .. } = signed_verdict else {
        return Err(AuthError::AccessDenied);
    };
    let Some(admission) = floor.bearer_alongside_signature_inner(view, operation, now)? else {
        return Err(AuthError::AccessDenied);
    };
    admission.verify_alongside_inner(verifier, raw_path, signed)
}

/// Verifies a host-established header token admission and produces `Verdict::HeaderToken` or rejection.
#[doc(hidden)]
#[must_use]
pub fn verify_header_token<V: HeaderTokenVerifier>(
    _seal: FacadeSeal,
    admission: HeaderTokenAdmission,
    verifier: &V,
    server_state: &TransportExtensions,
) -> Verdict {
    admission.verify_inner(verifier, server_state)
}

/// Attaches a [`QueryBearerClaim`] to an [`OperationFloor`] for allowlisted workspace dialects.
#[doc(hidden)]
#[must_use]
pub const fn with_query_bearer_claim(_seal: FacadeSeal, floor: OperationFloor, claim: QueryBearerClaim) -> OperationFloor {
    floor.with_query_bearer_claim_inner(claim)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
#[path = "facade_internal_tests.rs"]
mod tests;
