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

//! Sealed cross-crate facade bridge for bearer handler-context attachment (ADR-0056).
//!
//! Responsible for: forwarding `rustfs-gateway` to the crate-private signed-bearer context
//! attachment helper behind a zero-sized capability token.
//! NOT responsible for: any public API contract; `rustfs-gateway` never re-exports this module or
//! [`FacadeSeal`], and `scripts/check_token_sealing_surface.sh` rejects workspace references outside
//! `crates/gateway/src/service.rs` and unit tests.
//! Upstream: `rustfs-gateway`. Downstream: `crate::request_context::RequestContextView`.

use rustfs_gateway_sig::BearerReceipt;

use crate::request_context::RequestContextView;

/// Zero-sized capability token gating the facade-only core context bridge (ADR-0056).
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

/// Attaches a verified signed-path [`BearerReceipt`] to `context` and strips its query token.
///
/// Enforces fail-closed invariants: `context` must carry a signed principal, have no existing
/// bearer context, and match both `receipt.operation()` and `receipt.identity().access_key_id()`.
/// Otherwise `context` is returned unchanged.
#[doc(hidden)]
#[must_use]
pub fn attach_signed_bearer_receipt(
    _seal: FacadeSeal,
    context: RequestContextView,
    receipt: &BearerReceipt,
) -> RequestContextView {
    context.attach_signed_bearer_receipt_inner(receipt)
}
