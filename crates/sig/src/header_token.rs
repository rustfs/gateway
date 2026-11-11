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

//! A host-verified header token claim (ADR-0050, rustfs/gateway#1586).
//!
//! Responsible for: [`HeaderTokenClaim`] (the service-level opt-in: one lowercase header name),
//! [`HeaderTokenAdmission`] (the sealed result of the floor admitting a request by that claim),
//! the host's [`HeaderTokenVerifier`] trust boundary and the [`HeaderTokenReceipt`] only a
//! verification produces.
//! NOT responsible for: validating the token, its replay policy, expiry or revocation — the
//! host's outer layer did that before the gateway ran, and the verifier only reports the identity
//! that layer established — or authorization, which still runs on the receipt's principal.
//! Upstream: [`crate::SecurityFloor::admit`], the only producer of a [`HeaderTokenAdmission`].
//! Downstream: [`crate::Verdict::HeaderToken`], and the facade, which installs the claim and the
//! verifier together and removes the claimed header from the request head before acceptance.
//!
//! # Why a claim and not an anonymous request
//!
//! A host whose outer layer authenticated a non-AWS token (OpenStack Keystone's `X-Auth-Token`)
//! serves the request as that token's user. Admitting the request as anonymous would have the
//! governor, both authorization stages and the audit record judge it as nobody. The claim instead
//! admits it only as far as the host's verifier, and the verdict names the principal the host
//! established.
//!
//! # The token never enters this module
//!
//! The floor checks that the claimed header is present exactly once and well shaped, and copies
//! nothing: [`HeaderTokenAdmission`] holds no token, and [`HeaderTokenRequest`] has no accessor
//! for one. The verifier answers from the request's own server-side state.
//!
//! ```compile_fail,E0599
//! fn peek(request: &rustfs_gateway_sig::HeaderTokenRequest<'_>) -> &str {
//!     request.token()
//! }
//! ```
//!
//! # What cannot be forged
//!
//! [`HeaderTokenAdmission`] and [`HeaderTokenReceipt`] have private fields, no `Clone`, no
//! `Default` and no public constructor: the first comes only from the floor, the second only from
//! [`HeaderTokenAdmission::verify`], which calls the installed verifier.
//!
//! ```compile_fail,E0451
//! use rustfs_gateway_sig::{HeaderTokenAdmission, RequestNow};
//! fn forge(now: RequestNow) -> HeaderTokenAdmission {
//!     HeaderTokenAdmission { operation: "op", now }
//! }
//! ```
//!
//! ```compile_fail,E0624
//! use rustfs_gateway_sig::{HeaderTokenAdmission, RequestNow};
//! fn conjure(now: RequestNow) -> HeaderTokenAdmission {
//!     HeaderTokenAdmission::new("op", now)
//! }
//! ```
//!
//! ```compile_fail,E0599
//! use rustfs_gateway_sig::HeaderTokenAdmission;
//! fn copy(admission: &HeaderTokenAdmission) -> HeaderTokenAdmission {
//!     admission.clone()
//! }
//! ```
//!
//! ```compile_fail,E0599
//! use rustfs_gateway_sig::HeaderTokenAdmission;
//! fn conjure() -> HeaderTokenAdmission {
//!     HeaderTokenAdmission::default()
//! }
//! ```
//!
//! ```compile_fail,E0451
//! use rustfs_gateway_sig::{HeaderTokenReceipt, Identity};
//! fn forge(identity: Identity) -> HeaderTokenReceipt {
//!     HeaderTokenReceipt { identity, operation: "op" }
//! }
//! ```
//!
//! ```compile_fail,E0599
//! use rustfs_gateway_sig::HeaderTokenReceipt;
//! fn copy(receipt: &HeaderTokenReceipt) -> HeaderTokenReceipt {
//!     receipt.clone()
//! }
//! ```
//!
//! ```compile_fail,E0599
//! use rustfs_gateway_sig::HeaderTokenReceipt;
//! fn conjure() -> HeaderTokenReceipt {
//!     HeaderTokenReceipt::default()
//! }
//! ```
//!
//! Host code cannot wrap a receipt into a verdict itself; only [`HeaderTokenAdmission::verify`]
//! does:
//!
//! ```compile_fail,E0624
//! use rustfs_gateway_sig::{HeaderTokenReceipt, Verdict};
//! fn launder(receipt: HeaderTokenReceipt) -> Verdict {
//!     Verdict::header_token(receipt)
//! }
//! ```
//!
//! Nor build the variant directly:
//!
//! ```compile_fail,E0639
//! use rustfs_gateway_sig::{HeaderTokenReceipt, Verdict};
//! fn launder(receipt: HeaderTokenReceipt) -> Verdict {
//!     Verdict::HeaderToken(receipt)
//! }
//! ```
