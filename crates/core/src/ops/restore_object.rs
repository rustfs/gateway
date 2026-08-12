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

//! `RestoreObject`: an archived object version asked back into a readable tier.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `RestoreObject`, plus the [`HasOperation`] reverse mapping from its input type — and, in
//! [`ALT_SUCCESS_STATUSES`], the one place that says a success here is a `202` **or** a `200`.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/restore_object.rs` — the request document is the payload structure
//! `RestoreRequest`, and `x-amz-restore-output-path` is a plain response header; nor for the
//! document's semantic rules — the `Days`/`OutputLocation` grammar, the closed `Tier` set and
//! the `Type=SELECT` triple — which live once in [`shared::restore`](super::shared::restore);
//! nor for **performing** a retrieval: which tier a backend uses, how long it takes and whether
//! it exists at all are the storage side's, and nothing in this crate waits for one.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: restore, select. The second is not a mistake: a `RestoreRequest` may carry
//! `SelectParameters`, whose four members are the same four a `SelectObjectContentRequest`
//! carries, so [`shared::select`](super::shared::select)'s rules are what validates them — with
//! the same codes, so a select-on-restore and a plain select are refused identically.
//!
//! # The three success answers, and why they are not the handler's to invent
//!
//! A restore request has four documented outcomes and only two of them are the declared success
//! status. A first retrieval answers `202 Accepted`; a repeat against an object whose retrieval
//! has already **finished** answers `200 OK`; a repeat while one is still running is a `409
//! RestoreAlreadyInProgress`; and a request against an object that is not in an archive class at
//! all is a `403 InvalidObjectState`. A client polls on exactly this difference — `202` means
//! "come back later", `200` means "it is here now" — so a backend that answered its own
//! favourite number would break the poll loop while returning a status in the success family,
//! which no status assertion of the ordinary kind catches.
//!
//! So the mapping is data, in [`crate::ops::shared::restore::RestoreState::status`], and this file declares
//! the alternative the mapping is allowed to reach. The pair is asserted in both directions by
//! `tests/params_and_dispatch.rs`: every state the mapping can produce on success must be either
//! `SPEC.success_status` or a member of [`ALT_SUCCESS_STATUSES`], and every member of
//! [`ALT_SUCCESS_STATUSES`] must be a status some state actually produces. A list that grew a
//! number nothing answers, or a mapping that answered a number the list does not carry, is red.
//!
//! # Why the row exists before a backend does
//!
//! `POST /{Bucket}/{Key+}` was a shape the table knew only as the multipart band, so with no row
//! of its own `POST /b/k?restore` matched **nothing** and was refused with
//! `crate::dispatch::NO_ROUTE_MESSAGE` — the answer that says the endpoint is probably not an S3
//! endpoint. The row lands at 570, behind `CompleteMultipartUpload` (420) and
//! `CreateMultipartUpload` (450) so that a request naming an upload is still the upload it
//! names.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{RestoreObject, RestoreObjectInput, RestoreObjectOutput};

use crate::contracts::{RESTORE_VERSION_SELECTOR, RestoreVersionSelectorPolicy};
use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// The success statuses this operation may answer that are not the operation spec's `success_status`.
///
/// Exactly one: the `200` a repeat request against an already-restored copy answers. `409` and
/// `403` are refusals and are not here — a refusal never reaches an encoder.
pub const ALT_SUCCESS_STATUSES: &[u16] = &[200];

/// What this operation requires of a request once routing has chosen it.
///
/// `restore` is a routing discriminator, not a required parameter, and `versionId` selects a
/// version whose absence selects the current one. The payload is **not** promoted to required:
/// AWS documents a bodyless restore, and the missing-`RestoreRequest` refusal is the operation's
/// (`InvalidRequest`), not the parser's `MalformedXML` — see the module note in
/// [`shared::restore`](super::shared::restore).
static SPEC: OperationSpec = OperationSpec {
    name: "RestoreObject",
    success_status: 202,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:RestoreObject", ResourceShape::Object)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("RestoreObject", SigService::S3);

impl Operation for RestoreObject {
    const NAME: &'static str = "RestoreObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = RestoreObjectInput;
    type Output = RestoreObjectOutput;
    type DerivedResources = crate::authz::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        Ok(crate::authz::NoDerived)
    }

    fn seal_derived_input(input: &mut Self::Input) {
        if matches!(RESTORE_VERSION_SELECTOR, RestoreVersionSelectorPolicy::Drop) {
            input.version_id = None;
        }
    }

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for RestoreObjectInput {
    type Op = RestoreObject;
}
