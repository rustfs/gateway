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

//! `GetObjectLegalHold`: the legal-hold document of one object, and nothing else about it.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetObjectLegalHold`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_object_legal_hold.rs` — where the response root is the payload
//! member's `xmlName`, `LegalHold`, not the shape name `ObjectLockLegalHold` (`q-lock-0005`).
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: object_lock. The document this operation reads back is whatever a legal-hold write
//! validated under [`shared::object_lock`](super::shared::object_lock)'s rules.
//!
//! # Why the row exists before a backend does
//!
//! The retention read's reason, one subresource over: with no `?legal-hold` row the request was
//! claimed by `GetObject` and answered with the object's bytes. The row lands at 530, so an
//! unhandled legal-hold read is refused with `crate::dispatch::NOT_REGISTERED_MESSAGE` rather
//! than answered by its neighbour.
//!
//! An object with no legal hold is a **404 `NoSuchObjectLockConfiguration`** — the same
//! object-level code the retention read answers (`q-lock-0003`), never a `200` carrying an
//! `OFF` a compliance audit would read as a hold that exists.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetObjectLegalHold, GetObjectLegalHoldInput, GetObjectLegalHoldOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `legal-hold` is a routing discriminator, not a required parameter: a `GET` on an object key
/// without it is `GetObject`. Nothing else is required — `versionId` selects a version and its
/// absence selects the current one.
static SPEC: OperationSpec = OperationSpec::standard("GetObjectLegalHold")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetObjectLegalHold", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetObjectLegalHold", SigService::S3);

impl Operation for GetObjectLegalHold {
    const NAME: &'static str = "GetObjectLegalHold";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetObjectLegalHoldInput;
    type Output = GetObjectLegalHoldOutput;
    type DerivedResources = crate::authz::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        Ok(crate::authz::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for GetObjectLegalHoldInput {
    type Op = GetObjectLegalHold;
}
