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

//! `DeleteObject`: one key removed, idempotently.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `DeleteObject`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/delete_object.rs` from `generated/ir/DeleteObject.json` and mounted by
//! `crate::codec`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: nothing. It is the one member of the family with no body in either direction.
//!
//! The success status is `204` and it is unconditional: deleting a key that was never there is a
//! success, and answering `404` turns a retried delete into a client-visible failure. The status
//! comes from the model and the idempotence is recorded as `q-delete-0026`; neither is a decision
//! this file makes.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{DeleteObject, DeleteObjectInput, DeleteObjectOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec::builder("DeleteObject", 204, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:DeleteObject", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteObject", SigService::S3);

impl Operation for DeleteObject {
    const NAME: &'static str = "DeleteObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteObjectInput;
    type Output = DeleteObjectOutput;
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

impl HasOperation for DeleteObjectInput {
    type Op = DeleteObject;
}
