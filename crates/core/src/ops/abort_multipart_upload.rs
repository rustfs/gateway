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

//! `AbortMultipartUpload`: discard an upload, and say so with an empty 204.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `AbortMultipartUpload`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/abort_multipart_upload.rs` from
//! `generated/ir/AbortMultipartUpload.json`; nor for reclaiming the parts.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: the upload-id capability with the rest of the multipart family.
//!
//! # Why this is not the idempotent delete
//!
//! `DeleteObject` answers the same empty 204 whether or not the key was there, because the key is
//! a name the caller chose and a retried delete must not become a client-visible failure
//! (`q-delete-0026`). An upload id is the opposite: it is minted by the server, and a request
//! carrying one that does not exist is a request about something the caller was never given. So
//! an unknown or already-aborted id is `NoSuchUpload`, not a success — `q-mpu-abort-0035`.
//!
//! The 204 itself comes from the model, not from the overlay. Reviewing it here would be a second
//! source for the same fact.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{AbortMultipartUpload, AbortMultipartUploadInput, AbortMultipartUploadOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `uploadId` is a routing discriminator, not a required parameter: a `DELETE` on an object key
/// without it is `DeleteObject`, a different operation.
static SPEC: OperationSpec = OperationSpec::standard("AbortMultipartUpload")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:AbortMultipartUpload", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("AbortMultipartUpload", SigService::S3);

impl Operation for AbortMultipartUpload {
    const NAME: &'static str = "AbortMultipartUpload";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = AbortMultipartUploadInput;
    type Output = AbortMultipartUploadOutput;
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

impl HasOperation for AbortMultipartUploadInput {
    type Op = AbortMultipartUpload;
}
