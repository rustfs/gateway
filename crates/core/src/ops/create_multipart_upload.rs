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

//! `CreateMultipartUpload`: mint an upload id, and record everything the finished object will keep.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `CreateMultipartUpload`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/create_multipart_upload.rs` from `generated/ir/CreateMultipartUpload.json`
//! and mounted by `crate::codec`; nor for minting the upload id itself, which is the backend's.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: user metadata, content type, storage class and the SSE header set with the object
//! family; the upload-id capability with the rest of the multipart family; and the object-lock,
//! tagging and ACL header permissions with the object-write family (`shared::write_permissions`).
//!
//! This request is the only place the object's metadata is stated. `UploadPart` carries none of
//! it and `CompleteMultipartUpload` carries only the part list, so metadata dropped here is
//! dropped for good — the defect `q-mpu-metadata-0039` records.
//!
//! The response root is `InitiateMultipartUploadResult`, which is neither the operation name nor
//! the shape name. That is `xml.response_root` in the IR, read from the model, and not something
//! any encoder derives from a name.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{CreateMultipartUpload, CreateMultipartUploadInput, CreateMultipartUploadOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::write_permissions;
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `uploads` is a routing discriminator, not a required parameter: without it a `POST` to an
/// object key is a different operation rather than a malformed one.
static SPEC: OperationSpec = OperationSpec::standard("CreateMultipartUpload")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
    .extra_permissions(&write_permissions::OBJECT_WRITE)
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("CreateMultipartUpload", SigService::S3);

impl Operation for CreateMultipartUpload {
    const NAME: &'static str = "CreateMultipartUpload";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = CreateMultipartUploadInput;
    type Output = CreateMultipartUploadOutput;
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

impl HasOperation for CreateMultipartUploadInput {
    type Op = CreateMultipartUpload;
}
