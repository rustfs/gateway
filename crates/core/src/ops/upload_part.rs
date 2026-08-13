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

//! `UploadPart`: one numbered slice of an upload, and the entity tag completion will echo back.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `UploadPart`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/upload_part.rs` from `generated/ir/UploadPart.json` and mounted by
//! `crate::codec`; nor for storing the part.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: the packed checksum header, the streaming request body and the `Content-Length`
//! refusal with `PutObject`; the upload-id capability with the rest of the multipart family.
//!
//! # Why this is not `PutObject` with extra parameters
//!
//! The model spells this operation `PUT /{Bucket}/{Key+}?x-id=UploadPart`, and `x-id` is inert —
//! the SDKs write it on almost every request. Its real discriminators are `partNumber` and
//! `uploadId`, which the model's uri does not pin, so they are declared as `query_present` in
//! `model/overlays/ops/multipart.toml` and put this operation at precedence 410, ahead of
//! `PutObject` at 800. Without that, a part upload would route to `PutObject` and overwrite the
//! object it was a part of.
//!
//! `partNumber` and `uploadId` are therefore routing discriminators rather than required
//! parameters: a `PUT` without them is `PutObject`, a different operation, not a malformed one.
//! `Content-Length` is the opposite case — it is required here, with the same dedicated 411 code
//! `PutObject` uses, because a body with no declared length and no chunked framing is a framing
//! fact rather than a value fact.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{UploadPart, UploadPartInput, UploadPartOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// The 411 for a missing `Content-Length` is not expressible here: the pre-authentication status
/// set is `{400, 403, 501}`, so the refusal belongs to the decoder, where the IR carries
/// `missing_error = "MissingContentLength"` for the field.
static SPEC: OperationSpec = OperationSpec::builder("UploadPart", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged. A part body may be signed with any payload mode
/// `PutObject` accepts, including the chunked forms.
static FLOOR: OperationFloor = OperationFloor::builtin("UploadPart", SigService::S3);

impl Operation for UploadPart {
    const NAME: &'static str = "UploadPart";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = UploadPartInput;
    type Output = UploadPartOutput;
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

impl HasOperation for UploadPartInput {
    type Op = UploadPart;
}
