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

//! `ListMultipartUploads`: the uploads in flight in one bucket, under two cursors.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `ListMultipartUploads`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/list_multipart_uploads.rs` from
//! `generated/ir/ListMultipartUploads.json`; nor for the pagination module, which is `P5-05`'s.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: delimiter rollup, `CommonPrefixes`, `encoding-type` and the truncation contract with
//! the listing family; the upload-id capability with the rest of the multipart family.
//!
//! # Two cursors, not one
//!
//! One key can carry several concurrent uploads, so a page resumes from `key-marker` *and*
//! `upload-id-marker`. A resume that carries only the key cursor either repeats or skips every
//! upload that shared the boundary key — the failure `q-mpu-marker-0040` records, and the reason
//! both markers are echoed in the response as well as accepted in the request.
//!
//! `Upload` repeats directly under the result root with no wrapper, and the element name is not
//! the member name (`q-mpu-upload-0032`). Under `encoding-type=url` the key-shaped members —
//! `Prefix`, `Delimiter`, `KeyMarker`, `NextKeyMarker`, and each upload's `Key` — are
//! percent-encoded and the echo says so, which is `q-encoding-0015` shared with the listing
//! family.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{ListMultipartUploads, ListMultipartUploadsInput, ListMultipartUploadsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `uploads` is a routing discriminator, not a required parameter: without it a `GET` on a bucket
/// is a listing of objects rather than a malformed listing of uploads.
static SPEC: OperationSpec = OperationSpec::standard("ListMultipartUploads")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:ListBucketMultipartUploads", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("ListMultipartUploads", SigService::S3);

impl Operation for ListMultipartUploads {
    const NAME: &'static str = "ListMultipartUploads";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = ListMultipartUploadsInput;
    type Output = ListMultipartUploadsOutput;
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

impl HasOperation for ListMultipartUploadsInput {
    type Op = ListMultipartUploads;
}
