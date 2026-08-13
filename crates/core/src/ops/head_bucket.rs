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

//! `HeadBucket`: does the bucket exist and may you ask — status, headers, and no body ever.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `HeadBucket`, plus the [`HasOperation`] reverse mapping from its input type, and the family's
//! region-header duty for this member.
//! NOT responsible for: the wire bindings, generated into `generated/codec/ops/head_bucket.rs`;
//! or the zero-body rule itself, which is the response layer's RFC 9110 invariant — this family
//! contributes the regression cases that keep it held on the error paths.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_region
//!
//! # The region header is a required output, not a convention
//!
//! A `HeadBucket` success must carry `x-amz-bucket-region` — it is how SDKs discover a bucket's
//! region, and the `301 PermanentRedirect` must carry it too or the redirect cannot be completed.
//! The overlay therefore marks `BucketRegion` required, so the generated output type has no
//! `Option` around it: a handler that cannot name the region cannot construct a success at all,
//! which is the strongest available spelling of "this header is not optional". The IAM action is
//! `s3:ListBucket` — AWS defines no `s3:HeadBucket`.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{HeadBucket, HeadBucketInput, HeadBucketOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::bucket_region::RegionHeaderDuty;
use crate::registry::OperationSpec;

/// The one member whose *success* carries `x-amz-bucket-region`, enforced by the required output
/// field rather than by anything a renderer remembers to do.
pub static REGION_HEADER_DUTY: RegionHeaderDuty = RegionHeaderDuty::SuccessAndRedirect;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec::builder("HeadBucket", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:ListBucket", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("HeadBucket", SigService::S3);

impl Operation for HeadBucket {
    const NAME: &'static str = "HeadBucket";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = HeadBucketInput;
    type Output = HeadBucketOutput;
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

impl HasOperation for HeadBucketInput {
    type Op = HeadBucket;
}
