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

//! `DeleteBucket`: a bucket ceases to exist, answered with nothing at all.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `DeleteBucket`, plus the [`HasOperation`] reverse mapping from its input type, and the
//! family's region-header duty for this member.
//! NOT responsible for: the wire bindings, generated into `generated/codec/ops/delete_bucket.rs`;
//! or knowing whether the bucket is empty, which only a backend can answer — a bucket that still
//! holds anything is its `409 BucketNotEmpty`, a bucket that does not exist its `404
//! NoSuchBucket`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_region
//!
//! # A 204 is zero bytes, and the selector pins what it is not
//!
//! Success is `204` and the model says so; the output has no members, so there is nothing a body
//! could carry and RFC 9110 forbids one anyway. The selector pins the absence of every deferred
//! bucket-level DELETE subresource for the same reason `CreateBucket`'s does: without the list,
//! `DELETE /b?policy` would *delete the bucket* instead of answering 501 — the worst possible
//! reading of a request that only wanted a configuration removed.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{DeleteBucket, DeleteBucketInput, DeleteBucketOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::bucket_region::RegionHeaderDuty;
use crate::registry::OperationSpec;

/// A deletion's success is a bare 204; only its redirect carries `x-amz-bucket-region`.
pub static REGION_HEADER_DUTY: RegionHeaderDuty = RegionHeaderDuty::RedirectOnly;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec::builder("DeleteBucket", 204, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:DeleteBucket", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteBucket", SigService::S3);

impl Operation for DeleteBucket {
    const NAME: &'static str = "DeleteBucket";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteBucketInput;
    type Output = DeleteBucketOutput;
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

impl HasOperation for DeleteBucketInput {
    type Op = DeleteBucket;
}
