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

//! `CreateBucket`: a bucket comes into existence, and the region rules concentrate here.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `CreateBucket`, plus the [`HasOperation`] reverse mapping from its input type, and the two
//! family facts a backend reads: the region-match policy and the region-header duty.
//! NOT responsible for: the wire bindings, generated into `generated/codec/ops/create_bucket.rs`
//! from `generated/ir/CreateBucket.json`; the LocationConstraint semantics, which live in
//! `shared::location_constraint`; or deciding who owns a bucket, which only a backend knows.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_region, location_constraint
//!
//! # Success is 200 with a Location header, and the status matrix is the protocol's
//!
//! A new bucket is a `200` carrying `Location: /{bucket}` — not a `201`, which SDKs and the
//! upstream test suites would refuse. Re-creating a bucket you already own is `200` in us-east-1
//! (the historical behaviour) and `409 BucketAlreadyOwnedByYou` everywhere else; a name held by
//! another owner is `409 BucketAlreadyExists`. The *facts* come from the handler — the framework
//! does not know who owns a name — but all three outcomes are expressible and their statuses come
//! from the error table, never from a handler's own number.
//!
//! # Why the selector pins two dozen absent query keys
//!
//! `PUT /{bucket}` pins no positive query key, so without the `query_absent` list in
//! `model/overlays/ops/bucket.toml` this row would claim every bucket subresource write it does
//! not out-precede: `PUT /b?acl` would *create a bucket* instead of answering 501. The list names
//! served subresources (`cors`, `tagging`) too, which keeps this row provably disjoint from their
//! bands instead of merely later. Routing decides what a request means; the list keeps the
//! subresource meanings out of this row.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{CreateBucket, CreateBucketInput, CreateBucketOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::bucket_region::RegionHeaderDuty;
use crate::ops::shared::location_constraint::RegionMatchPolicy;
use crate::registry::OperationSpec;

/// How a presented `LocationConstraint` is matched against the deployment's regions, by default.
///
/// AWS's strict posture. A backend starts from this value and changes it only as a deployment
/// decision: the RustFS profile accepts an explicit us-east-1
/// ([`RegionMatchPolicy::AcceptExplicitUsEast1`], rustfs/gateway#914).
pub static REGION_MATCH_POLICY: RegionMatchPolicy = RegionMatchPolicy::Strict;

/// A creation's success says where the bucket is through `Location`; only its redirect carries
/// `x-amz-bucket-region`.
pub static REGION_HEADER_DUTY: RegionHeaderDuty = RegionHeaderDuty::RedirectOnly;

/// What this operation requires of a request once routing has chosen it.
///
/// Nothing beyond the bucket in the path: the configuration body is optional (its absence *is*
/// the us-east-1 spelling), and every header is optional. Content problems in the body are
/// parameter validation — a 400, never a routing miss.
static SPEC: OperationSpec = OperationSpec::standard("CreateBucket")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:CreateBucket", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("CreateBucket", SigService::S3);

impl Operation for CreateBucket {
    const NAME: &'static str = "CreateBucket";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = CreateBucketInput;
    type Output = CreateBucketOutput;
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

impl HasOperation for CreateBucketInput {
    type Op = CreateBucket;
}
