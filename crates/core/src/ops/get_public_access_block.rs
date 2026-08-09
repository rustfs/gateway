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

//! `GetPublicAccessBlock`: the four public-access switches of one bucket.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetPublicAccessBlock`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_public_access_block.rs` from `generated/ir/GetPublicAccessBlock.json`; nor for
//! the stored document itself, which is a backend's to keep.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_policy. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_policy`](super::shared::bucket_policy); this file states what is this operation's
//! alone.
//!
//! # The unconfigured answer is this family's third distinct 404
//!
//! A bucket with no public-access block answers **404 `NoSuchPublicAccessBlockConfiguration`** —
//! not the website code, not the policy code, and not an empty `200`. Three of this family's nine
//! reads answer a `404` and each answers a different literal; the other six answer an empty `200`.
//! The codes are not interchangeable and the boundary is not a detail: a client branches on it
//! (`q-pab-0001`).
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?publicAccessBlock` and `GET /{Bucket}` differ by one query key, and `?publicAccessBlock`
//! is not an
//! exclusive predicate of the key listing.
//! With no row of its own the read was claimed by `ListObjects` and answered with a page of keys
//! — the `GetPublicAccessBlock -> ListObjects` line of the route-coverage debt register.
//!
//! The row lands at 225, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{GetPublicAccessBlock, GetPublicAccessBlockInput, GetPublicAccessBlockOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `publicAccessBlock` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec {
    name: "GetPublicAccessBlock",
    success_status: 200,
    required_params: &[],
    not_configured_error: Some(ErrorCode::NO_SUCH_PUBLIC_ACCESS_BLOCK_CONFIGURATION),
    auth: Some(AuthRequirement::new("s3:GetBucketPublicAccessBlock", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetPublicAccessBlock", SigService::S3);

impl Operation for GetPublicAccessBlock {
    const NAME: &'static str = "GetPublicAccessBlock";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetPublicAccessBlockInput;
    type Output = GetPublicAccessBlockOutput;
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

impl HasOperation for GetPublicAccessBlockInput {
    type Op = GetPublicAccessBlock;
}
