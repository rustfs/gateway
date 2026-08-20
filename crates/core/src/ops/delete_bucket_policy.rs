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

//! `DeleteBucketPolicy`: the policy document removed, the bucket left alone.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `DeleteBucketPolicy`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/delete_bucket_policy.rs` from `generated/ir/DeleteBucketPolicy.json`; nor for
//! anything in a body — the operation has none in either direction.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_policy. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_policy`](super::shared::bucket_policy); this file states what is this operation's
//! alone.
//!
//! # The delete is 204 and unconditional
//!
//! Removing the policy of a bucket that has none is a success, not a `404` (`q-pol-0004`): a `404`
//! here would make "already gone" indistinguishable from "wrong bucket", which is what
//! `NoSuchBucket` is for. [`OperationSpec::not_configured_error`] is `None` for exactly that
//! reason, and the read beside it is the only member of the triple that carries one.
//!
//! # Why the row exists before a backend does
//!
//! `DELETE /{Bucket}?policy` and `DELETE /{Bucket}` differ by one query key, and `?policy` is not an
//! exclusive predicate of the bucket deletion.
//! `DeleteBucket`'s own `QueryAbsent` list names `policy`, which is what kept the request from
//! deleting the bucket, so the absence of a row made it unroutable rather than mis-served.
//!
//! The row lands at 217, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{DeleteBucketPolicy, DeleteBucketPolicyInput, DeleteBucketPolicyOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `policy` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec::standard("DeleteBucketPolicy")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:DeleteBucketPolicy", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteBucketPolicy", SigService::S3);

impl Operation for DeleteBucketPolicy {
    const NAME: &'static str = "DeleteBucketPolicy";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteBucketPolicyInput;
    type Output = DeleteBucketPolicyOutput;
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

impl HasOperation for DeleteBucketPolicyInput {
    type Op = DeleteBucketPolicy;
}
