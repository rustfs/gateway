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

//! `GetBucketPolicyStatus`: whether the stored policy makes the bucket public, as one boolean.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketPolicyStatus`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_policy_status.rs` from `generated/ir/GetBucketPolicyStatus.json`; nor
//! for
//! the stored document itself, which is a backend's to keep.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_policy. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_policy`](super::shared::bucket_policy); this file states what is this operation's
//! alone.
//!
//! # Why this shares the policy read's 404 rather than minting its own
//!
//! The answer is a reading of the policy document, so a bucket with no policy has no status to
//! report and answers **404 `NoSuchBucketPolicy`** — the same code the policy read answers, because
//! it is the same missing thing (`q-pol-0005`). The body is `<PolicyStatus><IsPublic>` with the
//! boolean in lower case, which is the XML boolean spelling and not a choice made here.
//!
//! Deciding *whether* a document is public is the authorizer's, never this file's: the gateway
//! transports the boolean a backend computed and has no policy evaluator of its own.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?policyStatus` and `GET /{Bucket}` differ by one query key, and `?policyStatus` is not an
//! exclusive predicate of the key listing.
//! With no row of its own the read was claimed by `ListObjects` and answered with a page of keys
//! — the `GetBucketPolicyStatus -> ListObjects` line of the route-coverage debt register.
//!
//! The row lands at 220, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{GetBucketPolicyStatus, GetBucketPolicyStatusInput, GetBucketPolicyStatusOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `policyStatus` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec::builder("GetBucketPolicyStatus", 200, Some(ErrorCode::NO_SUCH_BUCKET_POLICY))
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetBucketPolicyStatus", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketPolicyStatus", SigService::S3);

impl Operation for GetBucketPolicyStatus {
    const NAME: &'static str = "GetBucketPolicyStatus";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketPolicyStatusInput;
    type Output = GetBucketPolicyStatusOutput;
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

impl HasOperation for GetBucketPolicyStatusInput {
    type Op = GetBucketPolicyStatus;
}
