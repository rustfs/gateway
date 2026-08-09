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

//! `GetBucketPolicy`: the stored policy document of one bucket, answered as JSON.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketPolicy`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_policy.rs` from `generated/ir/GetBucketPolicy.json`; nor for
//! the stored document itself, which is a backend's to keep.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_policy. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_policy`](super::shared::bucket_policy); this file states what is this operation's
//! alone.
//!
//! # The one success body in this surface that is not XML
//!
//! The response is the policy document byte for byte with `Content-Type: application/json`, which
//! the generated encoder emits from `q-pol-0001` — a `media_type` quirk on the payload member,
//! resolved by `crates/codegen/src/emit/codec/media.rs`. The **error** body stays XML: a `404` here
//! is an `<Error>` document like every other, and a client that branched on the content type of the
//! success path would be reading the wrong body on the failure path (`q-pol-0002`).
//!
//! A bucket with no policy answers **404 `NoSuchBucketPolicy`**, not an empty document and not a
//! generic not-found. That is what [`OperationSpec::not_configured_error`] carries, and it is the
//! field an external backend reads to learn which code it owes.
//!
//! Nothing here ever repeats the document in an error. A policy names principals, account ids and
//! resource ARNs, so every refusal in this family is a constant built at compile time.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?policy` and `GET /{Bucket}` differ by one query key, and `?policy` is not an
//! exclusive predicate of the key listing.
//! With no row of its own the read was claimed by `ListObjects` and answered with a page of keys
//! — the `GetBucketPolicy -> ListObjects` line of the route-coverage debt register.
//!
//! The row lands at 215, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{GetBucketPolicy, GetBucketPolicyInput, GetBucketPolicyOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `policy` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec {
    name: "GetBucketPolicy",
    success_status: 200,
    required_params: &[],
    not_configured_error: Some(ErrorCode::NO_SUCH_BUCKET_POLICY),
    auth: Some(AuthRequirement::new("s3:GetBucketPolicy", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketPolicy", SigService::S3);

impl Operation for GetBucketPolicy {
    const NAME: &'static str = "GetBucketPolicy";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketPolicyInput;
    type Output = GetBucketPolicyOutput;
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

impl HasOperation for GetBucketPolicyInput {
    type Op = GetBucketPolicy;
}
