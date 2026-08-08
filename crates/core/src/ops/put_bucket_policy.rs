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

//! `PutBucketPolicy`: the whole policy document of one bucket, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketPolicy`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_policy.rs` from `generated/ir/PutBucketPolicy.json`; nor for
//! the integrity requirement, which the generated decoder settles
//! (`http_checksum_required` in the overlay); nor for the document's semantic rules, which
//! live once in the shared module so that no backend re-derives them.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_policy. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_policy`](super::shared::bucket_policy); this file states what is this operation's
//! alone.
//!
//! # What this validates, and the far larger thing it does not
//!
//! The request body is JSON, read as text by the generated decoder and checked by
//! [`shared::bucket_policy`](super::shared::bucket_policy) for three things and no more: it is
//! within the documented size ceiling, it parses as JSON, and it does not nest past the depth this
//! parser will follow. **The policy language is not evaluated here.** Whether a statement grants
//! what it claims, whether a principal exists, and whether the caller may hand out the access it
//! describes are the authorizer's questions; a gateway that answered them would be a second
//! implementation of an evaluator that already exists downstream.
//!
//! The refusal is `MalformedPolicy` and its message is a constant. A syntax error's offset would
//! be enough to reconstruct a document the caller is not otherwise allowed to read back.
//!
//! # Why the row exists before a backend does
//!
//! `PUT /{Bucket}?policy` and `PUT /{Bucket}` differ by one query key, and `?policy` is not an
//! exclusive predicate of the bucket creation.
//! `CreateBucket`'s own `QueryAbsent` list names `policy`, which is what kept the write from
//! creating a bucket, so the absence of a row made the request unroutable rather than mis-served.
//!
//! The row lands at 216, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutBucketPolicy, PutBucketPolicyInput, PutBucketPolicyOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `policy` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec {
    name: "PutBucketPolicy",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutBucketPolicy", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketPolicy", SigService::S3);

impl Operation for PutBucketPolicy {
    const NAME: &'static str = "PutBucketPolicy";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketPolicyInput;
    type Output = PutBucketPolicyOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for PutBucketPolicyInput {
    type Op = PutBucketPolicy;
}
