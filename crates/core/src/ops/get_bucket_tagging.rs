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

//! `GetBucketTagging`: the tag set of one bucket, and nothing else about it.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketTagging`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_tagging.rs` from `generated/ir/GetBucketTagging.json`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: tagging. The set this operation reads back is whatever a bucket tagging write
//! validated under [`crate::ops::shared::tagging`]'s bucket-scope rules, and [`TAG_SCOPE`] is
//! where this file says which scope that is.
//!
//! # The unconfigured answer is this operation's own 404
//!
//! A bucket that never had a tag set answers `404 NoSuchTagSet` — a dedicated code, declared in
//! [`OperationSpec::not_configured_error`] rather than raised ad hoc, because a client branches on
//! it: a generic not-found here reads as "no such bucket" and sends the operator to the wrong
//! fault. This is the *opposite* of the object read one band down, whose empty answer is a `200`
//! with an empty `TagSet` — the two rules meet nowhere, and each is pinned by its own case.
//!
//! The row lands at 310, in the bucket subresource band behind `?location` at 300: without it a
//! `GET /{Bucket}?tagging` fell through to `ListObjects` at 700 and was answered with a page of
//! keys.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{GetBucketTagging, GetBucketTaggingInput, GetBucketTaggingOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::tagging::TagScope;
use crate::registry::OperationSpec;

/// The scope whose rules govern this tag set: a bucket's, fifty tags at the ceiling.
pub static TAG_SCOPE: TagScope = TagScope::Bucket;

/// What this operation requires of a request once routing has chosen it.
///
/// `tagging` is a routing discriminator, not a required parameter: a `GET` on a bucket without it
/// is a listing. What this spec does declare is the unconfigured answer — see the module docs.
static SPEC: OperationSpec = OperationSpec {
    name: "GetBucketTagging",
    success_status: 200,
    required_params: &[],
    not_configured_error: Some(ErrorCode::NO_SUCH_TAG_SET),
    auth: Some(AuthRequirement::new("s3:GetBucketTagging", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketTagging", SigService::S3);

impl Operation for GetBucketTagging {
    const NAME: &'static str = "GetBucketTagging";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketTaggingInput;
    type Output = GetBucketTaggingOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for GetBucketTaggingInput {
    type Op = GetBucketTagging;
}
