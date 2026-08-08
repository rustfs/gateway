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

//! `DeleteBucketWebsite`: the static-website document removed, the bucket left alone.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `DeleteBucketWebsite`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/delete_bucket_website.rs` from `generated/ir/DeleteBucketWebsite.json`; nor for
//! anything in a body — the operation has none in either direction.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_website. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_website`](super::shared::bucket_website); this file states what is this operation's
//! alone.
//!
//! # The delete is 204 and unconditional
//!
//! Removing the website document of a bucket that has none is a success (`q-web-0005`), even though
//! the *read* of that same unconfigured bucket is a `404`. The asymmetry is deliberate and is the
//! reason [`OperationSpec::not_configured_error`] is `Some(..)` on the read and `None` here: a
//! delete that answered `404` would make a retry after a lost response look like a failure.
//!
//! # Why the row exists before a backend does
//!
//! `DELETE /{Bucket}?website` and `DELETE /{Bucket}` differ by one query key, and `?website` is not an
//! exclusive predicate of the bucket deletion.
//! `DeleteBucket`'s own `QueryAbsent` list names `website`, which is what kept the request from
//! deleting the bucket, so the absence of a row made it unroutable rather than mis-served.
//!
//! The row lands at 242, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{DeleteBucketWebsite, DeleteBucketWebsiteInput, DeleteBucketWebsiteOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `website` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec {
    name: "DeleteBucketWebsite",
    success_status: 204,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:DeleteBucketWebsite", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteBucketWebsite", SigService::S3);

impl Operation for DeleteBucketWebsite {
    const NAME: &'static str = "DeleteBucketWebsite";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteBucketWebsiteInput;
    type Output = DeleteBucketWebsiteOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for DeleteBucketWebsiteInput {
    type Op = DeleteBucketWebsite;
}
