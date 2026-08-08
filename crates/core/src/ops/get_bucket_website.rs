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

//! `GetBucketWebsite`: the static-website document of one bucket, and nothing that serves a page from it.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketWebsite`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_website.rs` from `generated/ir/GetBucketWebsite.json`; nor for
//! the stored document itself, which is a backend's to keep.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_website. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_website`](super::shared::bucket_website); this file states what is this operation's
//! alone.
//!
//! # The unconfigured answer is a 404 with this subresource's own code
//!
//! A bucket with no website document answers **404 `NoSuchWebsiteConfiguration`** — not the policy
//! code, not the public-access code, and not an empty `200` (`q-web-0001`). It is one of three
//! reads in this family that answer a `404` at all, and all three literals differ.
//!
//! `<RoutingRules>` is **wrapped**: the rules sit inside the element, one `<RoutingRule>` each. That
//! is the opposite of the notification family's three flattened lists in the file two doors down,
//! and rendering it flattened is a document every SDK reads as having no rules (`q-web-0002`).
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?website` and `GET /{Bucket}` differ by one query key, and `?website` is not an
//! exclusive predicate of the key listing.
//! With no row of its own the read was claimed by `ListObjects` and answered with a page of keys
//! — the `GetBucketWebsite -> ListObjects` line of the route-coverage debt register.
//!
//! The row lands at 240, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{GetBucketWebsite, GetBucketWebsiteInput, GetBucketWebsiteOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `website` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec {
    name: "GetBucketWebsite",
    success_status: 200,
    required_params: &[],
    not_configured_error: Some(ErrorCode::NO_SUCH_WEBSITE_CONFIGURATION),
    auth: Some(AuthRequirement::new("s3:GetBucketWebsite", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketWebsite", SigService::S3);

impl Operation for GetBucketWebsite {
    const NAME: &'static str = "GetBucketWebsite";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketWebsiteInput;
    type Output = GetBucketWebsiteOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for GetBucketWebsiteInput {
    type Op = GetBucketWebsite;
}
