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

//! `PutBucketWebsite`: the static-website document of one bucket, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketWebsite`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_website.rs` from `generated/ir/PutBucketWebsite.json`; nor for
//! the integrity requirement, which the generated decoder settles
//! (`http_checksum_required` in the overlay); nor for the document's semantic rules, which
//! live once in the shared module so that no backend re-derives them.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_website. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_website`](super::shared::bucket_website); this file states what is this operation's
//! alone.
//!
//! # The one mutual exclusion this family enforces
//!
//! `<RedirectAllRequestsTo>` and the `<IndexDocument>`/`<ErrorDocument>`/`<RoutingRules>` group are
//! alternatives, not a union: a document carrying both describes two different sites and AWS
//! refuses it. [`shared::bucket_website`](super::shared::bucket_website) makes that refusal, along
//! with the one grammar rule inside a rule — a `<RoutingRule>` with no `<Redirect>` says what to
//! match and not what to do (`q-web-0003`, `q-web-0004`).
//!
//! What the site *does* at runtime — serving the index document, mapping an error to a page,
//! answering a routing rule with a 301 — is a second protocol face beside the REST API and is
//! deliberately absent. This file settles the document and stops.
//!
//! # Why the row exists before a backend does
//!
//! `PUT /{Bucket}?website` and `PUT /{Bucket}` differ by one query key, and `?website` is not an
//! exclusive predicate of the bucket creation.
//! `CreateBucket`'s own `QueryAbsent` list names `website`, which is what kept the write from
//! creating a bucket, so the absence of a row made the request unroutable rather than mis-served.
//!
//! The row lands at 241, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutBucketWebsite, PutBucketWebsiteInput, PutBucketWebsiteOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `website` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec::standard("PutBucketWebsite")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutBucketWebsite", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketWebsite", SigService::S3);

impl Operation for PutBucketWebsite {
    const NAME: &'static str = "PutBucketWebsite";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketWebsiteInput;
    type Output = PutBucketWebsiteOutput;
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

impl HasOperation for PutBucketWebsiteInput {
    type Op = PutBucketWebsite;
}
