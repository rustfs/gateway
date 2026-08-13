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

//! `GetBucketVersioning`: the versioning state of one bucket, and nothing that creates a version.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketVersioning`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_versioning.rs` from `generated/ir/GetBucketVersioning.json`; nor for
//! the stored document itself, which is a backend's to keep.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_config. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_config`](super::shared::bucket_config); this file states what is this operation's
//! alone.
//!
//! # The unconfigured answer is a 200 with an empty document, and it must stay one
//!
//! A bucket that was never versioned answers `200` with `<VersioningConfiguration/>` carrying **no**
//! `<Status>` element — not `<Status></Status>`, not `<Status>Suspended</Status>`, and not a `404`
//! (`q-ver-0001`). The three are different states to a client: never-versioned buckets can still be
//! made versioned, suspended ones already have versions, and a `404` reads as "no such bucket".
//! [`OperationSpec::not_configured_error`] is `None` because of it.
//!
//! `MFADelete` is the model's member name and `MfaDelete` is its wire spelling, on **both**
//! directions — the pinned model gives the read and the write the same `xmlName`, so no
//! alternate-name rule is needed here (`q-ver-0004`).
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?versioning` and `GET /{Bucket}` differ by one query key, and `?versioning` is not an
//! exclusive predicate of the key listing.
//! With no row of its own the read was claimed by `ListObjects` and answered with a page of keys
//! — the `GetBucketVersioning -> ListObjects` line of the route-coverage debt register.
//!
//! The row lands at 235, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetBucketVersioning, GetBucketVersioningInput, GetBucketVersioningOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `versioning` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec::builder("GetBucketVersioning", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetBucketVersioning", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketVersioning", SigService::S3);

impl Operation for GetBucketVersioning {
    const NAME: &'static str = "GetBucketVersioning";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketVersioningInput;
    type Output = GetBucketVersioningOutput;
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

impl HasOperation for GetBucketVersioningInput {
    type Op = GetBucketVersioning;
}
