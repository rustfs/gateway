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

//! `PutBucketVersioning`: the versioning state of one bucket, switched.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketVersioning`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_versioning.rs` from `generated/ir/PutBucketVersioning.json`; nor for
//! the integrity requirement, which the generated decoder settles
//! (`http_checksum_required` in the overlay); nor for the document's semantic rules, which
//! live once in the shared module so that no backend re-derives them.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_config. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_config`](super::shared::bucket_config); this file states what is this operation's
//! alone.
//!
//! # Why the decoder is lenient here and strict two files away
//!
//! RustFS parses stored bucket configurations fail-open: a document that stops parsing degrades to
//! "no configuration". For versioning that degradation is not a feature switching off quietly — it
//! is **version retention switching off quietly**, and objects overwritten in the interval cannot be
//! recovered afterwards. So an unknown element is skipped and stored rather than refused
//! (`q-ver-0002`), and only the closed `<Status>` value set is enforced, by
//! [`shared::bucket_config`](super::shared::bucket_config).
//!
//! The `x-amz-mfa` header is parsed into the input and passed through untouched. Whether the
//! device and code it carries actually authorise the change is the backend's question; the header
//! value is never echoed, logged, or repeated in a refusal.
//!
//! # Why the row exists before a backend does
//!
//! `PUT /{Bucket}?versioning` and `PUT /{Bucket}` differ by one query key, and `?versioning` is not an
//! exclusive predicate of the bucket creation.
//! `CreateBucket`'s own `QueryAbsent` list names `versioning`, which is what kept the write from
//! creating a bucket, so the absence of a row made the request unroutable rather than mis-served.
//!
//! The row lands at 236, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutBucketVersioning, PutBucketVersioningInput, PutBucketVersioningOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `versioning` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec::standard("PutBucketVersioning")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutBucketVersioning", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketVersioning", SigService::S3);

impl Operation for PutBucketVersioning {
    const NAME: &'static str = "PutBucketVersioning";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketVersioningInput;
    type Output = PutBucketVersioningOutput;
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

impl HasOperation for PutBucketVersioningInput {
    type Op = PutBucketVersioning;
}
