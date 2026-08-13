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

//! `PutBucketLifecycleConfiguration`: the whole lifecycle document of one bucket, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketLifecycleConfiguration`, plus the [`HasOperation`] reverse mapping from its input
//! type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_lifecycle_configuration.rs` from
//! `generated/ir/PutBucketLifecycleConfiguration.json` — including the
//! `<LifecycleConfiguration>` request root the wire uses in place of the model's shape name
//! (`q-lc-0002`, `request_root` in the overlay, not an `if` here); nor for the integrity
//! requirement, which the generated decoder settles (`http_checksum_required` in the overlay);
//! nor for the document's semantic rules — the filter's one-child grammar, the expiration mutex,
//! the midnight rule, the thousand-rule cap — which live once in
//! [`shared::lifecycle`](super::shared::lifecycle) so that no backend re-derives them.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: lifecycle.
//!
//! # What the decoder refuses, and what it deliberately does not
//!
//! The decoder refuses a body that is not XML, a wrong root — the model's shape name
//! `BucketLifecycleConfiguration` included — and a document with no `Rule`. It does **not**
//! refuse an element it does not know, and it does not refuse a `Status` spelling outside the
//! documented pair: the stored configuration is re-parsed on every future release, and a decoder
//! that got stricter would silently turn lifecycle rules off with no symptom until objects stop
//! expiring (`q-lc-0006`, `q-lc-0014`). Semantic refusals — two filter conditions outside an
//! `<And>`, a `Date` that is not midnight, a duplicated id — are
//! [`shared::lifecycle::validate_lifecycle`](super::shared::lifecycle::validate_lifecycle)'s to
//! make, after decoding, with the specific codes AWS answers.
//!
//! There is no partial update: the document replaces the configuration entirely. Clearing it is
//! spelled `DeleteBucketLifecycle`, not an empty document — an empty document is refused.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{
    PutBucketLifecycleConfiguration, PutBucketLifecycleConfigurationInput, PutBucketLifecycleConfigurationOutput,
};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// The integrity header is a required *claim*, refused by the generated decoder before the body
/// is read — not a required *parameter*, which is a check on the request head alone. Nothing on
/// the head is required beyond the routing discriminator.
static SPEC: OperationSpec = OperationSpec::builder("PutBucketLifecycleConfiguration", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutLifecycleConfiguration", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketLifecycleConfiguration", SigService::S3);

impl Operation for PutBucketLifecycleConfiguration {
    const NAME: &'static str = "PutBucketLifecycleConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketLifecycleConfigurationInput;
    type Output = PutBucketLifecycleConfigurationOutput;
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

impl HasOperation for PutBucketLifecycleConfigurationInput {
    type Op = PutBucketLifecycleConfiguration;
}
