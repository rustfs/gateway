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

//! `PutBucketCors`: the whole CORS document of one bucket, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketCors`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_cors.rs` from `generated/ir/PutBucketCors.json`; nor for the
//! integrity requirement, which the generated decoder settles (`http_checksum_required` in the
//! overlay, not an `if` here); nor for the document's semantic rules — the closed method set, the
//! wildcard budget, the hundred-rule cap — which live once in
//! [`shared::cors`](super::shared::cors) so that no backend re-derives them.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: cors.
//!
//! # What the decoder refuses, and what it deliberately does not
//!
//! The decoder refuses a body that is not XML, a wrong root, and a document with no `CORSRule` —
//! those are `MalformedXML`. It does **not** refuse an element it does not know: the stored
//! configuration is re-parsed on every future release, and a decoder that got stricter would
//! silently turn off cross-origin access with only a browser-side symptom and one server-side
//! warn line (`q-cors-0007`). Semantic refusals — `PATCH` as a method, a second wildcard — are
//! [`shared::cors::validate_cors`](super::shared::cors::validate_cors)'s to make, after decoding, with the
//! specific codes AWS answers.
//!
//! There is no partial update: the document replaces the configuration entirely. Clearing it is
//! spelled `DeleteBucketCors`, not an empty document — an empty document is refused.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutBucketCors, PutBucketCorsInput, PutBucketCorsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// The integrity header is a required *claim*, refused by the generated decoder before the body
/// is read — not a required *parameter*, which is a check on the request head alone. Nothing on
/// the head is required beyond the routing discriminator.
static SPEC: OperationSpec = OperationSpec::standard("PutBucketCors")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutBucketCORS", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketCors", SigService::S3);

impl Operation for PutBucketCors {
    const NAME: &'static str = "PutBucketCors";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketCorsInput;
    type Output = PutBucketCorsOutput;
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

impl HasOperation for PutBucketCorsInput {
    type Op = PutBucketCors;
}
