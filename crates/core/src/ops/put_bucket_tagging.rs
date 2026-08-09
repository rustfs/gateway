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

//! `PutBucketTagging`: the whole tag set of one bucket, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutBucketTagging`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_bucket_tagging.rs` from `generated/ir/PutBucketTagging.json`; nor for
//! the body's integrity requirement, which the generated decoder enforces from the overlay's
//! `http_checksum_required` before a handler sees anything.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: tagging. The document this operation carries is validated under
//! [`crate::ops::shared::tagging`]'s bucket-scope rules — fifty tags where the object write
//! allows ten, every other rule identical — and [`TAG_SCOPE`] is where this file says so.
//!
//! # Why the row exists
//!
//! `PUT /{Bucket}?tagging` is the first `PUT` row on the bucket target, so before it existed the
//! request matched nothing and was refused as unroutable — a `501` where AWS answers the write.
//! There is no partial update: the document replaces the tag set entirely, and an empty
//! `<TagSet/>` clears it, which is why the write has no read-modify cycle to get wrong.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutBucketTagging, PutBucketTaggingInput, PutBucketTaggingOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::tagging::TagScope;
use crate::registry::OperationSpec;

/// The scope whose rules govern this write: a bucket's, fifty tags at the ceiling.
pub static TAG_SCOPE: TagScope = TagScope::Bucket;

/// What this operation requires of a request once routing has chosen it.
///
/// The `Tagging` document is a required *member*, refused by the decoder with `MalformedXML` when
/// the body is absent or wrongly rooted — not a required *parameter*, which is a check on the
/// request head. The integrity header is likewise the decoder's check, from the IR.
static SPEC: OperationSpec = OperationSpec {
    name: "PutBucketTagging",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutBucketTagging", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketTagging", SigService::S3);

impl Operation for PutBucketTagging {
    const NAME: &'static str = "PutBucketTagging";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketTaggingInput;
    type Output = PutBucketTaggingOutput;
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

impl HasOperation for PutBucketTaggingInput {
    type Op = PutBucketTagging;
}
