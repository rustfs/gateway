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

//! `DeleteBucketTagging`: the tag set removed, the bucket left alone.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `DeleteBucketTagging`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/delete_bucket_tagging.rs` from `generated/ir/DeleteBucketTagging.json`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: tagging. It has no body in either direction; what it clears is a set the shared
//! contract validated on the way in, and [`TAG_SCOPE`] says under which scope's rules.
//!
//! # The 204 is unconditional
//!
//! The model answers `204`, and — like both object-scope deletes — it is unconditional: untagging
//! a bucket that carries no tags is a success, not the `NoSuchTagSet` the *read* answers on the
//! same state. The asymmetry is the protocol's: a delete states a desired end state and that
//! state holds, while a read asks for a document that is not there. The row lands at 330; it is
//! the first `DELETE` row on the bucket target, so before it existed the request was refused as
//! unroutable rather than claimed by a neighbour.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{DeleteBucketTagging, DeleteBucketTaggingInput, DeleteBucketTaggingOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::tagging::TagScope;
use crate::registry::OperationSpec;

/// The scope whose rules govern the set this operation clears: a bucket's.
pub static TAG_SCOPE: TagScope = TagScope::Bucket;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec {
    name: "DeleteBucketTagging",
    success_status: 204,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:DeleteBucketTagging", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteBucketTagging", SigService::S3);

impl Operation for DeleteBucketTagging {
    const NAME: &'static str = "DeleteBucketTagging";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteBucketTaggingInput;
    type Output = DeleteBucketTaggingOutput;
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

impl HasOperation for DeleteBucketTaggingInput {
    type Op = DeleteBucketTagging;
}
