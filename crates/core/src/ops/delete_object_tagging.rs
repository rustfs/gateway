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

//! `DeleteObjectTagging`: the tag set removed, the object left alone.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `DeleteObjectTagging`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/delete_object_tagging.rs` from `generated/ir/DeleteObjectTagging.json`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: tagging. It has no body in either direction; what it clears is a set the shared
//! contract validated on the way in, and [`TAG_SCOPE`] says under which scope's rules.
//!
//! # Why the row exists before a backend does
//!
//! `DELETE /{Bucket}/{Key+}?tagging` was claimed by `DeleteObject`, whose selector pins nothing but
//! the method and the target — so a request to drop an object's labels **deleted the object**, and
//! answered the `204` that a successful untag looks exactly like. Of the three tagging rows this is
//! the one whose absence was unrecoverable. The row lands at 500, ahead of `DeleteObject` at 1000.
//!
//! The success status is `204` and, as for `DeleteObject`, it is unconditional: untagging an object
//! that carries no tags is a success.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{DeleteObjectTagging, DeleteObjectTaggingInput, DeleteObjectTaggingOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::tagging::TagScope;
use crate::registry::OperationSpec;

/// The scope whose rules govern the set this operation clears: an object's.
pub static TAG_SCOPE: TagScope = TagScope::Object;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec {
    name: "DeleteObjectTagging",
    success_status: 204,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:DeleteObjectTagging", ResourceShape::Object)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteObjectTagging", SigService::S3);

impl Operation for DeleteObjectTagging {
    const NAME: &'static str = "DeleteObjectTagging";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteObjectTaggingInput;
    type Output = DeleteObjectTaggingOutput;
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

impl HasOperation for DeleteObjectTaggingInput {
    type Op = DeleteObjectTagging;
}
