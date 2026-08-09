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

//! `GetObjectTagging`: the tag set of one object, and nothing else about it.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetObjectTagging`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_object_tagging.rs` from `generated/ir/GetObjectTagging.json`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: tagging. The value this operation reads back is whatever a tagging write validated
//! under [`crate::ops::shared::tagging`]'s object-scope rules, and [`TAG_SCOPE`] is where this
//! file says which scope that is.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}/{Key+}?tagging` and `GET /{Bucket}/{Key+}` differ by one query key, and
//! `?tagging` is not an exclusive predicate of `GetObject`. With no row of its own the tagging read
//! was claimed by `GetObject` and answered with the **object's bytes** — the same disclosure the
//! attributes read had, under a different subresource. The row lands at precedence 480, ahead of
//! the object band, so an unhandled tagging read is refused with
//! `crate::dispatch::NOT_REGISTERED_MESSAGE` rather than answered by its neighbour.
//!
//! An object with no tags is a `200` carrying an empty `TagSet`, not a `404`: `NoSuchTagSet` is the
//! bucket-level code and has no object-level twin.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetObjectTagging, GetObjectTaggingInput, GetObjectTaggingOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::tagging::TagScope;
use crate::registry::OperationSpec;

/// The scope whose rules govern this tag set: an object's, ten tags at the ceiling.
///
/// Declared here rather than assumed at the call site, so the shared contract's member list and
/// the operation agree in a form a guard can check — the same declarative shape the listing
/// operations use for their cursors.
pub static TAG_SCOPE: TagScope = TagScope::Object;

/// What this operation requires of a request once routing has chosen it.
///
/// `tagging` is a routing discriminator, not a required parameter: a `GET` on an object key without
/// it is `GetObject`. Nothing else is required — `versionId` selects a version and its absence
/// selects the current one.
static SPEC: OperationSpec = OperationSpec {
    name: "GetObjectTagging",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:GetObjectTagging", ResourceShape::Object)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetObjectTagging", SigService::S3);

impl Operation for GetObjectTagging {
    const NAME: &'static str = "GetObjectTagging";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetObjectTaggingInput;
    type Output = GetObjectTaggingOutput;
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

impl HasOperation for GetObjectTaggingInput {
    type Op = GetObjectTagging;
}
