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

//! `PutObjectTagging`: the whole tag set of one object, replaced.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutObjectTagging`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/put_object_tagging.rs` from `generated/ir/PutObjectTagging.json`; nor for
//! the body's integrity check, which `rustfs-gateway-http` settles before a handler sees anything.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: tagging. The document this operation carries is validated under
//! [`crate::ops::shared::tagging`]'s object-scope rules — the same validator the packed
//! `x-amz-tagging` header goes through — and [`TAG_SCOPE`] is where this file says which scope
//! applies. It carries no precondition header — a tagging write is not conditional.
//!
//! # Why the row exists before a backend does
//!
//! This is the sharpest of the three tagging rows. `PutObject`'s selector is `Method("PUT")` and
//! `Target("Object")` and nothing else, so with no `?tagging` row of its own a tagging write was
//! claimed by `PutObject` — which **stored the `<Tagging>` document as the object's body**, and
//! answered `200`. A caller relabelling an object destroyed it instead, with no signal at all. The
//! row lands at 490, ahead of `CopyObject` at 790 and `PutObject` at 800; the copy edge matters too,
//! since a tagging write that also carried `x-amz-copy-source` would otherwise be served as a copy.
//!
//! There is no partial update: the document replaces the tag set entirely, so an empty `TagSet`
//! clears it.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutObjectTagging, PutObjectTaggingInput, PutObjectTaggingOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::tagging::TagScope;
use crate::registry::OperationSpec;

/// The scope whose rules govern this write: an object's, ten tags at the ceiling.
pub static TAG_SCOPE: TagScope = TagScope::Object;

/// A request naming one version is asked `s3:PutObjectVersionTagging`, as AWS requires when
/// `versionId` is specified
/// (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html>).
/// Legacy RustFS asks `s3:PutObjectTagging` instead (`rustfs/src/storage/access.rs:3260` on
/// rustfs/rustfs `d60dfbb826`); the RustFS profile keeps that
/// (`ServiceBuilder::authorize_versions_as_legacy_rustfs`).
static VERSION_AUTH: AuthRequirement = AuthRequirement::new("s3:PutObjectVersionTagging", ResourceShape::Object);

/// What this operation requires of a request once routing has chosen it.
///
/// The `Tagging` document is a required *member*, refused by the decoder with `MalformedXML` when
/// the body is absent or wrongly rooted — not a required *parameter*, which is a check on the
/// request head. Nothing on the head is required beyond the routing discriminator.
static SPEC: OperationSpec = OperationSpec::standard("PutObjectTagging")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObjectTagging", ResourceShape::Object).with_version_requirement(&VERSION_AUTH))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutObjectTagging", SigService::S3);

impl Operation for PutObjectTagging {
    const NAME: &'static str = "PutObjectTagging";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutObjectTaggingInput;
    type Output = PutObjectTaggingOutput;
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

impl HasOperation for PutObjectTaggingInput {
    type Op = PutObjectTagging;
}
