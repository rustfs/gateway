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

//! `UploadPartCopy`: one part of an upload taken from a span of another object.
//!
//! Shares: copy_source. `x-amz-copy-source-range` and the copy-source conditional headers are
//! part of that one contract rather than modules of their own — `shared/precondition.rs` says so
//! from the other end — and the upload-id capability is shared with the rest of the multipart
//! family, which has no module under `shared/`.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `UploadPartCopy`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: parsing `x-amz-copy-source`, authorizing the source it names, or resolving
//! `x-amz-copy-source-range` — all three are
//! [`shared::copy_source`](super::shared::copy_source), shared with `CopyObject` — nor the wire
//! bindings, which are generated into `generated/codec/ops/upload_part_copy.rs` from
//! `generated/ir/UploadPartCopy.json` and mounted by `crate::codec`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! # Why this is the operation the advisories were written about
//!
//! `UploadPartCopy` is `CopyObject`'s source stage with a different destination: the destination is
//! an upload the caller already owns, so a check that looks only at the destination passes for
//! *every* source. GHSA-mx42 and GHSA-wfxj are that check. The contract this file uses is therefore
//! byte for byte the one `CopyObject` uses — one `parse`, one `authorize_source`, one `resolve` —
//! rather than a second copy of it with the source stage written slightly differently. Sharing the
//! module is what makes "the two operations authorize the same way" a fact about the `use` graph
//! instead of a claim in a review comment.
//!
//! # Why the routing discriminators are not required parameters
//!
//! `partNumber` and `uploadId` put this operation at precedence 400, ahead of `UploadPart` at 410,
//! and `x-amz-copy-source` is what separates the two. A `PUT` missing any of the three is a
//! different operation — `UploadPart`, or `CopyObject`, or `PutObject` — not a malformed one, so
//! none of them is a `RequiredParam`. The four-way overlap that creates is declared in
//! `crates/core/src/route/shadowing.rs`.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{UploadPartCopy, UploadPartCopyInput, UploadPartCopyOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::copy_source::CopySourceResources;
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// The action is the destination upload's, exactly as `CopyObject`'s is the destination object's.
/// The source's `s3:GetObject` is the second stage and is carried by the type state in
/// [`shared::copy_source`](super::shared::copy_source), not by this field — see the note on
/// `CopyObject`'s spec for why.
static SPEC: OperationSpec = OperationSpec::standard("UploadPartCopy")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged. The request carries no body: the bytes come from the
/// source object, so there is no payload mode to freeze beyond the empty one.
static FLOOR: OperationFloor = OperationFloor::builtin("UploadPartCopy", SigService::S3);

impl Operation for UploadPartCopy {
    const NAME: &'static str = "UploadPartCopy";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = UploadPartCopyInput;
    type Output = UploadPartCopyOutput;
    type DerivedResources = CopySourceResources;

    fn derive_resources(input: &Self::Input) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        CopySourceResources::parse(&input.copy_source)
    }

    fn derive_resources_under(
        input: &Self::Input,
        names: &rustfs_gateway_types::NamePolicy,
    ) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        CopySourceResources::parse_under(&input.copy_source, names)
    }

    fn seal_derived_input(input: &mut Self::Input) {
        input.copy_source.clear();
    }

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for UploadPartCopyInput {
    type Op = UploadPartCopy;
}
