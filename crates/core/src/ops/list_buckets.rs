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

//! `ListBuckets`: the caller's buckets, reached by `GET /` with no bucket in the path at all.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `ListBuckets`, plus the [`HasOperation`] reverse mapping from its input type and the cursor this
//! operation pages with.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/list_buckets.rs` from `generated/ir/ListBuckets.json` and mounted by
//! `crate::codec`; nor the cursor rules themselves, which are `shared::pagination`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: pagination.
//!
//! # Why the authorisation names the service and not a bucket
//!
//! Every other listing in this family authorises against the bucket in the path. This one has no
//! bucket in the path: it asks what buckets exist, so the resource the policy is written against is
//! the account, and the action is spelled differently from the one the other three share. That is
//! also why it cannot be given a bucket-shaped resource "for consistency" — a policy written
//! against a bucket would either never match or match everything, and both are wrong in the
//! direction that grants.
//!
//! # Why the entry list is wrapped when every other one is flattened
//!
//! The three key and version listings repeat their entry element directly under the result root.
//! This one nests every entry inside a single enclosing element. There is no rule that derives
//! which of the two a listing uses, so it is recorded as a quirk in
//! `model/overlays/quirks/list.toml` and the generated encoder reads it from there.
//!
//! # Why the pagination parameters are newer than the operation
//!
//! This operation predates its own cursor by well over a decade, so a response carrying no cursor
//! is a complete response and not a truncated one. An implementation that treats a missing cursor
//! as "there is more" pages forever against every server that never gained the parameter.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{ListBuckets, ListBucketsInput, ListBucketsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::pagination::CursorSpec;
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec::standard("ListBuckets")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:ListAllMyBuckets", ResourceShape::Service))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("ListBuckets", SigService::S3);

/// The cursor this operation pages with.
///
/// Opaque: the value is whatever the server minted, and the only correct thing to do with it is
/// hand it back. Nothing here compares it against a bucket name.
pub static CURSOR: CursorSpec = CursorSpec::opaque("continuation-token");

impl Operation for ListBuckets {
    const NAME: &'static str = "ListBuckets";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = ListBucketsInput;
    type Output = ListBucketsOutput;
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

impl HasOperation for ListBucketsInput {
    type Op = ListBuckets;
}
