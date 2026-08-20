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

//! `ListObjects`: a page of keys, reached by `GET /{Bucket}` with nothing to discriminate it.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `ListObjects`, plus the [`HasOperation`] reverse mapping from its input type and the cursor this
//! operation pages with.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/list_objects.rs` from `generated/ir/ListObjects.json` and mounted by
//! `crate::codec`; nor the cursor rules themselves, which are `shared::pagination`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: pagination.
//!
//! # Why this is not the second version with a flag
//!
//! The two key listings differ in four places, and every one of them is a place an implementation
//! that shares a body gets wrong for one of the two. The cursor in is `marker` rather than
//! `continuation-token`; the cursor out is `NextMarker`, written only on a truncated page; there is
//! no `KeyCount` element at all; and owner information is unconditional here while the second
//! version writes it only when asked. Those four live in `model/overlays/ops/list.toml` as data —
//! `element_order`, `output_required`, `url_encoded_fields` — so the generated codec differs
//! without anybody having written a branch, and this file states the operation and nothing else.
//!
//! The cursor is a key, not a token: a client may compose one itself and the listing compares it
//! against the key space. That is the opposite of the second version's cursor and the reason
//! [`CURSOR`] records which of the two it is.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{ListObjects, ListObjectsInput, ListObjectsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::pagination::CursorSpec;
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// No required parameter, and that is the point: this operation is what a `GET` on a bucket means
/// when no other bucket route claimed it, so it sits last in the bucket band rather than asserting
/// anything about the query string.
static SPEC: OperationSpec = OperationSpec::standard("ListObjects")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:ListBucket", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("ListObjects", SigService::S3);

/// The cursor this operation pages with.
///
/// A key, not a token. The client is entitled to compose one, so nothing may assume it round-trips
/// from a previous response — and it still passes through the shared ceiling and byte check,
/// because it is echoed into the response body.
pub static CURSOR: CursorSpec = CursorSpec::key("marker");

impl Operation for ListObjects {
    const NAME: &'static str = "ListObjects";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = ListObjectsInput;
    type Output = ListObjectsOutput;
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

impl HasOperation for ListObjectsInput {
    type Op = ListObjects;
}
