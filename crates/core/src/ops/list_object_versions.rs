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

//! `ListObjectVersions`: every version and delete marker of a key range, selected by `?versions`.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `ListObjectVersions`, plus the [`HasOperation`] reverse mapping from its input type and the two
//! cursors this operation pages with.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/list_object_versions.rs` from `generated/ir/ListObjectVersions.json` and
//! mounted by `crate::codec`; nor the cursor rules themselves, which are `shared::pagination`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: pagination.
//!
//! # Why this operation has two cursors and why their order matters
//!
//! A key listing pages through keys, so one cursor is enough. A version listing pages through
//! (key, version) pairs, and a key may hold more versions than a page can carry — so resuming
//! needs both halves, and [`CURSORS`] records them in the order they compose: the key cursor
//! selects where in the key space to resume, the version cursor selects where within that key.
//!
//! The version cursor alone says nothing. There is no key for it to be relative to, so a request
//! carrying it without its partner is malformed rather than a page request, and answering it with
//! a page means answering a question the client did not ask. That rule is registered as a quirk in
//! `model/overlays/quirks/list.toml` rather than left to whoever writes the handler.
//!
//! The two cursors are also different kinds. The key cursor is a key the client may compose; the
//! version cursor is a server-minted identifier with no client-visible structure, and treating it
//! as anything else is how an identifier ends up joined onto a path.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{ListObjectVersions, ListObjectVersionsInput, ListObjectVersionsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::pagination::CursorSpec;
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `versions` is a routing discriminator rather than a required parameter: without it the request
/// is a key listing, a different operation, not a malformed one.
static SPEC: OperationSpec = OperationSpec {
    name: "ListObjectVersions",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:ListBucket", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("ListObjectVersions", SigService::S3);

/// The two cursors this operation pages with, in the order they compose.
///
/// The key cursor first, then the version cursor within it. The order is the contract: the second
/// is meaningless without the first, and a reader that takes them as an unordered pair has already
/// lost the rule that makes the second one legal.
pub static CURSORS: [CursorSpec; 2] = [CursorSpec::key("key-marker"), CursorSpec::opaque("version-id-marker")];

impl Operation for ListObjectVersions {
    const NAME: &'static str = "ListObjectVersions";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = ListObjectVersionsInput;
    type Output = ListObjectVersionsOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for ListObjectVersionsInput {
    type Op = ListObjectVersions;
}
