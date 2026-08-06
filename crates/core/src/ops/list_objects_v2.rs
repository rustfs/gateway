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

//! `ListObjectsV2`: a page of keys, selected by `?list-type=2`.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `ListObjectsV2`, plus the [`HasOperation`] reverse mapping from its input type and the two
//! cursors this operation pages with.
//! NOT responsible for: pagination itself, delimiter rollup or the continuation-token codec, which
//! belong to the List cluster's shared module, `super::shared::pagination`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: pagination.
//!
//! The authorisation action is `s3:ListBucket`, not `s3:ListObjectsV2`. The IAM action name and
//! the API name differ here, which is the reason the action is declared per operation instead of
//! derived from the operation name.
//!
//! # Why two cursors, and which one wins
//!
//! `continuation-token` resumes a page this server minted; `start-after` is a key the client chose,
//! and it is only meaningful on a first page. A request carrying both asks to resume *and* to
//! begin, so the resumption wins and the starting key is ignored — the alternative silently skips
//! entries the client has not seen. [`CURSORS`] lists the two in that precedence order, and their
//! kinds record why they cannot be treated alike.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{ListObjectsV2, ListObjectsV2Input, ListObjectsV2Output};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::ops::shared::pagination::CursorSpec;
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `list-type=2` is a routing discriminator, not a required parameter: without it the request is
/// `ListObjects`, a different operation, rather than a malformed one.
static SPEC: OperationSpec = OperationSpec {
    name: "ListObjectsV2",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:ListBucket", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("ListObjectsV2", SigService::S3);

/// The cursors this operation pages with, in the order that decides which one applies.
///
/// The resumption cursor is opaque and comes first; the starting key is a key the client composed
/// and applies only when there is nothing to resume.
pub static CURSORS: [CursorSpec; 2] = [CursorSpec::opaque("continuation-token"), CursorSpec::key("start-after")];

impl Operation for ListObjectsV2 {
    const NAME: &'static str = "ListObjectsV2";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = ListObjectsV2Input;
    type Output = ListObjectsV2Output;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for ListObjectsV2Input {
    type Op = ListObjectsV2;
}
