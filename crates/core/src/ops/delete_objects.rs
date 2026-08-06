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

//! `DeleteObjects`: many keys removed in one request, each with its own outcome.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `DeleteObjects`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/delete_objects.rs` from `generated/ir/DeleteObjects.json` and mounted by
//! `crate::codec`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: the checksum-header rule with every operation that accepts one.
//!
//! Two facts shape it. The request body is in the `httpChecksumRequired` set, so a request with
//! neither `Content-MD5` nor an `x-amz-checksum-*` header is a `400` before the handler runs —
//! `http_checksum_required` in the overlay, not an `if` here. And every key in the request must
//! appear exactly once in the result, as either a deleted entry or an error entry: a caller that
//! gets back fewer entries than it sent cannot tell which of its keys survived.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{DeleteObjects, DeleteObjectsInput, DeleteObjectsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec {
    name: "DeleteObjects",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:DeleteObject", ResourceShape::Object)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteObjects", SigService::S3);

impl Operation for DeleteObjects {
    const NAME: &'static str = "DeleteObjects";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteObjectsInput;
    type Output = DeleteObjectsOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for DeleteObjectsInput {
    type Op = DeleteObjects;
}
