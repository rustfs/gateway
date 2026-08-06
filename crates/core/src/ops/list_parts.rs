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

//! `ListParts`: the parts of one upload, a page at a time.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `ListParts`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into `generated/codec/ops/list_parts.rs`
//! from `generated/ir/ListParts.json`; nor for the pagination module itself, which is `P5-05`'s —
//! this file declares the wire contract that module has to satisfy.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: the cursor-and-truncation contract with the listing family; the upload-id capability
//! with the rest of the multipart family.
//!
//! Two properties the cases pin, both recorded as `q-mpu-marker-0040`: `NextPartNumberMarker` is
//! usable verbatim as the next request's `part-number-marker`, and `MaxParts` echoes what the
//! caller asked for rather than what the server clamped it to. A listing whose echo is the
//! clamped value silently rewrites the caller's request in the caller's own record of it.
//!
//! `Part` repeats directly under the result root with no wrapper (`q-mpu-part-0031`); a wrapped
//! rendering is a page every SDK reads as empty.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{ListParts, ListPartsInput, ListPartsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `uploadId` is a routing discriminator, not a required parameter: a `GET` on an object key
/// without it is `GetObject`.
static SPEC: OperationSpec = OperationSpec {
    name: "ListParts",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:ListMultipartUploadParts", ResourceShape::Object)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("ListParts", SigService::S3);

impl Operation for ListParts {
    const NAME: &'static str = "ListParts";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = ListPartsInput;
    type Output = ListPartsOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for ListPartsInput {
    type Op = ListParts;
}
