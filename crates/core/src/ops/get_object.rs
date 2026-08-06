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

//! `GetObject`: one object read, with the response headers the request may overwrite.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetObject`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/get_object.rs` from `generated/ir/GetObject.json` and mounted by
//! `crate::codec`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: object attributes, user metadata, checksum and the `response-*` overrides with the object family.
//!
//! The `response-*` query parameters are applied by the generated encoder as a final pass over
//! the header set, from `OperationCodec::RESPONSE_OVERRIDES` — so an override wins over whatever
//! the object's own attributes wrote, without the ordering being something a reader has to work
//! out. `x-amz-storage-class` is suppressed for the default class, which is the exact opposite of
//! the listing body element; both are `omit_when` data in `model/overlays/ops/object.toml`, and
//! neither is a branch anybody wrote.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetObject, GetObjectInput, GetObjectOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec {
    name: "GetObject",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:GetObject", ResourceShape::Object)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetObject", SigService::S3);

impl Operation for GetObject {
    const NAME: &'static str = "GetObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetObjectInput;
    type Output = GetObjectOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for GetObjectInput {
    type Op = GetObject;
}
