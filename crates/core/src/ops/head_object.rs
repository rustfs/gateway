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

//! `HeadObject`: the header set of a `GetObject`, and never a body.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `HeadObject`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, which are generated into
//! `generated/codec/ops/head_object.rs` from `generated/ir/HeadObject.json` and mounted by
//! `crate::codec`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: its entire header contract with `GetObject`, by derivation rather than by copy.
//!
//! The header set is not written twice. The overlay declares `head_mirrors = "GetObject"`, so the
//! two encoders are generated from one binding table; upstream lost the entity tag on this
//! response precisely because its two tables were hand-written and only one of them was fixed.
//!
//! The absent body is not this file's rule either: `EncodedResponse::enforce_http_invariants` drops
//! the body of every `HEAD` response, on every status, once — RFC 9110 says so about HTTP, not
//! about `HeadObject`.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{HeadObject, HeadObjectInput, HeadObjectOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec {
    name: "HeadObject",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:GetObject", ResourceShape::Object)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("HeadObject", SigService::S3);

impl Operation for HeadObject {
    const NAME: &'static str = "HeadObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = HeadObjectInput;
    type Output = HeadObjectOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for HeadObjectInput {
    type Op = HeadObject;
}
