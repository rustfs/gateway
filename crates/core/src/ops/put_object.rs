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

//! `PutObject`: one object written in one request.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `PutObject`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the body — framing, `aws-chunked` decoding and checksum validation are
//! settled in `rustfs-gateway-http` before a handler sees anything.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: precondition and checksum handling with the Conditional and Checksum clusters, once
//! those modules exist.
//!
//! `PutObject` is the operation that makes the POST-policy shape interesting: a browser upload
//! reaches it through a signed form rather than a header signature. The floor here stays
//! header-only, because widening it is a decision about a deployment, and the default that is
//! never wrong is the narrow one.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{PutObject, PutObjectInput, PutObjectOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec {
    name: "PutObject",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutObject", ResourceShape::Object)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("PutObject", SigService::S3);

impl Operation for PutObject {
    const NAME: &'static str = "PutObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutObjectInput;
    type Output = PutObjectOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for PutObjectInput {
    type Op = PutObject;
}
