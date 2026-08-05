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

//! `GetBucketLocation`: the bucket's region, read from the bucket subresource `?location`.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketLocation`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: answering the request — that is a backend's `Handler<GetBucketLocation>` —
//! or the route row, which is generated.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: nothing. It is in no cross-operation cluster.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetBucketLocation, GetBucketLocationInput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec {
    name: "GetBucketLocation",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:GetBucketLocation", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged: the defaults, which is the point of the defaults.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketLocation", SigService::S3);

impl Operation for GetBucketLocation {
    const NAME: &'static str = "GetBucketLocation";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketLocationInput;
    type Output = rustfs_gateway_types::dto::GetBucketLocationOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for GetBucketLocationInput {
    type Op = GetBucketLocation;
}
