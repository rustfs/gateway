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

//! `GetBucketCors`: the stored CORS document of one bucket, and nothing about how it is matched.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketCors`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_cors.rs` from `generated/ir/GetBucketCors.json`; nor for
//! preflight — OPTIONS handling and `Access-Control-*` injection are a separately designed
//! pre-auth stage, not a route row here.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: cors. The document's validation rules live in
//! [`shared::cors`](super::shared::cors), reached by backends through the facade; this file only
//! states the read's spec.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?cors` and `GET /{Bucket}` differ by one query key, and `?cors` is not an
//! exclusive predicate of the listing fallback. With no row of its own the CORS read was claimed
//! by `ListObjects` and answered with a key listing — the `GetBucketCors -> ListObjects` line of
//! the route-coverage debt register. The row lands at 310, directly after `?location`, so an
//! unhandled CORS read is refused with `crate::dispatch::NOT_REGISTERED_MESSAGE` rather than
//! answered by its neighbour.
//!
//! A bucket that never had a CORS document is a **404 `NoSuchCORSConfiguration`**, the
//! operation-specific code — not a generic not-found, and not a `200` with an empty document.
//! That is what [`OperationSpec::not_configured_error`] carries for this operation and what
//! `q-cors-0001` records.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{GetBucketCors, GetBucketCorsInput, GetBucketCorsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `cors` is a routing discriminator, not a required parameter: a `GET` on a bucket without it is
/// the key listing. Nothing else is required.
static SPEC: OperationSpec = OperationSpec {
    name: "GetBucketCors",
    success_status: 200,
    required_params: &[],
    not_configured_error: Some(ErrorCode::NO_SUCH_CORS_CONFIGURATION),
    auth: Some(AuthRequirement::new("s3:GetBucketCORS", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketCors", SigService::S3);

impl Operation for GetBucketCors {
    const NAME: &'static str = "GetBucketCors";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketCorsInput;
    type Output = GetBucketCorsOutput;

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for GetBucketCorsInput {
    type Op = GetBucketCors;
}
