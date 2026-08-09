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

//! `DeleteBucketCors`: the CORS document removed, the bucket left alone.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `DeleteBucketCors`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/delete_bucket_cors.rs` from `generated/ir/DeleteBucketCors.json`. It has
//! no body in either direction — the model's output is `smithy.api#Unit`.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: cors. The family's document rules live in [`shared::cors`](super::shared::cors); this
//! operation carries no document, and is listed so a change to the family's contract knows all
//! three members.
//!
//! # Why the row exists before a backend does
//!
//! `DELETE /{Bucket}?cors` had no fallback row: unlike the tagging band, whose absence made a
//! neighbour destroy data, the absence here made the request unroutable. The row lands at 330 so
//! the request is refused by name — `crate::dispatch::NOT_REGISTERED_MESSAGE` naming
//! `DeleteBucketCors` — until a backend registers a handler.
//!
//! The success status is `204` and it is unconditional: removing the CORS configuration of a
//! bucket that has none is a success, not a `404` (`q-cors-0006`). The idempotency matters to
//! callers that tear configuration down without reading it first, and a `404` here would make
//! "already gone" indistinguishable from "wrong bucket" — which is what `NoSuchBucket` is for.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{DeleteBucketCors, DeleteBucketCorsInput, DeleteBucketCorsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
static SPEC: OperationSpec = OperationSpec {
    name: "DeleteBucketCors",
    success_status: 204,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:PutBucketCORS", ResourceShape::Bucket)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteBucketCors", SigService::S3);

impl Operation for DeleteBucketCors {
    const NAME: &'static str = "DeleteBucketCors";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteBucketCorsInput;
    type Output = DeleteBucketCorsOutput;
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

impl HasOperation for DeleteBucketCorsInput {
    type Op = DeleteBucketCors;
}
