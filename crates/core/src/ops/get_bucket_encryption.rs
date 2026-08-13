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

//! `GetBucketEncryption`: the stored default-encryption document of one bucket, and nothing
//! about whether an object write honours it.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketEncryption`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_encryption.rs` from `generated/ir/GetBucketEncryption.json`;
//! nor for applying the configuration — encrypting an object with the bucket default, and every
//! SSE header an object operation carries, is task P6-06's runtime half, never a route row here.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: encryption. The document's validation rules live in
//! [`shared::encryption`](super::shared::encryption), reached by backends through the facade;
//! this file only states the read's spec.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?encryption` and `GET /{Bucket}` differ by one query key, and `?encryption` is
//! not an exclusive predicate of the listing fallback. With no row of its own the encryption
//! read was claimed by `ListObjects` and answered with a key listing — the
//! `GetBucketEncryption -> ListObjects` line of the route-coverage debt register. The row lands
//! at 391, packed after the `?lifecycle` band because the tens-aligned subresource slots are
//! spoken for, so an unhandled encryption read is refused with
//! `crate::dispatch::NOT_REGISTERED_MESSAGE` rather than answered by its neighbour.
//!
//! A bucket that never had an encryption document is a **404
//! `ServerSideEncryptionConfigurationNotFoundError`** — the longest code in the error table, and
//! the operation-specific one: not a generic not-found, and not a `200` with an empty document.
//! That is what [`OperationSpec::not_configured_error`] carries for this operation and what
//! `q-enc-0001` records.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{GetBucketEncryption, GetBucketEncryptionInput, GetBucketEncryptionOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `encryption` is a routing discriminator, not a required parameter: a `GET` on a bucket
/// without it is the key listing. Nothing else is required.
static SPEC: OperationSpec = OperationSpec::builder(
    "GetBucketEncryption",
    200,
    Some(ErrorCode::SERVER_SIDE_ENCRYPTION_CONFIGURATION_NOT_FOUND),
)
.required_params(&[])
.auth(AuthRequirement::new("s3:GetEncryptionConfiguration", ResourceShape::Bucket))
.build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketEncryption", SigService::S3);

impl Operation for GetBucketEncryption {
    const NAME: &'static str = "GetBucketEncryption";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketEncryptionInput;
    type Output = GetBucketEncryptionOutput;
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

impl HasOperation for GetBucketEncryptionInput {
    type Op = GetBucketEncryption;
}
