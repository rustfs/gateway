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

//! `GetObjectLockConfiguration`: the stored object-lock document of one bucket, and nothing
//! about whether any object is actually protected by it.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetObjectLockConfiguration`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_object_lock_configuration.rs` from
//! `generated/ir/GetObjectLockConfiguration.json`; nor for *enforcing* the configuration —
//! whether a delete or overwrite of a protected object is refused is the storage side's later
//! task, never a route row here.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: object_lock. The document's validation rules live in
//! [`shared::object_lock`](super::shared::object_lock), reached by backends through the facade;
//! this file only states the read's spec.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?object-lock` and `GET /{Bucket}` differ by one query key, and `?object-lock`
//! is not an exclusive predicate of the listing fallback. With no row of its own the lock read
//! was claimed by `ListObjects` and answered with a key listing — the
//! `GetObjectLockConfiguration -> ListObjects` line of the route-coverage debt register. The
//! row lands at 397, packed behind the `?encryption` band because the tens-aligned subresource
//! slots are spoken for, so an unhandled lock read is refused with
//! `crate::dispatch::NOT_REGISTERED_MESSAGE` rather than answered by its neighbour.
//!
//! A bucket that never enabled object lock is a **404
//! `ObjectLockConfigurationNotFoundError`** — the bucket-level code, distinct from the
//! object-level `NoSuchObjectLockConfiguration` the retention and legal-hold reads answer.
//! That is what [`OperationSpec::not_configured_error`] carries for this operation and what
//! `q-lock-0001` records.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{GetObjectLockConfiguration, GetObjectLockConfigurationInput, GetObjectLockConfigurationOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `object-lock` is a routing discriminator, not a required parameter: a `GET` on a bucket
/// without it is the key listing. Nothing else is required.
static SPEC: OperationSpec =
    OperationSpec::builder("GetObjectLockConfiguration", 200, Some(ErrorCode::OBJECT_LOCK_CONFIGURATION_NOT_FOUND))
        .required_params(&[])
        .auth(AuthRequirement::new("s3:GetBucketObjectLockConfiguration", ResourceShape::Bucket))
        .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetObjectLockConfiguration", SigService::S3);

impl Operation for GetObjectLockConfiguration {
    const NAME: &'static str = "GetObjectLockConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetObjectLockConfigurationInput;
    type Output = GetObjectLockConfigurationOutput;
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

impl HasOperation for GetObjectLockConfigurationInput {
    type Op = GetObjectLockConfiguration;
}
