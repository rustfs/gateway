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

//! `GetBucketLifecycleConfiguration`: the stored lifecycle document of one bucket, and nothing
//! about when its rules fire.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketLifecycleConfiguration`, plus the [`HasOperation`] reverse mapping from its input
//! type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_lifecycle_configuration.rs` from
//! `generated/ir/GetBucketLifecycleConfiguration.json`; nor for evaluation — expiring an object
//! or transitioning its storage class is the storage backend's scanner, never a route row here.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: lifecycle. The document's validation rules live in
//! [`shared::lifecycle`](super::shared::lifecycle), reached by backends through the facade; this
//! file only states the read's spec.
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?lifecycle` and `GET /{Bucket}` differ by one query key, and `?lifecycle` is not
//! an exclusive predicate of the listing fallback. With no row of its own the lifecycle read was
//! claimed by `ListObjects` and answered with a key listing — the
//! `GetBucketLifecycleConfiguration -> ListObjects` line of the route-coverage debt register. The
//! row lands at 370, in the bucket-subresource band after `?cors`, so an unhandled lifecycle read
//! is refused with `crate::dispatch::NOT_REGISTERED_MESSAGE` rather than answered by its
//! neighbour.
//!
//! A bucket that never had a lifecycle document is a **404 `NoSuchLifecycleConfiguration`**, the
//! operation-specific code — not a generic not-found, and not a `200` with an empty document.
//! That is what [`OperationSpec::not_configured_error`] carries for this operation and what
//! `q-lc-0001` records.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{
    GetBucketLifecycleConfiguration, GetBucketLifecycleConfigurationInput, GetBucketLifecycleConfigurationOutput,
};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `lifecycle` is a routing discriminator, not a required parameter: a `GET` on a bucket without
/// it is the key listing. Nothing else is required.
static SPEC: OperationSpec =
    OperationSpec::builder("GetBucketLifecycleConfiguration", 200, Some(ErrorCode::NO_SUCH_LIFECYCLE_CONFIGURATION))
        .required_params(&[])
        .auth(AuthRequirement::new("s3:GetLifecycleConfiguration", ResourceShape::Bucket))
        .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketLifecycleConfiguration", SigService::S3);

impl Operation for GetBucketLifecycleConfiguration {
    const NAME: &'static str = "GetBucketLifecycleConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketLifecycleConfigurationInput;
    type Output = GetBucketLifecycleConfigurationOutput;
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

impl HasOperation for GetBucketLifecycleConfigurationInput {
    type Op = GetBucketLifecycleConfiguration;
}
