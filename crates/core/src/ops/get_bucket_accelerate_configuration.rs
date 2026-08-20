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

//! `GetBucketAccelerateConfiguration`: the transfer-acceleration switch of one bucket, and nothing about
//! whether a transfer is ever accelerated.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetBucketAccelerateConfiguration`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_bucket_accelerate_configuration.rs` from
//! `generated/ir/GetBucketAccelerateConfiguration.json`; nor for
//! the stored document itself, which is a backend's to keep.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: bucket_config. The rules this subresource holds in common with its siblings live in
//! [`shared::bucket_config`](super::shared::bucket_config); this file states what is this operation's
//! alone.
//!
//! # The unconfigured answer is a 200, not a 404
//!
//! A bucket that never had an acceleration document answers `200` with an empty
//! `<AccelerateConfiguration/>` — no `<Status>` element at all — which is why
//! [`OperationSpec::not_configured_error`] is `None` here and `Some(..)` on the website, policy and
//! public-access reads. The distinction is not cosmetic: an SDK that receives a `404` where AWS
//! answers an empty document treats acceleration as an error rather than as off (`q-acc-0002`).
//!
//! # Why the row exists before a backend does
//!
//! `GET /{Bucket}?accelerate` and `GET /{Bucket}` differ by one query key, and `?accelerate` is not an
//! exclusive predicate of the key listing.
//! With no row of its own the read was claimed by `ListObjects` and answered with a page of keys
//! — the `GetBucketAccelerateConfiguration -> ListObjects` line of the route-coverage debt
//! register.
//!
//! The row lands at 200, in the bucket-configuration band this family opens at 200 — ahead of
//! the listings, because the table is first-match and `ListObjects` at 700 pins no query key, so
//! any bucket `GET` row behind it is unreachable.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{
    GetBucketAccelerateConfiguration, GetBucketAccelerateConfigurationInput, GetBucketAccelerateConfigurationOutput,
};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `accelerate` is a routing discriminator, not a required parameter: nothing on the request head is
/// required beyond it.
static SPEC: OperationSpec = OperationSpec::standard("GetBucketAccelerateConfiguration")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetAccelerateConfiguration", ResourceShape::Bucket))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketAccelerateConfiguration", SigService::S3);

impl Operation for GetBucketAccelerateConfiguration {
    const NAME: &'static str = "GetBucketAccelerateConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketAccelerateConfigurationInput;
    type Output = GetBucketAccelerateConfigurationOutput;
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

impl HasOperation for GetBucketAccelerateConfigurationInput {
    type Op = GetBucketAccelerateConfiguration;
}
