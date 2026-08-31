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

//! `GetBucketInventoryConfiguration`: retrieval of one named inventory configuration.
//! Shares: nothing.
//!
//! Responsible for: the operation identity, security floor and authorization contract needed to
//! reserve an id-bearing inventory GET independently of backend registration.
//! NOT responsible for: storing inventory configurations, producing reports, or listing objects.
//! Upstream: the generated operation DTO and codec. Downstream: routing and handler registration.
//!
//! Without this operation contract, first-match routing exposes object keys through `ListObjects`
//! when the inventory handler is absent.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{
    GetBucketInventoryConfiguration, GetBucketInventoryConfigurationInput, GetBucketInventoryConfigurationOutput,
};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

static SPEC: OperationSpec = OperationSpec::standard("GetBucketInventoryConfiguration")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetInventoryConfiguration", ResourceShape::Bucket))
    .build();

static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketInventoryConfiguration", SigService::S3);

impl Operation for GetBucketInventoryConfiguration {
    const NAME: &'static str = "GetBucketInventoryConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketInventoryConfigurationInput;
    type Output = GetBucketInventoryConfigurationOutput;
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

impl HasOperation for GetBucketInventoryConfigurationInput {
    type Op = GetBucketInventoryConfiguration;
}
