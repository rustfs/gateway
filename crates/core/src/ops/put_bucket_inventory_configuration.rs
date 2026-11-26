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

//! `PutBucketInventoryConfiguration`: storing one named inventory configuration.
//!
//! Responsible for: the operation identity, required `id` parameter, security floor, and
//! authorization contract needed to reserve `PUT /{Bucket}?inventory` independently of bucket
//! creation.
//! NOT responsible for: persisting inventory rules, generating inventory exports, or creating
//! buckets.
//! Upstream: the generated operation DTO and codec. Downstream: routing and handler registration.
//! Shares: nothing.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{
    PutBucketInventoryConfiguration, PutBucketInventoryConfigurationInput, PutBucketInventoryConfigurationOutput,
};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::{OperationSpec, ParamKind, RequiredParam};

static SPEC: OperationSpec = OperationSpec::standard("PutBucketInventoryConfiguration")
    .required_params(&[RequiredParam {
        kind: ParamKind::Query,
        name: "id",
        missing_error: ErrorCode::INVALID_ARGUMENT,
        message: "The required parameter 'id' is missing",
    }])
    .auth(AuthRequirement::new("s3:PutInventoryConfiguration", ResourceShape::Bucket))
    .build();

static FLOOR: OperationFloor = OperationFloor::builtin("PutBucketInventoryConfiguration", SigService::S3);

impl Operation for PutBucketInventoryConfiguration {
    const NAME: &'static str = "PutBucketInventoryConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutBucketInventoryConfigurationInput;
    type Output = PutBucketInventoryConfigurationOutput;
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

impl HasOperation for PutBucketInventoryConfigurationInput {
    type Op = PutBucketInventoryConfiguration;
}
