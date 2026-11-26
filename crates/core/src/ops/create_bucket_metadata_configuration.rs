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

//! `CreateBucketMetadataConfiguration`: creating a V2 S3 Metadata configuration for a bucket.
//!
//! Responsible for: the operation identity, security floor, and authorization contract needed to
//! reserve `POST /{Bucket}?metadataConfiguration` independently of backend registration.
//! NOT responsible for: provisioning metadata tables, updating table configurations, or deleting
//! objects.
//! Upstream: the generated operation DTO and codec. Downstream: routing and handler registration.
//! Shares: nothing.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{
    CreateBucketMetadataConfiguration, CreateBucketMetadataConfigurationInput, CreateBucketMetadataConfigurationOutput,
};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

static SPEC: OperationSpec = OperationSpec::standard("CreateBucketMetadataConfiguration")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:CreateBucketMetadataTableConfiguration", ResourceShape::Bucket))
    .build();

static FLOOR: OperationFloor = OperationFloor::builtin("CreateBucketMetadataConfiguration", SigService::S3);

impl Operation for CreateBucketMetadataConfiguration {
    const NAME: &'static str = "CreateBucketMetadataConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = CreateBucketMetadataConfigurationInput;
    type Output = CreateBucketMetadataConfigurationOutput;
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

impl HasOperation for CreateBucketMetadataConfigurationInput {
    type Op = CreateBucketMetadataConfiguration;
}
