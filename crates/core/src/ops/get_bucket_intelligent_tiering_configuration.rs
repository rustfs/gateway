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

//! `GetBucketIntelligentTieringConfiguration`: retrieval of one named tiering policy.
//!
//! Responsible for: the operation identity, security floor and authorization contract needed to
//! reserve `GET /{Bucket}?intelligent-tiering&id=...` independently of backend registration.
//! NOT responsible for: applying storage tiers, implementing the handler, or listing objects.
//! Upstream: the generated operation DTO and codec. Downstream: routing and handler registration.
//!
//! # Why an unhandled operation still needs this contract
//!
//! Without this row, first-match sends the request to `ListObjects` and exposes object keys in
//! place of the requested configuration. A missing backend handler must instead fail by name.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{
    GetBucketIntelligentTieringConfiguration, GetBucketIntelligentTieringConfigurationInput,
    GetBucketIntelligentTieringConfigurationOutput,
};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires after the route selected an id-bearing tiering request.
static SPEC: OperationSpec = OperationSpec::standard("GetBucketIntelligentTieringConfiguration")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetIntelligentTieringConfiguration", ResourceShape::Bucket))
    .build();

/// Intelligent-tiering configuration retrieval uses the S3 signature service.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketIntelligentTieringConfiguration", SigService::S3);

impl Operation for GetBucketIntelligentTieringConfiguration {
    const NAME: &'static str = "GetBucketIntelligentTieringConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketIntelligentTieringConfigurationInput;
    type Output = GetBucketIntelligentTieringConfigurationOutput;
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

impl HasOperation for GetBucketIntelligentTieringConfigurationInput {
    type Op = GetBucketIntelligentTieringConfiguration;
}
