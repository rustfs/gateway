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

//! `GetBucketOwnershipControls`: retrieval of a bucket's object-ownership policy.
//!
//! Responsible for: the operation identity, security floor and authorization contract needed to
//! reserve `GET /{Bucket}?ownershipControls` independently of backend registration.
//! NOT responsible for: evaluating ACLs, implementing the handler, or listing bucket objects.
//! Upstream: the generated GetBucketOwnershipControls dto and codec. Downstream: routing and
//! handler registration.
//!
//! # Why an unhandled operation still needs this contract
//!
//! Without its route row, first-match sends the request to `ListObjects`. An unsupported backend
//! would then expose object keys instead of returning an operation-specific `NotImplemented`.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetBucketOwnershipControls, GetBucketOwnershipControlsInput, GetBucketOwnershipControlsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires once routing has selected the ownership-controls subresource.
static SPEC: OperationSpec = OperationSpec::standard("GetBucketOwnershipControls")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetBucketOwnershipControls", ResourceShape::Bucket))
    .build();

/// Ownership-controls retrieval uses the S3 signature service.
static FLOOR: OperationFloor = OperationFloor::builtin("GetBucketOwnershipControls", SigService::S3);

impl Operation for GetBucketOwnershipControls {
    const NAME: &'static str = "GetBucketOwnershipControls";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetBucketOwnershipControlsInput;
    type Output = GetBucketOwnershipControlsOutput;
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

impl HasOperation for GetBucketOwnershipControlsInput {
    type Op = GetBucketOwnershipControls;
}
