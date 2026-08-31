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

//! `ListDirectoryBuckets`: account-level listing through the S3 Express control endpoint.
//!
//! Responsible for: the operation identity, S3 Express signature floor and service authorization
//! contract needed to reserve directory-bucket listing independently of backend registration.
//! NOT responsible for: creating directory buckets, session credentials, or ordinary S3 bucket
//! listing.
//! Upstream: the generated operation DTO and codec. Downstream: routing and registration.
//! Shares: nothing.
//!
//! Without this operation contract, the generic `ListBuckets` row answers the request with the
//! wrong bucket namespace when a directory-bucket handler is absent.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{ListDirectoryBuckets, ListDirectoryBucketsInput, ListDirectoryBucketsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

static SPEC: OperationSpec = OperationSpec::standard("ListDirectoryBuckets")
    .required_params(&[])
    .auth(AuthRequirement::new("s3express:ListAllMyDirectoryBuckets", ResourceShape::Service))
    .build();

static FLOOR: OperationFloor = OperationFloor::builtin("ListDirectoryBuckets", SigService::S3Express);

impl Operation for ListDirectoryBuckets {
    const NAME: &'static str = "ListDirectoryBuckets";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = ListDirectoryBucketsInput;
    type Output = ListDirectoryBucketsOutput;
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

impl HasOperation for ListDirectoryBucketsInput {
    type Op = ListDirectoryBuckets;
}
