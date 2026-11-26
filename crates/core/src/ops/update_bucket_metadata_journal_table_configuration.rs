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

//! `UpdateBucketMetadataJournalTableConfiguration`: updating a bucket's metadata journal table.
//!
//! Responsible for: the operation identity, security floor, and authorization contract needed to
//! reserve `PUT /{Bucket}?metadataJournalTable` independently of bucket creation.
//! NOT responsible for: persisting metadata table settings, managing table backends, or creating
//! buckets.
//! Upstream: the generated operation DTO and codec. Downstream: routing and handler registration.
//! Shares: nothing.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{
    UpdateBucketMetadataJournalTableConfiguration, UpdateBucketMetadataJournalTableConfigurationInput,
    UpdateBucketMetadataJournalTableConfigurationOutput,
};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

static SPEC: OperationSpec = OperationSpec::standard("UpdateBucketMetadataJournalTableConfiguration")
    .required_params(&[])
    .auth(AuthRequirement::new(
        "s3:UpdateBucketMetadataJournalTableConfiguration",
        ResourceShape::Bucket,
    ))
    .build();

static FLOOR: OperationFloor = OperationFloor::builtin("UpdateBucketMetadataJournalTableConfiguration", SigService::S3);

impl Operation for UpdateBucketMetadataJournalTableConfiguration {
    const NAME: &'static str = "UpdateBucketMetadataJournalTableConfiguration";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = UpdateBucketMetadataJournalTableConfigurationInput;
    type Output = UpdateBucketMetadataJournalTableConfigurationOutput;
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

impl HasOperation for UpdateBucketMetadataJournalTableConfigurationInput {
    type Op = UpdateBucketMetadataJournalTableConfiguration;
}
