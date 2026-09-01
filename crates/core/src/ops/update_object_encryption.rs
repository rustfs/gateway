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

//! `UpdateObjectEncryption`: atomically changes one existing object's encryption envelope.
//!
//! Responsible for: the authorization floor and [`Operation`] identity for the object-scoped
//! encryption update selected by `?encryption`.
//! NOT responsible for: choosing an encryption variant, parsing its XML, or applying KMS policy;
//! the generated codec preserves the modeled structural union and the backend validates meaning.
//! Upstream: `rustfs-gateway-types` generated dto. Downstream: `crate::registry` and handlers.
//! Shares: nothing.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{UpdateObjectEncryption, UpdateObjectEncryptionInput, UpdateObjectEncryptionOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// The body is required XML, not a request-head parameter.
static SPEC: OperationSpec = OperationSpec::standard("UpdateObjectEncryption")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:UpdateObjectEncryption", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("UpdateObjectEncryption", SigService::S3);

impl Operation for UpdateObjectEncryption {
    const NAME: &'static str = "UpdateObjectEncryption";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = UpdateObjectEncryptionInput;
    type Output = UpdateObjectEncryptionOutput;
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

impl HasOperation for UpdateObjectEncryptionInput {
    type Op = UpdateObjectEncryption;
}
