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

//! `RenameObject`: one in-bucket object rename on the directory-bucket surface.
//!
//! Responsible for: the operation identity, security floor and authorization contract needed to
//! reserve `PUT /{Bucket}/{Key+}?renameObject` independently of backend registration.
//! NOT responsible for: implementing directory-bucket sessions, moving object state, or
//! interpreting the source/destination conditional headers.
//! Upstream: the generated RenameObject dto and codec. Downstream: routing and handler
//! registration.
//!
//! # Why an unhandled operation still needs this contract
//!
//! Without the generated route row, first-match sends the request to `PutObject`. A rename that
//! carries no object body then becomes an empty object write to the destination key. Keeping the
//! route independent of registration makes an unsupported backend answer `NotImplemented` for
//! `RenameObject` instead of mutating data as another operation.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{RenameObject, RenameObjectInput, RenameObjectOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires once routing has selected the directory-bucket rename surface.
static SPEC: OperationSpec = OperationSpec::standard("RenameObject")
    .required_params(&[])
    .auth(AuthRequirement::new("s3express:CreateSession", ResourceShape::Object))
    .build();

/// Rename requests use the S3 signature service and carry no request body.
static FLOOR: OperationFloor = OperationFloor::builtin("RenameObject", SigService::S3);

impl Operation for RenameObject {
    const NAME: &'static str = "RenameObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = RenameObjectInput;
    type Output = RenameObjectOutput;
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

impl HasOperation for RenameObjectInput {
    type Op = RenameObject;
}
