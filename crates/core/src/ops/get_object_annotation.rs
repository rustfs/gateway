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

//! `GetObjectAnnotation`: retrieval of one named object annotation.
//! Shares: nothing.
//!
//! Responsible for: the operation identity, security floor and authorization contract needed to
//! reserve `GET /{Bucket}/{Key+}?annotation&annotationName=...` independently of backend
//! registration.
//! NOT responsible for: storing annotations, implementing the handler, or interpreting the
//! annotation payload.
//! Upstream: the generated GetObjectAnnotation dto and codec. Downstream: routing and handler
//! registration.
//!
//! # Why an unhandled operation still needs this contract
//!
//! Without the generated route row, first-match sends the request to `GetObject`. That returns
//! the parent object's bytes under a different authorization action. Keeping routing independent
//! of registration makes an unsupported backend answer `NotImplemented` before object data can
//! be disclosed.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{GetObjectAnnotation, GetObjectAnnotationInput, GetObjectAnnotationOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires once routing has selected a named annotation.
static SPEC: OperationSpec = OperationSpec::standard("GetObjectAnnotation")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetObjectAnnotation", ResourceShape::Object))
    .build();

/// Annotation retrieval uses the S3 signature service and streams its own payload.
static FLOOR: OperationFloor = OperationFloor::builtin("GetObjectAnnotation", SigService::S3);

impl Operation for GetObjectAnnotation {
    const NAME: &'static str = "GetObjectAnnotation";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetObjectAnnotationInput;
    type Output = GetObjectAnnotationOutput;
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

impl HasOperation for GetObjectAnnotationInput {
    type Op = GetObjectAnnotation;
}
