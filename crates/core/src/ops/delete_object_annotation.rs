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

//! `DeleteObjectAnnotation`: permanent removal of one named object annotation.
//! Shares: nothing.
//!
//! Responsible for: the operation identity, required annotation name, security floor and
//! authorization contract needed to reserve `DELETE /{Bucket}/{Key+}?annotation` independently
//! of backend registration.
//! NOT responsible for: storing annotations, implementing the handler, or interpreting the
//! annotation value.
//! Upstream: the generated DeleteObjectAnnotation dto and codec. Downstream: routing and handler
//! registration.
//!
//! # Why an unhandled operation still needs this contract
//!
//! Without the generated route row, first-match sends the request to `DeleteObject`. That removes
//! the parent object instead of one annotation, and both operations answer 204 on success. Keeping
//! the route independent of registration makes an unsupported backend answer `NotImplemented`
//! for `DeleteObjectAnnotation` before any destructive handler runs.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{DeleteObjectAnnotation, DeleteObjectAnnotationInput, DeleteObjectAnnotationOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::{OperationSpec, ParamKind, RequiredParam};

/// What this operation requires once routing has selected the annotation subresource.
static SPEC: OperationSpec = OperationSpec::standard("DeleteObjectAnnotation")
    .required_params(&[RequiredParam {
        kind: ParamKind::Query,
        name: "annotationName",
        missing_error: ErrorCode::INVALID_REQUEST,
        message: "The annotationName query parameter is required and names the annotation to remove.",
    }])
    .auth(AuthRequirement::new("s3:DeleteObjectAnnotation", ResourceShape::Object))
    .build();

/// Annotation deletion uses the S3 signature service and carries no request body.
static FLOOR: OperationFloor = OperationFloor::builtin("DeleteObjectAnnotation", SigService::S3);

impl Operation for DeleteObjectAnnotation {
    const NAME: &'static str = "DeleteObjectAnnotation";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = DeleteObjectAnnotationInput;
    type Output = DeleteObjectAnnotationOutput;
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

impl HasOperation for DeleteObjectAnnotationInput {
    type Op = DeleteObjectAnnotation;
}
