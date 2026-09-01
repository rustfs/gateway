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

//! `PutObjectAnnotation`: storage of one named object annotation payload.
//! Shares: nothing.
//!
//! Responsible for: the operation identity, required annotation name, security floor and
//! authorization contract needed to reserve `PUT /{Bucket}/{Key+}?annotation` independently of
//! parent-object replacement.
//! NOT responsible for: persisting annotations, validating annotation text, or buffering the
//! required streaming payload.
//! Upstream: the generated PutObjectAnnotation dto and codec. Downstream: routing and handler
//! registration.
//!
//! # Why an unhandled operation still needs this contract
//!
//! Without this generated route, first-match sends the annotation payload to `PutObject` and
//! replaces the parent object's bytes. Keeping routing independent of registration makes an
//! unsupported backend answer `NotImplemented` before any object write can begin.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{PutObjectAnnotation, PutObjectAnnotationInput, PutObjectAnnotationOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::{OperationSpec, ParamKind, RequiredParam};

/// What this operation requires once routing has selected the annotation subresource.
static SPEC: OperationSpec = OperationSpec::standard("PutObjectAnnotation")
    .required_params(&[RequiredParam {
        kind: ParamKind::Query,
        name: "annotationName",
        missing_error: ErrorCode::INVALID_REQUEST,
        message: "The annotationName query parameter is required and names the annotation to store.",
    }])
    .auth(AuthRequirement::new("s3:PutObjectAnnotation", ResourceShape::Object))
    .build();

/// Annotation storage uses the S3 signature service and owns a live request payload.
static FLOOR: OperationFloor = OperationFloor::builtin("PutObjectAnnotation", SigService::S3);

impl Operation for PutObjectAnnotation {
    const NAME: &'static str = "PutObjectAnnotation";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PutObjectAnnotationInput;
    type Output = PutObjectAnnotationOutput;
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

impl HasOperation for PutObjectAnnotationInput {
    type Op = PutObjectAnnotation;
}
