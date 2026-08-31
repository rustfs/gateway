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

//! `ListObjectAnnotations`: paginated metadata for annotations attached to one object.
//!
//! Responsible for: the operation identity, security floor and authorization contract needed to
//! reserve `GET /{Bucket}/{Key+}?annotation` without `annotationName` independently of backend
//! registration.
//! NOT responsible for: listing stored annotations, pagination implementation, or interpreting
//! annotation payloads.
//! Upstream: the generated ListObjectAnnotations dto and codec. Downstream: routing and handler
//! registration.
//!
//! # Why an unhandled operation still needs this contract
//!
//! Without the generated route row, first-match sends the request to `GetObject`. That returns
//! the parent object's bytes instead of annotation metadata. Keeping routing independent of
//! registration makes an unsupported backend answer `NotImplemented` before object data can be
//! disclosed.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{ListObjectAnnotations, ListObjectAnnotationsInput, ListObjectAnnotationsOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires once routing has selected the annotation listing.
static SPEC: OperationSpec = OperationSpec::standard("ListObjectAnnotations")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:ListObjectAnnotations", ResourceShape::Object))
    .build();

/// Annotation listing uses the S3 signature service and returns an XML document.
static FLOOR: OperationFloor = OperationFloor::builtin("ListObjectAnnotations", SigService::S3);

impl Operation for ListObjectAnnotations {
    const NAME: &'static str = "ListObjectAnnotations";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = ListObjectAnnotationsInput;
    type Output = ListObjectAnnotationsOutput;
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

impl HasOperation for ListObjectAnnotationsInput {
    type Op = ListObjectAnnotations;
}
