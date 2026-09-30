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

//! `GetObjectAttributes`: an object's metadata, without the object.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `GetObjectAttributes`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/get_object_attributes.rs` from `generated/ir/GetObjectAttributes.json`;
//! nor for answering the request — backends opt in by registering a handler, and the honest answer
//! when they do not is `crate::dispatch::NOT_REGISTERED_MESSAGE`, not another operation's body.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: nothing. The entity tag it writes is the multipart family's composite value, but the
//! rendering is carried by the field's type (`ETag:XmlBare`), not by a shared helper.
//!
//! # Why this module exists before a handler does
//!
//! `GET /{Bucket}/{Key+}?attributes` and `GET /{Bucket}/{Key+}` differ by one query key.
//! `?attributes` is not an exclusive predicate of `GetObject`, so with no row of its own the
//! attributes request is claimed by `GetObject` and answered with the object's **bytes** — a
//! request whose meaning depends on which handlers happen to be registered. Routing is settled by
//! the protocol, so the row lands with the operation, ahead of the object band at precedence 470,
//! and an unhandled attributes request is refused rather than answered by its neighbour.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{GetObjectAttributes, GetObjectAttributesInput, GetObjectAttributesOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::{OperationSpec, ParamKind, RequiredParam};

/// A request naming one version is asked `s3:GetObjectVersion` alone: AWS requires the version
/// action when `versionId` is specified
/// (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html>), and
/// legacy RustFS asks it (`rustfs/src/storage/access.rs:2733-2735` on rustfs/rustfs `d60dfbb826`).
static VERSION_AUTH: AuthRequirement = AuthRequirement::new("s3:GetObjectVersion", ResourceShape::Object);

/// What this operation requires of a request once routing has chosen it.
///
/// `attributes` is a routing discriminator, not a required parameter: a `GET` on an object key
/// without it is `GetObject`. `x-amz-object-attributes` is the opposite — the model marks it
/// required, it selects which of the five attribute groups the response carries, and a request
/// that omits it names no attributes at all. It is checked here rather than in the decoder so the
/// refusal happens on the request head, before a body is read.
static SPEC: OperationSpec = OperationSpec::standard("GetObjectAttributes")
    .required_params(&[RequiredParam {
        kind: ParamKind::Header,
        name: "x-amz-object-attributes",
        missing_error: ErrorCode::INVALID_REQUEST,
        message: "The x-amz-object-attributes header is required and names which attribute groups the response carries.",
    }])
    .auth(AuthRequirement::new("s3:GetObject", ResourceShape::Object).with_version_requirement(&VERSION_AUTH))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("GetObjectAttributes", SigService::S3);

impl Operation for GetObjectAttributes {
    const NAME: &'static str = "GetObjectAttributes";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = GetObjectAttributesInput;
    type Output = GetObjectAttributesOutput;
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

impl HasOperation for GetObjectAttributesInput {
    type Op = GetObjectAttributes;
}
