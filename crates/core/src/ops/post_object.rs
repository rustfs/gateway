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

//! `PostObject`: one browser form upload written as one object.
//! Shares: nothing.
//!
//! Responsible for: the standard operation identity, security floor, authorization shape, and
//! the hand-authored codec needed because the Smithy S3 model omits this documented operation.
//! NOT responsible for: multipart framing or POST-policy verification; the gateway must produce
//! an accepted [`PostObjectInput`] before this codec can decode.
//! Upstream: the authenticated form pipeline and `rustfs-gateway-types`.
//! Downstream: `crate::registry` and backend handlers.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::EtagRender;
use rustfs_gateway_types::dto::{PostObject, PostObjectInput, PostObjectOutput};

use crate::codec::response::{EncodedResponse, status_code};
use crate::codec::{CodecError, MetaView, OperationCodec, RequestBody, RequestBodyMode};
use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires after routing selected the bucket form surface.
static SPEC: OperationSpec = OperationSpec::standard("PostObject")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
    .build();

/// Browser policies and anonymous public-write forms are explicit opt-ins for this operation.
static FLOOR: OperationFloor = OperationFloor::builtin("PostObject", SigService::S3)
    .allow_post_policy()
    .allow_anonymous_after_listing_in_the_posture_report();

impl Operation for PostObject {
    const NAME: &'static str = "PostObject";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = PostObjectInput;
    type Output = PostObjectOutput;
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

impl HasOperation for PostObjectInput {
    type Op = PostObject;
}

impl OperationCodec for PostObject {
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::PostObject;

    fn decode(_request: &MetaView<'_>, body: RequestBody) -> Result<Self::Input, CodecError> {
        body.into_post_object()
    }

    fn encode(output: Self::Output, request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut response = EncodedResponse::of(status);
        response.status = status_code(status)?;
        if let Some(e_tag) = output.e_tag.as_ref() {
            response.set_header("etag", &e_tag.render(EtagRender::HeaderQuoted));
        }
        if let Some(version_id) = output.version_id.as_deref() {
            response.set_header("x-amz-version-id", version_id);
        }
        response.enforce_http_invariants(request.method());
        Ok(response)
    }
}
