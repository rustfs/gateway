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

//! `CompleteMultipartUpload`: assemble the parts, and answer with an outcome the status cannot carry.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `CompleteMultipartUpload`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/complete_multipart_upload.rs` from
//! `generated/ir/CompleteMultipartUpload.json`; the composite entity tag, which is a value the
//! backend computes; or the precondition evaluator, which is `P5-02`'s.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: the packed checksum header and the SSE header set with the object family; the
//! upload-id capability and the part semantics with the rest of the multipart family; the
//! `If-Match` / `If-None-Match` evaluation with the conditional cluster.
//!
//! # The one operation whose response may fail after the head is gone
//!
//! Assembling ten thousand parts can outlast a client's read timeout, so S3 commits the status
//! line and the headers before it knows the outcome, writes whitespace while the work runs, and
//! puts either a result document or an `<Error>` document in the body. A client that decides
//! success from the status line reports a successful upload of an object that does not exist.
//!
//! Three consequences, and none of them is a branch anybody writes here:
//!
//! * `errors.allows_error_after_200` is `true` for this operation in the IR. That is what decides
//!   the response shape; no encoder reads an operation name to find it out.
//! * every header this operation can answer with — `x-amz-server-side-encryption`,
//!   `x-amz-version-id`, `x-amz-expiration` — is a header *binding* in the IR, so it is part of
//!   the head that is flushed first. A value that could only be known after assembly would have
//!   to be a body member; it must never be a header the encoder hopes to add later. That is the
//!   shape of the upstream defect `q-mpu-late-error-0033` cites.
//! * the whitespace written while the outcome is pending is leading whitespace in an XML
//!   document, which is well-formed. It is *not* a transport keep-alive setting, and any change
//!   here that reaches for a socket option is fixing a different problem.
//!
//! A trailer field is announced only when a trailer will actually be sent (`q-mpu-trailer-0034`);
//! this operation sends none, so it announces none.
//!
//! # Why the request root is not the shape name
//!
//! The body shape is `CompletedMultipartUpload` and the accepted root element is
//! `CompleteMultipartUpload`. The model carries that name on the member rather than on the shape,
//! so `xml.request_root` is set explicitly in `model/overlays/ops/multipart.toml`; a decoder that
//! took the shape name would reject every SDK request (`q-mpu-request-root-0030`).

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{CompleteMultipartUpload, CompleteMultipartUploadInput, CompleteMultipartUploadOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// `uploadId` is a routing discriminator, not a required parameter: a `POST` to an object key
/// without it is `CreateMultipartUpload` or `PostObject`, not a malformed completion.
static SPEC: OperationSpec = OperationSpec::builder("CompleteMultipartUpload", 200, None)
    .required_params(&[])
    .auth(AuthRequirement::new("s3:PutObject", ResourceShape::Object))
    .build();

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("CompleteMultipartUpload", SigService::S3);

impl Operation for CompleteMultipartUpload {
    const NAME: &'static str = "CompleteMultipartUpload";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = CompleteMultipartUploadInput;
    type Output = CompleteMultipartUploadOutput;
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

impl HasOperation for CompleteMultipartUploadInput {
    type Op = CompleteMultipartUpload;
}
