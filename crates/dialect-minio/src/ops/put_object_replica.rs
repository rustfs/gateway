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

//! `minio:PutObjectReplica`: a `PutObject` that names the version id its object must be stored
//! under, reachable only by a caller authorised to replicate.
//!
//! Responsible for: the operation — its type, input, specification, floor and derived resources —
//! its authorisation (`s3:ReplicateObject` on the object before the body is read, and
//! `s3:PutObject` on the same key before the handler runs), and its codec, which is `PutObject`'s
//! codec plus the `versionId` query.
//! NOT responsible for: its route row, overlay record or shadowing declaration (the
//! [`replication`](crate::replication) dialect); storing anything under that id (the handler); the
//! source-version-id header fallback, which arrives on an ordinary `PutObject`; or the multipart
//! replica create.
//! Upstream: `rustfs-gateway-core`'s `Operation` and codec traits and `PutObject`'s generated codec.
//! Downstream: [`replication_dialect`](crate::replication::replication_dialect), which declares it,
//! and a deployment that registers a handler for [`PutObjectReplica`].
//!
//! Its handler deadline is `Standard`, the class `PutObject` has: a replica write is the same
//! body-streaming `PUT` with one more query key.

use rustfs_gateway_core::codec::{
    CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode, ResponseOverride,
};
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec};
use rustfs_gateway_core::{DerivedResourceError, DerivedResourceSet, ResourceRef};
use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::ObjectKey;
use rustfs_gateway_types::dto::{PutObject, PutObjectInput, PutObjectOutput};

/// The operation name.
pub const NAME: &str = "minio:PutObjectReplica";

/// The action a caller must hold before a replica write is decoded.
pub const REPLICATE_OBJECT_ACTION: &str = "s3:ReplicateObject";

/// The action a caller must also hold on the key before the handler runs.
pub const PUT_OBJECT_ACTION: &str = "s3:PutObject";

/// The query key a replica write carries.
pub const VERSION_ID_QUERY: &str = "versionId";

/// A replica write: `PUT /{Bucket}/{Key+}?versionId=…` with no sub-resource key.
#[derive(Debug)]
pub struct PutObjectReplica;

/// What a replica write decodes to: an ordinary `PutObject` input and the version id the object
/// must be stored under.
pub struct PutObjectReplicaInput {
    /// Every member a `PutObject` carries, decoded by `PutObject`'s own codec.
    pub object: PutObjectInput,
    /// The source's version id, percent-decoded once and never empty. Opaque here: whether it is
    /// a well-formed id is the backend's grammar, not the protocol's.
    pub version_id: String,
}

/// The second authorisation a replica write owes: `s3:PutObject` on the key it writes.
#[derive(Debug)]
pub struct ReplicaWriteResources {
    key: ObjectKey,
}

impl ReplicaWriteResources {
    /// The key the write names.
    #[must_use]
    pub const fn key(&self) -> &ObjectKey {
        &self.key
    }
}

impl DerivedResourceSet for ReplicaWriteResources {
    fn visit(&self, visitor: &mut dyn FnMut(ResourceRef<'_>)) {
        visitor(ResourceRef::object(PUT_OBJECT_ACTION, None, &self.key));
    }
}

static SPEC: OperationSpec = OperationSpec::builder(NAME, 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new(REPLICATE_OBJECT_ACTION, ResourceShape::Object))
    .build();

/// Privileged and header-signed only: a replica write is never presigned.
static FLOOR: OperationFloor = OperationFloor::custom(NAME, SigService::S3);

impl Operation for PutObjectReplica {
    const NAME: &'static str = NAME;

    type Input = PutObjectReplicaInput;
    type Output = PutObjectOutput;
    type DerivedResources = ReplicaWriteResources;

    fn derive_resources(input: &Self::Input) -> Result<Self::DerivedResources, DerivedResourceError> {
        Ok(ReplicaWriteResources {
            key: input.object.key.clone(),
        })
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl OperationCodec for PutObjectReplica {
    const REQUEST_BODY: RequestBodyMode = <PutObject as OperationCodec>::REQUEST_BODY;
    const RESPONSE_OVERRIDES: &'static [ResponseOverride] = <PutObject as OperationCodec>::RESPONSE_OVERRIDES;

    fn decode(request: &MetaView<'_>, body: RequestBody) -> Result<Self::Input, CodecError> {
        // Read before the body is handed on: a replica write that names no version is refused
        // without the object decode ever holding the stream.
        let version_id = match request.query(VERSION_ID_QUERY) {
            Some(value) if !value.is_empty() => value.into_owned(),
            Some(_) => {
                return Err(CodecError::invalid_argument(
                    "a replica write must name the version id it is stored under",
                ));
            }
            None => {
                return Err(CodecError::invalid_request("a replica write is reached only through a versionId query"));
            }
        };
        let object = PutObject::decode(request, body)?;
        Ok(PutObjectReplicaInput { object, version_id })
    }

    fn encode(output: PutObjectOutput, request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        PutObject::encode(output, request, status)
    }
}
