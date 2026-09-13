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
//! Responsible for: the operation — its type, overlay row, route row and shadowing declaration —
//! its authorisation (`s3:ReplicateObject` on the object before the body is read, and
//! `s3:PutObject` on the same key before the handler runs), and its codec, which is `PutObject`'s
//! codec plus the `versionId` query.
//! NOT responsible for: storing anything under that id (the handler); the source-version-id header
//! fallback, which arrives on an ordinary `PutObject` and is read by the RustFS adapter under its
//! own replication-header authorisation; or the multipart replica create.
//! Upstream: `rustfs-gateway-core`'s dialect mechanism and `PutObject`'s generated codec.
//! Downstream: a deployment that installs [`replication_dialect`] and registers a handler for
//! [`PutObjectReplica`] — the RustFS adapter of rustfs/backlog#1752.
//!
//! # Why an operation of its own
//!
//! AWS `PutObject` has no version-id input: the service mints every version id. Replication
//! between MinIO-compatible servers writes a replica with `?versionId=` so the target keeps the
//! source's id; a target that ignores the query gives every replica a fresh id, and versions and
//! delete markers can then no longer be matched across the pair (rustfs/gateway#752).
//!
//! A member on `PutObject` would hand the choice of version id to every writer. A separate
//! operation puts it behind its own route row and its own action instead:
//!
//! - Without [`replication_dialect`] installed nothing changes: `PUT ?versionId=` routes to
//!   `PutObject`, whose model has no such member, and the query is ignored.
//! - Installed, the row sits at [`PRECEDENCE`] and contradicts every `PUT` row that names a
//!   sub-resource, so it overlaps `PutObject` alone: `?tagging&versionId=` still reaches
//!   `PutObjectTagging`. The caller must hold `s3:ReplicateObject` before the body is read and
//!   `s3:PutObject` on the key before the handler runs — the pair a RustFS target requires today.
//! - The floor is [`OperationFloor::custom`]: header signatures only, so a presigned URL cannot
//!   carry a chosen version id to somebody who never held the permission.

use http::Method;
use rustfs_gateway_core::codec::{
    CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode, ResponseOverride,
};
use rustfs_gateway_core::dialect::{Dialect, DialectError, DialectOverlay, DialectRoute, OverlayRow};
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec};
use rustfs_gateway_core::route::{Predicate, ShadowingDecl, TargetKind};
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

/// Where the row sits in the ordered table: in front of `PutObject` (800) and behind `CopyObject`
/// (790). Its selector contradicts every other `PUT` row on an object, so this is the one overlap.
pub const PRECEDENCE: u16 = 795;

/// The query key a replica write carries.
pub const VERSION_ID_QUERY: &str = "versionId";

/// Where a RustFS replication client puts the source version id on the replica `PUT`.
const RUSTFS_CLIENT_EVIDENCE: &str = "https://github.com/rustfs/rustfs/blob/62cc19e937c8cac4a14f4a353405a19d19319bd7/crates/ecstore/src/client/api_put_object_streaming.rs";
/// Where a RustFS target authorises a replica write as `s3:ReplicateObject` on top of `s3:PutObject`.
const RUSTFS_TARGET_EVIDENCE: &str =
    "https://github.com/rustfs/rustfs/blob/62cc19e937c8cac4a14f4a353405a19d19319bd7/rustfs/src/storage/access.rs";
/// Where the pinned s3s reads the query into its MinIO `PutObjectInput.version_id` member.
const S3S_MINIO_EVIDENCE: &str =
    "https://github.com/rustfs/s3s/blob/9c4690d8e73fc8d184031a19b2c4539ebc77d180/crates/s3s/src/dto/generated_minio.rs";
/// The issue that decided the operation.
const ISSUE_EVIDENCE: &str = "https://github.com/rustfs/gateway/issues/752";

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

/// A `PUT` on an object carrying `versionId` and none of the keys that select another `PUT`.
static SELECTOR: &[Predicate] = &[
    Predicate::Method(Method::PUT),
    Predicate::Target(TargetKind::Object),
    Predicate::QueryPresent(VERSION_ID_QUERY),
    Predicate::QueryAbsent("acl"),
    Predicate::QueryAbsent("annotation"),
    Predicate::QueryAbsent("encryption"),
    Predicate::QueryAbsent("legal-hold"),
    Predicate::QueryAbsent("partNumber"),
    Predicate::QueryAbsent("renameObject"),
    Predicate::QueryAbsent("retention"),
    Predicate::QueryAbsent("tagging"),
    Predicate::QueryAbsent("uploadId"),
    Predicate::HeaderPresent {
        header: "x-amz-copy-source",
        negated: true,
    },
];

/// The one overlap the placement creates.
static SHADOWS: &[ShadowingDecl] = &[ShadowingDecl {
    winner: NAME,
    shadowed: "PutObject",
    reason: "A PUT carrying versionId and no sub-resource key is a replica write naming the version id it must be \
             stored under; behind PutObject the query would be ignored and the replica would get a fresh id, which is \
             the wrong answer rather than an error.",
    evidence: &[RUSTFS_CLIENT_EVIDENCE, S3S_MINIO_EVIDENCE],
}];

/// The reviewed record of what this dialect adds.
static OVERLAY: DialectOverlay = DialectOverlay {
    name: "minio-replication",
    vendor: "minio",
    operations: &[OverlayRow {
        name: NAME,
        precedence: PRECEDENCE,
        selector: "Method(PUT) ∧ Target(Object) ∧ QueryPresent(\"versionId\") ∧ QueryAbsent(\"acl\") ∧ \
                   QueryAbsent(\"annotation\") ∧ QueryAbsent(\"encryption\") ∧ QueryAbsent(\"legal-hold\") ∧ \
                   QueryAbsent(\"partNumber\") ∧ QueryAbsent(\"renameObject\") ∧ QueryAbsent(\"retention\") ∧ \
                   QueryAbsent(\"tagging\") ∧ QueryAbsent(\"uploadId\") ∧ HeaderAbsent(\"x-amz-copy-source\")",
        action: REPLICATE_OBJECT_ACTION,
        resource: ResourceShape::Object,
        success_status: 200,
        anonymous: false,
        evidence: &[
            RUSTFS_CLIENT_EVIDENCE,
            RUSTFS_TARGET_EVIDENCE,
            S3S_MINIO_EVIDENCE,
            ISSUE_EVIDENCE,
        ],
    }],
};

/// The replica-write dialect: one route row for [`PutObjectReplica`] and its one declared overlap.
///
/// Installing it is the deployment's explicit choice (`ServiceBuilder::dialect`), and so is the
/// handler (`ServiceBuilder::register::<PutObjectReplica, _>`); an assembly that installs the row
/// without a handler answers the replica write `501`.
///
/// # Errors
///
/// Every refusal [`rustfs_gateway_core::dialect::DialectBuilder::build`] finds. None is expected:
/// the record and the declaration above state the same facts, and the tests pin that they do.
pub fn replication_dialect() -> Result<Dialect, Vec<DialectError>> {
    Dialect::assemble(&OVERLAY)
        .declare::<PutObjectReplica>(DialectRoute {
            precedence: PRECEDENCE,
            selector: SELECTOR,
            path_shape: "/{Bucket}/{Key+}",
            shadows: SHADOWS,
        })
        .build()
}
