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

//! The replica-write dialect: where `minio:PutObjectReplica` routes, and what it shadows.
//!
//! Responsible for: the operation's route row, overlay record and shadowing declaration, and
//! [`replication_dialect`], which assembles them.
//! NOT responsible for: the operation itself — its type, authorisation and codec live in
//! [`ops::put_object_replica`](crate::ops::put_object_replica) and are re-exported here; storing
//! anything under the version id (the handler); the source-version-id header fallback, which
//! arrives on an ordinary `PutObject` and is read by the RustFS adapter under its own
//! replication-header authorisation; or the multipart replica create.
//! Upstream: `rustfs-gateway-core`'s dialect mechanism and [`PutObjectReplica`].
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
//! - The floor is [`OperationFloor::custom`](rustfs_gateway_sig::OperationFloor::custom): header
//!   signatures only, so a presigned URL cannot carry a chosen version id to somebody who never
//!   held the permission.

use http::Method;
use rustfs_gateway_core::dialect::{Dialect, DialectError, DialectOverlay, DialectRoute, OverlayRow};
use rustfs_gateway_core::op::ResourceShape;
use rustfs_gateway_core::route::{Predicate, ShadowingDecl, TargetKind};

pub use crate::ops::put_object_replica::{
    NAME, PUT_OBJECT_ACTION, PutObjectReplica, PutObjectReplicaInput, REPLICATE_OBJECT_ACTION, ReplicaWriteResources,
    VERSION_ID_QUERY,
};

/// Where the row sits in the ordered table: in front of `PutObject` (800) and behind `CopyObject`
/// (790). Its selector contradicts every other `PUT` row on an object, so this is the one overlap.
pub const PRECEDENCE: u16 = 795;

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
    claims: &[],
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
