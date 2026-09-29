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

//! The reviewed exceptions to the seam generator's one rule — a gateway member converts into the
//! s3s member of the same name.
//!
//! Responsible for: the operations the generator covers, the ones kept hand-written, and every
//! member the two sides spell differently, each with the reason in one sentence.
//! NOT responsible for: type pairing (`super::expr`).
//! Upstream: review. Downstream: [`super`].
//!
//! A mismatch that is not listed here fails `cargo xtask codegen` naming the member, so a new
//! model or s3s member is a decision, never a silent drop.

/// What one member exception means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// The s3s member has no gateway counterpart. Forward it takes its `Default`; backward it is
    /// dropped, which the reason must justify.
    S3sOnly(&'static str),
    /// The gateway member has no s3s counterpart. Forward a present value is refused with a
    /// `ConversionError` naming the member (never dropped); backward the member is absent.
    GatewayOnly(&'static str),
    /// The gateway member has no s3s counterpart, and the s3s request still carries its value in
    /// the request headers the adapter hands over, where the RustFS body reads it. Forward it is
    /// not converted; backward it is absent.
    CarriedByHeaders(&'static str),
    /// The gateway member converts into the s3s member with this name.
    Rename(&'static str),
    /// Backward only: the gateway member is the same-named member of the s3s struct held in the
    /// named s3s member (the gateway flattens a result element the s3s output nests).
    Nested(&'static str),
    /// Forward only: the gateway moved the member into the derived resources it authorizes and
    /// cleared it in the input, so the input conversion takes the s3s value as a parameter the
    /// adapter builds from the authorized resource.
    Supplied(&'static str),
}

/// One member exception: the s3s struct, the member name on the side the rule names, the rule.
pub type MemberOverride = (&'static str, &'static str, Rule);

/// The RustFS `impl s3s::S3` operations the seam covers (rustfs/backlog#1752).
pub const OPERATIONS: &[&str] = &[
    "AbortMultipartUpload",
    "CompleteMultipartUpload",
    "CopyObject",
    "CreateBucket",
    "CreateMultipartUpload",
    "DeleteBucket",
    "DeleteBucketCors",
    "DeleteBucketEncryption",
    "DeleteBucketLifecycle",
    "DeleteBucketPolicy",
    "DeleteBucketReplication",
    "DeleteBucketTagging",
    "DeleteBucketWebsite",
    "DeleteObject",
    "DeleteObjectTagging",
    "DeleteObjects",
    "DeletePublicAccessBlock",
    "GetBucketAccelerateConfiguration",
    "GetBucketAcl",
    "GetBucketCors",
    "GetBucketEncryption",
    "GetBucketLifecycleConfiguration",
    "GetBucketLocation",
    "GetBucketLogging",
    "GetBucketNotificationConfiguration",
    "GetBucketPolicy",
    "GetBucketPolicyStatus",
    "GetBucketReplication",
    "GetBucketRequestPayment",
    "GetBucketTagging",
    "GetBucketVersioning",
    "GetBucketWebsite",
    "GetObject",
    "GetObjectAcl",
    "GetObjectAttributes",
    "GetObjectLegalHold",
    "GetObjectLockConfiguration",
    "GetObjectRetention",
    "GetObjectTagging",
    "GetObjectTorrent",
    "GetPublicAccessBlock",
    "HeadBucket",
    "HeadObject",
    "ListBuckets",
    "ListMultipartUploads",
    "ListObjectVersions",
    "ListObjects",
    "ListObjectsV2",
    "ListParts",
    "PutBucketAccelerateConfiguration",
    "PutBucketAcl",
    "PutBucketCors",
    "PutBucketEncryption",
    "PutBucketLifecycleConfiguration",
    "PutBucketLogging",
    "PutBucketNotificationConfiguration",
    "PutBucketPolicy",
    "PutBucketReplication",
    "PutBucketRequestPayment",
    "PutBucketTagging",
    "PutBucketVersioning",
    "PutBucketWebsite",
    "PutObject",
    "PutObjectAcl",
    "PutObjectLegalHold",
    "PutObjectLockConfiguration",
    "PutObjectRetention",
    "PutObjectTagging",
    "PutPublicAccessBlock",
    "RestoreObject",
    "SelectObjectContent",
    "UploadPart",
    "UploadPartCopy",
];

/// Operations whose seam stays hand-written, with the reason.
pub const HAND_WRITTEN: &[(&str, &str)] = &[
    (
        "GetBucketLocation",
        "compat/seam/get_bucket_location.rs, measured by the goldens context diff",
    ),
    (
        "PutObject",
        "compat/seam/put_object.rs: event-hold refusal, replica input and the live body adapter",
    ),
    (
        "SelectObjectContent",
        "the s3s input nests the request document and the output is an event stream; owned by rustfs/backlog#1730",
    ),
];

/// Member exceptions, by s3s struct.
pub const MEMBERS: &[MemberOverride] = &[
    // The Object Lock event hold of the 2026-09-17 model (rustfs/gateway#815): no s3s input holds it
    // and RustFS stores none, so a request naming one is refused rather than silently unheld
    // (rd-put-0009), and no answer reports one.
    ("CopyObjectInput", "object_lock_event_hold", Rule::GatewayOnly(EVENT_HOLD)),
    ("CopyObjectInput", "object_lock_event_hold_duration_days", Rule::GatewayOnly(EVENT_HOLD)),
    ("CopyObjectInput", "object_lock_event_hold_duration_years", Rule::GatewayOnly(EVENT_HOLD)),
    ("CreateMultipartUploadInput", "object_lock_event_hold", Rule::GatewayOnly(EVENT_HOLD)),
    (
        "CreateMultipartUploadInput",
        "object_lock_event_hold_duration_days",
        Rule::GatewayOnly(EVENT_HOLD),
    ),
    (
        "CreateMultipartUploadInput",
        "object_lock_event_hold_duration_years",
        Rule::GatewayOnly(EVENT_HOLD),
    ),
    ("GetObjectOutput", "object_lock_event_hold", Rule::GatewayOnly(EVENT_HOLD)),
    ("GetObjectOutput", "object_lock_event_hold_duration_days", Rule::GatewayOnly(EVENT_HOLD)),
    ("GetObjectOutput", "object_lock_event_hold_duration_years", Rule::GatewayOnly(EVENT_HOLD)),
    ("HeadObjectOutput", "object_lock_event_hold", Rule::GatewayOnly(EVENT_HOLD)),
    ("HeadObjectOutput", "object_lock_event_hold_duration_days", Rule::GatewayOnly(EVENT_HOLD)),
    ("HeadObjectOutput", "object_lock_event_hold_duration_years", Rule::GatewayOnly(EVENT_HOLD)),
    ("DefaultRetention", "default_event_hold", Rule::GatewayOnly(EVENT_HOLD)),
    ("ObjectLockRetention", "event_hold", Rule::GatewayOnly(EVENT_HOLD)),
    ("ObjectLockRetention", "event_hold_duration", Rule::GatewayOnly(EVENT_HOLD)),
    // The copy source is sealed into the authorized derived resources (`seal_derived_input`).
    ("CopyObjectInput", "copy_source", Rule::Supplied(SEALED)),
    ("UploadPartCopyInput", "copy_source", Rule::Supplied(SEALED)),
    // If-Range: s3s 0.17.0 has no input member; RustFS reads the header from the request.
    (
        "GetObjectInput",
        "if_range",
        Rule::CarriedByHeaders("RustFS evaluates If-Range from the request headers"),
    ),
    // The gateway flattens the CopyObject/UploadPartCopy result element into its output.
    ("CopyObjectOutput", "e_tag", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "last_modified", Rule::Nested("copy_object_result")),
    ("UploadPartCopyOutput", "e_tag", Rule::Nested("copy_part_result")),
    ("UploadPartCopyOutput", "last_modified", Rule::Nested("copy_part_result")),
    ("CopyObjectOutput", "checksum_type", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "checksum_crc32", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "checksum_crc32c", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "checksum_crc64nvme", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "checksum_sha1", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "checksum_sha256", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "checksum_sha512", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "checksum_md5", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "checksum_xxhash64", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "checksum_xxhash3", Rule::Nested("copy_object_result")),
    ("CopyObjectOutput", "checksum_xxhash128", Rule::Nested("copy_object_result")),
    ("UploadPartCopyOutput", "checksum_crc32", Rule::Nested("copy_part_result")),
    ("UploadPartCopyOutput", "checksum_crc32c", Rule::Nested("copy_part_result")),
    ("UploadPartCopyOutput", "checksum_crc64nvme", Rule::Nested("copy_part_result")),
    ("UploadPartCopyOutput", "checksum_sha1", Rule::Nested("copy_part_result")),
    ("UploadPartCopyOutput", "checksum_sha256", Rule::Nested("copy_part_result")),
    ("UploadPartCopyOutput", "checksum_sha512", Rule::Nested("copy_part_result")),
    ("UploadPartCopyOutput", "checksum_md5", Rule::Nested("copy_part_result")),
    ("UploadPartCopyOutput", "checksum_xxhash64", Rule::Nested("copy_part_result")),
    ("UploadPartCopyOutput", "checksum_xxhash3", Rule::Nested("copy_part_result")),
    ("UploadPartCopyOutput", "checksum_xxhash128", Rule::Nested("copy_part_result")),
    // MinIO extensions s3s decodes from `x-minio-*` / `?versionId=` (MINIO) or from bucket
    // configuration XML (MINIO_XML). The seam leaves them at their default: the adapter fills the
    // header ones, and the XML ones are open divergences.
    ("CopyObjectInput", "version_id", Rule::S3sOnly(MINIO)),
    ("CreateMultipartUploadInput", "version_id", Rule::S3sOnly(MINIO)),
    ("DeleteBucketInput", "force_delete", Rule::S3sOnly(MINIO)),
    ("LifecycleExpiration", "expired_object_all_versions", Rule::S3sOnly(MINIO_XML)),
    ("LifecycleRule", "del_marker_expiration", Rule::S3sOnly(MINIO_XML)),
    ("ReplicationRule", "delete_replication", Rule::S3sOnly(MINIO_XML)),
    ("VersioningConfiguration", "exclude_folders", Rule::S3sOnly(MINIO_XML)),
    ("VersioningConfiguration", "excluded_prefixes", Rule::S3sOnly(MINIO_XML)),
    ("BucketLifecycleConfiguration", "expiry_updated_at", Rule::S3sOnly(MINIO_XML)),
    // Members of AWS model revisions the gateway model does not carry; RustFS ignores the inputs
    // and sets none of the outputs.
    ("CopyObjectInput", "annotation_directive", Rule::S3sOnly(NOT_IN_MODEL)),
    ("CreateBucketInput", "bucket_namespace", Rule::S3sOnly(NOT_IN_MODEL)),
    ("CreateBucketOutput", "bucket_arn", Rule::S3sOnly(NOT_IN_MODEL)),
    ("CreateBucketConfiguration", "bucket", Rule::S3sOnly(NOT_IN_MODEL)),
    ("CreateBucketConfiguration", "location", Rule::S3sOnly(NOT_IN_MODEL)),
    ("CreateBucketConfiguration", "tags", Rule::S3sOnly(NOT_IN_MODEL)),
    ("HeadBucketOutput", "access_point_alias", Rule::S3sOnly(NOT_IN_MODEL)),
    ("HeadBucketOutput", "bucket_arn", Rule::S3sOnly(NOT_IN_MODEL)),
    ("HeadBucketOutput", "bucket_location_name", Rule::S3sOnly(NOT_IN_MODEL)),
    ("HeadBucketOutput", "bucket_location_type", Rule::S3sOnly(NOT_IN_MODEL)),
];

const SEALED: &str = "the gateway authorizes the copy source as a derived resource and clears the input member";
const EVENT_HOLD: &str = "an Object Lock event hold, which no pinned s3s shape holds and RustFS does not store";
const MINIO: &str = "a MinIO extension the adapter fills from the request headers";
const MINIO_XML: &str = "a MinIO XML extension the gateway model does not decode or encode; a divergence to rule before the bucket-configuration operations move (rustfs/gateway#967)";
const NOT_IN_MODEL: &str = "an AWS model member the gateway model does not carry and RustFS neither reads nor sets";
