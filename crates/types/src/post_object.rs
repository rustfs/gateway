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

//! The DTO surface for browser POST Object uploads omitted by the Smithy S3 model.
//!
//! Responsible for: the owned bucket, resolved key, live file stream, the object members the
//! form sets by field, and storage result passed between the POST Object codec and a backend
//! handler.
//! NOT responsible for: multipart framing, POST-policy evaluation, routing, or success-action
//! rendering. Upstream: the authenticated gateway form pipeline. Downstream: backend handlers.

use core::fmt;

use rustfs_gateway_stream::ByteStream;

use crate::dto::{
    Acl, ChecksumAlgorithm, ObjectLockLegalHoldStatus, ObjectLockMode, RequestPayer, ServerSideEncryption, StorageClass,
};
use crate::{BucketName, ETag, ObjectKey, OpaqueString, Timestamp};

/// The standard S3 POST Object operation marker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PostObject;

/// A browser upload after its form fields and POST policy have been accepted.
#[derive(Debug)]
pub struct PostObjectInput {
    /// The bucket named by both the route and the accepted policy.
    pub bucket: BucketName,
    /// The object key after `${filename}` substitution and name validation.
    pub key: ObjectKey,
    /// The file part as a live, policy-bounded stream.
    pub body: ByteStream,
    /// The file part's media type, or `None` for the S3 default.
    pub content_type: Option<String>,
    /// User metadata from accepted `x-amz-meta-*` form fields.
    pub metadata: Vec<(String, String)>,
    /// The other `PutObject` members the form set by field, as the RustFS profile reads them
    /// (`ServiceBuilder::legacy_rustfs_post_forms`); empty under the gateway's own grammar, which
    /// does not read them.
    pub fields: PostObjectFields,
}

/// The `PutObject` members a browser form sets by field, beyond its key, media type and user
/// metadata: each is the form field named like the `PutObject` header.
///
/// A text or enumeration member holds the field as the form spelled it. Unlike a header, a form
/// field is not read as absent for being empty: a field sent empty is `Some` of an empty value.
///
/// A handler gives each member the effect the store it fronts gives that form field, or refuses
/// the upload; it never ignores a member its store would act on. Legacy RustFS, for one, stores
/// the representation, tagging, class, encryption and Object Lock members (the last checked against
/// the bucket's Object Lock configuration first), and reads but never acts on the ACL
/// and grant members, the expected owner, the request payer, the bucket-key flag, the checksum
/// members, the KMS context, the write offset and the two conditions: its conditional write and
/// checksum verification read the request's own headers, never the form.
///
/// `Debug` never prints the KMS key id or context. There is no `PartialEq`, as on every operation
/// input: a member added later may hold an SSE-C key, which is never compared with `==`.
#[derive(Clone, Default)]
pub struct PostObjectFields {
    /// `x-amz-acl`.
    pub acl: Option<Acl>,
    /// `x-amz-server-side-encryption-bucket-key-enabled`.
    pub bucket_key_enabled: Option<bool>,
    /// `Cache-Control`.
    pub cache_control: Option<String>,
    /// `x-amz-sdk-checksum-algorithm`.
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    /// `x-amz-checksum-crc32`.
    pub checksum_crc32: Option<String>,
    /// `x-amz-checksum-crc32c`.
    pub checksum_crc32c: Option<String>,
    /// `x-amz-checksum-crc64nvme`.
    pub checksum_crc64nvme: Option<String>,
    /// `x-amz-checksum-md5`.
    pub checksum_md5: Option<String>,
    /// `x-amz-checksum-sha1`.
    pub checksum_sha1: Option<String>,
    /// `x-amz-checksum-sha256`.
    pub checksum_sha256: Option<String>,
    /// `x-amz-checksum-sha512`.
    pub checksum_sha512: Option<String>,
    /// `x-amz-checksum-xxhash128`.
    pub checksum_xxhash128: Option<String>,
    /// `x-amz-checksum-xxhash3`.
    pub checksum_xxhash3: Option<String>,
    /// `x-amz-checksum-xxhash64`.
    pub checksum_xxhash64: Option<String>,
    /// `Content-Disposition`.
    pub content_disposition: Option<String>,
    /// `Content-Encoding`.
    pub content_encoding: Option<String>,
    /// `Content-Language`.
    pub content_language: Option<String>,
    /// `Content-MD5`.
    pub content_md5: Option<String>,
    /// `x-amz-expected-bucket-owner`.
    pub expected_bucket_owner: Option<String>,
    /// `Expires`, kept as sent (`q-timestamp-0005`).
    pub expires: Option<OpaqueString>,
    /// `x-amz-grant-full-control`.
    pub grant_full_control: Option<String>,
    /// `x-amz-grant-read`.
    pub grant_read: Option<String>,
    /// `x-amz-grant-read-acp`.
    pub grant_read_acp: Option<String>,
    /// `x-amz-grant-write-acp`.
    pub grant_write_acp: Option<String>,
    /// `If-Match`, the condition as sent.
    pub if_match: Option<String>,
    /// `If-None-Match`, the condition as sent.
    pub if_none_match: Option<String>,
    /// `x-amz-object-lock-legal-hold`, as sent. Asking for it requires `s3:PutObjectLegalHold`.
    pub object_lock_legal_hold_status: Option<ObjectLockLegalHoldStatus>,
    /// `x-amz-object-lock-mode`, as sent. Asking for it requires `s3:PutObjectRetention`.
    pub object_lock_mode: Option<ObjectLockMode>,
    /// `x-amz-object-lock-retain-until-date`, read as an RFC 3339 date-time. Asking for it
    /// requires `s3:PutObjectRetention`.
    pub object_lock_retain_until_date: Option<Timestamp>,
    /// `x-amz-request-payer`.
    pub request_payer: Option<RequestPayer>,
    /// `x-amz-server-side-encryption`.
    pub server_side_encryption: Option<ServerSideEncryption>,
    /// `x-amz-server-side-encryption-context`.
    pub ssekms_encryption_context: Option<String>,
    /// `x-amz-server-side-encryption-aws-kms-key-id`.
    pub ssekms_key_id: Option<String>,
    /// `x-amz-storage-class`.
    pub storage_class: Option<StorageClass>,
    /// `x-amz-tagging`: the tag set as URL query-string pairs.
    pub tagging: Option<String>,
    /// `x-amz-website-redirect-location`.
    pub website_redirect_location: Option<String>,
    /// `x-amz-write-offset-bytes`.
    pub write_offset_bytes: Option<i64>,
}

impl PostObjectFields {
    /// Whether the form set none of these members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        // Exhaustive on purpose: a member added later must be counted here.
        let Self {
            acl,
            bucket_key_enabled,
            cache_control,
            checksum_algorithm,
            checksum_crc32,
            checksum_crc32c,
            checksum_crc64nvme,
            checksum_md5,
            checksum_sha1,
            checksum_sha256,
            checksum_sha512,
            checksum_xxhash128,
            checksum_xxhash3,
            checksum_xxhash64,
            content_disposition,
            content_encoding,
            content_language,
            content_md5,
            expected_bucket_owner,
            expires,
            grant_full_control,
            grant_read,
            grant_read_acp,
            grant_write_acp,
            if_match,
            if_none_match,
            object_lock_legal_hold_status,
            object_lock_mode,
            object_lock_retain_until_date,
            request_payer,
            server_side_encryption,
            ssekms_encryption_context,
            ssekms_key_id,
            storage_class,
            tagging,
            website_redirect_location,
            write_offset_bytes,
        } = self;
        let text = [
            cache_control,
            checksum_crc32,
            checksum_crc32c,
            checksum_crc64nvme,
            checksum_md5,
            checksum_sha1,
            checksum_sha256,
            checksum_sha512,
            checksum_xxhash128,
            checksum_xxhash3,
            checksum_xxhash64,
            content_disposition,
            content_encoding,
            content_language,
            content_md5,
            expected_bucket_owner,
            grant_full_control,
            grant_read,
            grant_read_acp,
            grant_write_acp,
            if_match,
            if_none_match,
            ssekms_encryption_context,
            ssekms_key_id,
            tagging,
            website_redirect_location,
        ];
        text.iter().all(|member| member.is_none())
            && acl.is_none()
            && bucket_key_enabled.is_none()
            && checksum_algorithm.is_none()
            && expires.is_none()
            && object_lock_legal_hold_status.is_none()
            && object_lock_mode.is_none()
            && object_lock_retain_until_date.is_none()
            && request_payer.is_none()
            && server_side_encryption.is_none()
            && storage_class.is_none()
            && write_offset_bytes.is_none()
    }
}

impl fmt::Debug for PostObjectFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const REDACTED: &str = "<redacted>";
        let Self {
            acl,
            bucket_key_enabled,
            cache_control,
            checksum_algorithm,
            checksum_crc32,
            checksum_crc32c,
            checksum_crc64nvme,
            checksum_md5,
            checksum_sha1,
            checksum_sha256,
            checksum_sha512,
            checksum_xxhash128,
            checksum_xxhash3,
            checksum_xxhash64,
            content_disposition,
            content_encoding,
            content_language,
            content_md5,
            expected_bucket_owner,
            expires,
            grant_full_control,
            grant_read,
            grant_read_acp,
            grant_write_acp,
            if_match,
            if_none_match,
            object_lock_legal_hold_status,
            object_lock_mode,
            object_lock_retain_until_date,
            request_payer,
            server_side_encryption,
            ssekms_encryption_context,
            ssekms_key_id,
            storage_class,
            tagging,
            website_redirect_location,
            write_offset_bytes,
        } = self;
        formatter
            .debug_struct("PostObjectFields")
            .field("acl", acl)
            .field("bucket_key_enabled", bucket_key_enabled)
            .field("cache_control", cache_control)
            .field("checksum_algorithm", checksum_algorithm)
            .field("checksum_crc32", checksum_crc32)
            .field("checksum_crc32c", checksum_crc32c)
            .field("checksum_crc64nvme", checksum_crc64nvme)
            .field("checksum_md5", checksum_md5)
            .field("checksum_sha1", checksum_sha1)
            .field("checksum_sha256", checksum_sha256)
            .field("checksum_sha512", checksum_sha512)
            .field("checksum_xxhash128", checksum_xxhash128)
            .field("checksum_xxhash3", checksum_xxhash3)
            .field("checksum_xxhash64", checksum_xxhash64)
            .field("content_disposition", content_disposition)
            .field("content_encoding", content_encoding)
            .field("content_language", content_language)
            .field("content_md5", content_md5)
            .field("expected_bucket_owner", expected_bucket_owner)
            .field("expires", expires)
            .field("grant_full_control", grant_full_control)
            .field("grant_read", grant_read)
            .field("grant_read_acp", grant_read_acp)
            .field("grant_write_acp", grant_write_acp)
            .field("if_match", if_match)
            .field("if_none_match", if_none_match)
            .field("object_lock_legal_hold_status", object_lock_legal_hold_status)
            .field("object_lock_mode", object_lock_mode)
            .field("object_lock_retain_until_date", object_lock_retain_until_date)
            .field("request_payer", request_payer)
            .field("server_side_encryption", server_side_encryption)
            .field("ssekms_encryption_context", &ssekms_encryption_context.as_ref().map(|_| REDACTED))
            .field("ssekms_key_id", &ssekms_key_id.as_ref().map(|_| REDACTED))
            .field("storage_class", storage_class)
            .field("tagging", tagging)
            .field("website_redirect_location", website_redirect_location)
            .field("write_offset_bytes", write_offset_bytes)
            .finish()
    }
}

/// The storage result used to render a POST Object response.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PostObjectOutput {
    /// The entity tag assigned to the stored object.
    pub e_tag: Option<ETag>,
    /// The version identifier assigned by a versioned bucket.
    pub version_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Negative — `Debug` names the KMS key id and context as present, never their values; the
    /// other members print.
    #[test]
    fn debug_never_prints_the_kms_key_id_or_context() {
        let fields = PostObjectFields {
            ssekms_key_id: Some("arn:aws:kms:us-east-1:111122223333:key/do-not-print".to_owned()),
            ssekms_encryption_context: Some("eyJkby1ub3QiOiJwcmludCJ9".to_owned()),
            cache_control: Some("max-age=60".to_owned()),
            ..PostObjectFields::default()
        };
        let printed = format!("{fields:?}");
        assert!(!printed.contains("do-not-print"), "{printed}");
        assert!(!printed.contains("eyJkby1ub3QiOiJwcmludCJ9"), "{printed}");
        assert!(printed.contains("ssekms_key_id: Some(\"<redacted>\")"), "{printed}");
        assert!(printed.contains("max-age=60"), "{printed}");
    }

    /// Positive and negative — a form that set nothing is empty; one member, an empty value
    /// included, is not.
    #[test]
    fn a_form_that_set_one_member_is_not_empty() {
        assert!(PostObjectFields::default().is_empty());
        for fields in [
            PostObjectFields {
                content_language: Some(String::new()),
                ..PostObjectFields::default()
            },
            PostObjectFields {
                write_offset_bytes: Some(0),
                ..PostObjectFields::default()
            },
            PostObjectFields {
                ssekms_key_id: Some("k".to_owned()),
                ..PostObjectFields::default()
            },
            PostObjectFields {
                storage_class: Some(StorageClass::custom(String::new())),
                ..PostObjectFields::default()
            },
        ] {
            assert!(!fields.is_empty(), "{fields:?}");
        }
    }
}
