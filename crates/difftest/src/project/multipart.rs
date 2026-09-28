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

//! Multipart projections: CreateMultipartUpload, UploadPart, CompleteMultipartUpload,
//! AbortMultipartUpload, ListParts.
//!
//! Responsible for: reading each operation's gateway input and pinned s3s input into the same
//! member paths — the upload id as its wire text, the completed-part list flattened to one path per
//! part member, the gateway's one checksum spread over the ten s3s checksum members, and the part
//! body handed to the handler.
//! NOT responsible for: comparing, or single-request object operations.
//! Upstream: the two DTOs. Downstream: `project/mod.rs`.

use rustfs_gateway::dto;

use super::object::{gateway_checksums, key_digest};
use super::{gateway_projection, oracle_projection};
use crate::fields::{FieldValue, Fields};
use crate::s3s::dto as oracle;

/// The upload id as the RustFS adapter reads it: through the gateway's own resolver, against a
/// record naming the request's bucket and key. An id that could never have been minted is never
/// handed out, and that is spelled rather than the bytes.
fn upload_id(
    fields: &mut Fields,
    claim: &rustfs_gateway_types::UploadIdClaim,
    bucket: &rustfs_gateway_types::BucketName,
    key: &rustfs_gateway_types::ObjectKey,
) {
    struct Same<'a>(&'a str, &'a str);
    impl rustfs_gateway_types::RecordedUpload for Same<'_> {
        fn bucket(&self) -> &str {
            self.0
        }
        fn key(&self) -> &str {
            self.1
        }
    }
    let value = match rustfs_gateway_types::resolve_upload(claim, bucket, key, |_| Some(Same(bucket.as_str(), key.as_str()))) {
        Ok((resolved, _)) => resolved.id().to_owned(),
        Err(_) => "<an id the gateway could never have minted>".to_owned(),
    };
    fields.set("upload_id", FieldValue::Present(value));
}

gateway_projection! {
    fn gateway_create_multipart_upload(request: dto::CreateMultipartUpload => input) as CREATE_MULTIPART_UPLOAD_MEMBERS {
        put: [bucket, key],
        opt: [
            acl, bucket_key_enabled, cache_control, checksum_algorithm, checksum_type, content_disposition,
            content_encoding, content_language, content_type, expected_bucket_owner, expires, grant_full_control,
            grant_read, grant_read_acp, grant_write_acp, object_lock_event_hold, object_lock_event_hold_duration_days,
            object_lock_event_hold_duration_years, object_lock_legal_hold_status, object_lock_mode,
            object_lock_retain_until_date, request_payer, server_side_encryption, sse_customer_algorithm,
            sse_customer_key_md5, ssekms_encryption_context, ssekms_key_id, storage_class, tagging,
            website_redirect_location,
        ],
        custom: [metadata, sse_customer_key],
    }
    |fields| {
        let rendered = crate::fields::render_map(input.metadata.iter().map(|(name, value)| (name.as_str(), value.as_str())));
        fields.set("metadata", if rendered.is_empty() { FieldValue::Absent } else { FieldValue::Present(rendered) });
        fields.opt("sse_customer_key", input.sse_customer_key.as_ref().map(|key| key_digest(key.expose_secret().as_bytes())).as_ref());
        None
    }
}

oracle_projection! {
    fn oracle_create_multipart_upload(oracle::CreateMultipartUploadInput) {
        put: [bucket, key],
        opt: [
            acl, bucket_key_enabled, cache_control, checksum_algorithm, checksum_type, content_disposition,
            content_encoding, content_language, content_type, expected_bucket_owner, expires, grant_full_control,
            grant_read, grant_read_acp, grant_write_acp, object_lock_legal_hold_status, object_lock_mode,
            object_lock_retain_until_date, request_payer, server_side_encryption, sse_customer_algorithm,
            sse_customer_key_md5, ssekms_encryption_context, ssekms_key_id, storage_class, tagging, version_id,
            website_redirect_location,
        ],
        custom: [metadata, sse_customer_key],
    }
    |fields| {
        let rendered = crate::fields::render_map(metadata.iter().flatten().map(|(name, value)| (name.as_str(), value.as_str())));
        fields.set("metadata", if rendered.is_empty() { FieldValue::Absent } else { FieldValue::Present(rendered) });
        fields.opt("sse_customer_key", sse_customer_key.as_ref().map(|key| key_digest(key.as_bytes())).as_ref());
        None
    }
}

gateway_projection! {
    fn gateway_upload_part(request: dto::UploadPart => input) as UPLOAD_PART_MEMBERS {
        put: [bucket, key, content_length, part_number],
        opt: [
            checksum_algorithm, content_md5, expected_bucket_owner, request_payer, sse_customer_algorithm,
            sse_customer_key_md5,
        ],
        custom: [body, checksum_spec, sse_customer_key, upload_id],
    }
    |fields| {
        upload_id(&mut fields, &input.upload_id, &input.bucket, &input.key);
        gateway_checksums(&mut fields, input.checksum_spec.as_ref());
        fields.opt("sse_customer_key", input.sse_customer_key.as_ref().map(|key| key_digest(key.expose_secret().as_bytes())).as_ref());
        input.body
    }
}

oracle_projection! {
    fn oracle_upload_part(oracle::UploadPartInput) {
        put: [bucket, key, part_number, upload_id],
        opt: [
            checksum_algorithm, checksum_crc32, checksum_crc32c, checksum_crc64nvme, checksum_md5, checksum_sha1,
            checksum_sha256, checksum_sha512, checksum_xxhash128, checksum_xxhash3, checksum_xxhash64,
            content_length, content_md5, expected_bucket_owner, request_payer, sse_customer_algorithm,
            sse_customer_key_md5,
        ],
        custom: [body, sse_customer_key],
    }
    |fields| {
        fields.opt("sse_customer_key", sse_customer_key.as_ref().map(|key| key_digest(key.as_bytes())).as_ref());
        body
    }
}

gateway_projection! {
    fn gateway_complete_multipart_upload(request: dto::CompleteMultipartUpload => input) as COMPLETE_MULTIPART_UPLOAD_MEMBERS {
        put: [bucket, key],
        opt: [
            checksum_type, expected_bucket_owner, if_match, if_none_match, mpu_object_size, request_payer,
            sse_customer_algorithm, sse_customer_key_md5,
        ],
        custom: [checksum_spec, multipart_upload, sse_customer_key, upload_id],
    }
    |fields| {
        upload_id(&mut fields, &input.upload_id, &input.bucket, &input.key);
        gateway_checksums(&mut fields, input.checksum_spec.as_ref());
        fields.opt("sse_customer_key", input.sse_customer_key.as_ref().map(|key| key_digest(key.expose_secret().as_bytes())).as_ref());
        let parts = &input.multipart_upload.parts;
        fields.put("multipart_upload.parts.len", &parts.len().to_string());
        for (index, part) in parts.iter().enumerate() {
            let prefix = format!("multipart_upload.parts[{index}]");
            fields.put(&format!("{prefix}.part_number"), &part.part_number);
            fields.opt(&format!("{prefix}.e_tag"), part.e_tag.as_ref());
            for (member, value) in [
                ("checksum_crc32", &part.checksum_crc32),
                ("checksum_crc32c", &part.checksum_crc32c),
                ("checksum_crc64nvme", &part.checksum_crc64nvme),
                ("checksum_md5", &part.checksum_md5),
                ("checksum_sha1", &part.checksum_sha1),
                ("checksum_sha256", &part.checksum_sha256),
                ("checksum_sha512", &part.checksum_sha512),
                ("checksum_xxhash128", &part.checksum_xxhash128),
                ("checksum_xxhash3", &part.checksum_xxhash3),
                ("checksum_xxhash64", &part.checksum_xxhash64),
            ] {
                fields.opt(&format!("{prefix}.{member}"), value.as_ref());
            }
        }
        None
    }
}

oracle_projection! {
    fn oracle_complete_multipart_upload(oracle::CompleteMultipartUploadInput) {
        put: [bucket, key, upload_id],
        opt: [
            checksum_crc32, checksum_crc32c, checksum_crc64nvme, checksum_md5, checksum_sha1, checksum_sha256,
            checksum_sha512, checksum_type, checksum_xxhash128, checksum_xxhash3, checksum_xxhash64,
            expected_bucket_owner, if_match, if_none_match, mpu_object_size, request_payer,
            sse_customer_algorithm, sse_customer_key_md5,
        ],
        custom: [multipart_upload, sse_customer_key],
    }
    |fields| {
        fields.opt("sse_customer_key", sse_customer_key.as_ref().map(|key| key_digest(key.as_bytes())).as_ref());
        let parts = multipart_upload.and_then(|upload| upload.parts).unwrap_or_default();
        fields.put("multipart_upload.parts.len", &parts.len().to_string());
        for (index, part) in parts.iter().enumerate() {
            let oracle::CompletedPart {
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
                e_tag,
                part_number,
            } = part;
            let prefix = format!("multipart_upload.parts[{index}]");
            fields.opt(&format!("{prefix}.part_number"), part_number.as_ref());
            fields.opt(&format!("{prefix}.e_tag"), e_tag.as_ref());
            for (member, value) in [
                ("checksum_crc32", checksum_crc32),
                ("checksum_crc32c", checksum_crc32c),
                ("checksum_crc64nvme", checksum_crc64nvme),
                ("checksum_md5", checksum_md5),
                ("checksum_sha1", checksum_sha1),
                ("checksum_sha256", checksum_sha256),
                ("checksum_sha512", checksum_sha512),
                ("checksum_xxhash128", checksum_xxhash128),
                ("checksum_xxhash3", checksum_xxhash3),
                ("checksum_xxhash64", checksum_xxhash64),
            ] {
                fields.opt(&format!("{prefix}.{member}"), value.as_ref());
            }
        }
        None
    }
}

gateway_projection! {
    fn gateway_abort_multipart_upload(request: dto::AbortMultipartUpload => input) as ABORT_MULTIPART_UPLOAD_MEMBERS {
        put: [bucket, key],
        opt: [expected_bucket_owner, if_match_initiated_time, request_payer],
        custom: [upload_id],
    }
    |fields| {
        upload_id(&mut fields, &input.upload_id, &input.bucket, &input.key);
        None
    }
}

oracle_projection! {
    fn oracle_abort_multipart_upload(oracle::AbortMultipartUploadInput) {
        put: [bucket, key, upload_id],
        opt: [expected_bucket_owner, if_match_initiated_time, request_payer],
        custom: [],
    }
    |fields| { None }
}

gateway_projection! {
    fn gateway_list_parts(request: dto::ListParts => input) as LIST_PARTS_MEMBERS {
        put: [bucket, key],
        opt: [
            expected_bucket_owner, max_parts, part_number_marker, request_payer, sse_customer_algorithm,
            sse_customer_key_md5,
        ],
        custom: [sse_customer_key, upload_id],
    }
    |fields| {
        upload_id(&mut fields, &input.upload_id, &input.bucket, &input.key);
        fields.opt("sse_customer_key", input.sse_customer_key.as_ref().map(|key| key_digest(key.expose_secret().as_bytes())).as_ref());
        None
    }
}

oracle_projection! {
    fn oracle_list_parts(oracle::ListPartsInput) {
        put: [bucket, key, upload_id],
        opt: [
            expected_bucket_owner, max_parts, part_number_marker, request_payer, sse_customer_algorithm,
            sse_customer_key_md5,
        ],
        custom: [sse_customer_key],
    }
    |fields| {
        fields.opt("sse_customer_key", sse_customer_key.as_ref().map(|key| key_digest(key.as_bytes())).as_ref());
        None
    }
}
