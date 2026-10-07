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

//! Object projections: GetObject, HeadObject, PutObject, DeleteObject, DeleteObjects, CopyObject.
//!
//! Responsible for: reading each operation's gateway input and pinned s3s input into the same
//! member paths, including the members the two models shape differently — one gateway checksum
//! against ten s3s checksum members, a metadata map s3s leaves unset when empty, a copy source the
//! gateway parses into its derived resources and s3s into the input, and SSE-C key material, which
//! is compared by digest and never spelled.
//! NOT responsible for: comparing, or listing, multipart and bucket operations.
//! Upstream: the two DTOs. Downstream: `project/mod.rs`.

use rustfs_gateway::dto;
use sha2::{Digest as _, Sha256};

use super::{gateway_projection, oracle_projection};
use crate::fields::{FieldValue, Fields, render_map};
use crate::s3s::dto as oracle;

/// The ten s3s checksum members, in the order the gateway's algorithm set lists them.
const CHECKSUM_MEMBERS: [(&str, rustfs_gateway_types::ChecksumAlgorithm); 10] = {
    use rustfs_gateway_types::ChecksumAlgorithm as A;
    [
        ("checksum_crc32", A::Crc32),
        ("checksum_crc32c", A::Crc32c),
        ("checksum_crc64nvme", A::Crc64Nvme),
        ("checksum_md5", A::Md5),
        ("checksum_sha1", A::Sha1),
        ("checksum_sha256", A::Sha256),
        ("checksum_sha512", A::Sha512),
        ("checksum_xxhash128", A::XxHash128),
        ("checksum_xxhash3", A::XxHash3),
        ("checksum_xxhash64", A::XxHash64),
    ]
};

/// The gateway's one checksum, spread over the s3s member its algorithm names.
pub(crate) fn gateway_checksums(fields: &mut Fields, spec: Option<&rustfs_gateway_types::ChecksumSpec>) {
    for (member, algorithm) in CHECKSUM_MEMBERS {
        let value = spec
            .filter(|spec| spec.algorithm() == algorithm)
            .map(|spec| spec.render_base64().to_owned());
        fields.opt(member, value.as_ref());
    }
}

/// SSE-C key material, by digest: the diff reports may be printed, and a key never is.
pub(crate) fn key_digest(key: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(key)))
}

/// A metadata map as one member; an empty map is unset, as s3s leaves it.
fn metadata<'a>(fields: &mut Fields, entries: impl Iterator<Item = (&'a str, &'a str)>) {
    let rendered = render_map(entries);
    fields.set(
        "metadata",
        if rendered.is_empty() {
            FieldValue::Absent
        } else {
            FieldValue::Present(rendered)
        },
    );
}

/// The copy source as the operation it names: grammar, bucket, key and version.
fn oracle_copy_source(fields: &mut Fields, source: &oracle::CopySource) {
    let rendered = match source {
        oracle::CopySource::Bucket { bucket, key, version_id } => {
            format!("bucket={bucket}\nkey={key}\nversion={}", version_id.as_deref().unwrap_or("<none>"))
        }
        other => format!("access-point:{other:?}"),
    };
    fields.set("copy_source", FieldValue::Present(rendered));
}

macro_rules! gateway_copy_source {
    ($fields:ident, $request:ident) => {{
        let rendered = $request.resources().source().resolve($request.read_proof()).map_or_else(
            || "<not resolvable under the request's read proof>".to_owned(),
            |source| match (source.form(), source.bucket()) {
                (rustfs_gateway::CopySourceForm::Path, Some(bucket)) => format!(
                    "bucket={}\nkey={}\nversion={}",
                    bucket.as_str(),
                    source.key().as_str(),
                    source.version_id().unwrap_or("<none>")
                ),
                (rustfs_gateway::CopySourceForm::Path, None) => "<path source without a bucket>".to_owned(),
                (other, _) => format!("access-point:{other:?}"),
            },
        );
        $fields.set("copy_source", FieldValue::Present(rendered));
    }};
}

gateway_projection! {
    fn gateway_get_object(request: dto::GetObject => input) as GET_OBJECT_MEMBERS {
        put: [bucket, key],
        opt: [
            checksum_mode, expected_bucket_owner, if_match, if_modified_since, if_none_match, if_range,
            if_unmodified_since, part_number, range, request_payer, response_cache_control,
            response_content_disposition, response_content_encoding, response_content_language,
            response_content_type, response_expires, sse_customer_algorithm, sse_customer_key_md5, version_id,
        ],
        custom: [sse_customer_key],
    }
    |fields| {
        fields.opt("sse_customer_key", input.sse_customer_key.as_ref().map(|key| key_digest(key.expose_secret().as_bytes())).as_ref());
        None
    }
}

oracle_projection! {
    fn oracle_get_object(oracle::GetObjectInput) {
        put: [bucket, key],
        opt: [
            checksum_mode, expected_bucket_owner, if_match, if_modified_since, if_none_match,
            if_unmodified_since, part_number, range, request_payer, response_cache_control,
            response_content_disposition, response_content_encoding, response_content_language,
            response_content_type, response_expires, sse_customer_algorithm, sse_customer_key_md5, version_id,
        ],
        custom: [sse_customer_key],
    }
    |fields| {
        fields.opt("sse_customer_key", sse_customer_key.as_ref().map(|key| key_digest(key.as_bytes())).as_ref());
        None
    }
}

gateway_projection! {
    fn gateway_head_object(request: dto::HeadObject => input) as HEAD_OBJECT_MEMBERS {
        put: [bucket, key],
        opt: [
            checksum_mode, expected_bucket_owner, if_match, if_modified_since, if_none_match,
            if_unmodified_since, part_number, range, request_payer, response_cache_control,
            response_content_disposition, response_content_encoding, response_content_language,
            response_content_type, response_expires, sse_customer_algorithm, sse_customer_key_md5, version_id,
        ],
        custom: [sse_customer_key],
    }
    |fields| {
        fields.opt("sse_customer_key", input.sse_customer_key.as_ref().map(|key| key_digest(key.expose_secret().as_bytes())).as_ref());
        None
    }
}

oracle_projection! {
    fn oracle_head_object(oracle::HeadObjectInput) {
        put: [bucket, key],
        opt: [
            checksum_mode, expected_bucket_owner, if_match, if_modified_since, if_none_match,
            if_unmodified_since, part_number, range, request_payer, response_cache_control,
            response_content_disposition, response_content_encoding, response_content_language,
            response_content_type, response_expires, sse_customer_algorithm, sse_customer_key_md5, version_id,
        ],
        custom: [sse_customer_key],
    }
    |fields| {
        fields.opt("sse_customer_key", sse_customer_key.as_ref().map(|key| key_digest(key.as_bytes())).as_ref());
        None
    }
}

gateway_projection! {
    fn gateway_put_object(request: dto::PutObject => input) as PUT_OBJECT_MEMBERS {
        put: [bucket, key, content_length],
        opt: [
            acl, bucket_key_enabled, cache_control, checksum_algorithm, content_disposition, content_encoding,
            content_language, content_md5, content_type, expected_bucket_owner, expires, grant_full_control,
            grant_read, grant_read_acp, grant_write_acp, if_match, if_none_match, object_lock_event_hold,
            object_lock_event_hold_duration_days, object_lock_event_hold_duration_years,
            object_lock_legal_hold_status, object_lock_mode, object_lock_retain_until_date, request_payer,
            server_side_encryption, sse_customer_algorithm, sse_customer_key_md5, ssekms_encryption_context,
            ssekms_key_id, storage_class, tagging, website_redirect_location, write_offset_bytes,
        ],
        custom: [body, checksum_spec, metadata, sse_customer_key],
    }
    |fields| {
        gateway_checksums(&mut fields, input.checksum_spec.as_ref());
        metadata(&mut fields, input.metadata.iter().map(|(name, value)| (name.as_str(), value.as_str())));
        fields.opt("sse_customer_key", input.sse_customer_key.as_ref().map(|key| key_digest(key.expose_secret().as_bytes())).as_ref());
        input.body
    }
}

oracle_projection! {
    fn oracle_put_object(oracle::PutObjectInput) {
        put: [bucket, key],
        opt: [
            acl, bucket_key_enabled, cache_control, checksum_algorithm, checksum_crc32, checksum_crc32c,
            checksum_crc64nvme, checksum_md5, checksum_sha1, checksum_sha256, checksum_sha512, checksum_xxhash128,
            checksum_xxhash3, checksum_xxhash64, content_disposition, content_encoding, content_language,
            content_length, content_md5, content_type, expected_bucket_owner, expires, grant_full_control,
            grant_read, grant_read_acp, grant_write_acp, if_match, if_none_match, object_lock_legal_hold_status,
            object_lock_mode, object_lock_retain_until_date, request_payer, server_side_encryption,
            sse_customer_algorithm, sse_customer_key_md5, ssekms_encryption_context, ssekms_key_id, storage_class,
            tagging, version_id, website_redirect_location, write_offset_bytes,
        ],
        custom: [body, metadata, sse_customer_key],
    }
    |fields| {
        let entries = metadata.iter().flatten().map(|(name, value)| (name.as_str(), value.as_str()));
        self::metadata(&mut fields, entries);
        fields.opt("sse_customer_key", sse_customer_key.as_ref().map(|key| key_digest(key.as_bytes())).as_ref());
        body
    }
}

gateway_projection! {
    fn gateway_delete_object(request: dto::DeleteObject => input) as DELETE_OBJECT_MEMBERS {
        put: [bucket, key],
        opt: [
            bypass_governance_retention, expected_bucket_owner, if_match, if_match_last_modified_time,
            if_match_size, mfa, request_payer, version_id,
        ],
        custom: [],
    }
    |fields| { None }
}

oracle_projection! {
    fn oracle_delete_object(oracle::DeleteObjectInput) {
        put: [bucket, key],
        opt: [
            bypass_governance_retention, expected_bucket_owner, if_match, if_match_last_modified_time,
            if_match_size, mfa, request_payer, version_id,
        ],
        custom: [],
    }
    |fields| { None }
}

gateway_projection! {
    /// The keys are read where the handler reads them: the gateway moves them out of the input
    /// into the derived resources before authorization, and a handler receives each key and
    /// version only through them. The per-object conditions (`ETag`, `LastModifiedTime`, `Size`)
    /// have no path to the handler at all, so they are not members here.
    fn gateway_delete_objects(request: dto::DeleteObjects => input) as DELETE_OBJECTS_MEMBERS {
        put: [bucket],
        opt: [bypass_governance_retention, checksum_algorithm, expected_bucket_owner, mfa, request_payer],
        custom: [delete],
    }
    before |fields| {
        match request.resources().resolve(request.read_proof()) {
            None => fields.set("delete.objects", FieldValue::Present("<not resolvable under the request's read proof>".to_owned())),
            Some(objects) => {
                fields.put("delete.objects.len", &objects.len().to_string());
                for (index, (key, version_id)) in objects.enumerate() {
                    fields.put(&format!("delete.objects[{index}].key"), key);
                    fields.opt(&format!("delete.objects[{index}].version_id"), version_id.map(str::to_owned).as_ref());
                }
            }
        }
    }
    |fields| {
        fields.opt("delete.quiet", input.delete.quiet.as_ref());
        None
    }
}

oracle_projection! {
    fn oracle_delete_objects(oracle::DeleteObjectsInput) {
        put: [bucket],
        opt: [bypass_governance_retention, checksum_algorithm, expected_bucket_owner, mfa, request_payer],
        custom: [delete],
    }
    |fields| {
        let oracle::Delete { objects, quiet } = delete;
        fields.opt("delete.quiet", quiet.as_ref());
        fields.put("delete.objects.len", &objects.len().to_string());
        for (index, object) in objects.iter().enumerate() {
            let oracle::ObjectIdentifier { e_tag, key, last_modified_time, size, version_id } = object;
            fields.put(&format!("delete.objects[{index}].key"), key);
            fields.opt(&format!("delete.objects[{index}].version_id"), version_id.as_ref());
            fields.opt(&format!("delete.objects[{index}].e_tag"), e_tag.as_ref());
            fields.opt(&format!("delete.objects[{index}].last_modified_time"), last_modified_time.as_ref());
            fields.opt(&format!("delete.objects[{index}].size"), size.as_ref());
        }
        None
    }
}

gateway_projection! {
    fn gateway_copy_object(request: dto::CopyObject => input) as COPY_OBJECT_MEMBERS {
        put: [bucket, key],
        opt: [
            acl, bucket_key_enabled, cache_control, checksum_algorithm, content_disposition, content_encoding,
            content_language, content_type, copy_source_if_match, copy_source_if_modified_since,
            copy_source_if_none_match, copy_source_if_unmodified_since, copy_source_sse_customer_algorithm,
            copy_source_sse_customer_key_md5, expected_bucket_owner, expected_source_bucket_owner, expires,
            grant_full_control, grant_read, grant_read_acp, grant_write_acp, if_match, if_none_match,
            metadata_directive, object_lock_event_hold, object_lock_event_hold_duration_days,
            object_lock_event_hold_duration_years, object_lock_legal_hold_status, object_lock_mode,
            object_lock_retain_until_date, request_payer, server_side_encryption, sse_customer_algorithm,
            sse_customer_key_md5, ssekms_encryption_context, ssekms_key_id, storage_class, tagging,
            tagging_directive, website_redirect_location,
        ],
        custom: [copy_source, copy_source_sse_customer_key, metadata, sse_customer_key],
    }
    before |fields| {
        gateway_copy_source!(fields, request);
    }
    |fields| {
        metadata(&mut fields, input.metadata.iter().map(|(name, value)| (name.as_str(), value.as_str())));
        fields.opt("sse_customer_key", input.sse_customer_key.as_ref().map(|key| key_digest(key.expose_secret().as_bytes())).as_ref());
        fields.opt(
            "copy_source_sse_customer_key",
            input.copy_source_sse_customer_key.as_ref().map(|key| key_digest(key.expose_secret().as_bytes())).as_ref(),
        );
        None
    }
}

oracle_projection! {
    fn oracle_copy_object(oracle::CopyObjectInput) {
        put: [bucket, key],
        opt: [
            acl, annotation_directive, bucket_key_enabled, cache_control, checksum_algorithm, content_disposition,
            content_encoding, content_language, content_type, copy_source_if_match, copy_source_if_modified_since,
            copy_source_if_none_match, copy_source_if_unmodified_since, copy_source_sse_customer_algorithm,
            copy_source_sse_customer_key_md5, expected_bucket_owner, expected_source_bucket_owner, expires,
            grant_full_control, grant_read, grant_read_acp, grant_write_acp, if_match, if_none_match,
            metadata_directive, object_lock_legal_hold_status, object_lock_mode, object_lock_retain_until_date,
            request_payer, server_side_encryption, sse_customer_algorithm, sse_customer_key_md5,
            ssekms_encryption_context, ssekms_key_id, storage_class, tagging, tagging_directive, version_id,
            website_redirect_location,
        ],
        custom: [copy_source, copy_source_sse_customer_key, metadata, sse_customer_key],
    }
    |fields| {
        oracle_copy_source(&mut fields, &copy_source);
        let entries = metadata.iter().flatten().map(|(name, value)| (name.as_str(), value.as_str()));
        self::metadata(&mut fields, entries);
        fields.opt("sse_customer_key", sse_customer_key.as_ref().map(|key| key_digest(key.as_bytes())).as_ref());
        fields.opt(
            "copy_source_sse_customer_key",
            copy_source_sse_customer_key.as_ref().map(|key| key_digest(key.as_bytes())).as_ref(),
        );
        None
    }
}
