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

//! Multipart output conversions: CreateMultipartUpload, UploadPart, CompleteMultipartUpload,
//! AbortMultipartUpload, ListParts.
//!
//! Responsible for: destructuring each pinned s3s output with no `..` and building the gateway
//! output; the part checksum folded into the gateway's one; the RustFS keep-alive future on a
//! completion refused rather than dropped.
//! NOT responsible for: encoding, or single-request object outputs.
//! Upstream: `convert/mod.rs` helpers. Downstream: the operation table.

use rustfs_gateway_types::dto;

use super::{
    Checksums, Converted, Unconvertible, bucket_name, entity_tag, enumeration, initiator, instant, object_key, opaque, owner,
    required,
};
use crate::s3s::dto as oracle;

/// CreateMultipartUpload.
pub(crate) fn create_multipart_upload(
    output: oracle::CreateMultipartUploadOutput,
) -> Converted<dto::CreateMultipartUploadOutput> {
    let oracle::CreateMultipartUploadOutput {
        abort_date,
        abort_rule_id,
        bucket,
        bucket_key_enabled,
        checksum_algorithm,
        checksum_type,
        key,
        request_charged,
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_encryption_context,
        ssekms_key_id,
        server_side_encryption,
        upload_id,
    } = output;
    Ok(dto::CreateMultipartUploadOutput {
        abort_date: instant("abort_date", abort_date)?,
        abort_rule_id,
        bucket: bucket_name("bucket", bucket)?,
        key: required("key", object_key("key", key)?)?,
        upload_id: required("upload_id", upload_id)?,
        server_side_encryption: enumeration(server_side_encryption),
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        ssekms_encryption_context,
        bucket_key_enabled,
        request_charged: enumeration(request_charged),
        checksum_algorithm: enumeration(checksum_algorithm),
        checksum_type: enumeration(checksum_type),
    })
}

/// UploadPart.
pub(crate) fn upload_part(output: oracle::UploadPartOutput) -> Converted<dto::UploadPartOutput> {
    let oracle::UploadPartOutput {
        bucket_key_enabled,
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
        request_charged,
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        server_side_encryption,
    } = output;
    let checksum_spec = Checksums {
        crc32: checksum_crc32,
        crc32c: checksum_crc32c,
        crc64nvme: checksum_crc64nvme,
        md5: checksum_md5,
        sha1: checksum_sha1,
        sha256: checksum_sha256,
        sha512: checksum_sha512,
        xxhash128: checksum_xxhash128,
        xxhash3: checksum_xxhash3,
        xxhash64: checksum_xxhash64,
    }
    .into_spec()?;
    Ok(dto::UploadPartOutput {
        server_side_encryption: enumeration(server_side_encryption),
        e_tag: required("e_tag", entity_tag("e_tag", e_tag)?)?,
        checksum_spec,
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        bucket_key_enabled,
        request_charged: enumeration(request_charged),
    })
}

/// CompleteMultipartUpload. A RustFS keep-alive future has no place in the gateway output, which
/// is written once; it is refused rather than dropped.
pub(crate) fn complete_multipart_upload(
    output: oracle::CompleteMultipartUploadOutput,
) -> Converted<dto::CompleteMultipartUploadOutput> {
    let oracle::CompleteMultipartUploadOutput {
        bucket,
        bucket_key_enabled,
        checksum_crc32,
        checksum_crc32c,
        checksum_crc64nvme,
        checksum_md5,
        checksum_sha1,
        checksum_sha256,
        checksum_sha512,
        checksum_type,
        checksum_xxhash128,
        checksum_xxhash3,
        checksum_xxhash64,
        e_tag,
        expiration,
        key,
        location,
        request_charged,
        ssekms_key_id,
        server_side_encryption,
        version_id,
        future,
    } = output;
    if future.is_some() {
        return Err(Unconvertible {
            member: "future",
            reason: "a deferred completion the gateway output cannot carry",
        });
    }
    Ok(dto::CompleteMultipartUploadOutput {
        location,
        bucket: bucket.map(|name| bucket_name("bucket", Some(name))).transpose()?,
        key: object_key("key", key)?,
        expiration: opaque(expiration),
        e_tag: entity_tag("e_tag", e_tag)?,
        checksum_crc32,
        checksum_crc32c,
        checksum_crc64nvme,
        checksum_sha1,
        checksum_sha256,
        checksum_sha512,
        checksum_md5,
        checksum_xxhash64,
        checksum_xxhash3,
        checksum_xxhash128,
        checksum_type: enumeration(checksum_type),
        server_side_encryption: enumeration(server_side_encryption),
        version_id,
        ssekms_key_id,
        bucket_key_enabled,
        request_charged: enumeration(request_charged),
    })
}

/// AbortMultipartUpload.
pub(crate) fn abort_multipart_upload(output: oracle::AbortMultipartUploadOutput) -> Converted<dto::AbortMultipartUploadOutput> {
    let oracle::AbortMultipartUploadOutput { request_charged } = output;
    Ok(dto::AbortMultipartUploadOutput {
        request_charged: enumeration(request_charged),
    })
}

/// ListParts.
pub(crate) fn list_parts(output: oracle::ListPartsOutput) -> Converted<dto::ListPartsOutput> {
    let oracle::ListPartsOutput {
        abort_date,
        abort_rule_id,
        bucket,
        checksum_algorithm,
        checksum_type,
        initiator: parts_initiator,
        is_truncated,
        key,
        max_parts,
        next_part_number_marker,
        owner: parts_owner,
        part_number_marker,
        parts,
        request_charged,
        storage_class,
        upload_id,
    } = output;
    let parts = parts
        .into_iter()
        .flatten()
        .map(
            |oracle::Part {
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
                 last_modified,
                 part_number,
                 size,
             }| {
                Ok(dto::Part {
                    part_number: required("parts.part_number", part_number)?,
                    last_modified: instant("parts.last_modified", last_modified)?,
                    e_tag: required("parts.e_tag", entity_tag("parts.e_tag", e_tag)?)?,
                    size: required("parts.size", size)?,
                    checksum_crc32,
                    checksum_crc32c,
                    checksum_crc64nvme,
                    checksum_sha1,
                    checksum_sha256,
                    checksum_sha512,
                    checksum_md5,
                    checksum_xxhash64,
                    checksum_xxhash3,
                    checksum_xxhash128,
                })
            },
        )
        .collect::<Converted<Vec<_>>>()?;
    Ok(dto::ListPartsOutput {
        abort_date: instant("abort_date", abort_date)?,
        abort_rule_id,
        bucket: bucket_name("bucket", bucket)?,
        key: required("key", object_key("key", key)?)?,
        upload_id: required("upload_id", upload_id)?,
        part_number_marker: part_number_marker.map(|marker| marker.to_string()),
        next_part_number_marker: next_part_number_marker.map(|marker| marker.to_string()),
        max_parts: required("max_parts", max_parts)?,
        is_truncated: required("is_truncated", is_truncated)?,
        parts,
        initiator: initiator(parts_initiator),
        owner: owner(parts_owner),
        storage_class: enumeration(storage_class),
        request_charged: enumeration(request_charged),
        checksum_algorithm: enumeration(checksum_algorithm),
        checksum_type: enumeration(checksum_type),
    })
}
