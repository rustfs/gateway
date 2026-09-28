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

//! Listing output conversions: ListObjects, ListObjectsV2, ListObjectVersions,
//! ListMultipartUploads, ListBuckets.
//!
//! Responsible for: destructuring each pinned s3s listing and its elements with no `..` and
//! building the gateway listing, refusing by name an element member the gateway requires and s3s
//! left unset.
//! NOT responsible for: encoding, or object and multipart outputs.
//! Upstream: `convert/mod.rs` helpers. Downstream: the operation table.

use rustfs_gateway_types::{OpaqueString, dto};

use super::{
    Converted, Unconvertible, bucket_name, entity_tag, enumeration, initiator, instant, object_key, opaque, owner, required,
};
use crate::s3s::dto as oracle;

fn common_prefixes(value: Option<Vec<oracle::CommonPrefix>>) -> Converted<Vec<dto::CommonPrefix>> {
    value
        .into_iter()
        .flatten()
        .map(|oracle::CommonPrefix { prefix }| {
            Ok(dto::CommonPrefix {
                prefix: required("common_prefixes.prefix", prefix)?,
            })
        })
        .collect()
}

fn restore_status(value: Option<oracle::RestoreStatus>) -> Converted<Option<dto::RestoreStatus>> {
    value
        .map(
            |oracle::RestoreStatus {
                 is_restore_in_progress,
                 restore_expiry_date,
             }| {
                Ok(dto::RestoreStatus {
                    is_restore_in_progress,
                    restore_expiry_date: instant("restore_status.restore_expiry_date", restore_expiry_date)?,
                })
            },
        )
        .transpose()
}

fn checksum_algorithms(value: Option<Vec<oracle::ChecksumAlgorithm>>) -> Vec<dto::ChecksumAlgorithm> {
    value
        .into_iter()
        .flatten()
        .filter_map(|algorithm| enumeration(Some(algorithm)))
        .collect()
}

fn required_key(member: &'static str, value: Option<String>) -> Converted<rustfs_gateway_types::ObjectKey> {
    required(member, object_key(member, value)?)
}

fn objects(value: Option<Vec<oracle::Object>>) -> Converted<Vec<dto::Object>> {
    value
        .into_iter()
        .flatten()
        .map(
            |oracle::Object {
                 checksum_algorithm,
                 checksum_type,
                 e_tag,
                 key,
                 last_modified,
                 owner: object_owner,
                 restore_status: restore,
                 size,
                 storage_class,
             }| {
                Ok(dto::Object {
                    key: required_key("contents.key", key)?,
                    last_modified: required("contents.last_modified", instant("contents.last_modified", last_modified)?)?,
                    e_tag: required("contents.e_tag", entity_tag("contents.e_tag", e_tag)?)?,
                    checksum_algorithm: checksum_algorithms(checksum_algorithm),
                    checksum_type: enumeration(checksum_type),
                    size: required("contents.size", size)?,
                    storage_class: required("contents.storage_class", enumeration(storage_class))?,
                    owner: owner(object_owner),
                    restore_status: restore_status(restore)?,
                })
            },
        )
        .collect()
}

/// ListObjects.
pub(crate) fn list_objects(output: oracle::ListObjectsOutput) -> Converted<dto::ListObjectsOutput> {
    let oracle::ListObjectsOutput {
        common_prefixes: prefixes,
        contents,
        delimiter,
        encoding_type,
        is_truncated,
        marker,
        max_keys,
        name,
        next_marker,
        prefix,
        request_charged,
    } = output;
    Ok(dto::ListObjectsOutput {
        is_truncated: required("is_truncated", is_truncated)?,
        marker: required("marker", marker)?,
        next_marker,
        contents: objects(contents)?,
        name: bucket_name("name", name)?,
        prefix: required("prefix", prefix)?,
        delimiter,
        max_keys: required("max_keys", max_keys)?,
        common_prefixes: common_prefixes(prefixes)?,
        encoding_type: enumeration(encoding_type),
        request_charged: enumeration(request_charged),
    })
}

/// ListObjectsV2.
pub(crate) fn list_objects_v2(output: oracle::ListObjectsV2Output) -> Converted<dto::ListObjectsV2Output> {
    let oracle::ListObjectsV2Output {
        name,
        prefix,
        max_keys,
        key_count,
        continuation_token,
        is_truncated,
        next_continuation_token,
        contents,
        common_prefixes: prefixes,
        delimiter,
        encoding_type,
        start_after,
        request_charged,
    } = output;
    Ok(dto::ListObjectsV2Output {
        is_truncated: required("is_truncated", is_truncated)?,
        contents: objects(contents)?,
        name: bucket_name("name", name)?,
        prefix: required("prefix", prefix)?,
        delimiter,
        max_keys: required("max_keys", max_keys)?,
        common_prefixes: common_prefixes(prefixes)?,
        encoding_type: enumeration(encoding_type),
        key_count: required("key_count", key_count)?,
        continuation_token: opaque(continuation_token),
        next_continuation_token: opaque(next_continuation_token),
        start_after,
        request_charged: enumeration(request_charged),
    })
}

/// ListObjectVersions.
pub(crate) fn list_object_versions(output: oracle::ListObjectVersionsOutput) -> Converted<dto::ListObjectVersionsOutput> {
    let oracle::ListObjectVersionsOutput {
        common_prefixes: prefixes,
        delete_markers,
        delimiter,
        encoding_type,
        is_truncated,
        key_marker,
        max_keys,
        name,
        next_key_marker,
        next_version_id_marker,
        prefix,
        request_charged,
        version_id_marker,
        versions,
    } = output;
    let versions = versions
        .into_iter()
        .flatten()
        .map(
            |oracle::ObjectVersion {
                 checksum_algorithm,
                 checksum_type,
                 e_tag,
                 is_latest,
                 key,
                 last_modified,
                 owner: version_owner,
                 restore_status: restore,
                 size,
                 storage_class,
                 version_id,
             }| {
                Ok(dto::ObjectVersion {
                    e_tag: required("versions.e_tag", entity_tag("versions.e_tag", e_tag)?)?,
                    checksum_algorithm: checksum_algorithms(checksum_algorithm),
                    checksum_type: enumeration(checksum_type),
                    size: required("versions.size", size)?,
                    storage_class: required("versions.storage_class", enumeration(storage_class))?,
                    key: required_key("versions.key", key)?,
                    version_id: OpaqueString::from(required("versions.version_id", version_id)?),
                    is_latest: required("versions.is_latest", is_latest)?,
                    last_modified: required("versions.last_modified", instant("versions.last_modified", last_modified)?)?,
                    owner: owner(version_owner),
                    restore_status: restore_status(restore)?,
                })
            },
        )
        .collect::<Converted<Vec<_>>>()?;
    let delete_markers = delete_markers
        .into_iter()
        .flatten()
        .map(
            |oracle::DeleteMarkerEntry {
                 is_latest,
                 key,
                 last_modified,
                 owner: marker_owner,
                 version_id,
             }| {
                Ok(dto::DeleteMarkerEntry {
                    owner: owner(marker_owner),
                    key: required_key("delete_markers.key", key)?,
                    version_id: OpaqueString::from(required("delete_markers.version_id", version_id)?),
                    is_latest: required("delete_markers.is_latest", is_latest)?,
                    last_modified: required(
                        "delete_markers.last_modified",
                        instant("delete_markers.last_modified", last_modified)?,
                    )?,
                })
            },
        )
        .collect::<Converted<Vec<_>>>()?;
    Ok(dto::ListObjectVersionsOutput {
        is_truncated: required("is_truncated", is_truncated)?,
        key_marker: required("key_marker", key_marker)?,
        version_id_marker: OpaqueString::from(required("version_id_marker", version_id_marker)?),
        next_key_marker,
        next_version_id_marker: opaque(next_version_id_marker),
        versions,
        delete_markers,
        name: bucket_name("name", name)?,
        prefix: required("prefix", prefix)?,
        delimiter,
        max_keys: required("max_keys", max_keys)?,
        common_prefixes: common_prefixes(prefixes)?,
        encoding_type: enumeration(encoding_type),
        request_charged: enumeration(request_charged),
    })
}

/// ListMultipartUploads.
pub(crate) fn list_multipart_uploads(output: oracle::ListMultipartUploadsOutput) -> Converted<dto::ListMultipartUploadsOutput> {
    let oracle::ListMultipartUploadsOutput {
        bucket,
        common_prefixes: prefixes,
        delimiter,
        encoding_type,
        is_truncated,
        key_marker,
        max_uploads,
        next_key_marker,
        next_upload_id_marker,
        prefix,
        request_charged,
        upload_id_marker,
        uploads,
    } = output;
    let uploads = uploads
        .into_iter()
        .flatten()
        .map(
            |oracle::MultipartUpload {
                 checksum_algorithm,
                 checksum_type,
                 initiated,
                 initiator: upload_initiator,
                 key,
                 owner: upload_owner,
                 storage_class,
                 upload_id,
             }| {
                Ok(dto::MultipartUpload {
                    upload_id,
                    key: object_key("uploads.key", key)?,
                    initiated: instant("uploads.initiated", initiated)?,
                    storage_class: enumeration(storage_class),
                    owner: owner(upload_owner),
                    initiator: initiator(upload_initiator),
                    checksum_algorithm: enumeration(checksum_algorithm),
                    checksum_type: enumeration(checksum_type),
                })
            },
        )
        .collect::<Converted<Vec<_>>>()?;
    Ok(dto::ListMultipartUploadsOutput {
        bucket: bucket_name("bucket", bucket)?,
        key_marker,
        upload_id_marker,
        next_key_marker,
        prefix,
        delimiter,
        next_upload_id_marker,
        max_uploads: required("max_uploads", max_uploads)?,
        is_truncated: required("is_truncated", is_truncated)?,
        uploads,
        common_prefixes: common_prefixes(prefixes)?,
        encoding_type: enumeration(encoding_type),
        request_charged: enumeration(request_charged),
    })
}

/// ListBuckets.
pub(crate) fn list_buckets(output: oracle::ListBucketsOutput) -> Converted<dto::ListBucketsOutput> {
    let oracle::ListBucketsOutput {
        buckets,
        continuation_token,
        owner: list_owner,
        prefix,
    } = output;
    let buckets = buckets
        .into_iter()
        .flatten()
        .map(
            |oracle::Bucket {
                 bucket_arn,
                 bucket_region,
                 creation_date,
                 name,
             }| {
                Ok(dto::Bucket {
                    name: bucket_name("buckets.name", name)?,
                    creation_date: required("buckets.creation_date", instant("buckets.creation_date", creation_date)?)?,
                    bucket_region,
                    bucket_arn,
                })
            },
        )
        .collect::<Converted<Vec<_>>>()?;
    Ok(dto::ListBucketsOutput {
        buckets,
        owner: owner(list_owner).ok_or(Unconvertible {
            member: "owner",
            reason: "the gateway output requires it and the s3s output left it unset",
        })?,
        continuation_token: opaque(continuation_token),
        prefix,
    })
}
