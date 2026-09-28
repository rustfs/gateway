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

//! Object output conversions: GetObject, HeadObject, PutObject (the production seam),
//! DeleteObject, DeleteObjects, CopyObject.
//!
//! Responsible for: destructuring each pinned s3s output with no `..` and building the gateway
//! output, refusing by name what the gateway output cannot hold; handing a GetObject body to the
//! gateway as a live stream without reading it.
//! NOT responsible for: listing, multipart or bucket outputs, or encoding.
//! Upstream: `convert/mod.rs` helpers. Downstream: the operation table.

use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use futures_core::Stream;
use rustfs_gateway_stream::{ByteStream, PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders};
use rustfs_gateway_types::dto;

use super::{Checksums, Converted, Unconvertible, absent, entity_tag, enumeration, instant, object_key, opaque, required};
use crate::s3s::dto as oracle;

/// PutObject: the production seam RustFS will run.
pub(crate) fn put_object(output: oracle::PutObjectOutput) -> Converted<dto::PutObjectOutput> {
    rustfs_gateway_types::compat::s3s_0_17_0::put_object::output_from_s3s(output).map_err(|error| Unconvertible {
        member: error.field,
        reason: error.reason,
    })
}

/// The s3s streaming body as the gateway's, read only when the gateway reads it.
struct BlobStream {
    blob: Mutex<oracle::StreamingBlob>,
    remaining: Option<u64>,
    done: bool,
}

impl PayloadStream for BlobStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(StreamError::polled_after_eof()));
        }
        let blob = this.blob.get_mut().unwrap_or_else(std::sync::PoisonError::into_inner);
        match Pin::new(blob).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => {
                if let Some(remaining) = this.remaining.as_mut() {
                    *remaining = remaining.saturating_sub(chunk.len() as u64);
                }
                Poll::Ready(Ok(PayloadRead::Chunk(chunk)))
            }
            Poll::Ready(Some(Err(_))) => {
                this.done = true;
                Poll::Ready(Err(StreamError::incomplete_body()))
            }
            Poll::Ready(None) => {
                this.done = true;
                Poll::Ready(Ok(PayloadRead::Eof {
                    trailers: TrailingHeaders::empty(),
                }))
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        if self.remaining.is_some() {
            PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH
        } else {
            PayloadCaps::PUSH
        }
    }

    fn len_hint(&self) -> Option<u64> {
        self.remaining
    }
}

fn body(blob: Option<oracle::StreamingBlob>) -> Converted<Option<ByteStream>> {
    blob.map(|blob| {
        use crate::s3s::stream::ByteStream as _;
        let remaining = blob.remaining_length().exact().map(|length| length as u64);
        ByteStream::new(Box::pin(BlobStream {
            blob: Mutex::new(blob),
            remaining,
            done: false,
        }))
        .map_err(|_| Unconvertible {
            member: "body",
            reason: "the gateway refused the body stream",
        })
    })
    .transpose()
}

fn metadata(value: Option<oracle::Metadata>) -> std::collections::BTreeMap<String, String> {
    value.into_iter().flatten().collect()
}

/// GetObject, the body handed over as a live stream.
pub(crate) fn get_object(output: oracle::GetObjectOutput) -> Converted<dto::GetObjectOutput> {
    let oracle::GetObjectOutput {
        accept_ranges,
        body: blob,
        bucket_key_enabled,
        cache_control,
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
        content_disposition,
        content_encoding,
        content_language,
        content_length,
        content_range,
        content_type,
        delete_marker,
        e_tag,
        expiration,
        expires,
        last_modified,
        metadata: meta,
        missing_meta,
        object_lock_legal_hold_status,
        object_lock_mode,
        object_lock_retain_until_date,
        parts_count,
        replication_status,
        request_charged,
        restore,
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        server_side_encryption,
        storage_class,
        tag_count,
        version_id,
        website_redirect_location,
    } = output;
    Ok(dto::GetObjectOutput {
        body: body(blob)?,
        delete_marker,
        accept_ranges,
        expiration: opaque(expiration),
        restore,
        last_modified: instant("last_modified", last_modified)?,
        content_length,
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
        missing_meta,
        version_id,
        cache_control,
        content_disposition,
        content_encoding,
        content_language,
        content_range,
        content_type,
        expires: opaque(expires),
        website_redirect_location,
        server_side_encryption: enumeration(server_side_encryption),
        metadata: metadata(meta),
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        bucket_key_enabled,
        storage_class: enumeration(storage_class),
        request_charged: enumeration(request_charged),
        replication_status: enumeration(replication_status),
        parts_count,
        tag_count,
        object_lock_mode: enumeration(object_lock_mode),
        object_lock_retain_until_date: instant("object_lock_retain_until_date", object_lock_retain_until_date)?,
        object_lock_legal_hold_status: enumeration(object_lock_legal_hold_status),
        ..Default::default()
    })
}

/// HeadObject.
pub(crate) fn head_object(output: oracle::HeadObjectOutput) -> Converted<dto::HeadObjectOutput> {
    let oracle::HeadObjectOutput {
        accept_ranges,
        archive_status,
        bucket_key_enabled,
        cache_control,
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
        content_disposition,
        content_encoding,
        content_language,
        content_length,
        content_range,
        content_type,
        delete_marker,
        e_tag,
        expiration,
        expires,
        last_modified,
        metadata: meta,
        missing_meta,
        object_lock_legal_hold_status,
        object_lock_mode,
        object_lock_retain_until_date,
        parts_count,
        replication_status,
        request_charged,
        restore,
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        server_side_encryption,
        storage_class,
        tag_count,
        version_id,
        website_redirect_location,
    } = output;
    Ok(dto::HeadObjectOutput {
        delete_marker,
        accept_ranges,
        expiration: opaque(expiration),
        restore,
        archive_status: enumeration(archive_status),
        last_modified: instant("last_modified", last_modified)?,
        content_length,
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
        missing_meta,
        version_id,
        cache_control,
        content_disposition,
        content_encoding,
        content_language,
        content_range,
        content_type,
        expires: opaque(expires),
        website_redirect_location,
        server_side_encryption: enumeration(server_side_encryption),
        metadata: metadata(meta),
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        bucket_key_enabled,
        storage_class: enumeration(storage_class),
        request_charged: enumeration(request_charged),
        replication_status: enumeration(replication_status),
        parts_count,
        tag_count,
        object_lock_mode: enumeration(object_lock_mode),
        object_lock_retain_until_date: instant("object_lock_retain_until_date", object_lock_retain_until_date)?,
        object_lock_legal_hold_status: enumeration(object_lock_legal_hold_status),
        ..Default::default()
    })
}

/// DeleteObject.
pub(crate) fn delete_object(output: oracle::DeleteObjectOutput) -> Converted<dto::DeleteObjectOutput> {
    let oracle::DeleteObjectOutput {
        delete_marker,
        request_charged,
        version_id,
    } = output;
    Ok(dto::DeleteObjectOutput {
        delete_marker,
        version_id,
        request_charged: enumeration(request_charged),
    })
}

/// DeleteObjects.
pub(crate) fn delete_objects(output: oracle::DeleteObjectsOutput) -> Converted<dto::DeleteObjectsOutput> {
    let oracle::DeleteObjectsOutput {
        deleted,
        errors,
        request_charged,
    } = output;
    let deleted = deleted
        .into_iter()
        .flatten()
        .map(
            |oracle::DeletedObject {
                 delete_marker,
                 delete_marker_version_id,
                 key,
                 version_id,
             }| {
                Ok(dto::DeletedObject {
                    key: object_key("deleted.key", key)?,
                    version_id,
                    delete_marker,
                    delete_marker_version_id,
                })
            },
        )
        .collect::<Converted<Vec<_>>>()?;
    let errors = errors
        .into_iter()
        .flatten()
        .map(
            |oracle::Error {
                 code,
                 key,
                 message,
                 version_id,
             }| {
                Ok(dto::Error {
                    key: object_key("errors.key", key)?,
                    version_id,
                    code,
                    message,
                })
            },
        )
        .collect::<Converted<Vec<_>>>()?;
    Ok(dto::DeleteObjectsOutput {
        deleted,
        request_charged: enumeration(request_charged),
        errors,
    })
}

/// CopyObject: the gateway output flattens the copy result's entity tag and time, and carries no
/// checksum of the copy.
pub(crate) fn copy_object(output: oracle::CopyObjectOutput) -> Converted<dto::CopyObjectOutput> {
    let oracle::CopyObjectOutput {
        bucket_key_enabled,
        copy_object_result,
        copy_source_version_id,
        expiration,
        request_charged,
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_encryption_context,
        ssekms_key_id,
        server_side_encryption,
        version_id,
    } = output;
    let oracle::CopyObjectResult {
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
        last_modified,
    } = required("copy_object_result", copy_object_result)?;
    Checksums {
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
    .none("copy_object_result.checksums")?;
    absent("copy_object_result.checksum_type", checksum_type.as_ref())?;
    Ok(dto::CopyObjectOutput {
        e_tag: required("copy_object_result.e_tag", entity_tag("copy_object_result.e_tag", e_tag)?)?,
        last_modified: instant("copy_object_result.last_modified", last_modified)?,
        expiration: opaque(expiration),
        copy_source_version_id,
        version_id,
        server_side_encryption: enumeration(server_side_encryption),
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        ssekms_encryption_context,
        bucket_key_enabled,
        request_charged: enumeration(request_charged),
    })
}
