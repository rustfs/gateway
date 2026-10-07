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

//! The PutObject migration seam: a pure conversion between the gateway typed shapes and the s3s
//! DTO of the revision this file is compiled against (`super::s3s`).
//!
//! Responsible for: turning a decoded gateway `PutObjectInput` into the s3s `PutObjectInput` a
//! RustFS app body receives today; turning the s3s `PutObjectOutput` that body returns into the
//! gateway `PutObjectOutput` the gateway codec writes; the same two conversions the other way
//! round for a RustFS use case ported to gateway types behind the legacy stack
//! (rustfs/backlog#2749); and moving a live body across in either direction without reading a
//! byte of it. A value one side cannot hold is a [`ConversionError`] naming the member, never a
//! silent drop or a default.
//! NOT responsible for: request context (`uri`, headers, extensions, credentials, region,
//! trailers), routing, authentication, or choosing a revision: this one source is compiled once per
//! seam revision in `compat.rs`.
//! Upstream: the generated dto and `rustfs-gateway-stream`. Downstream: the goldens decode/encode
//! diff under every seam revision (rustfs/backlog#1762), and the RustFS ring-2 adapter through the
//! revision RustFS links (rustfs/backlog#1752).
//!
//! # Direction
//!
//! Input goes gateway → s3s and output goes s3s → gateway, because that is the migration: the
//! gateway decodes and encodes the wire, and the RustFS app body in between keeps its s3s
//! signatures until it is ported. While it is being ported the legacy stack still decodes and
//! encodes the wire, so the reverse pair ([`input_from_s3s`], [`output_to_s3s`]) carries a
//! gateway-typed use case behind it.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::{Mutex, PoisonError};

use super::s3s;
use bytes::Bytes;
use rustfs_gateway_stream::{ByteStream, PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders};
use s3s::dto as oracle;

use crate::compat::ConversionError;
use crate::{BucketName, ChecksumAlgorithm, ChecksumSpec, ETag, ObjectKey, OpaqueString, SseCustomerKey, Timestamp, dto};

/// Every member of the gateway `PutObjectInput` that [`input_to_s3s`] maps.
///
/// The gateway DTO may not be destructured exhaustively (ADR-0004 P3), so the conversion declares
/// its members here and the goldens diff pins the count to `generated/dto/field_counts.txt`.
pub const GATEWAY_INPUT_MEMBERS: &[&str] = &[
    "acl",
    "body",
    "bucket",
    "cache_control",
    "content_disposition",
    "content_encoding",
    "content_language",
    "content_length",
    "content_md5",
    "checksum_spec",
    "content_type",
    "checksum_algorithm",
    "expires",
    "if_match",
    "if_none_match",
    "grant_full_control",
    "grant_read",
    "grant_read_acp",
    "grant_write_acp",
    "key",
    "write_offset_bytes",
    "metadata",
    "server_side_encryption",
    "storage_class",
    "website_redirect_location",
    "sse_customer_algorithm",
    "sse_customer_key",
    "sse_customer_key_md5",
    "ssekms_key_id",
    "ssekms_encryption_context",
    "bucket_key_enabled",
    "request_payer",
    "tagging",
    "object_lock_mode",
    "object_lock_retain_until_date",
    "object_lock_legal_hold_status",
    "object_lock_event_hold",
    "object_lock_event_hold_duration_days",
    "object_lock_event_hold_duration_years",
    "expected_bucket_owner",
];

/// The Object Lock event-hold members of the 2026-09-17 model (rustfs/gateway#815), which no
/// pinned s3s revision carries: its `PutObjectInput` has no such member, and the RustFS handlers
/// behind it store no event hold. A request naming one is refused rather than handed over with
/// the hold silently dropped — a WORM instruction the store did not apply is worse than a `400`
/// (`rd-put-0009`).
const EVENT_HOLD_MEMBERS: [&str; 3] = [
    "object_lock_event_hold",
    "object_lock_event_hold_duration_days",
    "object_lock_event_hold_duration_years",
];

/// Every member of the gateway `PutObjectOutput` that [`output_from_s3s`] sets.
pub const GATEWAY_OUTPUT_MEMBERS: &[&str] = &[
    "expiration",
    "e_tag",
    "checksum_spec",
    "checksum_type",
    "server_side_encryption",
    "version_id",
    "sse_customer_algorithm",
    "sse_customer_key_md5",
    "ssekms_key_id",
    "ssekms_encryption_context",
    "bucket_key_enabled",
    "size",
    "request_charged",
];

/// An optional header member as the legacy decoder hands it over: it reads a header whose value
/// is empty as absent, before parsing it (rustfs/gateway#1076).
fn text(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

/// [`text`] for an enumeration member, spelled as the legacy input holds it.
fn named(value: Option<&str>) -> Option<String> {
    value.filter(|value| !value.is_empty()).map(str::to_owned)
}

/// Converts a decoded gateway input into the s3s input a RustFS app body receives.
///
/// The body is moved, not read: the s3s input's body is the gateway's live stream behind an
/// adapter, and no byte of it is polled here.
///
/// # Errors
///
/// [`ConversionError`] when a member the gateway kept as wire text is one the s3s input can only
/// hold parsed — an `Expires` that is not an HTTP-date, on a revision that holds `Expires` parsed
/// (the gateway keeps it opaque, `q-timestamp-0005`; see the enclosing module's `expires` hook),
/// an entity-tag condition the s3s grammar rejects — an instant outside what s3s represents, or
/// an Object Lock event hold, which no pinned s3s input can hold (`EVENT_HOLD_MEMBERS`).
///
/// An optional header member the gateway holds as an empty value crosses as absent, as the legacy
/// decoder reads it.
pub fn input_to_s3s(input: dto::PutObjectInput) -> Result<oracle::PutObjectInput, ConversionError> {
    let event_hold_named = [
        named(input.object_lock_event_hold.as_ref().map(|value| value.as_str())).is_some(),
        input.object_lock_event_hold_duration_days.is_some(),
        input.object_lock_event_hold_duration_years.is_some(),
    ];
    if let Some(index) = event_hold_named.iter().position(|named| *named) {
        return Err(ConversionError {
            field: EVENT_HOLD_MEMBERS[index],
            reason: "an Object Lock event hold, which the pinned s3s input cannot hold and RustFS does not store",
        });
    }
    let checksum = input.checksum_spec;
    let checksum_value = |algorithm: ChecksumAlgorithm| {
        checksum
            .filter(|spec| spec.algorithm() == algorithm)
            .map(|spec| spec.render_base64().to_owned())
    };
    let expires = input
        .expires
        .filter(|value| !value.as_str().is_empty())
        .map(|value| super::expires(value.as_str()))
        .transpose()?;
    let if_match = text(input.if_match)
        .map(|value| etag_condition("if_match", &value))
        .transpose()?;
    let if_none_match = text(input.if_none_match)
        .map(|value| etag_condition("if_none_match", &value))
        .transpose()?;
    let object_lock_retain_until_date = input
        .object_lock_retain_until_date
        .map(|at| instant("object_lock_retain_until_date", at))
        .transpose()?;
    // s3s answers "no metadata" with `None`, never with an empty map.
    let metadata = (!input.metadata.is_empty()).then(|| input.metadata.into_iter().collect());
    Ok(oracle::PutObjectInput {
        acl: named(input.acl.as_ref().map(|value| value.as_str())).map(Into::into),
        body: input.body.map(streaming_blob),
        bucket: input.bucket.as_str().to_owned(),
        bucket_key_enabled: input.bucket_key_enabled,
        cache_control: text(input.cache_control),
        checksum_algorithm: named(input.checksum_algorithm.as_ref().map(|value| value.as_str())).map(Into::into),
        checksum_crc32: checksum_value(ChecksumAlgorithm::Crc32),
        checksum_crc32c: checksum_value(ChecksumAlgorithm::Crc32c),
        checksum_crc64nvme: checksum_value(ChecksumAlgorithm::Crc64Nvme),
        checksum_md5: checksum_value(ChecksumAlgorithm::Md5),
        checksum_sha1: checksum_value(ChecksumAlgorithm::Sha1),
        checksum_sha256: checksum_value(ChecksumAlgorithm::Sha256),
        checksum_sha512: checksum_value(ChecksumAlgorithm::Sha512),
        checksum_xxhash128: checksum_value(ChecksumAlgorithm::XxHash128),
        checksum_xxhash3: checksum_value(ChecksumAlgorithm::XxHash3),
        checksum_xxhash64: checksum_value(ChecksumAlgorithm::XxHash64),
        content_disposition: text(input.content_disposition),
        content_encoding: text(input.content_encoding),
        content_language: text(input.content_language),
        content_length: Some(input.content_length),
        content_md5: text(input.content_md5),
        content_type: text(input.content_type),
        expected_bucket_owner: text(input.expected_bucket_owner),
        expires,
        grant_full_control: text(input.grant_full_control),
        grant_read: text(input.grant_read),
        grant_read_acp: text(input.grant_read_acp),
        grant_write_acp: text(input.grant_write_acp),
        if_match,
        if_none_match,
        key: input.key.as_str().to_owned(),
        metadata,
        object_lock_legal_hold_status: named(input.object_lock_legal_hold_status.as_ref().map(|value| value.as_str()))
            .map(Into::into),
        object_lock_mode: named(input.object_lock_mode.as_ref().map(|value| value.as_str())).map(Into::into),
        object_lock_retain_until_date,
        request_payer: named(input.request_payer.as_ref().map(|value| value.as_str())).map(Into::into),
        sse_customer_algorithm: text(input.sse_customer_algorithm),
        // The s3s input holds the key as a plain `String`; that is its contract, not this one's.
        sse_customer_key: input.sse_customer_key.map(|key| key.expose_secret().to_owned()),
        sse_customer_key_md5: text(input.sse_customer_key_md5),
        ssekms_encryption_context: text(input.ssekms_encryption_context),
        ssekms_key_id: text(input.ssekms_key_id),
        server_side_encryption: named(input.server_side_encryption.as_ref().map(|value| value.as_str())).map(Into::into),
        storage_class: named(input.storage_class.as_ref().map(|value| value.as_str())).map(Into::into),
        tagging: text(input.tagging),
        // MinIO's `?versionId=` on a PUT has no member in the gateway model. Only the authorised
        // replica write carries one, and it converts through `replica_input_to_s3s`.
        version_id: None,
        website_redirect_location: text(input.website_redirect_location),
        write_offset_bytes: input.write_offset_bytes,
    })
}

/// Converts the input of the authorised replica write (`minio:PutObjectReplica`, in
/// `rustfs-gateway-dialect-minio`) into the s3s input a RustFS app body receives: [`input_to_s3s`],
/// plus the version id the replica must be stored under, in the MinIO member the pinned s3s reads
/// `?versionId=` into (rustfs/gateway#752).
///
/// Nothing else may call it with a version id a client chose: the gateway routes `?versionId=` on a
/// PUT to that operation only when the replication dialect is installed, and authorises it as
/// `s3:ReplicateObject` before decoding. An ordinary `PutObject` goes through [`input_to_s3s`] and
/// never carries one.
///
/// # Errors
///
/// As [`input_to_s3s`].
pub fn replica_input_to_s3s(input: dto::PutObjectInput, version_id: String) -> Result<oracle::PutObjectInput, ConversionError> {
    let mut converted = input_to_s3s(input)?;
    converted.version_id = Some(version_id);
    Ok(converted)
}

/// Converts a RustFS app body's whole answer — its output and the response headers it set beside
/// it — into the gateway output and the extra headers the gateway writes after it
/// (`Resp::with_extra_headers`). The legacy writer extends the output's headers with the body's
/// own, which replaces every value of a name the output already wrote, so a member whose header the
/// body set is left to that header here, and the gateway writes it as the body set it
/// (rustfs/gateway#1076). The generated operations have the same function.
///
/// # Errors
///
/// [`ConversionError`] as [`output_from_s3s`].
#[allow(clippy::needless_pass_by_value)]
pub fn answer_from_legacy(
    mut output: oracle::PutObjectOutput,
    headers: http::HeaderMap,
) -> Result<(dto::PutObjectOutput, http::HeaderMap), ConversionError> {
    let replaced = |name: &str| headers.contains_key(name);
    if replaced("x-amz-expiration") {
        output.expiration = None;
    }
    if replaced("etag") {
        output.e_tag = None;
    }
    for (name, member) in [
        ("x-amz-checksum-crc32", &mut output.checksum_crc32),
        ("x-amz-checksum-crc32c", &mut output.checksum_crc32c),
        ("x-amz-checksum-crc64nvme", &mut output.checksum_crc64nvme),
        ("x-amz-checksum-md5", &mut output.checksum_md5),
        ("x-amz-checksum-sha1", &mut output.checksum_sha1),
        ("x-amz-checksum-sha256", &mut output.checksum_sha256),
        ("x-amz-checksum-sha512", &mut output.checksum_sha512),
        ("x-amz-checksum-xxhash128", &mut output.checksum_xxhash128),
        ("x-amz-checksum-xxhash3", &mut output.checksum_xxhash3),
        ("x-amz-checksum-xxhash64", &mut output.checksum_xxhash64),
        ("x-amz-server-side-encryption-customer-algorithm", &mut output.sse_customer_algorithm),
        ("x-amz-server-side-encryption-customer-key-md5", &mut output.sse_customer_key_md5),
        ("x-amz-server-side-encryption-aws-kms-key-id", &mut output.ssekms_key_id),
        ("x-amz-server-side-encryption-context", &mut output.ssekms_encryption_context),
        ("x-amz-version-id", &mut output.version_id),
    ] {
        if replaced(name) {
            *member = None;
        }
    }
    if replaced("x-amz-checksum-type") {
        output.checksum_type = None;
    }
    if replaced("x-amz-server-side-encryption") {
        output.server_side_encryption = None;
    }
    if replaced("x-amz-server-side-encryption-bucket-key-enabled") {
        output.bucket_key_enabled = None;
    }
    if replaced("x-amz-object-size") {
        output.size = None;
    }
    if replaced("x-amz-request-charged") {
        output.request_charged = None;
    }
    Ok((output_from_s3s(output)?, headers))
}

/// Converts the s3s output a RustFS app body returned into the gateway output the codec writes.
///
/// # Errors
///
/// [`ConversionError`] when the s3s output holds something the gateway output cannot: no entity
/// tag, more than one checksum, or a value that is not well formed for its member.
pub fn output_from_s3s(output: oracle::PutObjectOutput) -> Result<dto::PutObjectOutput, ConversionError> {
    // Exhaustive on purpose: this is the pinned s3s struct, not a gateway DTO, and an oracle
    // re-pin that adds a member must be a compile error here rather than a member silently dropped.
    let oracle::PutObjectOutput {
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
        request_charged,
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_encryption_context,
        ssekms_key_id,
        server_side_encryption,
        size,
        version_id,
    } = output;
    let checksum_spec = checksum_spec_from([
        ("checksum_crc32", ChecksumAlgorithm::Crc32, checksum_crc32),
        ("checksum_crc32c", ChecksumAlgorithm::Crc32c, checksum_crc32c),
        ("checksum_crc64nvme", ChecksumAlgorithm::Crc64Nvme, checksum_crc64nvme),
        ("checksum_md5", ChecksumAlgorithm::Md5, checksum_md5),
        ("checksum_sha1", ChecksumAlgorithm::Sha1, checksum_sha1),
        ("checksum_sha256", ChecksumAlgorithm::Sha256, checksum_sha256),
        ("checksum_sha512", ChecksumAlgorithm::Sha512, checksum_sha512),
        ("checksum_xxhash128", ChecksumAlgorithm::XxHash128, checksum_xxhash128),
        ("checksum_xxhash3", ChecksumAlgorithm::XxHash3, checksum_xxhash3),
        ("checksum_xxhash64", ChecksumAlgorithm::XxHash64, checksum_xxhash64),
    ])?;
    let e_tag = match e_tag {
        Some(oracle::ETag::Strong(value)) => ETag::new(value),
        Some(oracle::ETag::Weak(value)) => ETag::new_weak(value),
        None => {
            return Err(ConversionError {
                field: "e_tag",
                reason: "a PutObject answer carries an entity tag and the gateway output cannot omit one",
            });
        }
    }
    .map_err(|_| ConversionError {
        field: "e_tag",
        reason: "not an entity tag the gateway can write",
    })?;
    Ok(dto::PutObjectOutput {
        expiration: expiration.map(OpaqueString::from),
        e_tag,
        checksum_spec,
        checksum_type: checksum_type.map(|value| dto::ChecksumType::custom(value.as_str().to_owned())),
        server_side_encryption: server_side_encryption.map(|value| dto::ServerSideEncryption::custom(value.as_str().to_owned())),
        version_id,
        sse_customer_algorithm,
        sse_customer_key_md5,
        ssekms_key_id,
        ssekms_encryption_context,
        bucket_key_enabled,
        size,
        request_charged: request_charged.map(|value| dto::RequestCharged::custom(value.as_str().to_owned())),
    })
}

/// The per-algorithm s3s checksum members as the one gateway spec.
fn checksum_spec_from(
    members: [(&'static str, ChecksumAlgorithm, Option<String>); 10],
) -> Result<Option<ChecksumSpec>, ConversionError> {
    let mut present = members
        .into_iter()
        .filter_map(|(field, algorithm, value)| value.map(|value| (field, algorithm, value)));
    match (present.next(), present.next()) {
        (None, _) => Ok(None),
        (Some(_), Some(_)) => Err(ConversionError {
            field: "checksum_spec",
            reason: "the gateway output carries one checksum, so a second would be lost",
        }),
        (Some((field, algorithm, value)), None) => {
            ChecksumSpec::parse_header(algorithm.header_name(), &value)
                .map(Some)
                .map_err(|_| ConversionError {
                    field,
                    reason: "not a checksum value of this algorithm's width",
                })
        }
    }
}

/// Members only the legacy decoder reads, which no gateway member holds: handed back beside the
/// gateway input by [`input_from_s3s`], never dropped, for the ported use case to apply as the
/// legacy stack did (rustfs/backlog#2749). Forward, only the authorised replica write carries
/// the member, through [`replica_input_to_s3s`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacyInput {
    /// MinIO's `?versionId=` on a PUT: the version the legacy stack stores a replica under.
    pub version_id: Option<String>,
}

/// Converts the s3s input the legacy stack decoded into the gateway input a ported RustFS use
/// case takes (rustfs/backlog#2749), with the legacy-only member beside it. The body is moved,
/// not read.
///
/// The gateway input requires `content_length`, which the legacy decoder leaves unset on an
/// upload with no wire `Content-Length` (an aws-chunked body over chunked transfer coding, whose
/// size is `x-amz-decoded-content-length`). The legacy stack resolves the authoritative size from
/// the request headers before it sizes anything (`resolve_put_object_authoritative_size` in
/// rustfs/rustfs `rustfs/src/app/object/put.rs`), and so must a caller of this conversion: fill
/// the s3s member from that resolution first, or the upload is refused here by name rather than
/// sized from the wrong length.
///
/// # Errors
///
/// [`ConversionError`] naming a member the gateway input cannot hold: no `Content-Length` (the
/// gateway requires one), a bucket or key outside the gateway grammar, an instant the gateway
/// cannot spell, two checksums at once or one of the wrong width, an `Expires` the revision holds
/// parsed and cannot spell (the enclosing module's `expires_text` hook), or an entity-tag
/// condition that is not a header value.
#[allow(clippy::too_many_lines)]
pub fn input_from_s3s(input: oracle::PutObjectInput) -> Result<(dto::PutObjectInput, LegacyInput), ConversionError> {
    // Exhaustive on purpose: an s3s re-pin that adds a member is a compile error, never a drop.
    let oracle::PutObjectInput {
        acl,
        body,
        bucket,
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
        content_length,
        content_md5,
        content_type,
        expected_bucket_owner,
        expires,
        grant_full_control,
        grant_read,
        grant_read_acp,
        grant_write_acp,
        if_match,
        if_none_match,
        key,
        metadata,
        object_lock_legal_hold_status,
        object_lock_mode,
        object_lock_retain_until_date,
        request_payer,
        sse_customer_algorithm,
        sse_customer_key,
        sse_customer_key_md5,
        ssekms_encryption_context,
        ssekms_key_id,
        server_side_encryption,
        storage_class,
        tagging,
        version_id,
        website_redirect_location,
        write_offset_bytes,
    } = input;
    let Some(content_length) = content_length else {
        return Err(ConversionError {
            field: "content_length",
            reason: "the gateway input requires a content length",
        });
    };
    let checksum_spec = checksum_spec_from([
        ("checksum_crc32", ChecksumAlgorithm::Crc32, checksum_crc32),
        ("checksum_crc32c", ChecksumAlgorithm::Crc32c, checksum_crc32c),
        ("checksum_crc64nvme", ChecksumAlgorithm::Crc64Nvme, checksum_crc64nvme),
        ("checksum_md5", ChecksumAlgorithm::Md5, checksum_md5),
        ("checksum_sha1", ChecksumAlgorithm::Sha1, checksum_sha1),
        ("checksum_sha256", ChecksumAlgorithm::Sha256, checksum_sha256),
        ("checksum_sha512", ChecksumAlgorithm::Sha512, checksum_sha512),
        ("checksum_xxhash128", ChecksumAlgorithm::XxHash128, checksum_xxhash128),
        ("checksum_xxhash3", ChecksumAlgorithm::XxHash3, checksum_xxhash3),
        ("checksum_xxhash64", ChecksumAlgorithm::XxHash64, checksum_xxhash64),
    ])?;
    let gateway = dto::PutObjectInput {
        acl: acl.map(|value| dto::Acl::custom(value.as_str().to_owned())),
        body: body.map(byte_stream),
        bucket: BucketName::new(bucket).map_err(|_| ConversionError {
            field: "bucket",
            reason: "not a bucket name the gateway can write",
        })?,
        cache_control,
        content_disposition,
        content_encoding,
        content_language,
        content_length,
        content_md5,
        checksum_spec,
        content_type,
        checksum_algorithm: checksum_algorithm.map(|value| dto::ChecksumAlgorithm::custom(value.as_str().to_owned())),
        expires: expires
            .map(|value| super::expires_text(&value))
            .transpose()?
            .map(OpaqueString::from),
        if_match: if_match.map(|value| condition_text("if_match", &value)).transpose()?,
        if_none_match: if_none_match
            .map(|value| condition_text("if_none_match", &value))
            .transpose()?,
        grant_full_control,
        grant_read,
        grant_read_acp,
        grant_write_acp,
        key: ObjectKey::new(key).map_err(|_| ConversionError {
            field: "key",
            reason: "not an object key the gateway can write",
        })?,
        write_offset_bytes,
        metadata: metadata.map(|map| map.into_iter().collect()).unwrap_or_default(),
        server_side_encryption: server_side_encryption.map(|value| dto::ServerSideEncryption::custom(value.as_str().to_owned())),
        storage_class: storage_class.map(|value| dto::StorageClass::custom(value.as_str().to_owned())),
        website_redirect_location,
        sse_customer_algorithm,
        // The s3s input holds the key as a plain `String`; the gateway rewraps it, never reads it.
        sse_customer_key: sse_customer_key.map(SseCustomerKey::new),
        sse_customer_key_md5,
        ssekms_key_id,
        ssekms_encryption_context,
        bucket_key_enabled,
        request_payer: request_payer.map(|value| dto::RequestPayer::custom(value.as_str().to_owned())),
        tagging,
        object_lock_mode: object_lock_mode.map(|value| dto::ObjectLockMode::custom(value.as_str().to_owned())),
        object_lock_retain_until_date: object_lock_retain_until_date
            .map(|at| instant_from("object_lock_retain_until_date", &at))
            .transpose()?,
        object_lock_legal_hold_status: object_lock_legal_hold_status
            .map(|value| dto::ObjectLockLegalHoldStatus::custom(value.as_str().to_owned())),
        // No pinned s3s input holds an event hold (`EVENT_HOLD_MEMBERS`), so none crosses.
        object_lock_event_hold: None,
        object_lock_event_hold_duration_days: None,
        object_lock_event_hold_duration_years: None,
        expected_bucket_owner,
    };
    Ok((gateway, LegacyInput { version_id }))
}

/// Converts the gateway output a ported RustFS use case returned into the s3s output the legacy
/// stack writes (rustfs/backlog#2749). Total: every gateway value has exactly one s3s spelling.
#[must_use]
pub fn output_to_s3s(output: dto::PutObjectOutput) -> oracle::PutObjectOutput {
    let checksum = output.checksum_spec;
    let checksum_value = |algorithm: ChecksumAlgorithm| {
        checksum
            .as_ref()
            .filter(|spec| spec.algorithm() == algorithm)
            .map(|spec| spec.render_base64().to_owned())
    };
    oracle::PutObjectOutput {
        bucket_key_enabled: output.bucket_key_enabled,
        checksum_crc32: checksum_value(ChecksumAlgorithm::Crc32),
        checksum_crc32c: checksum_value(ChecksumAlgorithm::Crc32c),
        checksum_crc64nvme: checksum_value(ChecksumAlgorithm::Crc64Nvme),
        checksum_md5: checksum_value(ChecksumAlgorithm::Md5),
        checksum_sha1: checksum_value(ChecksumAlgorithm::Sha1),
        checksum_sha256: checksum_value(ChecksumAlgorithm::Sha256),
        checksum_sha512: checksum_value(ChecksumAlgorithm::Sha512),
        checksum_type: output.checksum_type.map(|value| value.as_str().to_owned().into()),
        checksum_xxhash128: checksum_value(ChecksumAlgorithm::XxHash128),
        checksum_xxhash3: checksum_value(ChecksumAlgorithm::XxHash3),
        checksum_xxhash64: checksum_value(ChecksumAlgorithm::XxHash64),
        e_tag: Some(entity_tag(&output.e_tag)),
        expiration: output.expiration.map(OpaqueString::into_string),
        request_charged: output.request_charged.map(|value| value.as_str().to_owned().into()),
        sse_customer_algorithm: output.sse_customer_algorithm,
        sse_customer_key_md5: output.sse_customer_key_md5,
        ssekms_encryption_context: output.ssekms_encryption_context,
        ssekms_key_id: output.ssekms_key_id,
        server_side_encryption: output.server_side_encryption.map(|value| value.as_str().to_owned().into()),
        size: output.size,
        version_id: output.version_id,
    }
}

fn entity_tag(etag: &ETag) -> oracle::ETag {
    if etag.is_weak() {
        oracle::ETag::Weak(etag.opaque_tag().to_owned())
    } else {
        oracle::ETag::Strong(etag.opaque_tag().to_owned())
    }
}

/// The s3s condition as the conditional header text the gateway input holds.
fn condition_text(field: &'static str, condition: &oracle::ETagCondition) -> Result<String, ConversionError> {
    let header = condition.to_http_header().map_err(|_| ConversionError {
        field,
        reason: "an entity-tag condition that is not a header value",
    })?;
    header.to_str().map(str::to_owned).map_err(|_| ConversionError {
        field,
        reason: "an entity-tag condition spelled outside ASCII",
    })
}

/// The s3s instant as a gateway instant, to the millisecond s3s spells: a sub-millisecond digit
/// never reached a client of the legacy stack either.
fn instant_from(field: &'static str, at: &oracle::Timestamp) -> Result<Timestamp, ConversionError> {
    let mut spelled = Vec::new();
    at.format(oracle::TimestampFormat::DateTime, &mut spelled)
        .map_err(|_| ConversionError {
            field,
            reason: "an s3s instant that has no RFC 3339 spelling",
        })?;
    let spelled = String::from_utf8(spelled).map_err(|_| ConversionError {
        field,
        reason: "an s3s instant spelled outside ASCII",
    })?;
    Timestamp::parse(&spelled, crate::TimestampFormat::Iso8601).map_err(|_| ConversionError {
        field,
        reason: "an instant outside what the gateway timestamp can hold",
    })
}

fn etag_condition(field: &'static str, value: &str) -> Result<oracle::ETagCondition, ConversionError> {
    oracle::ETagCondition::parse_http_header(value.as_bytes()).map_err(|_| ConversionError {
        field,
        reason: "not an entity-tag condition the s3s input can hold",
    })
}

/// Spells the instant as epoch seconds with all nine fractional digits, the one s3s form that
/// carries nanoseconds exactly; the ISO 8601 rendering stops at milliseconds.
fn instant(field: &'static str, at: Timestamp) -> Result<oracle::Timestamp, ConversionError> {
    let spelled = format!("{}.{:09}", at.secs(), at.subsec_nanos());
    oracle::Timestamp::parse(oracle::TimestampFormat::EpochSeconds, &spelled).map_err(|_| ConversionError {
        field,
        reason: "an instant outside what the s3s input can hold",
    })
}

pub(super) fn streaming_blob(stream: ByteStream) -> oracle::StreamingBlob {
    oracle::StreamingBlob::new(GatewayBody {
        stream: Mutex::new(stream),
        done: false,
    })
}

/// The live gateway body, presented as the s3s streaming body.
///
/// The `Mutex` exists only because s3s requires `Sync` and the gateway producer is `Send` alone.
/// Polling goes through `get_mut`, which takes no lock; only the length query locks.
struct GatewayBody {
    stream: Mutex<ByteStream>,
    done: bool,
}

impl futures_core::Stream for GatewayBody {
    type Item = Result<Bytes, s3s::StdError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        let stream = this.stream.get_mut().unwrap_or_else(PoisonError::into_inner);
        let event = match Pin::new(stream).poll_read(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(event) => event,
        };
        Poll::Ready(match event {
            Ok(PayloadRead::Chunk(chunk)) => Some(Ok(chunk)),
            Ok(PayloadRead::Eof { trailers }) => {
                this.done = true;
                // s3s delivers trailers through the request context, which this seam does not
                // carry. Ending the body quietly would drop them, so the body fails instead.
                (!trailers.is_empty()).then(|| {
                    Err(Box::new(ConversionError {
                        field: "body",
                        reason: "the s3s body cannot carry trailer fields, which would be dropped",
                    }) as s3s::StdError)
                })
            }
            Err(error) => {
                this.done = true;
                Some(Err(Box::new(error)))
            }
        })
    }
}

impl s3s::stream::ByteStream for GatewayBody {
    fn remaining_length(&self) -> s3s::stream::RemainingLength {
        let remaining = self.stream.lock().ok().and_then(|stream| stream.remaining_length().get());
        match remaining.and_then(|length| usize::try_from(length).ok()) {
            Some(length) => s3s::stream::RemainingLength::new_exact(length),
            None => s3s::stream::RemainingLength::unknown(),
        }
    }
}

/// The s3s streaming body a RustFS answer carries, as the gateway body, unread.
#[must_use]
pub(super) fn byte_stream(blob: oracle::StreamingBlob) -> ByteStream {
    let remaining = s3s::stream::ByteStream::remaining_length(&blob)
        .exact()
        .and_then(|len| u64::try_from(len).ok());
    let body = S3sBody {
        blob,
        remaining,
        done: false,
    };
    ByteStream::new(Box::pin(body)).expect("S3sBody declares KNOWN_LENGTH exactly when it has a length") // caps are derived from the hint
}

/// An s3s body presented as a gateway push-model body.
struct S3sBody {
    blob: oracle::StreamingBlob,
    remaining: Option<u64>,
    done: bool,
}

impl PayloadStream for S3sBody {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(StreamError::new(rustfs_gateway_stream::StreamErrorKind::PolledAfterEof)));
        }
        match futures_core::Stream::poll_next(Pin::new(&mut this.blob), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.done = true;
                Poll::Ready(Ok(PayloadRead::Eof {
                    trailers: TrailingHeaders::empty(),
                }))
            }
            Poll::Ready(Some(Ok(chunk))) => {
                let chunk: Bytes = chunk;
                if let Some(remaining) = this.remaining.as_mut() {
                    *remaining = remaining.saturating_sub(chunk.len() as u64);
                }
                Poll::Ready(Ok(PayloadRead::Chunk(chunk)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.done = true;
                Poll::Ready(Err(StreamError::upstream(error)))
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
