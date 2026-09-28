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
//! gateway `PutObjectOutput` the gateway codec writes; and moving the live request body across
//! without reading a byte of it. A value one side cannot hold is a [`ConversionError`] naming the
//! member, never a silent drop or a default.
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
//! signatures until it is ported.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::{Mutex, PoisonError};

use super::s3s;
use bytes::Bytes;
use rustfs_gateway_stream::{ByteStream, PayloadRead, PayloadStream};
use s3s::dto as oracle;

use crate::compat::ConversionError;
use crate::{ChecksumAlgorithm, ChecksumSpec, ETag, OpaqueString, Timestamp, dto};

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
pub fn input_to_s3s(input: dto::PutObjectInput) -> Result<oracle::PutObjectInput, ConversionError> {
    let event_hold_named = [
        input.object_lock_event_hold.is_some(),
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
    let expires = input.expires.map(|value| super::expires(value.as_str())).transpose()?;
    let if_match = input.if_match.map(|value| etag_condition("if_match", &value)).transpose()?;
    let if_none_match = input
        .if_none_match
        .map(|value| etag_condition("if_none_match", &value))
        .transpose()?;
    let object_lock_retain_until_date = input
        .object_lock_retain_until_date
        .map(|at| instant("object_lock_retain_until_date", at))
        .transpose()?;
    // s3s answers "no metadata" with `None`, never with an empty map.
    let metadata = (!input.metadata.is_empty()).then(|| input.metadata.into_iter().collect());
    Ok(oracle::PutObjectInput {
        acl: input.acl.map(|value| value.as_str().to_owned().into()),
        body: input.body.map(streaming_blob),
        bucket: input.bucket.as_str().to_owned(),
        bucket_key_enabled: input.bucket_key_enabled,
        cache_control: input.cache_control,
        checksum_algorithm: input.checksum_algorithm.map(|value| value.as_str().to_owned().into()),
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
        content_disposition: input.content_disposition,
        content_encoding: input.content_encoding,
        content_language: input.content_language,
        content_length: Some(input.content_length),
        content_md5: input.content_md5,
        content_type: input.content_type,
        expected_bucket_owner: input.expected_bucket_owner,
        expires,
        grant_full_control: input.grant_full_control,
        grant_read: input.grant_read,
        grant_read_acp: input.grant_read_acp,
        grant_write_acp: input.grant_write_acp,
        if_match,
        if_none_match,
        key: input.key.as_str().to_owned(),
        metadata,
        object_lock_legal_hold_status: input
            .object_lock_legal_hold_status
            .map(|value| value.as_str().to_owned().into()),
        object_lock_mode: input.object_lock_mode.map(|value| value.as_str().to_owned().into()),
        object_lock_retain_until_date,
        request_payer: input.request_payer.map(|value| value.as_str().to_owned().into()),
        sse_customer_algorithm: input.sse_customer_algorithm,
        // The s3s input holds the key as a plain `String`; that is its contract, not this one's.
        sse_customer_key: input.sse_customer_key.map(|key| key.expose_secret().to_owned()),
        sse_customer_key_md5: input.sse_customer_key_md5,
        ssekms_encryption_context: input.ssekms_encryption_context,
        ssekms_key_id: input.ssekms_key_id,
        server_side_encryption: input.server_side_encryption.map(|value| value.as_str().to_owned().into()),
        storage_class: input.storage_class.map(|value| value.as_str().to_owned().into()),
        tagging: input.tagging,
        // MinIO's `?versionId=` on a PUT has no member in the gateway model. Only the authorised
        // replica write carries one, and it converts through `replica_input_to_s3s`.
        version_id: None,
        website_redirect_location: input.website_redirect_location,
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
    let mut present = [
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
    ]
    .into_iter()
    .filter_map(|(field, algorithm, value)| value.map(|value| (field, algorithm, value)));
    let checksum_spec = match (present.next(), present.next()) {
        (None, _) => None,
        (Some(_), Some(_)) => {
            return Err(ConversionError {
                field: "checksum_spec",
                reason: "the gateway output carries one checksum, so a second would be lost",
            });
        }
        (Some((field, algorithm, value)), None) => {
            Some(ChecksumSpec::parse_header(algorithm.header_name(), &value).map_err(|_| ConversionError {
                field,
                reason: "not a checksum value of this algorithm's width",
            })?)
        }
    };
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
