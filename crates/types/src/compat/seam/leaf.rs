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

//! The hand-written leaf conversions the generated seam (`super::generated`) calls: one function
//! per gateway scalar whose s3s spelling differs.
//!
//! Responsible for: timestamps, entity tags and conditions, checksum values and the checksum
//! fan-out, names, ranges, copy sources, upload ids, numbers carried as text, and moving a body
//! stream across in either direction without buffering it. A value the other side cannot hold is
//! a [`ConversionError`] naming the member, never a default.
//! NOT responsible for: structure and member matching, which is generated
//! (`crates/codegen/src/emit/seam`, rustfs/gateway#967).
//! Upstream: the gateway scalars and `super::s3s`. Downstream: `super::generated`.

use core::pin::Pin;
use core::task::{Context, Poll};

use super::s3s;
use bytes::Bytes;
use rustfs_gateway_stream::{ByteStream, PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders};
use s3s::dto as oracle;

use crate::compat::ConversionError;
use crate::{BucketName, ChecksumAlgorithm, ChecksumSpec, ETag, ObjectKey, RangeSpec, Timestamp, UploadIdClaim};

const fn refusal(field: &'static str, reason: &'static str) -> ConversionError {
    ConversionError { field, reason }
}

/// The instant as an s3s timestamp: epoch seconds with all nine fractional digits, the one s3s
/// form that carries nanoseconds exactly.
///
/// # Errors
///
/// An instant outside what s3s represents.
pub fn timestamp_to_s3s(field: &'static str, at: Timestamp) -> Result<oracle::Timestamp, ConversionError> {
    let spelled = format!("{}.{:09}", at.secs(), at.subsec_nanos());
    oracle::Timestamp::parse(oracle::TimestampFormat::EpochSeconds, &spelled)
        .map_err(|_| refusal(field, "an instant outside what the s3s shape can hold"))
}

/// The s3s timestamp as a gateway instant, to the millisecond s3s spells.
///
/// # Errors
///
/// An instant the gateway timestamp cannot hold.
pub fn timestamp_from_s3s(field: &'static str, at: &oracle::Timestamp) -> Result<Timestamp, ConversionError> {
    // s3s spells an instant to the millisecond at most (RFC 3339 here, and the same on the wire),
    // so a sub-millisecond digit never reached a client of the legacy stack either.
    let mut spelled = Vec::new();
    at.format(oracle::TimestampFormat::DateTime, &mut spelled)
        .map_err(|_| refusal(field, "an s3s instant that has no RFC 3339 spelling"))?;
    let spelled = String::from_utf8(spelled).map_err(|_| refusal(field, "an s3s instant spelled outside ASCII"))?;
    Timestamp::parse(&spelled, crate::TimestampFormat::Iso8601)
        .map_err(|_| refusal(field, "an instant outside what the gateway timestamp can hold"))
}

/// The entity tag as the s3s value.
#[must_use]
pub fn etag_to_s3s(etag: &ETag) -> oracle::ETag {
    if etag.is_weak() {
        oracle::ETag::Weak(etag.opaque_tag().to_owned())
    } else {
        oracle::ETag::Strong(etag.opaque_tag().to_owned())
    }
}

/// The s3s entity tag as the gateway value.
///
/// # Errors
///
/// A tag the gateway entity-tag grammar rejects.
pub fn etag_from_s3s(field: &'static str, etag: oracle::ETag) -> Result<ETag, ConversionError> {
    match etag {
        oracle::ETag::Strong(value) => ETag::new(value),
        oracle::ETag::Weak(value) => ETag::new_weak(value),
    }
    .map_err(|_| refusal(field, "not an entity tag the gateway can write"))
}

/// A conditional header value as the s3s condition.
///
/// # Errors
///
/// A value the s3s condition grammar rejects.
pub fn etag_condition_from_text(field: &'static str, value: &str) -> Result<oracle::ETagCondition, ConversionError> {
    oracle::ETagCondition::parse_http_header(value.as_bytes())
        .map_err(|_| refusal(field, "not an entity-tag condition the s3s input can hold"))
}

/// `x-amz-copy-source` as the s3s copy source.
///
/// # Errors
///
/// A value the s3s copy-source grammar rejects.
pub fn copy_source_to_s3s(field: &'static str, value: &str) -> Result<oracle::CopySource, ConversionError> {
    oracle::CopySource::parse(value).map_err(|_| refusal(field, "not a copy source the s3s input can hold"))
}

/// The `Range` header as the s3s range.
///
/// # Errors
///
/// A range the s3s grammar rejects. The gateway keeps an unparseable range as text and serves
/// the whole object (RFC 9110 §14.2); s3s has no such state, so the seam refuses instead of
/// guessing.
pub fn range_to_s3s(field: &'static str, range: &RangeSpec) -> Result<oracle::Range, ConversionError> {
    oracle::Range::parse(range.as_str()).map_err(|_| refusal(field, "not a byte range the s3s input can hold"))
}

/// The claimed upload id, as the plain string the s3s input holds.
#[must_use]
pub fn upload_id_to_s3s(claim: &UploadIdClaim) -> String {
    claim.wire_for_compat_seam().to_owned()
}

/// A number the gateway keeps as wire text (`part-number-marker`) as the s3s integer.
///
/// # Errors
///
/// Text that is not a 32-bit integer.
pub fn parse_i32(field: &'static str, value: &str) -> Result<i32, ConversionError> {
    value.parse().map_err(|_| refusal(field, "not a 32-bit integer"))
}

/// A bucket name an s3s answer carries, as the gateway name.
///
/// # Errors
///
/// A name the gateway bucket grammar rejects.
pub fn bucket_name(field: &'static str, value: String) -> Result<BucketName, ConversionError> {
    BucketName::new(value).map_err(|_| refusal(field, "not a bucket name the gateway can write"))
}

/// An object key an s3s answer carries, as the gateway key.
///
/// # Errors
///
/// A key the gateway key grammar rejects.
pub fn object_key(field: &'static str, value: String) -> Result<ObjectKey, ConversionError> {
    ObjectKey::new(value).map_err(|_| refusal(field, "not an object key the gateway can write"))
}

/// The per-algorithm s3s checksum member for `algorithm`: the gateway spec's base64 value when the
/// spec is of that algorithm.
#[must_use]
pub fn checksum_value(spec: Option<&ChecksumSpec>, algorithm: ChecksumAlgorithm) -> Option<String> {
    spec.filter(|spec| spec.algorithm() == algorithm)
        .map(|spec| spec.render_base64().to_owned())
}

/// The per-algorithm s3s checksum members as one gateway spec.
///
/// # Errors
///
/// Two members set at once (the gateway carries one checksum, so a second would be lost), or a
/// value not of its algorithm's width.
pub fn checksum_spec_from_s3s<const N: usize>(
    members: [(&'static str, ChecksumAlgorithm, Option<String>); N],
) -> Result<Option<ChecksumSpec>, ConversionError> {
    let mut present = members
        .into_iter()
        .filter_map(|(field, algorithm, value)| value.map(|value| (field, algorithm, value)));
    match (present.next(), present.next()) {
        (None, _) => Ok(None),
        (Some(_), Some(_)) => Err(refusal(
            "checksum_spec",
            "the gateway shape carries one checksum, so a second would be lost",
        )),
        (Some((field, algorithm, value)), None) => ChecksumSpec::parse_header(algorithm.header_name(), &value)
            .map(Some)
            .map_err(|_| refusal(field, "not a checksum value of this algorithm's width")),
    }
}

/// The raw request a member only the legacy decoder reads is decoded from: the query exactly as it
/// arrived, without its `?`, and every accepted header line. An adapter builds it from its
/// [`GatewayRequestContext`](super::request_context::GatewayRequestContext) with [`RequestWire::of`].
#[derive(Clone, Copy, Debug)]
pub struct RequestWire<'a> {
    /// The query exactly as it arrived, without its `?`; empty when there is none.
    pub raw_query: &'a str,
    /// Every accepted header line.
    pub headers: &'a http::HeaderMap,
}

impl<'a> RequestWire<'a> {
    /// The raw query and header lines `context` holds.
    #[must_use]
    pub fn of(context: &'a super::request_context::GatewayRequestContext) -> Self {
        Self {
            raw_query: &context.raw_query,
            headers: &context.headers,
        }
    }
}

/// A member the legacy decoder reads from the query parameter `name`: absent when the parameter
/// is, its decoded value when it appears once. The query is split into pairs exactly as the legacy
/// decoder splits it: as an `application/x-www-form-urlencoded` body, on `&`, each piece at its
/// first `=`, `+` read as a space and percent escapes decoded.
///
/// # Errors
///
/// The parameter appearing more than once, which the legacy decoder refuses, named by the
/// parameter; [`super::error::refusal_from_conversion`] answers it as that decoder did.
pub fn legacy_query(wire: &RequestWire<'_>, name: &'static str) -> Result<Option<String>, ConversionError> {
    let mut values = form_pairs(wire.raw_query)
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value);
    match (values.next(), values.next()) {
        (None, _) => Ok(None),
        (Some(value), None) => Ok(Some(value)),
        (Some(_), Some(_)) => Err(refusal(name, super::error::LEGACY_DUPLICATE_QUERY)),
    }
}

/// The name/value pairs of an `application/x-www-form-urlencoded` query, split as the legacy
/// decoder splits one: on `&`, skipping empty pieces; each piece at its first `=` (a piece without
/// one is a name with an empty value); `+` as a space; percent escapes decoded, an invalid one kept
/// as written; bytes that are not UTF-8 replaced.
fn form_pairs(query: &str) -> impl Iterator<Item = (String, String)> + '_ {
    query.split('&').filter(|piece| !piece.is_empty()).map(|piece| {
        let (name, value) = piece.split_once('=').unwrap_or((piece, ""));
        (form_decode(name), form_decode(value))
    })
}

fn form_decode(text: &str) -> String {
    let spaced = text.replace('+', " ");
    percent_encoding::percent_decode_str(&spaced).decode_utf8_lossy().into_owned()
}

/// A member the legacy decoder reads from the header `name` as a boolean: absent when the header
/// is absent or empty, `true` for `true` and `True`, `false` for `false` and `False`.
///
/// # Errors
///
/// Any other value, or more than one line, which the legacy decoder refuses, named by the header;
/// [`super::error::refusal_from_conversion`] answers it as that decoder did. Refusing here is what
/// keeps a value the legacy decoder rejects from reaching a RustFS body that re-reads the raw header
/// with a looser grammar.
pub fn legacy_bool_header(wire: &RequestWire<'_>, name: &'static str) -> Result<Option<bool>, ConversionError> {
    let mut lines = wire.headers.get_all(name).iter();
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return if wire.headers.contains_key(name) {
            Err(refusal(name, super::error::LEGACY_DUPLICATE_HEADER))
        } else {
            Ok(None)
        };
    };
    match line.as_bytes() {
        b"" => Ok(None),
        b"true" | b"True" => Ok(Some(true)),
        b"false" | b"False" => Ok(Some(false)),
        _ => Err(refusal(name, super::error::LEGACY_INVALID_BOOLEAN)),
    }
}

/// The live gateway body as the s3s streaming body, unread.
#[must_use]
pub fn streaming_blob(stream: ByteStream) -> oracle::StreamingBlob {
    super::put_object::streaming_blob(stream)
}

/// The s3s streaming body a RustFS answer carries, as the gateway body, unread.
#[must_use]
pub fn byte_stream(blob: oracle::StreamingBlob) -> ByteStream {
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
