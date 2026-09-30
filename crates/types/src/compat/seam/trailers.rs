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

//! An upload's trailer section, handed to a RustFS app body as the legacy stack hands it
//! (rustfs/gateway#1148).
//!
//! Responsible for: [`LegacyTrailers`], the handle a RustFS body reads the trailer section of an
//! aws-chunked upload from, with the legacy stack's handle's timing and contents — unfilled until
//! the body has been read to its end, then every field of the section but
//! `x-amz-trailer-signature`, readable in place or taken once, and unfilled for good when the body
//! ended without a section; [`LegacyTrailers::publishing`], the gateway body that fills the handle
//! at the moment the gateway hands over the end of the body, before that end reaches the reader;
//! [`legacy_attaches_trailers`], which requests the legacy stack attaches a handle to; and
//! [`legacy_checksum_algorithm`], the upload's checksum algorithm as the legacy decoder reads it,
//! which picks the trailer field RustFS answers with.
//! NOT responsible for: verifying the section (the gateway's ingest verifies the trailer signature
//! and the declared checksum before it hands over the end), or putting the handle where a RustFS
//! body looks for it (`request_context::request_to_legacy` puts it in the request's extensions).
//! Upstream: the gateway request body (`rustfs-gateway-stream`). Downstream:
//! `request_context::request_to_legacy`, and the RustFS ring-2 adapter, whose trailer adapter reads
//! the handle where it reads the legacy one today.
//!
//! # Why a handle of its own
//!
//! The legacy request's trailer member holds the legacy stack's own handle, which has no public
//! constructor, so the seam cannot fill that member. Legacy RustFS reads the handle through one
//! adapter (`rustfs/src/app/trailer_adapter.rs:22-44` on rustfs/rustfs `e870a6d25b`) and two direct
//! reads (`rustfs/src/app/object/shared.rs:585-590`, `rustfs/src/app/multipart_usecase.rs:1450`),
//! each of which asks one question — the value of one field, or none yet — so this handle answers
//! the same question with the same timing, and the adapter reads it from the request's extensions.
//!
//! It is a shared trailer slot, which the gateway's own pipeline never holds
//! (`scripts/check_no_shared_trailers.sh`: its trailers travel inside the end-of-body event). It
//! lives only on the legacy side of the seam, because every RustFS reader asks a shared handle; it
//! is filled inside that event, before the end reaches the reader, and keeps "not arrived" apart
//! from "arrived with no field", the confusion that guard exists to prevent.
//!
//! The three states are read differently, so each is kept exactly: RustFS echoes the trailer's
//! checksum in place of the header's once the handle is filled, a field missing from it included,
//! and keeps the header's while the handle is unfilled (`apply_trailing_checksums`,
//! `rustfs/src/app/object/shared.rs:583-615` on rustfs/rustfs `3268c42e00`). An aws-chunked upload
//! that declares no trailer leaves the legacy handle unfilled for good, so it leaves this one
//! unfilled too.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::{Arc, Mutex, PoisonError};

use http::{HeaderMap, HeaderName};
use rustfs_gateway_stream::{ByteStream, PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders};

use super::error::{LEGACY_DUPLICATE_HEADER, LEGACY_INVALID_HEADER};
use super::s3s::dto::ChecksumAlgorithm;
use crate::compat::ConversionError;

const fn refusal(field: &'static str, reason: &'static str) -> ConversionError {
    ConversionError { field, reason }
}

/// The field a signed trailer section carries its signature in, which the legacy handle leaves
/// out.
const TRAILER_SIGNATURE: HeaderName = HeaderName::from_static("x-amz-trailer-signature");

/// Every `x-amz-content-sha256` value under which the legacy stack decodes an aws-chunked body.
const STREAMING_PAYLOADS: [&[u8]; 5] = [
    b"STREAMING-UNSIGNED-PAYLOAD-TRAILER",
    b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
    b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
    b"STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD",
    b"STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER",
];

/// Whether the legacy stack attaches a trailer handle to a request, declared trailer or not: one
/// whose signature it verified as SigV4 (`verified_by_sigv4`: the handler's principal carries a
/// verified scope) and whose `x-amz-content-sha256` names an aws-chunked payload. An anonymous
/// request, a SigV2 one and a plain body get none.
#[must_use]
pub fn legacy_attaches_trailers(verified_by_sigv4: bool, headers: &HeaderMap) -> bool {
    verified_by_sigv4
        && headers
            .get("x-amz-content-sha256")
            .is_some_and(|value| STREAMING_PAYLOADS.contains(&value.as_bytes()))
}

/// The checksum headers an `x-amz-trailer` declaration may name, as the legacy decoder pairs each
/// with its algorithm.
const TRAILER_ALGORITHMS: [(&str, &str); 10] = [
    ("x-amz-checksum-crc32", "CRC32"),
    ("x-amz-checksum-crc32c", "CRC32C"),
    ("x-amz-checksum-sha1", "SHA1"),
    ("x-amz-checksum-sha256", "SHA256"),
    ("x-amz-checksum-crc64nvme", "CRC64NVME"),
    ("x-amz-checksum-sha512", "SHA512"),
    ("x-amz-checksum-md5", "MD5"),
    ("x-amz-checksum-xxhash64", "XXHASH64"),
    ("x-amz-checksum-xxhash3", "XXHASH3"),
    ("x-amz-checksum-xxhash128", "XXHASH128"),
];

/// The one value of the optional header `name` as the legacy decoder reads one: absent when the
/// header is absent or empty, and refused when it appears twice or is not text.
fn legacy_optional_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<Option<&'a str>, ConversionError> {
    let mut lines = headers.get_all(name).iter();
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return if headers.contains_key(name) {
            Err(refusal(name, LEGACY_DUPLICATE_HEADER))
        } else {
            Ok(None)
        };
    };
    if line.is_empty() {
        return Ok(None);
    }
    line.to_str().map(Some).map_err(|_| refusal(name, LEGACY_INVALID_HEADER))
}

/// An upload's `checksum_algorithm` as the legacy decoder reads it from the request's header lines,
/// for the RustFS profile (rustfs/gateway#1148): the value of `x-amz-checksum-algorithm` when it has one, otherwise the
/// algorithm of the one checksum header `x-amz-trailer` names (a name matched without regard to
/// case, any other name passed over), otherwise none.
///
/// The gateway input's member is read from `x-amz-sdk-checksum-algorithm`, the header the model
/// binds; legacy RustFS never read that one into the member, and it reads the member to choose the
/// trailing checksum it echoes in its answer (`rustfs/src/app/object/put.rs:1374-1378`,
/// `rustfs/src/app/multipart_usecase.rs:1449-1470` on rustfs/rustfs `3268c42e00`), so the RustFS
/// profile's adapter hands it this reading instead, for `PutObject` and `UploadPart`, the two
/// operations whose RustFS body reads the member.
///
/// Legacy-compat (rustfs/backlog#2684): legacy RustFS takes an upload's checksum algorithm from
/// `x-amz-checksum-algorithm` or the `x-amz-trailer` declaration and never from
/// `x-amz-sdk-checksum-algorithm`, the header the model binds; questionable because a client that
/// names its algorithm only there gets no trailing checksum echoed; intended future: hand RustFS
/// the model's member once the RustFS body reads the gateway input.
///
/// # Errors
///
/// Either header appearing twice or not text, and a declaration naming two checksum headers, each
/// refused by the header's name as the legacy decoder refuses them;
/// [`super::error::refusal_from_conversion`] answers each as that decoder did.
pub fn legacy_checksum_algorithm(headers: &HeaderMap) -> Result<Option<ChecksumAlgorithm>, ConversionError> {
    if let Some(value) = legacy_optional_header(headers, "x-amz-checksum-algorithm")? {
        return Ok(Some(ChecksumAlgorithm::from(value.to_owned())));
    }
    let Some(declared) = legacy_optional_header(headers, "x-amz-trailer")? else {
        return Ok(None);
    };
    let mut algorithm = None;
    for name in declared.split(',').map(str::trim).filter(|name| !name.is_empty()) {
        let Some((_, named)) = TRAILER_ALGORITHMS
            .iter()
            .find(|(header, _)| name.eq_ignore_ascii_case(header))
        else {
            continue;
        };
        if algorithm.replace(*named).is_some() {
            return Err(refusal("x-amz-trailer", LEGACY_INVALID_HEADER));
        }
    }
    Ok(algorithm.map(|named| ChecksumAlgorithm::from(named.to_owned())))
}

/// The trailer section of one upload, as a RustFS body reads it; see the module documentation.
///
/// Clones share one section, as clones of the legacy handle do.
#[derive(Clone, Debug, Default)]
pub struct LegacyTrailers(Arc<Mutex<Option<HeaderMap>>>);

impl LegacyTrailers {
    /// Whether the section has arrived: `false` until the body has been read to its end, and for
    /// good when the body ended without a section.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).is_some()
    }

    /// Takes the section, once: a second call answers `None`.
    #[must_use]
    pub fn take(&self) -> Option<HeaderMap> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }

    /// Reads the section in place, when it has arrived.
    pub fn read<R>(&self, read: impl FnOnce(&HeaderMap) -> R) -> Option<R> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).as_ref().map(read)
    }

    /// `body`, which fills this handle with its trailer section at its end — the moment it hands
    /// the reader that end, and before the reader can see it — and then ends with no trailer
    /// section of its own, so a reader that cannot carry one (the legacy streaming body) ends
    /// normally.
    ///
    /// A body that ends without a section leaves the handle unfilled, and one whose section holds
    /// nothing but the trailer signature fills it with no field, each as the legacy stack leaves
    /// its own. Every chunk, every error and the length are the body's own.
    #[must_use]
    pub fn publishing(&self, body: ByteStream) -> ByteStream {
        let publishing = Publishing {
            body,
            trailers: self.clone(),
        };
        ByteStream::new(Box::pin(publishing)).expect("a ByteStream's own capabilities agree with its length") // the wrapper reports the body's own caps and length, validated when the body was built
    }

    fn publish(&self, trailers: TrailingHeaders) {
        if trailers.is_empty() {
            return;
        }
        let mut section = trailers.into_header_map();
        section.remove(TRAILER_SIGNATURE);
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(section);
    }
}

/// The body [`LegacyTrailers::publishing`] returns.
struct Publishing {
    body: ByteStream,
    trailers: LegacyTrailers,
}

impl PayloadStream for Publishing {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        match Pin::new(&mut this.body).poll_read(cx) {
            Poll::Ready(Ok(PayloadRead::Eof { trailers })) => {
                this.trailers.publish(trailers);
                Poll::Ready(Ok(PayloadRead::Eof {
                    trailers: TrailingHeaders::empty(),
                }))
            }
            other => other,
        }
    }

    fn caps(&self) -> PayloadCaps {
        self.body.caps()
    }

    fn len_hint(&self) -> Option<u64> {
        self.body.len_hint()
    }
}
