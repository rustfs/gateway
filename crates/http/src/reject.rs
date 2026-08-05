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

//! Every way the acceptance layer can refuse a request, and what each refusal is on the wire.
//!
//! Responsible for: the [`WireReject`] set, its HTTP status and S3 error code, and the two
//! operational questions a caller must answer before it writes the response — may the body still
//! be read, and must the connection close.
//! NOT responsible for: rendering an error body (that is the response layer, P3-06), and any
//! authentication outcome — nothing here is ever a `403`.
//! Upstream: `http`, `rustfs-gateway-types`, this crate's `host`, `limits` and `metadata`. Downstream:
//! `wire`, and whatever serves the response.
//!
//! # Two rules the mapping encodes
//!
//! **A malformed request is a `400`, never a `403`.** A bad host, a duplicated header and a
//! broken chunk line are all client errors that have nothing to do with credentials. Answering
//! `403` would put them in the same bucket as a signature failure in every log and every metric,
//! which is precisely when an operator stops being able to tell an attack from a broken SDK.
//!
//! **A framing rejection ends the connection.** Once two components may have disagreed about
//! where the body ends, the bytes still in the socket have no owner. RFC 9112 §6.1 requires the
//! close for the `Content-Length`/`Transfer-Encoding` pair; this module extends it to every
//! framing verdict, and [`WireReject::may_read_body`] is `false` for all of them so no caller
//! drains a body it has just declared uninterpretable.

use http::{HeaderName, StatusCode};
use rustfs_gateway_types::ErrorCode;

use crate::host::HostError;
use crate::limits::LimitKind;
use crate::metadata::MetadataReject;

/// Why a request was refused before it reached the router.
///
/// Every variant is decidable from the request head alone. That is not a coincidence: a rejection
/// that needed body bytes would have to read them first, and reading the body of a request this
/// layer has already decided is malformed is how a limit check becomes a bandwidth amplifier.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireReject {
    /// W-1: `Content-Length` and `Transfer-Encoding` both present.
    ContentLengthTransferEncodingConflict,
    /// W-2: `Transfer-Encoding` repeated, or any coding other than a single `chunked`.
    TransferEncodingMalformed,
    /// W-3: a transfer coding on HTTP/2 or later, forbidden by RFC 9113 §8.2.2.
    TransferEncodingOnHttp2,
    /// W-4: `Content-Length` present more than once, equal values included.
    DuplicateContentLength,
    /// W-5: a `Content-Length` that is not a bare run of ASCII digits.
    MalformedContentLength,
    /// W-6: a chunk-size line that no two parsers would agree on.
    MalformedChunkFraming,
    /// A header with single-valued semantics appeared more than once.
    DuplicateSingleValuedHeader(&'static str),
    /// A query parameter with single-valued semantics appeared more than once.
    DuplicateSingleValuedQuery(&'static str),
    /// A query parameter name carried a percent-escape.
    ///
    /// Legitimate S3 parameter names are plain ASCII and are never escaped. An escaped spelling
    /// gives one parameter two names, so a duplicate check performed before decoding and a lookup
    /// performed after it see different requests.
    AmbiguousQueryParameterName,
    /// A header this layer or the signature attributes meaning to carried bytes that are not
    /// UTF-8.
    ///
    /// Unrelated headers are ignored instead — see [`crate::HeaderView`].
    NonUtf8SignificantHeader(HeaderName),
    /// A header value carried a control character, CR or LF included.
    MalformedHeaderValue(HeaderName),
    /// A user-metadata header failed its key or value rules.
    MalformedMetadata(MetadataReject),
    /// The request target was not a form this gateway serves, or carried a control character.
    MalformedRequestTarget,
    /// The query string could not be split into parameters.
    MalformedQuery,
    /// The effective host could not be determined; see [`HostError`].
    Host(HostError),
    /// A size ceiling was crossed; see [`LimitKind`].
    LimitExceeded(LimitKind),
}

impl WireReject {
    /// The HTTP status for this refusal: always `400`.
    ///
    /// An over-large body is the tempting exception, because `413` is what the HTTP semantics
    /// say. S3 does not send it: an upload past the single-PUT ceiling answers `400
    /// EntityTooLarge`, and clients branch on the error code in the XML body, not on the status.
    /// A `413` carrying an S3 error document is a shape no S3 client has ever seen. The status
    /// follows the service we must be compatible with, not the RFC we would prefer; the
    /// distinction the client can act on is carried by [`Self::error_code`].
    #[must_use]
    pub fn to_status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    /// The S3 error code for this refusal.
    ///
    /// Deliberately coarse. A code that named the exact rule would let a peer enumerate this
    /// layer's checks one request at a time, and no client branches on that detail; the specific
    /// variant belongs in the operator's log, not in the response.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::LimitExceeded(LimitKind::BodyBytes) => ErrorCode::ENTITY_TOO_LARGE,
            Self::LimitExceeded(_) => ErrorCode::MAX_MESSAGE_LENGTH_EXCEEDED,
            Self::MalformedRequestTarget => ErrorCode::INVALID_URI,
            Self::DuplicateSingleValuedQuery(_) | Self::AmbiguousQueryParameterName | Self::MalformedQuery => {
                ErrorCode::INVALID_ARGUMENT
            }
            Self::MalformedMetadata(_) => ErrorCode::INVALID_ARGUMENT,
            _ => ErrorCode::INVALID_REQUEST,
        }
    }

    /// Whether the body may still be read after this refusal.
    ///
    /// Always `false`. It is a method rather than a constant so the reason travels with the type:
    /// draining a body to keep a connection alive is exactly what an attacker wants when the
    /// request was refused *for* its size, and when the request was refused for its framing there
    /// is no agreed definition of how much body there is to drain.
    #[must_use]
    pub fn may_read_body(&self) -> bool {
        false
    }

    /// Whether the connection must be closed after the response.
    ///
    /// Required by RFC 9112 §6.1 for the framing conflicts, and applied to the rest because a
    /// peer that sent one ambiguous head on a reused connection has already put bytes of unknown
    /// ownership into the stream.
    #[must_use]
    pub fn must_close_connection(&self) -> bool {
        true
    }

    /// A short, stable label for logs, metrics and tests.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ContentLengthTransferEncodingConflict => "content-length-transfer-encoding-conflict",
            Self::TransferEncodingMalformed => "transfer-encoding-malformed",
            Self::TransferEncodingOnHttp2 => "transfer-encoding-on-http2",
            Self::DuplicateContentLength => "duplicate-content-length",
            Self::MalformedContentLength => "malformed-content-length",
            Self::MalformedChunkFraming => "malformed-chunk-framing",
            Self::DuplicateSingleValuedHeader(_) => "duplicate-single-valued-header",
            Self::DuplicateSingleValuedQuery(_) => "duplicate-single-valued-query",
            Self::AmbiguousQueryParameterName => "ambiguous-query-parameter-name",
            Self::NonUtf8SignificantHeader(_) => "non-utf8-significant-header",
            Self::MalformedHeaderValue(_) => "malformed-header-value",
            Self::MalformedMetadata(_) => "malformed-metadata",
            Self::MalformedRequestTarget => "malformed-request-target",
            Self::MalformedQuery => "malformed-query",
            Self::Host(_) => "host",
            Self::LimitExceeded(_) => "limit-exceeded",
        }
    }
}

impl From<HostError> for WireReject {
    fn from(error: HostError) -> Self {
        Self::Host(error)
    }
}

impl From<MetadataReject> for WireReject {
    fn from(error: MetadataReject) -> Self {
        Self::MalformedMetadata(error)
    }
}
