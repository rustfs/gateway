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
//!
//! **A head verdict does not.** It used to: both methods returned a constant, so every refusal in
//! this layer answered "close" and the flag carried no information. The rule that replaced the
//! constant is RFC 9112 §9.3 — read the whole body or close — which makes "may this be drained"
//! the only decision and the connection verdict its consequence. See [`WireReject::may_read_body`]
//! for the two families that may not be drained and why.
//!
//! # Two strings, and only one of them may leave the process
//!
//! [`WireReject::message`] is what a client reads. [`WireReject::label`] is what an operator
//! reads. They are separate methods because they were once the same one, and the renderer picked
//! the wrong one: `<Message>limit-exceeded</Message>` went out to callers for every ceiling this
//! layer enforces.
//!
//! That is a defect in two directions at once. `limit-exceeded` is an *internal identifier* — it
//! is chosen for grepping this repository, it changes when a variant is renamed, and a client that
//! parses it has taken a dependency on a refactor. And it says nothing: a caller reading it learns
//! neither what to change nor that anything was over a ceiling at all.
//!
//! So the invariant, asserted by `tests/reject_wording.rs`: **no string reachable from
//! [`WireReject::label`] is reachable from [`WireReject::message`], and no message contains an
//! identifier from this crate's source.** The labels are lowercase-with-hyphens by construction
//! and the messages are sentences, which is what makes the disjointness checkable rather than
//! merely intended.

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
    /// One user-metadata key carried more than one value.
    ///
    /// Field names are case-insensitive, so `X-Amz-Meta-Q` and `x-amz-meta-q` are the same key.
    /// Metadata is a map: keeping either value would silently discard the other, and joining them
    /// would store a value the client never sent. RustFS behind the pinned s3s refuses the request
    /// with `InvalidRequest` before any handler runs, and this is that refusal (rustfs/gateway
    /// migration ruling `rd-ctx-0006`).
    DuplicateMetadataHeader(HeaderName),
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
    /// Coarse, but not uniform. The unit is **what the client has to change**, which is coarser
    /// than the variant and finer than "something was refused":
    ///
    /// | Refusal | Code | What the caller does next |
    /// | --- | --- | --- |
    /// | [`LimitKind::BodyBytes`] | `EntityTooLarge` | split the upload into parts |
    /// | [`LimitKind::ChunkSizeLine`] | `InvalidRequest` | fix the `aws-chunked` framing |
    /// | [`LimitKind::HostBytes`] | `InvalidRequest` | send a `Host` that is a host |
    /// | every other [`LimitKind`] | `MaxMessageLengthExceeded` | send a smaller request |
    /// | a framing verdict | `InvalidRequest` | fix the framing |
    /// | a header verdict | `InvalidRequest` | fix the header |
    /// | a query verdict | `InvalidArgument` | fix the query string |
    /// | [`Self::MalformedRequestTarget`] | `InvalidURI` | fix the request target |
    ///
    /// Two ceilings that were previously folded into `MaxMessageLengthExceeded` are not size
    /// complaints at all and have moved out. A chunk-size line past its ceiling is the same
    /// verdict as [`Self::MalformedChunkFraming`] reached by a different route — no length of line
    /// is one this parser would have accepted, so telling the caller to shrink the request sends
    /// it to fix the wrong thing. An effective host past 263 bytes is not a long host, it is not a
    /// host; it belongs with the rest of [`HostError`].
    ///
    /// What deliberately does **not** happen is a code per ceiling. AWS publishes none, so
    /// inventing `QueryStringTooLong` would put a code on the wire that no S3 client has a branch
    /// for, and it would hand a peer a way to enumerate this layer's checks one request at a time.
    /// The distinction between "your query value is wrong" and "your request is too big" is real
    /// and the client does get it — but it comes from the operation's own ceiling answering
    /// `InvalidArgument` first, which is what the derivation in [`crate::Limits`] exists to
    /// guarantee, not from subdividing this table.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::LimitExceeded(LimitKind::BodyBytes) => ErrorCode::ENTITY_TOO_LARGE,
            Self::LimitExceeded(LimitKind::ChunkSizeLine) => ErrorCode::INVALID_REQUEST,
            Self::LimitExceeded(LimitKind::HostBytes) => ErrorCode::INVALID_REQUEST,
            Self::LimitExceeded(_) => ErrorCode::MAX_MESSAGE_LENGTH_EXCEEDED,
            Self::MalformedRequestTarget => ErrorCode::INVALID_URI,
            Self::DuplicateSingleValuedQuery(_) | Self::AmbiguousQueryParameterName | Self::MalformedQuery => {
                ErrorCode::INVALID_ARGUMENT
            }
            Self::MalformedMetadata(_) => ErrorCode::INVALID_ARGUMENT,
            _ => ErrorCode::INVALID_REQUEST,
        }
    }

    /// The sentence a client reads in `<Message>`.
    ///
    /// One message per row of the [`Self::error_code`] table, never one per variant. That is the
    /// same reason the codes are grouped: fifteen distinguishable sentences would restore, in
    /// prose, exactly the enumeration surface the coarse code set exists to close. The operator
    /// keeps the precise variant through [`Self::label`], which never leaves this process.
    ///
    /// Where AWS publishes a message for the code — `EntityTooLarge`,
    /// `MaxMessageLengthExceeded`, `InvalidURI` — that message is used verbatim, because an
    /// operator matching this gateway's responses against S3's own has to be able to diff them.
    /// The rest are written here, in the same register: a complete sentence about the request,
    /// naming no ceiling, no header count, and no identifier from this source tree.
    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            Self::LimitExceeded(LimitKind::BodyBytes) => "Your proposed upload exceeds the maximum allowed size.",
            Self::LimitExceeded(LimitKind::ChunkSizeLine) | Self::MalformedChunkFraming => CHUNK_FRAMING_MESSAGE,
            Self::LimitExceeded(LimitKind::HostBytes) | Self::Host(_) => HOST_MESSAGE,
            Self::LimitExceeded(_) => "Your request was too big.",
            Self::ContentLengthTransferEncodingConflict
            | Self::TransferEncodingMalformed
            | Self::TransferEncodingOnHttp2
            | Self::DuplicateContentLength
            | Self::MalformedContentLength => FRAMING_MESSAGE,
            Self::DuplicateSingleValuedHeader(_)
            | Self::DuplicateMetadataHeader(_)
            | Self::NonUtf8SignificantHeader(_)
            | Self::MalformedHeaderValue(_) => HEADER_MESSAGE,
            Self::MalformedMetadata(_) => METADATA_MESSAGE,
            Self::DuplicateSingleValuedQuery(_) | Self::AmbiguousQueryParameterName | Self::MalformedQuery => QUERY_MESSAGE,
            Self::MalformedRequestTarget => "Couldn't parse the specified URI.",
        }
    }

    /// Whether the unconsumed request body may still be drained after this refusal.
    ///
    /// This method and [`Self::must_close_connection`] are one decision, not two. RFC 9112 §9.3
    /// states the whole rule:
    ///
    /// > A server MUST read the entire request message body or close the connection after sending
    /// > its response; otherwise, the remaining data on a persistent connection would be
    /// > misinterpreted as the next request.
    ///
    /// So the only question a refusal answers is *may this body be drained*; the connection
    /// verdict follows from the answer rather than being chosen beside it. That is why
    /// `must_close_connection` is the negation of this method and cannot drift from it.
    ///
    /// `false` — the body must not be drained, so the connection ends — for two families:
    ///
    /// * **The framing verdicts.** RFC 9112 §6.1 names the close for the
    ///   `Content-Length`/`Transfer-Encoding` pair, and §6.3 is the reason it generalises: when the
    ///   head does not determine a message body length, "how much is there to drain" has no
    ///   answer, so draining is not an operation this server can perform at all.
    /// * **[`LimitKind::BodyBytes`].** Here the framing *is* intact and the remainder is
    ///   well-defined. The server declines anyway, because reading a body it refused *for its size*
    ///   performs exactly the transfer the refusal exists to avoid. The declining is this service's
    ///   policy; the close that follows it is the RFC's.
    ///
    /// `true` for every other verdict — a bad host, a repeated header, a query string that will not
    /// split, a head-shaped ceiling. The head is malformed and the framing is not: the body's
    /// extent is known and already bounded by [`crate::Limits`], so a caller that drains it may
    /// keep the connection. Draining is still not unconditional; see
    /// [`MAX_LINGER_DRAIN_BYTES`].
    #[must_use]
    pub fn may_read_body(&self) -> bool {
        !matches!(
            self,
            Self::ContentLengthTransferEncodingConflict
                | Self::TransferEncodingMalformed
                | Self::TransferEncodingOnHttp2
                | Self::DuplicateContentLength
                | Self::MalformedContentLength
                | Self::MalformedChunkFraming
                | Self::LimitExceeded(LimitKind::ChunkSizeLine)
                | Self::LimitExceeded(LimitKind::BodyBytes)
        )
    }

    /// Whether this refusal ends the connection whatever the caller does.
    ///
    /// The exact negation of [`Self::may_read_body`], for the RFC 9112 §9.3 reason written there.
    ///
    /// `false` is **not** "the connection survives". It is "the connection survives *if and only
    /// if* the remainder is drained": a caller that declines to drain — because the remainder is
    /// past [`MAX_LINGER_DRAIN_BYTES`], because the peer stopped sending, or because a stage above
    /// this one refused for a reason of its own — must still close. This method answers only what
    /// the refusal itself forces.
    #[must_use]
    pub fn must_close_connection(&self) -> bool {
        !self.may_read_body()
    }

    /// A short, stable label for logs, metrics and tests. **Never for a client.**
    ///
    /// Every value here is an internal identifier: it is the variant name in kebab case, it moves
    /// when the variant is renamed, and it names the individual check that fired. All three are
    /// exactly what makes it useful in a dashboard and disqualifying in a response body. See the
    /// module documentation for the day this string was the response body.
    #[must_use]
    pub fn label(&self) -> &'static str {
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
            Self::DuplicateMetadataHeader(_) => "duplicate-metadata-header",
            Self::MalformedRequestTarget => "malformed-request-target",
            Self::MalformedQuery => "malformed-query",
            // `host` on its own was the label until the disjointness guard caught it: it is an
            // ordinary English word, so every message that mentions a host contained it. A metric
            // label that collides with prose is a label that cannot be checked against prose.
            Self::Host(_) => "host-undetermined",
            Self::LimitExceeded(kind) => kind.as_str(),
        }
    }
}

/// How much of an abandoned request body a caller may drain before it closes instead.
///
/// RFC 9112 §9.6 describes the tear-down this bounds: a server that means to close reads on for a
/// while first, so that its response is not erased by a TCP reset. §9.3 is why it reads at all —
/// a connection that is to be *kept* has no choice but to reach the end of the body. Neither
/// section puts a number on it, and a server that drains without one has handed an unauthenticated
/// peer a way to make it read for as long as the peer keeps writing.
///
/// **This number is a judgement, not a citation.** 64 KiB is one socket buffer's worth: large
/// enough that every refusal whose body a client had already written in a single flush is drained
/// and its connection survives, small enough that draining is never a transfer. `nginx`'s
/// `lingering_close_max_size` and Apache's lingering-close budget exist for the same reason and
/// are the same order of magnitude.
pub const MAX_LINGER_DRAIN_BYTES: u64 = 64 * 1024;

/// Every framing verdict, in one sentence.
///
/// One sentence for seven checks. Naming which of them fired would tell a caller how to probe the
/// remaining six, and there is nothing in the difference a well-behaved client can act on: the fix
/// for all of them is to declare the body's length once and unambiguously.
const FRAMING_MESSAGE: &str = "The request does not declare the length of its body unambiguously.";

/// The `aws-chunked` framing verdicts, which are about the body's own framing rather than the
/// head's declaration of it.
const CHUNK_FRAMING_MESSAGE: &str = "The chunked encoding of the request body is not one this service can read.";

/// Every header verdict: repeated where it may not be, unreadable as text, or carrying a control
/// character.
const HEADER_MESSAGE: &str = "A request header is not one this service can accept.";

/// The user-metadata verdicts, kept apart from [`HEADER_MESSAGE`] because the caller's fix is a
/// different one: the header is theirs to choose, and it is the value that is wrong.
const METADATA_MESSAGE: &str = "The user metadata on this request is not valid.";

/// Every query-string verdict.
const QUERY_MESSAGE: &str = "The query string is not one this service can read as a set of parameters.";

/// The host verdicts: absent, duplicated, contradicted by the request target, or not a host at all.
const HOST_MESSAGE: &str = "The request does not name exactly one host.";

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
