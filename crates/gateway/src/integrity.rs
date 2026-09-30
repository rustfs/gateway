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

//! What this assembly knows about request-body integrity that the wire layer cannot.
//!
//! Responsible for: [`checksum_subject`], the per-operation fact of what an `x-amz-checksum-*`
//! header is the digest *of*, and [`checksum_refusal`], the response an integrity verdict renders
//! as — under the core's codes, or under legacy RustFS's ([`IntegrityCodes`], the RustFS profile of
//! rustfs/gateway#1057).
//! NOT responsible for: reading the headers, opening the digests, or comparing them —
//! `rustfs_gateway_http::BodyIntegrity` owns all three, and owns them alone.
//! Upstream: `crate::gate`, the only caller. Downstream: `rustfs-gateway-http`.
//!
//! # Why the subject is decided here and not there
//!
//! `rustfs-gateway-http` knows headers; it does not know operations, and giving it an operation
//! name would be the first thread of a route table in the wire layer. This assembly knows both, so
//! the two facts that depend on the operation live here and travel down as one enumerated value.

use http::Method;
use rustfs_gateway_core::{HandlerError, MetaView};
use rustfs_gateway_http::{
    BodyIntegrity, ChecksumReject, ChecksumSubject, ChunkReject, EmptyIntegrityHeaders, HeaderView, IngestPipeline,
    UnknownChecksumAlgorithms,
};
use rustfs_gateway_types::ErrorCode;

use crate::close::ConnectionIntent;
use crate::render::{S3Error, from_transport_limit};

/// The error codes this assembly answers a body-integrity refusal with.
///
/// # Why legacy RustFS answers `BadDigest`
///
/// Legacy RustFS verifies an `x-amz-checksum-*` claim in its own storage reader, and reports both
/// a value that is not valid for its algorithm and a digest that does not match as a checksum
/// mismatch (rustfs/rustfs@1e7065101d `crates/rio/src/checksum.rs:644-664`,
/// `crates/rio/src/hash_reader.rs:593-613`), which its API layer answers with `400 BadDigest`
/// (`rustfs/src/error.rs:545-561` and `:714-730`). The same mapping turns a streamed body that does
/// not match its signed `x-amz-content-sha256` into `BadDigest` (`rustfs/src/error.rs:452-465`).
/// The core keeps the AWS model's codes — `InvalidRequest` for an unreadable value,
/// `XAmzContentChecksumMismatch` and `XAmzContentSHA256Mismatch` for a mismatch — as its default.
///
/// The refusal is the same refusal either way, at the same point: only its code changes. A head
/// or buffered body is refused before any handler runs, and a streamed body's refusal is the
/// terminal verdict a handler's commit waits on, so a body that does not match its claim is never
/// stored under either.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum IntegrityCodes {
    /// The AWS model's codes, which the core answers by default.
    #[default]
    Model,
    /// Legacy RustFS's: `BadDigest` for every refusal it reports as a checksum mismatch.
    RustFs,
}

impl IntegrityCodes {
    /// Renders `reject` under these codes.
    pub(crate) fn refusal(self, reject: ChecksumReject) -> S3Error {
        match (self, reject) {
            (
                Self::RustFs,
                ChecksumReject::InvalidChecksumValue | ChecksumReject::ChecksumMismatch | ChecksumReject::TrailerChecksumMissing,
            ) => {
                // Legacy-compat (rustfs/backlog#2684): legacy RustFS answers an unreadable checksum
                // value, a missing trailer checksum and a mismatched digest alike with `BadDigest`,
                // so a client cannot tell a broken SDK from a corrupted transfer. (A trailer value
                // that is not base64 at all reaches legacy as `500 InternalError`, an accident this
                // does not copy; it gets the `BadDigest` legacy gives the rest of the class.) The
                // intended future behaviour is the core's codes: `InvalidRequest` for an unreadable
                // value, `XAmzContentChecksumMismatch` for a mismatch.
                from_transport_limit(
                    HandlerError::new(ErrorCode::BAD_DIGEST, reject.message()),
                    reject.to_status(),
                    ConnectionIntent::MayKeepAlive,
                )
            }
            _ => checksum_refusal(reject),
        }
    }

    /// Renders the refusal a framed body's chunk decoder settled on.
    ///
    /// Under the RustFS codes a trailer section that does not carry exactly the checksum trailer the
    /// head declared is `BadDigest`: legacy RustFS reads the declared checksum out of the trailer
    /// section and reports a missing or different one as a checksum mismatch (observed against a
    /// legacy RustFS build: none, a different checksum or an unrelated field where the head declared
    /// `x-amz-checksum-sha256` all answer `400 BadDigest` and store nothing). The status and the
    /// connection stay the decoder's.
    pub(crate) fn chunk_refusal<R>(self, pipeline: &IngestPipeline<R>) -> S3Error {
        match (self, pipeline.reject()) {
            (Self::RustFs, Some(reject @ ChunkReject::DeclaredTrailerMismatch)) => {
                // Legacy-compat (rustfs/backlog#2684): legacy RustFS answers a trailer section that
                // does not match the head's declaration with the checksum-mismatch code, as though
                // the digest had been compared and differed. The intended future behaviour is the
                // core's `InvalidRequest`, which says the framing, not the data, was wrong.
                from_transport_limit(
                    HandlerError::new(ErrorCode::BAD_DIGEST, ChecksumReject::TrailerChecksumMissing.message()),
                    reject.to_status(),
                    crate::close::after_chunk_reject(&reject),
                )
            }
            _ => crate::chunked::ChunkIngest::refusal(pipeline),
        }
    }

    /// Renders a streamed body that does not match its signed `x-amz-content-sha256`.
    ///
    /// Only the streamed path: legacy RustFS reports a buffered body's payload-hash mismatch as
    /// `500 InternalError`, which this does not copy, so the buffered path keeps the core's code.
    pub(crate) fn streamed_payload_hash_mismatch(self) -> S3Error {
        let refusal = crate::gate::content_sha256_mismatch();
        match self {
            Self::Model => refusal,
            Self::RustFs => crate::render::from_handler(
                HandlerError::new(ErrorCode::BAD_DIGEST, "the request body does not match x-amz-content-sha256"),
                rustfs_gateway_core::ResponseKind::Other,
                ConnectionIntent::MayKeepAlive,
            ),
        }
    }
}

/// One request body's integrity obligations, with the codes its refusals are answered with.
///
/// `From<BodyIntegrity>` answers with the core's codes, so every caller that has no RustFS profile
/// to apply passes the obligations alone.
pub(crate) struct Integrity {
    pub(crate) claims: BodyIntegrity,
    pub(crate) codes: IntegrityCodes,
}

impl From<BodyIntegrity> for Integrity {
    fn from(claims: BodyIntegrity) -> Self {
        Self {
            claims,
            codes: IntegrityCodes::Model,
        }
    }
}

/// What this request's `x-amz-checksum-*` header is the digest of.
///
/// Two rules, both stated here rather than inferred, so that `grep CompleteMultipartUpload` finds
/// the exception:
///
/// * A method that carries no request body carries no claim about one. S3 ignores a `Content-MD5`
///   on a read rather than refusing it, and a digest of bytes that were never sent describes
///   nothing this service received.
/// * `CompleteMultipartUpload`'s checksum header is the digest of the **assembled object**,
///   commonly in the composite `<base64>-N` form, while its body is the completion XML. Comparing
///   them is a check that can only fail — it would answer `400` to every SDK multipart completion
///   that carries a checksum. `Content-MD5` on that operation is still the message body's digest
///   and is still compared.
pub(crate) fn checksum_subject(method: &Method, operation: &str) -> ChecksumSubject {
    if !matches!(*method, Method::PUT | Method::POST) {
        return ChecksumSubject::None;
    }
    if operation == "CompleteMultipartUpload" {
        return ChecksumSubject::NamedResource;
    }
    ChecksumSubject::RequestBody
}

/// Renders an integrity refusal.
///
/// The connection is kept, and for two different reasons depending on where the refusal came from.
/// An arbitration refusal fires before a body byte is polled, which is the same pre-commit position
/// every other head-level refusal answers from with `MayKeepAlive`. A comparison refusal fires
/// after the body has been read to its end — that is how the digest was computed at all — so
/// RFC 9112 §9.3 leaves nothing to drain. Either way the peer is a client with a bad request rather
/// than one this service has reason to disconnect.
pub(crate) fn checksum_refusal(reject: ChecksumReject) -> S3Error {
    from_transport_limit(
        HandlerError::new(reject.error_code(), reject.message()),
        reject.to_status(),
        ConnectionIntent::MayKeepAlive,
    )
}

/// Settles what one request body owes, from the head and above the body read.
///
/// Called before `SealedBody::read` and never after: two integrity claims cannot be reconciled by
/// any number of body bytes, so a request carrying a contradiction is malformed however it ends,
/// and refusing it after the transfer would pay for the transfer first.
///
/// `headers` must be the **accepted** head — the map the codec binds the operation input from —
/// and not the copy taken before the stage filters run. The two differ exactly when a filter writes
/// a checksum header, and binding a claim into an input that nothing compared against the body is
/// the shape this whole seam exists to remove.
///
/// # Errors
///
/// The rendered [`ChecksumReject`] for any ambiguity in the head.
#[cfg(test)]
pub(crate) fn resolve(headers: &HeaderView<'_>, method: &Method, operation: &str) -> Result<BodyIntegrity, S3Error> {
    BodyIntegrity::resolve(headers, checksum_subject(method, operation)).map_err(checksum_refusal)
}

/// [`resolve`] as the pipeline calls it: every refusal — the head's now, the body's later — is
/// answered under the codes the routed view carries (the RustFS profile's `BadDigest`, or the
/// core's), and a header naming an unknown algorithm is refused or ignored, and an empty one read
/// or taken as absent, as the view says.
/// `resolve` itself is the test suites' entry, under the core's codes and refusing one.
///
/// # Errors
///
/// The [`ChecksumReject`] for any ambiguity in the head, rendered under the view's codes.
pub(crate) fn resolve_in(
    view: &MetaView<'_>,
    headers: &HeaderView<'_>,
    method: &Method,
    operation: &str,
) -> Result<Integrity, S3Error> {
    let codes = if view.checksum_failures_as_bad_digest() {
        IntegrityCodes::RustFs
    } else {
        IntegrityCodes::Model
    };
    let refuse = move |reject| codes.refusal(reject);
    let unknown = if view.unknown_checksum_algorithms_ignored() {
        UnknownChecksumAlgorithms::Ignored
    } else {
        UnknownChecksumAlgorithms::Refused
    };
    let empty = if view.empty_headers_absent() {
        EmptyIntegrityHeaders::Absent
    } else {
        EmptyIntegrityHeaders::Read
    };
    let claims = BodyIntegrity::resolve_reading(headers, checksum_subject(method, operation), unknown, empty).map_err(refuse)?;
    Ok(Integrity { claims, codes })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every refusal the wire layer can produce today. `ChecksumReject` is `#[non_exhaustive]`, so
    /// a new one reaches `IntegrityCodes::refusal`'s catch-all arm: the core's code, unchanged.
    const EVERY_REJECT: [ChecksumReject; 10] = [
        ChecksumReject::MultipleChecksumHeaders,
        ChecksumReject::SdkAlgorithmMismatch,
        ChecksumReject::UnknownAlgorithm,
        ChecksumReject::InvalidChecksumValue,
        ChecksumReject::InvalidDigest,
        ChecksumReject::BadDigest,
        ChecksumReject::ChecksumMismatch,
        ChecksumReject::HeaderAndTrailerBothPresent,
        ChecksumReject::TrailerChecksumMissing,
        ChecksumReject::TrailerNotAllowed,
    ];

    fn code_of(error: &S3Error) -> &str {
        error.code().map_or("", ErrorCode::as_str)
    }

    /// The three refusals legacy RustFS reports as a checksum mismatch become `BadDigest`.
    #[test]
    fn the_rustfs_codes_answer_checksum_mismatches_with_bad_digest() {
        for reject in [
            ChecksumReject::InvalidChecksumValue,
            ChecksumReject::ChecksumMismatch,
            ChecksumReject::TrailerChecksumMissing,
        ] {
            let refusal = IntegrityCodes::RustFs.refusal(reject);
            assert_eq!(code_of(&refusal), "BadDigest", "{reject:?}");
            assert_eq!(refusal.status(), reject.to_status(), "{reject:?}");
            assert!(!refusal.must_close_connection(), "{reject:?}");
        }
        let streamed = IntegrityCodes::RustFs.streamed_payload_hash_mismatch();
        assert_eq!((code_of(&streamed), streamed.status().as_u16()), ("BadDigest", 400));
    }

    /// Negative — the core's codes are exactly what the refusal carried before this existed.
    #[test]
    fn n_the_model_codes_are_the_refusals_own() {
        for reject in EVERY_REJECT {
            assert_eq!(IntegrityCodes::Model.refusal(reject), checksum_refusal(reject), "{reject:?}");
        }
        assert_eq!(
            IntegrityCodes::Model.streamed_payload_hash_mismatch(),
            crate::gate::content_sha256_mismatch()
        );
        assert_eq!(IntegrityCodes::default(), IntegrityCodes::Model);
    }

    /// Negative — every other refusal keeps its own code under the RustFS codes too: the
    /// `Content-MD5` pair, and every ambiguity legacy RustFS answers differently or not at all.
    #[test]
    fn n_the_rustfs_codes_leave_every_other_refusal_alone() {
        for reject in EVERY_REJECT {
            if matches!(
                reject,
                ChecksumReject::InvalidChecksumValue | ChecksumReject::ChecksumMismatch | ChecksumReject::TrailerChecksumMissing
            ) {
                continue;
            }
            assert_eq!(IntegrityCodes::RustFs.refusal(reject), checksum_refusal(reject), "{reject:?}");
        }
    }
}
