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

//! The integrity a request body owes, settled once from the head and discharged once at the end.
//!
//! Responsible for: reading a request's integrity claims off its headers exactly once
//! ([`BodyIntegrity::resolve`]), opening the digests those claims require and no others
//! ([`BodyIntegrity::begin`]), and turning the comparison at end-of-body into a value that cannot
//! be minted any other way ([`ChecksumVerified`]).
//! NOT responsible for: choosing a digest algorithm — [`rustfs_gateway_types::ChecksumAlgorithm`]
//! owns the table and the implementations — reading bytes off a socket, `aws-chunked` framing, or
//! parsing the trailer section. It does consume the EOF-only parsed fields to discharge a trailer
//! checksum obligation.
//! Upstream: `rustfs-gateway-types` for the algorithm table and the arbitration rules, this
//! crate's [`HeaderView`]. Downstream: the assembly that owns the body read, which is the only
//! place both halves of this module are reachable from.
//!
//! # Why the resolution is one function and not a rule per operation
//!
//! A request may claim its body's digest three ways at once — `Content-MD5`, one
//! `x-amz-checksum-<algo>` header, and `x-amz-sdk-checksum-algorithm` naming which of the latter
//! it meant. Every combination of those is either a rejection or an obligation, and there is no
//! third answer. When the choice is made in more than one place the two places eventually differ,
//! and the shape that difference takes is not a crash: one layer verifies a claim the other layer
//! discarded, and the request that gets committed is the one whose claim nobody checked.
//!
//! That is not hypothetical here. Before this module, this workspace held two implementations of
//! the same decision: [`rustfs_gateway_types::parse_request_checksum`], which had no caller on the
//! request path at all, and a second one in the codec layer which answered a malformed
//! `x-amz-checksum-crc32` value by *skipping the header* — reporting "this request claimed no
//! checksum" for a request that claimed one. [`BodyIntegrity::resolve`] delegates the
//! `x-amz-checksum-*` half to `parse_request_checksum` rather than restating it, so there is one
//! implementation and adding an algorithm moves both callers together.
//!
//! What that does *not* mean is that only one function in the tree ever looks at these headers.
//! `rustfs_gateway_core::codec::value::checksum_spec` still reads the same family, because it is
//! the *binder* that puts the value into an operation's input. The point is that it no longer
//! *decides* anything this module has not already decided: it runs after
//! [`BodyIntegrity::resolve`] has refused every ambiguity, over the same accepted head, and it now
//! refuses a malformed value instead of skipping it. Two code paths that cannot disagree are one
//! decision; two that can are the defect.
//!
//! # `Content-MD5` and `x-amz-checksum-*` are both verified, never one of them
//!
//! They are different protocol features with different error codes: a malformed `Content-MD5` is
//! `InvalidDigest`, a mismatched one is `BadDigest`, and a mismatched `x-amz-checksum-*` is
//! `XAmzContentChecksumMismatch`. A request carrying both owes both — settling for whichever is
//! cheaper to check would let a caller disable the check it did not want by also sending one it
//! could satisfy.
//!
//! # One header family, more than one meaning
//!
//! `x-amz-checksum-crc32` is the digest of the request body on `PutObject` and the digest of the
//! *assembled object* on `CompleteMultipartUpload`, where the body is a completion document. This
//! crate knows headers and not operations, so the caller states which through [`ChecksumSubject`];
//! the arbitration runs either way, and only the comparison is conditional.
//!
//! # Trailer checks happen only at EOF
//!
//! A trailer declaration opens its digest before the first body byte, but its expected value is
//! read only by [`BodyDigests::verify_with_trailers`]. The argument is a [`TrailingHeaders`] value,
//! which the stream crate exposes only inside an EOF event. Calling [`BodyDigests::verify`] on the
//! same obligation supplies an empty trailer set and fails with
//! [`ChecksumReject::TrailerChecksumMissing`]; looking too early can no longer mean "skip".
//!
//! [`HeaderView`]: crate::HeaderView

use http::StatusCode;
use http::header::HeaderName;
use rustfs_gateway_stream::TrailingHeaders;
use rustfs_gateway_types::{
    ChecksumAlgorithm, ChecksumError, ChecksumSpec, ChecksumType, Checksummer, ContentMd5, ErrorCode, Md5Digest,
    names_unknown_checksum_algorithm, parse_request_checksum,
};

use crate::header_view::HeaderView;

/// The header carrying the legacy whole-body digest.
const CONTENT_MD5: HeaderName = HeaderName::from_static("content-md5");
const X_AMZ_TRAILER: HeaderName = HeaderName::from_static("x-amz-trailer");
const SDK_CHECKSUM_ALGORITHM: HeaderName = HeaderName::from_static("x-amz-sdk-checksum-algorithm");
const CHECKSUM_TYPE: HeaderName = HeaderName::from_static("x-amz-checksum-type");

/// Why a request body's integrity claim was refused.
///
/// Separate from [`crate::ChunkReject`] and [`crate::WireReject`] because it is neither: a wire
/// rejection is decidable from the head and always `400`, a chunk rejection is a framing verdict,
/// and this is an integrity verdict whose three mismatch variants carry three different S3 error
/// codes that clients branch on.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumReject {
    /// Two different `x-amz-checksum-*` headers claimed two different digests.
    ///
    /// A rejection and not a choice: picking one verifies a claim the caller did not make and
    /// drops one it did, which for the dropped half is indistinguishable from no check at all.
    MultipleChecksumHeaders,
    /// `x-amz-sdk-checksum-algorithm` named an algorithm no value header carried, or named a
    /// different one from the value header that did arrive.
    SdkAlgorithmMismatch,
    /// An `x-amz-checksum-<algo>` header named an algorithm this build does not implement.
    UnknownAlgorithm,
    /// A checksum value is not base64 of its algorithm's width, or carries a bad `-N` suffix.
    ///
    /// Refused rather than ignored. An arbitration that skips a value it cannot parse answers
    /// "no checksum was claimed" for a request that claimed one.
    InvalidChecksumValue,
    /// `Content-MD5` is not base64 of sixteen bytes.
    InvalidDigest,
    /// `Content-MD5` did not match the body that arrived.
    BadDigest,
    /// An `x-amz-checksum-*` value did not match the body that arrived.
    ChecksumMismatch,
    /// A value checksum and a trailer checksum both claimed the same request body.
    HeaderAndTrailerBothPresent,
    /// The body ended without the checksum its `x-amz-trailer` declaration promised.
    TrailerChecksumMissing,
    /// A trailer checksum was declared for a request shape that cannot carry one.
    TrailerNotAllowed,
}

impl ChecksumReject {
    /// The HTTP status for this refusal.
    ///
    /// Constant, and deliberately so: integrity is a statement about the bytes the caller sent and
    /// never about who the caller is, so answering `403` for a digest mismatch would file a
    /// corrupted upload in the same dashboard bucket as a signature failure. It is a function
    /// rather than a `const` only because the refusal set may one day gain a variant that is not a
    /// `400`. **It is not a check**, and nothing asserts on it as though it were — a test that
    /// compares this against `BAD_REQUEST` is comparing a literal to itself.
    #[must_use]
    pub fn to_status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    /// The S3 error code for this refusal.
    ///
    /// The three mismatch codes stay distinct because the SDKs branch on them to decide what to
    /// retry: `BadDigest` says the `Content-MD5` was wrong, `XAmzContentChecksumMismatch` says the
    /// newer checksum header was, and collapsing them loses the distinction.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidDigest => ErrorCode::INVALID_DIGEST,
            Self::BadDigest => ErrorCode::BAD_DIGEST,
            Self::ChecksumMismatch => ErrorCode::X_AMZ_CONTENT_CHECKSUM_MISMATCH,
            _ => ErrorCode::INVALID_REQUEST,
        }
    }

    /// The sentence a client sees.
    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            Self::MultipleChecksumHeaders => "Expecting a single x-amz-checksum- header",
            Self::SdkAlgorithmMismatch => {
                "The algorithm named by x-amz-sdk-checksum-algorithm has no corresponding checksum header"
            }
            Self::UnknownAlgorithm => "The checksum algorithm is not supported",
            Self::InvalidChecksumValue => "The checksum value is not valid for the named algorithm",
            Self::InvalidDigest => "The Content-MD5 you specified is not valid",
            Self::BadDigest => "The Content-MD5 you specified did not match what we received",
            Self::ChecksumMismatch => "The checksum you specified did not match what we received",
            Self::HeaderAndTrailerBothPresent => "A checksum cannot be supplied in both the request headers and trailer",
            Self::TrailerChecksumMissing => "The declared trailer checksum did not arrive",
            Self::TrailerNotAllowed => "This request does not carry a trailer checksum",
        }
    }

    /// A short, stable label for logs, metrics and tests.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MultipleChecksumHeaders => "multiple-checksum-headers",
            Self::SdkAlgorithmMismatch => "sdk-algorithm-mismatch",
            Self::UnknownAlgorithm => "unknown-algorithm",
            Self::InvalidChecksumValue => "invalid-checksum-value",
            Self::InvalidDigest => "invalid-digest",
            Self::BadDigest => "bad-digest",
            Self::ChecksumMismatch => "checksum-mismatch",
            Self::HeaderAndTrailerBothPresent => "header-and-trailer-checksum",
            Self::TrailerChecksumMissing => "trailer-checksum-missing",
            Self::TrailerNotAllowed => "trailer-not-allowed",
        }
    }

    fn of(error: ChecksumError) -> Self {
        match error {
            ChecksumError::MultipleChecksumHeaders => Self::MultipleChecksumHeaders,
            ChecksumError::AlgorithmDeclaredWithoutValue => Self::SdkAlgorithmMismatch,
            ChecksumError::UnknownAlgorithm => Self::UnknownAlgorithm,
            ChecksumError::InvalidDigest => Self::InvalidDigest,
            ChecksumError::BadDigest => Self::BadDigest,
            ChecksumError::ChecksumMismatch => Self::ChecksumMismatch,
            // `InvalidChecksumValue`, `NotCombinable`, and any variant added to the
            // `#[non_exhaustive]` set later: a value this layer could not make sense of. Failing
            // closed on an unrecognised integrity error is the only safe default, because the
            // alternative is treating it as "no obligation".
            _ => Self::InvalidChecksumValue,
        }
    }
}

impl core::fmt::Display for ChecksumReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ChecksumReject {}

/// What an `x-amz-checksum-*` header on this request is the digest *of*.
///
/// The family does not mean the same thing on every operation, and this crate cannot tell them
/// apart: it knows headers, not operations. The caller — which knows both the method and the
/// operation — states the subject, and it is an enumeration rather than a `bool` because the third
/// answer is neither "verify it" nor "ignore it".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumSubject {
    /// The value is the digest of the bytes this request carries. The ordinary case: `PutObject`,
    /// `UploadPart`, and every configuration document write.
    RequestBody,
    /// The value describes a resource the request *names* rather than the bytes it carries, so it
    /// is arbitrated — two of them are still a contradiction — and never compared against the body.
    ///
    /// `CompleteMultipartUpload` is the whole of this case, and it is not a nicety: its
    /// `x-amz-checksum-*` header is the checksum of the **assembled object**, usually in the
    /// composite `<base64>-N` form, while the request body is the completion XML. Comparing the two
    /// is a check that can only fail, which is worse than no check at all — every SDK multipart
    /// completion that carries a checksum would be answered `400`.
    ///
    /// `Content-MD5` is unaffected: it is the digest of the message body on every operation, this
    /// one included, and stays verified.
    NamedResource,
    /// The request carries no body for a digest to describe, so a digest header claims nothing.
    ///
    /// S3 ignores `Content-MD5` on a read rather than refusing it, and a claim about bytes that
    /// were never sent is not a claim this service can be wrong about.
    None,
}

fn declared_trailer_checksum(headers: &HeaderView<'_>) -> Result<Option<ChecksumAlgorithm>, ChecksumReject> {
    let Some(value) = headers.get_bytes(&X_AMZ_TRAILER) else {
        return Ok(None);
    };
    let value = core::str::from_utf8(value).map_err(|_| ChecksumReject::InvalidChecksumValue)?;
    let mut names = value.split(',').map(|name| name.trim_matches([' ', '\t']));
    let Some(name) = names.next().filter(|name| !name.is_empty()) else {
        return Err(ChecksumReject::InvalidChecksumValue);
    };
    if names.next().is_some() {
        return Err(ChecksumReject::MultipleChecksumHeaders);
    }
    ChecksumAlgorithm::from_header_name(name)
        .map(Some)
        .ok_or(ChecksumReject::UnknownAlgorithm)
}

/// What [`BodyIntegrity::resolve_with`] does with a checksum header that names an algorithm this
/// build does not implement: an `x-amz-checksum-<name>` header no algorithm answers to, or an
/// `x-amz-sdk-checksum-algorithm` naming none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UnknownChecksumAlgorithms {
    /// Refused with [`ChecksumReject::UnknownAlgorithm`]: the default, so a new AWS algorithm
    /// arrives as a compile-and-test change and never as a claim silently left unverified.
    #[default]
    Refused,
    /// Left out, as though the header were not there; every other claim is arbitrated and verified
    /// as before, a `Content-MD5` and a known `x-amz-checksum-*` beside it included. Legacy RustFS's
    /// reading, which the RustFS profile keeps (rustfs/backlog#1677).
    Ignored,
}

/// What one request body's digests must come out to.
///
/// Resolved from the head, before a body byte is read, because no number of body bytes settles a
/// contradiction between two integrity claims: a request that carries two of them is malformed
/// however it ends, and refusing it after the transfer means paying for the transfer first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BodyIntegrity {
    md5: Option<ContentMd5>,
    checksum: Option<ChecksumSpec>,
    trailer_checksum: Option<ChecksumAlgorithm>,
    trailer_type: Option<ChecksumType>,
}

impl BodyIntegrity {
    /// A body that claimed nothing, and therefore owes nothing.
    pub const NONE: Self = Self {
        md5: None,
        checksum: None,
        trailer_checksum: None,
        trailer_type: None,
    };

    /// Reads every integrity claim a request head carries.
    ///
    /// The `x-amz-checksum-*` half is delegated to [`parse_request_checksum`], which is the
    /// arbitration authority for that family; this function adds `Content-MD5`, which is a
    /// separate protocol feature and is verified alongside rather than instead.
    ///
    /// **Arbitration runs for every subject.** Under [`ChecksumSubject::NamedResource`] and
    /// [`ChecksumSubject::None`] the checksum value is still parsed and still refused when it is
    /// ambiguous or malformed; what the subject decides is only whether the value becomes an
    /// obligation against *this* body. Skipping the arbitration instead would let a request that
    /// contradicts itself through on one operation and not another.
    ///
    /// # Errors
    ///
    /// [`ChecksumReject`] for every ambiguity: two different checksum headers, an
    /// `x-amz-sdk-checksum-algorithm` that names something no value header carried, an algorithm
    /// this build does not implement, a value that is not base64 of the right width, and a
    /// `Content-MD5` that is not base64 of sixteen bytes.
    pub fn resolve(headers: &HeaderView<'_>, subject: ChecksumSubject) -> Result<Self, ChecksumReject> {
        Self::resolve_with(headers, subject, UnknownChecksumAlgorithms::Refused)
    }

    /// [`BodyIntegrity::resolve`], with a checksum header that names an unknown algorithm refused
    /// or ignored as `unknown` says.
    ///
    /// # Errors
    ///
    /// As [`BodyIntegrity::resolve`]; under [`UnknownChecksumAlgorithms::Ignored`], never
    /// [`ChecksumReject::UnknownAlgorithm`] for an `x-amz-checksum-*` or
    /// `x-amz-sdk-checksum-algorithm` header.
    pub fn resolve_with(
        headers: &HeaderView<'_>,
        subject: ChecksumSubject,
        unknown: UnknownChecksumAlgorithms,
    ) -> Result<Self, ChecksumReject> {
        // An empty `x-amz-sdk-checksum-algorithm` names no algorithm at all rather than an unknown
        // one, and stays refused until an empty header reads as absent everywhere (#1087).
        let ignored = |name: &str, value: &str| {
            unknown == UnknownChecksumAlgorithms::Ignored && !value.is_empty() && names_unknown_checksum_algorithm(name, value)
        };
        let trailer_checksum = declared_trailer_checksum(headers)?;
        let checksum = parse_request_checksum(headers.iter_text().filter_map(|(name, value)| {
            if (trailer_checksum.is_some() && name == SDK_CHECKSUM_ALGORITHM) || ignored(name.as_str(), value) {
                None
            } else {
                Some((name.as_str(), value))
            }
        }))
        .map_err(ChecksumReject::of)?;
        if checksum.is_some() && trailer_checksum.is_some() {
            return Err(ChecksumReject::HeaderAndTrailerBothPresent);
        }
        if let Some(algorithm) = trailer_checksum {
            if subject != ChecksumSubject::RequestBody {
                return Err(ChecksumReject::TrailerNotAllowed);
            }
            if let Some(declared) = headers
                .get_str(&SDK_CHECKSUM_ALGORITHM)
                .filter(|declared| !ignored(SDK_CHECKSUM_ALGORITHM.as_str(), declared))
            {
                let declared = ChecksumAlgorithm::from_wire_name(declared).ok_or(ChecksumReject::UnknownAlgorithm)?;
                if declared != algorithm {
                    return Err(ChecksumReject::SdkAlgorithmMismatch);
                }
            }
        }
        let trailer_type = match headers.get_str(&CHECKSUM_TYPE) {
            Some(value) if trailer_checksum.is_some() => {
                Some(ChecksumType::parse(value).map_err(|_| ChecksumReject::InvalidChecksumValue)?)
            }
            _ => None,
        };
        // A keyed lookup, not a second walk of the map: the arbitration above already walks it
        // once, and this runs on every request including the overwhelming majority that claim
        // nothing.
        let md5 = match headers.get_str(&CONTENT_MD5) {
            Some(value) => Some(ContentMd5::parse(value).map_err(ChecksumReject::of)?),
            None => None,
        };
        Ok(match subject {
            ChecksumSubject::RequestBody => Self {
                md5,
                checksum,
                trailer_checksum,
                trailer_type,
            },
            ChecksumSubject::NamedResource => Self {
                md5,
                checksum: None,
                trailer_checksum: None,
                trailer_type: None,
            },
            ChecksumSubject::None => Self::NONE,
        })
    }

    /// Whether this body owes any comparison at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.md5.is_none() && self.checksum.is_none() && self.trailer_checksum.is_none()
    }

    /// The checksum the request claimed, before it has been checked against anything.
    ///
    /// Named `declared` rather than `checksum` so that a caller reaching for "the checksum of this
    /// object" cannot pick up the caller's claim by accident; the verified value lives on
    /// [`ChecksumVerified`] and only exists once the comparison has happened.
    #[must_use]
    pub fn declared_checksum(&self) -> Option<&ChecksumSpec> {
        self.checksum.as_ref()
    }

    /// Whether the request claimed a `Content-MD5`.
    #[must_use]
    pub fn declares_content_md5(&self) -> bool {
        self.md5.is_some()
    }

    /// Opens exactly the digests these obligations require, and no others.
    ///
    /// A body claiming nothing opens nothing, so the cost of this module on a request with no
    /// integrity claim is one branch.
    #[must_use]
    pub fn begin(self) -> BodyDigests {
        let algorithm = self.checksum.map(|spec| spec.algorithm()).or(self.trailer_checksum);
        BodyDigests {
            md5: self.md5.map(|_| ContentMd5::digester()),
            checksum: algorithm.map(ChecksumAlgorithm::checksummer),
            expected: self,
            observed_bytes: 0,
        }
    }
}

/// The digests of one body, running.
///
/// Fed from the same borrowed run of bytes the rest of the read already has in cache — the frame
/// the socket just delivered on the unframed path, the run the decoder just produced on the framed
/// one — so the digests cost a pass the body was making anyway rather than a pass of their own.
/// [`BodyDigests::observed_bytes`] is what turns "one pass" into an equality a test can state.
///
/// This is deliberately **not** a [`ByteObserver`]: an observer may not fail, and this ends in a
/// comparison that must be able to. Wearing the observer trait would force the failure to be
/// reported somewhere other than where it is discovered, which is how a mismatch becomes a log
/// line instead of a refusal.
///
/// [`ByteObserver`]: rustfs_gateway_stream::ByteObserver
pub struct BodyDigests {
    expected: BodyIntegrity,
    md5: Option<Md5Digest>,
    checksum: Option<Box<dyn Checksummer>>,
    observed_bytes: u64,
}

impl BodyDigests {
    /// Shows the digests the next run of body bytes.
    ///
    /// Must be called with the **decoded** body — the object's own octets — and never with the
    /// wire framing around them. A checksum computed over `aws-chunked` framing is a checksum of
    /// something the caller never claimed a digest for, so it can only ever fail, and a check that
    /// can only fail is indistinguishable in a report from a check that found something.
    pub fn update(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.observed_bytes = self.observed_bytes.saturating_add(bytes.len() as u64);
        if let Some(md5) = self.md5.as_mut() {
            md5.update(bytes);
        }
        if let Some(checksum) = self.checksum.as_mut() {
            checksum.update(bytes);
        }
    }

    /// How many body bytes the digests have been shown.
    ///
    /// The single-pass witness: a caller that fed the digests twice shows up here as twice the
    /// body length, which is an equality a test asserts rather than a timing difference nobody
    /// notices.
    #[must_use]
    pub fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }

    /// Closes every digest and compares it against what the request claimed.
    ///
    /// Consuming, because a comparison that could be repeated is a comparison whose answer depends
    /// on when it was asked.
    ///
    /// # Errors
    ///
    /// [`ChecksumReject::BadDigest`] when `Content-MD5` disagrees with the body, and
    /// [`ChecksumReject::ChecksumMismatch`] when the `x-amz-checksum-*` value does. `Content-MD5`
    /// is compared first only so that a request carrying both gets the older, more widely
    /// understood code for the older header; both are compared whichever fails.
    pub fn verify(self) -> Result<ChecksumVerified, ChecksumReject> {
        self.verify_with_trailers(&TrailingHeaders::empty())
    }

    /// Closes every digest after EOF and compares a trailer-carried checksum when declared.
    ///
    /// # Errors
    ///
    /// In addition to [`Self::verify`]'s mismatch errors,
    /// [`ChecksumReject::TrailerChecksumMissing`] when the declared field is absent and
    /// [`ChecksumReject::InvalidChecksumValue`] when it is not a strict checksum value.
    pub fn verify_with_trailers(self, trailers: &TrailingHeaders) -> Result<ChecksumVerified, ChecksumReject> {
        let Self {
            expected,
            md5,
            checksum,
            observed_bytes,
        } = self;

        // Each obligation is matched against its own running digest, and a claim whose digest is
        // missing is a refusal rather than a skip. `begin` opens one exactly when the other is
        // present, so the mismatched arms are unreachable — but "unreachable, therefore ignore it"
        // is the shape this module was written to remove, and writing it here would put the shape
        // back inside the one function that must not have it.
        match (expected.md5, md5) {
            (Some(claimed), Some(running)) => claimed.verify(&running.finish()).map_err(ChecksumReject::of)?,
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => return Err(ChecksumReject::BadDigest),
        }

        let expected_checksum = match (expected.checksum, expected.trailer_checksum) {
            (Some(claimed), None) => Some(claimed),
            (None, Some(algorithm)) => {
                let name = HeaderName::from_static(algorithm.header_name());
                let value = trailers
                    .get(&name)
                    .ok_or(ChecksumReject::TrailerChecksumMissing)?
                    .to_str()
                    .map_err(|_| ChecksumReject::InvalidChecksumValue)?;
                let claimed = ChecksumSpec::parse_header(algorithm.header_name(), value).map_err(ChecksumReject::of)?;
                Some(match expected.trailer_type {
                    Some(kind) => claimed.with_type(kind).map_err(ChecksumReject::of)?,
                    None => claimed,
                })
            }
            (Some(_), Some(_)) => return Err(ChecksumReject::HeaderAndTrailerBothPresent),
            (None, None) => None,
        };

        let verified = match (expected_checksum, checksum) {
            (Some(claimed), Some(running)) => {
                let digest = running.finalize();
                // The claim is compared as bytes, not as text: two base64 spellings of one digest
                // are one digest, and a text comparison would make the padding a security boundary.
                let expected_digest = claimed.digest().map_err(ChecksumReject::of)?;
                if expected_digest.as_bytes() != digest.as_ref() {
                    return Err(ChecksumReject::ChecksumMismatch);
                }
                Some(claimed)
            }
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => return Err(ChecksumReject::ChecksumMismatch),
        };

        Ok(ChecksumVerified {
            checksum: verified,
            verified_bytes: observed_bytes,
        })
    }
}

impl core::fmt::Debug for BodyDigests {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BodyDigests")
            .field("expected", &self.expected)
            .field("observed_bytes", &self.observed_bytes)
            .finish()
    }
}

/// Proof that a body's declared digests were computed and compared, and agreed.
///
/// There is no public constructor, no `Default`, and no way to build one from a checksum value:
/// the only expression in this workspace that produces a `ChecksumVerified` is the successful
/// return of [`BodyDigests::verify`], which has just done the comparison. It is deliberately
/// neither `Clone` nor `Copy`, so one request's receipt cannot be duplicated into another's.
///
/// **What it proves, exactly.** That every obligation this body carried was discharged. A body that
/// carried none produces one whose [`ChecksumVerified::checksum`] is `None` — "there was nothing to
/// compare" and "the comparison agreed" are both honest reasons to hold one, and the value
/// distinguishes them. What is *not* representable is a claimed checksum that was skipped: a
/// declared value that disagreed returns [`ChecksumReject::ChecksumMismatch`] and produces no
/// receipt at all.
///
/// It carries the checksum rather than a bare unit so the value a storage layer records is the one
/// that was checked, not the one that was claimed.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct ChecksumVerified {
    checksum: Option<ChecksumSpec>,
    verified_bytes: u64,
}

impl ChecksumVerified {
    /// The checksum that was compared and agreed, if the request claimed one.
    ///
    /// `None` means the request claimed no `x-amz-checksum-*` value — never that one was claimed
    /// and skipped, which is unrepresentable: a claimed value that did not agree returns
    /// [`ChecksumReject::ChecksumMismatch`] and produces no `ChecksumVerified` at all.
    #[must_use]
    pub fn checksum(&self) -> Option<&ChecksumSpec> {
        self.checksum.as_ref()
    }

    /// How many body bytes the agreeing digests were computed over.
    #[must_use]
    pub fn verified_bytes(&self) -> u64 {
        self.verified_bytes
    }
}
