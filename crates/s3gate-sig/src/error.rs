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

//! The rejection reasons produced while parsing the frozen signature dimensions.
//!
//! Responsible for: one closed, `Copy` reason code per way a signature dimension can fail to
//! parse, and a `Display` text that never echoes attacker-controlled input back to the caller.
//! NOT responsible for: HTTP status mapping (that is `s3gate-core`), verification outcomes
//! (see [`crate::VerifyRejection`]), or carrying any byte of the offending input.
//! Upstream: none. Downstream: every parser in this crate, then `s3gate-core`'s authn stage.

use core::fmt;

/// Why a value could not be parsed into one of the frozen signature dimensions.
///
/// Every variant is fieldless or carries a closed enum, so the type is `Copy` and cannot
/// smuggle a slice of the request into a log line. That is deliberate: an error that quotes
/// the rejected `x-amz-content-sha256` value turns the error log into a request-echo surface,
/// and an error that quotes a signature turns it into a signing oracle.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigParseError {
    /// `x-amz-content-sha256` is not any of the six accepted forms.
    MalformedContentSha256,
    /// A hex string was not exactly the expected length, or contained a byte outside `[0-9a-f]`.
    ///
    /// Uppercase hex is rejected: AWS canonicalises digests and signatures as lowercase, and
    /// accepting both spellings would make two distinct strings decode to one digest.
    MalformedHex,
    /// A base64 string was not canonical standard base64 of the expected length.
    ///
    /// Rejected: URL-safe alphabet, missing or extra padding, embedded whitespace, and a final
    /// character whose unused low bits are non-zero (two different strings would otherwise
    /// decode to the same digest, which is a comparison-bypass surface).
    MalformedBase64,
    /// The value was recognised, is a real AWS feature, and is deliberately not implemented.
    ///
    /// The caller must surface `501 NotImplemented`. It must never fall through to the
    /// SigV4 path: a SigV4a request handled by a SigV4 verifier is a downgrade.
    NotImplemented(Unimplemented),
    /// A trailer set was declared for a payload mode that has no trailer chunk.
    TrailerNotAllowed,
    /// A `-TRAILER` payload mode arrived without a declared trailer set.
    TrailerRequired,
    /// A trailer signature was declared for `STREAMING-UNSIGNED-PAYLOAD-TRAILER`.
    ///
    /// The unsigned streaming form has no chunk signatures, so it has no trailer signature
    /// to seed either; accepting one would mean verifying a signature chain that does not exist.
    TrailerSignatureNotAllowed,
    /// `x-amz-trailer` declared the trailer mode but named no trailer.
    ///
    /// An empty declaration cannot be cross-checked against what actually arrives, so it is an
    /// ambiguity surface rather than a permissive case.
    EmptyTrailerDeclaration,
    /// More trailers were declared than AWS can send (one checksum plus one trailer signature).
    TooManyTrailers,
    /// The same trailer name was declared twice.
    DuplicateTrailerName,
    /// A trailer name is not a lowercase `x-amz-` HTTP token.
    InvalidTrailerName,
    /// The `Authorization` algorithm token is not a known signing algorithm.
    UnknownAlgorithm,
    /// The credential-scope service is not one of the five S3-family services.
    UnknownService,
    /// A session token was present but empty.
    EmptySessionToken,
    /// An access key id was empty, over 128 bytes, or contained a non-graphic ASCII byte.
    ///
    /// The character-set rule is not cosmetic: the access key id is the one authentication value
    /// that legitimately reaches a log line and an audit record, so a `\r\n` inside it is log
    /// injection and a control byte can corrupt the record it is written into.
    InvalidAccessKeyId,
}

/// The recognised-but-unimplemented features, kept apart from "unknown" on purpose.
///
/// "Unknown" is a `400`; "recognised and refused" is a `501`. Collapsing the two would let a
/// SigV4a client believe its request was malformed, and — far worse — invites a later
/// maintainer to "fix" it by routing the request into the SigV4 verifier.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unimplemented {
    /// `AWS4-ECDSA-P256-SHA256` (SigV4a, used by Multi-Region Access Points).
    SigV4a,
    /// `STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD[-TRAILER]`, the streaming form of SigV4a.
    StreamingSigV4a,
}

impl fmt::Display for Unimplemented {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::SigV4a => "SigV4a (AWS4-ECDSA-P256-SHA256) is not implemented",
            Self::StreamingSigV4a => "streaming SigV4a is not implemented",
        };
        f.write_str(text)
    }
}

impl fmt::Display for SigParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every arm is a constant. Nothing derived from the request may appear here.
        let text = match self {
            Self::MalformedContentSha256 => "x-amz-content-sha256 is not a recognised payload mode",
            Self::MalformedHex => "expected a lowercase hex string of the exact required length",
            Self::MalformedBase64 => "expected canonical standard base64 of the exact required length",
            Self::NotImplemented(feature) => return fmt::Display::fmt(feature, f),
            Self::TrailerNotAllowed => "this payload mode does not carry a trailer",
            Self::TrailerRequired => "this payload mode requires a declared trailer set",
            Self::TrailerSignatureNotAllowed => "an unsigned streaming payload has no trailer signature",
            Self::EmptyTrailerDeclaration => "x-amz-trailer declared no trailer name",
            Self::TooManyTrailers => "more trailers were declared than the protocol allows",
            Self::DuplicateTrailerName => "a trailer name was declared more than once",
            Self::InvalidTrailerName => "a trailer name is not a lowercase x-amz- token",
            Self::UnknownAlgorithm => "unknown signing algorithm",
            Self::UnknownService => "unknown credential-scope service",
            Self::EmptySessionToken => "session token is present but empty",
            Self::InvalidAccessKeyId => "access key id is empty, too long, or not an ASCII graphic string",
        };
        f.write_str(text)
    }
}

impl core::error::Error for SigParseError {}
