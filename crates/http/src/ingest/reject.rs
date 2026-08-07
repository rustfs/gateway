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

//! Every way an `aws-chunked` body is refused, and what each refusal is on the wire.
//!
//! Responsible for: the [`ChunkReject`] set, its status and S3 error code, and the one question
//! an upper layer must answer at the moment of failure — may what has already been received be
//! committed.
//! NOT responsible for: deciding *when* to refuse (the decoder and the signer do that), and
//! rendering a response body.
//! Upstream: `http`, `rustfs-gateway-types`. Downstream: `decoder`, `signer`, `pipeline`, and
//! whatever serves the response.
//!
//! # Why this is not a `WireReject` variant
//!
//! [`crate::WireReject`] is decidable from the request head alone and is always a `400`; the
//! module documentation says so in as many words, and one of its refusals being a `403` would
//! put a signature failure in the same bucket as a malformed header in every log and metric. A
//! chunk signature failure *is* a `403`, and it is decidable only from the body — so it is a
//! different type, and the two stay honest about what they each are.

use http::StatusCode;
use rustfs_gateway_types::ErrorCode;

/// Why an `aws-chunked` body was refused.
///
/// Each variant names a rule an attacker would otherwise get to choose the interpretation of.
/// They are separate variants rather than one "malformed framing" because an operator watching a
/// flood needs to tell a broken SDK from a chunk-extension smuggling probe, and because a test
/// that asserts "it was refused" passes just as well when the wrong rule fired.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkReject {
    /// The announced chunk size is above [`crate::ChunkLimits::max_chunk_size`].
    ///
    /// Refused at the chunk header, before one data byte is read. This is the ceiling whose
    /// absence turns a chunk decoder into a remotely triggered memory exhaustion.
    ChunkSizeTooLarge {
        /// The size the peer announced.
        declared: u64,
        /// The configured ceiling.
        max: u32,
    },
    /// The chunk-size line, including its extension, is longer than the metadata ceiling.
    ChunkMetaTooLong,
    /// The chunk size is not a bare run of hexadecimal digits: a sign, a `0x` prefix, whitespace,
    /// an empty field, or more than sixteen digits.
    MalformedChunkSize,
    /// The chunk size carries more than one leading zero.
    ///
    /// Stricter than RFC 9112, deliberately: a thousand leading zeros is the same number to one
    /// parser and an overflow or a truncation to another, and that disagreement is the primitive
    /// a desync is built from.
    LeadingZeros,
    /// A line ended with something other than exactly CRLF.
    BadLineTerminator,
    /// The chunk extension is not the single, exact extension the mode permits.
    ///
    /// Signed framing accepts `;chunk-signature=<64 lowercase hex>` and nothing else — not a
    /// second extension, not a quoted value, not uppercase hex. Unsigned framing accepts no
    /// extension at all.
    UnexpectedExtension,
    /// A zero-sized chunk appeared in a position where the stream continues.
    ZeroSizedNonTerminalChunk,
    /// More chunks arrived than the declared decoded length can justify.
    TooManyChunks {
        /// The ceiling derived from the declared decoded length.
        max: u64,
    },
    /// The framing overhead outgrew its share of the decoded body.
    OverheadRatioExceeded {
        /// Bytes spent on chunk headers and CRLFs.
        overhead: u64,
        /// Bytes of body decoded so far.
        decoded: u64,
    },
    /// More body arrived than `x-amz-decoded-content-length` declared.
    ///
    /// Refused at the first byte past the declaration, not at the end: the whole point of the
    /// check is that the excess is never accepted, and a check at the end has already accepted it.
    DecodedLengthOverflow {
        /// The declared decoded length.
        declared: u64,
    },
    /// Less body arrived than `x-amz-decoded-content-length` declared.
    DecodedLengthUnderflow {
        /// The declared decoded length.
        declared: u64,
        /// What actually arrived.
        actual: u64,
    },
    /// A chunk signature did not verify, or the chain that seeds it was broken.
    SignatureChainBroken {
        /// The zero-based index of the chunk whose signature failed.
        chunk_index: u32,
    },
    /// The stream ended before the terminal chunk.
    ///
    /// Never an end-of-stream: presenting a truncated upload to the handler as a complete one is
    /// how a partial object is committed as a whole one.
    TruncatedStream,
    /// The declared framing mode and the declared lengths contradict each other.
    ModeConfusion(ModeConfusion),
}

/// Which of the mode/length cross-checks failed.
///
/// Separate from [`ChunkReject`] so the four cases can be asserted individually: "the request was
/// refused" is satisfied by the wrong rule firing just as well as by the right one.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeConfusion {
    /// A framed mode without `x-amz-decoded-content-length`.
    DecodedLengthMissing,
    /// A non-framed mode carrying `x-amz-decoded-content-length`.
    ///
    /// The header is forbidden rather than ignored: outside a framed mode there is no decoded
    /// length distinct from `Content-Length`, so a second length is a second answer to "how long
    /// is the body", which is the question a smuggler wants two answers to.
    DecodedLengthNotAllowed,
    /// `x-amz-decoded-content-length` is not a bare run of ASCII digits.
    DecodedLengthMalformed,
    /// The decoded length cannot fit inside the wire length once minimal framing is accounted for.
    DecodedLengthExceedsWireLength {
        /// The declared decoded length.
        decoded: u64,
        /// The wire `Content-Length`.
        wire: u64,
    },
    /// A framed body arrived without a wire length at all.
    ///
    /// `Transfer-Encoding: chunked` around `aws-chunked` gives two framing layers whose ends are
    /// declared independently; the outer one cannot be used to bound the inner one, so the
    /// consistency check of rule C-7 has nothing to run against.
    WireLengthMissing,
}

impl ChunkReject {
    /// The HTTP status for this refusal.
    ///
    /// `403` for a signature failure and `400` for everything else. The split is the reason this
    /// type exists separately from [`crate::WireReject`]: a framing error is a client bug and a
    /// signature failure is an authentication outcome, and an operator who cannot tell them apart
    /// in a dashboard cannot tell an attack from a broken SDK.
    #[must_use]
    pub fn to_status(&self) -> StatusCode {
        match self {
            Self::SignatureChainBroken { .. } => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// The S3 error code for this refusal.
    ///
    /// Coarse on purpose. The exact rule belongs in the operator's log; a code that named it
    /// would let a peer enumerate the decoder's checks one request at a time.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::SignatureChainBroken { .. } => ErrorCode::SIGNATURE_DOES_NOT_MATCH,
            Self::ChunkSizeTooLarge { .. } => ErrorCode::INVALID_CHUNK_SIZE,
            Self::DecodedLengthUnderflow { .. } | Self::TruncatedStream => ErrorCode::INCOMPLETE_BODY,
            Self::DecodedLengthOverflow { .. } => ErrorCode::INCOMPLETE_BODY,
            _ => ErrorCode::INVALID_REQUEST,
        }
    }

    /// Whether anything received so far may be committed.
    ///
    /// Always `false`. It is a method rather than a constant so the reason travels with the type:
    /// every refusal here means the gateway and the peer disagree about what the body was, and
    /// committing a prefix of a body whose framing is in dispute is how a truncation attack ends
    /// with a complete-looking object.
    #[must_use]
    pub fn may_commit(&self) -> bool {
        false
    }

    /// Whether this refusal ends the connection whatever the caller does.
    ///
    /// Not a constant. The rule is RFC 9112 §9.3 — *a server MUST read the entire request message
    /// body or close the connection after sending its response* — and the fact that makes it
    /// branch here is that **`aws-chunked` is not the connection's framing.** It is a content
    /// encoding carried inside a body whose extent RFC 9112 §6.3 already fixed from
    /// `Content-Length`; [`crate::validate_decoded_length`] refuses a framed body that has no wire
    /// length at all. So a chunk-level syntax error leaves the *connection* perfectly
    /// resynchronisable: the remaining wire octets are counted, and a caller that drains them may
    /// keep the connection.
    ///
    /// `true` — the connection ends — for four families, each for its own reason:
    ///
    /// | Family | Why the connection cannot survive |
    /// | --- | --- |
    /// | [`Self::TruncatedStream`] | the peer stopped sending; RFC 9112 §6.3 makes an incomplete request message one the server answers and then closes, and there is nothing left to drain in any case |
    /// | [`Self::SignatureChainBroken`] | the peer is not established as who it claimed, and draining is work this server would be doing for an unauthenticated caller. **Policy, not RFC**: §9.3 only forces the close once the decision not to drain is made |
    /// | [`Self::ChunkSizeTooLarge`], [`Self::TooManyChunks`], [`Self::OverheadRatioExceeded`], [`Self::DecodedLengthOverflow`] | refused *for* the resource they were about to spend, so draining performs the transfer the refusal exists to avoid. **Policy**, with the same §9.3 consequence |
    /// | [`ModeConfusion::WireLengthMissing`] | no wire length, so the remainder has no known extent — RFC 9112 §6.3, the same reason a framing verdict closes |
    ///
    /// Everything else — a malformed size line, leading zeros, a bad terminator, an unexpected
    /// extension, a zero-sized non-terminal chunk, an over-long meta line, a short body, the other
    /// mode confusions — is a syntax verdict inside an intact wire body, and answers `false`.
    ///
    /// `false` is not "the connection survives": it is "the connection survives if and only if the
    /// remainder is drained", exactly as in [`crate::WireReject::must_close_connection`].
    #[must_use]
    pub fn must_close_connection(&self) -> bool {
        matches!(
            self,
            Self::TruncatedStream
                | Self::SignatureChainBroken { .. }
                | Self::ChunkSizeTooLarge { .. }
                | Self::TooManyChunks { .. }
                | Self::OverheadRatioExceeded { .. }
                | Self::DecodedLengthOverflow { .. }
                | Self::ModeConfusion(ModeConfusion::WireLengthMissing)
        )
    }

    /// A short, stable label for logs, metrics and tests.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChunkSizeTooLarge { .. } => "chunk-size-too-large",
            Self::ChunkMetaTooLong => "chunk-meta-too-long",
            Self::MalformedChunkSize => "malformed-chunk-size",
            Self::LeadingZeros => "leading-zeros",
            Self::BadLineTerminator => "bad-line-terminator",
            Self::UnexpectedExtension => "unexpected-extension",
            Self::ZeroSizedNonTerminalChunk => "zero-sized-non-terminal-chunk",
            Self::TooManyChunks { .. } => "too-many-chunks",
            Self::OverheadRatioExceeded { .. } => "overhead-ratio-exceeded",
            Self::DecodedLengthOverflow { .. } => "decoded-length-overflow",
            Self::DecodedLengthUnderflow { .. } => "decoded-length-underflow",
            Self::SignatureChainBroken { .. } => "signature-chain-broken",
            Self::TruncatedStream => "truncated-stream",
            Self::ModeConfusion(_) => "mode-confusion",
        }
    }
}

impl core::fmt::Display for ChunkReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never renders a signature, presented or expected: "expected versus actual" in an
        // authentication error is a signing oracle. Only the chunk index appears.
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ChunkReject {}
