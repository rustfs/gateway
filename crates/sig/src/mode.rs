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

//! The frozen payload/framing mode, derived from `x-amz-content-sha256` and nothing else.
//!
//! Responsible for: the six [`PayloadMode`] states, the declared trailer set, the strict parse of
//! `x-amz-content-sha256`, and the two decisions the wire layer is allowed to ask for —
//! [`PayloadMode::is_framed`] and [`PayloadMode::requires_decoded_length`].
//! NOT responsible for: reading headers off a request, decoding chunks, verifying chunk
//! signatures, or computing digests. This module never sees a body and never sees
//! `Content-Encoding` — no function here takes it, which is the point.
//! Upstream: [`crate::SigParseError`], [`crate::codec`]. Downstream: `rustfs-gateway-http`'s chunked
//! decoder (P3-02), the ingest pipeline (P3-03), and P2-03's canonical request builder.

use core::fmt;
use std::borrow::Cow;

use crate::contracts::SIGNATURE_PAYLOAD_TOKEN_VERBATIM;

use smallvec::SmallVec;

use crate::codec::{decode_base64_sha256, decode_hex_lower, encode_base64_sha256, encode_hex_lower};
use crate::error::{SigParseError, Unimplemented};

/// The `x-amz-content-sha256` value that means "do not verify the payload".
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// The `x-amz-content-sha256` value that selects signed aws-chunked framing.
pub const STREAMING_SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
/// The `x-amz-content-sha256` value that selects signed aws-chunked framing with a trailer.
pub const STREAMING_SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
/// The `x-amz-content-sha256` value that selects unsigned aws-chunked framing with a trailer.
pub const STREAMING_UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
/// The SigV4a streaming value; recognised, refused with `501`, never treated as SigV4.
pub const STREAMING_ECDSA: &str = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD";
/// The SigV4a streaming-with-trailer value; recognised, refused with `501`.
pub const STREAMING_ECDSA_TRAILER: &str = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER";

/// Lowercase hex SHA-256 of the empty byte string, the token signed for a body-less request.
pub const EMPTY_PAYLOAD_SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The most trailers a request may declare: one checksum, plus the trailer signature.
pub const MAX_DECLARED_TRAILERS: usize = 2;

/// A validated trailing-header name, as declared by `x-amz-trailer`.
///
/// Construction is checked, so a `TrailerName` in hand is already lowercase and `x-amz-` scoped;
/// a case-insensitive comparison against what actually arrives is therefore unnecessary, and the
/// "declared" and "received" sets can be compared directly.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TrailerName(String);

impl TrailerName {
    /// Validates and stores a trailer name.
    ///
    /// # Errors
    ///
    /// [`SigParseError::InvalidTrailerName`] unless the name is a non-empty lowercase HTTP token
    /// starting with `x-amz-`. Uppercase is rejected rather than normalised: normalising here
    /// would mean two spellings map to one name, and the declared/received cross-check exists
    /// precisely to catch a mismatch between two spellings.
    pub fn new(name: &str) -> Result<Self, SigParseError> {
        if !name.starts_with("x-amz-") || name.len() <= "x-amz-".len() {
            return Err(SigParseError::InvalidTrailerName);
        }
        let valid = name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'));
        if !valid {
            return Err(SigParseError::InvalidTrailerName);
        }
        Ok(Self(name.to_owned()))
    }

    /// The validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TrailerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The trailer set a client declared through `x-amz-trailer`, with its invariants already checked.
///
/// Fields are private on purpose: [`DeclaredTrailers::new`] rejects the empty declaration, more
/// than [`MAX_DECLARED_TRAILERS`] names, and duplicates. A public field would let a caller build
/// exactly the states the constructor exists to reject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredTrailers {
    names: SmallVec<[TrailerName; 2]>,
    signed: bool,
}

impl DeclaredTrailers {
    /// Builds a declared trailer set.
    ///
    /// # Errors
    ///
    /// * [`SigParseError::EmptyTrailerDeclaration`] — the trailer mode was selected but nothing
    ///   was named, which leaves nothing to cross-check the arriving trailers against.
    /// * [`SigParseError::TooManyTrailers`] — more than one checksum plus one trailer signature.
    /// * [`SigParseError::DuplicateTrailerName`] — the same name twice; the duplicate would make
    ///   "declared count" and "received count" disagree for a well-formed request.
    pub fn new<I>(names: I, signed: bool) -> Result<Self, SigParseError>
    where
        I: IntoIterator<Item = TrailerName>,
    {
        let collected: SmallVec<[TrailerName; 2]> = names.into_iter().collect();
        if collected.is_empty() {
            return Err(SigParseError::EmptyTrailerDeclaration);
        }
        if collected.len() > MAX_DECLARED_TRAILERS {
            return Err(SigParseError::TooManyTrailers);
        }
        for (index, name) in collected.iter().enumerate() {
            if collected[index + 1..].contains(name) {
                return Err(SigParseError::DuplicateTrailerName);
            }
        }
        Ok(Self {
            names: collected,
            signed,
        })
    }

    /// The declared trailer names, in declaration order.
    #[must_use]
    pub fn names(&self) -> &[TrailerName] {
        &self.names
    }

    /// Whether `x-amz-trailer-signature` is expected after the trailing headers.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signed
    }

    /// Whether the trailers that actually arrived are exactly the declared set.
    ///
    /// Order is irrelevant, count is not: a request that declares one trailer and sends two has
    /// sent one unsigned trailing header, and the wire layer must reject it rather than ignore it.
    #[must_use]
    pub fn matches_received(&self, received: &[TrailerName]) -> bool {
        received.len() == self.names.len() && self.names.iter().all(|name| received.contains(name))
    }
}

/// The trailer dimension of a streaming payload.
///
/// This is not a `bool`: the trailer form has to carry the declared names and whether a trailer
/// signature follows, or the declared-versus-received cross-check cannot be written at all.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrailerSet {
    /// No `x-amz-trailer` was declared.
    None,
    /// `x-amz-trailer` declared a validated, non-empty set of trailing headers.
    Declared(DeclaredTrailers),
}

impl TrailerSet {
    /// Whether any trailer was declared.
    #[must_use]
    pub fn is_declared(&self) -> bool {
        matches!(self, Self::Declared(_))
    }

    /// The declared set, if any.
    #[must_use]
    pub fn declared(&self) -> Option<&DeclaredTrailers> {
        match self {
            Self::Declared(declared) => Some(declared),
            _ => None,
        }
    }
}

/// The exact string the client signed in the canonical request for this payload mode.
///
/// [`PayloadMode::Base64Sha256`] and [`PayloadMode::ExactSha256`] can hold the same 32 bytes and
/// still produce different tokens here — the canonical request must reproduce what the client
/// sent, not a re-spelling of it. Both spellings are canonicalised on parse (lowercase hex,
/// canonical standard base64), so re-encoding is byte-identical to the original header value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPayloadToken(Cow<'static, str>);

impl CanonicalPayloadToken {
    /// The token as it appears in the canonical request.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalPayloadToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How the payload is framed and how (or whether) it is verified.
///
/// # The one invariant of this crate
///
/// The framing mode is derived from `x-amz-content-sha256`, and from nothing else.
///
/// * `Content-Encoding: aws-chunked` is metadata. It must **never**, on its own, enable the chunk
///   parser. A plain `PutObject` that merely declares the encoding is not a streaming upload;
///   treating it as one produced three separate production regressions (rustfs#4960, #4964,
///   #4968), and disagreement between two layers about where the body ends is the classic
///   application-layer smuggling shape.
/// * `x-amz-decoded-content-length` is **required** under the two streaming modes and **rejected**
///   under the other four. See [`PayloadMode::requires_decoded_length`].
///
/// No constructor or method in this module accepts `Content-Encoding`, so the wrong derivation is
/// not merely discouraged — it cannot be expressed against this API.
///
/// # Adding a state stays non-breaking
///
/// The enum is `#[non_exhaustive]`: a downstream `match` must keep a wildcard arm, so the SigV4a
/// streaming mode can be added later without a major version. A `match` that omits the wildcard
/// does not compile:
///
/// ```compile_fail,E0004
/// use rustfs_gateway_sig::PayloadMode;
/// fn framed(mode: &PayloadMode) -> bool {
///     match mode {
///         PayloadMode::Empty | PayloadMode::Unsigned => false,
///         PayloadMode::ExactSha256(_) | PayloadMode::Base64Sha256(_) => false,
///         PayloadMode::StreamingSigned { .. } | PayloadMode::StreamingUnsigned { .. } => true,
///     }
/// }
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadMode {
    /// No body, and no `x-amz-content-sha256` header to interpret.
    ///
    /// The canonical token is the hex digest of the empty payload, which is what SDKs sign for a
    /// body-less request. A presigned request that omits the header is `Unsigned`, not `Empty`;
    /// that selection is P2-03's, because it needs the `AuthScheme`.
    Empty,
    /// `x-amz-content-sha256` was 64 lowercase hex characters.
    ExactSha256([u8; 32]),
    /// `x-amz-content-sha256` was the canonical base64 of a 32-byte digest.
    ///
    /// Generic REST SigV4 signers emit this form (s3s#631). It carries the same digest as
    /// [`PayloadMode::ExactSha256`] but a different canonical token, so the two cannot be merged.
    Base64Sha256([u8; 32]),
    /// `UNSIGNED-PAYLOAD`: the body is not covered by the signature.
    Unsigned,
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]`: aws-chunked framing, each chunk signed.
    StreamingSigned {
        /// The declared trailer set; [`TrailerSet::None`] for the non-`-TRAILER` form.
        trailer: TrailerSet,
    },
    /// `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: aws-chunked framing, no chunk signatures.
    StreamingUnsigned {
        /// The declared trailer set; always [`TrailerSet::Declared`] when produced by [`PayloadMode::parse`].
        trailer: TrailerSet,
    },
}

impl PayloadMode {
    /// Parses the `x-amz-content-sha256` header value together with the declared trailer set.
    ///
    /// The trailer set is a parameter rather than a later mutation because the two are only valid
    /// in specific combinations, and a type that can be half-built can be observed half-built.
    ///
    /// # Errors
    ///
    /// * [`SigParseError::NotImplemented`] for the SigV4a streaming values. The caller returns
    ///   `501`; it must not fall through to the SigV4 chunk decoder.
    /// * [`SigParseError::TrailerNotAllowed`] / [`SigParseError::TrailerRequired`] when the
    ///   declared trailers disagree with the mode.
    /// * [`SigParseError::TrailerSignatureNotAllowed`] for a trailer signature on the unsigned
    ///   streaming form, which has no signature chain to seed it.
    /// * [`SigParseError::MalformedContentSha256`] for anything else, including an empty value,
    ///   a differently-cased keyword, and a surrounding-whitespace variant of a valid value.
    pub fn parse(content_sha256: &str, trailer: TrailerSet) -> Result<Self, SigParseError> {
        match content_sha256 {
            UNSIGNED_PAYLOAD => {
                reject_trailer(&trailer)?;
                Ok(Self::Unsigned)
            }
            STREAMING_SIGNED => {
                reject_trailer(&trailer)?;
                Ok(Self::StreamingSigned { trailer })
            }
            STREAMING_SIGNED_TRAILER => {
                require_trailer(&trailer)?;
                Ok(Self::StreamingSigned { trailer })
            }
            STREAMING_UNSIGNED_TRAILER => {
                require_trailer(&trailer)?;
                if trailer.declared().is_some_and(DeclaredTrailers::is_signed) {
                    return Err(SigParseError::TrailerSignatureNotAllowed);
                }
                Ok(Self::StreamingUnsigned { trailer })
            }
            STREAMING_ECDSA | STREAMING_ECDSA_TRAILER => Err(SigParseError::NotImplemented(Unimplemented::StreamingSigV4a)),
            other if other.len() == 64 => {
                reject_trailer(&trailer)?;
                decode_hex_lower::<32>(other)
                    .map(Self::ExactSha256)
                    .map_err(|_| SigParseError::MalformedContentSha256)
            }
            other if other.len() == 44 => {
                reject_trailer(&trailer)?;
                decode_base64_sha256(other)
                    .map(Self::Base64Sha256)
                    .map_err(|_| SigParseError::MalformedContentSha256)
            }
            _ => Err(SigParseError::MalformedContentSha256),
        }
    }

    /// Whether the body is aws-chunked framed.
    ///
    /// This is the only sanctioned input to the decision "run the chunk parser". `Content-Encoding`
    /// is not an input to it, here or anywhere downstream.
    #[must_use]
    pub fn is_framed(&self) -> bool {
        matches!(self, Self::StreamingSigned { .. } | Self::StreamingUnsigned { .. })
    }

    /// Whether `x-amz-decoded-content-length` must be present.
    ///
    /// `true` means the header is mandatory and its absence is a rejection. `false` means the
    /// header is **forbidden**, not optional: under a non-streaming mode there is no decoded
    /// length distinct from `Content-Length`, so a second, contradictory length is an ambiguity
    /// the wire layer must refuse rather than reconcile.
    #[must_use]
    pub fn requires_decoded_length(&self) -> bool {
        self.is_framed()
    }

    /// Whether each chunk carries its own signature.
    #[must_use]
    pub fn has_chunk_signatures(&self) -> bool {
        matches!(self, Self::StreamingSigned { .. })
    }

    /// The declared trailer set, for the streaming modes.
    #[must_use]
    pub fn trailer(&self) -> Option<&TrailerSet> {
        match self {
            Self::StreamingSigned { trailer } | Self::StreamingUnsigned { trailer } => Some(trailer),
            _ => None,
        }
    }

    /// The 32-byte digest the body must hash to, when the mode pins one.
    #[must_use]
    pub fn digest(&self) -> Option<&[u8; 32]> {
        match self {
            Self::ExactSha256(digest) | Self::Base64Sha256(digest) => Some(digest),
            _ => None,
        }
    }

    /// The exact token this mode contributes to the canonical request.
    #[must_use]
    pub fn canonical_payload_token(&self) -> CanonicalPayloadToken {
        let token = match self {
            Self::Empty => Cow::Borrowed(EMPTY_PAYLOAD_SHA256_HEX),
            Self::ExactSha256(digest) => Cow::Owned(encode_hex_lower(digest)),
            Self::Base64Sha256(digest) if SIGNATURE_PAYLOAD_TOKEN_VERBATIM => Cow::Owned(encode_base64_sha256(digest)),
            Self::Base64Sha256(digest) => Cow::Owned(encode_hex_lower(digest)),
            Self::Unsigned => Cow::Borrowed(UNSIGNED_PAYLOAD),
            Self::StreamingSigned { trailer } => Cow::Borrowed(if trailer.is_declared() {
                STREAMING_SIGNED_TRAILER
            } else {
                STREAMING_SIGNED
            }),
            Self::StreamingUnsigned { .. } => Cow::Borrowed(STREAMING_UNSIGNED_TRAILER),
        };
        CanonicalPayloadToken(token)
    }
}

fn reject_trailer(trailer: &TrailerSet) -> Result<(), SigParseError> {
    if trailer.is_declared() {
        return Err(SigParseError::TrailerNotAllowed);
    }
    Ok(())
}

fn require_trailer(trailer: &TrailerSet) -> Result<(), SigParseError> {
    if trailer.is_declared() {
        return Ok(());
    }
    Err(SigParseError::TrailerRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crc32() -> TrailerName {
        TrailerName::new("x-amz-checksum-crc32").expect("valid trailer name")
    }

    #[test]
    fn trailer_name_rejects_out_of_scope_and_uppercase_names() {
        assert_eq!(TrailerName::new("x-amz-"), Err(SigParseError::InvalidTrailerName));
        assert_eq!(TrailerName::new(""), Err(SigParseError::InvalidTrailerName));
        assert_eq!(TrailerName::new("X-Amz-Checksum-Crc32"), Err(SigParseError::InvalidTrailerName));
        assert_eq!(TrailerName::new("content-length"), Err(SigParseError::InvalidTrailerName));
        assert_eq!(TrailerName::new("x-amz-checksum crc32"), Err(SigParseError::InvalidTrailerName));
    }

    #[test]
    fn declared_trailers_reject_duplicates() {
        let err = DeclaredTrailers::new([crc32(), crc32()], false).expect_err("duplicate must fail");
        assert_eq!(err, SigParseError::DuplicateTrailerName);
    }

    #[test]
    fn canonical_token_for_empty_is_the_empty_digest() {
        assert_eq!(PayloadMode::Empty.canonical_payload_token().as_str(), EMPTY_PAYLOAD_SHA256_HEX);
    }
}
