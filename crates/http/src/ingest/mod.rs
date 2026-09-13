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

//! Reading an upload body once: decode, verify, digest and deliver in a single pass.
//!
//! Responsible for: deciding whether the `aws-chunked` parser runs at all ([`ChunkFraming`]), the
//! head cross-checks between the declared decoded length and the wire length
//! ([`validate_decoded_length`]), and the pipeline that performs the pass ([`IngestPipeline`]).
//! NOT responsible for: parsing `x-amz-content-sha256` (that is `rustfs-gateway-sig`, one layer
//! above, which is why the framing facts arrive through [`PayloadFramingSource`] rather than as a
//! mode this crate could re-derive); verifying the request signature; parsing or verifying a
//! trailer checksum or trailer-signature comparison (P3-04); choosing which digests a request
//! needs (P3-04); and timeouts (P3-05).
//! Upstream: `rustfs-gateway-stream` for the pull model and the observer trait, this crate's
//! `framing` and `limits`. Downstream: `rustfs-gateway-core` and the storage layer.
//!
//! # The one rule the whole module is arranged around
//!
//! **The chunk parser runs when, and only when, the signature says the payload is framed.**
//! `Content-Encoding: aws-chunked` is object metadata and is not an input to that decision — no
//! type in this module takes it, and [`PayloadFramingSource`] has no method that could carry it.
//! When a quota layer reads one framing and the storage layer reads another, the bytes between
//! the two interpretations are a request nobody authenticated; the same confusion has already
//! been shipped and reverted three times upstream (rustfs#4960, #4964, #4968).
//!
//! # Where the numbers come from
//!
//! Three defects in the shape this module replaces, each with the measurement that made it worth
//! fixing:
//!
//! 1. **Key derivation per chunk.** The four-step SigV4 derivation depends only on the credential
//!    scope, never on the chunk, so a 5 GiB upload in 64 KiB chunks needs one derivation and
//!    81,920 chunk HMACs — 81,924 in total — where a per-chunk derivation performs 409,600, four
//!    fifths of them recomputing the same key. [`SigningKeyCache`] derives once per scope and
//!    counts both numbers so the ratio is a test assertion rather than a claim.
//! 2. **A second pass over every chunk.** Collecting a whole chunk and only then hashing it walks
//!    the body twice. [`IngestPipeline`] feeds the signer and every [`ByteObserver`] as each run
//!    of bytes is decoded, while it is still in cache, and a [`ByteCounter`] observer turns
//!    "exactly one pass" into an equality a test can assert.
//! 3. **An unbounded chunk.** See [`ChunkLimits`].
//!
//! [`ByteObserver`]: rustfs_gateway_stream::ByteObserver
//! [`ByteCounter`]: rustfs_gateway_stream::ByteCounter
//! [`ChunkLimits`]: crate::ChunkLimits

mod decoder;
mod pipeline;
mod reject;
mod signer;
mod trailer;

pub use crate::ingest::decoder::MIN_CHUNK_META_BYTES;
pub use crate::ingest::pipeline::{IngestPipeline, IngestPolicy};
pub use crate::ingest::reject::{ChunkReject, ModeConfusion};
pub use crate::ingest::signer::{
    ChunkScope, ChunkSeed, ChunkSigner, ChunkSigningKey, MAX_SCOPE_LINE_BYTES, ScopeId, SigningKeyCache,
};
pub use crate::ingest::trailer::{MAX_TRAILER_SECTION_BYTES, TrailerDeclaration};

use crate::framing::Framing;

/// The signature-derived facts the ingest layer is allowed to read about a payload.
///
/// This trait is the seam that keeps the layering honest. The authority on payload framing is
/// `rustfs-gateway-sig`'s `PayloadMode`, which sits *above* this crate — naming it here would
/// close a dependency cycle — so the mode is passed down as the four questions the decoder needs
/// answered. The seam is not a weakening: `Content-Encoding` cannot be smuggled through it,
/// because there is no method to smuggle it through, and there is no downcast to reach around it.
///
/// An implementation must answer from the `x-amz-content-sha256` value and from nothing else.
pub trait PayloadFramingSource {
    /// Whether the payload is `aws-chunked` framed.
    fn is_framed(&self) -> bool;

    /// Whether every chunk carries its own signature.
    fn has_chunk_signatures(&self) -> bool;

    /// Whether `x-amz-decoded-content-length` is mandatory.
    ///
    /// `false` means the header is *forbidden*, not optional.
    fn requires_decoded_length(&self) -> bool;

    /// Whether a trailer section was declared through `x-amz-trailer`.
    fn declares_trailers(&self) -> bool;
}

/// Whether, and how, the `aws-chunked` parser runs for one request.
///
/// The fields are private and [`ChunkFraming::derive`] is the only constructor, so a value of
/// this type is always the answer a signature gave. A public enum here would let any caller
/// construct "framed" from any evidence it liked, which is the exact defect the type exists to
/// prevent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkFraming {
    framed: bool,
    signed: bool,
    trailers: bool,
}

impl ChunkFraming {
    /// Reads the framing decision off a signature-derived source.
    ///
    /// # Errors
    ///
    /// [`ChunkReject::ModeConfusion`] when the source contradicts itself: a source that is framed
    /// but does not require a decoded length, one that is not framed but requires one, one that
    /// signs chunks without being framed at all, or one that declares trailers without being
    /// framed. Every one of those is a bug in the source rather than in the request, and a
    /// pipeline built on a contradictory framing decision is a pipeline whose limits apply to a
    /// body shape it is not actually reading.
    pub fn derive<S: PayloadFramingSource + ?Sized>(source: &S) -> Result<Self, ChunkReject> {
        let framed = source.is_framed();
        if framed != source.requires_decoded_length() {
            return Err(ChunkReject::ModeConfusion(if framed {
                ModeConfusion::DecodedLengthMissing
            } else {
                ModeConfusion::DecodedLengthNotAllowed
            }));
        }
        if !framed && (source.has_chunk_signatures() || source.declares_trailers()) {
            return Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthNotAllowed));
        }
        Ok(Self {
            framed,
            signed: source.has_chunk_signatures(),
            trailers: source.declares_trailers(),
        })
    }

    /// Whether the chunk parser runs.
    #[must_use]
    pub fn is_framed(&self) -> bool {
        self.framed
    }

    /// Whether each chunk carries a signature that must verify before its bytes are delivered.
    #[must_use]
    pub fn has_chunk_signatures(&self) -> bool {
        self.signed
    }

    /// Whether a trailer section follows the terminal chunk.
    #[must_use]
    pub fn declares_trailers(&self) -> bool {
        self.trailers
    }
}

/// A decoded body length that has been cross-checked against the wire length, or that stands as
/// the body's only ceiling because the transport, not a declared length, ends the wire body.
///
/// The type exists so that the consumers of an upload — quota, policy, storage, audit — cannot
/// accidentally read the *header*. The header is a number the peer chose; the pipeline's own
/// counter is the number that arrived, and the two are only ever allowed to be equal because the
/// decoder fails the moment they diverge. [`IngestPipeline::decoded_bytes`] is the counter, and
/// it is the value every consumer must read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedLength(u64);

impl DecodedLength {
    /// The declared decoded length in bytes.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// The smallest framing a signed chunk can be spelled with: one hex digit, the signature
/// extension, and the two CRLFs around the data.
const MIN_SIGNED_CHUNK_OVERHEAD: u64 = 1 + 17 + 64 + 2 + 2;
/// The same for unsigned framing.
const MIN_UNSIGNED_CHUNK_OVERHEAD: u64 = 1 + 2 + 2;

/// Cross-checks `x-amz-decoded-content-length` against the framing mode and the wire length.
///
/// The four rules, in the order they are applied:
///
/// * A framed body must carry the header; its absence leaves the decoder with nothing to check
///   the arriving length against, and "no ceiling" is the state every length check exists to
///   avoid.
/// * A non-framed body must *not* carry it. Ignoring it instead would leave two answers to "how
///   long is this body" on the wire, and a smuggler only needs the two answers to differ
///   somewhere in the chain.
/// * The value is a bare run of ASCII digits — no sign, no whitespace, no `0x`.
/// * The decoded length plus the minimum possible framing must fit inside `Content-Length`. A
///   body that declares more decoded bytes than the wire can carry is refused before it starts.
///
/// The last rule (C-7) needs a wire length, and a body the transport ends has none:
/// `Transfer-Encoding: chunked` around `aws-chunked`, which botocore sends for every trailer
/// upload over TLS, or HTTP/2 without `Content-Length` ([`Framing::is_transport_delimited`]). AWS
/// lets a streaming upload omit `Content-Length` for exactly that reason and makes the decoded
/// length mandatory in every mode. So for that shape the decoded length is the ceiling itself,
/// and nothing is lost by it: the decoder refuses the first byte past it and a terminal chunk
/// short of it, derives its chunk-count and overhead ceilings from it, and the assembly still
/// counts every wire byte against its body ceilings as the frames arrive. A present
/// `Content-Length` is always held to rule C-7, on HTTP/2 as on HTTP/1.1.
///
/// # Errors
///
/// [`ChunkReject::ModeConfusion`], with the specific rule in [`ModeConfusion`].
pub fn validate_decoded_length(
    framing: &ChunkFraming,
    header: Option<&str>,
    wire: &Framing,
) -> Result<Option<DecodedLength>, ChunkReject> {
    let Some(header) = header else {
        if framing.is_framed() {
            return Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMissing));
        }
        return Ok(None);
    };
    if !framing.is_framed() {
        return Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthNotAllowed));
    }

    let bytes = header.as_bytes();
    if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMalformed));
    }
    let mut decoded: u64 = 0;
    for byte in bytes {
        let digit = u64::from(byte.wrapping_sub(b'0'));
        decoded = decoded
            .checked_mul(10)
            .and_then(|acc| acc.checked_add(digit))
            .ok_or(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthMalformed))?;
    }

    if wire.is_transport_delimited() {
        return Ok(Some(DecodedLength(decoded)));
    }
    // Only a transport-delimited body lacks a wire length, and it has returned above; a zero
    // here would fail closed rather than skip the check.
    let wire_length = wire.declared_length().unwrap_or(0);

    let per_chunk = if framing.has_chunk_signatures() {
        MIN_SIGNED_CHUNK_OVERHEAD
    } else {
        MIN_UNSIGNED_CHUNK_OVERHEAD
    };
    // A terminal chunk always exists; a data chunk exists only for a non-empty body.
    let minimum_overhead = if decoded == 0 {
        per_chunk
    } else {
        per_chunk.saturating_mul(2)
    };
    if decoded.saturating_add(minimum_overhead) > wire_length {
        return Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthExceedsWireLength {
            decoded,
            wire: wire_length,
        }));
    }

    Ok(Some(DecodedLength(decoded)))
}
