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

//! One pass over an upload: read, decode, sign, digest, verify, deliver.
//!
//! Responsible for: owning the window the socket writes into, driving the decoder over it,
//! feeding the signer and every observer from the same borrowed run, holding a chunk back until
//! its signature verifies, and delivering only verified bytes.
//! NOT responsible for: framing rules (the decoder owns those), the signature chain (the signer
//! owns that), digest algorithms and trailer-signature comparison (P3-04), or timeouts and
//! cancellation (P3-05).
//! Upstream: `rustfs-gateway-stream`'s pull model and observer trait, this crate's `decoder`,
//! `signer` and `limits`. Downstream: `rustfs-gateway-core` and the storage layer.
//!
//! # Verify before deliver, and what it costs
//!
//! A chunk's signature arrives in that chunk's header and covers the data that follows it, so a
//! chunk cannot be verified until all of its data has been read. [`IngestPolicy`] has exactly one
//! variant, and it is the safe one: decoded bytes are held in the window until the chunk they
//! belong to verifies, and only then become visible to the consumer. When a signature fails, the
//! number of bytes the consumer has been shown from that chunk is zero — which is what makes
//! "roll back the partial object" a question that never has to be asked.
//!
//! The price of that guarantee, stated plainly: the consumer's own read is one copy out of the
//! window. It cannot be avoided while the guarantee holds, because writing unverified bytes into
//! the consumer's buffer *is* delivering them. What has been removed relative to a stack of
//! streams is everything else — the per-layer poll and waker hand-off, the per-chunk allocation,
//! the re-slicing, and the extra pass each digest would otherwise make over the body.
//!
//! # What the window costs
//!
//! One chunk plus two metadata lines, grown on demand from 64 KiB and never beyond the ceiling
//! that [`ChunkLimits::max_chunk_size`] implies. A body that announces a chunk larger than the
//! ceiling is refused at that chunk's header, so the window never grows to hold it.
//!
//! [`ChunkLimits::max_chunk_size`]: crate::ChunkLimits::max_chunk_size

use core::num::NonZeroU8;
use core::pin::Pin;
use core::task::{Context, Poll};

use rustfs_gateway_stream::{
    AsyncPayloadRead, ByteObserver, ObserverOutcome, PayloadCaps, ReadProgress, StreamError, TrailingHeaders,
};
use smallvec::SmallVec;

use crate::ingest::ChunkFraming;
use crate::ingest::DecodedLength;
use crate::ingest::decoder::{ChunkDecoder, DecodeEvent, MIN_CHUNK_META_BYTES};
use crate::ingest::reject::{ChunkReject, ModeConfusion};
use crate::ingest::signer::ChunkSigner;
use crate::ingest::trailer::{TrailerDeclaration, TrailerProgress, parse_trailer_section};
use crate::limits::ChunkLimits;

/// The window size the pipeline starts from before it learns how large the chunks really are.
const INITIAL_WINDOW_BYTES: usize = 64 * 1024;

/// When a decoded chunk becomes visible to the consumer.
///
/// One variant, on purpose. The alternative — deliver first and abort the object afterwards — is
/// defensible for a plain `PutObject`, whose commit happens after the body, and indefensible for
/// `UploadPart`, where the part must not reach storage at all. A policy with an opt-out variant
/// would be selected by somebody, once, for a benchmark; a policy with no such variant cannot be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestPolicy {
    /// Hold each chunk until its signature verifies, then deliver it.
    VerifyBeforeDeliver {
        /// How many chunks may be resident but undelivered. One: the chunk being verified.
        ///
        /// It is a [`NonZeroU8`] because zero would mean "deliver before verifying", which is the
        /// state this enum exists to make unrepresentable.
        lookahead_chunks: NonZeroU8,
    },
}

impl IngestPolicy {
    /// The only sane lookahead: the chunk currently being verified.
    #[must_use]
    pub fn verify_before_deliver() -> Self {
        Self::VerifyBeforeDeliver {
            // One is not zero.
            lookahead_chunks: NonZeroU8::MIN,
        }
    }

    /// How many chunks may be resident but not yet delivered.
    #[must_use]
    pub fn lookahead_chunks(&self) -> u8 {
        match self {
            Self::VerifyBeforeDeliver { lookahead_chunks } => lookahead_chunks.get(),
        }
    }
}

impl Default for IngestPolicy {
    fn default() -> Self {
        Self::verify_before_deliver()
    }
}

/// A run of bytes inside the window.
type Run = (usize, usize);

/// The single-pass `aws-chunked` ingest pipeline.
///
/// Constructed only for a body the signature declared framed; see [`IngestPipeline::new`].
pub struct IngestPipeline<R> {
    inner: R,
    decoder: ChunkDecoder,
    signer: Option<ChunkSigner>,
    observers: SmallVec<[Box<dyn ByteObserver>; 4]>,
    framing: ChunkFraming,
    policy: IngestPolicy,
    declared: u64,
    window: Vec<u8>,
    window_ceiling: usize,
    filled: usize,
    pending: SmallVec<[Run; 4]>,
    deliverable: SmallVec<[Run; 4]>,
    deliver_at: usize,
    deliver_offset: usize,
    delivered_bytes: u64,
    bytes_moved_total: u64,
    finished: bool,
    eof_emitted: bool,
    failed: bool,
    commit_allowed: bool,
    failure: Option<ChunkReject>,
    trailer_declaration: Option<TrailerDeclaration>,
    trailers: Option<TrailingHeaders>,
    trailer_section_complete: bool,
}

impl<R> IngestPipeline<R> {
    /// Builds a pipeline over a framed body.
    ///
    /// # Errors
    ///
    /// * [`ChunkReject::ModeConfusion`] when `framing` says the body is not framed. The chunk
    ///   parser exists to run on a body the *signature* declared framed; a pipeline that could be
    ///   built for any other body would be one `Content-Encoding` header away from the framing
    ///   confusion this whole module is arranged to prevent.
    /// * [`ChunkReject::SignatureChainBroken`] for chunk zero when signed framing arrives without
    ///   a signer, or unsigned framing arrives with one. Either way the pipeline would be
    ///   checking something other than what the mode promised.
    pub fn new(
        inner: R,
        framing: ChunkFraming,
        declared: DecodedLength,
        signer: Option<ChunkSigner>,
        observers: SmallVec<[Box<dyn ByteObserver>; 4]>,
        limits: ChunkLimits,
        policy: IngestPolicy,
    ) -> Result<Self, ChunkReject> {
        if !framing.is_framed() {
            return Err(ChunkReject::ModeConfusion(ModeConfusion::DecodedLengthNotAllowed));
        }
        if framing.has_chunk_signatures() != signer.is_some() {
            return Err(ChunkReject::SignatureChainBroken { chunk_index: 0 });
        }

        let meta = usize::from(limits.max_chunk_meta_size());
        let chunk = usize::try_from(limits.max_chunk_size()).unwrap_or(usize::MAX);
        let lookahead = usize::from(policy.lookahead_chunks());
        let window_ceiling = chunk
            .saturating_mul(lookahead)
            .saturating_add(meta.saturating_mul(2))
            .saturating_add(MIN_CHUNK_META_BYTES);
        let initial = INITIAL_WINDOW_BYTES.min(window_ceiling).max(meta.saturating_mul(2));

        Ok(Self {
            inner,
            decoder: ChunkDecoder::new(framing.has_chunk_signatures(), framing.declares_trailers(), declared.get(), limits),
            signer,
            observers,
            framing,
            policy,
            declared: declared.get(),
            window: vec![0u8; initial],
            window_ceiling,
            filled: 0,
            pending: SmallVec::new(),
            deliverable: SmallVec::new(),
            deliver_at: 0,
            deliver_offset: 0,
            delivered_bytes: 0,
            bytes_moved_total: 0,
            finished: false,
            eof_emitted: false,
            failed: false,
            commit_allowed: false,
            failure: None,
            trailer_declaration: None,
            trailers: None,
            trailer_section_complete: false,
        })
    }

    /// Attaches the trailer names already accepted from the request head.
    ///
    /// # Errors
    ///
    /// [`ChunkReject::TrailerInNonTrailerMode`] when the authenticated payload mode has no trailer
    /// section, and [`ChunkReject::DeclaredTrailerMismatch`] when the declaration's signed shape
    /// disagrees with that mode.
    pub fn with_trailer_declaration(mut self, trailer_declaration: TrailerDeclaration) -> Result<Self, ChunkReject> {
        if !self.framing.declares_trailers() {
            return Err(ChunkReject::TrailerInNonTrailerMode);
        }
        if self.framing.has_chunk_signatures() != trailer_declaration.signed() {
            return Err(ChunkReject::DeclaredTrailerMismatch);
        }
        self.trailer_declaration = Some(trailer_declaration);
        Ok(self)
    }

    /// How many body bytes the decoder has produced.
    ///
    /// **This is the length every consumer must read.** Quota, policy, checksum, storage and
    /// audit all read it and none of them reads `x-amz-decoded-content-length`, which is a number
    /// the peer chose: a quota checked against the header and an object written from the body is
    /// the shape in which a one-kilobyte allowance stores a gigabyte.
    #[must_use]
    pub fn decoded_bytes(&self) -> u64 {
        self.decoder.decoded_bytes()
    }

    /// How many verified body bytes have been handed to the consumer.
    ///
    /// Under [`IngestPolicy::VerifyBeforeDeliver`] this is zero for every chunk whose signature
    /// has not yet verified, which is what a signature-failure test asserts.
    #[must_use]
    pub fn delivered_bytes(&self) -> u64 {
        self.delivered_bytes
    }

    /// Whether what has arrived may be committed.
    ///
    /// `false` until every integrity obligation has been discharged.
    ///
    /// This parser can make a non-trailered body committable. A trailered body stays false even
    /// after [`Self::trailer_section_complete`] becomes true, because parsing the expected value
    /// is not comparing it against the body digest.
    #[must_use]
    pub fn commit_allowed(&self) -> bool {
        self.commit_allowed
    }

    /// Whether the exact declared trailer section arrived and transport EOF followed it.
    ///
    /// This is deliberately weaker than [`Self::commit_allowed`]: it proves framing and name-set
    /// completeness, not that a checksum or trailer signature agreed.
    #[must_use]
    pub fn trailer_section_complete(&self) -> bool {
        self.trailer_section_complete
    }

    /// How many bytes the pipeline has memmoved to keep the window compact.
    ///
    /// The single-pass gate reads this: decoding strips chunk headers by moving a cursor, not by
    /// moving the body, so this counter grows by at most one metadata line per compaction and
    /// never in proportion to the body.
    #[must_use]
    pub fn bytes_moved_total(&self) -> u64 {
        self.bytes_moved_total
    }

    /// How many bytes of chunk framing this body has spent so far.
    ///
    /// Read together with [`Self::decoded_bytes`] it is the overhead ratio the limits enforce; a
    /// micro-chunk flood shows up here as overhead approaching the size of the payload.
    #[must_use]
    pub fn overhead_bytes(&self) -> u64 {
        self.decoder.overhead_bytes()
    }

    /// The window size currently allocated.
    #[must_use]
    pub fn window_bytes(&self) -> usize {
        self.window.len()
    }

    /// The framing this pipeline was built for.
    #[must_use]
    pub fn framing(&self) -> ChunkFraming {
        self.framing
    }

    /// The delivery policy in force.
    #[must_use]
    pub fn policy(&self) -> IngestPolicy {
        self.policy
    }

    /// The signer, for the HMAC accounting a performance gate asserts on.
    #[must_use]
    pub fn signer(&self) -> Option<&ChunkSigner> {
        self.signer.as_ref()
    }

    /// Ends the observation and returns what every observer computed.
    ///
    /// Consuming: an observer that could be finished twice would be an observer whose digest
    /// depends on when it was asked.
    #[must_use]
    pub fn finish_observers(self) -> SmallVec<[ObserverOutcome; 4]> {
        self.observers.into_iter().map(ByteObserver::finish).collect()
    }

    /// Copies verified bytes into the caller's buffer, returning how many.
    fn drain_into(&mut self, buf: &mut [u8]) -> usize {
        let mut written = 0usize;
        while written < buf.len() {
            let Some((start, len)) = self.deliverable.get(self.deliver_at).copied() else {
                break;
            };
            let Some(remaining) = len.checked_sub(self.deliver_offset) else {
                break;
            };
            if remaining == 0 {
                self.deliver_at = self.deliver_at.saturating_add(1);
                self.deliver_offset = 0;
                continue;
            }
            let room = buf.len().saturating_sub(written);
            let take = remaining.min(room);
            let from = start.saturating_add(self.deliver_offset);
            let to = from.saturating_add(take);
            let dst_end = written.saturating_add(take);
            let (Some(src), Some(dst)) = (self.window.get(from..to), buf.get_mut(written..dst_end)) else {
                break;
            };
            dst.copy_from_slice(src);
            written = dst_end;
            self.deliver_offset = self.deliver_offset.saturating_add(take);
            if self.deliver_offset >= len {
                self.deliver_at = self.deliver_at.saturating_add(1);
                self.deliver_offset = 0;
            }
        }
        if self.deliver_at >= self.deliverable.len() {
            self.deliverable.clear();
            self.deliver_at = 0;
            self.deliver_offset = 0;
        }
        self.delivered_bytes = self.delivered_bytes.saturating_add(written as u64);
        written
    }

    /// Shows one decoded run to the signer and to every observer, in one pass.
    fn observe(&mut self, start: usize, len: usize) {
        let end = start.saturating_add(len);
        let Some(run) = self.window.get(start..end) else {
            return;
        };
        if let Some(signer) = self.signer.as_mut() {
            signer.update(run);
        }
        for observer in &mut self.observers {
            observer.update(run);
        }
    }

    /// Verifies the chunk that has just ended and promotes its bytes to deliverable.
    fn end_chunk(&mut self, signature: Option<[u8; 32]>) -> Result<(), ChunkReject> {
        match (self.signer.as_mut(), signature) {
            (Some(signer), Some(presented)) => signer.verify_chunk(&presented)?,
            (None, None) => {}
            // The decoder's extension whitelist already refuses these, so reaching here would be
            // a decoder bug; failing closed keeps it from becoming a verification bypass.
            (Some(signer), None) => {
                return Err(ChunkReject::SignatureChainBroken {
                    chunk_index: signer.chunks_verified(),
                });
            }
            (None, Some(_)) => return Err(ChunkReject::UnexpectedExtension),
        }
        self.deliverable.append(&mut self.pending);
        Ok(())
    }

    /// Makes room for another read: compact only when the window is genuinely full, then grow.
    ///
    /// Compacting on every read would be simpler and would memmove everything the socket has
    /// delivered ahead of the parse cursor, once per read — which is a memmove proportional to
    /// the body, exactly the cost this pipeline exists to avoid. Waiting until the window is full
    /// bounds the total movement to whatever of the *current* chunk is still unverified, once per
    /// window's worth of input. A body that fits in the window is never moved at all, even though
    /// every one of its chunk headers has been stripped: headers are skipped by advancing the
    /// cursor, never by moving the bytes around them.
    ///
    /// # What that bound is worth, as a number
    ///
    /// The sentence above is true and reads smaller than it is. One compaction moves the retained
    /// span and buys `window - span` bytes of room, so the movement per body byte is
    /// `span / (window - span)` — a **function of the chunk-size-to-window ratio**, not a
    /// constant. At an eighth of the window it is 0.13 of the body; at exactly half it is ~1.0,
    /// because the span and the room it buys are then the same size and every chunk is moved
    /// once. `crates/http/tests/ingest_perf_gates.rs` measures the curve and bounds it at both
    /// ends: never more than one retained span per window's worth of room, never a *full* second
    /// pass, and under half the body wherever the window is at least three times the chunk.
    ///
    /// The peak is a knife edge — at half the window the ratio reaches 0.9986, and a chunk 5%
    /// either side of it costs a third of that — but a peer picks its own chunk size, so treat it
    /// as reachable rather than as an accident.
    ///
    /// **The window is deliberately not grown to flatten that peak** (rustfs/gateway#265).
    /// Growing to three times the chunk would hold the movement under half the body everywhere,
    /// and it would triple what one connection is resident for. What that buys is one memcpy of
    /// the body, against the socket read, the SHA-256 and the per-chunk HMAC it sits beside; what
    /// it costs is the per-connection residency bound `c-ing-0063` and rustfs/gateway#229 are
    /// about. Residency is the scarcer of the two, so the ratio is written down here and asserted
    /// over its range instead of being engineered away.
    fn make_room(&mut self) -> Result<(), ChunkReject> {
        if self.filled < self.window.len() {
            return Ok(());
        }
        let cursor = self.decoder.cursor();
        let retain = self.pending.first().map_or(cursor, |(start, _)| (*start).min(cursor));
        if retain > 0 {
            let moved = self.filled.saturating_sub(retain);
            self.window.copy_within(retain..self.filled, 0);
            self.filled = moved;
            self.bytes_moved_total = self.bytes_moved_total.saturating_add(moved as u64);
            self.decoder.rebase(retain);
            for run in &mut self.pending {
                run.0 = run.0.saturating_sub(retain);
            }
        }
        if self.filled >= self.window.len() {
            let grown = self.window.len().saturating_mul(2).min(self.window_ceiling);
            if grown <= self.window.len() {
                // The window already holds a whole chunk plus two metadata lines, so anything
                // still incomplete is a metadata line longer than its ceiling.
                return Err(ChunkReject::ChunkMetaTooLong);
            }
            self.window.resize(grown, 0);
        }
        Ok(())
    }

    /// Turns a framing refusal into the stream error the pull contract carries.
    ///
    /// The refusal is also retained, because the response layer needs its status and error code
    /// and the alternative — recovering it by downcasting the boxed error — is a negotiation with
    /// no contract that fails silently the moment either side is refactored.
    fn fail(&mut self, reject: ChunkReject) -> StreamError {
        self.failed = true;
        self.commit_allowed = false;
        self.failure.get_or_insert(reject);
        StreamError::upstream(Box::new(reject)).with_bytes_before_error(self.delivered_bytes)
    }

    /// The refusal that ended this body, if one did.
    ///
    /// Named rather than recovered by downcast: the response layer reads
    /// [`ChunkReject::to_status`] and [`ChunkReject::error_code`] off this, and a failure to
    /// recover the reason would otherwise degrade into a generic `500` with no way to notice.
    #[must_use]
    pub fn reject(&self) -> Option<ChunkReject> {
        self.failure
    }
}

impl<R: AsyncPayloadRead + Unpin> IngestPipeline<R> {
    /// Runs the state machine one step, reading from the inner body when it needs bytes.
    fn advance(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let event = match self.decoder.step(self.window.get(..self.filled).unwrap_or(&[])) {
            Ok(event) => event,
            Err(reject) => return Poll::Ready(Err(self.fail(reject))),
        };
        match event {
            DecodeEvent::Data { start, len } => {
                self.observe(start, len);
                self.pending.push((start, len));
                Poll::Ready(Ok(()))
            }
            DecodeEvent::ChunkEnd { signature, .. } => match self.end_chunk(signature) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(reject) => Poll::Ready(Err(self.fail(reject))),
            },
            DecodeEvent::Done => self.finalize(cx),
            DecodeEvent::NeedMore => self.refill(cx),
        }
    }

    /// Reads more bytes from the inner body into the window.
    fn refill(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        if let Err(reject) = self.make_room() {
            return Poll::Ready(Err(self.fail(reject)));
        }
        let filled = self.filled;
        let Some(tail) = self.window.get_mut(filled..) else {
            return Poll::Ready(Err(self.fail(ChunkReject::ChunkMetaTooLong)));
        };
        match Pin::new(&mut self.inner).poll_fill(cx, tail) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.failed = true;
                Poll::Ready(Err(err.or_bytes_before_error(self.delivered_bytes)))
            }
            Poll::Ready(Ok(ReadProgress::Filled(n))) => {
                self.filled = self.filled.saturating_add(n);
                Poll::Ready(Ok(()))
            }
            // The stream ended without a terminal chunk. This must never become an end-of-stream:
            // a truncated upload presented as complete is a partial object committed as a whole
            // one, which is the whole of the truncation attack.
            Poll::Ready(Ok(ReadProgress::Eof { .. })) => Poll::Ready(Err(self.fail(ChunkReject::TruncatedStream))),
        }
    }

    /// Reads more of the bounded trailer section without retaining consumed chunk bytes.
    fn refill_trailer(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        if self.filled >= self.window.len() {
            let start = self.decoder.cursor();
            if start == 0 {
                return Poll::Ready(Err(self.fail(ChunkReject::TrailerSizeExceeded)));
            }
            self.window.copy_within(start..self.filled, 0);
            self.filled = self.filled.saturating_sub(start);
            self.decoder.rebase(start);
        }
        let filled = self.filled;
        let Some(tail) = self.window.get_mut(filled..).filter(|tail| !tail.is_empty()) else {
            return Poll::Ready(Err(self.fail(ChunkReject::TrailerSizeExceeded)));
        };
        match Pin::new(&mut self.inner).poll_fill(cx, tail) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.failed = true;
                Poll::Ready(Err(err.or_bytes_before_error(self.delivered_bytes)))
            }
            Poll::Ready(Ok(ReadProgress::Filled(n))) => {
                self.filled = self.filled.saturating_add(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(ReadProgress::Eof { .. })) => Poll::Ready(Err(self.fail(ChunkReject::TruncatedBeforeTrailer))),
        }
    }

    /// Settles what happens after the terminal chunk.
    fn finalize(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        if self.decoder.decoded_bytes() != self.declared {
            let reject = ChunkReject::DecodedLengthUnderflow {
                declared: self.declared,
                actual: self.decoder.decoded_bytes(),
            };
            return Poll::Ready(Err(self.fail(reject)));
        }
        if self.framing.declares_trailers() {
            let Some(declaration) = self.trailer_declaration.as_ref() else {
                // A caller using the compatibility constructor has no authenticated declaration
                // to compare with. Preserve the old fail-closed result.
                self.finished = true;
                self.commit_allowed = false;
                return Poll::Ready(Ok(()));
            };
            if self.trailers.is_none() {
                let start = self.decoder.cursor();
                let input = self.window.get(start..self.filled).unwrap_or(&[]);
                match parse_trailer_section(input, declaration) {
                    Err(reject) => return Poll::Ready(Err(self.fail(reject))),
                    Ok(TrailerProgress::NeedMore) => return self.refill_trailer(cx),
                    Ok(TrailerProgress::Complete { trailers, consumed }) => {
                        let end = start.saturating_add(consumed);
                        if end != self.filled {
                            return Poll::Ready(Err(self.fail(ChunkReject::DataAfterTrailer)));
                        }
                        self.trailers = Some(trailers);
                        self.filled = 0;
                        self.decoder.rebase(end);
                    }
                }
            }
        }
        if self.decoder.cursor() < self.filled {
            return Poll::Ready(Err(self.fail(ChunkReject::ZeroSizedNonTerminalChunk)));
        }
        // One more read, to establish that the terminal chunk really was terminal. Bytes after it
        // mean the peer treated a zero-sized chunk as an ordinary one.
        //
        // The room is made first, and that is not tidiness. A body whose terminal chunk ends
        // exactly on the window boundary leaves no tail at all, and a reader handed an empty
        // buffer answers `Filled(0)` — which the arm below reads as "the body is over". So a wire
        // body of exactly 65,536 bytes could carry anything it liked after its terminal chunk and
        // be committed, with the trailing octets left unread on a connection this service was
        // about to reuse. `make_room` compacts the consumed window back to nothing, so the probe
        // below is always a real read. rustfs/gateway#229.
        if let Err(reject) = self.make_room() {
            return Poll::Ready(Err(self.fail(reject)));
        }
        let filled = self.filled;
        // One guard rather than two, and it fails closed. Both halves are unreachable — `filled`
        // never exceeds the window's length, and `make_room` returning `Ok` leaves room in it —
        // but the arm this replaces answered "no buffer" with `commit_allowed = true`, which is
        // the same "nobody looked, so nothing follows" inference the empty tail above is the
        // reason for. Two adjacent unreachable arms that disagree about which way to fail is one
        // refactor away from the reachable one being the wrong one.
        let Some(tail) = self.window.get_mut(filled..).filter(|tail| !tail.is_empty()) else {
            return Poll::Ready(Err(self.fail(ChunkReject::ChunkMetaTooLong)));
        };
        match Pin::new(&mut self.inner).poll_fill(cx, tail) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.failed = true;
                Poll::Ready(Err(err.or_bytes_before_error(self.delivered_bytes)))
            }
            Poll::Ready(Ok(ReadProgress::Filled(0))) if self.framing.declares_trailers() => {
                Poll::Ready(Err(self.fail(ChunkReject::TruncatedBeforeTrailer)))
            }
            Poll::Ready(Ok(ReadProgress::Filled(0))) => {
                self.finished = true;
                self.commit_allowed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(ReadProgress::Eof { trailers })) if self.framing.declares_trailers() && !trailers.is_empty() => {
                Poll::Ready(Err(self.fail(ChunkReject::DataAfterTrailer)))
            }
            Poll::Ready(Ok(ReadProgress::Eof { .. })) => {
                self.finished = true;
                if self.framing.declares_trailers() {
                    self.trailer_section_complete = true;
                    self.commit_allowed = false;
                } else {
                    self.commit_allowed = true;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(ReadProgress::Filled(_))) if self.framing.declares_trailers() => {
                Poll::Ready(Err(self.fail(ChunkReject::DataAfterTrailer)))
            }
            Poll::Ready(Ok(ReadProgress::Filled(_))) => Poll::Ready(Err(self.fail(ChunkReject::ZeroSizedNonTerminalChunk))),
        }
    }
}

impl<R: AsyncPayloadRead + Unpin> AsyncPayloadRead for IngestPipeline<R> {
    fn poll_fill(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(ReadProgress::Filled(0)));
        }
        if this.failed {
            return Poll::Ready(Err(StreamError::incomplete_body().with_bytes_before_error(this.delivered_bytes)));
        }
        loop {
            let written = this.drain_into(buf);
            if written > 0 {
                return Poll::Ready(Ok(ReadProgress::Filled(written)));
            }
            if this.finished {
                if this.eof_emitted {
                    return Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(this.delivered_bytes)));
                }
                this.eof_emitted = true;
                return Poll::Ready(Ok(ReadProgress::Eof {
                    trailers: this.trailers.take().unwrap_or_else(TrailingHeaders::empty),
                }));
            }
            match this.advance(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {}
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PULL | PayloadCaps::KNOWN_LENGTH
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.declared.saturating_sub(self.delivered_bytes))
    }
}
