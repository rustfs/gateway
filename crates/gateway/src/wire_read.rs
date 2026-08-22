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

//! The one bounded, timed source of a request body's wire frames.
//!
//! Responsible for: [`WireFrames`] — pulling frames off the transport under
//! [`crate::gate::BodyCeilings`], [`crate::gate::BodyTimeouts`] and
//! [`MAX_PAYLOAD_FREE_FRAME_RUN`], feeding the signed payload hash from each frame, and reporting
//! the refusal that stopped it — and [`WireReader`], the pull-model view of the same frames that
//! `rustfs-gateway-http`'s chunk pipeline reads through.
//! NOT responsible for: what the bytes mean (`crate::gate` collects them, `crate::chunked`
//! decodes them), the byte ceilings' values (`crate::gate::BodyCeilings::of`), or any framing rule
//! (`rustfs_gateway_http::ingest`).
//! Upstream: `crate::gate`, the only module that builds either type. Downstream:
//! `rustfs_gateway_http::IngestPipeline`, which pulls through [`WireReader`].
//!
//! # Why the framed path pulls instead of collecting
//!
//! `aws-chunked` decoding used to run over a `BytesMut` holding the whole wire body, which the
//! caller had already collected under the ceilings. The pipeline's window then bounded how much
//! *decoded* material it worked on at a time — while the entire request sat beside it. A limit
//! enforced on an inner loop and not on its caller is not a limit, and this is the type that
//! removes the caller's copy: the pipeline pulls frames through [`WireReader`] as it needs them,
//! so the wire octets are resident only in the window they are decoded in. rustfs/gateway#229.
//!
//! # Why the refusal travels beside the stream and not inside it
//!
//! The pull contract carries a [`StreamError`], which has no status and no S3 error code. A
//! ceiling that answered `413` before would answer `400 IncompleteBody` if it were flattened into
//! one — so the refusal this layer produces is kept whole in [`WireProgress`] and read back by the
//! caller after the pipeline has finished. Recovering it by downcasting the boxed error would be a
//! negotiation with no contract; `c-object-0015` asserts the status this preserves.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::{Buf, Bytes};
use futures_timer::Delay;
use rustfs_gateway_stream::{AsyncPayloadRead, PayloadCaps, ReadProgress, StreamError, TrailingHeaders};
use sha2::{Digest, Sha256};

use crate::gate::{BodyCeilings, BodyDigestObligation, BodyTimeouts};
use crate::render::S3Error;

/// How many frames carrying no payload may arrive between two that carry some.
///
/// Two frame shapes carry nothing: a trailer section, which [`http_body::Frame::into_data`]
/// refuses, and a data frame of zero bytes. Neither advances [`WireProgress::seen`], so neither is
/// charged against either ceiling, and each one *is* a frame arriving, so each one resets the
/// between-frame deadline rather than expiring it. A peer that sends nothing else therefore keeps
/// this reader in its loop for ever, holding a task, never yielding, and never transferring a
/// byte — unbounded work with every bound that exists for it left unconsulted. rustfs/gateway#263.
///
/// # Why a run, and not a total for the body
///
/// The bound is on the number in a row, reset by any frame that carries payload. That is the
/// difference between a rule with a constant in it and a rule that restores an invariant: with the
/// run bounded at `N`, at least one frame in every `N + 1` carried a byte, and bytes are already
/// bounded by [`BodyCeilings`]. The reader's total work is then a function of the ceilings this
/// assembly already enforces rather than of what the peer feels like sending, and the ceiling is
/// what refuses a peer paying for its silence a byte at a time.
///
/// A per-body total would bound the loop too, and would also refuse a long, legitimate upload from
/// a framing layer that flushes — a refusal whose likelihood grows with the size of the body, which
/// is the wrong shape for an upload gateway to carry.
///
/// # Why eight
///
/// A conforming message never sends more than two in a row. Both wire protocols this service
/// accepts permit exactly one trailer section per message — RFC 9112 §7.1.2 gives a chunked body
/// one trailer-section, RFC 9113 §8.1 gives an HTTP/2 message one trailing HEADERS frame — and a
/// zero-length DATA frame is the one payload-free data frame a message can need, to carry
/// END_STREAM.
///
/// The floor is measured rather than assumed, because what this bound counts is what the
/// *transport* chose to hand over and not what the peer wrote. Over a real socket, hyper hands
/// this reader **exactly one** payload-free frame for an HTTP/1.1 chunked body carrying a trailer
/// section, and **none at all** for a `Content-Length` body:
/// `a_real_chunked_body_with_a_trailer_section_is_still_read_whole` is red at a bound of zero and
/// green at one, while `c_lim_0001_allows_a_long_socket_body_that_keeps_making_progress` is green
/// even at zero.
///
/// The remaining seven are headroom for a framing layer that flushes without producing payload,
/// and that part is a policy choice, stated rather than tuned: every value above the floor buys
/// the same property — the work a peer can extract per byte it actually sends is a constant — and
/// the value only decides how much slack a well-behaved intermediary gets before it is called a
/// spin.
pub(crate) const MAX_PAYLOAD_FREE_FRAME_RUN: u32 = 8;

/// What one body read accumulates that outlives the reader consuming it.
///
/// The reader is moved into `rustfs-gateway-http`'s pipeline and dropped with it, so everything
/// the caller still needs afterwards — how much arrived, the payload hash, and the refusal that
/// stopped the read — lives here and is borrowed rather than owned by the reader.
struct WireProgressState {
    seen: u64,
    /// The obligation and the hasher opened for it, held together so that the value compared is
    /// necessarily the value the hasher was opened for. Two parameters, one at construction and
    /// one at comparison, is a rule stated in two places and therefore a rule that can drift.
    digest: BodyDigestObligation,
    sha256: Option<Sha256>,
    refusal: Option<S3Error>,
}

/// Shared accounting retained by the request owner while a framed pipeline owns the reader.
#[derive(Clone)]
pub(crate) struct WireProgress {
    state: Arc<Mutex<WireProgressState>>,
    observer: Option<tokio::sync::watch::Sender<u64>>,
}

impl WireProgress {
    /// Opens the accounting for one body, hashing only when a digest was actually promised.
    ///
    /// The hash is fed on both paths even though only the unframed one can carry an obligation
    /// today — `presigned_body_obligation` refuses a presigned streaming request outright, and it
    /// is the only place a [`BodyDigestObligation::Sha256`] is minted. Feeding it here rather than
    /// in the unframed branch is the fail-safe arrangement: the day a header-signed request's
    /// payload hash is compared — the P2 gap `crate::gate` records — the framed path gets the
    /// comparison rather than silently skipping it.
    pub(crate) fn new(digest: BodyDigestObligation) -> Self {
        Self {
            state: Arc::new(Mutex::new(WireProgressState {
                seen: 0,
                digest,
                sha256: match digest {
                    BodyDigestObligation::None => None,
                    BodyDigestObligation::Sha256(_) => Some(Sha256::new()),
                },
                refusal: None,
            })),
            observer: None,
        }
    }

    /// Publishes cumulative wire-byte progress to the request owner.
    #[must_use]
    pub(crate) fn with_observer(mut self, observer: tokio::sync::watch::Sender<u64>) -> Self {
        self.observer = Some(observer);
        self
    }

    fn state(&self) -> MutexGuard<'_, WireProgressState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// The refusal this read stopped on, when the reader produced one.
    pub(crate) fn take_refusal(&self) -> Option<S3Error> {
        self.state().refusal.take()
    }

    /// Whether the wire bytes that arrived match the digest the request was signed with.
    ///
    /// `true` when nothing was promised: an obligation nobody made cannot be broken.
    pub(crate) fn digest_matches(&self) -> bool {
        let mut state = self.state();
        if let (BodyDigestObligation::Sha256(expected), Some(hasher)) = (state.digest, state.sha256.take()) {
            let actual: [u8; 32] = hasher.finalize().into();
            return actual == expected;
        }
        true
    }

    pub(crate) fn seen(&self) -> u64 {
        self.state().seen
    }

    fn record(&self, bytes: &Bytes) -> u64 {
        let mut state = self.state();
        state.seen = state.seen.saturating_add(bytes.len() as u64);
        if let Some(hasher) = state.sha256.as_mut() {
            hasher.update(bytes);
        }
        let seen = state.seen;
        drop(state);
        if let Some(observer) = &self.observer {
            observer.send_replace(seen);
        }
        seen
    }

    fn refuse(&self, refusal: S3Error) -> StreamError {
        let mut state = self.state();
        state.refusal.get_or_insert(refusal);
        StreamError::incomplete_body().with_bytes_before_error(state.seen)
    }
}

/// One request body's frames, bounded twice and deadlined between frames.
///
/// Every frame passes the ceilings *before* its bytes are handed on, so the frame that crosses a
/// line is refused rather than buffered — which is the whole difference between a ceiling and a
/// report about a buffer that already exists.
pub(crate) struct WireFrames<B> {
    body: Pin<Box<B>>,
    progress: WireProgress,
    ceilings: BodyCeilings,
    timeouts: BodyTimeouts,
    /// The deadline for the frame currently being waited on; `None` before the first poll of one.
    delay: Option<Delay>,
    /// How many frames carrying no payload have arrived since the last one that carried some.
    /// Bounded by [`MAX_PAYLOAD_FREE_FRAME_RUN`], which is where the reason lives.
    payload_free_run: u32,
    /// A fuse, not a state anything branches on today. Both callers stop on the first `None` —
    /// `crate::gate`'s collector is a `while let Some`, and [`WireReader`] guards with
    /// `eof_emitted` — so nothing reaches the early return below. It stays because
    /// `http_body::Body` says nothing about polling a body that has already answered `None`, and
    /// "whoever adds the third caller will remember" is not a guarantee.
    ended: bool,
}

impl<B> WireFrames<B>
where
    B: http_body::Body,
{
    /// Opens the read. Nothing is polled until [`Self::poll_next`] is.
    pub(crate) fn new(body: B, progress: WireProgress, ceilings: BodyCeilings, timeouts: BodyTimeouts) -> Self {
        Self {
            body: Box::pin(body),
            progress,
            ceilings,
            timeouts,
            delay: None,
            payload_free_run: 0,
            ended: false,
        }
    }

    /// The next data frame, or `None` once the body is over.
    ///
    /// Trailer frames are skipped rather than counted: this assembly does not verify trailers, and
    /// the framing layer is where one is judged. Skipped, but not free — a frame that carries no
    /// payload is charged against [`MAX_PAYLOAD_FREE_FRAME_RUN`], which is what stops this loop
    /// from running for ever on a body that never delivers anything.
    pub(crate) fn poll_next(&mut self, context: &mut Context<'_>) -> Poll<Result<Option<Bytes>, S3Error>> {
        loop {
            if self.ended {
                return Poll::Ready(Ok(None));
            }
            let frame = match self.poll_frame(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(None)) => {
                    self.ended = true;
                    return Poll::Ready(Ok(None));
                }
                Poll::Ready(Ok(Some(frame))) => frame,
            };
            let Ok(mut data) = frame.into_data() else {
                if let Some(refusal) = self.charge_payload_free_frame() {
                    return Poll::Ready(Err(refusal));
                }
                continue;
            };
            let length = data.remaining();
            // Inside the loop, before the bytes are kept. `data` is dropped with the error, so the
            // frame that crossed the line is not buffered either.
            let bytes = data.copy_to_bytes(length);
            if length as u64 > self.ceilings.buffered {
                return Poll::Ready(Err(crate::gate::past_buffered_ceiling()));
            }
            let seen = self.progress.record(&bytes);
            if let Some(cap) = self.ceilings.declared
                && seen > cap
            {
                return Poll::Ready(Err(crate::gate::past_declared_cap()));
            }
            if self.ceilings.whole_body && seen > self.ceilings.buffered {
                return Poll::Ready(Err(crate::gate::past_buffered_ceiling()));
            }
            if length == 0 {
                // A frame carrying nothing is not the end of anything, and handing it on as a
                // zero-length read would tell a pull consumer it made progress when it did not.
                if let Some(refusal) = self.charge_payload_free_frame() {
                    return Poll::Ready(Err(refusal));
                }
                continue;
            }
            // The run is spent by a frame that carried something, and only by one.
            self.payload_free_run = 0;
            // Taken whole rather than walked run by run. `Buf::copy_to_bytes` over a `Bytes` is a
            // split of the same allocation, which is what lets the unframed caller hand the frame
            // to its collector without copying it — `tests/request_allocations.rs` keeps that at
            // zero copies. The framed caller copies it into the pipeline's window either way, as
            // any pull-model consumer must; `tests/chunked_allocations.rs` is what bounds that.
            return Poll::Ready(Ok(Some(bytes)));
        }
    }

    /// Charges one frame that carried no payload against [`MAX_PAYLOAD_FREE_FRAME_RUN`].
    ///
    /// The refusal is the idle one, and deliberately the same refusal a stalled socket gets: both
    /// mean the body has stopped making progress, both are true statements about a transfer that
    /// is not happening, and both close the connection — a body abandoned mid-stream leaves no
    /// synchronisation point to resume from (RFC 9112 §9.3). Minting a second refusal would put a
    /// distinction on the wire that a client has no different action to take on.
    /// `None` while the run is still inside the bound, and the refusal on the frame that crosses
    /// it. An [`Option`] rather than a unit-success result, because
    /// `scripts/check_error_resolution_surface.sh` forbids that shape anywhere under
    /// `crates/gateway/src`: an already-resolved error is a value this crate renders, never one a
    /// step that otherwise returns nothing hands back.
    fn charge_payload_free_frame(&mut self) -> Option<S3Error> {
        self.payload_free_run = self.payload_free_run.saturating_add(1);
        (self.payload_free_run > MAX_PAYLOAD_FREE_FRAME_RUN).then(crate::gate::body_idle_timeout)
    }

    /// Records the refusal that stopped this read and returns the error the pull contract carries.
    ///
    /// The first refusal stands: a later generic failure must not overwrite the rule that fired.
    fn fail(&mut self, refusal: S3Error) -> StreamError {
        self.progress.refuse(refusal)
    }

    /// One frame, under the deadline that applies to it.
    ///
    /// The first poll of a frame asks the transport before it arms the deadline, so a frame that
    /// is already available is never charged for waiting; every poll after that checks the
    /// deadline first, so an expiry is not lost to a transport that keeps answering `Pending`.
    /// The deadline is dropped with the frame it belonged to, which is what makes it a
    /// *between-frame* idle bound rather than a bound on the whole body.
    fn poll_frame(&mut self, context: &mut Context<'_>) -> Poll<Result<Option<http_body::Frame<B::Data>>, S3Error>> {
        match self.delay.as_mut() {
            None => {
                if let Poll::Ready(frame) = self.body.as_mut().poll_frame(context) {
                    return Poll::Ready(Self::settle(frame));
                }
                let mut delay = Delay::new(self.timeouts.waiting_for(self.progress.seen() != 0));
                if Pin::new(&mut delay).poll(context).is_ready() {
                    return Poll::Ready(Err(crate::gate::body_idle_timeout()));
                }
                self.delay = Some(delay);
                Poll::Pending
            }
            Some(delay) => {
                if Pin::new(delay).poll(context).is_ready() {
                    return Poll::Ready(Err(crate::gate::body_idle_timeout()));
                }
                match self.body.as_mut().poll_frame(context) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(frame) => {
                        self.delay = None;
                        Poll::Ready(Self::settle(frame))
                    }
                }
            }
        }
    }

    /// A transport error is a body that did not arrive as it was framed, and nothing more
    /// specific: the transport's own reason is not a sentence to put on the wire.
    fn settle(frame: Option<Result<http_body::Frame<B::Data>, B::Error>>) -> Result<Option<http_body::Frame<B::Data>>, S3Error> {
        match frame {
            None => Ok(None),
            Some(Ok(frame)) => Ok(Some(frame)),
            Some(Err(_)) => Err(crate::gate::incomplete()),
        }
    }
}

/// The pull-model view of [`WireFrames`], for a consumer that owns its buffer.
///
/// `rustfs_gateway_http::IngestPipeline` reads through this, so the wire bytes it decodes are
/// resident in its window and nowhere else.
pub(crate) struct WireReader<B> {
    frames: WireFrames<B>,
    /// What is left of the frame the last fill did not finish copying out.
    leftover: Bytes,
    eof_emitted: bool,
}

impl<B> WireReader<B>
where
    B: http_body::Body,
{
    /// Wraps a frame source. The reader owns it, so the frames have exactly one consumer.
    pub(crate) fn new(frames: WireFrames<B>) -> Self {
        Self {
            frames,
            leftover: Bytes::new(),
            eof_emitted: false,
        }
    }
}

impl<B> AsyncPayloadRead for WireReader<B>
where
    B: http_body::Body,
{
    fn poll_fill(self: Pin<&mut Self>, context: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(ReadProgress::Filled(0)));
        }
        if this.eof_emitted {
            return Poll::Ready(Err(StreamError::polled_after_eof()));
        }
        if this.leftover.is_empty() {
            match this.frames.poll_next(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(refusal)) => return Poll::Ready(Err(this.frames.fail(refusal))),
                Poll::Ready(Ok(None)) => {
                    this.eof_emitted = true;
                    // Empty, and honestly so: a trailer section is `rustfs-gateway-http`'s to
                    // parse out of the framing, and this layer never saw one.
                    return Poll::Ready(Ok(ReadProgress::Eof {
                        trailers: TrailingHeaders::empty(),
                    }));
                }
                Poll::Ready(Ok(Some(frame))) => this.leftover = frame,
            }
        }
        let take = this.leftover.len().min(buf.len());
        let (Some(source), Some(target)) = (this.leftover.get(..take), buf.get_mut(..take)) else {
            return Poll::Ready(Err(StreamError::incomplete_body()));
        };
        target.copy_from_slice(source);
        this.leftover.advance(take);
        Poll::Ready(Ok(ReadProgress::Filled(take)))
    }

    /// Trait obligations. `IngestPipeline` reads neither, so these answer as narrowly as the
    /// contract allows rather than reasoning about a value nothing consumes: no `KNOWN_LENGTH`,
    /// because what is left is a number of *wire* bytes while the only length this request
    /// declared is the decoded one.
    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PULL
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}
