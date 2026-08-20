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
//! [`crate::gate::BodyCeilings`] and [`crate::gate::BodyTimeouts`], feeding the signed payload
//! hash from each frame, and reporting the refusal that stopped it — and [`WireReader`], the
//! pull-model view of the same frames that `rustfs-gateway-http`'s chunk pipeline reads through.
//! NOT responsible for: what the bytes mean (`crate::gate` collects them, `crate::chunked`
//! decodes them), the ceilings' values (`crate::gate::BodyCeilings::of`), or any framing rule
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

use bytes::{Buf, Bytes};
use futures_timer::Delay;
use rustfs_gateway_stream::{AsyncPayloadRead, PayloadCaps, ReadProgress, StreamError, TrailingHeaders};
use sha2::{Digest, Sha256};

use crate::gate::{BodyCeilings, BodyDigestObligation, BodyTimeouts};
use crate::render::S3Error;

/// What one body read accumulates that outlives the reader consuming it.
///
/// The reader is moved into `rustfs-gateway-http`'s pipeline and dropped with it, so everything
/// the caller still needs afterwards — how much arrived, the payload hash, and the refusal that
/// stopped the read — lives here and is borrowed rather than owned by the reader.
pub(crate) struct WireProgress {
    seen: u64,
    /// The obligation and the hasher opened for it, held together so that the value compared is
    /// necessarily the value the hasher was opened for. Two parameters, one at construction and
    /// one at comparison, is a rule stated in two places and therefore a rule that can drift.
    digest: BodyDigestObligation,
    sha256: Option<Sha256>,
    refusal: Option<S3Error>,
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
            seen: 0,
            digest,
            sha256: match digest {
                BodyDigestObligation::None => None,
                BodyDigestObligation::Sha256(_) => Some(Sha256::new()),
            },
            refusal: None,
        }
    }

    /// The refusal this read stopped on, when the reader produced one.
    pub(crate) fn take_refusal(&mut self) -> Option<S3Error> {
        self.refusal.take()
    }

    /// Whether the wire bytes that arrived match the digest the request was signed with.
    ///
    /// `true` when nothing was promised: an obligation nobody made cannot be broken.
    pub(crate) fn digest_matches(&mut self) -> bool {
        if let (BodyDigestObligation::Sha256(expected), Some(hasher)) = (self.digest, self.sha256.take()) {
            let actual: [u8; 32] = hasher.finalize().into();
            return actual == expected;
        }
        true
    }
}

/// One request body's frames, bounded twice and deadlined between frames.
///
/// Every frame passes the ceilings *before* its bytes are handed on, so the frame that crosses a
/// line is refused rather than buffered — which is the whole difference between a ceiling and a
/// report about a buffer that already exists.
pub(crate) struct WireFrames<'a, B> {
    body: Pin<&'a mut B>,
    progress: &'a mut WireProgress,
    ceilings: BodyCeilings,
    timeouts: BodyTimeouts,
    /// The deadline for the frame currently being waited on; `None` before the first poll of one.
    delay: Option<Delay>,
    /// A fuse, not a state anything branches on today. Both callers stop on the first `None` —
    /// `crate::gate`'s collector is a `while let Some`, and [`WireReader`] guards with
    /// `eof_emitted` — so nothing reaches the early return below. It stays because
    /// `http_body::Body` says nothing about polling a body that has already answered `None`, and
    /// "whoever adds the third caller will remember" is not a guarantee.
    ended: bool,
}

impl<'a, B> WireFrames<'a, B>
where
    B: http_body::Body,
{
    /// Opens the read. Nothing is polled until [`Self::poll_next`] is.
    pub(crate) fn new(
        body: Pin<&'a mut B>,
        progress: &'a mut WireProgress,
        ceilings: BodyCeilings,
        timeouts: BodyTimeouts,
    ) -> Self {
        Self {
            body,
            progress,
            ceilings,
            timeouts,
            delay: None,
            ended: false,
        }
    }

    /// The next data frame, or `None` once the body is over.
    ///
    /// Trailer frames are skipped rather than counted: this assembly does not verify trailers, and
    /// the framing layer is where one is judged.
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
            // Neither this skip nor the empty-frame skip below is bounded — rustfs/gateway#263.
            let Ok(mut data) = frame.into_data() else {
                continue;
            };
            let length = data.remaining();
            // Inside the loop, before the bytes are kept. `data` is dropped with the error, so the
            // frame that crossed the line is not buffered either.
            self.progress.seen = self.progress.seen.saturating_add(length as u64);
            if let Some(cap) = self.ceilings.declared
                && self.progress.seen > cap
            {
                return Poll::Ready(Err(crate::gate::past_declared_cap()));
            }
            if self.progress.seen > self.ceilings.buffered {
                return Poll::Ready(Err(crate::gate::past_buffered_ceiling()));
            }
            if length == 0 {
                // A frame carrying nothing is not the end of anything, and handing it on as a
                // zero-length read would tell a pull consumer it made progress when it did not.
                continue;
            }
            // Taken whole rather than walked run by run. `Buf::copy_to_bytes` over a `Bytes` is a
            // split of the same allocation, which is what lets the unframed caller hand the frame
            // to its collector without copying it — `tests/request_allocations.rs` keeps that at
            // zero copies. The framed caller copies it into the pipeline's window either way, as
            // any pull-model consumer must; `tests/chunked_allocations.rs` is what bounds that.
            let bytes = data.copy_to_bytes(length);
            if let Some(hasher) = self.progress.sha256.as_mut() {
                hasher.update(&bytes);
            }
            return Poll::Ready(Ok(Some(bytes)));
        }
    }

    /// Records the refusal that stopped this read and returns the error the pull contract carries.
    ///
    /// The first refusal stands: a later generic failure must not overwrite the rule that fired.
    fn fail(&mut self, refusal: S3Error) -> StreamError {
        self.progress.refusal.get_or_insert(refusal);
        StreamError::incomplete_body().with_bytes_before_error(self.progress.seen)
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
                let mut delay = Delay::new(self.timeouts.waiting_for(self.progress.seen != 0));
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
pub(crate) struct WireReader<'a, B> {
    frames: WireFrames<'a, B>,
    /// What is left of the frame the last fill did not finish copying out.
    leftover: Bytes,
    eof_emitted: bool,
}

impl<'a, B> WireReader<'a, B>
where
    B: http_body::Body,
{
    /// Wraps a frame source. The reader owns it, so the frames have exactly one consumer.
    pub(crate) fn new(frames: WireFrames<'a, B>) -> Self {
        Self {
            frames,
            leftover: Bytes::new(),
            eof_emitted: false,
        }
    }
}

impl<B> AsyncPayloadRead for WireReader<'_, B>
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
