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

//! The owned producer for a verified streaming request body.
//!
//! Responsible for: moving the sole transport owner into a protocol-neutral `ByteStream`,
//! publishing decoded runs only after their per-run verification, and settling one gateway-owned
//! terminal verdict at EOF, failure, or drop, and publishing wire progress to the body monitor.
//! NOT responsible for: choosing which operations stream, invoking handlers, or rendering the
//! terminal refusal. Upstream: `crate::gate` after
//! authentication. Downstream: generated streaming request fields and the handler wrapper.

use core::future::{Future, poll_fn};
use core::panic::AssertUnwindSafe;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::panic::catch_unwind;

use bytes::Bytes;
use rustfs_gateway_http::{BodyDigests, IngestPipeline};
use rustfs_gateway_stream::{
    AsyncPayloadRead, ByteStream, PayloadCaps, PayloadRead, PayloadStream, ReadProgress, StreamError, TrailingHeaders,
};
use tokio::sync::{oneshot, watch};

use crate::chunked::ChunkIngest;
use crate::ext::{BodyQuota, VerifiedBodyProgress};
use crate::gate::{BodyCeilings, BodyDigestObligation, BodyTimeouts};
use crate::integrity::{Integrity, IntegrityCodes};
use crate::render::S3Error;
use crate::request_deadline::armed;
use crate::wire_read::{WireFrames, WireProgress, WireReader};

const DELIVERY_BYTES: usize = 64 * 1024;

enum Source<B> {
    Empty,
    Plain(WireFrames<B>),
    Framed(Box<IngestPipeline<WireReader<B>>>),
}

/// The live stream plus the gateway-owned verdict that must permit a response.
pub(crate) struct StreamingRead {
    stream: ByteStream,
    terminal: BodyMonitor,
}

impl StreamingRead {
    pub(crate) fn new<B>(
        body: Option<B>,
        (declared_length, object_ceiling): (Option<u64>, Option<u64>),
        body_plan: (BodyCeilings, BodyTimeouts, Option<std::sync::Arc<dyn BodyQuota>>),
        ingest: Option<ChunkIngest>,
        digest: BodyDigestObligation,
        integrity: impl Into<Integrity>,
    ) -> Result<Self, S3Error>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (ceilings, timeouts, body_quota) = body_plan;
        let Integrity { claims, codes } = integrity.into();
        let (progress_tx, progress_rx) = watch::channel(0_u64);
        let progress = WireProgress::for_body(digest, body.as_ref()).with_observer(progress_tx);
        if let Some(cap) = ceilings.declared
            && declared_length.is_some_and(|length| length > cap)
        {
            return Err(crate::gate::past_declared_cap(progress.request_body_unfinished()));
        }
        if ceilings.whole_body && declared_length.is_some_and(|length| length > ceilings.buffered) {
            return Err(crate::gate::past_buffered_ceiling(progress.request_body_unfinished()));
        }
        let decoded_length = ingest.as_ref().map(ChunkIngest::decoded_length).or(declared_length);
        if let Some(ceiling) = object_ceiling
            && decoded_length.is_some_and(|length| length > ceiling)
        {
            return Err(crate::gate::past_object_ceiling(progress.request_body_unfinished()));
        }
        if ingest.is_none() && body.as_ref().is_none_or(http_body::Body::is_end_stream) {
            let verdict = if !progress.digest_matches() {
                Err(codes.streamed_payload_hash_mismatch())
            } else {
                let refuse = move |reject| codes.refusal(reject);
                claims.begin().verify().map(|_| BodyVerified).map_err(refuse)
            };
            let (terminal_tx, terminal_rx) = oneshot::channel();
            let _ = terminal_tx.send(BodyTerminal::Complete(verdict));
            return Ok(Self {
                stream: ByteStream::from_bytes(Bytes::new()),
                terminal: BodyMonitor {
                    terminal: terminal_rx,
                    progress: progress_rx,
                    wire_progress: progress,
                    timeouts,
                },
            });
        }
        let source = match (body, ingest) {
            (None, _) => Source::Empty,
            (Some(body), None) => Source::Plain(WireFrames::new(body, progress.clone(), ceilings, timeouts)),
            (Some(body), Some(ingest)) => {
                let frames = WireFrames::new(body, progress.clone(), ceilings, timeouts);
                Source::Framed(Box::new(ingest.into_pipeline(WireReader::new(frames))?))
            }
        };
        let (terminal_tx, terminal_rx) = oneshot::channel();
        let producer = VerifiedRequestBody {
            source,
            progress: progress.clone(),
            digests: Some(claims.begin()),
            codes,
            terminal: Some(terminal_tx),
            body_quota,
            decoded_length,
            delivered: 0,
            ended: false,
        };
        let stream = ByteStream::new(Box::pin(producer)).map_err(|_| crate::gate::incomplete())?;
        Ok(Self {
            stream,
            terminal: BodyMonitor {
                terminal: terminal_rx,
                progress: progress_rx,
                wire_progress: progress,
                timeouts,
            },
        })
    }

    pub(crate) fn into_parts(self) -> (ByteStream, BodyMonitor) {
        (self.stream, self.terminal)
    }
}

/// The exact terminal body verdict retained outside the protocol-neutral stream.
pub struct BodyMonitor {
    terminal: oneshot::Receiver<BodyTerminal>,
    pub(crate) progress: watch::Receiver<u64>,
    wire_progress: WireProgress,
    pub(crate) timeouts: BodyTimeouts,
}

#[derive(Debug)]
pub(crate) struct BodyVerified;

pub(crate) enum BodyEvent {
    Complete(Result<BodyVerified, S3Error>),
    /// The handler dropped the stream before one wire octet of it was read.
    ///
    /// Not a verdict on its own, because what it means depends on the handler's answer, which only
    /// the caller sees: a refusal made without reading the body is the answer the client gets, and
    /// a success over a body that never arrived is refused like any other (`c-ck-0062`).
    /// rustfs/gateway#794.
    Unread(WireProgress),
    Quota(WireProgress),
    Idle(WireProgress),
    Throughput(WireProgress),
}

pub(crate) enum BodyTerminal {
    Complete(Result<BodyVerified, S3Error>),
    /// Dropped with nothing read; see [`BodyEvent::Unread`].
    Unread,
    Quota,
}

impl BodyMonitor {
    pub(crate) async fn next_event(&mut self) -> BodyEvent {
        enum Wake {
            Terminal(Result<BodyTerminal, oneshot::error::RecvError>),
            Progress(Result<(), watch::error::RecvError>),
            Idle,
            Throughput,
        }

        let mut body_started = *self.progress.borrow() != 0;
        // A lifted deadline arms nothing, so its slot stays `None` and never wakes (ADR-0034).
        let mut idle_deadline = armed(self.timeouts.waiting_for(body_started)).map(Box::pin);
        let mut throughput_deadline = if body_started {
            armed(self.timeouts.throughput_window()).map(Box::pin)
        } else {
            None
        };
        let mut window_start_bytes = 0_u64;
        loop {
            let wake = {
                let mut changed = Box::pin(self.progress.changed());
                poll_fn(|context| {
                    if let Poll::Ready(verdict) = Pin::new(&mut self.terminal).poll(context) {
                        return Poll::Ready(Wake::Terminal(verdict));
                    }
                    if let Poll::Ready(progress) = changed.as_mut().poll(context) {
                        return Poll::Ready(Wake::Progress(progress));
                    }
                    if throughput_deadline
                        .as_mut()
                        .is_some_and(|deadline| deadline.as_mut().poll(context).is_ready())
                    {
                        return Poll::Ready(Wake::Throughput);
                    }
                    if idle_deadline
                        .as_mut()
                        .is_some_and(|deadline| deadline.as_mut().poll(context).is_ready())
                    {
                        return Poll::Ready(Wake::Idle);
                    }
                    Poll::Pending
                })
                .await
            };
            match wake {
                Wake::Terminal(Ok(BodyTerminal::Complete(verdict))) => return BodyEvent::Complete(verdict),
                Wake::Terminal(Ok(BodyTerminal::Unread)) => return BodyEvent::Unread(self.wire_progress.clone()),
                Wake::Terminal(Ok(BodyTerminal::Quota)) => return BodyEvent::Quota(self.wire_progress.clone()),
                Wake::Terminal(Err(_)) | Wake::Progress(Err(_)) => {
                    return BodyEvent::Complete(Err(crate::gate::incomplete()));
                }
                Wake::Progress(Ok(())) => {
                    let delivered = *self.progress.borrow();
                    if delivered != 0 {
                        if !body_started {
                            body_started = true;
                            throughput_deadline = armed(self.timeouts.throughput_window()).map(Box::pin);
                        }
                        idle_deadline = armed(self.timeouts.waiting_for(true)).map(Box::pin);
                    }
                }
                Wake::Idle => {
                    return BodyEvent::Idle(self.wire_progress.clone());
                }
                Wake::Throughput => {
                    let delivered = *self.progress.borrow();
                    if delivered.saturating_sub(window_start_bytes) < self.timeouts.minimum_throughput_bytes() {
                        return BodyEvent::Throughput(self.wire_progress.clone());
                    }
                    window_start_bytes = delivered;
                    throughput_deadline = armed(self.timeouts.throughput_window()).map(Box::pin);
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait(mut self) -> Result<BodyVerified, S3Error> {
        match self.next_event().await {
            BodyEvent::Complete(verdict) => verdict,
            BodyEvent::Unread(_) => Err(crate::gate::incomplete()),
            BodyEvent::Quota(progress) => Err(crate::gate::body_quota_refusal(progress.request_body_unfinished())),
            BodyEvent::Idle(progress) => Err(crate::gate::body_idle_timeout(progress.request_body_unfinished())),
            BodyEvent::Throughput(progress) => Err(crate::gate::body_throughput_timeout(progress.request_body_unfinished())),
        }
    }

    #[cfg(test)]
    pub(crate) fn pending_for_test(timeouts: BodyTimeouts) -> (Self, oneshot::Sender<BodyTerminal>, watch::Sender<u64>) {
        struct PendingBody;

        impl http_body::Body for PendingBody {
            type Data = Bytes;
            type Error = core::convert::Infallible;

            fn poll_frame(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                Poll::Pending
            }
        }

        let pending_body = PendingBody;
        let wire_progress = WireProgress::for_body(BodyDigestObligation::None, Some(&pending_body));
        Self::pending_with_wire_progress_for_test(timeouts, wire_progress)
    }

    #[cfg(test)]
    pub(crate) fn pending_with_wire_progress_for_test(
        timeouts: BodyTimeouts,
        wire_progress: WireProgress,
    ) -> (Self, oneshot::Sender<BodyTerminal>, watch::Sender<u64>) {
        let (terminal_tx, terminal) = oneshot::channel();
        let (progress_tx, progress) = watch::channel(0);
        (
            Self {
                terminal,
                progress,
                wire_progress,
                timeouts,
            },
            terminal_tx,
            progress_tx,
        )
    }
}

struct VerifiedRequestBody<B> {
    source: Source<B>,
    progress: WireProgress,
    digests: Option<BodyDigests>,
    /// The codes a verification refusal of this body is answered with.
    codes: IntegrityCodes,
    terminal: Option<oneshot::Sender<BodyTerminal>>,
    body_quota: Option<std::sync::Arc<dyn BodyQuota>>,
    decoded_length: Option<u64>,
    delivered: u64,
    ended: bool,
}

impl<B> VerifiedRequestBody<B> {
    fn settle(&mut self, verdict: Result<BodyVerified, S3Error>) {
        if let Some(terminal) = self.terminal.take() {
            let _ = terminal.send(BodyTerminal::Complete(verdict));
        }
        self.ended = true;
    }

    fn fail(&mut self, refusal: S3Error) -> Poll<Result<PayloadRead, StreamError>> {
        self.settle(Err(refusal));
        Poll::Ready(Err(StreamError::incomplete_body().with_bytes_before_error(self.delivered)))
    }

    fn deliver(&mut self, bytes: Bytes) -> Poll<Result<PayloadRead, StreamError>> {
        let newly_verified_bytes = bytes.len() as u64;
        let verified_bytes = self.delivered.saturating_add(newly_verified_bytes);
        if self.body_quota.as_ref().is_some_and(|quota| {
            catch_unwind(AssertUnwindSafe(|| {
                quota.check(VerifiedBodyProgress::new(verified_bytes, newly_verified_bytes))
            }))
            .map_or(true, |decision| decision.is_err())
        }) {
            if let Some(terminal) = self.terminal.take() {
                let _ = terminal.send(BodyTerminal::Quota);
            }
            self.ended = true;
            return Poll::Ready(Err(StreamError::incomplete_body().with_bytes_before_error(self.delivered)));
        }
        if let Some(digests) = self.digests.as_mut() {
            digests.update(&bytes);
        }
        self.delivered = verified_bytes;
        Poll::Ready(Ok(PayloadRead::Chunk(bytes)))
    }

    fn finish(
        &mut self,
        parser_commit_allowed: bool,
        trailer_section_complete: bool,
        trailer_signature_satisfied: bool,
        trailers: TrailingHeaders,
    ) -> Poll<Result<PayloadRead, StreamError>> {
        if let Some(refusal) = self.progress.take_refusal() {
            return self.fail(refusal);
        }
        if !self.progress.digest_matches() {
            return self.fail(self.codes.streamed_payload_hash_mismatch());
        }
        let Some(digests) = self.digests.take() else {
            return self.fail(crate::gate::incomplete());
        };
        let verified = match digests.verify_with_trailers(&trailers) {
            Ok(verified) => verified,
            Err(rejection) => return self.fail(self.codes.refusal(rejection)),
        };
        if !parser_commit_allowed && !(trailer_section_complete && trailer_signature_satisfied && verified.checksum().is_some()) {
            return self.fail(crate::chunked::trailers_not_verified());
        }
        self.settle(Ok(BodyVerified));
        Poll::Ready(Ok(PayloadRead::Eof { trailers }))
    }
}

impl<B> PayloadStream for VerifiedRequestBody<B>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.as_mut().get_mut();
        if this.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(this.delivered)));
        }
        match &mut this.source {
            Source::Empty => this.finish(true, false, true, TrailingHeaders::empty()),
            Source::Plain(frames) => match frames.poll_next(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(refusal)) => this.fail(refusal),
                Poll::Ready(Ok(Some(bytes))) => this.deliver(bytes),
                Poll::Ready(Ok(None)) => this.finish(true, false, true, TrailingHeaders::empty()),
            },
            Source::Framed(pipeline) => {
                let mut buffer = vec![0_u8; DELIVERY_BYTES];
                match Pin::new(pipeline.as_mut()).poll_fill(context, &mut buffer) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        let refusal = this
                            .progress
                            .take_refusal()
                            .unwrap_or_else(|| this.progress.mark_refusal_if_unfinished(this.codes.chunk_refusal(pipeline)));
                        this.fail(refusal)
                    }
                    Poll::Ready(Ok(ReadProgress::Filled(0))) => this.fail(crate::gate::incomplete()),
                    Poll::Ready(Ok(ReadProgress::Filled(written))) => {
                        buffer.truncate(written);
                        this.deliver(Bytes::from(buffer))
                    }
                    Poll::Ready(Ok(ReadProgress::Eof { trailers })) => {
                        let commit_allowed = pipeline.commit_allowed();
                        let trailer_section_complete = pipeline.trailer_section_complete();
                        let trailer_signature_satisfied = pipeline.trailer_signature_satisfied();
                        this.finish(commit_allowed, trailer_section_complete, trailer_signature_satisfied, trailers)
                    }
                }
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        let caps = PayloadCaps::PUSH;
        if self.decoded_length.is_some() {
            caps | PayloadCaps::KNOWN_LENGTH
        } else {
            caps
        }
    }

    fn len_hint(&self) -> Option<u64> {
        self.decoded_length.map(|length| length.saturating_sub(self.delivered))
    }
}

impl<B> Drop for VerifiedRequestBody<B> {
    fn drop(&mut self) {
        if let Some(terminal) = self.terminal.take() {
            // Two different drops. Nothing read is a body the handler declined, and its refusal may
            // be the answer; anything read is a body it began and left in a state the wire cannot
            // resynchronise from, which stays a refusal of its own (rustfs/gateway#794).
            let verdict = if self.progress.seen() == 0 {
                BodyTerminal::Unread
            } else {
                BodyTerminal::Complete(Err(crate::gate::incomplete()))
            };
            let _ = terminal.send(verdict);
        }
    }
}

#[cfg(test)]
#[path = "request_body_tests.rs"]
mod tests;
