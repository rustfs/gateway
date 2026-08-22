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
use core::pin::Pin;
use core::task::{Context, Poll};

use bytes::Bytes;
use rustfs_gateway_http::{BodyDigests, BodyIntegrity, IngestPipeline};
use rustfs_gateway_stream::{
    AsyncPayloadRead, ByteStream, PayloadCaps, PayloadRead, PayloadStream, ReadProgress, StreamError, TrailingHeaders,
};
use tokio::sync::{oneshot, watch};

use crate::chunked::ChunkIngest;
use crate::gate::{BodyCeilings, BodyDigestObligation, BodyTimeouts};
use crate::integrity::checksum_refusal;
use crate::render::S3Error;
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
        declared_length: Option<u64>,
        ceilings: BodyCeilings,
        timeouts: BodyTimeouts,
        ingest: Option<ChunkIngest>,
        digest: BodyDigestObligation,
        integrity: BodyIntegrity,
    ) -> Result<Self, S3Error>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (progress_tx, progress_rx) = watch::channel(0_u64);
        let progress = WireProgress::new(digest).with_observer(progress_tx);
        let decoded_length = ingest.as_ref().map(ChunkIngest::decoded_length).or(declared_length);
        if ingest.is_none() && body.as_ref().is_none_or(http_body::Body::is_end_stream) {
            let verdict = if !progress.digest_matches() {
                Err(crate::gate::content_sha256_mismatch())
            } else {
                integrity.begin().verify().map(|_| BodyVerified).map_err(checksum_refusal)
            };
            let (terminal_tx, terminal_rx) = oneshot::channel();
            let _ = terminal_tx.send(verdict);
            return Ok(Self {
                stream: ByteStream::from_bytes(Bytes::new()),
                terminal: BodyMonitor {
                    terminal: terminal_rx,
                    progress: progress_rx,
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
            progress,
            digests: Some(integrity.begin()),
            terminal: Some(terminal_tx),
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
    terminal: oneshot::Receiver<Result<BodyVerified, S3Error>>,
    pub(crate) progress: watch::Receiver<u64>,
    pub(crate) timeouts: BodyTimeouts,
}

#[derive(Debug)]
pub(crate) struct BodyVerified;

pub(crate) enum BodyEvent {
    Complete(Result<BodyVerified, S3Error>),
    Idle,
    Throughput,
}

impl BodyMonitor {
    pub(crate) async fn next_event(&mut self) -> BodyEvent {
        enum Wake {
            Terminal(Result<Result<BodyVerified, S3Error>, oneshot::error::RecvError>),
            Progress(Result<(), watch::error::RecvError>),
            Idle,
            Throughput,
        }

        let mut body_started = *self.progress.borrow() != 0;
        let mut idle_deadline = Box::pin(futures_timer::Delay::new(self.timeouts.waiting_for(body_started)));
        let mut throughput_deadline =
            body_started.then(|| Box::pin(futures_timer::Delay::new(self.timeouts.throughput_window())));
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
                    if idle_deadline.as_mut().poll(context).is_ready() {
                        return Poll::Ready(Wake::Idle);
                    }
                    Poll::Pending
                })
                .await
            };
            match wake {
                Wake::Terminal(Ok(verdict)) => return BodyEvent::Complete(verdict),
                Wake::Terminal(Err(_)) | Wake::Progress(Err(_)) => {
                    return BodyEvent::Complete(Err(crate::gate::incomplete()));
                }
                Wake::Progress(Ok(())) => {
                    let delivered = *self.progress.borrow();
                    if delivered != 0 {
                        if !body_started {
                            body_started = true;
                            throughput_deadline = Some(Box::pin(futures_timer::Delay::new(self.timeouts.throughput_window())));
                        }
                        idle_deadline = Box::pin(futures_timer::Delay::new(self.timeouts.waiting_for(true)));
                    }
                }
                Wake::Idle => return BodyEvent::Idle,
                Wake::Throughput => {
                    let delivered = *self.progress.borrow();
                    if delivered.saturating_sub(window_start_bytes) < self.timeouts.minimum_throughput_bytes() {
                        return BodyEvent::Throughput;
                    }
                    window_start_bytes = delivered;
                    throughput_deadline = Some(Box::pin(futures_timer::Delay::new(self.timeouts.throughput_window())));
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait(mut self) -> Result<BodyVerified, S3Error> {
        match self.next_event().await {
            BodyEvent::Complete(verdict) => verdict,
            BodyEvent::Idle => Err(crate::gate::body_idle_timeout()),
            BodyEvent::Throughput => Err(crate::gate::body_throughput_timeout()),
        }
    }

    #[cfg(test)]
    pub(crate) fn pending_for_test(
        timeouts: BodyTimeouts,
    ) -> (Self, oneshot::Sender<Result<BodyVerified, S3Error>>, watch::Sender<u64>) {
        let (terminal_tx, terminal) = oneshot::channel();
        let (progress_tx, progress) = watch::channel(0);
        (
            Self {
                terminal,
                progress,
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
    terminal: Option<oneshot::Sender<Result<BodyVerified, S3Error>>>,
    decoded_length: Option<u64>,
    delivered: u64,
    ended: bool,
}

impl<B> VerifiedRequestBody<B> {
    fn settle(&mut self, verdict: Result<BodyVerified, S3Error>) {
        if let Some(terminal) = self.terminal.take() {
            let _ = terminal.send(verdict);
        }
        self.ended = true;
    }

    fn fail(&mut self, refusal: S3Error) -> Poll<Result<PayloadRead, StreamError>> {
        self.settle(Err(refusal));
        Poll::Ready(Err(StreamError::incomplete_body().with_bytes_before_error(self.delivered)))
    }

    fn deliver(&mut self, bytes: Bytes) -> Poll<Result<PayloadRead, StreamError>> {
        if let Some(digests) = self.digests.as_mut() {
            digests.update(&bytes);
        }
        self.delivered = self.delivered.saturating_add(bytes.len() as u64);
        Poll::Ready(Ok(PayloadRead::Chunk(bytes)))
    }

    fn finish(&mut self, commit_allowed: bool) -> Poll<Result<PayloadRead, StreamError>> {
        if !commit_allowed {
            return self.fail(crate::chunked::trailers_not_verified());
        }
        if let Some(refusal) = self.progress.take_refusal() {
            return self.fail(refusal);
        }
        if !self.progress.digest_matches() {
            return self.fail(crate::gate::content_sha256_mismatch());
        }
        let Some(digests) = self.digests.take() else {
            return self.fail(crate::gate::incomplete());
        };
        if let Err(rejection) = digests.verify() {
            return self.fail(checksum_refusal(rejection));
        }
        self.settle(Ok(BodyVerified));
        Poll::Ready(Ok(PayloadRead::Eof {
            trailers: TrailingHeaders::empty(),
        }))
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
            Source::Empty => this.finish(true),
            Source::Plain(frames) => match frames.poll_next(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(refusal)) => this.fail(refusal),
                Poll::Ready(Ok(Some(bytes))) => this.deliver(bytes),
                Poll::Ready(Ok(None)) => this.finish(true),
            },
            Source::Framed(pipeline) => {
                let mut buffer = vec![0_u8; DELIVERY_BYTES];
                match Pin::new(pipeline.as_mut()).poll_fill(context, &mut buffer) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        let refusal = this.progress.take_refusal().unwrap_or_else(|| ChunkIngest::refusal(pipeline));
                        this.fail(refusal)
                    }
                    Poll::Ready(Ok(ReadProgress::Filled(0))) => this.fail(crate::gate::incomplete()),
                    Poll::Ready(Ok(ReadProgress::Filled(written))) => {
                        buffer.truncate(written);
                        this.deliver(Bytes::from(buffer))
                    }
                    Poll::Ready(Ok(ReadProgress::Eof { .. })) => {
                        let commit_allowed = pipeline.commit_allowed();
                        this.finish(commit_allowed)
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
            let _ = terminal.send(Err(crate::gate::incomplete()));
        }
    }
}

#[cfg(test)]
#[path = "request_body_tests.rs"]
mod tests;
