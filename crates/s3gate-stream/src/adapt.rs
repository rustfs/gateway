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

//! Moving a body between the pull and the push model, and stating what that costs.
//!
//! Responsible for: the in-memory producers, the two direction adapters, and the `AdaptCost`
//! every adapter must declare. An adaptation is always allowed and never silent: the cost is a
//! value, and the copying kind is counted, so a lost zero-copy path shows up as a number rather
//! than as a slow request nobody can attribute.
//! NOT responsible for: choosing whether to adapt. The transport decides, from the capability
//! bits, and only then asks for the conversion.
//! Upstream: `bytes`, plus this crate's `read`, `stream`, `caps` and `error`. Downstream:
//! `payload`, which is the only place that constructs these adapters, and `metrics`.

use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll};

use bytes::{Buf, Bytes};

use std::collections::VecDeque;

use crate::caps::PayloadCaps;
use crate::error::StreamError;
use crate::read::{AsyncPayloadRead, BoxPayloadReader, ReadProgress};
use crate::stream::{BoxPayloadStream, PayloadRead, PayloadStream};
use crate::trailers::TrailingHeaders;

/// The default buffer size a pull-to-push adapter allocates per chunk.
const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// What it costs to consume a payload through a model it does not natively support.
///
/// Three levels, not a boolean, because "needs an owned buffer" and "copies every byte twice"
/// are different problems: the first costs an allocation per chunk, the second costs memory
/// bandwidth proportional to the object size and is the one worth failing a gate over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptCost {
    /// The payload is consumed in its native model; no adapter sits in the path.
    Free,
    /// The adapter must own the buffer it hands on, but no byte is written twice.
    Buffer {
        /// The number of body bytes expected to flow through the adapter, when known.
        est_bytes: Option<u64>,
    },
    /// Every byte is written once by the producer and then copied again by the adapter.
    ///
    /// This is the cost a performance gate asserts to be absent on a large transfer; it is
    /// counted in [`StreamMetrics::adapt_copies_total`].
    ///
    /// [`StreamMetrics::adapt_copies_total`]: crate::StreamMetrics::adapt_copies_total
    Copy {
        /// The number of body bytes expected to be copied, when known.
        est_bytes: Option<u64>,
    },
}

impl AdaptCost {
    /// Whether the payload is consumed natively.
    #[must_use]
    pub fn is_free(&self) -> bool {
        matches!(self, Self::Free)
    }

    /// Whether every byte is copied a second time.
    #[must_use]
    pub fn is_copy(&self) -> bool {
        matches!(self, Self::Copy { .. })
    }

    /// The number of body bytes the adapter expects to move, when known.
    #[must_use]
    pub fn est_bytes(&self) -> Option<u64> {
        match self {
            Self::Free => None,
            Self::Buffer { est_bytes } | Self::Copy { est_bytes } => *est_bytes,
        }
    }
}

/// Implemented by everything that sits between a producer and a consumer of a different model.
///
/// A type that implements this trait states its price up front, which is what lets the price be
/// counted at the point the adapter is built instead of being discovered in a flame graph.
pub trait Adapt {
    /// What consuming a body through this adapter costs.
    fn adapt_cost(&self) -> AdaptCost;
}

/// A producer contract violation an adapter cannot repair.
#[derive(Debug)]
struct FillContractViolation;

impl fmt::Display for FillContractViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pull-model body reported zero progress without reaching end-of-stream")
    }
}

impl std::error::Error for FillContractViolation {}

/// A push-model producer over segments that are already in memory.
#[derive(Debug)]
pub struct MemoryStream {
    segments: VecDeque<Bytes>,
    trailers: Option<TrailingHeaders>,
    remaining: u64,
    produced: u64,
}

impl MemoryStream {
    /// Builds a producer over `segments`, ending with `trailers`.
    ///
    /// Empty segments are dropped: an empty chunk carries no progress and would blur the one
    /// signal that matters, which is that the body is over.
    #[must_use]
    pub fn new(segments: impl IntoIterator<Item = Bytes>, trailers: TrailingHeaders) -> Self {
        let segments: VecDeque<Bytes> = segments.into_iter().filter(|s| !s.is_empty()).collect();
        let remaining = segments.iter().fold(0u64, |acc, s| acc.saturating_add(s.len() as u64));
        Self {
            segments,
            trailers: Some(trailers),
            remaining,
            produced: 0,
        }
    }
}

impl PayloadStream for MemoryStream {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if let Some(chunk) = this.segments.pop_front() {
            let len = chunk.len() as u64;
            this.remaining = this.remaining.saturating_sub(len);
            this.produced = this.produced.saturating_add(len);
            return Poll::Ready(Ok(PayloadRead::Chunk(chunk)));
        }
        match this.trailers.take() {
            Some(trailers) => Poll::Ready(Ok(PayloadRead::Eof { trailers })),
            None => Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(this.produced))),
        }
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::IN_MEMORY | PayloadCaps::KNOWN_LENGTH | PayloadCaps::VECTORED | PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.remaining)
    }
}

impl Adapt for MemoryStream {
    fn adapt_cost(&self) -> AdaptCost {
        AdaptCost::Free
    }
}

/// A pull-model producer over segments that are already in memory.
///
/// Filling the caller's buffer moves bytes, but the move is the caller's own read, not an
/// adaptation: no intermediate buffer exists and nothing is written twice. The cost is
/// therefore [`AdaptCost::Free`].
#[derive(Debug)]
pub struct MemoryReader {
    segments: VecDeque<Bytes>,
    trailers: Option<TrailingHeaders>,
    remaining: u64,
    produced: u64,
}

impl MemoryReader {
    /// Builds a reader over `segments`, ending with `trailers`.
    #[must_use]
    pub fn new(segments: impl IntoIterator<Item = Bytes>, trailers: TrailingHeaders) -> Self {
        let segments: VecDeque<Bytes> = segments.into_iter().filter(|s| !s.is_empty()).collect();
        let remaining = segments.iter().fold(0u64, |acc, s| acc.saturating_add(s.len() as u64));
        Self {
            segments,
            trailers: Some(trailers),
            remaining,
            produced: 0,
        }
    }
}

impl AsyncPayloadRead for MemoryReader {
    fn poll_fill(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        let this = self.get_mut();
        if let Some(front) = this.segments.front_mut() {
            if buf.is_empty() {
                return Poll::Ready(Ok(ReadProgress::Filled(0)));
            }
            let n = buf.len().min(front.len());
            buf[..n].copy_from_slice(&front[..n]);
            front.advance(n);
            if front.is_empty() {
                this.segments.pop_front();
            }
            this.remaining = this.remaining.saturating_sub(n as u64);
            this.produced = this.produced.saturating_add(n as u64);
            return Poll::Ready(Ok(ReadProgress::Filled(n)));
        }
        match this.trailers.take() {
            Some(trailers) => Poll::Ready(Ok(ReadProgress::Eof { trailers })),
            None => Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(this.produced))),
        }
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::IN_MEMORY | PayloadCaps::KNOWN_LENGTH | PayloadCaps::VECTORED | PayloadCaps::PULL
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.remaining)
    }
}

impl Adapt for MemoryReader {
    fn adapt_cost(&self) -> AdaptCost {
        AdaptCost::Free
    }
}

/// Consumes a push-model body through the pull model.
///
/// The producer allocates and fills a chunk, then this adapter copies it into the consumer's
/// buffer: every byte is written twice. This is the adaptation that costs a full extra memory
/// pass over an upload, and it is the reason [`AdaptCost::Copy`] exists and is counted.
pub struct StreamToReader {
    inner: BoxPayloadStream,
    leftover: Bytes,
    ended: bool,
    copied: u64,
    est_bytes: Option<u64>,
}

impl StreamToReader {
    /// Wraps a push-model body so a pull-model consumer can read it.
    #[must_use]
    pub fn new(inner: BoxPayloadStream) -> Self {
        let est_bytes = inner.len_hint();
        Self {
            inner,
            leftover: Bytes::new(),
            ended: false,
            copied: 0,
            est_bytes,
        }
    }
}

impl AsyncPayloadRead for StreamToReader {
    fn poll_fill(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        let this = self.get_mut();
        loop {
            if !this.leftover.is_empty() {
                if buf.is_empty() {
                    return Poll::Ready(Ok(ReadProgress::Filled(0)));
                }
                let n = buf.len().min(this.leftover.len());
                buf[..n].copy_from_slice(&this.leftover[..n]);
                this.leftover.advance(n);
                this.copied = this.copied.saturating_add(n as u64);
                return Poll::Ready(Ok(ReadProgress::Filled(n)));
            }
            if this.ended {
                return Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(this.copied)));
            }
            match this.inner.as_mut().poll_read(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(err.or_bytes_before_error(this.copied)));
                }
                Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => {
                    this.leftover = chunk;
                }
                Poll::Ready(Ok(PayloadRead::Eof { trailers })) => {
                    this.ended = true;
                    return Poll::Ready(Ok(ReadProgress::Eof { trailers }));
                }
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        (self.inner.caps() & !(PayloadCaps::PUSH | PayloadCaps::VECTORED)) | PayloadCaps::PULL
    }

    fn len_hint(&self) -> Option<u64> {
        self.inner.len_hint()
    }
}

impl fmt::Debug for StreamToReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamToReader")
            .field("leftover", &self.leftover.len())
            .field("ended", &self.ended)
            .field("copied", &self.copied)
            .field("est_bytes", &self.est_bytes)
            .finish_non_exhaustive()
    }
}

impl Adapt for StreamToReader {
    fn adapt_cost(&self) -> AdaptCost {
        AdaptCost::Copy {
            est_bytes: self.est_bytes,
        }
    }
}

/// Consumes a pull-model body through the push model.
///
/// The adapter owns the buffer the producer fills, so it pays an allocation per chunk, but the
/// producer writes each byte straight into that buffer and nothing is written twice: the cost
/// is [`AdaptCost::Buffer`], not [`AdaptCost::Copy`].
pub struct ReaderToStream {
    inner: BoxPayloadReader,
    chunk_size: usize,
    ended: bool,
    produced: u64,
    est_bytes: Option<u64>,
}

impl ReaderToStream {
    /// Wraps a pull-model body so a push-model consumer can read it.
    #[must_use]
    pub fn new(inner: BoxPayloadReader) -> Self {
        let est_bytes = inner.len_hint();
        Self {
            inner,
            chunk_size: DEFAULT_CHUNK_SIZE,
            ended: false,
            produced: 0,
            est_bytes,
        }
    }

    /// Sets the buffer size the adapter allocates per chunk; zero is raised to one byte.
    #[must_use]
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size.max(1);
        self
    }

    fn next_capacity(&self) -> usize {
        match self.inner.len_hint() {
            Some(remaining) if remaining > 0 => {
                let remaining = usize::try_from(remaining).unwrap_or(self.chunk_size);
                remaining.min(self.chunk_size).max(1)
            }
            _ => self.chunk_size,
        }
    }
}

impl PayloadStream for ReaderToStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(this.produced)));
        }
        let mut buf = vec![0u8; this.next_capacity()];
        match this.inner.as_mut().poll_fill(cx, &mut buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.or_bytes_before_error(this.produced))),
            Poll::Ready(Ok(ReadProgress::Filled(0))) => Poll::Ready(Err(
                StreamError::upstream(Box::new(FillContractViolation)).with_bytes_before_error(this.produced)
            )),
            Poll::Ready(Ok(ReadProgress::Filled(n))) => {
                buf.truncate(n);
                this.produced = this.produced.saturating_add(n as u64);
                Poll::Ready(Ok(PayloadRead::Chunk(Bytes::from(buf))))
            }
            Poll::Ready(Ok(ReadProgress::Eof { trailers })) => {
                this.ended = true;
                Poll::Ready(Ok(PayloadRead::Eof { trailers }))
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        (self.inner.caps() & !PayloadCaps::PULL) | PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        self.inner.len_hint()
    }
}

impl fmt::Debug for ReaderToStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReaderToStream")
            .field("chunk_size", &self.chunk_size)
            .field("ended", &self.ended)
            .field("produced", &self.produced)
            .field("est_bytes", &self.est_bytes)
            .finish_non_exhaustive()
    }
}

impl Adapt for ReaderToStream {
    fn adapt_cost(&self) -> AdaptCost {
        AdaptCost::Buffer {
            est_bytes: self.est_bytes,
        }
    }
}
