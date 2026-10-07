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

//! The bridges between `tokio::io::AsyncRead` and the two halves of the data plane.
//!
//! Responsible for: [`TokioReadPayload`], which lets any `tokio::io::AsyncRead` serve as a
//! pull-model body and holds it to a declared length when one is given, and [`PayloadReader`],
//! which lets a push-model body be read through `tokio::io::AsyncRead` and keeps the trailer
//! section the body ended with. Neither owns an intermediate buffer: the first hands the
//! consumer's own slice to the reader, the second serves each chunk out of the producer's buffer
//! and lets it go as soon as its last byte is taken. Neither spawns and neither needs a runtime;
//! the crate's `tokio` dependency carries `io-util` alone, so nothing here could.
//! NOT responsible for: framing, back-pressure policy, or length policing on the push side — a
//! stream that must hold itself to a declared length is wrapped in `ByteStream` first, and
//! `PayloadReader` reports whatever that stream reports.
//! Upstream: `tokio` (`io-util`), `bytes`, and this crate's `read`, `stream`, `caps`, `error`,
//! `adapt` and `trailers`. Downstream: the file-backed response fallback in the facade, and any
//! handler that drains a request body into an `AsyncRead` consumer.
//!
//! Both bridges declare [`AdaptCost::Free`]. A `TokioReadPayload` fill is the reader writing
//! into the consumer's slice, exactly as it would without the bridge. A `PayloadReader` read is
//! the consumer copying out of the producer's chunk into its own buffer, which is what every
//! `AsyncRead` read is — the move [`MemoryReader`] makes and calls free for the same reason —
//! and no byte is written into a buffer this module owns.
//!
//! [`MemoryReader`]: crate::MemoryReader

use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;

use bytes::{Buf, Bytes};
use http::HeaderMap;
use tokio::io::{AsyncRead, ReadBuf};

use crate::adapt::{Adapt, AdaptCost};
use crate::caps::PayloadCaps;
use crate::error::{StreamError, StreamErrorKind};
use crate::read::{AsyncPayloadRead, ReadProgress};
use crate::stream::{PayloadRead, PayloadStream};
use crate::trailers::TrailingHeaders;

/// A `tokio::io::AsyncRead` served as a pull-model body.
///
/// The reader writes straight into the slice the consumer passes to `poll_fill`; this type adds
/// end-of-stream detection, the once-only `Eof` contract of [`AsyncPayloadRead`], and — when a
/// length was declared — the two length failures a bare reader cannot report: ending short of
/// the declaration is [`StreamErrorKind::IncompleteBody`], running past it is
/// [`StreamErrorKind::LengthMismatch`]. An `AsyncRead` carries no trailer section, so `Eof`
/// always arrives with an empty one.
pub struct TokioReadPayload<R> {
    inner: R,
    declared: Option<u64>,
    observed: u64,
    ended: bool,
}

impl<R> TokioReadPayload<R> {
    /// Wraps a reader whose length is not known up front.
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            declared: None,
            observed: 0,
            ended: false,
        }
    }

    /// Wraps a reader that will deliver exactly `len` bytes, and fails it if it does not.
    #[must_use]
    pub fn with_len_hint(inner: R, len: u64) -> Self {
        Self {
            inner,
            declared: Some(len),
            observed: 0,
            ended: false,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncPayloadRead for TokioReadPayload<R> {
    fn poll_fill(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(this.observed)));
        }
        if buf.is_empty() {
            // Not a read. `AsyncRead` answers a read into no room with zero bytes, and zero bytes
            // is also its end-of-stream signal; consulting the reader here would end the body.
            return Poll::Ready(Ok(ReadProgress::Filled(0)));
        }
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                this.ended = true;
                Poll::Ready(Err(StreamError::from(err).with_bytes_before_error(this.observed)))
            }
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled().len();
                if filled == 0 {
                    this.ended = true;
                    if let Some(declared) = this.declared
                        && this.observed < declared
                    {
                        return Poll::Ready(Err(StreamError::incomplete_body().with_bytes_before_error(this.observed)));
                    }
                    return Poll::Ready(Ok(ReadProgress::Eof {
                        trailers: TrailingHeaders::empty(),
                    }));
                }
                let observed = this.observed.saturating_add(filled as u64);
                if let Some(declared) = this.declared
                    && observed > declared
                {
                    this.ended = true;
                    return Poll::Ready(Err(
                        StreamError::length_mismatch(declared, observed).with_bytes_before_error(this.observed)
                    ));
                }
                this.observed = observed;
                Poll::Ready(Ok(ReadProgress::Filled(filled)))
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        let mut caps = PayloadCaps::PULL;
        caps.set(PayloadCaps::KNOWN_LENGTH, self.declared.is_some());
        caps
    }

    fn len_hint(&self) -> Option<u64> {
        self.declared.map(|declared| declared.saturating_sub(self.observed))
    }
}

impl<R> Adapt for TokioReadPayload<R> {
    fn adapt_cost(&self) -> AdaptCost {
        AdaptCost::Free
    }
}

impl<R> fmt::Debug for TokioReadPayload<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokioReadPayload")
            .field("declared", &self.declared)
            .field("observed", &self.observed)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

/// Where a [`PayloadReader`] stands relative to the end of its body.
enum End {
    /// Body bytes may still come.
    Open,
    /// The producer reported end-of-stream, with this trailer section.
    Eof(TrailingHeaders),
    /// The producer failed; the body has no end and no trailer section.
    Failed,
}

/// A push-model body read through `tokio::io::AsyncRead`.
///
/// Each chunk the producer hands over is held as-is and served into the consumer's `ReadBuf`
/// piece by piece; nothing is copied into a buffer of this type's own, and the chunk is released
/// the moment its last byte has been taken. The trailer section becomes reachable through
/// [`PayloadReader::trailers`] only after a read has observed end-of-stream, which is the same
/// ordering rule the rest of this crate enforces through [`PayloadRead::Eof`].
///
/// Dropping the reader drops the producer: cancellation is ownership, and no task outlives it.
pub struct PayloadReader<S> {
    inner: S,
    current: Bytes,
    served: u64,
    end: End,
}

impl<S> PayloadReader<S> {
    /// Wraps a push-model body so an `AsyncRead` consumer can read it.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            current: Bytes::new(),
            served: 0,
            end: End::Open,
        }
    }

    /// The trailer section the body ended with.
    ///
    /// `None` means exactly one thing: no read has observed end-of-stream yet. A body that ended
    /// without a trailer field answers `Some` of an empty map, so the two facts stay apart.
    #[must_use]
    pub fn trailers(&self) -> Option<&HeaderMap> {
        match &self.end {
            End::Eof(trailers) => Some(trailers.as_header_map()),
            End::Open | End::Failed => None,
        }
    }

    /// Consumes the reader and returns the trailer section, if end-of-stream was observed.
    #[must_use]
    pub fn into_trailers(self) -> Option<TrailingHeaders> {
        match self.end {
            End::Eof(trailers) => Some(trailers),
            End::Open | End::Failed => None,
        }
    }
}

impl<S: PayloadStream + Unpin> AsyncRead for PayloadReader<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            // No room is not a read: taking a chunk now would only move it into this type.
            return Poll::Ready(Ok(()));
        }
        loop {
            if !this.current.is_empty() {
                let n = buf.remaining().min(this.current.len());
                buf.put_slice(&this.current[..n]);
                this.current.advance(n);
                this.served = this.served.saturating_add(n as u64);
                if this.current.is_empty() {
                    // An advanced-to-empty view still pins the producer's allocation; drop it.
                    this.current = Bytes::new();
                }
                return Poll::Ready(Ok(()));
            }
            match this.end {
                // `AsyncRead` reports end-of-stream by filling nothing. The producer is not
                // polled again; its contract says the answer would be an error.
                End::Eof(_) => return Poll::Ready(Ok(())),
                End::Failed => {
                    return Poll::Ready(Err(into_io_error(StreamError::polled_after_eof().with_bytes_before_error(this.served))));
                }
                End::Open => {}
            }
            match Pin::new(&mut this.inner).poll_read(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => {
                    this.end = End::Failed;
                    return Poll::Ready(Err(into_io_error(err.or_bytes_before_error(this.served))));
                }
                Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => this.current = chunk,
                Poll::Ready(Ok(PayloadRead::Eof { trailers })) => {
                    this.end = End::Eof(trailers);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S> Adapt for PayloadReader<S> {
    fn adapt_cost(&self) -> AdaptCost {
        AdaptCost::Free
    }
}

impl<S> fmt::Debug for PayloadReader<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match &self.end {
            End::Open => "open",
            End::Eof(_) => "eof",
            End::Failed => "failed",
        };
        f.debug_struct("PayloadReader")
            .field("current", &self.current.len())
            .field("served", &self.served)
            .field("end", &state)
            .finish_non_exhaustive()
    }
}

/// Turns a body failure into the `io::Error` an `AsyncRead` consumer expects.
///
/// An i/o error the producer reported is handed back as it was, not wrapped in a description
/// of itself. Every other kind keeps the whole [`StreamError`] — its byte count included — as
/// the error's payload, under the `io::ErrorKind` nearest to its meaning.
fn into_io_error(err: StreamError) -> io::Error {
    let kind = match err.kind() {
        StreamErrorKind::Io(inner) => inner.kind(),
        StreamErrorKind::IncompleteBody => io::ErrorKind::UnexpectedEof,
        StreamErrorKind::LengthMismatch { .. } => io::ErrorKind::InvalidData,
        StreamErrorKind::PolledAfterEof | StreamErrorKind::Upstream(_) => io::ErrorKind::Other,
    };
    let bytes_before_error = err.bytes_before_error();
    match err.into_kind() {
        StreamErrorKind::Io(inner) => inner,
        other => io::Error::new(kind, StreamError::new(other).with_bytes_before_error(bytes_before_error)),
    }
}
