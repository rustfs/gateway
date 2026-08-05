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

//! The push half of the data plane: the producer owns the buffers and hands them over.
//!
//! Responsible for: the `PayloadStream` trait, the read event it produces, and the ordering
//! rule that makes the trailer section unobtainable before the body is over.
//! NOT responsible for: framing. Nothing here knows how a byte stream is cut into chunks;
//! a producer is handed already-decoded bytes. The chunk decoder lives in the wire layer.
//! Upstream: `bytes`, plus this crate's `caps`, `error` and `trailers`. Downstream: `payload`,
//! `body`, `byte_stream`, the wire layer producers, and every consumer of a response body.

use core::pin::Pin;
use core::task::{Context, Poll};

use bytes::Bytes;

use crate::caps::PayloadCaps;
use crate::error::StreamError;
use crate::trailers::TrailingHeaders;

/// One event from a push-model body.
///
/// The trailer section appears in exactly one place — inside [`PayloadRead::Eof`]. A consumer
/// that has not seen `Eof` has no value of type [`TrailingHeaders`] in scope and therefore
/// cannot read a trailer field early; the ordering is a property of the type, not of a comment.
#[derive(Debug)]
pub enum PayloadRead {
    /// A non-empty run of body bytes.
    ///
    /// Producers never emit an empty chunk: an empty chunk is indistinguishable from progress
    /// and makes "the body is over" ambiguous. A zero-length body goes straight to `Eof`.
    Chunk(Bytes),
    /// The body is over, and this is everything that trailed it.
    ///
    /// Emitted exactly once, as the last event. A body that ends early — because the connection
    /// dropped, or because the announced trailer never arrived — must fail with
    /// [`StreamErrorKind::IncompleteBody`] instead. Emitting `Eof` there would present a
    /// truncated body to the handler as a complete one.
    ///
    /// [`StreamErrorKind::IncompleteBody`]: crate::StreamErrorKind::IncompleteBody
    Eof {
        /// The trailer section; empty when the producer sent no trailer field.
        trailers: TrailingHeaders,
    },
}

impl PayloadRead {
    /// The number of body bytes carried by this event.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Chunk(bytes) => bytes.len(),
            Self::Eof { .. } => 0,
        }
    }

    /// Whether this event ends the stream.
    #[must_use]
    pub fn is_eof(&self) -> bool {
        matches!(self, Self::Eof { .. })
    }
}

/// A push-model body: the producer allocates, fills and hands over each chunk.
///
/// This is the natural shape for a proxied upstream response and for a producer that already
/// owns an internal buffer. Its counterpart is [`AsyncPayloadRead`], where the consumer owns
/// the buffer. Both models are first class here; supporting only one of them means every
/// participant on the other side pays a copy per byte, which is the concrete cost this crate
/// exists to make visible and countable.
///
/// # Contract
///
/// * `poll_read` returns [`PayloadRead::Eof`] exactly once, as the final event.
/// * After `Eof`, any further poll returns [`StreamErrorKind::PolledAfterEof`]; it must never
///   return another chunk.
/// * A stream that cannot reach the end of the body fails; it never substitutes `Eof`.
/// * `caps()` and `len_hint()` must satisfy [`validate_caps`].
///
/// [`AsyncPayloadRead`]: crate::AsyncPayloadRead
/// [`StreamErrorKind::PolledAfterEof`]: crate::StreamErrorKind::PolledAfterEof
/// [`validate_caps`]: crate::validate_caps
pub trait PayloadStream {
    /// Polls for the next event.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>>;

    /// The capabilities of the remaining body.
    fn caps(&self) -> PayloadCaps;

    /// The exact number of body bytes still to come, when it is known.
    fn len_hint(&self) -> Option<u64>;
}

/// A boxed push-model body.
///
/// The box is pinned rather than plain. Producers written as async state machines are not
/// `Unpin`, and this crate forbids `unsafe`, so there is no sound way to project a `Pin` into
/// a plain `Box<dyn PayloadStream>`. Pinning at the box makes every adapter in this crate
/// `Unpin` and removes the need for a projection — and therefore for `unsafe` — entirely.
pub type BoxPayloadStream = Pin<Box<dyn PayloadStream + Send>>;

impl<S: PayloadStream + ?Sized> PayloadStream for Pin<Box<S>> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        self.get_mut().as_mut().poll_read(cx)
    }

    fn caps(&self) -> PayloadCaps {
        (**self).caps()
    }

    fn len_hint(&self) -> Option<u64> {
        (**self).len_hint()
    }
}
