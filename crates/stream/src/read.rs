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

//! The pull half of the data plane: the consumer owns the buffer and asks it to be filled.
//!
//! Responsible for: the `AsyncPayloadRead` trait and its progress event, which carries the same
//! end-of-stream trailer rule as the push half.
//! NOT responsible for: buffering policy, back-pressure or read-ahead sizing — the consumer
//! picks the buffer, which is the whole point of this half.
//! Upstream: this crate's `caps`, `error` and `trailers`. Downstream: `payload`, the wire layer,
//! and any consumer that already owns a buffer and would otherwise pay a copy per byte.

use core::pin::Pin;
use core::task::{Context, Poll};

use crate::caps::PayloadCaps;
use crate::error::StreamError;
use crate::trailers::TrailingHeaders;

/// The outcome of one fill attempt against a consumer-owned buffer.
///
/// As on the push half, the trailer section exists only inside the end-of-stream variant, so a
/// consumer cannot hold a [`TrailingHeaders`] value before the body is over.
#[derive(Debug)]
pub enum ReadProgress {
    /// This many bytes were written to the front of the caller's buffer; never zero unless the
    /// caller passed an empty buffer.
    Filled(usize),
    /// The body is over, and this is everything that trailed it. Emitted exactly once.
    Eof {
        /// The trailer section; empty when the producer sent no trailer field.
        trailers: TrailingHeaders,
    },
}

impl ReadProgress {
    /// The number of body bytes this outcome placed in the caller's buffer.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Filled(n) => *n,
            Self::Eof { .. } => 0,
        }
    }

    /// Whether this outcome ends the stream.
    #[must_use]
    pub fn is_eof(&self) -> bool {
        matches!(self, Self::Eof { .. })
    }
}

/// A pull-model body: the consumer supplies the buffer, the producer fills it.
///
/// This is the shape a hashing or erasure-coding reader wants. Handing such a consumer a
/// push-model body instead forces an adapter that copies every byte into the consumer's buffer;
/// that adaptation is legal here, but it is named [`AdaptCost::Copy`] and it is counted.
///
/// # Contract
///
/// * `poll_fill` returns [`ReadProgress::Eof`] exactly once, as the final successful outcome.
/// * After `Eof` or an error, any further poll returns [`StreamErrorKind::PolledAfterEof`].
/// * A body that cannot be read to its end fails; it never substitutes `Eof`.
/// * `caps()` and `len_hint()` must satisfy [`validate_caps`].
///
/// [`AdaptCost::Copy`]: crate::AdaptCost::Copy
/// [`StreamErrorKind::PolledAfterEof`]: crate::StreamErrorKind::PolledAfterEof
/// [`validate_caps`]: crate::validate_caps
pub trait AsyncPayloadRead {
    /// Fills the front of `buf` with the next body bytes.
    ///
    /// `buf` is a plain initialised slice. An uninitialised-buffer API would save one zeroing
    /// pass per buffer, and it cannot be written without `unsafe`, which this crate forbids;
    /// the zeroing is paid once per buffer, not once per byte, and buffers are reused.
    fn poll_fill(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>>;

    /// The capabilities of the remaining body.
    fn caps(&self) -> PayloadCaps;

    /// The exact number of body bytes still to come, when it is known.
    fn len_hint(&self) -> Option<u64>;
}

/// A boxed pull-model body. Pinned at the box for the same reason as [`BoxPayloadStream`].
///
/// [`BoxPayloadStream`]: crate::BoxPayloadStream
pub type BoxPayloadReader = Pin<Box<dyn AsyncPayloadRead + Send>>;

impl<R: AsyncPayloadRead + ?Sized> AsyncPayloadRead for Pin<Box<R>> {
    fn poll_fill(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        self.get_mut().as_mut().poll_fill(cx, buf)
    }

    fn caps(&self) -> PayloadCaps {
        (**self).caps()
    }

    fn len_hint(&self) -> Option<u64> {
        (**self).len_hint()
    }
}
