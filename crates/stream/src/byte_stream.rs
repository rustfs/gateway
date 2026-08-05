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

//! A push-model body that holds itself to the length it declared.
//!
//! Responsible for: tracking how much of a declared body is still outstanding, and turning the
//! two ways that count can be wrong into errors — a body that ends early fails as incomplete, a
//! body that overruns fails as a length mismatch. Both must be errors rather than a shrug: a
//! short body that reports end-of-stream is a partial upload presented as a whole one.
//! NOT responsible for: where the declared length came from. Nothing here reads a header; the
//! wire layer decides the length and passes it in.
//! Upstream: this crate's `stream`, `caps` and `error`. Downstream: `rustfs-gateway-types`, whose
//! streaming blob fields wrap this, and `rustfs-gateway-http`.

use core::pin::Pin;
use core::task::{Context, Poll};

use bytes::Bytes;

use crate::adapt::MemoryStream;
use crate::body::Body;
use crate::caps::{CapsInconsistency, PayloadCaps, validate_caps};
use crate::error::StreamError;
use crate::payload::Payload;
use crate::stream::{BoxPayloadStream, PayloadRead, PayloadStream};
use crate::trailers::TrailingHeaders;

/// How many body bytes are still outstanding.
///
/// A newtype rather than a bare `Option<u64>` so that "unknown" cannot be mistaken for "zero"
/// at a call site — the two lead to opposite framing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemainingLength(Option<u64>);

impl RemainingLength {
    /// A known number of outstanding bytes.
    #[must_use]
    pub fn exact(len: u64) -> Self {
        Self(Some(len))
    }

    /// An unknown number of outstanding bytes.
    #[must_use]
    pub fn unknown() -> Self {
        Self(None)
    }

    /// The number of outstanding bytes, when it is known.
    #[must_use]
    pub fn get(self) -> Option<u64> {
        self.0
    }

    /// Whether the number of outstanding bytes is known.
    #[must_use]
    pub fn is_known(self) -> bool {
        self.0.is_some()
    }
}

impl From<Option<u64>> for RemainingLength {
    fn from(value: Option<u64>) -> Self {
        Self(value)
    }
}

/// A push-model body with the length bookkeeping a consumer would otherwise repeat.
///
/// This is the type the generated streaming fields wrap. It is itself a [`PayloadStream`], so
/// wrapping costs nothing at the type level and the length check cannot be bypassed by reading
/// the inner producer directly — the inner producer is private.
pub struct ByteStream {
    inner: BoxPayloadStream,
    declared: Option<u64>,
    observed: u64,
    ended: bool,
}

impl ByteStream {
    /// Wraps a producer, taking its declared length from its own length hint.
    pub fn new(inner: BoxPayloadStream) -> Result<Self, CapsInconsistency> {
        validate_caps(inner.caps(), inner.len_hint())?;
        let declared = inner.len_hint();
        Ok(Self {
            inner,
            declared,
            observed: 0,
            ended: false,
        })
    }

    /// A stream over bytes that are already in memory.
    #[must_use]
    pub fn from_bytes(bytes: Bytes) -> Self {
        let declared = bytes.len() as u64;
        Self {
            inner: Box::pin(MemoryStream::new([bytes], TrailingHeaders::empty())),
            declared: Some(declared),
            observed: 0,
            ended: false,
        }
    }

    /// How many body bytes are still outstanding.
    #[must_use]
    pub fn remaining_length(&self) -> RemainingLength {
        RemainingLength(self.declared.map(|d| d.saturating_sub(self.observed)))
    }

    /// How many body bytes have been delivered so far.
    #[must_use]
    pub fn observed_length(&self) -> u64 {
        self.observed
    }

    /// Turns the stream into a body, keeping the length checking in place.
    #[must_use]
    pub fn into_body(self) -> Body {
        Body::from_payload(Payload::Stream(Box::pin(self)))
    }
}

impl PayloadStream for ByteStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(this.observed)));
        }
        match this.inner.as_mut().poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err.or_bytes_before_error(this.observed))),
            Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => {
                this.observed = this.observed.saturating_add(chunk.len() as u64);
                if let Some(declared) = this.declared
                    && this.observed > declared
                {
                    this.ended = true;
                    return Poll::Ready(Err(
                        StreamError::length_mismatch(declared, this.observed).with_bytes_before_error(this.observed)
                    ));
                }
                Poll::Ready(Ok(PayloadRead::Chunk(chunk)))
            }
            Poll::Ready(Ok(PayloadRead::Eof { trailers })) => {
                this.ended = true;
                if let Some(declared) = this.declared
                    && this.observed < declared
                {
                    return Poll::Ready(Err(StreamError::incomplete_body().with_bytes_before_error(this.observed)));
                }
                Poll::Ready(Ok(PayloadRead::Eof { trailers }))
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        let caps = self.inner.caps() | PayloadCaps::PUSH;
        if self.declared.is_some() {
            caps | PayloadCaps::KNOWN_LENGTH
        } else {
            caps & !PayloadCaps::KNOWN_LENGTH
        }
    }

    fn len_hint(&self) -> Option<u64> {
        self.remaining_length().get()
    }
}

impl core::fmt::Debug for ByteStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ByteStream")
            .field("declared", &self.declared)
            .field("observed", &self.observed)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}
