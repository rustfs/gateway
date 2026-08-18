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

//! The payload itself: one named variant per shape a body can have.
//!
//! Responsible for: the `Payload` enum, its capability bits, and the explicit negotiation a
//! transport uses to reach a faster path — `try_into_file_region`, `try_as_vectored`,
//! `try_into_reader`, `try_into_stream`. Every one of them either succeeds or hands the payload
//! back unchanged with a named reason, so a lost fast path is visible instead of silent.
//! NOT responsible for: performing a transfer, decoding framing, or any protocol meaning of the
//! bytes. A payload is bytes and the ways to get at them, nothing else.
//! Upstream: `bytes`, plus this crate's `adapt`, `caps`, `read`, `stream` and `metrics`.
//! Downstream: `body`, `byte_stream`, and the wire and transport layers.

use core::fmt;

use bytes::Bytes;

use crate::adapt::{AdaptCost, MemoryReader, MemoryStream, ReaderToStream, StreamToReader};
use crate::caps::{CapsInconsistency, PayloadCaps, validate_caps};
use crate::metrics::StreamMetrics;
use crate::read::{AsyncPayloadRead, BoxPayloadReader};
use crate::stream::{BoxPayloadStream, PayloadStream};
use crate::trailers::TrailingHeaders;

#[cfg(unix)]
use crate::file_region::FileRegion;
#[cfg(unix)]
use crate::zero_copy::{NoZeroCopy, ZeroCopyQuery};

/// A body, in whichever shape its producer had it.
///
/// The variants are named capabilities. There is deliberately no `as_any()` and no downcast:
/// a downcast is a negotiation with no contract, so when it stops matching, the fast path is
/// lost with no compile error and no counter, and it also lets a transport pull the inner
/// payload out of a wrapper that was there to validate the bytes.
#[derive(Default)]
pub enum Payload {
    /// No body at all.
    #[default]
    Empty,
    /// One run of bytes already in memory.
    Bytes(Bytes),
    /// Several runs of bytes already in memory, writable in one vectored call.
    Vectored(Vec<Bytes>),
    /// A range of a file, which a kernel-side transfer can send without a user-space copy.
    #[cfg(unix)]
    File(FileRegion),
    /// A pull-model body: the consumer supplies the buffer.
    Reader(BoxPayloadReader),
    /// A push-model body: the producer supplies the buffer.
    Stream(BoxPayloadStream),
}

/// A `Payload` is moved through every stage of the data plane — wire, ingest, handler, response
/// — and is stored inside request and response types that are themselves moved. Sixty-four bytes
/// is one cache line: past it, each of those moves starts costing a second line's worth of
/// traffic, on a type whose whole reason to exist is to stop copying.
///
/// The budget is a compile-time assertion rather than a comment because the way it gets blown is
/// invisible in review. Replacing `Vectored(Vec<Bytes>)` with an inline `SmallVec<[Bytes; 4]>`
/// reads as a pure win — it removes a heap allocation for the common case of at most four
/// segments — and it takes the enum to 136 bytes, because the four `Bytes` are stored inline in
/// every `Payload` ever constructed, including the `Empty` ones. The trade is real and may still
/// be worth making, but it must be made deliberately, against a measurement, not arrived at.
const _: () = assert!(size_of::<Payload>() <= 64);

/// Why a payload could not be converted into the requested model.
///
/// Named and exhaustible, so a caller can log or count the reason. This is the shape that
/// replaces "the downcast returned `None`", which carried no reason at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptRefusal {
    /// The payload is a file region: turning it into a byte stream needs an i/o driver, which
    /// this crate does not own. Consume it with [`Payload::try_into_file_region`], or convert
    /// it in the layer that has a driver.
    NeedsIoDriver,
}

impl fmt::Display for AdaptRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedsIoDriver => f.write_str("payload can only be read by a layer that owns an i/o driver"),
        }
    }
}

impl std::error::Error for AdaptRefusal {}

impl Payload {
    /// Builds an in-memory payload, normalising an empty input to [`Payload::Empty`].
    #[must_use]
    pub fn from_bytes(bytes: Bytes) -> Self {
        if bytes.is_empty() { Self::Empty } else { Self::Bytes(bytes) }
    }

    /// Builds an in-memory payload from segments, dropping the empty ones.
    #[must_use]
    pub fn from_segments(segments: impl IntoIterator<Item = Bytes>) -> Self {
        let mut segments: Vec<Bytes> = segments.into_iter().filter(|s| !s.is_empty()).collect();
        match segments.len() {
            0 => Self::Empty,
            1 => Self::Bytes(segments.remove(0)),
            _ => Self::Vectored(segments),
        }
    }

    /// Boxes a push-model producer, checking that its declared capabilities are self-consistent.
    pub fn from_stream<S>(stream: S) -> Result<Self, CapsInconsistency>
    where
        S: PayloadStream + Send + 'static,
    {
        validate_caps(stream.caps(), stream.len_hint())?;
        Ok(Self::Stream(Box::pin(stream)))
    }

    /// Boxes a pull-model producer, checking that its declared capabilities are self-consistent.
    pub fn from_reader<R>(reader: R) -> Result<Self, CapsInconsistency>
    where
        R: AsyncPayloadRead + Send + 'static,
    {
        validate_caps(reader.caps(), reader.len_hint())?;
        Ok(Self::Reader(Box::pin(reader)))
    }

    /// What this payload can do.
    #[must_use]
    pub fn caps(&self) -> PayloadCaps {
        const IN_MEMORY: PayloadCaps = PayloadCaps::KNOWN_LENGTH
            .union(PayloadCaps::SEEKABLE)
            .union(PayloadCaps::REPLAYABLE)
            .union(PayloadCaps::IN_MEMORY)
            .union(PayloadCaps::VECTORED)
            .union(PayloadCaps::PULL)
            .union(PayloadCaps::PUSH);

        match self {
            Self::Empty | Self::Bytes(_) | Self::Vectored(_) => IN_MEMORY,
            #[cfg(unix)]
            Self::File(_) => {
                PayloadCaps::KNOWN_LENGTH | PayloadCaps::SEEKABLE | PayloadCaps::REPLAYABLE | PayloadCaps::FILE_REGION
            }
            Self::Reader(reader) => reader.caps() | PayloadCaps::PULL,
            Self::Stream(stream) => stream.caps() | PayloadCaps::PUSH,
        }
    }

    /// The exact body length, when it is known.
    #[must_use]
    pub fn len_hint(&self) -> Option<u64> {
        match self {
            Self::Empty => Some(0),
            Self::Bytes(bytes) => Some(bytes.len() as u64),
            Self::Vectored(segments) => Some(segments.iter().fold(0u64, |acc, s| acc.saturating_add(s.len() as u64))),
            #[cfg(unix)]
            Self::File(region) => Some(region.len()),
            Self::Reader(reader) => reader.len_hint(),
            Self::Stream(stream) => stream.len_hint(),
        }
    }

    /// Whether this payload is known to carry no bytes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len_hint() == Some(0)
    }

    /// Takes the file region out of the payload, for a transfer that can use one.
    ///
    /// Succeeds only when [`PayloadCaps::FILE_REGION`] is set. On refusal the payload comes
    /// back unchanged, together with the reason: a negotiation that consumed the body on failure
    /// would turn "this transport cannot use a file region" into data loss, and a producer-driven
    /// body cannot be produced a second time. The reason is a named [`NoZeroCopy`] rather than a
    /// bare `None`, because "not a file" and "the transport cannot do it" call for different
    /// actions and a counter that cannot tell them apart is a counter nobody acts on.
    ///
    /// This is the payload-only form: it can only ever refuse with [`NoZeroCopy::NotFileBacked`].
    /// A transport must use [`Payload::try_into_file_region_for`], which also sees the
    /// transport's capabilities and the body's outstanding verification obligation.
    ///
    /// # Errors
    ///
    /// [`NoZeroCopy::NotFileBacked`] when the payload is any other variant.
    #[cfg(unix)]
    pub fn try_into_file_region(self) -> Result<FileRegion, (Self, NoZeroCopy)> {
        match self {
            Self::File(region) => Ok(region),
            other => Err((other, NoZeroCopy::NotFileBacked)),
        }
    }

    /// Takes the file region out of the payload for a specific transport, recording a refusal.
    ///
    /// The query is checked before the payload's own shape. That order is the security order: a
    /// body carrying a [`VerificationObligation::Present`] is refused as such even when it also
    /// happens not to be a file, so the log never says "not file backed" about a body that would
    /// have been refused anyway for the reason that matters.
    ///
    /// # Errors
    ///
    /// One of the four [`NoZeroCopy`] reasons, together with the unchanged payload.
    ///
    /// [`VerificationObligation::Present`]: crate::VerificationObligation::Present
    #[cfg(unix)]
    pub fn try_into_file_region_for(
        self,
        query: &ZeroCopyQuery,
        metrics: &StreamMetrics,
    ) -> Result<FileRegion, (Self, NoZeroCopy)> {
        if let Some(reason) = query.refusal() {
            metrics.record_zero_copy_refusal(reason, self.len_hint());
            return Err((self, reason));
        }
        match self {
            Self::File(region) => Ok(region),
            other => {
                metrics.record_zero_copy_refusal(NoZeroCopy::NotFileBacked, other.len_hint());
                Err((other, NoZeroCopy::NotFileBacked))
            }
        }
    }

    /// Borrows the payload as a segment slice, for one vectored write.
    ///
    /// Returns `None` for the two producer-driven variants, whose bytes do not exist yet.
    #[must_use]
    pub fn try_as_vectored(&self) -> Option<&[Bytes]> {
        match self {
            Self::Empty => Some(&[]),
            Self::Bytes(bytes) => Some(core::slice::from_ref(bytes)),
            Self::Vectored(segments) => Some(segments),
            #[cfg(unix)]
            Self::File(_) => None,
            Self::Reader(_) | Self::Stream(_) => None,
        }
    }

    /// Converts the payload into the pull model, recording what the conversion costs.
    ///
    /// The metrics handle is a required argument, not an option: an adaptation whose cost is
    /// not counted anywhere is exactly the regression this crate is meant to make visible.
    pub fn try_into_reader(self, metrics: &StreamMetrics) -> Result<(BoxPayloadReader, AdaptCost), (Self, AdaptRefusal)> {
        let (reader, cost): (BoxPayloadReader, AdaptCost) = match self {
            Self::Empty => (Box::pin(MemoryReader::new([], TrailingHeaders::empty())), AdaptCost::Free),
            Self::Bytes(bytes) => (Box::pin(MemoryReader::new([bytes], TrailingHeaders::empty())), AdaptCost::Free),
            Self::Vectored(segments) => (Box::pin(MemoryReader::new(segments, TrailingHeaders::empty())), AdaptCost::Free),
            #[cfg(unix)]
            Self::File(region) => {
                return Err((Self::File(region), AdaptRefusal::NeedsIoDriver));
            }
            Self::Reader(reader) => (reader, AdaptCost::Free),
            Self::Stream(stream) => {
                let adapter = StreamToReader::new(stream);
                let cost = crate::adapt::Adapt::adapt_cost(&adapter);
                (Box::pin(adapter), cost)
            }
        };
        metrics.record_adapt(&cost);
        Ok((reader, cost))
    }

    /// Converts the payload into the push model, recording what the conversion costs.
    pub fn try_into_stream(self, metrics: &StreamMetrics) -> Result<(BoxPayloadStream, AdaptCost), (Self, AdaptRefusal)> {
        let (stream, cost): (BoxPayloadStream, AdaptCost) = match self {
            Self::Empty => (Box::pin(MemoryStream::new([], TrailingHeaders::empty())), AdaptCost::Free),
            Self::Bytes(bytes) => (Box::pin(MemoryStream::new([bytes], TrailingHeaders::empty())), AdaptCost::Free),
            Self::Vectored(segments) => (Box::pin(MemoryStream::new(segments, TrailingHeaders::empty())), AdaptCost::Free),
            #[cfg(unix)]
            Self::File(region) => {
                return Err((Self::File(region), AdaptRefusal::NeedsIoDriver));
            }
            Self::Reader(reader) => {
                let adapter = ReaderToStream::new(reader);
                let cost = crate::adapt::Adapt::adapt_cost(&adapter);
                (Box::pin(adapter), cost)
            }
            Self::Stream(stream) => (stream, AdaptCost::Free),
        };
        metrics.record_adapt(&cost);
        Ok((stream, cost))
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Payload::Empty"),
            Self::Bytes(bytes) => write!(f, "Payload::Bytes({} bytes)", bytes.len()),
            Self::Vectored(segments) => write!(f, "Payload::Vectored({} segments)", segments.len()),
            #[cfg(unix)]
            Self::File(region) => write!(f, "Payload::File(offset {}, {} bytes)", region.offset(), region.len()),
            Self::Reader(_) => f.write_str("Payload::Reader(..)"),
            Self::Stream(_) => f.write_str("Payload::Stream(..)"),
        }
    }
}
