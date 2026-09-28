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

//! The one body type a request or a response carries.
//!
//! Responsible for: giving both body shapes — bytes already in hand, and bytes still to come —
//! a single owned type, exposing that type as an `http_body::Body` without flattening in-memory
//! segments, and keeping its verification obligation attached through response-transport
//! negotiation. A pipeline stage can therefore hold a body without a lifetime parameter.
//! That matters beyond tidiness: a stage that borrowed its body would become self-referential the
//! moment it crossed an await point, and pinning it safely is not expressible without `unsafe`.
//! NOT responsible for: shape-level capability rules, which belong to the payload it wraps, or any
//! protocol meaning — a body here has no length header, no digest and no status code.
//! Upstream: `bytes`, plus this crate's `payload`, `caps` and zero-copy refusal types. Downstream:
//! `rustfs-gateway-types`, `rustfs-gateway-http`, and the gateway response transport that consumes
//! the opaque `BodyTransport` typestate.

use bytes::Bytes;
use http_body::{Frame, SizeHint};
use std::sync::Arc;
#[cfg(unix)]
use std::{fs::File, io, os::unix::fs::FileExt};

use crate::caps::{CapsInconsistency, PayloadCaps};
use crate::error::StreamError;
use crate::metrics::StreamMetrics;
use crate::payload::Payload;
use crate::read::AsyncPayloadRead;
use crate::stream::{PayloadRead, PayloadStream};
use crate::zero_copy::VerificationObligation;
#[cfg(unix)]
use crate::zero_copy::{NoZeroCopy, TransportCaps, ZeroCopyQuery};

#[cfg(unix)]
use crate::file_region::FileRegion;

/// A request or response body.
///
/// A thin owned wrapper over [`Payload`]. It exists so that the layers above have one name for
/// "the body", while the capability detail stays in the payload where a transport can negotiate
/// over it.
#[derive(Debug)]
pub struct Body {
    payload: Payload,
    metrics: Arc<StreamMetrics>,
    verification_obligation: VerificationObligation,
    ended: bool,
}

/// A body whose complete safety state is owned by a response transport.
///
/// The fields are intentionally opaque: transports negotiate through this type instead of
/// decomposing a body into independently discardable values.
#[derive(Debug)]
pub struct BodyTransport {
    body: Body,
}

/// A body returned unchanged after the requested kernel-side transfer was refused.
#[cfg(unix)]
#[derive(Debug)]
pub struct RefusedBodyTransport {
    body: Body,
    reason: NoZeroCopy,
}

/// A file region that may only be delivered through a user-space copied path.
#[cfg(unix)]
#[derive(Debug)]
pub struct CopiedFileBody {
    file: File,
    next_offset: u64,
    remaining: u64,
    len: u64,
    metrics: Arc<StreamMetrics>,
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl Body {
    /// A body with no bytes.
    #[must_use]
    pub fn empty() -> Self {
        Self::from_payload(Payload::Empty)
    }

    /// A body whose bytes are already in memory.
    #[must_use]
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self::from_payload(Payload::from_bytes(bytes))
    }

    /// A body assembled from segments that are already in memory.
    #[must_use]
    pub fn from_segments(segments: impl IntoIterator<Item = Bytes>) -> Self {
        Self::from_payload(Payload::from_segments(segments))
    }

    /// A body produced by a push-model producer.
    ///
    /// Returns an error when the producer's capability bits contradict its length hint. The
    /// check happens here, where the producer enters the system, because every consumer
    /// downstream trusts those bits.
    pub fn from_stream<S>(stream: S) -> Result<Self, CapsInconsistency>
    where
        S: PayloadStream + Send + 'static,
    {
        Ok(Self::from_payload(Payload::from_stream(stream)?))
    }

    /// A body produced by a pull-model producer.
    pub fn from_reader<R>(reader: R) -> Result<Self, CapsInconsistency>
    where
        R: AsyncPayloadRead + Send + 'static,
    {
        Ok(Self::from_payload(Payload::from_reader(reader)?))
    }

    /// A body that is a range of a file.
    #[cfg(unix)]
    #[must_use]
    pub fn from_file_region(region: FileRegion) -> Self {
        Self::from_payload(Payload::File(region))
    }

    /// A body over an already built payload.
    #[must_use]
    pub fn from_payload(payload: Payload) -> Self {
        Self::from_payload_with_metrics(payload, Arc::new(StreamMetrics::new()))
    }

    /// A body over an already built payload, recording any pull/push adaptation in `metrics`.
    ///
    /// A server that exports stream metrics keeps a clone of the handle before handing the body
    /// to Hyper. The default constructors create a private handle for callers that do not export
    /// metrics, but adaptation is still counted rather than silently performed.
    #[must_use]
    pub fn from_payload_with_metrics(payload: Payload, metrics: Arc<StreamMetrics>) -> Self {
        Self {
            payload,
            metrics,
            verification_obligation: VerificationObligation::None,
            ended: false,
        }
    }

    /// Carries an outstanding byte-verification obligation to the response transport.
    ///
    /// The value is owned and transport-shaped: it states only whether the bytes may move without
    /// being observed, not why a higher layer requires observation.
    #[must_use]
    pub fn requiring_verification(mut self) -> Self {
        self.verification_obligation = VerificationObligation::Present;
        self
    }

    /// The byte-verification obligation the response transport must honor.
    #[must_use]
    pub fn verification_obligation(&self) -> VerificationObligation {
        self.verification_obligation
    }

    /// Borrows in-memory segments without exposing an owned payload or file descriptor.
    #[must_use]
    pub fn try_as_vectored(&self) -> Option<&[Bytes]> {
        self.payload.try_as_vectored()
    }

    /// The end offset of a file-backed body, without exposing its descriptor.
    #[cfg(unix)]
    #[must_use]
    pub fn file_region_end_offset(&self) -> Option<u64> {
        match &self.payload {
            Payload::File(region) => Some(region.end_offset()),
            _ => None,
        }
    }

    /// The counters this body updates when an HTTP consumer requires a pull/push adaptation.
    #[must_use]
    pub fn stream_metrics(&self) -> &Arc<StreamMetrics> {
        &self.metrics
    }

    /// Moves the complete body into an opaque response-transport negotiation state.
    ///
    /// Payload, metrics and outstanding verification state remain inseparable. A transport must
    /// negotiate through [`BodyTransport`] and cannot accidentally discard one tuple member.
    #[must_use]
    pub fn into_transport(self) -> BodyTransport {
        BodyTransport { body: self }
    }

    /// What this body can do.
    #[must_use]
    pub fn caps(&self) -> PayloadCaps {
        self.payload.caps()
    }

    /// The exact body length, when it is known.
    #[must_use]
    pub fn len_hint(&self) -> Option<u64> {
        self.payload.len_hint()
    }

    /// Whether this body is known to carry no bytes at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

impl BodyTransport {
    /// Attempts a kernel-side file transfer using the obligation owned by this body.
    ///
    /// A refusal returns an opaque state carrying the complete unchanged body and the recorded
    /// reason. A successful result can only contain a file region whose obligation was absent.
    #[cfg(unix)]
    pub fn try_into_file_region_for(self, transport: TransportCaps) -> Result<FileRegion, RefusedBodyTransport> {
        let Body {
            payload,
            metrics,
            verification_obligation,
            ended,
        } = self.body;
        let query = ZeroCopyQuery::new(transport, verification_obligation);
        match payload.try_into_file_region_for(&query, &metrics) {
            Ok(region) => Ok(region),
            Err((payload, reason)) => Err(RefusedBodyTransport {
                body: Body {
                    payload,
                    metrics,
                    verification_obligation,
                    ended,
                },
                reason,
            }),
        }
    }

    /// Takes a file-backed body onto the user-space copied path for a transport that has no
    /// kernel-side one, recording the refusal under `reason` — or under
    /// [`NoZeroCopy::VerificationObligationPresent`] when the body still owes a verification, which
    /// outranks any transport reason.
    ///
    /// A body that is not file-backed is returned unchanged, with nothing recorded: it was never a
    /// candidate for a kernel transfer, and counting it would make every in-memory response look
    /// like a refused one.
    #[cfg(unix)]
    pub fn try_into_copied_file_for(self, reason: NoZeroCopy) -> Result<CopiedFileBody, Body> {
        if !matches!(self.body.payload, Payload::File(_)) {
            return Err(self.body);
        }
        let reason = if self.body.verification_obligation.is_present() {
            NoZeroCopy::VerificationObligationPresent
        } else {
            reason
        };
        self.body
            .metrics
            .record_zero_copy_refusal(reason, self.body.payload.len_hint());
        RefusedBodyTransport { body: self.body, reason }
            .try_into_copied_file()
            .map_err(RefusedBodyTransport::into_body)
    }

    /// Returns the unchanged body for a terminal user-space streaming path.
    #[must_use]
    pub fn into_body(self) -> Body {
        self.body
    }
}

#[cfg(unix)]
impl RefusedBodyTransport {
    /// The observed reason the requested kernel-side path was refused.
    #[must_use]
    pub fn reason(&self) -> NoZeroCopy {
        self.reason
    }

    /// Returns the unchanged body for ordinary user-space streaming.
    #[must_use]
    pub fn into_body(self) -> Body {
        self.body
    }

    /// Extracts a file only after kernel-side transfer was refused.
    ///
    /// Non-file bodies return the same refused state unchanged. The successful value is a
    /// distinct copied-path type so it cannot be confused with a kernel-ready body.
    pub fn try_into_copied_file(self) -> Result<CopiedFileBody, Self> {
        let Self { body, reason } = self;
        let Body {
            payload,
            metrics,
            verification_obligation,
            ended,
        } = body;
        match payload {
            Payload::File(region) => {
                let next_offset = region.offset();
                let len = region.len();
                Ok(CopiedFileBody {
                    file: File::from(region.into_fd()),
                    next_offset,
                    remaining: len,
                    len,
                    metrics,
                })
            }
            payload => Err(Self {
                body: Body {
                    payload,
                    metrics,
                    verification_obligation,
                    ended,
                },
                reason,
            }),
        }
    }
}

#[cfg(unix)]
impl CopiedFileBody {
    /// The original file-region length selected for user-space copying.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether every selected byte has been read through this copied-path state.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining == 0
    }

    /// Records that the terminal response writer entered this copied path.
    pub fn record_copy_adaptation(&self) {
        self.metrics.record_adapt(&crate::adapt::AdaptCost::Copy {
            est_bytes: Some(self.len),
        });
    }

    /// Hands the file, positioned at the next selected byte, and the count still selected to a
    /// transport that reads it on its own asynchronous file reader.
    ///
    /// The value is still a copied-path value: the caller has already been refused the kernel
    /// path and recorded why, so this cannot be mistaken for a kernel-ready region.
    pub fn into_positioned_file(mut self) -> io::Result<(File, u64)> {
        use std::io::{Seek, SeekFrom};
        self.file.seek(SeekFrom::Start(self.next_offset))?;
        Ok((self.file, self.remaining))
    }

    /// Reads the next selected bytes without exposing a file descriptor or kernel-ready region.
    ///
    /// This call may block on file I/O. An asynchronous transport must run it on its blocking-I/O
    /// executor rather than on an event-loop thread.
    pub fn read_blocking(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let wanted = usize::try_from(self.remaining.min(buffer.len() as u64)).map_err(io::Error::other)?;
        if wanted == 0 {
            return Ok(0);
        }
        let destination = buffer
            .get_mut(..wanted)
            .ok_or_else(|| io::Error::other("copied file read exceeds its buffer"))?;
        let read = self.file.read_at(destination, self.next_offset)?;
        let read_u64 = u64::try_from(read).map_err(io::Error::other)?;
        self.next_offset = self
            .next_offset
            .checked_add(read_u64)
            .ok_or_else(|| io::Error::other("copied file offset overflowed"))?;
        self.remaining = self
            .remaining
            .checked_sub(read_u64)
            .ok_or_else(|| io::Error::other("copied file read exceeded the selected region"))?;
        Ok(read)
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = StreamError;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        use core::task::Poll;

        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }

        if !matches!(this.payload, Payload::Stream(_)) {
            let payload = core::mem::take(&mut this.payload);
            match payload.try_into_stream(this.metrics.as_ref()) {
                Ok((stream, _cost)) => this.payload = Payload::Stream(stream),
                Err((_payload, refusal)) => {
                    this.ended = true;
                    return Poll::Ready(Some(Err(StreamError::upstream(Box::new(refusal)))));
                }
            }
        }

        let Payload::Stream(stream) = &mut this.payload else {
            unreachable!("the conversion above either builds a stream or returns an error")
        };
        match stream.as_mut().poll_read(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.ended = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(Ok(PayloadRead::Chunk(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Ok(PayloadRead::Eof { trailers })) => {
                this.ended = true;
                if trailers.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(Frame::trailers(trailers.into_header_map()))))
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended || matches!(self.payload, Payload::Empty)
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        if self.ended {
            hint.set_exact(0);
        } else if let Some(exact) = self.payload.len_hint() {
            hint.set_exact(exact);
        }
        hint
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Self {
        Self::from_bytes(Bytes::from(bytes))
    }
}

impl From<Payload> for Body {
    fn from(payload: Payload) -> Self {
        Self::from_payload(payload)
    }
}
