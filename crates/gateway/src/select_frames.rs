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

//! A select answer framed from a record source one message at a time.
//!
//! Responsible for: turning a [`ByteStream`] of result bytes into the event stream a select
//! response carries — `Records` frames no larger than [`MAX_PAYLOAD_BYTES`], then the
//! accounting and the terminator, or an error frame if the source fails — while holding at most
//! one source chunk and one frame at a time.
//! NOT responsible for: producing records, evaluating a query, or choosing chunk sizes for the
//! source; nor for putting frames on a socket.
//! Upstream: a backend's record producer, and the core `event_stream` framing it drives.
//! Downstream: [`crate::Resp::event_stream`].
//!
//! It lives in the facade rather than beside [`EventSequence`] in core because it is a response
//! body adapter, not framing: it owns a pinned stream, and core keeps its one pinned future per
//! request.

use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::task::{Context, Poll};

use bytes::Bytes;
use rustfs_gateway_stream::{ByteStream, PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders};

use rustfs_gateway_core::ops::shared::event_stream::{
    EventSequence, EventStreamError, MAX_PAYLOAD_BYTES, encode_exception, stats_document,
};

/// The error code sent in-band when the record source fails after the `200` has gone out.
const SOURCE_FAILED_CODE: &str = "InternalError";
/// A constant message: the source's own error may carry backend detail and never reaches the wire.
const SOURCE_FAILED_MESSAGE: &str = "the select result could not be produced";

/// Frames `records` lazily into a complete select event stream.
///
/// Each read of the returned stream yields exactly one message. Source bytes become `Records`
/// frames of at most [`MAX_PAYLOAD_BYTES`], in order; a source chunk larger than that is split
/// without being copied first. When the source ends, one `Stats` frame reports the number of
/// record bytes for all three counters, and `End` follows. When the source fails, one error frame
/// with a constant code and message ends the stream and no `End` is sent.
///
/// Memory: the adapter holds the source chunk it is splitting and the one frame it is writing,
/// never the answer, so the resident cost is bounded by the source's chunk size and the frame
/// ceiling rather than by the size of the result.
///
/// A producer that needs `Progress`, `Cont`, or its own scan accounting frames with
/// [`EventSequence`] directly.
#[must_use]
pub fn frame_records(records: ByteStream) -> ByteStream {
    let framed: rustfs_gateway_stream::BoxPayloadStream = Box::pin(FramedRecords {
        source: records,
        sequence: ManuallyDrop::new(EventSequence::new()),
        pending: Bytes::new(),
        returned: 0,
        stage: Stage::Records,
    });
    match ByteStream::new(framed) {
        Ok(stream) => stream,
        // `FramedRecords` reports `PUSH` with no length, which `validate_caps` always accepts; a
        // refusal here would be a stream-crate contract change, answered with an in-band error.
        Err(_) => ByteStream::from_bytes(Bytes::from(source_failed_frame())),
    }
}

/// The complete error frame for a source failure, outside any sequence.
fn source_failed_frame() -> Vec<u8> {
    let mut out = Vec::new();
    // The code and message are short constants, so the header ceilings cannot refuse them.
    let _ = encode_exception(SOURCE_FAILED_CODE, SOURCE_FAILED_MESSAGE, &mut out);
    out
}

/// Where the adapter is between the source and the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Records are still being framed.
    Records,
    /// The accounting has been yielded; the terminator is next.
    Terminate,
    /// The terminating frame has been yielded; only end-of-stream is left.
    Done,
}

struct FramedRecords {
    source: ByteStream,
    /// Held without drop glue: a consumer that stops reading — a client that disconnects — drops
    /// the adapter mid-stream legitimately, and that is not the producer bug the sequence's
    /// unterminated-drop assertion exists to catch. The sequence owns no heap memory.
    sequence: ManuallyDrop<EventSequence>,
    /// The unframed remainder of the current source chunk.
    pending: Bytes,
    /// Record bytes taken from the source so far.
    returned: u64,
    stage: Stage,
}

impl FramedRecords {
    fn frame(&mut self, write: impl FnOnce(&mut EventSequence, &mut Vec<u8>) -> Result<(), EventStreamError>) -> Bytes {
        let mut out = Vec::new();
        if write(&mut self.sequence, &mut out).is_err() {
            // Every call below is legal in the phase it is made from and within every ceiling, so
            // this is unreachable; if it ever is reached, the client is still told and not hung.
            out.clear();
            let _ = self.sequence.exception(SOURCE_FAILED_CODE, SOURCE_FAILED_MESSAGE, &mut out);
            self.stage = Stage::Done;
        }
        Bytes::from(out)
    }
}

impl PayloadStream for FramedRecords {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        loop {
            match this.stage {
                Stage::Done => {
                    return Poll::Ready(Ok(PayloadRead::Eof {
                        trailers: TrailingHeaders::empty(),
                    }));
                }
                Stage::Terminate => {
                    this.stage = Stage::Done;
                    return Poll::Ready(Ok(PayloadRead::Chunk(this.frame(|sequence, out| sequence.end(out)))));
                }
                Stage::Records => {}
            }
            if !this.pending.is_empty() {
                let take = this.pending.len().min(MAX_PAYLOAD_BYTES);
                let chunk = this.pending.split_to(take);
                return Poll::Ready(Ok(PayloadRead::Chunk(this.frame(|sequence, out| sequence.records(&chunk, out)))));
            }
            match Pin::new(&mut this.source).poll_read(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => {
                    this.returned = this.returned.saturating_add(chunk.len() as u64);
                    this.pending = chunk;
                }
                Poll::Ready(Ok(PayloadRead::Eof { .. })) => {
                    let returned = this.returned;
                    this.stage = Stage::Terminate;
                    let frame = this.frame(|sequence, out| sequence.stats(&stats_document(returned, returned, returned), out));
                    return Poll::Ready(Ok(PayloadRead::Chunk(frame)));
                }
                Poll::Ready(Err(_)) => {
                    this.stage = Stage::Done;
                    let frame = this.frame(|sequence, out| sequence.exception(SOURCE_FAILED_CODE, SOURCE_FAILED_MESSAGE, out));
                    return Poll::Ready(Ok(PayloadRead::Chunk(frame)));
                }
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}
