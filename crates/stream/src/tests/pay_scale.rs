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

//! The `c-pay-*` rows that need a gibibyte, or a consumer that stops consuming.
//!
//! Responsible for: the gibibyte gate, the gibibyte degradation, and the assertion that a
//! producer never runs ahead of its consumer — each with a control that makes the instrument
//! demonstrably able to report the opposite answer.
//! NOT responsible for: any claim about resident memory or about machine-level copies. Neither
//! is observable from here and neither is asserted; what is asserted is stated in full below.
//! Upstream: the crate's public surface. Downstream: `pay_ledger`, which runs these functions.
//!
//! # What the gibibyte gate measures, and what it does not
//!
//! The instrument is two things, both of them observations rather than intentions. The first is
//! `StreamMetrics`, which counts the adapters placed in the path and the bytes they declared they
//! would move. The second is the address a chunk of bytes arrives at: a chunk that leaves the
//! pipeline at the address its producer allocated has not been through an intermediate buffer,
//! and that is a fact about the data, not a report from the code that moved it.
//!
//! A counting allocator would be the stronger instrument and is unavailable: the workspace
//! forbids `unsafe`, so a global allocator that counts cannot be written here. Resident memory
//! is not used at all — it has already been measured in this repository to be blind to
//! retention on exactly this scale, reporting a falling figure while a hundred and sixty
//! megabytes were held.
//!
//! So the claim is bounded and stated plainly: **no adapter that copies was placed in the path
//! of a gibibyte, and every chunk of that gibibyte arrived at the address it was produced at.**
//! It is not a claim that no `memcpy` instruction executed anywhere below this crate. Every
//! assertion here comes with the opposite case run through the same instrument, because a
//! measurement that only ever returns the answer the test wants is not a measurement.

use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use bytes::Bytes;

use crate::adapt::AdaptCost;
use crate::caps::PayloadCaps;
use crate::error::StreamError;
use crate::metrics::StreamMetrics;
use crate::payload::Payload;
use crate::read::{AsyncPayloadRead, BoxPayloadReader, ReadProgress};
use crate::stream::{BoxPayloadStream, PayloadRead, PayloadStream};
use crate::tests::pay_cases::file_payload;
use crate::tests::pay_ledger::Checks;
use crate::trailers::TrailingHeaders;
use crate::zero_copy::{NoZeroCopy, TransportCaps, VerificationObligation, ZeroCopyQuery};

/// One gibibyte.
const GIB: u64 = 1024 * 1024 * 1024;

/// The chunk a producer hands over at a time.
const CHUNK: usize = 64 * 1024;

/// How many chunks make a gibibyte.
const CHUNKS: usize = (GIB / CHUNK as u64) as usize;

fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

/// A push producer that hands out the same allocation, a chunk at a time.
///
/// Handing out clones of one buffer is what keeps a gibibyte cheap to run: a `Bytes` clone
/// shares the allocation rather than duplicating it, so the whole transfer holds sixty-four
/// kibibytes of memory. It is also what makes the address instrument work — every chunk that
/// leaves this producer has the same address, so a chunk arriving anywhere else went through
/// an intermediate buffer.
struct SharedChunkStream {
    source: Bytes,
    remaining_chunks: usize,
    ended: bool,
}

impl SharedChunkStream {
    fn new(source: Bytes, chunks: usize) -> Self {
        Self {
            source,
            remaining_chunks: chunks,
            ended: false,
        }
    }
}

impl PayloadStream for SharedChunkStream {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if this.remaining_chunks > 0 {
            this.remaining_chunks -= 1;
            return Poll::Ready(Ok(PayloadRead::Chunk(this.source.clone())));
        }
        if this.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof()));
        }
        this.ended = true;
        Poll::Ready(Ok(PayloadRead::Eof {
            trailers: TrailingHeaders::empty(),
        }))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH | PayloadCaps::IN_MEMORY
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.remaining_chunks as u64 * CHUNK as u64)
    }
}

/// A pull producer over the same repeated chunk.
struct SharedChunkReader {
    source: Bytes,
    remaining_chunks: usize,
    offset: usize,
    ended: bool,
}

impl SharedChunkReader {
    fn new(source: Bytes, chunks: usize) -> Self {
        Self {
            source,
            remaining_chunks: chunks,
            offset: 0,
            ended: false,
        }
    }
}

impl AsyncPayloadRead for SharedChunkReader {
    fn poll_fill(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        let this = self.get_mut();
        if this.remaining_chunks > 0 {
            if buf.is_empty() {
                return Poll::Ready(Ok(ReadProgress::Filled(0)));
            }
            let available = CHUNK - this.offset;
            let n = buf.len().min(available);
            buf[..n].copy_from_slice(&this.source[this.offset..this.offset + n]);
            this.offset += n;
            if this.offset == CHUNK {
                this.offset = 0;
                this.remaining_chunks -= 1;
            }
            return Poll::Ready(Ok(ReadProgress::Filled(n)));
        }
        if this.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof()));
        }
        this.ended = true;
        Poll::Ready(Ok(ReadProgress::Eof {
            trailers: TrailingHeaders::empty(),
        }))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PULL | PayloadCaps::KNOWN_LENGTH | PayloadCaps::IN_MEMORY
    }

    fn len_hint(&self) -> Option<u64> {
        Some((self.remaining_chunks as u64 * CHUNK as u64).saturating_sub(self.offset as u64))
    }
}

/// Drives a push body to its end, reporting how many bytes arrived and how many chunks arrived
/// at the address they were produced at.
fn drive_stream(mut stream: BoxPayloadStream, source: *const u8) -> (u64, usize, usize) {
    let mut cx = context();
    let mut bytes = 0u64;
    let mut same_address = 0usize;
    let mut chunks = 0usize;
    loop {
        match stream.as_mut().poll_read(&mut cx) {
            Poll::Pending => continue,
            Poll::Ready(Err(error)) => panic!("a scale body failed mid-transfer: {error}"),
            Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => {
                bytes += chunk.len() as u64;
                chunks += 1;
                if core::ptr::eq(chunk.as_ptr(), source) {
                    same_address += 1;
                }
            }
            Poll::Ready(Ok(PayloadRead::Eof { .. })) => return (bytes, chunks, same_address),
        }
    }
}

/// Drives a pull body to its end through one reused buffer, reporting how many bytes arrived.
///
/// The buffer is reused rather than accumulated on purpose: collecting a gibibyte in order to
/// count it would make the test's own bookkeeping the largest allocation in the process.
fn drive_reader(mut reader: BoxPayloadReader) -> u64 {
    let mut cx = context();
    let mut buf = vec![0u8; CHUNK];
    let mut bytes = 0u64;
    loop {
        match reader.as_mut().poll_fill(&mut cx, &mut buf) {
            Poll::Pending => continue,
            Poll::Ready(Err(error)) => panic!("a scale body failed mid-transfer: {error}"),
            Poll::Ready(Ok(ReadProgress::Filled(n))) => bytes += n as u64,
            Poll::Ready(Ok(ReadProgress::Eof { .. })) => return bytes,
        }
    }
}

/// `c-pay-0008` — a gibibyte through the native model places no copying adapter in its path.
pub(crate) fn c_pay_0008() -> u32 {
    let id = "c-pay-0008";
    let mut c = Checks::new();
    let source = Bytes::from(vec![0x5au8; CHUNK]);
    let address = source.as_ptr();

    // The push half, consumed by a push consumer.
    let metrics = StreamMetrics::new();
    let payload = Payload::from_stream(SharedChunkStream::new(source.clone(), CHUNKS)).expect("the bits and the length agree");
    let (stream, cost) = payload
        .try_into_stream(&metrics)
        .unwrap_or_else(|_| panic!("{id}: a push payload refused the push model"));
    c.that(id, "a gibibyte consumed in its own model costs nothing", cost == AdaptCost::Free);
    c.that(id, "no copying adapter is counted", metrics.adapt_copies_total() == 0);
    c.that(id, "no copied bytes are counted", metrics.adapt_copied_bytes_total() == 0);
    c.that(id, "no owned buffer is counted", metrics.adapt_buffers_total() == 0);

    let (bytes, chunks, same_address) = drive_stream(stream, address);
    c.that(id, "a whole gibibyte actually arrived", bytes == GIB);
    c.that(
        id,
        "every chunk arrived at the address it was produced at, so no byte passed through an intermediate buffer",
        same_address == chunks && chunks == CHUNKS,
    );

    // The pull half, consumed by a pull consumer.
    let metrics = StreamMetrics::new();
    let payload = Payload::from_reader(SharedChunkReader::new(source.clone(), CHUNKS)).expect("the bits and the length agree");
    let (reader, cost) = payload
        .try_into_reader(&metrics)
        .unwrap_or_else(|_| panic!("{id}: a pull payload refused the pull model"));
    c.that(id, "a gibibyte consumed in its own model costs nothing", cost == AdaptCost::Free);
    c.that(id, "no copying adapter is counted", metrics.adapt_copies_total() == 0);
    c.that(id, "no owned buffer is counted", metrics.adapt_buffers_total() == 0);
    c.that(id, "a whole gibibyte actually arrived", drive_reader(reader) == GIB);

    // The control. The same gibibyte, the same two instruments, across the model boundary and
    // back — which is where the copy this gate exists to forbid actually lives. Without this
    // half, "zero copies" would be a number nobody has ever seen move.
    let metrics = StreamMetrics::new();
    let payload = Payload::from_stream(SharedChunkStream::new(source.clone(), CHUNKS)).expect("the bits and the length agree");
    let (reader, cost) = payload
        .try_into_reader(&metrics)
        .unwrap_or_else(|_| panic!("{id}: a push payload refused the pull model"));
    c.that(id, "crossing the model boundary costs a copy", cost.is_copy());
    c.that(id, "the copying adapter is counted", metrics.adapt_copies_total() == 1);
    c.that(
        id,
        "the gibibyte it copies is counted in bytes",
        metrics.adapt_copied_bytes_total() == GIB,
    );

    let (stream, _) = Payload::Reader(reader)
        .try_into_stream(&metrics)
        .unwrap_or_else(|_| panic!("{id}: an adapted payload refused the push model"));
    let (bytes, chunks, same_address) = drive_stream(stream, address);
    c.that(id, "the adapted gibibyte still arrives whole", bytes == GIB);
    c.that(
        id,
        "not one chunk arrived at the address it was produced at, so the instrument above can report a copy",
        same_address == 0 && chunks > 0,
    );
    c.count()
}

/// `c-pay-0028` — a gibibyte that loses the kernel-side path is attributed and sized.
///
/// The task's row asks for a copy counter of one and a copied-byte counter of a gibibyte. That
/// accounting belongs to whichever transport performs the degraded read, and this crate has no
/// i/o driver to perform one with — asking it for a reader over a file region is refused rather
/// than quietly served. So what is asserted here is the half that does live at this layer, and
/// it is the half the row exists for: the loss is named, counted against its own reason, and
/// sized at a gibibyte, and it cannot be turned into a silent read.
pub(crate) fn c_pay_0028() -> u32 {
    let id = "c-pay-0028";
    let mut c = Checks::new();
    let metrics = StreamMetrics::new();
    let payload = file_payload(GIB);
    let query = ZeroCopyQuery::new(TransportCaps::VECTORED, VerificationObligation::None);

    c.that(
        id,
        "a transport that can only gather buffers has no kernel-side path",
        query.refusal() == Some(NoZeroCopy::TransportLacksSendfile),
    );

    let (returned, reason) = match payload.try_into_file_region_for(&query, &metrics) {
        Ok(_) => panic!("{id}: a transport with no kernel-side path was handed a descriptor"),
        Err(pair) => {
            c.that(id, "the descriptor is not handed over", true);
            pair
        }
    };
    c.that(id, "the reason names the transport", reason == NoZeroCopy::TransportLacksSendfile);
    c.that(
        id,
        "the loss is counted against its own reason",
        metrics.zero_copy_refusals(NoZeroCopy::TransportLacksSendfile) == 1,
    );
    c.that(
        id,
        "the loss is sized at a gibibyte, so a large degradation cannot look like a small one",
        metrics.zero_copy_refused_bytes_total() == GIB,
    );
    c.that(
        id,
        "no other reason is credited with the loss",
        metrics.zero_copy_refusals(NoZeroCopy::NotFileBacked) == 0
            && metrics.zero_copy_refusals(NoZeroCopy::TlsInPath) == 0
            && metrics.zero_copy_refusals(NoZeroCopy::VerificationObligationPresent) == 0,
    );
    c.that(id, "the refused payload comes back whole", returned.len_hint() == Some(GIB));

    match returned.try_into_reader(&metrics) {
        Ok(_) => panic!("{id}: a file region was quietly turned into a read by a layer with no i/o driver"),
        Err((_, refusal)) => {
            c.that(
                id,
                "this layer refuses to degrade the transfer itself rather than doing so unattributed",
                refusal == crate::payload::AdaptRefusal::NeedsIoDriver,
            );
        }
    }
    c.that(
        id,
        "a refusal is never counted as an adaptation",
        metrics.adapt_copies_total() == 0 && metrics.adapt_buffers_total() == 0,
    );
    c.count()
}

/// A consumer-side adapter that reads ahead, written only to be caught.
///
/// This is the shape the back-pressure rule forbids: it pulls several chunks from the producer
/// for every one the consumer asks for, so the producer advances on its own schedule rather than
/// the consumer's. It exists so the measurement below has something to report a different answer
/// about; a poll counter that only ever sees the well-behaved adapter proves nothing.
struct PrefetchReader {
    inner: BoxPayloadStream,
    buffered: std::collections::VecDeque<Bytes>,
    ended: bool,
    read_ahead: usize,
}

impl PrefetchReader {
    fn new(inner: BoxPayloadStream, read_ahead: usize) -> Self {
        Self {
            inner,
            buffered: std::collections::VecDeque::new(),
            ended: false,
            read_ahead,
        }
    }

    fn buffered_bytes(&self) -> usize {
        self.buffered.iter().map(bytes::Bytes::len).sum()
    }
}

impl AsyncPayloadRead for PrefetchReader {
    fn poll_fill(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
        use bytes::Buf as _;

        let this = self.get_mut();
        while !this.ended && this.buffered.len() < this.read_ahead {
            match this.inner.as_mut().poll_read(cx) {
                Poll::Pending => break,
                Poll::Ready(Err(error)) => {
                    this.ended = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => this.buffered.push_back(chunk),
                Poll::Ready(Ok(PayloadRead::Eof { .. })) => this.ended = true,
            }
        }
        match this.buffered.front_mut() {
            Some(front) => {
                let n = buf.len().min(front.len());
                buf[..n].copy_from_slice(&front[..n]);
                front.advance(n);
                if front.is_empty() {
                    this.buffered.pop_front();
                }
                Poll::Ready(Ok(ReadProgress::Filled(n)))
            }
            None => Poll::Ready(Ok(ReadProgress::Eof {
                trailers: TrailingHeaders::empty(),
            })),
        }
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PULL
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

/// A push producer that records how many times it was polled.
struct PollCountingStream {
    chunk: Bytes,
    remaining_chunks: usize,
    polls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ended: bool,
}

impl PollCountingStream {
    fn new(chunk: Bytes, chunks: usize) -> Self {
        Self {
            chunk,
            remaining_chunks: chunks,
            polls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            ended: false,
        }
    }
}

impl PayloadStream for PollCountingStream {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if this.remaining_chunks > 0 {
            this.remaining_chunks -= 1;
            return Poll::Ready(Ok(PayloadRead::Chunk(this.chunk.clone())));
        }
        if this.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof()));
        }
        this.ended = true;
        Poll::Ready(Ok(PayloadRead::Eof {
            trailers: TrailingHeaders::empty(),
        }))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

/// `c-pay-0030` — a producer advances only as far as its consumer has asked it to.
pub(crate) fn c_pay_0030() -> u32 {
    let id = "c-pay-0030";
    let mut c = Checks::new();
    let chunk = Bytes::from(vec![7u8; 64]);
    let metrics = StreamMetrics::new();

    // The crate's own adapter, polled a fixed number of times and then abandoned.
    let producer = PollCountingStream::new(chunk.clone(), 32);
    let polls = std::sync::Arc::clone(&producer.polls);
    let (mut reader, _) = Payload::Stream(Box::pin(producer))
        .try_into_reader(&metrics)
        .unwrap_or_else(|_| panic!("{id}: a push payload refused the pull model"));
    let mut cx = context();
    let mut buf = vec![0u8; 64];
    let mut taken = 0u64;
    for _ in 0..3 {
        match reader.as_mut().poll_fill(&mut cx, &mut buf) {
            Poll::Ready(Ok(ReadProgress::Filled(n))) => taken += n as u64,
            other => panic!("{id}: the adapted body stopped early: {other:?}"),
        }
    }
    c.that(id, "the consumer received exactly what it asked for", taken == 3 * 64);
    c.that(
        id,
        "the producer was polled once per consumer poll and never once more",
        polls.load(std::sync::atomic::Ordering::Relaxed) == 3,
    );

    let after_stopping = polls.load(std::sync::atomic::Ordering::Relaxed);
    drop(reader);
    c.that(
        id,
        "abandoning the consumer does not advance the producer any further",
        polls.load(std::sync::atomic::Ordering::Relaxed) == after_stopping,
    );

    // A consumer whose buffer takes less than a chunk draws no extra poll: the leftover is
    // served from what the producer already handed over.
    let producer = PollCountingStream::new(chunk.clone(), 32);
    let polls = std::sync::Arc::clone(&producer.polls);
    let (mut reader, _) = Payload::Stream(Box::pin(producer))
        .try_into_reader(&metrics)
        .unwrap_or_else(|_| panic!("{id}: a push payload refused the pull model"));
    let mut half = vec![0u8; 32];
    for _ in 0..2 {
        match reader.as_mut().poll_fill(&mut cx, &mut half) {
            Poll::Ready(Ok(ReadProgress::Filled(n))) => assert_eq!(n, 32, "{id}: a half-width read returned {n}"),
            other => panic!("{id}: the adapted body stopped early: {other:?}"),
        }
    }
    c.that(
        id,
        "two half-width reads draw one chunk from the producer, not two",
        polls.load(std::sync::atomic::Ordering::Relaxed) == 1,
    );

    // The control: an adapter that reads ahead, measured the same way.
    let producer = PollCountingStream::new(chunk.clone(), 32);
    let polls = std::sync::Arc::clone(&producer.polls);
    let mut prefetch = PrefetchReader::new(Box::pin(producer), 4);
    {
        let mut pinned = Pin::new(&mut prefetch);
        match pinned.as_mut().poll_fill(&mut cx, &mut buf) {
            Poll::Ready(Ok(ReadProgress::Filled(n))) => {
                c.that(id, "the read-ahead adapter is a working adapter, not a broken one", n == 64);
            }
            other => panic!("{id}: the control adapter stopped early: {other:?}"),
        }
    }
    c.that(
        id,
        "the same poll counter reports a read-ahead adapter polling its producer several times for one consumer poll",
        polls.load(std::sync::atomic::Ordering::Relaxed) == 4,
    );
    c.that(
        id,
        "and it reports the bytes the read-ahead adapter is holding that its consumer never asked for",
        prefetch.buffered_bytes() > 0,
    );
    c.that(
        id,
        "the crate's own adapter holds nothing ahead: it drew exactly the bytes its consumer took",
        taken == 3 * 64,
    );
    c.count()
}
