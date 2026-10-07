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

//! The two bridges to `tokio::io::AsyncRead`, in both directions.
//!
//! Responsible for: proving that `TokioReadPayload` fills the consumer's own buffer and holds a
//! reader to its declared length, that `PayloadReader` serves each chunk out of the producer's
//! buffer and answers with a trailer section only after end-of-stream, that errors cross either
//! bridge unchanged, that neither bridge touches the adaptation counters, and that dropping a
//! bridge drops its source.
//! NOT responsible for: the adapters themselves, or any runtime — every future here is polled by
//! hand with a no-op waker, which is also what proves the adapters need none.
//! Upstream: `tokio_io`, `adapt`, `byte_stream`, `metrics`, and the scripted producers in
//! `support`. Downstream: nothing.

use core::future::Future;
use core::pin::{Pin, pin};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt as _, ReadBuf};

use crate::adapt::{Adapt, AdaptCost, MemoryStream};
use crate::byte_stream::ByteStream;
use crate::caps::{PayloadCaps, validate_caps};
use crate::error::{StreamError, StreamErrorKind};
use crate::metrics::StreamMetrics;
use crate::read::{AsyncPayloadRead, ReadProgress};
use crate::stream::{PayloadRead, PayloadStream};
use crate::tests::support::{ScriptedStream, Step, drain_reader, trailer_value, trailers};
use crate::tokio_io::{PayloadReader, TokioReadPayload};
use crate::trailers::TrailingHeaders;

const MEBIBYTE: usize = 1024 * 1024;
/// A prime buffer size, so fills never line up with chunk or page boundaries.
const ODD_BUFFER: usize = 7919;

fn noop_context() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

/// Drives a future to completion with a no-op waker. Every producer here reports `Pending` a
/// scripted number of times at most, so the loop always ends.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = noop_context();
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

/// Deterministic pseudo-random bytes (xorshift64*), so a failure reproduces.
fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Cuts `data` into chunks of irregular, deterministic sizes.
fn irregular_chunks(data: &[u8]) -> Vec<Bytes> {
    let sizes = [1usize, 4093, 17, 65_536, 2, 31_337, 8191, 1024];
    let mut chunks = Vec::new();
    let mut offset = 0;
    for size in sizes.iter().cycle() {
        if offset >= data.len() {
            break;
        }
        let end = (offset + size).min(data.len());
        chunks.push(Bytes::copy_from_slice(&data[offset..end]));
        offset = end;
    }
    chunks
}

/// Polls a pull-model body exactly once through `buf`.
fn poll_fill_once<R: AsyncPayloadRead + Unpin>(reader: &mut R, buf: &mut [u8]) -> Poll<Result<ReadProgress, StreamError>> {
    let mut cx = noop_context();
    Pin::new(reader).poll_fill(&mut cx, buf)
}

/// Polls an `AsyncRead` exactly once through `buf`, answering with the number of bytes filled.
fn read_once<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut [u8]) -> Poll<io::Result<usize>> {
    let mut cx = noop_context();
    let mut read_buf = ReadBuf::new(buf);
    Pin::new(reader)
        .poll_read(&mut cx, &mut read_buf)
        .map_ok(|()| read_buf.filled().len())
}

/// One scripted `AsyncRead` event.
enum ReadStep {
    /// Hand out these bytes, across as many reads as the caller's buffers need.
    Data(Vec<u8>),
    /// Report "not ready" once, then continue with the next step.
    Pending,
    /// Fail with this i/o error.
    Fail(io::ErrorKind, &'static str),
}

/// An `AsyncRead` that replays a script and records where it was asked to write.
struct ScriptedAsyncRead {
    steps: VecDeque<ReadStep>,
    calls: Arc<AtomicUsize>,
    /// The address of the slice the last `poll_read` was handed.
    last_buffer: Arc<AtomicUsize>,
}

impl ScriptedAsyncRead {
    fn new(steps: impl IntoIterator<Item = ReadStep>) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let last_buffer = Arc::new(AtomicUsize::new(0));
        let reader = Self {
            steps: steps.into_iter().collect(),
            calls: Arc::clone(&calls),
            last_buffer: Arc::clone(&last_buffer),
        };
        (reader, calls, last_buffer)
    }
}

impl AsyncRead for ScriptedAsyncRead {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.calls.fetch_add(1, Ordering::SeqCst);
        this.last_buffer
            .store(buf.initialize_unfilled().as_ptr().addr(), Ordering::SeqCst);
        match this.steps.pop_front() {
            Some(ReadStep::Data(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    this.steps.push_front(ReadStep::Data(data[n..].to_vec()));
                }
                Poll::Ready(Ok(()))
            }
            Some(ReadStep::Pending) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Some(ReadStep::Fail(kind, message)) => Poll::Ready(Err(io::Error::new(kind, message))),
            None => Poll::Ready(Ok(())),
        }
    }
}

/// A push-model producer that counts how often it is polled and whether it was dropped.
struct Counted {
    inner: ScriptedStream,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Counted {
    fn new(inner: ScriptedStream) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let counted = Self {
            inner,
            polls: Arc::clone(&polls),
            drops: Arc::clone(&drops),
        };
        (counted, polls, drops)
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl PayloadStream for Counted {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut this.inner).poll_read(cx)
    }

    fn caps(&self) -> PayloadCaps {
        self.inner.caps()
    }

    fn len_hint(&self) -> Option<u64> {
        self.inner.len_hint()
    }
}

fn io_error_kind(progress: &Poll<io::Result<usize>>) -> Option<io::ErrorKind> {
    match progress {
        Poll::Ready(Err(err)) => Some(err.kind()),
        Poll::Ready(Ok(_)) | Poll::Pending => None,
    }
}

mod tokio_read_payload {
    use super::*;

    #[test]
    fn one_mebibyte_round_trips_from_an_async_read() {
        let data = random_bytes(MEBIBYTE, 0x5eed);
        let adapter = TokioReadPayload::with_len_hint(io::Cursor::new(data.clone()), MEBIBYTE as u64);
        assert_eq!(adapter.len_hint(), Some(MEBIBYTE as u64));
        assert!(adapter.caps().contains(PayloadCaps::PULL | PayloadCaps::KNOWN_LENGTH));
        assert!(validate_caps(adapter.caps(), adapter.len_hint()).is_ok());

        let (out, trailers) = drain_reader(Box::pin(adapter), ODD_BUFFER).expect("the reader drains to its end");
        assert_eq!(out, data);
        assert!(trailers.is_empty(), "an AsyncRead carries no trailer section");
    }

    #[test]
    fn len_hint_is_none_for_a_reader_of_unknown_length() {
        let data = random_bytes(3 * ODD_BUFFER + 11, 7);
        let adapter = TokioReadPayload::new(io::Cursor::new(data.clone()));
        assert_eq!(adapter.len_hint(), None);
        assert!(adapter.caps().contains(PayloadCaps::PULL));
        assert!(!adapter.caps().contains(PayloadCaps::KNOWN_LENGTH));
        assert!(validate_caps(adapter.caps(), adapter.len_hint()).is_ok());

        let (out, _) = drain_reader(Box::pin(adapter), ODD_BUFFER).expect("an unknown length still drains");
        assert_eq!(out, data);
    }

    #[test]
    fn len_hint_counts_down_as_bytes_are_filled() {
        let mut adapter = TokioReadPayload::with_len_hint(&b"0123456789"[..], 10);
        let mut buf = [0u8; 4];
        assert!(matches!(poll_fill_once(&mut adapter, &mut buf), Poll::Ready(Ok(ReadProgress::Filled(4)))));
        assert_eq!(&buf, b"0123");
        assert_eq!(adapter.len_hint(), Some(6));
        assert!(validate_caps(adapter.caps(), adapter.len_hint()).is_ok());
    }

    #[test]
    fn a_zero_length_reader_reaches_eof_at_once() {
        let empty: &[u8] = &[];
        for mut adapter in [TokioReadPayload::new(empty), TokioReadPayload::with_len_hint(empty, 0)] {
            let mut buf = [0u8; 8];
            match poll_fill_once(&mut adapter, &mut buf) {
                Poll::Ready(Ok(ReadProgress::Eof { trailers })) => assert!(trailers.is_empty()),
                other => panic!("a zero-length reader must end at once, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_empty_caller_buffer_is_no_progress_and_no_read() {
        let (reader, calls, _) = ScriptedAsyncRead::new([ReadStep::Data(b"ab".to_vec())]);
        let mut adapter = TokioReadPayload::new(reader);
        assert!(matches!(poll_fill_once(&mut adapter, &mut []), Poll::Ready(Ok(ReadProgress::Filled(0)))));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "an empty buffer must not reach the reader: its zero-byte answer would read as end-of-stream"
        );
        let mut buf = [0u8; 4];
        assert!(matches!(poll_fill_once(&mut adapter, &mut buf), Poll::Ready(Ok(ReadProgress::Filled(2)))));
    }

    #[test]
    fn polling_after_eof_is_an_error_not_a_second_eof() {
        let mut adapter = TokioReadPayload::new(&b"xyz"[..]);
        let mut buf = [0u8; 8];
        assert!(matches!(poll_fill_once(&mut adapter, &mut buf), Poll::Ready(Ok(ReadProgress::Filled(3)))));
        assert!(matches!(
            poll_fill_once(&mut adapter, &mut buf),
            Poll::Ready(Ok(ReadProgress::Eof { .. }))
        ));
        match poll_fill_once(&mut adapter, &mut buf) {
            Poll::Ready(Err(err)) => {
                assert!(matches!(err.kind(), StreamErrorKind::PolledAfterEof), "{err}");
                assert_eq!(err.bytes_before_error(), 3);
            }
            other => panic!("a finished reader must refuse another poll, got {other:?}"),
        }
    }

    #[test]
    fn an_io_error_surfaces_unchanged_and_ends_the_body() {
        let (reader, calls, _) = ScriptedAsyncRead::new([
            ReadStep::Data(b"abc".to_vec()),
            ReadStep::Fail(io::ErrorKind::ConnectionReset, "peer went away"),
            ReadStep::Data(b"never".to_vec()),
        ]);
        let mut adapter = TokioReadPayload::new(reader);
        let mut buf = [0u8; 8];
        assert!(matches!(poll_fill_once(&mut adapter, &mut buf), Poll::Ready(Ok(ReadProgress::Filled(3)))));
        match poll_fill_once(&mut adapter, &mut buf) {
            Poll::Ready(Err(err)) => {
                match err.kind() {
                    StreamErrorKind::Io(inner) => {
                        assert_eq!(inner.kind(), io::ErrorKind::ConnectionReset);
                        assert_eq!(inner.to_string(), "peer went away");
                    }
                    other => panic!("the reader's own error must cross as-is, got {other}"),
                }
                assert_eq!(err.bytes_before_error(), 3);
            }
            other => panic!("expected the reader's failure, got {other:?}"),
        }
        match poll_fill_once(&mut adapter, &mut buf) {
            Poll::Ready(Err(err)) => assert!(matches!(err.kind(), StreamErrorKind::PolledAfterEof), "{err}"),
            other => panic!("a failed reader must not be read again, got {other:?}"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the reader is not consulted after it failed");
    }

    #[test]
    fn a_reader_that_ends_short_of_its_hint_is_incomplete() {
        let mut adapter = TokioReadPayload::with_len_hint(&b"abcd"[..], 10);
        let mut buf = [0u8; 8];
        assert!(matches!(poll_fill_once(&mut adapter, &mut buf), Poll::Ready(Ok(ReadProgress::Filled(4)))));
        match poll_fill_once(&mut adapter, &mut buf) {
            Poll::Ready(Err(err)) => {
                assert!(matches!(err.kind(), StreamErrorKind::IncompleteBody), "{err}");
                assert_eq!(err.bytes_before_error(), 4);
            }
            other => panic!("a short reader must fail rather than end, got {other:?}"),
        }
    }

    #[test]
    fn a_reader_that_overruns_its_hint_is_a_length_mismatch() {
        let mut adapter = TokioReadPayload::with_len_hint(&b"abcd"[..], 2);
        let mut buf = [0u8; 8];
        match poll_fill_once(&mut adapter, &mut buf) {
            Poll::Ready(Err(err)) => {
                assert!(
                    matches!(
                        err.kind(),
                        StreamErrorKind::LengthMismatch {
                            declared: 2,
                            observed: 4
                        }
                    ),
                    "{err}"
                );
                assert_eq!(err.bytes_before_error(), 0);
            }
            other => panic!("an overrun must fail, got {other:?}"),
        }
        match poll_fill_once(&mut adapter, &mut buf) {
            Poll::Ready(Err(err)) => assert!(matches!(err.kind(), StreamErrorKind::PolledAfterEof), "{err}"),
            other => panic!("a failed reader must not be read again, got {other:?}"),
        }
    }

    #[test]
    fn pending_is_passed_through_without_inventing_eof() {
        let (reader, _, _) = ScriptedAsyncRead::new([ReadStep::Pending, ReadStep::Data(b"ab".to_vec())]);
        let mut adapter = TokioReadPayload::new(reader);
        let mut buf = [0u8; 8];
        assert!(matches!(poll_fill_once(&mut adapter, &mut buf), Poll::Pending));
        assert!(matches!(poll_fill_once(&mut adapter, &mut buf), Poll::Ready(Ok(ReadProgress::Filled(2)))));
        assert!(matches!(
            poll_fill_once(&mut adapter, &mut buf),
            Poll::Ready(Ok(ReadProgress::Eof { .. }))
        ));
    }

    #[test]
    fn the_reader_fills_the_callers_buffer_itself_and_nothing_is_counted_as_a_copy() {
        let (reader, _, last_buffer) = ScriptedAsyncRead::new([ReadStep::Data(b"payload".to_vec())]);
        let mut adapter = TokioReadPayload::new(reader);
        let metrics = StreamMetrics::new();
        assert_eq!(adapter.adapt_cost(), AdaptCost::Free);
        metrics.record_adapt(&adapter.adapt_cost());

        let mut buf = [0u8; 16];
        let callers_buffer = buf.as_ptr().addr();
        assert!(matches!(poll_fill_once(&mut adapter, &mut buf), Poll::Ready(Ok(ReadProgress::Filled(7)))));
        assert_eq!(&buf[..7], b"payload");
        assert_eq!(
            last_buffer.load(Ordering::SeqCst),
            callers_buffer,
            "the reader must write into the consumer's slice; an intermediate buffer is a copy"
        );
        assert_eq!(metrics.adapt_copies_total(), 0);
        assert_eq!(metrics.adapt_copied_bytes_total(), 0);
        assert_eq!(metrics.adapt_buffers_total(), 0);
    }
}

mod payload_reader {
    use super::*;

    #[test]
    fn one_mebibyte_round_trips_into_an_async_read() {
        let data = random_bytes(MEBIBYTE, 0xbeef);
        let stream = MemoryStream::new(irregular_chunks(&data), trailers(&[("x-test-trailer", "present")]));
        let mut reader = PayloadReader::new(stream);
        assert!(reader.trailers().is_none(), "no trailer section exists before end-of-stream");

        let mut out = Vec::new();
        let n = block_on(reader.read_to_end(&mut out)).expect("the body reads to its end");
        assert_eq!(n, MEBIBYTE);
        assert_eq!(out, data);

        let section = reader
            .trailers()
            .expect("the trailer section is reachable after end-of-stream");
        assert_eq!(section.get("x-test-trailer").map(|v| v.as_bytes()), Some(&b"present"[..]));
        let owned = reader
            .into_trailers()
            .expect("the owned section is reachable after end-of-stream");
        assert_eq!(trailer_value(&owned, "x-test-trailer").as_deref(), Some("present"));
    }

    #[test]
    fn trailers_stay_none_until_end_of_stream_is_observed() {
        // Every body byte has been served, and the end-of-stream event has not been polled yet.
        let stream = MemoryStream::new([Bytes::from_static(b"abc")], trailers(&[("x-test-trailer", "late")]));
        let mut reader = PayloadReader::new(stream);
        let mut buf = [0u8; 3];
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(3))));
        assert!(
            reader.trailers().is_none(),
            "all bytes delivered is not the same fact as the body being over"
        );
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(0))));
        assert!(reader.trailers().is_some());
    }

    #[test]
    fn a_zero_length_stream_is_eof_at_once_with_its_trailers() {
        let stream = MemoryStream::new([], trailers(&[("x-test-trailer", "only")]));
        let mut reader = PayloadReader::new(stream);
        assert!(reader.trailers().is_none());
        let mut buf = [0u8; 8];
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(0))));
        let section = reader
            .trailers()
            .expect("a zero-length body still ends with its trailer section");
        assert_eq!(section.len(), 1);
    }

    #[test]
    fn reading_after_eof_returns_zero_bytes_and_leaves_the_producer_alone() {
        let (counted, polls, _) = Counted::new(ScriptedStream::new([Step::Chunk("ab"), Step::Eof(trailers(&[]))]));
        let mut reader = PayloadReader::new(counted);
        let mut buf = [0u8; 8];
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(2))));
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(0))));
        let polled = polls.load(Ordering::SeqCst);
        for _ in 0..3 {
            assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(0))));
        }
        assert_eq!(
            polls.load(Ordering::SeqCst),
            polled,
            "a finished producer is never polled again; it would answer with an error"
        );
        assert!(reader.trailers().is_some());
    }

    #[test]
    fn an_io_error_from_the_producer_surfaces_unchanged() {
        let stream = ScriptedStream::new([
            Step::Chunk("abc"),
            Step::Fail(StreamErrorKind::Io(io::Error::new(io::ErrorKind::ConnectionReset, "peer went away"))),
        ]);
        let mut reader = PayloadReader::new(stream);
        let mut buf = [0u8; 8];
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(3))));
        match read_once(&mut reader, &mut buf) {
            Poll::Ready(Err(err)) => {
                assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
                assert_eq!(err.to_string(), "peer went away", "the producer's i/o error must cross as-is");
            }
            other => panic!("expected the producer's failure, got {other:?}"),
        }
        assert!(reader.trailers().is_none(), "a failed body has no trailer section");
        // A failed body stays failed: it does not turn into a clean end-of-stream on the next read.
        match read_once(&mut reader, &mut buf) {
            Poll::Ready(Err(err)) => {
                assert_eq!(err.kind(), io::ErrorKind::Other);
                assert!(err.to_string().contains("polled after end-of-stream"), "{err}");
            }
            other => panic!("a failed reader must not read as finished, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_body_is_an_unexpected_eof() {
        let stream = ScriptedStream::new([Step::Chunk("ab"), Step::Fail(StreamErrorKind::IncompleteBody)]);
        let mut reader = PayloadReader::new(stream);
        let mut buf = [0u8; 8];
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(2))));
        match read_once(&mut reader, &mut buf) {
            Poll::Ready(Err(err)) => {
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
                assert_eq!(err.to_string(), "body stream ended before it was complete (after 2 body bytes)");
            }
            other => panic!("a truncated body must fail, got {other:?}"),
        }
        assert!(reader.trailers().is_none());
    }

    #[test]
    fn a_length_mismatch_is_invalid_data() {
        let inner = ScriptedStream::new([Step::Chunk("abcd"), Step::Eof(trailers(&[]))])
            .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
            .with_len_hint(Some(2))
            .boxed();
        let stream = ByteStream::new(inner).expect("the producer declares consistent capabilities");
        let mut reader = PayloadReader::new(stream);
        let mut buf = [0u8; 8];
        match read_once(&mut reader, &mut buf) {
            Poll::Ready(Err(err)) => {
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    err.to_string(),
                    "body length mismatch: declared 2 bytes, observed 4 bytes (after 0 body bytes)"
                );
            }
            other => panic!("an overlong body must fail, got {other:?}"),
        }
        assert!(reader.trailers().is_none());
    }

    #[test]
    fn a_zero_capacity_read_buffer_consumes_nothing() {
        let (counted, polls, _) = Counted::new(ScriptedStream::new([Step::Chunk("ab"), Step::Eof(trailers(&[]))]));
        let mut reader = PayloadReader::new(counted);
        assert!(matches!(read_once(&mut reader, &mut []), Poll::Ready(Ok(0))));
        assert_eq!(polls.load(Ordering::SeqCst), 0, "a read with no room must not take a chunk");
        let mut buf = [0u8; 8];
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(2))));
        assert_eq!(&buf[..2], b"ab");
    }

    #[test]
    fn pending_from_the_producer_is_pending_here() {
        let stream = ScriptedStream::new([Step::Pending, Step::Chunk("ab"), Step::Eof(trailers(&[]))]);
        let mut reader = PayloadReader::new(stream);
        let mut buf = [0u8; 8];
        let first = read_once(&mut reader, &mut buf);
        assert!(matches!(first, Poll::Pending), "{:?}", io_error_kind(&first));
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(2))));
    }

    #[test]
    fn a_read_buffer_smaller_than_the_chunk_is_served_in_pieces_from_one_chunk() {
        let (counted, polls, _) = Counted::new(ScriptedStream::new([Step::Chunk("abcdef"), Step::Eof(trailers(&[]))]));
        let mut reader = PayloadReader::new(counted);
        let mut buf = [0u8; 4];
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(4))));
        assert_eq!(&buf, b"abcd");
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(2))));
        assert_eq!(&buf[..2], b"ef");
        assert_eq!(polls.load(Ordering::SeqCst), 1, "the rest of a chunk is served without a second poll");
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(0))));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dropping_the_reader_drops_the_producer_exactly_once() {
        let (counted, polls, drops) = Counted::new(ScriptedStream::new([Step::Pending, Step::Chunk("ab")]));
        let mut reader = PayloadReader::new(counted);
        let mut buf = [0u8; 8];
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Pending));
        assert_eq!(polls.load(Ordering::SeqCst), 1, "the producer was polled before cancellation");
        assert_eq!(drops.load(Ordering::SeqCst), 0, "the producer stays owned while the reader lives");
        drop(reader);
        assert_eq!(drops.load(Ordering::SeqCst), 1, "cancellation drops the producer once");
    }

    #[test]
    fn a_chunk_is_served_from_the_producers_buffer_and_released_after_it() {
        let chunk = Bytes::from(vec![0x5au8; 64]);
        let probe = chunk.clone();
        let stream = MemoryStream::new([chunk], TrailingHeaders::empty());
        let mut reader = PayloadReader::new(stream);
        let metrics = StreamMetrics::new();
        assert_eq!(reader.adapt_cost(), AdaptCost::Free);
        metrics.record_adapt(&reader.adapt_cost());

        let mut buf = [0u8; 16];
        assert!(matches!(read_once(&mut reader, &mut buf), Poll::Ready(Ok(16))));
        assert!(buf.iter().all(|b| *b == 0x5a));
        // Half-way through the chunk the reader still holds the producer's buffer; a copy would
        // have let go of it, and the probe would be its only holder.
        let probe = match probe.try_into_mut() {
            Ok(_) => panic!("the reader copied the chunk out instead of serving the producer's buffer"),
            Err(shared) => shared,
        };
        let mut rest = [0u8; 48];
        assert!(matches!(read_once(&mut reader, &mut rest), Poll::Ready(Ok(48))));
        assert!(rest.iter().all(|b| *b == 0x5a));
        // Once the last byte has been served the buffer is released: the probe is the only holder.
        assert!(probe.try_into_mut().is_ok(), "a fully served chunk must not stay pinned by the reader");

        assert_eq!(metrics.adapt_copies_total(), 0);
        assert_eq!(metrics.adapt_copied_bytes_total(), 0);
        assert_eq!(metrics.adapt_buffers_total(), 0);
    }
}
