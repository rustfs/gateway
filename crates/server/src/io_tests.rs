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

//! Unit controls for `ProgressIo` lingering-close, write-progress and HTTP/2 header deadlines.
//!
//! Responsible for: verifying transport progress timers on deterministic in-memory transports.
//! NOT responsible for: `Duration::MAX` clamping (`io_deadline_tests.rs`) or real-socket sendfile
//! readiness (`io_sendfile_tests.rs`).
//! Upstream: `ProgressIo`. Downstream: deterministic fake transports.

use std::collections::VecDeque;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

struct DelayedReader {
    ready: Pin<Box<Sleep>>,
    body: Option<&'static [u8]>,
}

impl DelayedReader {
    fn new(delay: Duration, body: &'static [u8]) -> Self {
        Self {
            ready: Box::pin(sleep(delay)),
            body: Some(body),
        }
    }
}

impl AsyncRead for DelayedReader {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.ready.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }
        if let Some(body) = self.body.take() {
            buffer.put_slice(body);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for DelayedReader {
    fn poll_write(self: Pin<&mut Self>, _context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn delayed_lingering_io(
    delay: Duration,
    body: &'static [u8],
    body_unfinished: bool,
    drained: Arc<AtomicU64>,
) -> ProgressIo<DelayedReader> {
    ProgressIo::new(
        DelayedReader::new(delay, body),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(true)),
        deadline_after(Duration::from_secs(60)),
        Duration::from_secs(60),
        Duration::from_secs(60),
        Duration::from_secs(2),
    )
    .request_body_unfinished(Arc::new(AtomicBool::new(body_unfinished)))
    .count_octets_into(Arc::new(AtomicU64::new(0)), drained)
}

/// Positive — an early refusal waits for a body already known to be unfinished even when the
/// first transport read loses the arrival race.
#[tokio::test(start_paused = true)]
async fn a_known_unfinished_body_that_arrives_after_shutdown_starts_is_drained() {
    let drained = Arc::new(AtomicU64::new(0));
    let mut io = delayed_lingering_io(LINGER_QUIET / 2, b"late body", true, Arc::clone(&drained));
    let shutdown = tokio::spawn(async move { io.shutdown().await });
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished(), "the initial Pending abandoned a body known to be unfinished");
    tokio::time::advance(LINGER_QUIET / 2).await;
    shutdown.await.expect("shutdown task joins").expect("shutdown succeeds");
    assert_eq!(drained.load(Ordering::Relaxed), 9);
}

/// Negative — an ordinary close with no unfinished-body proof still retires immediately.
#[tokio::test(start_paused = true)]
async fn an_initially_pending_transport_without_body_proof_does_not_linger() {
    let started = transport_now();
    let mut io = delayed_lingering_io(Duration::from_secs(60), b"not owed", false, Arc::new(AtomicU64::new(0)));
    io.shutdown().await.expect("a bodyless close retires immediately");
    assert_eq!(started.elapsed(), Duration::ZERO, "the bodyless close spent a linger interval");
}

/// Negative — an unfinished peer that sends nothing gets only the existing quiet grace, not
/// the whole outer linger budget.
#[tokio::test(start_paused = true)]
async fn a_known_unfinished_body_that_stays_silent_is_bounded_by_the_quiet_grace() {
    let started = transport_now();
    let mut io = delayed_lingering_io(Duration::from_secs(60), b"never arrives", true, Arc::new(AtomicU64::new(0)));
    let shutdown = tokio::spawn(async move { io.shutdown().await });
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished(), "the unfinished body was abandoned without its quiet grace");
    tokio::time::advance(LINGER_QUIET + Duration::from_millis(1)).await;
    shutdown.await.expect("shutdown task joins").expect("shutdown succeeds");
    assert_eq!(
        started.elapsed(),
        LINGER_QUIET + Duration::from_millis(1),
        "the silent body was charged more than the existing quiet grace"
    );
}

struct StalledWriter;

/// Neither writer below has a peer, so "the peer sent nothing and never will" is the honest
/// read side for both: end of stream. It also keeps the drain out of the way of the cases
/// below, which are about the write-progress deadline.
impl AsyncRead for StalledWriter {
    fn poll_read(self: Pin<&mut Self>, _context: &mut Context<'_>, _buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for PacedWriter {
    fn poll_read(self: Pin<&mut Self>, _context: &mut Context<'_>, _buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for StalledWriter {
    fn poll_write(self: Pin<&mut Self>, _context: &mut Context<'_>, _bytes: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct PacedWriter {
    delay: Duration,
    max_write: usize,
    written: Arc<AtomicUsize>,
    sleep: Pin<Box<Sleep>>,
}

impl PacedWriter {
    fn new(delay: Duration, max_write: usize, written: Arc<AtomicUsize>) -> Self {
        Self {
            delay,
            max_write,
            written,
            sleep: Box::pin(sleep(delay)),
        }
    }
}

impl AsyncWrite for PacedWriter {
    fn poll_write(mut self: Pin<&mut Self>, context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        if self.sleep.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }
        let written = bytes.len().min(self.max_write);
        self.written.fetch_add(written, Ordering::Relaxed);
        let delay = self.delay;
        self.sleep.as_mut().reset(deadline_after(delay));
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn a_stalled_transport_fails_after_one_write_progress_gap() {
    let in_flight = Arc::new(AtomicUsize::new(1));
    let mut io = ProgressIo::new(
        StalledWriter,
        in_flight,
        Arc::new(AtomicBool::new(true)),
        deadline_after(Duration::from_secs(60)),
        Duration::from_secs(60),
        Duration::from_millis(10),
        Duration::from_secs(2),
    );
    let write = tokio::spawn(async move { io.write_all(b"x").await });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(11)).await;
    tokio::task::yield_now().await;
    assert!(write.is_finished(), "the progress deadline must wake the pending writer");
    let error = write
        .await
        .expect("write task joins")
        .expect_err("a stalled write must time out");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test(start_paused = true)]
async fn a_srv_0012_one_hundred_mib_of_continuous_progress_outlives_the_interval() {
    const BODY_LEN: usize = 100 * 1024 * 1024;
    let in_flight = Arc::new(AtomicUsize::new(1));
    let written = Arc::new(AtomicUsize::new(0));
    let mut io = ProgressIo::new(
        PacedWriter::new(Duration::from_millis(9), 1024 * 1024, Arc::clone(&written)),
        in_flight,
        Arc::new(AtomicBool::new(true)),
        deadline_after(Duration::from_secs(60)),
        Duration::from_secs(60),
        Duration::from_millis(10),
        Duration::from_secs(2),
    );
    let started = transport_now();
    io.write_all(&vec![b'x'; BODY_LEN])
        .await
        .expect("every sub-interval write makes progress");
    assert_eq!(written.load(Ordering::Relaxed), BODY_LEN);
    assert!(started.elapsed() >= Duration::from_millis(900));
}

struct ScriptedChunks {
    chunks: VecDeque<Vec<u8>>,
}

impl AsyncRead for ScriptedChunks {
    fn poll_read(mut self: Pin<&mut Self>, _context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.chunks.pop_front() {
            Some(chunk) => {
                buffer.put_slice(&chunk);
                Poll::Ready(Ok(()))
            }
            None => Poll::Pending,
        }
    }
}

/// Negative — after the first request, an incomplete HTTP/2 `HEADERS` block times out at
/// `h2_header_read_timeout` even while `keep_alive_idle` is much longer and another stream is active.
#[tokio::test(start_paused = true)]
async fn n_h2_incomplete_headers_times_out_at_header_timeout_even_with_inflight_stream() {
    let mut first = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    // Stream 3 HEADERS without END_HEADERS (flags = 0x00), len = 2, payload = [0x82, 0x86]
    first.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x82, 0x86]);
    let mut io = ProgressIo::new(
        ScriptedChunks {
            chunks: VecDeque::from([first]),
        },
        Arc::new(AtomicUsize::new(1)),
        Arc::new(AtomicBool::new(true)),
        deadline_after(Duration::from_secs(60)),
        Duration::from_secs(60),
        Duration::from_secs(60),
        Duration::from_secs(2),
    )
    .h2_header_read_timeout(Duration::from_millis(50));

    let mut scratch = [0_u8; 64];
    let n = io.read(&mut scratch).await.expect("initial preface + HEADERS read");
    assert!(n > 24);

    let read = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        io.read(&mut buf).await
    });
    tokio::task::yield_now().await;
    assert!(!read.is_finished(), "timer has not expired yet");
    tokio::time::advance(Duration::from_millis(51)).await;
    tokio::task::yield_now().await;
    assert!(read.is_finished(), "incomplete HTTP/2 header block must wake and time out");
    let error = read.await.expect("read task joins").expect_err("must return TimedOut");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

struct PrefaceThenDelayed {
    initial: Option<&'static [u8]>,
    ready: Pin<Box<Sleep>>,
    late: Option<&'static [u8]>,
}

impl PrefaceThenDelayed {
    fn new(initial: &'static [u8], delay: Duration, late: &'static [u8]) -> Self {
        Self {
            initial: Some(initial),
            ready: Box::pin(sleep(delay)),
            late: Some(late),
        }
    }
}

impl AsyncRead for PrefaceThenDelayed {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if let Some(initial) = self.initial.take() {
            buffer.put_slice(initial);
            return Poll::Ready(Ok(()));
        }
        if self.ready.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }
        if let Some(late) = self.late.take() {
            buffer.put_slice(late);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PrefaceThenDelayed {
    fn poll_write(self: Pin<&mut Self>, _context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buffers.iter().map(|slice| slice.len()).sum()))
    }
}

const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_ERROR_GOAWAY: &[u8] = &[0, 0, 8, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const H2_NO_ERROR_GOAWAY: &[u8] = &[0, 0, 8, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn preface_io(
    initial: &'static [u8],
    delay: Duration,
    late: &'static [u8],
    drained: Arc<AtomicU64>,
) -> ProgressIo<PrefaceThenDelayed> {
    ProgressIo::new(
        PrefaceThenDelayed::new(initial, delay, late),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(true)),
        deadline_after(Duration::from_secs(60)),
        Duration::from_secs(60),
        Duration::from_secs(60),
        Duration::from_secs(2),
    )
    .count_octets_into(Arc::new(AtomicU64::new(0)), drained)
}

/// Positive — after writing an HTTP/2 error `GOAWAY`, `poll_shutdown` waits inside `LINGER_QUIET`
/// and drains a late-arriving pipelined frame instead of closing early into a TCP reset.
#[tokio::test(start_paused = true)]
async fn h2_error_goaway_waits_for_late_arriving_pipelined_frames_during_shutdown() {
    let drained = Arc::new(AtomicU64::new(0));
    let mut io = preface_io(H2_CLIENT_PREFACE, LINGER_QUIET / 2, b"late-h2-headers", Arc::clone(&drained));
    let mut scratch = [0_u8; 32];
    assert_eq!(io.read(&mut scratch).await.expect("preface reads"), H2_CLIENT_PREFACE.len());
    io.write_all(H2_ERROR_GOAWAY).await.expect("error GOAWAY writes");
    assert!(io.needs_protocol_error_linger());

    let shutdown = tokio::spawn(async move {
        io.shutdown().await.expect("shutdown succeeds");
        assert!(!io.needs_protocol_error_linger(), "completed shutdown clears reclaim need");
    });
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished(), "error GOAWAY shutdown must wait for late pipelined frame");
    tokio::time::advance(LINGER_QUIET / 2).await;
    shutdown.await.expect("shutdown task joins");
    assert_eq!(drained.load(Ordering::Relaxed), 15);
}

/// Positive — vectored error `GOAWAY` writes across slices also arm error-GOAWAY lingering, and
/// dropping `ReclaimableIo` without shutdown returns `ProgressIo` requesting post-error linger.
#[tokio::test(start_paused = true)]
async fn h2_error_goaway_via_vectored_write_reclaims_unshut_transport() {
    let drained = Arc::new(AtomicU64::new(0));
    let io = preface_io(H2_CLIENT_PREFACE, LINGER_QUIET / 2, b"late-frame", Arc::clone(&drained));
    let (mut wrapped, mut reclaim_rx) = reclaimable(io);
    let mut scratch = [0_u8; 32];
    assert_eq!(wrapped.read(&mut scratch).await.expect("preface reads"), H2_CLIENT_PREFACE.len());
    let (head, tail) = H2_ERROR_GOAWAY.split_at_checked(11).expect("17-byte GOAWAY");
    let slices = [io::IoSlice::new(head), io::IoSlice::new(tail)];
    assert_eq!(wrapped.write_vectored(&slices).await.expect("vectored write"), H2_ERROR_GOAWAY.len());
    drop(wrapped);

    let mut reclaimed = reclaim_rx.try_recv().expect("dropped ReclaimableIo returns ProgressIo");
    assert!(reclaimed.needs_protocol_error_linger());
    let shutdown = tokio::spawn(async move { reclaimed.shutdown().await });
    tokio::task::yield_now().await;
    tokio::time::advance(LINGER_QUIET / 2).await;
    shutdown.await.expect("shutdown joins").expect("shutdown succeeds");
    assert_eq!(drained.load(Ordering::Relaxed), 10);
}

/// Negative — graceful HTTP/2 `GOAWAY(NO_ERROR)` must not linger on an initially-pending read.
#[tokio::test(start_paused = true)]
async fn n_h2_no_error_goaway_does_not_linger_when_pending() {
    let mut io = preface_io(H2_CLIENT_PREFACE, Duration::from_secs(60), b"never", Arc::new(AtomicU64::new(0)));
    let mut scratch = [0_u8; 32];
    assert_eq!(io.read(&mut scratch).await.expect("preface reads"), H2_CLIENT_PREFACE.len());
    io.write_all(H2_NO_ERROR_GOAWAY).await.expect("NO_ERROR GOAWAY writes");
    assert!(!io.needs_protocol_error_linger());
    let started = transport_now();
    io.shutdown().await.expect("NO_ERROR close retires immediately");
    assert_eq!(started.elapsed(), Duration::ZERO);
}

/// Negative — HTTP/1.1 bytes matching a GOAWAY frame never arm HTTP/2 error-GOAWAY lingering.
#[tokio::test(start_paused = true)]
async fn n_http1_response_containing_goaway_bytes_never_triggers_h2_linger() {
    let mut io = preface_io(b"GET / HTTP/1.1\r\n\r\n", Duration::from_secs(60), b"never", Arc::new(AtomicU64::new(0)));
    let mut scratch = [0_u8; 32];
    assert_eq!(io.read(&mut scratch).await.expect("H1 head reads"), 18);
    io.write_all(H2_ERROR_GOAWAY).await.expect("raw bytes write");
    assert!(!io.needs_protocol_error_linger());
    let started = transport_now();
    io.shutdown().await.expect("HTTP/1.1 close retires immediately");
    assert_eq!(started.elapsed(), Duration::ZERO);
}

/// Negative — if the peer already sent EOF before drop, reclaim linger must stay disabled.
#[tokio::test(start_paused = true)]
async fn n_h2_error_goaway_after_peer_eof_does_not_request_reclaim_linger() {
    let mut io = preface_io(H2_CLIENT_PREFACE, Duration::ZERO, b"", Arc::new(AtomicU64::new(0)));
    let mut scratch = [0_u8; 32];
    assert_eq!(io.read(&mut scratch).await.expect("preface reads"), H2_CLIENT_PREFACE.len());
    io.write_all(H2_ERROR_GOAWAY).await.expect("error GOAWAY writes");
    assert!(io.needs_protocol_error_linger());
    assert_eq!(io.read(&mut scratch).await.expect("peer EOF reads"), 0);
    assert!(!io.needs_protocol_error_linger());
}

/// Negative — an error `GOAWAY` followed by a silent peer stays bounded by `LINGER_QUIET`, not
/// the outer two-second linger budget.
#[tokio::test(start_paused = true)]
async fn n_h2_error_goaway_with_silent_peer_is_bounded_by_quiet_grace() {
    let mut io = preface_io(H2_CLIENT_PREFACE, Duration::from_secs(60), b"silent", Arc::new(AtomicU64::new(0)));
    let mut scratch = [0_u8; 32];
    assert_eq!(io.read(&mut scratch).await.expect("preface reads"), H2_CLIENT_PREFACE.len());
    io.write_all(H2_ERROR_GOAWAY).await.expect("error GOAWAY writes");
    let started = transport_now();
    let shutdown = tokio::spawn(async move { io.shutdown().await });
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    tokio::time::advance(LINGER_QUIET + Duration::from_millis(1)).await;
    shutdown.await.expect("shutdown joins").expect("shutdown succeeds");
    assert_eq!(started.elapsed(), LINGER_QUIET + Duration::from_millis(1));
}
