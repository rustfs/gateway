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

//! The lazy `frame_records` adapter, and the memory a framed select answer is allowed to hold.
//!
//! Responsible for: `frame_records` turning a record source into a complete event stream one
//! message per read — records split at the one-message ceiling, accounting, terminator, or an
//! error frame when the source fails — never waiting on its own, not declaring a length, and
//! tolerating a consumer that stops reading; and c-sel-0012: one GiB of records framed through it
//! adds less than eight MiB to the peak resident set of a separate process, measured by the
//! operating system against an empty result and a touched ballast.
//! NOT responsible for: frame byte layout or `EventSequence` splitting, which the core tests pin;
//! or HTTP delivery, which the transport tests observe.
//! Upstream: `rustfs_gateway::frame_records`. Downstream: Cargo's harness.
//!
//! 2 positive / 7 negative, plus the c-sel-0012 peak-RSS measurement.

use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use rustfs_gateway::{MAX_PAYLOAD_BYTES, frame_records, stats_document};
use rustfs_gateway_stream::{
    BoxPayloadStream, ByteStream, MemoryStream, PayloadCaps, PayloadRead, PayloadStream, StreamError, StreamErrorKind,
    TrailingHeaders,
};

use crate::select_restore_intent::{Frame, header_of, read_stream};

fn event_type(frame: &Frame) -> String {
    match header_of(frame, ":message-type") {
        Some("error") => format!("error:{}", header_of(frame, ":error-code").unwrap_or_default()),
        _ => header_of(frame, ":event-type").unwrap_or_default().to_owned(),
    }
}

/// Splits concatenated messages with the independent reader.
fn frames(stream: &[u8]) -> Vec<Frame> {
    read_stream(stream).expect("well-formed messages")
}

/// One `poll_read`, with a waker that is never woken: every source here is ready or says so.
fn poll_once(stream: &mut ByteStream) -> Poll<Result<PayloadRead, StreamError>> {
    Pin::new(stream).poll_read(&mut Context::from_waker(Waker::noop()))
}

/// Drains the framed answer, asserting that each read yields exactly one whole message.
fn drain(mut stream: ByteStream) -> Vec<Frame> {
    let mut out = Vec::new();
    loop {
        match poll_once(&mut stream) {
            Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => {
                let mut one = frames(&chunk);
                assert_eq!(one.len(), 1, "a read carried {} messages", one.len());
                out.append(&mut one);
            }
            Poll::Ready(Ok(PayloadRead::Eof { .. })) => return out,
            Poll::Ready(Err(error)) => panic!("the framed answer failed: {error}"),
            Poll::Pending => panic!("an in-memory source never waits"),
        }
    }
}

fn memory(segments: Vec<Bytes>) -> ByteStream {
    ByteStream::new(Box::pin(MemoryStream::new(segments, TrailingHeaders::empty()))).expect("consistent caps")
}

/// A source that yields its chunks, then waits once or fails, as scripted.
struct Scripted {
    chunks: Vec<Bytes>,
    then: Then,
}

enum Then {
    Fail,
    WaitOnce,
}

impl PayloadStream for Scripted {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if !this.chunks.is_empty() {
            return Poll::Ready(Ok(PayloadRead::Chunk(this.chunks.remove(0))));
        }
        match this.then {
            Then::Fail => Poll::Ready(Err(StreamError::new(StreamErrorKind::IncompleteBody))),
            Then::WaitOnce => {
                this.then = Then::Fail;
                Poll::Pending
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

fn scripted(chunks: Vec<Bytes>, then: Then) -> ByteStream {
    let inner: BoxPayloadStream = Box::pin(Scripted { chunks, then });
    ByteStream::new(inner).expect("consistent caps")
}

#[test]
fn a_record_source_is_framed_one_message_per_read_then_counted_and_ended() {
    let big: Bytes = (0..=MAX_PAYLOAD_BYTES).map(|at| (at % 253) as u8).collect::<Vec<_>>().into();
    let frames = drain(frame_records(memory(vec![big.clone(), Bytes::from_static(b"tail")])));
    let kinds: Vec<_> = frames.iter().map(event_type).collect();
    assert_eq!(kinds, ["Records", "Records", "Records", "Stats", "End"]);
    let records: Vec<u8> = frames[..3].iter().flat_map(|frame| frame.payload.clone()).collect();
    assert_eq!(records, [big.as_ref(), b"tail"].concat());
    let returned = (MAX_PAYLOAD_BYTES + 5) as u64;
    assert_eq!(frames[3].payload, stats_document(returned, returned, returned).into_bytes());
}

#[test]
fn n_an_empty_source_is_still_counted_and_ended() {
    let frames = drain(frame_records(memory(Vec::new())));
    assert_eq!(frames.iter().map(event_type).collect::<Vec<_>>(), ["Stats", "End"]);
    assert_eq!(frames[0].payload, stats_document(0, 0, 0).into_bytes());
}

#[test]
fn n_a_failing_source_ends_with_an_error_frame_and_no_terminator() {
    let frames = drain(frame_records(scripted(vec![Bytes::from_static(b"row\n")], Then::Fail)));
    assert_eq!(frames.iter().map(event_type).collect::<Vec<_>>(), ["Records", "error:InternalError"]);
    assert!(frames[1].payload.is_empty(), "an error frame carries no payload");
}

#[test]
fn n_a_waiting_source_yields_pending_rather_than_a_frame() {
    let mut stream = frame_records(scripted(vec![Bytes::from_static(b"row\n")], Then::WaitOnce));
    assert!(matches!(poll_once(&mut stream), Poll::Ready(Ok(PayloadRead::Chunk(_)))));
    assert!(poll_once(&mut stream).is_pending());
    let rest = drain(stream);
    assert_eq!(rest.iter().map(event_type).collect::<Vec<_>>(), ["error:InternalError"]);
}

#[test]
fn n_a_client_that_stops_reading_is_not_a_producer_bug() {
    let mut stream = frame_records(memory(vec![Bytes::from_static(b"row\n")]));
    assert!(matches!(poll_once(&mut stream), Poll::Ready(Ok(PayloadRead::Chunk(_)))));
    // Dropping mid-stream is a disconnect; the unterminated-sequence debug assertion must not fire.
    drop(stream);
}

#[test]
fn n_the_framed_answer_has_no_declared_length() {
    let stream = frame_records(memory(vec![Bytes::from_static(b"row\n")]));
    assert_eq!(stream.remaining_length().get(), None);
    assert!(!stream.caps().contains(PayloadCaps::KNOWN_LENGTH));
}

/// A source that never produces anything: a scan that is still looking.
struct Silent;

impl PayloadStream for Silent {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        Poll::Pending
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

fn silent() -> ByteStream {
    let inner: BoxPayloadStream = Box::pin(Silent);
    ByteStream::new(inner).expect("consistent caps")
}

/// Polls once from inside the runtime, so a timer the adapter arms is registered with it.
async fn poll_in_runtime(stream: &mut ByteStream) -> Poll<Result<PayloadRead, StreamError>> {
    std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut *stream).poll_read(cx))).await
}

/// c-sel-0006. A scan that produces nothing for the keep-alive interval gets a `Cont` frame, and
/// another one each further interval, so the client does not take the silence for a stall.
#[tokio::test(start_paused = true)]
async fn a_silent_source_is_kept_alive_with_cont_frames() {
    let mut stream = frame_records(silent());
    assert!(poll_in_runtime(&mut stream).await.is_pending());
    for _ in 0..2 {
        tokio::time::advance(std::time::Duration::from_secs(rustfs_gateway::commit::KEEPALIVE_INTERVAL_SECONDS)).await;
        match poll_in_runtime(&mut stream).await {
            Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => {
                assert_eq!(frames(&chunk).iter().map(event_type).collect::<Vec<_>>(), ["Cont"]);
            }
            other => panic!("expected a keep-alive frame, observed {other:?}"),
        }
        assert!(poll_in_runtime(&mut stream).await.is_pending(), "one keep-alive per interval");
    }
}

/// Negative — before the interval has passed, a silent scan yields nothing at all.
#[tokio::test(start_paused = true)]
async fn n_no_keep_alive_is_sent_before_the_interval() {
    let mut stream = frame_records(silent());
    assert!(poll_in_runtime(&mut stream).await.is_pending());
    tokio::time::advance(std::time::Duration::from_secs(rustfs_gateway::commit::KEEPALIVE_INTERVAL_SECONDS - 1)).await;
    assert!(poll_in_runtime(&mut stream).await.is_pending());
}

/// A source that waits until its gate opens, yields one chunk, then waits forever.
struct Gated {
    open: std::sync::Arc<std::sync::atomic::AtomicBool>,
    sent: bool,
}

impl PayloadStream for Gated {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if this.sent || !this.open.load(std::sync::atomic::Ordering::SeqCst) {
            return Poll::Pending;
        }
        this.sent = true;
        Poll::Ready(Ok(PayloadRead::Chunk(Bytes::from_static(b"row\n"))))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

/// Negative — a frame restarts the interval: records that arrive in time are not followed by a
/// keep-alive measured from before them.
#[tokio::test(start_paused = true)]
async fn n_records_restart_the_keep_alive_interval() {
    let interval = std::time::Duration::from_secs(rustfs_gateway::commit::KEEPALIVE_INTERVAL_SECONDS);
    let open = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let inner: BoxPayloadStream = Box::pin(Gated {
        open: open.clone(),
        sent: false,
    });
    let mut stream = frame_records(ByteStream::new(inner).expect("consistent caps"));
    assert!(poll_in_runtime(&mut stream).await.is_pending());
    tokio::time::advance(interval - std::time::Duration::from_secs(1)).await;
    open.store(true, std::sync::atomic::Ordering::SeqCst);
    match poll_in_runtime(&mut stream).await {
        Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => {
            assert_eq!(frames(&chunk).iter().map(event_type).collect::<Vec<_>>(), ["Records"]);
        }
        other => panic!("expected the records, observed {other:?}"),
    }
    assert!(poll_in_runtime(&mut stream).await.is_pending());
    tokio::time::advance(interval - std::time::Duration::from_secs(1)).await;
    assert!(poll_in_runtime(&mut stream).await.is_pending(), "the interval restarts at the last frame");
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    assert!(poll_in_runtime(&mut stream).await.is_ready(), "and elapses a full interval after it");
}

const RSS_PROBE_ENV: &str = "RUSTFS_GATEWAY_SELECT_FRAMING_RSS_PROBE";
const RSS_PROBE_TEST: &str = "c_sel_0012_one_gibibyte_of_records_adds_less_than_eight_mibibytes_of_peak_rss";
const RSS_HEADROOM_BYTES: u64 = 8 * 1024 * 1024;
const RSS_BALLAST_BYTES: usize = 24 * 1024 * 1024;
const RESULT_BYTES: u64 = 1 << 30;
const SOURCE_CHUNK_BYTES: usize = 64 * 1024;

/// A one-GiB record source that owns one 64 KiB buffer and yields it again and again.
struct Repeating {
    chunk: Bytes,
    left: u64,
}

impl PayloadStream for Repeating {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if this.left == 0 {
            return Poll::Ready(Ok(PayloadRead::Eof {
                trailers: TrailingHeaders::empty(),
            }));
        }
        this.left -= this.chunk.len() as u64;
        Poll::Ready(Ok(PayloadRead::Chunk(this.chunk.clone())))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

#[derive(Clone, Copy)]
enum Mode {
    /// An empty result: the same code path with nothing to frame.
    Control,
    /// One GiB of records.
    Result,
    /// The control plus a touched ballast, proving the instrument sees what it is asked to bound.
    Ballast,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Result => "result",
            Self::Ballast => "ballast",
        }
    }

    fn requested() -> Option<Self> {
        match std::env::var(RSS_PROBE_ENV).ok()?.as_str() {
            "control" => Some(Self::Control),
            "result" => Some(Self::Result),
            "ballast" => Some(Self::Ballast),
            other => panic!("unknown c-sel-0012 probe mode: {other}"),
        }
    }
}

/// Streams the answer for `mode`, reading each message's lengths from its prelude only; the
/// frame layout itself is proved by the tests above.
fn run_probe(mode: Mode) {
    let mut ballast = match mode {
        Mode::Ballast => vec![0_u8; RSS_BALLAST_BYTES],
        Mode::Control | Mode::Result => Vec::new(),
    };
    for byte in ballast.iter_mut().step_by(4096) {
        *byte = 0xA5;
    }
    std::hint::black_box(&ballast);
    let size = match mode {
        Mode::Result => RESULT_BYTES,
        Mode::Control | Mode::Ballast => 0,
    };
    let source: BoxPayloadStream = Box::pin(Repeating {
        chunk: Bytes::from(vec![b'r'; SOURCE_CHUNK_BYTES]),
        left: size,
    });
    let mut stream = frame_records(ByteStream::new(source).expect("consistent caps"));
    let (mut messages, mut payload, mut last) = (0_u64, 0_u64, Bytes::new());
    loop {
        match poll_once(&mut stream) {
            Poll::Ready(Ok(PayloadRead::Chunk(message))) => {
                let total = u32::from_be_bytes(message[..4].try_into().expect("a prelude")) as usize;
                let headers = u32::from_be_bytes(message[4..8].try_into().expect("a prelude")) as usize;
                assert_eq!(total, message.len(), "one message per read");
                payload += (total - 16 - headers) as u64;
                messages += 1;
                last = message;
            }
            Poll::Ready(Ok(PayloadRead::Eof { .. })) => break,
            other => panic!("the framed answer did not complete: {other:?}"),
        }
    }
    let stats = stats_document(size, size, size).len() as u64;
    assert_eq!(payload, size + stats, "every record byte and the accounting were framed");
    assert_eq!(
        messages,
        size / SOURCE_CHUNK_BYTES as u64 + 2,
        "one Records frame per chunk, then Stats and End"
    );
    assert_eq!(event_type(&frames(&last).remove(0)), "End");
    std::hint::black_box(&ballast);
}

#[cfg(target_os = "linux")]
fn parse_peak_rss(stderr: &str) -> u64 {
    let kibibytes = stderr
        .lines()
        .find_map(|line| line.trim().strip_prefix("Maximum resident set size (kbytes):"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .expect("GNU time reports maximum resident set size");
    kibibytes.checked_mul(1024).expect("peak RSS fits in u64")
}

#[cfg(target_os = "macos")]
fn parse_peak_rss(stderr: &str) -> u64 {
    stderr
        .lines()
        .find_map(|line| line.trim().strip_suffix("maximum resident set size"))
        .and_then(|value| value.trim().parse::<u64>().ok())
        .expect("BSD time reports maximum resident set size")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn parse_peak_rss(_stderr: &str) -> u64 {
    unreachable!("the probe is skipped on platforms without an OS peak-RSS observer")
}

/// Runs this test binary again, filtered to the probe, under the operating system's `time`.
fn measure_peak_rss(mode: Mode) -> u64 {
    let executable = std::env::current_exe().expect("the active test binary has a path");
    let name = match module_path!().split_once("::") {
        Some((_, rest)) => format!("{rest}::{RSS_PROBE_TEST}"),
        None => RSS_PROBE_TEST.to_owned(),
    };
    let mut command = std::process::Command::new("/usr/bin/time");
    #[cfg(target_os = "linux")]
    command.arg("-v");
    #[cfg(target_os = "macos")]
    command.arg("-l");
    let output = command
        .arg(executable)
        .args(["--exact", &name, "--nocapture", "--test-threads=1"])
        .env(RSS_PROBE_ENV, mode.name())
        .output()
        .expect("the peak-RSS probe starts under /usr/bin/time");
    assert!(
        output.status.success(),
        "the {} peak-RSS probe failed:\n{}{}",
        mode.name(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_peak_rss(&String::from_utf8_lossy(&output.stderr))
}

/// c-sel-0012. One GiB of records framed through `frame_records` adds less than eight MiB to the
/// peak resident set of a separate process, against an empty result on the same code path; a
/// 24 MiB touched ballast shows the instrument can see that much.
#[test]
fn c_sel_0012_one_gibibyte_of_records_adds_less_than_eight_mibibytes_of_peak_rss() {
    if let Some(mode) = Mode::requested() {
        run_probe(mode);
        return;
    }
    if cfg!(not(any(target_os = "linux", target_os = "macos"))) {
        eprintln!("SKIP c-sel-0012 peak RSS: this platform has no supported OS peak-RSS observer");
        return;
    }
    let control = measure_peak_rss(Mode::Control);
    let result = measure_peak_rss(Mode::Result);
    let ballast = measure_peak_rss(Mode::Ballast);
    println!("c-sel-0012 peak RSS: control={control}, result={result}, ballast={ballast}");
    assert!(
        ballast.saturating_sub(control) >= RSS_HEADROOM_BYTES,
        "the RSS instrument saw only {} additional bytes from a {RSS_BALLAST_BYTES}-byte touched ballast",
        ballast.saturating_sub(control)
    );
    assert!(
        result.saturating_sub(control) < RSS_HEADROOM_BYTES,
        "one GiB of records increased peak RSS by {} bytes (control {control}, result {result})",
        result.saturating_sub(control)
    );
}
