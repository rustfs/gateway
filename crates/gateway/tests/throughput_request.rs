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

//! Live-socket evidence for the request-body throughput floor.
//!
//! Responsible for: signed `aws-chunked` slow-body refusal, the sustained-progress control and the
//! self-measuring pacer it relies on, and concurrent slow-upload RSS and healthy-peer latency.
//! NOT responsible for: idle-body or back-pressure contracts.
//! Upstream: the streaming fixture in `support/streaming.rs`. Downstream: c-ing-0062.

#![allow(clippy::expect_used, clippy::panic)]

use super::streaming_request::{resident_ballast, rss_bytes};
use crate::support::streaming::{
    SIGNED_CHUNK_BYTES, StreamingOutput, StreamingPut, live_server, service_with_deadlines, signed_chunked_request, stop,
};

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use rustfs_gateway::{Handler, HandlerCancellation, HandlerError, HandlerResult, Req, RequestBodyDeadlineConfig, Resp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;

/// How many requested pacer pauses fit inside the read-idle deadline of the sustained-progress
/// control. The old 60 ms deadline left a 20 ms pacer a 3x margin, and one injected 100 ms pause
/// was enough to reproduce the `BrokenPipe` (#507). The margin is a count of pauses the control
/// checks before it starts; how far the host actually stalled is measured, never assumed.
const SUSTAINED_PACE_MARGIN: u32 = 15;

/// The measured outcome of a paced upload whose every inter-write gap stayed under the read-idle
/// deadline: the widest gap the host opened between two consecutive write completions.
#[derive(Debug)]
struct PaceReport {
    max_gap: Duration,
}

/// The pacer stalled: an inter-write gap reached the read-idle deadline, so the server was entitled
/// to refuse the body and nothing about its response can be asserted.
#[derive(Debug)]
struct PaceViolation {
    max_gap: Duration,
}

/// Writes `wire` in `piece`-byte writes `pause` apart, measuring every gap between consecutive
/// write completions against `read_idle`. A gap that reaches `read_idle` is reported before the
/// next write is attempted, so a peer that has already refused the idle body is never observed as
/// a `BrokenPipe`; a write that fails inside the deadline is a real failure and panics with the gap.
async fn paced_upload(
    stream: &mut TcpStream,
    wire: &[u8],
    piece: usize,
    pause: Duration,
    read_idle: Duration,
) -> Result<PaceReport, PaceViolation> {
    let mut max_gap = Duration::ZERO;
    let mut last_write = Instant::now();
    for bytes in wire.chunks(piece) {
        max_gap = max_gap.max(last_write.elapsed());
        if max_gap >= read_idle {
            return Err(PaceViolation { max_gap });
        }
        let written = stream.write_all(bytes).await;
        max_gap = max_gap.max(last_write.elapsed());
        if max_gap >= read_idle {
            return Err(PaceViolation { max_gap });
        }
        if let Err(error) = written {
            panic!("the paced body write failed after a {max_gap:?} gap, inside the {read_idle:?} read-idle deadline: {error}");
        }
        last_write = Instant::now();
        tokio::time::sleep(pause).await;
    }
    Ok(PaceReport { max_gap })
}

struct ThroughputBackend {
    entered: AtomicUsize,
    cancellation: Mutex<Option<HandlerCancellation>>,
}

impl ThroughputBackend {
    fn new() -> Self {
        Self {
            entered: AtomicUsize::new(0),
            cancellation: Mutex::new(None),
        }
    }
}

impl Handler<StreamingPut> for ThroughputBackend {
    async fn call(&self, _request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        Err(HandlerError::internal_error("the context-aware entry was bypassed"))
    }

    async fn call_with_context(
        &self,
        request: Req<StreamingPut>,
        context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<StreamingPut> {
        self.entered.fetch_add(1, Ordering::AcqRel);
        let mut body = request.into_input().body.into_body();
        loop {
            tokio::select! {
                biased;
                reason = context.cancelled() => {
                    *self.cancellation.lock().expect("not poisoned") = Some(reason);
                    return Err(HandlerError::internal_error("the slow upload rolled back"));
                }
                frame = body.frame() => match frame {
                    Some(Ok(_)) => {}
                    Some(Err(_)) => return Err(HandlerError::internal_error("the request body failed")),
                    None => return Ok(Resp::new(StreamingOutput)),
                }
            }
        }
    }
}

fn deadlines(minimum_bytes: u64, window: Duration, read_idle: Duration) -> RequestBodyDeadlineConfig {
    RequestBodyDeadlineConfig::new(Duration::from_secs(2), read_idle)
        .expect("non-zero body deadlines")
        .try_with_throughput_floor(minimum_bytes, window)
        .expect("a non-zero throughput floor")
}

fn require_complete_http_response(read: std::io::Result<usize>, response: &[u8]) -> std::io::Result<()> {
    match read {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset && has_complete_content_length_response(response) => {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn has_complete_content_length_response(response: &[u8]) -> bool {
    let Some(head_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let Ok(head) = std::str::from_utf8(&response[..head_end]) else {
        return false;
    };
    let mut lines = head.split("\r\n");
    let Some(status) = lines.next() else {
        return false;
    };
    if !status.starts_with("HTTP/1.1 ") {
        return false;
    }

    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return false;
            }
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return false;
            }
            let Ok(parsed) = value.parse::<usize>() else {
                return false;
            };
            content_length = Some(parsed);
        }
    }

    content_length.is_some_and(|declared| response.len() - head_end - 4 == declared)
}

#[test]
fn complete_response_accepts_connection_reset_after_declared_body() {
    let response = b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 4\r\n\r\nslow";
    let read = Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));

    require_complete_http_response(read, response).expect("the complete response survives the reset");
}

#[test]
fn complete_response_accepts_clean_eof() {
    require_complete_http_response(Ok(4), b"body").expect("a clean EOF remains valid");
}

#[test]
fn complete_response_rejects_reset_after_truncated_body() {
    let response = b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 5\r\n\r\nslow";
    let read = Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));

    assert_eq!(
        require_complete_http_response(read, response)
            .expect_err("the truncated response stays rejected")
            .kind(),
        std::io::ErrorKind::ConnectionReset
    );
}

#[test]
fn complete_response_rejects_reset_without_content_length() {
    let response = b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\nslow";
    let read = Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));

    assert_eq!(
        require_complete_http_response(read, response)
            .expect_err("an unframed response stays rejected")
            .kind(),
        std::io::ErrorKind::ConnectionReset
    );
}

#[test]
fn complete_response_rejects_unrelated_read_error() {
    let response = b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 4\r\n\r\nslow";
    let read = Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));

    assert_eq!(
        require_complete_http_response(read, response)
            .expect_err("an unrelated read error stays rejected")
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

async fn exchange(address: SocketAddr, head: &[u8], wire: &[u8]) -> (Duration, String) {
    let started = Instant::now();
    let mut stream = TcpStream::connect(address).await.expect("the client connects");
    stream.write_all(head).await.expect("the signed head writes");
    stream.write_all(wire).await.expect("the signed body writes");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("the response completes")
        .expect("the response reads");
    (started.elapsed(), String::from_utf8(response).expect("an HTTP/1.1 response"))
}

/// `c-ing-0062`. Negative — a complete, valid signed body offered at one wire byte per second is
/// retired by the throughput window even though every byte arrives inside the read-idle deadline.
#[tokio::test]
async fn c_ing_0062_one_byte_per_second_is_closed_for_body_throughput() {
    let backend = Arc::new(ThroughputBackend::new());
    let running = live_server(service_with_deadlines(
        Arc::clone(&backend),
        deadlines(4, Duration::from_secs(2), Duration::from_millis(1500)),
    ));
    let (head, wire) = signed_chunked_request(SIGNED_CHUNK_BYTES);
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(&head).await.expect("the signed head writes");
    let (mut reader, mut writer) = stream.into_split();
    let feeder = tokio::spawn(async move {
        for byte in wire {
            if writer.write_all(&[byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let mut response = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(4), reader.read_to_end(&mut response))
        .await
        .expect("the throughput floor retires the request");
    require_complete_http_response(read, &response).expect("the response reads completely");
    feeder.abort();
    let _ = feeder.await;
    let text = String::from_utf8(response).expect("an HTTP/1.1 response");
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert!(text.contains("the request body remained below the minimum throughput"), "{text}");
    assert_eq!(
        *backend.cancellation.lock().expect("not poisoned"),
        Some(HandlerCancellation::BodyThroughput)
    );
    stop(running).await;
}

/// `c-ing-0062`. Positive control — sustained progress above the floor completes even though the
/// total transfer spans many read-idle intervals. The pacer measures its own gaps: a host that
/// stalls it past the deadline is reported as an unmet precondition, not as a refusal.
#[tokio::test]
async fn c_ing_0062_sustained_progress_outlives_one_idle_interval() {
    const PIECE: usize = 32;
    let read_idle = Duration::from_millis(300);
    let pause = Duration::from_millis(20);
    assert!(
        pause * SUSTAINED_PACE_MARGIN <= read_idle,
        "the {pause:?} pacer needs {SUSTAINED_PACE_MARGIN} pauses inside the {read_idle:?} read-idle deadline"
    );
    let backend = Arc::new(ThroughputBackend::new());
    let running = live_server(service_with_deadlines(backend, deadlines(64, Duration::from_millis(500), read_idle)));
    let (head, wire) = signed_chunked_request(16 * SIGNED_CHUNK_BYTES);
    let started = Instant::now();
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(&head).await.expect("the signed head writes");
    let report = match paced_upload(&mut stream, &wire, PIECE, pause, read_idle).await {
        Ok(report) => report,
        Err(PaceViolation { max_gap }) => {
            eprintln!("skipped: host stalled the pacer {max_gap:?} >= read_idle {read_idle:?}");
            // Drain the server's refusal so the shutdown report below still counts nothing in flight.
            let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut Vec::new())).await;
            stop(running).await;
            return;
        }
    };
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("the sustained upload completes")
        .expect("the response reads");
    let elapsed = started.elapsed();
    let text = String::from_utf8(response).expect("an HTTP/1.1 response");
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(elapsed > read_idle * 4, "the {elapsed:?} transfer did not span several idle intervals");
    eprintln!(
        "c-ing-0062 sustained: pieces={} max_gap={:?} read_idle={read_idle:?} elapsed={elapsed:?}",
        wire.chunks(PIECE).len(),
        report.max_gap
    );
    stop(running).await;
}

/// Negative — a pacer that stalls past the read-idle deadline against a peer that has closed
/// reports the measured gap as an unmet precondition, never the peer's refusal as a `BrokenPipe`.
#[tokio::test]
async fn n_a_pacer_that_stalls_past_read_idle_reports_the_gap() {
    const PIECE: usize = 32;
    let read_idle = Duration::from_millis(40);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("the peer binds");
    let address = listener.local_addr().expect("the peer has an address");
    let peer = tokio::spawn(async move {
        let (mut accepted, _) = listener.accept().await.expect("the peer accepts");
        let mut first = [0u8; PIECE];
        accepted.read_exact(&mut first).await.expect("the peer takes the first piece");
        drop(accepted);
        first
    });
    let wire: Vec<u8> = (0..3 * PIECE).map(|index| (index % 251) as u8).collect();
    let mut stream = TcpStream::connect(address).await.expect("the client connects");

    let violation = paced_upload(&mut stream, &wire, PIECE, 5 * read_idle, read_idle)
        .await
        .expect_err("a stalled pacer reports the gap");

    assert!(
        violation.max_gap >= read_idle,
        "the reported {:?} gap is under the {read_idle:?} read-idle deadline",
        violation.max_gap
    );
    assert_eq!(
        peer.await.expect("the peer finishes").as_slice(),
        &wire[..PIECE],
        "the peer took the first piece before closing"
    );
}

async fn healthy_p99(address: SocketAddr, head: &[u8], wire: &[u8]) -> Duration {
    let mut samples = Vec::with_capacity(10);
    for _ in 0..10 {
        let (elapsed, response) = exchange(address, head, wire).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        samples.push(elapsed);
    }
    samples.sort_unstable();
    samples[9]
}

/// `c-ing-0062`. Negative resource control — concurrent trickle uploads keep bounded resident
/// ownership and do not starve healthy signed peers before the throughput window retires them.
#[tokio::test]
async fn c_ing_0062_concurrent_slow_uploads_bound_rss_and_healthy_p99() {
    const TEST_NAME: &str = "throughput_request::c_ing_0062_concurrent_slow_uploads_bound_rss_and_healthy_p99";
    const CHILD: &str = "RUSTFS_GATEWAY_THROUGHPUT_RSS_CHILD";
    const CONNECTIONS: usize = 8;
    const BALLAST_BYTES: usize = 8 * 1024 * 1024;
    const PROCESS_BUDGET: usize = CONNECTIONS * 1024 * 1024 + 8 * 1024 * 1024;

    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().expect("the test executable has a path"))
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .expect("the isolated throughput probe starts");
        let report = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success(), "the isolated throughput probe failed:\n{report}");
        assert!(report.contains("1 passed"), "the isolated child ran no test:\n{report}");
        return;
    }

    let Some(before_ballast) = rss_bytes() else {
        eprintln!("SKIP c-ing-0062 RSS: ps did not expose resident bytes on this host");
        return;
    };
    let ballast = resident_ballast(BALLAST_BYTES);
    std::hint::black_box(&ballast);
    let after_ballast = rss_bytes().expect("RSS remains readable");
    assert!(
        after_ballast.saturating_sub(before_ballast) >= BALLAST_BYTES / 2,
        "the RSS observer did not see the unique ballast pages"
    );

    let backend = Arc::new(ThroughputBackend::new());
    let running = live_server(service_with_deadlines(
        Arc::clone(&backend),
        deadlines(256, Duration::from_secs(1), Duration::from_millis(200)),
    ));
    let (healthy_head, healthy_wire) = signed_chunked_request(SIGNED_CHUNK_BYTES);
    let control_p99 = healthy_p99(running.local_addr, &healthy_head, &healthy_wire).await;
    let baseline = rss_bytes().expect("RSS is readable before the slow wave");
    let barrier = Arc::new(Barrier::new(CONNECTIONS + 1));
    let mut writers = Vec::with_capacity(CONNECTIONS);
    for _ in 0..CONNECTIONS {
        let address = running.local_addr;
        let barrier = Arc::clone(&barrier);
        let head = healthy_head.clone();
        let wire = healthy_wire.clone();
        writers.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.expect("the slow upload connects");
            stream.write_all(&head).await.expect("the slow head writes");
            stream.write_all(&wire[..1]).await.expect("the first slow byte writes");
            barrier.wait().await;
            for byte in &wire[1..] {
                if stream.write_all(&[*byte]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), barrier.wait())
        .await
        .expect("every slow upload reaches the live barrier");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(backend.entered.load(Ordering::Acquire) >= CONNECTIONS + 10);
    let loaded = rss_bytes().expect("RSS is readable with the slow wave resident");
    let growth = loaded.saturating_sub(baseline);
    assert!(
        growth <= PROCESS_BUDGET,
        "the slow wave retained {growth} bytes above its {PROCESS_BUDGET}-byte budget"
    );

    let contended_p99 = healthy_p99(running.local_addr, &healthy_head, &healthy_wire).await;
    let p99_ceiling = control_p99.saturating_mul(5).max(Duration::from_millis(100));
    assert!(
        contended_p99 <= p99_ceiling,
        "healthy p99 rose from {control_p99:?} to {contended_p99:?}, above {p99_ceiling:?}"
    );
    eprintln!(
        "c-ing-0062 slow-wave: rss_growth={growth} rss_budget={PROCESS_BUDGET} control_p99={control_p99:?} contended_p99={contended_p99:?}"
    );

    for writer in writers {
        writer.abort();
        let _ = writer.await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop(running).await;
    drop(ballast);
}
