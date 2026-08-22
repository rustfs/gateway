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
//! Responsible for: signed `aws-chunked` slow-body refusal, the sustained-progress control, and
//! concurrent slow-upload RSS and healthy-peer latency. NOT responsible for: idle-body or
//! back-pressure contracts. Upstream: the streaming request fixture. Downstream: c-ing-0062.

#![allow(clippy::expect_used, clippy::panic)]

use super::streaming_request::{
    StreamingOutput, StreamingPut, live_server, resident_ballast, rss_bytes, service_with_deadlines, stop,
};
use crate::support;

use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{Handler, HandlerCancellation, HandlerError, HandlerResult, Req, RequestBodyDeadlineConfig, Resp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Barrier;

pub(super) const SIGNED_CHUNK_BYTES: usize = 256;

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

pub(super) fn signed_chunked_request(decoded_len: usize) -> (Vec<u8>, Vec<u8>) {
    signed_chunked_request_with_chunk_bytes(decoded_len, SIGNED_CHUNK_BYTES)
}

pub(super) fn signed_chunked_request_with_chunk_bytes(decoded_len: usize, chunk_bytes: usize) -> (Vec<u8>, Vec<u8>) {
    let decoded: Vec<u8> = (0..decoded_len).map(|index| (index % 251) as u8).collect();
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let probe = http::Request::builder()
        .method(http::Method::PUT)
        .uri("/")
        .header("host", "localhost")
        .body(())
        .expect("a valid request");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("an acceptable host");
    let wire_len = decoded
        .chunks(chunk_bytes)
        .map(|chunk| chunk.len() + format!("{:x}", chunk.len()).len() + 17 + 64 + 4)
        .sum::<usize>()
        + 1
        + 17
        + 64
        + 4;
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("localhost"));
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&wire_len.to_string()).expect("a digit run"),
    );
    let signing = SigningRequest::new(
        &http::Method::PUT,
        "/",
        "",
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::StreamingSigned {
            trailer: rustfs_gateway::sig::TrailerSet::None,
        },
        stamp,
    )
    .with_wire_content_length(wire_len as u64)
    .with_decoded_content_length(decoded_len as u64);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let mut wire = Vec::with_capacity(wire_len);
    for chunk in decoded.chunks(chunk_bytes) {
        wire.extend_from_slice(&chain.encode_chunk(chunk));
    }
    wire.extend_from_slice(&chain.encode_chunk(b""));
    assert_eq!(wire.len(), wire_len, "the signed wire length must be the one that was signed");

    let mut head = b"PUT / HTTP/1.1\r\n".to_vec();
    for (name, value) in signed.headers() {
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    (head, wire)
}

fn deadlines(minimum_bytes: u64, window: Duration, read_idle: Duration) -> RequestBodyDeadlineConfig {
    RequestBodyDeadlineConfig::new(Duration::from_secs(2), read_idle)
        .expect("non-zero body deadlines")
        .try_with_throughput_floor(minimum_bytes, window)
        .expect("a non-zero throughput floor")
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
    tokio::time::timeout(Duration::from_secs(4), reader.read_to_end(&mut response))
        .await
        .expect("the throughput floor retires the request")
        .expect("the response reads");
    feeder.abort();
    let _ = feeder.await;
    let text = String::from_utf8(response).expect("an HTTP/1.1 response");
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert!(text.contains("the request body remained below the minimum throughput"), "{text}");
    assert_eq!(
        *backend.cancellation.lock().expect("not poisoned"),
        Some(HandlerCancellation::BodyThroughput)
    );
    stop(running).await;
}

/// `c-ing-0062`. Positive control — sustained progress above the floor completes even though the
/// total transfer spans many read-idle intervals.
#[tokio::test]
async fn c_ing_0062_sustained_progress_outlives_one_idle_interval() {
    let read_idle = Duration::from_millis(60);
    let backend = Arc::new(ThroughputBackend::new());
    let running = live_server(service_with_deadlines(backend, deadlines(64, Duration::from_millis(100), read_idle)));
    let (head, wire) = signed_chunked_request(4 * SIGNED_CHUNK_BYTES);
    let started = Instant::now();
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(&head).await.expect("the signed head writes");
    for chunk in wire.chunks(32) {
        stream.write_all(chunk).await.expect("the sustained body writes");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("the sustained upload completes")
        .expect("the response reads");
    let elapsed = started.elapsed();
    let text = String::from_utf8(response).expect("an HTTP/1.1 response");
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(elapsed > read_idle * 4, "the {elapsed:?} transfer did not span several idle intervals");
    stop(running).await;
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
