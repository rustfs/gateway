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

//! Isolated allocation and retained-heap controls for the fallback request reader.
//!
//! Responsible for: actual allocator observations around body polling and real head reads.
//! NOT responsible for: throughput, scan bounds, or production-driver optimization.
//! Upstream: the self-held request parser. Downstream: isolated regression probes.

#![allow(clippy::expect_used, clippy::indexing_slicing)] // Test fixtures intentionally panic when setup or measured invariants fail.

use std::process::Command;
use std::sync::Mutex as SyncMutex;

use http_body_util::BodyExt;
use rustfs_gateway_server::{AcceptedConnection, ConnectionDriver, ConnectionFuture, Server, ServerConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use super::*;

// The integration binary has its own allocator; this declaration belongs only to the lib-test binary.
#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

const PROBE_ENV: &str = "GATEWAY_SELF_HELD_COST_PROBE";
const SENTINEL: &str = "self-held request cost: ";
const PAYLOAD_BYTES: usize = 4096;

#[derive(Clone, Copy)]
enum Probe {
    Frames(usize),
    Retention,
    RetainedControl,
}

#[derive(Debug)]
struct Observation {
    blocks: u64,
    bytes: u64,
    frames: usize,
    payload_bytes: usize,
    checksum: usize,
    retained_bytes: usize,
}

fn allocator_observes_allocation_and_release() {
    let profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get();
    let allocation = vec![7_u8; 32 * 1024];
    std::hint::black_box(&allocation);
    let live = dhat::HeapStats::get();
    assert!(live.total_blocks > before.total_blocks, "allocator must observe a real allocation");
    assert!(live.total_bytes - before.total_bytes >= 32 * 1024);
    assert!(live.curr_bytes - before.curr_bytes >= allocation.len());
    drop(allocation);
    let released = dhat::HeapStats::get();
    assert!(live.curr_bytes - released.curr_bytes >= 32 * 1024, "live heap must fall after release");
    drop(profiler);
}

async fn observe(stream: PlaintextConnection, probe: Probe) -> Observation {
    let mut connection = ConnectionIo::new(stream);
    match probe {
        Probe::Frames(count) => {
            assert_eq!(PAYLOAD_BYTES % count, 0);
            // All encoding, buffer growth, connection setup, and Arc allocation precede the window.
            let payload = "x".repeat(PAYLOAD_BYTES / count);
            let mut encoded = String::new();
            for _ in 0..count {
                use std::fmt::Write;
                write!(encoded, "{:x}\r\n{payload}\r\n", payload.len()).expect("String formatting");
            }
            encoded.push_str("0\r\n\r\n");
            connection.buffer = BytesMut::from(encoded.as_bytes());
            connection.body = BodyState::Chunked(ChunkState { phase: ChunkPhase::Size });
            let io = Arc::new(Mutex::new(connection));
            let mut body = SelfHeldRequestBody::new(io, None);
            let profiler = dhat::Profiler::builder().testing().build();
            let mut frames = 0;
            let mut payload_bytes = 0;
            let mut checksum = 0;
            while let Some(frame) = body.frame().await {
                let frame = frame.expect("valid preloaded chunk framing");
                let data = frame.into_data().expect("fixture has no trailers");
                frames += 1;
                payload_bytes += data.len();
                checksum += data.iter().map(|byte| usize::from(*byte)).sum::<usize>();
            }
            let stats = dhat::HeapStats::get();
            drop(profiler);
            Observation {
                blocks: stats.total_blocks,
                bytes: stats.total_bytes,
                frames,
                payload_bytes,
                checksum,
                retained_bytes: 0,
            }
        }
        Probe::Retention | Probe::RetainedControl => {
            let io = Arc::new(Mutex::new(connection));
            // This path uses the real fill/reserve/read_buf, never the scripted-fill override.
            let profiler = dhat::Profiler::builder().testing().build();
            let parsed = read_request(Arc::clone(&io), 4096, HeaderTimeout::After(Duration::from_secs(5)))
                .await
                .expect("head reads")
                .expect("one request");
            assert_eq!(parsed.request.uri().path(), "/idle");
            assert!(!parsed.body_expected);
            drop(parsed);
            let mut locked = io.lock().await;
            assert!(locked.buffer.is_empty(), "fixture has no body or pipelined bytes");
            if matches!(probe, Probe::RetainedControl) {
                locked.buffer.reserve(8192);
            }
            let live = dhat::HeapStats::get();
            locked.buffer = BytesMut::new();
            let released = dhat::HeapStats::get();
            let retained_bytes = live
                .curr_bytes
                .checked_sub(released.curr_bytes)
                .expect("buffer release cannot grow the heap");
            drop(profiler);
            Observation {
                blocks: live.total_blocks,
                bytes: live.total_bytes,
                frames: 0,
                payload_bytes: 0,
                checksum: 0,
                retained_bytes,
            }
        }
    }
}

#[derive(Clone)]
struct ProbeDriver {
    probe: Probe,
    result: Arc<SyncMutex<Option<oneshot::Sender<Observation>>>>,
}

impl<S: Send + 'static> ConnectionDriver<S> for ProbeDriver {
    fn drive(&self, accepted: AcceptedConnection<S>) -> ConnectionFuture {
        let driver = self.clone();
        Box::pin(async move {
            let (stream, _service) = accepted.into_plaintext().expect("plaintext probe");
            let observation = observe(stream, driver.probe).await;
            let _ = driver
                .result
                .lock()
                .expect("sender lock")
                .take()
                .expect("one connection")
                .send(observation);
        })
    }
}

async fn run_probe(probe: Probe) -> Observation {
    let (sender, receiver) = oneshot::channel();
    let driver = ProbeDriver {
        probe,
        result: Arc::new(SyncMutex::new(Some(sender))),
    };
    let config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().expect("literal address"),
        plaintext: true,
        ..ServerConfig::default()
    };
    let server = Server::new(config, super::tests::UnusedService)
        .serve_with(driver)
        .expect("probe listener starts");
    let mut client = TcpStream::connect(server.local_addr).await.expect("probe connects");
    if matches!(probe, Probe::Retention | Probe::RetainedControl) {
        client
            .write_all(b"GET /idle HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("probe head writes");
    }
    let observation = tokio::time::timeout(Duration::from_secs(5), receiver)
        .await
        .expect("probe completes")
        .expect("probe reports");
    drop(client);
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    server.task.await.expect("server joins").expect("server stops");
    observation
}

fn child(test: &str) -> Vec<Vec<u64>> {
    let output = Command::new(std::env::current_exe().expect("test binary path"))
        .args(["--exact", test, "--nocapture"])
        .env(PROBE_ENV, "1")
        .output()
        .expect("isolated probe starts");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "probe failed: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix(SENTINEL))
        .map(|line| {
            let fields: Vec<u64> = line
                .split_whitespace()
                .map(|field| field.parse().expect("numeric observation"))
                .collect();
            assert_eq!(fields.len(), 6, "complete observation row");
            fields
        })
        .collect()
}

fn print_probe(probe: Probe) {
    allocator_observes_allocation_and_release();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("probe runtime");
    let observed = runtime.block_on(run_probe(probe));
    println!(
        "\n{SENTINEL}{} {} {} {} {} {}",
        observed.blocks, observed.bytes, observed.frames, observed.payload_bytes, observed.checksum, observed.retained_bytes
    );
}

#[test]
fn body_frame_allocations_do_not_scale_with_frame_count() {
    if std::env::var_os(PROBE_ENV).is_some() {
        print_probe(Probe::Frames(1));
        print_probe(Probe::Frames(64));
        return;
    }
    let rows = child("conn::request::cost_tests::body_frame_allocations_do_not_scale_with_frame_count");
    assert_eq!(rows.len(), 2, "both frame counts were measured");
    for (row, frames) in rows.iter().zip([1, 64]) {
        assert_eq!(row[2], frames, "actual data-frame count");
        assert_eq!(row[3], PAYLOAD_BYTES as u64, "equal payload consumed");
        assert_eq!(row[4], (PAYLOAD_BYTES * usize::from(b'x')) as u64, "every payload byte consumed");
    }
    println!("frame allocation observations: {rows:?}");
    assert!(rows[1][0] <= rows[0][0] + 8, "per-frame allocations remain: {rows:?}");
}

#[test]
fn idle_head_buffer_retention_is_bounded() {
    if std::env::var_os(PROBE_ENV).is_some() {
        print_probe(Probe::Retention);
        print_probe(Probe::RetainedControl);
        return;
    }
    let rows = child("conn::request::cost_tests::idle_head_buffer_retention_is_bounded");
    assert_eq!(rows.len(), 2, "normal and deliberately retained buffers were measured");
    assert!(rows[1][5] >= 8192, "observer must resolve known retained storage: {rows:?}");
    println!("idle allocation observation: {rows:?}");
    assert!(rows[0][5] <= 4096, "small idle head retains more than 4 KiB: {rows:?}");
}
