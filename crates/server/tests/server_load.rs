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

//! Real-load resident-memory and latency contracts for the listener.
//!
//! Responsible for: what a thousand concurrent connections cost in resident memory, what a
//! thousand readers parked on a stalled response cost the traffic beside them, and that the
//! write-progress deadline is the layer that retires them. NOT responsible for: the deadline
//! implementations themselves or single-connection timeout behaviour, which are next door in
//! `server_runtime.rs`. Upstream: rustfs/backlog#1699. Downstream: `docs/capacity-planning.md`.
//!
//! Every case here re-executes itself alone in a child process. A resident-set reading taken while
//! the rest of the suite is running measures the suite, not the case.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use rustfs_gateway_server::{RunningServer, Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tower::service_fn;

fn plaintext_config() -> ServerConfig {
    ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: Duration::from_millis(100),
        keep_alive_idle: Duration::from_millis(250),
        ..ServerConfig::default()
    }
}

fn echo_server(config: ServerConfig) -> RunningServer {
    let service = service_fn(|_request: Request<hyper::body::Incoming>| async {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
    });
    Server::new(config, service).serve().expect("server starts")
}

fn rss_bytes() -> Option<usize> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let kibibytes = String::from_utf8(output.stdout).ok()?.trim().parse::<usize>().ok()?;
    kibibytes.checked_mul(1024)
}

/// Tells a re-executed copy of this test binary that it is the isolated child.
const RSS_CHILD_MARKER: &str = "RUSTFS_GATEWAY_SERVER_RUNTIME_RSS_CHILD";

/// Re-runs `test_name` alone in a child process, so a resident-set reading belongs to that test
/// and not to whatever else the harness happens to be running beside it.
///
/// Returns `true` when this process *is* the isolated child and must do the work. The parent does
/// not trust the child's exit status on its own: `--exact` on a name libtest cannot find runs no
/// test and still exits zero, which reads exactly like a pass, so the summary line is checked too.
fn run_isolated(test_name: &str) -> bool {
    if std::env::var_os(RSS_CHILD_MARKER).is_some() {
        return true;
    }
    let output = Command::new(std::env::current_exe().expect("test executable path is available"))
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(RSS_CHILD_MARKER, "1")
        .output()
        .expect("the isolated child starts");
    let report = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "the isolated child for {test_name} failed:\n{report}");
    assert!(
        report.contains("1 passed"),
        "the isolated child for {test_name} ran no test, which is not the same as passing:\n{report}"
    );
    false
}

/// Opens `count` connections that stay open, one in ten carrying a complete request and one in ten
/// a half-written header, and returns them once the listener reports every one of them as active.
async fn mixed_load(addr: SocketAddr, metrics: &rustfs_gateway_server::ServerMetrics, count: usize) -> Vec<TcpStream> {
    let mut connections = Vec::with_capacity(count);
    for index in 0..count {
        let mut stream = TcpStream::connect(addr).await.expect("connection succeeds");
        if index % 10 == 0 {
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .expect("mixed-load request writes");
        } else if index % 10 == 1 {
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost:")
                .await
                .expect("mixed slow header writes");
        }
        connections.push(stream);
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        while metrics.active_connections() < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("every connection of the wave is admitted and still open");
    connections
}

/// c-lim-0006 / a-srv-0008. Positive — a thousand concurrent connections of mixed load stay
/// inside the per-connection resident budget, and a second identical wave does not buy a second
/// wave of memory. One wave alone only shows that the ceiling is survivable once; the claim the
/// task makes is that the bound is *predictable*, and a bound that is paid again on every wave is
/// not a bound at all.
#[tokio::test]
async fn c_lim_0006_a_srv_0008_one_thousand_connections_stay_inside_the_rss_budget() {
    const TEST_NAME: &str = "c_lim_0006_a_srv_0008_one_thousand_connections_stay_inside_the_rss_budget";
    const CONNECTIONS: usize = 1_000;
    /// Allocator and runtime noise between two readings of the same idle process.
    const REUSE_SLACK: usize = 8 * 1024 * 1024;
    if !run_isolated(TEST_NAME) {
        return;
    }
    let mut config = plaintext_config();
    // The wave has to still *be* a thousand open connections when the resident set is read, so
    // neither the header deadline nor the keep-alive gap may retire any of it first.
    config.header_read_timeout = Duration::from_secs(30);
    config.keep_alive_idle = Duration::from_secs(30);
    config.max_connections_per_ip = None;
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(config);
    let Some(before) = rss_bytes() else {
        eprintln!("SKIP c-lim-0006 / a-srv-0008: this runner cannot report RSS through ps");
        let _ = shutdown.trigger(Duration::from_secs(1)).await;
        let _ = task.await;
        return;
    };
    let first = mixed_load(local_addr, &metrics, CONNECTIONS).await;
    let loaded = rss_bytes().expect("RSS remains readable");
    let growth = loaded.saturating_sub(before);
    let budget = rustfs_gateway_server::conn_memory_budget(CONNECTIONS);
    eprintln!("c-lim-0006 first wave: growth_bytes={growth} budget_bytes={budget}");
    assert!(growth <= budget + budget / 2, "RSS growth {growth} exceeded the 1.5x budget");
    drop(first);
    tokio::time::timeout(Duration::from_secs(10), async {
        while metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the first wave is fully retired");
    let second = mixed_load(local_addr, &metrics, CONNECTIONS).await;
    let reloaded = rss_bytes().expect("RSS remains readable");
    let second_wave_growth = reloaded.saturating_sub(loaded);
    let wave_reuse_ceiling = REUSE_SLACK;
    eprintln!("c-lim-0006 second wave: growth_bytes={second_wave_growth} ceiling_bytes={wave_reuse_ceiling}");
    assert!(
        second_wave_growth <= wave_reuse_ceiling,
        "a second identical wave added {second_wave_growth} bytes against a {wave_reuse_ceiling}-byte ceiling: connection memory is accumulating per wave, not being reused"
    );
    drop(second);
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

/// Connects with a four-kibibyte receive window, so that a response larger than that window
/// cannot be absorbed by the client's kernel buffer and the server's write really does stall.
///
/// Without this the peer's default loopback receive buffer auto-tunes large enough to swallow the
/// whole response, the write never stalls, and a case about the write-progress deadline passes on
/// the keep-alive gap instead — which is exactly what this case did before the window was pinned.
async fn pinhole_connect(addr: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().expect("a v4 socket is available");
    socket.set_recv_buffer_size(4 * 1024).expect("the receive window is settable");
    socket.connect(addr).await.expect("slow reader connects")
}

/// Returns the 99th-percentile sample, which is the worst of a hundred and not the average of them.
fn p99(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    let index = samples.len().saturating_mul(99) / 100;
    let last = samples.len().saturating_sub(1);
    samples[index.min(last)]
}

/// Times one complete request/response on its own connection, charging a stalled probe the full
/// ceiling rather than hanging the test on it.
async fn healthy_probe(addr: SocketAddr, ceiling: Duration) -> Duration {
    let started = std::time::Instant::now();
    let probe = async {
        let mut stream = TcpStream::connect(addr).await.expect("probe connects");
        stream
            .write_all(b"GET /healthy HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("probe request writes");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("probe response reads");
        response
    };
    match tokio::time::timeout(ceiling, probe).await {
        Ok(response) => {
            assert!(response.starts_with(b"HTTP/1.1 200"), "the healthy probe was answered");
            started.elapsed()
        }
        Err(_) => ceiling,
    }
}

/// Collects `count` sequential probe latencies and returns their 99th percentile.
async fn probe_p99(addr: SocketAddr, count: usize, ceiling: Duration) -> Duration {
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        samples.push(healthy_probe(addr, ceiling).await);
    }
    p99(samples)
}

/// Opens `count` connections and returns once the listener reports every one of them as active.
///
/// No request is written here on purpose. The write-progress deadline starts at a connection's
/// first stalled write, so a wave that asked for the stalling response while it was still being
/// opened would have its earliest members retired before its last ones were admitted, and the
/// census below would never see the whole wave at once.
async fn park_slow_readers(addr: SocketAddr, metrics: &rustfs_gateway_server::ServerMetrics, count: usize) -> Vec<TcpStream> {
    let mut readers = Vec::with_capacity(count);
    for _ in 0..count {
        readers.push(pinhole_connect(addr).await);
    }
    if tokio::time::timeout(Duration::from_secs(15), async {
        while metrics.active_connections() < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_err()
    {
        panic!(
            "only {} of {count} slow readers were admitted (accepted {}, per-ip rejections {})",
            metrics.active_connections(),
            metrics.accepted_connections(),
            metrics.per_ip_rejections()
        );
    }
    readers
}

/// Asks every parked reader for the stalling response, then takes exactly one byte from each and
/// stops.
///
/// One byte each, and then nothing: a reader that never reads at all is a closed window, and the
/// layer under test is an *interval* deadline, so the interval has to start somewhere.
async fn stall_slow_readers(readers: &mut [TcpStream]) {
    for reader in readers.iter_mut() {
        reader
            .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("slow reader request writes");
    }
    for reader in readers.iter_mut() {
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut byte))
            .await
            .expect("the stalled response is already flowing")
            .expect("the slow reader takes its one byte");
        assert_eq!(read, 1, "the slow reader takes exactly one byte and then stops");
    }
}

/// Returns how long the write-progress deadline took to retire every stalled reader.
async fn retire_slow_readers(readers: Vec<TcpStream>, metrics: &rustfs_gateway_server::ServerMetrics) -> Duration {
    let stalled_at = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(15), async {
        while metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the write-progress deadline retires every slow reader");
    let closed_after = stalled_at.elapsed();
    drop(readers);
    closed_after
}

/// c-lim-0061 / a-srv-0026. Negative — a thousand slow readers, each of which takes one byte and
/// then stops, are all closed by the write-progress deadline; a healthy connection's p99 does not
/// degrade while they are parked; resident memory while they are parked stays inside the
/// per-connection budget; and a second identical wave does not buy a second wave of memory.
///
/// The four observations are separate on purpose. That the deadline fires says nothing about what
/// the parked connections cost the connections beside them, and neither says anything about the
/// memory — the task asks for all of it, and each is measured here rather than inferred from the
/// others.
///
/// The last one is a *reuse* measurement and not a return-to-baseline one, deliberately. A freed
/// allocation is not a shrinking resident set: the allocator is free to keep the pages, and on
/// this platform it does, so "RSS came back down" is a claim this harness cannot make honestly.
/// What it can observe is that a second wave costs a fraction of the first — which is the thing
/// an unbounded-growth defect would fail, and the thing a return-to-baseline reading would only
/// have implied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic() {
    const TEST_NAME: &str = "c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic";
    const SLOW_READERS: usize = 1_000;
    const PROBES: usize = 100;
    /// Larger than any socket buffer a loopback peer will auto-tune to, so the response really
    /// does stall. One allocation is shared by every reader: what this case measures is what a
    /// *connection* costs while it is parked, and a private body per reader would bury that under
    /// a number the server does not own.
    const RESPONSE_LEN: usize = 8 * 1024 * 1024;
    /// A probe that has not been answered inside this is a stalled probe, not a slow one.
    const PROBE_CEILING: Duration = Duration::from_secs(5);
    /// Allocator and runtime noise between two readings of the same process.
    const REUSE_SLACK: usize = 8 * 1024 * 1024;
    if !run_isolated(TEST_NAME) {
        return;
    }
    let mut config = plaintext_config();
    config.header_read_timeout = Duration::from_secs(30);
    config.max_connections_per_ip = None;
    config.so_sndbuf = Some(4 * 1024);
    // Sixty seconds is not a timeout this test can reach; it is here so that the only layer that
    // can retire a parked reader inside the waits below is the write-progress deadline.
    config.keep_alive_idle = Duration::from_secs(60);
    config.write_progress_timeout = Duration::from_secs(3);
    let stalling_body = Bytes::from(vec![b'x'; RESPONSE_LEN]);
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let body = if request.uri().path() == "/healthy" {
            Bytes::from_static(b"ok")
        } else {
            stalling_body.clone()
        };
        async move { Ok::<_, Infallible>(Response::new(Full::new(body))) }
    });
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = Server::new(config, service).serve().expect("server starts");
    let Some(before) = rss_bytes() else {
        eprintln!("SKIP c-lim-0061 / a-srv-0026: this runner cannot report RSS through ps");
        let _ = shutdown.trigger(Duration::from_secs(1)).await;
        let _ = task.await;
        return;
    };

    let unloaded = probe_p99(local_addr, PROBES, PROBE_CEILING).await;
    let mut first_wave = park_slow_readers(local_addr, &metrics, SLOW_READERS).await;
    stall_slow_readers(&mut first_wave).await;

    let parked = rss_bytes().expect("RSS remains readable");
    let parked_growth = parked.saturating_sub(before);
    let parked_budget = rustfs_gateway_server::conn_memory_budget(SLOW_READERS);
    eprintln!("c-lim-0061 parked: growth_bytes={parked_growth} budget_bytes={parked_budget}");
    assert!(
        parked_growth <= parked_budget,
        "{SLOW_READERS} parked slow readers grew the resident set by {parked_growth} bytes, past the {parked_budget}-byte per-connection budget"
    );

    let loaded = probe_p99(local_addr, PROBES, PROBE_CEILING).await;
    let ceiling = unloaded.saturating_mul(8) + Duration::from_millis(100);
    eprintln!("c-lim-0061 p99: unloaded={unloaded:?} loaded={loaded:?} ceiling={ceiling:?}");
    assert!(
        loaded <= ceiling,
        "a healthy connection's p99 went from {unloaded:?} to {loaded:?} while {SLOW_READERS} slow readers were parked, past the {ceiling:?} ceiling"
    );

    let first_closure = retire_slow_readers(first_wave, &metrics).await;
    let after_first = rss_bytes().expect("RSS remains readable");
    let first_growth = after_first.saturating_sub(before);

    let mut second_wave = park_slow_readers(local_addr, &metrics, SLOW_READERS).await;
    stall_slow_readers(&mut second_wave).await;
    let second_closure = retire_slow_readers(second_wave, &metrics).await;
    let after_second = rss_bytes().expect("RSS remains readable");
    let second_growth = after_second.saturating_sub(after_first);
    let reuse_ceiling = REUSE_SLACK;
    eprintln!("c-lim-0061 closure: first={first_closure:?} second={second_closure:?}");
    eprintln!("c-lim-0061 reuse: first_bytes={first_growth} second_bytes={second_growth} ceiling_bytes={reuse_ceiling}");
    assert!(
        second_growth <= reuse_ceiling,
        "a second wave of {SLOW_READERS} slow readers added {second_growth} bytes against a {reuse_ceiling}-byte ceiling: the memory a retired slow reader owned is accumulating, not being reused"
    );

    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}
