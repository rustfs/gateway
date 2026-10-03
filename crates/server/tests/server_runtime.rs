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

//! Live socket acceptance contracts for connection admission and shutdown.
//!
//! Responsible for: observable listener, connection limit, panic containment and three-phase
//! shutdown behaviour. NOT responsible for: TLS certificate replacement, covered separately.
//! Upstream: rustfs/backlog#1739. Downstream: the public server API.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[cfg(unix)]
#[path = "server_runtime/accept_recovery.rs"]
mod accept_recovery;
#[path = "server_runtime/connection_driver.rs"]
mod connection_driver;
#[path = "server_runtime/drain_fixture.rs"]
mod drain_fixture;
pub(crate) use drain_fixture::observed_shutdown_drain;
#[path = "server_runtime/frozen_clock.rs"]
pub(crate) mod frozen_clock;
#[path = "server_runtime/global_admission.rs"]
mod global_admission;
#[path = "server_runtime/shutdown_drain.rs"]
mod shutdown_drain;
#[path = "server_runtime/task_reaping.rs"]
mod task_reaping;
#[path = "server_runtime/unbounded_timeouts.rs"]
mod unbounded_timeouts;

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use rustfs_gateway_server::{ConnectionInfo, Listener, RequestCancellation, RunningServer, Server, ServerConfig, ShutdownReport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
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

async fn get(addr: SocketAddr) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.expect("connect succeeds");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("response reads");
    response
}

#[cfg(target_os = "linux")]
fn linux_listener_backlog(addr: SocketAddr) -> usize {
    let output = Command::new("ss").arg("-ltn").output().expect("Linux acceptance requires ss");
    assert!(output.status.success(), "ss -ltn must report listening sockets");
    let text = String::from_utf8(output.stdout).expect("ss output is UTF-8");
    let port = format!(":{}", addr.port());
    let fields = text
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|fields| fields.get(3).is_some_and(|local| local.ends_with(&port)))
        .expect("ss reports the test listener");
    fields[2].parse().expect("ss Send-Q is the effective listen backlog")
}

#[tokio::test]
async fn a_srv_0001_serves_one_hundred_concurrent_requests() {
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = echo_server(plaintext_config());
    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..100 {
        clients.spawn(get(local_addr));
    }
    while let Some(result) = clients.join_next().await {
        let response = result.expect("client task completes");
        assert!(response.starts_with(b"HTTP/1.1 200"));
    }
    assert_eq!(shutdown.trigger(Duration::from_secs(1)).await, ShutdownReport { drained: 0, aborted: 0 });
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_srv_0002_dual_stack_listener_accepts_v4_and_v6() {
    let mut config = ServerConfig {
        bind_addr: "[::]:0".parse().expect("fixture address"),
        plaintext: true,
        dual_stack: true,
        ..ServerConfig::default()
    };
    config.header_read_timeout = Duration::from_secs(1);
    let running = match std::panic::catch_unwind(|| echo_server(config)) {
        Ok(running) => running,
        Err(_) => {
            eprintln!("SKIP a-srv-0002: this runner has no dual-stack IPv6 listener");
            return;
        }
    };
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = running;
    let port = local_addr.port();
    let v6 = get(SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port));
    let v4 = get(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    let (v6, v4) = tokio::join!(v6, v4);
    assert!(v6.starts_with(b"HTTP/1.1 200"));
    assert!(v4.starts_with(b"HTTP/1.1 200"));
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_srv_0003_listener_options_are_read_back_from_the_socket() {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        so_rcvbuf: Some(64 * 1024),
        so_sndbuf: Some(64 * 1024),
        tcp_nodelay: true,
        backlog: 32,
        reuse_address: true,
        ..ServerConfig::default()
    };
    let listener = Listener::bind(&config).expect("listener binds");
    let observed = listener.options();
    assert!(observed.reuse_address);
    assert!(observed.keepalive);
    assert!(observed.tcp_nodelay);
    assert!(
        observed.recv_buffer_size >= 64 * 1024,
        "kernel must not lower the requested receive buffer"
    );
    assert!(observed.send_buffer_size >= 64 * 1024, "kernel must not lower the requested send buffer");
    #[cfg(target_os = "linux")]
    assert_eq!(
        linux_listener_backlog(listener.local_addr().expect("listener address")),
        config.backlog as usize
    );
    #[cfg(not(target_os = "linux"))]
    eprintln!("SKIP backlog read-back: ss -ltn is a Linux-only observation");
    drop(listener);

    let (nodelay_sender, nodelay_receiver) = tokio::sync::oneshot::channel();
    let nodelay_sender = std::sync::Arc::new(std::sync::Mutex::new(Some(nodelay_sender)));
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let nodelay_sender = std::sync::Arc::clone(&nodelay_sender);
        async move {
            let observed = request
                .extensions()
                .get::<ConnectionInfo>()
                .expect("connection facts are inserted");
            if let Some(sender) = nodelay_sender.lock().expect("fixture lock").take() {
                let _ = sender.send(observed.tcp_nodelay());
            }
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        }
    });
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(config, service).serve().expect("server starts");
    assert!(get(local_addr).await.starts_with(b"HTTP/1.1 200"));
    assert!(nodelay_receiver.await.expect("handler observes the accepted socket"));
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_srv_0006_in_flight_request_drains_before_grace() {
    observed_shutdown_drain(|| {}).await;
}

#[tokio::test]
async fn c_lim_0035_a_srv_0011_a_one_byte_slow_reader_triggers_the_write_progress_timeout() {
    const BODY_LEN: usize = 100 * 1024 * 1024;
    let mut config = plaintext_config();
    config.so_sndbuf = Some(4 * 1024);
    config.keep_alive_idle = Duration::from_secs(60);
    config.write_progress_timeout = Duration::from_millis(20);
    let service = service_fn(|_request: Request<hyper::body::Incoming>| async {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(vec![b'x'; BODY_LEN]))))
    });
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = Server::new(config, service).serve().expect("server starts");
    let mut stream = TcpStream::connect(local_addr).await.expect("connect succeeds");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    tokio::time::timeout(Duration::from_secs(1), async {
        while metrics.active_connections() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the slow reader owns one admitted connection");
    let bytes_read = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let slow_reader = tokio::spawn({
        let bytes_read = std::sync::Arc::clone(&bytes_read);
        async move {
            let mut byte = [0_u8; 1];
            loop {
                match stream.read(&mut byte).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        bytes_read.fetch_add(read, std::sync::atomic::Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the one-byte-per-second reader stalls the 100 MiB response");
    assert!(bytes_read.load(std::sync::atomic::Ordering::Relaxed) <= 2);
    slow_reader.abort();
    let _ = slow_reader.await;
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn c_lim_0036_an_idle_keep_alive_connection_closes_after_one_gap() {
    let mut config = plaintext_config();
    config.header_read_timeout = Duration::from_secs(1);
    config.keep_alive_idle = Duration::from_millis(40);
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(config);
    let mut stream = TcpStream::connect(local_addr).await.expect("connect succeeds");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("keep-alive request writes");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut buffer = [0_u8; 1024];
        while !response.windows(b"\r\n\r\nok".len()).any(|window| window == b"\r\n\r\nok") {
            let read = stream.read(&mut buffer).await.expect("response reads");
            assert_ne!(read, 0, "the connection closed before the response completed");
            response.extend_from_slice(&buffer[..read]);
        }
    })
    .await
    .expect("the response arrives before the idle interval");
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(
        !String::from_utf8_lossy(&response)
            .to_ascii_lowercase()
            .contains("connection: close")
    );
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_millis(250), stream.read_to_end(&mut tail))
        .await
        .expect("the idle deadline closes the socket")
        .expect("idle close reaches EOF");
    assert!(tail.is_empty(), "no second response was written");
    tokio::time::timeout(Duration::from_millis(250), async {
        while metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the idle connection releases its admission permit");
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn c_lim_0038_in_flight_request_limit_pauses_accept_before_the_next_socket() {
    let mut config = plaintext_config();
    config.max_global_inflight_requests = 1;
    let entered = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let release = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let service = service_fn({
        let entered = entered.clone();
        let release = release.clone();
        let calls = calls.clone();
        move |_request: Request<hyper::body::Incoming>| {
            let entered = entered.clone();
            let release = release.clone();
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if call == 0 {
                    entered.wait().await;
                    release.wait().await;
                }
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        }
    });
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = Server::new(config, service).serve().expect("server starts");

    let mut first = TcpStream::connect(local_addr).await.expect("first connection succeeds");
    first
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("first request writes");
    entered.wait().await;

    let mut second = TcpStream::connect(local_addr)
        .await
        .expect("the kernel completes the second TCP handshake");
    second
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("the queued connection accepts request bytes");
    let accepted_early = tokio::time::timeout(Duration::from_millis(50), async {
        while metrics.accepted_connections() == 1 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(accepted_early.is_err(), "request exhaustion must pause the listener before accept");
    assert_eq!(metrics.accepted_connections(), 1, "the second socket remains in the kernel backlog");
    let mut probe = [0_u8; 1];
    let error = second
        .try_read(&mut probe)
        .expect_err("the queued socket has neither a response nor EOF/RST");
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

    release.wait().await;
    let mut first_response = Vec::new();
    first.read_to_end(&mut first_response).await.expect("first response reads");
    assert!(first_response.starts_with(b"HTTP/1.1 200"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while metrics.accepted_connections() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("releasing the request permit lets the accept loop take the queued socket");
    let mut second_response = Vec::new();
    second.read_to_end(&mut second_response).await.expect("second response reads");
    assert!(second_response.starts_with(b"HTTP/1.1 200"));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);

    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_srv_0013_slow_headers_do_not_block_a_healthy_connection() {
    let _exclusive_load_lease = crate::server_load::exclusive_server_load_lease().await;
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(plaintext_config());
    let slow = frozen_clock::with_header_clock_frozen(async {
        let mut slow = Vec::new();
        for _ in 0..100 {
            let mut stream = TcpStream::connect(local_addr).await.expect("slow connection succeeds");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost:")
                .await
                .expect("partial header writes");
            slow.push(stream);
        }
        while metrics.active_connections() != 100 || metrics.accepted_connections() != 100 {
            tokio::task::yield_now().await;
        }
        let healthy = get(local_addr).await;
        assert!(healthy.starts_with(b"HTTP/1.1 200"));
        assert_eq!(metrics.accepted_connections(), 101);
        slow
    })
    .await;
    drop(slow);
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_srv_0016_expired_grace_reports_one_aborted_request() {
    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let started_sender = std::sync::Arc::new(std::sync::Mutex::new(Some(started_sender)));
    let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
        let started_sender = std::sync::Arc::clone(&started_sender);
        async move {
            if let Some(sender) = started_sender.lock().expect("fixture lock").take() {
                let _ = sender.send(());
            }
            std::future::pending::<Result<Response<Full<Bytes>>, Infallible>>().await
        }
    });
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(plaintext_config(), service).serve().expect("server starts");
    let client = tokio::spawn(get(local_addr));
    started_receiver.await.expect("handler is in flight before shutdown");
    let report = shutdown.trigger(Duration::from_millis(20)).await;
    assert_eq!(report, ShutdownReport { drained: 0, aborted: 1 });
    assert!(task.await.expect("server task joins").is_ok());
    let _ = client.await;
}

#[tokio::test]
async fn a_srv_0017_shutdown_closes_the_listener_before_new_connections() {
    let entered = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let release = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let service = service_fn({
        let entered = std::sync::Arc::clone(&entered);
        let release = std::sync::Arc::clone(&release);
        move |_request: Request<hyper::body::Incoming>| {
            let entered = std::sync::Arc::clone(&entered);
            let release = std::sync::Arc::clone(&release);
            async move {
                entered.wait().await;
                release.wait().await;
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        }
    });
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(plaintext_config(), service).serve().expect("server starts");
    let client = tokio::spawn(get(local_addr));
    entered.wait().await;
    let shutdown_task = tokio::spawn(shutdown.trigger(Duration::from_secs(5)));
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match TcpStream::connect(local_addr).await {
                Ok(stream) => drop(stream),
                Err(_) => break,
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("listener closes while the in-flight handler remains blocked");
    assert!(!shutdown_task.is_finished(), "shutdown waits for the in-flight handler");
    assert!(!client.is_finished(), "the in-flight response has not completed");

    release.wait().await;
    let report = shutdown_task.await.expect("shutdown task joins");
    assert_eq!(report, ShutdownReport { drained: 1, aborted: 0 });
    assert!(client.await.expect("client task joins").starts_with(b"HTTP/1.1 200"));
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn dropping_the_trigger_does_not_become_an_implicit_shutdown_path() {
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = echo_server(plaintext_config());
    drop(shutdown);
    tokio::task::yield_now().await;
    assert!(get(local_addr).await.starts_with(b"HTTP/1.1 200"));
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn a_srv_0018_shutdown_announces_close_on_an_established_h1_connection() {
    let entered = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let release = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let service = service_fn({
        let entered = std::sync::Arc::clone(&entered);
        let release = std::sync::Arc::clone(&release);
        move |_request: Request<hyper::body::Incoming>| {
            let entered = std::sync::Arc::clone(&entered);
            let release = std::sync::Arc::clone(&release);
            async move {
                entered.wait().await;
                release.wait().await;
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        }
    });
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(plaintext_config(), service).serve().expect("server starts");
    let mut stream = TcpStream::connect(local_addr).await.expect("connect succeeds");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    entered.wait().await;
    let shutdown_task = tokio::spawn(shutdown.trigger(Duration::from_secs(5)));
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match TcpStream::connect(local_addr).await {
                Ok(stream) => drop(stream),
                Err(_) => break,
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown has stopped accept before the handler is released");
    assert!(!shutdown_task.is_finished(), "shutdown is still draining the established request");
    release.wait().await;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("draining response reads");
    let lower = String::from_utf8_lossy(&response).to_ascii_lowercase();
    assert!(lower.contains("connection: close"));
    assert_eq!(
        shutdown_task.await.expect("shutdown task joins"),
        ShutdownReport { drained: 1, aborted: 0 }
    );
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_srv_0019_client_reset_releases_the_connection_permit() {
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(plaintext_config());
    let mut stream = TcpStream::connect(local_addr).await.expect("connect succeeds");
    tokio::time::timeout(Duration::from_secs(1), async {
        while metrics.active_connections() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the connection owns one admission permit before reset");
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000000\r\n\r\nx")
        .await
        .expect("partial body writes");
    let socket = socket2::Socket::from(stream.into_std().expect("stream converts"));
    socket.set_linger(Some(Duration::ZERO)).expect("RST linger configures");
    drop(socket);
    tokio::time::timeout(Duration::from_secs(1), async {
        while metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("connection permit is released");
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_client_reset_signals_request_cancellation_before_the_permit_is_reused() {
    let entered = Arc::new(Notify::new());
    let rollback = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let service = service_fn({
        let entered = Arc::clone(&entered);
        let rollback = Arc::clone(&rollback);
        let calls = Arc::clone(&calls);
        move |request: Request<hyper::body::Incoming>| {
            let entered = Arc::clone(&entered);
            let rollback = Arc::clone(&rollback);
            let calls = Arc::clone(&calls);
            async move {
                if calls.fetch_add(1, Ordering::AcqRel) == 0 {
                    let mut cancellation = request
                        .extensions()
                        .get::<RequestCancellation>()
                        .cloned()
                        .expect("the server inserts request cancellation");
                    entered.notify_one();
                    while !*cancellation.borrow() {
                        if cancellation.changed().await.is_err() {
                            core::future::pending::<()>().await;
                        }
                    }
                    rollback.store(true, Ordering::Release);
                }
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        }
    });
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(
        ServerConfig {
            max_global_inflight_requests: 1,
            ..plaintext_config()
        },
        service,
    )
    .serve()
    .expect("server starts");

    let mut reset = TcpStream::connect(local_addr).await.expect("first connection succeeds");
    reset
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("first request writes");
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("the first request enters the service");
    let socket = socket2::Socket::from(reset.into_std().expect("stream converts"));
    socket.set_linger(Some(Duration::ZERO)).expect("RST linger configures");
    drop(socket);

    tokio::time::timeout(Duration::from_secs(1), async {
        while !rollback.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("request cancellation reaches cleanup after reset");
    let response = tokio::time::timeout(Duration::from_secs(1), get(local_addr))
        .await
        .expect("the released permit admits another request");
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 "));

    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}

#[tokio::test]
async fn a_srv_0020_panicking_handler_returns_500_and_server_survives() {
    let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
        if request.uri().path() == "/panic" {
            panic!("fixture panic");
        }
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
    });
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = Server::new(plaintext_config(), service).serve().expect("server starts");
    let mut stream = TcpStream::connect(local_addr).await.expect("connect succeeds");
    stream
        .write_all(b"GET /panic HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("panic request writes");
    let mut response = [0_u8; 256];
    let read = stream.read(&mut response).await.expect("panic response reads");
    assert!(response[..read].starts_with(format!("HTTP/1.1 {}", StatusCode::INTERNAL_SERVER_ERROR.as_u16()).as_bytes()));
    stream
        .write_all(b"GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("second request writes");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("second response reads");
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let _ = shutdown.trigger(Duration::from_secs(1)).await;
    assert!(task.await.expect("server task joins").is_ok());
}
