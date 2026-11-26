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

//! Graceful shutdown tracking for detached peer-loss cleanup and HTTP/2 stream tasks.
//!
//! Responsible for: proving `ShutdownTrigger::trigger` waits for detached peer-loss cleanup and
//! HTTP/2 stream tasks within its grace budget and aborts them when grace expires.
//! NOT responsible for: connection-level write receipts (`shutdown_drain.rs`) or blocking file
//! transfer shutdown (`conn/file_transfer_shutdown_tests.rs`).
//! Upstream: rustfs/gateway#1632. Downstream: the public server API.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{Empty, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustfs_gateway_server::{RequestCancellation, Server, ServerConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tower::service_fn;

fn config() -> ServerConfig {
    ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: Duration::from_secs(5),
        ..ServerConfig::default()
    }
}

struct DropMarker(Arc<AtomicBool>);

impl Drop for DropMarker {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Negative — a detached peer-loss cleanup task must complete before `ShutdownTrigger::trigger`
/// reports a clean shutdown.
#[tokio::test]
async fn n_shutdown_waits_for_detached_peer_loss_cleanup_before_returning() {
    let handler_entered = Arc::new(Notify::new());
    let cleanup_started = Arc::new(Notify::new());
    let cleanup_release = Arc::new(Notify::new());
    let cleanup_finished = Arc::new(AtomicBool::new(false));
    let service = service_fn({
        let handler_entered = Arc::clone(&handler_entered);
        let cleanup_started = Arc::clone(&cleanup_started);
        let cleanup_release = Arc::clone(&cleanup_release);
        let cleanup_finished = Arc::clone(&cleanup_finished);
        move |request: Request<hyper::body::Incoming>| {
            let handler_entered = Arc::clone(&handler_entered);
            let cleanup_started = Arc::clone(&cleanup_started);
            let cleanup_release = Arc::clone(&cleanup_release);
            let cleanup_finished = Arc::clone(&cleanup_finished);
            async move {
                let mut cancellation = request
                    .extensions()
                    .get::<RequestCancellation>()
                    .cloned()
                    .expect("server inserts RequestCancellation");
                handler_entered.notify_one();
                while !*cancellation.borrow() {
                    cancellation
                        .changed()
                        .await
                        .expect("cancellation channel stays open until peer loss");
                }
                cleanup_started.notify_one();
                cleanup_release.notified().await;
                cleanup_finished.store(true, Ordering::SeqCst);
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        }
    });
    let server = Server::new(config(), service).serve().expect("server starts");

    let mut client = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    tokio::time::timeout(Duration::from_secs(2), handler_entered.notified())
        .await
        .expect("handler enters");
    // Drop the client socket so Hyper cancels the connection and detaches cleanup.
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), cleanup_started.notified())
        .await
        .expect("detached peer-loss cleanup begins");

    // Wait until the connection task itself has exited so only the detached cleanup remains.
    tokio::time::timeout(Duration::from_secs(2), async {
        while server.metrics.active_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("connection task finishes after peer disconnect");

    let mut shutdown = tokio::spawn(server.shutdown.trigger(Duration::from_secs(5)));
    assert!(
        tokio::time::timeout(Duration::from_millis(80), &mut shutdown).await.is_err(),
        "shutdown reported clean completion while detached peer-loss cleanup was still running"
    );
    assert!(!cleanup_finished.load(Ordering::SeqCst), "cleanup has not been released yet");

    cleanup_release.notify_one();
    let report = tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .expect("shutdown finishes promptly once detached cleanup ends")
        .expect("shutdown task joins");
    assert!(
        cleanup_finished.load(Ordering::SeqCst),
        "detached cleanup completed before shutdown returned"
    );
    assert_eq!(report.aborted, 0, "cleanly drained cleanup is not force-aborted");
    assert!(server.task.await.expect("server task joins").is_ok());
}

/// Negative — a detached peer-loss cleanup task that outlives the shutdown grace budget is
/// force-aborted and dropped before `ShutdownTrigger::trigger` returns.
#[tokio::test]
async fn n_shutdown_grace_expiry_aborts_stuck_detached_peer_loss_cleanup() {
    let handler_entered = Arc::new(Notify::new());
    let cleanup_started = Arc::new(Notify::new());
    let dropped = Arc::new(AtomicBool::new(false));
    let service = service_fn({
        let handler_entered = Arc::clone(&handler_entered);
        let cleanup_started = Arc::clone(&cleanup_started);
        let dropped = Arc::clone(&dropped);
        move |request: Request<hyper::body::Incoming>| {
            let handler_entered = Arc::clone(&handler_entered);
            let cleanup_started = Arc::clone(&cleanup_started);
            let dropped = Arc::clone(&dropped);
            async move {
                let _marker = DropMarker(dropped);
                let mut cancellation = request
                    .extensions()
                    .get::<RequestCancellation>()
                    .cloned()
                    .expect("server inserts RequestCancellation");
                handler_entered.notify_one();
                while !*cancellation.borrow() {
                    cancellation
                        .changed()
                        .await
                        .expect("cancellation channel stays open until peer loss");
                }
                cleanup_started.notify_one();
                std::future::pending::<()>().await;
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        }
    });
    let server = Server::new(config(), service).serve().expect("server starts");

    let mut client = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    tokio::time::timeout(Duration::from_secs(2), handler_entered.notified())
        .await
        .expect("handler enters");
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), cleanup_started.notified())
        .await
        .expect("detached peer-loss cleanup begins");

    tokio::time::timeout(Duration::from_secs(2), async {
        while server.metrics.active_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("connection task finishes after peer disconnect");

    let report = tokio::time::timeout(Duration::from_secs(2), server.shutdown.trigger(Duration::from_millis(50)))
        .await
        .expect("shutdown respects its grace budget");
    assert!(
        dropped.load(Ordering::SeqCst),
        "stuck detached cleanup future must be aborted and dropped before shutdown returns"
    );
    assert_eq!(report.aborted, 1, "aborted detached cleanup is accounted for");
    assert!(server.task.await.expect("server task joins").is_ok());
}

/// Negative — an HTTP/2 stream task whose peer disconnected must still be tracked by graceful
/// shutdown until it finishes within grace or is aborted at grace expiry.
#[tokio::test]
async fn n_shutdown_tracks_http2_stream_tasks_after_peer_disconnect() {
    let handler_entered = Arc::new(Notify::new());
    let cleanup_started = Arc::new(Notify::new());
    let cleanup_release = Arc::new(Notify::new());
    let cleanup_finished = Arc::new(AtomicBool::new(false));
    let service = service_fn({
        let handler_entered = Arc::clone(&handler_entered);
        let cleanup_started = Arc::clone(&cleanup_started);
        let cleanup_release = Arc::clone(&cleanup_release);
        let cleanup_finished = Arc::clone(&cleanup_finished);
        move |request: Request<hyper::body::Incoming>| {
            let handler_entered = Arc::clone(&handler_entered);
            let cleanup_started = Arc::clone(&cleanup_started);
            let cleanup_release = Arc::clone(&cleanup_release);
            let cleanup_finished = Arc::clone(&cleanup_finished);
            async move {
                let mut cancellation = request
                    .extensions()
                    .get::<RequestCancellation>()
                    .cloned()
                    .expect("server inserts RequestCancellation");
                handler_entered.notify_one();
                while !*cancellation.borrow() {
                    if cancellation.changed().await.is_err() {
                        break;
                    }
                }
                cleanup_started.notify_one();
                cleanup_release.notified().await;
                cleanup_finished.store(true, Ordering::SeqCst);
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        }
    });
    let server = Server::new(config(), service).serve().expect("server starts");

    let stream = TokioIo::new(TcpStream::connect(server.local_addr).await.expect("TCP connects"));
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(stream)
        .await
        .expect("h2 handshake succeeds");
    let conn_task = tokio::spawn(connection);
    let response_fut = sender.send_request(
        Request::get("http://localhost/")
            .body(Empty::<Bytes>::new())
            .expect("request"),
    );
    let request_task = tokio::spawn(response_fut);
    tokio::time::timeout(Duration::from_secs(2), handler_entered.notified())
        .await
        .expect("h2 handler enters");

    // Tear down the client connection abruptly so the server's H2 connection exits while the stream task cleans up.
    request_task.abort();
    conn_task.abort();
    drop(sender);
    tokio::time::timeout(Duration::from_secs(2), cleanup_started.notified())
        .await
        .expect("h2 stream cleanup begins");

    let mut shutdown = tokio::spawn(server.shutdown.trigger(Duration::from_secs(5)));
    assert!(
        tokio::time::timeout(Duration::from_millis(80), &mut shutdown).await.is_err(),
        "shutdown returned while HTTP/2 stream task was still running"
    );

    cleanup_release.notify_one();
    let report = tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .expect("shutdown finishes once HTTP/2 stream completes")
        .expect("shutdown task joins");
    assert!(
        cleanup_finished.load(Ordering::SeqCst),
        "HTTP/2 stream cleanup completed before shutdown returned"
    );
    assert_eq!(report.aborted, 0);
    assert!(server.task.await.expect("server task joins").is_ok());
}
