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

//! Graceful close and hard fallback on `ServerConfig::connection_lifetime` expiry.
//!
//! Responsible for: proving `connection_lifetime` initiates `graceful_shutdown` so in-flight
//! HTTP/1.1 and HTTP/2 requests finish cleanly before closing, while hung connections are still
//! dropped after the hard drain bound.
//! NOT responsible for: global server shutdown (`shutdown_drain.rs`, `shutdown_tracking.rs`).
//! Upstream: rustfs/gateway#1632. Downstream: the public server API.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustfs_gateway_server::{Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tower::service_fn;

/// Negative — expiring `connection_lifetime` while an HTTP/1.1 request is in flight must not
/// hard-drop the socket mid-response; it must gracefully complete the in-flight response and then
/// close the connection.
#[tokio::test]
async fn n_connection_lifetime_gracefully_completes_inflight_http1_and_closes() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let service = service_fn({
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        move |_request: Request<hyper::body::Incoming>| {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            async move {
                entered.notify_one();
                release.notified().await;
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"graceful-h1"))))
            }
        }
    });
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        connection_lifetime: Some(Duration::from_millis(60)),
        write_progress_timeout: Duration::from_secs(2),
        lingering_close_time: Duration::from_millis(200),
        header_read_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let server = Server::new(config, service).serve().expect("server starts");

    let mut client = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .expect("handler enters");

    // Let connection_lifetime expire while the handler is still running.
    tokio::time::sleep(Duration::from_millis(120)).await;
    release.notify_one();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .expect("response completes and socket closes cleanly")
        .expect("read succeeds");
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 200") && text.contains("graceful-h1"),
        "in-flight HTTP/1.1 response must finish gracefully on lifetime expiry, got: {text:?}"
    );
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(server.task.await.expect("server joins").is_ok());
}

/// Negative — expiring `connection_lifetime` while an HTTP/2 stream is in flight must send GOAWAY
/// and let the in-flight stream complete instead of hard-dropping it.
#[tokio::test]
async fn n_connection_lifetime_gracefully_completes_inflight_http2_with_goaway() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let service = service_fn({
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        move |_request: Request<hyper::body::Incoming>| {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            async move {
                entered.notify_one();
                release.notified().await;
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"graceful-h2"))))
            }
        }
    });
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        connection_lifetime: Some(Duration::from_millis(60)),
        write_progress_timeout: Duration::from_secs(2),
        lingering_close_time: Duration::from_millis(200),
        header_read_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let server = Server::new(config, service).serve().expect("server starts");

    let stream = TokioIo::new(TcpStream::connect(server.local_addr).await.expect("TCP connects"));
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(stream)
        .await
        .expect("h2 handshake succeeds");
    let conn_task = tokio::spawn(connection);
    let response_task = tokio::spawn(
        sender.send_request(
            Request::get("http://localhost/")
                .body(Empty::<Bytes>::new())
                .expect("request"),
        ),
    );
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .expect("h2 handler enters");

    // Let connection_lifetime expire while the stream is in flight.
    tokio::time::sleep(Duration::from_millis(120)).await;
    release.notify_one();

    let response = tokio::time::timeout(Duration::from_secs(2), response_task)
        .await
        .expect("in-flight stream finishes")
        .expect("request task joins")
        .expect("in-flight HTTP/2 stream must not be hard-dropped on lifetime expiry");
    let body = response.into_body().collect().await.expect("body reads").to_bytes();
    assert_eq!(body, b"graceful-h2"[..]);

    // After GOAWAY + in-flight stream completion, the connection closes cleanly.
    tokio::time::timeout(Duration::from_secs(2), conn_task)
        .await
        .expect("h2 connection closes after graceful drain")
        .expect("connection task joins")
        .expect("clean GOAWAY close");

    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(server.task.await.expect("server joins").is_ok());
}

/// Negative — a connection that ignores graceful shutdown after `connection_lifetime` expiry is
/// still forcibly dropped after the hard drain bound so its admission slot is reclaimed.
#[tokio::test]
async fn n_connection_lifetime_hard_drops_hung_request_after_grace() {
    let entered = Arc::new(Notify::new());
    let service = service_fn({
        let entered = Arc::clone(&entered);
        move |_request: Request<hyper::body::Incoming>| {
            let entered = Arc::clone(&entered);
            async move {
                entered.notify_one();
                std::future::pending::<Result<Response<Full<Bytes>>, Infallible>>().await
            }
        }
    });
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        connection_lifetime: Some(Duration::from_millis(40)),
        write_progress_timeout: Duration::from_millis(60),
        lingering_close_time: Duration::from_millis(20),
        header_read_timeout: Duration::from_secs(2),
        ..ServerConfig::default()
    };
    let server = Server::new(config, service).serve().expect("server starts");

    let mut client = TcpStream::connect(server.local_addr).await.expect("TCP connects");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .expect("hung handler enters");

    tokio::time::timeout(Duration::from_secs(2), async {
        while server.metrics.active_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("hung connection must be forcibly dropped after lifetime grace expires");

    let _ = server.shutdown.trigger(Duration::from_millis(50)).await;
    assert!(server.task.await.expect("server joins").is_ok());
}
