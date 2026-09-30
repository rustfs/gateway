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

//! A configured duration no deadline can represent means "never", not a panic (rustfs/gateway#1211).
//!
//! Responsible for: serving HTTP/1.1 and HTTP/2 on a listener whose every timeout is
//! `Duration::MAX`, through each timer those settings arm, and shutting it down cleanly.
//! NOT responsible for: `tcp_keepalive`, which the socket library saturates and the kernel accepts
//! or refuses at bind time, before any task exists.
//! Upstream: `crates/server/src/io.rs`'s deadline arithmetic. Downstream: none.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustfs_gateway_server::{RunningServer, ServerConfig, ShutdownReport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::echo_server;

/// Every duration a deployment configures, at the largest value it can write down.
fn never_config() -> ServerConfig {
    ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: Duration::MAX,
        write_progress_timeout: Duration::MAX,
        keep_alive_idle: Duration::MAX,
        lingering_close_time: Duration::MAX,
        connection_lifetime: Some(Duration::MAX),
        h2_keep_alive_interval: Some(Duration::MAX),
        h2_keep_alive_timeout: Duration::MAX,
        ..ServerConfig::default()
    }
}

/// Reads one `200 ok` response off a keep-alive connection.
async fn read_one_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\nok") {
        let mut chunk = [0_u8; 256];
        let read = stream.read(&mut chunk).await.expect("response reads");
        assert_ne!(read, 0, "the connection closed before its response: {response:?}");
        response.extend_from_slice(&chunk[..read]);
    }
    response
}

/// Negative — the accept loop derives each socket's header deadline from `header_read_timeout`;
/// before #1211 that sum panicked on the first accept and ended the listener. The two requests
/// drive the idle and write-progress timers on every read and write, and the closing request the
/// lingering close.
#[tokio::test]
async fn duration_max_timeouts_serve_http1_and_shut_down() {
    let RunningServer {
        local_addr,
        metrics,
        task,
        shutdown,
    } = echo_server(never_config());
    let mut stream = TcpStream::connect(local_addr).await.expect("TCP connects");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("first request writes");
    assert!(read_one_response(&mut stream).await.starts_with(b"HTTP/1.1 200"));
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("second request writes");
    let mut rest = Vec::new();
    stream
        .read_to_end(&mut rest)
        .await
        .expect("the closing response ends cleanly");
    assert!(rest.starts_with(b"HTTP/1.1 200"), "second response: {rest:?}");
    assert_eq!(metrics.accepted_connections(), 1);
    assert_eq!(shutdown.trigger(Duration::from_secs(1)).await, ShutdownReport::default());
    assert!(task.await.expect("the accept task did not panic").is_ok(), "the listener ends cleanly");
}

/// Serves two HTTP/2 requests on one connection, `pause` apart, then shuts the listener down.
async fn serve_two_http2_requests(config: ServerConfig, pause: Duration) {
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = echo_server(config);
    let stream = TokioIo::new(TcpStream::connect(local_addr).await.expect("TCP connects"));
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(stream)
        .await
        .expect("h2 handshake succeeds");
    let connection = tokio::spawn(connection);
    for round in 0..2 {
        if round == 1 {
            tokio::time::sleep(pause).await;
        }
        let request = Request::builder()
            .uri("http://localhost/")
            .body(Empty::<Bytes>::new())
            .expect("fixture request");
        let response = sender.send_request(request).await.expect("the stream is answered");
        assert_eq!(response.into_body().collect().await.expect("body reads").to_bytes(), b"ok"[..]);
    }
    let shutdown = tokio::spawn(shutdown.trigger(Duration::from_secs(1)));
    assert!(
        connection.await.expect("client connection task joins").is_ok(),
        "the server ends the connection with GOAWAY, not by dropping it"
    );
    assert_eq!(shutdown.await.expect("shutdown joins"), ShutdownReport::default());
    assert!(task.await.expect("the accept task did not panic").is_ok(), "the listener ends cleanly");
}

/// Negative — the HTTP/2 keep-alive interval is handed to Hyper, which adds it to the instant of the
/// last frame it read.
#[tokio::test]
async fn duration_max_timeouts_serve_http2_and_shut_down() {
    serve_two_http2_requests(never_config(), Duration::ZERO).await;
}

/// Negative — the acknowledgement timeout is added to the clock only once a keep-alive PING goes
/// out, so the interval here is short and the connection is left idle for twenty of them first.
#[tokio::test]
async fn a_duration_max_ping_acknowledgement_timeout_survives_a_sent_ping() {
    let config = ServerConfig {
        h2_keep_alive_interval: Some(Duration::from_millis(10)),
        ..never_config()
    };
    serve_two_http2_requests(config, Duration::from_millis(200)).await;
}
