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

//! Payload behaviour observed through a real Hyper HTTP/1.1 connection.
//!
//! Responsible for: proving that the generic payload body reaches Hyper with truthful length
//! information and that Hyper therefore frames an unknown-length response as chunked without a
//! Content-Length. NOT responsible for: Hyper's framing implementation or stream negotiation,
//! which belong to Hyper and `rustfs-gateway-stream` respectively.
//! Upstream: `rustfs-gateway-stream::Body` and the generic server runtime. Downstream: the
//! `c-pay-*` acceptance ledger.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use rustfs_gateway_server::{Server, ServerConfig};
use rustfs_gateway_stream::{
    AsyncPayloadRead, Body, PayloadCaps, PayloadRead, PayloadStream, ReadProgress, StreamError, TrailingHeaders,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tower::service_fn;

const LARGE_BODY_LEN: usize = 100 * 1024 * 1024;
const CHUNK_LEN: usize = 64 * 1024;

struct ObservedStream {
    chunk: Bytes,
    remaining: usize,
    polls: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

impl ObservedStream {
    fn large(polls: Arc<AtomicUsize>, dropped: Arc<AtomicBool>) -> Self {
        Self {
            chunk: Bytes::from(vec![b'x'; CHUNK_LEN]),
            remaining: LARGE_BODY_LEN,
            polls,
            dropped,
        }
    }
}

impl PayloadStream for ObservedStream {
    fn poll_read(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        self.polls.fetch_add(1, Ordering::Release);
        if self.remaining == 0 {
            return Poll::Ready(Ok(PayloadRead::Eof {
                trailers: TrailingHeaders::empty(),
            }));
        }
        let take = self.remaining.min(self.chunk.len());
        self.remaining -= take;
        Poll::Ready(Ok(PayloadRead::Chunk(self.chunk.slice(..take))))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH
    }

    fn len_hint(&self) -> Option<u64> {
        u64::try_from(self.remaining).ok()
    }
}

impl Drop for ObservedStream {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

fn observed_body(polls: Arc<AtomicUsize>, dropped: Arc<AtomicBool>) -> Body {
    Body::from_stream(ObservedStream::large(polls, dropped)).expect("the observed stream declares consistent capabilities")
}

async fn wait_for_drop(dropped: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !dropped.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the server drops the response producer");
}

struct UnknownLengthReader {
    bytes: Option<Bytes>,
    ended: bool,
}

impl UnknownLengthReader {
    fn hello() -> Self {
        Self {
            bytes: Some(Bytes::from_static(b"hello")),
            ended: false,
        }
    }
}

impl AsyncPayloadRead for UnknownLengthReader {
    fn poll_fill(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<Result<ReadProgress, StreamError>> {
        if let Some(bytes) = self.bytes.take() {
            buffer[..bytes.len()].copy_from_slice(&bytes);
            return Poll::Ready(Ok(ReadProgress::Filled(bytes.len())));
        }
        if self.ended {
            return Poll::Ready(Err(StreamError::polled_after_eof().with_bytes_before_error(5)));
        }
        self.ended = true;
        Poll::Ready(Ok(ReadProgress::Eof {
            trailers: TrailingHeaders::empty(),
        }))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PULL
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

/// `c-pay-0009`. An unknown-length response is chunked on a real connection and never announces
/// a Content-Length that the producer did not know.
#[tokio::test]
async fn c_pay_0009_an_unknown_length_response_is_chunked_without_content_length() {
    let service = service_fn(|_request: Request<hyper::body::Incoming>| async {
        let body = Body::from_reader(UnknownLengthReader::hello()).expect("the reader's capabilities are consistent");
        Ok::<_, Infallible>(Response::new(body))
    });
    let running = Server::new(
        ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            ..ServerConfig::default()
        },
        service,
    )
    .serve()
    .expect("the payload server starts");

    let mut client = TcpStream::connect(running.local_addr).await.expect("the client connects");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("the request writes");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
        .await
        .expect("the response terminates")
        .expect("the response reads");

    let text = String::from_utf8(response).expect("the response is HTTP text");
    let lower = text.to_ascii_lowercase();
    assert!(lower.starts_with("http/1.1 200 "), "{text}");
    assert!(lower.contains("transfer-encoding: chunked\r\n"), "{text}");
    assert!(!lower.contains("content-length:"), "{text}");
    assert!(text.ends_with("\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), "{text}");

    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("the server task joins").is_ok());
}

/// `c-pay-0060`. Resetting a connection during a response drops its producer and releases the
/// connection without waiting for shutdown.
#[tokio::test]
async fn c_pay_0060_a_client_reset_drops_the_response_producer_and_connection() {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let service = service_fn({
        let polls = Arc::clone(&polls);
        let dropped = Arc::clone(&dropped);
        move |_request: Request<hyper::body::Incoming>| {
            let body = observed_body(Arc::clone(&polls), Arc::clone(&dropped));
            async move { Ok::<_, Infallible>(Response::new(body)) }
        }
    });
    let running = Server::new(
        ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            so_sndbuf: Some(4 * 1024),
            ..ServerConfig::default()
        },
        service,
    )
    .serve()
    .expect("the payload server starts");

    let mut client = TcpStream::connect(running.local_addr).await.expect("the client connects");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("the request writes");
    let mut first_bytes = [0_u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut first_bytes))
        .await
        .expect("the response starts")
        .expect("the response head reads");
    assert!(read > 0, "the reset must happen after the response starts");
    assert!(polls.load(Ordering::Acquire) > 0, "the producer was not polled before reset");

    let socket = socket2::Socket::from(client.into_std().expect("the client stream converts"));
    socket.set_linger(Some(Duration::ZERO)).expect("RST linger configures");
    drop(socket);

    wait_for_drop(&dropped).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while running.metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the reset releases the connection");

    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("the server task joins").is_ok());
}

/// `c-pay-0063`. A zero receive window trips the write-progress deadline, drops the response
/// producer, and releases the connection.
#[tokio::test]
async fn c_pay_0063_a_zero_window_timeout_drops_the_response_producer_and_connection() {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let service = service_fn({
        let polls = Arc::clone(&polls);
        let dropped = Arc::clone(&dropped);
        move |_request: Request<hyper::body::Incoming>| {
            let body = observed_body(Arc::clone(&polls), Arc::clone(&dropped));
            async move { Ok::<_, Infallible>(Response::new(body)) }
        }
    });
    let running = Server::new(
        ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            so_sndbuf: Some(4 * 1024),
            write_progress_timeout: Duration::from_millis(20),
            keep_alive_idle: Duration::from_secs(60),
            ..ServerConfig::default()
        },
        service,
    )
    .serve()
    .expect("the payload server starts");

    let socket = TcpSocket::new_v4().expect("the client socket opens");
    socket.set_recv_buffer_size(4 * 1024).expect("the receive window is bounded");
    let mut client = socket.connect(running.local_addr).await.expect("the client connects");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("the request writes");

    tokio::time::timeout(Duration::from_secs(1), async {
        while polls.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the response producer starts");
    wait_for_drop(&dropped).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while running.metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the write-progress timeout releases the connection");
    drop(client);

    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("the server task joins").is_ok());
}
