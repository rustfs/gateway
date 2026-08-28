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

//! Live controls for the production self-held plaintext HTTP/1.1 driver.
//!
//! Responsible for: socket request, response and reuse controls. NOT responsible for: file-region
//! kernel transfer. Upstream: the integration harness. Downstream: production cleartext assembly.

#![allow(clippy::expect_used, clippy::panic)]

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use rustfs_gateway::{Body, ConnectionIntent, S3Service, SelfHeldHttp1Driver, SelfHeldRequestBody};
use rustfs_gateway_server::{ConnectionDriver, Server, ServerConfig, ServerError, ServerMetrics};
use rustfs_gateway_stream::{AsyncPayloadRead, PayloadCaps, ReadProgress, StreamError, TrailingHeaders};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{net::TcpStream, task::JoinError};
use tower::Service;

#[derive(Clone, Default)]
struct TestService {
    calls: Arc<AtomicUsize>,
}

impl Service<Request<SelfHeldRequestBody>> for TestService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<SelfHeldRequestBody>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let duplicate_header_count = request.headers().get_all("x-duplicate").iter().count();
            let collected = match request.into_body().collect().await {
                Ok(collected) => collected,
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header(header::CONTENT_LENGTH, 0)
                        .body(Body::empty())
                        .expect("static bad-request response is valid"));
                }
            };
            let trailer = collected
                .trailers()
                .and_then(|trailers| trailers.get("x-test"))
                .and_then(|value| value.to_str().ok())
                .unwrap_or("none")
                .to_owned();
            let request_body = collected.to_bytes();
            if path == "/stream" {
                return Ok(Response::new(
                    Body::from_reader(UnknownBodyReader { step: 0 }).expect("the scripted reader has consistent capabilities"),
                ));
            }
            if path == "/vectored" {
                return Ok(Response::new(Body::from_segments([
                    Bytes::from_static(b"ab"),
                    Bytes::from_static(b"cd"),
                    Bytes::from_static(b"ef"),
                ])));
            }
            if path == "/conflicting-response" {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, 5)
                    .header(header::TRANSFER_ENCODING, "chunked")
                    .body(Body::from_bytes(Bytes::from_static(b"hello")))
                    .expect("static conflicting response is constructible"));
            }
            if path == "/duplicate-content-length" {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, 5)
                    .header(header::CONTENT_LENGTH, 5)
                    .body(Body::from_bytes(Bytes::from_static(b"hello")))
                    .expect("static duplicate-length response is constructible"));
            }
            if path == "/mismatched-content-length" {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, 4)
                    .body(Body::from_bytes(Bytes::from_static(b"hello")))
                    .expect("static mismatched-length response is constructible"));
            }
            let (status, payload) = match (method, path.as_str()) {
                (Method::HEAD, _) => (StatusCode::OK, Bytes::from_static(b"ignored")),
                (_, "/first") => (StatusCode::OK, Bytes::from_static(b"one")),
                (_, "/second") => (StatusCode::OK, Bytes::from_static(b"two")),
                (_, "/no-content") => (StatusCode::NO_CONTENT, Bytes::from_static(b"ignored")),
                (_, "/intent-close" | "/intent-keep") => (StatusCode::OK, Bytes::from_static(b"intent")),
                (_, "/echo-len") => (StatusCode::OK, Bytes::from(request_body.len().to_string())),
                (_, "/echo-len-and-header-count") => {
                    (StatusCode::OK, Bytes::from(format!("{}:{duplicate_header_count}", request_body.len())))
                }
                (_, "/echo-trailer") => (StatusCode::OK, Bytes::from(format!("{}:{trailer}", request_body.len()))),
                _ => (StatusCode::NOT_FOUND, Bytes::new()),
            };
            let mut response = Response::builder()
                .status(status)
                .header(header::CONTENT_LENGTH, payload.len())
                .body(Body::from_bytes(payload))
                .expect("static response parts are valid");
            if path == "/intent-close" {
                response.extensions_mut().insert(ConnectionIntent::Close);
            } else if path == "/intent-keep" {
                response.extensions_mut().insert(ConnectionIntent::MayKeepAlive);
            }
            Ok(response)
        })
    }
}

/// Positive control: a fixed body does not consume the next buffered request and duplicate headers survive parsing.
#[tokio::test]
async fn production_driver_preserves_fixed_body_and_duplicate_header_boundaries() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(
            b"POST /echo-len-and-header-count HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nx-duplicate: first\r\nx-duplicate: second\r\n\r\nhelloGET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("fixed body and pipelined request write together");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("both responses complete");
    assert_eq!(
        response
            .windows(b"HTTP/1.1 200 OK\r\n".len())
            .filter(|window| *window == b"HTTP/1.1 200 OK\r\n")
            .count(),
        2
    );
    assert!(
        response
            .windows(b"\r\n\r\n5:2HTTP/1.1 200 OK\r\n".len())
            .any(|window| { window == b"\r\n\r\n5:2HTTP/1.1 200 OK\r\n" })
    );
    assert!(response.ends_with(b"two"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 2);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Positive binary control: a coalesced fixed body LF is data, not request-head syntax.
#[tokio::test]
async fn production_driver_bounds_bare_lf_checks_before_a_fixed_body() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(b"PUT /echo-len HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\n\n")
        .await
        .expect("coalesced binary request writes");
    let response = read_until(&mut client, b"\r\n\r\n1").await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 1);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Positive binary control: trailer syntax ends before the next pipelined request body LF.
#[tokio::test]
async fn production_driver_bounds_bare_lf_checks_after_complete_trailers() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(
            b"PUT /echo-trailer HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: x-test\r\n\r\n0\r\nx-test: yes\r\n\r\nPUT /echo-len HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\n\n",
        )
        .await
        .expect("trailers and pipelined binary request write together");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("both responses complete");
    assert_eq!(
        response
            .windows(b"HTTP/1.1 200 OK\r\n".len())
            .filter(|window| *window == b"HTTP/1.1 200 OK\r\n")
            .count(),
        2
    );
    assert!(
        response
            .windows(b"\r\n\r\n0:yesHTTP/1.1 200 OK\r\n".len())
            .any(|window| { window == b"\r\n\r\n0:yesHTTP/1.1 200 OK\r\n" })
    );
    assert!(response.ends_with(b"1"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 2);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

struct UnknownBodyReader {
    step: u8,
}

impl AsyncPayloadRead for UnknownBodyReader {
    fn poll_fill(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<Result<ReadProgress, StreamError>> {
        if self.step == 0 {
            let Some(target) = buffer.get_mut(..5) else {
                return Poll::Ready(Err(StreamError::upstream(Box::new(io::Error::other(
                    "test buffer is unexpectedly short",
                )))));
            };
            target.copy_from_slice(b"hello");
            self.step = 1;
            return Poll::Ready(Ok(ReadProgress::Filled(5)));
        }
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-test", http::HeaderValue::from_static("done"));
        self.step = 2;
        Poll::Ready(Ok(ReadProgress::Eof {
            trailers: TrailingHeaders::from_header_map(trailers),
        }))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PULL
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

struct RunningServer {
    addr: SocketAddr,
    task: ServerTask,
    shutdown: rustfs_gateway_server::ShutdownTrigger,
    metrics: ServerMetrics,
}

type ServerTask = Pin<Box<dyn Future<Output = Result<Result<(), ServerError>, JoinError>> + Send>>;

fn start(service: TestService) -> RunningServer {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        tcp_nodelay: true,
        ..ServerConfig::default()
    };
    start_with_config(service, config)
}

fn start_with_config(service: TestService, config: ServerConfig) -> RunningServer {
    let running = Server::new(config, service)
        .serve_with(SelfHeldHttp1Driver)
        .expect("self-held server starts");
    RunningServer {
        addr: running.local_addr,
        task: Box::pin(running.task),
        shutdown: running.shutdown,
        metrics: running.metrics,
    }
}

fn start_gateway(service: S3Service) -> RunningServer {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        tcp_nodelay: true,
        ..ServerConfig::default()
    };
    let running = Server::new(config, service)
        .serve_with(SelfHeldHttp1Driver)
        .expect("self-held gateway server starts");
    RunningServer {
        addr: running.local_addr,
        task: Box::pin(running.task),
        shutdown: running.shutdown,
        metrics: running.metrics,
    }
}

async fn read_until(stream: &mut TcpStream, suffix: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut response = Vec::new();
        let mut chunk = [0_u8; 256];
        while !response.ends_with(suffix) {
            let read = stream.read(&mut chunk).await.expect("response read succeeds");
            assert_ne!(read, 0, "connection stays open until the expected response is complete");
            response.extend_from_slice(&chunk[..read]);
        }
        response
    })
    .await
    .expect("response arrives before the test deadline")
}

/// Positive control: one production connection parses and answers two sequential requests.
#[tokio::test]
async fn production_driver_reuses_one_connection_for_two_requests() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");

    for fragment in b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n".chunks(3) {
        client.write_all(fragment).await.expect("fragmented first request writes");
    }
    let first = read_until(&mut client, b"one").await;
    assert!(first.starts_with(b"HTTP/1.1 200 OK\r\n"));

    client
        .write_all(b"GET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("second request writes");
    let second = read_until(&mut client, b"two").await;
    assert!(second.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let mut eof = [0_u8; 1];
    assert_eq!(client.read(&mut eof).await.expect("close is observable"), 0);
    assert_eq!(service.calls.load(Ordering::Relaxed), 2);

    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Paired wire control: typed close intent ends the socket, while may-keep intent permits another request.
#[tokio::test]
async fn production_driver_honors_both_typed_connection_intents() {
    let closing_service = TestService::default();
    let closing = start(closing_service.clone());
    let mut closing_client = TcpStream::connect(closing.addr).await.expect("closing client connects");
    closing_client
        .write_all(b"GET /intent-close HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("typed-close request writes");
    let mut closing_response = Vec::new();
    closing_client
        .read_to_end(&mut closing_response)
        .await
        .expect("typed-close response ends cleanly");
    assert!(closing_response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        closing_response
            .windows(b"connection: close\r\n".len())
            .any(|window| { window.eq_ignore_ascii_case(b"connection: close\r\n") })
    );
    assert!(closing_response.ends_with(b"intent"));
    assert_eq!(closing_service.calls.load(Ordering::Relaxed), 1);
    let _ = closing.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(closing.task.await.expect("closing server task joins").is_ok());

    let keeping_service = TestService::default();
    let keeping = start(keeping_service.clone());
    let mut keeping_client = TcpStream::connect(keeping.addr).await.expect("keeping client connects");
    keeping_client
        .write_all(b"GET /intent-keep HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("typed-keep request writes");
    let first = read_until(&mut keeping_client, b"intent").await;
    assert!(first.starts_with(b"HTTP/1.1 200 OK\r\n"));
    keeping_client
        .write_all(b"GET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request after may-keep writes");
    let second = read_until(&mut keeping_client, b"two").await;
    assert!(second.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(keeping_service.calls.load(Ordering::Relaxed), 2);
    let _ = keeping.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(keeping.task.await.expect("keeping server task joins").is_ok());
}

/// Positive control: a valid chunked request and its trailer reach the service exactly once.
#[tokio::test]
async fn production_driver_streams_a_chunked_request_body() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(
            b"PUT /echo-trailer HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: x-test\r\nConnection: close\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nx-test: yes\r\n\r\n",
        )
        .await
        .expect("chunked request writes");
    let response = read_until(&mut client, b"5:yes").await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 1);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Positive control: a client waiting for `100 Continue` can make body progress before dispatch completes.
#[tokio::test]
async fn production_driver_answers_expect_continue_before_reading_the_body() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(
            b"PUT /echo-len HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("expect request head writes");
    let interim = read_until(&mut client, b"\r\n\r\n").await;
    assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    client
        .write_all(b"hello")
        .await
        .expect("body writes after the interim response");
    let response = read_until(&mut client, b"\r\n\r\n5").await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 1);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: an unsupported expectation is rejected without application dispatch or body wait.
#[tokio::test]
async fn production_driver_refuses_an_unsupported_expectation() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(b"PUT /echo-len HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nExpect: something-else\r\n\r\n")
        .await
        .expect("unsupported expectation writes");
    let response = read_until(&mut client, b"\r\n\r\n").await;
    assert!(response.starts_with(b"HTTP/1.1 417 Expectation Failed\r\n"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 0);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative assembly control: the plaintext-only driver refuses TLS before a listener is bound.
#[test]
fn production_driver_refuses_tls_during_driver_validation() {
    let config = ServerConfig::default();
    let driver = SelfHeldHttp1Driver;
    assert!(<SelfHeldHttp1Driver as ConnectionDriver<TestService>>::validate(&driver, &config, true).is_err());
    assert!(<SelfHeldHttp1Driver as ConnectionDriver<TestService>>::validate(&driver, &config, false).is_ok());
}

/// Positive control: two requests already buffered together are dispatched in wire order.
#[tokio::test]
async fn production_driver_preserves_pipelined_request_boundaries() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(
            b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\nGET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("pipelined requests write together");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("both pipelined responses complete");
    assert_eq!(
        response
            .windows(b"HTTP/1.1 200 OK\r\n".len())
            .filter(|window| { *window == b"HTTP/1.1 200 OK\r\n" })
            .count(),
        2
    );
    assert!(response.windows(3).any(|window| window == b"one"));
    assert!(response.ends_with(b"two"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 2);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Positive control: unknown-length bodies use exact chunk framing and carry trailers at EOF.
#[tokio::test]
async fn production_driver_writes_chunked_responses_with_trailers() {
    let running = start(TestService::default());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("streaming request writes");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("chunked response completes");
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        response
            .windows(b"transfer-encoding: chunked\r\n".len())
            .any(|window| { window.eq_ignore_ascii_case(b"transfer-encoding: chunked\r\n") })
    );
    assert!(
        !response
            .windows(b"content-length:".len())
            .any(|window| { window.eq_ignore_ascii_case(b"content-length:") })
    );
    assert!(response.ends_with(b"5\r\nhello\r\n0\r\nx-test: done\r\n\r\n"));
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Positive capability control: in-memory segments remain vectored until the socket writer.
#[tokio::test]
async fn production_driver_writes_vectored_payloads_without_stream_adaptation() {
    let running = start(TestService::default());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(b"GET /vectored HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("vectored response request writes");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("vectored response completes");
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        response
            .windows(b"content-length: 6\r\n".len())
            .any(|window| { window.eq_ignore_ascii_case(b"content-length: 6\r\n") })
    );
    assert!(response.ends_with(b"abcdef"));
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: HEAD and bodyless statuses never leak the application payload.
#[tokio::test]
async fn production_driver_suppresses_forbidden_response_bodies() {
    let running = start(TestService::default());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(b"HEAD /head HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("HEAD request writes");
    let head = read_until(&mut client, b"\r\n\r\n").await;
    assert!(!head.ends_with(b"ignored"));

    client
        .write_all(b"GET /no-content HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("bodyless request writes");
    let no_content = read_until(&mut client, b"\r\n\r\n").await;
    assert!(no_content.starts_with(b"HTTP/1.1 204 No Content\r\n"));
    assert!(!no_content.ends_with(b"ignored"));
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: the HTTP/2 preface is refused before any application dispatch.
#[tokio::test]
async fn production_driver_refuses_the_http2_preface() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("preface writes");
    let response = read_until(&mut client, b"\r\n\r\n").await;
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 0);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: parser-level invalid header syntax never reaches the application.
#[tokio::test]
async fn production_driver_refuses_a_malformed_header_line() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(b"GET / HTTP/1.1\r\nBad Header: value\r\n\r\n")
        .await
        .expect("malformed request writes");
    let response = read_until(&mut client, b"\r\n\r\n").await;
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 0);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: a complete head cannot bypass the configured byte ceiling by arriving at once.
#[tokio::test]
async fn production_driver_refuses_an_oversized_complete_request_head() {
    let service = TestService::default();
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        h1_max_buf_size: 8 * 1_024,
        ..ServerConfig::default()
    };
    let running = start_with_config(service.clone(), config);
    let mut request = b"GET /first HTTP/1.1\r\nHost: localhost\r\nx-large: ".to_vec();
    request.extend(std::iter::repeat_n(b'a', 8 * 1_024));
    request.extend_from_slice(b"\r\n\r\n");
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client.write_all(&request).await.expect("oversized request head writes");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("oversized head connection closes");
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 0);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: the common gateway acceptance rejects CL/TE without dispatching the bytes after it.
#[tokio::test]
async fn production_driver_cannot_smuggle_a_second_request_after_cl_te() {
    let running = start_gateway(super::support::service());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await
        .expect("ambiguous request and smuggled suffix write together");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("ambiguous connection closes");
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(
        response
            .windows(b"HTTP/1.1 ".len())
            .filter(|window| *window == b"HTTP/1.1 ")
            .count(),
        1
    );
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative wire control: rejecting a request with unread bytes ends in FIN, not a reset that can erase the refusal.
#[tokio::test]
async fn production_driver_lingers_over_an_unread_rejected_body() {
    const BODY_BYTES: usize = 64 * 1_024;
    let running = start_gateway(super::support::service());
    let mut request =
        format!("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {BODY_BYTES}\r\nTransfer-Encoding: chunked\r\n\r\n")
            .into_bytes();
    request.extend(std::iter::repeat_n(b'x', BODY_BYTES));
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(&request)
        .await
        .expect("ambiguous request and unread body write");
    client.shutdown().await.expect("client write side closes");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("server closes cleanly after preserving the refusal");
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(
        response
            .windows(b"HTTP/1.1 ".len())
            .filter(|window| *window == b"HTTP/1.1 ")
            .count(),
        1
    );
    assert!(
        running.metrics.lingering_octets_drained() > 0,
        "the server must observe bytes discarded after the refusal"
    );
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: malformed chunk syntax becomes a response and prevents connection reuse.
#[tokio::test]
async fn production_driver_rejects_a_non_hex_chunk_size() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(
            b"PUT /echo-len HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\nabc\r\n0\r\n\r\nGET /first HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await
        .expect("malformed chunk and suffix write together");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("malformed chunk connection closes");
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 1, "the suffix never reaches the service");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: a chunk extension cannot bypass the parser's line-size ceiling.
#[tokio::test]
async fn production_driver_rejects_an_oversized_complete_chunk_line() {
    let service = TestService::default();
    let running = start(service.clone());
    let mut request =
        b"PUT /echo-len HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1;".to_vec();
    request.extend(std::iter::repeat_n(b'a', 1_024));
    request.extend_from_slice(b"\r\nx\r\n0\r\n\r\n");
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client.write_all(&request).await.expect("oversized chunk line writes");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("oversized chunk line connection closes");
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(service.calls.load(Ordering::Relaxed), 1);
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative source control: the transport cannot become a second request-acceptance authority.
#[test]
fn production_driver_keeps_one_wire_acceptance_call() {
    let service = include_str!("../src/service.rs");
    let driver = concat!(
        include_str!("../src/conn/mod.rs"),
        include_str!("../src/conn/request.rs"),
        include_str!("../src/conn/response.rs")
    );
    assert_eq!(service.matches("WireRequest::accept(").count(), 1);
    assert_eq!(driver.matches("WireRequest::accept(").count(), 0);
    assert!(!driver.contains("rustfs_gateway_http"));
}

/// Negative control: response CL/TE ambiguity is never written to the peer.
#[tokio::test]
async fn production_driver_refuses_conflicting_response_framing() {
    let running = start(TestService::default());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(b"GET /conflicting-response HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("invalid response closes the socket");
    assert!(response.is_empty(), "no ambiguous response head reaches the wire");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: duplicate response lengths are refused before any bytes reach the peer.
#[tokio::test]
async fn production_driver_refuses_duplicate_response_content_length() {
    let running = start(TestService::default());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(b"GET /duplicate-content-length HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("invalid response closes");
    assert!(response.is_empty(), "no duplicate framing reaches the wire");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}

/// Negative control: an exact body size that contradicts Content-Length is refused before the head.
#[tokio::test]
async fn production_driver_refuses_known_response_length_mismatch() {
    let running = start(TestService::default());
    let mut client = TcpStream::connect(running.addr).await.expect("client connects");
    client
        .write_all(b"GET /mismatched-content-length HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request writes");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("invalid response closes");
    assert!(response.is_empty(), "no contradictory response head reaches the wire");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(running.task.await.expect("server task joins").is_ok());
}
