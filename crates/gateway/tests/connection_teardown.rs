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

//! Compile-time or regression support for this module.
//!
//! Responsible for: exercising the contract named by this file.
//! NOT responsible for: implementing the production behavior under test.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

//! What a refusal does to the connection it arrived on, checked where the decision is carried.
//!
//! Two flags — `WireReject::must_close_connection` and `ChunkReject::must_close_connection` — were
//! declared, returned a constant, and were dropped by the renderer, so no response ever carried
//! `Connection: close` and no assertion that read either one could fail. That is
//! <https://github.com/rustfs/gateway/issues/20>. The suite below pins the three halves of the
//! repair separately, because they fail independently:
//!
//! 1. the flag branches (`crates/http`'s own suites, and `rustfs_gateway::close`'s unit tests);
//! 2. the renderer carries it onto the response, in the extensions — this file;
//! 3. a transport reads it and turns it into `Connection: close` on a socket it then closes.
//!    `crate::adapt` does the header half for the hyper and tower paths; nothing in this crate does
//!    the socket half, because nothing in this crate owns a socket.
//!
//! # Why the verdict is not a header until a transport says so
//!
//! `Connection` is hop-by-hop. `render` used to write it, which made this crate a second writer
//! behind whatever transport was already writing its own — and a response reached the wire carrying
//! `Connection: close` *and* `Connection: keep-alive`. The verdict now travels in the response's
//! extensions, which never reach the wire, and exactly one place turns it into a header.
//!
//! # What this file deliberately does not claim
//!
//! Nothing below asserts that a connection closed. A test in this crate that said so would be
//! reporting the service's intention as an observation, which is the defect class the issue was
//! opened about and which this suite has now produced six times. Every assertion here is about a
//! value or a header, and is worded as one.

use crate::support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use rustfs_gateway::{
    ConnectionIntent, Handler, HandlerCancellation, HandlerDeadlineConfig, HandlerDeadlineReport, HandlerResult, Limits,
    Observer, OperationSetEnd, OperationSetNode, Req, RequestEvent, Resp, S3Service, ServiceConfig, connection_intent_of,
};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, ShutdownReport};
use support::{Backend, Failing, Ping, PingOutput, ping_route, plain, service, wired, wired_denying};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

async fn refusal(service: &S3Service, request: http::Request<Bytes>) -> http::Response<rustfs_gateway::Body> {
    service.call_bytes(request).await
}

struct DeadlineBackend {
    acknowledges_cleanup: bool,
}

#[derive(Default)]
struct DeadlineReportRecorder {
    seen: Mutex<Vec<Option<HandlerDeadlineReport>>>,
}

impl Observer for DeadlineReportRecorder {
    fn on_response(&self, event: &RequestEvent<'_>) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(event.handler_deadline);
        }
    }
}

impl Handler<Ping> for DeadlineBackend {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        Err(rustfs_gateway::HandlerError::internal_error(
            "the context-aware handler entry was bypassed",
        ))
    }

    async fn call_with_context(&self, _request: Req<Ping>, context: rustfs_gateway::HandlerContext) -> HandlerResult<Ping> {
        if self.acknowledges_cleanup {
            loop {
                if matches!(context.cancellation_reason(), Some(HandlerCancellation::Deadline)) {
                    return Ok(Resp::new(PingOutput {
                        message: "the late result must be discarded".to_owned(),
                    }));
                }
                futures_timer::Delay::new(Duration::from_millis(1)).await;
            }
        }
        core::future::pending().await
    }
}

fn deadline_config() -> ServiceConfig {
    let deadlines = HandlerDeadlineConfig::new(Duration::from_millis(10), Duration::from_millis(10))
        .expect("non-zero handler deadlines")
        .try_with_cleanup_grace(Duration::from_millis(20))
        .expect("a non-zero cleanup grace");
    ServiceConfig::new(1024).with_handler_deadlines(deadlines)
}

fn deadline_service(acknowledges_cleanup: bool) -> (S3Service, Arc<DeadlineBackend>, Arc<DeadlineReportRecorder>) {
    let backend = Arc::new(DeadlineBackend { acknowledges_cleanup });
    let recorder = Arc::new(DeadlineReportRecorder::default());
    let (builder, _handle) = wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .route(ping_route())
        .observer(Arc::clone(&recorder))
        .config(deadline_config());
    (builder.build().expect("a complete assembly"), backend, recorder)
}

fn live_server(service: S3Service) -> RunningServer {
    live_server_with_config(
        service,
        ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            header_read_timeout: Duration::from_secs(1),
            keep_alive_idle: Duration::from_secs(2),
            ..ServerConfig::default()
        },
    )
}

fn live_server_with_config(service: S3Service, config: ServerConfig) -> RunningServer {
    let service = tower::service_fn(move |request| {
        let mut service = service.clone();
        async move {
            let response = <S3Service as tower::Service<_>>::call(&mut service, request)
                .await
                .expect("the adapter error type is Infallible");
            let collected = rustfs_gateway::collect(response).await.expect("an in-memory response body");
            let (status, headers, body, _trailers) = collected.into_parts();
            let mut response = http::Response::new(Full::new(body));
            *response.status_mut() = status;
            for (name, value) in headers {
                response.headers_mut().append(name, value);
            }
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    Server::new(config, service).serve().expect("server starts")
}

struct ResetBackend {
    calls: AtomicUsize,
    entered: Notify,
    cancellations: Mutex<Vec<HandlerCancellation>>,
    rollback_completed: AtomicBool,
}

impl ResetBackend {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            cancellations: Mutex::new(Vec::new()),
            rollback_completed: AtomicBool::new(false),
        }
    }
}

impl Handler<Ping> for ResetBackend {
    async fn call(&self, _request: Req<Ping>) -> HandlerResult<Ping> {
        Err(rustfs_gateway::HandlerError::internal_error(
            "the context-aware handler entry was bypassed",
        ))
    }

    async fn call_with_context(&self, _request: Req<Ping>, context: rustfs_gateway::HandlerContext) -> HandlerResult<Ping> {
        if self.calls.fetch_add(1, Ordering::AcqRel) == 0 {
            self.entered.notify_one();
            let reason = context.cancelled().await;
            self.cancellations.lock().expect("not poisoned").push(reason);
            self.rollback_completed.store(true, Ordering::Release);
            return Err(rustfs_gateway::HandlerError::internal_error("the cancelled request rolled back"));
        }
        Ok(Resp::new(PingOutput {
            message: "the released permit admitted the next request".to_owned(),
        }))
    }
}

async fn pipelined_response_count(service: S3Service) -> (usize, String) {
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = live_server(service);
    let mut stream = TcpStream::connect(local_addr).await.expect("connect succeeds");
    stream
        .write_all(
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n\
              POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("pipelined requests write");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
        .await
        .expect("the connection reaches an observed terminal state")
        .expect("response reads");
    assert_eq!(shutdown.trigger(Duration::from_secs(1)).await, ShutdownReport { drained: 0, aborted: 0 });
    assert!(task.await.expect("server task joins").is_ok());
    let response = String::from_utf8(response).expect("an HTTP/1.1 response");
    (response.matches("HTTP/1.1 500").count(), response)
}

#[tokio::test]
async fn a_framing_conflict_reaches_the_response_as_a_close() {
    let mut request = plain(http::Method::POST, "/");
    request
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
    request
        .headers_mut()
        .insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
    let response = refusal(&service(), request).await;
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::Close));
}

#[tokio::test]
async fn a_head_verdict_reaches_the_response_without_one() {
    let mut request = plain(http::Method::POST, "/");
    request
        .headers_mut()
        .append(http::header::HOST, http::HeaderValue::from_static("other.example"));
    let response = refusal(&service(), request).await;
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::MayKeepAlive));
}

#[tokio::test]
async fn the_body_ceiling_closes_and_a_head_ceiling_does_not() {
    let body_limits = Limits {
        max_body_bytes: 0,
        ..Limits::default()
    };
    let body_service = wired()
        .register::<Ping, _>(std::sync::Arc::new(Backend))
        .route(ping_route())
        .limits(body_limits)
        .build()
        .expect("a complete assembly");
    let mut request = plain(http::Method::POST, "/");
    request
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("1"));
    let response = refusal(&body_service, request).await;
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::Close));

    let head_limits = Limits {
        max_header_count: 0,
        ..Limits::default()
    };
    let head_service = wired()
        .register::<Ping, _>(std::sync::Arc::new(Backend))
        .route(ping_route())
        .limits(head_limits)
        .build()
        .expect("a complete assembly");
    let response = refusal(&head_service, plain(http::Method::POST, "/")).await;
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::MayKeepAlive));
}

#[tokio::test]
async fn an_authorisation_denial_keeps_the_connection() {
    let service = wired_denying()
        .register::<Ping, _>(std::sync::Arc::new(Backend))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    let response = refusal(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::MayKeepAlive));
}

#[tokio::test]
async fn an_ordinary_refusal_keeps_the_connection_and_no_refusal_writes_the_header() {
    let service = wired()
        .register::<Ping, _>(std::sync::Arc::new(Failing))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    let response = refusal(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::MayKeepAlive));
    assert!(response.headers().get(http::header::CONNECTION).is_none());
}

#[tokio::test]
async fn a_response_no_refusal_produced_carries_no_verdict() {
    let response = refusal(&service(), plain(http::Method::POST, "/")).await;
    assert_eq!(connection_intent_of(&response), None);
}

/// Negative — an unacknowledged handler cancellation closes the real HTTP/1.1 connection after
/// the deadline response, so a pipelined second request cannot be answered on contaminated state.
#[tokio::test]
async fn an_unacknowledged_handler_deadline_closes_the_observed_socket() {
    let (service, _backend, recorder) = deadline_service(false);
    let (responses, wire) = pipelined_response_count(service).await;
    assert_eq!(
        responses, 1,
        "the server answered a pipelined request after unacknowledged cancellation: {wire}"
    );
    assert!(
        wire.to_ascii_lowercase().contains("connection: close\r\n"),
        "the peer was not warned before close: {wire}"
    );
    assert_eq!(
        recorder.seen.lock().expect("not poisoned").as_slice(),
        [Some(HandlerDeadlineReport::Unacknowledged)]
    );
}

/// Positive — a handler that acknowledges cancellation finishes cleanup before the grace expires,
/// so the same connection remains usable for the next request.
#[tokio::test]
async fn an_acknowledged_handler_deadline_keeps_the_observed_socket_reusable() {
    let (service, _backend, recorder) = deadline_service(true);
    let (responses, wire) = pipelined_response_count(service).await;
    assert_eq!(responses, 2, "the server closed a connection whose handler acknowledged cleanup: {wire}");
    assert_eq!(
        recorder.seen.lock().expect("not poisoned").as_slice(),
        [
            Some(HandlerDeadlineReport::Acknowledged),
            Some(HandlerDeadlineReport::Acknowledged),
        ]
    );
}

/// `c-lim-0060`. Negative — resetting a request while its one global request permit is held
/// signals the handler, lets it finish rollback, and releases the permit for another connection.
#[tokio::test]
async fn c_wire_0060_c_lim_0060_a_client_reset_cancels_the_handler_rolls_back_and_releases_its_permit() {
    let backend = Arc::new(ResetBackend::new());
    let service = wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    let server = live_server_with_config(
        service,
        ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            max_global_inflight_requests: 1,
            header_read_timeout: Duration::from_secs(1),
            keep_alive_idle: Duration::from_secs(2),
            ..ServerConfig::default()
        },
    );

    let mut reset = TcpStream::connect(server.local_addr)
        .await
        .expect("first connection succeeds");
    reset
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        .await
        .expect("first request writes");
    tokio::time::timeout(Duration::from_secs(1), backend.entered.notified())
        .await
        .expect("the first handler owns the request permit");
    let socket = socket2::Socket::from(reset.into_std().expect("stream converts"));
    socket.set_linger(Some(Duration::ZERO)).expect("RST linger configures");
    drop(socket);

    tokio::time::timeout(Duration::from_secs(1), async {
        while !backend.rollback_completed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the reset explicitly reaches the handler and rollback completes");

    let mut next = TcpStream::connect(server.local_addr)
        .await
        .expect("second connection succeeds");
    next.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .expect("second request writes");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), next.read_to_end(&mut response))
        .await
        .expect("the released permit admits the next request")
        .expect("second response reads");
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 "),
        "the next request was not admitted: {}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(
        backend.cancellations.lock().expect("not poisoned").as_slice(),
        [HandlerCancellation::RequestAborted]
    );

    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    assert!(server.task.await.expect("server task joins").is_ok());
}

/// Negative — the monomorphic path records the same unacknowledged cancellation verdict before
/// its response leaves the shared service pipeline.
#[tokio::test]
async fn a_monomorphic_unacknowledged_handler_deadline_carries_close_intent() {
    type Operations = OperationSetNode<Ping, OperationSetEnd>;
    let backend = Arc::new(DeadlineBackend {
        acknowledges_cleanup: false,
    });
    let recorder = Arc::new(DeadlineReportRecorder::default());
    let (builder, _handle) = wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .route(ping_route())
        .observer(Arc::clone(&recorder))
        .config(deadline_config());
    let service = builder
        .build_monomorphic::<_, Operations>(backend)
        .expect("a complete static assembly");

    let response = service.call_bytes(plain(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::Close));
    assert_eq!(
        recorder.seen.lock().expect("not poisoned").as_slice(),
        [Some(HandlerDeadlineReport::Unacknowledged)]
    );
}

/// Positive — a handler that completes before its deadline records no deadline outcome.
#[tokio::test]
async fn a_completed_handler_reports_no_deadline() {
    let recorder = Arc::new(DeadlineReportRecorder::default());
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .observer(Arc::clone(&recorder))
        .build()
        .expect("a complete assembly");

    let response = service.call_bytes(plain(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(recorder.seen.lock().expect("not poisoned").as_slice(), [None]);
}

/// `c-wire-0063`, server half. Negative — a `Content-Length` past the wire ceiling is refused on a
/// real socket before one byte of the body it promises is sent, and the socket is then closed.
///
/// The `crates/http` half of this case (`c_wire_0063_an_over_large_declared_body_is_400_entity_too_large_and_never_drained`)
/// reads `may_read_body()` and `must_close_connection()`, which are the service's *intentions*.
/// Neither is an observation of what the wire did, and this repository has shipped that
/// substitution seven times. What is observed here instead: the client writes a head declaring
/// 4096 body bytes and then writes nothing at all, and the complete response still arrives. An
/// implementation that drained the declared body before answering would still be waiting, and this
/// case would fail by timeout rather than by assertion.
///
/// The status is the second half. `EntityTooLarge` is a `400` in AWS's published error table and
/// in this repository's single status authority (`ErrorCode::ENTITY_TOO_LARGE`); a `413` carrying
/// that code would be a pairing no S3 client has seen, and would fork the wire layer away from the
/// one table that answers "which status does this code get?".
#[tokio::test]
async fn c_wire_0063_c_lim_0021_an_over_large_body_is_refused_on_the_socket_before_it_is_sent() {
    let limits = Limits {
        max_body_bytes: 16,
        ..Limits::default()
    };
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .limits(limits)
        .build()
        .expect("a complete assembly");
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = live_server(service);
    let mut stream = TcpStream::connect(local_addr).await.expect("connect succeeds");
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4096\r\n\r\n")
        .await
        .expect("the request head writes");

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("the refusal arrives without the body it declared, and the socket then reaches end of stream")
        .expect("response reads");
    let wire = String::from_utf8(response).expect("an HTTP/1.1 response");
    assert!(wire.starts_with("HTTP/1.1 400 "), "the refusal was not a 400: {wire}");
    assert!(
        wire.contains(rustfs_gateway::ErrorCode::ENTITY_TOO_LARGE.as_str()),
        "the refusal did not carry the S3 code clients branch on: {wire}"
    );
    assert!(
        wire.to_ascii_lowercase().contains("connection: close\r\n"),
        "the peer was not warned before close: {wire}"
    );

    assert_eq!(shutdown.trigger(Duration::from_secs(1)).await, ShutdownReport { drained: 0, aborted: 0 });
    assert!(task.await.expect("server task joins").is_ok());
}
