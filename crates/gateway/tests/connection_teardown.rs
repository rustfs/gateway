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
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use rustfs_gateway::{
    ConnectionIntent, Handler, HandlerCancellation, HandlerDeadlineConfig, HandlerResult, Limits, OperationSetEnd,
    OperationSetNode, Req, Resp, S3Service, ServiceConfig, connection_intent_of,
};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, ShutdownReport};
use support::{Backend, Failing, Ping, PingOutput, ping_route, plain, service, wired, wired_denying};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn refusal(service: &S3Service, request: http::Request<Bytes>) -> http::Response<rustfs_gateway::Body> {
    service.call_bytes(request).await
}

struct DeadlineBackend {
    acknowledges_cleanup: bool,
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

fn deadline_service(acknowledges_cleanup: bool) -> (S3Service, Arc<DeadlineBackend>) {
    let backend = Arc::new(DeadlineBackend { acknowledges_cleanup });
    let (builder, _handle) = wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .route(ping_route())
        .config(deadline_config());
    (builder.build().expect("a complete assembly"), backend)
}

fn live_server(service: S3Service) -> RunningServer {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: Duration::from_secs(1),
        keep_alive_idle: Duration::from_secs(2),
        ..ServerConfig::default()
    };
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
    let (service, _backend) = deadline_service(false);
    let (responses, wire) = pipelined_response_count(service).await;
    assert_eq!(
        responses, 1,
        "the server answered a pipelined request after unacknowledged cancellation: {wire}"
    );
    assert!(
        wire.to_ascii_lowercase().contains("connection: close\r\n"),
        "the peer was not warned before close: {wire}"
    );
}

/// Positive — a handler that acknowledges cancellation finishes cleanup before the grace expires,
/// so the same connection remains usable for the next request.
#[tokio::test]
async fn an_acknowledged_handler_deadline_keeps_the_observed_socket_reusable() {
    let (service, _backend) = deadline_service(true);
    let (responses, wire) = pipelined_response_count(service).await;
    assert_eq!(responses, 2, "the server closed a connection whose handler acknowledged cleanup: {wire}");
}

/// Negative — the monomorphic path records the same unacknowledged cancellation verdict before
/// its response leaves the shared service pipeline.
#[tokio::test]
async fn a_monomorphic_unacknowledged_handler_deadline_carries_close_intent() {
    type Operations = OperationSetNode<Ping, OperationSetEnd>;
    let backend = Arc::new(DeadlineBackend {
        acknowledges_cleanup: false,
    });
    let (builder, _handle) = wired()
        .register::<Ping, _>(Arc::clone(&backend))
        .route(ping_route())
        .config(deadline_config());
    let service = builder
        .build_monomorphic::<_, Operations>(backend)
        .expect("a complete static assembly");

    let response = service.call_bytes(plain(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::Close));
}
