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

//! A handler's refusal before it reads a streaming body, against the dropped body's own verdict.
//!
//! Responsible for: rustfs/gateway#794 — a handler that refuses without reading a byte of its
//! body is answered with that refusal, in process over a `Full` body for `PutObject` and
//! `UploadPart` and over both production drivers on a real socket; and the two answers that must
//! not move with it: a body abandoned after the handler started reading it, and a success over a
//! body the handler never read (`c-ck-0062`), are both still refused for the body.
//! NOT responsible for: the stream's own terminal verdicts (`request_body_tests.rs`) or the body
//! deadlines (`streaming_request.rs`).
//! Upstream: `rustfs-gateway`, the streaming fixture in `support/streaming.rs`. Downstream:
//! goldens `rd-err-0004`, conformance `c-mpu-0053`.

#![allow(clippy::expect_used, clippy::panic)]

use crate::support;
use crate::support::streaming::{StreamingOutput, StreamingPut, service_with_deadlines};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use rustfs_gateway::{
    ConnectionIntent, Handler, HandlerError, HandlerErrorContext, HandlerResult, ObservedBody, OperationSetEnd, OperationSetNode,
    Req, RequestBodyDeadlineConfig, Resp, RunningServer, S3Service, SelfHeldHttp1Driver, dto,
};
use rustfs_gateway_server::{Server, ServerConfig, UnfinishedRequestBody};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn no_such_bucket() -> HandlerError {
    HandlerErrorContext::missing_bucket().into()
}

/// Refuses every request without reading a byte of its body.
///
/// The two object operations take the two orders the body verdict and the handler result can
/// arrive in. `PutObject` drops its body as it returns, so the verdict is sent inside the poll that
/// produces the refusal; `UploadPart` drops its body and yields first, so the verdict wakes the
/// monitor while the handler is still pending — the order a RustFS body awaiting its bucket lookup
/// takes.
struct RefusesUnread;

impl Handler<dto::PutObject> for RefusesUnread {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        drop(request.into_input());
        Err(no_such_bucket())
    }
}

impl Handler<dto::UploadPart> for RefusesUnread {
    async fn call(&self, request: Req<dto::UploadPart>) -> HandlerResult<dto::UploadPart> {
        drop(request.into_input());
        tokio::task::yield_now().await;
        Err(no_such_bucket())
    }
}

impl Handler<StreamingPut> for RefusesUnread {
    async fn call(&self, request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        drop(request.into_input());
        Err(no_such_bucket())
    }
}

/// Reads the first frame of its body, then refuses and abandons the rest.
struct AbandonsMidBody;

impl Handler<StreamingPut> for AbandonsMidBody {
    async fn call(&self, request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        let mut body = request.into_input().body.into_body();
        match body.frame().await {
            Some(Ok(_)) => Err(no_such_bucket()),
            _ => Err(HandlerError::internal_error("the first frame never arrived")),
        }
    }
}

/// Answers success over a body it never read.
struct SucceedsUnread;

impl Handler<StreamingPut> for SucceedsUnread {
    async fn call(&self, request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        drop(request.into_input());
        Ok(Resp::new(StreamingOutput))
    }
}

fn object_service() -> S3Service {
    let backend = Arc::new(RefusesUnread);
    support::wired_at_signed_time()
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::UploadPart, _>(backend)
        .build()
        .expect("a PutObject and UploadPart assembly")
}

fn streaming_service<B: Handler<StreamingPut>>(backend: B) -> S3Service {
    let deadlines = RequestBodyDeadlineConfig::new(Duration::from_secs(1), Duration::from_secs(1)).expect("non-zero deadlines");
    service_with_deadlines(Arc::new(backend), deadlines)
}

/// What one in-process answer carried: status, `<Code>`, the connection intent, and whether the
/// response tells the transport a body is still owed.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    status: u16,
    code: Option<String>,
    intent: Option<ConnectionIntent>,
    body_owed: bool,
}

async fn answer_of(response: http::Response<rustfs_gateway::Body>) -> Answer {
    let intent = response.extensions().get::<ConnectionIntent>().copied();
    let body_owed = response.extensions().get::<UnfinishedRequestBody>().is_some();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.expect("a finite response").to_bytes();
    let text = String::from_utf8_lossy(&body);
    Answer {
        status,
        code: support::element_text(&text, "Code").map(str::to_owned),
        intent,
        body_owed,
    }
}

fn refused_as_itself() -> Answer {
    Answer {
        status: 404,
        code: Some("NoSuchBucket".to_owned()),
        intent: Some(ConnectionIntent::MayKeepAlive),
        body_owed: true,
    }
}

fn refused_for_the_body() -> Answer {
    Answer {
        status: 400,
        code: Some("IncompleteBody".to_owned()),
        intent: Some(ConnectionIntent::Close),
        body_owed: false,
    }
}

fn signed_put(target: &str) -> http::Request<Bytes> {
    support::signed_target_with_body_and_headers(
        http::Method::PUT,
        target,
        &[("content-length", "5")],
        Bytes::from_static(b"hello"),
    )
}

fn unsigned_put(body: Bytes) -> http::Request<Bytes> {
    http::Request::put("/")
        .header("host", "localhost")
        .header("content-length", body.len())
        .body(body)
        .expect("a valid request")
}

/// rustfs/gateway#794, `PutObject`. Negative — the backend's `404` over a `Full` body it never
/// read is the answer in process, not `400 IncompleteBody`; the unread five bytes are left to the
/// transport's linger rather than turned into a close.
#[tokio::test]
async fn a_put_object_refused_before_its_body_is_read_answers_the_refusal_in_process() {
    let answer = answer_of(object_service().call_bytes(signed_put("/bucket/key")).await).await;
    assert_eq!(answer, refused_as_itself());
}

/// rustfs/gateway#794, `UploadPart`. Negative — the same over the other race order: the dropped
/// body's verdict reaches the monitor while the handler is still pending.
#[tokio::test]
async fn an_upload_part_refused_before_its_body_is_read_answers_the_refusal_in_process() {
    let request = signed_put("/bucket/key?partNumber=1&uploadId=missing-upload");
    let answer = answer_of(object_service().call_bytes(request).await).await;
    assert_eq!(answer, refused_as_itself());
}

/// rustfs/gateway#794 on the sealed monomorphic path, which settles the unread body in its own
/// handler wrapper. Negative — both operations, both race orders, answer as themselves there too.
#[tokio::test]
async fn the_monomorphic_path_answers_a_refusal_before_the_body_as_itself() {
    type Operations = OperationSetNode<dto::PutObject, OperationSetNode<dto::UploadPart, OperationSetEnd>>;
    let backend = Arc::new(RefusesUnread);
    let service = support::wired_at_signed_time()
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::UploadPart, _>(Arc::clone(&backend))
        .build_monomorphic::<_, Operations>(backend)
        .expect("a static PutObject and UploadPart assembly");
    for target in ["/bucket/key", "/bucket/key?partNumber=1&uploadId=missing-upload"] {
        let answer = answer_of(service.call_bytes(signed_put(target)).await).await;
        assert_eq!(answer, refused_as_itself(), "{target}");
    }
}

/// Negative control — a handler that read the first frame and then abandoned the body is still
/// answered for the body: the refusal it gave is not allowed to hide octets it consumed and then
/// left behind, and the connection closes (rd-err-0003's rule for a body in an unknown state).
#[tokio::test]
async fn a_body_abandoned_after_its_first_frame_is_still_refused_for_the_body() {
    let (parts, _) = unsigned_put(Bytes::from_static(b"first-second")).into_parts();
    let (body, progress) = ObservedBody::new([Bytes::from_static(b"first-"), Bytes::from_static(b"second")]);
    let response = streaming_service(AbandonsMidBody)
        .call(http::Request::from_parts(parts, body))
        .await;
    assert_eq!(answer_of(response).await, refused_for_the_body());
    assert_eq!(progress.bytes_read(), 6, "the handler read exactly its first frame");
}

/// Negative control (`c-ck-0062`) — a success over a body the handler never read is still refused:
/// only a refusal may stand over an unread body, because no commit may be manufactured from bytes
/// that never arrived.
#[tokio::test]
async fn a_success_over_a_body_never_read_is_still_refused() {
    let response = streaming_service(SucceedsUnread)
        .call_bytes(unsigned_put(Bytes::from_static(b"hello")))
        .await;
    assert_eq!(answer_of(response).await, refused_for_the_body());
}

// ── the wire ──────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Driver {
    Hyper,
    SelfHeld,
}

fn serve(service: S3Service, driver: Driver) -> RunningServer {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        tcp_nodelay: true,
        ..ServerConfig::default()
    };
    let server = Server::new(config, service);
    match driver {
        Driver::Hyper => server.serve(),
        Driver::SelfHeld => server.serve_with(SelfHeldHttp1Driver),
    }
    .expect("the loopback server starts")
}

async fn halt(running: RunningServer) {
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}

/// Sends one `PUT /` with a 30-byte body, `first` of it before `settle` resolves and the rest
/// after, and reads until the server closes or goes quiet.
async fn exchange(address: SocketAddr, first: usize, settle: impl core::future::Future<Output = ()>) -> (String, bool) {
    const BODY: &[u8; 30] = b"a part the backend never reads";
    let mut stream = TcpStream::connect(address).await.expect("the client connects");
    stream
        .write_all(b"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 30\r\n\r\n")
        .await
        .expect("the head writes");
    stream.write_all(&BODY[..first]).await.expect("the first octets write");
    settle.await;
    let _ = stream.write_all(&BODY[first..]).await;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    let closed = loop {
        match tokio::time::timeout(Duration::from_millis(400), stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break true,
            Ok(Ok(read)) => response.extend_from_slice(&buffer[..read]),
            Err(_) => break false,
        }
    };
    (String::from_utf8_lossy(&response).into_owned(), closed)
}

/// rustfs/gateway#794 on the wire. Negative — both production drivers answer the backend's
/// refusal of a body it never read, with the whole error document; a `400 IncompleteBody` here
/// would blame the client's framing for octets the server chose not to read.
#[tokio::test]
async fn both_drivers_answer_a_refusal_before_the_body_as_itself() {
    for driver in [Driver::Hyper, Driver::SelfHeld] {
        let running = serve(streaming_service(RefusesUnread), driver);
        let (text, _) = exchange(running.local_addr, 30, async {}).await;
        assert!(text.starts_with("HTTP/1.1 404"), "{driver:?}: {text}");
        assert!(text.contains("<Code>NoSuchBucket</Code>"), "{driver:?}: {text}");
        assert!(!text.to_ascii_lowercase().contains("connection: close"), "{driver:?}: {text}");
        halt(running).await;
    }
}

/// Negative control on the wire — a body abandoned after its first frame is still `400
/// IncompleteBody` with a close on both drivers: the fix does not reach a body the handler began.
#[tokio::test]
async fn both_drivers_still_refuse_a_body_abandoned_mid_read() {
    for driver in [Driver::Hyper, Driver::SelfHeld] {
        let running = serve(streaming_service(AbandonsMidBody), driver);
        let (text, closed) = exchange(running.local_addr, 10, tokio::time::sleep(Duration::from_millis(100))).await;
        assert!(text.starts_with("HTTP/1.1 400"), "{driver:?}: {text}");
        assert!(text.contains("<Code>IncompleteBody</Code>"), "{driver:?}: {text}");
        assert!(text.to_ascii_lowercase().contains("connection: close"), "{driver:?}: {text}");
        assert!(closed, "{driver:?}: the connection outlived a body in an unknown state");
        halt(running).await;
    }
}
