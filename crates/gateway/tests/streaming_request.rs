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

//! Live-socket contracts for streaming request ownership and back-pressure.
//!
//! Responsible for: proving that handler polling drives socket polling in both directions and
//! that body-idle cancellation reaches a live handler. NOT responsible for: signed-chunk framing
//! or resident-set measurement. Upstream: `rustfs-gateway` and the generic server runtime.
//! Downstream: c-ing-0061 acceptance evidence.

#![allow(clippy::expect_used, clippy::panic)]

use crate::support;

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use rustfs_gateway::{
    AuthRequirement, ByteStream, CodecError, EncodedResponse, Handler, HandlerCancellation, HandlerDeadlineClass, HandlerError,
    HandlerResult, MetaView, NoDerived, Operation, OperationCodec, OperationFloor, OperationSpec, Predicate, Req, RequestBody,
    RequestBodyDeadlineConfig, RequestBodyMode, ResourceShape, Resp, ResponseBody, RouteEntry, RouteSelector, S3Service,
    ServiceConfig, SigService, TargetKind,
};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, ShutdownReport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::sync::{Barrier, watch};

struct StreamingPut;

struct StreamingInput {
    body: ByteStream,
}

struct StreamingOutput;

static STREAMING_SPEC: OperationSpec = OperationSpec::builder("example:StreamingPut", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("example:StreamingPut", ResourceShape::Service))
    .build();

static STREAMING_FLOOR: OperationFloor =
    OperationFloor::custom("example:StreamingPut", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

static STREAMING_PREDICATES: &[Predicate] = &[Predicate::Method(http::Method::PUT), Predicate::Target(TargetKind::Service)];

impl Operation for StreamingPut {
    const NAME: &'static str = "example:StreamingPut";

    type Input = StreamingInput;
    type Output = StreamingOutput;
    type DerivedResources = NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway::DerivedResourceError> {
        Ok(NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &STREAMING_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &STREAMING_FLOOR
    }
}

impl OperationCodec for StreamingPut {
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::Streaming;

    fn decode(_request: &MetaView<'_>, body: RequestBody) -> Result<Self::Input, CodecError> {
        body.into_stream()
            .map(|body| StreamingInput { body })
            .ok_or_else(|| CodecError::internal("the streaming operation was not handed a live body"))
    }

    fn encode(_output: Self::Output, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut response = EncodedResponse::of(status);
        response.body = ResponseBody::Complete(b"ok".to_vec());
        Ok(response)
    }
}

fn streaming_route() -> RouteEntry {
    RouteEntry {
        precedence: 50,
        selector: RouteSelector::new(STREAMING_PREDICATES),
        op_name: StreamingPut::NAME,
        path_shape: "/",
    }
}

async fn first_frame(body: &mut rustfs_gateway::Body) -> Result<usize, HandlerError> {
    match body.frame().await {
        Some(Ok(frame)) => frame
            .into_data()
            .map(|bytes| bytes.len())
            .map_err(|_| HandlerError::internal_error("the first request frame carried no data")),
        Some(Err(_)) | None => Err(HandlerError::internal_error("the request body ended before its first data frame")),
    }
}

struct IdleBackend {
    entered: Notify,
    cancellation: Mutex<Option<HandlerCancellation>>,
}

impl IdleBackend {
    fn new() -> Self {
        Self {
            entered: Notify::new(),
            cancellation: Mutex::new(None),
        }
    }
}

impl Handler<StreamingPut> for IdleBackend {
    async fn call(&self, _request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        Err(HandlerError::internal_error("the context-aware entry was bypassed"))
    }

    async fn call_with_context(
        &self,
        request: Req<StreamingPut>,
        context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<StreamingPut> {
        let mut body = request.into_input().body.into_body();
        let _ = first_frame(&mut body).await?;
        self.entered.notify_one();
        let reason = context.cancelled().await;
        *self.cancellation.lock().expect("not poisoned") = Some(reason);
        Err(HandlerError::internal_error("the cancelled upload rolled back"))
    }
}

struct PausingBackend {
    entered: Notify,
    release: Notify,
    drain_after_release: bool,
    observed: Mutex<usize>,
}

struct ResidentBackend {
    barrier: Arc<Barrier>,
    release: watch::Sender<bool>,
    entered: AtomicUsize,
}

struct SwallowingBackend;

impl Handler<StreamingPut> for SwallowingBackend {
    async fn call(&self, request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        let mut body = request.into_input().body.into_body();
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                break;
            }
        }
        Ok(Resp::new(StreamingOutput))
    }
}

impl Handler<StreamingPut> for ResidentBackend {
    async fn call(&self, _request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        Err(HandlerError::internal_error("the context-aware entry was bypassed"))
    }

    async fn call_with_context(
        &self,
        request: Req<StreamingPut>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<StreamingPut> {
        let mut release = self.release.subscribe();
        let mut body = request.into_input().body.into_body();
        let _ = first_frame(&mut body).await?;
        self.entered.fetch_add(1, Ordering::AcqRel);
        self.barrier.wait().await;
        while !*release.borrow() {
            release
                .changed()
                .await
                .map_err(|_| HandlerError::internal_error("the resident probe release disappeared"))?;
        }
        Ok(Resp::new(StreamingOutput))
    }
}

impl PausingBackend {
    fn new(drain_after_release: bool) -> Self {
        Self {
            entered: Notify::new(),
            release: Notify::new(),
            drain_after_release,
            observed: Mutex::new(0),
        }
    }
}

impl Handler<StreamingPut> for PausingBackend {
    async fn call(&self, _request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        Err(HandlerError::internal_error("the context-aware entry was bypassed"))
    }

    async fn call_with_context(
        &self,
        request: Req<StreamingPut>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<StreamingPut> {
        let mut body = request.into_input().body.into_body();
        let mut observed = first_frame(&mut body).await?;
        self.entered.notify_one();
        self.release.notified().await;
        if self.drain_after_release {
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| HandlerError::internal_error("the request body failed"))?;
                if let Ok(bytes) = frame.into_data() {
                    observed = observed.saturating_add(bytes.len());
                }
            }
        }
        *self.observed.lock().expect("not poisoned") = observed;
        Ok(Resp::new(StreamingOutput))
    }
}

fn service<B>(backend: Arc<B>, body_idle: Duration) -> S3Service
where
    B: Handler<StreamingPut>,
{
    let deadlines = RequestBodyDeadlineConfig::new(Duration::from_secs(1), body_idle).expect("non-zero body deadlines");
    let (builder, _handle) = support::wired()
        .register::<StreamingPut, _>(backend)
        .route(streaming_route())
        .config(ServiceConfig::new(1024 * 1024).with_request_body_deadlines(deadlines));
    builder.build().expect("a complete streaming assembly")
}

fn live_server(service: S3Service) -> RunningServer {
    let service = tower::service_fn(move |request| {
        let mut service = service.clone();
        async move {
            let response = <S3Service as tower::Service<_>>::call(&mut service, request)
                .await
                .expect("the adapter is infallible");
            let collected = rustfs_gateway::collect(response).await.expect("the response is finite");
            let (status, headers, body, _trailers) = collected.into_parts();
            let mut response = http::Response::new(Full::new(body));
            *response.status_mut() = status;
            for (name, value) in headers {
                response.headers_mut().append(name, value);
            }
            Ok::<_, Infallible>(response)
        }
    });
    Server::new(
        ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            so_rcvbuf: Some(8 * 1024),
            lingering_close_time: Duration::from_millis(20),
            ..ServerConfig::default()
        },
        service,
    )
    .serve()
    .expect("the loopback server starts")
}

fn head(content_length: usize) -> Vec<u8> {
    format!("PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n").into_bytes()
}

fn head_with(content_length: usize, header: &str) -> Vec<u8> {
    format!("PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {content_length}\r\n{header}\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

async fn stop(running: RunningServer) {
    assert_eq!(
        running.shutdown.trigger(Duration::from_secs(1)).await,
        ShutdownReport { drained: 0, aborted: 0 }
    );
    assert!(running.task.await.expect("the server task joins").is_ok());
}

fn rss_bytes() -> Option<usize> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let kibibytes = String::from_utf8(output.stdout).ok()?.trim().parse::<usize>().ok()?;
    kibibytes.checked_mul(1024)
}

fn resident_ballast(bytes: usize) -> Vec<u8> {
    let mut state = 0x6d2b_79f5_u32;
    let mut ballast = Vec::with_capacity(bytes);
    for _ in 0..bytes {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        ballast.push(state as u8);
    }
    ballast
}

/// `c-ing-0061`. Negative — a handler that stops polling is cancelled for body idleness, and the
/// live HTTP/1 connection observes the corresponding closing `408` response.
#[tokio::test]
async fn c_ing_0061_body_idle_cancels_a_live_handler_and_closes_the_socket() {
    let backend = Arc::new(IdleBackend::new());
    let running = live_server(service(Arc::clone(&backend), Duration::from_millis(30)));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(&head(4)).await.expect("the head writes");
    stream.write_all(b"x").await.expect("the first body byte writes");
    backend.entered.notified().await;

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
        .await
        .expect("the body-idle deadline retires the request")
        .expect("the response reads");
    let text = String::from_utf8(response).expect("an HTTP/1.1 response");
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert_eq!(*backend.cancellation.lock().expect("not poisoned"), Some(HandlerCancellation::BodyIdle));
    stop(running).await;
}

/// `c-ing-0061`. Negative direction — once the handler stops polling, a live client's writes hit
/// TCP back-pressure instead of the gateway reading ahead into a whole-body collector.
#[tokio::test]
async fn c_ing_0061_handler_stall_stops_live_socket_progress() {
    const LOGICAL_BYTES: usize = 64 * 1024 * 1024;
    let backend = Arc::new(PausingBackend::new(false));
    let running = live_server(service(Arc::clone(&backend), Duration::from_secs(2)));
    let standard = std::net::TcpStream::connect(running.local_addr).expect("the client connects");
    socket2::SockRef::from(&standard)
        .set_send_buffer_size(8 * 1024)
        .expect("the client send buffer is bounded");
    standard.set_nonblocking(true).expect("the socket becomes asynchronous");
    let mut stream = TcpStream::from_std(standard).expect("tokio adopts the socket");
    stream.write_all(&head(LOGICAL_BYTES)).await.expect("the head writes");
    stream.write_all(b"x").await.expect("the first body byte writes");
    backend.entered.notified().await;

    let chunk = [0x5a_u8; 64 * 1024];
    let write = async {
        let mut sent = 1usize;
        while sent < LOGICAL_BYTES {
            stream.write_all(&chunk).await.expect("the live socket remains writable");
            sent = sent.saturating_add(chunk.len());
        }
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(200), write).await.is_err(),
        "the gateway read the complete 64 MiB logical body while its handler was stalled"
    );
    backend.release.notify_one();
    drop(stream);
    stop(running).await;
}

/// `c-ing-0061`. Positive direction — after a paused handler polls again, bytes already offered by
/// the same live socket resume flowing and the complete terminal verdict permits `200`.
#[tokio::test]
async fn c_ing_0061_resumed_handler_resumes_live_socket_progress() {
    let backend = Arc::new(PausingBackend::new(true));
    let running = live_server(service(Arc::clone(&backend), Duration::from_secs(1)));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(&head(12)).await.expect("the head writes");
    stream.write_all(b"first-").await.expect("the first frame writes");
    backend.entered.notified().await;
    stream.write_all(b"second").await.expect("the remaining frame writes");
    backend.release.notify_one();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
        .await
        .expect("the resumed handler completes")
        .expect("the response reads");
    let text = String::from_utf8(response).expect("an HTTP/1.1 response");
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert_eq!(*backend.observed.lock().expect("not poisoned"), 12);
    stop(running).await;
}

/// Negative — a handler cannot swallow the stream's terminal checksum error and commit its own
/// successful result. The gateway-owned terminal verdict wins before the response head.
#[tokio::test]
async fn a_terminal_checksum_refusal_outranks_a_handlers_success() {
    let running = live_server(service(Arc::new(SwallowingBackend), Duration::from_secs(1)));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream
        .write_all(&head_with(5, "x-amz-checksum-crc32: DUoRhQ=="))
        .await
        .expect("the checksummed head writes");
    stream.write_all(b"wrong").await.expect("the mismatching body writes");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
        .await
        .expect("the terminal checksum verdict completes")
        .expect("the response reads");
    let text = String::from_utf8(response).expect("an HTTP/1.1 response");
    assert!(!text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("<Code>XAmzContentChecksumMismatch</Code>"), "{text}");
    stop(running).await;
}

/// Negative — an early socket EOF remains `IncompleteBody` even when the handler catches the
/// stream error and returns success.
#[tokio::test]
async fn a_terminal_length_refusal_outranks_a_handlers_success() {
    let running = live_server(service(Arc::new(SwallowingBackend), Duration::from_secs(1)));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(&head(4)).await.expect("the head writes");
    stream.write_all(b"abc").await.expect("the short body writes");
    stream.shutdown().await.expect("the client publishes EOF");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
        .await
        .expect("the terminal length verdict completes")
        .expect("the response reads");
    let text = String::from_utf8(response).expect("an HTTP/1.1 response");
    assert!(!text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("<Code>IncompleteBody</Code>"), "{text}");
    stop(running).await;
}

/// `c-ing-0063`. Negative — eight concurrent 16 MiB logical uploads stay below the 4 MiB
/// per-connection resident contract while all eight handlers are stopped at the same live-socket
/// barrier. Every writer generates private changing pages; no shared pre-built body stands in for
/// resident ownership.
#[tokio::test]
async fn c_ing_0063_concurrent_large_live_uploads_keep_bounded_resident_ownership() {
    const TEST_NAME: &str = "streaming_request::c_ing_0063_concurrent_large_live_uploads_keep_bounded_resident_ownership";
    const CHILD: &str = "RUSTFS_GATEWAY_STREAMING_RSS_CHILD";
    const CONNECTIONS: usize = 8;
    const LOGICAL_BYTES: usize = 16 * 1024 * 1024;
    const PER_CONNECTION_BUDGET: usize = 4 * 1024 * 1024;
    const PROCESS_HEADROOM: usize = 8 * 1024 * 1024;
    const BALLAST_BYTES: usize = 8 * 1024 * 1024;

    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().expect("the test executable has a path"))
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .expect("the isolated resident probe starts");
        let report = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success(), "the isolated resident probe failed:\n{report}");
        assert!(report.contains("1 passed"), "the isolated child ran no test:\n{report}");
        return;
    }

    let before_ballast = rss_bytes().expect("RSS is readable through ps");
    let ballast = resident_ballast(BALLAST_BYTES);
    std::hint::black_box(&ballast);
    let after_ballast = rss_bytes().expect("RSS remains readable");
    let ballast_seen = after_ballast.saturating_sub(before_ballast);
    assert!(
        ballast_seen >= BALLAST_BYTES / 2,
        "the RSS observer saw only {ballast_seen} of {BALLAST_BYTES} unique ballast bytes"
    );

    let barrier = Arc::new(Barrier::new(CONNECTIONS + 1));
    let (release, _release_rx) = watch::channel(false);
    let backend = Arc::new(ResidentBackend {
        barrier: Arc::clone(&barrier),
        release,
        entered: AtomicUsize::new(0),
    });
    let running = live_server(service(Arc::clone(&backend), Duration::from_secs(5)));
    let baseline = rss_bytes().expect("RSS is readable before the live upload wave");
    let mut writers = Vec::with_capacity(CONNECTIONS);
    for connection in 0..CONNECTIONS {
        let address = running.local_addr;
        writers.push(tokio::spawn(async move {
            let standard = std::net::TcpStream::connect(address).expect("the upload connects");
            socket2::SockRef::from(&standard)
                .set_send_buffer_size(8 * 1024)
                .expect("the upload send buffer is bounded");
            standard.set_nonblocking(true).expect("the upload becomes asynchronous");
            let mut stream = TcpStream::from_std(standard).expect("tokio adopts the upload socket");
            stream.write_all(&head(LOGICAL_BYTES)).await.expect("the upload head writes");
            let mut sent = 0usize;
            let mut state = (connection as u32).wrapping_add(1).wrapping_mul(0x9e37_79b9);
            let mut chunk = [0_u8; 64 * 1024];
            while sent < LOGICAL_BYTES {
                for byte in &mut chunk {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    *byte = state as u8;
                }
                stream.write_all(&chunk).await.expect("the live upload remains writable");
                sent = sent.saturating_add(chunk.len());
            }
            stream
        }));
    }

    tokio::time::timeout(Duration::from_secs(3), barrier.wait())
        .await
        .expect("every live handler reaches the synchronized resident barrier");
    assert_eq!(backend.entered.load(Ordering::Acquire), CONNECTIONS);
    let loaded = rss_bytes().expect("RSS is readable at the synchronized live-socket barrier");
    let growth = loaded.saturating_sub(baseline);
    let budget = CONNECTIONS * PER_CONNECTION_BUDGET + PROCESS_HEADROOM;
    eprintln!(
        "c-ing-0063 live RSS: connections={CONNECTIONS} logical_bytes={LOGICAL_BYTES} growth_bytes={growth} budget_bytes={budget}"
    );
    assert!(
        growth <= budget,
        "{CONNECTIONS} concurrent live uploads retained {growth} bytes, above the {budget}-byte process budget"
    );

    for writer in writers {
        writer.abort();
        let _ = writer.await;
    }
    let _ = backend.release.send(true);
    tokio::time::sleep(Duration::from_millis(50)).await;
    stop(running).await;
    drop(ballast);
}
