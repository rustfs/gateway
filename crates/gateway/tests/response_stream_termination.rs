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

//! How a streaming response installed by `StageFilter::on_response` ends on a real socket.
//!
//! Responsible for: c-mw-0024. A response filter can replace a body with one whose length nobody
//! knows, and declare a `Content-Length` of its own. The final invariant pass corrects a declared
//! length only when the body's length is known, so for such a body the declaration reaches the
//! transport unchanged. This suite checks what each production HTTP/1.1 driver (the default Hyper
//! driver and the self-held driver) then does in four cases: the stream reaches the declared
//! length exactly, it ends short, it fails mid-stream, or the client goes away mid-stream. It also
//! records where the observer is called in each case, for ordinary and committed responses.
//! NOT responsible for: framing of bodies whose length is known, which `payload_transport.rs` and
//! the invariant unit tests cover; or committed-response keep-alive timing (`committed_progress.rs`).
//! Upstream: `S3Service` behind `rustfs_gateway_server::Server`. Downstream: the c-mw-0024 row of
//! rustfs/backlog#1731.
//!
//! # Where the observer fires
//!
//! On an ordinary response the observer is called once, inside the service call, before the
//! response is handed to the transport. It therefore reports the head and nothing about the body:
//! the report is identical whether the body completes, ends short, fails or is abandoned, and it is
//! recorded before the transport polls the first body frame. On a committed response the report
//! waits for the detached work. It is not sent when the head leaves, and it still arrives after the
//! client abandons the body.

use crate::support;

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use rustfs_gateway::dto::{CopyObject, CopyObjectOutput};
use rustfs_gateway::{
    Body, Handler, HandlerResult, HeadPart, Observer, Req, RequestEvent, Resp, S3Service, SelfHeldHttp1Driver, response_filter,
};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig};
use rustfs_gateway_stream::{PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders};
use support::{Backend, Ping};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

const DECLARED: usize = 12;
const PING: &[u8] = b"POST / HTTP/1.1\r\nHost: s3.example.com\r\nContent-Length: 0\r\n\r\n";
const DEADLINE: Duration = Duration::from_secs(3);

type Events = Arc<Mutex<Vec<String>>>;

fn note(events: &Events, event: impl Into<String>) {
    events.lock().expect("the event log is not poisoned").push(event.into());
}

fn events_of(events: &Events) -> Vec<String> {
    events.lock().expect("the event log is not poisoned").clone()
}

// ── the body a filter installs ──────────────────────────────────────────────────────────────────

/// How the installed stream ends after its chunks.
#[derive(Clone, Copy)]
enum End {
    /// A clean end of stream.
    Eof,
    /// A producer failure.
    Fail,
    /// Never ends: one more chunk on every poll, for a client that leaves.
    Endless,
}

/// Holds a stream between its chunks and its end until the test has read what came before.
///
/// Without it the head, the chunks and the end are produced in one poll, and a driver may abandon
/// the connection before flushing any of them, which is a different case: the client then sees a
/// close with no response at all. The gate makes "mid-stream" mean that the client has already
/// received the head and the first bytes.
#[derive(Default)]
struct Gate {
    open: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Gate {
    fn open(&self) {
        self.open.store(true, Ordering::Release);
        if let Some(waker) = self.waker.lock().expect("the gate is not poisoned").take() {
            waker.wake();
        }
    }

    fn is_open(&self, context: &Context<'_>) -> bool {
        if self.open.load(Ordering::Acquire) {
            return true;
        }
        *self.waker.lock().expect("the gate is not poisoned") = Some(context.waker().clone());
        self.open.load(Ordering::Acquire)
    }
}

/// A push stream that states no length, so no invariant can check it against a declaration.
struct Installed {
    chunks: VecDeque<Bytes>,
    end: End,
    gate: Option<Arc<Gate>>,
    polled: bool,
    events: Events,
    dropped: Arc<AtomicBool>,
}

impl PayloadStream for Installed {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        if !self.polled {
            self.polled = true;
            note(&self.events, "first body poll");
        }
        if let Some(chunk) = self.chunks.pop_front() {
            return Poll::Ready(Ok(PayloadRead::Chunk(chunk)));
        }
        if self.gate.as_ref().is_some_and(|gate| !gate.is_open(context)) {
            return Poll::Pending;
        }
        Poll::Ready(match self.end {
            End::Eof => Ok(PayloadRead::Eof {
                trailers: TrailingHeaders::empty(),
            }),
            End::Fail => Err(StreamError::upstream(Box::new(std::io::Error::other("the installed producer failed")))),
            End::Endless => Ok(PayloadRead::Chunk(Bytes::from(vec![b'x'; 16 * 1024]))),
        })
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

/// What the filter installs, once: the first `Ping` gets it, later requests are left alone.
struct Plan {
    declared: Option<usize>,
    chunks: Vec<&'static [u8]>,
    end: End,
    /// Whether the end waits for [`Installation::gate`].
    held: bool,
}

struct Recorder(Events);

impl Observer for Recorder {
    fn on_response(&self, event: &RequestEvent<'_>) {
        note(
            &self.0,
            format!("observer {} error={:?}", event.status, event.error.map(|code| code.as_str().to_owned())),
        );
    }
}

struct Installation {
    events: Events,
    dropped: Arc<AtomicBool>,
    gate: Arc<Gate>,
    service: S3Service,
}

fn installing(plan: Plan) -> Installation {
    let events = Events::default();
    let dropped = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(Gate::default());
    let slot = Mutex::new(Some(plan));
    let stream_events = Arc::clone(&events);
    let stream_dropped = Arc::clone(&dropped);
    let stream_gate = Arc::clone(&gate);
    let service = support::wired()
        .dialect(&support::ping_dialect())
        .register::<Ping, _>(Arc::new(Backend))
        .stage_filter(response_filter(move |view, response| {
            if view.operation() != Some("example:Ping") {
                return Ok(());
            }
            let Some(plan) = slot.lock().expect("the plan slot is not poisoned").take() else {
                return Ok(());
            };
            let stream = Installed {
                chunks: plan.chunks.into_iter().map(Bytes::from_static).collect(),
                end: plan.end,
                gate: plan.held.then(|| Arc::clone(&stream_gate)),
                polled: false,
                events: Arc::clone(&stream_events),
                dropped: Arc::clone(&stream_dropped),
            };
            *response.body_mut() = Body::from_stream(stream).expect("a lengthless push stream is consistent");
            let headers = response.headers_mut();
            headers.remove(http::header::CONTENT_LENGTH);
            if let Some(declared) = plan.declared {
                headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(declared));
            }
            Ok(())
        }))
        .observer(Recorder(Arc::clone(&events)))
        .build()
        .expect("a complete assembly");
    Installation {
        events,
        dropped,
        gate,
        service,
    }
}

// ── the two production drivers ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Driver {
    Hyper,
    SelfHeld,
}

const DRIVERS: [Driver; 2] = [Driver::Hyper, Driver::SelfHeld];

fn start(service: S3Service, driver: Driver) -> RunningServer {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        tcp_nodelay: true,
        so_sndbuf: Some(4 * 1024),
        keep_alive_idle: Duration::from_secs(30),
        ..ServerConfig::default()
    };
    let server = Server::new(config, service);
    match driver {
        Driver::Hyper => server.serve(),
        Driver::SelfHeld => server.serve_with(SelfHeldHttp1Driver),
    }
    .expect("the server starts")
}

async fn stop(running: RunningServer) {
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}

/// Reads until the end of the response head and returns it with whatever body bytes followed.
async fn read_head(client: &mut TcpStream) -> (String, Vec<u8>) {
    tokio::time::timeout(DEADLINE, async {
        let mut received = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8(received[..end + 4].to_vec()).expect("an HTTP head is text");
                return (head.to_ascii_lowercase(), received[end + 4..].to_vec());
            }
            let read = client.read(&mut buffer).await.expect("the head reads");
            assert_ne!(read, 0, "the connection closed before a response head arrived");
            received.extend_from_slice(&buffer[..read]);
        }
    })
    .await
    .expect("a response head arrives")
}

/// Reads until `needle` has arrived, so a later failure is known to happen mid-stream.
async fn read_through(client: &mut TcpStream, mut received: Vec<u8>, needle: &[u8]) -> Vec<u8> {
    tokio::time::timeout(DEADLINE, async {
        let mut buffer = [0_u8; 1024];
        while !received.windows(needle.len()).any(|window| window == needle) {
            let read = client.read(&mut buffer).await.expect("the body reads");
            assert_ne!(read, 0, "the connection closed before the first body bytes arrived");
            received.extend_from_slice(&buffer[..read]);
        }
        received
    })
    .await
    .expect("the first body bytes arrive")
}

/// Reads until the peer ends the connection. A reset ends it too; neither is a hang.
async fn read_to_close(client: &mut TcpStream, mut received: Vec<u8>) -> Vec<u8> {
    tokio::time::timeout(DEADLINE, async {
        let mut buffer = [0_u8; 1024];
        loop {
            match client.read(&mut buffer).await {
                Ok(0) | Err(_) => return received,
                Ok(read) => received.extend_from_slice(&buffer[..read]),
            }
        }
    })
    .await
    .expect("the connection ends instead of leaving the client waiting for the declared bytes")
}

async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    tokio::time::timeout(DEADLINE, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting until {what}"));
}

async fn connect(running: &RunningServer, request: &[u8]) -> TcpStream {
    let mut client = TcpStream::connect(running.local_addr).await.expect("the client connects");
    client.write_all(request).await.expect("the request writes");
    client
}

fn reset(client: TcpStream) {
    let socket = socket2::Socket::from(client.into_std().expect("the client stream converts"));
    socket.set_linger(Some(Duration::ZERO)).expect("an RST linger configures");
    drop(socket);
}

/// The ordinary-response observer contract: one report, of the head, before the body was polled.
fn assert_head_reported_before_the_body(events: &Events, driver: Driver) {
    assert_eq!(
        events_of(events),
        ["observer 200 error=None", "first body poll"],
        "{driver:?}: the observer reports the head once, before the transport polls the body"
    );
}

// ── cases ───────────────────────────────────────────────────────────────────────────────────────

/// Positive control. A stream that reaches its declared length exactly is delivered with that
/// `Content-Length` and no chunked framing, and the connection stays usable: the next request on
/// the same socket is answered in full, so the declared length and the bytes on the wire agreed.
#[tokio::test]
async fn c_mw_0024_an_exact_declared_length_is_delivered_and_keeps_the_connection() {
    for driver in DRIVERS {
        let installed = installing(Plan {
            declared: Some(DECLARED),
            chunks: vec![b"hello ", b"world!"],
            end: End::Eof,
            held: false,
        });
        let running = start(installed.service.clone(), driver);
        let mut client = connect(&running, PING).await;
        let (head, mut body) = read_head(&mut client).await;
        assert!(head.starts_with("http/1.1 200 "), "{driver:?}: {head}");
        assert!(head.contains("content-length: 12\r\n"), "{driver:?}: {head}");
        assert!(!head.contains("transfer-encoding"), "{driver:?}: {head}");
        tokio::time::timeout(DEADLINE, async {
            let mut buffer = [0_u8; 64];
            while body.len() < DECLARED {
                let read = client.read(&mut buffer).await.expect("the body reads");
                assert_ne!(read, 0, "{driver:?}: the connection closed before the declared length");
                body.extend_from_slice(&buffer[..read]);
            }
        })
        .await
        .expect("the declared bytes arrive");
        assert_eq!(body, b"hello world!", "{driver:?}");
        assert_head_reported_before_the_body(&installed.events, driver);

        client.write_all(PING).await.expect("the second request writes");
        let (second, mut rest) = read_head(&mut client).await;
        assert!(second.starts_with("http/1.1 200 "), "{driver:?}: {second}");
        tokio::time::timeout(DEADLINE, async {
            let mut buffer = [0_u8; 256];
            while !rest.ends_with(b"</Ping>") {
                let read = client.read(&mut buffer).await.expect("the second body reads");
                assert_ne!(read, 0, "{driver:?}: the reused connection closed");
                rest.extend_from_slice(&buffer[..read]);
            }
        })
        .await
        .expect("the second response completes on the same connection");
        stop(running).await;
    }
}

/// Negative, and the case c-mw-0024 names. A stream that ends before its declared length is not
/// passed off as complete, and the client is not left waiting for bytes that will never come: the
/// connection ends, carrying fewer body bytes than declared, and the server releases it.
#[tokio::test]
async fn c_mw_0024_a_stream_shorter_than_its_declared_length_ends_the_connection() {
    for driver in DRIVERS {
        let installed = installing(Plan {
            declared: Some(DECLARED),
            chunks: vec![b"hello "],
            end: End::Eof,
            held: true,
        });
        let running = start(installed.service.clone(), driver);
        let mut client = connect(&running, PING).await;
        let (head, body) = read_head(&mut client).await;
        assert!(head.contains("content-length: 12\r\n"), "{driver:?}: {head}");
        let body = read_through(&mut client, body, b"hello ").await;
        installed.gate.open();
        let body = read_to_close(&mut client, body).await;
        assert_eq!(body, b"hello ", "{driver:?}: the client was sent bytes the stream never produced");
        wait_until("the server releases the connection", || running.metrics.active_connections() == 0).await;
        assert!(installed.dropped.load(Ordering::Acquire), "{driver:?}: the producer was not released");
        assert_head_reported_before_the_body(&installed.events, driver);
        stop(running).await;
    }
}

/// Negative. A producer that fails under a declared length ends the connection short of it, the
/// same way a short stream does.
#[tokio::test]
async fn c_mw_0024_a_stream_failing_under_a_declared_length_ends_the_connection() {
    for driver in DRIVERS {
        let installed = installing(Plan {
            declared: Some(DECLARED),
            chunks: vec![b"hello "],
            end: End::Fail,
            held: true,
        });
        let running = start(installed.service.clone(), driver);
        let mut client = connect(&running, PING).await;
        let (head, body) = read_head(&mut client).await;
        assert!(head.contains("content-length: 12\r\n"), "{driver:?}: {head}");
        let body = read_through(&mut client, body, b"hello ").await;
        installed.gate.open();
        let body = read_to_close(&mut client, body).await;
        assert_eq!(body, b"hello ", "{driver:?}: the client was sent bytes the stream never produced");
        wait_until("the server releases the connection", || running.metrics.active_connections() == 0).await;
        assert!(installed.dropped.load(Ordering::Acquire), "{driver:?}: the producer was not released");
        assert_head_reported_before_the_body(&installed.events, driver);
        stop(running).await;
    }
}

/// Negative. With no declared length the response is chunked, so a mid-stream failure is only
/// visible to the client if the terminating zero-size chunk is withheld. It is withheld: the
/// connection ends with the bytes sent so far and no `0\r\n\r\n`, so a truncated object cannot be
/// mistaken for a complete one.
#[tokio::test]
async fn c_mw_0024_a_chunked_stream_failure_never_sends_the_last_chunk() {
    for driver in DRIVERS {
        let installed = installing(Plan {
            declared: None,
            chunks: vec![b"hello "],
            end: End::Fail,
            held: true,
        });
        let running = start(installed.service.clone(), driver);
        let mut client = connect(&running, PING).await;
        let (head, body) = read_head(&mut client).await;
        assert!(head.contains("transfer-encoding: chunked\r\n"), "{driver:?}: {head}");
        assert!(!head.contains("content-length"), "{driver:?}: {head}");
        let body = read_through(&mut client, body, b"hello ").await;
        installed.gate.open();
        let body = read_to_close(&mut client, body).await;
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("0\r\n\r\n"),
            "{driver:?}: the failure was framed as a complete body: {text:?}"
        );
        wait_until("the server releases the connection", || running.metrics.active_connections() == 0).await;
        assert!(installed.dropped.load(Ordering::Acquire), "{driver:?}: the producer was not released");
        assert_head_reported_before_the_body(&installed.events, driver);
        stop(running).await;
    }
}

/// Negative. A client that resets the connection mid-stream releases the producer and the
/// connection, and the observer's single report, made at the head, is not repeated or retracted.
#[tokio::test]
async fn c_mw_0024_a_client_reset_mid_stream_releases_the_producer_once_reported() {
    for driver in DRIVERS {
        let installed = installing(Plan {
            declared: Some(1 << 30),
            chunks: vec![b"hello "],
            end: End::Endless,
            held: false,
        });
        let running = start(installed.service.clone(), driver);
        let mut client = connect(&running, PING).await;
        let (head, _) = read_head(&mut client).await;
        assert!(head.starts_with("http/1.1 200 "), "{driver:?}: {head}");
        reset(client);
        wait_until("the producer is released", || installed.dropped.load(Ordering::Acquire)).await;
        wait_until("the server releases the connection", || running.metrics.active_connections() == 0).await;
        assert_head_reported_before_the_body(&installed.events, driver);
        stop(running).await;
    }
}

// ── the committed path ──────────────────────────────────────────────────────────────────────────

/// A committed `CopyObject` whose detached work waits for the test to release it.
struct GatedCopy(Mutex<Option<oneshot::Receiver<()>>>);

impl Handler<CopyObject> for GatedCopy {
    async fn call(&self, _request: Req<CopyObject>) -> HandlerResult<CopyObject> {
        let gate = self.0.lock().expect("the gate is not poisoned").take();
        let head = HeadPart::new(http::HeaderMap::new()).expect("an empty generated operation head");
        Ok(Resp::commit(
            head,
            Box::pin(async move {
                if let Some(gate) = gate {
                    let _ = gate.await;
                }
                Ok(CopyObjectOutput::default())
            }),
        ))
    }
}

fn http1(request: &http::Request<Bytes>) -> Vec<u8> {
    let mut raw = format!("{} {} HTTP/1.1\r\n", request.method(), request.uri()).into_bytes();
    for (name, value) in request.headers() {
        raw.extend_from_slice(name.as_str().as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(value.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(format!("content-length: {}\r\n\r\n", request.body().len()).as_bytes());
    raw.extend_from_slice(request.body());
    raw
}

/// Negative. A committed response reports when its detached work finishes, not when its head
/// leaves: nothing is reported while the work is held, and a client that resets the connection
/// after the head does not cancel the report. It arrives exactly once, with the committed status.
///
/// The connection is only released after the work is: while the work is held the committed body
/// is pending between keep-alive bytes and writes nothing, so neither driver learns of the reset
/// until its next write.
#[tokio::test]
async fn c_mw_0024_a_committed_report_waits_for_the_work_and_survives_a_client_reset() {
    for driver in DRIVERS {
        let events = Events::default();
        let (release, gate) = oneshot::channel();
        let service = support::wired_at_signed_time()
            .register::<CopyObject, _>(Arc::new(GatedCopy(Mutex::new(Some(gate)))))
            .observer(Recorder(Arc::clone(&events)))
            .build()
            .expect("the committed-response assembly is valid");
        let running = start(service, driver);
        let mut client = connect(&running, &http1(&support::copy_commit_request())).await;
        let (head, _) = read_head(&mut client).await;
        assert!(head.starts_with("http/1.1 200 "), "{driver:?}: {head}");
        assert!(events_of(&events).is_empty(), "{driver:?}: reported before the work finished");

        reset(client);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(events_of(&events).is_empty(), "{driver:?}: the reset produced a report");
        release.send(()).expect("the detached work still holds its gate");
        wait_until("the committed work reports", || !events_of(&events).is_empty()).await;
        wait_until("the server releases the connection", || running.metrics.active_connections() == 0).await;
        assert_eq!(events_of(&events), ["observer 200 error=None"], "{driver:?}");
        stop(running).await;
    }
}
