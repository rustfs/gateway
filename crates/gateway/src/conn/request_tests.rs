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

//! Deterministic request-parser fragmentation and scan-work controls.
//!
//! Responsible for: forced Pending/read boundaries, protocol results, and actual scan visits.
//! NOT responsible for: production socket performance or allocation accounting.
//! Upstream: the self-held request parser. Downstream: regression and mutation checks.

#![allow(clippy::expect_used, clippy::panic)] // Test fixtures intentionally panic when setup or measured invariants fail.

use std::cell::Cell;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::poll_fn;
use std::sync::Mutex as SyncMutex;

use http::Response;
use http_body_util::BodyExt;
use rustfs_gateway_server::{AcceptedConnection, ConnectionDriver, ConnectionFuture, Server, ServerConfig};
use rustfs_gateway_stream::Body;
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use super::*;

thread_local! {
    static HEAD_WINDOWS: Cell<usize> = const { Cell::new(0) };
    static LF_BYTES: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn record_head_window() {
    HEAD_WINDOWS.set(HEAD_WINDOWS.get() + 1);
}

pub(super) fn record_lf_byte() {
    LF_BYTES.set(LF_BYTES.get() + 1);
}

pub(super) struct ScriptedInput {
    chunks: VecDeque<Vec<u8>>,
    pending: usize,
    reads: usize,
    yielded: bool,
}

impl ScriptedInput {
    pub(super) fn poll_fill(&mut self, context: &mut Context<'_>, buffer: &mut BytesMut) -> Poll<io::Result<bool>> {
        if !self.yielded {
            self.yielded = true;
            self.pending += 1;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.yielded = false;
        self.reads += 1;
        let chunk = self.chunks.pop_front();
        if let Some(chunk) = &chunk {
            assert!(!chunk.is_empty(), "scripted data reads are nonempty");
            buffer.extend_from_slice(chunk);
        }
        Poll::Ready(Ok(chunk.is_some()))
    }
}

#[derive(Debug, PartialEq)]
struct ObservedRequest {
    path: String,
    body: Vec<u8>,
    trailer: Option<String>,
}

struct Observation {
    result: Result<Vec<ObservedRequest>, io::ErrorKind>,
    windows: usize,
    lf_bytes: usize,
    pending: usize,
    reads: usize,
}

#[derive(Clone)]
struct ScriptDriver {
    chunks: Arc<Vec<Vec<u8>>>,
    limit: usize,
    cancel_after: Option<usize>,
    result: Arc<SyncMutex<Option<oneshot::Sender<Observation>>>>,
}

impl<S: Send + 'static> ConnectionDriver<S> for ScriptDriver {
    fn drive(&self, accepted: AcceptedConnection<S>) -> ConnectionFuture {
        let script = self.clone();
        Box::pin(async move {
            let (stream, _service) = accepted.into_plaintext().expect("fixture is plaintext");
            let mut connection = ConnectionIo::new(stream);
            connection.scripted_input = Some(ScriptedInput {
                chunks: script.chunks.iter().cloned().collect(),
                pending: 0,
                reads: 0,
                yielded: false,
            });
            let io = Arc::new(Mutex::new(connection));
            HEAD_WINDOWS.set(0);
            LF_BYTES.set(0);
            let result = observe_requests(Arc::clone(&io), script.limit, script.cancel_after).await;
            let locked = io.lock().await;
            let input = locked.scripted_input.as_ref().expect("script remains installed");
            let observation = Observation {
                result: result.map_err(|error| error.kind()),
                windows: HEAD_WINDOWS.get(),
                lf_bytes: LF_BYTES.get(),
                pending: input.pending,
                reads: input.reads,
            };
            let _ = script
                .result
                .lock()
                .expect("fixture sender lock")
                .take()
                .expect("one connection")
                .send(observation);
        })
    }
}

#[derive(Default)]
struct LockWake(std::sync::atomic::AtomicUsize);

impl std::task::Wake for LockWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

async fn observe_requests(
    io: Arc<Mutex<ConnectionIo>>,
    limit: usize,
    mut cancel_after: Option<usize>,
) -> io::Result<Vec<ObservedRequest>> {
    let mut requests = Vec::new();
    while let Some(parsed) = read_request(Arc::clone(&io), limit, HeaderTimeout::After(Duration::from_secs(5))).await? {
        let path = parsed.request.uri().path().to_owned();
        let mut body = parsed.request.into_body();
        if let Some(frames) = cancel_after.take() {
            let external_guard = io.lock().await;
            let wake = Arc::new(LockWake::default());
            {
                let waker = std::task::Waker::from(Arc::clone(&wake));
                let mut context = Context::from_waker(&waker);
                assert!(
                    http_body::Body::poll_frame(Pin::new(&mut body), &mut context).is_pending(),
                    "contended body polling must wait"
                );
            }
            assert_eq!(
                wake.0.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "held lock cannot wake its waiter yet"
            );
            drop(external_guard);
            assert!(
                wake.0.load(std::sync::atomic::Ordering::SeqCst) > 0,
                "releasing the external guard wakes the body waiter"
            );
            for _ in 0..frames {
                body.frame().await.expect("fixture data frame").expect("valid data");
                assert!(
                    io.try_lock().is_ok(),
                    "a returned frame releases the connection lock before the next frame"
                );
            }
            poll_fn(|context| {
                assert!(
                    http_body::Body::poll_frame(Pin::new(&mut body), context).is_pending(),
                    "cancellation must interrupt an actual Pending read"
                );
                Poll::Ready(())
            })
            .await;
            drop(body);
            let mut locked = io.lock().await;
            assert!(locked.drain_request_body(4096).await?, "unread body drains within budget");
            assert!(locked.body_complete(), "drain reaches framing EOF");
            requests.push(ObservedRequest {
                path,
                body: vec![],
                trailer: None,
            });
            continue;
        }
        let collected = body.collect().await?;
        let trailer = collected
            .trailers()
            .and_then(|map| map.get("x-test"))
            .map(|value| value.to_str().expect("ASCII fixture").to_owned());
        requests.push(ObservedRequest {
            path,
            body: collected.to_bytes().to_vec(),
            trailer,
        });
    }
    Ok(requests)
}

#[derive(Clone)]
pub(super) struct UnusedService;

impl tower::Service<Request<SelfHeldRequestBody>> for UnusedService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _request: Request<SelfHeldRequestBody>) -> Self::Future {
        panic!("the parser fixture must not invoke the service")
    }
}

async fn run_script(bytes: Vec<u8>, limit: usize) -> Observation {
    run_script_chunks(bytes.into_iter().map(|byte| vec![byte]).collect(), limit).await
}

async fn run_script_chunks(chunks: Vec<Vec<u8>>, limit: usize) -> Observation {
    run_script_options(chunks, limit, None).await
}

async fn run_script_options(chunks: Vec<Vec<u8>>, limit: usize, cancel_after: Option<usize>) -> Observation {
    let (sender, receiver) = oneshot::channel();
    let driver = ScriptDriver {
        chunks: Arc::new(chunks),
        limit,
        cancel_after,
        result: Arc::new(SyncMutex::new(Some(sender))),
    };
    let service = UnusedService;
    let config = ServerConfig {
        bind_addr: "127.0.0.1:0".parse().expect("literal address"),
        plaintext: true,
        ..ServerConfig::default()
    };
    let server = Server::new(config, service)
        .serve_with(driver)
        .expect("fixture listener starts");
    let client = TcpStream::connect(server.local_addr).await.expect("fixture connection opens");
    let observation = tokio::time::timeout(Duration::from_secs(5), receiver)
        .await
        .expect("script finishes")
        .expect("driver reports");
    drop(client);
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    server.task.await.expect("server task joins").expect("server shuts down");
    assert!(observation.reads > 0, "the real parser must consume scripted reads");
    if cancel_after.is_some() {
        assert!(observation.pending >= observation.reads, "completed reads must have reached Pending");
    } else {
        assert_eq!(observation.pending, observation.reads, "every read must first return Pending");
    }
    observation
}

#[test]
fn scan_observers_count_actual_examined_inputs() {
    HEAD_WINDOWS.set(0);
    LF_BYTES.set(0);
    assert_eq!(find_head_end(b"abc\r\n\r\nignored"), Some(3));
    assert_eq!(HEAD_WINDOWS.get(), 4);
    assert!(!contains_bare_lf(b"ab\r\n"));
    assert_eq!(LF_BYTES.get(), 4);
    assert!(contains_bare_lf(b"x\nignored"));
    assert_eq!(LF_BYTES.get(), 6);
}

#[tokio::test]
async fn fragmented_head_scan_work_is_linear() {
    for length in [64, 1024] {
        let wire = format!("GET /first HTTP/1.1\r\nHost: localhost\r\nX-Padding: {}\r\n\r\n", "a".repeat(length)).into_bytes();
        let size = wire.len();
        let observed = run_script(wire, 4096).await;
        eprintln!(
            "head scan: input_bytes={size} delimiter_windows={} lf_bytes={} pending={} reads={}",
            observed.windows, observed.lf_bytes, observed.pending, observed.reads
        );
        assert_eq!(
            observed.result,
            Ok(vec![ObservedRequest {
                path: "/first".into(),
                body: vec![],
                trailer: None
            }])
        );
        assert!(observed.windows >= size - 3, "delimiter work cannot disappear");
        assert!(observed.lf_bytes >= size, "LF work cannot disappear");
        assert!(observed.windows <= 4 * size, "rescanned {} windows for {size} bytes", observed.windows);
        assert!(observed.lf_bytes <= 3 * size, "rescanned {} LF bytes for {size} bytes", observed.lf_bytes);
    }
}

#[tokio::test]
async fn fragmented_fixed_and_chunked_bodies_preserve_pipeline_and_trailers() {
    let wire = b"PUT /fixed HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\na\nbPUT /chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n2\r\ncd\r\n0\r\nx-test: yes\r\n\r\nGET /last HTTP/1.1\r\nHost: localhost\r\n\r\n";
    assert_eq!(
        run_script(wire.to_vec(), 4096).await.result,
        Ok(vec![
            ObservedRequest {
                path: "/fixed".into(),
                body: b"a\nb".to_vec(),
                trailer: None
            },
            ObservedRequest {
                path: "/chunked".into(),
                body: b"cd".to_vec(),
                trailer: Some("yes".into())
            },
            ObservedRequest {
                path: "/last".into(),
                body: vec![],
                trailer: None
            },
        ])
    );
}

#[tokio::test]
async fn fragmented_heads_reject_malformed_and_incomplete_inputs() {
    let cases: &[(&[u8], usize, io::ErrorKind)] = &[
        (b"GET / HTTP/1.1\nHost: localhost\r\n\r\n", 4096, io::ErrorKind::InvalidData),
        (b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", 16, io::ErrorKind::InvalidData),
        (HTTP2_PREFACE, 4096, io::ErrorKind::InvalidData),
        (b"PRI * HTTP/2.0\r\n\r\nX", 4096, io::ErrorKind::InvalidData),
        (b"GET / HTTP/1.1\r\nHost: localhost\r\n\r", 4096, io::ErrorKind::UnexpectedEof),
        (b"GET / HTTP/1.1\r\nMalformed\r\n\r\n", 4096, io::ErrorKind::InvalidData),
    ];
    for &(wire, limit, expected) in cases {
        assert_eq!(run_script(wire.to_vec(), limit).await.result, Err(expected), "wire: {wire:?}");
    }
}

#[tokio::test]
async fn co_buffered_binary_body_and_next_request_stay_outside_head_validation() {
    let wire =
        b"PUT /fixed HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\na\nbGET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let observed = run_script_chunks(vec![wire.to_vec()], 4096).await;
    assert_eq!(observed.reads, 2, "one co-buffered data read followed by EOF");
    assert_eq!(
        observed.result,
        Ok(vec![
            ObservedRequest {
                path: "/fixed".into(),
                body: b"a\nb".to_vec(),
                trailer: None
            },
            ObservedRequest {
                path: "/next".into(),
                body: vec![],
                trailer: None
            },
        ])
    );
}

#[tokio::test]
async fn dropping_pending_body_preserves_drain_and_next_request() {
    let next = b"GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let cases: &[(&[u8], &[u8], usize)] = &[
        (b"PUT /drop HTTP/1.1\r\nContent-Length: 3\r\n\r\n", b"abc", 0),
        (b"PUT /drop HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", b"3\r\nabc\r\n0\r\n\r\n", 0),
        (
            b"PUT /drop HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nx-test:",
            b" yes\r\n\r\n",
            1,
        ),
    ];
    for &(prefix, remaining, frames) in cases {
        let tail = [remaining, next].concat();
        let observed = run_script_options(vec![prefix.to_vec(), tail], 4096, Some(frames)).await;
        assert_eq!(
            observed.result,
            Ok(vec![
                ObservedRequest {
                    path: "/drop".into(),
                    body: vec![],
                    trailer: None
                },
                ObservedRequest {
                    path: "/next".into(),
                    body: vec![],
                    trailer: None
                },
            ])
        );
    }
}
