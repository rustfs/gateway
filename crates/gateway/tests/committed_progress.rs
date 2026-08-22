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

//! What ends a committed response whose continuation stopped making progress.
//!
//! Responsible for: proving, over a real HTTP/1.1 connection, that the bound in
//! `rustfs_gateway::request_deadline` is the thing that ends such a response — and that nothing
//! else on that connection can be mistaken for it.
//! NOT responsible for: the wire shape of a committed response, which `crate::commit`'s unit tests
//! own, or for what any backend chooses to commit.
//! Upstream: `rustfs_gateway`, `rustfs_gateway_server`. Downstream: nothing.
//!
//! # Why these are on a socket and not on `call_bytes`
//!
//! The question this file answers is *which mechanism retired the request*, and in process there is
//! only one candidate, so an in-process assertion could not have told them apart. On a connection
//! there are three, and two of them are the reason `P3-06` §4.3 says a green "the connection
//! closed" reads exactly like a green "the bound fired":
//!
//! | mechanism | where | what makes it fire |
//! | --- | --- | --- |
//! | connection-idle keep-alive | `crates/server/src/io.rs::check_idle` | no read **and** no request in flight |
//! | write-progress deadline | `crates/server/src/io.rs::mark_write_pending` | a `poll_write` that returned `Pending` |
//! | committed-progress deadline | `rustfs_gateway::request_deadline` | a continuation with no outcome |
//!
//! The first two cannot fire here, and that is asserted rather than argued:
//! [`nothing_but_the_bound_ends_a_stalled_committed_response`] runs the same stall with the bound
//! moved out of reach and a keep-alive idle of 200 ms, and observes that after fifteen times that
//! idle **not one byte** has arrived and the socket has not reached end of stream. `check_idle`
//! resets whenever `in_flight != 0`, and a continuation that writes nothing never puts a write into
//! `Pending`, so a stalled committed response is invisible to both. That control is what makes the
//! green line in [`a_stalled_committed_continuation_is_ended_by_the_progress_bound`] mean what it
//! says.
//!
//! # Why the assertion is the document and not the connection
//!
//! A test that asserted "the connection closed" would also be satisfied by a panic, by the process
//! dying, and by any transport-level retirement — and `<Code>InternalError</Code>` alone would be
//! satisfied by a backend that simply reported an internal failure. What is pinned instead is the
//! message `rustfs_gateway::commit::COMMIT_PROGRESS_EXPIRED`, which no backend can produce: it is
//! written by the framework at the moment it stops waiting, and
//! [`a_committed_refusal_reports_its_own_code_rather_than_the_bounds`] is the direction that stops
//! the bound from swallowing a refusal the backend really made.

use crate::support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rustfs_gateway::{
    DEFAULT_COMMIT_PROGRESS_DEADLINE, ErrorCode, Handler, HandlerDeadlineConfig, HandlerError, HandlerResult, HeadPart,
    KEEPALIVE_INTERVALS_WITHOUT_PROGRESS, Req, Resp, S3Service, ServiceConfig, commit::COMMIT_PROGRESS_EXPIRED,
    commit::KEEPALIVE_INTERVAL_SECONDS, dto::CopyObject, dto::CopyObjectOutput,
};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The bound this suite installs, small enough that a test can wait for it.
const BOUND: Duration = Duration::from_millis(400);

/// What a committed continuation does after the head is out.
#[derive(Clone, Copy)]
enum Continuation {
    /// Never resolves. The backend a bound on progress exists for.
    StopsMakingProgress,
    /// Resolves with the answer, after a delay well inside the bound.
    AnswersSlowly(Duration),
    /// Resolves with a refusal of its own, which has no status left to travel in.
    Refuses,
}

struct CommittingBackend {
    continuation: Continuation,
    /// How many continuations this backend started. Read by the control, where "nothing arrived"
    /// has to be told apart from "nothing happened".
    committed: Arc<AtomicUsize>,
    /// How many continuations reached a terminal answer after any delay.
    completed: Arc<AtomicUsize>,
}

impl Handler<CopyObject> for CommittingBackend {
    async fn call(&self, _request: Req<CopyObject>) -> HandlerResult<CopyObject> {
        let continuation = self.continuation;
        let committed = Arc::clone(&self.committed);
        let completed = Arc::clone(&self.completed);
        Ok(Resp::commit(
            HeadPart::new(http::HeaderMap::new()).expect("an empty generated operation head"),
            Box::pin(async move {
                committed.fetch_add(1, Ordering::SeqCst);
                match continuation {
                    Continuation::StopsMakingProgress => core::future::pending::<()>().await,
                    Continuation::AnswersSlowly(delay) => futures_timer::Delay::new(delay).await,
                    Continuation::Refuses => {
                        return Err(HandlerError::new(ErrorCode::INVALID_PART, "the backend's own refusal"));
                    }
                }
                completed.fetch_add(1, Ordering::SeqCst);
                Ok(CopyObjectOutput::default())
            }),
        ))
    }
}

fn committing_service(continuation: Continuation, bound: Duration) -> (S3Service, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let deadlines = HandlerDeadlineConfig::default()
        .try_with_commit_progress(bound)
        .expect("a non-zero commit progress bound");
    let committed = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let (builder, _handle) = support::wired_at_signed_time()
        .register::<CopyObject, _>(Arc::new(CommittingBackend {
            continuation,
            committed: Arc::clone(&committed),
            completed: Arc::clone(&completed),
        }))
        .config(ServiceConfig::new(1024).with_handler_deadlines(deadlines));
    (builder.build().expect("a complete assembly"), committed, completed)
}

/// A live HTTP/1.1 server whose connection-idle keep-alive is the one named here.
///
/// The keep-alive is a parameter because it is the mechanism this suite has to rule out, and a
/// hard-coded generous value would rule it out by never giving it a chance to fire.
fn live_server(service: S3Service, keep_alive_idle: Duration) -> RunningServer {
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: Duration::from_secs(1),
        keep_alive_idle,
        ..ServerConfig::default()
    };
    Server::new(config, service).serve().expect("server starts")
}

fn request_bytes() -> Vec<u8> {
    let request = support::copy_commit_request();
    let mut wire = format!("{} {} HTTP/1.1\r\n", request.method(), request.uri()).into_bytes();
    for (name, value) in request.headers() {
        wire.extend_from_slice(name.as_str().as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"Connection: close\r\nContent-Length: 0\r\n\r\n");
    wire
}

/// What the client saw, kept as three distinguishable states rather than one string.
///
/// A read that timed out and a read that reached end of stream are the same empty `Vec`, and this
/// suite's control turns on telling them apart: "nothing arrived and the peer is still there" is
/// the observation that says no transport-level mechanism retired the request.
#[derive(Debug)]
enum Seen {
    /// A response arrived, with the wall time from the first request byte to the last response one.
    Response(String, Duration),
    /// The peer closed without writing anything.
    ClosedWithoutAnswering,
    /// Nothing arrived inside the budget and the connection was still open.
    NothingInsideTheBudget,
    /// A response head and prefix arrived, but the response remained open inside the budget.
    PartialResponse(String, Duration),
}

async fn exchange_over_a_socket(service: S3Service, keep_alive_idle: Duration, budget: Duration) -> Seen {
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = live_server(service, keep_alive_idle);
    let mut stream = TcpStream::connect(local_addr).await.expect("connect succeeds");
    let started = Instant::now();
    stream.write_all(&request_bytes()).await.expect("the request head writes");

    let mut response = Vec::new();
    let seen = match tokio::time::timeout(budget, stream.read_to_end(&mut response)).await {
        Err(_) if response.is_empty() => Seen::NothingInsideTheBudget,
        Err(_) => Seen::PartialResponse(String::from_utf8(response).expect("an HTTP/1.1 response"), started.elapsed()),
        Ok(read) => {
            read.expect("the response reads");
            if response.is_empty() {
                Seen::ClosedWithoutAnswering
            } else {
                Seen::Response(String::from_utf8(response).expect("an HTTP/1.1 response"), started.elapsed())
            }
        }
    };
    // Dropped rather than joined on the stalled paths: the continuation is still pending there, so
    // the request has not finished and a drain would wait for what this suite is proving never
    // arrives.
    drop(stream);
    let _ = shutdown.trigger(Duration::from_millis(200)).await;
    drop(task);
    seen
}

fn chunked_body(wire: &str) -> Vec<u8> {
    let Some((_, mut framed)) = wire.split_once("\r\n\r\n") else {
        return Vec::new();
    };
    let mut body = Vec::new();
    while let Some((size, rest)) = framed.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size, 16) else {
            break;
        };
        if size == 0 || rest.len() < size.saturating_add(2) {
            break;
        }
        body.extend_from_slice(&rest.as_bytes()[..size]);
        framed = &rest[size + 2..];
    }
    body
}

/// **Negative — a committed continuation that stops making progress ends as a document, on time.**
///
/// Everything the assertion rests on is in the body, because the body is the only channel a
/// committed response has left. The message is the discriminator: `InternalError` alone is what a
/// backend reporting an internal failure produces, and this is the one string that only the
/// framework's own bound can write.
#[tokio::test]
async fn a_stalled_committed_continuation_is_ended_by_the_progress_bound() {
    let (service, committed, _completed) = committing_service(Continuation::StopsMakingProgress, BOUND);
    let seen = exchange_over_a_socket(service, Duration::from_secs(30), Duration::from_secs(10)).await;
    assert_eq!(committed.load(Ordering::SeqCst), 1, "the continuation never started");
    let Seen::Response(wire, elapsed) = seen else {
        panic!("the stalled completion did not end as a response: {seen:?}");
    };
    assert!(wire.starts_with("HTTP/1.1 200 "), "the committed status did not survive: {wire}");
    assert!(wire.contains(&format!("<Code>{}</Code>", ErrorCode::INTERNAL_ERROR.as_str())), "{wire}");
    assert!(wire.contains(COMMIT_PROGRESS_EXPIRED), "the refusal was not the progress bound's: {wire}");
    assert!(!wire.contains("<Ping>"), "a stalled continuation answered: {wire}");
    // The bound is a bound: the response is not allowed to arrive before it, which is what stops
    // this from being satisfied by a backend that failed immediately.
    assert!(elapsed >= BOUND, "the response arrived in {elapsed:?}, before the {BOUND:?} bound");
}

/// **Negative — the control: with the bound out of reach, only the committed prefix arrives.**
///
/// The keep-alive idle here is 200 ms and the budget is fifteen times that, so a connection-idle
/// retirement had every chance to happen. It cannot: `ProgressIo::check_idle` resets the idle
/// deadline whenever a request is in flight, and this request is. Neither can the write-progress
/// deadline, which arms only on a `poll_write` that returned `Pending`.
///
/// This is the assertion that makes the one above mean what it says. Without it, "the response
/// arrived carrying the bound's message" would be consistent with a transport that retired the
/// connection and a service that happened to render the same document.
#[tokio::test]
async fn nothing_but_the_bound_ends_a_stalled_committed_response() {
    let keep_alive_idle = Duration::from_millis(200);
    let (service, committed, _completed) = committing_service(Continuation::StopsMakingProgress, Duration::from_secs(600));
    let seen = exchange_over_a_socket(service, keep_alive_idle, keep_alive_idle * 15).await;
    assert_eq!(committed.load(Ordering::SeqCst), 1, "the request never reached a committed continuation");
    let Seen::PartialResponse(wire, _) = seen else {
        panic!("something retired the stalled committed response: {seen:?}");
    };
    assert!(wire.starts_with("HTTP/1.1 200 "), "the head was not committed: {wire}");
    assert_eq!(chunked_body(&wire), rustfs_gateway::commit::PROLOGUE.as_bytes());
    assert!(!wire.contains(COMMIT_PROGRESS_EXPIRED), "the out-of-reach bound fired: {wire}");
}

/// Positive — the real socket receives exactly one whitespace byte after the first five seconds.
#[tokio::test]
async fn a_stalled_commit_writes_one_keepalive_byte_after_five_seconds() {
    let (service, committed, _completed) = committing_service(Continuation::StopsMakingProgress, Duration::from_secs(600));
    let seen = exchange_over_a_socket(service, Duration::from_secs(30), Duration::from_millis(5_500)).await;
    assert_eq!(committed.load(Ordering::SeqCst), 1);
    let Seen::PartialResponse(wire, elapsed) = seen else {
        panic!("the stalled response did not remain open after its first keep-alive: {seen:?}");
    };
    assert!(elapsed >= Duration::from_secs(5), "the keep-alive arrived early: {elapsed:?}");
    let mut expected = rustfs_gateway::commit::PROLOGUE.as_bytes().to_vec();
    expected.push(rustfs_gateway::commit::KEEPALIVE_BYTE);
    assert_eq!(chunked_body(&wire), expected);
}

/// **Positive — the third direction: a slow continuation that finishes inside the bound is not cut
/// off.**
///
/// A bound that ended every committed response would satisfy the first test perfectly. What stops
/// it is a continuation that takes real time and still answers: the same operation, the same
/// transport, the same bound, and a generated result document on the wire.
#[tokio::test]
async fn a_slow_committed_continuation_inside_the_bound_still_answers() {
    let (service, _committed, _completed) = committing_service(Continuation::AnswersSlowly(BOUND / 4), BOUND);
    let seen = exchange_over_a_socket(service, Duration::from_secs(30), Duration::from_secs(10)).await;
    let Seen::Response(wire, _) = seen else {
        panic!("a continuation that answered inside the bound did not reach the wire: {seen:?}");
    };
    assert!(wire.starts_with("HTTP/1.1 200 "), "{wire}");
    assert!(wire.contains("<CopyObjectResult"), "{wire}");
    assert!(
        !wire.contains(COMMIT_PROGRESS_EXPIRED),
        "a continuation that answered was bounded: {wire}"
    );
}

/// **Negative — a continuation's own refusal survives the bound rather than being replaced by it.**
///
/// The bound wraps every committed continuation, so the failure mode is that it reports its own
/// verdict for one that already had one. `InvalidPart` here, and the bound's message absent: two
/// assertions, because the first alone would be green if the wrapper reported the backend's code
/// with the bound's message.
#[tokio::test]
async fn a_committed_refusal_reports_its_own_code_rather_than_the_bounds() {
    let (service, _committed, _completed) = committing_service(Continuation::Refuses, BOUND);
    let seen = exchange_over_a_socket(service, Duration::from_secs(30), Duration::from_secs(10)).await;
    let Seen::Response(wire, _) = seen else {
        panic!("the committed refusal did not reach the wire: {seen:?}");
    };
    assert!(wire.starts_with("HTTP/1.1 200 "), "{wire}");
    assert!(wire.contains(&format!("<Code>{}</Code>", ErrorCode::INVALID_PART.as_str())), "{wire}");
    assert!(
        !wire.contains(COMMIT_PROGRESS_EXPIRED),
        "the bound replaced a refusal the backend made: {wire}"
    );
}

/// **Negative — resetting the client socket does not cancel work whose head was committed.**
///
/// The client waits until it has observed the `200` and committed prologue, then forces an RST
/// while the backend is still delayed. Completion is observed through backend state rather than
/// through the dead connection. If the response body owns the work, dropping that body makes this
/// counter stay at zero.
#[tokio::test]
async fn a_client_reset_after_the_committed_head_does_not_cancel_backend_work() {
    let (service, started, completed) =
        committing_service(Continuation::AnswersSlowly(Duration::from_millis(500)), Duration::from_secs(10));
    let RunningServer {
        local_addr,
        task,
        shutdown,
        ..
    } = live_server(service, Duration::from_secs(30));
    let mut stream = TcpStream::connect(local_addr).await.expect("connect succeeds");
    stream.write_all(&request_bytes()).await.expect("the request head writes");

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !response
            .windows(rustfs_gateway::commit::PROLOGUE.len())
            .any(|window| window == rustfs_gateway::commit::PROLOGUE.as_bytes())
        {
            let read = stream.read_buf(&mut response).await.expect("the committed prefix reads");
            assert_ne!(read, 0, "the peer closed before the committed prefix");
        }
    })
    .await
    .expect("the committed head arrives before the backend answer");
    assert_eq!(started.load(Ordering::SeqCst), 1, "the detached work did not start");
    assert_eq!(completed.load(Ordering::SeqCst), 0, "the backend answered before the reset");

    let socket = socket2::Socket::from(stream.into_std().expect("the client stream converts"));
    socket.set_linger(Some(Duration::ZERO)).expect("RST linger configures");
    drop(socket);

    tokio::time::timeout(Duration::from_secs(2), async {
        while completed.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("backend work survives the reset and completes");
    assert_eq!(completed.load(Ordering::SeqCst), 1);

    let _ = shutdown.trigger(Duration::from_millis(200)).await;
    drop(task);
}

/// Positive — the shipped default is the keep-alive cadence, counted.
///
/// Asserted from the two published constants rather than from `60`, so that a change to either is a
/// change to a relationship somebody has to look at: the interval at which a client is told "still
/// working" and the number of those it may be told are the same question from either side.
#[test]
fn the_default_bound_is_a_whole_number_of_keepalive_intervals() {
    assert_eq!(
        DEFAULT_COMMIT_PROGRESS_DEADLINE,
        Duration::from_secs(KEEPALIVE_INTERVAL_SECONDS * KEEPALIVE_INTERVALS_WITHOUT_PROGRESS)
    );
    assert_eq!(DEFAULT_COMMIT_PROGRESS_DEADLINE, Duration::from_secs(60));
    // Far enough above the interval that a client is told "still working" several times before it
    // is told anything else. One interval would end a response at the first keep-alive byte.
    const { assert!(KEEPALIVE_INTERVALS_WITHOUT_PROGRESS >= 2) };
}
