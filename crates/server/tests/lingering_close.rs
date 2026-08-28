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

//! How a refused connection ends, asked of a real socket.
//!
//! Responsible for: what `ProgressIo::poll_shutdown` leaves behind — the refusal survives and the
//! socket ends in a close rather than a reset, a connection nobody refused stays open, a close
//! with nothing in flight costs no connection slot, a peer that stops mid-body is released by the
//! per-block grace, and a peer that never stops writing is released at the outer bound.
//! NOT responsible for: which refusals announce `Connection: close` — that is `crates/gateway`'s
//! `close.rs`, and this crate never sees it; nor the write-progress and idle deadlines, which are
//! next door in `server_runtime.rs` and `server_load.rs`.
//! Upstream: rustfs/gateway#211, split out of #20. Downstream: every S3 client that needs to read
//! the refusal it was sent.
//!
//! # Why every case here states all three outcomes
//!
//! `closed`, `open` and `reset` are three different findings and an observer that had quietly lost
//! the ability to report one of them would satisfy every case that expects the other two. So the
//! socket is asked the same question by every case in this file, and the file contains one case
//! that must answer `closed`, one that must answer `open`, and one — against a deliberately
//! abortive server that is not this runtime — that must answer `reset`.
//!
//! # Why keep-alive cannot be the reason anything here closes
//!
//! Every listener in this file runs with a header deadline and a keep-alive gap far longer than
//! any case's wall time, so the only layer that can end a connection inside a case is the
//! `Connection: close` the service wrote. Without that, "the connection closed" would go green on
//! the idle timer and read exactly like a pass.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, ServerMetrics, UnfinishedRequestBody};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tower::service_fn;

/// What a socket was left in, asked of the socket and of nothing the server said.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionState {
    /// The peer is still holding the connection: it neither ended the stream nor reset it.
    Open,
    /// End of stream. This is what a `FIN` the peer never followed with a reset looks like.
    Closed,
    /// `ECONNRESET`. The peer aborted, and whatever it had sent may have gone with it.
    Reset,
}

/// How long `observe` waits before calling a silent peer `Open`.
///
/// A close already decided reaches a loopback peer in microseconds, so this is orders of magnitude
/// more than an honest `Closed` needs, and it is far shorter than any listener's keep-alive gap in
/// this file, so an `Open` verdict is never the idle timer not having fired yet.
const OBSERVE: Duration = Duration::from_millis(150);

/// The lingering-close budget a listener here gets unless its case names its own.
///
/// Deliberately far larger than any drain in this file should need. The cases that are *about* the
/// bound set a small one of their own, and every other case has to be free of it: a budget tight
/// enough to be spent is a budget a slow runner can expire mid-drain, and a drain cut short by its
/// own budget is not a finding about the close. That is not hypothetical — this file's positive
/// case first shipped with a 500ms budget shared from here, passed locally in about 200ms, and on
/// a CI runner expired after 368640 of the 1048576 octets it was draining.
///
/// That each case can choose is the point of the bound being a configuration value rather than a
/// constant: a test that restated `src/io.rs`'s default as a literal would be asserting against a
/// number it could not see change. The positive case names its own for that reason and not this
/// one — it asserts a *completed* drain, so the bound it runs under has to be a number it chose.
const PATIENT_BUDGET: Duration = Duration::from_secs(10);

/// Asks the socket what state it is in, waiting `ceiling` before calling a silent peer `Open`.
///
/// The ceiling only costs wall time when the answer is `Open`, so a case that expects an ending
/// can afford a generous one and a case that expects `Open` pays for what it asks.
async fn observe<R: AsyncRead + Unpin>(reader: &mut R, ceiling: Duration) -> ConnectionState {
    let mut probe = [0_u8; 1];
    match tokio::time::timeout(ceiling, reader.read(&mut probe)).await {
        Err(_) => ConnectionState::Open,
        Ok(Ok(0)) => ConnectionState::Closed,
        Ok(Ok(_)) => ConnectionState::Open,
        Ok(Err(error)) => match error.kind() {
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => ConnectionState::Reset,
            _ => ConnectionState::Closed,
        },
    }
}

/// The listener configuration every case in this file runs under.
///
/// One function rather than a literal per case: the claim each case makes is about the close, and
/// two configuration literals side by side is how a case quietly starts measuring a timer instead.
///
/// `so_rcvbuf` is *pinned*, and its value sits between two other constants in this file. Both
/// relations are load-bearing, and getting the lower one wrong is what rustfs/gateway#274 turned
/// out to be:
///
/// - **[`SLAB`] < `so_rcvbuf`.** The refusals below never read their request body, so the only
///   thing that makes a socket *hold* unread octets at the moment it is dropped is a receive
///   buffer holding more than the request parser took out of it in one read. The parser reads
///   once — the head is complete, and nothing above it ever polls the body — so a receive buffer
///   the parser can *empty* leaves an empty receive queue behind, the drain correctly declines
///   (there is nothing left to be reset over), and the case is measuring a race between one read
///   and one `poll_shutdown` rather than measuring a drain. Observed on a hosted runner with this
///   buffer pinned to 8 KiB: the parser took 12353 octets, the receive queue was empty, the drain
///   accepted 0, and the connection retired in 1.302µs. Pinning the buffer above the slab the
///   peer queues before the refusal is what makes "the socket holds unread octets" true rather
///   than likely.
/// - **`so_rcvbuf` < the body.** A buffer the kernel auto-tunes into the megabytes swallows the
///   whole body, and then the case is measuring the buffer rather than the drain.
///
/// That the failure was a race in both directions is also the whole of #274's flake history: the
/// same case sometimes lost the race and read *nothing* — passing, because the assertion it had
/// was on a client-side count — and sometimes won it and ran out of clock partway through a
/// mebibyte. One cause, two symptoms, opposite colours.
fn plaintext_config() -> ServerConfig {
    ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: Duration::from_secs(30),
        keep_alive_idle: Duration::from_secs(60),
        write_progress_timeout: Duration::from_secs(30),
        max_connections_per_ip: None,
        so_rcvbuf: Some(128 * 1024),
        lingering_close_time: PATIENT_BUDGET,
        ..ServerConfig::default()
    }
}

/// A listener that refuses `/refuse` the way every early refusal in this service is shaped — an
/// answer written without reading a byte of the request body, carrying the `Connection: close`
/// that `crates/gateway`'s `announce_connection_verdict` writes — and answers everything else
/// with a plain `200` that says nothing about the connection.
fn refusing_server(config: ServerConfig) -> RunningServer {
    let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
        let is_refusal = request.uri().path() == "/refuse";
        let body_is_unfinished = request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length != 0);
        let mut response = (if is_refusal {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(http::header::CONNECTION, "close")
                .body(Full::new(Bytes::from_static(b"<Error/>")))
        } else {
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from_static(b"ok")))
        })
        .expect("the response is well formed");
        if is_refusal && body_is_unfinished {
            response.extensions_mut().insert(UnfinishedRequestBody);
        }
        Ok::<_, Infallible>(response)
    });
    Server::new(config, service).serve().expect("server starts")
}

/// Reads one complete response — head, then exactly the `Content-Length` it declares.
///
/// Deliberately not `read_to_end`: that conflates the two findings this file exists to separate,
/// returning `Ok` for a clean close and `Err` for a reset only after it has already thrown away
/// the distinction between "the answer arrived and then the socket ended" and "the answer arrived
/// at all".
async fn read_response<R: AsyncRead + Unpin>(reader: &mut R, ceiling: Duration) -> Result<Vec<u8>, String> {
    let mut seen = Vec::new();
    let mut block = [0_u8; 4096];
    loop {
        if let Some(head_end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..head_end]).to_ascii_lowercase();
            let declared = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .ok_or_else(|| format!("the response declared no content-length: {head}"))?;
            if seen.len() >= head_end + 4 + declared {
                return Ok(seen);
            }
        }
        match tokio::time::timeout(ceiling, reader.read(&mut block)).await {
            Err(_) => return Err(format!("no complete response inside {ceiling:?}, after {} bytes", seen.len())),
            Ok(Ok(0)) => return Err(format!("end of stream after {} bytes, before a complete response", seen.len())),
            Ok(Ok(read)) => seen.extend_from_slice(&block[..read]),
            Ok(Err(error)) => {
                return Err(format!("the response was lost to {:?} after {} bytes: {error}", error.kind(), seen.len()));
            }
        }
    }
}

/// Waits for the listener to report no open connection, and returns how long that took.
async fn wait_retired(metrics: &ServerMetrics, ceiling: Duration) -> Option<Duration> {
    let started = Instant::now();
    tokio::time::timeout(ceiling, async {
        while metrics.active_connections() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .ok()
    .map(|()| started.elapsed())
}

/// Body queued *before* anything waits for the refusal, and the reason this file is not a race.
///
/// The head alone is enough for the service to refuse, so a client whose body writer is still
/// being scheduled when the refusal is written leaves nothing in flight — the drain finds an empty
/// transport, declines, and the case passes having measured the scheduler instead of the close.
/// Observed: two cases here did exactly that, and one of them was the case about the *bound*,
/// which reported a connection retired in 2.375µs against a two-second budget it never spent.
///
/// Four times the largest read the request parser has been observed to take, and half the pinned
/// receive buffer, so the whole slab reaches the listener's receive queue and one parser read
/// cannot empty it. See `plaintext_config` for why both halves of that sandwich matter.
const SLAB: usize = 64 * 1024;

/// How long each block of the slab may take to leave. Reached only when nothing is draining, which
/// is the defect under test rather than a harness failure — so a block that does not leave in time
/// ends the slab and the case goes on to report what it observes.
const SLAB_BLOCK_CEILING: Duration = Duration::from_secs(2);

/// One block of a streamed body, and the same size as the drain's own `LINGER_BLOCK`, so a short
/// count reported by a case here is a whole number of the reads the drain actually makes.
const BLOCK: usize = 8 * 1024;

/// Writes up to `slab` octets of body, counting exactly what the peer accepted.
///
/// `write` and not `write_all`: a cancelled `write` has written nothing, so the count survives the
/// ceiling, while a cancelled `write_all` would leave an unknown number of octets on the wire and
/// make the "everything owed was accepted" assertion unable to say anything.
async fn queue_body(writer: &mut OwnedWriteHalf, slab: usize) -> usize {
    let block = vec![b'x'; BLOCK];
    let mut sent = 0;
    while sent < slab {
        let next = &block[..(slab - sent).min(BLOCK)];
        match tokio::time::timeout(SLAB_BLOCK_CEILING, writer.write(next)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(written)) => sent += written,
        }
    }
    sent
}

/// The request head every refused connection here opens with.
///
/// A function and not a literal at its one call site because one case asserts on the exact octet
/// count the server accepted, and that count is this head plus the body — a second spelling of
/// these bytes would be a second place for that arithmetic to be wrong.
fn refused_head(declared: usize) -> String {
    format!("PUT /refuse HTTP/1.1\r\nHost: localhost\r\ncontent-length: {declared}\r\n\r\n")
}

/// Opens a connection, writes a `PUT /refuse` head declaring `declared` octets, and queues [`SLAB`]
/// of them before returning. Returns the two halves and how much body is already on the wire.
async fn open_refused(addr: SocketAddr, declared: usize) -> (tokio::net::tcp::OwnedReadHalf, OwnedWriteHalf, usize) {
    let stream = TcpStream::connect(addr).await.expect("the listener accepts");
    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(refused_head(declared).as_bytes())
        .await
        .expect("the head writes");
    let queued = queue_body(&mut writer, SLAB.min(declared)).await;
    (reader, writer, queued)
}

async fn shut_down(server: RunningServer) {
    let _ = server.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = server.task.await;
}

/// **Positive — a refusal answered over a body the service never read ends in a close, not a
/// reset.**
///
/// This is the arrangement rustfs/gateway#211 is about and the one this runtime produced a `RST`
/// for: the client is still streaming a mebibyte when the `400` arrives, so the socket the runtime
/// drops is a socket holding unread received octets, and dropping one of those sends `RST` rather
/// than finishing the `FIN` exchange. RFC 9112 §9.6 is about exactly that, and the cost is stated
/// there: the reset can discard the peer's receive buffer before its parser has read it, so the
/// client learns `ECONNRESET` instead of learning why it was refused.
///
/// Measured before the fix, on this listener with this configuration: the client's body write
/// stopped at 458232 bytes with `Connection reset by peer`, and the probe below returned
/// [`ConnectionState::Reset`].
///
/// Five assertions, and they are five separate facts:
///
/// 1. the whole refusal arrived — this is the one the reset actually costs a client;
/// 2. the socket ended in end of stream and not `ECONNRESET`;
/// 3. the peer got its whole body out. This is a *precondition* of the last two and not a claim
///    about the server; see below.
/// 4. the server accepted every octet the peer sent — head and body, exactly, with nothing left
///    unread at the drop. Without this a drain that read nothing would still satisfy the first two
///    on a fast enough loopback, and the case would be measuring the scheduler.
/// 5. and it was the *drain* that accepted the body rather than the request parser, which is the
///    claim rustfs/gateway#211 is actually about.
///
/// # Why the last two assertions read server counters and not the client's byte count
///
/// This case used to assert `sent == BODY` and nothing else, and rustfs/gateway#274 is what that
/// cost. `write()` returns once the octets are in the *client's* send buffer, not once this server
/// has read them, so `sent` is not an observation of the drain in either direction: it goes short
/// when the runner is slow — 39, 45, 60 and 80 of 128 blocks across four hosted runs, against one
/// pass — and it can go long when a kernel-auto-tuned send buffer absorbs the whole body while the
/// drain reads nothing, which is precisely the failure the assertion was added to catch. So the
/// count under test is now `ServerMetrics::lingering_octets_drained`, incremented where the octets
/// are actually discarded.
///
/// `sent == BODY` stays, downgraded to what it always was: the peer has to finish sending for
/// "the drain accepted the remainder" to mean anything. It cannot be the load-bearing assertion,
/// and it is no longer asked to be.
///
/// # Why the body shrank and the budget grew
///
/// The drain is bounded by a *clock* — `ServerConfig::lingering_close_time` — and the old case
/// asserted a *byte total* against it, which is not a property the design promises: whether 1 MiB
/// fits inside the bound is a fact about the host. Two numbers make that consistent again. The
/// body is sized so that the slowest rate any runner has been observed to deliver (3.9 blocks of
/// 8 KiB per second) drains it in about a fifth of this case's budget, and the budget is stated
/// here rather than inherited so the bound under test is a number this case chose.
///
/// # Why the receive buffer moved
///
/// Sizing the body was not enough on its own, and the counters above are what showed it. On a
/// hosted runner this case reported `server accepted 12353 of 262209 and drained 0`: the request
/// parser's single read had emptied an 8 KiB receive buffer, so the socket the runtime dropped
/// held no unread octets, the drain correctly declined — there was nothing to be reset over — and
/// the case's own premise had quietly stopped holding. `plaintext_config` now pins the buffer
/// above [`SLAB`], and the assertion on `queued` below states that arrangement instead of
/// assuming it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_over_an_undrained_body_ends_in_a_close_and_not_a_reset() {
    /// Four times the 64 KiB byte budget the conformance transport's drain used to stop at, four
    /// times the slab already queued when the refusal is written, and twice the pinned receive
    /// buffer — so a byte-bounded drain cannot pass this case, neither can one that only empties
    /// what was already buffered, and the buffer cannot swallow the body whole.
    const BODY: usize = 256 * 1024;
    /// The least the drain may have accepted, and the assertion that it was the *drain* that took
    /// the body rather than the request parser.
    ///
    /// Everything except the slab already queued when the refusal was written, which bounds what
    /// the parser could have buffered alongside the head: it reads once, gets the head and
    /// whatever the pinned receive buffer was holding behind it, and never reads the body again
    /// because nothing above it polls the body. Three times the 64 KiB byte budget, so a
    /// byte-bounded drain cannot reach it either. Measured on a developer machine: the parser's
    /// share was 32703 octets, half of the headroom this leaves.
    const DRAINED_FLOOR: u64 = (BODY - SLAB) as u64;
    /// This case's own outer bound, and generous on purpose. [`BODY`] needs 32 blocks; the worst
    /// rate observed on a hosted runner delivers that in 8.2s, so the bound is not what ends this
    /// drain on any host that is working. A budget is only spent when the peer keeps writing past
    /// it, which this peer does not — the cases next door are the ones that spend theirs.
    const BUDGET: Duration = Duration::from_secs(30);
    /// How long the probe waits for the socket to end once the peer has stopped writing. Generous
    /// on purpose: it costs wall time only when the answer is `Open`, which is a failure, and the
    /// drain still owes the peer one per-block grace before it closes.
    const CLOSING: Duration = Duration::from_secs(2);
    let server = refusing_server(ServerConfig {
        lingering_close_time: BUDGET,
        ..plaintext_config()
    });
    let started = Instant::now();
    let (mut reader, mut writer, queued) = open_refused(server.local_addr, BODY).await;
    // The arrangement, stated as an assertion rather than assumed. The whole slab has to reach the
    // listener before the refusal is written, because one parser read is all this connection gets
    // and the octets it leaves behind are the ones the drain exists to accept. A receive buffer
    // that stopped fitting the slab would silently turn every assertion below into a race.
    assert_eq!(
        queued, SLAB,
        "the peer could not queue its slab, so the refusal will not be answered over unread octets"
    );
    // Tolerated rather than expected: a runtime that abandoned the connection makes this stop
    // short, and that is a finding for the assertions below to report rather than a panic here.
    let sender = tokio::spawn(async move { queued + queue_body(&mut writer, BODY - queued).await });
    let response = read_response(&mut reader, Duration::from_secs(10)).await;
    // Observed only once the peer has stopped writing, and that ordering is what makes the verdict
    // deterministic rather than a race between two segments. An abortive close puts `FIN` and
    // `RST` on the wire microseconds apart, and a probe that reads between them sees end of stream
    // and reports `Closed` — the right answer to the wrong question. Once the peer's own writes
    // have failed, the `RST` has provably arrived and the probe reports what the connection
    // actually did. The ceiling covers the per-block grace the drain spends before it closes.
    let sent = tokio::time::timeout(Duration::from_secs(20), sender)
        .await
        .expect("the body task finishes inside the linger budget")
        .expect("the body task joins");
    let state = observe(&mut reader, CLOSING).await;
    // The `FIN` this probe reads is written *before* the drain runs — `poll_shutdown` half-closes
    // first, so that the peer stops pipelining — which means `Closed` says nothing about whether
    // the drain has finished. The connection slot is what the drain holds for its whole duration,
    // so retirement is the barrier the counter below has to be read after.
    let retired = wait_retired(&server.metrics, BUDGET + CLOSING).await;
    let drained = server.metrics.lingering_octets_drained();
    let accepted = server.metrics.transport_octets_read();
    let owed = (refused_head(BODY).len() + BODY) as u64;
    eprintln!(
        "a-srv-0211 refused drain: client sent {sent} of {BODY}, server accepted {accepted} of {owed} and drained {drained}, retired after {retired:?}, case took {:?}",
        started.elapsed()
    );

    let response = response.expect("the refusal must survive the close it announces");
    assert!(
        response.starts_with(b"HTTP/1.1 400 "),
        "{}",
        String::from_utf8_lossy(&response[..response.len().min(120)])
    );
    assert_eq!(
        state,
        ConnectionState::Closed,
        "a close over undrained octets is a reset, and a client cannot tell a reset from a lost response"
    );
    assert!(
        retired.is_some(),
        "the connection still held its slot after {:?}: the drain never ended",
        BUDGET + CLOSING
    );
    assert_eq!(
        sent, BODY,
        "the peer did not finish sending, so nothing below can say what the drain would have accepted"
    );
    assert_eq!(
        accepted, owed,
        "the server left octets unread at the drop, which is the condition that turns its close into a reset"
    );
    assert!(
        drained >= DRAINED_FLOOR,
        "the lingering read accepted {drained} of the {owed} octets this connection took, against a floor of {DRAINED_FLOOR}: the body was not drained, it was read by something that then had nothing to linger over"
    );
    shut_down(server).await;
}

/// **Negative — the same probe, in the opposite direction: a connection nobody refused stays
/// open.**
///
/// Half of the three-outcome proof, and it is not decoration. An observer stuck on `Closed` would
/// satisfy the case above no matter what the drain did; this is the case that cannot pass unless
/// the probe can still say `Open`. It is also the guard on the drain's blast radius — a lingering
/// read that ran on a connection the service is keeping would be reading the *next* request and
/// discarding it, and `Open` alone would not catch that, so the connection is asserted by being
/// used again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_no_refusal_ended_stays_open_and_carries_another_request() {
    let server = refusing_server(plaintext_config());
    let stream = TcpStream::connect(server.local_addr).await.expect("the listener accepts");
    let (mut reader, mut writer) = stream.into_split();
    for exchange in 0..2 {
        writer
            .write_all(b"GET /keep HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap_or_else(|error| panic!("request {exchange} writes: {error}"));
        let response = read_response(&mut reader, Duration::from_secs(10))
            .await
            .unwrap_or_else(|reason| panic!("request {exchange} is answered: {reason}"));
        assert!(response.starts_with(b"HTTP/1.1 200 "), "request {exchange}");
        assert_eq!(
            observe(&mut reader, OBSERVE).await,
            ConnectionState::Open,
            "nothing refused this exchange, so nothing may end the connection"
        );
    }
    shut_down(server).await;
}

/// **Negative — the third outcome, so that `Closed` above is a claim and not the only word this
/// file knows.**
///
/// The server here is not this runtime: it is nine lines of `std::net` that answers and then drops
/// the socket over octets it never read, which is what `crates/server` did before #211. If this
/// case ever stops reporting `Reset`, the probe has lost the ability to distinguish an abortive
/// close from an orderly one and the positive case above has become unfalsifiable.
///
/// The ordering is `peek` and not a sleep: the bare server blocks until the client's post-response
/// octets are provably sitting in its receive buffer, and only then goes away without reading
/// them. Eight kibibytes rather than a mebibyte, because a client writing a mebibyte at a server
/// that is not reading would deadlock the pair — and one unread octet is all an abortive close
/// needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_that_closes_without_lingering_is_observed_reset() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let addr = listener.local_addr().expect("the kernel assigned one");
    let served = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let mut seen = Vec::new();
        let mut block = [0_u8; 4096];
        while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
            match stream.read(&mut block) {
                Ok(0) | Err(_) => return,
                Ok(read) => seen.extend_from_slice(&block[..read]),
            }
        }
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 8\r\nconnection: close\r\n\r\n<Error/>");
        let _ = stream.flush();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let mut waiting = [0_u8; 1];
        let _ = stream.peek(&mut waiting);
        drop(stream);
    });
    let stream = TcpStream::connect(addr).await.expect("the bare listener accepts");
    let (mut reader, mut writer) = stream.into_split();
    writer
        .write_all(b"PUT /refuse HTTP/1.1\r\nHost: localhost\r\ncontent-length: 8192\r\n\r\n")
        .await
        .expect("the head writes");
    let response = read_response(&mut reader, Duration::from_secs(10))
        .await
        .expect("the refusal arrives before the reset");
    assert!(response.starts_with(b"HTTP/1.1 400 "));
    writer
        .write_all(&vec![b'x'; 8192])
        .await
        .expect("octets the bare server chose not to read");
    served.join().expect("the bare server thread joins");
    assert_eq!(
        observe(&mut reader, PATIENT_BUDGET).await,
        ConnectionState::Reset,
        "an abortive close must still be reported as one, or `closed` stops being a claim"
    );
}

/// **Negative — a close with nothing in flight is not charged the linger budget.**
///
/// The drain is bounded in time, which means an unconditional drain would hold every closing
/// connection — and its seat in `active_connections()` — for a slice of that bound, on the
/// keep-alive expiry and graceful-shutdown paths as much as on a refusal. So the lingering read
/// only starts when the transport already has something to give, which is the condition nginx's
/// `lingering_close on` default uses.
///
/// Measured as a total across many closes rather than as one, and that is what makes it able to
/// fail. A single close held for one quiet interval is a hundred milliseconds, which no honest
/// per-connection ceiling could tell from scheduler weather; thirty of them in a row is three
/// seconds against a ceiling of one, and the same thirty cost single-digit milliseconds when the
/// drain declines to start. The assertion is that ratio and not a byte of wall clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_with_nothing_in_flight_holds_no_connection_slot() {
    /// Enough closes that one drain each is far outside [`CEILING`], and few enough that thirty
    /// loopback round trips are not themselves the measurement.
    const CLOSES: usize = 30;
    /// Small, so that a drain that ran here is loud rather than merely slow.
    const BUDGET: Duration = Duration::from_millis(500);
    /// Thirty drains that each spend [`BUDGET`] cost fifteen seconds. Thirty declined ones cost
    /// milliseconds — measured at 10ms to 87ms. Anything between is a host too loaded to be
    /// measuring this at all.
    const CEILING: Duration = Duration::from_secs(1);
    let server = refusing_server(ServerConfig {
        lingering_close_time: BUDGET,
        ..plaintext_config()
    });
    let started = Instant::now();
    for close in 0..CLOSES {
        let stream = TcpStream::connect(server.local_addr).await.expect("the listener accepts");
        let (mut reader, mut writer) = stream.into_split();
        // No body, no `content-length`: there is nothing this peer still owes, so there is nothing
        // for a lingering read to find.
        writer
            .write_all(b"GET /refuse HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap_or_else(|error| panic!("close {close} writes: {error}"));
        let response = read_response(&mut reader, Duration::from_secs(10))
            .await
            .unwrap_or_else(|reason| panic!("close {close} is answered: {reason}"));
        assert!(response.starts_with(b"HTTP/1.1 400 "), "close {close}");
        assert_eq!(observe(&mut reader, OBSERVE).await, ConnectionState::Closed, "close {close}");
        let retired = wait_retired(&server.metrics, Duration::from_secs(10))
            .await
            .unwrap_or_else(|| panic!("close {close} is retired"));
        assert!(
            retired < BUDGET / 2,
            "close {close} held a connection slot for {retired:?}, which is the linger budget being spent on a connection with nothing in flight"
        );
    }
    let elapsed = started.elapsed();
    eprintln!("a-srv-0211 idle closes: {CLOSES} closes retired in {elapsed:?} against a {CEILING:?} ceiling");
    assert!(
        elapsed <= CEILING,
        "{CLOSES} closes with nothing in flight took {elapsed:?} against a {CEILING:?} ceiling: the lingering read is running on connections that have nothing to drain"
    );
    shut_down(server).await;
}

/// **Negative — a peer that goes silent mid-body is let go long before the budget.**
///
/// The complement of the case below. The outer budget alone would charge the whole of itself to
/// a peer that simply stopped — a client that was killed, a network that went away — and that is
/// the slow-loris shape with the roles reversed: nothing is being sent, and a connection slot is
/// held anyway. So the drain also carries nginx's `lingering_timeout` in its per-block role, reset
/// by every block that arrives, and this is the case that spends *that* clock rather than the
/// outer one.
///
/// The peer here declares a mebibyte, sends the slab, and then says nothing more, ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_stops_mid_body_is_let_go_well_inside_the_linger_bound() {
    /// This case's own outer budget. The two clocks have to be far enough apart that a stopwatch
    /// can tell them apart on a loaded runner: the claim is that the *inner* clock released this
    /// peer, so the outer one is set out of reach of the ceiling below and the ceiling sits
    /// between them.
    const BUDGET: Duration = Duration::from_secs(2);
    /// Between the per-block grace stated in `src/io.rs` — the observed figure is about a tenth of
    /// this — and [`BUDGET`], so a drain rescued by the outer clock instead fails here.
    const CEILING: Duration = Duration::from_secs(1);
    let server = refusing_server(ServerConfig {
        lingering_close_time: BUDGET,
        ..plaintext_config()
    });
    let (mut reader, writer, queued) = open_refused(server.local_addr, 1024 * 1024).await;
    assert!(queued > 0, "the peer must have something in flight for the drain to start on");
    let response = read_response(&mut reader, Duration::from_secs(10))
        .await
        .expect("the refusal arrives");
    assert!(response.starts_with(b"HTTP/1.1 400 "));
    let retired = wait_retired(&server.metrics, CEILING).await;
    // Held until here, and no further octet written on it: the connection under test is a peer
    // that owes 1 MiB, has sent 64 KiB of it, and has stopped.
    drop(writer);
    let retired = retired.unwrap_or_else(|| {
        panic!(
            "a peer that stopped sending still held a connection slot after {CEILING:?}: the drain is spending the whole {BUDGET:?} budget on a peer that will never send again"
        )
    });
    eprintln!("a-srv-0211 silent peer: retired after {retired:?} against a {CEILING:?} ceiling");
    shut_down(server).await;
}

/// **Negative — a peer that never stops writing does not own the connection.**
///
/// The other end of the same bound. A drain that read until the peer was finished would hand any
/// client an unbounded hold on a task and a connection slot simply by never finishing, which is a
/// slow-loris with extra steps. The budget stated in `src/io.rs` is the answer, and this is the
/// case that spends it.
///
/// The client stops writing at [`WRITES_FOR`] so that a drain with no bound at all fails this case
/// by timing out rather than by hanging the suite. The ceiling sits between the stated budget and
/// that: past the budget the connection must already be gone, and it must not be able to wait for
/// the client to lose interest instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_never_stops_writing_is_let_go_at_the_linger_bound() {
    /// Longer than the ceiling below, so a drain that outlasts its budget outlasts the assertion
    /// too rather than being rescued by the client giving up.
    const WRITES_FOR: Duration = Duration::from_secs(4);
    /// The budget this case exists to spend, and small because it spends all of it.
    const BUDGET: Duration = Duration::from_millis(500);
    /// A gibibyte declared and never finished: the peer's willingness to keep writing is the point,
    /// so the framing must not be what ends the exchange.
    const DECLARED: usize = 1024 * 1024 * 1024;
    let server = refusing_server(ServerConfig {
        lingering_close_time: BUDGET,
        ..plaintext_config()
    });
    let (mut reader, mut writer, _) = open_refused(server.local_addr, DECLARED).await;
    let sender = tokio::spawn(async move {
        let block = vec![b'x'; BLOCK];
        let until = Instant::now() + WRITES_FOR;
        while Instant::now() < until {
            if writer.write(&block).await.is_err() {
                break;
            }
        }
    });
    let response = read_response(&mut reader, Duration::from_secs(10))
        .await
        .expect("the refusal arrives");
    assert!(response.starts_with(b"HTTP/1.1 400 "));
    // Generously past the stated budget, so that a busy host is not mistaken for an unbounded
    // drain, and well short of how long this peer keeps writing.
    let ceiling = BUDGET * 3;
    let retired = wait_retired(&server.metrics, ceiling).await;
    sender.abort();
    let retired = retired.unwrap_or_else(|| {
        panic!("a peer writing continuously still held a connection slot after {ceiling:?}: the lingering read is not bounded")
    });
    eprintln!("a-srv-0211 endless peer: retired after {retired:?} against a {ceiling:?} ceiling");
    shut_down(server).await;
}
