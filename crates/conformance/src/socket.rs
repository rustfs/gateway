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

//! The socket target: the same service, reached over a real TCP connection.
//!
//! Responsible for: [`Listener`], which serves one [`rustfs_gateway::S3Service`] over hand-rolled
//! HTTP/1.1 framing; [`Connection`], which writes request bytes and reads a response back; and
//! [`observe_connection`], which reports what state the socket was left in. Together they are what
//! makes `expect.connection_after` an observation.
//! NOT responsible for: judging anything (`crate::expect`), building or signing a request
//! (`crate::inprocess`, whose reader and signer this module reuses rather than copying), or
//! deciding whether the server *should* close (that is the server's policy, below).
//! Upstream: `rustfs-gateway`, `crate::inprocess`. Downstream: `crate::cli`.
//!
//! # Why `connection_after` cannot be read off a header
//!
//! The whole reason this module exists is stated in the in-process target's documentation and in
//! <https://github.com/rustfs/gateway/issues/20>: reporting `closed` because the response carried
//! `Connection: close` reports the server's *intention* as an observation. A server can write that
//! header and keep the socket up; a server can close without ever writing it. The header and the
//! socket are two different facts, and only one of them is what the assertion names.
//!
//! So [`observe_connection`] never looks at the response at all. It is handed a socket and asks the
//! socket: read again, and classify what happens.
//!
//! * a clean end of stream — the peer sent FIN — is [`ConnectionState::Closed`];
//! * `ECONNRESET` is [`ConnectionState::Reset`], which the corpus spells as a different assertion;
//! * bytes, or a read that would block, mean the connection is still there — [`ConnectionState::Open`];
//! * a peer that closed only its write side is [`ConnectionState::HalfClosed`], distinguished by
//!   the socket still accepting a write after the read returned end of stream.
//!
//! The proof that this is what happens is the four-corner matrix at the bottom of this file. Two
//! servers lie in opposite directions — one announces `close` and keeps the socket, one announces
//! `keep-alive` and closes it — and the observer has to disagree with both announcements. One lie
//! alone would prove nothing, because an observer stuck at a single answer satisfies whichever
//! control happens to agree with it. If those tests ever start agreeing with the header, every
//! `connection_after` assertion in the corpus has quietly stopped measuring anything.
//!
//! # Ports and parallelism
//!
//! [`Listener::start`] binds `127.0.0.1:0` and asks the kernel for the port. Nothing here writes a
//! port number down, nothing scans for a free one, and two listeners in one test binary — or in
//! twenty parallel `cargo test` threads — cannot collide, because the kernel does not hand the same
//! ephemeral port to two live sockets. A hard-coded port, or a "find a free port then bind it"
//! dance, are both races; asking the kernel is not.
//!
//! # Why the framing is hand-rolled
//!
//! Three of the facts this target exists to expose are ones a general-purpose HTTP server hides. It
//! drains a request body the handler abandoned, so "the refusal arrived before the payload was
//! consumed" stops being visible; it answers a half-closed write side with an error of its own; and
//! it owns the keep-alive decision, so a close would be its verdict rather than this framework's.
//! A path whose purpose is to make those observable cannot delegate them. This is also why the
//! workspace keeps `hyper` on `default-features = false`: nothing here needs its server.
//!
//! # Why there is no async runtime
//!
//! One thread per connection, and the service future driven on that thread by [`crate::exec::block_on`].
//! This crate is a product other S3 implementations run against themselves, and every dependency it
//! carries is one they inherit; a work-stealing scheduler to run one future at a time is the largest
//! thing it could inherit for the least reason. Blocking inside `poll_frame` is sound because the
//! thread doing it serves one connection and has nothing else to make progress on.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustfs_gateway::{S3Service, collect};

use crate::exec::block_on;
use crate::observation::ConnectionState;
use crate::sut::SutError;

/// How long a server thread waits on a silent peer before giving the thread back.
///
/// Generous, because a case may legitimately pace a body across seconds; the case's own
/// `timeout_ms` is the budget that decides a verdict, and this only stops a wedged connection from
/// holding a thread for the life of the process.
const SERVER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long [`observe_connection`] waits for the peer to reveal what it did with the socket.
///
/// Short, because by the time it is called the response has already been read in full: a server
/// that was going to close has already sent FIN, and one that is keeping the connection will sit
/// there saying nothing. This is the cost of classifying "open", paid once per exchange.
const OBSERVE_TIMEOUT: Duration = Duration::from_millis(250);

/// What the server knows about the request body when the response is ready.
///
/// Measured on the socket, never declared: `consumed` counts bytes the service actually pulled
/// through, and `drained` records whether it read on to the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyDisposition {
    /// The number of body bytes the head framed.
    ///
    /// `Some(0)` for a request with no framing headers, which RFC 9112 §6.3 gives a zero-length
    /// body — not an unbounded one. `None` means chunked framing, where the length is not knowable
    /// from the head at all.
    pub declared: Option<u64>,
    /// Payload bytes the service pulled out of the socket.
    pub consumed: u64,
    /// Whether the service read on until the body reported its end.
    pub drained: bool,
}

impl BodyDisposition {
    /// Whether bytes the peer still owes may be unread on this connection.
    ///
    /// The RFC 9112 §9.6 condition: the next bytes on a connection whose last request body was not
    /// read to its end are the tail of that body, and a server that parses them as a request line
    /// is the receiving half of a request-smuggling pair.
    #[must_use]
    pub const fn leaves_unread_bytes(&self) -> bool {
        !self.drained
    }
}

/// Whether a connection survives one exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionDisposition {
    /// The connection stays up and the next request is read from it.
    Keep,
    /// The write side is shut down and the socket is dropped.
    Close,
}

/// Decides whether a connection survives one exchange.
///
/// Injected rather than fixed, and that is the point of this type existing at all. The corpus
/// asserts `connection_after = "closed"` for a signature failure (`c-sig-0001`) and an over-cap
/// body (`c-object-0015`), and `"open"` for a contradictory-checksum refusal (`c-object-0013`) —
/// and all three leave the request body unread, so "an undrained body closes" is not the rule the
/// corpus describes. Neither is size: `c-sig-0001`'s body is twenty-four bytes and
/// `c-object-0013`'s is eleven, so any byte budget that keeps one open keeps the other open too.
///
/// The rule that separates them is *which refusal fired* — which is what
/// `WireReject::must_close_connection` already encodes, and what nothing carries out of the
/// pipeline into a layer that could act on it. Settling that is a maintainer's decision (issue
/// #20). Until it is settled this stays a parameter, because a rule guessed here would decide
/// conformance verdicts by assertion while reading exactly like one that had been measured.
pub type ClosePolicy = Arc<dyn Fn(&BodyDisposition) -> ConnectionDisposition + Send + Sync>;

/// The RFC 9112 §9.6 rule: a request body the server did not read to its end ends the connection.
///
/// Documented as *not* reconciling `c-object-0013`, which asserts `open` under exactly this
/// condition. The disagreement is left visible rather than tuned away.
#[must_use]
pub fn rfc9112_lingering_close() -> ClosePolicy {
    Arc::new(|body| {
        if body.leaves_unread_bytes() {
            ConnectionDisposition::Close
        } else {
            ConnectionDisposition::Keep
        }
    })
}

/// A policy that never closes, whatever the exchange did.
///
/// Its purpose is to be the control in the header-versus-socket proof: a server running this while
/// every response carries `Connection: close` is the one arrangement that can tell an observer
/// reading the socket from one reading the header. A version of this that closed under some
/// condition would make that proof vacuous, which is why it takes no arguments it could branch on.
#[must_use]
pub fn never_close() -> ClosePolicy {
    Arc::new(|_body| ConnectionDisposition::Keep)
}

/// What `Connection` header the server writes, independently of what it does to the socket.
///
/// The two are separable *only* so that the proof in `tests/socket_observation.rs` can drive them
/// apart. In every real run they agree, and [`Announce::Matching`] is what says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Announce {
    /// Announce what is actually about to happen to the socket.
    Matching,
    /// Always announce `close`, whatever the policy decided.
    ///
    /// A server that lies in this direction is the control case: an observer that believes it will
    /// report `closed` for every exchange, and an observer that reads the socket will not.
    AlwaysClose,
    /// Always announce `keep-alive`, whatever the policy decided.
    ///
    /// The control case for the other direction: a server that closes while announcing that it
    /// will not. An observer reading the header reports `open` here and is wrong. Both lies are
    /// needed, because an observer stuck at one answer satisfies whichever single control agrees
    /// with it.
    AlwaysKeepAlive,
}

/// The socket, plus whatever of the head was read past its end.
///
/// Head parsing reads in blocks and will usually over-read into the body, so the leftover travels
/// with the reader. Discarding it is how a server loses the first bytes of every body it is handed.
struct ConnReader {
    stream: TcpStream,
    buffer: Vec<u8>,
    position: usize,
}

impl ConnReader {
    fn new(stream: TcpStream) -> ConnReader {
        ConnReader {
            stream,
            buffer: Vec::new(),
            position: 0,
        }
    }

    fn buffered(&self) -> &[u8] {
        self.buffer.get(self.position..).unwrap_or_default()
    }

    fn fill(&mut self) -> std::io::Result<usize> {
        let mut block = [0_u8; 8192];
        let read = self.stream.read(&mut block)?;
        self.buffer.extend_from_slice(block.get(..read).unwrap_or_default());
        Ok(read)
    }

    /// Takes up to `limit` buffered bytes, reading from the socket when nothing is buffered.
    ///
    /// `Ok(None)` is end of stream, which on a half-closed connection is a fact about the peer and
    /// not an error.
    fn take(&mut self, limit: usize) -> std::io::Result<Option<Vec<u8>>> {
        if self.buffered().is_empty() && self.fill()? == 0 {
            return Ok(None);
        }
        let available = self.buffered().len().min(limit);
        let end = self.position.saturating_add(available);
        let out = self.buffer.get(self.position..end).unwrap_or_default().to_vec();
        self.position = end;
        Ok(Some(out))
    }

    /// Reads until the blank line that ends a request head.
    ///
    /// Bounded: an unbounded head read is a memory-exhaustion primitive available to any peer that
    /// never sends the blank line.
    fn read_head(&mut self, max: usize) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(end) = find_head_end(self.buffered()) {
                let head = self.buffered().get(..end).unwrap_or_default().to_vec();
                self.position = self.position.saturating_add(end);
                return Ok(Some(head));
            }
            if self.buffered().len() > max || self.fill()? == 0 {
                return Ok(None);
            }
        }
    }
}

/// The offset just past the blank line that ends a request head.
fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4)
}

/// A request body read straight off the socket, one block per poll.
///
/// Lazy on purpose: a service that pulls three frames and stops is what "the refusal arrived before
/// the payload was consumed" *is*, and a body that had buffered everything in advance could not
/// tell that apart from a service that read it all.
struct SocketBody {
    reader: Arc<Mutex<ConnReader>>,
    remaining: Option<u64>,
    consumed: Arc<AtomicU64>,
    drained: Arc<AtomicBool>,
}

impl http_body::Body for SocketBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        _context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let want = match this.remaining {
            Some(0) => {
                this.drained.store(true, Ordering::SeqCst);
                return core::task::Poll::Ready(None);
            }
            Some(left) => usize::try_from(left.min(8192)).unwrap_or(8192),
            None => 8192,
        };
        let Ok(mut reader) = this.reader.lock() else {
            return core::task::Poll::Ready(Some(Err(std::io::Error::other("the connection reader was poisoned"))));
        };
        match reader.take(want) {
            Err(error) => core::task::Poll::Ready(Some(Err(error))),
            Ok(None) => {
                // A declared length that did not arrive is a truncated body, and the service has to
                // be told: presenting a short upload to a handler as a complete one is how a
                // partial object is committed as a whole one.
                if this.remaining.unwrap_or(0) > 0 {
                    return core::task::Poll::Ready(Some(Err(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "the request body ended before its declared length",
                    ))));
                }
                this.drained.store(true, Ordering::SeqCst);
                core::task::Poll::Ready(None)
            }
            Ok(Some(block)) => {
                this.consumed.fetch_add(block.len() as u64, Ordering::SeqCst);
                if let Some(left) = this.remaining.as_mut() {
                    *left = left.saturating_sub(block.len() as u64);
                }
                core::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes::Bytes::from(block)))))
            }
        }
    }
}

/// A listener serving one service over its own HTTP/1.1 framing.
///
/// The port is the kernel's: see the module documentation for why that is the only arrangement
/// that does not race.
pub struct Listener {
    addr: SocketAddr,
    running: Arc<AtomicBool>,
}

impl Listener {
    /// Binds a loopback listener on a kernel-chosen port and starts serving.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when the socket cannot be bound.
    pub fn start(service: S3Service, policy: ClosePolicy, announce: Announce) -> Result<Listener, SutError> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|error| SutError::Environment(format!("cannot bind a loopback listener: {error}")))?;
        let addr = listener
            .local_addr()
            .map_err(|error| SutError::Environment(format!("the listener has no address: {error}")))?;
        let running = Arc::new(AtomicBool::new(true));
        let accepting = Arc::clone(&running);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if !accepting.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else { continue };
                let service = service.clone();
                let policy = Arc::clone(&policy);
                std::thread::spawn(move || serve(stream, &service, &policy, announce));
            }
        });
        Ok(Listener { addr, running })
    }

    /// The address the kernel assigned.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Serves requests on one connection until it ends.
fn serve(stream: TcpStream, service: &S3Service, policy: &ClosePolicy, announce: Announce) {
    let Ok(mut writer) = stream.try_clone() else { return };
    let _ = stream.set_read_timeout(Some(SERVER_READ_TIMEOUT));
    let reader = Arc::new(Mutex::new(ConnReader::new(stream)));
    while let Ok(ConnectionDisposition::Keep) = exchange(&reader, &mut writer, service, policy, announce) {}
    // The write side is shut down before the socket is dropped, so the peer observes an orderly
    // close rather than inferring one from a reset. `closed` and `reset` are two different
    // assertions in the corpus, and a server that always produced the second would make the first
    // unobservable.
    if let Ok(guard) = reader.lock() {
        let _ = guard.stream.shutdown(Shutdown::Both);
    }
}

/// Reads one request, drives the service, writes the response, reports the disposition.
fn exchange(
    reader: &Arc<Mutex<ConnReader>>,
    writer: &mut TcpStream,
    service: &S3Service,
    policy: &ClosePolicy,
    announce: Announce,
) -> Result<ConnectionDisposition, ()> {
    let head = {
        let mut guard = reader.lock().map_err(|_| ())?;
        match guard.read_head(64 * 1024) {
            Ok(Some(head)) => head,
            Ok(None) | Err(_) => return Err(()),
        }
    };
    let parsed = parse_head(&head).ok_or(())?;
    let consumed = Arc::new(AtomicU64::new(0));
    let drained = Arc::new(AtomicBool::new(false));
    let body = SocketBody {
        reader: Arc::clone(reader),
        remaining: parsed.declared_length,
        consumed: Arc::clone(&consumed),
        drained: Arc::clone(&drained),
    };
    let mut builder = http::Request::builder()
        .method(parsed.method.as_str())
        .uri(parsed.target.as_str());
    for (name, value) in &parsed.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let request = builder.body(body).map_err(|_| ())?;

    let response = block_on(service.call(request));
    let collected = block_on(collect(response)).map_err(|_| ())?;

    let disposition = BodyDisposition {
        declared: parsed.declared_length,
        consumed: consumed.load(Ordering::SeqCst),
        drained: drained.load(Ordering::SeqCst),
    };
    let verdict = policy(&disposition);
    write_response(writer, &collected, verdict, announce).map_err(|_| ())?;
    Ok(verdict)
}

/// A request head, parsed into the pieces the body framing needs.
struct ParsedHead {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    declared_length: Option<u64>,
}

/// Parses a request head.
///
/// Deliberately permissive about what it accepts: refusing a malformed head is
/// `WireRequest::accept`'s decision, and a connection layer that refused first would answer with
/// its own error and the case would never reach the code it is measuring. Only what this layer
/// needs in order to frame the body is interpreted here.
fn parse_head(head: &[u8]) -> Option<ParsedHead> {
    let text = core::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_owned();
    let target = request_line.next()?.to_owned();
    let mut headers = Vec::new();
    let mut declared_length = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_owned();
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            declared_length = value.parse::<u64>().ok();
        }
        if name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
        headers.push((name, value));
    }
    Some(ParsedHead {
        method,
        target,
        headers,
        // RFC 9112 §6.3: a *request* with neither `Transfer-Encoding` nor `Content-Length` has a
        // body of length zero. It is never "read until the peer closes" — that rule is for
        // responses, and applying it to a request would make every body-less `GET` on a keep-alive
        // connection block until the client gave up.
        //
        // This does not take the `411` decision away from the service. The framing decided here is
        // how many body bytes to read; the service still sees a head with no `Content-Length` and
        // still answers `411 MissingContentLength` to a write that needs one. The two questions are
        // separate and only one of them belongs to this layer.
        //
        // `None` therefore means one thing only: chunked framing, where the length is not knowable
        // from the head. The corpus reaches chunked bodies through `aws-chunked`, which is framed by
        // `Content-Length`, so no case in it takes this branch today.
        declared_length: if chunked { None } else { Some(declared_length.unwrap_or(0)) },
    })
}

/// Writes one response, and the `Connection` header.
///
/// The header is derived *from* the disposition; the disposition is never derived from a header.
/// That direction is the whole point of this module.
fn write_response(
    writer: &mut TcpStream,
    response: &rustfs_gateway::WireResponse,
    disposition: ConnectionDisposition,
    announce: Announce,
) -> std::io::Result<()> {
    let status = response.status();
    let mut out = Vec::new();
    out.extend_from_slice(
        format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status.canonical_reason().unwrap_or("Unknown")).as_bytes(),
    );
    for (name, value) in response.headers() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    let body = response.body();
    // Only when the service did not state one itself. Writing a second `Content-Length` would put
    // the exact shape `WireReject::DuplicateContentLength` exists to refuse onto the wire, and this
    // server would then be generating the smuggling primitive the suite is meant to detect.
    if !response.headers().iter().any(|(name, _)| name.as_str() == "content-length") {
        out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    }
    let announced = match (announce, disposition) {
        (Announce::AlwaysClose, _) | (Announce::Matching, ConnectionDisposition::Close) => b"close\r\n".as_slice(),
        (Announce::AlwaysKeepAlive, _) | (Announce::Matching, ConnectionDisposition::Keep) => b"keep-alive\r\n".as_slice(),
    };
    out.extend_from_slice(b"connection: ");
    out.extend_from_slice(announced);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    writer.write_all(&out)?;
    writer.flush()
}

/// What state a socket was left in, asked of the socket and of nothing else.
///
/// Never consults a response, a header, or anything the server said. See the module documentation
/// for why that is the entire contract, and the four-corner matrix in this file's tests for the
/// proof that it is what happens.
///
/// The classification:
///
/// * end of stream — the peer sent FIN — is [`ConnectionState::Closed`];
/// * `ECONNRESET` / `ECONNABORTED` is [`ConnectionState::Reset`];
/// * a read that timed out or would block means the peer is still holding the connection open, so
///   [`ConnectionState::Open`];
/// * unread bytes also mean open — the peer is still talking.
///
/// # Why `half_closed` is never reported
///
/// From this end of a TCP connection, a peer that shut down only its write side and a peer that
/// closed both look identical: a read returns end of stream in each case. The only way to tell them
/// apart is to *write* and see whether the write is refused — and a write that succeeds has put
/// bytes into a stream the next exchange will try to parse as a request, while a write that fails
/// has cost a `RST` that turns the very state being measured into a different one.
///
/// So this returns [`ConnectionState::Closed`] for both and never [`ConnectionState::HalfClosed`].
/// A case asserting `half_closed` is therefore red here for a stated reason, which is the honest
/// outcome: the alternative — guessing from a zero-length write, which on most platforms never
/// touches the socket and always succeeds — reports `closed` unconditionally while reading like a
/// measurement. `half_closed` is observable on the *server* side, where the shutdown arrives as an
/// end of stream on a body the peer still expects an answer to.
#[must_use]
pub fn observe_connection(stream: &TcpStream) -> ConnectionState {
    let _ = stream.set_read_timeout(Some(OBSERVE_TIMEOUT));
    let mut probe = [0_u8; 1];
    let mut reader = stream;
    match reader.read(&mut probe) {
        Ok(0) => ConnectionState::Closed,
        Ok(_) => ConnectionState::Open,
        Err(error) => match error.kind() {
            // No answer within the window. The peer is sitting on an open connection, which is
            // exactly what `open` asserts.
            ErrorKind::WouldBlock | ErrorKind::TimedOut => ConnectionState::Open,
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => ConnectionState::Reset,
            _ => ConnectionState::Closed,
        },
    }
}

/// One client connection, writing raw bytes and reading raw bytes back.
///
/// Raw on purpose: an SDK normalises away the malformed framing a negative case exists to send, so
/// there is no HTTP client here beyond what reading a response requires.
pub struct Connection {
    stream: TcpStream,
}

impl Connection {
    /// Opens a connection to a listener.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when the connection cannot be made.
    pub fn open(addr: SocketAddr) -> Result<Connection, SutError> {
        let stream = TcpStream::connect(addr).map_err(|error| SutError::Environment(format!("cannot connect: {error}")))?;
        Ok(Connection { stream })
    }

    /// Writes bytes on the connection.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when the write fails.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), SutError> {
        self.stream
            .write_all(bytes)
            .and_then(|()| self.stream.flush())
            .map_err(|error| SutError::Environment(format!("cannot write on the connection: {error}")))
    }

    /// Shuts the write side down, leaving the read side open.
    ///
    /// This is `half_close` as the corpus spells it: the server can still answer, so a case can
    /// assert the error it must produce rather than only that nothing arrived.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when the shutdown fails.
    pub fn half_close(&mut self) -> Result<(), SutError> {
        self.stream
            .shutdown(Shutdown::Write)
            .map_err(|error| SutError::Environment(format!("cannot half-close: {error}")))
    }

    /// Reads one HTTP/1.1 response: head, then a `Content-Length` body.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when no complete response arrives.
    pub fn read_response(&mut self, timeout: Duration) -> Result<RawResponse, SutError> {
        let _ = self.stream.set_read_timeout(Some(timeout));
        let mut buffer = Vec::new();
        let head_end = loop {
            if let Some(end) = find_head_end(&buffer) {
                break end;
            }
            let mut block = [0_u8; 4096];
            let read = self
                .stream
                .read(&mut block)
                .map_err(|error| SutError::Environment(format!("cannot read a response head: {error}")))?;
            if read == 0 {
                return Err(SutError::Environment("the connection ended before a response head arrived".to_owned()));
            }
            buffer.extend_from_slice(block.get(..read).unwrap_or_default());
        };
        let head = core::str::from_utf8(buffer.get(..head_end).unwrap_or_default())
            .map_err(|_| SutError::Environment("the response head is not UTF-8".to_owned()))?
            .to_owned();
        let (status, headers) = parse_response_head(&head)
            .ok_or_else(|| SutError::Environment("the response head is not a status line and headers".to_owned()))?;
        let length = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = buffer.get(head_end..).unwrap_or_default().to_vec();
        while body.len() < length {
            let mut block = [0_u8; 4096];
            let read = self
                .stream
                .read(&mut block)
                .map_err(|error| SutError::Environment(format!("cannot read a response body: {error}")))?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(block.get(..read).unwrap_or_default());
        }
        body.truncate(length);
        Ok(RawResponse { status, headers, body })
    }

    /// What state the socket is in, asked of the socket.
    #[must_use]
    pub fn observe(&self) -> ConnectionState {
        observe_connection(&self.stream)
    }
}

/// A response as it arrived, in wire order and wire casing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    /// The status code from the status line.
    pub status: u16,
    /// Response headers, in the order and casing they arrived in.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Vec<u8>,
}

/// Splits a response head into its status and its headers, keeping wire order and wire casing.
fn parse_response_head(head: &str) -> Option<(u16, Vec<(String, String)>)> {
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split(' ').nth(1)?.parse::<u16>().ok()?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    Some((status, headers))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Negative — a head with no blank line is not a head, however much of it arrived.
    #[test]
    fn an_unterminated_head_has_no_end() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\nhost: x\r\n"), None);
        assert_eq!(find_head_end(b""), None);
    }

    /// Positive — the end is just past the blank line, so the next byte is the first body byte.
    #[test]
    fn the_head_ends_just_past_the_blank_line() {
        let head = b"GET / HTTP/1.1\r\nhost: x\r\n\r\nBODY";
        let end = find_head_end(head).expect("a terminated head");
        assert_eq!(&head[end..], b"BODY");
    }

    /// Negative — a chunked request declares no length, so the framing must not fall back to a
    /// `Content-Length` that a smuggling pair supplied alongside it.
    #[test]
    fn a_chunked_head_declares_no_length() {
        let head = b"PUT /b/k HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\ncontent-length: 9\r\n\r\n";
        assert_eq!(parse_head(head).expect("parsable").declared_length, None);
    }

    /// Negative — a request with no framing headers has a zero-length body, not an unbounded one.
    ///
    /// RFC 9112 §6.3. Reading such a request until the peer closed would hang every body-less `GET`
    /// on a keep-alive connection, which is the defect this pins.
    #[test]
    fn a_head_with_no_framing_frames_an_empty_body() {
        let parsed = parse_head(b"PUT /b/k HTTP/1.1\r\nhost: x\r\n\r\n").expect("parsable");
        assert_eq!(parsed.declared_length, Some(0));
        assert_eq!(parsed.method, "PUT");
        assert_eq!(parsed.target, "/b/k");
        // And the head still carries no `content-length`, so the service can still answer `411`.
        assert!(
            !parsed
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        );
    }

    /// Positive — a declared length survives parsing, because it is what frames the body.
    #[test]
    fn a_declared_length_is_read() {
        let parsed = parse_head(b"PUT /b/k HTTP/1.1\r\nhost: x\r\ncontent-length: 11\r\n\r\n").expect("parsable");
        assert_eq!(parsed.declared_length, Some(11));
    }

    /// Negative — a response head that is not a status line yields nothing rather than a zero.
    #[test]
    fn a_malformed_response_head_is_not_a_status() {
        assert_eq!(parse_response_head("not a status line\r\n\r\n"), None);
        assert_eq!(parse_response_head("HTTP/1.1 nope OK\r\n\r\n"), None);
    }

    /// Positive — wire casing and wire order survive, because `header_order` and
    /// `header_name_bytes_exact` are assertions no normalised map could answer.
    #[test]
    fn a_response_head_keeps_wire_order_and_casing() {
        let (status, headers) =
            parse_response_head("HTTP/1.1 403 Forbidden\r\nContent-Type: application/xml\r\nX-Amz-Id-2: k\r\n\r\n")
                .expect("parsable");
        assert_eq!(status, 403);
        assert_eq!(headers[0].0, "Content-Type");
        assert_eq!(headers[1].0, "X-Amz-Id-2");
    }

    /// Negative — a body the service abandoned leaves bytes with no owner, and the default policy
    /// says so. This is the RFC 9112 §9.6 condition the default is grounded in.
    #[test]
    fn an_abandoned_body_leaves_bytes_unread() {
        let abandoned = BodyDisposition {
            declared: Some(4_000_000),
            consumed: 8192,
            drained: false,
        };
        assert!(abandoned.leaves_unread_bytes());
        assert_eq!(rfc9112_lingering_close()(&abandoned), ConnectionDisposition::Close);
    }

    /// Negative — a drained body is not a close, or every exchange would end the connection and
    /// `connection_after = "open"` would be unobservable.
    #[test]
    fn a_drained_body_is_not_a_close() {
        let drained = BodyDisposition {
            declared: Some(11),
            consumed: 11,
            drained: true,
        };
        assert!(!drained.leaves_unread_bytes());
        assert_eq!(rfc9112_lingering_close()(&drained), ConnectionDisposition::Keep);
    }

    /// Negative — the control policy never closes, whatever it is handed. The header-versus-socket
    /// proof runs against this, and a version that closed under some condition would make the proof
    /// vacuous.
    #[test]
    fn the_control_policy_never_closes() {
        for drained in [true, false] {
            let disposition = BodyDisposition {
                declared: Some(9),
                consumed: 0,
                drained,
            };
            assert_eq!(never_close()(&disposition), ConnectionDisposition::Keep);
        }
    }

    // -- The socket-versus-header proof -------------------------------------------------------
    //
    // Everything below drives a real listener on a real port. The two that matter are the pair:
    // one server announces `close` and does not close, the other announces `close` and does close,
    // and the observer must tell them apart. A harness that read the header would report `closed`
    // for both, and the corpus would then carry two assertions that cannot fail.

    /// A listener over a service assembled from the facade, on a port the kernel chose.
    fn listener(policy: ClosePolicy, announce: Announce) -> Listener {
        let target = crate::inprocess::InProcess::new(std::path::PathBuf::from("."));
        let service = target.assemble(0, 0).expect("the service assembles");
        Listener::start(service, policy, announce).expect("a loopback listener binds")
    }

    /// Performs one exchange and reports what the socket was left in.
    fn exchange_then_observe(listener: &Listener) -> (RawResponse, ConnectionState) {
        let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
        connection
            .write(b"GET /?x=1 HTTP/1.1\r\nhost: s3.example.com\r\n\r\n")
            .expect("the request is written");
        let response = connection.read_response(Duration::from_secs(10)).expect("a response arrives");
        (response, connection.observe())
    }

    fn announced_close(response: &RawResponse) -> bool {
        response
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("connection") && value.eq_ignore_ascii_case("close"))
    }

    /// **Negative — the assertion this whole module exists to make falsifiable.**
    ///
    /// The server announces `Connection: close` on every response and never closes anything. A
    /// harness that inferred the connection state from the response header would report `closed`
    /// here; one that asks the socket reports `open`. If this test ever goes red with `closed`,
    /// `observe_connection` has started reading the header and every `connection_after` assertion
    /// in the corpus has quietly stopped measuring anything.
    #[test]
    fn a_response_announcing_close_over_a_socket_that_stayed_up_is_observed_open() {
        let listener = listener(never_close(), Announce::AlwaysClose);
        let (response, state) = exchange_then_observe(&listener);
        assert!(
            announced_close(&response),
            "the control server must announce close: {:?}",
            response.headers
        );
        assert_eq!(
            state,
            ConnectionState::Open,
            "the socket stayed up, so the observation must be `open` however the response was headed"
        );
    }

    /// Positive — the other half of the pair. Same announcement, and this time the socket really
    /// does close, so the observation moves. One test without the other proves nothing: a stuck
    /// `open` would satisfy the negative above on its own.
    #[test]
    fn a_socket_the_server_actually_closed_is_observed_closed() {
        let listener = listener(Arc::new(|_body| ConnectionDisposition::Close), Announce::AlwaysClose);
        let (response, state) = exchange_then_observe(&listener);
        assert!(announced_close(&response));
        assert_eq!(state, ConnectionState::Closed);
    }

    /// **Negative — the same proof in the opposite direction.**
    ///
    /// The server closes the socket while announcing `keep-alive`. A harness reading the header
    /// reports `open` and is wrong. Both lies are needed: an observer stuck at a single answer
    /// satisfies whichever one control happens to agree with it, so one control alone proves
    /// nothing about the other.
    #[test]
    fn a_socket_closed_while_announcing_keep_alive_is_still_observed_closed() {
        let listener = listener(Arc::new(|_body| ConnectionDisposition::Close), Announce::AlwaysKeepAlive);
        let (response, state) = exchange_then_observe(&listener);
        assert!(!announced_close(&response), "{:?}", response.headers);
        assert_eq!(
            state,
            ConnectionState::Closed,
            "the socket was closed, so the observation must be `closed` however the response was headed"
        );
    }

    /// Negative — the server never writes two `Content-Length` headers.
    ///
    /// A duplicate is the exact shape `WireReject::DuplicateContentLength` refuses, so a server
    /// that emitted one would be generating the smuggling primitive this suite exists to detect —
    /// and every response it framed would be one the corpus's own rules call malformed.
    #[test]
    fn a_response_carries_exactly_one_content_length() {
        let listener = listener(never_close(), Announce::Matching);
        let (response, _) = exchange_then_observe(&listener);
        let lengths = response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .count();
        assert_eq!(lengths, 1, "{:?}", response.headers);
    }

    /// Positive — a kept connection really is reusable, which is what `open` claims. Asserted by
    /// using it: a second request on the same socket is answered.
    #[test]
    fn a_connection_observed_open_carries_another_request() {
        let listener = listener(never_close(), Announce::Matching);
        let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
        for _ in 0..2 {
            connection
                .write(b"GET /?x=1 HTTP/1.1\r\nhost: s3.example.com\r\n\r\n")
                .expect("written");
            let response = connection.read_response(Duration::from_secs(10)).expect("answered");
            assert!(response.status > 0);
            assert_eq!(connection.observe(), ConnectionState::Open);
        }
    }

    /// Negative — two listeners are on two different ports without either of them naming one.
    ///
    /// This is the whole of the port-collision argument: nothing here picks a port, so nothing can
    /// pick the same one twice, however many run at once.
    #[test]
    fn two_listeners_never_share_a_port() {
        let first = listener(never_close(), Announce::Matching);
        let second = listener(never_close(), Announce::Matching);
        assert_ne!(first.addr().port(), second.addr().port());
        assert_ne!(first.addr().port(), 0, "the kernel assigned a real port");
    }
}
