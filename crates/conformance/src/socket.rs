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
//! # Pacing: why the clock is never waited on
//!
//! A body written into a loopback socket in one call is in the kernel buffer before the server has
//! read a byte of it. Measure "how much of the body had gone out when the answer arrived" from the
//! client under those conditions and the number is the size of the buffer, not a fact about the
//! server — so `c-sig-0001`'s `body_bytes_sent_at_response = 0` would be handed the whole body and
//! **invert while still reading as measured**. That is why `--transport conn` did not exist before
//! this module could pace.
//!
//! The obvious way to pace is to sleep for `dataChunk.delay_ms`. It is also the wrong way, and the
//! reason is in the corpus rather than in taste: `c-sig-0001` declares two 300 ms pauses *and*
//! `terminate_within_ms = 3000`, `c-chunked-0001` declares 40 ms and 20 ms pauses *and*
//! `terminate_within_ms = 5000`. Sleeping spends the case's own timing budget on the harness, and
//! how much of it is left over is a property of the build machine. A suite whose verdicts move with
//! the load average is a suite whose red is not information.
//!
//! So this paces on the **peer**, not on the clock. [`Pacer`] is a rendezvous between the client
//! thread and the server thread of one connection:
//!
//! * the server signals [`Pacer::server_wants_body`] at the moment it is about to block reading
//!   body bytes off the socket — it has asked, and there is nothing buffered to answer with;
//! * it signals [`Pacer::server_ended_body`] when the body reported its end, and
//!   [`Pacer::server_answered`] when the service has produced a response.
//!
//! The client writes the head, then waits, and releases the next frame only when the server has
//! asked for it. It stops writing the moment the response exists. No `Duration` enters the decision
//! anywhere, so *the bytes on the wire are the same on an idle laptop and on a machine under load*,
//! and the byte counts a case asserts are reproducible rather than probabilistic. The one
//! [`Duration`] in the rendezvous is a safety net measured in tens of seconds, whose only job is to
//! stop a wedged server from holding the run: it is never the path a passing case takes, and when it
//! does fire the exchange is reported as an environment failure — a skip with a reason — rather than
//! as a byte count nobody measured.
//!
//! What this deliberately does **not** do is honour the *number* in `dataChunk.delay_ms`. The value
//! stays unread and `crate::keys::DECLARED` still says so. Pacing by acknowledgement gives the case
//! everything the pause was there to buy — the server gets the chance to answer before the next
//! frame exists — and gives it deterministically, which the pause could not.
//!
//! # Why there is no async runtime
//!
//! One thread per connection, and the service future driven on that thread by [`crate::exec::block_on`].
//! This crate is a product other S3 implementations run against themselves, and every dependency it
//! carries is one they inherit; a work-stealing scheduler to run one future at a time is the largest
//! thing it could inherit for the least reason. Blocking inside `poll_frame` is sound because the
//! thread doing it serves one connection and has nothing else to make progress on.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rustfs_gateway::{ConnectionIntent, S3Service, collect, connection_intent_of};

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
    ///
    /// A *declared* length settles this by arithmetic rather than by whether anybody bothered to
    /// read: a request that framed zero bytes owes none, so a body-less request the service never
    /// polled leaves nothing behind. Chunked framing has no arithmetic to do it with, so there
    /// `drained` is the only fact there is.
    ///
    /// **Measured**: on today's corpus this and the older `!drained` agree on every case, because
    /// the codec drains what it is given and `drained` is therefore true wherever the arithmetic
    /// says the debt is settled. The change is not worth a conformance number and is not claimed to
    /// be one. It is here because the RFC's condition is about bytes the peer still owes and the
    /// flag is about what a reader did, and the day a handler answers a zero-length request without
    /// touching its body — a `411`, an authorisation refusal — the flag says the connection is
    /// carrying a smuggled request that does not exist.
    #[must_use]
    pub const fn leaves_unread_bytes(&self) -> bool {
        self.undrained_bytes() > 0
    }

    /// How many body bytes the peer still owes.
    ///
    /// `u64::MAX` for a chunked body that did not end, because there is no arithmetic that can say
    /// how much is left and a drain budget must not be handed a number it invented. Zero once the
    /// debt is settled.
    #[must_use]
    pub const fn undrained_bytes(&self) -> u64 {
        match self.declared {
            Some(declared) => declared.saturating_sub(self.consumed),
            None if self.drained => 0,
            None => u64::MAX,
        }
    }
}

/// The rendezvous that replaces a sleep between two body frames.
///
/// One per connection. See the module documentation for why pacing is driven by the peer rather
/// than by the clock; this type is that argument in code. Every field is a monotone fact about what
/// the *server* thread has done, and the client thread waits on them.
#[derive(Debug, Default)]
pub struct Pacer {
    state: Mutex<PacerState>,
    signal: Condvar,
}

#[derive(Debug, Default, Clone, Copy)]
struct PacerState {
    /// How many times the server has been about to block reading body bytes with nothing buffered.
    ///
    /// A counter rather than a flag: the client compares it against how many demands it has already
    /// answered, so a demand that arrives while the client is mid-write is not lost.
    wants: u64,
    /// Whether the body reported its end to the service.
    ended: bool,
    /// Whether the service has produced a response.
    answered: bool,
}

/// What released a client waiting on a [`Pacer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demand {
    /// The server asked for body bytes it did not have.
    More,
    /// The service produced a response; nothing more of the body will be read.
    Answered,
    /// Neither happened inside the safety net. Never the path a passing case takes.
    Wedged,
}

impl Pacer {
    /// A fresh rendezvous.
    #[must_use]
    pub fn new() -> Pacer {
        Pacer::default()
    }

    /// Clears the record, for the next exchange on a reused connection.
    ///
    /// Safe only because the client calls it *before* writing the next request head: the server
    /// cannot have signalled anything about a request whose first byte has not been written.
    pub fn reset(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = PacerState::default();
        }
        self.signal.notify_all();
    }

    /// The server is about to block reading body bytes and has nothing buffered.
    pub fn server_wants_body(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.wants = state.wants.saturating_add(1);
        }
        self.signal.notify_all();
    }

    /// The body reported its end to the service.
    pub fn server_ended_body(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.ended = true;
        }
        self.signal.notify_all();
    }

    /// The service produced a response.
    pub fn server_answered(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.answered = true;
        }
        self.signal.notify_all();
    }

    /// Whether the service has already answered.
    #[must_use]
    pub fn answered(&self) -> bool {
        self.state.lock().map(|state| state.answered).unwrap_or(true)
    }

    /// Waits until the server asks for body bytes it has not already been given, or answers.
    ///
    /// `answered` is how many demands this client has already satisfied, and is advanced on the way
    /// out. Passing the same counter through a whole chunk sequence is what stops a demand raised
    /// while the client was writing from being waited on twice.
    pub fn await_demand(&self, satisfied: &mut u64, budget: Duration) -> Demand {
        let deadline = std::time::Instant::now() + budget;
        let Ok(mut state) = self.state.lock() else {
            return Demand::Wedged;
        };
        loop {
            if state.answered {
                return Demand::Answered;
            }
            if state.wants > *satisfied {
                *satisfied = state.wants;
                return Demand::More;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Demand::Wedged;
            }
            let Ok((next, _)) = self.signal.wait_timeout(state, deadline - now) else {
                return Demand::Wedged;
            };
            state = next;
        }
    }

    /// Waits until the server has taken everything written so far, one way or another.
    ///
    /// What a client asks before tearing the connection down: "close here" is only a meaningful
    /// instruction once the bytes before it have been handed over, and this is how that is known
    /// without guessing at a delay. Three things count as handed over, and all three are needed:
    ///
    /// * the body reported its end — the declared length was met;
    /// * the service answered — nothing more of the body will be read;
    /// * **the server asked again** — it consumed what was there and wants more, which is the only
    ///   one of the three that a *truncating* case ever reaches. Waiting for the body's end alone
    ///   wedged `c-mpu-0043` for its whole budget: a part that announces a megabyte and writes
    ///   twenty-nine bytes is never going to end, and the half-close is the point.
    pub fn await_handover(&self, satisfied: &mut u64, budget: Duration) -> Demand {
        let deadline = std::time::Instant::now() + budget;
        let Ok(mut state) = self.state.lock() else {
            return Demand::Wedged;
        };
        loop {
            if state.ended || state.wants > *satisfied {
                *satisfied = state.wants;
                return Demand::More;
            }
            if state.answered {
                return Demand::Answered;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Demand::Wedged;
            }
            let Ok((next, _)) = self.signal.wait_timeout(state, deadline - now) else {
                return Demand::Wedged;
            };
            state = next;
        }
    }

    /// Waits up to `budget` for the service to answer, and reports whether it did.
    ///
    /// This is how a `stall` control chunk is carried out: hold the connection open and send
    /// nothing, but stop holding it the moment there is an answer to read.
    pub fn stall_until_answered(&self, budget: Duration) -> bool {
        let deadline = std::time::Instant::now() + budget;
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        loop {
            if state.answered {
                return true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let Ok((next, _)) = self.signal.wait_timeout(state, deadline - now) else {
                return false;
            };
            state = next;
        }
    }
}

/// Pacers waiting to be bound to the next connection the listener accepts.
///
/// The client pushes one, *then* connects; the server pops one on accept. Accept order is connect
/// order for a single client, which is the only arrangement this suite creates. A connection that
/// finds the queue empty gets a detached pacer, so an unpaced caller — the tests at the bottom of
/// this file, for instance — never blocks a server thread.
pub type PacerQueue = Arc<Mutex<VecDeque<Arc<Pacer>>>>;

/// Whether a connection survives one exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionDisposition {
    /// The connection stays up and the next request is read from it.
    Keep,
    /// The write side is shut down and the socket is dropped.
    Close,
}

/// How much of a body the service abandoned this server is willing to read before giving up on the
/// connection.
///
/// RFC 9112 §9.6 describes the lingering read and puts no number on it; `rustfs-gateway-http` has
/// its own `MAX_LINGER_DRAIN_BYTES` and the facade does not re-export it, so this is a second
/// number rather than the same one — stated here so that a reader of a `connection_after` verdict
/// can see which budget produced it. It only ever decides cases where the service said
/// [`ConnectionIntent::MayKeepAlive`] over a body it did not finish: too much left to drain and the
/// connection ends anyway, which is exactly what that variant's documentation says a transport may
/// do.
pub const MAX_LINGER_DRAIN_BYTES: u64 = 64 * 1024;

/// How long the drain waits for the remainder to arrive.
///
/// Generous, and never on the path of a case that passes: the peer is a client in this same process
/// which writes its remainder as soon as it learns there is an answer. A drain that timed out is a
/// peer that stopped sending, and RFC 9112 §9.3 then leaves no choice about the connection.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(200);

/// The whole lingering close, end to end, however much the peer still has to say.
///
/// [`DRAIN_TIMEOUT`] bounds one read; a peer that keeps writing resets it on every block and would
/// otherwise hold this thread for as long as it cared to. This is the outer bound, and it is a
/// *time* rather than a byte count on purpose — see [`close_orderly`] for why the byte count that
/// used to sit here made `connection_after = "closed"` unreachable for the cases that most need it.
const LINGER_TIME: Duration = Duration::from_secs(2);

/// Decides whether a connection survives one exchange.
///
/// Still injected, but no longer because the rule is unknown. `crates/gateway`'s `close.rs` now
/// states it as a table and carries the verdict out of the pipeline as a response extension, so
/// [`honour_the_services_intent`] is the policy a real run uses and it asks the service. What the
/// parameter is for is the four-corner proof at the bottom of this file, which needs a server that
/// lies — and a policy that could not be replaced could not lie.
pub type ClosePolicy = Arc<dyn Fn(&BodyDisposition, ConnectionIntent) -> ConnectionDisposition + Send + Sync>;

/// The service decides, and RFC 9112 §9.3 decides the rest.
///
/// Two inputs, and neither of them is a header:
///
/// * what the service said — [`rustfs_gateway::connection_intent_of`], read off the response as an
///   extension. `ConnectionIntent::Close` ends the connection whatever this layer would prefer.
/// * what is left on the wire. `MayKeepAlive` is not a promise that the connection survives; its
///   own documentation says it survives *if the remainder of the request body is drained*. So this
///   server drains it, and closes when it will not — the remainder is past
///   [`MAX_LINGER_DRAIN_BYTES`], or it never arrived.
///
/// This is what makes `connection_after` a measurement of the service on this transport rather than
/// of the harness. Flip a row in `close.rs` and a case moves; leave `close.rs` alone and edit this
/// function and the four-corner proof below goes red.
#[must_use]
pub fn honour_the_services_intent() -> ClosePolicy {
    Arc::new(|body, intent| {
        if intent.must_close() || body.undrained_bytes() > MAX_LINGER_DRAIN_BYTES {
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
/// condition would make that proof vacuous, which is why it branches on neither argument.
#[must_use]
pub fn never_close() -> ClosePolicy {
    Arc::new(|_body, _intent| ConnectionDisposition::Keep)
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
    pacer: Arc<Pacer>,
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
                this.pacer.server_ended_body();
                return core::task::Poll::Ready(None);
            }
            Some(left) => usize::try_from(left.min(8192)).unwrap_or(8192),
            None => 8192,
        };
        let Ok(mut reader) = this.reader.lock() else {
            return core::task::Poll::Ready(Some(Err(std::io::Error::other("the connection reader was poisoned"))));
        };
        // The demand is raised *before* the read blocks, and only when there is nothing buffered to
        // answer it with. Both halves matter: signalling afterwards would deadlock a paced client
        // waiting for the demand that the block is waiting for, and signalling when bytes are
        // already in hand would let the client run a frame ahead of the server for no reason.
        if reader.buffered().is_empty() {
            this.pacer.server_wants_body();
        }
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
                this.pacer.server_ended_body();
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
    pacers: PacerQueue,
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
        let pacers: PacerQueue = Arc::new(Mutex::new(VecDeque::new()));
        let serving = Arc::clone(&pacers);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if !accepting.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else { continue };
                let service = service.clone();
                let policy = Arc::clone(&policy);
                let pacer = serving
                    .lock()
                    .ok()
                    .and_then(|mut queue| queue.pop_front())
                    .unwrap_or_else(|| Arc::new(Pacer::new()));
                std::thread::spawn(move || serve(stream, &service, &policy, announce, &pacer));
            }
        });
        Ok(Listener { addr, running, pacers })
    }

    /// The address the kernel assigned.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Binds a rendezvous to the *next* connection this listener accepts.
    ///
    /// Called before `TcpStream::connect`, never after: the queue is ordered and accept order is
    /// connect order, so a pacer pushed after the connection was made would be handed to somebody
    /// else's socket.
    pub fn enqueue_pacer(&self, pacer: &Arc<Pacer>) {
        if let Ok(mut queue) = self.pacers.lock() {
            queue.push_back(Arc::clone(pacer));
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Serves requests on one connection until it ends.
fn serve(stream: TcpStream, service: &S3Service, policy: &ClosePolicy, announce: Announce, pacer: &Arc<Pacer>) {
    let Ok(mut writer) = stream.try_clone() else { return };
    let _ = stream.set_read_timeout(Some(SERVER_READ_TIMEOUT));
    let reader = Arc::new(Mutex::new(ConnReader::new(stream)));
    while let Ok(ConnectionDisposition::Keep) = exchange(&reader, &mut writer, service, policy, announce, pacer) {}
    close_orderly(&reader);
}

/// Ends a connection so that the peer sees a close and not a reset.
///
/// Two acts, in this order, and the order is the whole of it:
///
/// 1. **`shutdown(Write)`** sends FIN. That is what `connection_after = "closed"` is: the peer's
///    next read returns end of stream.
/// 2. **Read what is still in flight and throw it away.** Closing a socket that still holds unread
///    received octets sends `RST` instead — and the corpus spells `closed` and `reset` as two
///    different assertions, so a server that produced the second would make the first unobservable.
///    There *is* something in flight in the ordinary case: this suite's client paces its body on the
///    server's demands and finishes writing what it owes as soon as it learns there is an answer, so
///    a refusal that never read the payload is followed by the payload arriving.
///
/// # Why the bound is a clock and not a byte count
///
/// This used to stop after [`MAX_LINGER_DRAIN_BYTES`], and that made the second act useless in
/// exactly the case it exists for. A refusal that fires *because* the body is too large leaves far
/// more than 64 KiB in flight by construction, so the drain stopped early, `shutdown(Both)` ran
/// over a socket still holding unread octets, and the peer got `RST` — erasing the refusal it had
/// not finished reading. That is the failure RFC 9112 §9.6 describes in as many words, and
/// `c-object-0015` observed it as `reset` against an assertion of `closed`.
///
/// The byte count is also the wrong quantity. What the ceilings above refuse to spend is *memory*:
/// aggregating a body before deciding about it is the out-of-memory condition. Reading a block and
/// dropping it costs no memory at all, so the resource a drain has to be bounded in is time — which
/// is what `lingering_time` bounds in nginx and what Apache's lingering close bounds too. Both
/// bounds are still here: [`DRAIN_TIMEOUT`] per read, so a peer that goes silent does not hold the
/// thread, and [`LINGER_TIME`] overall, so a peer that keeps writing does not either.
/// [`MAX_LINGER_DRAIN_BYTES`] keeps the job it was always right for — deciding in
/// [`honour_the_services_intent`] whether a connection is worth keeping — and no longer decides how
/// a connection that is already ending gets ended.
fn close_orderly(reader: &Arc<Mutex<ConnReader>>) {
    let Ok(mut guard) = reader.lock() else { return };
    let _ = guard.stream.shutdown(Shutdown::Write);
    let _ = guard.stream.set_read_timeout(Some(DRAIN_TIMEOUT));
    let deadline = Instant::now() + LINGER_TIME;
    while Instant::now() < deadline {
        match guard.take(8192) {
            Ok(Some(block)) if !block.is_empty() => {}
            _ => break,
        }
    }
    let _ = guard.stream.shutdown(Shutdown::Both);
}

/// Reads one request, drives the service, writes the response, reports the disposition.
fn exchange(
    reader: &Arc<Mutex<ConnReader>>,
    writer: &mut TcpStream,
    service: &S3Service,
    policy: &ClosePolicy,
    announce: Announce,
    pacer: &Arc<Pacer>,
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
        pacer: Arc::clone(pacer),
    };
    let mut builder = http::Request::builder()
        .method(parsed.method.as_str())
        .uri(parsed.target.as_str());
    for (name, value) in &parsed.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let request = builder.body(body).map_err(|_| ())?;

    let response = block_on(service.call(request));
    // Read before the response is consumed, and read as an *extension* rather than as a header.
    // `crate::render` deliberately does not write `Connection: close`; only the hyper and tower
    // adapters do, and a harness that reported the header would be reporting an announcement.
    let intent = connection_intent_of(&response).unwrap_or_default();
    let collected = block_on(collect(response));
    // Raised whatever the collect returned, and *before* a byte of the response is written: a
    // client blocked waiting to release the next frame has to be told that no further frame will
    // ever be read, and a stream that failed halfway is still an answer in that sense. Signalling
    // after `write_response` would wedge every case whose service refuses without draining.
    pacer.server_answered();
    let collected = collected.map_err(|_| ())?;

    let disposition = BodyDisposition {
        declared: parsed.declared_length,
        consumed: consumed.load(Ordering::SeqCst),
        drained: drained.load(Ordering::SeqCst),
    };
    let mut verdict = policy(&disposition, intent);
    // `MayKeepAlive` is a condition, not a promise: the connection survives if what the peer still
    // owes is read off it. Performed here rather than assumed, because the next bytes on a
    // connection whose last body was left half-read are the tail of that body, and a server that
    // parsed them as a request line is the receiving half of a request-smuggling pair. A drain that
    // does not complete turns the verdict back into a close, which is what §9.3 leaves.
    if verdict == ConnectionDisposition::Keep
        && disposition.leaves_unread_bytes()
        && !drain_remainder(reader, disposition.undrained_bytes())
    {
        verdict = ConnectionDisposition::Close;
    }
    write_response(writer, &collected, verdict, announce, &parsed.method).map_err(|_| ())?;
    Ok(verdict)
}

/// Reads what the peer still owes, and reports whether all of it arrived.
fn drain_remainder(reader: &Arc<Mutex<ConnReader>>, mut remaining: u64) -> bool {
    let Ok(mut guard) = reader.lock() else { return false };
    let _ = guard.stream.set_read_timeout(Some(DRAIN_TIMEOUT));
    while remaining > 0 {
        let want = usize::try_from(remaining.min(8192)).unwrap_or(8192);
        match guard.take(want) {
            Ok(Some(block)) if !block.is_empty() => remaining = remaining.saturating_sub(block.len() as u64),
            _ => return false,
        }
    }
    let _ = guard.stream.set_read_timeout(Some(SERVER_READ_TIMEOUT));
    true
}

/// Whether a response to `method` with this status carries a body at all.
///
/// RFC 9112 §6.3: a `HEAD` response, a `204` and a `304` have no body *whatever their headers say*,
/// and a reader that trusted `Content-Length` on one of them waits for bytes that are never coming.
/// This is the rule for the writer and for the reader alike, which is why it is one function: a
/// server that framed one way and a client that read the other is a hang neither of them can see.
#[must_use]
pub fn carries_a_body(method: &str, status: u16) -> bool {
    !method.eq_ignore_ascii_case("HEAD") && status != 204 && status != 304 && !(100..200).contains(&status)
}

/// A request head, parsed into the pieces the body framing needs.
pub(crate) struct ParsedHead {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) declared_length: Option<u64>,
}

/// Parses a request head.
///
/// Deliberately permissive about what it accepts: refusing a malformed head is
/// `WireRequest::accept`'s decision, and a connection layer that refused first would answer with
/// its own error and the case would never reach the code it is measuring. Only what this layer
/// needs in order to frame the body is interpreted here.
pub(crate) fn parse_head(head: &[u8]) -> Option<ParsedHead> {
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
    method: &str,
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
    let framed = carries_a_body(method, status.as_u16());
    // Only when the service did not state one itself. Writing a second `Content-Length` would put
    // the exact shape `WireReject::DuplicateContentLength` exists to refuse onto the wire, and this
    // server would then be generating the smuggling primitive the suite is meant to detect.
    //
    // And only on a response that has a body. Synthesising `content-length: 0` onto a `304` puts a
    // framing header on the one status whose whole contract is not to carry one — `c-cond-0022` is
    // the case that says so — and it would be *this layer* putting it there, so the case would be
    // red for something the service never did.
    if framed && !response.headers().iter().any(|(name, _)| name.as_str() == "content-length") {
        out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    }
    let announced = match (announce, disposition) {
        (Announce::AlwaysClose, _) | (Announce::Matching, ConnectionDisposition::Close) => b"close\r\n".as_slice(),
        (Announce::AlwaysKeepAlive, _) | (Announce::Matching, ConnectionDisposition::Keep) => b"keep-alive\r\n".as_slice(),
    };
    out.extend_from_slice(b"connection: ");
    out.extend_from_slice(announced);
    out.extend_from_slice(b"\r\n");
    if framed {
        out.extend_from_slice(body);
    }
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
    body_written: u64,
    torn_down: bool,
}

impl Connection {
    /// Opens a connection to a listener.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when the connection cannot be made.
    pub fn open(addr: SocketAddr) -> Result<Connection, SutError> {
        let stream = TcpStream::connect(addr).map_err(|error| SutError::Environment(format!("cannot connect: {error}")))?;
        Ok(Connection {
            stream,
            body_written: 0,
            torn_down: false,
        })
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

    /// Writes payload bytes, counting them.
    ///
    /// The count is what `expect.request_progress.body_bytes_sent_at_response` names, and it counts
    /// *payload* only: head bytes are not body bytes, and a transport that lumped them together
    /// would answer `0` for nothing and make the assertion unsatisfiable rather than unfalsifiable.
    /// Each call is its own `write_all` plus `flush`, which is the frame boundary
    /// `dataChunk.flush` asks for.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when the write fails.
    pub fn write_body(&mut self, bytes: &[u8]) -> Result<(), SutError> {
        self.write(bytes)?;
        self.body_written = self.body_written.saturating_add(bytes.len() as u64);
        Ok(())
    }

    /// Payload bytes written on this connection so far.
    #[must_use]
    pub const fn body_written(&self) -> u64 {
        self.body_written
    }

    /// Forgets the payload counter, for the next exchange on a reused connection.
    pub const fn start_exchange(&mut self) {
        self.body_written = 0;
    }

    /// Whether this client tore the connection down itself.
    ///
    /// Recorded rather than inferred, because a socket the client closed and a socket the server
    /// closed read identically from here and are two different findings.
    #[must_use]
    pub const fn torn_down(&self) -> bool {
        self.torn_down
    }

    /// Closes both directions: the `close` control chunk.
    ///
    /// # Errors
    ///
    /// Returns [`SutError::Environment`] when the shutdown fails.
    pub fn close(&mut self) -> Result<(), SutError> {
        self.torn_down = true;
        self.stream
            .shutdown(Shutdown::Both)
            .map_err(|error| SutError::Environment(format!("cannot close: {error}")))
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
    /// Returns [`SutError::Environment`] when no complete response arrives. Callers that have to
    /// tell "nothing came" from "the peer hung up" apart use [`Connection::read_response_classified`]:
    /// those are `expect.kind = "hang"` and `expect.kind = "connection_reset"`, which are two
    /// different verdicts.
    pub fn read_response(&mut self, timeout: Duration) -> Result<RawResponse, SutError> {
        self.read_response_classified("GET", timeout)
            .map_err(|failure| SutError::Environment(failure.to_string()))
    }

    /// Reads one response, naming *how* it failed to arrive when it did not.
    ///
    /// `method` is the method of the request this answers, because that is half of whether the
    /// response has a body at all — see [`carries_a_body`]. Reading a body off a `HEAD` answer
    /// because its `Content-Length` named one is a hang, and a hang that looks from the report like
    /// a server that never replied.
    ///
    /// # Errors
    ///
    /// Returns the classification, which the caller turns into an [`crate::observation::Outcome`].
    pub fn read_response_classified(&mut self, method: &str, timeout: Duration) -> Result<RawResponse, ReadFailure> {
        let _ = self.stream.set_read_timeout(Some(timeout));
        let mut buffer = Vec::new();
        let head_end = loop {
            if let Some(end) = find_head_end(&buffer) {
                break end;
            }
            let read = self.pull(&mut buffer)?;
            if read == 0 {
                return Err(if buffer.is_empty() {
                    ReadFailure::ClosedBeforeHead
                } else {
                    ReadFailure::Truncated
                });
            }
        };
        let head = core::str::from_utf8(buffer.get(..head_end).unwrap_or_default())
            .map_err(|_| ReadFailure::Malformed("the response head is not UTF-8".to_owned()))?
            .to_owned();
        let (status, headers) = parse_response_head(&head)
            .ok_or_else(|| ReadFailure::Malformed("the response head is not a status line and headers".to_owned()))?;
        let length = if carries_a_body(method, status) {
            headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.parse::<usize>().ok())
                .unwrap_or(0)
        } else {
            0
        };
        let mut body = buffer.split_off(head_end);
        while body.len() < length {
            if self.pull(&mut body)? == 0 {
                break;
            }
        }
        body.truncate(length);
        Ok(RawResponse { status, headers, body })
    }

    /// One read into `sink`, with the failure classified rather than stringified.
    fn pull(&mut self, sink: &mut Vec<u8>) -> Result<usize, ReadFailure> {
        let mut block = [0_u8; 4096];
        match self.stream.read(&mut block) {
            Ok(read) => {
                sink.extend_from_slice(block.get(..read).unwrap_or_default());
                Ok(read)
            }
            Err(error) => Err(match error.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => ReadFailure::TimedOut,
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => ReadFailure::Reset,
                _ => ReadFailure::Malformed(error.to_string()),
            }),
        }
    }

    /// What state the socket is in, asked of the socket.
    #[must_use]
    pub fn observe(&self) -> ConnectionState {
        observe_connection(&self.stream)
    }
}

/// Why a response did not arrive.
///
/// Four outcomes rather than one string, because `expect.kind` spells three of them differently:
/// a budget that ran out is a `hang`, a peer that hung up without answering is a
/// `connection_reset`, and a head that arrived malformed is neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadFailure {
    /// Nothing more arrived inside the budget.
    TimedOut,
    /// The peer ended the stream without writing anything.
    ClosedBeforeHead,
    /// The peer ended the stream part way through the head.
    Truncated,
    /// The peer reset the connection.
    Reset,
    /// Bytes arrived and were not a response head.
    Malformed(String),
}

impl core::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReadFailure::TimedOut => f.write_str("no response arrived inside the budget"),
            ReadFailure::ClosedBeforeHead => f.write_str("the connection ended before a response head arrived"),
            ReadFailure::Truncated => f.write_str("the connection ended part way through a response head"),
            ReadFailure::Reset => f.write_str("the peer reset the connection without answering"),
            ReadFailure::Malformed(detail) => write!(f, "the response head could not be read: {detail}"),
        }
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

    /// **Negative — the service's verdict is what closes the connection, and this is where a
    /// harness-side rule would show up instead.**
    ///
    /// Both bodies below are abandoned. The one the service said `MayKeepAlive` about is small
    /// enough to drain and the connection survives; the one it said `Close` about does not, and no
    /// amount of drainability rescues it. A policy that ignored the intent would answer the same
    /// for both — which is what "an undrained body closes" did, and the corpus refutes it:
    /// `c-object-0013` leaves eleven bytes unread and asserts `open`, `c-sig-0001` leaves
    /// twenty-four and asserts `closed`.
    #[test]
    fn the_intent_decides_and_the_remainder_only_narrows_it() {
        let small = BodyDisposition {
            declared: Some(11),
            consumed: 0,
            drained: false,
        };
        assert_eq!(
            honour_the_services_intent()(&small, ConnectionIntent::MayKeepAlive),
            ConnectionDisposition::Keep
        );
        assert_eq!(
            honour_the_services_intent()(&small, ConnectionIntent::Close),
            ConnectionDisposition::Close,
            "the service's close is not overridden by a body that could have been drained"
        );
    }

    /// Negative — `MayKeepAlive` over a remainder too large to read is still a close.
    ///
    /// Its own documentation says so: the variant promises the connection survives *if* the
    /// remainder is drained, and four megabytes is the transfer a refusal exists to avoid. A
    /// transport that read `MayKeepAlive` as "keep" would perform it.
    #[test]
    fn a_remainder_too_large_to_drain_closes_despite_a_permissive_intent() {
        let abandoned = BodyDisposition {
            declared: Some(4_000_000),
            consumed: 8192,
            drained: false,
        };
        assert!(abandoned.leaves_unread_bytes());
        assert!(abandoned.undrained_bytes() > MAX_LINGER_DRAIN_BYTES);
        assert_eq!(
            honour_the_services_intent()(&abandoned, ConnectionIntent::MayKeepAlive),
            ConnectionDisposition::Close
        );
        // A chunked body that never ended owes an unknowable amount, which is not a licence to
        // guess a small one.
        let unbounded = BodyDisposition {
            declared: None,
            consumed: 8192,
            drained: false,
        };
        assert_eq!(unbounded.undrained_bytes(), u64::MAX);
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
        assert_eq!(drained.undrained_bytes(), 0);
        assert_eq!(
            honour_the_services_intent()(&drained, ConnectionIntent::MayKeepAlive),
            ConnectionDisposition::Keep
        );
    }

    /// Negative — the control policy never closes, whatever it is handed. The header-versus-socket
    /// proof runs against this, and a version that closed under some condition would make the proof
    /// vacuous.
    #[test]
    fn the_control_policy_never_closes() {
        for drained in [true, false] {
            for intent in [ConnectionIntent::MayKeepAlive, ConnectionIntent::Close] {
                let disposition = BodyDisposition {
                    declared: Some(9),
                    consumed: 0,
                    drained,
                };
                assert_eq!(never_close()(&disposition, intent), ConnectionDisposition::Keep);
            }
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
        let listener = listener(Arc::new(|_body, _intent| ConnectionDisposition::Close), Announce::AlwaysClose);
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
        let listener = listener(Arc::new(|_body, _intent| ConnectionDisposition::Close), Announce::AlwaysKeepAlive);
        let (response, state) = exchange_then_observe(&listener);
        assert!(!announced_close(&response), "{:?}", response.headers);
        assert_eq!(
            state,
            ConnectionState::Closed,
            "the socket was closed, so the observation must be `closed` however the response was headed"
        );
    }

    /// **Positive — the lingering close, on a real socket, with the peer still writing.**
    ///
    /// This is the arrangement every early refusal produces and the one the byte-budgeted drain
    /// could not survive: the server has answered and decided to close, and a megabyte the service
    /// never asked for is on its way. RFC 9112 §9.6 is about precisely this — a full close over
    /// unread octets sends `RST`, and the reset can erase the response the peer has not finished
    /// reading. So there are two claims here and they are one fact each: the answer arrives intact,
    /// *and* the socket ends in a close rather than a reset.
    ///
    /// The megabyte is sixteen times the 64 KiB budget this drain used to stop at, which is what
    /// makes it a measurement of the drain rather than of the kernel's buffers.
    #[test]
    fn a_megabyte_arriving_after_the_refusal_ends_in_a_close_and_not_a_reset() {
        let listener = listener(Arc::new(|_body, _intent| ConnectionDisposition::Close), Announce::Matching);
        let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
        connection
            .write(b"GET /?x=1 HTTP/1.1\r\nhost: s3.example.com\r\ncontent-length: 1048576\r\n\r\n")
            .expect("the head is written");
        // Tolerated rather than expected: a server that abandoned the connection makes this write
        // fail, and that is a finding for the assertions below to report rather than a panic here.
        let written = connection.write_body(&vec![b'x'; 1024 * 1024]);
        let response = connection.read_response(Duration::from_secs(10));
        assert!(
            response.is_ok(),
            "the refusal must survive the close it announces: {:?} (body write: {written:?})",
            response.err()
        );
        assert_eq!(
            connection.observe(),
            ConnectionState::Closed,
            "a close over undrained octets is a reset, and the corpus spells the two differently"
        );
    }

    /// **Negative — the control for the test above, and the shape it is a fix for.**
    ///
    /// A server that answers and closes without lingering, over the same megabyte, is observed
    /// `reset`. Both halves of the pair are needed: an observer that had lost the ability to say
    /// `reset` at all would satisfy the positive above no matter what the drain did, which is the
    /// one-directional control this repository has been caught by before. It is also the exact
    /// behaviour `close_orderly` had while it stopped at [`MAX_LINGER_DRAIN_BYTES`], so this is the
    /// observation `c-object-0015` was making before the drain became time-bounded.
    #[test]
    fn a_server_that_closes_without_lingering_is_observed_reset() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let addr = listener.local_addr().expect("the kernel assigned one");
        let served = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            // Read the head and stop there. Everything after it stays in the receive buffer, which
            // is what turns the close below into a reset.
            let mut seen = Vec::new();
            let mut block = [0_u8; 4096];
            while find_head_end(&seen).is_none() {
                match stream.read(&mut block) {
                    Ok(0) | Err(_) => return,
                    Ok(read) => seen.extend_from_slice(block.get(..read).unwrap_or_default()),
                }
            }
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            let _ = stream.flush();
            // No half-close and no drain: the socket goes away with octets nobody read.
        });
        let mut connection = Connection::open(addr).expect("the listener accepts");
        connection
            .write(b"GET /?x=1 HTTP/1.1\r\nhost: s3.example.com\r\ncontent-length: 1048576\r\n\r\n")
            .expect("the head is written");
        let response = connection
            .read_response(Duration::from_secs(10))
            .expect("the refusal arrives before the reset");
        assert_eq!(response.status, 400);
        // The join first, so the socket on the other end is gone before a byte of this is written:
        // a megabyte sent to a fully closed peer is answered with `RST` by that peer's stack, and
        // waiting removes the only ordering this test would otherwise be at the mercy of.
        served.join().expect("the bare server thread joins");
        let _ = connection.write_body(&vec![b'x'; 1024 * 1024]);
        assert_eq!(
            connection.observe(),
            ConnectionState::Reset,
            "an abortive close must still be reported as one, or `closed` stops being a claim"
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

    // -- The framing rules --------------------------------------------------------------------

    /// Negative — a request that framed no body leaves nothing unread, however little was polled.
    ///
    /// The older `!drained` says the opposite, and this is the only place that says so: no case in
    /// the corpus separates the two today, because the codec drains what it is given. So this test
    /// is the whole of the guard, and it pins the shape that will separate them — a refusal that
    /// answers a body-less request without touching its body, which under `!drained` is a
    /// connection closed for carrying bytes nobody sent.
    #[test]
    fn a_body_that_framed_nothing_leaves_nothing_unread() {
        let empty = BodyDisposition {
            declared: Some(0),
            consumed: 0,
            drained: false,
        };
        assert!(!empty.leaves_unread_bytes());
        assert_eq!(
            honour_the_services_intent()(&empty, ConnectionIntent::MayKeepAlive),
            ConnectionDisposition::Keep
        );
    }

    /// Negative — a declared length that was only partly consumed leaves the rest, whatever the
    /// drained flag says. Arithmetic, not a flag: the flag is set by the reader and the bytes are
    /// owed by the peer.
    #[test]
    fn a_partly_consumed_declared_body_still_owes_bytes() {
        let short = BodyDisposition {
            declared: Some(24),
            consumed: 12,
            drained: false,
        };
        assert!(short.leaves_unread_bytes());
        // And chunked framing, where there is no arithmetic to do it with, falls back to the flag.
        let chunked = BodyDisposition {
            declared: None,
            consumed: 12,
            drained: false,
        };
        assert!(chunked.leaves_unread_bytes());
    }

    /// Negative — three answers have no body whatever their headers claim, and one does.
    ///
    /// Both ends of this connection ask the same function. They used to disagree by construction:
    /// the writer put `content-length` on a `304` that had none, and the reader then waited for a
    /// body that was never coming — a hang that reads in a report as a server which never replied.
    #[test]
    fn a_head_a_204_and_a_304_carry_no_body() {
        assert!(!carries_a_body("HEAD", 200));
        assert!(!carries_a_body("head", 200));
        assert!(!carries_a_body("GET", 204));
        assert!(!carries_a_body("GET", 304));
        assert!(!carries_a_body("GET", 100));
        assert!(carries_a_body("GET", 200));
        assert!(carries_a_body("PUT", 400));
    }

    // -- The rendezvous ------------------------------------------------------------------------

    /// Negative — a service that answered without ever asking releases the client with `Answered`,
    /// not with `More`.
    ///
    /// If this ever returns `More`, the client writes a frame the server never asked for and
    /// `body_bytes_sent_at_response = 0` becomes unsatisfiable — which is the same defect as the
    /// inversion, pointing the other way.
    #[test]
    fn an_answer_that_never_asked_for_the_body_stops_the_client() {
        let pacer = Pacer::new();
        pacer.server_answered();
        let mut satisfied = 0;
        assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(50)), Demand::Answered);
        assert_eq!(satisfied, 0, "nothing was released");
    }

    /// Negative — one demand releases one frame, not every frame.
    ///
    /// The counter is why. A flag would be cleared by the first waiter and then set again by the
    /// second poll, and a client that read it as "the server is hungry" would empty its whole chunk
    /// list into the socket on a single demand — which is exactly the unpaced write this module
    /// exists to avoid.
    #[test]
    fn one_demand_releases_one_frame() {
        let pacer = Pacer::new();
        let mut satisfied = 0;
        pacer.server_wants_body();
        assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(50)), Demand::More);
        assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(50)), Demand::Wedged);
        pacer.server_wants_body();
        assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(50)), Demand::More);
    }

    /// Negative — a silent peer is `Wedged` and never `More`.
    ///
    /// The safety net has to be distinguishable from a demand, or a wedged exchange would be
    /// reported as a byte count somebody measured.
    #[test]
    fn a_silent_peer_is_wedged_rather_than_hungry() {
        let pacer = Pacer::new();
        let mut satisfied = 0;
        assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(20)), Demand::Wedged);
        assert!(!pacer.answered());
    }

    /// Negative — a handover is complete when the server asks again, not only when the body ends.
    ///
    /// A truncating case never reaches the body's end: `c-mpu-0043` announces a megabyte, writes
    /// twenty-nine bytes and half-closes. Waiting for `ended` alone held that case for its whole
    /// twenty-second budget and failed it on the timing assertion — for the wrong reason, since
    /// what it is about is what the server does with a short body.
    #[test]
    fn a_handover_completes_when_the_server_asks_again() {
        let pacer = Pacer::new();
        let mut satisfied = 0;
        pacer.server_wants_body();
        assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(50)), Demand::More);
        pacer.server_wants_body();
        assert_eq!(
            pacer.await_handover(&mut satisfied, Duration::from_millis(50)),
            Demand::More,
            "a server asking for more has taken what it was given"
        );
    }

    /// Negative — a reset forgets an answer, so the next exchange on a reused connection does not
    /// start already released.
    #[test]
    fn a_reset_pacer_does_not_carry_the_previous_answer() {
        let pacer = Pacer::new();
        pacer.server_answered();
        assert!(pacer.answered());
        pacer.reset();
        assert!(!pacer.answered());
        let mut satisfied = 0;
        assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_millis(20)), Demand::Wedged);
    }

    // -- The pacing proof ----------------------------------------------------------------------
    //
    // The pair below is to pacing what the four-corner matrix above is to `connection_after`. One
    // client waits for the server; one does not. They send the same bytes to the same server and
    // get the same answer, and the number the corpus asserts on comes out differently. If the two
    // ever agree, pacing has stopped happening and `body_bytes_sent_at_response` has gone back to
    // measuring the kernel buffer.

    /// Writes a `PUT` head, then its body only when the server asks for it.
    fn paced_put(listener: &Listener, body: &[u8]) -> (u64, RawResponse) {
        let pacer = Arc::new(Pacer::new());
        listener.enqueue_pacer(&pacer);
        let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
        connection.write(&put_head(body.len())).expect("the head is written");
        let mut satisfied = 0;
        if pacer.await_demand(&mut satisfied, Duration::from_secs(5)) == Demand::More {
            connection.write_body(body).expect("the body is written");
        }
        let response = connection
            .read_response_classified("PUT", Duration::from_secs(10))
            .expect("a response arrives");
        (connection.body_written(), response)
    }

    /// Writes the same request without waiting for anything — the control.
    fn unpaced_put(listener: &Listener, body: &[u8]) -> (u64, RawResponse) {
        let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
        connection.write(&put_head(body.len())).expect("the head is written");
        connection.write_body(body).expect("the body is written");
        let response = connection
            .read_response_classified("PUT", Duration::from_secs(10))
            .expect("a response arrives");
        (connection.body_written(), response)
    }

    fn put_head(length: usize) -> Vec<u8> {
        format!("PUT /conf/k HTTP/1.1\r\nhost: s3.example.com\r\ncontent-length: {length}\r\n\r\n").into_bytes()
    }

    /// **Negative — the assertion pacing exists to keep falsifiable.**
    ///
    /// The request is anonymous, so it is refused before the service asks for a byte of the body. A
    /// paced client has therefore written *nothing* when the answer arrives, which is what
    /// `c-sig-0001` asserts. If this ever reports the whole body, the client has stopped waiting on
    /// the server and every early-refusal assertion in the corpus is being judged against the size
    /// of a socket buffer.
    #[test]
    fn a_refusal_that_never_read_the_body_finds_a_paced_client_had_sent_none_of_it() {
        let listener = listener(never_close(), Announce::Matching);
        let body = b"twenty-four bytes payload";
        let (written, response) = paced_put(&listener, body);
        assert!(response.status >= 400, "the request must be refused: {}", response.status);
        assert_eq!(written, 0, "the answer came before the body was asked for");
    }

    /// Positive — the other half of the pair, and the reason one test alone proves nothing.
    ///
    /// Same server, same bytes, same answer; the only difference is that this client did not wait.
    /// It has written the whole body by the time the identical refusal arrives, because on a
    /// loopback socket the payload is in the kernel before the server reads the head. A harness
    /// built this way reports "the client had sent all of it" for `c-sig-0001` and the case inverts
    /// while still reading as measured.
    #[test]
    fn an_unpaced_client_has_written_the_whole_body_before_the_same_refusal_arrives() {
        let listener = listener(never_close(), Announce::Matching);
        let body = b"twenty-four bytes payload";
        let (paced, refusal) = paced_put(&listener, body);
        let (unpaced, same_refusal) = unpaced_put(&listener, body);
        assert_eq!(refusal.status, same_refusal.status, "the server answered both the same way");
        assert_eq!(unpaced, body.len() as u64);
        assert_ne!(paced, unpaced, "pacing is what makes the two numbers different");
    }

    /// Positive — pacing is not a way of always reporting zero.
    ///
    /// A service that does read the body releases every frame, so a client that paced its way
    /// through the whole payload reports the whole payload. Without this, "wait for the server"
    /// could be implemented as "never write anything" and the negative above would still be green.
    #[test]
    fn a_service_that_reads_the_body_gets_all_of_it_from_a_paced_client() {
        let listener = listener(never_close(), Announce::Matching);
        // Two pacers, and they must stay two. `serve` raises `server_answered` on whichever pacer
        // it was handed, the moment the service returns — and this service does not read the body,
        // so it returns at once. Sharing one pacer put that answer in a race with the demand raised
        // below, and `await_demand` reports `Answered` ahead of `More` when both are set, so the
        // assertion turned on which thread the runner scheduled first. It failed about one run in
        // three on a loaded machine and never on an idle one. Nothing here needs the served pacer:
        // `Connection` does not hold one, and `write_body` only writes and counts.
        let serving = Arc::new(Pacer::new());
        listener.enqueue_pacer(&serving);
        let pacer = Arc::new(Pacer::new());
        let mut connection = Connection::open(listener.addr()).expect("the listener accepts");
        let body = b"hello world";
        connection.write(&put_head(body.len())).expect("written");
        // Stand in for a service that pulls the body: the rendezvous is between two threads and
        // this is the other one. What is under test is that a demand really releases the frame.
        let asking = Arc::clone(&pacer);
        std::thread::spawn(move || asking.server_wants_body());
        let mut satisfied = 0;
        assert_eq!(pacer.await_demand(&mut satisfied, Duration::from_secs(5)), Demand::More);
        connection.write_body(body).expect("written");
        assert_eq!(connection.body_written(), body.len() as u64);
        // The separation asserted rather than assumed, and in both directions: the served pacer is
        // the one that carries the answer, and the rendezvous under test never does. Waiting for
        // the answer first is what makes the pair deterministic — without the wait the second line
        // would pass merely by being early. Sharing one pacer fails here on any machine, which is
        // the point: the defect this replaced only failed on a loaded one.
        let mut served = 0;
        assert_eq!(serving.await_demand(&mut served, Duration::from_secs(5)), Demand::Answered);
        assert!(!pacer.answered());
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
