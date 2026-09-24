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

//! The connection target: the same service, reached by writing bytes on a socket.
//! Responsible for: turning one `[request]` block into wire bytes, writing them on a real TCP
//! connection after both peer demand and the case's not-before delay, reading the response back,
//! and asking the socket what state it was left in.
//! NOT responsible for: framing the server side or observing the socket (`crate::socket`), reading
//! or signing a request (`crate::inprocess`, whose reader and signer this module reuses rather than
//! copying), judging anything (`crate::expect`), or storing anything (`crate::fixture`).
//! Upstream: `crate::socket`, `crate::inprocess`. Downstream: `crate::cli`.
//!
//! # What this target can see that the in-process one cannot
//!
//! * **`connection_after`** is asked of the socket — [`crate::socket::observe_connection`] — and
//!   never of a `Connection:` header. See that module for why the two are different facts.
//! * **`request_progress`** is the client's own count of payload bytes it had released when the
//!   response existed. That number is only worth having because of the pacing below; written in one
//!   call it would be the size of the kernel buffer.
//! * **Control chunks** — `close`, `half_close`, `stall` — are carried out rather than refused, so
//!   the truncation and disconnection cases run instead of being skipped.
//! * **A raw head** goes on the wire as the case wrote it.
//! * **`connection.reuse = false`** is honoured by opening a new connection.
//!
//! # What it still cannot see, and says so
//!
//! * **`connection.pipeline = true`** writes both requests before either response is read, which
//!   this transport can now do — and it still refuses the flag, because the property the one case
//!   using it asserts is not reachable that way. This server reads one request off a connection,
//!   answers it, and only then reads the next; pipelining on the wire does not make two writes
//!   *race*, and neither this framing layer nor the fixture has a window between evaluating a
//!   condition and committing under it. Answering the case from a strictly ordered pair would make
//!   it fail for a reason it is not about, which is what it already did before it was skipped.
//! # Where the close rule comes from, now that it has one
//!
//! It used to be this harness's own, because `render.rs` dropped the flag and nothing the service
//! returned carried a close decision out. That is no longer true: `crates/gateway`'s `close.rs`
//! states the rule as a table and the verdict travels on the response as an extension. This target
//! runs [`crate::socket::honour_the_services_intent`], which reads that extension and adds one
//! thing the service cannot know — whether the remainder of the body actually turned up — because
//! `ConnectionIntent::MayKeepAlive` is a condition rather than a promise.
//!
//! Two facts about the *server*, then, and neither is a header: what it decided, and what it left
//! unread. Which is why `c-object-0013` and `c-object-0015` can disagree here — eleven bytes
//! refused on the head against megabytes refused for their size — and why moving either verdict
//! means moving a row in `close.rs` rather than a line in the harness.
//! * **Streaming signature modes** (`sigv4_streaming*`) still need aws-chunked framing on the wire,
//!   which nothing here writes. `crate::inprocess::sign_request` refuses them by name.
//! * **HTTP/2** exists only as an authored `request.h2_frames` script against the production Hyper
//!   driver (`h2`); a structured request with `http_version = "h2"` is still refused.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::inprocess::{ChunkStep, HOST, InProcess, Wire, clock_of, sign_request};
use crate::interpolate::Captures;
use crate::observation::{
    ConnectionState, Observation, Outcome, StreamTermination, decode_event_stream, has_event_stream_content_type,
    late_error_offset,
};
#[cfg(feature = "production-transports")]
use crate::production::{ProductionDriver, ProductionServer};
#[cfg(test)]
use crate::socket::{Announce, honour_the_services_intent};
use crate::socket::{Connection, Demand, Listener, Pacer, ReadFailure, parse_head};
use crate::sut::{ExchangePlan, Sut, SutError};
use crate::value::Value;
mod bind;
mod exchange;
mod external;
mod external_endpoint;
mod external_fixture;
mod external_pacing;
mod external_tls;
mod h2;
mod server;
#[cfg(test)]
use exchange::read_concurrent_connection;
use external_endpoint::ExternalEndpoint;
/// How long the client waits on a silent server before calling the exchange wedged.
///
/// Used only when the case declares no `timeout_ms`. This is a safety net and never the path a
/// passing case takes: the rendezvous in [`Pacer`] is released by the server, not by this timer,
/// and when the timer does fire the exchange is reported as an environment failure rather than as a
/// byte count nobody measured.
const DEFAULT_BUDGET: Duration = Duration::from_secs(15);
/// The ceiling on that budget, whatever a case declares.
///
/// `c-mpu-0040` declares two minutes. A run that really waited two minutes for one wedged exchange
/// would be a run nobody executes, and the case is red on its own terms long before then.
const MAX_BUDGET: Duration = Duration::from_secs(60);
/// A service behind a loopback listener, plus the fixtures the current case established.
pub struct Conn {
    /// The in-process target, used for everything that is not the wire: the fixture it prepares,
    /// the service it assembles, the `[request]` block it reads, and the signature it computes.
    /// Reused rather than copied, so the two transports cannot disagree about what a case says.
    inner: InProcess,
    external: Option<ExternalEndpoint>,
    external_fixtures: external_fixture::ExternalFixtures,
    listener: Option<Listener>,
    connection: Option<Connection>,
    #[cfg(feature = "production-transports")]
    production: Option<ProductionServer>,
    #[cfg(feature = "production-transports")]
    driver: Option<ProductionDriver>,
    pacer: Arc<Pacer>,
}
impl Conn {
    /// Builds a target rooted at a corpus directory.
    #[must_use]
    pub fn new(root: std::path::PathBuf) -> Conn {
        Conn {
            inner: InProcess::new(root),
            external: None,
            external_fixtures: external_fixture::ExternalFixtures::disabled(),
            listener: None,
            connection: None,
            #[cfg(feature = "production-transports")]
            production: None,
            #[cfg(feature = "production-transports")]
            driver: None,
            pacer: Arc::new(Pacer::new()),
        }
    }
    /// Builds a target backed by one real production connection driver.
    #[cfg(feature = "production-transports")]
    #[must_use]
    pub fn production(root: std::path::PathBuf, driver: ProductionDriver) -> Conn {
        Conn {
            inner: InProcess::new(root),
            external: None,
            external_fixtures: external_fixture::ExternalFixtures::disabled(),
            listener: None,
            connection: None,
            production: None,
            driver: Some(driver),
            pacer: Arc::new(Pacer::new()),
        }
    }
}
/// Reads `[connection]`, refusing every instruction this transport cannot carry out.
///
/// `reuse` is the one that is honoured rather than refused, in both directions, and it is honoured
/// by actually opening a socket or actually keeping one.
fn read_connection(connection: Option<&Value>) -> Result<bool, SutError> {
    let empty = Value::empty_table();
    let connection = connection.unwrap_or(&empty);
    if connection.read("connection.pipeline").and_then(Value::as_bool) == Some(true) {
        return Err(SutError::Environment(
            "`connection.pipeline = true` asks for the next request to be written before the \
             previous response is read. This transport can do that — but the case that declares it \
             asserts that two conditional creates *race*, and writing both requests onto one \
             connection does not make them race: this server reads one request off a connection, \
             answers it, and only then reads the next, and the fixture evaluates a condition and \
             commits under it inside one lock. The loser therefore meets an object that is simply \
             there, and `412` is the honest answer to a question the case did not ask. Reaching the \
             race needs a server that dispatches pipelined requests concurrently and a store with a \
             window between the check and the commit; neither is approximated here"
                .to_owned(),
        ));
    }
    if connection.read("connection.tls").is_some() {
        return Err(SutError::Environment(
            "`[connection.tls]` needs a TLS implementation; this transport writes cleartext bytes \
             on a TCP socket and negotiates nothing"
                .to_owned(),
        ));
    }
    if connection.read("connection.read_window_bytes").is_some() {
        return Err(SutError::Environment(
            "`connection.read_window_bytes` induces backpressure by leaving response bytes unread; \
             this client reads a response to its end before it judges anything, and a window it \
             declared but did not apply would report a server that ignored flow control as one that \
             honoured it"
                .to_owned(),
        ));
    }
    if connection.read("connection.idle_timeout_ms").is_some() {
        return Err(SutError::Environment(
            "`connection.idle_timeout_ms` times out an idle connection; this server holds a \
             connection open until its own generous read timeout and has no per-case idle bound"
                .to_owned(),
        ));
    }
    Ok(connection.read("connection.reuse").and_then(Value::as_bool).unwrap_or(true))
}

/// The head bytes to write, and the payload length the framing declares.
struct Head {
    bytes: Vec<u8>,
    declared_length: u64,
}

impl Conn {
    /// Builds the request head, signed, in the form the case asked for.
    fn head(&self, wire: &Wire, request_time: &crate::time::Instant) -> Result<Head, SutError> {
        match &wire.raw_head {
            Some(raw) => self.raw_head(wire, raw, request_time),
            None => self.structured_head(wire, request_time),
        }
    }

    /// A head assembled from `method`, `target` and the header table.
    fn structured_head(&self, wire: &Wire, request_time: &crate::time::Instant) -> Result<Head, SutError> {
        let mut headers = wire.headers.clone();
        if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
            let host = self.external.as_ref().map_or(HOST, ExternalEndpoint::authority);
            headers.push(("host".to_owned(), host.to_owned()));
        }
        if !wire.body.is_empty() && !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
            headers.push(("content-length".to_owned(), wire.body.len().to_string()));
        }
        // The framing is the header's, not the payload's: a case that announces five gigabytes and
        // writes ten bytes is announcing five gigabytes, and both the signature and the server's
        // body reader have to agree with what went on the wire.
        let declared_length = declared_content_length(&headers).unwrap_or(wire.body.len() as u64);
        let (headers, target) = match &wire.sign {
            None => (headers, wire.target.clone()),
            Some(sign) => sign_request(sign, wire, &headers, request_time, self.inner.limits(), declared_length)?,
        };
        let mut bytes = format!("{} {} HTTP/1.1\r\n", wire.method, target).into_bytes();
        for (name, value) in &headers {
            bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        Ok(Head { bytes, declared_length })
    }

    /// A head the case wrote out byte for byte.
    ///
    /// The bytes are preserved and the signature is **appended**, never merged in. A raw head is an
    /// escape hatch for framing — `c-mpu-0045`'s whole subject is the `content-length` that is not
    /// there — and rewriting it to carry a signature would edit the very thing under test. What is
    /// added is what a real client adds and nothing else: the headers the signer minted that the
    /// head does not already carry.
    fn raw_head(&self, wire: &Wire, raw: &[u8], request_time: &crate::time::Instant) -> Result<Head, SutError> {
        let Some(sign) = &wire.sign else {
            return Ok(Head {
                bytes: raw.to_vec(),
                declared_length: parse_head(raw).map_or(0, |head| declared_content_length(&head.headers).unwrap_or(0)),
            });
        };
        let parsed = parse_head(raw).ok_or_else(|| {
            SutError::Environment(
                "`request.raw_head_utf8` declares a signature and this head cannot be parsed well \
                 enough to compute one; a head that malformed has to be sent unsigned, which is a \
                 different case"
                    .to_owned(),
            )
        })?;
        let declared_length = declared_content_length(&parsed.headers).unwrap_or(0);
        // Signing needs a `Wire`, and the one the case wrote has no method or target of its own —
        // the raw head is where they live. Rebuilt from the parse so the signer sees what the wire
        // will carry.
        let signable = Wire {
            method: parsed.method.clone(),
            target: parsed.target.clone(),
            headers: parsed.headers.clone(),
            raw_head: None,
            h2_frames: Vec::new(),
            http_version: None,
            body: wire.body.clone(),
            frames: Vec::new(),
            steps: Vec::new(),
            sign: wire.sign.clone(),
        };
        let (signed, target) =
            sign_request(sign, &signable, &parsed.headers, request_time, self.inner.limits(), declared_length)?;
        if target != parsed.target {
            return Err(SutError::Environment(
                "`sign.tamper` rewrote the request target of a raw head. Sending it would mean \
                 re-spelling the request line the case pinned, and sending the original would mean \
                 measuring a request nobody meant to send"
                    .to_owned(),
            ));
        }
        // Everything up to and including the last CRLF that ends the final header line; the blank
        // line is re-added after the appended headers so the head stays one message.
        let body_start = raw.len().saturating_sub(2);
        let mut bytes = raw.get(..body_start).unwrap_or_default().to_vec();
        for (name, value) in &signed {
            if parsed.headers.iter().any(|(have, _)| have.eq_ignore_ascii_case(name)) {
                continue;
            }
            bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        bytes.extend_from_slice(b"\r\n");
        Ok(Head { bytes, declared_length })
    }
}

/// The length the head declares, when it declares one.
fn declared_content_length(headers: &[(String, String)]) -> Option<u64> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<u64>().ok())
}

/// How the body writing ended.
#[derive(Debug)]
struct BodyProgress {
    /// Payload bytes released before a response observer fired.
    sent_at_response: u64,
    /// Whether that byte count came from peer demand or response-byte observation.
    measured_at_response: bool,
    /// Whether everything the framing declared was written.
    fully_sent: bool,
    /// Whether this client tore the connection down as part of the body.
    torn_down: bool,
    /// What the transport had to produce some way other than by measuring it.
    notes: Vec<String>,
}

impl Sut for Conn {
    fn describe(&self) -> String {
        if let Some(endpoint) = &self.external {
            return endpoint.description();
        }
        #[cfg(feature = "production-transports")]
        match self.driver {
            Some(ProductionDriver::Hyper) => "rustfs-gateway production Hyper driver over loopback TCP".to_owned(),
            Some(ProductionDriver::SelfHeld) => {
                "rustfs-gateway production self-held HTTP/1.1 driver over loopback TCP".to_owned()
            }
            None => "rustfs-gateway test socket harness over loopback TCP".to_owned(),
        }
        #[cfg(not(feature = "production-transports"))]
        return "rustfs-gateway test socket harness over loopback TCP".to_owned();
    }
    fn prepare(&mut self, case_id: &str, setup: Option<&Value>) -> Result<Captures, SutError> {
        if self.external.is_some() {
            return self.prepare_external(case_id, setup);
        }
        // Dropped before the fixture is rebuilt: the listener holds a service assembled at the
        // previous case's clock, and a case that ran against the wrong instant is a case that
        // measured something nobody described.
        self.connection = None;
        self.listener = None;
        #[cfg(feature = "production-transports")]
        {
            self.production = None;
        }
        self.inner.prepare(case_id, setup)
    }

    fn exchange(&mut self, plan: &ExchangePlan<'_>) -> Result<Observation, SutError> {
        if self.external.is_some() {
            return self.exchange_external(plan);
        }
        let (fixed, request_time, skew_ms) = clock_of(plan.clock)?;
        let reuse = read_connection(plan.connection)?;
        self.inner.set_fixture_now(fixed.unix_seconds);

        let wire = self.inner.read_wire(&plan.request)?;
        self.inner.record_exchange();
        if !wire.h2_frames.is_empty() {
            return self.exchange_h2(plan, &wire, fixed.unix_seconds, skew_ms, reuse);
        }
        if wire.http_version.as_deref() == Some("h2") {
            return Err(SutError::Environment(
                "`request.http_version = \"h2\"` needs a real HTTP/2 framing layer".to_owned(),
            ));
        }
        let head = self.head(&wire, &request_time)?;
        let budget = budget_of(plan.timeout_ms);

        let addr = self.addr(fixed.unix_seconds, skew_ms, plan.profile)?;
        // Replace a connection already observed closed rather than hiding that fact behind a later write error.
        // The probe is an observation window, so what it costs is the harness's, not the target's.
        let mut reuse_probe = Duration::ZERO;
        let fresh = !reuse
            || self
                .connection
                .as_ref()
                .is_none_or(|connection| charged_to_harness(&mut reuse_probe, || connection.observe()) != ConnectionState::Open);
        if fresh {
            self.connection = None;
            let pacer = Arc::new(Pacer::new());
            #[cfg(feature = "production-transports")]
            if let Some(production) = &self.production {
                self.connection = Some(bind::connect(production, addr, &pacer)?);
            } else {
                let listener = self.listener(fixed.unix_seconds, skew_ms, plan.profile)?;
                self.connection = Some(bind::connect(listener, addr, &pacer)?);
            }
            #[cfg(not(feature = "production-transports"))]
            {
                let listener = self.listener(fixed.unix_seconds, skew_ms, plan.profile)?;
                self.connection = Some(bind::connect(listener, addr, &pacer)?);
            }
            self.pacer = pacer;
        } else {
            // Safe only here: the server cannot have signalled anything about a request whose first
            // byte has not been written yet.
            self.pacer.reset();
        }
        let pacer = Arc::clone(&self.pacer);
        #[cfg(feature = "production-transports")]
        if !fresh && let Some(production) = &self.production {
            production.enqueue_pacer(&pacer);
        }
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| SutError::Environment("no connection was opened".to_owned()))?;
        let mut result = exchange::execute_socket_exchange(connection, &pacer, &wire, &head, budget)?;
        if result.torn_down {
            self.connection = None;
        }
        result.observation.harness_wait_ms = result
            .observation
            .harness_wait_ms
            .saturating_add(u64::try_from(reuse_probe.as_millis()).unwrap_or(u64::MAX));
        Ok(result.observation)
    }

    fn exchange_concurrent(&mut self, plans: &[ExchangePlan<'_>]) -> Result<Vec<Observation>, SutError> {
        if self.external.is_some() {
            return Err(SutError::Environment(
                "concurrent external endpoint exchanges are not implemented; refusing to serialize a declared race".to_owned(),
            ));
        }
        self.exchange_concurrent_sockets(plans)
    }

    fn finish(&mut self, case_id: &str) -> Result<(), SutError> {
        self.finish_case(case_id)
    }
}

struct DispatchedExchange {
    progress: BodyProgress,
    started: Instant,
    deadline: Instant,
    /// What the harness itself spent waiting while the request went out: authored pacing,
    /// stalls, and teardown delays. Measured around each wait, so scheduler overshoot lands here
    /// rather than on the target.
    harness_wait: Duration,
}

/// Runs `wait` and adds its wall-clock cost to the harness's own account.
fn charged_to_harness<T>(harness_wait: &mut Duration, wait: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let result = wait();
    *harness_wait += started.elapsed();
    result
}

/// One exchange's clock: the deadline the target is held to, and what the harness has spent of
/// the wall time on its own waiting, which the runner subtracts before judging that deadline.
struct ExchangeClock {
    deadline: Instant,
    harness_wait: Duration,
}

impl ExchangeClock {
    fn until(deadline: Instant) -> Self {
        Self {
            deadline,
            harness_wait: Duration::ZERO,
        }
    }

    fn remaining(&self) -> Result<Duration, SutError> {
        remaining(self.deadline)
    }

    /// An authored wait spends harness time, not the target's remaining deadline.
    fn paced<T>(&mut self, wait: impl FnOnce() -> T) -> T {
        let before = self.harness_wait;
        let result = self.charged(wait);
        self.deadline += self.harness_wait - before;
        result
    }

    /// Runs `wait` on the harness's account.
    fn charged<T>(&mut self, wait: impl FnOnce() -> T) -> T {
        charged_to_harness(&mut self.harness_wait, wait)
    }
}

fn dispatch_socket_exchange(
    connection: &mut Connection,
    pacer: &Arc<Pacer>,
    wire: &Wire,
    head: &Head,
    budget: Duration,
) -> Result<DispatchedExchange, SutError> {
    connection.start_exchange();
    let started = Instant::now();
    let deadline = started + budget;
    connection.write(&head.bytes)?;
    let mut clock = ExchangeClock::until(deadline);
    let progress = write_body(connection, pacer, wire, head.declared_length, &mut clock)?;
    Ok(DispatchedExchange {
        progress,
        started,
        deadline,
        harness_wait: clock.harness_wait,
    })
}

fn observe_socket_exchange(
    connection: &mut Connection,
    wire: &Wire,
    head: &Head,
    dispatched: DispatchedExchange,
) -> exchange::SocketExchangeResult {
    let DispatchedExchange {
        progress,
        mut harness_wait,
        started,
        deadline,
    } = dispatched;
    let method = request_method(wire, head);
    let read = match remaining(deadline) {
        Ok(remaining) => connection.read_response_classified(&method, remaining),
        Err(_) => Err(ReadFailure::TimedOut),
    };
    let read_failure = read.as_ref().err().cloned();
    let ttfb_ms = elapsed_ms(started);
    let torn_down = progress.torn_down;
    let observation = match read {
        Ok(response) => {
            let elapsed_ms = elapsed_ms(started);
            let (outcome, termination, before_error, events, event_note) =
                classify_body(response.status, &response.headers, &response.body);
            let mut notes = progress.notes;
            if let Some(note) = event_note {
                notes.push(note);
            }
            Observation {
                outcome,
                stream_termination: termination,
                status: Some(response.status),
                http_version: Some("http/1.1".to_owned()),
                h2_control_frames: None,
                socket_read_after: None,
                headers: response.headers,
                trailers: Vec::new(),
                body: response.body,
                body_bytes_before_error: before_error,
                request_body_bytes_sent_at_response: progress.measured_at_response.then_some(progress.sent_at_response),
                request_body_fully_sent: Some(progress.fully_sent),
                ttfb_ms: Some(ttfb_ms),
                elapsed_ms,
                harness_wait_ms: 0,
                deadline_expiry: None,
                connection_after: None,
                events,
                notes,
            }
        }
        Err(ReadFailure::TimedOut) => Observation {
            outcome: Outcome::Hang,
            stream_termination: None,
            status: None,
            http_version: None,
            h2_control_frames: None,
            socket_read_after: None,
            headers: Vec::new(),
            trailers: Vec::new(),
            body: Vec::new(),
            body_bytes_before_error: None,
            request_body_bytes_sent_at_response: progress.measured_at_response.then_some(progress.sent_at_response),
            request_body_fully_sent: Some(progress.fully_sent),
            ttfb_ms: None,
            elapsed_ms: elapsed_ms(started),
            harness_wait_ms: 0,
            deadline_expiry: None,
            connection_after: None,
            events: Vec::new(),
            notes: progress.notes,
        },
        Err(failure) => Observation {
            outcome: Outcome::ConnectionReset,
            stream_termination: None,
            status: None,
            http_version: None,
            h2_control_frames: None,
            socket_read_after: None,
            headers: Vec::new(),
            trailers: Vec::new(),
            body: Vec::new(),
            body_bytes_before_error: None,
            request_body_bytes_sent_at_response: progress.measured_at_response.then_some(progress.sent_at_response),
            request_body_fully_sent: Some(progress.fully_sent),
            ttfb_ms: None,
            elapsed_ms: elapsed_ms(started),
            harness_wait_ms: 0,
            deadline_expiry: None,
            connection_after: None,
            events: Vec::new(),
            notes: {
                let mut notes = progress.notes;
                if !torn_down {
                    notes.push(format!("the response could not be read: {failure}"));
                }
                notes
            },
        },
    };
    let (connection_after, pending_input) = charged_to_harness(&mut harness_wait, || connection.observe_pending());
    exchange::SocketExchangeResult {
        observation: Observation {
            h2_control_frames: None,
            socket_read_after: None,
            connection_after: Some(connection_after),
            harness_wait_ms: u64::try_from(harness_wait.as_millis()).unwrap_or(u64::MAX),
            deadline_expiry: None,
            ..observation
        },
        torn_down,
        read_failure,
        pending_input,
    }
}

/// The method that went on the wire, which decides whether the answer has a body.
///
/// Read back off the head bytes for a raw head rather than off the case, because a raw head is
/// exactly the shape whose request line the case did not spell as `method`.
fn request_method(wire: &Wire, head: &Head) -> String {
    if wire.raw_head.is_none() {
        return wire.method.clone();
    }
    parse_head(&head.bytes).map_or_else(|| wire.method.clone(), |parsed| parsed.method)
}

/// What a complete response's body makes of it: outcome, termination, error offset, events, and a
/// note when the body could not be decoded.
type Classified = (
    Outcome,
    Option<StreamTermination>,
    Option<u64>,
    Vec<crate::observation::ObservedEvent>,
    Option<String>,
);

/// Classifies a complete response body, for the HTTP/1.1 reader here and the HTTP/2 reader in `h2`:
/// an event stream is decoded, and an `<Error>` document inside a success status is a stream error.
fn classify_body(status: u16, headers: &[(String, String)], body: &[u8]) -> Classified {
    if has_event_stream_content_type(headers) {
        return match decode_event_stream(body) {
            Ok(events) => (Outcome::EventStream, None, None, events, None),
            Err(error) => (
                Outcome::StreamError,
                Some(StreamTermination::MalformedEventStream),
                None,
                Vec::new(),
                Some(format!("the event stream could not be decoded: {error}")),
            ),
        };
    }
    match late_error_offset(status, body) {
        None => (Outcome::Response, None, None, Vec::new(), None),
        Some(offset) => (
            Outcome::StreamError,
            Some(StreamTermination::ErrorDocument),
            Some(offset),
            Vec::new(),
            None,
        ),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn remaining(deadline: Instant) -> Result<Duration, SutError> {
    deadline.checked_duration_since(Instant::now()).ok_or_else(|| {
        SutError::Environment("the exchange exhausted its declared timeout before the response could be observed".to_owned())
    })
}

/// The wait a wedged exchange is cut off at, which is never the path a passing case takes.
fn budget_of(timeout_ms: Option<i64>) -> Duration {
    timeout_ms
        .filter(|value| *value > 0)
        .map_or(DEFAULT_BUDGET, |value| Duration::from_millis(value.unsigned_abs()))
        .min(MAX_BUDGET)
}

/// Writes the body after peer demand and each authored not-before deadline.
///
/// The loop is the whole argument of this transport. Before every frame it waits for the server to
/// ask for body bytes it does not have; if the response exists instead, it stops writing. A data
/// frame also waits until its independently authored `delay_ms` has elapsed. Fixing that deadline
/// when the frame becomes current makes the release time the later of peer demand and not-before,
/// rather than incorrectly adding one wait to the other.
fn write_body(
    connection: &mut Connection,
    pacer: &Arc<Pacer>,
    wire: &Wire,
    declared_length: u64,
    clock: &mut ExchangeClock,
) -> Result<BodyProgress, SutError> {
    let mut satisfied = 0_u64;
    let mut notes = Vec::new();
    let mut sent_at_response = None;
    for (index, step) in wire.steps.iter().enumerate() {
        match step {
            ChunkStep::Data(bytes, delay_ms) => {
                let not_before = Instant::now()
                    .checked_add(Duration::from_millis(*delay_ms))
                    .filter(|not_before| *not_before <= clock.deadline)
                    .ok_or_else(|| {
                        SutError::Environment(format!(
                            "data chunk {index} declares a {delay_ms}ms delay beyond the remaining exchange timeout"
                        ))
                    })?;
                let wait = clock.remaining()?;
                match pacer.await_demand(&mut satisfied, wait) {
                    Demand::More => {}
                    Demand::Answered => {
                        // The measurement point. Everything after this is a client finishing a
                        // request whose answer it already has, and none of it can change what had
                        // been written when the answer existed.
                        sent_at_response = Some(connection.body_written());
                        catch_up(connection, wire, index);
                        break;
                    }
                    Demand::Wedged => {
                        return Err(SutError::Environment(format!(
                            "the server neither asked for the next body frame nor answered within \
                             {}ms. That is a wedged exchange, not a byte count: reporting the \
                             frames this client happened to have written would be reporting the \
                             timeout",
                            wait.as_millis()
                        )));
                    }
                }
                if clock.charged(|| pacer.await_delay_or_answered(not_before.saturating_duration_since(Instant::now()))) {
                    sent_at_response = Some(connection.body_written());
                    catch_up(connection, wire, index);
                    break;
                }
                connection.write_body(bytes)?;
            }
            ChunkStep::Control {
                action,
                delay_ms,
                duration_ms,
            } => {
                if let Some(note) = control(connection, pacer, &mut satisfied, action, *delay_ms, *duration_ms, clock)? {
                    notes.push(note);
                }
                if connection.torn_down() {
                    break;
                }
            }
        }
    }
    let sent_at_response = sent_at_response.unwrap_or_else(|| connection.body_written());
    Ok(BodyProgress {
        sent_at_response,
        measured_at_response: true,
        // What the *framing* declared, not what the chunk list happened to contain. A part that
        // announces a megabyte and writes twenty-nine bytes before half-closing has not finished
        // sending its body, and `c-chunked-0001` and `c-object-0013` both assert exactly that.
        fully_sent: sent_at_response >= declared_length,
        torn_down: connection.torn_down(),
        notes,
    })
}

mod control_chunks;
#[cfg(test)]
mod tests;

use control_chunks::{catch_up, control};
