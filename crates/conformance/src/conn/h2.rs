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

//! Authored HTTP/2 frames, written on a real socket to the production Hyper driver.
//! Responsible for: deciding whether one exchange can run as an authored frame script, writing the
//! 24-octet client preface magic and then every authored frame envelope exactly as declared — type,
//! flags, stream id, payload octets, and not-before delay, in declaration order — and reading the
//! peer's frames back into an observation of the response on the script's stream.
//! NOT responsible for: building a request. The request header block is the HPACK octets the case
//! authored; nothing here encodes one, and no HTTP client library touches the wire. Nor does it
//! acknowledge SETTINGS, answer PING, or replenish flow-control windows: the harness writes nothing
//! the case did not author except the preface magic, which the schema has no way to spell.
//! Upstream: `super::Conn::exchange`. Downstream: `crate::socket::Connection`, `hpack`.
//!
//! # What is executed, and what is refused by name
//!
//! * SETTINGS, HEADERS, CONTINUATION, DATA, WINDOW_UPDATE, RST_STREAM, GOAWAY, PRIORITY, PING and
//!   `raw` frames are written; `control` compiles the last five. What the peer does after them is
//!   observed like any other reaction: a status, received controls, and measured termination. A
//!   client reset of the selected stream ends the observation only through the reset barrier.
//! * The selected stream is the one the last authored HEADERS frame names; other opened streams are
//!   read (`receive`) but not observed. Received RST_STREAM frames are recorded in arrival order;
//!   resetting the selected stream ends its observation without implying a TCP reset. GOAWAY is
//!   recorded without ending an in-flight stream or inventing receive-side termination.
//! * The production Hyper driver runs scripts in cleartext with prior knowledge; external endpoints
//!   run them in cleartext too, or over TLS once the peer selected ALPN `h2`. The self-held driver,
//!   the test harness, and in-harness `[connection.tls]` refuse the script.

mod control;
mod duplex;
mod flow;
mod hpack;
mod huffman;
mod receive;
#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::{Conn, ExchangeClock, budget_of, classify_body, elapsed_ms};
use crate::inprocess::Wire;
use crate::inprocess::h2_frames::H2Frame;
use crate::observation::{ConnectionState, Observation, ObservedH2ControlFrame, Outcome, SocketReadState, StreamTermination};
#[cfg(feature = "production-transports")]
use crate::production::ProductionDriver;
use crate::socket::{Connection, ReadFailure};
use crate::sut::{ExchangePlan, SutError};
use receive::PeerFrame;
use receive::{FrameReader, Receiver, Response};

/// The client connection preface magic (RFC 9113 section 3.4). The SETTINGS frame that completes
/// the preface is authored like every other frame.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;
/// The largest payload a 24-bit frame length can declare.
const MAX_PAYLOAD: usize = (1 << 24) - 1;
/// The largest 31-bit stream identifier.
const MAX_STREAM_ID: u32 = 0x7fff_ffff;
/// SETTINGS_HEADER_TABLE_SIZE before any SETTINGS (RFC 9113 section 6.5.2).
const DEFAULT_HEADER_TABLE_SIZE: usize = 4_096;
/// Initial connection and stream credit before SETTINGS or WINDOW_UPDATE (RFC 9113 section 6.9.2).
const INITIAL_CONNECTION_WINDOW: usize = 65_535;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

/// One frame envelope, fixed from its declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Envelope {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
    delay_ms: u64,
}

impl Envelope {
    /// The 9-octet frame header and the payload (RFC 9113 section 4.1), reserved bit zero.
    fn bytes(&self) -> Vec<u8> {
        let length = u32::try_from(self.payload.len()).unwrap_or(u32::MAX).to_be_bytes();
        let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        bytes.extend_from_slice(length.get(1..).unwrap_or_default());
        bytes.push(self.frame_type);
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.stream_id.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

/// An authored script this writer can carry out.
#[derive(Debug)]
struct Script {
    envelopes: Vec<Envelope>,
    /// The stream the last authored HEADERS frame opens; the response on it is the observation.
    stream_id: u32,
    /// Every stream an authored HEADERS frame names, the observed one included. The peer's frames
    /// on the others are read — header blocks decompressed, DATA charged to connection credit —
    /// and not observed.
    opened: Vec<u32>,
    /// The dynamic-table ceiling this client advertised, which bounds the peer's HPACK encoder.
    header_table_size: usize,
    /// The opaque octets of the last PING authored after a client RST_STREAM on the selected
    /// stream. Its acknowledgement proves the peer processed the reset, and ends the observation.
    reset_barrier: Option<Vec<u8>>,
    /// Whether the script authors a typed PING, the version-5 construct under which received
    /// acknowledgements are recorded. A version-4 list of controls never contains one.
    observes_pings: bool,
}

fn refused(reason: String) -> SutError {
    SutError::Environment(reason)
}

/// Validates an authored script and fixes every envelope, refusing by name what is not executed.
fn compile(wire: &Wire) -> Result<Script, SutError> {
    if wire.http_version.as_deref() != Some("h2") {
        return Err(refused(
            "`request.h2_frames` needs `request.http_version = \"h2\"`; running authored frames \
             under any other declaration would execute a request the case did not describe"
                .to_owned(),
        ));
    }
    for (field, present) in [
        ("raw_head_utf8/raw_head_hex", wire.raw_head.is_some()),
        ("headers/raw_headers/host", !wire.headers.is_empty()),
        ("body/chunks", !wire.steps.is_empty()),
        ("sign", wire.sign.is_some()),
    ] {
        if present {
            return Err(refused(format!(
                "`request.{field}` cannot accompany `request.h2_frames`: the authored HEADERS payload \
                 is the whole header block and authored DATA frames are the whole body, so the field \
                 would be dropped rather than sent"
            )));
        }
    }
    let mut envelopes = Vec::with_capacity(wire.h2_frames.len());
    let mut stream_id = None;
    let mut opened = Vec::new();
    let mut header_table_size = DEFAULT_HEADER_TABLE_SIZE;
    for (index, frame) in wire.h2_frames.iter().enumerate() {
        let envelope = envelope(index, frame)?;
        // The last stream a HEADERS frame opens is the observed one; the others are read. Trailers
        // on an earlier stream do not open it again, so they do not move the observation.
        if envelope.frame_type == HEADERS && !opened.contains(&envelope.stream_id) {
            opened.push(envelope.stream_id);
            stream_id = Some(envelope.stream_id);
        }
        if envelope.frame_type == SETTINGS
            && envelope.flags & ACK == 0
            && let Some(size) = advertised_header_table_size(&envelope.payload)
        {
            // Permissive on purpose: a peer may use the larger table before it has seen the ACK.
            header_table_size = header_table_size.max(size);
        }
        envelopes.push(envelope);
    }
    if !envelopes.iter().any(|envelope| envelope.frame_type == HEADERS) {
        return Err(refused(
            "`request.h2_frames` declares no HEADERS frame, so no stream carries a response to observe".to_owned(),
        ));
    }
    let stream_id = stream_id.unwrap_or_default();
    let reset_barrier = control::reset_barrier(&wire.h2_frames, &envelopes, stream_id)?;
    let observes_pings = wire.h2_frames.iter().any(|frame| frame.kind == "ping");
    Ok(Script {
        envelopes,
        stream_id,
        header_table_size,
        reset_barrier,
        observes_pings,
        opened,
    })
}

fn envelope(index: usize, frame: &H2Frame) -> Result<Envelope, SutError> {
    if control::owns(&frame.kind) {
        return control::envelope(index, frame);
    }
    let (frame_type, known): (u8, &[(&str, u8)]) = match frame.kind.as_str() {
        "settings" => (SETTINGS, &[("ack", ACK)]),
        "window_update" => (WINDOW_UPDATE, &[]),
        "headers" => (
            HEADERS,
            &[
                ("end_stream", END_STREAM),
                ("end_headers", END_HEADERS),
                ("padded", PADDED),
                ("priority", PRIORITY_FLAG),
            ],
        ),
        "continuation" => (CONTINUATION, &[("end_headers", END_HEADERS)]),
        "data" => (DATA, &[("end_stream", END_STREAM), ("padded", PADDED)]),
        other => {
            return Err(refused(format!(
                "`h2_frames[{index}].type = \"{other}\"` is not executed: this writer carries out \
                 settings, headers, continuation, data, window_update, rst_stream, goaway, priority and raw \
                 frames; spell any other frame type as a raw frame"
            )));
        }
    };
    let kind = frame.kind.as_str();
    if frame.error_code.is_some() {
        return Err(refused(format!(
            "`h2_frames[{index}].error_code` belongs to rst_stream and goaway, not to {kind}"
        )));
    }
    if frame.increment.is_some() && frame_type != WINDOW_UPDATE {
        return Err(refused(format!("`h2_frames[{index}].increment` belongs to window_update, not to {kind}")));
    }
    let mut flags = 0_u8;
    for name in &frame.flags {
        let bit = known
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, bit)| *bit)
            .ok_or_else(|| refused(format!("`h2_frames[{index}].flags` names `{name}`, which is not a {kind} flag")))?;
        flags |= bit;
    }
    let stream_id = declared_stream(index, frame, frame_type == SETTINGS)?;
    within_frame_length(index, frame)?;
    let payload = if frame_type == WINDOW_UPDATE {
        if let Some(increment) = frame.increment {
            if frame.payload_declared {
                return Err(refused(format!("`h2_frames[{index}]` declares both increment and payload_hex")));
            }
            u32::try_from(increment)
                .ok()
                .filter(|value| *value <= MAX_STREAM_ID)
                .ok_or_else(|| refused(format!("`h2_frames[{index}].increment` cannot be represented in 31 bits")))?
                .to_be_bytes()
                .to_vec()
        } else {
            frame.payload.clone()
        }
    } else {
        frame.payload.clone()
    };
    Ok(Envelope {
        frame_type,
        flags,
        stream_id,
        payload,
        delay_ms: frame.delay_ms,
    })
}

/// The declared 31-bit stream identifier, or stream zero when the frame type is connection-scoped
/// by default and the case declared none.
fn declared_stream(index: usize, frame: &H2Frame, defaults_to_zero: bool) -> Result<u32, SutError> {
    let declared = match frame.stream_id {
        Some(id) => id,
        None if defaults_to_zero => 0,
        None => {
            return Err(refused(format!("`h2_frames[{index}]` is a {} frame with no stream_id", frame.kind)));
        }
    };
    u32::try_from(declared)
        .ok()
        .filter(|id| *id <= MAX_STREAM_ID)
        .ok_or_else(|| refused(format!("`h2_frames[{index}].stream_id = {declared}` is not a 31-bit stream identifier")))
}

/// Refuses a payload the 24-bit frame length cannot declare, which the header would misstate.
fn within_frame_length(index: usize, frame: &H2Frame) -> Result<(), SutError> {
    if frame.payload.len() > MAX_PAYLOAD {
        return Err(refused(format!(
            "`h2_frames[{index}].payload_hex` is {} octets, beyond the 24-bit frame length",
            frame.payload.len()
        )));
    }
    Ok(())
}

/// The SETTINGS_HEADER_TABLE_SIZE a SETTINGS payload advertises (RFC 9113 section 6.5.1).
fn advertised_header_table_size(payload: &[u8]) -> Option<usize> {
    if !payload.len().is_multiple_of(6) {
        return None;
    }
    // The last occurrence of a setting is the one that takes effect.
    payload
        .chunks_exact(6)
        .rev()
        .find_map(|setting| {
            let [a, b, c, d, e, f] = <[u8; 6]>::try_from(setting).ok()?;
            (u16::from_be_bytes([a, b]) == 1).then(|| u32::from_be_bytes([c, d, e, f]))
        })
        .and_then(|size| usize::try_from(size).ok())
}

impl Conn {
    /// Runs one exchange as an authored frame script on a fresh HTTP/2 connection.
    pub(super) fn exchange_h2(
        &mut self,
        plan: &ExchangePlan<'_>,
        wire: &Wire,
        at_unix_seconds: i64,
        skew_ms: i64,
        reuse: bool,
    ) -> Result<Observation, SutError> {
        let deadline = plan.deadline.unwrap_or_else(|| Instant::now() + budget_of(plan.timeout_ms));
        let script = compile(wire)?;
        self.require_h2_driver()?;
        if reuse && plan.index > 0 {
            return Err(refused(
                "exchange after the first asks to reuse the connection; carrying an HTTP/2 \
                 connection across exchanges is not implemented, and a fresh one would answer a \
                 different case"
                    .to_owned(),
            ));
        }
        // Nothing an HTTP/1.1 exchange left open can carry HTTP/2 frames.
        self.connection = None;
        execute_started(|| self.addr(at_unix_seconds, skew_ms, plan.profile), &script, deadline, None)
    }

    fn require_h2_driver(&self) -> Result<(), SutError> {
        #[cfg(feature = "production-transports")]
        if let Some(driver) = self.driver {
            return match driver {
                ProductionDriver::Hyper => Ok(()),
                ProductionDriver::SelfHeld => Err(refused(
                    "the production self-held driver speaks HTTP/1.1 only; authored HTTP/2 frames \
                     run on the production Hyper driver"
                        .to_owned(),
                )),
            };
        }
        Err(refused(
            "the test socket harness frames HTTP/1.1 only; authored HTTP/2 frames run on the \
             production Hyper driver"
                .to_owned(),
        ))
    }
}

impl Conn {
    /// Runs one exchange as an authored frame script against an external endpoint: over cleartext
    /// with prior knowledge (RFC 9113 section 3.3), or over TLS once the peer selected ALPN `h2`
    /// (section 3.2). Connection setup is the target's time, as on the external HTTP/1.1 path.
    pub(super) fn exchange_h2_external(
        &mut self,
        plan: &ExchangePlan<'_>,
        wire: &Wire,
        endpoint: &super::external_endpoint::ExternalEndpoint,
        reuse: bool,
    ) -> Result<Observation, SutError> {
        let script = compile(wire)?;
        if reuse && plan.index > 0 {
            return Err(refused(
                "exchange after the first asks to reuse the connection; carrying an HTTP/2 connection \
                 across exchanges is not implemented, and a fresh one would answer a different case"
                    .to_owned(),
            ));
        }
        self.connection = None;
        let started = Instant::now();
        let deadline = plan.deadline.unwrap_or_else(|| started + budget_of(plan.timeout_ms));
        let connection = endpoint.open_h2(deadline)?;
        if endpoint.is_tls() {
            // Over TLS, HTTP/2 is in use only when the peer selected `h2`; nothing is written otherwise.
            // The client offers only `h2`, so the peer either selects it, selects nothing, or fails
            // the handshake with `no_application_protocol`.
            if connection.alpn_protocol().as_deref() != Some(b"h2".as_slice()) {
                return Err(refused(
                    "the endpoint selected no ALPN protocol, not `h2`; the authored frames were not written".to_owned(),
                ));
            }
        }
        execute_on(connection, &script, ExchangeClock::until(deadline), started, None)
    }
}

/// The `:method` of every authored request header block, decoded in order the way the peer's
/// decoder will, so a guard can classify what a script asks the peer to do. A block interrupted by
/// another frame, or a CONTINUATION with no open block, is skipped: the peer must end the
/// connection there (RFC 9113 section 6.10) instead of running it.
pub(super) fn authored_methods(wire: &Wire) -> Result<Vec<String>, SutError> {
    let script = compile(wire)?;
    let mut decoder = hpack::Decoder::new(DEFAULT_HEADER_TABLE_SIZE);
    let mut methods = Vec::new();
    let mut open: Option<Vec<u8>> = None;
    for envelope in &script.envelopes {
        let fragment = match envelope.frame_type {
            HEADERS => receive::unpadded(&PeerFrame {
                frame_type: HEADERS,
                flags: envelope.flags,
                stream_id: envelope.stream_id,
                payload: envelope.payload.clone(),
            })?
            .to_vec(),
            CONTINUATION if open.is_some() => envelope.payload.clone(),
            _ => continue,
        };
        let mut block = if envelope.frame_type == HEADERS {
            Vec::new()
        } else {
            open.take().unwrap_or_default()
        };
        block.extend_from_slice(&fragment);
        if envelope.flags & END_HEADERS == 0 {
            open = Some(block);
            continue;
        }
        let fields = decoder
            .decode(&block)
            .map_err(|error| refused(format!("an authored header block could not be decoded: {error}")))?;
        methods.extend(
            fields
                .into_iter()
                .filter(|(name, _)| name == ":method")
                .map(|(_, value)| value),
        );
    }
    Ok(methods)
}

/// Opens one connection, writes the preface and the script, and observes the response.
#[cfg(test)]
fn execute(addr: SocketAddr, script: &Script, budget: Duration) -> Result<Observation, SutError> {
    execute_inner(addr, script, Instant::now() + budget, None)
}

/// [`execute`], with the not-before wait handed in, so a test can record every wait the writer
/// asks for instead of inferring it from wall-clock arrival gaps.
#[cfg(test)]
fn execute_paced(
    addr: SocketAddr,
    script: &Script,
    budget: Duration,
    sleep: &mut dyn FnMut(Duration),
) -> Result<Observation, SutError> {
    execute_inner(addr, script, Instant::now() + budget, Some(sleep))
}

#[cfg(test)]
fn execute_inner(
    addr: SocketAddr,
    script: &Script,
    deadline: Instant,
    sleep: Option<&mut dyn FnMut(Duration)>,
) -> Result<Observation, SutError> {
    execute_started(|| Ok(addr), script, deadline, sleep)
}

/// Starts the peer with `start`, then runs the script against the address it returns.
///
/// Starting a lazily assembled listener is the harness's own setup, so it is paced: it extends
/// the deadline by exactly the time it took and is reported as harness waiting, never charged to
/// the target the case is timing.
fn execute_started(
    start: impl FnOnce() -> Result<SocketAddr, SutError>,
    script: &Script,
    deadline: Instant,
    sleep: Option<&mut dyn FnMut(Duration)>,
) -> Result<Observation, SutError> {
    let mut clock = ExchangeClock::until(deadline);
    let addr = clock.paced(start)?;
    let started = Instant::now();
    let connection = Connection::open_before(addr, clock.deadline)?;
    execute_on(connection, script, clock, started, sleep)
}

/// Writes the preface and the script on an open connection and observes the response.
fn execute_on(
    mut connection: Connection,
    script: &Script,
    mut clock: ExchangeClock,
    started: Instant,
    sleep: Option<&mut dyn FnMut(Duration)>,
) -> Result<Observation, SutError> {
    let (response, progress) = duplex::run(&mut connection, script, &mut clock, sleep)?;
    let elapsed = elapsed_ms(started);
    // A consumed reset must not become EOF merely because a later peek sees a drained socket.
    let socket_read_after = match &response.cut_short {
        Some(ReadFailure::Reset) => Some(SocketReadState::Reset),
        // Under TLS an end of stream is read through records (`close_notify` may precede the TCP
        // FIN), and a peek sees records that could be an alert as easily as data: not measured.
        _ if connection.is_tls() => None,
        Some(ReadFailure::ClosedBeforeHead | ReadFailure::Truncated) => Some(SocketReadState::Eof),
        _ => clock.charged(|| connection.observe_read_side()),
    };
    let goaway = response
        .control_frames
        .iter()
        .any(|frame| matches!(frame, ObservedH2ControlFrame::GoAway { .. }));
    let connection_after = match socket_read_after {
        Some(SocketReadState::NoTerminationObserved) if !goaway => Some(ConnectionState::Open),
        Some(SocketReadState::Eof) => Some(ConnectionState::Closed),
        Some(SocketReadState::Reset) => Some(ConnectionState::Reset),
        _ => None,
    };
    let mut observed = observe(response, elapsed, clock.harness_wait, connection_after, script.stream_id)?;
    observed.socket_read_after = socket_read_after;
    observed.deadline_expiry = progress.deadline_expiry;
    observed.request_body_bytes_sent_at_response = progress.at_response;
    observed.request_body_fully_sent = Some(progress.body_complete);
    if progress.truncated_tls {
        observed
            .notes
            .push("the TLS peer ended the TCP stream without a close_notify alert".to_owned());
    }
    if progress.unfinished_script {
        observed
            .notes
            .push("the peer exchange ended before all authored HTTP/2 frame bytes were written".to_owned());
    }
    Ok(observed)
}

fn type_name(frame_type: u8) -> String {
    match frame_type {
        DATA => "DATA".to_owned(),
        HEADERS => "HEADERS".to_owned(),
        PRIORITY => "PRIORITY".to_owned(),
        RST_STREAM => "RST_STREAM".to_owned(),
        SETTINGS => "SETTINGS".to_owned(),
        0x5 => "PUSH_PROMISE".to_owned(),
        PING => "PING".to_owned(),
        GOAWAY => "GOAWAY".to_owned(),
        WINDOW_UPDATE => "WINDOW_UPDATE".to_owned(),
        CONTINUATION => "CONTINUATION".to_owned(),
        other => format!("frame type 0x{other:02x}"),
    }
}

fn observe(
    response: Response,
    elapsed_ms: u64,
    harness_wait: Duration,
    connection_after: Option<ConnectionState>,
    stream_id: u32,
) -> Result<Observation, SutError> {
    let reset_selected_stream = response
        .control_frames
        .iter()
        .any(|frame| matches!(frame, ObservedH2ControlFrame::ResetStream { stream_id: received, .. } if *received == stream_id));
    let (outcome, stream_termination, body_bytes_before_error, events, notes) = if response.client_reset {
        (Outcome::ClientReset, None, None, Vec::new(), Vec::new())
    } else if reset_selected_stream {
        if response.status.is_some() {
            (
                Outcome::StreamError,
                Some(StreamTermination::Reset),
                Some(u64::try_from(response.body.len()).unwrap_or(u64::MAX)),
                Vec::new(),
                Vec::new(),
            )
        } else {
            (Outcome::StreamReset, None, None, Vec::new(), Vec::new())
        }
    } else {
        match (&response.cut_short, response.status) {
            (None, Some(status)) => {
                let (outcome, termination, before_error, events, note) = classify_body(status, &response.headers, &response.body);
                (outcome, termination, before_error, events, note.into_iter().collect())
            }
            (None, None) => {
                return Err(refused(format!("the peer ended stream {stream_id} without a final response")));
            }
            (Some(ReadFailure::TimedOut), _) => (Outcome::Hang, None, None, Vec::new(), Vec::new()),
            (Some(ReadFailure::Malformed(detail)), _) => (
                Outcome::ConnectionReset,
                None,
                None,
                Vec::new(),
                vec![format!("the peer's frames could not be read: {detail}")],
            ),
            (Some(_), None) => (Outcome::ConnectionReset, None, None, Vec::new(), Vec::new()),
            // The unpadded DATA octets that arrived before the socket ended are measured.
            (Some(ReadFailure::Reset), Some(_)) => (
                Outcome::StreamError,
                Some(StreamTermination::Reset),
                Some(u64::try_from(response.body.len()).unwrap_or(u64::MAX)),
                Vec::new(),
                Vec::new(),
            ),
            (Some(_), Some(_)) => (
                Outcome::StreamError,
                Some(StreamTermination::AbruptClose),
                Some(u64::try_from(response.body.len()).unwrap_or(u64::MAX)),
                Vec::new(),
                Vec::new(),
            ),
        }
    };
    Ok(Observation {
        outcome,
        stream_termination,
        status: response.status,
        http_version: (response.status.is_some() || !response.control_frames.is_empty()).then(|| "h2".to_owned()),
        headers: response.headers,
        trailers: response.trailers,
        body: response.body,
        body_bytes_before_error,
        // The executor attaches request progress; time to first byte remains unavailable.
        request_body_bytes_sent_at_response: None,
        request_body_fully_sent: None,
        ttfb_ms: None,
        elapsed_ms,
        harness_wait_ms: u64::try_from(harness_wait.as_millis()).unwrap_or(u64::MAX),
        deadline_expiry: None,
        connection_after,
        socket_read_after: None,
        h2_control_frames: Some(response.control_frames),
        events,
        notes,
    })
}
