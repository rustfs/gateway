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
//! * SETTINGS, HEADERS, CONTINUATION, DATA and WINDOW_UPDATE are written. RST_STREAM, GOAWAY,
//!   PRIORITY and `raw` are refused: what a peer does after them is not yet observable here.
//! * One stream per script. Received RST_STREAM frames are recorded in arrival order; resetting
//!   the selected stream ends its observation without implying a TCP reset. GOAWAY is recorded
//!   without ending an in-flight stream or inventing receive-side termination.
//! * Only the production Hyper driver speaks HTTP/2 in cleartext with prior knowledge. The
//!   self-held driver, the test harness, external endpoints, and TLS refuse the script.

mod duplex;
mod flow;
mod hpack;
mod huffman;
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
    /// The one stream the script opens; the response on it is the observation.
    stream_id: u32,
    /// The dynamic-table ceiling this client advertised, which bounds the peer's HPACK encoder.
    header_table_size: usize,
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
    let mut header_table_size = DEFAULT_HEADER_TABLE_SIZE;
    for (index, frame) in wire.h2_frames.iter().enumerate() {
        let envelope = envelope(index, frame)?;
        if matches!(envelope.frame_type, HEADERS | CONTINUATION | DATA) {
            let opened = *stream_id.get_or_insert(envelope.stream_id);
            if envelope.stream_id != opened {
                return Err(refused(format!(
                    "`h2_frames[{index}]` is on stream {} after the script opened stream {opened}; \
                     scripts with more than one stream are not executed yet",
                    envelope.stream_id
                )));
            }
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
    Ok(Script {
        envelopes,
        stream_id,
        header_table_size,
    })
}

fn envelope(index: usize, frame: &H2Frame) -> Result<Envelope, SutError> {
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
                 settings, headers, continuation, data and window_update, and what a peer does after an authored \
                 {other} frame is not yet observable here"
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
    let declared = match (frame.stream_id, frame_type) {
        (Some(id), _) => id,
        (None, SETTINGS) => 0,
        (None, _) => return Err(refused(format!("`h2_frames[{index}]` is a {kind} frame with no stream_id"))),
    };
    let stream_id = u32::try_from(declared)
        .ok()
        .filter(|id| *id <= MAX_STREAM_ID)
        .ok_or_else(|| refused(format!("`h2_frames[{index}].stream_id = {declared}` is not a 31-bit stream identifier")))?;
    if frame.payload.len() > MAX_PAYLOAD {
        return Err(refused(format!(
            "`h2_frames[{index}].payload_hex` is {} octets, beyond the 24-bit frame length",
            frame.payload.len()
        )));
    }
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
        let addr = self.addr(at_unix_seconds, skew_ms, plan.profile)?;
        execute_inner(addr, &script, deadline, None)
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

fn execute_inner(
    addr: SocketAddr,
    script: &Script,
    deadline: Instant,
    sleep: Option<&mut dyn FnMut(Duration)>,
) -> Result<Observation, SutError> {
    let started = Instant::now();
    let mut clock = ExchangeClock::until(deadline);
    let mut connection = Connection::open_before(addr, clock.deadline)?;
    let (response, progress) = duplex::run(&mut connection, script, &mut clock, sleep)?;
    let elapsed = elapsed_ms(started);
    // A consumed reset must not become EOF merely because a later peek sees a drained socket.
    let socket_read_after = match &response.cut_short {
        Some(ReadFailure::Reset) => Some(SocketReadState::Reset),
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
    if progress.unfinished_script {
        observed
            .notes
            .push("the peer exchange ended before all authored HTTP/2 frame bytes were written".to_owned());
    }
    Ok(observed)
}

/// One frame the peer sent.
#[derive(Debug)]
struct PeerFrame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

/// Splits the peer's octets into frames.
#[derive(Debug, Default)]
struct FrameReader {
    buffered: Vec<u8>,
}

impl FrameReader {
    fn take(&mut self) -> Option<PeerFrame> {
        let header = self.buffered.get(..FRAME_HEADER_LEN)?;
        let [l0, l1, l2, frame_type, flags, s0, s1, s2, s3] = <[u8; FRAME_HEADER_LEN]>::try_from(header).ok()?;
        let end = FRAME_HEADER_LEN + usize::try_from(u32::from_be_bytes([0, l0, l1, l2])).ok()?;
        let payload = self.buffered.get(FRAME_HEADER_LEN..end)?.to_vec();
        self.buffered.drain(..end);
        Some(PeerFrame {
            frame_type,
            flags,
            stream_id: u32::from_be_bytes([s0, s1, s2, s3]) & MAX_STREAM_ID,
            payload,
        })
    }
}

/// The response on the script's stream, as far as it arrived.
#[derive(Debug, Default)]
struct Response {
    status: Option<u16>,
    headers: Vec<(String, String)>,
    trailers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Supported control frames actually received, including resets of other streams.
    control_frames: Vec<ObservedH2ControlFrame>,
    /// Why reading stopped before the peer ended the stream, when it did.
    cut_short: Option<ReadFailure>,
}

struct Receiver {
    decoder: hpack::Decoder,
    response: Response,
    open_block: Option<(Vec<u8>, bool)>,
}

impl Receiver {
    fn new(script: &Script) -> Self {
        Self {
            decoder: hpack::Decoder::new(script.header_table_size),
            response: Response::default(),
            open_block: None,
        }
    }

    /// Consumes one complete received frame; true means the selected exchange has ended.
    fn accept(&mut self, frame: PeerFrame, script: &Script, flow: &mut flow::Flow) -> Result<bool, SutError> {
        let Self {
            decoder,
            response,
            open_block,
        } = self;
        if let Some((mut fragment, ends_stream)) = open_block.take() {
            if frame.frame_type != CONTINUATION || frame.stream_id != script.stream_id {
                return Err(refused(format!(
                    "the peer sent {} on stream {} inside an unfinished header block, which RFC 9113 \
                     section 6.10 forbids",
                    type_name(frame.frame_type),
                    frame.stream_id
                )));
            }
            fragment.extend_from_slice(&frame.payload);
            if frame.flags & END_HEADERS == 0 {
                *open_block = Some((fragment, ends_stream));
                return Ok(false);
            }
            accept_block(response, decoder, &fragment)?;
            if ends_stream {
                return Ok(true);
            }
            return Ok(false);
        }
        match frame.frame_type {
            // Connection management addressed to this client: read, and answered only when the case
            // authored an answer.
            SETTINGS => {
                if frame.stream_id != 0 {
                    return Err(refused("SETTINGS requires stream zero".to_owned()));
                }
                flow.received_settings(&frame.payload, frame.flags)?;
            }
            PING | PRIORITY => {}
            WINDOW_UPDATE => {
                let bytes = <[u8; 4]>::try_from(frame.payload.as_slice())
                    .map_err(|_| refused("WINDOW_UPDATE requires exactly four payload octets".to_owned()))?;
                let increment = u32::from_be_bytes(bytes) & MAX_STREAM_ID;
                if increment == 0 {
                    return Err(refused("WINDOW_UPDATE increment must not be zero".to_owned()));
                }
                flow.received_update(frame.stream_id, increment)?;
                response.control_frames.push(ObservedH2ControlFrame::WindowUpdate {
                    stream_id: frame.stream_id,
                    increment,
                });
            }
            HEADERS if frame.stream_id == script.stream_id => {
                let fragment = unpadded(&frame)?.to_vec();
                let ends_stream = frame.flags & END_STREAM != 0;
                if frame.flags & END_HEADERS == 0 {
                    *open_block = Some((fragment, ends_stream));
                    return Ok(false);
                }
                accept_block(response, decoder, &fragment)?;
                if ends_stream {
                    return Ok(true);
                }
            }
            DATA if frame.stream_id == script.stream_id => {
                if response.status.is_none() {
                    return Err(refused(format!(
                        "the peer sent DATA on stream {} before a final response header block",
                        frame.stream_id
                    )));
                }
                flow.received_data(frame.payload.len())?;
                response.body.extend_from_slice(unpadded(&frame)?);
                if frame.flags & END_STREAM != 0 {
                    return Ok(true);
                }
            }
            RST_STREAM => {
                let code = <[u8; 4]>::try_from(frame.payload.as_slice())
                    .map_err(|_| refused("the peer sent RST_STREAM with a payload length other than four octets".to_owned()))?;
                if frame.stream_id == 0 {
                    return Err(refused("the peer sent RST_STREAM on connection stream zero".to_owned()));
                }
                response.control_frames.push(ObservedH2ControlFrame::ResetStream {
                    stream_id: frame.stream_id,
                    error_code: u32::from_be_bytes(code),
                });
                if frame.stream_id == script.stream_id {
                    return Ok(true);
                }
            }
            GOAWAY => {
                if frame.stream_id != 0 || frame.payload.len() < 8 {
                    return Err(refused("GOAWAY requires stream zero and at least eight payload octets".to_owned()));
                }
                let last_stream_id =
                    u32::from_be_bytes([frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3]]) & MAX_STREAM_ID;
                let error_code = u32::from_be_bytes([frame.payload[4], frame.payload[5], frame.payload[6], frame.payload[7]]);
                response.control_frames.push(ObservedH2ControlFrame::GoAway {
                    last_stream_id,
                    error_code,
                });
                // Existing streams can still complete. GOAWAY is not EOF, RST_STREAM, or a status.
                // Debug bytes after the numeric fields carry no assertion and are not retained.
            }
            other => {
                return Err(refused(format!(
                    "the peer sent {} on stream {}, which this reader does not interpret",
                    type_name(other),
                    frame.stream_id
                )));
            }
        }
        Ok(false)
    }
}

/// Decodes a complete header block into the response head, or into its trailers once a head exists.
fn accept_block(response: &mut Response, decoder: &mut hpack::Decoder, block: &[u8]) -> Result<(), SutError> {
    let fields = decoder
        .decode(block)
        .map_err(|error| refused(format!("the peer's header block could not be decoded: {error}")))?;
    if response.status.is_some() {
        response.trailers.extend(fields);
        return Ok(());
    }
    let mut fields = fields.into_iter();
    let status = match fields.next() {
        Some((name, value)) if name == ":status" && value.len() == 3 => value.parse::<u16>().ok(),
        _ => None,
    }
    .filter(|status| (100..=599).contains(status))
    .ok_or_else(|| refused("the peer's response header block does not begin with a valid :status".to_owned()))?;
    // An interim response; the final one follows on the same stream.
    if status < 200 {
        return Ok(());
    }
    response.status = Some(status);
    response.headers = fields.collect();
    Ok(())
}

/// A DATA or HEADERS payload without its padding and priority fields (RFC 9113 sections 6.1, 6.2).
fn unpadded(frame: &PeerFrame) -> Result<&[u8], SutError> {
    let malformed = || {
        refused(format!(
            "the peer's {} frame on stream {} is shorter than its padding or priority fields",
            type_name(frame.frame_type),
            frame.stream_id
        ))
    };
    let mut payload = frame.payload.as_slice();
    let mut padding = 0_usize;
    if frame.flags & PADDED != 0 {
        let (&length, rest) = payload.split_first().ok_or_else(malformed)?;
        padding = usize::from(length);
        payload = rest;
    }
    if frame.frame_type == HEADERS && frame.flags & PRIORITY_FLAG != 0 {
        payload = payload.get(5..).ok_or_else(malformed)?;
    }
    payload
        .len()
        .checked_sub(padding)
        .and_then(|end| payload.get(..end))
        .ok_or_else(malformed)
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
    let (outcome, stream_termination, body_bytes_before_error, events, notes) = if reset_selected_stream {
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
            (Some(ReadFailure::Reset), Some(_)) => {
                (Outcome::StreamError, Some(StreamTermination::Reset), None, Vec::new(), Vec::new())
            }
            (Some(_), Some(_)) => (Outcome::StreamError, Some(StreamTermination::AbruptClose), None, Vec::new(), Vec::new()),
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
