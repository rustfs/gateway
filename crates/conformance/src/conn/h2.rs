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
//! * SETTINGS, HEADERS, CONTINUATION and DATA are written. RST_STREAM, WINDOW_UPDATE, GOAWAY,
//!   PRIORITY and `raw` are refused: what a peer does after them is not yet observable here.
//! * One stream per script. The response on it is the observation; a peer RST_STREAM or GOAWAY
//!   before it completes is refused as unobservable rather than reported as a response.
//! * Only the production Hyper driver speaks HTTP/2 in cleartext with prior knowledge. The
//!   self-held driver, the test harness, external endpoints, and TLS refuse the script.

mod hpack;
mod huffman;
#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::{Conn, ExchangeClock, budget_of, classify_body, elapsed_ms};
use crate::inprocess::Wire;
use crate::inprocess::h2_frames::H2Frame;
use crate::observation::{ConnectionState, Observation, Outcome, StreamTermination};
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
/// What a peer may send on a connection before this client would owe it a WINDOW_UPDATE
/// (RFC 9113 section 6.9.2), which it sends only when a case authors one.
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
                 settings, headers, continuation and data, and what a peer does after an authored \
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
    if frame.increment.is_some() {
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
    Ok(Envelope {
        frame_type,
        flags,
        stream_id,
        payload: frame.payload.clone(),
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
        execute(addr, &script, budget_of(plan.timeout_ms))
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
fn execute(addr: SocketAddr, script: &Script, budget: Duration) -> Result<Observation, SutError> {
    execute_paced(addr, script, budget, &mut |delay| std::thread::sleep(delay))
}

/// [`execute`], with the not-before wait handed in, so a test can record every wait the writer
/// asks for instead of inferring it from wall-clock arrival gaps.
fn execute_paced(
    addr: SocketAddr,
    script: &Script,
    budget: Duration,
    sleep: &mut dyn FnMut(Duration),
) -> Result<Observation, SutError> {
    let started = Instant::now();
    let mut clock = ExchangeClock::until(started + budget);
    let mut connection = Connection::open_before(addr, clock.deadline)?;
    connection.write(PREFACE)?;
    for (index, envelope) in script.envelopes.iter().enumerate() {
        let delay = Duration::from_millis(envelope.delay_ms);
        if delay >= clock.remaining()? {
            return Err(refused(format!(
                "`h2_frames[{index}]` declares a {}ms delay beyond the remaining exchange timeout",
                envelope.delay_ms
            )));
        }
        if !delay.is_zero() {
            clock.charged(|| sleep(delay));
        }
        connection.write(&envelope.bytes())?;
    }
    let response = read_response(&mut connection, script, clock.deadline)?;
    let elapsed = elapsed_ms(started);
    let connection_after = clock.charged(|| connection.observe());
    observe(response, elapsed, clock.harness_wait, connection_after, script.stream_id)
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
    fn next(&mut self, connection: &mut Connection, deadline: Instant) -> Result<PeerFrame, ReadFailure> {
        loop {
            if let Some(frame) = self.take() {
                return Ok(frame);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(ReadFailure::TimedOut)?;
            if connection.read_available(&mut self.buffered, remaining)? == 0 {
                return Err(if self.buffered.is_empty() {
                    ReadFailure::ClosedBeforeHead
                } else {
                    ReadFailure::Truncated
                });
            }
        }
    }

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
    /// Why reading stopped before the peer ended the stream, when it did.
    cut_short: Option<ReadFailure>,
}

fn read_response(connection: &mut Connection, script: &Script, deadline: Instant) -> Result<Response, SutError> {
    let mut reader = FrameReader::default();
    let mut decoder = hpack::Decoder::new(script.header_table_size);
    let mut response = Response::default();
    // A header block the peer started without END_HEADERS, and whether it ends the stream.
    let mut open_block: Option<(Vec<u8>, bool)> = None;
    let mut flow_controlled = 0_usize;
    loop {
        let frame = match reader.next(connection, deadline) {
            Ok(frame) => frame,
            Err(failure) => {
                response.cut_short = Some(failure);
                return Ok(response);
            }
        };
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
                open_block = Some((fragment, ends_stream));
                continue;
            }
            accept_block(&mut response, &mut decoder, &fragment)?;
            if ends_stream {
                return Ok(response);
            }
            continue;
        }
        match frame.frame_type {
            // Connection management addressed to this client: read, and answered only when the case
            // authored an answer.
            SETTINGS | PING | WINDOW_UPDATE | PRIORITY => {}
            HEADERS if frame.stream_id == script.stream_id => {
                let fragment = unpadded(&frame)?.to_vec();
                let ends_stream = frame.flags & END_STREAM != 0;
                if frame.flags & END_HEADERS == 0 {
                    open_block = Some((fragment, ends_stream));
                    continue;
                }
                accept_block(&mut response, &mut decoder, &fragment)?;
                if ends_stream {
                    return Ok(response);
                }
            }
            DATA if frame.stream_id == script.stream_id => {
                if response.status.is_none() {
                    return Err(refused(format!(
                        "the peer sent DATA on stream {} before a final response header block",
                        frame.stream_id
                    )));
                }
                flow_controlled += frame.payload.len();
                response.body.extend_from_slice(unpadded(&frame)?);
                if frame.flags & END_STREAM != 0 {
                    return Ok(response);
                }
                if flow_controlled >= INITIAL_CONNECTION_WINDOW {
                    return Err(refused(format!(
                        "the response filled the {INITIAL_CONNECTION_WINDOW}-octet initial flow-control \
                         window without ending the stream; this client sends WINDOW_UPDATE only when a \
                         case authors one, so the rest of the body cannot arrive"
                    )));
                }
            }
            RST_STREAM if frame.stream_id == script.stream_id => {
                return Err(refused(format!(
                    "the peer reset stream {} with {}; observing RST_STREAM is not implemented, so the \
                     case is refused rather than reported as a response",
                    frame.stream_id,
                    error_name(&frame.payload, 0)
                )));
            }
            GOAWAY => {
                let last_stream = frame
                    .payload
                    .get(..4)
                    .and_then(|octets| <[u8; 4]>::try_from(octets).ok())
                    .map_or(0, |octets| u32::from_be_bytes(octets) & MAX_STREAM_ID);
                return Err(refused(format!(
                    "the peer sent GOAWAY (last stream {last_stream}, {}) before stream {} completed; \
                     observing GOAWAY is not implemented, so the case is refused rather than \
                     reported as a response",
                    error_name(&frame.payload, 4),
                    script.stream_id
                )));
            }
            other => {
                return Err(refused(format!(
                    "the peer sent {} on stream {}, which this reader does not interpret",
                    type_name(other),
                    frame.stream_id
                )));
            }
        }
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

/// The RFC 9113 section 7 name of the error code at `offset`.
fn error_name(payload: &[u8], offset: usize) -> String {
    const NAMES: [&str; 14] = [
        "NO_ERROR",
        "PROTOCOL_ERROR",
        "INTERNAL_ERROR",
        "FLOW_CONTROL_ERROR",
        "SETTINGS_TIMEOUT",
        "STREAM_CLOSED",
        "FRAME_SIZE_ERROR",
        "REFUSED_STREAM",
        "CANCEL",
        "COMPRESSION_ERROR",
        "CONNECT_ERROR",
        "ENHANCE_YOUR_CALM",
        "INADEQUATE_SECURITY",
        "HTTP_1_1_REQUIRED",
    ];
    let Some(code) = payload
        .get(offset..offset + 4)
        .and_then(|octets| <[u8; 4]>::try_from(octets).ok())
        .map(u32::from_be_bytes)
    else {
        return "no error code".to_owned();
    };
    usize::try_from(code)
        .ok()
        .and_then(|index| NAMES.get(index))
        .map_or_else(|| format!("error code 0x{code:x}"), |name| (*name).to_owned())
}

fn observe(
    response: Response,
    elapsed_ms: u64,
    harness_wait: Duration,
    connection_after: ConnectionState,
    stream_id: u32,
) -> Result<Observation, SutError> {
    let (outcome, stream_termination, body_bytes_before_error, events, notes) = match (&response.cut_short, response.status) {
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
    };
    Ok(Observation {
        outcome,
        stream_termination,
        status: response.status,
        http_version: response.status.map(|_| "h2".to_owned()),
        headers: response.headers,
        trailers: response.trailers,
        body: response.body,
        body_bytes_before_error,
        // Request progress and time to first byte are not measured on this transport.
        request_body_bytes_sent_at_response: None,
        request_body_fully_sent: None,
        ttfb_ms: None,
        elapsed_ms,
        harness_wait_ms: u64::try_from(harness_wait.as_millis()).unwrap_or(u64::MAX),
        connection_after: Some(connection_after),
        events,
        notes,
    })
}
