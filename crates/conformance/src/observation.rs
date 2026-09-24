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

//! What a transport observed while running one exchange.
//!
//! Responsible for: the record the expectation engine judges — the response head and body as they
//! arrived, the trailers, the two byte counters the schema keeps deliberately distinct, the timing
//! measurements, and the state the connection was left in. It carries wire order and wire casing
//! for headers, because `header_order` and `header_name_bytes_exact` are assertions no normalised
//! map could answer.
//! It also holds [`late_error_offset`], which is the one classification a transport cannot make by
//! watching the connection: whether a response that *arrived intact* was nonetheless a failure. That
//! is decided by the bytes, is the same decision for every transport, and is here rather than in one
//! of them so that a socket target and an in-process target cannot disagree about it.
//! NOT responsible for: performing I/O (`crate::sut`), or judging anything (`crate::expect`).
//! Upstream: nothing. Downstream: `crate::sut`, `crate::expect`.

/// How the exchange ended, mirroring `expect.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A complete response arrived, success or error.
    Response,
    /// The operation failed after the response head was committed.
    StreamError,
    /// The selected HTTP/2 stream was reset before a response head arrived.
    StreamReset,
    /// A framed event sequence arrived.
    EventStream,
    /// No complete response arrived within the case's budget.
    Hang,
    /// The peer reset the connection without answering.
    ConnectionReset,
}

impl Outcome {
    /// The `expect.kind` spelling of this outcome.
    #[must_use]
    pub fn as_kind(self) -> &'static str {
        match self {
            Outcome::Response => "response",
            Outcome::StreamError => "stream_error",
            Outcome::StreamReset => "stream_reset",
            Outcome::EventStream => "event_stream",
            Outcome::Hang => "hang",
            Outcome::ConnectionReset => "connection_reset",
        }
    }
}

/// How a `stream_error` ended, mirroring `expect.stream_termination`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamTermination {
    /// A 200 whose body carries an `<Error>`.
    ErrorDocument,
    /// The body simply stopped.
    AbruptClose,
    /// The stream was reset.
    Reset,
    /// The failure was reported in a trailer.
    TrailerError,
    /// The body claimed to be an event stream but its framing or sequence was invalid.
    MalformedEventStream,
}

impl StreamTermination {
    /// The `expect.stream_termination` spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            StreamTermination::ErrorDocument => "error_document",
            StreamTermination::AbruptClose => "abrupt_close",
            StreamTermination::Reset => "reset",
            StreamTermination::TrailerError => "trailer_error",
            StreamTermination::MalformedEventStream => "malformed_event_stream",
        }
    }
}

/// The state the connection was in once the exchange finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Still reusable.
    Open,
    /// Closed cleanly.
    Closed,
    /// Reset.
    Reset,
    /// One direction shut down.
    HalfClosed,
}

impl ConnectionState {
    /// The `expect.connection_after` spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectionState::Open => "open",
            ConnectionState::Closed => "closed",
            ConnectionState::Reset => "reset",
            ConnectionState::HalfClosed => "half_closed",
        }
    }
}

/// Receive-side termination measured during the transport's observation window.
///
/// This does not assert that both TCP directions closed, that no future termination will occur,
/// or that the connection can carry another HTTP request. `None` on the observation means this
/// fact was not measured or the probe failed for an unclassified reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketReadState {
    /// Reads or a bounded peek found no EOF or connection reset within the observation window.
    NoTerminationObserved,
    /// A read or peek returned zero bytes, establishing receive-side EOF only.
    Eof,
    /// A read or peek reported a connection reset or abort.
    Reset,
}

impl SocketReadState {
    /// The `expect.socket_read_after` spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoTerminationObserved => "no_termination_observed",
            Self::Eof => "eof",
            Self::Reset => "reset",
        }
    }
}

/// One frame of an event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEvent {
    /// The event type, or the error code of a terminal request-level error.
    pub event_type: String,
    /// Event headers, in arrival order.
    pub headers: Vec<(String, String)>,
    /// Event payload bytes.
    pub payload: Vec<u8>,
}

/// Whether the observed head declares an AWS event-stream body.
#[must_use]
pub(crate) fn has_event_stream_content_type(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && value
                .split(';')
                .next()
                .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/vnd.amazon.event-stream"))
    })
}

impl ObservedEvent {
    /// Whether this frame is an `event` message named `event_type`.
    ///
    /// A request-level error frame never matches: its error code is the server's own text, and a
    /// code spelled `End` must not read as the success terminator.
    #[must_use]
    pub(crate) fn is_event_of(&self, event_type: &str) -> bool {
        self.event_type == event_type && event_header(&self.headers, ":message-type") == Some("event")
    }
}

/// Decodes and validates the complete event-stream body observed on the wire.
///
/// This parser is deliberately independent of the framework's encoder. It checks both CRC-32s,
/// every declared length, the string-header grammar and the Select sequence contract before an
/// event becomes observable to a case.
pub(crate) fn decode_event_stream(body: &[u8]) -> Result<Vec<ObservedEvent>, String> {
    const MIN_FRAME_BYTES: usize = 16;
    const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Phase {
        Scanning,
        Counted,
        Terminated,
    }

    let mut remaining = body;
    let mut events = Vec::new();
    let mut phase = Phase::Scanning;
    while !remaining.is_empty() {
        if phase == Phase::Terminated {
            return Err("an event-stream frame followed the terminator".to_owned());
        }
        let total = read_u32(remaining, 0)? as usize;
        let headers_len = read_u32(remaining, 4)? as usize;
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&total) {
            return Err("an event-stream frame declared an invalid total length".to_owned());
        }
        let frame = remaining
            .get(..total)
            .ok_or_else(|| "an event-stream frame ended before its declared total length".to_owned())?;
        let payload_start = 12_usize
            .checked_add(headers_len)
            .ok_or_else(|| "the event-stream header length overflowed".to_owned())?;
        let payload_end = total
            .checked_sub(4)
            .ok_or_else(|| "the event-stream frame is shorter than its checksum".to_owned())?;
        if payload_start > payload_end {
            return Err("the event-stream header block runs past the frame".to_owned());
        }
        if crate::crc32::checksum(frame.get(..8).unwrap_or_default()) != read_u32(frame, 8)? {
            return Err("the event-stream prelude CRC does not match".to_owned());
        }
        if crate::crc32::checksum(frame.get(..payload_end).unwrap_or_default()) != read_u32(frame, payload_end)? {
            return Err("the event-stream message CRC does not match".to_owned());
        }
        let headers = decode_event_headers(
            frame
                .get(12..payload_start)
                .ok_or_else(|| "the event-stream header block is outside the frame".to_owned())?,
        )?;
        let message_type =
            event_header(&headers, ":message-type").ok_or_else(|| "an event-stream frame has no :message-type".to_owned())?;
        let event_type = match message_type {
            "event" => event_header(&headers, ":event-type")
                .ok_or_else(|| "an event frame has no :event-type".to_owned())?
                .to_owned(),
            "error" => {
                let code = event_header(&headers, ":error-code").ok_or_else(|| "an error frame has no :error-code".to_owned())?;
                if event_header(&headers, ":error-message").is_none() {
                    return Err("an error frame has no :error-message".to_owned());
                }
                if payload_start != payload_end {
                    return Err("an error frame has a payload".to_owned());
                }
                code.to_owned()
            }
            _ => return Err("an event-stream frame has an unknown :message-type".to_owned()),
        };
        phase = match (message_type, event_type.as_str(), phase) {
            ("error", _, Phase::Scanning | Phase::Counted) => Phase::Terminated,
            ("event", "Records" | "Progress" | "Cont", Phase::Scanning) => Phase::Scanning,
            ("event", "Stats", Phase::Scanning) => Phase::Counted,
            ("event", "End", Phase::Counted) => Phase::Terminated,
            _ => return Err("an event-stream frame arrived out of sequence".to_owned()),
        };
        events.push(ObservedEvent {
            event_type,
            headers,
            payload: frame.get(payload_start..payload_end).unwrap_or_default().to_vec(),
        });
        remaining = remaining
            .get(total..)
            .ok_or_else(|| "the event-stream cursor ran past the body".to_owned())?;
    }
    if phase != Phase::Terminated {
        return Err("the event stream ended without End or an error frame".to_owned());
    }
    Ok(events)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| "an event-stream integer runs past the available bytes".to_owned())?;
    let wide: [u8; 4] = value
        .try_into()
        .map_err(|_| "an event-stream integer is not four bytes".to_owned())?;
    Ok(u32::from_be_bytes(wide))
}

fn decode_event_headers(mut bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut headers = Vec::new();
    while !bytes.is_empty() {
        let name_len = usize::from(
            *bytes
                .first()
                .ok_or_else(|| "an event-stream header has no name length".to_owned())?,
        );
        let name_end = 1_usize
            .checked_add(name_len)
            .ok_or_else(|| "an event-stream header name length overflowed".to_owned())?;
        let value_type = *bytes
            .get(name_end)
            .ok_or_else(|| "an event-stream header has no value type".to_owned())?;
        if value_type != 7 {
            return Err("an event-stream header value is not a string".to_owned());
        }
        let value_len_offset = name_end.saturating_add(1);
        let value_len_bytes = bytes
            .get(value_len_offset..value_len_offset.saturating_add(2))
            .ok_or_else(|| "an event-stream header has no value length".to_owned())?;
        let value_len = usize::from(u16::from_be_bytes(
            value_len_bytes
                .try_into()
                .map_err(|_| "an event-stream header value length is not two bytes".to_owned())?,
        ));
        let value_start = value_len_offset.saturating_add(2);
        let value_end = value_start
            .checked_add(value_len)
            .ok_or_else(|| "an event-stream header value length overflowed".to_owned())?;
        let name = core::str::from_utf8(
            bytes
                .get(1..name_end)
                .ok_or_else(|| "an event-stream header name runs past the block".to_owned())?,
        )
        .map_err(|_| "an event-stream header name is not UTF-8".to_owned())?;
        let value = core::str::from_utf8(
            bytes
                .get(value_start..value_end)
                .ok_or_else(|| "an event-stream header value runs past the block".to_owned())?,
        )
        .map_err(|_| "an event-stream header value is not UTF-8".to_owned())?;
        headers.push((name.to_owned(), value.to_owned()));
        bytes = bytes
            .get(value_end..)
            .ok_or_else(|| "the event-stream header cursor ran past the block".to_owned())?;
    }
    Ok(headers)
}

fn event_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}

/// Where an `<Error>` document begins in a response whose status line says the request succeeded.
///
/// This is the one shape in S3 where the status and the outcome are different facts: an operation
/// that commits its head before it knows how it ends answers `200`, writes whatever prologue and
/// keep-alive bytes it owes, and then writes an `<Error>` document instead of a result. The offset
/// returned is how much of the body had already gone out when the failure became known, which is
/// exactly what `expect.body_bytes_before_error` names — measured from the bytes, never assumed.
///
/// `None` for every other response, and the two exclusions are the point. A refusal that carries
/// its own `4xx` or `5xx` is an ordinary response and not a late failure; a success whose body is a
/// result document is an ordinary success. Only the disagreement between the two is a stream error,
/// and a transport that reported one without checking would turn `expect.kind` into a field that
/// agrees with whatever it is given.
#[must_use]
pub fn late_error_offset(status: u16, body: &[u8]) -> Option<u64> {
    if !(200..300).contains(&status) {
        return None;
    }
    let (offset, name) = document_element(body)?;
    (name == b"Error").then_some(offset as u64)
}

/// The offset and the name of the first element that is not a declaration, comment or instruction.
///
/// Over bytes rather than over `str`, because the answer is a byte offset into the body as it
/// arrived and a lossy decode would move it.
fn document_element(body: &[u8]) -> Option<(usize, &[u8])> {
    let mut index = 0;
    while index < body.len() {
        if body[index] != b'<' {
            index += 1;
            continue;
        }
        let end = index + body[index..].iter().position(|byte| *byte == b'>')?;
        if matches!(body.get(index + 1), Some(b'?' | b'!')) {
            index = end + 1;
            continue;
        }
        let inner = body.get(index + 1..end)?;
        let name_end = inner
            .iter()
            .position(|byte| byte.is_ascii_whitespace() || *byte == b'/')
            .unwrap_or(inner.len());
        return Some((index, inner.get(..name_end)?));
    }
    None
}

/// One received HTTP/2 control frame, in wire arrival order.
///
/// Only supported control types are represented: RST_STREAM, GOAWAY and WINDOW_UPDATE. This is not a record of
/// every HTTP/2 frame; DATA, headers, and application event streams retain their separate views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedH2ControlFrame {
    /// A valid four-octet WINDOW_UPDATE, after masking its reserved payload bit.
    WindowUpdate {
        /// Zero for connection credit, otherwise the identified stream.
        stream_id: u32,
        /// The positive 31-bit increment received from the peer.
        increment: u32,
    },
    /// A connection-scoped GOAWAY with both numeric fields present; opaque debug data is discarded.
    GoAway {
        /// The 31-bit last-stream identifier, excluding its reserved high bit.
        last_stream_id: u32,
        /// The numeric wire code, including codes unknown to this runner.
        error_code: u32,
    },
    /// A complete four-octet RST_STREAM payload on a nonzero stream.
    ResetStream {
        /// The stream identified by the received frame header.
        stream_id: u32,
        /// The numeric wire code, including codes unknown to this runner.
        error_code: u32,
    },
}

/// A monotonic-clock receipt captured when an executor observes its deadline expire.
///
/// This is not an outcome assertion or an authored timeout. Construction is crate-private;
/// external targets that cannot measure this boundary leave the observation field absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadlineExpiry {
    pub(crate) deadline: std::time::Instant,
    pub(crate) observed_at: std::time::Instant,
    pub(crate) harness_wait: std::time::Duration,
}

impl DeadlineExpiry {
    /// The actual deadline against which the executor stopped waiting.
    #[must_use]
    pub fn deadline(&self) -> std::time::Instant {
        self.deadline
    }

    /// When the executor observed that the deadline had expired.
    #[must_use]
    pub fn observed_at(&self) -> std::time::Instant {
        self.observed_at
    }
}

/// The record of one exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// How the exchange ended.
    pub outcome: Outcome,
    /// How a stream error ended, when the outcome was one.
    pub stream_termination: Option<StreamTermination>,
    /// Status code, when a head arrived.
    pub status: Option<u16>,
    /// The HTTP version the response was framed in, spelled as the schema spells it.
    pub http_version: Option<String>,
    /// Response headers, in wire order and wire casing.
    pub headers: Vec<(String, String)>,
    /// Trailing headers, in wire order.
    pub trailers: Vec<(String, String)>,
    /// The response body exactly as it arrived.
    pub body: Vec<u8>,
    /// Response bytes received before the stream error marker.
    pub body_bytes_before_error: Option<u64>,
    /// Request body bytes the client had written when it observed the response head.
    /// For HTTP/2 reset before a head, the snapshot is taken when that reset is observed.
    /// Unavailable when authored HTTP/2 padding prevents application-byte accounting.
    pub request_body_bytes_sent_at_response: Option<u64>,
    /// Whether the client finished sending the request body.
    pub request_body_fully_sent: Option<bool>,
    /// Milliseconds from the first request byte to the response head.
    pub ttfb_ms: Option<u64>,
    /// Milliseconds from the first request byte until the exchange finished.
    pub elapsed_ms: u64,
    /// Milliseconds of `elapsed_ms` that were the harness's own waiting rather than the target's:
    /// authored `delay_ms` pacing, `stall` durations, teardown delays, and the window spent
    /// observing the connection after the response. Measured where the wait happens, never
    /// derived from what a case declared, and excluded from `case.timeout_ms`, which budgets the
    /// target (rustfs/gateway#426). A transport with no waiting of its own reports `0`.
    pub harness_wait_ms: u64,
    /// Actual deadline expiry, when measured by a bounded executor rather than inferred from kind.
    pub deadline_expiry: Option<DeadlineExpiry>,
    /// The connection state afterwards.
    pub connection_after: Option<ConnectionState>,
    /// Receive-side termination observed within the transport's bounded observation window.
    /// This is independent of protocol shutdown announcements and connection reusability.
    pub socket_read_after: Option<SocketReadState>,
    /// Supported HTTP/2 control frames in received order, until this exchange ended.
    ///
    /// `None` means unmeasured. `Some([])` means no supported control frame was received during
    /// the observation. RST_STREAM, GOAWAY, and WINDOW_UPDATE are supported; this never implies the absence
    /// of other frame types or proves that a connection remains reusable.
    pub h2_control_frames: Option<Vec<ObservedH2ControlFrame>>,
    /// Frames, when this was an event stream.
    pub events: Vec<ObservedEvent>,
    /// What about this record the transport could not measure and produced some other way.
    ///
    /// The runner turns each of these into a warning on the case, and that is the whole point:
    /// this suite has repeatedly grown assertions that could not fail while reading exactly like
    /// assertions that had been checked. Some facts really are true by construction — after a
    /// client tears its own connection down, "no response arrived" and "the socket is closed" are
    /// not findings about a server — and the honest handling is to report them *and say so on the
    /// case*, rather than to let a green line stand for a measurement nobody made.
    ///
    /// Empty for anything the transport actually observed. A transport that filled this routinely
    /// would be describing itself rather than the exchange.
    pub notes: Vec<String>,
}

impl Observation {
    /// A minimal complete response, for tests and for transports that observe nothing else.
    #[must_use]
    pub fn response(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Observation {
        Observation {
            outcome: Outcome::Response,
            stream_termination: None,
            status: Some(status),
            http_version: None,
            headers,
            trailers: Vec::new(),
            body,
            body_bytes_before_error: None,
            request_body_bytes_sent_at_response: None,
            request_body_fully_sent: None,
            ttfb_ms: None,
            elapsed_ms: 0,
            harness_wait_ms: 0,
            deadline_expiry: None,
            connection_after: None,
            socket_read_after: None,
            h2_control_frames: None,
            events: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// The body decoded as UTF-8, lossily, for text assertions and diagnostics.
    #[must_use]
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The first value of a header, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[cfg(test)]
mod select_error_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use rustfs_gateway::EventKind;
    use rustfs_gateway::{EventSequence, encode_event, stats_document};

    /// Positive — a complete stream becomes the events the case schema judges, in wire order.
    #[test]
    fn a_complete_event_stream_is_observed_frame_by_frame() {
        let mut bytes = Vec::new();
        let mut sequence = EventSequence::new();
        sequence.records(b"a,b\n", &mut bytes).expect("records first");
        sequence.stats(&stats_document(4, 4, 4), &mut bytes).expect("accounting");
        sequence.end(&mut bytes).expect("terminator");

        let events = decode_event_stream(&bytes).expect("a valid stream");
        let types: Vec<&str> = events.iter().map(|event| event.event_type.as_str()).collect();
        assert_eq!(types, ["Records", "Stats", "End"]);
        assert_eq!(events[0].payload, b"a,b\n");
        assert_eq!(events[0].headers[0], (":message-type".to_owned(), "event".to_owned()));
    }

    /// Negative — a frame whose message CRC no longer covers its bytes is not an observation.
    #[test]
    fn n_a_corrupt_event_stream_frame_is_refused() {
        let mut bytes = Vec::new();
        let mut sequence = EventSequence::new();
        sequence.records(b"a,b\n", &mut bytes).expect("records first");
        let first_frame = read_u32(&bytes, 0).expect("a total length") as usize;
        sequence.stats(&stats_document(4, 4, 4), &mut bytes).expect("accounting");
        sequence.end(&mut bytes).expect("terminator");
        let payload = first_frame - 5;
        bytes[payload] ^= 1;
        assert!(decode_event_stream(&bytes).is_err());
    }

    /// Negative — an incomplete frame is not silently reported as a shorter successful stream.
    #[test]
    fn n_a_truncated_event_stream_frame_is_refused() {
        let mut bytes = Vec::new();
        let mut sequence = EventSequence::new();
        sequence.records(b"a,b\n", &mut bytes).expect("records first");
        sequence.stats(&stats_document(4, 4, 4), &mut bytes).expect("accounting");
        sequence.end(&mut bytes).expect("terminator");
        bytes.pop();
        assert!(decode_event_stream(&bytes).is_err());
    }

    /// Negative — a syntactically valid Records frame is not a complete Select response without a
    /// terminal End or error frame.
    #[test]
    fn n_an_event_stream_without_a_terminator_is_refused() {
        let mut bytes = Vec::new();
        encode_event(EventKind::Records, b"a,b\n", &mut bytes).expect("a records frame");
        assert!(decode_event_stream(&bytes).is_err());
    }

    /// Negative — the event-stream header grammar used by Select carries string values. Accepting
    /// another type would move the cursor by the wrong width and misread every following byte.
    #[test]
    fn n_a_non_string_event_header_is_refused() {
        let mut bytes = Vec::new();
        let mut sequence = EventSequence::new();
        sequence.records(b"a,b\n", &mut bytes).expect("records first");
        let first_frame = read_u32(&bytes, 0).expect("a total length") as usize;
        sequence.stats(&stats_document(4, 4, 4), &mut bytes).expect("accounting");
        sequence.end(&mut bytes).expect("terminator");
        let first_value_type = 12 + 1 + ":message-type".len();
        bytes[first_value_type] = 6;
        let message_crc_offset = first_frame - 4;
        let message_crc = crate::crc32::checksum(&bytes[..message_crc_offset]);
        bytes[message_crc_offset..first_frame].copy_from_slice(&message_crc.to_be_bytes());
        assert!(decode_event_stream(&bytes).is_err());
    }

    #[test]
    fn header_lookup_ignores_case_but_the_record_keeps_it() {
        let observation = Observation::response(200, vec![("Content-Type".to_owned(), "application/xml".to_owned())], Vec::new());
        assert_eq!(observation.header("content-type"), Some("application/xml"));
        assert_eq!(observation.headers[0].0, "Content-Type");
    }

    #[test]
    fn kind_spellings_match_the_schema() {
        assert_eq!(Outcome::StreamError.as_kind(), "stream_error");
        assert_eq!(StreamTermination::ErrorDocument.as_str(), "error_document");
        assert_eq!(StreamTermination::MalformedEventStream.as_str(), "malformed_event_stream");
        assert_eq!(ConnectionState::HalfClosed.as_str(), "half_closed");
    }

    const DECLARATION: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

    /// Positive — a success whose body carries an `<Error>` is a late failure, and the offset is the
    /// bytes that had already gone out. The declaration is 39 of them, which is what `c-mpu-0001`
    /// and `c-copy-0038` pin.
    #[test]
    fn a_success_whose_body_is_an_error_reports_where_the_error_began() {
        let mut body = DECLARATION.to_vec();
        assert_eq!(body.len(), 39);
        body.extend_from_slice(b"<Error><Code>InvalidPart</Code></Error>");
        assert_eq!(late_error_offset(200, &body), Some(39));
        // Keep-alive whitespace written while the outcome was pending counts too: it is body that
        // was committed before the failure was known.
        let mut held = DECLARATION.to_vec();
        held.extend_from_slice(b"   ");
        held.extend_from_slice(b"<Error><Code>InvalidPart</Code></Error>");
        assert_eq!(late_error_offset(200, &held), Some(42));
    }

    /// Negative — an ordinary refusal is not a late failure. It carries its own status, so reporting
    /// it as a `stream_error` would make `expect.kind` agree with every error response in the corpus
    /// and assert nothing.
    #[test]
    fn a_refusal_that_carries_its_own_status_is_not_a_late_failure() {
        let mut body = DECLARATION.to_vec();
        body.extend_from_slice(b"<Error><Code>InvalidPart</Code></Error>");
        for status in [400_u16, 404, 412, 416, 500, 503] {
            assert_eq!(late_error_offset(status, &body), None, "{status}");
        }
    }

    /// Negative — a success whose body is a result document is not a late failure, and neither is an
    /// empty body or one that never opens an element.
    #[test]
    fn a_success_that_answered_is_not_a_late_failure() {
        let mut result = DECLARATION.to_vec();
        result.extend_from_slice(b"<CompleteMultipartUploadResult><Bucket>b</Bucket></CompleteMultipartUploadResult>");
        assert_eq!(late_error_offset(200, &result), None);
        assert_eq!(late_error_offset(200, b""), None);
        assert_eq!(late_error_offset(204, b""), None);
        assert_eq!(late_error_offset(200, b"not xml at all"), None);
        assert_eq!(late_error_offset(200, DECLARATION), None);
    }

    /// Negative — an element whose name merely starts with `Error` is not an `<Error>`.
    ///
    /// The scan compares the whole name rather than a prefix, because `<ErrorDocument>` is a real S3
    /// element and a prefix test would read a website-configuration body as a failed request.
    #[test]
    fn an_element_that_only_looks_like_an_error_is_not_one() {
        assert_eq!(late_error_offset(200, b"<ErrorDocument><Key>404.html</Key></ErrorDocument>"), None);
        assert_eq!(late_error_offset(200, b"<Error xmlns=\"x\"><Code>c</Code></Error>"), Some(0));
        assert_eq!(late_error_offset(200, b"<Error/>"), Some(0));
    }

    /// Negative — a truncated head is not read past its end. A body that opens a tag and never
    /// closes it has no document element, and inventing one would name an offset the wire never had.
    #[test]
    fn an_unterminated_tag_yields_no_document_element() {
        assert_eq!(late_error_offset(200, b"<Error"), None);
        assert_eq!(late_error_offset(200, b"<?xml version=\"1.0\""), None);
    }
}
