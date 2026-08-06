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

/// One frame of an event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEvent {
    /// The event type as the server named it.
    pub event_type: String,
    /// Event headers, in arrival order.
    pub headers: Vec<(String, String)>,
    /// Event payload bytes.
    pub payload: Vec<u8>,
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
    /// Request body bytes the client had written when the response head arrived.
    pub request_body_bytes_sent_at_response: Option<u64>,
    /// Whether the client finished sending the request body.
    pub request_body_fully_sent: Option<bool>,
    /// Milliseconds from the first request byte to the response head.
    pub ttfb_ms: Option<u64>,
    /// Milliseconds from the first request byte until the exchange finished.
    pub elapsed_ms: u64,
    /// The connection state afterwards.
    pub connection_after: Option<ConnectionState>,
    /// Frames, when this was an event stream.
    pub events: Vec<ObservedEvent>,
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
            connection_after: None,
            events: Vec::new(),
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
mod tests {
    use super::*;

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
