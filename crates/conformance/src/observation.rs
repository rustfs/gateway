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
}
