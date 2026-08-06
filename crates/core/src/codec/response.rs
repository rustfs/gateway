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

//! What an encoder produces, and the two rules every encoder is held to afterwards.
//!
//! Responsible for: [`EncodedResponse`] and [`ResponseBody`], the RFC 9110 body invariants, and
//! the `response-*` override table.
//! NOT responsible for: writing any header an operation declares — that is the generated encoder,
//! from IR data.
//! Upstream: `http`, `rustfs-gateway-stream`. Downstream: every generated codec, and the facade
//! that puts the result on a socket.
//!
//! # Why the two rules live here and not in the generated code
//!
//! "A `HEAD` response has no body" and "a `304` has no body" are properties of HTTP, not of any
//! operation. Generating them per operation would produce seventy-three copies of one rule and
//! seventy-three chances to write it once as `!=`. [`EncodedResponse::enforce_http_invariants`] is
//! the single copy, applied to every encoder's output by the same generated line.

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rustfs_gateway_stream::ByteStream;

use crate::codec::error::CodecError;
use crate::codec::view::MetaView;

/// What an encoder produced, before it reaches a transport.
#[derive(Debug)]
pub struct EncodedResponse {
    /// The status line.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: ResponseBody,
}

/// The three shapes a response body can take.
#[derive(Debug, Default)]
pub enum ResponseBody {
    /// No body at all.
    #[default]
    Empty,
    /// A complete document, already serialised.
    Complete(Vec<u8>),
    /// The operation's own streaming payload.
    Stream(ByteStream),
}

impl ResponseBody {
    /// Whether the body carries no bytes at all.
    ///
    /// A stream is never "empty" here even when it will produce nothing: its length is not a fact
    /// this layer has.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Complete(bytes) => bytes.is_empty(),
            Self::Stream(_) => false,
        }
    }
}

impl EncodedResponse {
    /// An empty response with a status.
    #[must_use]
    pub fn of(status: u16) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
            headers: HeaderMap::new(),
            body: ResponseBody::Empty,
        }
    }

    /// Sets a header, ignoring a value the HTTP grammar cannot carry.
    ///
    /// Ignoring rather than failing: a value that will not fit in a header field is a value the
    /// storage layer accepted and this layer cannot express, and dropping the header is what AWS
    /// does. The one class this must never silently drop is user metadata, which
    /// `rustfs-gateway-http`'s acceptance rules have already constrained on the way in.
    pub fn set_header(&mut self, name: &'static str, value: &str) {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            return;
        };
        let Ok(value) = HeaderValue::from_str(value) else {
            return;
        };
        self.headers.insert(name, value);
    }

    /// Sets a header whose name is only known at run time — the `x-amz-meta-*` family.
    pub fn set_prefixed_header(&mut self, prefix: &str, suffix: &str, value: &str) {
        let mut name = String::with_capacity(prefix.len().saturating_add(suffix.len()));
        name.push_str(prefix);
        name.push_str(suffix);
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            return;
        };
        let Ok(value) = HeaderValue::from_str(value) else {
            return;
        };
        self.headers.insert(name, value);
    }

    /// Applies the operation's `response-*` overrides, once, after every header has been written.
    ///
    /// The table is IR data the generated encoder passes in, not a list written here: an operation
    /// that has no override parameters passes an empty table and this is a no-op. Applying it as a
    /// final pass rather than inside each field's binding is what makes "the override wins"
    /// true by construction instead of true by field ordering.
    pub fn apply_response_overrides(&mut self, request: &MetaView<'_>, table: &[ResponseOverride]) {
        for entry in table {
            let Some(value) = request.query(entry.query) else {
                continue;
            };
            let Ok(name) = HeaderName::from_bytes(entry.header.as_bytes()) else {
                continue;
            };
            let Ok(value) = HeaderValue::from_str(value.as_ref()) else {
                continue;
            };
            self.headers.insert(name, value);
        }
    }

    /// Applies the RFC 9110 body invariants, and is the last thing every encoder does.
    ///
    /// Two rules, and neither is negotiable per operation:
    ///
    /// * a response to `HEAD` carries the headers a `GET` would and no content;
    /// * `1xx`, `204`, `205` and `304` carry no content, and no framing header describing one.
    ///
    /// The framing headers go with the body in the second case only. A `HEAD` keeps its
    /// `Content-Length`, because that number is the answer the request was asking for.
    pub fn enforce_http_invariants(&mut self, method: &Method) {
        let status = self.status.as_u16();
        let statusless_body = self.status.is_informational() || status == 204 || status == 205 || status == 304;

        if statusless_body {
            self.body = ResponseBody::Empty;
            self.headers.remove(http::header::CONTENT_LENGTH);
            self.headers.remove(http::header::TRANSFER_ENCODING);
            return;
        }
        if method == Method::HEAD {
            self.body = ResponseBody::Empty;
        }
    }
}

/// One `response-<x>` query parameter and the response header it overwrites.
///
/// The pair is IR data: the query key is the input field's wire name, and the header is that name
/// with the `response-` prefix removed. Nothing here decides which parameters exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseOverride {
    /// The query parameter, as it appears on the wire.
    pub query: &'static str,
    /// The response header it overwrites, lowercase.
    pub header: &'static str,
}

impl ResponseOverride {
    /// One entry of the table.
    #[must_use]
    pub const fn new(query: &'static str, header: &'static str) -> Self {
        Self { query, header }
    }
}

/// Turns a status the IR carries into an [`http::StatusCode`].
///
/// # Errors
///
/// [`CodecError::internal`] for a number outside the status range. The IR cannot express one, so
/// reaching this is a generator defect rather than anything a caller did.
pub fn status_code(status: u16) -> Result<StatusCode, CodecError> {
    StatusCode::from_u16(status).map_err(|_| CodecError::internal("the operation declares a status that is not an HTTP status"))
}
