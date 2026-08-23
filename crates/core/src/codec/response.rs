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
//!
//! # Why the decision is a function and the enforcement is not
//!
//! [`EncodedResponse`] is what an *encoder* produced, and a refusal never reaches an encoder — it
//! is rendered straight into an `http::Response` by the facade. So this type cannot be the only
//! place the rule runs, and a second copy of the rule written against the facade's response type
//! is exactly the drift the paragraph above is about. [`body_allowance`] is therefore the decision
//! on its own, over a method and a status and nothing else; both call sites enforce the same
//! answer over their own response type, and neither can disagree about what the answer is.

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rustfs_gateway_http::encode_metadata_value;
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
        let rendered = if prefix == rustfs_gateway_http::METADATA_PREFIX {
            let Ok(rendered) = encode_metadata_value(value) else {
                return;
            };
            rendered
        } else {
            std::borrow::Cow::Borrowed(value)
        };
        let Ok(value) = HeaderValue::from_str(&rendered) else {
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
    /// The value it writes is the one [`override_header_value`] accepts, and a request carrying any
    /// other value was refused by [`crate::codec::value::verify_response_overrides`] before a
    /// handler ran — so the skip below is unreachable through a decoded request rather than a
    /// second, quieter policy about the same bytes.
    pub fn apply_response_overrides(&mut self, request: &MetaView<'_>, table: &[ResponseOverride]) {
        for entry in table {
            let Some(value) = request.query(entry.query) else {
                continue;
            };
            let Ok(name) = HeaderName::from_bytes(entry.header.as_bytes()) else {
                continue;
            };
            let Some(value) = override_header_value(value.as_ref()) else {
                continue;
            };
            self.headers.insert(name, value);
        }
    }

    /// Applies the RFC 9110 body invariants, and is the last thing every encoder does.
    ///
    /// The decisions are [`response_body_allowed`] and [`response_framing_allowed`]; this method is
    /// the half that knows how to drop a body and a header off *this* type. The facade applies the
    /// same decisions to a refusal, which never reaches an encoder and therefore never reaches here.
    pub fn enforce_http_invariants(&mut self, method: &Method) {
        if !response_body_allowed(method, self.status) {
            self.body = ResponseBody::Empty;
        }
        if !response_framing_allowed(method, self.status) {
            self.headers.remove(http::header::CONTENT_LENGTH);
            self.headers.remove(http::header::TRANSFER_ENCODING);
        }
    }
}

/// What RFC 9110 lets a response carry, given the method it answers and the status it goes out with.
///
/// Three answers rather than two, because "no content" and "no content and no framing header" are
/// different responses and the difference is the whole of [`Self::HeadOfContent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyAllowance {
    /// Content, and the framing headers that describe it.
    Content,
    /// No content — and `Content-Length` still reporting the length a `GET` would have sent.
    ///
    /// RFC 9110 §9.3.2. The number is not a lie and must not be rewritten to `0`: it is the answer
    /// a `HEAD` was asking for, and a client that reads `0` concludes the object is empty. Dropping
    /// the *bytes* is the rule; reporting zero of them is a different bug.
    HeadOfContent,
    /// No content, and no framing header describing one — `1xx`, `204`, `205`, `304`.
    Bodyless,
}

/// The one decision behind both body invariants.
///
/// A function of the method and the status alone, so that the success path and the refusal path can
/// each enforce it over their own response type without either holding a second copy of the rule.
/// The status is checked first: RFC 9110 §9.3.2 states the `HEAD` rule with no status exception, so
/// the two overlap on a `304` answered to a `HEAD` and the stricter answer is the right one there.
#[must_use]
pub fn body_allowance(method: &Method, status: StatusCode) -> BodyAllowance {
    match (response_body_allowed(method, status), response_framing_allowed(method, status)) {
        (true, _) => BodyAllowance::Content,
        (false, true) => BodyAllowance::HeadOfContent,
        (false, false) => BodyAllowance::Bodyless,
    }
}

/// Whether a response may carry content bytes after the final invariant pass.
#[must_use]
pub fn response_body_allowed(method: &Method, status: StatusCode) -> bool {
    let code = status.as_u16();
    if code == 304 {
        return matches!(
            crate::contracts::NOT_MODIFIED_BODY_POLICY,
            crate::contracts::NotModifiedBodyPolicy::Preserve
        );
    }
    if status.is_informational() || code == 204 || code == 205 {
        return false;
    }
    method != Method::HEAD || !crate::contracts::suppress_head_body()
}

/// Whether a response may carry `Content-Length` or `Transfer-Encoding` after the final invariant pass.
#[must_use]
pub fn response_framing_allowed(_method: &Method, status: StatusCode) -> bool {
    let code = status.as_u16();
    if code == 304 {
        return matches!(
            crate::contracts::NOT_MODIFIED_FRAMING_POLICY,
            crate::contracts::NotModifiedFramingPolicy::Preserve
        );
    }
    !(status.is_informational() || code == 204 || code == 205)
}

/// One `response-<x>` query parameter and the response header it overwrites.
///
/// The triple is IR data: the query key is the input field's wire name, the header is that name
/// with the `response-` prefix removed, and the member is the model member the field binds.
/// Nothing here decides which parameters exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseOverride {
    /// The query parameter, as it appears on the wire.
    pub query: &'static str,
    /// The response header it overwrites, lowercase.
    pub header: &'static str,
    /// The model member the parameter binds, for the refusal to name.
    pub member: &'static str,
}

impl ResponseOverride {
    /// One entry of the table.
    #[must_use]
    pub const fn new(query: &'static str, header: &'static str, member: &'static str) -> Self {
        Self { query, header, member }
    }
}

/// The one reading of "this value fits in a response header", shared by the refusal and the write.
///
/// The value comes from the request — a `response-*` parameter is client input that ends up in the
/// response head — so a CR or an LF in it is an attempt to terminate the header block early and
/// append headers, or a whole second response, of the caller's choosing. What the grammar excludes
/// is wider than that pair (`HeaderValue` refuses every C0 control except tab, and DEL) and the
/// whole class is refused, because a decoder that forwarded a NUL would only have moved the
/// question to whatever parses the response next.
///
/// Returning the parsed value rather than a `bool` is what keeps the two halves from drifting:
/// the decoder refuses a request exactly when this answers `None`, and the encoder writes exactly
/// what it answers, so there is no second predicate that could disagree with this one.
///
/// Not a `HeaderName` question: the name is a compile-time constant from the IR and never a value
/// the request chose.
#[must_use]
pub fn override_header_value(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(value).ok()
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
