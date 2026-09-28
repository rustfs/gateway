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

//! The response headers a handler adds beyond its operation's output, and the floor they may not
//! cross (rustfs/gateway#1018).
//!
//! Responsible for: [`OWNED_RESPONSE_HEADERS`], the names the gateway alone writes on a response,
//! and [`EncodedResponse::append_extra_headers`], which appends a handler's extra headers after the
//! operation's encoder ran and refuses one that is owned or that the encoder already wrote.
//! Also [`Resp::with_extra_headers`], the handler's way in, kept here beside the floor it meets.
//! NOT responsible for: deciding when they apply — both dispatch paths append them to a settled
//! answer only and refuse them on a committed or event-stream one.
//! Upstream: the monomorphic and registry dispatch paths. Downstream: the facade's response writer.
//!
//! # Why a refusal and not a drop
//!
//! A header a handler asked for and the client never received is a silent wire change: the RustFS
//! legacy stack writes every header its body sets (CORS, MinIO restore, additional checksums), and
//! the migration rule is that the gateway stack answers the same. Dropping one would pass every
//! test that does not look for it. Refusing makes the conflict a `500` the adapter's own tests see.
//!
//! # Why the encoder's headers win
//!
//! A header the encoder wrote is an output member: its value was validated against the model, and
//! a second value from the handler would be two answers to one question. Replacing it would let the
//! extra path launder a value the typed path would refuse.

use http::{HeaderMap, HeaderName};

use crate::op::Operation;
use crate::{CodecError, EncodedResponse, Resp};

/// Response header names the gateway alone writes, whatever the operation.
///
/// Framing and connection management (a handler that could write them could desynchronise the
/// connection), the four the service stamps on every response (`Date`, `Server`, the request id and
/// the host id), and the two authentication challenges and session cookies no S3 answer carries.
pub const OWNED_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "date",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "server",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "www-authenticate",
    "x-amz-id-2",
    "x-amz-request-id",
];

/// Whether the gateway alone writes `name` on a response.
#[must_use]
pub fn is_owned_response_header(name: &HeaderName) -> bool {
    OWNED_RESPONSE_HEADERS.contains(&name.as_str())
}

impl<O: Operation> Resp<O> {
    /// Adds response headers the operation's output cannot express (rustfs/gateway#1018).
    ///
    /// For a backend whose own answer carries headers no output member holds — per-bucket CORS,
    /// MinIO restore dates, additional checksums — and which must reach the client exactly as the
    /// backend wrote them. They are appended after the encoder's headers, every value kept; calling
    /// this twice appends both sets.
    ///
    /// The floor is not negotiable, and a conflict is a `500` rather than a silent drop: the
    /// response is refused when a name is one the gateway owns
    /// ([`OWNED_RESPONSE_HEADERS`]: framing, `Date`, `Server`, the
    /// request and host ids, authentication challenges and cookies), when the encoder already wrote
    /// it (an output member is the typed answer to that question), or when the answer is committed
    /// or an event stream (its head is decided before these could be checked).
    #[must_use]
    pub fn with_extra_headers(mut self, headers: http::HeaderMap) -> Self {
        for (name, value) in &headers {
            self.extra_headers.append(name.clone(), value.clone());
        }
        self
    }

    /// The extra headers added so far.
    #[must_use]
    pub const fn extra_headers(&self) -> &http::HeaderMap {
        &self.extra_headers
    }
}

impl EncodedResponse {
    /// Appends a handler's extra response headers after the encoder's own.
    ///
    /// Every value of every name is appended as given; `HeaderValue` already refuses a line break,
    /// so no value can split the head.
    ///
    /// # Errors
    ///
    /// [`CodecError::internal`] when a name is [owned by the gateway](OWNED_RESPONSE_HEADERS) or
    /// was already written by the operation's encoder. Nothing is appended then: the response is
    /// refused whole rather than sent with some of the extra headers.
    pub fn append_extra_headers(&mut self, extra: HeaderMap) -> Result<(), CodecError> {
        for name in extra.keys() {
            if is_owned_response_header(name) {
                return Err(CodecError::internal("a handler's extra response header is one the gateway owns"));
            }
            if self.headers.contains_key(name) {
                return Err(CodecError::internal(
                    "a handler's extra response header was already written by the operation's encoder",
                ));
            }
        }
        for (name, value) in &extra {
            self.headers.append(name.clone(), value.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn encoded() -> EncodedResponse {
        let mut encoded = EncodedResponse::of(200);
        encoded.set_header("content-type", "application/xml");
        encoded.set_header("etag", "\"abc\"");
        encoded
    }

    fn extra(lines: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in lines {
            headers.append(HeaderName::from_static(name), HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn extra_headers_are_appended_after_the_encoders_with_every_value() {
        let mut response = encoded();
        let added = extra(&[
            ("access-control-allow-origin", "https://app.example"),
            ("vary", "Origin"),
            ("vary", "Access-Control-Request-Method"),
            ("x-amz-restore-request-date", "Fri, 02 Jan 2026 03:04:05 GMT"),
        ]);
        response
            .append_extra_headers(added)
            .expect("nothing owned or already written");
        let vary: Vec<_> = response.headers.get_all("vary").iter().collect();
        assert_eq!(vary, ["Origin", "Access-Control-Request-Method"]);
        assert_eq!(
            response.headers.get("access-control-allow-origin").map(HeaderValue::as_bytes),
            Some(&b"https://app.example"[..])
        );
        assert_eq!(response.headers.get("etag").map(HeaderValue::as_bytes), Some(&b"\"abc\""[..]));
        assert_eq!(response.headers.len(), 6);
    }

    #[test]
    fn no_extra_headers_leave_the_response_unchanged() {
        let mut response = encoded();
        response.append_extra_headers(HeaderMap::new()).expect("nothing to refuse");
        assert_eq!(response.headers, encoded().headers);
    }

    #[test]
    fn n_every_owned_name_is_refused_and_nothing_is_appended() {
        for name in OWNED_RESPONSE_HEADERS {
            let mut response = encoded();
            let mut added = extra(&[("x-amz-restore-expiry-days", "3")]);
            added.append(HeaderName::from_static(name), HeaderValue::from_static("1"));
            let refused = response.append_extra_headers(added);
            assert!(refused.is_err(), "{name} was admitted");
            assert_eq!(response.headers, encoded().headers, "{name}: a partial append");
        }
    }

    #[test]
    fn n_a_name_the_encoder_already_wrote_is_refused_whatever_its_value() {
        for (name, value) in [("etag", "\"abc\""), ("etag", "\"other\""), ("content-type", "text/plain")] {
            let mut response = encoded();
            let refused = response.append_extra_headers(extra(&[("vary", "Origin"), (name, value)]));
            assert!(refused.is_err(), "{name}: {value}");
            assert_eq!(response.headers, encoded().headers, "{name}: a partial append");
        }
    }

    #[test]
    fn n_the_owned_set_is_checked_by_name_not_by_prefix() {
        let mut response = encoded();
        response
            .append_extra_headers(extra(&[("x-amz-request-id-echo", "1"), ("content-length-hint", "2")]))
            .expect("neither is an owned name");
        assert!(!is_owned_response_header(&HeaderName::from_static("x-amz-checksum-crc32")));
        assert!(is_owned_response_header(&http::header::TRANSFER_ENCODING));
    }
}
