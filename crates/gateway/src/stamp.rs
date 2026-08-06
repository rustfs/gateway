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

//! The four headers every response carries because the framework put them there.
//!
//! Responsible for: [`stamp`] — the one site that writes `x-amz-request-id`, `x-amz-id-2`, `Server`
//! and `Date`, on the success path and the refusal path alike — and [`is_reserved`], the predicate
//! that refuses anything else the same names.
//! NOT responsible for: minting the identifiers (`crate::trace`), reading the clock
//! (`crate::clock`; this module is handed one reading and cannot take another), or any header an
//! operation declares — those are the generated encoder's.
//! Upstream: `crate::trace`, `crate::clock`, `rustfs-gateway-types`. Downstream: `crate::service`,
//! which calls this once per request, and `crate::render`, which consults [`is_reserved`].
//!
//! # Why these four are one function
//!
//! They share a property that nothing else in a response has: **their value is a fact about the
//! service, not about the answer.** Who answered, when, and under which identifier are questions
//! the framework can always answer and a backend can only get wrong — a backend-chosen
//! `x-amz-request-id` makes two requests claim one identity, and a backend-chosen `Date` makes a
//! cache and an audit log disagree about when something happened. Writing them in one place is what
//! makes "the framework guarantees these" a property of the code rather than a promise in a
//! document, and it is what gives [`is_reserved`] a single list to be the complement of.
//!
//! `insert` rather than `append`, for `crate::trace`'s reason: a response carrying two of any of
//! these is a response an intermediary is free to pick either half of.
//!
//! # Why `Date` comes from the clock abstraction
//!
//! Reading the system clock here would make every conformance case that pins `[clock] fixed`
//! irreproducible in exactly one header, and a case cannot assert on a value that moves. The
//! reading arrives as a parameter, taken once at the top of the pipeline beside the one minting of
//! the identifiers, so the `Date` a caller receives is the same instant the signature's skew window
//! was judged against.

use http::header::{DATE, HeaderMap, HeaderName, HeaderValue, SERVER};
use rustfs_gateway_sig::RequestNow;
use rustfs_gateway_types::{Timestamp, TimestampFormat};

use crate::trace::{HOST_ID_HEADER, REQUEST_ID_HEADER, RequestTrace};

/// What this service calls itself in a `Server` header.
///
/// # Security
///
/// A product name and nothing else: no version, no build, no operating system. A version here is a
/// vulnerability-scanner's first hit and buys a caller nothing it cannot learn from behaviour, so
/// the field is deliberately unhelpful.
pub(crate) const SERVER_NAME: &str = "RustFS";

/// The headers `stamp` writes, and the two the error renderer owns.
///
/// The complement of what a backend may set on a refusal: `rustfs_gateway_core::ErrorHeader` cannot
/// *name* any of these — the closed set has no variant for them — and this predicate is the second
/// lock, so that widening that set by accident cannot silently hand a backend one of them.
/// `Content-Type` and `Content-Length` are here because on a refusal they describe the `<Error>`
/// document the renderer just built; a backend that changed either would produce a body length no
/// client could read the document by.
pub(crate) fn is_reserved(name: &HeaderName) -> bool {
    *name == REQUEST_ID_HEADER
        || *name == HOST_ID_HEADER
        || *name == SERVER
        || *name == DATE
        || *name == http::header::CONTENT_TYPE
        || *name == http::header::CONTENT_LENGTH
}

/// Writes the four framework-guaranteed headers into a response head.
///
/// Called once per request, at the top level, over whatever the pipeline produced — so it is the
/// last writer, and an encoder or a backend that wrote one of these loses.
pub(crate) fn stamp(headers: &mut HeaderMap, trace: &RequestTrace, now: RequestNow) {
    trace.apply(headers);
    headers.insert(SERVER, HeaderValue::from_static(SERVER_NAME));
    if let Some(value) = http_date(now) {
        headers.insert(DATE, value);
    }
}

/// The reading as an RFC 9110 §5.6.7 `IMF-fixdate`, or nothing when it cannot be one.
///
/// Nothing rather than a placeholder: RFC 9110 §6.6.1 requires the header from an origin server
/// that has a usable clock, and a reading outside the four-digit year range the wire format can
/// express is a clock that is not usable. A malformed `Date` is worse than an absent one — caches
/// and SDKs parse it, and a value they cannot parse is a value they may substitute their own for.
fn http_date(now: RequestNow) -> Option<HeaderValue> {
    let text = Timestamp::from_secs(now.unix_seconds())
        .render(TimestampFormat::HttpDate)
        .ok()?;
    HeaderValue::from_str(&text).ok()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn trace() -> RequestTrace {
        RequestTrace::from_bits(0x0123_4567_89AB_CDEF, 0)
    }

    fn stamped(now: i64) -> HeaderMap {
        let mut headers = HeaderMap::new();
        stamp(&mut headers, &trace(), RequestNow::from_unix_seconds(now));
        headers
    }

    /// Positive — all four headers arrive, and the date is the instant the clock was read at rather
    /// than the instant this test ran.
    #[test]
    fn every_response_carries_the_four_headers() {
        let headers = stamped(1_767_323_045); // 2026-01-02T03:04:05Z, the instant the cases pin.
        assert_eq!(headers.get(REQUEST_ID_HEADER).map(HeaderValue::as_bytes), Some(&b"0123456789ABCDEF"[..]));
        assert!(headers.contains_key(HOST_ID_HEADER));
        assert_eq!(headers.get(SERVER).map(HeaderValue::as_bytes), Some(&b"RustFS"[..]));
        assert_eq!(headers.get(DATE).map(HeaderValue::as_bytes), Some(&b"Fri, 02 Jan 2026 03:04:05 GMT"[..]));
    }

    /// Negative — a value already in the map is replaced, not joined. This is the assertion that an
    /// encoder or a backend cannot make a response carry two dates or two identifiers.
    #[test]
    fn a_value_already_present_is_replaced_rather_than_appended() {
        let mut headers = HeaderMap::new();
        headers.insert(SERVER, HeaderValue::from_static("SomethingElse"));
        headers.insert(DATE, HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"));
        headers.append(REQUEST_ID_HEADER, HeaderValue::from_static("CALLERCHOSEN0000"));
        stamp(&mut headers, &trace(), RequestNow::from_unix_seconds(1_767_323_045));
        assert_eq!(headers.get_all(SERVER).iter().count(), 1);
        assert_eq!(headers.get_all(DATE).iter().count(), 1);
        assert_eq!(headers.get_all(REQUEST_ID_HEADER).iter().count(), 1);
        assert_eq!(headers.get(SERVER).map(HeaderValue::as_bytes), Some(&b"RustFS"[..]));
        assert_ne!(headers.get(DATE).map(HeaderValue::as_bytes), Some(&b"Thu, 01 Jan 1970 00:00:00 GMT"[..]));
    }

    /// Negative — the same clock reading gives the same header twice, which is what lets a case pin
    /// a `Date` at all. A second reading of a system clock would not.
    #[test]
    fn one_reading_renders_one_value() {
        assert_eq!(stamped(1_767_323_045).get(DATE), stamped(1_767_323_045).get(DATE));
        assert_ne!(stamped(1_767_323_045).get(DATE), stamped(1_767_323_046).get(DATE));
    }

    /// Negative — the server name says nothing about the build. A version here is a scanner's first
    /// hit, and this assertion is what stops one being added "for support".
    #[test]
    fn the_server_name_carries_no_version() {
        assert!(!SERVER_NAME.contains(char::is_numeric), "{SERVER_NAME}");
        assert!(!SERVER_NAME.contains('/'), "{SERVER_NAME}");
    }

    /// Negative — a reading the wire format cannot express produces no header rather than a
    /// malformed one. A `Date` a cache cannot parse is a `Date` it may replace with its own.
    #[test]
    fn an_unrenderable_reading_omits_the_header_rather_than_writing_a_bad_one() {
        assert!(http_date(RequestNow::from_unix_seconds(i64::MAX)).is_none());
        assert!(http_date(RequestNow::from_unix_seconds(i64::MIN)).is_none());
        assert!(!stamped(i64::MAX).contains_key(DATE));
        // The other three do not depend on the clock, so they are still there.
        assert!(stamped(i64::MAX).contains_key(SERVER));
        assert!(stamped(i64::MAX).contains_key(REQUEST_ID_HEADER));
    }

    /// Negative — every header this module writes is reserved, so the two lists cannot drift into a
    /// state where the framework stamps a header a backend is also allowed to set.
    #[test]
    fn everything_this_module_writes_is_reserved() {
        for name in stamped(1_767_323_045).keys() {
            assert!(is_reserved(name), "{name} is stamped but not reserved");
        }
    }

    /// Negative — the reserved set covers the error document's own framing headers too, and does
    /// not cover a header a backend legitimately sets on a refusal.
    #[test]
    fn the_reserved_set_is_the_complement_of_what_a_backend_may_set() {
        for name in [
            http::header::CONTENT_TYPE,
            http::header::CONTENT_LENGTH,
            REQUEST_ID_HEADER,
            HOST_ID_HEADER,
            SERVER,
            DATE,
        ] {
            assert!(is_reserved(&name), "{name}");
        }
        for name in [http::header::CONTENT_RANGE, http::header::RETRY_AFTER, http::header::ETAG] {
            assert!(!is_reserved(&name), "{name}");
        }
    }

    /// Negative — no variant of the backend-settable set is reserved. The two closed sets live in
    /// different crates, and this is the assertion that joins them: widening
    /// `rustfs_gateway_core::ErrorHeader` with a header the framework stamps goes red here.
    #[test]
    fn no_backend_settable_header_is_a_reserved_one() {
        for header in [
            rustfs_gateway_core::ErrorHeader::UnsatisfiedRange { complete_length: 1 },
            rustfs_gateway_core::ErrorHeader::RetryAfter { seconds: 1 },
        ] {
            assert!(!is_reserved(&header.name()), "{}", header.name());
        }
    }
}
