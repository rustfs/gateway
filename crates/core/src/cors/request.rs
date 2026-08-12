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

//! Which requests the CORS runtime is allowed to answer, decided from the head alone.
//!
//! Responsible for: [`classify`] — the three-way split between "this is a preflight", "this
//! claims to be a preflight and its own headers are unusable" and "this is an ordinary request"
//! — the ceilings that make the first two decidable in constant time, and the parsed
//! [`RequestedHeaders`] list a preflight carries.
//! NOT responsible for: reading any stored configuration, matching anything ([`super::rule`]),
//! or rendering an answer ([`super::answer`]). Nothing here awaits, allocates per request, or
//! looks at a body: it runs before the security floor, so a caller who has proved nothing must
//! not be able to make it do work.
//! Upstream: `rustfs-gateway-http`'s `HeaderView`. Downstream: the facade's preflight branch.
//!
//! # Why "malformed preflight" is its own answer and not a refusal to classify
//!
//! An `OPTIONS` with no `Origin` is not a CORS preflight at all — it is a request for the
//! server's own options, and the route table is entitled to answer it. An `OPTIONS` with two
//! `Origin` header lines *is* a preflight attempt, and letting it fall through to the route table
//! would answer a CORS question with a routing error. Worse, the two `Origin` values are the
//! request-smuggling shape of this feature: whichever one a downstream cache keyed on, the answer
//! it stores is the answer to the other. So it is refused here, with the same constant refusal
//! every other preflight failure gets, and it never reaches an operation.
//!
//! # The ceilings, and what each one is for
//!
//! [`MAX_ORIGIN_BYTES`] bounds the value that would otherwise be echoed into a response header.
//! [`MAX_REQUESTED_HEADERS`] and [`MAX_REQUESTED_HEADER_BYTES`] bound the list the matcher walks
//! once per rule: without them one request head buys a hundred rules times an unbounded list of
//! comparisons, which is the CPU half of the same amplifier the storage read is the I/O half of.

use http::{HeaderName, Method};
use rustfs_gateway_http::HeaderView;

use crate::contracts;

/// The header a browser puts the requesting origin in.
pub const ORIGIN: HeaderName = HeaderName::from_static("origin");
/// The preflight's statement of which method the real request will use.
pub const ACCESS_CONTROL_REQUEST_METHOD: HeaderName = HeaderName::from_static("access-control-request-method");
/// The preflight's statement of which headers the real request will carry.
pub const ACCESS_CONTROL_REQUEST_HEADERS: HeaderName = HeaderName::from_static("access-control-request-headers");

/// The longest `Origin` this runtime will consider. An origin is a scheme, a host and an optional
/// port; 2 KiB is far above any real one and far below anything worth echoing.
pub const MAX_ORIGIN_BYTES: usize = 2048;

/// The most header names one preflight may ask about.
pub const MAX_REQUESTED_HEADERS: usize = 64;

/// The longest single header name a preflight may ask about.
pub const MAX_REQUESTED_HEADER_BYTES: usize = 128;

/// The header names a preflight declared, already split and checked.
///
/// Borrowed from the request head rather than owned: this runs pre-authentication, and a type
/// that allocated per request would be a per-request cost an unauthenticated caller controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestedHeaders<'a> {
    raw: Option<&'a str>,
}

impl<'a> RequestedHeaders<'a> {
    /// The list a preflight that declared no headers carries.
    #[must_use]
    pub const fn empty() -> Self {
        Self { raw: None }
    }

    /// Splits and checks an `Access-Control-Request-Headers` value.
    ///
    /// A blank value is [`RequestedHeaders::empty`]: a browser that has nothing to declare and
    /// sends the header anyway is asking the same question as one that omits it.
    ///
    /// # Errors
    ///
    /// [`HeadersRejected`] when the list is longer than [`MAX_REQUESTED_HEADERS`], when a name is
    /// longer than [`MAX_REQUESTED_HEADER_BYTES`], when an element is empty — `a,,b` — or when a
    /// name is not an RFC 9110 field name. The names are compared against a stored rule and then
    /// written back into `Access-Control-Allow-Headers`, so anything that is not a field name is
    /// refused before either happens.
    pub fn parse(value: &'a str) -> Result<Self, HeadersRejected> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Ok(Self::empty());
        }
        let mut count = 0usize;
        for element in trimmed.split(',') {
            let name = element.trim();
            count += 1;
            if count > MAX_REQUESTED_HEADERS {
                return Err(HeadersRejected);
            }
            if name.is_empty() || name.len() > MAX_REQUESTED_HEADER_BYTES || !is_field_name(name) {
                return Err(HeadersRejected);
            }
        }
        Ok(Self { raw: Some(trimmed) })
    }

    /// The names, trimmed, in the order the caller wrote them.
    pub fn names(&self) -> impl Iterator<Item = &'a str> {
        self.raw.into_iter().flat_map(|raw| raw.split(',').map(str::trim))
    }

    /// Whether the preflight declared no header at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.raw.is_none()
    }
}

/// An `Access-Control-Request-Headers` value this runtime will not read.
///
/// Carries nothing: it is raised on the pre-authentication path, and a rejection that carried the
/// offending bytes would be a reflection surface for whoever sent them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadersRejected;

/// A recognised CORS preflight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreflightRequest<'a> {
    /// The `Origin` value, checked to be a plausible origin and short enough to echo.
    pub origin: &'a str,
    /// The method the real request will use, verbatim. Not checked against S3's closed set here:
    /// a method outside it simply matches no stored rule, which is the same refusal by a shorter
    /// road and one fewer place the set is written down.
    pub method: &'a str,
    /// The headers the real request will carry.
    pub headers: RequestedHeaders<'a>,
}

/// What the CORS runtime makes of one request head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreflightClass<'a> {
    /// Not a preflight. The pipeline continues; the route table answers it.
    NotPreflight,
    /// A preflight whose own headers cannot be read. Answered with the constant refusal, and
    /// never routed — see the module documentation for why falling through would be worse.
    Malformed,
    /// A preflight.
    Preflight(PreflightRequest<'a>),
}

/// Decides what one request head is, from the method and three headers.
///
/// The `Access-Control-Request-Method` header is what separates a preflight from a plain
/// `OPTIONS`; the Fetch Standard requires a browser to send both it and `Origin` on every
/// preflight, so requiring both is not a leniency to be tightened later.
#[must_use]
pub fn classify<'a>(method: &Method, headers: &HeaderView<'a>) -> PreflightClass<'a> {
    if method != Method::OPTIONS {
        return PreflightClass::NotPreflight;
    }
    let origin_lines = headers.count(&ORIGIN);
    let method_lines = headers.count(&ACCESS_CONTROL_REQUEST_METHOD);
    if origin_lines == 0 && method_lines == 0 {
        return if contracts::cors_bare_options_is_routed() {
            PreflightClass::NotPreflight
        } else {
            PreflightClass::Malformed
        };
    }
    // One of the two is present, so this is a preflight attempt and the answer is this runtime's
    // from here on. Everything below refuses rather than falling back to routing.
    if origin_lines == 0 || method_lines == 0 {
        return if contracts::cors_preflight_requires_both_headers() {
            PreflightClass::Malformed
        } else {
            PreflightClass::NotPreflight
        };
    }
    if contracts::cors_origin_requires_exactly_one() && origin_lines != 1
        || contracts::cors_request_method_requires_exactly_one() && method_lines != 1
        || contracts::cors_request_headers_allow_at_most_one() && headers.count(&ACCESS_CONTROL_REQUEST_HEADERS) > 1
    {
        return PreflightClass::Malformed;
    }
    let (Some(origin), Some(requested_method)) = (headers.get_str(&ORIGIN), headers.get_str(&ACCESS_CONTROL_REQUEST_METHOD))
    else {
        return PreflightClass::Malformed;
    };
    if !is_plausible_origin(origin) || !is_method_token(requested_method) {
        return PreflightClass::Malformed;
    }
    let headers = match headers.get_str(&ACCESS_CONTROL_REQUEST_HEADERS) {
        Some(value) => match RequestedHeaders::parse(value) {
            Ok(parsed) => parsed,
            Err(HeadersRejected) => return PreflightClass::Malformed,
        },
        None => RequestedHeaders::empty(),
    };
    PreflightClass::Preflight(PreflightRequest {
        origin,
        method: requested_method,
        headers,
    })
}

/// Whether a value is short enough and clean enough to be compared with a stored rule and then
/// written back into a response header.
///
/// Not a URL parse. What matters is that the bytes cannot become a second header line, cannot
/// carry a control character into a log, and are bounded — an origin that satisfies this and is
/// still nonsense simply matches no rule. `null` satisfies it, which is correct: `null` is the
/// origin a sandboxed document sends, and a rule may legitimately name it.
#[must_use]
pub fn is_plausible_origin(value: &str) -> bool {
    (!contracts::cors_origin_rejects_empty() || !value.is_empty())
        && contracts::cors_origin_max_bytes().is_none_or(|max| value.len() <= max)
        && (!contracts::cors_origin_requires_visible_ascii() || value.bytes().all(|byte| byte.is_ascii_graphic()))
}

/// Whether a value is an RFC 9110 method token.
fn is_method_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(is_tchar)
}

/// Whether a value is an RFC 9110 field name.
fn is_field_name(value: &str) -> bool {
    value.bytes().all(is_tchar)
}

/// RFC 9110 §5.6.2 `tchar`.
const fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use http::HeaderMap;

    /// An owned rendering of [`PreflightClass`], so a helper can build a header map, classify it
    /// and drop it without handing a borrow back to the caller.
    #[derive(Debug, PartialEq, Eq)]
    enum Class {
        NotPreflight,
        Malformed,
        Preflight {
            origin: String,
            method: String,
            headers: Vec<String>,
        },
    }

    fn classify_head(method: &Method, lines: &[(&'static str, &str)]) -> Class {
        let mut map = HeaderMap::new();
        for (name, value) in lines {
            map.append(HeaderName::from_static(name), http::HeaderValue::from_str(value).expect("a header value"));
        }
        match classify(method, &HeaderView::new(&map)) {
            PreflightClass::NotPreflight => Class::NotPreflight,
            PreflightClass::Malformed => Class::Malformed,
            PreflightClass::Preflight(request) => Class::Preflight {
                origin: request.origin.to_owned(),
                method: request.method.to_owned(),
                headers: request.headers.names().map(str::to_owned).collect(),
            },
        }
    }

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    /// Positive — the two headers a browser always sends make a preflight.
    #[test]
    fn origin_and_request_method_make_a_preflight() {
        assert_eq!(
            classify_head(
                &Method::OPTIONS,
                &[("origin", "https://a.invalid"), ("access-control-request-method", "PUT")],
            ),
            Class::Preflight {
                origin: "https://a.invalid".to_owned(),
                method: "PUT".to_owned(),
                headers: Vec::new(),
            }
        );
    }

    /// Positive — the declared header list is split, trimmed and kept in order.
    #[test]
    fn the_requested_header_list_is_split_and_trimmed() {
        let parsed = RequestedHeaders::parse(" x-amz-acl ,  x-amz-meta-a ").expect("a readable list");
        assert_eq!(parsed.names().collect::<Vec<_>>(), vec!["x-amz-acl", "x-amz-meta-a"]);
    }

    /// Positive — a header line that is present but blank asks the same question as an absent
    /// one.
    #[test]
    fn a_blank_requested_header_list_is_no_headers() {
        assert!(RequestedHeaders::parse("").expect("readable").is_empty());
        assert!(RequestedHeaders::parse("   ").expect("readable").is_empty());
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    /// Negative — a `GET` carrying an `Origin` is not a preflight. It is the ordinary request the
    /// browser makes after one, and it must be served.
    #[test]
    fn n_a_get_with_an_origin_is_not_a_preflight() {
        assert_eq!(classify_head(&Method::GET, &[("origin", "https://a.invalid")]), Class::NotPreflight);
        assert_eq!(classify_head(&Method::HEAD, &[("origin", "https://a.invalid")]), Class::NotPreflight);
    }

    /// Negative — an `OPTIONS` with neither header is not a preflight, so the route table answers
    /// it. Claiming it here would turn every `OPTIONS` into a CORS answer.
    #[test]
    fn n_a_bare_options_is_not_a_preflight() {
        assert_eq!(classify_head(&Method::OPTIONS, &[]), Class::NotPreflight);
    }

    /// Negative — half a preflight is a malformed preflight, not a routable request. Falling
    /// through would answer a CORS question with a 501.
    #[test]
    fn n_half_a_preflight_is_malformed() {
        assert_eq!(classify_head(&Method::OPTIONS, &[("origin", "https://a.invalid")]), Class::Malformed);
        assert_eq!(
            classify_head(&Method::OPTIONS, &[("access-control-request-method", "PUT")]),
            Class::Malformed
        );
    }

    /// Negative — two `Origin` lines are refused. Whichever one a shared cache keys on, the entry
    /// it stores answers the other.
    #[test]
    fn n_a_repeated_origin_is_refused() {
        assert_eq!(
            classify_head(
                &Method::OPTIONS,
                &[
                    ("origin", "https://a.invalid"),
                    ("origin", "https://evil.invalid"),
                    ("access-control-request-method", "GET"),
                ],
            ),
            Class::Malformed
        );
    }

    /// Negative — a repeated `Access-Control-Request-Method` or `-Headers` is refused for the
    /// same reason.
    #[test]
    fn n_a_repeated_request_method_or_header_list_is_refused() {
        assert_eq!(
            classify_head(
                &Method::OPTIONS,
                &[
                    ("origin", "https://a.invalid"),
                    ("access-control-request-method", "GET"),
                    ("access-control-request-method", "PUT"),
                ],
            ),
            Class::Malformed
        );
        assert_eq!(
            classify_head(
                &Method::OPTIONS,
                &[
                    ("origin", "https://a.invalid"),
                    ("access-control-request-method", "GET"),
                    ("access-control-request-headers", "x-a"),
                    ("access-control-request-headers", "x-b"),
                ],
            ),
            Class::Malformed
        );
    }

    /// Negative — an empty origin, one carrying a space, and one over the ceiling are all
    /// refused before anything can echo them.
    #[test]
    fn n_an_unusable_origin_is_refused() {
        assert!(!is_plausible_origin(""));
        assert!(!is_plausible_origin("https://a.invalid evil"));
        assert!(!is_plausible_origin(&"a".repeat(MAX_ORIGIN_BYTES + 1)));
        assert!(is_plausible_origin(&"a".repeat(MAX_ORIGIN_BYTES)));
        assert!(is_plausible_origin("null"));
    }

    /// Negative — an origin carrying a control character never reaches the matcher. `http`
    /// refuses CR and LF in a header value already; this is the second door, because the value
    /// is echoed into a response header and one door is not a control.
    #[test]
    fn n_a_control_character_in_an_origin_is_refused() {
        assert!(!is_plausible_origin("https://a.invalid\u{7f}"));
        assert!(!is_plausible_origin("https://a.invalid\t"));
    }

    /// Negative — an empty element in the requested header list is refused rather than skipped.
    /// `a,,b` is a client bug, and skipping it would make the echoed list disagree with the one
    /// that was checked.
    #[test]
    fn n_an_empty_element_in_the_header_list_is_refused() {
        assert_eq!(RequestedHeaders::parse("x-a,,x-b"), Err(HeadersRejected));
        assert_eq!(RequestedHeaders::parse(","), Err(HeadersRejected));
    }

    /// Negative — a requested header name that is not a field name is refused, so nothing that
    /// could split a header ever reaches `Access-Control-Allow-Headers`.
    #[test]
    fn n_a_non_token_header_name_is_refused() {
        assert_eq!(RequestedHeaders::parse("x-a: b"), Err(HeadersRejected));
        assert_eq!(RequestedHeaders::parse("x-a b"), Err(HeadersRejected));
        assert_eq!(RequestedHeaders::parse("x-a/b"), Err(HeadersRejected));
    }

    /// Negative — both list ceilings refuse rather than truncate, and both are inclusive.
    #[test]
    fn n_the_requested_header_ceilings_refuse() {
        let within = (0..MAX_REQUESTED_HEADERS)
            .map(|i| format!("x-{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(RequestedHeaders::parse(&within).is_ok());
        let over = (0..=MAX_REQUESTED_HEADERS)
            .map(|i| format!("x-{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(RequestedHeaders::parse(&over), Err(HeadersRejected));
        assert_eq!(RequestedHeaders::parse(&"x".repeat(MAX_REQUESTED_HEADER_BYTES + 1)), Err(HeadersRejected));
        assert!(RequestedHeaders::parse(&"x".repeat(MAX_REQUESTED_HEADER_BYTES)).is_ok());
    }

    /// Negative — a request method that is not a token is refused; it would otherwise be compared
    /// with a stored rule and, on a match, its bytes reflected.
    #[test]
    fn n_a_non_token_request_method_is_refused() {
        assert_eq!(
            classify_head(
                &Method::OPTIONS,
                &[("origin", "https://a.invalid"), ("access-control-request-method", "PU T")],
            ),
            Class::Malformed
        );
    }
}
