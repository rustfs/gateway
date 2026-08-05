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

//! Cases `c-wire-0001`..`0004`, `0007` and `0033`..`0039`: the six ways a request can be
//! ambiguous about which host it is for.
//!
//! Responsible for: proving that each row of the decision table in `host.rs` is decided the way
//! it is documented, and that a malformed host is a `400` rather than a `403`.
//! NOT responsible for: framing (`framing_smuggling.rs`) or header hygiene
//! (`header_and_query.rs`).
//! Upstream: `support`. Downstream: nothing.
//!
//! Six of these shapes are answered `200` by a bare hyper server, which performs no `Host`
//! validation of any kind. Every one of them is refused here.

mod support;

use http::{Request, StatusCode, Version, header::HOST};
use s3gate_http::{HostError, HostSource, Limits, WireReject, WireRequest};
use support::{absolute_form, accept, h2, origin_form, raw_value};

fn host_error(request: Request<&'static str>) -> HostError {
    match accept(request) {
        Err(WireReject::Host(error)) => error,
        other => panic!("expected a host rejection, got {other:?}"),
    }
}

// ── positive ────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_wire_0001_origin_form_with_host_header_is_accepted() {
    let accepted = accept(origin_form("/object.txt")).expect("origin form is the common case");
    assert_eq!(accepted.host().as_str(), "b.example.com");
    assert_eq!(accepted.host().source(), HostSource::HostHeader);
    assert_eq!(accepted.host().raw_for_signing().as_bytes(), b"b.example.com");
}

#[test]
fn c_wire_0002_http2_authority_without_host_header_is_accepted() {
    let accepted = accept(h2(Some("b.example.com"), None)).expect("authority alone is a complete host");
    assert_eq!(accepted.host().as_str(), "b.example.com");
    assert_eq!(accepted.host().source(), HostSource::Authority);
}

#[test]
fn c_wire_0003_http2_host_header_without_authority_is_accepted() {
    // RFC 9113 §8.3.1 permits this shape, and hyper reports no authority and no scheme for it.
    let accepted = accept(h2(None, Some("only.example.com"))).expect("host header alone is legal on h2");
    assert_eq!(accepted.host().as_str(), "only.example.com");
    assert_eq!(accepted.host().source(), HostSource::HostHeader);
}

#[test]
fn c_wire_0004_authority_and_host_agreeing_case_insensitively_is_accepted() {
    let accepted = accept(h2(Some("B.Example.COM"), Some("b.example.com"))).expect("case-insensitive agreement");
    assert_eq!(accepted.host().as_str(), "b.example.com");
    assert_eq!(accepted.host().raw_for_signing().as_str(), "B.Example.COM");
}

#[test]
fn c_wire_0007_routing_and_signing_read_the_same_stored_host() {
    let request = Request::builder()
        .uri("/object.txt")
        .header(HOST, "B.Example.com.:443")
        .body("")
        .expect("valid fixture request");
    let accepted = accept(request).expect("a default port is not an ambiguity");
    assert_eq!(accepted.host().as_str(), "b.example.com:443");
    assert_eq!(accepted.host().host_without_port(), "b.example.com");
    assert_eq!(accepted.host().port(), Some(443));
    // The signer sees the bytes as sent, trailing dot and original case intact; anything else
    // would make several spellings share one signature.
    assert_eq!(accepted.host().raw_for_signing().as_str(), "B.Example.com.:443");
}

#[test]
fn c_wire_0007b_ipv6_literal_with_port_keeps_its_brackets() {
    let request = Request::builder()
        .uri("/object.txt")
        .header(HOST, "[2001:DB8::1]:9000")
        .body("")
        .expect("valid fixture request");
    let accepted = accept(request).expect("a bracketed literal is a valid authority");
    assert_eq!(accepted.host().host_without_port(), "[2001:db8::1]");
    assert_eq!(accepted.host().port(), Some(9000));
}

// ── negative ────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_wire_0033_missing_host_is_rejected() {
    let request = Request::builder().uri("/object.txt").body("").expect("valid fixture request");
    assert_eq!(host_error(request), HostError::Missing);
}

#[test]
fn c_wire_0034_empty_host_is_rejected() {
    let request = Request::builder()
        .uri("/object.txt")
        .header(HOST, "")
        .body("")
        .expect("valid fixture request");
    assert_eq!(host_error(request), HostError::Invalid);
}

#[test]
fn c_wire_0035_two_conflicting_host_headers_are_rejected() {
    let request = Request::builder()
        .uri("/object.txt")
        .header(HOST, "a.example.com")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    assert_eq!(host_error(request), HostError::Duplicate);
}

#[test]
fn c_wire_0036_two_identical_host_headers_are_also_rejected() {
    let request = Request::builder()
        .uri("/object.txt")
        .header(HOST, "b.example.com")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    assert_eq!(host_error(request), HostError::Duplicate);
}

#[test]
fn c_wire_0037_absolute_form_disagreeing_with_host_header_is_rejected() {
    // A bare hyper server answers this 200 while reporting two different hosts to two different
    // accessors. It is the cheapest signature-bypass shape there is.
    let request = absolute_form("http://good.example.com/object.txt", "evil.example.com");
    assert_eq!(host_error(request), HostError::Conflict);
}

#[test]
fn c_wire_0038_http2_authority_disagreeing_with_host_header_is_rejected() {
    assert_eq!(host_error(h2(Some("good.example.com"), Some("evil.example.com"))), HostError::Conflict);
}

#[test]
fn c_wire_0039_non_ascii_host_is_rejected_as_invalid_not_forbidden() {
    let mut request = Request::builder().uri("/object.txt").body("").expect("valid fixture request");
    request.headers_mut().insert(HOST, raw_value("bücket.example.com".as_bytes()));
    let reject = accept(request).expect_err("a non-ASCII host has no single interpretation");
    assert_eq!(reject, WireReject::Host(HostError::Invalid));
    // A `403` here would file a malformed request next to a failed signature in every log.
    assert_eq!(reject.to_status(), StatusCode::BAD_REQUEST);
}

#[test]
fn c_wire_0039b_host_with_userinfo_is_rejected() {
    let request = Request::builder()
        .uri("/object.txt")
        .header(HOST, "user@b.example.com")
        .body("")
        .expect("valid fixture request");
    assert_eq!(host_error(request), HostError::Invalid);
}

#[test]
fn c_wire_0039c_host_with_a_malformed_port_is_rejected() {
    for spelling in [
        "b.example.com:",
        "b.example.com:99999",
        "b.example.com:80a",
        "b.example.com:+80",
    ] {
        let request = Request::builder()
            .uri("/object.txt")
            .header(HOST, spelling)
            .body("")
            .expect("valid fixture request");
        assert_eq!(host_error(request), HostError::Invalid, "spelling {spelling}");
    }
}

#[test]
fn c_wire_0039d_host_with_an_empty_label_is_rejected() {
    for spelling in [".example.com", "a..example.com"] {
        let request = Request::builder()
            .uri("/object.txt")
            .header(HOST, spelling)
            .body("")
            .expect("valid fixture request");
        assert_eq!(host_error(request), HostError::Invalid, "spelling {spelling}");
    }
}

#[test]
fn c_wire_0039e_over_long_host_is_refused_by_the_limit() {
    let long = format!("{}.example.com", "a".repeat(300));
    let request = Request::builder()
        .uri("/object.txt")
        .header(HOST, long)
        .body("")
        .expect("valid fixture request");
    // The host validator's own ceiling fires before the configured limit does, and both are 400.
    assert_eq!(host_error(request), HostError::Invalid);
}

#[test]
fn c_wire_0039f_asterisk_form_target_is_rejected_before_the_host_is_read() {
    let request = Request::builder()
        .method("OPTIONS")
        .uri("*")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    assert_eq!(accept(request).err(), Some(WireReject::MalformedRequestTarget));
}

#[test]
fn every_host_rejection_is_four_hundred_and_closes_the_connection() {
    for error in [
        HostError::Missing,
        HostError::Duplicate,
        HostError::Conflict,
        HostError::Invalid,
    ] {
        let reject = WireReject::Host(error);
        assert_eq!(reject.to_status(), StatusCode::BAD_REQUEST, "{error:?}");
        assert!(reject.must_close_connection(), "{error:?}");
        assert!(!reject.may_read_body(), "{error:?}");
    }
}

#[test]
fn http_one_one_and_http_two_agree_on_every_host_verdict() {
    // The same ambiguity must not be fatal on one version and tolerated on the other; a peer that
    // can choose its version would otherwise choose the tolerant one.
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let request = Request::builder()
            .version(version)
            .uri("/object.txt")
            .header(HOST, "a.example.com")
            .header(HOST, "b.example.com")
            .body("")
            .expect("valid fixture request");
        assert_eq!(
            WireRequest::accept(request, &Limits::default()).err(),
            Some(WireReject::Host(HostError::Duplicate)),
            "{version:?}"
        );
    }
}
