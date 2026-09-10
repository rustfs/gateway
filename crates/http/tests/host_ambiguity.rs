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

use crate::support::{absolute_form, accept, h2, origin_form, raw_value};
use http::{Request, StatusCode, Version, header::HOST};
use rustfs_gateway_http::{HostError, HostSource, Limits, MAX_HOST_BYTES, RawHost, WireReject, WireRequest};

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
fn c_wire_0004_authority_and_host_agreeing_byte_for_byte_is_accepted() {
    let accepted = accept(h2(Some("B.Example.COM"), Some("B.Example.COM"))).expect("byte-identical agreement");
    assert_eq!(accepted.host().as_str(), "b.example.com");
    assert_eq!(accepted.host().raw_for_signing().as_str(), "B.Example.COM");
    // When both sources are present the header's bytes are the ones kept, so that is the source
    // recorded: the signature covered the `Host` header, and an audit record that named the
    // authority instead would be naming bytes nobody signed.
    assert_eq!(accepted.host().raw_for_signing().source(), HostSource::HostHeader);
}

#[test]
fn c_wire_0004b_a_raw_host_can_be_built_from_either_source_and_is_never_normalised() {
    // `RawHost` is what `rustfs-gateway-sig` builds a canonical request from, and it is public so
    // that a layer already holding one host can spell the signer's argument. It applies the same
    // grammar `accept` does, and it changes nothing about the bytes.
    for spelling in ["EXAMPLE.COM", "example.com.", "example.com:443", "example.com"] {
        let from_header = RawHost::from_host_header(spelling.as_bytes()).expect("a valid authority");
        assert_eq!(from_header.as_str(), spelling, "nothing may be normalised");
        assert_eq!(from_header.source(), HostSource::HostHeader);
        assert_eq!(from_header.to_string(), spelling);

        let from_authority = RawHost::from_authority(spelling).expect("a valid authority");
        assert_eq!(from_authority.as_bytes(), from_header.as_bytes());
        // The source is part of the value: the two sources are signed and trusted differently.
        assert_ne!(from_authority, from_header);
        assert_eq!(from_authority.source(), HostSource::Authority);
    }
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
fn c_wire_0038b_authority_and_host_differing_only_in_case_agree() {
    // Host names are case-insensitive, so these are one host, not two: the difference cannot
    // point at a different bucket or a different origin. Refusing it would only break a
    // deployment behind a case-normalising proxy. Non-ASCII never reaches the comparison, so
    // there is no IDN folding hiding behind the case fold.
    let accepted = accept(h2(Some("B.Example.COM"), Some("b.example.com"))).expect("one host");
    // The header's bytes are the ones kept, because that is what the signature covered.
    assert_eq!(accepted.host().raw_for_signing().as_bytes(), b"b.example.com");

    let accepted = accept(h2(Some("b.example.com"), Some("B.Example.COM"))).expect("one host");
    assert_eq!(accepted.host().raw_for_signing().as_bytes(), b"B.Example.COM");
}

#[test]
fn c_wire_0038c_a_trailing_dot_or_an_explicit_port_is_still_a_conflict() {
    // Unlike case, these change the bytes the signature was computed over, and `b.example.com`
    // versus `b.example.com:443` is a genuine disagreement about the authority.
    assert_eq!(host_error(h2(Some("b.example.com"), Some("b.example.com."))), HostError::Conflict);
    assert_eq!(host_error(h2(Some("b.example.com"), Some("b.example.com:443"))), HostError::Conflict);
}

#[test]
fn c_wire_0038c_a_malformed_host_beside_a_valid_authority_is_invalid_not_conflict() {
    // Both are a 400, so nothing is admitted either way; the point is that the header is validated
    // before the comparison, so no value reaches the comparison unvalidated and the log names the
    // fault that is actually present.
    assert_eq!(host_error(h2(Some("b.example.com"), Some("user@b.example.com"))), HostError::Invalid);
    assert_eq!(host_error(h2(Some("b.example.com"), Some(""))), HostError::Invalid);
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
fn c_wire_0039g_the_host_ceiling_is_the_stricter_of_the_two_merged_ones() {
    // 263: the DNS name ceiling of 255, plus room for `:65535` and a trailing dot. The wire draft
    // carried 273; nothing legitimate lives between the two numbers, and a host is an input to the
    // canonical request, so the tighter bound is the one that limits what a peer can inflate.
    assert_eq!(MAX_HOST_BYTES, 263);
    assert!(RawHost::from_host_header(&[b'a'; MAX_HOST_BYTES]).is_ok());
    assert_eq!(RawHost::from_host_header(&[b'a'; MAX_HOST_BYTES + 1]), Err(HostError::Invalid));
    let at_ceiling = "a".repeat(MAX_HOST_BYTES);
    let request = Request::builder()
        .uri("/object.txt")
        .header(HOST, &at_ceiling)
        .body("")
        .expect("valid fixture request");
    assert_eq!(accept(request).expect("a host at the ceiling is accepted").host().as_str(), at_ceiling);
}

#[test]
fn every_host_rejection_names_itself_and_quotes_no_byte_of_the_request() {
    // The reason strings are what an operator reads. They are constants, so a host carrying a
    // control character or somebody else's bucket name cannot reach a log line through this path.
    assert_eq!(HostError::HTTP_STATUS, 400);
    for error in [
        HostError::Missing,
        HostError::Duplicate,
        HostError::Conflict,
        HostError::Invalid,
    ] {
        assert!(!error.as_str().is_empty());
        assert!(!error.reason().is_empty());
        assert_eq!(format!("{error}"), error.reason());
    }
    assert_eq!(HostError::Duplicate.as_str(), "duplicate");
    assert_eq!(HostSource::HostHeader.to_string(), "host-header");
    assert_eq!(HostSource::Authority.to_string(), "authority");
}

#[test]
fn every_host_rejection_is_four_hundred_and_keeps_the_connection() {
    for error in [
        HostError::Missing,
        HostError::Duplicate,
        HostError::Conflict,
        HostError::Invalid,
    ] {
        let reject = WireReject::Host(error);
        assert_eq!(reject.to_status(), StatusCode::BAD_REQUEST, "{error:?}");
        // A host verdict is a statement about the head. The body's framing is untouched and its
        // extent is known, so RFC 9112 §9.3's first branch applies: drain it and the connection
        // survives. This used to assert the opposite, and could not have failed either way —
        // both methods returned a constant.
        assert!(!reject.must_close_connection(), "{error:?}");
        assert!(reject.may_read_body(), "{error:?}");
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
