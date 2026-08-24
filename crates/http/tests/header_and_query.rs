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

//! Cases `c-wire-0005`, `0006`, `0040`..`0045`: header tolerance, header ambiguity, metadata
//! injection, and repeated query parameters.
//!
//! Responsible for: proving that an unrelated unreadable header is ignored while a significant
//! one is refused, that an empty header is legal, that repeats of single-valued names are
//! refused, and that a metadata value is validated again after decoding.
//! NOT responsible for: framing or host, which have their own suites.
//! Upstream: `support`. Downstream: nothing.

mod support;

use http::{HeaderName, Request, header::CONTENT_TYPE, header::HOST};
use rustfs_gateway_http::{
    CanonicalHeadersError, LimitKind, Limits, MetadataReject, SignedHeaderList, SignedHeadersError, WireReject,
    decode_metadata_value, encode_metadata_value, is_significant_header, validate_metadata_key, validate_metadata_value,
};
use support::{accept, accept_with, raw_value};

fn put(headers: Vec<(HeaderName, http::HeaderValue)>) -> Request<&'static str> {
    let mut request = Request::builder()
        .method("PUT")
        .uri("/bucket/key?uploads")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    for (name, value) in headers {
        request.headers_mut().append(name, value);
    }
    request
}

fn name(text: &'static str) -> HeaderName {
    HeaderName::from_static(text)
}

// ── positive ────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_wire_0005_an_unrelated_non_utf8_header_is_ignored_not_fatal() {
    // The production shape: a reverse proxy injects a tag whose bytes are not UTF-8, and every
    // PutObject behind it starts failing (s3s#597, rustfs#3124).
    let request = put(vec![(name("x-proxy-tag"), raw_value(&[0xC3, 0x28, 0xFF]))]);
    let accepted = accept(request).expect("an unrelated unreadable header must not fail the request");
    let readable: Vec<&str> = accepted.headers().iter_text().map(|(name, _)| name.as_str()).collect();
    assert!(readable.contains(&"host"));
    assert!(!readable.contains(&"x-proxy-tag"), "the unreadable header is skipped, not repaired");
    // And it is still there byte-for-byte for anything that wants the raw form.
    assert_eq!(accepted.headers().get_bytes(&name("x-proxy-tag")), Some(&[0xC3, 0x28, 0xFF][..]));
}

#[test]
fn c_wire_0006_an_empty_header_value_is_accepted() {
    let request = put(vec![(name("x-custom"), raw_value(b""))]);
    let accepted = accept(request).expect("an empty field value is legal (s3s#382)");
    assert_eq!(accepted.headers().get_str(&name("x-custom")), Some(""));
}

#[test]
fn c_wire_0151_boolean_headers_are_case_insensitive() {
    // The AWS CLI sends `True`; a case-sensitive parser refuses a request the SDKs consider well
    // formed (s3s#151).
    for (spelling, expected) in [
        ("true", true),
        ("True", true),
        ("TRUE", true),
        ("False", false),
        ("false", false),
    ] {
        let request = put(vec![(name("x-amz-bypass-governance-retention"), raw_value(spelling.as_bytes()))]);
        let accepted = accept(request).expect("valid fixture");
        assert_eq!(
            accepted.headers().bool_flag(&name("x-amz-bypass-governance-retention")),
            Ok(Some(expected)),
            "spelling {spelling}"
        );
    }
}

#[test]
fn an_absent_or_empty_boolean_header_is_none_rather_than_an_error() {
    let accepted = accept(put(vec![(name("x-amz-bypass-governance-retention"), raw_value(b""))])).expect("valid fixture");
    assert_eq!(accepted.headers().bool_flag(&name("x-amz-bypass-governance-retention")), Ok(None));
    assert_eq!(accepted.headers().bool_flag(&name("x-amz-mfa")), Ok(None));
}

/// c-fast-0006: canonical output follows the validated signed-name order without sorting.
#[test]
fn canonical_headers_are_written_without_sorting_anything() {
    let request = put(vec![
        (name("x-amz-date"), raw_value(b"20260805T000000Z")),
        (CONTENT_TYPE, raw_value(b"  text/plain   ; charset=utf-8  ")),
    ]);
    let accepted = accept(request).expect("valid fixture");
    let signed = SignedHeaderList::parse("content-type;host;x-amz-date").expect("ascending list");
    let mut out = String::new();
    accepted
        .headers()
        .write_canonical_headers_with_host(&signed, &"b.example.com", &mut out)
        .expect("every signed header is present and readable");
    assert_eq!(
        out,
        "content-type:text/plain ; charset=utf-8\nhost:b.example.com\nx-amz-date:20260805T000000Z\n"
    );
}

#[test]
fn canonical_values_collapse_whitespace_inside_a_quoted_string() {
    let request = put(vec![(name("x-amz-meta-note"), raw_value(b"a  \"b   c\"  d"))]);
    let accepted = accept(request).expect("valid fixture");
    let signed = SignedHeaderList::parse("host;x-amz-meta-note").expect("ascending list");
    let mut out = String::new();
    accepted
        .headers()
        .write_canonical_headers(&signed, &mut out)
        .expect("readable");
    assert_eq!(out, "host:b.example.com\nx-amz-meta-note:a \"b c\" d\n");
}

#[test]
fn canonical_headers_use_the_callers_effective_host() {
    let accepted = accept(put(vec![])).expect("valid fixture");
    let signed = SignedHeaderList::parse("host").expect("ascending list");
    let mut out = String::new();
    accepted
        .headers()
        .write_canonical_headers_with_host(&signed, &"authority.example.com:9443", &mut out)
        .expect("the caller supplies host");
    assert_eq!(out, "host:authority.example.com:9443\n");
}

/// c-fast-0007: repeated values retain their wire arrival order.
#[test]
fn a_repeated_multi_valued_header_is_joined_in_arrival_order() {
    let request = put(vec![
        (name("x-amz-checksum-algorithm"), raw_value(b"crc32")),
        (name("x-amz-checksum-algorithm"), raw_value(b"sha256")),
    ]);
    let accepted = accept(request).expect("this name has no single-valued semantics");
    let signed = SignedHeaderList::parse("host;x-amz-checksum-algorithm").expect("ascending list");
    let mut out = String::new();
    accepted
        .headers()
        .write_canonical_headers_with_host(&signed, &"b.example.com", &mut out)
        .expect("readable");
    assert_eq!(out, "host:b.example.com\nx-amz-checksum-algorithm:crc32,sha256\n");
}

#[test]
fn the_query_view_preserves_arrival_order_and_undecoded_values() {
    let request = Request::builder()
        .uri("/bucket?list-type=2&prefix=a%2Fb&delimiter=%2F&fetch-owner")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    let accepted = accept(request).expect("valid fixture");
    let query = accepted.query();
    assert_eq!(query.len(), 4);
    assert_eq!(query.get("prefix"), Some("a%2Fb"), "values stay encoded until decoded once");
    assert_eq!(query.get("fetch-owner"), Some(""), "a flag parameter has an empty value");
    let order: Vec<&str> = query.iter().map(|(name, _)| name).collect();
    assert_eq!(order, vec!["list-type", "prefix", "delimiter", "fetch-owner"]);
}

#[test]
fn c_wire_0044b_a_metadata_value_that_decodes_cleanly_is_accepted() {
    assert_eq!(validate_metadata_value(b"=?utf-8?B?aGVsbG8=?="), Ok(()));
    assert_eq!(validate_metadata_value(b"=?utf-8?Q?hello_world?="), Ok(()));
    assert_eq!(validate_metadata_value(b"plain text"), Ok(()));
    assert_eq!(validate_metadata_key("x-amz-meta-note"), Ok(()));
}

#[test]
fn c_wire_0044e_metadata_encoding_splits_only_at_unicode_boundaries() {
    let original = format!("prefix-{}-suffix", "\u{4e2d}\u{6587}".repeat(20));
    let encoded = encode_metadata_value(&original).expect("printable Unicode encodes");
    for word in encoded.split(' ') {
        assert!(word.len() <= 75, "RFC 2047 caps each encoded-word: {word}");
    }
    assert_eq!(decode_metadata_value(&encoded).as_deref(), Ok(original.as_str()));
}

#[test]
fn c_wire_0044f_q_and_latin1_metadata_decode_to_unicode() {
    assert_eq!(decode_metadata_value("=?ISO-8859-1?Q?caf=E9?=").as_deref(), Ok("café"));
    assert_eq!(decode_metadata_value("plain").as_deref(), Ok("plain"));
}

#[test]
fn the_raw_path_is_handed_over_undecoded() {
    let request = Request::builder()
        .uri("/bucket/a%2Fb%20c")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    let accepted = accept(request).expect("valid fixture");
    assert_eq!(accepted.raw_path().as_str(), "/bucket/a%2Fb%20c");
    assert!(!accepted.raw_path().is_root());
}

// ── negative ────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_wire_0040_a_repeated_authorization_header_is_rejected() {
    let request = put(vec![
        (name("authorization"), raw_value(b"AWS4-HMAC-SHA256 Credential=good")),
        (name("authorization"), raw_value(b"AWS4-HMAC-SHA256 Credential=evil")),
    ]);
    assert_eq!(accept(request).err(), Some(WireReject::DuplicateSingleValuedHeader("authorization")));
}

#[test]
fn c_wire_0041_a_repeated_content_sha256_header_is_rejected() {
    let request = put(vec![
        (name("x-amz-content-sha256"), raw_value(b"UNSIGNED-PAYLOAD")),
        (name("x-amz-content-sha256"), raw_value(b"STREAMING-AWS4-HMAC-SHA256-PAYLOAD")),
    ]);
    assert_eq!(
        accept(request).err(),
        Some(WireReject::DuplicateSingleValuedHeader("x-amz-content-sha256"))
    );
}

#[test]
fn c_ck_0028_a_repeated_trailer_declaration_is_rejected_before_the_body() {
    let request = put(vec![
        (name("x-amz-trailer"), raw_value(b"x-amz-checksum-crc32")),
        (name("x-amz-trailer"), raw_value(b"x-amz-checksum-sha256")),
    ]);
    assert_eq!(accept(request).err(), Some(WireReject::DuplicateSingleValuedHeader("x-amz-trailer")));
}

/// Negative — `range` is deliberately *not* single-valued, and this is the case that says so.
///
/// RFC 9110 §5.3 already defines what two field lines mean, and §14.2 already defines what a
/// `Range` the server cannot interpret produces: the whole representation. Refusing the pair here
/// answers `400` to a request the RFC says to serve, and it takes the decision away from the only
/// layer that can see the object (`c-range-0017`). Acceptance lets it through and the binding joins
/// it; the join is unparseable, which is the outcome — reached by one rule instead of two.
#[test]
fn n_a_repeated_range_header_is_accepted_and_joined_rather_than_refused() {
    assert!(
        !rustfs_gateway_http::SINGLE_VALUED_HEADERS.contains(&"range"),
        "a `Range` sent twice has an answer in RFC 9110; it is not two answers to one question"
    );
    let request = put(vec![
        (name("range"), raw_value(b"bytes=0-4")),
        (name("range"), raw_value(b"bytes=9-9")),
    ]);
    let accepted = accept(request).expect("two Range headers are served, not refused");
    assert!(
        accepted.headers().is_multi(&name("range")),
        "both field lines survive acceptance, for the binding to join and then refuse"
    );
}

#[test]
fn every_single_valued_header_is_refused_when_repeated() {
    for header in rustfs_gateway_http::SINGLE_VALUED_HEADERS {
        // `content-length` and `transfer-encoding` are caught one rule earlier, by framing.
        if *header == "content-length" || *header == "transfer-encoding" {
            continue;
        }
        let field = HeaderName::from_bytes(header.as_bytes()).expect("a valid header name");
        let request = put(vec![(field.clone(), raw_value(b"one")), (field, raw_value(b"two"))]);
        assert_eq!(
            accept(request).err(),
            Some(WireReject::DuplicateSingleValuedHeader(header)),
            "header {header}"
        );
    }
}

#[test]
fn c_wire_0042_a_repeated_single_valued_query_parameter_is_rejected() {
    let request = Request::builder()
        .uri("/bucket/key?versionId=v1&versionId=v2")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    assert_eq!(accept(request).err(), Some(WireReject::DuplicateSingleValuedQuery("versionId")));
}

#[test]
fn c_wire_0042b_two_identical_single_valued_query_parameters_are_also_rejected() {
    let request = Request::builder()
        .uri("/bucket/key?uploadId=abc&uploadId=abc")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    assert_eq!(accept(request).err(), Some(WireReject::DuplicateSingleValuedQuery("uploadId")));
}

#[test]
fn c_wire_0042c_a_percent_escaped_parameter_name_is_rejected() {
    // `%76ersionId` and `versionId` are one parameter with two spellings: a duplicate check that
    // runs before decoding and a lookup that runs after it would see different requests.
    let request = Request::builder()
        .uri("/bucket/key?versionId=v1&%76ersionId=v2")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    assert_eq!(accept(request).err(), Some(WireReject::AmbiguousQueryParameterName));
}

#[test]
fn c_wire_0043_a_signed_or_significant_header_with_non_utf8_bytes_is_rejected() {
    let request = put(vec![(name("x-amz-meta-foo"), raw_value(&[0xFF, 0xFE]))]);
    assert_eq!(
        accept(request).err(),
        Some(WireReject::NonUtf8SignificantHeader(name("x-amz-meta-foo"))),
        "an x-amz-* header must never take the ignore path"
    );
}

#[test]
fn c_wire_0043b_an_unreadable_header_that_is_signed_fails_canonicalisation() {
    // A header outside the significant set is accepted, but the moment the signature claims to
    // cover it the canonical request cannot be built over bytes nobody can read.
    let request = put(vec![(name("x-proxy-tag"), raw_value(&[0xFF]))]);
    let accepted = accept(request).expect("unrelated header, accepted");
    let signed = SignedHeaderList::parse("host;x-proxy-tag").expect("ascending list");
    let mut out = String::new();
    assert_eq!(
        accepted.headers().write_canonical_headers(&signed, &mut out),
        Err(CanonicalHeadersError::NonUtf8SignedHeader)
    );
}

/// c-fast-1007: supplying the effective host does not hide another missing signed header.
#[test]
fn a_signed_header_that_is_absent_fails_canonicalisation() {
    let accepted = accept(put(vec![])).expect("valid fixture");
    let signed = SignedHeaderList::parse("host;x-amz-date").expect("ascending list");
    let mut out = String::new();
    assert_eq!(
        accepted
            .headers()
            .write_canonical_headers_with_host(&signed, &"b.example.com", &mut out),
        Err(CanonicalHeadersError::MissingSignedHeader)
    );
}

/// c-fast-1005 and c-fast-1006: nonascending and repeated signed names are both rejected.
#[test]
fn a_signed_headers_list_that_is_not_strictly_ascending_is_rejected() {
    for (raw, expected) in [
        ("x-amz-date;host", SignedHeadersError::NotAscending),
        ("host;host", SignedHeadersError::NotAscending),
        ("Host;x-amz-date", SignedHeadersError::MalformedName),
        ("host;;x-amz-date", SignedHeadersError::MalformedName),
        ("host;x amz", SignedHeadersError::MalformedName),
        ("", SignedHeadersError::Empty),
        ("content-type;x-amz-date", SignedHeadersError::HostNotSigned),
    ] {
        assert_eq!(SignedHeaderList::parse(raw).err(), Some(expected), "list {raw:?}");
    }
}

#[test]
fn c_wire_0044_a_metadata_value_that_decodes_to_crlf_is_rejected() {
    // `DQo=` is base64 for CR LF. Nothing in the encoded form is a control character, which is
    // why validating only the encoded form is not enough.
    assert_eq!(
        validate_metadata_value(b"=?utf-8?B?DQo=?="),
        Err(MetadataReject::ControlCharacterAfterDecoding)
    );
    assert_eq!(
        validate_metadata_value(b"=?utf-8?Q?a=0D=0Ab?="),
        Err(MetadataReject::ControlCharacterAfterDecoding)
    );
    assert_eq!(
        validate_metadata_value(b"prefix =?iso-8859-1?B?DQo=?= suffix"),
        Err(MetadataReject::ControlCharacterAfterDecoding)
    );
}

#[test]
fn c_wire_0044b_a_metadata_value_whose_encoded_word_does_not_parse_is_rejected() {
    for value in [
        &b"=?utf-8?B?!!!!?="[..],
        b"=?utf-8?X?aGk=?=",
        b"=?utf-8?B?aGk=",
        b"=??B?aGk=?=",
        b"=?utf-8?Q?a=ZZ?=",
    ] {
        assert_eq!(
            validate_metadata_value(value),
            Err(MetadataReject::MalformedEncodedWord),
            "value {value:?}"
        );
    }
}

#[test]
fn c_wire_0044c_a_metadata_value_with_noncanonical_base64_is_rejected() {
    for value in [
        &b"=?utf-8?B?YQ=?="[..],
        b"=?utf-8?B?YQ===?=",
        b"=?utf-8?B?YR==?=",
        b"=?utf-8?B??=",
    ] {
        assert_eq!(
            validate_metadata_value(value),
            Err(MetadataReject::MalformedEncodedWord),
            "value {value:?}"
        );
    }
}

#[test]
fn c_wire_0044d_a_raw_or_encoded_tab_in_metadata_is_rejected() {
    assert_eq!(validate_metadata_value(b"before\tafter"), Err(MetadataReject::ControlCharacterInValue));
    assert_eq!(
        validate_metadata_value(b"=?utf-8?Q?before=09after?="),
        Err(MetadataReject::ControlCharacterAfterDecoding)
    );
    assert_eq!(
        validate_metadata_value(b"=?utf-8?B?CQ==?="),
        Err(MetadataReject::ControlCharacterAfterDecoding)
    );
}

#[test]
fn c_wire_0044g_unsupported_or_non_text_encoded_words_are_rejected() {
    for value in ["=?UTF-16?B?YQ==?=", "=?UTF-8?B?/w==?=", "=?US-ASCII?B?w6k=?="] {
        assert_eq!(decode_metadata_value(value), Err(MetadataReject::MalformedEncodedWord), "value {value:?}");
    }
}

#[test]
fn c_wire_0045_a_metadata_key_that_is_not_a_token_is_rejected() {
    for key in [
        "x-amz-meta-fo:o",
        "x-amz-meta-fo o",
        "x-amz-meta-fo\ro",
        "x-amz-meta-",
        "x-amz-metafoo",
        "foo",
    ] {
        assert_eq!(validate_metadata_key(key), Err(MetadataReject::MalformedKey), "key {key}");
    }
}

#[test]
fn a_control_character_in_a_field_value_is_refused_by_both_gates() {
    // The `http` crate refuses to build such a value at all, which is the first gate.
    assert!(http::HeaderValue::from_bytes(b"a\x01b").is_err());
    assert!(http::HeaderValue::from_bytes(b"a\r\nb").is_err());
    // The second gate is this crate's own, because a value can also be constructed in process and
    // the promise made here must not depend on which door the request came through.
    assert_eq!(validate_metadata_value(b"a\x01b"), Err(MetadataReject::ControlCharacterInValue));
    assert_eq!(validate_metadata_value(b"a\r\nb"), Err(MetadataReject::ControlCharacterInValue));
}

#[test]
fn a_metadata_header_that_decodes_to_crlf_is_rejected_at_acceptance() {
    let request = put(vec![(name("x-amz-meta-note"), raw_value(b"=?utf-8?B?DQo=?="))]);
    assert_eq!(
        accept(request).err(),
        Some(WireReject::MalformedMetadata(MetadataReject::ControlCharacterAfterDecoding))
    );
}

#[test]
fn the_header_count_and_byte_ceilings_are_enforced() {
    let limits = Limits {
        max_header_count: 3,
        ..Limits::default()
    };
    let request = put(vec![
        (name("x-one"), raw_value(b"1")),
        (name("x-two"), raw_value(b"2")),
        (name("x-three"), raw_value(b"3")),
    ]);
    assert_eq!(
        accept_with(request, &limits).err(),
        Some(WireReject::LimitExceeded(LimitKind::HeaderCount))
    );

    let byte_limits = Limits {
        max_header_bytes: 16,
        ..Limits::default()
    };
    let request = put(vec![(name("x-one"), raw_value(&[b'a'; 64]))]);
    assert_eq!(
        accept_with(request, &byte_limits).err(),
        Some(WireReject::LimitExceeded(LimitKind::HeaderBytes))
    );
}

#[test]
fn the_query_ceilings_are_enforced() {
    let limits = Limits {
        max_query_params: 2,
        ..Limits::default()
    };
    let request = Request::builder()
        .uri("/bucket?a=1&b=2&c=3")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    assert_eq!(
        accept_with(request, &limits).err(),
        Some(WireReject::LimitExceeded(LimitKind::QueryParams))
    );

    let byte_limits = Limits {
        max_query_bytes: 4,
        ..Limits::default()
    };
    let request = Request::builder()
        .uri("/bucket?prefix=aaaaaaaaaa")
        .header(HOST, "b.example.com")
        .body("")
        .expect("valid fixture request");
    assert_eq!(
        accept_with(request, &byte_limits).err(),
        Some(WireReject::LimitExceeded(LimitKind::QueryBytes))
    );
}

#[test]
fn the_significant_header_set_covers_the_whole_x_amz_family() {
    assert!(is_significant_header(&name("x-amz-meta-foo")));
    assert!(is_significant_header(&name("x-amz-content-sha256")));
    assert!(is_significant_header(&name("host")));
    assert!(is_significant_header(&name("authorization")));
    assert!(!is_significant_header(&name("x-proxy-tag")));
    assert!(!is_significant_header(&name("user-agent")));
}
