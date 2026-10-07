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

//! The canonical request's own unit suite, moved out of `canonical.rs` unchanged.
//!
//! Responsible for: the canonical request and string-to-sign rules decidable from the module's
//! private items.
//! NOT responsible for: whole-request verification, which is `crates/sig/tests/`.
//! Upstream: `super`. Downstream: Cargo's test harness.

use super::*;
use crate::mode::PayloadMode;

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("test header name");
        map.append(name, value.parse().expect("test header value"));
    }
    map
}

fn host() -> RawHost {
    RawHost::from_host_header(b"example.amazonaws.com").expect("valid")
}

#[test]
fn the_vanilla_canonical_request_is_byte_exact() {
    let map = headers(&[("x-amz-date", "20150830T123600Z")]);
    let signed = SignedHeaderSet::parse_and_enforce("host;x-amz-date", &map, None).expect("valid");
    let paths = UriPathCandidates::new("/").expect("valid");
    let query = RawQuery::new("");
    let host = host();
    let spec = CanonicalRequestSpec::new(
        &Method::GET,
        &paths,
        &query,
        &map,
        &signed,
        &host,
        PayloadMode::Empty.canonical_payload_token(),
    );
    let mut candidates = spec.candidates().expect("built");
    assert_eq!(candidates.len(), 1);
    let request = candidates.next().expect("one candidate");
    assert_eq!(
        request.text(),
        concat!(
            "GET\n",
            "/\n",
            "\n",
            "host:example.amazonaws.com\n",
            "x-amz-date:20150830T123600Z\n",
            "\n",
            "host;x-amz-date\n",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
    );
    assert_eq!(request.path_candidate(), PathCandidate::Decoded);
}

#[test]
fn whitespace_is_trimmed_and_collapsed_including_inside_quotes() {
    let map = headers(&[("x-amz-meta-note", "  value1  \"a     b    c\"  value3  ")]);
    let signed = SignedHeaderSet::parse_and_enforce("host;x-amz-meta-note", &map, None).expect("valid");
    let paths = UriPathCandidates::new("/").expect("valid");
    let query = RawQuery::new("");
    let host = host();
    let spec = CanonicalRequestSpec::new(
        &Method::GET,
        &paths,
        &query,
        &map,
        &signed,
        &host,
        PayloadMode::Empty.canonical_payload_token(),
    );
    let request = spec.candidates().expect("built").next().expect("one");
    assert!(request.text().contains("x-amz-meta-note:value1 \"a b c\" value3\n"));
}

#[test]
fn a_repeated_header_joins_with_commas_in_arrival_order() {
    let map = headers(&[
        ("my-header1", "value4"),
        ("my-header1", "value1"),
        ("my-header1", "value3"),
        ("x-amz-date", "20150830T123600Z"),
    ]);
    let signed = SignedHeaderSet::parse_and_enforce("host;my-header1;x-amz-date", &map, None).expect("valid");
    let paths = UriPathCandidates::new("/").expect("valid");
    let query = RawQuery::new("");
    let host = host();
    let spec = CanonicalRequestSpec::new(
        &Method::GET,
        &paths,
        &query,
        &map,
        &signed,
        &host,
        PayloadMode::Empty.canonical_payload_token(),
    );
    let request = spec.candidates().expect("built").next().expect("one");
    assert!(request.text().contains("my-header1:value4,value1,value3\n"));
}

#[test]
fn a_proxy_rewritten_path_produces_two_candidates_in_a_fixed_order() {
    let paths = UriPathCandidates::new("/my key").expect("valid");
    assert_eq!(paths.decoded(), "/my%20key");
    assert_eq!(paths.raw(), "/my key");
    assert!(!paths.is_single());
    assert_eq!(paths.order().as_slice(), [PathCandidate::Decoded, PathCandidate::Raw]);
}

/// Positive — the legacy fallback still tries the wire spelling of a path that carries an
/// unencoded byte: `=`, `+`, a space, `!*()'`, `,;:@&$`, a non-ASCII byte.
#[test]
fn the_legacy_fallback_tries_a_wire_path_with_an_unencoded_byte() {
    for raw in [
        "/b/sitemap.xmlage=",
        "/b/a+b",
        "/b/a b",
        "/b/a!*()'",
        "/b/a,;:@&$",
        "/b/caf\u{e9}",
        "/b/a%20b=",
    ] {
        let paths = UriPathCandidates::new(raw)
            .expect("valid")
            .with_raw_fallback(RawPathFallback::WithUnencodedBytes);
        assert_eq!(paths.order().as_slice(), [PathCandidate::Decoded, PathCandidate::Raw], "{raw}");
    }
}

/// Negative — the legacy fallback does not try a wire path that differs from the decoded one
/// only in how its escapes are spelled; the default still does.
#[test]
fn n_the_legacy_fallback_skips_a_wire_path_that_only_respells_escapes() {
    for raw in ["/b/a%7Eb", "/b/a%3d", "/b/%41", "/b/a%2fb"] {
        let paths = UriPathCandidates::new(raw).expect("valid");
        assert!(!paths.is_single(), "{raw}: the two spellings differ");
        assert_eq!(paths.order().as_slice(), [PathCandidate::Decoded, PathCandidate::Raw], "{raw}");
        let legacy = paths.with_raw_fallback(RawPathFallback::WithUnencodedBytes);
        assert_eq!(legacy.order().as_slice(), [PathCandidate::Decoded], "{raw}");
    }
    assert_eq!(RawPathFallback::default(), RawPathFallback::WhenRespelled);
}

#[test]
fn an_already_canonical_path_gets_exactly_one_candidate() {
    let paths = UriPathCandidates::new("/my%20key").expect("valid");
    assert!(paths.is_single());
    assert_eq!(paths.order().len(), 1);
}

#[test]
fn dot_segments_and_encoded_slashes_survive_canonicalisation() {
    assert_eq!(UriPathCandidates::new("/./").expect("valid").decoded(), "/./");
    assert_eq!(UriPathCandidates::new("/a/b/../..").expect("valid").decoded(), "/a/b/../..");
    // An encoded slash stays inside its segment; decoding it into a separator would restructure
    // the request.
    assert_eq!(UriPathCandidates::new("/a%2Fb").expect("valid").decoded(), "/a%2Fb");
}

#[test]
fn control_characters_and_bad_escapes_in_a_path_are_refused() {
    for bad in ["/a\nb", "/a\rb", "/a%zzb", "/a%2"] {
        assert!(UriPathCandidates::new(bad).is_err(), "must reject {bad:?}");
    }
}

#[test]
fn the_mismatch_detail_stays_out_of_the_response_unless_asked() {
    let map = headers(&[("x-amz-date", "20150830T123600Z")]);
    let signed = SignedHeaderSet::parse_and_enforce("host;x-amz-date", &map, None).expect("valid");
    let paths = UriPathCandidates::new("/").expect("valid");
    let query = RawQuery::new("");
    let host = host();
    let spec = CanonicalRequestSpec::new(
        &Method::GET,
        &paths,
        &query,
        &map,
        &signed,
        &host,
        PayloadMode::Empty.canonical_payload_token(),
    );
    let request = spec.candidates().expect("built").next().expect("one");
    let date = AmzDate::parse("20150830T123600Z").expect("valid");
    let scope = CredentialScope::parse("AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request").expect("valid");
    let detail = SignatureMismatchDetail::new(&request, &request.string_to_sign(&date, &scope));
    assert!(detail.for_response(false).is_none());
    assert!(detail.for_response(true).is_some());
    assert!(detail.canonical_request().starts_with("GET\n"));
}
