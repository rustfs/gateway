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

//! The canonical-request case suite (`c-sig-0201` .. `c-sig-0246`, `c-sig-0255` .. `c-sig-0257`).
//!
//! Responsible for: every P2-03 case expressible through the public API at the *plaintext* level —
//! the canonical request and the string-to-sign. Tampering cases assert that the canonical text
//! changes, which is the assertion worth making: the signature is a pure function of that text, so
//! "the text differs" implies "the signature differs" short of a SHA-256 collision, and unlike a
//! signature comparison it says *what* differed.
//! NOT responsible for: the host cases (`tests/effective_host.rs`), the full derive-and-compare
//! chain and the upstream AWS suite (`src/full_chain_tests.rs`, which needs the crate-internal
//! `VerifiedScope` constructor), or the compile-time cases `c-sig-0253`/`c-sig-0254`, which are
//! `compile_fail` doctests on `RawHost` and on the `derive` module.
//! Upstream: the `rustfs-gateway-sig` public API. Downstream: none (test target).

use http::Method;
use http::header::{HeaderMap, HeaderName};
use rustfs_gateway_sig::{
    AmzDate, AuthError, CanonicalRequest, CanonicalRequestSpec, CredentialScope, PathCandidate, PayloadMode, RawHost, RawQuery,
    SigV4Authorization, SignatureMismatchDetail, SignedHeaderSet, TrailerSet, Unimplemented, UriPathCandidates,
};

const HOST: &str = "example.amazonaws.com";
const DATE: &str = "20150830T123600Z";
const CRED: &str = "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request";
const SIG_HEX: &str = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("test header name");
        map.append(name, value.parse().expect("test header value"));
    }
    map
}

/// Builds the first canonical request candidate for a request description.
fn canonical(method: &str, path: &str, query: &str, pairs: &[(&str, &str)], signed: &str, payload: PayloadMode) -> String {
    build(method, path, query, pairs, signed, payload, HOST)
        .next()
        .expect("at least one candidate")
        .text()
        .to_owned()
}

fn build(
    method: &str,
    path: &str,
    query: &str,
    pairs: &[(&str, &str)],
    signed: &str,
    payload: PayloadMode,
    host: &str,
) -> impl Iterator<Item = CanonicalRequest> {
    let method = Method::from_bytes(method.as_bytes()).expect("test method");
    let map = headers(pairs);
    let signed = SignedHeaderSet::parse_and_enforce(signed, &map, None).expect("valid signed headers");
    let paths = UriPathCandidates::new(path).expect("valid path");
    let host = RawHost::from_host_header(host.as_bytes()).expect("valid host");
    let query_owned = query.to_owned();
    // The spec borrows; build the candidates before anything is dropped.
    let raw_query = RawQuery::new(&query_owned);
    CanonicalRequestSpec::new(&method, &paths, &raw_query, &map, &signed, &host, payload.canonical_payload_token())
        .candidates()
        .expect("canonicalisable")
}

fn amz_date() -> AmzDate {
    AmzDate::parse(DATE).expect("valid timestamp")
}

fn scope() -> CredentialScope {
    CredentialScope::parse(CRED).expect("valid scope")
}

fn vanilla() -> String {
    canonical("GET", "/", "", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty)
}

// ---------------------------------------------------------------------------
// Positive cases
// ---------------------------------------------------------------------------

/// Positive — c-sig-0201: an already-encoded key is encoded once, never twice (s3s#13).
#[test]
fn c_sig_0201_an_encoded_key_is_not_encoded_a_second_time() {
    let text = canonical(
        "GET",
        "/bucket/my%20key/%E1%88%B4",
        "",
        &[("x-amz-date", DATE)],
        "host;x-amz-date",
        PayloadMode::Empty,
    );
    assert!(text.starts_with("GET\n/bucket/my%20key/%E1%88%B4\n"), "got {text}");
    assert!(!text.contains("%2520"), "a second encoding pass leaked in: {text}");
    // The two `double-*-encode` cases of the AWS suite are what a non-S3 service expects.
    let arn = UriPathCandidates::new("/2015-03-31/functions/arn%3Aaws%3Alambda/invocations").expect("valid");
    assert_eq!(arn.decoded(), "/2015-03-31/functions/arn%3Aaws%3Alambda/invocations");
}

/// Positive — c-sig-0202: leading, trailing and repeated whitespace in a header value collapses
/// (s3s#393); the AWS suite's `get-header-value-trim` expects it inside quotes too.
#[test]
fn c_sig_0202_header_values_are_trimmed_and_collapsed() {
    let text = canonical(
        "GET",
        "/",
        "",
        &[
            ("my-header1", "  value1  "),
            ("my-header2", "\"a     b    c\""),
            ("x-amz-date", DATE),
        ],
        "host;my-header1;my-header2;x-amz-date",
        PayloadMode::Empty,
    );
    assert!(text.contains("my-header1:value1\n"), "got {text}");
    assert!(text.contains("my-header2:\"a b c\"\n"), "got {text}");
}

/// Positive — c-sig-0203: a header sent several times joins with commas, in arrival order (s3s#408).
#[test]
fn c_sig_0203_repeated_headers_join_with_commas_in_arrival_order() {
    let text = canonical(
        "GET",
        "/",
        "",
        &[
            ("my-header1", "value4"),
            ("my-header1", "value1"),
            ("my-header1", "value3"),
            ("my-header1", "value2"),
            ("x-amz-date", DATE),
        ],
        "host;my-header1;x-amz-date",
        PayloadMode::Empty,
    );
    assert!(text.contains("my-header1:value4,value1,value3,value2\n"), "got {text}");
}

/// Positive — c-sig-0204: query parameters sort by encoded name, in byte order.
#[test]
fn c_sig_0204_query_parameters_sort_by_encoded_name() {
    let text = canonical(
        "GET",
        "/",
        "Param-3=Value3&Param=Value2&%E1%88%B4=Value1",
        &[("x-amz-date", DATE)],
        "host;x-amz-date",
        PayloadMode::Empty,
    );
    assert!(text.contains("\n%E1%88%B4=Value1&Param=Value2&Param-3=Value3\n"), "got {text}");
}

/// Positive — c-sig-0205: a parameter with no value is written with a trailing `=`.
#[test]
fn c_sig_0205_a_valueless_parameter_keeps_its_equals_sign() {
    let text = canonical("GET", "/bucket", "acl", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
    assert!(text.contains("\nacl=\n"), "got {text}");
}

/// Positive — c-sig-0210: a base64 `x-amz-content-sha256` is reproduced verbatim, not re-spelled
/// as hex (s3s#631) — the two modes carry the same digest and sign different strings.
#[test]
fn c_sig_0210_the_payload_token_is_the_client_s_own_spelling() {
    let digest_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let digest_b64 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    let hex_mode = PayloadMode::parse(digest_hex, TrailerSet::None).expect("valid");
    let b64_mode = PayloadMode::parse(digest_b64, TrailerSet::None).expect("valid");
    assert_eq!(hex_mode.digest(), b64_mode.digest(), "the two spellings carry one digest");

    let hex_text = canonical("GET", "/", "", &[("x-amz-date", DATE)], "host;x-amz-date", hex_mode);
    let b64_text = canonical("GET", "/", "", &[("x-amz-date", DATE)], "host;x-amz-date", b64_mode);
    assert!(hex_text.ends_with(digest_hex));
    ::core::assert!(b64_text.ends_with(digest_b64), "q-sig-payload-token-verbatim-0158");
    assert_ne!(hex_text, b64_text);
}

/// Positive — c-sig-0211: `?prefix=a%2Bb` keeps its literal plus and does not collide with
/// `?prefix=a%20b` — the measured `aws-sigv4` 1.5.1 defect.
#[test]
fn c_sig_0211_a_literal_plus_is_encoded_and_does_not_collide_with_a_space() {
    let plus = canonical("GET", "/", "prefix=a%2Bb", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
    let space = canonical("GET", "/", "prefix=a%20b", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
    let bare_plus = canonical("GET", "/", "prefix=a+b", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
    assert!(plus.contains("\nprefix=a%2Bb\n"));
    assert!(space.contains("\nprefix=a%20b\n"));
    assert_eq!(plus, bare_plus, "a bare `+` and `%2B` are one byte and must canonicalise alike");
    assert_ne!(plus, space);
}

/// Positive — the string-to-sign reproduces the client's own scope line, not the server's.
#[test]
fn c_sig_0212_the_string_to_sign_has_the_documented_four_line_shape() {
    let request = build("GET", "/", "", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty, HOST)
        .next()
        .expect("one candidate");
    let string_to_sign = request.string_to_sign(&amz_date(), &scope());
    assert_eq!(
        string_to_sign.text(),
        concat!(
            "AWS4-HMAC-SHA256\n",
            "20150830T123600Z\n",
            "20150830/us-east-1/s3/aws4_request\n",
            "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
        )
    );
}

// ---------------------------------------------------------------------------
// Negative cases
// ---------------------------------------------------------------------------

/// Negative — c-sig-0230: changing the method changes the canonical request.
#[test]
fn c_sig_0230_a_tampered_method_changes_the_canonical_request() {
    let tampered = canonical("HEAD", "/", "", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
    assert_ne!(vanilla(), tampered);
}

/// Negative — c-sig-0231: changing one byte of the path changes the canonical request.
#[test]
fn c_sig_0231_a_single_tampered_path_byte_changes_the_canonical_request() {
    let base = canonical("GET", "/bucket/key", "", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
    let tampered = canonical("GET", "/bucket/kez", "", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
    assert_ne!(base, tampered);
}

/// Negative — c-sig-0232: changing any query value changes the canonical request.
#[test]
fn c_sig_0232_a_tampered_query_value_changes_the_canonical_request() {
    let base = canonical("GET", "/", "prefix=a", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
    let tampered = canonical("GET", "/", "prefix=b", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
    assert_ne!(base, tampered);
}

/// Negative — c-sig-0233: tampering with *each* signed header, one case per header.
#[test]
fn c_sig_0233_every_signed_header_is_covered_individually() {
    let signed = "content-type;host;x-amz-acl;x-amz-date;x-amz-storage-class";
    let base_pairs = [
        ("content-type", "text/plain"),
        ("x-amz-acl", "private"),
        ("x-amz-date", DATE),
        ("x-amz-storage-class", "STANDARD"),
    ];
    let base = canonical("PUT", "/b/k", "", &base_pairs, signed, PayloadMode::Empty);
    for index in 0..base_pairs.len() {
        let mut tampered_pairs = base_pairs;
        let replacement = match tampered_pairs[index].0 {
            "content-type" => "text/html",
            "x-amz-acl" => "public-read",
            "x-amz-date" => "20150830T123601Z",
            _ => "GLACIER",
        };
        tampered_pairs[index].1 = replacement;
        let tampered = canonical("PUT", "/b/k", "", &tampered_pairs, signed, PayloadMode::Empty);
        assert_ne!(base, tampered, "tampering with {} must change the canonical request", base_pairs[index].0);
    }
}

/// Negative — c-sig-0234: changing the payload hash changes the canonical request.
#[test]
fn c_sig_0234_a_tampered_payload_hash_changes_the_canonical_request() {
    let tampered = canonical("GET", "/", "", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Unsigned);
    assert_ne!(vanilla(), tampered);
    assert!(tampered.ends_with("UNSIGNED-PAYLOAD"));
}

/// Negative — c-sig-0235: tampering with each scope field changes the string-to-sign.
#[test]
fn c_sig_0235_every_scope_field_changes_the_string_to_sign() {
    let request = build("GET", "/", "", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty, HOST)
        .next()
        .expect("one candidate");
    let base = request.string_to_sign(&amz_date(), &scope());
    for tampered_scope in [
        "AKIDEXAMPLE/20150831/us-east-1/s3/aws4_request",
        "AKIDEXAMPLE/20150830/eu-west-1/s3/aws4_request",
        "AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request",
    ] {
        let parsed = CredentialScope::parse(tampered_scope).expect("valid");
        assert_ne!(base, request.string_to_sign(&amz_date(), &parsed), "{tampered_scope}");
    }
    // The fourth field, the terminator, cannot even be tampered with: it does not parse.
    assert!(CredentialScope::parse("AKIDEXAMPLE/20150830/us-east-1/s3/aws4-request").is_err());
}

/// Negative — c-sig-0236: a scope that does not end in `aws4_request` is refused.
#[test]
fn c_sig_0236_the_scope_terminator_is_a_literal() {
    for bad in [
        "AKID/20150830/us-east-1/s3/AWS4_REQUEST",
        "AKID/20150830/us-east-1/s3/aws4_requests",
        "AKID/20150830/us-east-1/s3/",
    ] {
        assert_eq!(
            CredentialScope::parse(bad),
            Err(AuthError::AuthorizationHeaderMalformed),
            "must reject {bad}"
        );
    }
}

/// Negative — c-sig-0238: appending any parameter invalidates the request; there is no allow-list.
#[test]
fn c_sig_0238_an_appended_query_parameter_always_changes_the_canonical_request() {
    let base = canonical("GET", "/b/k", "", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
    for appended in ["foo=1", "response-content-disposition=attachment", "versionId=7"] {
        let tampered = canonical("GET", "/b/k", appended, &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty);
        assert_ne!(base, tampered, "appending {appended} must change the canonical request");
    }
}

/// Negative — c-sig-0239: the same query parameter twice is an ambiguity, not a choice (s3s#176).
#[test]
fn c_sig_0239_a_repeated_query_parameter_is_refused() {
    assert_eq!(
        RawQuery::new("versionId=1&versionId=2").canonical(rustfs_gateway_sig::QueryExclusion::None),
        Err(AuthError::AuthorizationHeaderMalformed)
    );
}

/// Negative — c-sig-0240: a `SignedHeaders` list without `host` is refused.
#[test]
fn c_sig_0240_signed_headers_must_cover_host() {
    let map = headers(&[("x-amz-date", DATE)]);
    assert_eq!(
        SignedHeaderSet::parse_and_enforce("x-amz-date", &map, None),
        Err(AuthError::SignatureDoesNotMatch)
    );
}

/// Negative — c-sig-0241: an empty `SignedHeaders` list is refused.
#[test]
fn c_sig_0241_an_empty_signed_headers_list_is_refused() {
    let map = headers(&[("x-amz-date", DATE)]);
    assert_eq!(SignedHeaderSet::parse_and_enforce("", &map, None), Err(AuthError::SignatureDoesNotMatch));
}

/// Negative — c-sig-0242: an unsorted or repeating `SignedHeaders` list is refused.
#[test]
fn c_sig_0242_signed_headers_must_be_strictly_ascending() {
    let map = headers(&[("x-amz-date", DATE), ("content-type", "text/plain")]);
    for bad in [
        "x-amz-date;host",
        "host;content-type;x-amz-date",
        "host;host;x-amz-date",
        "Host;x-amz-date",
    ] {
        assert_eq!(
            SignedHeaderSet::parse_and_enforce(bad, &map, None),
            Err(AuthError::AuthorizationHeaderMalformed),
            "must reject {bad}"
        );
    }
}

/// Negative — c-sig-0243: declaring a header the request never sent is refused.
#[test]
fn c_sig_0243_a_declared_but_absent_header_is_refused() {
    let map = headers(&[("x-amz-date", DATE)]);
    assert_eq!(
        SignedHeaderSet::parse_and_enforce("content-type;host;x-amz-date", &map, None),
        Err(AuthError::SignatureDoesNotMatch)
    );
}

/// Negative — c-sig-0244 and c-sig-0245: every `x-amz-*` header that arrives must be signed. One
/// assertion per header, covering the SSE-C trio, copy-source, the directives, ACL, tagging,
/// object lock and the session token.
#[test]
fn c_sig_0244_and_0245_every_unsigned_amz_header_is_refused_individually() {
    let injectable = [
        "x-amz-copy-source",
        "x-amz-acl",
        "x-amz-metadata-directive",
        "x-amz-tagging",
        "x-amz-object-lock-mode",
        "x-amz-object-lock-retain-until-date",
        "x-amz-server-side-encryption-customer-algorithm",
        "x-amz-server-side-encryption-customer-key",
        "x-amz-server-side-encryption-customer-key-md5",
        "x-amz-security-token",
    ];
    for name in injectable {
        let map = headers(&[("x-amz-date", DATE), (name, "injected")]);
        assert_eq!(
            SignedHeaderSet::parse_and_enforce("host;x-amz-date", &map, None),
            Err(AuthError::SignatureDoesNotMatch),
            "an unsigned {name} must be refused"
        );
        // And it is accepted the moment the client actually signs it.
        let signed = format!("host;x-amz-date;{name}");
        let mut names: Vec<&str> = signed.split(';').collect();
        names.sort_unstable();
        assert!(SignedHeaderSet::parse_and_enforce(&names.join(";"), &map, None).is_ok(), "{name}");
    }
}

/// Negative — c-sig-0246: a signed `content-length` must agree with the length the wire settled on.
#[test]
fn c_sig_0246_a_signed_content_length_must_match_the_wire_length() {
    let map = headers(&[("content-length", "13"), ("x-amz-date", DATE)]);
    assert!(SignedHeaderSet::parse_and_enforce("content-length;host;x-amz-date", &map, Some(13)).is_ok());
    assert_eq!(
        SignedHeaderSet::parse_and_enforce("content-length;host;x-amz-date", &map, Some(9_999)),
        Err(AuthError::SignatureDoesNotMatch)
    );
}

/// Negative — c-sig-0255: a malformed `Authorization` header is refused and never downgraded to
/// anonymous — the parser has no success path that drops the credential.
#[test]
fn c_sig_0255_malformed_authorization_headers_are_refused() {
    for bad in [
        format!("AWS4-HMAC-SHA256 SignedHeaders=host, Signature={SIG_HEX}"),
        format!("AWS4-HMAC-SHA256 Credential={CRED}, Signature={SIG_HEX}"),
        format!("AWS4-HMAC-SHA256 Credential={CRED}, SignedHeaders=host"),
        format!("AWS4-HMAC-SHA256 Credential={CRED}, SignedHeaders=host, Signature={SIG_HEX},"),
    ] {
        assert_eq!(
            SigV4Authorization::parse(&bad).err(),
            Some(AuthError::AuthorizationHeaderMalformed),
            "must reject {bad}"
        );
    }
}

/// Negative — c-sig-0256: an unknown algorithm token is refused and never falls through to SigV4.
#[test]
fn c_sig_0256_an_unknown_algorithm_never_falls_through_to_sigv4() {
    let unknown = format!("AWS4-HMAC-SHA512 Credential={CRED}, SignedHeaders=host, Signature={SIG_HEX}");
    assert_eq!(SigV4Authorization::parse(&unknown).err(), Some(AuthError::AuthorizationHeaderMalformed));
    let sigv4a = format!("AWS4-ECDSA-P256-SHA256 Credential={CRED}, SignedHeaders=host, Signature={SIG_HEX}");
    assert_eq!(
        SigV4Authorization::parse(&sigv4a).err(),
        Some(AuthError::NotImplemented(Unimplemented::SigV4a)),
        "SigV4a is recognised and refused, never verified as SigV4"
    );
}

/// Negative — c-sig-0257: the intermediates stay out of the response body unless a deployment asks,
/// and the expected signature is not in them at all — `AuthError` has no field that could carry it.
#[test]
fn c_sig_0257_the_intermediates_are_gated_and_carry_no_expected_signature() {
    let request = build("GET", "/", "", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty, HOST)
        .next()
        .expect("one candidate");
    let string_to_sign = request.string_to_sign(&amz_date(), &scope());
    let detail = SignatureMismatchDetail::new(&request, &string_to_sign);

    assert!(detail.for_response(false).is_none(), "the default must render nothing");
    let (canonical_request, sts) = detail.for_response(true).expect("verbose mode renders both");
    assert!(canonical_request.starts_with("GET\n"));
    assert!(sts.starts_with("AWS4-HMAC-SHA256\n"));
    assert!(!canonical_request.contains(SIG_HEX), "no signature may appear in an intermediate");
    assert!(!sts.contains(SIG_HEX), "no signature may appear in an intermediate");

    // The rejection itself is fieldless, so nothing rides along into a log line.
    let error = AuthError::SignatureDoesNotMatch;
    assert!(!format!("{error}").contains(SIG_HEX));
    assert_eq!(error.message(), AuthError::InvalidAccessKeyId.message());
}

/// Negative — a control character in the path cannot terminate the canonical request early.
#[test]
fn c_sig_0231b_a_control_character_in_the_path_is_refused() {
    for bad in ["/a\nb", "/a\rb", "/\u{0}"] {
        assert_eq!(
            UriPathCandidates::new(bad),
            Err(AuthError::AuthorizationHeaderMalformed),
            "must reject {bad:?}"
        );
    }
}

/// Negative — the raw fallback candidate exists, is second, and is not offered twice.
#[test]
fn c_sig_0209a_the_fallback_candidate_is_second_and_never_duplicated() {
    let rewritten = UriPathCandidates::new("/my key").expect("valid");
    assert!(!rewritten.is_single());
    let already_canonical = UriPathCandidates::new("/my%20key").expect("valid");
    assert!(already_canonical.is_single());

    let mut candidates = build("GET", "/my key", "", &[("x-amz-date", DATE)], "host;x-amz-date", PayloadMode::Empty, HOST);
    let first = candidates.next().expect("decoded candidate");
    let second = candidates.next().expect("raw candidate");
    assert_eq!(first.path_candidate(), PathCandidate::Decoded);
    ::core::assert_eq!(second.path_candidate(), PathCandidate::Raw, "q-sig-raw-path-fallback-0157");
    assert!(first.text().contains("\n/my%20key\n"));
    assert!(second.text().contains("\n/my key\n"));
    assert!(candidates.next().is_none(), "there is no third spelling");
}
