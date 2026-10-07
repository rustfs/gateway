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

//! Literal percent and encoded-separator handling in legacy RustFS paths (#1314, #1315).
//!
//! Responsible for: exact path bytes and strict boundaries around the opt-in constructor.
//! NOT responsible for: HTTP routing or credential lookup.
//! Upstream: `UriPathCandidates` and the query codec. Downstream: Cargo's test harness.

use rustfs_gateway_sig::{AuthError, UriPathCandidates, percent_decode};

const MALFORMED: [(&str, &str); 7] = [
    ("/bad%zz", "/bad%25zz"),
    ("/bad%", "/bad%25"),
    ("/bad%2", "/bad%252"),
    ("/%g0/%0g", "/%25g0/%250g"),
    ("/%%41", "/%25A"),
    ("/a%2Fb%zz/%2500", "/a/b%25zz/%2500"),
    ("/é%zz", "/%C3%A9%25zz"),
];

#[test]
fn legacy_paths_have_the_observed_canonical_bytes() {
    for (raw, decoded) in MALFORMED {
        let paths = UriPathCandidates::for_legacy_rustfs(raw).expect("literal percent is allowed");
        assert_eq!(paths.decoded(), decoded, "{raw}");
        assert_eq!(paths.raw(), raw, "wire bytes must survive: {raw}");
    }
}

#[test]
fn n_default_paths_still_reject_malformed_escapes() {
    for (raw, _) in MALFORMED {
        assert_eq!(UriPathCandidates::new(raw), Err(AuthError::AuthorizationHeaderMalformed));
    }
}

#[test]
fn n_literal_controls_never_become_canonical_request_lines() {
    for control in ['\0', '\r', '\n', '\t', '\u{7f}', '\u{85}'] {
        for path in [format!("/bad%zz{control}host:x"), format!("/{control}")] {
            assert_eq!(
                UriPathCandidates::for_legacy_rustfs(&path),
                Err(AuthError::AuthorizationHeaderMalformed),
                "{path:?}"
            );
        }
    }
}

#[test]
fn n_legacy_paths_preserve_escape_depth_and_dot_segments() {
    for (raw, decoded) in [
        ("", "/"),
        ("/", "/"),
        ("/a//b/.././", "/a//b/.././"),
        ("/%2f/%5c/%00/%ff/%25", "///%5C/%00/%FF/%25"),
        ("/%252F/%257A/%2500", "/%252F/%257A/%2500"),
        ("/a+b=", "/a%2Bb%3D"),
    ] {
        let paths = UriPathCandidates::for_legacy_rustfs(raw).expect("legacy path");
        assert_eq!(paths.decoded(), decoded);
    }
}

#[test]
fn n_default_paths_keep_encoded_separators() {
    for raw in ["/a%2Fb", "/a%2fb"] {
        assert_eq!(UriPathCandidates::new(raw).expect("strict path").decoded(), "/a%2Fb");
    }
}

#[test]
fn n_query_percent_decoding_remains_strict() {
    for (raw, _) in MALFORMED {
        assert_eq!(percent_decode(raw), Err(AuthError::AuthorizationHeaderMalformed));
    }
}

// ── the table catalog's generic SigV4 path (rustfs/gateway#1232) ─────────────────────────────

/// The canonical request candidates of a `GET` of `paths`, signed over `host` alone.
fn candidate_paths(paths: &UriPathCandidates) -> Vec<String> {
    use http::{HeaderMap, HeaderValue, Method};
    use rustfs_gateway_sig::{CanonicalRequestSpec, PayloadMode, RawHost, RawQuery, SignedHeaderSet};

    let mut headers = HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_static("catalog.example:9000"));
    let signed = SignedHeaderSet::parse_and_enforce("host", &headers, None).expect("signed headers");
    let host = RawHost::from_host_header(b"catalog.example:9000").expect("a host");
    let query = RawQuery::new("");
    CanonicalRequestSpec::new(
        &Method::GET,
        paths,
        &query,
        &headers,
        &signed,
        &host,
        PayloadMode::Empty.canonical_payload_token(),
    )
    .candidates()
    .expect("canonicalisable")
    .map(|candidate| candidate.text().lines().nth(1).expect("a path line").to_owned())
    .collect()
}

/// Positive — the wire spelling is encoded once more, segment by segment, as botocore's generic
/// signer encodes an Iceberg path (rustfs/rustfs#8291); it is the only candidate.
#[test]
fn a_double_encoded_path_is_the_wire_spelling_encoded_once_more() {
    for (raw, signed) in [
        (
            "/iceberg/v1/warehouse/namespaces/ods%1Fkfk_log_order/tables/files",
            "/iceberg/v1/warehouse/namespaces/ods%251Fkfk_log_order/tables/files",
        ),
        ("/_iceberg/v1/config", "/_iceberg/v1/config"),
        ("/iceberg/v1/a%2Fb", "/iceberg/v1/a%252Fb"),
        ("/iceberg/v1/a%zz", "/iceberg/v1/a%25zz"),
        ("/iceberg/v1/a+b=", "/iceberg/v1/a%2Bb%3D"),
        ("/iceberg/v1//./..", "/iceberg/v1//./.."),
        ("", "/"),
    ] {
        let paths = UriPathCandidates::double_encoded(raw).expect("a wire path");
        assert_eq!(paths.decoded(), signed, "{raw}");
        assert_eq!(paths.raw(), if raw.is_empty() { "/" } else { raw }, "wire bytes must survive: {raw}");
        assert_eq!(candidate_paths(&paths), [signed], "one candidate only: {raw}");
    }
}

/// Negative — the S3 spelling of the same path is no candidate, and neither is the wire spelling:
/// the decoded-and-re-encoded path and the raw fallback both stay with the other constructors.
#[test]
fn n_a_double_encoded_path_tries_neither_the_s3_nor_the_wire_spelling() {
    let raw = "/iceberg/v1/warehouse/namespaces/ods%1Forders/tables/files";
    let double = candidate_paths(&UriPathCandidates::double_encoded(raw).expect("a wire path"));
    let s3 = candidate_paths(&UriPathCandidates::new(raw).expect("an S3 path"));
    assert_eq!(s3, [raw], "the S3 spelling, which here equals the wire spelling");
    assert!(!double.iter().any(|path| path == raw));
    let legacy = candidate_paths(&UriPathCandidates::for_legacy_rustfs(raw).expect("a legacy path"));
    assert_eq!(legacy, [raw]);
    assert!(!double.iter().any(|path| legacy.contains(path)));
}

/// Negative — no raw-path fallback brings a second candidate back to a doubly encoded path.
#[test]
fn n_a_raw_path_fallback_leaves_a_double_encoded_path_single() {
    let raw = "/iceberg/v1/a+b=/ns%1Fx";
    let alone = candidate_paths(&UriPathCandidates::double_encoded(raw).expect("a wire path"));
    for fallback in [
        rustfs_gateway_sig::RawPathFallback::WhenRespelled,
        rustfs_gateway_sig::RawPathFallback::WithUnencodedBytes,
    ] {
        let with = UriPathCandidates::double_encoded(raw)
            .expect("a wire path")
            .with_raw_fallback(fallback);
        assert_eq!(candidate_paths(&with), alone, "{fallback:?}");
        assert_eq!(alone.len(), 1);
    }
}

/// Negative — a control character never becomes a canonical request line.
#[test]
fn n_a_double_encoded_path_refuses_control_characters() {
    for control in ['\0', '\r', '\n', '\t', '\u{7f}', '\u{85}'] {
        assert_eq!(
            UriPathCandidates::double_encoded(&format!("/iceberg/v1/{control}host:x")),
            Err(AuthError::AuthorizationHeaderMalformed),
            "{control:?}"
        );
    }
}
