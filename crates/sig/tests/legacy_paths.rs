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
