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

//! SigV4 string-to-sign output and allocation controls.
//!
//! Responsible for: rejecting temporary output allocations and altered client scope bytes across
//! ordinary, empty, boundary and extended scopes, with two independently hashed request fixtures
//! and both matching and deliberately different output observations.
//! NOT responsible for: HMAC verification, scope authorization, request-wide costs or time.
//! Upstream: the signature crate and isolated allocator harness. Downstream: the resource ratchet.

use crate::support;

use http::{HeaderMap, HeaderValue, Method};
use rustfs_gateway_sig::{
    AmzDate, CanonicalRequest, CanonicalRequestSpec, CredentialScope, EmptyRegion, PayloadMode, RawHost, RawQuery, RegionLength,
    RegionRule, ServiceReading, SignedHeaderSet, UriPathCandidates,
};

const ENV: &str = "RUSTFS_GATEWAY_STRING_TO_SIGN_ALLOCATION_PROBE";
const SENTINEL: &str = "rustfs-gateway string-to-sign allocations: ";
const TEST: &str = "signature_text_allocations::string_to_sign_owns_only_its_final_text";
const CALLS: u64 = 256;
const CASES: usize = 6;
const DATE: &str = "20150830T123600Z";
// SHA-256 computed with Python hashlib over literal canonical requests, independently of this
// crate's hash/hex routines. These are request digests, not signatures or expected signatures.
const DIGESTS: [&str; 2] = [
    "63a36edef107cae479e45f4df20bea8bfb8d79981ab84daa1f77772e8486f8d6",
    "7cf8539fc04cc55a0c47b016c1e4d3395d0104a2946dc91f5d4b160aa689edf5",
];

fn canonical(case: usize) -> CanonicalRequest {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("example.com"));
    let signed = SignedHeaderSet::parse_and_enforce("host", &headers, None).expect("a host-only allow-list");
    let (method, path) = if case.is_multiple_of(2) {
        (Method::GET, "/bucket/key")
    } else {
        (Method::PUT, "/bucket/other")
    };
    let paths = UriPathCandidates::new(path).expect("a static path");
    let query = RawQuery::new("");
    let host = RawHost::from_host_header(b"example.com").expect("a static host");
    CanonicalRequestSpec::new(
        &method,
        &paths,
        &query,
        &headers,
        &signed,
        &host,
        PayloadMode::Empty.canonical_payload_token(),
    )
    .candidates()
    .expect("canonical request candidates")
    .next()
    .expect("the first path candidate")
}

fn fixture(case: usize) -> (CredentialScope, String) {
    let (day, region, service) = match case {
        0 => ("20150830", String::from("us-east-1"), "s3"),
        1 => ("20150829", String::from("eu-west-1"), "s3"),
        2 => ("20150830", String::new(), "sts"),
        3 => ("20150830", "r".repeat(CredentialScope::MAX_REGION_LEN), "sts"),
        4 => ("20150830", "r".repeat(1024), "s3"),
        5 => ("20150830", String::from("us-east-1"), "\u{670d}\u{52a1}-\u{e9}"),
        _ => panic!("an unknown scope fixture"),
    };
    let scope_text = format!("{day}/{region}/{service}/aws4_request");
    let rule = RegionRule::STRICT
        .with_empty(EmptyRegion::Admitted)
        .with_length(RegionLength::Unbounded)
        .with_services(ServiceReading::AnyName);
    let scope = CredentialScope::parse_with(&format!("AKID/{scope_text}"), rule).expect("a client scope fixture");
    let digest = DIGESTS[case % 2];
    let expected = format!("AWS4-HMAC-SHA256\n{DATE}\n{scope_text}\n{digest}");
    (scope, expected)
}

fn cost(kind: usize) -> (u64, u64, u64) {
    let case = kind / 4;
    let request = canonical(case);
    let (scope, expected) = fixture(case);
    let different = fixture((case + 1) % CASES).1;
    let date = AmzDate::parse(DATE).expect("a static timestamp");
    let profiler = dhat::Profiler::builder().testing().build();
    let mut matched = 0_u64;
    for _ in 0..CALLS {
        // A measured heap sentinel in every mode detects an empty observation window. The
        // deliberately amplified mode below also rejects an observer stuck on one nonzero value.
        std::hint::black_box(Box::new([0_u8; 1]));
        let correct = match kind % 4 {
            0 => std::hint::black_box(expected.clone()) == expected,
            1 => {
                request
                    .string_to_sign(std::hint::black_box(&date), std::hint::black_box(&scope))
                    .text()
                    == expected
            }
            2 => {
                let owned = std::hint::black_box(expected.clone());
                std::hint::black_box(owned.clone()) == expected
            }
            3 => {
                request
                    .string_to_sign(std::hint::black_box(&date), std::hint::black_box(&scope))
                    .text()
                    == different
            }
            _ => unreachable!("a remainder below four"),
        };
        matched = matched.saturating_add(u64::from(correct));
    }
    let stats = dhat::HeapStats::get();
    drop(profiler);
    (stats.total_blocks, stats.total_bytes, matched)
}

/// One healthy output fixture plus five boundary/alternate-scope regressions refuse any extra
/// heap blocks or bytes beyond a single owned output. Actual values and both observer controls
/// must pass before the resource ceilings can be accepted.
#[test]
fn string_to_sign_owns_only_its_final_text() {
    if let Some(kinds) = support::allocations::requested_sizes(ENV) {
        for kind in kinds {
            let (blocks, bytes, matched) = cost(kind);
            println!("{SENTINEL}{blocks} {bytes} {matched}");
        }
        return;
    }
    let kinds: Vec<_> = (0..CASES * 4).collect();
    let rows = support::allocations::measure(TEST, ENV, SENTINEL, &kinds, 3);
    assert!(
        rows.iter().any(|row| row[2] == CALLS) && rows.iter().any(|row| row[2] == 0),
        "the value observer did not measure both matching and deliberately different outputs"
    );
    for (kind, row) in rows.iter().enumerate() {
        let expected = if kind % 4 == 3 { 0 } else { CALLS };
        assert_eq!(row[2], expected, "the value observer did not measure probe {kind}");
        assert!(row[0] >= CALLS, "the mandatory heap sentinels were not observed: {row:?}");
        assert!(row[1] >= CALLS, "the mandatory heap sentinel bytes were not observed: {row:?}");
    }
    for (case, rows) in rows.chunks_exact(4).enumerate() {
        let (control, actual, amplified) = (&rows[0], &rows[1], &rows[2]);
        assert!(
            amplified[0] > control[0],
            "case {case}: a deliberately copied output did not allocate more"
        );
        assert!(
            amplified[1] > control[1],
            "case {case}: a deliberately copied output did not allocate more bytes"
        );
        println!(
            "case {case}: {} blocks, {} bytes; control {} blocks, {} bytes",
            actual[0], actual[1], control[0], control[1]
        );
        assert!(actual[0] <= control[0], "case {case}: output construction added temporary heap blocks");
        assert!(
            actual[1] <= control[1],
            "case {case}: output construction allocated beyond its exact final bytes"
        );
    }
}
