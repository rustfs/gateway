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

//! SigV4 candidate storage, string-to-sign output and allocation controls.
//!
//! Responsible for: rejecting temporary output allocations and altered client scope bytes across
//! ordinary, empty, boundary and extended scopes, with two independently hashed request fixtures.
//! Candidate controls also compare selected paths and method ownership against independent clones.
//! NOT responsible for: HMAC verification, scope authorization, request-wide costs or time.
//! Upstream: the signature crate and isolated allocator harness. Downstream: the resource ratchet.

use crate::support;

use http::{HeaderMap, HeaderValue, Method};
use rustfs_gateway_sig::{
    AmzDate, CanonicalCandidates, CanonicalRequest, CanonicalRequestSpec, CredentialScope, EmptyRegion, PathCandidate,
    PayloadMode, RawHost, RawPathFallback, RawQuery, RegionLength, RegionRule, ServiceReading, SignedHeaderSet,
    UriPathCandidates,
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
    let case = kind / 3;
    let request = canonical(case);
    let (scope, expected) = fixture(case);
    let date = AmzDate::parse(DATE).expect("a static timestamp");
    let profiler = dhat::Profiler::builder().testing().build();
    let mut matched = 0_u64;
    for _ in 0..CALLS {
        // A measured heap sentinel in every mode detects an empty observation window. The
        // deliberately amplified mode below also rejects an observer stuck on one nonzero value.
        std::hint::black_box(Box::new([0_u8; 1]));
        let correct = match kind % 3 {
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
            _ => unreachable!("a remainder below three"),
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
    let kinds: Vec<_> = (0..CASES * 3).collect();
    let rows = support::allocations::measure(TEST, ENV, SENTINEL, &kinds, 3);
    for row in &rows {
        assert_eq!(row[2], CALLS, "every observed result must match the independent output fixture");
        assert!(row[0] >= CALLS, "the mandatory heap sentinels were not observed: {row:?}");
        assert!(row[1] >= CALLS, "the mandatory heap sentinel bytes were not observed: {row:?}");
    }
    for (case, rows) in rows.chunks_exact(3).enumerate() {
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

const CANDIDATE_ENV: &str = "RUSTFS_GATEWAY_CANDIDATE_STORAGE_ALLOCATION_PROBE";
const CANDIDATE_SENTINEL: &str = "rustfs-gateway candidate storage allocations: ";
const CANDIDATE_PATH: &str = "/key/%7E";
const EXTENSION_METHOD: &str = "LONG-EXTENSION-METHOD-WITH-MORE-THAN-SIXTEEN-BYTES";

fn candidate_cost(kind: usize) -> (u64, u64, u64) {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("example.com"));
    let signed = SignedHeaderSet::parse_and_enforce("host", &headers, None).expect("a host-only list");
    let host = RawHost::from_host_header(b"example.com").expect("a fixture host");
    let single = UriPathCandidates::new(CANDIDATE_PATH)
        .expect("a respelled path")
        .with_raw_fallback(RawPathFallback::WithUnencodedBytes);
    let dual = UriPathCandidates::new(CANDIDATE_PATH).expect("a respelled path");
    let extension = Method::from_bytes(EXTENSION_METHOD.as_bytes()).expect("a fixture extension method");
    let raw = CANDIDATE_PATH.to_owned();
    let query = RawQuery::new("");
    let spec = |method, paths| {
        CanonicalRequestSpec::new(
            method,
            paths,
            &query,
            &headers,
            &signed,
            &host,
            PayloadMode::Empty.canonical_payload_token(),
        )
    };
    let standard_single = spec(&Method::GET, &single);
    let standard_dual = spec(&Method::GET, &dual);
    let extended_single = spec(&extension, &single);
    let profiler = dhat::Profiler::builder().testing().build();
    let mut matched = 0_u64;
    for _ in 0..CALLS {
        let sentinel = std::hint::black_box(Box::new([0_u8; 1]));
        let correct = match kind {
            0 => std::hint::black_box(standard_single.candidates().expect("single candidates")).len() == 1,
            1 => std::hint::black_box(standard_dual.candidates().expect("dual candidates")).len() == 2,
            2 => std::hint::black_box(extended_single.candidates().expect("extension candidates")).len() == 1,
            3 => std::hint::black_box(Method::GET.clone()).as_str() == "GET",
            4 => std::hint::black_box(extension.clone()).as_str() == EXTENSION_METHOD,
            5 => std::hint::black_box(raw.clone()) == CANDIDATE_PATH,
            6 => sentinel[0] == 0,
            7 => std::hint::black_box(Box::new([0_u8; 1024]))[0] == 0,
            8 => std::hint::black_box(standard_single.candidates().expect("wrong observation candidates")).len() == 99,
            _ => panic!("an unknown candidate probe"),
        };
        matched = matched.saturating_add(u64::from(correct));
    }
    let stats = dhat::HeapStats::get();
    drop(profiler);
    (stats.total_blocks, stats.total_bytes, matched)
}

fn candidate_rows(test: &str) -> Option<Vec<Vec<u64>>> {
    if let Some(kinds) = support::allocations::requested_sizes(CANDIDATE_ENV) {
        for kind in kinds {
            let (blocks, bytes, matched) = candidate_cost(kind);
            println!("{CANDIDATE_SENTINEL}{blocks} {bytes} {matched}");
        }
        return None;
    }
    let rows = support::allocations::measure(test, CANDIDATE_ENV, CANDIDATE_SENTINEL, &(0..9).collect::<Vec<_>>(), 3);
    for (kind, row) in rows.iter().enumerate() {
        println!("candidate mode {kind}: {row:?}");
        assert_eq!(
            row[2],
            if kind == 8 { 0 } else { CALLS },
            "candidate probe {kind} observed the wrong shape"
        );
        assert!(row[0] >= CALLS, "candidate probe {kind} missed heap block sentinels");
        assert!(row[1] >= CALLS, "candidate probe {kind} missed heap byte sentinels");
    }
    for dimension in [0, 1] {
        assert!(
            rows[7][dimension] > rows[6][dimension],
            "candidate amplification missed dimension {dimension}"
        );
        assert!(rows[5][dimension] > rows[6][dimension], "raw path clone missed dimension {dimension}");
        assert!(
            rows[4][dimension] > rows[3][dimension],
            "extension method clone missed dimension {dimension}"
        );
    }
    Some(rows)
}

/// Reject copying an unused path: enabling the second spelling owes exactly its independent clone.
#[test]
fn candidate_paths_own_only_selected_spellings() {
    let Some(rows) = candidate_rows("signature_text_allocations::candidate_paths_own_only_selected_spellings") else {
        return;
    };
    for dimension in [0, 1] {
        let selected = rows[1][dimension]
            .checked_sub(rows[0][dimension])
            .expect("two paths cannot cost less than one");
        let control = rows[5][dimension]
            .checked_sub(rows[6][dimension])
            .expect("the raw clone exceeds its sentinel");
        assert_eq!(
            selected, control,
            "candidate path storage copied an unselected spelling in dimension {dimension}"
        );
    }
}

/// Reject an extra method text buffer: normalize standard and extension costs by Method clones.
#[test]
fn candidate_methods_use_the_owned_method_type() {
    let Some(rows) = candidate_rows("signature_text_allocations::candidate_methods_use_the_owned_method_type") else {
        return;
    };
    for dimension in [0, 1] {
        let standard = rows[0][dimension]
            .checked_sub(rows[3][dimension])
            .expect("the constructor exceeds its method control");
        let extension = rows[2][dimension]
            .checked_sub(rows[4][dimension])
            .expect("the constructor exceeds its method control");
        assert_eq!(
            standard, extension,
            "candidate method storage copied method text in dimension {dimension}"
        );
    }
}

fn owned_candidates(extension: bool, two: bool) -> CanonicalCandidates {
    let method = if extension {
        Method::from_bytes(EXTENSION_METHOD.as_bytes()).expect("a fixture extension method")
    } else {
        Method::GET
    };
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("example.com"));
    let signed = SignedHeaderSet::parse_and_enforce("host", &headers, None).expect("a host-only list");
    let host = RawHost::from_host_header(b"example.com").expect("a fixture host");
    let paths = UriPathCandidates::new(CANDIDATE_PATH).expect("a respelled path");
    let paths = if two {
        paths
    } else {
        paths.with_raw_fallback(RawPathFallback::WithUnencodedBytes)
    };
    let query = RawQuery::new("");
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
    .expect("owned candidate storage")
}

fn candidate_outputs(candidates: &mut CanonicalCandidates) -> Vec<(PathCandidate, String)> {
    candidates
        .map(|request| (request.path_candidate(), request.text().to_owned()))
        .collect()
}

/// Inputs have been dropped; clones before, during and after iteration retain owned byte-exact output.
#[test]
fn owned_candidate_clones_keep_the_remaining_outputs() {
    const TAIL: &str = "\n\nhost:example.com\n\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for (extension, two) in [(false, false), (false, true), (true, true)] {
        let method = if extension { EXTENSION_METHOD } else { "GET" };
        let mut expected = vec![(PathCandidate::Decoded, format!("{method}\n/key/~{TAIL}"))];
        if two {
            expected.push((PathCandidate::Raw, format!("{method}\n{CANDIDATE_PATH}{TAIL}")));
        }
        let mut original = owned_candidates(extension, two);
        let mut before = original.clone();
        assert_eq!(original.len(), expected.len(), "the total candidate count changed");
        assert!(!original.is_empty(), "owned candidates cannot be empty");
        assert_eq!(
            candidate_outputs(&mut before),
            expected,
            "the complete owned clone changed bytes or order"
        );
        let first = original.next().expect("one selected candidate");
        assert_eq!(
            (first.path_candidate(), first.text()),
            (expected[0].0, expected[0].1.as_str()),
            "the first owned output changed"
        );
        let mut during = original.clone();
        assert_eq!(
            candidate_outputs(&mut during),
            expected[1..],
            "the partial clone changed remaining output"
        );
        assert_eq!(
            candidate_outputs(&mut original),
            expected[1..],
            "iteration after cloning changed remaining output"
        );
        assert_eq!(original.len(), expected.len(), "len reports the original total after exhaustion");
        assert!(!original.is_empty(), "is_empty describes the selected set after exhaustion");
        assert!(original.next().is_none(), "the exhausted iterator produced an extra candidate");
        assert!(original.clone().next().is_none(), "the exhausted clone produced an extra candidate");
    }
}
