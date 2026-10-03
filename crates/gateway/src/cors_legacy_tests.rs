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

//! Legacy RustFS's CORS rules, one by one, split out of their module for size.
//!
//! Responsible for: the scenarios of RustFS's own CORS tests — `rustfs/src/server/layer.rs`
//! (`test_is_s3_path_excludes_admin_and_special_paths`, the three `test_generic_cors_layer_*`
//! tests, `conditional_cors_*`, `test_resolve_s3_options_cors_headers_*`,
//! `test_apply_bucket_cors_result_*`) and `rustfs/src/storage/ecfs_test.rs`
//! (`test_matches_origin_pattern_*`, `test_cors_headers_validation`,
//! `test_apply_cors_headers_*`) — restated over this module's functions.
//! NOT responsible for: the pipeline's use of them (`tests/legacy_cors.rs` and `compat/sut`).
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used)]

use super::*;

fn legacy(fallback: Option<&str>) -> LegacyRustfsCors {
    LegacyRustfsCors::with_fallback_origins(fallback)
}

fn request(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(HeaderName::from_static(name), HeaderValue::from_static(value));
    }
    headers
}

/// The names of an answer's headers, in the order it writes them. Asserting the whole list is how
/// these cases say which headers an answer does *not* carry — credentials above all — without
/// spelling one here.
fn names(pairs: &[(HeaderName, HeaderValue)]) -> Vec<&str> {
    pairs.iter().map(|(name, _)| name.as_str()).collect()
}

fn get<'a>(pairs: &'a [(HeaderName, HeaderValue)], name: &HeaderName) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .and_then(|(_, value)| value.to_str().ok())
}

fn rule(origins: &[&str], methods: &[&str], headers: &[&str], expose: &[&str], max_age: Option<i32>) -> CorsRule {
    CorsRule {
        allowed_origins: origins.iter().map(|value| (*value).to_owned()).collect(),
        allowed_methods: methods.iter().map(|value| (*value).to_owned()).collect(),
        allowed_headers: headers.iter().map(|value| (*value).to_owned()).collect(),
        expose_headers: expose.iter().map(|value| (*value).to_owned()).collect(),
        max_age_seconds: max_age,
        ..CorsRule::default()
    }
}

fn document(rules: Vec<CorsRule>) -> CorsConfiguration {
    CorsConfiguration { cors_rules: rules }
}

/// The lab document: an exact origin, a wildcard origin, and a one-`*` pattern.
fn lab() -> CorsConfiguration {
    document(vec![
        rule(
            &["https://app.example.com"],
            &["GET", "PUT"],
            &["*"],
            &["ETag", "x-amz-request-id"],
            Some(600),
        ),
        rule(&["*"], &["HEAD"], &[], &[], None),
        rule(&["https://*.wild.example"], &["POST"], &["content-type"], &[], None),
    ])
}

// ── which paths are S3 paths ───────────────────────────────────────────────────────────────────

#[test]
fn the_s3_paths_are_everything_but_the_non_s3_surfaces() {
    let cors = legacy(None);
    for path in [
        "/my-bucket/key",
        "/",
        "/minio/adminx/object",
        "/rustfs/administrator/object",
        "/bucket",
    ] {
        assert!(cors.is_s3_path(path), "{path}");
    }
    for path in [
        "/rustfs/admin",
        "/rustfs/admin/v3/info",
        "/minio/admin/v3/info",
        "/iceberg/v1/config",
        "/_iceberg/v1/config",
        "/rustfs/rpc/read_file_stream",
        "/health",
        "/health/ready",
        "/health/live",
        "/minio/health/cluster/read",
        "/profile/cpu",
        "/profile/memory",
        "/favicon.ico",
        "/rustfs/console",
        "/rustfs/console/index.html",
    ] {
        assert!(!cors.is_s3_path(path), "{path}");
    }
    let moved = legacy(None).with_console_prefix("/ui/");
    assert!(!moved.is_s3_path("/ui/index.html"));
    assert!(moved.is_s3_path("/rustfs/console/index.html"));
}

// ── the fallback headers ───────────────────────────────────────────────────────────────────────

#[test]
fn n_no_fallback_origins_means_no_fallback_headers() {
    let origin = request(&[("origin", "https://example.com")]);
    for fallback in [None, Some(""), Some("   ")] {
        assert!(legacy(fallback).fallback_headers(&origin).is_empty(), "{fallback:?}");
    }
}

/// Positive — a listed origin is echoed with the fixed methods, headers and exposed headers, and,
/// unlike legacy RustFS, without credentials (see the module documentation).
#[test]
fn a_listed_fallback_origin_is_echoed_without_credentials() {
    let cors = legacy(Some(" https://other.com , https://allowed.com "));
    assert!(
        cors.fallback_headers(&request(&[("origin", "https://denied.com")]))
            .is_empty()
    );
    let pairs = cors.fallback_headers(&request(&[("origin", "https://allowed.com")]));
    assert_eq!(
        names(&pairs),
        [
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-expose-headers"
        ]
    );
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_ORIGIN), Some("https://allowed.com"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_METHODS), Some("GET, POST, PUT, DELETE, OPTIONS, HEAD"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_HEADERS), Some("*"));
    let exposed = get(&pairs, &ACCESS_CONTROL_EXPOSE_HEADERS).expect("exposed headers");
    assert!(exposed.split(',').any(|name| name.trim() == "x-request-id"));
    assert!(exposed.split(',').any(|name| name.trim() == "x-amz-request-id"));
}

#[test]
fn n_a_wildcard_fallback_allows_no_credentials() {
    let pairs = legacy(Some("*")).fallback_headers(&request(&[("origin", "https://example.com")]));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_ORIGIN), Some("*"));
    assert_eq!(names(&pairs).len(), 4, "{pairs:?}");
    // A list that merely contains `*` is a list: only the literal origin `*` matches it.
    assert!(
        legacy(Some("https://a.com,*"))
            .fallback_headers(&request(&[("origin", "https://b.com")]))
            .is_empty()
    );
}

#[test]
fn n_a_request_without_origin_gets_no_fallback_headers() {
    assert!(legacy(Some("*")).fallback_headers(&HeaderMap::new()).is_empty());
}

// ── what a preflight and an ordinary request read from ─────────────────────────────────────────

#[test]
fn the_preflight_plan_follows_the_path_and_the_two_headers() {
    let cors = legacy(None);
    let both = request(&[("origin", "https://a.com"), ("access-control-request-method", "GET")]);
    let no_method = request(&[("origin", "https://a.com")]);
    let no_origin = request(&[("access-control-request-method", "GET")]);
    assert_eq!(cors.preflight_plan("/bucket/key", &both), PreflightPlan::Bucket("bucket"));
    assert_eq!(cors.preflight_plan("//bucket/key", &both), PreflightPlan::Bucket("bucket"));
    assert_eq!(cors.preflight_plan("/bucket", &both), PreflightPlan::Bucket("bucket"));
    assert_eq!(cors.preflight_plan("/", &both), PreflightPlan::Fallback);
    for path in ["/bucket/key", "/"] {
        assert_eq!(cors.preflight_plan(path, &no_method), PreflightPlan::BadRequest, "{path}");
        assert_eq!(cors.preflight_plan(path, &no_origin), PreflightPlan::BadRequest, "{path}");
        assert_eq!(cors.preflight_plan(path, &HeaderMap::new()), PreflightPlan::BadRequest, "{path}");
    }
    // Any other path answers the fallback, whether or not the preflight headers are there.
    for headers in [&both, &no_method, &HeaderMap::new()] {
        assert_eq!(cors.preflight_plan("/rustfs/admin/v3/info", headers), PreflightPlan::Fallback);
    }
}

#[test]
fn the_actual_plan_needs_an_origin_and_reads_the_first_segment() {
    let cors = legacy(None);
    let origin = request(&[("origin", "https://a.com")]);
    assert_eq!(cors.actual_plan("/bucket/key", &HeaderMap::new()), None);
    assert_eq!(cors.actual_plan("/bucket/key", &origin), Some(ActualPlan::Bucket("bucket")));
    assert_eq!(cors.actual_plan("/", &origin), Some(ActualPlan::Fallback));
    assert_eq!(cors.actual_plan("/minio/admin/v3/info", &origin), Some(ActualPlan::Fallback));
}

// ── the bucket's rules ─────────────────────────────────────────────────────────────────────────

fn preflight_headers(pairs: &[(&'static str, &'static str)]) -> Option<Vec<(HeaderName, HeaderValue)>> {
    bucket_headers(&lab(), &Method::OPTIONS, &request(pairs))
}

#[test]
fn a_matched_preflight_answers_the_rule() {
    let pairs = preflight_headers(&[
        ("origin", "https://app.example.com"),
        ("access-control-request-method", "PUT"),
        ("access-control-request-headers", "Content-Type, X-Amz-Meta-Foo"),
    ])
    .expect("a readable origin");
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_ORIGIN), Some("https://app.example.com"));
    assert_eq!(
        get(&pairs, &VARY),
        Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
    );
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_METHODS), Some("GET, PUT"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_HEADERS), Some("content-type,x-amz-meta-foo"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_MAX_AGE), Some("600"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_EXPOSE_HEADERS), None, "a preflight exposes nothing");
    assert_eq!(
        names(&pairs),
        [
            "access-control-allow-origin",
            "vary",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-max-age"
        ]
    );
}

#[test]
fn a_wildcard_rule_answers_a_star_to_an_uncredentialed_preflight() {
    let pairs = preflight_headers(&[("origin", "https://any.example"), ("access-control-request-method", "HEAD")])
        .expect("a readable origin");
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_ORIGIN), Some("*"));
    assert_eq!(get(&pairs, &VARY), Some("Access-Control-Request-Method, Access-Control-Request-Headers"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_METHODS), Some("HEAD"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_MAX_AGE), None);
}

/// Positive — a credentialed request under a wildcard rule gets its own origin echoed, with
/// `Vary: Origin`, as legacy RustFS answers it; negative — and none of the credentials legacy
/// RustFS adds (see the module documentation).
#[test]
fn a_credentialed_request_matching_a_wildcard_rule_gets_its_origin_without_credentials() {
    let configuration = document(vec![rule(&["*"], &["GET"], &["*"], &[], None)]);
    let pairs = bucket_headers(
        &configuration,
        &Method::OPTIONS,
        &request(&[
            ("origin", "https://console.localhost"),
            ("access-control-request-method", "GET"),
            ("access-control-request-headers", "x-amz-content-sha256"),
            ("authorization", "AWS4-HMAC-SHA256 Credential=test/20260302/us-east-1/s3/aws4_request"),
        ]),
    )
    .expect("a readable origin");
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_ORIGIN), Some("https://console.localhost"));
    assert_eq!(
        get(&pairs, &VARY),
        Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
    );
    assert_eq!(
        names(&pairs),
        [
            "access-control-allow-origin",
            "vary",
            "access-control-allow-methods",
            "access-control-allow-headers"
        ]
    );
    for credential in ["cookie", "x-amz-security-token", "x-amz-content-sha256"] {
        let mut headers = request(&[("origin", "https://console.localhost")]);
        headers.insert(HeaderName::from_static(credential), HeaderValue::from_static("x"));
        let pairs = bucket_headers(&configuration, &Method::GET, &headers).expect("a readable origin");
        assert_eq!(
            get(&pairs, &ACCESS_CONTROL_ALLOW_ORIGIN),
            Some("https://console.localhost"),
            "{credential}"
        );
        assert_eq!(get(&pairs, &VARY), Some("Origin"), "{credential}");
        assert_eq!(
            names(&pairs),
            ["access-control-allow-origin", "vary", "access-control-allow-methods"],
            "{credential}"
        );
    }
}

#[test]
fn a_one_star_pattern_matches_by_prefix_and_suffix() {
    let pairs = preflight_headers(&[
        ("origin", "https://a.wild.example"),
        ("access-control-request-method", "POST"),
        ("access-control-request-headers", "content-type"),
    ])
    .expect("a readable origin");
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_ORIGIN), Some("https://a.wild.example"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_HEADERS), Some("content-type"));
    assert!(matches_origin_pattern("https://*.example.com", "https://api.sub.example.com"));
    assert!(matches_origin_pattern("https://*", "https://any-domain.com"));
    assert!(matches_origin_pattern("*://example.com", "http://example.com"));
    assert!(matches_origin_pattern("", ""));
    assert!(!matches_origin_pattern("https://*.*.com", "https://app.example.com"));
    assert!(!matches_origin_pattern("https://*.example.com", "https://example.com"));
    assert!(!matches_origin_pattern("https://example.com", "http://example.com"));
    assert!(!matches_origin_pattern("", "https://example.com"));
}

#[test]
fn n_a_preflight_no_rule_admits_gets_nothing() {
    for pairs in [
        vec![("origin", "https://evil.example"), ("access-control-request-method", "GET")],
        vec![
            ("origin", "https://app.example.com"),
            ("access-control-request-method", "get"),
        ],
        vec![
            ("origin", "https://app.example.com"),
            ("access-control-request-method", "PATCH"),
        ],
        vec![
            ("origin", "https://a.wild.example"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "x-other"),
        ],
        // A rule with no allowed headers admits no preflight that lists any, an empty list included.
        vec![
            ("origin", "https://any.example"),
            ("access-control-request-method", "HEAD"),
            ("access-control-request-headers", ""),
        ],
    ] {
        let answer = preflight_headers(&pairs).expect("a readable origin");
        assert!(answer.is_empty(), "{pairs:?} answered {answer:?}");
    }
}

#[test]
fn n_an_empty_document_and_an_unruled_method_answer_nothing() {
    let origin = request(&[("origin", "https://app.example.com")]);
    assert_eq!(bucket_headers(&document(Vec::new()), &Method::GET, &origin), Some(Vec::new()));
    assert_eq!(bucket_headers(&lab(), &Method::PATCH, &origin), Some(Vec::new()));
}

#[test]
fn n_an_unreadable_origin_reads_as_no_document() {
    let mut headers = HeaderMap::new();
    headers.insert(ORIGIN, HeaderValue::from_bytes(b"https://caf\xc3\xa9.example").expect("an opaque value"));
    assert_eq!(bucket_headers(&lab(), &Method::GET, &headers), None);
    assert_eq!(bucket_headers(&lab(), &Method::GET, &HeaderMap::new()), None);
}

#[test]
fn an_ordinary_request_is_answered_with_exposed_headers_and_no_preflight_headers() {
    let pairs = bucket_headers(&lab(), &Method::GET, &request(&[("origin", "https://app.example.com")])).expect("readable");
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_ORIGIN), Some("https://app.example.com"));
    assert_eq!(get(&pairs, &VARY), Some("Origin"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_METHODS), Some("GET, PUT"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_EXPOSE_HEADERS), Some("ETag, x-amz-request-id"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_HEADERS), None);
    assert_eq!(get(&pairs, &ACCESS_CONTROL_MAX_AGE), None);
}

#[test]
fn an_ordinary_request_carrying_a_request_method_is_matched_on_it() {
    let pairs = bucket_headers(
        &lab(),
        &Method::GET,
        &request(&[("origin", "https://any.example"), ("access-control-request-method", "HEAD")]),
    )
    .expect("readable");
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_METHODS), Some("HEAD"));
    let unmatched = bucket_headers(&lab(), &Method::GET, &request(&[("origin", "https://any.example")])).expect("readable");
    assert!(unmatched.is_empty(), "GET matched the HEAD-only wildcard rule: {unmatched:?}");
}

#[test]
fn a_header_value_that_cannot_be_written_is_left_out() {
    let configuration = document(vec![rule(&["https://app.example.com"], &["GET"], &[], &["etag\u{7f}"], Some(-5))]);
    let pairs =
        bucket_headers(&configuration, &Method::GET, &request(&[("origin", "https://app.example.com")])).expect("readable");
    assert_eq!(get(&pairs, &ACCESS_CONTROL_ALLOW_ORIGIN), Some("https://app.example.com"));
    assert_eq!(get(&pairs, &ACCESS_CONTROL_EXPOSE_HEADERS), None);
    let preflight = bucket_headers(
        &configuration,
        &Method::OPTIONS,
        &request(&[
            ("origin", "https://app.example.com"),
            ("access-control-request-method", "GET"),
        ]),
    )
    .expect("readable");
    assert_eq!(
        get(&preflight, &ACCESS_CONTROL_MAX_AGE),
        Some("-5"),
        "legacy writes a negative age as it is"
    );
}
