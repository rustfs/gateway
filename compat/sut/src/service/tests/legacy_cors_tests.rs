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

//! CORS as the RustFS-profile launcher answers it: legacy RustFS's answers (rustfs/gateway#1120).
//!
//! Responsible for: every preflight and ordinary-request scenario observed side by side against a
//! legacy RustFS build over one stored document — an exact origin, a wildcard origin and a one-`*`
//! pattern — and over a bucket without one: statuses, the empty `400`/`403`/`200` preflight
//! answers, each `Access-Control-*` header and `Vary`, the decoration of errors and of refusals
//! before authentication, and what a refused write leaves in storage.
//! NOT responsible for: the rules one by one (`rustfs-gateway`'s `src/cors_legacy_tests.rs`) or the
//! fallback origins, which this launcher does not configure (`rustfs-gateway`'s
//! `tests/legacy_cors.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour: `ConditionalCorsLayer` (`rustfs/src/server/layer.rs:2012-2309`) and
//! `apply_cors_headers` (`rustfs/src/storage/ecfs_extend.rs:852-1060`) on rustfs/rustfs
//! `e870a6d25b`, observed against a legacy RustFS build (`RUSTFS_S3_STACK=legacy`) with the same
//! document stored; every expectation below is one of those observations but one: legacy RustFS
//! also answers `Access-Control-Allow-Credentials: true` to every request carrying
//! `Authorization`, `Cookie`, `x-amz-security-token` or `x-amz-content-sha256`, echoing the origin
//! even under the wildcard rule, and the RustFS profile never does (GHSA-x5xv-223c-8vm7; the
//! gateway writes that header from one place only). Those cases assert its absence.

use super::*;

const RULES: &str = "<CORSConfiguration>\
<CORSRule><AllowedOrigin>https://app.example.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod>\
<AllowedHeader>*</AllowedHeader><ExposeHeader>ETag</ExposeHeader><ExposeHeader>x-amz-request-id</ExposeHeader>\
<MaxAgeSeconds>600</MaxAgeSeconds></CORSRule>\
<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>HEAD</AllowedMethod></CORSRule>\
<CORSRule><AllowedOrigin>https://*.wild.example</AllowedOrigin><AllowedMethod>POST</AllowedMethod>\
<AllowedHeader>content-type</AllowedHeader></CORSRule>\
</CORSConfiguration>";

const CONTENT: &[u8] = b"cors content";

/// Two buckets, one object, and the document stored on the first.
async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    for bucket in ["/cors-bucket", "/plain-bucket"] {
        let created = exchange(&service, as_main(http::Method::PUT, bucket, Bytes::new())).await;
        assert_eq!(created.status(), 200, "{}", body_of(&created));
    }
    let put = exchange(&service, as_main(http::Method::PUT, "/cors-bucket/obj", Bytes::from_static(CONTENT))).await;
    assert_eq!(put.status(), 200, "{}", body_of(&put));
    let stored = exchange(
        &service,
        as_main(http::Method::PUT, "/cors-bucket?cors", Bytes::from_static(RULES.as_bytes())),
    )
    .await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

/// An unsigned request, as a browser's preflight always is.
fn unsigned(method: http::Method, path: &str, pairs: &[(&str, &str)], body: &'static [u8]) -> http::Request<Bytes> {
    let mut request = http::Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::HOST, "s3.example.com");
    for (name, value) in pairs {
        request = request.header(*name, *value);
    }
    if !body.is_empty() {
        request = request.header(http::header::CONTENT_LENGTH, body.len());
    }
    request.body(Bytes::from_static(body)).expect("a valid request")
}

fn options(path: &str, pairs: &[(&str, &str)]) -> http::Request<Bytes> {
    unsigned(http::Method::OPTIONS, path, pairs, b"")
}

fn header<'a>(response: &'a WireResponse, name: &str) -> Option<&'a str> {
    response.header(name)
}

const CORS_HEADERS: [&str; 6] = [
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-allow-credentials",
    "access-control-max-age",
];

fn assert_no_cors(response: &WireResponse, what: &str) {
    for name in CORS_HEADERS {
        assert_eq!(header(response, name), None, "{what}: {name}");
    }
}

/// A legacy preflight answer that allows nothing: `status`, `Content-Length: 0`, and no content,
/// no `Content-Type`, no `Access-Control-*` header.
fn assert_empty_answer(response: &WireResponse, status: u16, what: &str) {
    assert_eq!(response.status(), status, "{what}: {}", body_of(response));
    assert!(response.body().is_empty(), "{what}: {}", body_of(response));
    assert_eq!(header(response, "content-length"), Some("0"), "{what}");
    assert_eq!(header(response, "content-type"), None, "{what}");
    assert_no_cors(response, what);
}

// ── preflights ─────────────────────────────────────────────────────────────────────────────────

/// Positive — a preflight a rule admits is `200` with no content, the rule's methods, the
/// requested headers lower-cased and comma-joined, its max age, a three-name `Vary` for an echoed
/// origin, and no exposed headers.
#[tokio::test]
async fn a_matched_preflight_answers_the_rule() {
    let root = TestRoot::new();
    let service = served(&root).await;

    let get = exchange(
        &service,
        options(
            "/cors-bucket/obj",
            &[
                ("origin", "https://app.example.com"),
                ("access-control-request-method", "GET"),
            ],
        ),
    )
    .await;
    assert_eq!(get.status(), 200, "{}", body_of(&get));
    assert!(get.body().is_empty());
    assert_eq!(header(&get, "content-length"), Some("0"));
    assert_eq!(header(&get, "access-control-allow-origin"), Some("https://app.example.com"));
    assert_eq!(
        header(&get, "vary"),
        Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
    );
    assert_eq!(header(&get, "access-control-allow-methods"), Some("GET, PUT"));
    assert_eq!(header(&get, "access-control-max-age"), Some("600"));
    assert_eq!(header(&get, "access-control-expose-headers"), None);
    assert_eq!(header(&get, "access-control-allow-headers"), None);
    assert_eq!(header(&get, "access-control-allow-credentials"), None);

    let put = exchange(
        &service,
        options(
            "/cors-bucket/obj",
            &[
                ("origin", "https://app.example.com"),
                ("access-control-request-method", "PUT"),
                ("access-control-request-headers", "Content-Type, X-Amz-Meta-Foo"),
            ],
        ),
    )
    .await;
    assert_eq!(put.status(), 200);
    assert_eq!(header(&put, "access-control-allow-headers"), Some("content-type,x-amz-meta-foo"));

    let bucket_only = exchange(
        &service,
        options(
            "/cors-bucket",
            &[
                ("origin", "https://app.example.com"),
                ("access-control-request-method", "GET"),
            ],
        ),
    )
    .await;
    assert_eq!(bucket_only.status(), 200);
    assert_eq!(header(&bucket_only, "access-control-allow-origin"), Some("https://app.example.com"));
}

/// Positive — a wildcard rule answers `*` without `Origin` in `Vary`; a one-`*` pattern echoes the
/// origin.
#[tokio::test]
async fn a_wildcard_rule_and_a_pattern_rule_answer_their_origins() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let wildcard = exchange(
        &service,
        options(
            "/cors-bucket/obj",
            &[("origin", "https://any.example"), ("access-control-request-method", "HEAD")],
        ),
    )
    .await;
    assert_eq!(wildcard.status(), 200);
    assert_eq!(header(&wildcard, "access-control-allow-origin"), Some("*"));
    assert_eq!(header(&wildcard, "access-control-allow-methods"), Some("HEAD"));
    assert_eq!(
        header(&wildcard, "vary"),
        Some("Access-Control-Request-Method, Access-Control-Request-Headers")
    );
    let pattern = exchange(
        &service,
        options(
            "/cors-bucket/obj",
            &[
                ("origin", "https://a.wild.example"),
                ("access-control-request-method", "POST"),
                ("access-control-request-headers", "content-type"),
            ],
        ),
    )
    .await;
    assert_eq!(pattern.status(), 200);
    assert_eq!(header(&pattern, "access-control-allow-origin"), Some("https://a.wild.example"));
    assert_eq!(header(&pattern, "access-control-allow-headers"), Some("content-type"));
}

/// Negative — a preflight carrying `Authorization` under the wildcard rule gets its origin echoed
/// with `Origin` in `Vary`, as legacy RustFS answers it, and none of the credentials legacy RustFS
/// adds.
#[tokio::test]
async fn n_a_credentialed_preflight_gets_its_origin_and_no_credentials() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let answered = exchange(
        &service,
        options(
            "/cors-bucket/obj",
            &[
                ("origin", "https://any.example"),
                ("access-control-request-method", "HEAD"),
                ("authorization", "x"),
            ],
        ),
    )
    .await;
    assert_eq!(answered.status(), 200, "{}", body_of(&answered));
    assert_eq!(header(&answered, "access-control-allow-origin"), Some("https://any.example"));
    assert_eq!(
        header(&answered, "vary"),
        Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
    );
    assert_eq!(header(&answered, "access-control-allow-methods"), Some("HEAD"));
    assert_eq!(header(&answered, "access-control-allow-credentials"), None);
}

/// Negative — a preflight no rule admits is `403` with no content and no header naming why: an
/// unknown origin, a method in another case, a method no rule can hold, a header the rule does not
/// allow.
#[tokio::test]
async fn n_a_preflight_no_rule_admits_is_an_empty_forbidden() {
    let root = TestRoot::new();
    let service = served(&root).await;
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
    ] {
        let refused = exchange(&service, options("/cors-bucket/obj", &pairs)).await;
        assert_empty_answer(&refused, 403, &format!("{pairs:?}"));
    }
}

/// Negative — without `Origin` or `Access-Control-Request-Method` a preflight of a bucket path or
/// of `/` is `400` with no content.
#[tokio::test]
async fn n_an_incomplete_preflight_is_an_empty_bad_request() {
    let root = TestRoot::new();
    let service = served(&root).await;
    for path in ["/cors-bucket/obj", "/plain-bucket/obj", "/"] {
        for pairs in [
            vec![("origin", "https://app.example.com")],
            vec![("access-control-request-method", "GET")],
            vec![],
        ] {
            let refused = exchange(&service, options(path, &pairs)).await;
            assert_empty_answer(&refused, 400, &format!("{path} {pairs:?}"));
        }
    }
}

/// Negative — a bucket without a document, a bucket that does not exist, `/`, and a path that is
/// not an S3 path answer a complete preflight `200` with no CORS header when no fallback origins
/// are configured, as they are not for RustFS; the non-S3 path needs no preflight headers at all.
#[tokio::test]
async fn n_a_preflight_without_a_document_is_answered_by_the_fallback() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let complete = [
        ("origin", "https://app.example.com"),
        ("access-control-request-method", "GET"),
    ];
    for path in ["/plain-bucket/obj", "/no-such-bucket-here/obj", "/", "/rustfs/admin/v3/info"] {
        let answered = exchange(&service, options(path, &complete)).await;
        assert_empty_answer(&answered, 200, path);
    }
    let admin_without_headers = exchange(&service, options("/rustfs/admin/v3/info", &[])).await;
    assert_empty_answer(&admin_without_headers, 200, "an admin path needs no preflight headers");
}

// ── ordinary requests ──────────────────────────────────────────────────────────────────────────

/// Positive — a signed request whose origin a rule admits gets the rule's headers with its origin
/// echoed — on success, on an error, on a listing and on a write — and none of the credentials
/// legacy RustFS adds to a signed request.
#[tokio::test]
async fn a_signed_request_gets_the_rule_and_no_credentials() {
    let root = TestRoot::new();
    let service = served(&root).await;
    for (method, target, status) in [
        (http::Method::GET, "/cors-bucket/obj", 200),
        (http::Method::GET, "/cors-bucket/absent", 404),
        (http::Method::GET, "/cors-bucket?list-type=2", 200),
        (http::Method::PUT, "/cors-bucket/written", 200),
    ] {
        let body = if method == http::Method::PUT {
            Bytes::from_static(b"written")
        } else {
            Bytes::new()
        };
        let response = exchange(
            &service,
            signed(
                MAIN_KEY,
                MAIN_SECRET,
                method.clone(),
                target,
                body,
                &[("origin", "https://app.example.com")],
            ),
        )
        .await;
        let what = format!("{method} {target}");
        assert_eq!(response.status(), status, "{what}: {}", body_of(&response));
        assert_eq!(
            header(&response, "access-control-allow-origin"),
            Some("https://app.example.com"),
            "{what}"
        );
        assert_eq!(header(&response, "vary"), Some("Origin"), "{what}");
        assert_eq!(header(&response, "access-control-allow-methods"), Some("GET, PUT"), "{what}");
        assert_eq!(
            header(&response, "access-control-expose-headers"),
            Some("ETag, x-amz-request-id"),
            "{what}"
        );
        assert_eq!(header(&response, "access-control-max-age"), None, "{what}");
        assert_eq!(header(&response, "access-control-allow-credentials"), None, "{what}");
    }
    let written = exchange(&service, as_main(http::Method::GET, "/cors-bucket/written", Bytes::new())).await;
    assert_eq!(written.body().as_ref(), b"written");
}

/// Positive, and the data-layer half — a request refused before authentication gets the rule's
/// headers as well, a `Cookie` changing nothing but what legacy RustFS would have added; the
/// refused write stores nothing.
#[tokio::test]
async fn a_refusal_before_authentication_is_decorated_too() {
    let root = TestRoot::new();
    let service = served(&root).await;
    for (method, body) in [(http::Method::GET, &b""[..]), (http::Method::PUT, &b"anon"[..])] {
        for pairs in [
            vec![("origin", "https://app.example.com")],
            vec![("origin", "https://app.example.com"), ("cookie", "session=1")],
        ] {
            let refused = exchange(&service, unsigned(method.clone(), "/cors-bucket/anonymous", &pairs, body)).await;
            let what = format!("{method} {pairs:?}");
            assert_eq!(refused.status(), 403, "{what}: {}", body_of(&refused));
            assert_eq!(header(&refused, "access-control-allow-origin"), Some("https://app.example.com"), "{what}");
            assert_eq!(header(&refused, "vary"), Some("Origin"), "{what}");
            assert_eq!(header(&refused, "access-control-allow-methods"), Some("GET, PUT"), "{what}");
            assert_eq!(header(&refused, "access-control-allow-credentials"), None, "{what}");
        }
    }
    let stored = exchange(&service, as_main(http::Method::GET, "/cors-bucket/anonymous", Bytes::new())).await;
    assert_eq!(stored.status(), 404, "{}", body_of(&stored));
}

/// Positive — a wildcard rule answers `*` to an unsigned request and the echoed origin to a signed
/// one, without credentials; `Access-Control-Request-Method` on an ordinary request selects the
/// rule.
#[tokio::test]
async fn a_wildcard_rule_follows_the_credential_and_the_request_method_header() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let anonymous = exchange(
        &service,
        unsigned(http::Method::HEAD, "/cors-bucket/obj", &[("origin", "https://any.example")], b""),
    )
    .await;
    assert_eq!(anonymous.status(), 403);
    assert_eq!(header(&anonymous, "access-control-allow-origin"), Some("*"));
    assert_eq!(header(&anonymous, "vary"), None);
    assert_eq!(header(&anonymous, "access-control-allow-methods"), Some("HEAD"));

    let signed_head = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::HEAD,
            "/cors-bucket/obj",
            Bytes::new(),
            &[("origin", "https://any.example")],
        ),
    )
    .await;
    assert_eq!(signed_head.status(), 200);
    assert_eq!(header(&signed_head, "access-control-allow-origin"), Some("https://any.example"));
    assert_eq!(header(&signed_head, "vary"), Some("Origin"));
    assert_eq!(header(&signed_head, "access-control-allow-credentials"), None);

    let selected = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::GET,
            "/cors-bucket/obj",
            Bytes::new(),
            &[("origin", "https://any.example"), ("access-control-request-method", "HEAD")],
        ),
    )
    .await;
    assert_eq!(selected.status(), 200);
    assert_eq!(header(&selected, "access-control-allow-methods"), Some("HEAD"));
}

/// Negative — an origin no rule admits, a bucket without a document, and a request without
/// `Origin` get no CORS header and no `Vary`.
#[tokio::test]
async fn n_an_unadmitted_request_gets_no_cors_header() {
    let root = TestRoot::new();
    let service = served(&root).await;
    for (target, pairs) in [
        ("/cors-bucket/obj", vec![("origin", "https://evil.example")]),
        ("/plain-bucket?list-type=2", vec![("origin", "https://app.example.com")]),
        ("/cors-bucket/obj", vec![]),
    ] {
        let response = exchange(&service, signed(MAIN_KEY, MAIN_SECRET, http::Method::GET, target, Bytes::new(), &pairs)).await;
        assert_eq!(response.status(), 200, "{target}: {}", body_of(&response));
        assert_no_cors(&response, target);
        assert_eq!(header(&response, "vary"), None, "{target}");
    }
}

/// Positive — a `304` is decorated like any other answer, after the RustFS profile strips it to
/// legacy RustFS's headers: a `GET`'s keeps its validators beside the rule's headers, a `HEAD`'s has
/// only the rule's.
#[tokio::test]
async fn a_not_modified_answer_is_decorated_too() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let etag = exchange(&service, as_main(http::Method::HEAD, "/cors-bucket/obj", Bytes::new()))
        .await
        .header("etag")
        .expect("an entity tag")
        .to_owned();

    let get = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::GET,
            "/cors-bucket/obj",
            Bytes::new(),
            &[("origin", "https://app.example.com"), ("if-none-match", etag.as_str())],
        ),
    )
    .await;
    assert_eq!(get.status(), 304, "{}", body_of(&get));
    assert_eq!(header(&get, "etag"), Some(etag.as_str()));
    assert!(header(&get, "last-modified").is_some());
    assert_eq!(header(&get, "access-control-allow-origin"), Some("https://app.example.com"));
    assert_eq!(header(&get, "vary"), Some("Origin"));
    assert_eq!(header(&get, "access-control-allow-methods"), Some("GET, PUT"));
    assert_eq!(header(&get, "access-control-expose-headers"), Some("ETag, x-amz-request-id"));
    assert_eq!(header(&get, "access-control-allow-credentials"), None);

    let head = exchange(
        &service,
        signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::HEAD,
            "/cors-bucket/obj",
            Bytes::new(),
            &[("origin", "https://any.example"), ("if-none-match", etag.as_str())],
        ),
    )
    .await;
    assert_eq!(head.status(), 304);
    assert_eq!(header(&head, "etag"), None);
    assert_eq!(header(&head, "access-control-allow-origin"), Some("https://any.example"));
    assert_eq!(header(&head, "vary"), Some("Origin"));
    assert_eq!(header(&head, "access-control-allow-methods"), Some("HEAD"));
    assert_eq!(header(&head, "access-control-allow-credentials"), None);
}
