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

//! Legacy RustFS's CORS answers through the facade (rustfs/gateway#1120): the deployment-wide
//! fallback origins, and what a handler already wrote.
//!
//! Responsible for: `RUSTFS_CORS_ALLOWED_ORIGINS` read as `*` and as a list — on `/`, on a path
//! that is not an S3 path, on a bucket without a document, on a preflight and on an ordinary
//! answer — the bucket's document deciding over whatever `Access-Control-*` headers a handler
//! handed over, credentials among them, a handler's own allowance kept where the fallback applies,
//! and the gateway's own answers without the setting.
//! NOT responsible for: the rules one by one (`src/cors_legacy_tests.rs`) or the scenarios over a
//! stored document behind the RustFS assembly (`compat/sut`'s `legacy_cors_tests.rs`).
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! Every expectation but the credentials is legacy RustFS's answer (`ConditionalCorsLayer`,
//! rustfs/rustfs `e870a6d25b` `rustfs/src/server/layer.rs:2012-2309`): legacy RustFS allows
//! credentials to a listed fallback origin and to a credentialed request a rule matches, and these
//! answers require an explicit exact-origin operator policy (`src/cors_legacy.rs` says why).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use bytes::Bytes;
use rustfs_gateway::dto::{
    CorsConfiguration, CorsRule, GetBucketVersioning, GetBucketVersioningOutput, ListBuckets, ListBucketsOutput,
};
use rustfs_gateway::{
    BoxFuture, BucketName, CorsOrigins, CorsPolicy, CorsSource, CorsSourceError, Handler, HandlerResult, LegacyRustfsCors, Req,
    Resp, S3Service, WireResponse,
};

use crate::support::{exchange_wire, signed_with, wired_at_signed_time};

/// The one bucket with a document: `https://app.example.com` may `GET`.
const DOCUMENTED: &str = "documented";

struct OneDocument(&'static str);

impl CorsSource for OneDocument {
    fn load<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        let found = (bucket.as_str() == DOCUMENTED).then(|| CorsConfiguration {
            cors_rules: vec![CorsRule {
                allowed_origins: vec![self.0.to_owned()],
                allowed_methods: vec!["GET".to_owned()],
                ..CorsRule::default()
            }],
        });
        Box::pin(async move { Ok(found) })
    }
}

/// Handlers that hand over `Access-Control-*` headers of their own, as a bridged RustFS object
/// handler does.
struct WritesItsOwn;

fn own_headers() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert("access-control-allow-origin", http::HeaderValue::from_static("https://app.example.com"));
    headers.insert("access-control-allow-credentials", http::HeaderValue::from_static("true"));
    headers.insert("access-control-allow-methods", http::HeaderValue::from_static("PATCH"));
    headers
}

impl Handler<GetBucketVersioning> for WritesItsOwn {
    async fn call(&self, _request: Req<GetBucketVersioning>) -> HandlerResult<GetBucketVersioning> {
        Ok(Resp::new(GetBucketVersioningOutput::default()).with_extra_headers(own_headers()))
    }
}

impl Handler<ListBuckets> for WritesItsOwn {
    async fn call(&self, _request: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
        let mut headers = http::HeaderMap::new();
        headers.insert("access-control-allow-origin", http::HeaderValue::from_static("https://handler.example"));
        Ok(Resp::new(ListBucketsOutput::default()).with_extra_headers(headers))
    }
}

fn assembly(cors: Option<LegacyRustfsCors>) -> S3Service {
    assembly_with_policy(cors, CorsPolicy::default(), "https://app.example.com")
}

fn assembly_with_policy(cors: Option<LegacyRustfsCors>, policy: CorsPolicy, bucket_origin: &'static str) -> S3Service {
    let backend = Arc::new(WritesItsOwn);
    let builder = wired_at_signed_time()
        .cors_source(Arc::new(OneDocument(bucket_origin)))
        .cors_policy(policy)
        .register::<GetBucketVersioning, _>(Arc::clone(&backend))
        .register::<ListBuckets, _>(backend);
    match cors {
        Some(cors) => builder.answer_cors_as_legacy_rustfs(cors),
        None => builder,
    }
    .build()
    .expect("a complete assembly")
}

fn unsigned(method: http::Method, target: &str, pairs: &[(&str, &str)]) -> http::Request<Bytes> {
    let mut request = http::Request::builder()
        .method(method)
        .uri(target)
        .header(http::header::HOST, "s3.example.com");
    for (name, value) in pairs {
        request = request.header(*name, *value);
    }
    request.body(Bytes::new()).expect("a valid request")
}

fn header<'a>(response: &'a WireResponse, name: &str) -> Option<&'a str> {
    response.header(name)
}

/// The fallback answer: `origin` allowed with the fixed methods, headers and exposed headers, and
/// no credentials.
fn assert_fallback(response: &WireResponse, origin: &str, what: &str) {
    assert_eq!(header(response, "access-control-allow-origin"), Some(origin), "{what}");
    assert_eq!(
        header(response, "access-control-allow-methods"),
        Some("GET, POST, PUT, DELETE, OPTIONS, HEAD"),
        "{what}"
    );
    assert_eq!(header(response, "access-control-allow-headers"), Some("*"), "{what}");
    assert_eq!(
        header(response, "access-control-expose-headers"),
        Some("x-request-id, x-amz-request-id, content-type, content-length, etag"),
        "{what}"
    );
    assert_eq!(header(response, "access-control-allow-credentials"), None, "{what}");
}

const PREFLIGHT: [(&str, &str); 2] = [("origin", "https://any.example"), ("access-control-request-method", "GET")];

/// Positive — with the fallback `*`, a preflight of `/`, of a path that is not an S3 path, and of a
/// bucket without a document is `200` with `*` and the fixed lists; an ordinary answer on those
/// paths, a refusal included, carries them too.
#[tokio::test]
async fn a_fallback_star_answers_every_path_without_a_document() {
    let service = assembly(Some(LegacyRustfsCors::with_fallback_origins(Some("*"))));
    for target in ["/", "/rustfs/admin/v3/info", "/undocumented/key"] {
        let response = exchange_wire(&service, unsigned(http::Method::OPTIONS, target, &PREFLIGHT)).await;
        assert_eq!(response.status(), 200, "{target}");
        assert!(response.body().is_empty(), "{target}");
        assert_fallback(&response, "*", target);
    }
    for target in ["/", "/undocumented/key"] {
        let refused = exchange_wire(&service, unsigned(http::Method::GET, target, &[("origin", "https://any.example")])).await;
        // Anonymous `ListBuckets` is refused, and this assembly serves no `GetObject`: both refusals.
        assert!(refused.status().as_u16() >= 400, "{target}: {}", refused.status());
        assert_fallback(&refused, "*", target);
    }
}

/// Positive and negative — with a list, a listed origin is echoed with the fixed lists and no
/// credentials; an origin the list does not name gets nothing, and neither does a request whose
/// bucket's document admits nothing, whatever the fallback says.
#[tokio::test]
async fn a_listed_fallback_origin_is_echoed_and_nothing_else_is() {
    let service = assembly(Some(LegacyRustfsCors::with_fallback_origins(Some(
        "https://a.example, https://b.example",
    ))));
    let listed = exchange_wire(
        &service,
        unsigned(
            http::Method::OPTIONS,
            "/",
            &[("origin", "https://b.example"), ("access-control-request-method", "GET")],
        ),
    )
    .await;
    assert_eq!(listed.status(), 200);
    assert_fallback(&listed, "https://b.example", "listed");

    let unlisted = exchange_wire(
        &service,
        unsigned(
            http::Method::OPTIONS,
            "/",
            &[("origin", "https://c.example"), ("access-control-request-method", "GET")],
        ),
    )
    .await;
    assert_eq!(unlisted.status(), 200);
    assert_eq!(header(&unlisted, "access-control-allow-origin"), None);

    let documented = exchange_wire(
        &service,
        signed_with(
            http::Method::GET,
            &format!("/{DOCUMENTED}?versioning"),
            &[("origin", "https://a.example")],
        ),
    )
    .await;
    assert_eq!(documented.status(), 200);
    for name in [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-credentials",
    ] {
        assert_eq!(header(&documented, name), None, "{name}");
    }
}

/// Negative — the bucket's document decides over the `Access-Control-*` headers a handler handed
/// over: its methods replace the handler's, and the handler's credentials are gone.
#[tokio::test]
async fn n_a_documented_bucket_replaces_what_a_handler_wrote() {
    let service = assembly(Some(LegacyRustfsCors::with_fallback_origins(None)));
    let response = exchange_wire(
        &service,
        signed_with(
            http::Method::GET,
            &format!("/{DOCUMENTED}?versioning"),
            &[("origin", "https://app.example.com")],
        ),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(header(&response, "access-control-allow-origin"), Some("https://app.example.com"));
    assert_eq!(header(&response, "access-control-allow-methods"), Some("GET"));
    assert_eq!(header(&response, "vary"), Some("Origin"));
    assert_eq!(header(&response, "access-control-allow-credentials"), None);
}

/// Positive — where the fallback applies, an answer whose handler already allowed an origin is
/// left as the handler wrote it, as legacy RustFS leaves it.
#[tokio::test]
async fn a_handlers_own_allowance_is_kept_where_the_fallback_applies() {
    let service = assembly(Some(LegacyRustfsCors::with_fallback_origins(Some("*"))));
    let response = exchange_wire(&service, signed_with(http::Method::GET, "/", &[("origin", "https://any.example")])).await;
    assert_eq!(response.status(), 200);
    assert_eq!(header(&response, "access-control-allow-origin"), Some("https://handler.example"));
    assert_eq!(header(&response, "access-control-allow-methods"), None);
}

/// Negative — without the setting the gateway answers its own CORS: a preflight of a bucket without
/// a document is refused with a document, and a path that is not an S3 path is not answered as a
/// preflight at all.
#[tokio::test]
async fn n_without_the_setting_the_gateways_own_answers_stand() {
    let service = assembly(None);
    let undocumented = exchange_wire(&service, unsigned(http::Method::OPTIONS, "/undocumented/key", &PREFLIGHT)).await;
    assert_eq!(undocumented.status(), 403);
    assert!(!undocumented.body().is_empty());
    let root = exchange_wire(&service, unsigned(http::Method::OPTIONS, "/", &PREFLIGHT)).await;
    assert_ne!(root.status(), 200);
}

fn exact_policy(origin: &str, credentials: bool) -> CorsPolicy {
    CorsPolicy::new(CorsOrigins::Exact(Box::from([origin.to_owned()])), credentials).expect("an exact origin policy")
}

fn credentialed_assembly(policy: CorsPolicy, bucket_origin: &'static str, fallback: &str) -> S3Service {
    assembly_with_policy(Some(LegacyRustfsCors::with_fallback_origins(Some(fallback))), policy, bucket_origin)
}

const APP: &str = "https://app.example.com";
const APP_PREFLIGHT: [(&str, &str); 2] = [("origin", APP), ("access-control-request-method", "GET")];

#[tokio::test]
async fn exact_operator_and_bucket_origins_allow_credentials_on_both_browser_requests() {
    let service = credentialed_assembly(exact_policy(APP, true), APP, "*");
    let preflight = exchange_wire(&service, unsigned(http::Method::OPTIONS, "/documented?versioning", &APP_PREFLIGHT)).await;
    let actual = exchange_wire(&service, signed_with(http::Method::GET, "/documented?versioning", &[("origin", APP)])).await;
    for response in [preflight, actual] {
        assert_eq!(response.status(), 200);
        assert_eq!(header(&response, "access-control-allow-origin"), Some(APP));
        assert_eq!(header(&response, "access-control-allow-credentials"), Some("true"));
    }
}

#[tokio::test]
async fn exact_operator_and_fallback_origins_allow_credentials_on_preflight_and_refusal() {
    let service = credentialed_assembly(exact_policy(APP, true), APP, APP);
    let preflight = exchange_wire(
        &service,
        unsigned(
            http::Method::OPTIONS,
            "/undocumented/key",
            &[
                ("origin", APP),
                ("access-control-request-method", "GET"),
                ("access-control-request-headers", "Authorization, X-Amz-Date"),
            ],
        ),
    )
    .await;
    assert_eq!(preflight.status(), 200);
    assert_eq!(header(&preflight, "access-control-allow-headers"), Some("authorization, x-amz-date"));
    assert_eq!(
        header(&preflight, "vary"),
        Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
    );
    assert_eq!(header(&preflight, "access-control-allow-credentials"), Some("true"));
    let refused = exchange_wire(&service, unsigned(http::Method::GET, "/undocumented/key", &[("origin", APP)])).await;
    assert!(refused.status().as_u16() >= 400);
    assert_eq!(header(&refused, "access-control-allow-origin"), Some(APP));
    assert_eq!(header(&refused, "access-control-allow-credentials"), Some("true"));
}

#[tokio::test]
async fn n_a_bucket_allowance_cannot_override_the_operators_credential_policy() {
    for policy in [
        exact_policy("https://other.example", true),
        exact_policy(APP, false),
        CorsPolicy::default(),
    ] {
        let service = credentialed_assembly(policy, APP, APP);
        let preflight = exchange_wire(&service, unsigned(http::Method::OPTIONS, "/documented?versioning", &APP_PREFLIGHT)).await;
        let actual = exchange_wire(&service, signed_with(http::Method::GET, "/documented?versioning", &[("origin", APP)])).await;
        for response in [preflight, actual] {
            assert_eq!(response.status(), 200);
            assert_eq!(header(&response, "access-control-allow-credentials"), None);
        }
    }
}

#[tokio::test]
async fn n_a_wildcard_bucket_rule_never_supplies_credentials_even_to_a_signed_request() {
    for origin in ["*", "https://*.example.com"] {
        let service = credentialed_assembly(exact_policy(APP, true), origin, APP);
        let preflight = exchange_wire(&service, unsigned(http::Method::OPTIONS, "/documented?versioning", &APP_PREFLIGHT)).await;
        let actual = exchange_wire(&service, signed_with(http::Method::GET, "/documented?versioning", &[("origin", APP)])).await;
        for response in [preflight, actual] {
            assert_eq!(response.status(), 200);
            assert_eq!(header(&response, "access-control-allow-credentials"), None);
        }
    }
}

#[tokio::test]
async fn n_a_fallback_star_or_unlisted_origin_never_supplies_credentials() {
    for (fallback, origin) in [("*", APP), (APP, "https://other.example")] {
        let service = credentialed_assembly(exact_policy(APP, true), APP, fallback);
        let preflight = exchange_wire(
            &service,
            unsigned(
                http::Method::OPTIONS,
                "/undocumented/key",
                &[("origin", origin), ("access-control-request-method", "GET")],
            ),
        )
        .await;
        let actual = exchange_wire(&service, unsigned(http::Method::GET, "/undocumented/key", &[("origin", origin)])).await;
        for response in [preflight, actual] {
            assert_eq!(header(&response, "access-control-allow-credentials"), None);
        }
    }
}

#[tokio::test]
async fn n_an_exact_operator_origin_cannot_override_a_bucket_method_refusal() {
    let service = credentialed_assembly(exact_policy(APP, true), APP, APP);
    let response = exchange_wire(
        &service,
        unsigned(
            http::Method::OPTIONS,
            "/documented/key",
            &[("origin", APP), ("access-control-request-method", "PUT")],
        ),
    )
    .await;
    assert_eq!(response.status(), 403);
    assert_eq!(header(&response, "access-control-allow-origin"), None);
    assert_eq!(header(&response, "access-control-allow-credentials"), None);
}

#[tokio::test]
async fn n_credentialed_cors_does_not_authenticate_an_unsigned_or_forged_request() {
    let service = credentialed_assembly(exact_policy(APP, true), APP, APP);
    let unsigned = unsigned(
        http::Method::GET,
        "/documented?versioning",
        &[("origin", APP), ("cookie", "session=untrusted")],
    );
    let mut forged = signed_with(http::Method::GET, "/documented?versioning", &[("origin", APP)]);
    forged
        .headers_mut()
        .insert("origin", http::HeaderValue::from_static("https://changed.example"));
    for request in [unsigned, forged] {
        let response = exchange_wire(&service, request).await;
        assert_eq!(response.status(), 403);
    }
}

#[tokio::test]
async fn n_duplicate_origins_cannot_enable_credentials() {
    let service = credentialed_assembly(exact_policy(APP, true), APP, APP);
    for path in ["/documented?versioning", "/undocumented/key"] {
        let mut request = unsigned(http::Method::OPTIONS, path, &APP_PREFLIGHT);
        request
            .headers_mut()
            .append("origin", http::HeaderValue::from_static("https://other.example"));
        let response = exchange_wire(&service, request).await;
        assert_eq!(header(&response, "access-control-allow-credentials"), None);
    }
}

#[tokio::test]
async fn n_a_handlers_other_origin_cannot_inherit_the_requests_credentials() {
    let service = credentialed_assembly(exact_policy(APP, true), APP, APP);
    let response = exchange_wire(&service, signed_with(http::Method::GET, "/", &[("origin", APP)])).await;
    assert_eq!(response.status(), 200);
    assert_eq!(header(&response, "access-control-allow-origin"), Some("https://handler.example"));
    assert_eq!(header(&response, "access-control-allow-credentials"), None);
}

#[tokio::test]
async fn n_malformed_origins_cannot_enable_credentials_even_when_listed() {
    for origin in ["", "https://app.example.com other"] {
        let service = credentialed_assembly(exact_policy(origin, true), origin, origin);
        for path in ["/documented?versioning", "/undocumented/key"] {
            let response = exchange_wire(
                &service,
                unsigned(
                    http::Method::OPTIONS,
                    path,
                    &[("origin", origin), ("access-control-request-method", "GET")],
                ),
            )
            .await;
            assert_eq!(header(&response, "access-control-allow-credentials"), None);
        }
    }
}

#[tokio::test]
async fn n_credentialed_fallback_rejects_invalid_or_ambiguous_requested_headers() {
    let service = credentialed_assembly(exact_policy(APP, true), APP, APP);
    for value in ["authorization,,x-amz-date", "not a header", "authorization"] {
        let mut request = unsigned(
            http::Method::OPTIONS,
            "/undocumented/key",
            &[
                ("origin", APP),
                ("access-control-request-method", "GET"),
                ("access-control-request-headers", value),
            ],
        );
        if value == "authorization" {
            request
                .headers_mut()
                .append("access-control-request-headers", http::HeaderValue::from_static("x-amz-date"));
        }
        let response = exchange_wire(&service, request).await;
        assert_eq!(header(&response, "access-control-allow-credentials"), None);
    }
}

#[tokio::test]
async fn n_credentialed_fallback_must_preserve_the_handlers_vary_dimensions() {
    struct Varying;
    impl Handler<ListBuckets> for Varying {
        async fn call(&self, _: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
            let mut headers = http::HeaderMap::new();
            headers.insert("vary", http::HeaderValue::from_static("Accept-Encoding"));
            Ok(Resp::new(ListBucketsOutput::default()).with_extra_headers(headers))
        }
    }
    let service = wired_at_signed_time()
        .cors_policy(exact_policy(APP, true))
        .answer_cors_as_legacy_rustfs(LegacyRustfsCors::with_fallback_origins(Some(APP)))
        .register::<ListBuckets, _>(Arc::new(Varying))
        .build()
        .expect("a fallback assembly");
    let response = exchange_wire(&service, signed_with(http::Method::GET, "/", &[("origin", APP)])).await;
    let dimensions: Vec<_> = response
        .headers()
        .iter()
        .filter(|(name, _)| name == "vary")
        .flat_map(|(_, value)| value.to_str().unwrap().split(',').map(str::trim))
        .collect();
    assert!(dimensions.contains(&"Accept-Encoding"));
    assert!(dimensions.contains(&"Origin"));
    assert_eq!(header(&response, "access-control-allow-credentials"), Some("true"));
}
