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
//! answers never do (`src/cors_legacy.rs` says why).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;

use bytes::Bytes;
use rustfs_gateway::dto::{
    CorsConfiguration, CorsRule, GetBucketVersioning, GetBucketVersioningOutput, ListBuckets, ListBucketsOutput,
};
use rustfs_gateway::{
    BoxFuture, BucketName, CorsSource, CorsSourceError, Handler, HandlerResult, LegacyRustfsCors, Req, Resp, S3Service,
    WireResponse,
};

use crate::support::{exchange_wire, signed_with, wired_at_signed_time};

/// The one bucket with a document: `https://app.example.com` may `GET`.
const DOCUMENTED: &str = "documented";

struct OneDocument;

impl CorsSource for OneDocument {
    fn load<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        let found = (bucket.as_str() == DOCUMENTED).then(|| CorsConfiguration {
            cors_rules: vec![CorsRule {
                allowed_origins: vec!["https://app.example.com".to_owned()],
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
    let backend = Arc::new(WritesItsOwn);
    let builder = wired_at_signed_time()
        .cors_source(Arc::new(OneDocument))
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
