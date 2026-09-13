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

//! One test per RustFS tower patch layer, asserting that its landing here is real.
//!
//! Responsible for: nine assertions, one for each row of the landing table in
//! `docs/middleware.md`. Six of the nine land on something the framework already does, two on a
//! [`StageFilter`](rustfs_gateway::StageFilter) and one on an
//! [`OpLayer`](rustfs_gateway::OpLayer); this file is where "it lands here" stops being a claim.
//! NOT responsible for: the middleware mechanism itself, which is `tests/middleware.rs`. A test
//! here asserts the *destination*, not the machinery that carries it.
//! Upstream: `tests/support`. Downstream: `scripts/check_patch_layer_map.sh`, which requires the
//! set of test names in this file and the set of rows in the table to be the same set, in both
//! directions.
//!
//! # Why this file has exactly nine tests and no helpers that look like tests
//!
//! The guard reads `fn <name>` under a `#[test]` or `#[tokio::test]` attribute here and compares
//! the set to the table's. A tenth test with no row, or a row naming a test that was renamed,
//! fails the guard — which is the only thing standing between "the table says it lands here" and
//! nobody ever checking. `P10-06` deletes the nine layers from the RustFS tree against this list.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use crate::support;

use std::sync::Arc;

use bytes::Bytes;
use rustfs_gateway::dto::{CorsConfiguration, CorsRule};
use rustfs_gateway::{
    AuthRequirement, BoxFuture, BucketName, CodecError, CorsSource, CorsSourceError, EncodedResponse, Handler, HandlerResult,
    MetaView, Operation, OperationCodec, OperationFloor, OperationSpec, Predicate, Req, RequestBody, ResourceShape, Resp,
    ResponseBody, ResponseView, SigService, TargetKind, VirtualHostStyle, response_filter, wire_filter,
};
use rustfs_gateway_core::{Dialect, DialectOverlay, DialectRoute, HandlerDeadlineClass, OverlayRow};
use support::{
    Backend, ContentPing, HeadPing, LENGTH_ECHO, Ping, attributes_request, attributes_service, exchange, exchange_wire,
    fixed_clock, plain, signed, wired,
};

// ── 1. BodylessStatusFixLayer → the response invariant ──────────────────────────────────────────

/// Negative — a `304` goes out with no content and no framing header, whatever method asked and
/// whatever the encoder wrote. RustFS's layer exists because s3s serialised an XML body onto these
/// statuses, which costs an h2 `GOAWAY`; here the rule is applied once, to every response.
///
/// Two-directional: the same operation answering `200` keeps its content, so the rule is a
/// function of the status and not a body that is always dropped.
#[tokio::test]
async fn bodyless_status_fix_is_the_response_invariant() {
    let service = wired()
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::content_ping_dialect())
        .build()
        .expect("a complete assembly");

    let bodyless = exchange_wire(&service, plain(http::Method::PUT, "/?not-modified")).await;
    assert_eq!(bodyless.status(), http::StatusCode::NOT_MODIFIED);
    assert!(bodyless.body().is_empty(), "a 304 carried content");
    assert_eq!(bodyless.header("content-length"), None);
    assert_eq!(bodyless.header("transfer-encoding"), None);

    let allowed = exchange_wire(&service, plain(http::Method::PUT, "/")).await;
    assert_eq!(allowed.status(), http::StatusCode::OK);
    assert!(!allowed.body().is_empty(), "a 200 lost its content");
}

// ── 2. HeadRequestBodyFixLayer → the response invariant, on the error path ──────────────────────

/// Negative — a `HEAD` that is *refused* still carries no content. This is the half RustFS's layer
/// was written for: the success path is easy to get right and the `404`/`403` path is where an XML
/// error document reached an h2 client that had asked for no body at all.
///
/// Two-directional: the same refusal under a method that may carry content keeps the document, so
/// the rule is about the method and not about errors losing their bodies.
#[tokio::test]
async fn head_request_body_fix_is_the_response_invariant() {
    let service = wired()
        .register::<HeadPing, _>(Arc::new(Backend))
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::head_ping_dialect())
        .dialect(&crate::support::content_ping_dialect())
        .build()
        .expect("a complete assembly");

    let head = exchange_wire(&service, plain(http::Method::HEAD, "/?refuse")).await;
    assert_eq!(head.status(), http::StatusCode::PRECONDITION_FAILED);
    assert!(head.body().is_empty(), "a refused HEAD carried an error document");

    let content = exchange_wire(&service, plain(http::Method::PUT, "/?refuse")).await;
    assert_eq!(content.status(), http::StatusCode::PRECONDITION_FAILED);
    assert!(!content.body().is_empty(), "a refused PUT lost its error document");
}

// ── 3. DoubleSlashListBucketsCompatLayer → the route table ──────────────────────────────────────

/// Positive — `GET //` reaches `ListBuckets`, exactly as `GET /` does. RustFS's layer rewrites the
/// target because s3s read the empty first segment as a bucket name and answered
/// `InvalidBucketName`; here the route table answers the service operation for both spellings, so
/// there is nothing to rewrite.
///
/// Two-directional: `GET /a-bucket` does **not** reach `ListBuckets` — it is a bucket-target
/// request this assembly has no handler for — so the assertion is about the empty segment and not
/// about every `GET` answering a bucket list.
#[tokio::test]
async fn double_slash_list_buckets_compat_is_the_route_table() {
    let service = wired()
        .clock_with_skew_ack(
            fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<rustfs_gateway::dto::ListBuckets, _>(Arc::new(Backend))
        .build()
        .expect("a complete assembly");

    for target in ["/", "//"] {
        let (status, body) = exchange(&service, signed(http::Method::GET, target)).await;
        assert_eq!(status, http::StatusCode::OK, "GET {target}: {body}");
        assert!(body.contains("<ListAllMyBucketsResult"), "GET {target}: {body}");
    }

    let (status, _) = exchange(&service, signed(http::Method::GET, "/a-bucket")).await;
    assert_ne!(status, http::StatusCode::OK, "a named bucket answered the bucket list");
}

// ── 4. VirtualHostStyleHintLayer → the host resolver's diagnostic ───────────────────────────────

/// Negative — a request that looks virtual-hosted against a deployment that serves no base domain
/// is refused with a sentence naming the cause. RustFS's layer exists because the bare `501` for
/// `PUT /` was unreadable; here the diagnostic is the resolver's, and it replaces the message and
/// nothing else.
///
/// Two-directional: with the base domain configured the same request gets the ordinary message, so
/// the hint is a property of the configuration rather than a sentence on every `501`.
#[tokio::test]
async fn virtual_host_style_hint_is_the_host_resolver() {
    let vhosted = || {
        http::Request::builder()
            .method(http::Method::PUT)
            .uri("/")
            .header("host", "bucket.s3.example.com")
            .body(Bytes::new())
            .expect("a valid request")
    };

    let unconfigured = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&unconfigured, vhosted()).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("virtual host"), "{body}");

    let configured = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .host_resolver(VirtualHostStyle::new(["s3.example.com"]).expect("a valid base domain"))
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&configured, vhosted()).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED);
    assert!(!body.contains("virtual host"), "the hint fired on a host the deployment serves: {body}");
}

// ── 5. EmptyBodyContentLengthCompatLayer → StageFilter::on_wire ─────────────────────────────────

/// Positive — the first of the two layers that become a `StageFilter`. A deployment supplies the
/// missing `Content-Length` at the wire seam and the pipeline sees it, which is what the tower
/// layer does today from outside s3s.
///
/// Two-directional: the same assembly without the filter leaves the header off.
#[tokio::test]
async fn empty_body_content_length_compat_is_a_stage_filter() {
    let with_filter = wired()
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::content_ping_dialect())
        .stage_filter(wire_filter(|head: &mut rustfs_gateway::WireHead<'_>| {
            if head.header(&http::header::CONTENT_LENGTH).is_none() {
                head.set_header(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"))?;
            }
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&with_filter, plain(http::Method::PUT, "/")).await;
    assert_eq!(response.header(LENGTH_ECHO), Some("0"));

    let without = wired()
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::content_ping_dialect())
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&without, plain(http::Method::PUT, "/")).await;
    assert_eq!(response.header(LENGTH_ECHO), None);
}

// ── 6. S3ErrorMessageCompatLayer → the dialect, with StageFilter::on_response underneath ────────

/// Positive — the second of the two. A deployment whose clients expect a different sentence for a
/// refusal rewrites the document at the response seam. The dialect (`P6-08`) is the first answer
/// for a whole error table; this is the per-message escape hatch underneath it, and the point is
/// that it exists inside the pipeline rather than as a tower layer around it.
///
/// Two-directional: the same refusal without the filter carries the framework's own sentence.
#[tokio::test]
async fn s3_error_message_compat_is_a_stage_filter() {
    let rewritten = wired()
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::content_ping_dialect())
        .stage_filter(response_filter(
            |_view: &ResponseView<'_>, response: &mut http::Response<rustfs_gateway::Body>| {
                if response.status().is_client_error() {
                    *response.body_mut() = rustfs_gateway::Body::from_bytes(Bytes::from_static(
                        b"<Error><Message>as MinIO says it</Message></Error>",
                    ));
                }
                Ok::<(), rustfs_gateway::HandlerError>(())
            },
        ))
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&rewritten, plain(http::Method::PUT, "/?refuse")).await;
    assert_eq!(status, http::StatusCode::PRECONDITION_FAILED);
    assert!(body.contains("as MinIO says it"), "{body}");

    let plain_service = wired()
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::content_ping_dialect())
        .build()
        .expect("a complete assembly");
    let (_, body) = exchange(&plain_service, plain(http::Method::PUT, "/?refuse")).await;
    assert!(!body.contains("as MinIO says it"), "{body}");
    assert!(body.contains("<Code>PreconditionFailed</Code>"), "{body}");
}

// ── 7. ObjectAttributesEtagFixLayer → the quirk table, with OpLayer over it ─────────────────────

/// Positive — the built-in answer first: `q-mpu-attributes-etag-0036` renders this operation's
/// entity tag **bare**, which is what RustFS's layer parses the response XML to achieve. Then the
/// override: an `OpLayer<GetObjectAttributes>` reaches the typed field in three statements.
///
/// Two-directional in both halves: the value without the layer is the backend's, and the rendering
/// carries no quotes — a quoted one would be the defect the quirk exists for.
#[tokio::test]
async fn object_attributes_etag_fix_is_the_quirk_table_and_an_op_layer() {
    let (status, body) = exchange(&attributes_service(false), attributes_request()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert!(body.contains("<ETag>backend-etag</ETag>"), "{body}");
    assert!(!body.contains("&quot;"), "the attributes ETag was rendered quoted: {body}");

    let (status, body) = exchange(&attributes_service(true), attributes_request()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert!(body.contains("<ETag>rewritten-by-a-layer</ETag>"), "{body}");
}

// ── 8. StsQueryApiCompatLayer → an extension operation with a query predicate ───────────────────

/// A vendor operation reached by a query key, which is the shape an STS `Action=` call has.
struct QueryShaped;

/// What it decodes to.
struct QueryShapedInput;

/// What it answers with.
struct QueryShapedOutput;

static QUERY_SHAPED_SPEC: OperationSpec = OperationSpec::builder("example:QueryShaped", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("example:QueryShaped", ResourceShape::Service))
    .build();

static QUERY_SHAPED_FLOOR: OperationFloor =
    OperationFloor::custom("example:QueryShaped", SigService::Sts).allow_anonymous_after_listing_in_the_posture_report();

static QUERY_SHAPED_PREDICATES: &[Predicate] = &[
    Predicate::Method(http::Method::POST),
    Predicate::Target(TargetKind::Service),
    Predicate::QueryPresent("Action"),
];

static QUERY_SHAPED_OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-query-test",
    vendor: "example",
    claims: &[],
    operations: &[OverlayRow {
        name: "example:QueryShaped",
        precedence: 49,
        selector: "Method(POST) ∧ Target(Service) ∧ QueryPresent(\"Action\")",
        action: "example:QueryShaped",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: true,
        evidence: &["https://github.com/rustfs/gateway/issues/37"],
    }],
};

fn query_shaped_dialect() -> Dialect {
    Dialect::assemble(&QUERY_SHAPED_OVERLAY)
        .declare::<QueryShaped>(DialectRoute {
            precedence: 49,
            selector: QUERY_SHAPED_PREDICATES,
            path_shape: "/",
            shadows: &[],
        })
        .build()
        .expect("the query-shaped overlay and codec declaration must agree")
}

impl Operation for QueryShaped {
    const NAME: &'static str = "example:QueryShaped";

    type Input = QueryShapedInput;
    type Output = QueryShapedOutput;
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &QUERY_SHAPED_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &QUERY_SHAPED_FLOOR
    }
}

impl OperationCodec for QueryShaped {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<QueryShapedInput, CodecError> {
        Ok(QueryShapedInput)
    }

    fn encode(_output: QueryShapedOutput, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut encoded = EncodedResponse::of(status);
        encoded.set_header("content-type", "application/xml");
        encoded.body = ResponseBody::Complete(b"<AssumeRoleResponse/>".to_vec());
        Ok(encoded)
    }
}

/// A backend for it.
struct QueryBackend;

impl Handler<QueryShaped> for QueryBackend {
    async fn call(&self, _request: Req<QueryShaped>) -> HandlerResult<QueryShaped> {
        Ok(Resp::new(QueryShapedOutput))
    }

    async fn call_with_context(
        &self,
        _request: Req<QueryShaped>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<QueryShaped> {
        Ok(Resp::new(QueryShapedOutput))
    }
}

/// Positive — an operation this workspace does not define is registered, given a route selected by
/// a query key, and reached. RustFS's layer exists because the STS query shape had to be rewritten
/// before s3s would look at it; here the shape is a predicate, and the operation travels the same
/// authentication path as `GetObject`.
///
/// Two-directional: the same `POST /` without the query key matches nothing, so the predicate is
/// what is doing the selecting rather than the method and the path.
#[tokio::test]
async fn sts_query_api_compat_is_an_extension_operation() {
    let service = wired()
        .register::<QueryShaped, _>(Arc::new(QueryBackend))
        .dialect(&query_shaped_dialect())
        .build()
        .expect("a complete assembly");

    let (status, body) = exchange(&service, plain(http::Method::POST, "/?Action=AssumeRole")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert!(body.contains("<AssumeRoleResponse"), "{body}");

    let (status, _) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(
        status,
        http::StatusCode::NOT_IMPLEMENTED,
        "the query predicate selected an operation without its query key"
    );
}

// ── 9. ConditionalCorsLayer → the built-in preflight ────────────────────────────────────────────

/// A CORS source that answers one document for one bucket.
struct OneBucket;

impl CorsSource for OneBucket {
    fn load<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        let found = (bucket.as_str() == "cors-bucket").then(|| CorsConfiguration {
            cors_rules: vec![CorsRule {
                allowed_methods: vec!["GET".to_owned()],
                allowed_origins: vec!["https://app.example.com".to_owned()],
                ..CorsRule::default()
            }],
        });
        Box::pin(async move { Ok(found) })
    }
}

/// Positive — a browser preflight is answered from the bucket's own stored document, before
/// routing and without a signature. RustFS's layer exists because s3s has no bucket-level CORS at
/// all, so the tower layer had to decide conditionally which paths got the headers; here the rule
/// set is the bucket's and the framework answers it.
///
/// Two-directional: an origin the document does not name is refused, so the allowance is a
/// decision about the request rather than a header written on every `OPTIONS`.
#[tokio::test]
async fn conditional_cors_is_the_built_in_preflight() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .cors_source(OneBucket)
        .build()
        .expect("a complete assembly");

    let preflight = |origin: &str| {
        http::Request::builder()
            .method(http::Method::OPTIONS)
            .uri("/cors-bucket/key")
            .header("host", "s3.example.com")
            .header("origin", origin)
            .header("access-control-request-method", "GET")
            .body(Bytes::new())
            .expect("a valid request")
    };

    let allowed = exchange_wire(&service, preflight("https://app.example.com")).await;
    assert_eq!(allowed.status(), http::StatusCode::OK);
    assert_eq!(allowed.header("access-control-allow-origin"), Some("https://app.example.com"));

    let refused = exchange_wire(&service, preflight("https://stranger.invalid")).await;
    assert_ne!(refused.status(), http::StatusCode::OK);
    assert_eq!(refused.header("access-control-allow-origin"), None);
}
