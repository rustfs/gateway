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

//! The `s3vectors_auth` fuzz property: S3 Vectors signing, floor admission, and service routing.
//!
//! Responsible for: exercising `SigService::S3Vectors` query canonicalization, `SigV4Signer`
//! signing, `SecurityFloor::admit`, and `Dialect::assemble_for_service` +
//! `RouterBuilder::for_service(SigService::S3Vectors)` route dispatch (action + claimed tag routes)
//! without duplicating `SigV4Authorization::parse` (`credential_header_parse.rs`).
//! NOT responsible for: S3 Vectors storage handlers or JSON payload schemas.
//! Upstream: libFuzzer bytes or fixed replay tests in `crates/core/tests/service_routes.rs`.
//! Downstream: `rustfs-gateway-sig` and `rustfs-gateway-core`.

use std::sync::{Arc, OnceLock};

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rustfs_gateway_core::{
    AuthRequirement, ClaimedRoute, ClaimedRow, Dialect, DialectOverlay, DialectRoute, Handler, HandlerDeadlineClass,
    HandlerResult, HostClass, NoDerived, Operation, OperationSpec, OverlayRow, PathClaim, Predicate, Req, ResourceShape, Resp,
    RouteRequestParts, Router, RouterBuilder, TargetKind,
};
use rustfs_gateway_http::{HeaderView, Limits, QueryIndex, QueryView};
use rustfs_gateway_sig::{
    AmzDate, OperationFloor, PayloadMode, QueryExclusion, RawHost, RawQuery, RequestNow, ScopeDate, SecurityFloor, SigService,
    SigV4Signer, SigningCredentials, SigningRequest, SigningScope, WireView,
};

const METHODS: [Method; 4] = [Method::POST, Method::GET, Method::DELETE, Method::PUT];
const TARGETS: [TargetKind; 3] = [TargetKind::Service, TargetKind::Bucket, TargetKind::Object];
const HOST_CLASSES: [HostClass; 4] = [
    HostClass::Standard,
    HostClass::ObjectLambda,
    HostClass::S3Express,
    HostClass::Website,
];
const NOW: i64 = 1_440_938_160; // 2015-08-30T12:36:00Z
const OP_NAMES: [&str; 2] = ["s3vectors:PutVectors", "s3vectors:ListTagsForResource"];
const EVIDENCE: &[&str] = &["https://docs.aws.amazon.com/AmazonS3/latest/API/API_S3VectorBuckets_ListTagsForResource.html"];
const TAG_CLAIM: PathClaim = PathClaim {
    prefix: "/tags",
    reason: "S3 Vectors owns its /tags/{+resource_arn} claimed route.",
    evidence: EVIDENCE,
};
const ACTION_PREDICATES: &[Predicate] = &[Predicate::Method(Method::POST), Predicate::PathLiteral("/PutVectors")];
const TAG_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/tags/{+resource_arn}",
    selector: &[Predicate::Method(Method::GET)],
}];

struct S3VectorsOp<const N: usize>;

const fn op_spec(name: &'static str) -> OperationSpec {
    OperationSpec::builder(name, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .auth(AuthRequirement::new("s3vectors:PutVectors", ResourceShape::Service))
        .build()
}

static SPECS: [OperationSpec; 2] = [op_spec(OP_NAMES[0]), op_spec(OP_NAMES[1])];
static FLOORS: [OperationFloor; 2] = [
    OperationFloor::custom(OP_NAMES[0], SigService::S3Vectors).require_sigv4_under_every_policy(),
    OperationFloor::custom(OP_NAMES[1], SigService::S3Vectors).require_sigv4_under_every_policy(),
];

impl<const N: usize> Operation for S3VectorsOp<N> {
    const NAME: &'static str = OP_NAMES[N];
    type Input = ();
    type Output = ();
    type DerivedResources = NoDerived;

    fn derive_resources(_: &Self::Input) -> Result<NoDerived, rustfs_gateway_core::DerivedResourceError> {
        Ok(NoDerived)
    }

    fn seal_derived_input(_: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPECS[N]
    }

    fn floor() -> &'static OperationFloor {
        &FLOORS[N]
    }
}

struct StubBackend;

impl<const N: usize> Handler<S3VectorsOp<N>> for StubBackend {
    async fn call(&self, _: Req<S3VectorsOp<N>>) -> HandlerResult<S3VectorsOp<N>> {
        Ok(Resp::new(()))
    }
}

fn s3vectors_router() -> &'static Router {
    static ROUTER: OnceLock<Router> = OnceLock::new();
    ROUTER.get_or_init(|| {
        let action_overlay: &'static DialectOverlay = Box::leak(Box::new(DialectOverlay {
            name: "s3vectors-fuzz-action",
            vendor: "s3vectors",
            claims: &[],
            operations: Box::leak(
                vec![OverlayRow {
                    name: OP_NAMES[0],
                    precedence: 50,
                    selector: "Method(POST) ∧ PathLiteral(\"/PutVectors\")",
                    action: "s3vectors:PutVectors",
                    resource: ResourceShape::Service,
                    success_status: 200,
                    anonymous: false,
                    evidence: EVIDENCE,
                }]
                .into_boxed_slice(),
            ),
        }));
        let tag_selector: &'static str = Box::leak(rustfs_gateway_core::dialect::render_claimed_rows(TAG_ROWS).into_boxed_str());
        let tags_overlay: &'static DialectOverlay = Box::leak(Box::new(DialectOverlay {
            name: "s3vectors-fuzz-tags",
            vendor: "s3vectors",
            claims: &[TAG_CLAIM],
            operations: Box::leak(
                vec![OverlayRow {
                    name: OP_NAMES[1],
                    precedence: 50,
                    selector: tag_selector,
                    action: "s3vectors:PutVectors",
                    resource: ResourceShape::Service,
                    success_status: 200,
                    anonymous: false,
                    evidence: EVIDENCE,
                }]
                .into_boxed_slice(),
            ),
        }));
        let action_dialect = Dialect::assemble_for_service(action_overlay, SigService::S3Vectors)
            .declare::<S3VectorsOp<0>>(DialectRoute {
                precedence: 50,
                selector: ACTION_PREDICATES,
                path_shape: "/PutVectors",
                shadows: &[],
            })
            .build()
            .expect("s3vectors action dialect builds");
        let tags_dialect = Dialect::assemble_for_service(tags_overlay, SigService::S3Vectors)
            .declare_claimed::<S3VectorsOp<1>>(ClaimedRoute {
                precedence: 50,
                rows: TAG_ROWS,
                shadows: &[],
                bucket_param: None,
            })
            .build()
            .expect("s3vectors tags dialect builds");
        let backend = Arc::new(StubBackend);
        RouterBuilder::for_service(SigService::S3Vectors)
            .dialect(&action_dialect)
            .dialect(&tags_dialect)
            .handle_without_codec::<S3VectorsOp<0>, _>(Arc::clone(&backend))
            .handle_without_codec::<S3VectorsOp<1>, _>(backend)
            .build()
            .expect("s3vectors router builds")
    })
}

fn take_str(input: &mut &[u8], max_len: usize) -> String {
    let Some((&len, rest)) = input.split_first() else {
        return String::new();
    };
    let n = usize::from(len).min(max_len).min(rest.len());
    let (head, tail) = rest.split_at(n);
    *input = tail;
    String::from_utf8_lossy(head).into_owned()
}

/// Exercises S3 Vectors signing, floor admission, and `RouterBuilder::for_service(S3Vectors)`
/// dispatch on arbitrary bytes, returning the matched operation name (if any).
pub(crate) fn check(input: &[u8]) -> Option<&'static str> {
    let mut rest = input;
    let selector = rest.first().copied().unwrap_or_default();
    rest = rest.get(1..).unwrap_or_default();

    let method = &METHODS[usize::from(selector) % METHODS.len()];
    let target = TARGETS[usize::from(selector >> 2) % TARGETS.len()];
    let host_class = HOST_CLASSES[usize::from(selector >> 4) % HOST_CLASSES.len()];
    let raw_path = take_str(&mut rest, 128);
    let path = if raw_path.starts_with('/') {
        raw_path
    } else {
        format!("/{raw_path}")
    };
    let query = take_str(&mut rest, 256);
    let auth_header = take_str(&mut rest, 256);
    let date_header = take_str(&mut rest, 64);

    // 1. S3 Vectors query canonicalization & SigV4 signing.
    let _ = RawQuery::new(&query).canonical(QueryExclusion::None);
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("synthetic credentials");
    let date = ScopeDate::parse("20150830").expect("valid scope date");
    let stamp = AmzDate::parse("20150830T123600Z").expect("valid timestamp");
    let host = RawHost::from_host_header(b"vectors.example.com").expect("valid host");
    let headers = HeaderMap::new();

    if let Ok(scope) = SigningScope::new(date, "us-east-1", SigService::S3Vectors) {
        let mut signer = SigV4Signer::new(credentials, scope);
        let req = SigningRequest::new(method, &path, &query, &headers, &host, PayloadMode::Empty, stamp);
        let _ = signer.sign_headers(&req);
    }

    // 2. S3 Vectors SecurityFloor admission against arbitrary headers and queries.
    let mut wire_headers = HeaderMap::new();
    wire_headers.insert(HeaderName::from_static("host"), HeaderValue::from_static("vectors.example.com"));
    if let Ok(val) = HeaderValue::from_str(&auth_header) {
        wire_headers.insert(HeaderName::from_static("authorization"), val);
    }
    if let Ok(val) = HeaderValue::from_str(&date_header) {
        wire_headers.insert(HeaderName::from_static("x-amz-date"), val);
    }
    let floor = OperationFloor::builtin("s3vectors:PutVectors", SigService::S3Vectors).require_sigv4_under_every_policy();
    let view = WireView::new(&wire_headers, RawQuery::new(&query));
    let _ = SecurityFloor::new().admit(view, &floor, RequestNow::from_unix_seconds(NOW));

    // 3. S3 Vectors Dialect::assemble_for_service + RouterBuilder::for_service dispatch.
    let router = s3vectors_router();
    let mut matched = None;
    if let Ok(query_index) = QueryIndex::parse(&query, &Limits::default()) {
        let parts = RouteRequestParts {
            method,
            path: &path,
            target,
            host_class,
            arn_form: None,
            query: QueryView::new(&query, &query_index),
            headers: HeaderView::new(&wire_headers),
            host_named_bucket: false,
        };
        if let Ok(dispatched) = router.dispatch(&parts) {
            assert!(
                OP_NAMES.contains(&dispatched.spec.name),
                "S3 Vectors service router must only match S3 Vectors operations, matched {}",
                dispatched.spec.name
            );
            if dispatched.spec.name == OP_NAMES[1] {
                let claimed = dispatched.claimed.expect("claimed tags route retains its claim");
                let _ = claimed.template().extract(&path);
            }
            matched = Some(dispatched.spec.name);
        }
    }
    matched
}
