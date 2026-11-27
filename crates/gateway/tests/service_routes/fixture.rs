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

//! Shared fixtures, dialect definitions, and SigV4 helpers for S3 Vectors isolation tests.
//!
//! Responsible for: defining S3 Vectors test operations, dialect assembly, counting S3-middleware
//! probes, signing helpers, and REST-JSON refusal assertions.
//! NOT responsible for: production S3 Vectors routing or codec logic.
//! Upstream: `rustfs-gateway`, `rustfs-gateway-core`, `rustfs-gateway-sig`, `crate::support`.
//! Downstream: `super` (`tests/s3_vectors_isolation.rs`).

use crate::support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use rustfs_gateway::{
    AuthRequirement, BoxFuture, BucketOwnerError, BucketOwnerSource, ClockSkewAck, CodecError, CorsSource, CorsSourceError,
    Credentials, EncodedResponse, HOST_ID_HEADER, Handler, HandlerDeadlineClass, HandlerError, HandlerResult, MetaView,
    NoDerived, Operation, OperationCodec, OperationFloor, OperationSpec, Predicate, REQUEST_ID_HEADER, RegionSet, Req,
    RequestBody, RequestBodyMode, ResourceShape, Resp, S3Service, ServiceBuilder, SigService, SigV4Authenticator,
    StaticCredentials, allow_when, collect,
};
use rustfs_gateway_core::{ClaimedRoute, ClaimedRow, Dialect, DialectOverlay, DialectRoute, OverlayRow, PathClaim};
use rustfs_gateway_sig::{
    AmzDate, PayloadMode, RawHost, ScopeDate, SigV4Signer, SigningCredentials, SigningRequest, SigningScope,
};
use rustfs_gateway_types::{BucketName, ErrorCode, dto::CorsConfiguration};
use sha2::{Digest as _, Sha256};

pub(super) const SERVICE: SigService = SigService::S3Vectors;
const EVIDENCE: &[&str] = &["https://docs.aws.amazon.com/AmazonS3/latest/API/API_S3VectorBuckets_PutVectors.html"];
const TAGS_CLAIM: PathClaim = PathClaim {
    prefix: "/tags",
    reason: "S3 Vectors owns the /tags/{+resource_arn} route family.",
    evidence: EVIDENCE,
};
pub(super) const TAG_ARN_PATH: &str = "/tags/arn%3Aaws%3As3vectors%3Aus-east-1%3A123456789012%3Abucket%2Fmy-bucket";
pub(super) const DOUBLE_ENCODED_ARN: &str =
    "/tags/arn%253Aaws%253As3vectors%253Aus-east-1%253A123456789012%253Abucket%252Fmy-bucket";

const PUT_PREDICATES: &[Predicate] = &[Predicate::Method(Method::POST), Predicate::PathLiteral("/PutVectors")];
const FAIL_PREDICATES: &[Predicate] = &[Predicate::Method(Method::POST), Predicate::PathLiteral("/FailVectors")];
const LIST_TAG_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/tags/{+resource_arn}",
    selector: &[Predicate::Method(Method::GET)],
}];
const TAG_RESOURCE_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/tags/{+resource_arn}",
    selector: &[Predicate::Method(Method::POST)],
}];
const UNTAG_RESOURCE_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/tags/{+resource_arn}",
    selector: &[Predicate::Method(Method::DELETE)],
}];

const fn op_spec(name: &'static str, action: &'static str) -> OperationSpec {
    OperationSpec::builder(name, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .auth(AuthRequirement::new(action, ResourceShape::Service))
        .build()
}

macro_rules! define_vector_op {
    ($ty:ident, $name:expr, $action:expr, $body_mode:expr) => {
        pub(super) struct $ty;
        impl Operation for $ty {
            const NAME: &'static str = $name;
            type Input = usize;
            type Output = ();
            type DerivedResources = NoDerived;
            fn derive_resources(_: &Self::Input) -> Result<NoDerived, rustfs_gateway::DerivedResourceError> {
                Ok(NoDerived)
            }
            fn seal_derived_input(_: &mut Self::Input) {}
            fn spec() -> &'static OperationSpec {
                static SPEC: OperationSpec = op_spec($name, $action);
                &SPEC
            }
            fn floor() -> &'static OperationFloor {
                static FLOOR: OperationFloor = OperationFloor::builtin($name, SERVICE).require_sigv4_under_every_policy();
                &FLOOR
            }
        }
        impl OperationCodec for $ty {
            const REQUEST_BODY: RequestBodyMode = $body_mode;
            fn decode(request: &MetaView<'_>, body: RequestBody) -> Result<usize, CodecError> {
                if request.bucket().is_some() || request.key().is_some() {
                    return Err(CodecError::invalid_argument("a service action cannot carry an S3 target"));
                }
                Ok(match body {
                    RequestBody::Buffered(bytes) => bytes.len(),
                    _ => 0,
                })
            }
            fn encode(_: (), _: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
                let mut encoded = EncodedResponse::of(status);
                encoded.set_header("content-type", "application/json");
                Ok(encoded)
            }
        }
    };
}

define_vector_op!(PutVectors, "example:PutVectors", "example:PutVectors", RequestBodyMode::Full);
define_vector_op!(FailVectors, "example:FailVectors", "example:FailVectors", RequestBodyMode::None);
define_vector_op!(
    ListTags,
    "example:ListTagsForResource",
    "example:ListTagsForResource",
    RequestBodyMode::None
);
define_vector_op!(TagResource, "example:TagResource", "example:TagResource", RequestBodyMode::Full);
define_vector_op!(UntagResource, "example:UntagResource", "example:UntagResource", RequestBodyMode::None);

#[derive(Default)]
pub(super) struct VectorBackend {
    pub(super) calls: AtomicUsize,
    pub(super) last_body_len: AtomicUsize,
}

macro_rules! impl_ok_handler {
    ($ty:ty) => {
        impl Handler<$ty> for VectorBackend {
            async fn call(&self, req: Req<$ty>) -> HandlerResult<$ty> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.last_body_len.store(*req.input(), Ordering::SeqCst);
                Ok(Resp::new(()))
            }
        }
    };
}

impl_ok_handler!(PutVectors);
impl_ok_handler!(ListTags);
impl_ok_handler!(TagResource);
impl_ok_handler!(UntagResource);

impl Handler<FailVectors> for VectorBackend {
    async fn call(&self, _: Req<FailVectors>) -> HandlerResult<FailVectors> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(HandlerError::new(
            ErrorCode::custom("ConflictException", StatusCode::CONFLICT),
            "vector \"a\\b\"\nexists",
        ))
    }
}

#[derive(Default)]
pub(super) struct CountingOwnerSource {
    pub(super) calls: AtomicUsize,
}

impl BucketOwnerSource for CountingOwnerSource {
    fn owner<'a>(&'a self, _: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(BucketOwnerError::unavailable()) })
    }
}

#[derive(Default)]
pub(super) struct CountingCorsSource {
    pub(super) calls: AtomicUsize,
}

impl CorsSource for CountingCorsSource {
    fn load<'a>(&'a self, _: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(None) })
    }
}

fn overlay_row(name: &'static str, selector: &'static str, action: &'static str) -> OverlayRow {
    OverlayRow {
        name,
        precedence: 50,
        selector,
        action,
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: false,
        evidence: EVIDENCE,
    }
}

fn vectors_dialect() -> Dialect {
    let list_sel: &'static str = Box::leak(rustfs_gateway_core::dialect::render_claimed_rows(LIST_TAG_ROWS).into_boxed_str());
    let tag_sel: &'static str = Box::leak(rustfs_gateway_core::dialect::render_claimed_rows(TAG_RESOURCE_ROWS).into_boxed_str());
    let untag_sel: &'static str =
        Box::leak(rustfs_gateway_core::dialect::render_claimed_rows(UNTAG_RESOURCE_ROWS).into_boxed_str());
    let overlay: &'static DialectOverlay = Box::leak(Box::new(DialectOverlay {
        name: "s3vectors-isolation-test",
        vendor: "example",
        claims: &[TAGS_CLAIM],
        operations: Box::leak(
            vec![
                overlay_row(PutVectors::NAME, "Method(POST) ∧ PathLiteral(\"/PutVectors\")", "example:PutVectors"),
                overlay_row(FailVectors::NAME, "Method(POST) ∧ PathLiteral(\"/FailVectors\")", "example:FailVectors"),
                overlay_row(ListTags::NAME, list_sel, "example:ListTagsForResource"),
                overlay_row(TagResource::NAME, tag_sel, "example:TagResource"),
                overlay_row(UntagResource::NAME, untag_sel, "example:UntagResource"),
            ]
            .into_boxed_slice(),
        ),
    }));
    Dialect::assemble_for_service(overlay, SERVICE)
        .declare::<PutVectors>(DialectRoute {
            precedence: 50,
            selector: PUT_PREDICATES,
            path_shape: "/PutVectors",
            shadows: &[],
        })
        .declare::<FailVectors>(DialectRoute {
            precedence: 50,
            selector: FAIL_PREDICATES,
            path_shape: "/FailVectors",
            shadows: &[],
        })
        .declare_claimed::<ListTags>(ClaimedRoute {
            precedence: 50,
            rows: LIST_TAG_ROWS,
            shadows: &[],
            bucket_param: None,
        })
        .declare_claimed::<TagResource>(ClaimedRoute {
            precedence: 50,
            rows: TAG_RESOURCE_ROWS,
            shadows: &[],
            bucket_param: None,
        })
        .declare_claimed::<UntagResource>(ClaimedRoute {
            precedence: 50,
            rows: UNTAG_RESOURCE_ROWS,
            shadows: &[],
            bucket_param: None,
        })
        .build()
        .expect("S3 Vectors test dialect")
}

pub(super) fn vectors_builder(backend: Arc<VectorBackend>, rustfs_profile: bool) -> ServiceBuilder {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("test credentials")));
    let auth = SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("region"));
    let auth = if rustfs_profile { auth.rustfs_profile() } else { auth };
    let builder = ServiceBuilder::for_service(SERVICE)
        .dialect(&vectors_dialect())
        .register::<PutVectors, _>(Arc::clone(&backend))
        .register::<FailVectors, _>(Arc::clone(&backend))
        .register::<ListTags, _>(Arc::clone(&backend))
        .register::<TagResource, _>(Arc::clone(&backend))
        .register::<UntagResource, _>(backend)
        .authenticator(auth)
        .authorizer(allow_when(|_| true))
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        );
    if rustfs_profile { builder.rustfs_profile() } else { builder }
}

pub(super) fn signed_request(
    service: SigService,
    method: Method,
    host: &str,
    path: &str,
    query: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Request<Bytes> {
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("signing creds");
    let scope =
        SigningScope::new(ScopeDate::parse(&support::SIGNED_AT_STAMP[..8]).expect("date"), "us-east-1", service).expect("scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let mut headers = HeaderMap::new();
    for (name, value) in extra_headers {
        headers.insert(
            http::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    let raw_host = RawHost::from_host_header(host.as_bytes()).expect("host");
    let payload = if body.is_empty() {
        PayloadMode::Empty
    } else {
        PayloadMode::ExactSha256(Sha256::digest(body).into())
    };
    let req = SigningRequest::new(
        &method,
        path,
        query,
        &headers,
        &raw_host,
        payload,
        AmzDate::parse(support::SIGNED_AT_STAMP).expect("stamp"),
    );
    let signed = signer.sign_headers(&req).expect("signed");
    let uri = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let mut builder = Request::builder().method(method).uri(uri).header(http::header::HOST, host);
    if !body.is_empty() {
        builder = builder.header(http::header::CONTENT_LENGTH, body.len().to_string());
    }
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::copy_from_slice(body)).expect("request")
}

#[allow(clippy::too_many_arguments)]
pub(super) fn hand_signed(
    service: SigService,
    access_key: &str,
    method: Method,
    host: &str,
    uri: &str,
    canonical_uri: &str,
    canonical_query: &str,
    body: &[u8],
) -> Request<Bytes> {
    let stamp = support::SIGNED_AT_STAMP;
    let day = &stamp[..8];
    let service_name = service.as_str();
    let scope = format!("{day}/us-east-1/{service_name}/aws4_request");
    let digest: String = Sha256::digest(body).iter().map(|b| format!("{b:02x}")).collect();
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\nhost:{host}\nx-amz-content-sha256:{digest}\nx-amz-date:{stamp}\n\n{signed_headers}\n{digest}"
    );
    let canonical_hash: String = Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{canonical_hash}");
    let hmac = |key: &[u8], data: &[u8]| -> [u8; 32] {
        let mut block = [0_u8; 64];
        block[..key.len()].copy_from_slice(key);
        let mut inner = Sha256::new();
        inner.update(block.map(|b| b ^ 0x36));
        inner.update(data);
        let mut outer = Sha256::new();
        outer.update(block.map(|b| b ^ 0x5c));
        outer.update(inner.finalize());
        outer.finalize().into()
    };
    let mut key = hmac(b"AWS4secret", day.as_bytes());
    for part in ["us-east-1", service_name, "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    let signature: String = hmac(&key, string_to_sign.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::HOST, host)
        .header("x-amz-date", stamp)
        .header("x-amz-content-sha256", digest)
        .header(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"),
        );
    if !body.is_empty() {
        builder = builder.header(http::header::CONTENT_LENGTH, body.len().to_string());
    }
    builder.body(Bytes::copy_from_slice(body)).expect("hand-signed request")
}

pub(super) async fn exchange_full(service: &S3Service, request: Request<Bytes>) -> (StatusCode, HeaderMap, String) {
    let response = service.call_bytes(request).await;
    let status = response.status();
    let headers = response.headers().clone();
    let wire = collect(response).await.expect("collected body");
    let body = String::from_utf8(wire.body().to_vec()).expect("utf-8 body");
    (status, headers, body)
}

pub(super) fn assert_rest_json_error(
    status: StatusCode,
    headers: &HeaderMap,
    body: &str,
    expected_status: StatusCode,
    expected_code: &str,
) {
    assert_eq!(status, expected_status, "body={body}");
    assert_eq!(
        headers.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "expected REST-JSON content-type, headers={headers:?}, body={body}"
    );
    assert_eq!(
        headers.get("x-amzn-errortype").and_then(|v| v.to_str().ok()),
        Some(expected_code),
        "expected x-amzn-errortype={expected_code}, headers={headers:?}, body={body}"
    );
    assert!(!body.contains("<Error"), "REST-JSON error must never emit S3 XML: {body}");
    assert!(!body.contains("<?xml"), "REST-JSON error must never emit XML declaration: {body}");
    assert!(body.starts_with('{') && body.ends_with('}'), "expected JSON object body: {body}");
    assert!(headers.contains_key(REQUEST_ID_HEADER), "missing x-amz-request-id: {headers:?}");
    assert!(!headers.contains_key(HOST_ID_HEADER), "non-S3 response must omit x-amz-id-2: {headers:?}");
}
