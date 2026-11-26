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

//! Security-hardening regressions for rustfs/gateway#1628: authentication timing floor,
//! copy-source/POST owner enforcement, `HeadObject` visibility masking, and verbose-error redaction.
//!
//! Responsible for: proving `FailureFloor` awaiting on every authentication refusal path,
//! `BucketOwnerSource` enforcement for copy-source and POST form owner assertions, `HeadObject`
//! missing-object visibility masking, and `verbose_signature_errors` redaction of bearer tokens,
//! presigned SSE-C query parameters, and sensitive signed headers.
//! NOT responsible for: `PostObject` SSE/redirect/quota/timeout checks (`hardening_post_object.rs`)
//! or low-level SigV4/SigV2 parser rules (`rustfs-gateway-sig`).
//! Upstream: `rustfs-gateway` public API. Downstream: Cargo's integration test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use core::future::Future;
use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{
    CopyObject, CopyObjectOutput, GetObject, HeadObject, ListBuckets, PostObject, PostObjectOutput, UploadPartCopy,
    UploadPartCopyOutput,
};
use rustfs_gateway::{
    AuthRequirement, BoxFuture, BucketName, BucketOwnerError, BucketOwnerSource, CodecError, DEFAULT_MAX_BUFFERED_BODY_BYTES,
    ETag, EncodedResponse, Handler, HandlerErrorContext, HandlerResult, MetaView, MissingObject, Operation, OperationCodec,
    OperationFloor, OperationSetEnd, OperationSetNode, OperationSpec, Predicate, Req, RequestBody, ResourceShape,
    ResourceVisibility, Resp, ResponseBody, ServiceConfig, SigService, TransportSecurity, allow_when,
};
use rustfs_gateway_core::{ClaimedRoute, ClaimedRow, Dialect, DialectOverlay, OverlayRow, PathClaim};
use rustfs_gateway_sig::{BearerGrant, BearerRefused, BearerTokenRequest, BearerTokenVerifier, QueryBearerClaim};

use rustfs_gateway_core::HandlerDeadlineClass;

use crate::support::{self, exchange_wire};

const BOUNDARY: &str = "----RustFSHardening1628Auth";

/// Observes that a future enters the shared failure floor (yields `Poll::Pending` on its first
/// poll) rather than answering synchronously on a fast path.
async fn assert_enters_failure_floor(future: impl Future<Output = rustfs_gateway::WireResponse>) -> rustfs_gateway::WireResponse {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    assert!(
        matches!(future.as_mut().poll(&mut context), Poll::Pending),
        "authentication refusal completed without awaiting FailureFloor"
    );
    future.await
}

// ── Item 1: FailureFloor on every authentication refusal path ───────────────────────────────────

struct BearerDownload;
struct BearerDownloadInput;
struct BearerDownloadOutput;

static BEARER_CLAIM: QueryBearerClaim = QueryBearerClaim::new("dl_token", ".zip");

static BEARER_SPEC: OperationSpec = OperationSpec::builder("example:BearerDownload", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("example:BearerDownload", ResourceShape::Service))
    .build();

static BEARER_FLOOR: OperationFloor =
    OperationFloor::custom("example:BearerDownload", SigService::S3).with_query_bearer_claim(BEARER_CLAIM);

static BEARER_GET: &[Predicate] = &[Predicate::Method(Method::GET)];

static BEARER_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/example/downloads/{id}",
    selector: BEARER_GET,
}];

impl Operation for BearerDownload {
    const NAME: &'static str = "example:BearerDownload";
    type Input = BearerDownloadInput;
    type Output = BearerDownloadOutput;
    type DerivedResources = rustfs_gateway_core::NoDerived;
    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }
    fn seal_derived_input(_input: &mut Self::Input) {}
    fn spec() -> &'static OperationSpec {
        &BEARER_SPEC
    }
    fn floor() -> &'static OperationFloor {
        &BEARER_FLOOR
    }
}

impl OperationCodec for BearerDownload {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<BearerDownloadInput, CodecError> {
        Ok(BearerDownloadInput)
    }
    fn encode(_output: BearerDownloadOutput, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut encoded = EncodedResponse::of(status);
        encoded.body = ResponseBody::Complete(b"zip".to_vec());
        Ok(encoded)
    }
}

struct BearerBackend;
impl Handler<BearerDownload> for BearerBackend {
    async fn call(&self, _request: Req<BearerDownload>) -> HandlerResult<BearerDownload> {
        Ok(Resp::new(BearerDownloadOutput))
    }
}

struct RejectBearer;
impl BearerTokenVerifier for RejectBearer {
    fn verify(&self, _request: &BearerTokenRequest<'_>) -> Result<BearerGrant, BearerRefused> {
        Err(BearerRefused)
    }
}

static BEARER_OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-bearer",
    vendor: "example",
    claims: &[PathClaim {
        prefix: "/example/downloads",
        reason: "Test bearer download claim ahead of S3 routes.",
        evidence: &["https://github.com/rustfs/gateway/issues/1628"],
    }],
    operations: &[OverlayRow {
        name: "example:BearerDownload",
        precedence: 10,
        selector: "PathTemplate(\"/example/downloads/{id}\") ∧ Method(GET)",
        action: "example:BearerDownload",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: false,
        evidence: &["https://github.com/rustfs/gateway/issues/1628"],
    }],
};

fn bearer_dialect() -> Dialect {
    Dialect::assemble(&BEARER_OVERLAY)
        .declare_claimed::<BearerDownload>(ClaimedRoute {
            precedence: 10,
            rows: BEARER_ROWS,
            shadows: &[],
            bucket_param: None,
        })
        .build()
        .expect("bearer dialect")
}

/// Negative & positive — `floor.admit()`, `verdict.rejection()` (bad signature, unknown key, wrong
/// region), `bearer_alongside_signature`, `refused_post`, and pre-routing RustFS SigV4 header-guard
/// refusals must all await `FailureFloor`, while a valid authenticated control completes on its
/// first poll without sleeping.
#[tokio::test]
async fn n_every_authentication_refusal_path_awaits_failure_floor() {
    let service = support::wired_at_signed_time()
        .register::<ListBuckets, _>(Arc::new(support::Backend))
        .register::<BearerDownload, _>(Arc::new(BearerBackend))
        .dialect(&bearer_dialect())
        .bearer_token_verifier(RejectBearer)
        .authorizer(allow_when(|_| true))
        .build()
        .expect("service");

    // Positive control: a valid authenticated request does NOT wait on FailureFloor.
    let ok_request = support::signed(Method::GET, "/");
    let mut ok_future = Box::pin(exchange_wire(&service, ok_request));
    let mut cx = Context::from_waker(Waker::noop());
    let ok_response = match ok_future.as_mut().poll(&mut cx) {
        Poll::Ready(response) => response,
        Poll::Pending => panic!("positive control unexpectedly yielded Pending before completion"),
    };
    assert_eq!(ok_response.status(), StatusCode::OK);

    // 1. `floor.admit()` rejection: anonymous request to non-anonymous ListBuckets.
    let anon = Request::builder()
        .method(Method::GET)
        .uri("http://host.invalid/")
        .header("host", "host.invalid")
        .body(Bytes::new())
        .expect("request");
    let refused = assert_enters_failure_floor(exchange_wire(&service, anon)).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    // 2. `floor.admit()` rejection: skewed timestamp.
    let skewed = Request::builder()
        .method(Method::GET)
        .uri("http://host.invalid/")
        .header("host", "host.invalid")
        .header("x-amz-date", "20100101T000000Z")
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20100101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
        )
        .body(Bytes::new())
        .expect("request");
    let refused = assert_enters_failure_floor(exchange_wire(&service, skewed)).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    // 3. `verdict.rejection()` — bad signature for known access key.
    let mut bad_sig = support::signed(Method::GET, "/");
    bad_sig.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
        ),
    );
    let refused = assert_enters_failure_floor(exchange_wire(&service, bad_sig)).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(refused.body()).contains("<Code>SignatureDoesNotMatch</Code>"));

    // 4. `verdict.rejection()` — unknown access key.
    let mut unknown_key = support::signed(Method::GET, "/");
    unknown_key.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=AKIDUNKNOWN00/20260102/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
        ),
    );
    let refused = assert_enters_failure_floor(exchange_wire(&service, unknown_key)).await;
    let unknown_body = String::from_utf8_lossy(refused.body());
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{unknown_body}");
    assert!(unknown_body.contains("<Code>InvalidAccessKeyId</Code>"), "{unknown_body}");

    // 5. `verdict.rejection()` — unserved region (AuthorizationHeaderMalformed).
    let mut bad_region = support::signed(Method::GET, "/");
    bad_region.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
        ),
    );
    let refused = assert_enters_failure_floor(exchange_wire(&service, bad_region)).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(refused.body()).contains("<Code>AuthorizationHeaderMalformed</Code>"));

    // 6. `bearer_alongside_signature` failure: valid SigV4 signature on bearer-claimed op without valid token.
    let signed_no_token = support::signed(Method::GET, "/example/downloads/archive.zip");
    let refused = assert_enters_failure_floor(exchange_wire(&service, signed_no_token)).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(refused.body()).contains("<Code>AccessDenied</Code>"));

    let signed_bad_token = support::signed(Method::GET, "/example/downloads/archive.zip?dl_token=bad");
    let refused = assert_enters_failure_floor(exchange_wire(&service, signed_bad_token)).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(refused.body()).contains("<Code>AccessDenied</Code>"));

    // 7. `refused_post` authentication refusal on unrouted object-path POST under RustfsLegacy.
    let legacy_service = support::wired_at_signed_time()
        .register::<ListBuckets, _>(Arc::new(support::Backend))
        .select_operations_as_legacy_rustfs()
        .legacy_rustfs_post_forms()
        .authorizer(allow_when(|_| true))
        .build()
        .expect("legacy service");
    let bad_unrouted_body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"x-amz-signature\"\r\n\r\n{}\r\n\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\nhi\r\n\
         --{BOUNDARY}--\r\n",
        "0".repeat(64)
    );
    let unrouted_req = Request::builder()
        .method(Method::POST)
        .uri("http://host.invalid/example-bucket/some-key")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .header("content-length", bad_unrouted_body.len())
        .body(Bytes::from(bad_unrouted_body))
        .expect("unrouted post");
    let refused = assert_enters_failure_floor(exchange_wire(&legacy_service, unrouted_req)).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

    // 8. Pre-routing RustFS SigV4 header guard refusal awaits `FailureFloor`.
    let guarded_service = support::wired_at_signed_time()
        .register::<ListBuckets, _>(Arc::new(support::Backend))
        .refuse_unsigned_amz_headers_before_routing()
        .authorizer(allow_when(|_| true))
        .build()
        .expect("guarded service");
    let bad_alg = Request::builder()
        .method(Method::GET)
        .uri("http://host.invalid/")
        .header("host", "host.invalid")
        .header("authorization", "AWS4-HMAC-SHA256 malformed")
        .body(Bytes::new())
        .expect("bad alg request");
    let refused = assert_enters_failure_floor(exchange_wire(&guarded_service, bad_alg)).await;
    let guard_body = String::from_utf8_lossy(refused.body());
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{guard_body}");
    assert!(guard_body.contains("Invalid SigV4 authorization header"), "{guard_body}");
}

// ── Item 3: BucketOwnerSource on CopyObject, UploadPartCopy, and PostObject ────────────────────

struct MapOwnerSource(BTreeMap<String, String>);

impl BucketOwnerSource for MapOwnerSource {
    fn owner<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        let found = self.0.get(bucket.as_str()).cloned();
        Box::pin(async move { found.map(Arc::<str>::from).ok_or_else(BucketOwnerError::unavailable) })
    }
}

#[derive(Default)]
struct RecordingCopyAndPost {
    copy_calls: AtomicUsize,
    part_copy_calls: AtomicUsize,
    post_calls: AtomicUsize,
}

impl Handler<CopyObject> for RecordingCopyAndPost {
    async fn call(&self, _request: Req<CopyObject>) -> HandlerResult<CopyObject> {
        self.copy_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(CopyObjectOutput::default()))
    }
}

impl Handler<UploadPartCopy> for RecordingCopyAndPost {
    async fn call(&self, _request: Req<UploadPartCopy>) -> HandlerResult<UploadPartCopy> {
        self.part_copy_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(UploadPartCopyOutput::default()))
    }
}

impl Handler<PostObject> for RecordingCopyAndPost {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        self.post_calls.fetch_add(1, Ordering::SeqCst);
        let _ = request.into_input().body.into_body().collect().await;
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(ETag::new("etag").expect("etag")),
            version_id: None,
        }))
    }
}

fn post_form_request(fields: &[(&str, &str)]) -> Request<Bytes> {
    let mut body = String::new();
    for (name, value) in [("key", "obj")].iter().chain(fields) {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\nhi\r\n--{BOUNDARY}--\r\n"
    ));
    Request::builder()
        .method(Method::POST)
        .uri("http://host.invalid/dest-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .header("content-length", body.len())
        .body(Bytes::from(body))
        .expect("post request")
}

/// Negative & positive — `CopyObject` and `UploadPartCopy` enforce `x-amz-source-expected-bucket-owner`
/// against `BucketOwnerSource` for the source bucket (failing closed when no source is installed
/// and denying mismatches before the handler runs).
#[tokio::test]
async fn n_copy_and_upload_part_copy_validate_source_expected_bucket_owner() {
    let backend = Arc::new(RecordingCopyAndPost::default());

    // Default NoBucketOwner must fail closed on both CopyObject and UploadPartCopy.
    let no_owner_svc = support::wired_at_signed_time()
        .register::<CopyObject, _>(Arc::clone(&backend))
        .register::<UploadPartCopy, _>(Arc::clone(&backend))
        .authorizer(allow_when(|_| true))
        .build()
        .expect("service");
    let copy_req = support::signed_with(
        Method::PUT,
        "/dest-bucket/dst",
        &[
            ("x-amz-copy-source", "/src-bucket/src"),
            ("x-amz-source-expected-bucket-owner", "111122223333"),
        ],
    );
    assert_eq!(exchange_wire(&no_owner_svc, copy_req).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.copy_calls.load(Ordering::SeqCst), 0);

    let part_req = support::signed_with(
        Method::PUT,
        "/dest-bucket/dst?partNumber=1&uploadId=u1",
        &[
            ("x-amz-copy-source", "/src-bucket/src"),
            ("x-amz-source-expected-bucket-owner", "111122223333"),
        ],
    );
    assert_eq!(exchange_wire(&no_owner_svc, part_req).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.part_copy_calls.load(Ordering::SeqCst), 0);

    // Distinct owners for source vs destination: destination owner must NOT satisfy source owner.
    let mut owners = BTreeMap::new();
    owners.insert("dest-bucket".to_owned(), "222222222222".to_owned());
    owners.insert("src-bucket".to_owned(), "111111111111".to_owned());
    let owner_svc = support::wired_at_signed_time()
        .register::<CopyObject, _>(Arc::clone(&backend))
        .register::<UploadPartCopy, _>(Arc::clone(&backend))
        .bucket_owner_source(MapOwnerSource(owners))
        .authorizer(allow_when(|_| true))
        .build()
        .expect("service");

    let wrong_copy = support::signed_with(
        Method::PUT,
        "/dest-bucket/dst",
        &[
            ("x-amz-copy-source", "/src-bucket/src"),
            ("x-amz-source-expected-bucket-owner", "222222222222"),
        ],
    );
    assert_eq!(exchange_wire(&owner_svc, wrong_copy).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.copy_calls.load(Ordering::SeqCst), 0);

    let wrong_part = support::signed_with(
        Method::PUT,
        "/dest-bucket/dst?partNumber=1&uploadId=u1",
        &[
            ("x-amz-copy-source", "/src-bucket/src"),
            ("x-amz-source-expected-bucket-owner", "999999999999"),
        ],
    );
    assert_eq!(exchange_wire(&owner_svc, wrong_part).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.part_copy_calls.load(Ordering::SeqCst), 0);

    // Positive controls: matching source owner succeeds.
    let ok_copy = support::signed_with(
        Method::PUT,
        "/dest-bucket/dst",
        &[
            ("x-amz-copy-source", "/src-bucket/src"),
            ("x-amz-source-expected-bucket-owner", "111111111111"),
        ],
    );
    assert_eq!(exchange_wire(&owner_svc, ok_copy).await.status(), StatusCode::OK);
    assert_eq!(backend.copy_calls.load(Ordering::SeqCst), 1);

    let ok_part = support::signed_with(
        Method::PUT,
        "/dest-bucket/dst?partNumber=1&uploadId=u1",
        &[
            ("x-amz-copy-source", "/src-bucket/src"),
            ("x-amz-source-expected-bucket-owner", "111111111111"),
        ],
    );
    assert_eq!(exchange_wire(&owner_svc, ok_part).await.status(), StatusCode::OK);
    assert_eq!(backend.part_copy_calls.load(Ordering::SeqCst), 1);
}

/// Negative & positive — `PostObject` validates multipart form field `x-amz-expected-bucket-owner`
/// against `BucketOwnerSource` under both legacy and gateway form grammars.
#[tokio::test]
async fn n_post_object_form_expected_bucket_owner_is_validated() {
    for legacy in [true, false] {
        let backend = Arc::new(RecordingCopyAndPost::default());
        let builder = support::wired_at_signed_time()
            .register::<PostObject, _>(Arc::clone(&backend))
            .authorizer(allow_when(|_| true));
        let no_owner_svc = if legacy { builder.legacy_rustfs_post_forms() } else { builder }
            .build()
            .expect("service");
        let resp = exchange_wire(&no_owner_svc, post_form_request(&[("x-amz-expected-bucket-owner", "111122223333")])).await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "legacy={legacy} default NoBucketOwner must fail closed"
        );
        assert_eq!(backend.post_calls.load(Ordering::SeqCst), 0);

        let mut owners = BTreeMap::new();
        owners.insert("dest-bucket".to_owned(), "111122223333".to_owned());
        let builder = support::wired_at_signed_time()
            .register::<PostObject, _>(Arc::clone(&backend))
            .bucket_owner_source(MapOwnerSource(owners))
            .authorizer(allow_when(|_| true));
        let owner_svc = if legacy { builder.legacy_rustfs_post_forms() } else { builder }
            .build()
            .expect("service");

        let mismatch = exchange_wire(&owner_svc, post_form_request(&[("x-amz-expected-bucket-owner", "999999999999")])).await;
        assert_eq!(mismatch.status(), StatusCode::FORBIDDEN, "legacy={legacy} mismatch must deny");
        assert_eq!(backend.post_calls.load(Ordering::SeqCst), 0);

        // Positive control: matching form expected-bucket-owner succeeds.
        let matched = exchange_wire(&owner_svc, post_form_request(&[("x-amz-expected-bucket-owner", "111122223333")])).await;
        assert_eq!(matched.status(), StatusCode::NO_CONTENT, "legacy={legacy} match must succeed");
        assert_eq!(backend.post_calls.load(Ordering::SeqCst), 1);
    }
}

// ── Item 4: HeadObject missing-object visibility mask (s3:ListBucket) ──────────────────────────

struct MissingObjectBackend;

impl Handler<GetObject> for MissingObjectBackend {
    async fn call(&self, request: Req<GetObject>) -> HandlerResult<GetObject> {
        Err(
            HandlerErrorContext::missing_object_for(request.input().key.clone(), MissingObject::Key, ResourceVisibility::Visible)
                .into(),
        )
    }
}

impl Handler<HeadObject> for MissingObjectBackend {
    async fn call(&self, request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        Err(
            HandlerErrorContext::missing_object_for(request.input().key.clone(), MissingObject::Key, ResourceVisibility::Visible)
                .into(),
        )
    }
}

/// Negative & positive — `HeadObject` enforces the identical `s3:ListBucket` visibility mask as
/// `GetObject` on both dynamic and monomorphic dispatch: missing keys answer `403` without
/// `s3:ListBucket` and `404` with it.
#[tokio::test]
async fn n_head_object_hides_missing_object_without_list_bucket_permission() {
    type Ops = OperationSetNode<GetObject, OperationSetNode<HeadObject, OperationSetEnd>>;

    for allow_list_bucket in [false, true] {
        let expected_status = if allow_list_bucket {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::FORBIDDEN
        };
        let authz = allow_when(move |req| match req.action {
            "s3:GetObject" => true,
            "s3:ListBucket" => allow_list_bucket,
            _ => false,
        });
        let dynamic = support::wired_at_signed_time()
            .register::<GetObject, _>(Arc::new(MissingObjectBackend))
            .register::<HeadObject, _>(Arc::new(MissingObjectBackend))
            .authorizer(authz)
            .build()
            .expect("dynamic service");
        let authz_mono = allow_when(move |req| match req.action {
            "s3:GetObject" => true,
            "s3:ListBucket" => allow_list_bucket,
            _ => false,
        });
        let mono_backend = Arc::new(MissingObjectBackend);
        let mono = support::wired_at_signed_time()
            .register::<GetObject, _>(Arc::clone(&mono_backend))
            .register::<HeadObject, _>(Arc::clone(&mono_backend))
            .authorizer(authz_mono)
            .build_monomorphic::<MissingObjectBackend, Ops>(mono_backend)
            .expect("monomorphic service");

        let get_dyn = exchange_wire(&dynamic, support::signed(Method::GET, "/bucket/missing")).await;
        let head_dyn = exchange_wire(&dynamic, support::signed(Method::HEAD, "/bucket/missing")).await;
        assert_eq!(get_dyn.status(), expected_status, "dynamic GetObject allow_list={allow_list_bucket}");
        assert_eq!(head_dyn.status(), expected_status, "dynamic HeadObject allow_list={allow_list_bucket}");
        assert!(head_dyn.body().is_empty(), "HEAD response must remain bodyless");

        let head_mono = mono.call_bytes(support::signed(Method::HEAD, "/bucket/missing")).await;
        assert_eq!(
            head_mono.status(),
            expected_status,
            "monomorphic HeadObject allow_list={allow_list_bucket}"
        );
    }
}

// ── Item 8: verbose_signature_errors redaction gaps ─────────────────────────────────────────────

/// Negative — `verbose_signature_errors` must redact ADR-0042 bearer `token` and declared claim
/// parameters, presigned SSE-C query keys, and sensitive signed headers (`cookie`,
/// `proxy-authorization`, `authorization`).
#[tokio::test]
async fn n_verbose_signature_errors_redacts_bearer_ssec_query_and_sensitive_headers() {
    let (builder, _handle) = support::wired_at_signed_time()
        .register::<GetObject, _>(Arc::new(MissingObjectBackend))
        .register::<BearerDownload, _>(Arc::new(BearerBackend))
        .dialect(&bearer_dialect())
        .bearer_token_verifier(RejectBearer)
        .authorizer(allow_when(|_| true))
        .config(ServiceConfig::new(DEFAULT_MAX_BUFFERED_BODY_BYTES).with_verbose_signature_errors(true));
    let svc = builder.build().expect("verbose service");

    // 1. Header-signed request signing `cookie` and `proxy-authorization`, plus `token` and presigned SSE-C query keys.
    let cookie_secret = "session=super-secret-cookie-value";
    let proxy_secret = "Basic cHJveHk6c2VjcmV0";
    let mut headers_req = Request::builder()
        .method(Method::GET)
        .uri("http://host.invalid/bucket/key?token=bearer-secret-xyz&X-Amz-Server-Side-Encryption-Customer-Key=ssec-query-secret-123&X-Amz-Server-Side-Encryption-Customer-Key-MD5=ssec-md5-secret-456&X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key=copy-ssec-secret-789")
        .header("host", "host.invalid")
        .header("x-amz-date", support::SIGNED_AT_STAMP)
        .header("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .header("cookie", cookie_secret)
        .header("proxy-authorization", proxy_secret)
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request, SignedHeaders=cookie;host;proxy-authorization;x-amz-content-sha256;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
        )
        .body(Bytes::new())
        .expect("request");
    headers_req.extensions_mut().insert(TransportSecurity::Encrypted);
    let resp = exchange_wire(&svc, headers_req).await;
    let body = String::from_utf8_lossy(resp.body());
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    assert!(body.contains("<CanonicalRequest>"), "{body}");
    for leaked in [
        cookie_secret,
        proxy_secret,
        "bearer-secret-xyz",
        "ssec-query-secret-123",
        "ssec-md5-secret-456",
        "copy-ssec-secret-789",
    ] {
        assert!(!body.contains(leaked), "secret `{leaked}` leaked into verbose error: {body}");
    }
    assert!(body.contains("cookie:__REDACTED__"), "{body}");
    assert!(body.contains("proxy-authorization:__REDACTED__"), "{body}");
    assert!(body.contains("token=__REDACTED__"), "{body}");
    assert!(body.contains("X-Amz-Server-Side-Encryption-Customer-Key=__REDACTED__"), "{body}");
    assert!(body.contains("X-Amz-Server-Side-Encryption-Customer-Key-MD5=__REDACTED__"), "{body}");
    assert!(
        body.contains("X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key=__REDACTED__"),
        "{body}"
    );

    // 2. Declared non-`token` bearer claim parameter (`dl_token`) on a bearer-claimed route.
    let custom_bearer_req = Request::builder()
        .method(Method::GET)
        .uri("http://host.invalid/example/downloads/archive.zip?dl_token=custom-dl-secret-999")
        .header("host", "host.invalid")
        .header("x-amz-date", support::SIGNED_AT_STAMP)
        .header("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
        )
        .body(Bytes::new())
        .expect("request");
    let custom_resp = exchange_wire(&svc, custom_bearer_req).await;
    let custom_body = String::from_utf8_lossy(custom_resp.body());
    assert_eq!(custom_resp.status(), StatusCode::FORBIDDEN, "{custom_body}");
    assert!(custom_body.contains("<CanonicalRequest>"), "{custom_body}");
    assert!(
        !custom_body.contains("custom-dl-secret-999"),
        "declared bearer claim token leaked into verbose error: {custom_body}"
    );
    assert!(custom_body.contains("dl_token=__REDACTED__"), "{custom_body}");
}
