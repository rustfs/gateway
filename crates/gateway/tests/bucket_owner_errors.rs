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

//! `BucketOwnerSource` error distinction and existence-oracle regressions (rustfs/gateway#1589).
//!
//! Responsible for: proving that `BucketOwnerError::not_found()` maps to `404 NoSuchBucket` (and
//! bodyless `404` on `HEAD`) only after authorization has allowed the request, that
//! `BucketOwnerError::backend_failure()` maps to retryable `500 InternalError`, that mismatches,
//! `BucketOwnerError::unavailable()`, `NoBucketOwner`, empty owners, and panics stay `403
//! AccessDenied`, that `BucketOwnerSource` is never consulted when the header is absent or
//! authorization denies, and that `BucketOwnerError`'s `Display`/`Debug` stay opaque.
//! NOT responsible for: `BucketOwnerSource` on non-S3 services (`tests/service_routes/isolation.rs`)
//! or `read_empty_headers_as_absent` (`tests/empty_headers_absent.rs`).
//! Upstream: `rustfs-gateway` public API. Downstream: Cargo's integration test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt as _;
use rustfs_gateway::dto::{
    CopyObject, CopyObjectOutput, HeadBucket, HeadBucketOutput, ListBuckets, ListBucketsOutput, ListObjectsV2,
    ListObjectsV2Output, PostObject, PostObjectOutput, PutObject, PutObjectOutput, UploadPartCopy, UploadPartCopyOutput,
};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, BucketName, BucketOwnerError, BucketOwnerSource, Decision, ETag, Handler, HandlerError,
    HandlerResult, InputAuthzRequest, InputDecisions, Req, RequestContext, Resp, S3Service, allow_when, decide_with,
};

use crate::support::{self, exchange_wire};

const OWNER: &str = "111122223333";
const OTHER_OWNER: &str = "999988887777";
const BOUNDARY: &str = "----RustFSBucketOwner1589";

#[derive(Clone, Copy)]
enum ScriptedReply {
    Owner(&'static str),
    Unavailable,
    NotFound,
    Backend,
    SyncPanic,
    AsyncPanic,
}

struct SpyOwnerSource {
    replies: BTreeMap<String, ScriptedReply>,
    default: ScriptedReply,
    queries: Mutex<Vec<String>>,
}

impl SpyOwnerSource {
    fn new(default: ScriptedReply) -> Self {
        Self {
            replies: BTreeMap::new(),
            default,
            queries: Mutex::new(Vec::new()),
        }
    }

    fn with_bucket(mut self, bucket: &str, reply: ScriptedReply) -> Self {
        self.replies.insert(bucket.to_owned(), reply);
        self
    }

    fn take_queries(&self) -> Vec<String> {
        std::mem::take(&mut *self.queries.lock().expect("not poisoned"))
    }
}

impl BucketOwnerSource for SpyOwnerSource {
    fn owner<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Arc<str>, BucketOwnerError>> {
        self.queries.lock().expect("not poisoned").push(bucket.as_str().to_owned());
        let reply = self.replies.get(bucket.as_str()).copied().unwrap_or(self.default);
        match reply {
            ScriptedReply::SyncPanic => panic!("sync bucket owner source panic"),
            ScriptedReply::AsyncPanic => Box::pin(async { panic!("async bucket owner source panic") }),
            ScriptedReply::Owner(owner) => Box::pin(async move { Ok(Arc::from(owner)) }),
            ScriptedReply::Unavailable => Box::pin(async { Err(BucketOwnerError::unavailable()) }),
            ScriptedReply::NotFound => Box::pin(async { Err(BucketOwnerError::not_found()) }),
            ScriptedReply::Backend => Box::pin(async { Err(BucketOwnerError::backend_failure()) }),
        }
    }
}

#[derive(Default)]
struct CountingHandlers {
    list: AtomicUsize,
    head: AtomicUsize,
    put: AtomicUsize,
    post: AtomicUsize,
    copy: AtomicUsize,
    part_copy: AtomicUsize,
}

impl CountingHandlers {
    fn total(&self) -> usize {
        self.list.load(Ordering::SeqCst)
            + self.head.load(Ordering::SeqCst)
            + self.put.load(Ordering::SeqCst)
            + self.post.load(Ordering::SeqCst)
            + self.copy.load(Ordering::SeqCst)
            + self.part_copy.load(Ordering::SeqCst)
    }
}

impl Handler<ListBuckets> for CountingHandlers {
    async fn call(&self, _request: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
        self.list.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(ListBucketsOutput::default()))
    }
}

impl Handler<ListObjectsV2> for CountingHandlers {
    async fn call(&self, _request: Req<ListObjectsV2>) -> HandlerResult<ListObjectsV2> {
        self.list.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(ListObjectsV2Output::default()))
    }
}

impl Handler<HeadBucket> for CountingHandlers {
    async fn call(&self, _request: Req<HeadBucket>) -> HandlerResult<HeadBucket> {
        self.head.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(HeadBucketOutput::default()))
    }
}

impl Handler<PutObject> for CountingHandlers {
    async fn call(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        if let Some(body) = request.into_input().body {
            let mut body = body.into_body();
            while let Some(frame) = body.frame().await {
                frame.map_err(|_| HandlerError::internal_error("body stream failed"))?;
            }
        }
        self.put.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(PutObjectOutput {
            e_tag: ETag::new("5d41402abc4b2a76b9719d911017c592").expect("etag"),
            ..Default::default()
        }))
    }
}

impl Handler<PostObject> for CountingHandlers {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        self.post.fetch_add(1, Ordering::SeqCst);
        let _ = request.into_input().body.into_body().collect().await;
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(ETag::new("5d41402abc4b2a76b9719d911017c592").expect("etag")),
            version_id: None,
        }))
    }
}

impl Handler<CopyObject> for CountingHandlers {
    async fn call(&self, _request: Req<CopyObject>) -> HandlerResult<CopyObject> {
        self.copy.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(CopyObjectOutput::default()))
    }
}

impl Handler<UploadPartCopy> for CountingHandlers {
    async fn call(&self, _request: Req<UploadPartCopy>) -> HandlerResult<UploadPartCopy> {
        self.part_copy.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(UploadPartCopyOutput::default()))
    }
}

fn register_all(builder: rustfs_gateway::ServiceBuilder, backend: &Arc<CountingHandlers>) -> rustfs_gateway::ServiceBuilder {
    builder
        .register::<ListBuckets, _>(Arc::clone(backend))
        .register::<ListObjectsV2, _>(Arc::clone(backend))
        .register::<HeadBucket, _>(Arc::clone(backend))
        .register::<PutObject, _>(Arc::clone(backend))
        .register::<PostObject, _>(Arc::clone(backend))
        .register::<CopyObject, _>(Arc::clone(backend))
        .register::<UploadPartCopy, _>(Arc::clone(backend))
}

fn post_form_request(bucket: &str, fields: &[(&str, &str)]) -> Request<Bytes> {
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
        .uri(format!("http://host.invalid/{bucket}"))
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .header("content-length", body.len())
        .body(Bytes::from(body))
        .expect("post request")
}

fn body_text(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn error_code(response: &rustfs_gateway::WireResponse) -> Option<String> {
    support::element_text(&body_text(response), "Code").map(str::to_owned)
}

fn redact_ids(xml: &str) -> String {
    let mut out = xml.to_owned();
    for tag in ["RequestId", "HostId"] {
        if let Some(value) = support::element_text(&out, tag) {
            let owned = value.to_owned();
            out = out.replace(&owned, "__REDACTED__");
        }
    }
    out
}

struct RouteAllowInputDecide(Decision);

impl Authorizer for RouteAllowInputDecide {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decision = self.0;
        let decisions = request.decide_all(Decision::Allow, |_| decision);
        Box::pin(async move { decisions })
    }
}

/// Negative — `BucketOwnerError` is a 1-byte closed error value whose `Display` and `Debug`
/// carry no request, bucket, owner, or backend data.
#[test]
fn n_bucket_owner_error_display_and_debug_stay_opaque() {
    assert_eq!(core::mem::size_of::<BucketOwnerError>(), 1);

    let unavailable = BucketOwnerError::unavailable();
    let not_found = BucketOwnerError::not_found();
    let backend = BucketOwnerError::backend_failure();

    assert_ne!(unavailable, not_found);
    assert_ne!(unavailable, backend);
    assert_ne!(not_found, backend);
    assert_eq!(unavailable.to_string(), "bucket owner unavailable");
    assert_eq!(not_found.to_string(), "bucket not found");
    assert_eq!(backend.to_string(), "bucket owner lookup failed");

    for error in [unavailable, not_found, backend] {
        let _: &dyn std::error::Error = &error;
        let rendered = format!("{error} / {error:?}");
        assert!(!rendered.contains(OWNER), "owner leaked: {rendered}");
        assert!(!rendered.contains("bucket-"), "bucket leaked: {rendered}");
    }
}

/// Negative — on `x-amz-expected-bucket-owner`, an authorized caller receives `404 NoSuchBucket`
/// for `not_found()`, `500 InternalError` for `backend_failure()`, and `403 AccessDenied` for
/// mismatches, `unavailable()`, default `NoBucketOwner`, empty owners, and panics; `HEAD` stays
/// bodyless with the matching status.
#[tokio::test]
async fn n_route_header_distinguishes_not_found_and_backend_failure_while_others_stay_403() {
    let backend = Arc::new(CountingHandlers::default());
    let spy = Arc::new(
        SpyOwnerSource::new(ScriptedReply::Unavailable)
            .with_bucket("owned-bucket", ScriptedReply::Owner(OWNER))
            .with_bucket("missing-bucket", ScriptedReply::NotFound)
            .with_bucket("broken-bucket", ScriptedReply::Backend)
            .with_bucket("unavail-bucket", ScriptedReply::Unavailable)
            .with_bucket("empty-owner-bucket", ScriptedReply::Owner(""))
            .with_bucket("sync-panic-bucket", ScriptedReply::SyncPanic)
            .with_bucket("async-panic-bucket", ScriptedReply::AsyncPanic),
    );
    let service = register_all(support::wired_at_signed_time(), &backend)
        .bucket_owner_source(Arc::clone(&spy))
        .authorizer(allow_when(|_| true))
        .build()
        .expect("service");

    // 1. Missing bucket -> 404 NoSuchBucket on GET, bodyless 404 on HEAD.
    let get_missing = exchange_wire(
        &service,
        support::signed_with(Method::GET, "/missing-bucket?list-type=2", &[("x-amz-expected-bucket-owner", OWNER)]),
    )
    .await;
    assert_eq!(get_missing.status(), StatusCode::NOT_FOUND, "{}", body_text(&get_missing));
    assert_eq!(error_code(&get_missing).as_deref(), Some("NoSuchBucket"));
    assert!(
        !body_text(&get_missing).contains("missing-bucket") && !body_text(&get_missing).contains(OWNER),
        "wire error leaked bucket or owner: {}",
        body_text(&get_missing)
    );

    let head_missing = exchange_wire(
        &service,
        support::signed_with(Method::HEAD, "/missing-bucket", &[("x-amz-expected-bucket-owner", OWNER)]),
    )
    .await;
    assert_eq!(head_missing.status(), StatusCode::NOT_FOUND);
    assert!(head_missing.body().is_empty(), "HEAD 404 must be bodyless");

    // 2. Backend failure -> retryable 500 InternalError on GET, bodyless 500 on HEAD.
    let get_broken = exchange_wire(
        &service,
        support::signed_with(Method::GET, "/broken-bucket?list-type=2", &[("x-amz-expected-bucket-owner", OWNER)]),
    )
    .await;
    assert_eq!(get_broken.status(), StatusCode::INTERNAL_SERVER_ERROR, "{}", body_text(&get_broken));
    assert_eq!(error_code(&get_broken).as_deref(), Some("InternalError"));
    assert!(
        !body_text(&get_broken).contains("broken-bucket") && !body_text(&get_broken).contains(OWNER),
        "wire 500 leaked bucket or owner: {}",
        body_text(&get_broken)
    );

    let head_broken = exchange_wire(
        &service,
        support::signed_with(Method::HEAD, "/broken-bucket", &[("x-amz-expected-bucket-owner", OWNER)]),
    )
    .await;
    assert_eq!(head_broken.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(head_broken.body().is_empty(), "HEAD 500 must be bodyless");

    // 3. Mismatch, Unavailable, empty actual owner, empty expected owner (even against empty actual
    // owner), sync panic, and async panic all stay 403 AccessDenied.
    for (bucket, header_val, label) in [
        ("owned-bucket", OTHER_OWNER, "mismatch"),
        ("unavail-bucket", OWNER, "unavailable"),
        ("empty-owner-bucket", OWNER, "empty actual owner"),
        ("empty-owner-bucket", "", "empty expected and empty actual owner"),
        ("missing-bucket", "", "empty expected owner on missing bucket"),
        ("sync-panic-bucket", OWNER, "sync panic"),
        ("async-panic-bucket", OWNER, "async panic"),
    ] {
        let resp = exchange_wire(
            &service,
            support::signed_with(
                Method::GET,
                &format!("/{bucket}?list-type=2"),
                &[("x-amz-expected-bucket-owner", header_val)],
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{label}: {}", body_text(&resp));
        assert_eq!(error_code(&resp).as_deref(), Some("AccessDenied"), "{label}");
    }

    // 4. Service-level request (`ListBuckets`, no bucket) with expected-owner header stays 403
    // and never consults `BucketOwnerSource`.
    let _ = spy.take_queries();
    let service_level = exchange_wire(
        &service,
        support::signed_with(Method::GET, "/", &[("x-amz-expected-bucket-owner", OWNER)]),
    )
    .await;
    assert_eq!(service_level.status(), StatusCode::FORBIDDEN, "{}", body_text(&service_level));
    assert_eq!(error_code(&service_level).as_deref(), Some("AccessDenied"));
    assert!(spy.take_queries().is_empty(), "service-level request must not consult BucketOwnerSource");

    // 5. Default NoBucketOwner remains unchanged: 403 AccessDenied.
    let default_svc = register_all(support::wired_at_signed_time(), &backend)
        .authorizer(allow_when(|_| true))
        .build()
        .expect("default service");
    let default_resp = exchange_wire(
        &default_svc,
        support::signed_with(Method::GET, "/missing-bucket?list-type=2", &[("x-amz-expected-bucket-owner", OWNER)]),
    )
    .await;
    assert_eq!(default_resp.status(), StatusCode::FORBIDDEN, "{}", body_text(&default_resp));
    assert_eq!(error_code(&default_resp).as_deref(), Some("AccessDenied"));

    assert_eq!(backend.total(), 0, "no failing owner check may reach a handler");
}

/// Negative — unauthorized callers (denied on the base action, indeterminate on the base action,
/// or denied on a triggered extra permission) stay `403 AccessDenied` and never trigger
/// `BucketOwnerSource::owner()`, eliminating bucket-existence and backend-fault oracles.
#[tokio::test]
async fn n_denied_caller_cannot_probe_missing_bucket_or_backend_fault() {
    let backend = Arc::new(CountingHandlers::default());
    let spy = Arc::new(
        SpyOwnerSource::new(ScriptedReply::NotFound)
            .with_bucket("existing-bucket", ScriptedReply::Owner(OWNER))
            .with_bucket("missing-bucket", ScriptedReply::NotFound)
            .with_bucket("broken-bucket", ScriptedReply::Backend),
    );

    // Base route Deny and Indeterminate: existing, missing, and broken buckets produce identical 403s
    // and zero BucketOwnerSource calls.
    for verdict in [Decision::Deny, Decision::Indeterminate] {
        let svc = register_all(support::wired_at_signed_time(), &backend)
            .bucket_owner_source(Arc::clone(&spy))
            .authorizer(decide_with(move |_| verdict))
            .build()
            .expect("service");
        let existing = exchange_wire(
            &svc,
            support::signed_with(Method::GET, "/existing-bucket?list-type=2", &[("x-amz-expected-bucket-owner", OWNER)]),
        )
        .await;
        let missing = exchange_wire(
            &svc,
            support::signed_with(Method::GET, "/missing-bucket?list-type=2", &[("x-amz-expected-bucket-owner", OWNER)]),
        )
        .await;
        let broken = exchange_wire(
            &svc,
            support::signed_with(Method::GET, "/broken-bucket?list-type=2", &[("x-amz-expected-bucket-owner", OWNER)]),
        )
        .await;
        for (label, resp) in [("existing", &existing), ("missing", &missing), ("broken", &broken)] {
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{verdict:?} {label}");
            assert_eq!(error_code(resp).as_deref(), Some("AccessDenied"), "{verdict:?} {label}");
        }
        assert_eq!(redact_ids(&body_text(&existing)), redact_ids(&body_text(&missing)));
        assert_eq!(redact_ids(&body_text(&existing)), redact_ids(&body_text(&broken)));
        assert!(spy.take_queries().is_empty(), "BucketOwnerSource was consulted despite {verdict:?}");
    }

    // Extra-permission denial: allowed s3:PutObject, denied s3:PutObjectTagging -> must stay 403
    // and never probe missing-bucket via BucketOwnerSource.
    let extra_denied = register_all(support::wired_at_signed_time(), &backend)
        .bucket_owner_source(Arc::clone(&spy))
        .authorizer(allow_when(|req| req.action == "s3:PutObject"))
        .build()
        .expect("extra denied service");
    let tagged_put = support::signed_target_with_body_and_headers(
        Method::PUT,
        "/missing-bucket/key",
        &[
            ("content-length", "1"),
            ("x-amz-tagging", "k=v"),
            ("x-amz-expected-bucket-owner", OWNER),
        ],
        Bytes::from_static(b"x"),
    );
    let denied_resp = exchange_wire(&extra_denied, tagged_put).await;
    assert_eq!(denied_resp.status(), StatusCode::FORBIDDEN, "{}", body_text(&denied_resp));
    assert_eq!(error_code(&denied_resp).as_deref(), Some("AccessDenied"));
    assert!(
        spy.take_queries().is_empty(),
        "BucketOwnerSource was consulted when extra permission s3:PutObjectTagging was denied"
    );

    // Positive control: when both s3:PutObject and s3:PutObjectTagging are allowed, the same
    // request reaches BucketOwnerSource and reports 404 NoSuchBucket.
    let extra_allowed = register_all(support::wired_at_signed_time(), &backend)
        .bucket_owner_source(Arc::clone(&spy))
        .authorizer(allow_when(|req| matches!(req.action, "s3:PutObject" | "s3:PutObjectTagging")))
        .build()
        .expect("extra allowed service");
    let allowed_put = support::signed_target_with_body_and_headers(
        Method::PUT,
        "/missing-bucket/key",
        &[
            ("content-length", "1"),
            ("x-amz-tagging", "k=v"),
            ("x-amz-expected-bucket-owner", OWNER),
        ],
        Bytes::from_static(b"x"),
    );
    let not_found_resp = exchange_wire(&extra_allowed, allowed_put).await;
    assert_eq!(not_found_resp.status(), StatusCode::NOT_FOUND, "{}", body_text(&not_found_resp));
    assert_eq!(error_code(&not_found_resp).as_deref(), Some("NoSuchBucket"));
    assert_eq!(spy.take_queries(), ["missing-bucket"]);
    assert_eq!(backend.total(), 0);
}

/// Negative — `PostObject` form-supplied `x-amz-expected-bucket-owner` maps `NotFound` -> `404
/// NoSuchBucket`, `Backend` -> `500 InternalError`, and `Unavailable`/mismatch/empty/panic -> `403
/// AccessDenied` under both form grammars, while denied callers remain `403` without consulting the
/// source.
#[tokio::test]
async fn n_post_object_form_expected_owner_error_mapping_and_oracle_guard() {
    for legacy in [false, true] {
        let backend = Arc::new(CountingHandlers::default());
        let spy = Arc::new(
            SpyOwnerSource::new(ScriptedReply::Unavailable)
                .with_bucket("missing-bucket", ScriptedReply::NotFound)
                .with_bucket("broken-bucket", ScriptedReply::Backend)
                .with_bucket("unavail-bucket", ScriptedReply::Unavailable)
                .with_bucket("panic-bucket", ScriptedReply::AsyncPanic)
                .with_bucket("owned-bucket", ScriptedReply::Owner(OWNER)),
        );
        let builder = register_all(support::wired_at_signed_time(), &backend)
            .bucket_owner_source(Arc::clone(&spy))
            .authorizer(allow_when(|_| true));
        let svc = if legacy { builder.legacy_rustfs_post_forms() } else { builder }
            .build()
            .expect("post service");

        let missing = exchange_wire(&svc, post_form_request("missing-bucket", &[("x-amz-expected-bucket-owner", OWNER)])).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND, "legacy={legacy}: {}", body_text(&missing));
        assert_eq!(error_code(&missing).as_deref(), Some("NoSuchBucket"), "legacy={legacy}");

        let broken = exchange_wire(&svc, post_form_request("broken-bucket", &[("x-amz-expected-bucket-owner", OWNER)])).await;
        assert_eq!(
            broken.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "legacy={legacy}: {}",
            body_text(&broken)
        );
        assert_eq!(error_code(&broken).as_deref(), Some("InternalError"), "legacy={legacy}");

        for (bucket, expected, label) in [
            ("unavail-bucket", OWNER, "unavailable"),
            ("owned-bucket", OTHER_OWNER, "mismatch"),
            ("missing-bucket", "", "empty form owner"),
            ("panic-bucket", OWNER, "panic"),
        ] {
            let resp = exchange_wire(&svc, post_form_request(bucket, &[("x-amz-expected-bucket-owner", expected)])).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "legacy={legacy} {label}");
            assert_eq!(error_code(&resp).as_deref(), Some("AccessDenied"), "legacy={legacy} {label}");
        }
        let _ = spy.take_queries();

        // Denied caller must stay 403 and never query BucketOwnerSource.
        let denied_builder = register_all(support::wired_at_signed_time(), &backend)
            .bucket_owner_source(Arc::clone(&spy))
            .authorizer(decide_with(|_| Decision::Deny));
        let denied_svc = if legacy {
            denied_builder.legacy_rustfs_post_forms()
        } else {
            denied_builder
        }
        .build()
        .expect("denied post service");
        let denied = exchange_wire(
            &denied_svc,
            post_form_request("missing-bucket", &[("x-amz-expected-bucket-owner", OWNER)]),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN, "legacy={legacy}");
        assert_eq!(error_code(&denied).as_deref(), Some("AccessDenied"), "legacy={legacy}");
        assert!(spy.take_queries().is_empty(), "legacy={legacy} consulted source when denied");
        assert_eq!(backend.total(), 0);
    }
}

/// Negative — `CopyObject` and `UploadPartCopy` enforce `x-amz-source-expected-bucket-owner`
/// with `NotFound` -> `404 NoSuchBucket`, `Backend` -> `500 InternalError`, and
/// `Unavailable`/mismatch/empty/panic/ARN -> `403 AccessDenied`, only after input authorization
/// allows the source bucket.
#[tokio::test]
async fn n_copy_source_expected_owner_error_mapping_and_input_authz_guard() {
    let backend = Arc::new(CountingHandlers::default());
    let spy = Arc::new(
        SpyOwnerSource::new(ScriptedReply::Unavailable)
            .with_bucket("dest-bucket", ScriptedReply::Owner(OWNER))
            .with_bucket("src-missing", ScriptedReply::NotFound)
            .with_bucket("src-broken", ScriptedReply::Backend)
            .with_bucket("src-unavail", ScriptedReply::Unavailable)
            .with_bucket("src-panic", ScriptedReply::AsyncPanic)
            .with_bucket("src-empty", ScriptedReply::Owner(""))
            .with_bucket("src-owned", ScriptedReply::Owner(OWNER)),
    );

    // Input authorization denies source bucket while route allows destination -> must stay 403
    // and never consult BucketOwnerSource for the source bucket.
    let input_denied = register_all(support::wired_at_signed_time(), &backend)
        .bucket_owner_source(Arc::clone(&spy))
        .authorizer(RouteAllowInputDecide(Decision::Deny))
        .build()
        .expect("input denied service");
    for uri in ["/dest-bucket/dst", "/dest-bucket/dst?partNumber=1&uploadId=u1"] {
        let req = support::signed_with(
            Method::PUT,
            uri,
            &[
                ("x-amz-copy-source", "/src-missing/key"),
                ("x-amz-source-expected-bucket-owner", OWNER),
            ],
        );
        let resp = exchange_wire(&input_denied, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}: {}", body_text(&resp));
        assert_eq!(error_code(&resp).as_deref(), Some("AccessDenied"));
    }
    assert!(
        spy.take_queries().is_empty(),
        "BucketOwnerSource was consulted for copy source denied by authorize_input"
    );

    // Route + input authorization allowed -> distinguish NotFound (404) and Backend (500) from 403.
    let allowed = register_all(support::wired_at_signed_time(), &backend)
        .bucket_owner_source(Arc::clone(&spy))
        .authorizer(allow_when(|_| true))
        .build()
        .expect("allowed copy service");

    for uri in ["/dest-bucket/dst", "/dest-bucket/dst?partNumber=1&uploadId=u1"] {
        let missing = exchange_wire(
            &allowed,
            support::signed_with(
                Method::PUT,
                uri,
                &[
                    ("x-amz-copy-source", "/src-missing/key"),
                    ("x-amz-source-expected-bucket-owner", OWNER),
                ],
            ),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND, "{uri}: {}", body_text(&missing));
        assert_eq!(error_code(&missing).as_deref(), Some("NoSuchBucket"), "{uri}");

        let broken = exchange_wire(
            &allowed,
            support::signed_with(
                Method::PUT,
                uri,
                &[
                    ("x-amz-copy-source", "/src-broken/key"),
                    ("x-amz-source-expected-bucket-owner", OWNER),
                ],
            ),
        )
        .await;
        assert_eq!(broken.status(), StatusCode::INTERNAL_SERVER_ERROR, "{uri}: {}", body_text(&broken));
        assert_eq!(error_code(&broken).as_deref(), Some("InternalError"), "{uri}");

        for (source, expected, label) in [
            ("/src-unavail/key", OWNER, "unavailable"),
            ("/src-owned/key", OTHER_OWNER, "mismatch"),
            ("/src-empty/key", OWNER, "empty actual"),
            ("/src-missing/key", "", "empty expected"),
            ("/src-panic/key", OWNER, "panic"),
            (
                "arn:aws:s3:us-east-1:999988887777:accesspoint/src-missing/object/key",
                OWNER,
                "accesspoint arn",
            ),
        ] {
            let resp = exchange_wire(
                &allowed,
                support::signed_with(
                    Method::PUT,
                    uri,
                    &[
                        ("x-amz-copy-source", source),
                        ("x-amz-source-expected-bucket-owner", expected),
                    ],
                ),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri} {label}: {}", body_text(&resp));
            assert_eq!(error_code(&resp).as_deref(), Some("AccessDenied"), "{uri} {label}");
        }
    }
    assert_eq!(backend.total(), 0);
}

/// Negative — when no expected-owner header or form field is presented, `BucketOwnerSource` is
/// never consulted on route, POST form, or copy requests.
#[tokio::test]
async fn n_absent_owner_header_never_consults_bucket_owner_source() {
    let backend = Arc::new(CountingHandlers::default());
    let spy = Arc::new(SpyOwnerSource::new(ScriptedReply::SyncPanic));
    let svc: S3Service = register_all(support::wired_at_signed_time(), &backend)
        .bucket_owner_source(Arc::clone(&spy))
        .authorizer(allow_when(|_| true))
        .build()
        .expect("service");

    let list_resp = exchange_wire(&svc, support::signed(Method::GET, "/any-bucket?list-type=2")).await;
    assert_eq!(list_resp.status(), StatusCode::OK, "{}", body_text(&list_resp));

    let post_resp = exchange_wire(&svc, post_form_request("any-bucket", &[])).await;
    assert_eq!(post_resp.status(), StatusCode::NO_CONTENT, "{}", body_text(&post_resp));

    let copy_resp = exchange_wire(
        &svc,
        support::signed_with(Method::PUT, "/dest-bucket/dst", &[("x-amz-copy-source", "/src-bucket/src")]),
    )
    .await;
    assert_eq!(copy_resp.status(), StatusCode::OK, "{}", body_text(&copy_resp));

    assert!(
        spy.take_queries().is_empty(),
        "BucketOwnerSource must never be called when expected-owner assertions are absent"
    );
    assert_eq!(backend.list.load(Ordering::SeqCst), 1);
    assert_eq!(backend.post.load(Ordering::SeqCst), 1);
    assert_eq!(backend.copy.load(Ordering::SeqCst), 1);
}

/// Positive — matching owners succeed across route header (`ListObjectsV2`, `HeadBucket`),
/// `PostObject` form field, and copy-source (`CopyObject`, `UploadPartCopy`).
#[tokio::test]
async fn matching_owner_succeeds_across_all_expected_owner_surfaces() {
    let backend = Arc::new(CountingHandlers::default());
    let spy = Arc::new(
        SpyOwnerSource::new(ScriptedReply::NotFound)
            .with_bucket("dest-bucket", ScriptedReply::Owner(OWNER))
            .with_bucket("src-bucket", ScriptedReply::Owner(OTHER_OWNER)),
    );
    let svc = register_all(support::wired_at_signed_time(), &backend)
        .bucket_owner_source(Arc::clone(&spy))
        .authorizer(allow_when(|_| true))
        .build()
        .expect("service");

    let list = exchange_wire(
        &svc,
        support::signed_with(Method::GET, "/dest-bucket?list-type=2", &[("x-amz-expected-bucket-owner", OWNER)]),
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);

    let head = exchange_wire(
        &svc,
        support::signed_with(Method::HEAD, "/dest-bucket", &[("x-amz-expected-bucket-owner", OWNER)]),
    )
    .await;
    assert_eq!(head.status(), StatusCode::OK);

    let post = exchange_wire(&svc, post_form_request("dest-bucket", &[("x-amz-expected-bucket-owner", OWNER)])).await;
    assert_eq!(post.status(), StatusCode::NO_CONTENT);

    let copy = exchange_wire(
        &svc,
        support::signed_with(
            Method::PUT,
            "/dest-bucket/dst",
            &[
                ("x-amz-expected-bucket-owner", OWNER),
                ("x-amz-copy-source", "/src-bucket/src"),
                ("x-amz-source-expected-bucket-owner", OTHER_OWNER),
            ],
        ),
    )
    .await;
    assert_eq!(copy.status(), StatusCode::OK);

    let part_copy = exchange_wire(
        &svc,
        support::signed_with(
            Method::PUT,
            "/dest-bucket/dst?partNumber=1&uploadId=u1",
            &[
                ("x-amz-expected-bucket-owner", OWNER),
                ("x-amz-copy-source", "/src-bucket/src"),
                ("x-amz-source-expected-bucket-owner", OTHER_OWNER),
            ],
        ),
    )
    .await;
    assert_eq!(part_copy.status(), StatusCode::OK);

    assert_eq!(
        spy.take_queries(),
        [
            "dest-bucket",
            "dest-bucket",
            "dest-bucket",
            "dest-bucket",
            "src-bucket",
            "dest-bucket",
            "src-bucket",
        ]
    );
    assert_eq!(backend.list.load(Ordering::SeqCst), 1);
    assert_eq!(backend.head.load(Ordering::SeqCst), 1);
    assert_eq!(backend.post.load(Ordering::SeqCst), 1);
    assert_eq!(backend.copy.load(Ordering::SeqCst), 1);
    assert_eq!(backend.part_copy.load(Ordering::SeqCst), 1);
}
