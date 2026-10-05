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

//! Legacy RustFS's operation selection through the facade (rustfs/gateway#1127): which handler a
//! request reaches under `select_operations_as_legacy_rustfs` when its query carries `x-id` or two
//! operation keys.
//!
//! Responsible for: an `x-id` named once selecting its operation over the query's keys, two
//! operation keys selecting the first in legacy RustFS's order, and an undeclared `x-id` refused
//! `400 InvalidRequest` before any handler; each against the default assembly, which routes as it
//! always has. Every expectation is legacy RustFS's answer on a legacy build.
//! NOT responsible for: the order itself (`rustfs-gateway-core`'s `legacy_rustfs` tests) or what
//! the handler stores (`compat/sut`'s selection cases).
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::dto::{
    AbortMultipartUpload, CreateMultipartUpload, DeleteObjectTagging, GetBucketAcl, GetBucketVersioning, GetObjectTagging,
    ListObjects, PutObject, PutObjectTagging,
};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Classification, ClockSkewAck, Credentials, Decision, ErrorCode, HandlerError,
    HandlerResult, InputAuthzRequest, InputDecisions, RegionSet, Req, RequestContext, S3Service, SecurityFloor, ServiceBuilder,
    SigV4Authenticator, StaticCredentials,
};

use crate::support::{exchange, exchange_wire, fixed_clock, signed, signed_target_with_body_and_headers};

/// The operations the handlers were reached as, in order.
#[derive(Default)]
struct Seen(Mutex<Vec<&'static str>>);

impl Seen {
    fn take(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.0.lock().expect("not poisoned"))
    }

    fn hand(&self, operation: &'static str) {
        self.0.lock().expect("not poisoned").push(operation);
    }
}

struct Allow;

impl Authorizer for Allow {
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
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

struct Recorder(Arc<Seen>);

fn recorded<T>() -> Result<T, HandlerError> {
    Err(HandlerError::new(ErrorCode::NOT_IMPLEMENTED, "recorded"))
}

#[rustfs_gateway::handlers]
impl Recorder {
    async fn put_object(&self, _request: Req<PutObject>) -> HandlerResult<PutObject> {
        self.0.hand("PutObject");
        recorded()
    }

    async fn put_object_tagging(&self, _request: Req<PutObjectTagging>) -> HandlerResult<PutObjectTagging> {
        self.0.hand("PutObjectTagging");
        recorded()
    }

    async fn get_object_tagging(&self, _request: Req<GetObjectTagging>) -> HandlerResult<GetObjectTagging> {
        self.0.hand("GetObjectTagging");
        recorded()
    }

    async fn delete_object_tagging(&self, _request: Req<DeleteObjectTagging>) -> HandlerResult<DeleteObjectTagging> {
        self.0.hand("DeleteObjectTagging");
        recorded()
    }

    async fn abort_multipart_upload(&self, _request: Req<AbortMultipartUpload>) -> HandlerResult<AbortMultipartUpload> {
        self.0.hand("AbortMultipartUpload");
        recorded()
    }

    async fn create_multipart_upload(&self, _request: Req<CreateMultipartUpload>) -> HandlerResult<CreateMultipartUpload> {
        self.0.hand("CreateMultipartUpload");
        recorded()
    }

    async fn get_bucket_acl(&self, _request: Req<GetBucketAcl>) -> HandlerResult<GetBucketAcl> {
        self.0.hand("GetBucketAcl");
        recorded()
    }

    async fn get_bucket_versioning(&self, _request: Req<GetBucketVersioning>) -> HandlerResult<GetBucketVersioning> {
        self.0.hand("GetBucketVersioning");
        recorded()
    }

    async fn list_objects(&self, _request: Req<ListObjects>) -> HandlerResult<ListObjects> {
        self.0.hand("ListObjects");
        recorded()
    }
}

fn assembled(rustfs: bool) -> (S3Service, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid key")));
    let recorder = Arc::new(Recorder(Arc::clone(&seen)));
    let builder = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .authorizer(Allow)
        .register::<PutObject, _>(Arc::clone(&recorder))
        .register::<PutObjectTagging, _>(Arc::clone(&recorder))
        .register::<GetObjectTagging, _>(Arc::clone(&recorder))
        .register::<DeleteObjectTagging, _>(Arc::clone(&recorder))
        .register::<AbortMultipartUpload, _>(Arc::clone(&recorder))
        .register::<CreateMultipartUpload, _>(Arc::clone(&recorder))
        .register::<GetBucketAcl, _>(Arc::clone(&recorder))
        .register::<GetBucketVersioning, _>(Arc::clone(&recorder))
        .register::<ListObjects, _>(recorder);
    let builder = if rustfs {
        builder.select_operations_as_legacy_rustfs().legacy_rustfs_post_forms()
    } else {
        builder
    };
    (builder.build().expect("a complete assembly"), seen)
}

const TAGS: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";

/// `TAGS`' Content-MD5, which the tagging operation requires of its body.
const TAGS_MD5: &str = "EbdZDxVT2OADmYhaGBi6mA==";

/// A signed `PUT` of the tagging document to `target`.
fn put_tags(target: &str) -> http::Request<Bytes> {
    let headers = [("content-md5", TAGS_MD5), ("content-length", "75")];
    signed_target_with_body_and_headers(http::Method::PUT, target, &headers, Bytes::from_static(TAGS))
}

/// The operation a signed request reached, and the answer it got.
async fn reached(service: &S3Service, seen: &Seen, request: http::Request<Bytes>) -> (Vec<&'static str>, http::StatusCode) {
    let (status, _) = exchange(service, request).await;
    (seen.take(), status)
}

/// Positive — an `x-id` named once is the operation, whatever the query's keys name: a tagging
/// document sent with `x-id=PutObjectTagging` reaches the tagging handler, not `PutObject`.
#[tokio::test]
async fn an_x_id_selects_the_operation_it_names() {
    let (service, seen) = assembled(true);
    assert_eq!(
        reached(&service, &seen, put_tags("/bkt/obj?x-id=PutObjectTagging")).await.0,
        ["PutObjectTagging"]
    );
    let acl = signed(http::Method::GET, "/bkt?x-id=GetBucketAcl");
    assert_eq!(reached(&service, &seen, acl).await.0, ["GetBucketAcl"]);
    let versioning = signed(http::Method::GET, "/bkt?acl&x-id=GetBucketVersioning");
    assert_eq!(reached(&service, &seen, versioning).await.0, ["GetBucketVersioning"]);
}

/// Positive — two operation keys: the first in legacy RustFS's order.
#[tokio::test]
async fn two_operation_keys_select_the_first_in_legacy_order() {
    let (service, seen) = assembled(true);
    for (method, target, expected) in [
        (http::Method::GET, "/bkt?acl&versioning", "GetBucketAcl"),
        (http::Method::GET, "/bkt/obj?uploadId=u&tagging", "GetObjectTagging"),
        (http::Method::DELETE, "/bkt/obj?tagging&uploadId=u", "DeleteObjectTagging"),
        (http::Method::POST, "/bkt/obj?uploadId=u&uploads", "CreateMultipartUpload"),
    ] {
        let (reached, _) = reached(&service, &seen, signed(method.clone(), target)).await;
        assert_eq!(reached, [expected], "{method} {target}");
    }
}

/// Negative — an `x-id` legacy RustFS does not accept is `400 InvalidRequest`, before any handler.
#[tokio::test]
async fn n_an_undeclared_x_id_is_refused_before_any_handler() {
    let (service, seen) = assembled(true);
    for target in ["/bkt?x-id=NoSuchOp", "/bkt?x-id=GetObject", "/bkt?x-id=a&x-id=b"] {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(target)
            .header("host", "s3.example.com")
            .body(Bytes::new())
            .expect("a valid request");
        let (status, body) = exchange(&service, request).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{target}: {body}");
        assert!(body.contains("<Code>InvalidRequest</Code>"), "{target}: {body}");
    }
    assert!(seen.take().is_empty());
}

/// Negative — the default assembly routes by its own precedences and ignores `x-id`.
#[tokio::test]
async fn n_the_default_assembly_is_unchanged() {
    let (service, seen) = assembled(false);
    assert_eq!(
        reached(&service, &seen, put_tags("/bkt/obj?x-id=PutObjectTagging")).await.0,
        ["PutObject"]
    );
    let pair = signed(http::Method::GET, "/bkt?acl&versioning");
    assert_eq!(reached(&service, &seen, pair).await.0, ["GetBucketVersioning"]);
    let unknown = signed(http::Method::GET, "/bkt?x-id=NoSuchOp");
    assert_eq!(reached(&service, &seen, unknown).await.0, ["ListObjects"]);
}

const FORM: &[u8] = b"--form\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nobj\r\n--form\r\nContent-Disposition: form-data; name=\"file\"; filename=\"obj\"\r\n\r\nform-object-bytes\r\n--form--\r\n";

fn post_form(target: &str) -> http::Request<Bytes> {
    signed_target_with_body_and_headers(
        http::Method::POST,
        target,
        &[("content-type", "multipart/form-data; boundary=form")],
        Bytes::from_static(FORM),
    )
}

/// The RustFS profile refuses an object-path form before any handler (#1184).
#[tokio::test]
async fn n_an_object_form_without_an_operation_reaches_no_handler() {
    let (service, seen) = assembled(true);
    for target in ["/bkt/obj", "/bkt/obj?unknown=1", "/bkt/obj?versionId=v", "/bkt/obj?acl"] {
        let answer = exchange_wire(&service, post_form(target)).await;
        assert!(seen.take().is_empty(), "{target}: an object form reached a handler");
        let body = String::from_utf8(answer.body().to_vec()).expect("an XML answer");
        assert_eq!(answer.status(), http::StatusCode::METHOD_NOT_ALLOWED, "{target}: {body}");
        assert!(body.contains("<Code>MethodNotAllowed</Code>"), "{target}: {body}");
    }
}

/// The default profile still answers an object-path form with 501.
#[tokio::test]
async fn n_an_object_form_keeps_the_default_profile_answer() {
    let (service, seen) = assembled(false);
    let answer = exchange_wire(&service, post_form("/bkt/obj")).await;
    assert!(seen.take().is_empty(), "the default profile must not dispatch an object form");
    assert_eq!(answer.status(), http::StatusCode::NOT_IMPLEMENTED);
    assert!(String::from_utf8_lossy(answer.body()).contains("<Code>NotImplemented</Code>"));
}

/// A head-only classifier reports the bounded body work needed before this refusal.
#[tokio::test]
async fn n_an_object_form_classification_does_not_promise_a_head_only_refusal() {
    let (service, _) = assembled(true);
    let (head, _) = post_form("/bkt/obj").into_parts();
    assert_eq!(service.classify(&head), Classification::UnroutedPostForm);
}

/// A recognized operation keeps its existing dispatch; the refusal helper is only for no route.
#[tokio::test]
async fn a_form_with_an_uploads_route_reaches_that_handler() {
    let (service, seen) = assembled(true);
    let _ = exchange_wire(&service, post_form("/bkt/obj?uploads")).await;
    assert_eq!(seen.take(), ["CreateMultipartUpload"]);
}

struct FormFrames {
    frames: std::collections::VecDeque<Bytes>,
    read: Arc<std::sync::atomic::AtomicUsize>,
}

impl http_body::Body for FormFrames {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let frame = this.frames.pop_front().map(|bytes| {
            this.read.fetch_add(bytes.len(), std::sync::atomic::Ordering::SeqCst);
            Ok(http_body::Frame::data(bytes))
        });
        std::task::Poll::Ready(frame)
    }
}

/// The actual body observer sees metadata consumed and the separate file frame untouched.
#[tokio::test]
async fn n_an_unrouted_form_reads_only_its_bounded_prelude() {
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (service, seen) = assembled(true);
    let end = FORM.windows(4).rposition(|window| window == b"\r\n\r\n").expect("file head") + 4;
    let read = Arc::new(AtomicUsize::new(0));
    let body = FormFrames {
        frames: [Bytes::from_static(&FORM[..end]), Bytes::from_static(&FORM[end..])].into(),
        read: Arc::clone(&read),
    };
    let (head, _) = post_form("/bkt/obj").into_parts();
    let response = service.call(http::Request::from_parts(head, body)).await;
    let status = response.status();
    let _ = response.into_body().collect().await.expect("response body");
    assert_eq!(read.load(Ordering::SeqCst), end);
    assert_eq!(status, http::StatusCode::METHOD_NOT_ALLOWED);
    assert!(seen.take().is_empty());
}

/// Generic and non-form route errors do not read their bodies.
#[tokio::test]
async fn n_other_unrouted_posts_keep_their_head_only_refusal() {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;
    for (rustfs, content_type) in [
        (false, "multipart/form-data; boundary=form"),
        (true, "application/octet-stream"),
    ] {
        let (service, _) = assembled(rustfs);
        let (body, read) = crate::support::CountingBody::new(Bytes::from_static(FORM));
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("/bkt/obj")
            .header("host", "s3.example.com")
            .header("content-type", content_type)
            .body(body)
            .expect("valid request");
        let response = service.call(request).await;
        let status = response.status();
        let _ = response.into_body().collect().await.expect("response body");
        assert_eq!(read.load(Ordering::SeqCst), 0);
        assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED);
    }
}

type AdmissionSeen = (
    String,
    Option<String>,
    Option<u64>,
    Option<rustfs_gateway::ClientAddr>,
    rustfs_gateway::ClassKind,
);

struct FormGovernor {
    admit: bool,
    work: Arc<Seen>,
    requests: Mutex<Vec<AdmissionSeen>>,
}

struct FormLease(Arc<Seen>);

impl rustfs_gateway::BodyQuota for FormLease {
    fn check(&self, _: rustfs_gateway::VerifiedBodyProgress) -> Result<(), rustfs_gateway::BodyQuotaExceeded> {
        Ok(())
    }
}

impl Drop for FormLease {
    fn drop(&mut self) {
        self.0.hand("release");
    }
}

impl rustfs_gateway::Governor for FormGovernor {
    fn try_acquire<'a>(
        &'a self,
        request: &'a rustfs_gateway::GovernorRequest<'a>,
    ) -> BoxFuture<'a, Result<rustfs_gateway::Lease, ()>> {
        self.requests.lock().expect("request observations").push((
            request.operation().to_owned(),
            request.bucket().map(|bucket| bucket.as_str().to_owned()),
            request.declared_body_bytes(),
            request.client_addr(),
            request.kind(),
        ));
        self.work.hand(if self.admit { "admit" } else { "refuse" });
        Box::pin(async move {
            if self.admit {
                Ok(rustfs_gateway::Lease::admit().with_body_quota(FormLease(Arc::clone(&self.work))))
            } else {
                Err(())
            }
        })
    }
}

struct FormCredentials {
    work: Arc<Seen>,
    credentials: StaticCredentials,
}

impl rustfs_gateway::CredentialProvider for FormCredentials {
    fn lookup<'a>(
        &'a self,
        key: &'a str,
    ) -> BoxFuture<'a, Result<rustfs_gateway::CredentialLookup, rustfs_gateway::ProviderError>> {
        self.work.hand("lookup");
        rustfs_gateway::CredentialProvider::lookup(&self.credentials, key)
    }
}

struct GovernedForm {
    body: crate::support::CountingBody,
    work: Arc<Seen>,
}

impl http_body::Body for GovernedForm {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        this.work.hand("body");
        std::pin::Pin::new(&mut this.body).poll_frame(context)
    }
}

fn governed_form(admit: bool) -> (S3Service, Arc<FormGovernor>, Arc<Seen>) {
    let work = Arc::new(Seen::default());
    let governor = Arc::new(FormGovernor {
        admit,
        work: Arc::clone(&work),
        requests: Mutex::new(Vec::new()),
    });
    let seen = Arc::new(Seen::default());
    let credentials = Arc::new(FormCredentials {
        work,
        credentials: StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid key")),
    });
    let service = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .authorizer(Allow)
        .register::<PutObject, _>(Arc::new(Recorder(Arc::clone(&seen))))
        .select_operations_as_legacy_rustfs()
        .legacy_rustfs_post_forms()
        .governor(Arc::clone(&governor))
        .build()
        .expect("a complete assembly");
    (service, governor, seen)
}

fn forged_form() -> Bytes {
    let fields = [
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", "AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"),
        ("x-amz-date", "20260102T030405Z"),
        (
            "policy",
            "eyJleHBpcmF0aW9uIjogIjIwOTktMDEtMDFUMDA6MDA6MDBaIiwgImNvbmRpdGlvbnMiOiBbeyJ4LWFtei1kYXRlIjogIjIwMjYwMTAyVDAzMDQwNVoifSwgeyJ4LWFtei1jcmVkZW50aWFsIjogIkFLSURFWEFNUExFLzIwMjYwMTAyL3VzLWVhc3QtMS9zMy9hd3M0X3JlcXVlc3QifV19",
        ),
        ("x-amz-signature", "0000000000000000000000000000000000000000000000000000000000000000"),
    ];
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str(&format!("--form\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"));
    }
    body.push_str(std::str::from_utf8(FORM).expect("ASCII form"));
    Bytes::from(body)
}

/// A rejecting governor prevents both new unauthenticated work surfaces.
#[tokio::test]
async fn n_a_refused_unrouted_form_never_reads_or_looks_up_credentials() {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;
    let (service, governor, seen) = governed_form(false);
    let (head, _) = post_form("/bkt/obj").into_parts();
    let (body, read) = crate::support::CountingBody::new(forged_form());
    let response = service
        .call(http::Request::from_parts(
            head,
            GovernedForm {
                body,
                work: Arc::clone(&governor.work),
            },
        ))
        .await;
    let status = response.status();
    let answer = response.into_body().collect().await.expect("response body").to_bytes();
    assert_eq!(read.load(Ordering::SeqCst), 0);
    assert_eq!(governor.work.take(), ["refuse"]);
    assert_eq!(status, http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(String::from_utf8_lossy(&answer).contains("<Code>SlowDown</Code>"));
    assert!(seen.take().is_empty());
}

/// The admitted control observes body and credential work inside the same lease.
#[tokio::test]
async fn a_governed_unrouted_form_retains_its_peer_bucket_and_lease() {
    use http_body_util::BodyExt;
    use std::sync::atomic::Ordering;
    let (service, governor, seen) = governed_form(true);
    let body = forged_form();
    let length = body.len() as u64;
    let (mut head, _) = post_form("/bkt/obj?unknown=1").into_parts();
    head.headers
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(length));
    head.headers
        .insert("x-forwarded-for", http::HeaderValue::from_static("198.51.100.9"));
    let peer = rustfs_gateway::ClientAddr::from_peer("192.0.2.44".parse().expect("a peer address"));
    head.extensions.insert(peer);
    let (body, read) = crate::support::CountingBody::new(body);
    let response = service
        .call(http::Request::from_parts(
            head,
            GovernedForm {
                body,
                work: Arc::clone(&governor.work),
            },
        ))
        .await;
    let status = response.status();
    let _ = response.into_body().collect().await.expect("response body");
    assert_eq!(governor.work.take(), ["admit", "body", "lookup", "release"]);
    assert_eq!(read.load(Ordering::SeqCst), length);
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert_eq!(
        *governor.requests.lock().expect("request observations"),
        [(
            "UnroutedPostForm".to_owned(),
            Some("bkt".to_owned()),
            Some(length),
            Some(peer),
            rustfs_gateway::ClassKind::CredentialLookup
        )]
    );
    assert!(seen.take().is_empty());
}

/// Preparing governor metadata does not insert a new bucket refusal before the form.
#[tokio::test]
async fn n_an_unrouted_form_does_not_gain_an_early_bucket_refusal() {
    use http_body_util::BodyExt;
    let (service, governor, _) = governed_form(true);
    let (head, _) = post_form("/BAD/obj").into_parts();
    let (body, _) = crate::support::CountingBody::new(Bytes::from_static(FORM));
    let response = service
        .call(http::Request::from_parts(
            head,
            GovernedForm {
                body,
                work: Arc::clone(&governor.work),
            },
        ))
        .await;
    let status = response.status();
    let _ = response.into_body().collect().await.expect("response body");
    assert_eq!(governor.work.take(), ["admit", "body", "release"]);
    assert_eq!(status, http::StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(governor.requests.lock().expect("request observations")[0].1, None);
}
