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

//! End-to-end gateway runtime tests for S3 Express `CreateSession`, `x-amz-s3session-token`
//! header and presigned authentication, `PutBucketPolicy` `204`, and promoted bucket subresources.
//!
//! Responsible for: proving through an assembled `S3Service` that `CreateSession` enforces
//! `s3express` scope even under legacy RustFS service widening, refuses `x-amz-s3session-token`,
//! host header tokens (ADR-0054), presigned URLs, and anonymous delegation, and returns
//! `CreateSessionResult` XML + SSE headers; that `GetObject` with `x-amz-s3session-token` (header
//! or presigned query) enforces `s3express` scope, verifies session tokens against
//! `Credentials::with_session`, redacts the token in verbose `SignatureDoesNotMatch` responses,
//! and refuses duplicate headers at wire acceptance; and that `PutBucketPolicy` answers `204`
//! while promoted keyed bucket subresources answer `400 InvalidArgument` when `id` is omitted.
//! NOT responsible for: low-level security-floor matrix cases (`crates/sig`).
//! Upstream: `rustfs-gateway`, `support`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::header::{HOST, HeaderMap, HeaderValue};
use http::{Method, Request, StatusCode};
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SecurityFloor, SessionToken, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope,
    X_AMZ_S3SESSION_TOKEN_HEADER,
};
use rustfs_gateway::{
    ClockSkewAck, Credentials, DEFAULT_MAX_BUFFERED_BODY_BYTES, Handler, HandlerResult, HeaderTokenClaim, HeaderTokenRefused,
    HeaderTokenVerifier, Identity, RegionSet, Req, RequestNow, Resp, S3Service, ServiceBuilder, ServiceConfig, SessionBinding,
    SigV4Authenticator, StaticCredentials, Timestamp, allow_when, dto,
};
use rustfs_gateway_http::RawHost;

use crate::support;

const LONG_TERM_KEY: &str = "AKIDEXPRESSLONGTERM";
const STS_KEY: &str = "ASIAEXPRESSSTS00001";
const STS_TOKEN: &str = "FwoGZXIvYXdzSTS_TOKEN_VALUE";
const EXPRESS_KEY: &str = "ASIAEXPRESSSESS0001";
const EXPRESS_TOKEN: &str = "AQoDYXdzS3EXPRESS_SESSION_SENTINEL";
const EXPIRED_EXPRESS_KEY: &str = "ASIAEXPRESSEXP00001";
const EXPIRED_EXPRESS_TOKEN: &str = "AQoDYXdzS3EXPRESS_EXPIRED_TOKEN";
const SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const WRONG_SECRET: &[u8] = b"wrong-secret-key-for-mismatch-test-00000";

#[derive(Default)]
struct ExpressBackend {
    create_session_calls: AtomicUsize,
    get_object_calls: AtomicUsize,
    put_policy_calls: AtomicUsize,
    put_analytics_calls: AtomicUsize,
    delete_analytics_calls: AtomicUsize,
}

impl Handler<dto::CreateSession> for ExpressBackend {
    async fn call(&self, request: Req<dto::CreateSession>) -> HandlerResult<dto::CreateSession> {
        self.create_session_calls.fetch_add(1, Ordering::SeqCst);
        let input = request.input();
        Ok(Resp::new(dto::CreateSessionOutput {
            server_side_encryption: input.server_side_encryption.clone(),
            ssekms_key_id: input.ssekms_key_id.clone(),
            ssekms_encryption_context: input.ssekms_encryption_context.clone(),
            bucket_key_enabled: input.bucket_key_enabled,
            credentials: dto::SessionCredentials {
                access_key_id: EXPRESS_KEY.to_owned(),
                secret_access_key: "minted-secret-key".to_owned(),
                session_token: EXPRESS_TOKEN.to_owned(),
                expiration: Timestamp::from_secs(support::SIGNED_AT_UNIX_SECONDS + 300),
            },
        }))
    }
}

impl Handler<dto::GetObject> for ExpressBackend {
    async fn call(&self, request: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        self.get_object_calls.fetch_add(1, Ordering::SeqCst);
        let principal = request.context().principal().expect("authenticated principal");
        assert_eq!(principal.scheme().service(), SigService::S3Express);
        assert!(principal.scheme().is_temporary());
        Ok(Resp::new(dto::GetObjectOutput::default()))
    }
}

impl Handler<dto::PutBucketPolicy> for ExpressBackend {
    async fn call(&self, _request: Req<dto::PutBucketPolicy>) -> HandlerResult<dto::PutBucketPolicy> {
        self.put_policy_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::PutBucketPolicyOutput::default()))
    }
}

impl Handler<dto::PutBucketAnalyticsConfiguration> for ExpressBackend {
    async fn call(
        &self,
        _request: Req<dto::PutBucketAnalyticsConfiguration>,
    ) -> HandlerResult<dto::PutBucketAnalyticsConfiguration> {
        self.put_analytics_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::PutBucketAnalyticsConfigurationOutput::default()))
    }
}

impl Handler<dto::DeleteBucketAnalyticsConfiguration> for ExpressBackend {
    async fn call(
        &self,
        _request: Req<dto::DeleteBucketAnalyticsConfiguration>,
    ) -> HandlerResult<dto::DeleteBucketAnalyticsConfiguration> {
        self.delete_analytics_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::DeleteBucketAnalyticsConfigurationOutput::default()))
    }
}

#[derive(Clone)]
struct HostEstablished(&'static str);

struct AcceptingHostToken {
    calls: Arc<AtomicUsize>,
}

impl HeaderTokenVerifier for AcceptingHostToken {
    type Established = HostEstablished;

    fn identity(&self, established: &HostEstablished, _now: RequestNow) -> Result<Identity, HeaderTokenRefused> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Identity::new(established.0).map_err(|_| HeaderTokenRefused)
    }
}

fn credentials_store() -> Arc<StaticCredentials> {
    let live_binding =
        SessionBinding::new("s3express.example.com", support::SIGNED_AT_UNIX_SECONDS + 300).expect("valid binding");
    let expired_binding =
        SessionBinding::new("s3express.example.com", support::SIGNED_AT_UNIX_SECONDS - 10).expect("valid binding");
    Arc::new(
        StaticCredentials::new()
            .with(Credentials::new(LONG_TERM_KEY, SECRET).expect("valid long-term"))
            .with(
                Credentials::new(STS_KEY, SECRET)
                    .expect("valid sts")
                    .with_session(STS_TOKEN, live_binding.clone())
                    .expect("valid sts session"),
            )
            .with(
                Credentials::new(EXPRESS_KEY, SECRET)
                    .expect("valid express")
                    .with_s3_express_session(EXPRESS_TOKEN, live_binding)
                    .expect("valid express session"),
            )
            .with(
                Credentials::new(EXPIRED_EXPRESS_KEY, SECRET)
                    .expect("valid expired express")
                    .with_s3_express_session(EXPIRED_EXPRESS_TOKEN, expired_binding)
                    .expect("valid expired session"),
            ),
    )
}

fn assemble(legacy_services: bool, verbose: bool, host_token: bool) -> (S3Service, Arc<ExpressBackend>, Arc<AtomicUsize>) {
    let backend = Arc::new(ExpressBackend::default());
    let host_token_calls = Arc::new(AtomicUsize::new(0));
    let mut auth = SigV4Authenticator::new(credentials_store(), RegionSet::new(["us-east-1"]).expect("non-empty"));
    if legacy_services {
        auth = auth.accept_legacy_rustfs_signing_services();
    }
    let mut floor = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
    if host_token {
        floor = floor.with_header_token_claim(HeaderTokenClaim::new("x-auth-token").expect("valid claim"));
    }
    let mut builder = if verbose {
        ServiceBuilder::new()
            .config(ServiceConfig::new(DEFAULT_MAX_BUFFERED_BODY_BYTES).with_verbose_signature_errors(true))
            .0
    } else {
        ServiceBuilder::new()
    };
    builder = builder
        .authenticator(auth)
        .authorizer(allow_when(|_| true))
        .security_floor(floor)
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::CreateSession, _>(Arc::clone(&backend))
        .register::<dto::GetObject, _>(Arc::clone(&backend))
        .register::<dto::PutBucketPolicy, _>(Arc::clone(&backend))
        .register::<dto::PutBucketAnalyticsConfiguration, _>(Arc::clone(&backend))
        .register::<dto::DeleteBucketAnalyticsConfiguration, _>(Arc::clone(&backend));
    if host_token {
        builder = builder.host_verified_header_token(
            HeaderTokenClaim::new("x-auth-token").expect("valid claim"),
            AcceptingHostToken {
                calls: Arc::clone(&host_token_calls),
            },
        );
    }
    let service = builder.build().expect("express test service builds");
    (service, backend, host_token_calls)
}

async fn exchange(
    service: &S3Service,
    request: Request<Bytes>,
) -> (StatusCode, Vec<(http::header::HeaderName, HeaderValue)>, String) {
    let wire = support::exchange_wire(service, request).await;
    (wire.status(), wire.headers().to_vec(), String::from_utf8_lossy(wire.body()).into_owned())
}

fn sign_header(
    method: Method,
    path: &str,
    query: &str,
    extra_headers: &[(&str, &str)],
    creds: SigningCredentials,
    service: SigService,
    body: Bytes,
) -> Request<Bytes> {
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("valid stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", service).expect("valid scope");
    let mut signer = SigV4Signer::new(creds, scope);
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("s3.example.com"));
    for (name, value) in extra_headers {
        headers.insert(
            http::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    let host = RawHost::from_host_header(b"s3.example.com").expect("valid host");
    let req = SigningRequest::new(&method, path, query, &headers, &host, PayloadMode::Unsigned, stamp);
    let signed = signer.sign_headers(&req).expect("signs header");
    let target = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let mut builder = Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(body).expect("valid request")
}

fn sign_presigned(method: Method, path: &str, query: &str, creds: SigningCredentials, service: SigService) -> Request<Bytes> {
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("valid stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", service).expect("valid scope");
    let mut signer = SigV4Signer::new(creds, scope);
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("s3.example.com"));
    let host = RawHost::from_host_header(b"s3.example.com").expect("valid host");
    let req = SigningRequest::new(&method, path, query, &headers, &host, PayloadMode::Unsigned, stamp);
    let signed = signer.presign(&req, 60).expect("presigns");
    let mut builder = Request::builder().method(method).uri(format!("{path}?{}", signed.query()));
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("valid request")
}

// ── negative ───────────────────────────────────────────────────────────────────────────────────

/// Negative — `CreateSession` enforces `s3express` scope and refuses `s3`, `sts`, and
/// `s3-object-lambda` even when `accept_legacy_rustfs_signing_services()` is turned on.
#[tokio::test]
async fn n_create_session_refuses_non_s3express_scopes_even_under_legacy_services() {
    for legacy in [false, true] {
        let (service, backend, _) = assemble(legacy, false, false);
        for wrong_service in [SigService::S3, SigService::Sts, SigService::S3ObjectLambda] {
            let creds = SigningCredentials::new(LONG_TERM_KEY, SECRET).expect("creds");
            let req = sign_header(Method::GET, "/dir-bucket", "session", &[], creds, wrong_service, Bytes::new());
            let (status, _, body) = exchange(&service, req).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "legacy={legacy} {wrong_service:?}: {body}");
            assert!(
                body.contains("<Code>AuthorizationHeaderMalformed</Code>"),
                "legacy={legacy} {wrong_service:?}: {body}"
            );
        }
        assert_eq!(backend.create_session_calls.load(Ordering::SeqCst), 0);
    }
}

/// Negative — `CreateSession` refuses `x-amz-s3session-token` with `403 AccessDenied`
/// (`DisableS3ExpressSessionAuth`), never reaching the handler.
#[tokio::test]
async fn n_create_session_refuses_s3session_token_header() {
    let (service, backend, _) = assemble(false, false, false);
    let creds = SigningCredentials::new(EXPRESS_KEY, SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new(EXPRESS_TOKEN).expect("token"));
    let req = sign_header(Method::GET, "/dir-bucket", "session", &[], creds, SigService::S3Express, Bytes::new());
    let (status, _, body) = exchange(&service, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(backend.create_session_calls.load(Ordering::SeqCst), 0);
}

/// Negative — STS vs S3 Express session-surface isolation: presenting an S3 Express session token
/// in `x-amz-security-token` cannot bypass `CreateSession`'s `DisableS3ExpressSessionAuth` or
/// authenticate ordinary `s3` requests, presenting an STS token in `x-amz-s3session-token` cannot
/// authenticate `s3express` requests (header or presigned query), and an expired cross-surface
/// presentation answers uniform `InvalidAccessKeyId` rather than `ExpiredToken`.
#[tokio::test]
async fn n_sts_and_s3_express_tokens_cannot_cross_authenticate_surfaces() {
    let (service, backend, _) = assemble(false, false, false);
    let cases = [
        // 1. S3 Express token in x-amz-security-token against CreateSession (s3express).
        (EXPRESS_KEY, EXPRESS_TOKEN, false, false, "/dir-bucket", "session", SigService::S3Express),
        // 2. S3 Express token in x-amz-security-token (header & presigned) against GetObject (s3).
        (EXPRESS_KEY, EXPRESS_TOKEN, false, false, "/dir-bucket/obj", "", SigService::S3),
        (EXPRESS_KEY, EXPRESS_TOKEN, false, true, "/dir-bucket/obj", "", SigService::S3),
        // 3. STS token in x-amz-s3session-token (header & presigned) against GetObject (s3express).
        (STS_KEY, STS_TOKEN, true, false, "/dir-bucket/obj", "", SigService::S3Express),
        (STS_KEY, STS_TOKEN, true, true, "/dir-bucket/obj", "", SigService::S3Express),
        // 4. Expired S3 Express token on x-amz-security-token -> uniform InvalidAccessKeyId, never ExpiredToken.
        (
            EXPIRED_EXPRESS_KEY,
            EXPIRED_EXPRESS_TOKEN,
            false,
            false,
            "/dir-bucket/obj",
            "",
            SigService::S3,
        ),
    ];
    for (key, token, as_express, presigned, path, query, scope_service) in cases {
        let base = SigningCredentials::new(key, SECRET).expect("creds");
        let tok = SessionToken::new(token).expect("token");
        let creds = if as_express {
            base.with_s3_express_session_token(tok)
        } else {
            base.with_session_token(tok)
        };
        let req = if presigned {
            sign_presigned(Method::GET, path, query, creds, scope_service)
        } else {
            sign_header(Method::GET, path, query, &[], creds, scope_service, Bytes::new())
        };
        let (status, _, body) = exchange(&service, req).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{key} {path}?{query}: {body}");
        assert!(body.contains("<Code>InvalidAccessKeyId</Code>"), "{key} {path}?{query}: {body}");
    }
    assert_eq!(backend.create_session_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.get_object_calls.load(Ordering::SeqCst), 0);
}

/// Negative — `CreateSession` refuses host header-token auth (ADR-0054) even when the claim,
/// established identity, and an accepting verifier are installed on the service.
#[tokio::test]
async fn n_create_session_refuses_host_header_token_per_adr_0054() {
    let (service, backend, verifier_calls) = assemble(false, false, true);
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/dir-bucket?session")
        .header(HOST, "s3.example.com")
        .header("x-auth-token", "keystone-token-value")
        .body(Bytes::new())
        .expect("valid request");
    req.extensions_mut().insert(HostEstablished("HOSTTOKENUSER"));
    let (status, _, body) = exchange(&service, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(verifier_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.create_session_calls.load(Ordering::SeqCst), 0);
}

/// Negative — `CreateSession` refuses presigned URLs and anonymous requests even under anonymous
/// delegation.
#[tokio::test]
async fn n_create_session_refuses_presigned_and_anonymous_requests() {
    let (service, backend, _) = assemble(false, false, false);

    let creds = SigningCredentials::new(LONG_TERM_KEY, SECRET).expect("creds");
    let presigned = sign_presigned(Method::GET, "/dir-bucket", "session", creds, SigService::S3Express);
    let (status, _, body) = exchange(&service, presigned).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");

    let anon = Request::builder()
        .method(Method::GET)
        .uri("/dir-bucket?session")
        .header(HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("valid request");
    let (status, _, body) = exchange(&service, anon).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(backend.create_session_calls.load(Ordering::SeqCst), 0);
}

/// Negative — `GetObject` carrying `x-amz-s3session-token` (header or presigned) refuses `s3`
/// scope even under legacy RustFS service widening.
#[tokio::test]
async fn n_s3session_token_refuses_s3_scope_even_under_legacy_services() {
    for legacy in [false, true] {
        let (service, backend, _) = assemble(legacy, false, false);
        let creds_hdr = SigningCredentials::new(EXPRESS_KEY, SECRET)
            .expect("creds")
            .with_s3_express_session_token(SessionToken::new(EXPRESS_TOKEN).expect("token"));
        let req_hdr = sign_header(Method::GET, "/dir-bucket/obj", "", &[], creds_hdr, SigService::S3, Bytes::new());
        let (status, _, body) = exchange(&service, req_hdr).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "hdr legacy={legacy}: {body}");
        assert!(body.contains("<Code>AuthorizationHeaderMalformed</Code>"), "{body}");

        let creds_q = SigningCredentials::new(EXPRESS_KEY, SECRET)
            .expect("creds")
            .with_s3_express_session_token(SessionToken::new(EXPRESS_TOKEN).expect("token"));
        let req_q = sign_presigned(Method::GET, "/dir-bucket/obj", "", creds_q, SigService::S3);
        let (status, _, body) = exchange(&service, req_q).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "query legacy={legacy}: {body}");
        assert!(body.contains("<Code>AuthorizationHeaderMalformed</Code>"), "{body}");
        assert_eq!(backend.get_object_calls.load(Ordering::SeqCst), 0);
    }
}

/// Negative — wrong token or expired S3 Express session token (header or presigned) is refused.
#[tokio::test]
async fn n_wrong_or_expired_s3session_token_is_refused() {
    let (service, backend, _) = assemble(false, false, false);

    // Wrong token for EXPRESS_KEY -> uniform InvalidAccessKeyId.
    let swapped = SigningCredentials::new(EXPRESS_KEY, SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new("wrong-express-token").expect("token"));
    let (status, _, body) = exchange(
        &service,
        sign_header(Method::GET, "/dir-bucket/obj", "", &[], swapped, SigService::S3Express, Bytes::new()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>InvalidAccessKeyId</Code>"), "{body}");

    // Expired S3 Express session with its issued token -> ExpiredToken.
    let expired_hdr = SigningCredentials::new(EXPIRED_EXPRESS_KEY, SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new(EXPIRED_EXPRESS_TOKEN).expect("token"));
    let (status, _, body) = exchange(
        &service,
        sign_header(Method::GET, "/dir-bucket/obj", "", &[], expired_hdr, SigService::S3Express, Bytes::new()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>ExpiredToken</Code>"), "{body}");

    let expired_q = SigningCredentials::new(EXPIRED_EXPRESS_KEY, SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new(EXPIRED_EXPRESS_TOKEN).expect("token"));
    let (status, _, body) = exchange(
        &service,
        sign_presigned(Method::GET, "/dir-bucket/obj", "", expired_q, SigService::S3Express),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>ExpiredToken</Code>"), "{body}");
    assert_eq!(backend.get_object_calls.load(Ordering::SeqCst), 0);
}

/// Negative — an unsigned `x-amz-s3session-token` header is refused `403 SignatureDoesNotMatch`.
#[tokio::test]
async fn n_unsigned_s3session_token_header_is_refused_end_to_end() {
    let (service, backend, _) = assemble(false, false, false);
    let creds = SigningCredentials::new(EXPRESS_KEY, SECRET).expect("creds");
    let mut req = sign_header(Method::GET, "/dir-bucket/obj", "", &[], creds, SigService::S3Express, Bytes::new());
    req.headers_mut()
        .insert(X_AMZ_S3SESSION_TOKEN_HEADER, HeaderValue::from_static(EXPRESS_TOKEN));
    let (status, _, body) = exchange(&service, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    assert_eq!(backend.get_object_calls.load(Ordering::SeqCst), 0);
}

/// Negative — verbose `SignatureDoesNotMatch` redacts `x-amz-s3session-token` in both header and
/// presigned-query canonical requests, never reflecting the live session token.
#[tokio::test]
async fn n_verbose_signature_mismatch_redacts_s3session_token_in_header_and_query() {
    let (service, _, _) = assemble(false, true, false);

    let bad_hdr = SigningCredentials::new(EXPRESS_KEY, WRONG_SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new(EXPRESS_TOKEN).expect("token"));
    let (status, _, body_hdr) = exchange(
        &service,
        sign_header(Method::GET, "/dir-bucket/obj", "", &[], bad_hdr, SigService::S3Express, Bytes::new()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body_hdr}");
    assert!(body_hdr.contains("<Code>SignatureDoesNotMatch</Code>"), "{body_hdr}");
    assert!(body_hdr.contains("x-amz-s3session-token:__REDACTED__"), "{body_hdr}");
    assert!(!body_hdr.contains(EXPRESS_TOKEN), "live session token leaked: {body_hdr}");

    let bad_q = SigningCredentials::new(EXPRESS_KEY, WRONG_SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new(EXPRESS_TOKEN).expect("token"));
    let (status, _, body_q) =
        exchange(&service, sign_presigned(Method::GET, "/dir-bucket/obj", "", bad_q, SigService::S3Express)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body_q}");
    assert!(body_q.contains("<Code>SignatureDoesNotMatch</Code>"), "{body_q}");
    assert!(body_q.contains("X-Amz-S3session-Token=__REDACTED__"), "{body_q}");
    assert!(!body_q.contains(EXPRESS_TOKEN), "live presigned session token leaked: {body_q}");
}

/// Negative — duplicate `x-amz-s3session-token` headers or `X-Amz-S3session-Token` query
/// parameters are refused at wire acceptance.
#[tokio::test]
async fn n_duplicate_s3session_token_header_is_refused_at_wire_acceptance() {
    let (service, backend, _) = assemble(false, false, false);
    let creds = SigningCredentials::new(EXPRESS_KEY, SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new(EXPRESS_TOKEN).expect("token"));
    let mut req = sign_header(Method::GET, "/dir-bucket/obj", "", &[], creds, SigService::S3Express, Bytes::new());
    req.headers_mut()
        .append(X_AMZ_S3SESSION_TOKEN_HEADER, HeaderValue::from_static("second-token"));
    let (status, _, body) = exchange(&service, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let creds_q = SigningCredentials::new(EXPRESS_KEY, SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new(EXPRESS_TOKEN).expect("token"));
    let mut req_q = sign_presigned(Method::GET, "/dir-bucket/obj", "", creds_q, SigService::S3Express);
    let dup_uri = format!("{}&X-Amz-S3session-Token=second-token", req_q.uri());
    *req_q.uri_mut() = dup_uri.parse().expect("valid dup uri");
    let (status, _, body) = exchange(&service, req_q).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(backend.get_object_calls.load(Ordering::SeqCst), 0);
}

/// Negative — keyed bucket config PUT/DELETE without `id` answers `400 InvalidArgument` end-to-end.
#[tokio::test]
async fn n_keyed_bucket_ops_without_id_answer_400_end_to_end() {
    let (service, backend, _) = assemble(false, false, false);
    for (method, target_query) in [(Method::PUT, "analytics"), (Method::DELETE, "analytics")] {
        let creds = SigningCredentials::new(LONG_TERM_KEY, SECRET).expect("creds");
        let req = sign_header(method, "/bucket", target_query, &[], creds, SigService::S3, Bytes::new());
        let (status, _, body) = exchange(&service, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("<Code>InvalidArgument</Code>"), "{body}");
    }
    assert_eq!(backend.put_analytics_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.delete_analytics_calls.load(Ordering::SeqCst), 0);
}

// ── positive ───────────────────────────────────────────────────────────────────────────────────

/// Positive — `CreateSession` succeeds with both long-term IAM and STS `x-amz-security-token`
/// credentials under `s3express`, returning `CreateSessionResult` XML and SSE headers.
#[tokio::test]
async fn create_session_succeeds_with_long_term_and_sts_credentials_under_s3express() {
    let (service, backend, _) = assemble(true, false, false);
    let sse_headers = [
        ("x-amz-create-session-mode", "ReadWrite"),
        ("x-amz-server-side-encryption", "aws:kms"),
        ("x-amz-server-side-encryption-bucket-key-enabled", "true"),
    ];

    for creds in [
        SigningCredentials::new(LONG_TERM_KEY, SECRET).expect("long-term"),
        SigningCredentials::new(STS_KEY, SECRET)
            .expect("sts")
            .with_session_token(SessionToken::new(STS_TOKEN).expect("sts token")),
    ] {
        let req = sign_header(
            Method::GET,
            "/dir-bucket",
            "session",
            &sse_headers,
            creds,
            SigService::S3Express,
            Bytes::new(),
        );
        let (status, headers, body) = exchange(&service, req).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "x-amz-server-side-encryption" && v == "aws:kms"),
            "{headers:?}"
        );
        assert!(body.contains("<CreateSessionResult"), "{body}");
        assert!(body.contains("<AccessKeyId>ASIAEXPRESSSESS0001</AccessKeyId>"), "{body}");
        assert!(body.contains("<SessionToken>"), "{body}");
    }
    assert_eq!(backend.create_session_calls.load(Ordering::SeqCst), 2);
}

/// Positive — `GetObject` with `x-amz-s3session-token` (header and presigned query) under
/// `s3express` authenticates as a temporary `SigService::S3Express` session and reaches the handler.
#[tokio::test]
async fn get_object_with_s3session_token_header_and_presigned_query_succeeds() {
    let (service, backend, _) = assemble(true, false, false);

    let creds_hdr = SigningCredentials::new(EXPRESS_KEY, SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new(EXPRESS_TOKEN).expect("token"));
    let (status, _, body) = exchange(
        &service,
        sign_header(Method::GET, "/dir-bucket/obj", "", &[], creds_hdr, SigService::S3Express, Bytes::new()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let creds_q = SigningCredentials::new(EXPRESS_KEY, SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new(EXPRESS_TOKEN).expect("token"));
    let (status, _, body) = exchange(
        &service,
        sign_presigned(Method::GET, "/dir-bucket/obj", "", creds_q, SigService::S3Express),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(backend.get_object_calls.load(Ordering::SeqCst), 2);
}

/// Positive — `PutBucketPolicy` answers `204 No Content` with an empty body end-to-end.
#[tokio::test]
async fn put_bucket_policy_answers_204_no_content_end_to_end() {
    let (service, backend, _) = assemble(false, false, false);
    let policy = Bytes::from_static(br#"{"Version":"2012-10-17","Statement":[]}"#);
    let creds = SigningCredentials::new(LONG_TERM_KEY, SECRET).expect("creds");
    let req = sign_header(
        Method::PUT,
        "/bucket",
        "policy",
        &[
            ("content-type", "application/json"),
            ("content-md5", "7ysbf9u2zR7hHgNqh4BIYg=="),
        ],
        creds,
        SigService::S3,
        policy,
    );
    let (status, _, body) = exchange(&service, req).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(body.is_empty(), "204 must carry no body: {body}");
    assert_eq!(backend.put_policy_calls.load(Ordering::SeqCst), 1);
}

/// Positive — promoted `PutBucketAnalyticsConfiguration` (`200`) and
/// `DeleteBucketAnalyticsConfiguration` (`204`) round-trip end-to-end when `id` is present.
#[tokio::test]
async fn promoted_analytics_put_and_delete_succeed_end_to_end() {
    let (service, backend, _) = assemble(false, false, false);
    let xml = Bytes::from_static(
        br#"<AnalyticsConfiguration><Id>report</Id><Filter><Prefix>logs/</Prefix></Filter><StorageClassAnalysis/></AnalyticsConfiguration>"#,
    );
    let creds_put = SigningCredentials::new(LONG_TERM_KEY, SECRET).expect("creds");
    let req_put = sign_header(
        Method::PUT,
        "/bucket",
        "analytics&id=report",
        &[("content-type", "application/xml")],
        creds_put,
        SigService::S3,
        xml,
    );
    let (status, _, body) = exchange(&service, req_put).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let creds_del = SigningCredentials::new(LONG_TERM_KEY, SECRET).expect("creds");
    let req_del = sign_header(
        Method::DELETE,
        "/bucket",
        "analytics&id=report",
        &[],
        creds_del,
        SigService::S3,
        Bytes::new(),
    );
    let (status, _, body) = exchange(&service, req_del).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(body.is_empty(), "{body}");
    assert_eq!(backend.put_analytics_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.delete_analytics_calls.load(Ordering::SeqCst), 1);
}

/// Positive + Negative — under `ServiceBuilder::rustfs_profile()`, `CreateSession` and
/// `x-amz-s3session-token` requests succeed on directory bucket names (`--x-s3`), while an
/// ordinary `GetObject` without a session token signed with `s3express` still answers legacy `501`.
#[tokio::test]
async fn s3_express_under_rustfs_profile_serves_express_and_keeps_legacy_501_on_ordinary_s3() {
    let backend = Arc::new(ExpressBackend::default());
    let service = ServiceBuilder::new()
        .rustfs_profile()
        .authenticator(
            SigV4Authenticator::new(credentials_store(), RegionSet::new(["us-east-1"]).expect("region")).rustfs_profile(),
        )
        .authorizer(allow_when(|_| true))
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::CreateSession, _>(Arc::clone(&backend))
        .register::<dto::GetObject, _>(Arc::clone(&backend))
        .build()
        .expect("rustfs_profile express service builds");

    let create_req = sign_header(
        Method::GET,
        "/dir-bucket--use1-az4--x-s3",
        "session",
        &[],
        SigningCredentials::new(LONG_TERM_KEY, SECRET).expect("creds"),
        SigService::S3Express,
        Bytes::new(),
    );
    let (status, _, body) = exchange(&service, create_req).await;
    assert_eq!(status, StatusCode::OK, "CreateSession under rustfs_profile: {body}");
    assert!(body.contains("<CreateSessionResult"), "{body}");

    let express_creds = SigningCredentials::new(EXPRESS_KEY, SECRET)
        .expect("creds")
        .with_s3_express_session_token(SessionToken::new(EXPRESS_TOKEN).expect("token"));
    let get_express = sign_header(
        Method::GET,
        "/dir-bucket--use1-az4--x-s3/obj",
        "",
        &[],
        express_creds,
        SigService::S3Express,
        Bytes::new(),
    );
    let (status, _, body) = exchange(&service, get_express).await;
    assert_eq!(status, StatusCode::OK, "GetObject with s3session token under rustfs_profile: {body}");

    // Negative control: ordinary S3 GetObject without x-amz-s3session-token under s3express still gets legacy 501.
    let get_wrong_scope = sign_header(
        Method::GET,
        "/dir-bucket--use1-az4--x-s3/obj",
        "",
        &[],
        SigningCredentials::new(LONG_TERM_KEY, SECRET).expect("creds"),
        SigService::S3Express,
        Bytes::new(),
    );
    let (status, _, body) = exchange(&service, get_wrong_scope).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");
    assert!(
        body.contains("unknown service &apos;s3express&apos; in credential scope; expected one of: s3, sts, s3tables"),
        "{body}"
    );
    assert_eq!(backend.create_session_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.get_object_calls.load(Ordering::SeqCst), 1);
}
