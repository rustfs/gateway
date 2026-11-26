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

//! Single-use presigned-URL replay protection (`ReplayNonceStore`, H7) wired into `ServiceBuilder`
//! and `SigV4Authenticator`.
//!
//! Responsible for: proving that installing a `ReplayNonceStore` admits the first valid use of a
//! presigned URL, rejects the second use with `403 AccessDenied` obeying `FailureFloor`, does not
//! let forged/unauthenticated presigned requests burn a valid nonce, leaves header-signed requests
//! reusable, and fails closed on `ReplayDecision::Unavailable` or store panics.
//! NOT responsible for: replay-store persistence or distributed eviction policy.
//! Upstream: `rustfs_gateway::ServiceBuilder::replay_nonce_store`,
//! `rustfs_gateway::SigV4Authenticator::with_replay_nonce_store`.
//! Downstream: Cargo integration test harness.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, RegionSet, ReplayDecision, ReplayFingerprint, ReplayNonceStore, SigService, SigV4Signer,
    SigningCredentials, SigningRequest, SigningScope,
};
use rustfs_gateway::{
    ClockSkewAck, Credentials, Handler, HandlerResult, Req, Resp, S3Service, ServiceBuilder, SigV4Authenticator,
    StaticCredentials, dto,
};

use crate::support::{SIGNED_AT_STAMP, fixed_clock};

struct OkGetObject;

impl Handler<dto::GetObject> for OkGetObject {
    async fn call(&self, _request: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        Ok(Resp::new(dto::GetObjectOutput::default()))
    }
}

#[derive(Default)]
struct InMemoryReplayStore {
    seen: Mutex<HashSet<ReplayFingerprint>>,
    calls: AtomicUsize,
}

impl ReplayNonceStore for InMemoryReplayStore {
    fn record_first_use(&self, fingerprint: ReplayFingerprint) -> ReplayDecision {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut seen = self.seen.lock().expect("replay store lock");
        if seen.insert(fingerprint) {
            ReplayDecision::FirstUse
        } else {
            ReplayDecision::Replayed
        }
    }
}

struct UnavailableReplayStore;

impl ReplayNonceStore for UnavailableReplayStore {
    fn record_first_use(&self, _fingerprint: ReplayFingerprint) -> ReplayDecision {
        ReplayDecision::Unavailable
    }
}

struct PanickingReplayStore;

impl ReplayNonceStore for PanickingReplayStore {
    fn record_first_use(&self, _fingerprint: ReplayFingerprint) -> ReplayDecision {
        panic!("simulated replay store panic");
    }
}

fn presigned_get_request(path: &str) -> Request<Bytes> {
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("valid stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("valid scope");
    let mut signer = SigV4Signer::new(credentials, scope);

    let probe = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header(header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("probe");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("accepted");

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("s3.example.com"));
    let signing = SigningRequest::new(
        &Method::GET,
        path,
        "",
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    );
    let signed = signer.presign(&signing, 300).expect("presigned GET");
    let mut builder = Request::builder().method(Method::GET).uri(signed.target());
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("valid presigned GET request")
}

fn header_signed_get_request(path: &str) -> Request<Bytes> {
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("valid stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("valid scope");
    let mut signer = SigV4Signer::new(credentials, scope);

    let probe = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header(header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("probe");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("accepted");

    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("s3.example.com"));
    let signing = SigningRequest::new(
        &Method::GET,
        path,
        "",
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    );
    let signed = signer.sign_headers(&signing).expect("header-signed GET");
    let mut builder = Request::builder().method(Method::GET).uri(signed.target());
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("valid header-signed GET request")
}

fn service_with_builder_store(store: Arc<dyn ReplayNonceStore + Send + Sync>) -> S3Service {
    crate::support::wired_at_signed_time()
        .register::<dto::GetObject, _>(Arc::new(OkGetObject))
        .replay_nonce_store(store)
        .build()
        .expect("service with builder replay store")
}

fn service_with_authenticator_store(store: Arc<dyn ReplayNonceStore + Send + Sync>) -> S3Service {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    let authenticator = Arc::new(
        SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("region")).with_replay_nonce_store(store),
    );
    ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(rustfs_gateway::allow_when(|_| true))
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .register::<dto::GetObject, _>(Arc::new(OkGetObject))
        .build()
        .expect("service with authenticator replay store")
}

/// Positive & negative — `ServiceBuilder::replay_nonce_store` allows the first use of a presigned
/// URL, rejects the second use with `403` obeying `FailureFloor`, does not burn nonces on forged
/// presigned requests, and leaves header-signed requests unaffected.
#[tokio::test]
async fn service_builder_replay_nonce_store_rejects_second_presigned_use() {
    let store = Arc::new(InMemoryReplayStore::default());
    let service = service_with_builder_store(Arc::clone(&store) as Arc<dyn ReplayNonceStore + Send + Sync>);

    let valid = presigned_get_request("/bucket/single-use");

    // Negative: a forged presigned request (same URI with tampered signature) must NOT record into the store.
    let mut forged_uri = valid.uri().to_string();
    let last = forged_uri.pop().expect("non-empty URI");
    forged_uri.push(if last == '0' { '1' } else { '0' });
    let forged = Request::builder()
        .method(Method::GET)
        .uri(forged_uri)
        .header(header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("forged request");
    let forged_resp = service.call_bytes(forged).await;
    assert_eq!(forged_resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        store.calls.load(Ordering::SeqCst),
        0,
        "forged presigned request must not invoke ReplayNonceStore before signature verification"
    );

    // Positive: first valid use succeeds.
    let first = service.call_bytes(valid.clone()).await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);

    // Negative: second use of the exact same presigned URL is rejected and obeys FailureFloor.
    let started = Instant::now();
    let second = service.call_bytes(valid).await;
    assert_eq!(second.status(), StatusCode::FORBIDDEN);
    assert!(
        started.elapsed() >= Duration::from_millis(25),
        "replayed presigned rejection must obey FailureFloor"
    );
    assert_eq!(store.calls.load(Ordering::SeqCst), 2);

    // Positive control: header-signed requests are not presigned and remain unaffected.
    let header_req = header_signed_get_request("/bucket/header-signed");
    assert_eq!(service.call_bytes(header_req.clone()).await.status(), StatusCode::OK);
    assert_eq!(service.call_bytes(header_req).await.status(), StatusCode::OK);
    assert_eq!(store.calls.load(Ordering::SeqCst), 2);
}

/// Positive & negative — `SigV4Authenticator::with_replay_nonce_store` rejects the second use of
/// a presigned URL while admitting the first.
#[tokio::test]
async fn sigv4_authenticator_replay_nonce_store_rejects_second_presigned_use() {
    let store = Arc::new(InMemoryReplayStore::default());
    let service = service_with_authenticator_store(Arc::clone(&store) as Arc<dyn ReplayNonceStore + Send + Sync>);

    let valid = presigned_get_request("/bucket/auth-single-use");
    assert_eq!(service.call_bytes(valid.clone()).await.status(), StatusCode::OK);
    assert_eq!(service.call_bytes(valid).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(store.calls.load(Ordering::SeqCst), 2);
}

/// Negative — both `ReplayDecision::Unavailable` and a panicking `ReplayNonceStore` fail closed
/// with `403` on both wiring seams.
#[tokio::test]
async fn n_unavailable_and_panicking_replay_stores_fail_closed() {
    for service in [
        service_with_builder_store(Arc::new(UnavailableReplayStore)),
        service_with_builder_store(Arc::new(PanickingReplayStore)),
        service_with_authenticator_store(Arc::new(UnavailableReplayStore)),
        service_with_authenticator_store(Arc::new(PanickingReplayStore)),
    ] {
        let req = presigned_get_request("/bucket/fail-closed");
        let resp = service.call_bytes(req).await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "unavailable or panicking replay store must fail closed with 403"
        );
    }
}
