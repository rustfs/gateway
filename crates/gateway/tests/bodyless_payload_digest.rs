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

//! The signed digest of a request without a body, through the whole service (rustfs/gateway#1099).
//!
//! Responsible for: proving that `ServiceBuilder::accept_mismatched_payload_digests_without_a_body`
//! serves a header-signed `GetObject` that declares another payload's digest — which the default
//! assembly answers `400 XAmzContentSHA256Mismatch` before any handler — and that an upload
//! declaring another payload's digest is still refused under it and hands no bytes over.
//! NOT responsible for: which body modes the switch reaches (`src/builder/bodyless_digest.rs`'s
//! unit tests) or the launcher that turns it on (`compat/sut`).
//! Upstream: `S3Service` with recording `GetObject` and `PutObject` backends. Downstream: none.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp, S3Service, dto};
use sha2::{Digest as _, Sha256};

use crate::support;

#[derive(Default)]
struct Recorded {
    reads: AtomicUsize,
    uploads: Mutex<Vec<Vec<u8>>>,
}

struct Backend(Arc<Recorded>);

impl Handler<dto::GetObject> for Backend {
    fn call(&self, _request: Req<dto::GetObject>) -> impl core::future::Future<Output = HandlerResult<dto::GetObject>> + Send {
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        async { Ok(Resp::new(dto::GetObjectOutput::default())) }
    }
}

impl Handler<dto::PutObject> for Backend {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let recorded = Arc::clone(&self.0);
        let body = request.into_input().body;
        async move {
            let mut body = body
                .ok_or_else(|| HandlerError::internal_error("PutObject reached its handler without a body stream"))?
                .into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
                if let Ok(data) = frame.into_data() {
                    bytes.extend_from_slice(&data);
                }
            }
            recorded.uploads.lock().expect("the record is never poisoned").push(bytes);
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

fn assembled(legacy: bool) -> (S3Service, Arc<Recorded>) {
    let recorded = Arc::new(Recorded::default());
    let backend = Arc::new(Backend(Arc::clone(&recorded)));
    let mut builder = support::wired_at_signed_time();
    if legacy {
        builder = builder.accept_mismatched_payload_digests_without_a_body();
    }
    let service = builder
        .register::<dto::GetObject, _>(Arc::clone(&backend))
        .register::<dto::PutObject, _>(backend)
        .build()
        .expect("a complete assembly");
    (service, recorded)
}

/// A header-signed request carrying `body` and declaring, and signing, the digest of `declared`.
fn signed(method: http::Method, body: &'static [u8], declared: &[u8]) -> http::Request<Bytes> {
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    if !body.is_empty() {
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len()));
    }
    let payload = PayloadMode::ExactSha256(Sha256::digest(declared).into());
    let signing = SigningRequest::new(&method, "/bucket/object", "", &headers, &host, payload, stamp)
        .with_wire_content_length(body.len() as u64);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(method).uri("/bucket/object");
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(Bytes::from_static(body)).expect("a valid request")
}

/// Positive — under the switch a read declaring another payload's digest reaches its handler.
#[tokio::test]
async fn a_bodyless_read_declaring_another_digest_is_served_under_the_switch() {
    let (service, recorded) = assembled(true);
    let (status, body) = support::exchange(&service, signed(http::Method::GET, b"", b"another payload")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 1);
}

/// Negative — the default assembly answers the same read `400 XAmzContentSHA256Mismatch` and
/// reaches no handler.
#[tokio::test]
async fn n_the_default_refuses_a_bodyless_read_declaring_another_digest() {
    let (service, recorded) = assembled(false);
    let (status, body) = support::exchange(&service, signed(http::Method::GET, b"", b"another payload")).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>XAmzContentSHA256Mismatch</Code>"), "{body}");
    assert_eq!(recorded.reads.load(Ordering::SeqCst), 0);
}

/// Negative — under the switch an upload declaring another payload's digest is still refused, and
/// no bytes are handed over as a complete upload.
#[tokio::test]
async fn n_an_upload_declaring_another_digest_is_still_refused_under_the_switch() {
    let (service, recorded) = assembled(true);
    let (status, body) = support::exchange(&service, signed(http::Method::PUT, b"hello", b"another payload")).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("<Code>XAmzContentSHA256Mismatch</Code>"), "{body}");
    assert!(recorded.uploads.lock().expect("the record is never poisoned").is_empty());
}

/// Negative — under the switch a read declaring the empty body's own digest is served as before.
#[tokio::test]
async fn n_a_bodyless_read_declaring_the_empty_digest_is_served_either_way() {
    for legacy in [false, true] {
        let (service, recorded) = assembled(legacy);
        let (status, body) = support::exchange(&service, signed(http::Method::GET, b"", b"")).await;
        assert_eq!(status, http::StatusCode::OK, "{legacy}: {body}");
        assert_eq!(recorded.reads.load(Ordering::SeqCst), 1, "{legacy}");
    }
}
