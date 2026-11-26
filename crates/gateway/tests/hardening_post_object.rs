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

//! Security-hardening regressions for rustfs/gateway#1628: `PostObject` SSE contradiction,
//! legacy non-HTTP redirect refusal, Governor `body_quota`, and `RequestTimeout` preservation.
//!
//! Responsible for: proving item 7 protections on `PostObject` under both gateway and legacy
//! RustFS form grammars.
//! NOT responsible for: authentication timing floor, bucket-owner enforcement, `HeadObject`
//! visibility, or verbose-error redaction (`hardening_auth_and_owner.rs`).
//! Upstream: `rustfs-gateway` public API. Downstream: Cargo's integration test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{PostObject, PostObjectOutput};
use rustfs_gateway::{
    BodyQuota, BodyQuotaExceeded, BoxFuture, ETag, Governor, GovernorRequest, Handler, HandlerCancellation, HandlerContext,
    HandlerError, HandlerResult, Lease, Req, Resp, TransportSecurity, VerifiedBodyProgress, allow_when,
};

use crate::support::{self, exchange_wire};

const BOUNDARY: &str = "----RustFSHardening1628Post";
const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const MD5_A: &str = "tP/LI3N87DFaSk0aoqYgzg==";
const KEY_B: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
const MD5_B: &str = "v2HomVYPq94vbXb0BabrcA==";

#[derive(Default)]
struct RecordingPost {
    post_calls: AtomicUsize,
}

impl Handler<PostObject> for RecordingPost {
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

/// Negative — conflicting SSE channels split across HTTP headers and POST form fields must be
/// rejected with `400 InvalidArgument` (`SseRejection::ChannelsContradict`) before the handler runs.
#[tokio::test]
async fn n_post_object_rejects_header_versus_form_sse_contradiction() {
    for legacy in [true, false] {
        let backend = Arc::new(RecordingPost::default());
        let builder = support::wired_at_signed_time()
            .register::<PostObject, _>(Arc::clone(&backend))
            .authorizer(allow_when(|_| true));
        let svc = if legacy { builder.legacy_rustfs_post_forms() } else { builder }
            .build()
            .expect("service");

        // Case A: Managed SSE header + SSE-C form fields over TLS.
        let mut req_a = post_form_request(&[
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", KEY_A),
            ("x-amz-server-side-encryption-customer-key-md5", MD5_A),
        ]);
        req_a
            .headers_mut()
            .insert("x-amz-server-side-encryption", http::HeaderValue::from_static("AES256"));
        req_a.extensions_mut().insert(TransportSecurity::Encrypted);
        let resp_a = exchange_wire(&svc, req_a).await;
        let body_a = String::from_utf8_lossy(resp_a.body());
        assert_eq!(resp_a.status(), StatusCode::BAD_REQUEST, "legacy={legacy} case A: {body_a}");
        assert!(body_a.contains("<Code>InvalidArgument</Code>"), "legacy={legacy} case A: {body_a}");
        assert!(body_a.contains("not both"), "legacy={legacy} case A: {body_a}");
        assert_eq!(backend.post_calls.load(Ordering::SeqCst), 0);

        // Case B: SSE-C headers + Managed SSE form field over TLS.
        let mut req_b = post_form_request(&[("x-amz-server-side-encryption", "AES256")]);
        req_b.headers_mut().insert(
            "x-amz-server-side-encryption-customer-algorithm",
            http::HeaderValue::from_static("AES256"),
        );
        req_b
            .headers_mut()
            .insert("x-amz-server-side-encryption-customer-key", http::HeaderValue::from_static(KEY_A));
        req_b
            .headers_mut()
            .insert("x-amz-server-side-encryption-customer-key-md5", http::HeaderValue::from_static(MD5_A));
        req_b.extensions_mut().insert(TransportSecurity::Encrypted);
        let resp_b = exchange_wire(&svc, req_b).await;
        let body_b = String::from_utf8_lossy(resp_b.body());
        assert_eq!(resp_b.status(), StatusCode::BAD_REQUEST, "legacy={legacy} case B: {body_b}");
        assert!(body_b.contains("<Code>InvalidArgument</Code>"), "legacy={legacy} case B: {body_b}");
        assert!(body_b.contains("not both"), "legacy={legacy} case B: {body_b}");
        assert_eq!(backend.post_calls.load(Ordering::SeqCst), 0);

        // Case C: SSE-C headers + different SSE-C form key over TLS.
        let mut req_c = post_form_request(&[
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", KEY_B),
            ("x-amz-server-side-encryption-customer-key-md5", MD5_B),
        ]);
        req_c.headers_mut().insert(
            "x-amz-server-side-encryption-customer-algorithm",
            http::HeaderValue::from_static("AES256"),
        );
        req_c
            .headers_mut()
            .insert("x-amz-server-side-encryption-customer-key", http::HeaderValue::from_static(KEY_A));
        req_c
            .headers_mut()
            .insert("x-amz-server-side-encryption-customer-key-md5", http::HeaderValue::from_static(MD5_A));
        req_c.extensions_mut().insert(TransportSecurity::Encrypted);
        let resp_c = exchange_wire(&svc, req_c).await;
        let body_c = String::from_utf8_lossy(resp_c.body());
        assert_eq!(resp_c.status(), StatusCode::BAD_REQUEST, "legacy={legacy} case C: {body_c}");
        assert!(body_c.contains("<Code>InvalidArgument</Code>"), "legacy={legacy} case C: {body_c}");
        assert_eq!(backend.post_calls.load(Ordering::SeqCst), 0);
    }
}

/// Negative — `legacy_redirect_action` must reject non-HTTP/HTTPS schemes (`javascript:`, `data:`,
/// `file:`, `ftp:`, `mailto:`) before storage.
#[tokio::test]
async fn n_post_object_legacy_redirect_rejects_non_http_schemes() {
    let backend = Arc::new(RecordingPost::default());
    let svc = support::wired_at_signed_time()
        .register::<PostObject, _>(Arc::clone(&backend))
        .legacy_rustfs_post_forms()
        .authorizer(allow_when(|_| true))
        .build()
        .expect("service");
    for field in ["success_action_redirect", "redirect"] {
        for dangerous in [
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
            "ftp://client.example/done",
            "mailto:upload@client.example",
        ] {
            let resp = exchange_wire(&svc, post_form_request(&[(field, dangerous)])).await;
            let body = String::from_utf8_lossy(resp.body());
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{field}={dangerous}: {body}");
            assert!(body.contains("<Code>MalformedPOSTRequest</Code>"), "{field}={dangerous}: {body}");
            assert_eq!(backend.post_calls.load(Ordering::SeqCst), 0, "{field}={dangerous} reached handler");
        }
    }
}

struct DenyAfterFirstQuota(Arc<AtomicUsize>);

impl BodyQuota for DenyAfterFirstQuota {
    fn check(&self, _progress: VerifiedBodyProgress) -> Result<(), BodyQuotaExceeded> {
        let count = self.0.fetch_add(1, Ordering::SeqCst);
        if count == 0 { Err(BodyQuotaExceeded::new()) } else { Ok(()) }
    }
}

struct PostQuotaGovernor(Arc<AtomicUsize>);

impl Governor for PostQuotaGovernor {
    fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        let checks = Arc::clone(&self.0);
        Box::pin(async move { Ok(Lease::admit().with_body_quota(DenyAfterFirstQuota(checks))) })
    }
}

struct CancellablePostBackend {
    committed: AtomicBool,
    cancelled: Mutex<Option<HandlerCancellation>>,
}

impl Handler<PostObject> for CancellablePostBackend {
    async fn call(&self, _request: Req<PostObject>) -> HandlerResult<PostObject> {
        Err(HandlerError::internal_error("context-aware handler must run"))
    }
    async fn call_with_context(&self, request: Req<PostObject>, context: HandlerContext) -> HandlerResult<PostObject> {
        let mut body = request.into_input().body.into_body();
        loop {
            tokio::select! {
                biased;
                reason = context.cancelled() => {
                    *self.cancelled.lock().expect("lock") = Some(reason);
                    return Err(HandlerError::internal_error("cancelled"));
                }
                frame = body.frame() => match frame {
                    Some(Ok(_)) => {}
                    Some(Err(_)) => {
                        let reason = tokio::time::timeout(Duration::from_secs(1), context.cancelled()).await.ok();
                        *self.cancelled.lock().expect("lock") = reason;
                        return Err(HandlerError::internal_error("stream failed"));
                    }
                    None => {
                        self.committed.store(true, Ordering::SeqCst);
                        return Ok(Resp::new(PostObjectOutput::default()));
                    }
                }
            }
        }
    }
}

/// Negative — `PostObject` streaming must wire the Governor's `body_quota` so quota refusal during
/// file streaming returns `503 SlowDown` and cancels the handler instead of committing.
#[tokio::test]
async fn n_post_object_streaming_enforces_governor_body_quota() {
    let checks = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(CancellablePostBackend {
        committed: AtomicBool::new(false),
        cancelled: Mutex::new(None),
    });
    let svc = support::wired_at_signed_time()
        .register::<PostObject, _>(Arc::clone(&backend))
        .governor(PostQuotaGovernor(Arc::clone(&checks)))
        .authorizer(allow_when(|_| true))
        .build()
        .expect("service");
    let resp = exchange_wire(&svc, post_form_request(&[])).await;
    let body = String::from_utf8_lossy(resp.body());
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("<Code>SlowDown</Code>"), "{body}");
    assert!(checks.load(Ordering::SeqCst) >= 1, "body_quota was never invoked");
    assert!(!backend.committed.load(Ordering::SeqCst), "quota-refused upload must not commit");
    assert_eq!(*backend.cancelled.lock().expect("lock"), Some(HandlerCancellation::BodyQuota));
}

struct StallingPostBody {
    prelude: Option<Bytes>,
}

impl Body for StallingPostBody {
    type Data = Bytes;
    type Error = rustfs_gateway::HostBodyReadTimeout;

    fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if let Some(bytes) = self.prelude.take() {
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        Poll::Ready(Some(Err(rustfs_gateway::HostBodyReadTimeout)))
    }
}

/// Negative — a `HostBodyReadTimeout` while streaming a `PostObject` file must return
/// `408 RequestTimeout` rather than being flattened into `400 IncompleteBody`.
#[tokio::test]
async fn n_post_object_preserves_request_timeout_instead_of_incomplete_body() {
    let backend = Arc::new(RecordingPost::default());
    let svc = support::wired_at_signed_time()
        .register::<PostObject, _>(Arc::clone(&backend))
        .authorizer(allow_when(|_| true))
        .build()
        .expect("service");
    let prelude = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nobj\r\n\
         --{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\npartial"
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://host.invalid/dest-bucket")
        .header("host", "host.invalid")
        .header("content-type", format!("multipart/form-data; boundary={BOUNDARY}"))
        .body(StallingPostBody {
            prelude: Some(Bytes::from(prelude)),
        })
        .expect("request");
    let response = svc.call(request).await;
    let status = response.status();
    let body = response.into_body().collect().await.expect("body").to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("<Code>RequestTimeout</Code>"), "{text}");
    assert!(!text.contains("IncompleteBody"), "{text}");
}
