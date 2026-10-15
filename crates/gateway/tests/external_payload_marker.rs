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

//! Reserved external-data markers cannot reach ordinary empty-body handlers.
//!
//! Responsible for: proving default and feature-enabled service rejection before backend effects.
//! NOT responsible for: external transport execution or signature implementation.
//! Upstream: the real service entry and signed test requests. Downstream: the test harness.

use crate::support;
use http::{Method, StatusCode};
use rustfs_gateway::{Handler, HandlerResult, Req, Resp, S3Service, dto};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Backend(Arc<AtomicUsize>);
impl Handler<dto::PutObject> for Backend {
    async fn call(&self, _request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}
fn service() -> (S3Service, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = support::wired_at_signed_time()
        .register::<dto::PutObject, _>(Arc::new(Backend(calls.clone())))
        .build()
        .expect("valid assembly");
    (service, calls)
}
#[tokio::test]
async fn required_marker_is_rejected_without_backend_effects() {
    let (service, calls) = service();
    let request = support::signed_with(
        Method::PUT,
        "/bucket/object",
        &[("content-length", "0"), ("x-rustfs-rdma-required", "true")],
    );
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("NotImplemented"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn an_orphan_transfer_marker_is_rejected() {
    let (service, calls) = service();
    let request = support::signed_with(
        Method::PUT,
        "/bucket/object",
        &[("content-length", "0"), ("x-rustfs-rdma-transfer", "transfer")],
    );
    let (status, _) = support::exchange(&service, request).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn a_false_required_marker_cannot_select_ordinary_upload() {
    let (service, calls) = service();
    let request = support::signed_with(
        Method::PUT,
        "/bucket/object",
        &[("content-length", "0"), ("x-rustfs-rdma-required", "false")],
    );
    let (status, _) = support::exchange(&service, request).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn ordinary_empty_put_keeps_its_existing_path() {
    let (service, calls) = service();
    let (status, _) =
        support::exchange(&service, support::signed_with(Method::PUT, "/bucket/object", &[("content-length", "0")])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
