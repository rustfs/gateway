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

//! The heads the assembly writes successful answers with, as legacy RustFS writes them
//! (`ServiceBuilder::answer_heads_as_legacy_rustfs`, rustfs/gateway#1148).
//!
//! Responsible for: a policy write answered `204` with no body framing, a policy read with no
//! `Content-Type` and the policy as its body, and a `HeadBucket` still naming the region this
//! backend knows — the switch drops only a region left unnamed, which only the RustFS adapter hands
//! over.
//! NOT responsible for: the switch's own rules (`rustfs-gateway`'s `builder/legacy_heads.rs`), or
//! the RustFS answers through the migration seam (the difftest seam answer diff).
//! Upstream: `super::build_service`. Downstream: nothing.

use super::policy_tests::{policed, put_policy};
use super::*;

const POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policed/*"}]}"#;
const POLICY_MD5: &str = "ouGcIOtfCBshpi+mj/AR2A==";

fn header<'a>(response: &'a WireResponse, name: &str) -> Option<&'a str> {
    response
        .headers()
        .iter()
        .find(|(line, _)| line.as_str() == name)
        .and_then(|(_, value)| value.to_str().ok())
}

/// A policy write is `204 No Content`, as legacy RustFS's writer answers it, with no body and none
/// of a body's framing.
#[tokio::test]
async fn a_policy_write_answers_no_content() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    let written = put_policy(&service, POLICY, POLICY_MD5).await;
    assert_eq!(written.status(), 204, "{}", body_of(&written));
    assert!(body_of(&written).is_empty());
    assert_eq!((header(&written, "content-length"), header(&written, "content-type")), (None, None));
}

/// A policy read carries the policy as its body and no `Content-Type`, as legacy RustFS's writer
/// sets none.
#[tokio::test]
async fn a_policy_read_is_the_policy_with_no_content_type() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    assert_eq!(put_policy(&service, POLICY, POLICY_MD5).await.status(), 204);
    let read = exchange(&service, as_main(http::Method::GET, "/policed?policy", Bytes::new())).await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    assert_eq!(body_of(&read), POLICY);
    assert_eq!(header(&read, "content-type"), None);
}

/// Negative — a region the backend names is still written: only an unnamed one is dropped, and
/// this backend names its own.
#[tokio::test]
async fn n_a_head_bucket_still_names_the_region_this_backend_knows() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    let head = exchange(&service, as_main(http::Method::HEAD, "/policed", Bytes::new())).await;
    assert_eq!(head.status(), 200);
    assert_eq!(header(&head, "x-amz-bucket-region"), Some("us-east-1"));
}

/// Negative — a refused policy write keeps its refusal: the switch touches a successful head only.
#[tokio::test]
async fn n_a_refused_policy_write_is_still_refused() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    let refused = put_policy(&service, POLICY, "AAAAAAAAAAAAAAAAAAAAAA==").await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    assert!(body_of(&refused).contains("<Code>BadDigest</Code>"), "{}", body_of(&refused));
}

/// Negative — a missing policy is still the `404` its code carries, typed as the error document it
/// is.
#[tokio::test]
async fn n_a_missing_policy_is_still_the_typed_404() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    let missing = exchange(&service, as_main(http::Method::GET, "/policed?policy", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", body_of(&missing));
    assert_eq!(header(&missing, "content-type"), Some("application/xml"));
}
