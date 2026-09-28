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

//! `If-Match` and `If-None-Match` on `CompleteMultipartUpload` (rustfs/gateway#1002).
//!
//! Responsible for: a completion publishing only when its write conditions hold against the key's
//! current object — the same verdict `PutObject` gives (rustfs/gateway#808) — and a refused
//! completion leaving both the current object and the upload in place.
//! NOT responsible for: the condition grammar or verdict table (`conditional_requests`).
//! Upstream: the fs backend through the production `S3Service`. Downstream: nothing.

use super::*;
use rustfs_gateway::WireResponse;

async fn put(service: &S3Service, target: &str, body: &'static [u8]) -> WireResponse {
    exchange(service, signed(http::Method::PUT, target, Bytes::from_static(body))).await
}

async fn complete_if(service: &S3Service, key: &str, upload_id: &str, part: &str, condition: (&str, &str)) -> WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_bytes(condition.0.as_bytes()).expect("a header name"),
        http::HeaderValue::from_str(condition.1).expect("a header value"),
    );
    exchange(
        service,
        signed_with_headers(
            http::Method::POST,
            &format!("/mpc/{key}?uploadId={upload_id}"),
            completion(&[(1, part)]),
            headers,
        ),
    )
    .await
}

async fn body_of(service: &S3Service, key: &str) -> Vec<u8> {
    let response = exchange(service, signed(http::Method::GET, &format!("/mpc/{key}"), Bytes::new())).await;
    assert_eq!(response.status(), 200);
    response.body().to_vec()
}

fn current_etag(response: &WireResponse) -> String {
    header(response, "etag")
        .and_then(|value| value.to_str().ok())
        .expect("an entity tag")
        .to_owned()
}

/// Positive — `If-None-Match: *` on an absent key and a matching `If-Match` both publish.
#[tokio::test]
async fn holding_conditions_publish() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "mpc").await;

    let upload_id = initiate(&service, "mpc", "fresh").await;
    let part = upload_part(&service, "mpc", "fresh", &upload_id, 1, b"first").await;
    let created = complete_if(&service, "fresh", &upload_id, &part, ("if-none-match", "*")).await;
    assert_eq!(created.status(), 200, "{}", String::from_utf8_lossy(created.body()));

    let existing = put(&service, "/mpc/key", b"old").await;
    let upload_id = initiate(&service, "mpc", "key").await;
    let part = upload_part(&service, "mpc", "key", &upload_id, 1, b"new").await;
    let replaced = complete_if(&service, "key", &upload_id, &part, ("if-match", &current_etag(&existing))).await;
    assert_eq!(replaced.status(), 200, "{}", String::from_utf8_lossy(replaced.body()));
    assert_eq!(body_of(&service, "key").await, b"new");
}

/// Negative — `If-None-Match: *` over an existing object and a stale `If-Match` are `412`: the
/// current object is untouched, and the upload survives to be completed without the condition.
#[tokio::test]
async fn n_failed_conditions_publish_nothing_and_keep_the_upload() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "mpc").await;
    assert_eq!(put(&service, "/mpc/key", b"old").await.status(), 200);

    for condition in [("if-none-match", "*"), ("if-match", "\"0123456789abcdef0123456789abcdef\"")] {
        let upload_id = initiate(&service, "mpc", "key").await;
        let part = upload_part(&service, "mpc", "key", &upload_id, 1, b"new").await;
        let refused = complete_if(&service, "key", &upload_id, &part, condition).await;
        assert_eq!(refused.status(), 412, "{condition:?}: {}", String::from_utf8_lossy(refused.body()));
        assert_eq!(body_of(&service, "key").await, b"old", "{condition:?}");
        let later = complete(&service, "mpc", "key", &upload_id, &[(1, part.as_str())]).await;
        assert_eq!(later.status(), 200, "{condition:?}: the refused upload is still completable");
        assert_eq!(put(&service, "/mpc/key", b"old").await.status(), 200);
    }
}
