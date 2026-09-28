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

//! Bucket CORS configuration through the production registry (rustfs/gateway#1004).
//!
//! Responsible for: the document stored, read back across a restart and deleted, `404
//! NoSuchCORSConfiguration` when absent, the idempotent `204` delete, the shared refusal storing
//! nothing, the missing-bucket refusals, and [`FsBackend`]'s `CorsSource` answering the stored
//! document.
//! NOT responsible for: evaluating a preflight, which the gateway does (`compat-sut` measures it
//! end to end), or the document rules (`crates/core` `cors`).
//! Upstream: the fs backend through the production `S3Service`. Downstream: nothing.

use super::*;
use rustfs_gateway::{BucketName, CorsSource, WireResponse};

const RULES: &str = "<CORSConfiguration><CORSRule><AllowedOrigin>*.get</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule><CORSRule><AllowedOrigin>*.put</AllowedOrigin><AllowedMethod>PUT</AllowedMethod><AllowedHeader>x-amz-meta-*</AllowedHeader></CORSRule></CORSConfiguration>";
const RULES_MD5: &str = "m/sxqUlywtddbP0rcNh6PA==";
const BAD_METHOD: &str = "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>PATCH</AllowedMethod></CORSRule></CORSConfiguration>";
const BAD_METHOD_MD5: &str = "/I7pYYtIJSNahyse96LrAw==";

async fn put(service: &S3Service, target: &str, body: &'static str, md5: &str) -> WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-md5", http::HeaderValue::from_str(md5).expect("a header value"));
    exchange(
        service,
        signed_with_headers(http::Method::PUT, target, Bytes::from_static(body.as_bytes()), headers),
    )
    .await
}

async fn get(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, signed(http::Method::GET, target, Bytes::new())).await
}

fn text(response: &WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn assert_absent(response: &WireResponse) {
    assert_eq!(response.status(), 404, "{}", text(response));
    assert!(text(response).contains("<Code>NoSuchCORSConfiguration</Code>"), "{}", text(response));
}

/// Positive — the document round-trips across a restart, the backend's `CorsSource` answers it,
/// and a delete (twice) leaves the bucket with none.
#[tokio::test]
async fn a_cors_document_is_stored_read_back_served_and_deleted() {
    let root = TestRoot::new();
    let (_, first) = service(&root);
    create_bucket(&first, "corsy").await;
    assert_absent(&get(&first, "/corsy?cors").await);
    let written = put(&first, "/corsy?cors", RULES, RULES_MD5).await;
    assert_eq!(written.status(), 200, "{}", text(&written));
    drop(first);

    let (backend, service) = service(&root);
    let read = get(&service, "/corsy?cors").await;
    assert_eq!(read.status(), 200, "{}", text(&read));
    assert_eq!(text(&read).matches("<CORSRule>").count(), 2, "{}", text(&read));
    assert!(text(&read).contains("<AllowedOrigin>*.put</AllowedOrigin>"), "{}", text(&read));
    let served = backend
        .load(&BucketName::new("corsy").expect("a bucket name"))
        .await
        .expect("a readable document")
        .expect("a stored document");
    assert_eq!(served.cors_rules.len(), 2);

    for _ in 0..2 {
        let deleted = exchange(&service, signed(http::Method::DELETE, "/corsy?cors", Bytes::new())).await;
        assert_eq!(deleted.status(), 204, "{}", text(&deleted));
    }
    assert_absent(&get(&service, "/corsy?cors").await);
    assert!(
        backend
            .load(&BucketName::new("corsy").expect("a bucket name"))
            .await
            .expect("readable")
            .is_none()
    );
}

/// Negative — a method outside the documented set is refused by the shared rules and not stored;
/// a missing bucket is `NoSuchBucket` for all three operations and serves no document.
#[tokio::test]
async fn n_refused_documents_and_missing_buckets() {
    let root = TestRoot::new();
    let (backend, service) = service(&root);
    create_bucket(&service, "corsy").await;
    let refused = put(&service, "/corsy?cors", BAD_METHOD, BAD_METHOD_MD5).await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert_absent(&get(&service, "/corsy?cors").await);

    for response in [
        put(&service, "/ghost?cors", RULES, RULES_MD5).await,
        get(&service, "/ghost?cors").await,
        exchange(&service, signed(http::Method::DELETE, "/ghost?cors", Bytes::new())).await,
    ] {
        assert_eq!(response.status(), 404, "{}", text(&response));
        assert!(text(&response).contains("<Code>NoSuchBucket</Code>"), "{}", text(&response));
    }
    assert!(
        backend
            .load(&BucketName::new("ghost").expect("a bucket name"))
            .await
            .expect("readable")
            .is_none()
    );
}

/// Negative — the document leaves with its bucket.
#[tokio::test]
async fn n_a_recreated_bucket_starts_without_cors() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "corsy").await;
    assert_eq!(put(&service, "/corsy?cors", RULES, RULES_MD5).await.status(), 200);
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/corsy", Bytes::new()))
            .await
            .status(),
        204
    );
    create_bucket(&service, "corsy").await;
    assert_absent(&get(&service, "/corsy?cors").await);
}
