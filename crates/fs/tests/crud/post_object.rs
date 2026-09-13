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

//! Production-service evidence for browser `POST` Object uploads (rustfs/gateway#721).
//!
//! Responsible for: an accepted form's file being stored and readable afterwards with its
//! `x-amz-meta-*` fields, its version reported in a versioning bucket, and the storage refusals —
//! a missing bucket and an unstorable metadata field — reaching the uploader.
//! NOT responsible for: POST-policy signatures, conditions, or success actions, which the gateway
//! form pipeline owns and `rustfs-gateway`'s own tests prove. The fixture service allows every
//! request, so these forms are anonymous and carry no policy.
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

use super::*;

const BOUNDARY: &str = "----RustFSFsPostObject";

fn form(key: &str, fields: &[(&str, &str)], file: &str) -> Bytes {
    let mut body = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{key}\r\n");
    for (name, value) in fields {
        body.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n{file}\r\n--{BOUNDARY}--\r\n"
    ));
    Bytes::from(body)
}

async fn post(service: &S3Service, bucket: &str, body: Bytes) -> rustfs_gateway::WireResponse {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("/{bucket}"))
        .header(http::header::HOST, "s3.example.com")
        .header(http::header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"))
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(body)
        .expect("a valid form request");
    exchange(service, request).await
}

/// Positive — the form's file is stored under the resolved key, with its metadata, and reads back.
#[tokio::test]
async fn a_form_upload_is_stored_and_readable() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "browser").await;
    let posted = post(
        &service,
        "browser",
        form("uploads/${filename}", &[("x-amz-meta-origin", "browser")], "hello from a form"),
    )
    .await;
    assert_eq!(posted.status(), 204, "{}", String::from_utf8_lossy(posted.body()));
    let e_tag = header(&posted, "etag").expect("the stored entity tag").to_owned();

    let fetched = exchange(&service, signed(http::Method::GET, "/browser/uploads/upload.txt", Bytes::new())).await;
    assert_eq!(fetched.status(), 200, "{}", String::from_utf8_lossy(fetched.body()));
    assert_eq!(fetched.body().as_ref(), b"hello from a form");
    assert_eq!(header(&fetched, "etag"), Some(&e_tag));
    assert_eq!(
        header(&fetched, "x-amz-meta-origin").map(|value| value.to_str().expect("ASCII")),
        Some("browser")
    );
}

/// Positive — a form upload into a versioning bucket reports the version it minted.
#[tokio::test]
async fn a_form_upload_reports_its_version() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "browser-versions").await;
    let enabled = super::multipart_versioning::set_versioning(&service, "browser-versions", "Enabled").await;
    assert_eq!(enabled.status(), 200, "{}", String::from_utf8_lossy(enabled.body()));
    let posted = post(&service, "browser-versions", form("doc", &[], "one")).await;
    assert_eq!(posted.status(), 204, "{}", String::from_utf8_lossy(posted.body()));
    let version = header(&posted, "x-amz-version-id").expect("a minted version").to_owned();
    let headed = exchange(&service, signed(http::Method::HEAD, "/browser-versions/doc", Bytes::new())).await;
    assert_eq!(header(&headed, "x-amz-version-id"), Some(&version));
}

/// Negative — a form naming a bucket that does not exist stores nothing and answers `NoSuchBucket`.
#[tokio::test]
async fn a_form_for_a_missing_bucket_is_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let refused = post(&service, "absent", form("doc", &[], "lost")).await;
    assert_eq!(refused.status(), 404, "{}", String::from_utf8_lossy(refused.body()));
    assert!(String::from_utf8_lossy(refused.body()).contains("<Code>NoSuchBucket</Code>"));
}

/// Negative — a form that repeats a metadata field is refused rather than resolved by picking one
/// of its values, and nothing is stored.
///
/// This observes the end-to-end answer, whichever layer gives it: today the gateway's form
/// pipeline refuses the repeat before the handler runs, so the handler's own refusal is pinned by
/// the `form_metadata` unit tests instead.
#[tokio::test]
async fn a_repeated_metadata_field_is_refused_without_a_write() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "browser-repeated").await;
    let refused = post(
        &service,
        "browser-repeated",
        form("doc", &[("x-amz-meta-origin", "first"), ("x-amz-meta-origin", "second")], "never stored"),
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    let fetched = exchange(&service, signed(http::Method::GET, "/browser-repeated/doc", Bytes::new())).await;
    assert_eq!(fetched.status(), 404);
}

/// Negative — a metadata field that could never be returned as a header is refused before
/// anything is stored.
#[tokio::test]
async fn an_unstorable_metadata_field_is_refused_without_a_write() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "browser-refused").await;
    let refused = post(
        &service,
        "browser-refused",
        form("doc", &[("x-amz-meta-bad key", "value")], "never stored"),
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    let fetched = exchange(&service, signed(http::Method::GET, "/browser-refused/doc", Bytes::new())).await;
    assert_eq!(fetched.status(), 404);
}
