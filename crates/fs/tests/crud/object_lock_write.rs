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

//! Signed write requests carrying Object Lock headers on an unlocked bucket or unsupported event holds.
//! Responsible for: `400` refusal on standard lock headers against unlocked buckets and `501` refusal
//! on unsupported event-hold headers, with no publication on PUT, multipart initiation, and COPY.
//! NOT responsible for: full lock-enabled bucket persistence and enforcement (`object_lock.rs`).
//! Upstream: the CRUD service fixture. Downstream: the filesystem capability boundary.

use super::*;

const LOCK_FIELDS: [(&str, &str, u16); 6] = [
    ("x-amz-object-lock-mode", "GOVERNANCE", 400),
    ("x-amz-object-lock-retain-until-date", "2027-01-02T03:04:05Z", 400),
    ("x-amz-object-lock-legal-hold", "ON", 400),
    ("x-amz-object-lock-event-hold", "ON", 501),
    ("x-amz-object-lock-event-hold-duration-days", "1", 501),
    ("x-amz-object-lock-event-hold-duration-years", "1", 501),
];

async fn write(
    service: &S3Service,
    method: http::Method,
    target: &str,
    body: Bytes,
    field: (&str, &str),
    copy: bool,
) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_bytes(field.0.as_bytes()).expect("header name"),
        http::HeaderValue::from_str(field.1).expect("header value"),
    );
    if copy {
        headers.insert("x-amz-copy-source", http::HeaderValue::from_static("/lock-fields/source"));
    }
    exchange(service, signed_with_headers(method, target, body, headers)).await
}

#[tokio::test]
async fn put_lock_fields_do_not_publish_unprotected_objects() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "lock-fields").await;
    let mut results = Vec::new();
    for (index, (name, value, expected)) in LOCK_FIELDS.iter().copied().enumerate() {
        let path = format!("/lock-fields/put-{index}");
        let response = write(&service, http::Method::PUT, &path, Bytes::from_static(b"object"), (name, value), false).await;
        let head = exchange(&service, signed(http::Method::HEAD, &path, Bytes::new())).await;
        results.push((name, expected, response.status().as_u16(), head.status().as_u16()));
    }
    assert!(
        results
            .iter()
            .all(|(_, expected, response, head)| *response == *expected && *head == 404),
        "{results:?}"
    );
}

#[tokio::test]
async fn multipart_lock_fields_do_not_create_uploads() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "lock-fields").await;
    let mut results = Vec::new();
    for (index, (name, value, expected)) in LOCK_FIELDS.iter().copied().enumerate() {
        let path = format!("/lock-fields/multipart-{index}?uploads");
        let response = write(&service, http::Method::POST, &path, Bytes::new(), (name, value), false).await;
        results.push((name, expected, response.status().as_u16()));
    }
    let list = exchange(&service, signed(http::Method::GET, "/lock-fields?uploads", Bytes::new())).await;
    assert_eq!(list.status(), 200);
    assert!(
        results.iter().all(|(_, expected, response)| *response == *expected)
            && !String::from_utf8_lossy(list.body()).contains("<Upload>"),
        "{results:?}; uploads: {}",
        String::from_utf8_lossy(list.body())
    );
}

#[tokio::test]
async fn copy_lock_fields_do_not_publish_unprotected_objects() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "lock-fields").await;
    let source = exchange(&service, signed(http::Method::PUT, "/lock-fields/source", Bytes::from_static(b"source"))).await;
    assert_eq!(source.status(), 200);
    let mut results = Vec::new();
    for (index, (name, value, expected)) in LOCK_FIELDS.iter().copied().enumerate() {
        let path = format!("/lock-fields/copy-{index}");
        let response = write(&service, http::Method::PUT, &path, Bytes::new(), (name, value), true).await;
        let head = exchange(&service, signed(http::Method::HEAD, &path, Bytes::new())).await;
        results.push((name, expected, response.status().as_u16(), head.status().as_u16()));
    }
    assert!(
        results
            .iter()
            .all(|(_, expected, response, head)| *response == *expected && *head == 404),
        "{results:?}"
    );
}

#[tokio::test]
async fn ordinary_writes_remain_available() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "lock-fields").await;
    let put = exchange(&service, signed(http::Method::PUT, "/lock-fields/source", Bytes::from_static(b"source"))).await;
    assert_eq!(put.status(), 200);
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-copy-source", http::HeaderValue::from_static("/lock-fields/source"));
    let copy = exchange(
        &service,
        signed_with_headers(http::Method::PUT, "/lock-fields/copy", Bytes::new(), headers),
    )
    .await;
    assert_eq!(copy.status(), 200);
    let get = exchange(&service, signed(http::Method::GET, "/lock-fields/copy", Bytes::new())).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.body().as_ref(), b"source");
    let upload = exchange(&service, signed(http::Method::POST, "/lock-fields/upload?uploads", Bytes::new())).await;
    assert_eq!(upload.status(), 200);
    let list = exchange(&service, signed(http::Method::GET, "/lock-fields?uploads", Bytes::new())).await;
    assert_eq!(list.status(), 200);
    assert!(String::from_utf8_lossy(list.body()).contains("<Key>upload</Key>"));
}
