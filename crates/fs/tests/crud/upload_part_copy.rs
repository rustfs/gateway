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

//! `UploadPartCopy` through the production registry (rustfs/gateway#979).
//!
//! Responsible for: a whole source and ranged spans of a source copied into parts that complete
//! into the expected bytes, an explicit source version, and the refusals — a malformed or
//! out-of-source range, an unknown upload, a missing source, a failed copy-source condition —
//! each writing no part.
//! NOT responsible for: parsing or authorizing `x-amz-copy-source`, or the range grammar itself
//! (`rustfs_gateway_core::ops::shared::copy_source`).
//! Upstream: the fs backend through the production `S3Service`. Downstream: nothing.

use super::*;
use rustfs_gateway::WireResponse;

#[path = "copy_source_arns.rs"]
mod arn_sources;

async fn put(service: &S3Service, target: &str, body: &'static [u8]) -> WireResponse {
    exchange(service, signed(http::Method::PUT, target, Bytes::from_static(body))).await
}

async fn part_copy(
    service: &S3Service,
    target: &str,
    upload_id: &str,
    part: i32,
    source: &str,
    extra: &[(&str, &str)],
) -> WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-copy-source", http::HeaderValue::from_str(source).expect("a copy source"));
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            http::HeaderValue::from_str(value).expect("a header value"),
        );
    }
    exchange(
        service,
        signed_with_headers(
            http::Method::PUT,
            &format!("{target}?partNumber={part}&uploadId={upload_id}"),
            Bytes::new(),
            headers,
        ),
    )
    .await
}

fn text(response: &WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn copied_etag(response: &WireResponse) -> String {
    assert_eq!(response.status(), 200, "{}", text(response));
    element(response.body(), "ETag")
        .expect("a CopyPartResult entity tag")
        .replace("&quot;", "\"")
}

async fn read(service: &S3Service, target: &str) -> Vec<u8> {
    let response = exchange(service, signed(http::Method::GET, target, Bytes::new())).await;
    assert_eq!(response.status(), 200, "{}", text(&response));
    response.body().to_vec()
}

async fn part_count(service: &S3Service, target: &str, upload_id: &str) -> usize {
    let listed = exchange(
        service,
        signed(http::Method::GET, &format!("{target}?uploadId={upload_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(listed.status(), 200, "{}", text(&listed));
    text(&listed).matches("<Part>").count()
}

/// Positive — a whole source copied into the only part completes into the source's bytes.
#[tokio::test]
async fn a_whole_source_copies_into_a_part() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "src").await;
    create_bucket(&service, "dst").await;
    assert_eq!(put(&service, "/src/obj", b"0123456789").await.status(), 200);

    let upload_id = initiate(&service, "dst", "copy").await;
    let e_tag = copied_etag(&part_copy(&service, "/dst/copy", &upload_id, 1, "/src/obj", &[]).await);
    let completed = complete(&service, "dst", "copy", &upload_id, &[(1, e_tag.as_str())]).await;
    assert_eq!(completed.status(), 200, "{}", text(&completed));
    assert_eq!(read(&service, "/dst/copy").await, b"0123456789");
}

/// Positive — ranged spans are inclusive at both ends, and an explicit source version is the one
/// read even after the key moved on.
#[tokio::test]
async fn ranged_spans_of_an_explicit_version_complete_in_order() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "src").await;
    let versioned = exchange(
        &service,
        signed_with_headers(
            http::Method::PUT,
            "/src?versioning",
            Bytes::from_static(b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"),
            {
                let mut headers = http::HeaderMap::new();
                headers.insert("content-md5", http::HeaderValue::from_static("8qj8HSeDu3APPMQZVG06WQ=="));
                headers
            },
        ),
    )
    .await;
    assert_eq!(versioned.status(), 200, "{}", text(&versioned));
    let first = put(&service, "/src/obj", b"abcdefghij").await;
    let version = header(&first, "x-amz-version-id")
        .and_then(|value| value.to_str().ok())
        .expect("a version id")
        .to_owned();
    assert_eq!(put(&service, "/src/obj", b"ZZZZZZZZZZ").await.status(), 200);

    let source = format!("/src/obj?versionId={version}");
    for (range, key, expected) in [("bytes=5-9", "tail", &b"fghij"[..]), ("bytes=0-0", "first", &b"a"[..])] {
        let upload_id = initiate(&service, "src", key).await;
        let e_tag = copied_etag(
            &part_copy(
                &service,
                &format!("/src/{key}"),
                &upload_id,
                1,
                &source,
                &[("x-amz-copy-source-range", range)],
            )
            .await,
        );
        let completed = complete(&service, "src", key, &upload_id, &[(1, e_tag.as_str())]).await;
        assert_eq!(completed.status(), 200, "{range}: {}", text(&completed));
        assert_eq!(read(&service, &format!("/src/{key}")).await, expected, "{range}");
    }
}

/// Negative — a range the grammar refuses, or one the source cannot satisfy, is `InvalidArgument`
/// and writes no part.
#[tokio::test]
async fn n_bad_ranges_are_refused_and_write_no_part() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "src").await;
    assert_eq!(put(&service, "/src/obj", b"01234").await.status(), 200);
    let upload_id = initiate(&service, "src", "dest").await;
    for range in ["0-2", "bytes=0", "bytes=hello-world", "bytes=0-2,3-4", "bytes=0-21"] {
        let refused = part_copy(&service, "/src/dest", &upload_id, 1, "/src/obj", &[("x-amz-copy-source-range", range)]).await;
        assert_eq!(refused.status(), 400, "{range}: {}", text(&refused));
        assert!(text(&refused).contains("<Code>InvalidArgument</Code>"), "{range}: {}", text(&refused));
    }
    assert_eq!(part_count(&service, "/src/dest", &upload_id).await, 0);
}

/// Negative — an upload that does not exist is `NoSuchUpload`, a missing source `NoSuchKey`.
#[tokio::test]
async fn n_a_missing_upload_or_source_is_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "src").await;
    assert_eq!(put(&service, "/src/obj", b"01234").await.status(), 200);

    let unknown = part_copy(&service, "/src/dest", "not-an-upload", 1, "/src/obj", &[]).await;
    assert_eq!(unknown.status(), 404, "{}", text(&unknown));
    assert!(text(&unknown).contains("<Code>NoSuchUpload</Code>"), "{}", text(&unknown));

    let upload_id = initiate(&service, "src", "dest").await;
    let missing = part_copy(&service, "/src/dest", &upload_id, 1, "/src/ghost", &[]).await;
    assert_eq!(missing.status(), 404, "{}", text(&missing));
    assert!(text(&missing).contains("<Code>NoSuchKey</Code>"), "{}", text(&missing));
    assert_eq!(part_count(&service, "/src/dest", &upload_id).await, 0);
}

/// Negative — a failed copy-source condition is `412` and writes no part.
#[tokio::test]
async fn n_a_failed_source_condition_writes_no_part() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "src").await;
    assert_eq!(put(&service, "/src/obj", b"01234").await.status(), 200);
    let upload_id = initiate(&service, "src", "dest").await;
    let refused = part_copy(
        &service,
        "/src/dest",
        &upload_id,
        1,
        "/src/obj",
        &[("x-amz-copy-source-if-none-match", "*")],
    )
    .await;
    assert_eq!(refused.status(), 412, "{}", text(&refused));
    assert_eq!(part_count(&service, "/src/dest", &upload_id).await, 0);
}
