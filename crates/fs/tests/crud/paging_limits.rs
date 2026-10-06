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

//! Populated pagination boundaries for the filesystem reference handlers.
//!
//! Responsible for: upload/part ceilings, invalid limits, and usable resume markers.
//! NOT responsible for: native RustFS parity or changing ListBuckets pagination.
//! Upstream: signed CRUD requests; downstream: filesystem listing responses.

use super::*;

async fn get(service: &S3Service, target: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::GET, target, Bytes::new())).await
}

fn text(response: &rustfs_gateway::WireResponse) -> &str {
    std::str::from_utf8(response.body()).expect("the listing or error is UTF-8 XML")
}

fn count(response: &rustfs_gateway::WireResponse, element: &str) -> usize {
    text(response).matches(&format!("<{element}>")).count()
}

fn page(response: &rustfs_gateway::WireResponse, member: &str, size: usize, limit: (&str, &str), truncated: bool) {
    assert_eq!(response.status(), 200, "{}", text(response));
    assert_eq!(count(response, member), size);
    assert_eq!(element(response.body(), limit.0).as_deref(), Some(limit.1));
    assert_eq!(
        element(response.body(), "IsTruncated").as_deref(),
        Some(if truncated { "true" } else { "false" })
    );
}

fn refused(response: &rustfs_gateway::WireResponse) {
    assert_eq!(response.status(), 400, "{}", text(response));
    assert_eq!(element(response.body(), "Code").as_deref(), Some("InvalidArgument"));
}

/// Positive: the documented upper upload boundary produces a resumable, complete second page.
#[tokio::test]
async fn upload_pages_at_one_and_one_thousand_resume_without_skipping() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "upload-limits").await;
    let service = &running;
    let create = |index| async move {
        if index < 1001 {
            initiate(service, "upload-limits", &format!("key-{index:04}")).await;
        }
    };
    // Prepare all records through real requests, with bounded concurrent filesystem writes.
    for index in (0..1001).step_by(8) {
        tokio::join!(
            create(index),
            create(index + 1),
            create(index + 2),
            create(index + 3),
            create(index + 4),
            create(index + 5),
            create(index + 6),
            create(index + 7),
        );
    }
    for (limit, expected_last, remaining) in [(1, "key-0000", 1000), (1000, "key-0999", 1)] {
        let first = get(&running, &format!("/upload-limits?uploads&max-uploads={limit}")).await;
        page(&first, "Upload", limit, ("MaxUploads", &limit.to_string()), true);
        let key = element(first.body(), "NextKeyMarker").expect("a truncated page's key");
        let upload = element(first.body(), "NextUploadIdMarker").expect("a truncated page's upload");
        assert_eq!(key, expected_last);
        let second = get(
            &running,
            &format!("/upload-limits?uploads&max-uploads=1000&key-marker={key}&upload-id-marker={upload}"),
        )
        .await;
        page(&second, "Upload", remaining, ("MaxUploads", "1000"), false);
        assert!(element(second.body(), "NextKeyMarker").is_none());
        assert!(element(second.body(), "NextUploadIdMarker").is_none());
        assert_eq!(
            element(second.body(), "Key").as_deref(),
            Some(if limit == 1 { "key-0001" } else { "key-1000" })
        );
    }
}

async fn invalid_upload_limits(values: &[&str]) {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "bad-upload-limits").await;
    initiate(&running, "bad-upload-limits", "key").await;
    for value in values {
        refused(&get(&running, &format!("/bad-upload-limits?uploads&max-uploads={value}")).await);
    }
    page(
        &get(&running, "/bad-upload-limits?uploads&max-uploads=1").await,
        "Upload",
        1,
        ("MaxUploads", "1"),
        false,
    );
}

/// Negative: zero is outside ListMultipartUploads' documented 1..=1000 request range.
#[tokio::test]
async fn n_zero_upload_limit_is_refused() {
    invalid_upload_limits(&["0"]).await;
}

/// Negative: a larger request cannot lift the reference backend's upload response ceiling.
#[tokio::test]
async fn n_oversized_upload_limits_are_refused() {
    invalid_upload_limits(&["1001", "5000", "2147483647"]).await;
}

/// Negative: signs, overflow and malformed numbers cannot become an empty upload page.
#[tokio::test]
async fn n_invalid_upload_limit_numbers_are_refused() {
    invalid_upload_limits(&["-1", "-2147483648", "2147483648", "oops"]).await;
}

async fn parts(service: &S3Service, bucket: &str, size: i32) -> String {
    create_bucket(service, bucket).await;
    let upload = initiate(service, bucket, "key").await;
    let upload_id = upload.as_str();
    let write = |part| async move {
        if part <= size {
            upload_part(service, bucket, "key", upload_id, part, b"part").await;
        }
    };
    for part in (1..=size).step_by(8) {
        tokio::join!(
            write(part),
            write(part + 1),
            write(part + 2),
            write(part + 3),
            write(part + 4),
            write(part + 5),
            write(part + 6),
            write(part + 7),
        );
    }
    upload
}

/// Negative: even an oversized request cannot return more than 1000 parts or strand the tail.
#[tokio::test]
async fn n_oversized_part_page_is_capped_and_resumes() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    let upload = parts(&running, "part-ceiling", 1001).await;
    for limit in [1000, 1001, 5000, i32::MAX] {
        let first = get(&running, &format!("/part-ceiling/key?uploadId={upload}&max-parts={limit}")).await;
        page(&first, "Part", 1000, ("MaxParts", "1000"), true);
        let marker = element(first.body(), "NextPartNumberMarker").expect("a truncated part marker");
        assert_eq!(marker, "1000");
        let second = get(
            &running,
            &format!("/part-ceiling/key?uploadId={upload}&max-parts={limit}&part-number-marker={marker}"),
        )
        .await;
        page(&second, "Part", 1, ("MaxParts", "1000"), false);
        assert_eq!(element(second.body(), "PartNumber").as_deref(), Some("1001"));
        assert!(element(second.body(), "NextPartNumberMarker").is_none());
    }
}

/// Positive: a one-part page resumes at the next part rather than repeating the marker.
#[tokio::test]
async fn one_part_pages_make_progress() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    let upload = parts(&running, "part-minimum", 2).await;
    let first = get(&running, &format!("/part-minimum/key?uploadId={upload}&max-parts=1")).await;
    page(&first, "Part", 1, ("MaxParts", "1"), true);
    assert_eq!(element(first.body(), "PartNumber").as_deref(), Some("1"));
    let marker = element(first.body(), "NextPartNumberMarker").expect("a part marker");
    assert_eq!(marker, "1");
    let second = get(
        &running,
        &format!("/part-minimum/key?uploadId={upload}&max-parts=1&part-number-marker={marker}"),
    )
    .await;
    page(&second, "Part", 1, ("MaxParts", "1"), false);
    assert_eq!(element(second.body(), "PartNumber").as_deref(), Some("2"));
    assert!(element(second.body(), "NextPartNumberMarker").is_none());
}

/// Negative: accepting a zero-part page must not advertise an unusable continuation.
#[tokio::test]
async fn n_zero_part_page_does_not_claim_truncation_without_a_marker() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    let upload = parts(&running, "part-zero", 2).await;
    let listed = get(&running, &format!("/part-zero/key?uploadId={upload}&max-parts=0")).await;
    page(&listed, "Part", 0, ("MaxParts", "0"), false);
    assert!(element(listed.body(), "NextPartNumberMarker").is_none());
}

/// Negative: invalid part limits remain refusals, including before clamping.
#[tokio::test]
async fn n_invalid_part_limit_numbers_are_refused() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    let upload = parts(&running, "bad-part-limits", 1).await;
    for value in ["-1", "-2147483648", "2147483648", "oops"] {
        refused(&get(&running, &format!("/bad-part-limits/key?uploadId={upload}&max-parts={value}")).await);
    }
    page(
        &get(&running, &format!("/bad-part-limits/key?uploadId={upload}&max-parts=1")).await,
        "Part",
        1,
        ("MaxParts", "1"),
        false,
    );
}

async fn version_fixture(service: &S3Service) {
    create_bucket(service, "version-limits").await;
    for key in ["a", "b"] {
        let put = exchange(
            service,
            signed(http::Method::PUT, &format!("/version-limits/{key}"), Bytes::from_static(b"body")),
        )
        .await;
        assert_eq!(put.status(), 200);
    }
}

/// Negative: a negative version-list limit must not silently turn into a successful empty page.
#[tokio::test]
async fn n_negative_version_limits_are_refused() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    version_fixture(&running).await;
    for value in ["-1", "-2147483648"] {
        refused(&get(&running, &format!("/version-limits?versions&max-keys={value}")).await);
    }
}

/// Negative: overflow and malformed version-list limits fail at the request boundary.
#[tokio::test]
async fn n_invalid_version_limit_numbers_are_refused() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    version_fixture(&running).await;
    for value in ["2147483648", "oops"] {
        refused(&get(&running, &format!("/version-limits?versions&max-keys={value}")).await);
    }
}

/// Positive: zero is empty and a one-version page has a usable next position.
#[tokio::test]
async fn version_pages_keep_zero_and_one_boundaries() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    version_fixture(&running).await;
    let zero = get(&running, "/version-limits?versions&max-keys=0").await;
    page(&zero, "Version", 0, ("MaxKeys", "0"), false);
    assert!(element(zero.body(), "NextKeyMarker").is_none());
    let first = get(&running, "/version-limits?versions&max-keys=1").await;
    page(&first, "Version", 1, ("MaxKeys", "1"), true);
    let key = element(first.body(), "NextKeyMarker").expect("a version key marker");
    let version = element(first.body(), "NextVersionIdMarker").expect("a version id marker");
    assert_eq!(key, "a");
    let second = get(
        &running,
        &format!("/version-limits?versions&max-keys=1&key-marker={key}&version-id-marker={version}"),
    )
    .await;
    page(&second, "Version", 1, ("MaxKeys", "1"), false);
    assert_eq!(element(second.body(), "Key").as_deref(), Some("b"));
    assert!(element(second.body(), "NextKeyMarker").is_none());
}
