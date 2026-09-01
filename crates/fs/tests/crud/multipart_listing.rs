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

//! Production upload-listing evidence for the filesystem reference backend.
//!
//! Responsible for: proving restarted upload pages, delimiter rollup, marker pairs, cleanup, and
//! storage refusals through signed production requests.
//! NOT responsible for: part listing, multipart completion semantics, lifecycle, or object versions.
//! Upstream: the filesystem multipart authority and shared List pagination contract. Downstream:
//! the crate verification gate.

use bytes::Bytes;

use super::{TestRoot, create_bucket, element, exchange, initiate, service, signed};

fn elements(body: &[u8], name: &str) -> Vec<String> {
    let Ok(body) = std::str::from_utf8(body) else { return Vec::new() };
    let opening = format!("<{name}>");
    let closing = format!("</{name}>");
    let mut remaining = body;
    let mut values = Vec::new();
    while let Some(start) = remaining.find(&opening) {
        let value_start = start + opening.len();
        let Some(end) = remaining[value_start..].find(&closing) else { break };
        values.push(remaining[value_start..value_start + end].to_owned());
        remaining = &remaining[value_start + end + closing.len()..];
    }
    values
}

/// Positive — marker pairs resume the byte-ordered upload view after reopening storage.
#[tokio::test]
async fn list_multipart_uploads_pages_with_delimiter_after_restart() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "upload-pages").await;
    let first_same_key = initiate(&running, "upload-pages", "photos/a%20b.txt").await;
    let second_same_key = initiate(&running, "upload-pages", "photos/a%20b.txt").await;
    let nested = initiate(&running, "upload-pages", "photos/sub/item.txt").await;
    let second_nested = initiate(&running, "upload-pages", "photos/sub/other.txt").await;
    let final_upload = initiate(&running, "upload-pages", "photos/z.txt").await;
    let outside_prefix = initiate(&running, "upload-pages", "other.txt").await;

    let first = exchange(
        &running,
        signed(
            http::Method::GET,
            "/upload-pages?uploads&prefix=photos%2F&delimiter=%2F&encoding-type=url&max-uploads=2",
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(first.status(), 200, "{}", String::from_utf8_lossy(first.body()));
    assert_eq!(elements(first.body(), "Key"), ["photos%2Fa%20b.txt", "photos%2Fa%20b.txt"]);
    let mut expected_ids = [first_same_key, second_same_key];
    expected_ids.sort();
    assert_eq!(elements(first.body(), "UploadId"), expected_ids);
    assert_eq!(
        elements(first.body(), "Initiated"),
        ["2026-01-02T03:04:05.000Z", "2026-01-02T03:04:05.000Z"]
    );
    assert_eq!(element(first.body(), "KeyMarker").as_deref(), Some(""));
    assert_eq!(element(first.body(), "UploadIdMarker").as_deref(), Some(""));
    assert_eq!(element(first.body(), "EncodingType").as_deref(), Some("url"));
    assert_eq!(element(first.body(), "MaxUploads").as_deref(), Some("2"));
    assert_eq!(element(first.body(), "IsTruncated").as_deref(), Some("true"));
    assert_eq!(element(first.body(), "NextKeyMarker").as_deref(), Some("photos%2Fa%20b.txt"));
    let upload_marker = element(first.body(), "NextUploadIdMarker").expect("a truncated upload page carries both markers");
    assert_eq!(upload_marker, expected_ids[1]);

    let (_, restarted) = service(&root);
    let second = exchange(
        &restarted,
        signed(
            http::Method::GET,
            &format!(
                "/upload-pages?uploads&prefix=photos%2F&delimiter=%2F&encoding-type=url&max-uploads=2&key-marker=photos%2Fa%20b.txt&upload-id-marker={upload_marker}"
            ),
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(second.status(), 200, "{}", String::from_utf8_lossy(second.body()));
    assert_eq!(elements(second.body(), "Key"), ["photos%2Fz.txt"]);
    assert_eq!(elements(second.body(), "UploadId"), [final_upload]);
    let common_prefixes = elements(second.body(), "CommonPrefixes");
    assert_eq!(common_prefixes.len(), 1);
    assert!(common_prefixes[0].contains("<Prefix>photos%2Fsub%2F</Prefix>"));
    assert!(!elements(second.body(), "UploadId").contains(&nested));
    assert!(!elements(second.body(), "UploadId").contains(&second_nested));
    assert!(!elements(second.body(), "UploadId").contains(&outside_prefix));
    assert_eq!(element(second.body(), "KeyMarker").as_deref(), Some("photos%2Fa%20b.txt"));
    assert_eq!(element(second.body(), "UploadIdMarker").as_deref(), Some(upload_marker.as_str()));
    assert_eq!(element(second.body(), "MaxUploads").as_deref(), Some("2"));
    assert_eq!(element(second.body(), "IsTruncated").as_deref(), Some("false"));
    assert!(element(second.body(), "NextKeyMarker").is_none());
    assert!(element(second.body(), "NextUploadIdMarker").is_none());
}

/// Negative — an empty bucket and a missing bucket are not the same upload listing.
#[tokio::test]
async fn n_upload_listing_distinguishes_empty_and_missing_buckets() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "empty-uploads").await;

    let empty = exchange(&service, signed(http::Method::GET, "/empty-uploads?uploads", Bytes::new())).await;
    assert_eq!(empty.status(), 200, "{}", String::from_utf8_lossy(empty.body()));
    assert!(elements(empty.body(), "UploadId").is_empty());
    assert_eq!(element(empty.body(), "IsTruncated").as_deref(), Some("false"));

    let missing = exchange(&service, signed(http::Method::GET, "/missing-uploads?uploads", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", String::from_utf8_lossy(missing.body()));
    assert!(String::from_utf8_lossy(missing.body()).contains("<Code>NoSuchBucket</Code>"));
}

/// Negative — retiring one upload removes it from the authoritative active-upload view.
#[tokio::test]
async fn n_aborted_upload_is_absent_from_listing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "retired-upload").await;
    let kept = initiate(&service, "retired-upload", "kept").await;
    let retired = initiate(&service, "retired-upload", "retired").await;
    let aborted = exchange(
        &service,
        signed(http::Method::DELETE, &format!("/retired-upload/retired?uploadId={retired}"), Bytes::new()),
    )
    .await;
    assert_eq!(aborted.status(), 204, "{}", String::from_utf8_lossy(aborted.body()));

    let listed = exchange(&service, signed(http::Method::GET, "/retired-upload?uploads", Bytes::new())).await;
    assert_eq!(listed.status(), 200, "{}", String::from_utf8_lossy(listed.body()));
    assert_eq!(elements(listed.body(), "UploadId"), [kept]);
    assert!(!elements(listed.body(), "UploadId").contains(&retired));
}

/// Negative — an upload-id marker cannot select a position without its key marker.
#[tokio::test]
async fn n_upload_id_marker_requires_key_marker() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "marker-pair").await;
    let upload_id = initiate(&service, "marker-pair", "key").await;

    let response = exchange(
        &service,
        signed(
            http::Method::GET,
            &format!("/marker-pair?uploads&upload-id-marker={upload_id}"),
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), 400, "{}", String::from_utf8_lossy(response.body()));
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidArgument</Code>"));
}

/// Negative — a negative page size is rejected instead of wrapping to an unbounded page.
#[tokio::test]
async fn n_negative_max_uploads_is_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "negative-max").await;

    let response = exchange(&service, signed(http::Method::GET, "/negative-max?uploads&max-uploads=-1", Bytes::new())).await;
    assert_eq!(response.status(), 400, "{}", String::from_utf8_lossy(response.body()));
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidArgument</Code>"));
}

/// Negative — upload listing never follows a symbolic link replacing its persisted authority.
#[cfg(unix)]
#[tokio::test]
async fn n_symlinked_upload_storage_is_refused() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "upload-link").await;
    let uploads = root.0.join(format!("b-{}/uploads", hex::encode("upload-link")));
    std::fs::remove_dir(&uploads).expect("an empty upload directory");
    symlink(&outside.0, uploads).expect("a test symlink");

    let response = exchange(&service, signed(http::Method::GET, "/upload-link?uploads", Bytes::new())).await;
    assert_eq!(response.status(), 400, "{}", String::from_utf8_lossy(response.body()));
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidRequest</Code>"));
}
