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

//! ListObjects V1/V2 production-handler and persisted-pagination evidence.
//!
//! Responsible for: proving byte-ordered current-object pages, delimiter rollup, opaque cursor
//! scope, URL encoding, restart recovery, and unsafe-storage refusals through signed requests.
//! NOT responsible for: upload listing, lifecycle, or multipart completion.
//! Upstream: the shared CRUD service fixture. Downstream: the FS crate verification gate.

use super::*;

fn elements(body: &[u8], name: &str) -> Vec<String> {
    let text = std::str::from_utf8(body).expect("listing XML is UTF-8");
    let opening = format!("<{name}>");
    let closing = format!("</{name}>");
    let mut rest = text;
    let mut values = Vec::new();
    while let Some(start) = rest.find(&opening) {
        let value_start = start + opening.len();
        let Some(relative_end) = rest[value_start..].find(&closing) else {
            panic!("the listing element is closed");
        };
        let end = value_start + relative_end;
        values.push(rest[value_start..end].to_owned());
        rest = &rest[end + closing.len()..];
    }
    values
}

async fn put(service: &S3Service, bucket: &str, key: &str, bytes: &'static [u8]) {
    let response = exchange(service, signed(http::Method::PUT, &format!("/{bucket}/{key}"), Bytes::from_static(bytes))).await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
}

fn owner_service(root: &TestRoot) -> (Arc<FsBackend>, S3Service) {
    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
            .expect("a usable test root")
            .with_owner("bucket<&owner", "Bucket <Display> & Name"),
    );
    let credentials = Arc::new(
        StaticCredentials::new()
            .with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid primary fixture credentials"))
            .with(Credentials::new("AKIDALTERNATE", b"alternate").expect("valid alternate fixture credentials")),
    );
    service_with_backend_and_credentials(backend, credentials)
}

/// Negative — the authenticated requester never replaces the backend's fixed bucket owner.
#[tokio::test]
async fn n_two_identities_report_the_same_escaped_bucket_owner() {
    let root = TestRoot::new();
    let (_, service) = owner_service(&root);
    create_bucket(&service, "shared-owner").await;
    put(&service, "shared-owner", "key", b"body").await;

    for request in [
        signed_as("AKIDEXAMPLE", b"secret", http::Method::GET, "/shared-owner", Bytes::new()),
        signed_as("AKIDALTERNATE", b"alternate", http::Method::GET, "/shared-owner", Bytes::new()),
    ] {
        let listed = exchange(&service, request).await;
        assert_eq!(listed.status(), 200, "{}", String::from_utf8_lossy(listed.body()));
        assert_eq!(elements(listed.body(), "ID"), ["bucket&lt;&amp;owner"]);
        assert_eq!(elements(listed.body(), "DisplayName"), ["Bucket &lt;Display&gt; &amp; Name"]);
    }
}

/// Positive — the V1 marker resumes after either an object or rolled-up prefix after restart.
#[tokio::test]
async fn list_objects_v1_pages_with_a_delimiter_marker_after_restart() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "v1-pages").await;
    put(&running, "v1-pages", "photos/z.txt", b"z").await;
    put(&running, "v1-pages", "photos/sub/item.txt", b"nested").await;
    put(&running, "v1-pages", "photos/a%20b.txt", b"a").await;

    let first = exchange(
        &running,
        signed(
            http::Method::GET,
            "/v1-pages?prefix=photos%2F&delimiter=%2F&encoding-type=url&max-keys=2",
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(first.status(), 200, "{}", String::from_utf8_lossy(first.body()));
    assert_eq!(elements(first.body(), "Key"), ["photos%2Fa%20b.txt"]);
    assert_eq!(elements(first.body(), "Prefix").last().map(String::as_str), Some("photos%2Fsub%2F"));
    assert_eq!(element(first.body(), "MaxKeys").as_deref(), Some("2"));
    assert_eq!(element(first.body(), "IsTruncated").as_deref(), Some("true"));
    let marker = element(first.body(), "NextMarker").expect("a truncated delimited page carries a marker");
    assert_eq!(marker, "photos%2Fsub%2F");

    let (_, restarted) = service(&root);
    let second = exchange(
        &restarted,
        signed(
            http::Method::GET,
            &format!("/v1-pages?prefix=photos%2F&delimiter=%2F&encoding-type=url&max-keys=2&marker={marker}"),
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(second.status(), 200, "{}", String::from_utf8_lossy(second.body()));
    assert_eq!(elements(second.body(), "Key"), ["photos%2Fz.txt"]);
    assert!(elements(second.body(), "CommonPrefixes").is_empty());
    assert_eq!(element(second.body(), "Marker").as_deref(), Some(marker.as_str()));
    assert_eq!(element(second.body(), "MaxKeys").as_deref(), Some("2"));
    assert_eq!(element(second.body(), "IsTruncated").as_deref(), Some("false"));
    assert!(element(second.body(), "NextMarker").is_none());
}

/// Negative — V1 also distinguishes an empty bucket from a missing bucket.
#[tokio::test]
async fn n_v1_empty_and_missing_buckets_are_not_the_same_listing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "v1-empty").await;
    let empty = exchange(&service, signed(http::Method::GET, "/v1-empty", Bytes::new())).await;
    assert_eq!(empty.status(), 200, "{}", String::from_utf8_lossy(empty.body()));
    assert!(elements(empty.body(), "Key").is_empty());
    assert_eq!(element(empty.body(), "Marker").as_deref(), Some(""));
    assert_eq!(element(empty.body(), "IsTruncated").as_deref(), Some("false"));

    let missing = exchange(&service, signed(http::Method::GET, "/v1-missing", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", String::from_utf8_lossy(missing.body()));
    assert!(String::from_utf8_lossy(missing.body()).contains("<Code>NoSuchBucket</Code>"));
}

/// Negative — V1 reads the same current-object selection and hides a current delete marker.
#[tokio::test]
async fn n_v1_does_not_list_a_current_delete_marker() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "v1-hidden").await;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("x-amz-checksum-sha256"),
        http::HeaderValue::from_static("3W9vIcyGgMxcMrupjUKX43VSJ51+Mmo134R+0nE/LWo="),
    );
    assert_eq!(
        exchange(
            &service,
            signed_with_headers(
                http::Method::PUT,
                "/v1-hidden?versioning",
                Bytes::from_static(b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"),
                headers,
            ),
        )
        .await
        .status(),
        200
    );
    put(&service, "v1-hidden", "gone", b"old").await;
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/v1-hidden/gone", Bytes::new()))
            .await
            .status(),
        204
    );
    let listed = exchange(&service, signed(http::Method::GET, "/v1-hidden", Bytes::new())).await;
    assert_eq!(listed.status(), 200, "{}", String::from_utf8_lossy(listed.body()));
    assert!(elements(listed.body(), "Key").is_empty());
}

/// Negative — V1 never follows a symbolic link that replaces its persisted source.
#[cfg(unix)]
#[tokio::test]
async fn n_v1_symlinked_listing_storage_is_refused() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "v1-link").await;
    let versions = root.0.join(format!("b-{}/versions", hex::encode("v1-link")));
    std::fs::remove_dir(&versions).expect("an empty versions directory");
    symlink(&outside.0, versions).expect("a test symlink");
    let response = exchange(&service, signed(http::Method::GET, "/v1-link", Bytes::new())).await;
    assert_eq!(response.status(), 400, "{}", String::from_utf8_lossy(response.body()));
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidRequest</Code>"));
}

/// Positive — the opaque cursor resumes the byte-ordered current view after reopening storage.
#[tokio::test]
async fn list_objects_v2_pages_without_duplicates_after_restart() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "paged").await;
    put(&running, "paged", "z.txt", b"z").await;
    put(&running, "paged", "folder/b.txt", b"b").await;
    put(&running, "paged", "a.txt", b"a").await;
    put(&running, "paged", "folder/a.txt", b"a2").await;

    let first = exchange(&running, signed(http::Method::GET, "/paged?list-type=2&max-keys=2", Bytes::new())).await;
    assert_eq!(first.status(), 200, "{}", String::from_utf8_lossy(first.body()));
    assert_eq!(elements(first.body(), "Key"), ["a.txt", "folder/a.txt"]);
    assert_eq!(element(first.body(), "KeyCount").as_deref(), Some("2"));
    assert_eq!(element(first.body(), "IsTruncated").as_deref(), Some("true"));
    let token = element(first.body(), "NextContinuationToken").expect("a truncated page carries a cursor");

    let (_, restarted) = service(&root);
    let second = exchange(
        &restarted,
        signed(
            http::Method::GET,
            &format!("/paged?list-type=2&max-keys=2&continuation-token={token}"),
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(second.status(), 200, "{}", String::from_utf8_lossy(second.body()));
    assert_eq!(elements(second.body(), "Key"), ["folder/b.txt", "z.txt"]);
    assert_eq!(element(second.body(), "KeyCount").as_deref(), Some("2"));
    assert_eq!(element(second.body(), "IsTruncated").as_deref(), Some("false"));
    assert_eq!(element(second.body(), "ContinuationToken").as_deref(), Some(token.as_str()));

    let started = exchange(
        &restarted,
        signed(
            http::Method::GET,
            "/paged?list-type=2&max-keys=1&start-after=folder%2Fa.txt",
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(started.status(), 200, "{}", String::from_utf8_lossy(started.body()));
    assert_eq!(elements(started.body(), "Key"), ["folder/b.txt"]);
    assert_eq!(element(started.body(), "StartAfter").as_deref(), Some("folder/a.txt"));
    assert_eq!(element(started.body(), "IsTruncated").as_deref(), Some("true"));
}

/// Positive — a common prefix consumes one page slot and every requested field is URL encoded.
#[tokio::test]
async fn list_objects_v2_rolls_up_delimiters_and_url_encodes_the_page() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "rollup").await;
    put(&service, "rollup", "photos/2026/sub/item.txt", b"nested").await;
    put(&service, "rollup", "notes.txt", b"note").await;
    put(&service, "rollup", "photos/other.txt", b"other").await;
    put(&service, "rollup", "photos/2026/a%20b.txt", b"space").await;

    let response = exchange(
        &service,
        signed(
            http::Method::GET,
            "/rollup?list-type=2&prefix=photos%2F2026%2F&delimiter=%2F&encoding-type=url&max-keys=2",
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    assert_eq!(elements(response.body(), "Key"), ["photos%2F2026%2Fa%20b.txt"]);
    assert_eq!(
        elements(response.body(), "Prefix").last().map(String::as_str),
        Some("photos%2F2026%2Fsub%2F")
    );
    assert_eq!(element(response.body(), "KeyCount").as_deref(), Some("2"));
    assert_eq!(element(response.body(), "EncodingType").as_deref(), Some("url"));
}

/// Negative — absence has two distinct answers: an empty page and `NoSuchBucket`.
#[tokio::test]
async fn n_empty_and_missing_buckets_are_not_the_same_listing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "empty-list").await;
    let empty = exchange(&service, signed(http::Method::GET, "/empty-list?list-type=2", Bytes::new())).await;
    assert_eq!(empty.status(), 200, "{}", String::from_utf8_lossy(empty.body()));
    assert!(elements(empty.body(), "Key").is_empty());
    assert!(elements(empty.body(), "CommonPrefixes").is_empty());
    assert_eq!(element(empty.body(), "KeyCount").as_deref(), Some("0"));
    assert_eq!(element(empty.body(), "IsTruncated").as_deref(), Some("false"));

    let missing = exchange(&service, signed(http::Method::GET, "/missing-list?list-type=2", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", String::from_utf8_lossy(missing.body()));
    assert!(String::from_utf8_lossy(missing.body()).contains("<Code>NoSuchBucket</Code>"));
}

/// Negative — an opaque token is authority for one bucket only, never a reusable key marker.
#[tokio::test]
async fn n_a_continuation_token_cannot_cross_buckets() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "cursor-a").await;
    create_bucket(&service, "cursor-b").await;
    put(&service, "cursor-a", "a", b"a").await;
    put(&service, "cursor-a", "b", b"b").await;
    put(&service, "cursor-b", "a", b"a").await;
    put(&service, "cursor-b", "b", b"b").await;
    let first = exchange(&service, signed(http::Method::GET, "/cursor-a?list-type=2&max-keys=1", Bytes::new())).await;
    let token = element(first.body(), "NextContinuationToken").expect("a first-page token");
    let crossed = exchange(
        &service,
        signed(
            http::Method::GET,
            &format!("/cursor-b?list-type=2&continuation-token={token}"),
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(crossed.status(), 400, "{}", String::from_utf8_lossy(crossed.body()));
    assert!(String::from_utf8_lossy(crossed.body()).contains("<Code>InvalidArgument</Code>"));
}

/// Negative — continuation wins over `start-after` and is bound to the original filter scope.
#[tokio::test]
async fn n_a_continuation_token_cannot_be_reinterpreted_under_another_prefix() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "cursor-scope").await;
    put(&service, "cursor-scope", "a/one", b"one").await;
    put(&service, "cursor-scope", "a/two", b"two").await;
    put(&service, "cursor-scope", "b/one", b"other").await;
    let first = exchange(
        &service,
        signed(http::Method::GET, "/cursor-scope?list-type=2&prefix=a%2F&max-keys=1", Bytes::new()),
    )
    .await;
    let token = element(first.body(), "NextContinuationToken").expect("a scoped token");
    let changed = exchange(
        &service,
        signed(
            http::Method::GET,
            &format!("/cursor-scope?list-type=2&prefix=b%2F&start-after=b%2Fone&continuation-token={token}"),
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(changed.status(), 400, "{}", String::from_utf8_lossy(changed.body()));
    assert!(String::from_utf8_lossy(changed.body()).contains("<Code>InvalidArgument</Code>"));
}

/// Negative — a traversal-shaped opaque cursor is never interpreted as a storage path or key.
#[tokio::test]
async fn n_a_traversal_shaped_continuation_token_is_inert() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "cursor-path").await;
    put(&service, "cursor-path", "a", b"a").await;
    put(&service, "cursor-path", "b", b"b").await;
    let response = exchange(
        &service,
        signed(
            http::Method::GET,
            "/cursor-path?list-type=2&continuation-token=..%2F..%2Foutside",
            Bytes::new(),
        ),
    )
    .await;
    assert_eq!(response.status(), 400, "{}", String::from_utf8_lossy(response.body()));
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidArgument</Code>"));
}

/// Negative — a current delete marker hides the historical object from ordinary listing.
#[tokio::test]
async fn n_a_delete_marker_is_not_a_current_object() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "hidden-marker").await;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("x-amz-checksum-sha256"),
        http::HeaderValue::from_static("3W9vIcyGgMxcMrupjUKX43VSJ51+Mmo134R+0nE/LWo="),
    );
    let enabled = exchange(
        &service,
        signed_with_headers(
            http::Method::PUT,
            "/hidden-marker?versioning",
            Bytes::from_static(b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"),
            headers,
        ),
    )
    .await;
    assert_eq!(enabled.status(), 200, "{}", String::from_utf8_lossy(enabled.body()));
    put(&service, "hidden-marker", "gone", b"old").await;
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/hidden-marker/gone", Bytes::new()),)
            .await
            .status(),
        204
    );
    let listed = exchange(&service, signed(http::Method::GET, "/hidden-marker?list-type=2", Bytes::new())).await;
    assert_eq!(listed.status(), 200, "{}", String::from_utf8_lossy(listed.body()));
    assert!(elements(listed.body(), "Key").is_empty());
    assert_eq!(element(listed.body(), "KeyCount").as_deref(), Some("0"));
}

/// Negative — listing never follows a symbolic link that replaces persisted version storage.
#[cfg(unix)]
#[tokio::test]
async fn n_symlinked_listing_storage_is_refused() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "list-link").await;
    let versions = root.0.join(format!("b-{}/versions", hex::encode("list-link")));
    std::fs::remove_dir(&versions).expect("an empty versions directory");
    symlink(&outside.0, versions).expect("a test symlink");
    let response = exchange(&service, signed(http::Method::GET, "/list-link?list-type=2", Bytes::new())).await;
    assert_eq!(response.status(), 400, "{}", String::from_utf8_lossy(response.body()));
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>InvalidRequest</Code>"));
}
