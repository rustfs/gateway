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

//! `If-Match` on `DeleteObject`, evaluated as legacy RustFS evaluates it once
//! `FsBackend::evaluating_delete_if_match` is on (rustfs/gateway#1191).
//!
//! Responsible for: the default leaving the header unread; and with the option on, a `412` that
//! deletes nothing and writes no marker when the current or named version is another object, a
//! delete marker, or — in an unversioned bucket or for an excluded key — nothing at all; a `204`
//! removal when the tag or `*` matches; legacy RustFS's spellings; the versioned key never written,
//! marked without evaluation; an unknown version deleting nothing; a plain object file judged by
//! its bytes; and the verdict and the delete made under the lock racing writers take.
//! NOT responsible for: unconditional deletion (`versioning.rs`, `delete_objects.rs`), or
//! `DeleteObjects`, whose input carries no `If-Match`.
//! Upstream: the assembled service over the fs backend (`super`). Downstream: nothing.

use super::*;

const BODY: &[u8] = b"conditional body";
/// The entity tag of [`BODY`], unquoted.
const BODY_TAG: &str = "86ba1d7a943f65bb6da23b4ef56d99a2";
const REPLACEMENT: &[u8] = b"replacement body";
/// The entity tag of [`REPLACEMENT`], unquoted.
const REPLACEMENT_TAG: &str = "9c3ed5e642d32b0398e6733bd9e51aa5";
/// A tag no object here carries.
const OTHER_TAG: &str = "\"wrong-etag\"";

/// The fixture service over a backend that evaluates `If-Match` on `DeleteObject`.
fn guarded(root: &TestRoot) -> S3Service {
    let backend = FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
        .expect("a usable test root")
        .evaluating_delete_if_match();
    service_with_backend(Arc::new(backend)).1
}

fn quoted(tag: &str) -> String {
    format!("\"{tag}\"")
}

async fn put(service: &S3Service, target: &str, body: &'static [u8]) -> Option<String> {
    let response = exchange(service, signed(http::Method::PUT, target, Bytes::from_static(body))).await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    text(&response, "x-amz-version-id").map(ToOwned::to_owned)
}

async fn delete(service: &S3Service, target: &str, if_match: Option<&str>) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    if let Some(value) = if_match {
        headers.insert(
            http::header::IF_MATCH,
            http::HeaderValue::from_str(value).expect("an ASCII fixture header"),
        );
    }
    exchange(service, signed_with_headers(http::Method::DELETE, target, Bytes::new(), headers)).await
}

async fn head_status(service: &S3Service, target: &str) -> u16 {
    exchange(service, signed(http::Method::HEAD, target, Bytes::new()))
        .await
        .status()
        .as_u16()
}

fn text<'a>(response: &'a rustfs_gateway::WireResponse, name: &str) -> Option<&'a str> {
    header(response, name).and_then(|value| value.to_str().ok())
}

/// Asserts legacy RustFS's refusal: `412`, its sentence, and no `Condition` element.
fn assert_refused(response: &rustfs_gateway::WireResponse, context: &str) {
    let body = String::from_utf8_lossy(response.body());
    assert_eq!(response.status(), 412, "{context}: {body}");
    assert!(body.contains("<Code>PreconditionFailed</Code>"), "{context}: {body}");
    assert!(
        body.contains("<Message>At least one of the pre-conditions you specified did not hold</Message>"),
        "{context}: {body}"
    );
    assert!(!body.contains("<Condition>"), "{context}: {body}");
    assert_eq!(text(response, "x-amz-delete-marker"), None, "{context}");
    assert_eq!(text(response, "x-amz-version-id"), None, "{context}");
}

fn assert_deleted_without_marker(response: &rustfs_gateway::WireResponse, context: &str) {
    assert_eq!(response.status(), 204, "{context}: {}", String::from_utf8_lossy(response.body()));
    assert_ne!(text(response, "x-amz-delete-marker"), Some("true"), "{context}");
}

/// The delete markers and object versions a bucket's census lists, in census order.
async fn census(service: &S3Service, bucket: &str) -> (usize, usize) {
    let response = exchange(service, signed(http::Method::GET, &format!("/{bucket}?versions"), Bytes::new())).await;
    assert_eq!(response.status(), 200);
    let body = String::from_utf8_lossy(response.body()).into_owned();
    (body.matches("<DeleteMarker>").count(), body.matches("<Version>").count())
}

async fn versioned(service: &S3Service, bucket: &str, status: &str) {
    create_bucket(service, bucket).await;
    let configured = super::multipart_versioning::set_versioning(service, bucket, status).await;
    assert_eq!(configured.status(), 200, "{}", String::from_utf8_lossy(configured.body()));
}

/// Positive — by default the header is not read: a wrong tag deletes, and a missing key is `204`.
#[tokio::test]
async fn the_default_backend_leaves_if_match_unread() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "unread").await;
    put(&service, "/unread/key", BODY).await;

    assert_deleted_without_marker(&delete(&service, "/unread/key", Some(OTHER_TAG)).await, "wrong tag");
    assert_eq!(head_status(&service, "/unread/key").await, 404);
    assert_deleted_without_marker(&delete(&service, "/unread/never", Some("*")).await, "missing key");
}

/// Negative — another tag, quoted or bare, is refused and the object stays.
#[tokio::test]
async fn n_another_entity_tag_is_refused_and_the_object_kept() {
    let root = TestRoot::new();
    let service = guarded(&root);
    create_bucket(&service, "kept").await;
    put(&service, "/kept/key", BODY).await;

    assert_refused(&delete(&service, "/kept/key", Some(OTHER_TAG)).await, "quoted");
    assert_refused(&delete(&service, "/kept/key", Some(REPLACEMENT_TAG)).await, "bare");
    let read = exchange(&service, signed(http::Method::GET, "/kept/key", Bytes::new())).await;
    assert_eq!(read.status(), 200);
    assert_eq!(read.body().as_ref(), BODY);
}

/// Positive — the object's own tag, quoted or bare, and `*` delete it.
#[tokio::test]
async fn the_objects_own_tag_or_the_wildcard_deletes_it() {
    let root = TestRoot::new();
    let service = guarded(&root);
    create_bucket(&service, "matched").await;
    for (key, condition) in [
        ("quoted", quoted(BODY_TAG)),
        ("bare", BODY_TAG.to_owned()),
        ("wildcard", "*".to_owned()),
    ] {
        let target = format!("/matched/{key}");
        put(&service, &target, BODY).await;
        assert_deleted_without_marker(&delete(&service, &target, Some(&condition)).await, key);
        assert_eq!(head_status(&service, &target).await, 404, "{key}");
    }
}

/// Negative — in an unversioned bucket a key holding nothing fails every condition, `*` included,
/// whether it was never written or has just been deleted, and nothing is recorded for it.
#[tokio::test]
async fn n_a_missing_key_fails_the_condition_in_an_unversioned_bucket() {
    let root = TestRoot::new();
    let service = guarded(&root);
    create_bucket(&service, "absent").await;
    assert_refused(&delete(&service, "/absent/never", Some("*")).await, "never written, *");
    assert_refused(&delete(&service, "/absent/never", Some(&quoted(BODY_TAG))).await, "never written, tag");

    put(&service, "/absent/gone", BODY).await;
    assert_deleted_without_marker(&delete(&service, "/absent/gone", None).await, "unconditional");
    assert_refused(&delete(&service, "/absent/gone", Some("*")).await, "deleted, *");
    assert_refused(&delete(&service, "/absent/gone", Some(&quoted(BODY_TAG))).await, "deleted, tag");
    assert_eq!(census(&service, "absent").await, (0, 0));
}

/// Negative — a versioned or suspended bucket refuses another tag and writes no delete marker.
#[tokio::test]
async fn n_a_versioned_bucket_refuses_another_tag_without_a_marker() {
    let root = TestRoot::new();
    let service = guarded(&root);
    for (bucket, status) in [("enabled-kept", "Enabled"), ("suspended-kept", "Suspended")] {
        versioned(&service, bucket, status).await;
        let target = format!("/{bucket}/key");
        put(&service, &target, BODY).await;
        assert_refused(&delete(&service, &target, Some(OTHER_TAG)).await, status);
        assert_eq!(census(&service, bucket).await, (0, 1), "{status}");
        assert_eq!(head_status(&service, &target).await, 200, "{status}");
    }
}

/// Positive — a matching tag or `*` on a versioned or suspended bucket writes the delete marker an
/// unconditional delete would: a new id when enabled, `null` when suspended.
#[tokio::test]
async fn a_matching_delete_in_a_versioned_bucket_writes_a_marker() {
    let root = TestRoot::new();
    let service = guarded(&root);
    for (bucket, status) in [("enabled-marked", "Enabled"), ("suspended-marked", "Suspended")] {
        versioned(&service, bucket, status).await;
        for (key, condition) in [("tagged", quoted(BODY_TAG)), ("wildcard", "*".to_owned())] {
            let target = format!("/{bucket}/{key}");
            put(&service, &target, BODY).await;
            let deleted = delete(&service, &target, Some(&condition)).await;
            assert_eq!(deleted.status(), 204, "{status} {key}: {}", String::from_utf8_lossy(deleted.body()));
            assert_eq!(text(&deleted, "x-amz-delete-marker"), Some("true"), "{status} {key}");
            let marker = text(&deleted, "x-amz-version-id").expect("a marker id");
            assert_eq!(marker == "null", status == "Suspended", "{status} {key}: {marker}");
            assert_eq!(head_status(&service, &target).await, 404, "{status} {key}");
        }
    }
}

/// Negative — when the current version is a delete marker, `*` and the old tag both fail, and no
/// second marker is written.
#[tokio::test]
async fn n_a_current_delete_marker_fails_the_condition() {
    let root = TestRoot::new();
    let service = guarded(&root);
    for (bucket, status) in [("enabled-marker", "Enabled"), ("suspended-marker", "Suspended")] {
        versioned(&service, bucket, status).await;
        let target = format!("/{bucket}/key");
        put(&service, &target, BODY).await;
        assert_eq!(delete(&service, &target, None).await.status(), 204, "{status}");
        let before = census(&service, bucket).await;
        assert_refused(&delete(&service, &target, Some("*")).await, status);
        assert_refused(&delete(&service, &target, Some(&quoted(BODY_TAG))).await, status);
        assert_eq!(census(&service, bucket).await, before, "{status}");
    }
}

/// Positive, legacy RustFS's quirk — a versioned or suspended bucket's key that was never written
/// is not judged at all: the delete writes a marker, whatever the condition names.
#[tokio::test]
async fn a_versioned_key_never_written_is_marked_without_evaluation() {
    let root = TestRoot::new();
    let service = guarded(&root);
    for (bucket, status) in [("enabled-never", "Enabled"), ("suspended-never", "Suspended")] {
        versioned(&service, bucket, status).await;
        for (key, condition) in [("wildcard", "*"), ("tagged", OTHER_TAG)] {
            let deleted = delete(&service, &format!("/{bucket}/{key}"), Some(condition)).await;
            assert_eq!(deleted.status(), 204, "{status} {key}: {}", String::from_utf8_lossy(deleted.body()));
            assert_eq!(text(&deleted, "x-amz-delete-marker"), Some("true"), "{status} {key}");
        }
        assert_eq!(census(&service, bucket).await.0, 2, "{status}");
    }
}

/// Negative — an excluded key of a versioned bucket is judged as an unversioned bucket's key is:
/// missing fails, another tag fails, and its own tag deletes it without a marker.
#[tokio::test]
async fn n_an_excluded_key_is_judged_as_an_unversioned_key() {
    const EXCLUDING: &str = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status><ExcludedPrefixes><Prefix>logs/</Prefix></ExcludedPrefixes></VersioningConfiguration>";
    let root = TestRoot::new();
    let service = guarded(&root);
    create_bucket(&service, "excluding").await;
    let mut headers = http::HeaderMap::new();
    headers.insert("content-md5", http::HeaderValue::from_static("yiLSEm19VwhgnQErYUeIDw=="));
    let configured = exchange(
        &service,
        signed_with_headers(
            http::Method::PUT,
            "/excluding?versioning",
            Bytes::from_static(EXCLUDING.as_bytes()),
            headers,
        ),
    )
    .await;
    assert_eq!(configured.status(), 200, "{}", String::from_utf8_lossy(configured.body()));

    assert_refused(&delete(&service, "/excluding/logs/never", Some("*")).await, "missing");
    put(&service, "/excluding/logs/present", BODY).await;
    assert_refused(&delete(&service, "/excluding/logs/present", Some(OTHER_TAG)).await, "other tag");
    assert_deleted_without_marker(&delete(&service, "/excluding/logs/present", Some(&quoted(BODY_TAG))).await, "own tag");
    assert_eq!(census(&service, "excluding").await, (0, 0));
}

/// Negative — a named version is judged by its own tag, not the current one's.
#[tokio::test]
async fn n_a_named_version_is_judged_by_its_own_tag() {
    let root = TestRoot::new();
    let service = guarded(&root);
    versioned(&service, "named", "Enabled").await;
    let first = put(&service, "/named/key", BODY)
        .await
        .expect("an enabled put reports its id");
    put(&service, "/named/key", REPLACEMENT).await;
    let target = format!("/named/key?versionId={first}");

    assert_refused(&delete(&service, &target, Some(&quoted(REPLACEMENT_TAG))).await, "current tag");
    assert_eq!(head_status(&service, &target).await, 200);
    let deleted = delete(&service, &target, Some(&quoted(BODY_TAG))).await;
    assert_eq!(deleted.status(), 204, "{}", String::from_utf8_lossy(deleted.body()));
    assert_eq!(text(&deleted, "x-amz-version-id"), Some(first.as_str()));
    assert_eq!(head_status(&service, &target).await, 404);
    assert_eq!(head_status(&service, "/named/key").await, 200);
}

/// Negative — a named delete marker fails even `*`, and stays.
#[tokio::test]
async fn n_a_named_delete_marker_fails_the_condition() {
    let root = TestRoot::new();
    let service = guarded(&root);
    versioned(&service, "named-marker", "Enabled").await;
    put(&service, "/named-marker/key", BODY).await;
    let marked = delete(&service, "/named-marker/key", None).await;
    let marker = text(&marked, "x-amz-version-id").expect("a marker id").to_owned();

    assert_refused(
        &delete(&service, &format!("/named-marker/key?versionId={marker}"), Some("*")).await,
        "named marker",
    );
    assert_eq!(census(&service, "named-marker").await, (1, 1));
}

/// Positive — an unknown version, or `null` where no null version exists, deletes nothing and
/// reports no version, whatever the condition names.
#[tokio::test]
async fn an_unknown_version_deletes_nothing() {
    let root = TestRoot::new();
    let service = guarded(&root);
    versioned(&service, "unknown", "Enabled").await;
    put(&service, "/unknown/key", BODY).await;
    let unknown = "0".repeat(64);
    for version in [unknown.as_str(), "null"] {
        for condition in ["*", OTHER_TAG] {
            let deleted = delete(&service, &format!("/unknown/key?versionId={version}"), Some(condition)).await;
            assert_eq!(deleted.status(), 204, "{version} {condition}");
            assert_eq!(text(&deleted, "x-amz-delete-marker"), None, "{version} {condition}");
            assert_eq!(text(&deleted, "x-amz-version-id"), None, "{version} {condition}");
        }
    }
    assert_eq!(census(&service, "unknown").await, (0, 1));
}

/// Negative — spellings legacy RustFS never matches: a weak tag, another case, and a list, even one
/// naming the object's own tag.
#[tokio::test]
async fn n_spellings_legacy_rustfs_never_matches() {
    let root = TestRoot::new();
    let service = guarded(&root);
    create_bucket(&service, "never-matches").await;
    put(&service, "/never-matches/key", BODY).await;
    let weak = format!("W/{}", quoted(BODY_TAG));
    let upper = quoted(&BODY_TAG.to_ascii_uppercase());
    let list = format!("\"nope\", {}", quoted(BODY_TAG));
    for condition in [weak, upper, list] {
        assert_refused(&delete(&service, "/never-matches/key", Some(&condition)).await, &condition);
    }
    assert_eq!(head_status(&service, "/never-matches/key").await, 200);
}

/// Positive — spellings legacy RustFS matches: every surrounding quote stripped, `"*"` as the
/// wildcard, surrounding whitespace ignored, and an empty value read as no condition at all.
#[tokio::test]
async fn spellings_legacy_rustfs_matches() {
    let root = TestRoot::new();
    let service = guarded(&root);
    create_bucket(&service, "matches").await;
    for (key, condition) in [
        ("doubled", format!("\"\"{BODY_TAG}\"\"")),
        ("quoted-wildcard", "\"*\"".to_owned()),
        ("padded", format!("  {}  ", quoted(BODY_TAG))),
        ("empty", String::new()),
    ] {
        let target = format!("/matches/{key}");
        put(&service, &target, BODY).await;
        assert_deleted_without_marker(&delete(&service, &target, Some(&condition)).await, key);
        assert_eq!(head_status(&service, &target).await, 404, "{key}");
    }
}

/// Negative — a missing bucket is reported before any condition is judged.
#[tokio::test]
async fn n_a_missing_bucket_is_reported_first() {
    let root = TestRoot::new();
    let service = guarded(&root);
    let deleted = delete(&service, "/no-such-bucket/key", Some("*")).await;
    assert_eq!(deleted.status(), 404);
    assert!(String::from_utf8_lossy(deleted.body()).contains("<Code>NoSuchBucket</Code>"));
}

/// Negative — an object file written before version records existed is judged by its bytes, both
/// as the current object and as the named `null` version.
#[tokio::test]
async fn n_a_plain_object_file_is_judged_by_its_bytes() {
    let root = TestRoot::new();
    let service = guarded(&root);
    create_bucket(&service, "plain").await;
    for (key, target) in [("current", "/plain/current"), ("named", "/plain/named?versionId=null")] {
        let file = legacy_object_path(&root, "plain", key);
        std::fs::write(&file, BODY).expect("the plain object fixture is writable");
        assert_refused(&delete(&service, target, Some(OTHER_TAG)).await, key);
        assert!(file.is_file(), "{key}");
        assert_eq!(delete(&service, target, Some(&quoted(BODY_TAG))).await.status(), 204, "{key}");
        assert!(!file.exists(), "{key}");
    }
}

/// Negative — the verdict and the delete are made under the one lock writers take: a delete naming
/// the old tag while a replacement is written either lands first or is refused, so the
/// replacement survives every interleaving. A delete that judged, let the lock go and took it back
/// to delete would remove a replacement written in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n_a_racing_replacement_is_never_deleted() {
    let root = TestRoot::new();
    let service = Arc::new(guarded(&root));
    create_bucket(&service, "racing").await;
    let keys = (0..64).map(|index| format!("/racing/key-{index}")).collect::<Vec<_>>();
    for key in &keys {
        put(&service, key, BODY).await;
    }
    let mut tasks = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        let (deleter, writer) = (Arc::clone(&service), Arc::clone(&service));
        let (delete_key, write_key) = (key.clone(), key.clone());
        let deleting = async move { delete(&deleter, &delete_key, Some(&quoted(BODY_TAG))).await.status().as_u16() };
        let writing = async move {
            put(&writer, &write_key, REPLACEMENT).await;
            200
        };
        if index % 2 == 0 {
            tasks.push(tokio::spawn(writing));
            tasks.push(tokio::spawn(deleting));
        } else {
            tasks.push(tokio::spawn(deleting));
            tasks.push(tokio::spawn(writing));
        }
    }
    for task in tasks {
        let status = task.await.expect("the request task completes");
        assert!([200, 204, 412].contains(&status), "{status}");
    }
    for key in &keys {
        let read = exchange(&service, signed(http::Method::GET, key, Bytes::new())).await;
        assert_eq!(read.status(), 200, "{key}: the replacement was deleted");
        assert_eq!(read.body().as_ref(), REPLACEMENT, "{key}");
    }
}
