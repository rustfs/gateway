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

//! Production object-tagging evidence for the filesystem reference backend.
//!
//! Responsible for: current and explicit-version tag replacement, restart persistence, validation,
//! deletion, and lifecycle-filter consumption. NOT responsible for: bucket tags, transition actions,
//! or the lifecycle scheduler. Upstream: the version authority and shared tagging validator.
//! Downstream: lifecycle expiration and the crate verification gate.

use super::*;

const COLD: &str = "<Tagging><TagSet><Tag><Key>class</Key><Value>cold</Value></Tag></TagSet></Tagging>";
const COLD_MD5: &str = "2kPh1HS4GURzNuOzDUdH/w==";
const HOT: &str = "<Tagging><TagSet><Tag><Key>class</Key><Value>hot</Value></Tag></TagSet></Tagging>";
const HOT_MD5: &str = "3Jr6oGpppSJQxNtrQ+3+sA==";
const COLD_BLUE: &str = concat!(
    "<Tagging><TagSet><Tag><Key>class</Key><Value>cold</Value></Tag>",
    "<Tag><Key>tenant</Key><Value>blue</Value></Tag></TagSet></Tagging>"
);
const COLD_BLUE_MD5: &str = "LHJaauf5qE+r2r++TqfNsQ==";
const AND_TAG_FILTER: &str = concat!(
    "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration><ID>and-tags</ID>",
    "<Filter><And><Tag><Key>class</Key><Value>cold</Value></Tag>",
    "<Tag><Key>tenant</Key><Value>blue</Value></Tag></And></Filter>",
    "<Status>Enabled</Status></Rule></LifecycleConfiguration>"
);
const AND_TAG_FILTER_MD5: &str = "k3JCUwJm8ypo6wJ3zRPyKg==";
const EMPTY: &str = "<Tagging><TagSet></TagSet></Tagging>";
const EMPTY_MD5: &str = "k6PBbu32RmFaV5nRULDSlw==";
const INVALID: &str = "<Tagging><TagSet><Tag><Key></Key><Value>bad</Value></Tag></TagSet></Tagging>";
const INVALID_MD5: &str = "r3BCGeE4PMsvsFM9d0tPgA==";

async fn put_tags(
    service: &S3Service,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    document: &'static str,
    checksum: &'static str,
) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-md5", http::HeaderValue::from_static(checksum));
    let target = version_id.map_or_else(
        || format!("/{bucket}/{key}?tagging"),
        |version_id| format!("/{bucket}/{key}?tagging&versionId={version_id}"),
    );
    exchange(
        service,
        signed_with_headers(http::Method::PUT, &target, Bytes::from_static(document.as_bytes()), headers),
    )
    .await
}

async fn get_tags(service: &S3Service, bucket: &str, key: &str, version_id: Option<&str>) -> rustfs_gateway::WireResponse {
    let target = version_id.map_or_else(
        || format!("/{bucket}/{key}?tagging"),
        |version_id| format!("/{bucket}/{key}?tagging&versionId={version_id}"),
    );
    exchange(service, signed(http::Method::GET, &target, Bytes::new())).await
}

async fn delete_tags(service: &S3Service, bucket: &str, key: &str, version_id: Option<&str>) -> rustfs_gateway::WireResponse {
    let target = version_id.map_or_else(
        || format!("/{bucket}/{key}?tagging"),
        |version_id| format!("/{bucket}/{key}?tagging&versionId={version_id}"),
    );
    exchange(service, signed(http::Method::DELETE, &target, Bytes::new())).await
}

fn response_version(response: &rustfs_gateway::WireResponse) -> String {
    header(response, "x-amz-version-id")
        .expect("a versioned response names its version")
        .to_str()
        .expect("an ASCII version id")
        .to_owned()
}

fn only_tag_path(root: &TestRoot, bucket: &str) -> std::path::PathBuf {
    let versions = root.0.join(format!("b-{}/versions", hex::encode(bucket)));
    let records = std::fs::read_dir(versions)
        .expect("the version authority exists")
        .map(|entry| entry.expect("a readable version entry").path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1, "the fixture has exactly one object version");
    records[0].join("tags")
}

/// Positive — persisted object tags survive restart and make a matching lifecycle rule observable.
#[tokio::test]
async fn tags_survive_restart_and_drive_lifecycle_expiration() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "tag-expire").await;
    super::lifecycle_expiration::put_policy(
        &initial,
        "tag-expire",
        super::lifecycle_expiration::TAG_FILTER,
        super::lifecycle_expiration::TAG_FILTER_MD5,
    )
    .await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "tag-expire", "key", b"body")
            .await
            .status(),
        200
    );
    let tagged = put_tags(&initial, "tag-expire", "key", None, COLD, COLD_MD5).await;
    assert_eq!(tagged.status(), 200);
    assert!(header(&tagged, "x-amz-version-id").is_none());
    drop(initial);

    let (backend, reopened) = super::lifecycle_expiration::expiring_service(&root, SIGNED_AT_SECONDS + 1);
    let fetched = get_tags(&reopened, "tag-expire", "key", None).await;
    assert_eq!(fetched.status(), 200);
    assert!(String::from_utf8_lossy(fetched.body()).contains("<Key>class</Key><Value>cold</Value>"));
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 1);
    assert_eq!(
        super::lifecycle_expiration::get(&reopened, "tag-expire", "key")
            .await
            .status(),
        404
    );
}

/// Positive — an `And` selector expires only an object carrying every required tag pair.
#[tokio::test]
async fn lifecycle_and_filter_requires_every_tag() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "tag-and").await;
    super::lifecycle_expiration::put_policy(&initial, "tag-and", AND_TAG_FILTER, AND_TAG_FILTER_MD5).await;
    for key in ["complete", "partial"] {
        assert_eq!(
            super::lifecycle_expiration::put(&initial, "tag-and", key, b"body")
                .await
                .status(),
            200
        );
    }
    assert_eq!(
        put_tags(&initial, "tag-and", "complete", None, COLD_BLUE, COLD_BLUE_MD5)
            .await
            .status(),
        200
    );
    assert_eq!(put_tags(&initial, "tag-and", "partial", None, COLD, COLD_MD5).await.status(), 200);
    drop(initial);

    let (backend, reopened) = super::lifecycle_expiration::expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 1);
    assert_eq!(
        super::lifecycle_expiration::get(&reopened, "tag-and", "complete")
            .await
            .status(),
        404
    );
    assert_eq!(
        super::lifecycle_expiration::get(&reopened, "tag-and", "partial")
            .await
            .status(),
        200
    );
}

/// Negative — a valid but non-matching tag never satisfies the lifecycle selector.
#[tokio::test]
async fn n_nonmatching_tag_remains_visible() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "tag-keep").await;
    super::lifecycle_expiration::put_policy(
        &initial,
        "tag-keep",
        super::lifecycle_expiration::TAG_FILTER,
        super::lifecycle_expiration::TAG_FILTER_MD5,
    )
    .await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "tag-keep", "key", b"body")
            .await
            .status(),
        200
    );
    assert_eq!(put_tags(&initial, "tag-keep", "key", None, HOT, HOT_MD5).await.status(), 200);
    drop(initial);

    let (backend, reopened) = super::lifecycle_expiration::expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    assert_eq!(super::lifecycle_expiration::get(&reopened, "tag-keep", "key").await.status(), 200);
}

/// Negative — every tagging verb refuses a key that does not name an object.
#[tokio::test]
async fn n_missing_object_refuses_get_put_and_delete() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "tag-missing").await;
    assert_eq!(
        super::lifecycle_expiration::put(&running, "tag-missing", "decoy", b"untouched")
            .await
            .status(),
        200
    );

    let statuses = [
        get_tags(&running, "tag-missing", "absent", None).await.status(),
        put_tags(&running, "tag-missing", "absent", None, COLD, COLD_MD5)
            .await
            .status(),
        delete_tags(&running, "tag-missing", "absent", None).await.status(),
    ];
    assert_eq!(statuses, [404, 404, 404]);
    assert_eq!(
        super::lifecycle_expiration::get(&running, "tag-missing", "decoy")
            .await
            .body()
            .as_ref(),
        b"untouched"
    );
}

/// Negative — changing one version's tags never changes the current version or the object bytes.
#[tokio::test]
async fn n_explicit_version_tags_are_isolated_and_delete_is_idempotent() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "tag-versions").await;
    assert_eq!(
        super::multipart_versioning::set_versioning(&running, "tag-versions", "Enabled")
            .await
            .status(),
        200
    );
    let first = super::lifecycle_expiration::put(&running, "tag-versions", "key", b"first").await;
    let first_id = response_version(&first);
    let first_tagged = put_tags(&running, "tag-versions", "key", Some(&first_id), COLD, COLD_MD5).await;
    assert_eq!(first_tagged.status(), 200);
    assert_eq!(response_version(&first_tagged), first_id);
    let second = super::lifecycle_expiration::put(&running, "tag-versions", "key", b"second").await;
    let second_id = response_version(&second);
    assert_ne!(first_id, second_id);
    let current_tagged = put_tags(&running, "tag-versions", "key", None, HOT, HOT_MD5).await;
    assert_eq!(current_tagged.status(), 200);
    assert_eq!(response_version(&current_tagged), second_id);

    let historic = get_tags(&running, "tag-versions", "key", Some(&first_id)).await;
    let current = get_tags(&running, "tag-versions", "key", None).await;
    assert_eq!(response_version(&historic), first_id);
    assert_eq!(response_version(&current), second_id);
    assert!(String::from_utf8_lossy(historic.body()).contains("<Value>cold</Value>"));
    assert!(String::from_utf8_lossy(current.body()).contains("<Value>hot</Value>"));
    let deleted = delete_tags(&running, "tag-versions", "key", Some(&first_id)).await;
    assert_eq!(deleted.status(), 204);
    assert_eq!(response_version(&deleted), first_id);
    assert_eq!(delete_tags(&running, "tag-versions", "key", Some(&first_id)).await.status(), 204);
    assert!(!String::from_utf8_lossy(get_tags(&running, "tag-versions", "key", Some(&first_id)).await.body()).contains("<Tag>"));
    assert_eq!(
        exchange(
            &running,
            signed(http::Method::GET, &format!("/tag-versions/key?versionId={first_id}"), Bytes::new(),),
        )
        .await
        .body()
        .as_ref(),
        b"first"
    );
    assert_eq!(
        super::lifecycle_expiration::get(&running, "tag-versions", "key")
            .await
            .body()
            .as_ref(),
        b"second"
    );
}

/// Negative — an invalid replacement leaves the previously persisted tag set unchanged.
#[tokio::test]
async fn n_invalid_replacement_preserves_existing_tags() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "tag-invalid").await;
    assert_eq!(
        super::lifecycle_expiration::put(&running, "tag-invalid", "key", b"body")
            .await
            .status(),
        200
    );
    assert_eq!(put_tags(&running, "tag-invalid", "key", None, COLD, COLD_MD5).await.status(), 200);

    let rejected = put_tags(&running, "tag-invalid", "key", None, INVALID, INVALID_MD5).await;
    assert_eq!(rejected.status(), 400);
    assert!(String::from_utf8_lossy(rejected.body()).contains("<Code>InvalidTag</Code>"));
    assert!(String::from_utf8_lossy(get_tags(&running, "tag-invalid", "key", None).await.body()).contains("<Value>cold</Value>"));
}

/// Negative — corrupt tag state aborts lifecycle preflight before deleting its object.
#[tokio::test]
async fn n_corrupt_tag_authority_is_not_treated_as_an_empty_set() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "tag-corrupt").await;
    super::lifecycle_expiration::put_policy(
        &initial,
        "tag-corrupt",
        super::lifecycle_expiration::TAG_FILTER,
        super::lifecycle_expiration::TAG_FILTER_MD5,
    )
    .await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "tag-corrupt", "key", b"body")
            .await
            .status(),
        200
    );
    assert_eq!(put_tags(&initial, "tag-corrupt", "key", None, COLD, COLD_MD5).await.status(), 200);
    std::fs::write(only_tag_path(&root, "tag-corrupt"), b"corrupt").expect("the exact tag authority is writable");
    drop(initial);

    let (backend, reopened) = super::lifecycle_expiration::expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(get_tags(&reopened, "tag-corrupt", "key", None).await.status(), 500);
    assert!(backend.expire_lifecycle_once().await.is_err());
    assert_eq!(
        super::lifecycle_expiration::get(&reopened, "tag-corrupt", "key")
            .await
            .status(),
        200
    );
}

/// Negative — no tagging verb follows a symbolic link outside the version authority.
#[cfg(unix)]
#[tokio::test]
async fn n_tag_authority_symlink_is_refused_for_read_write_and_delete() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "tag-linked").await;
    assert_eq!(
        super::lifecycle_expiration::put(&running, "tag-linked", "key", b"body")
            .await
            .status(),
        200
    );
    assert_eq!(put_tags(&running, "tag-linked", "key", None, COLD, COLD_MD5).await.status(), 200);
    let outside = root.0.join("outside-tags");
    std::fs::write(&outside, HOT).expect("an outside tag fixture");
    let authority = only_tag_path(&root, "tag-linked");
    std::fs::remove_file(&authority).expect("the tag authority is removable");
    symlink(&outside, &authority).expect("a tag symlink fixture");

    let statuses = [
        get_tags(&running, "tag-linked", "key", None).await.status(),
        put_tags(&running, "tag-linked", "key", None, COLD, COLD_MD5).await.status(),
        delete_tags(&running, "tag-linked", "key", None).await.status(),
    ];
    assert_eq!(statuses, [400, 400, 400]);
    assert_eq!(std::fs::read_to_string(outside).expect("outside state remains readable"), HOT);
}

async fn tagging_counts(service: &S3Service, target: &str) -> [Option<String>; 2] {
    let mut counts = [None, None];
    for (slot, method) in counts.iter_mut().zip([http::Method::GET, http::Method::HEAD]) {
        let response = exchange(service, signed(method, target, Bytes::new())).await;
        assert_eq!(response.status(), 200);
        *slot = header(&response, "x-amz-tagging-count")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
    }
    counts
}

/// Positive — `GetObject` and `HeadObject` report how many tags the version carries
/// (rustfs/gateway#1000), and follow a replacement.
#[tokio::test]
async fn reads_report_the_tag_count() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "tag-count").await;
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-tagging", http::HeaderValue::from_static("a=1&b=2"));
    let written = exchange(
        &service,
        signed_with_headers(http::Method::PUT, "/tag-count/key", Bytes::from_static(b"body"), headers),
    )
    .await;
    assert_eq!(written.status(), 200);
    assert_eq!(
        tagging_counts(&service, "/tag-count/key").await,
        [Some("2".to_owned()), Some("2".to_owned())]
    );

    assert_eq!(put_tags(&service, "tag-count", "key", None, COLD, COLD_MD5).await.status(), 200);
    assert_eq!(
        tagging_counts(&service, "/tag-count/key").await,
        [Some("1".to_owned()), Some("1".to_owned())]
    );
}

/// Negative — an object with no tags, or whose tags were deleted, reports no count.
#[tokio::test]
async fn n_untagged_reads_report_no_tag_count() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "tag-count").await;
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/tag-count/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );
    assert_eq!(tagging_counts(&service, "/tag-count/key").await, [None, None]);
    assert_eq!(put_tags(&service, "tag-count", "key", None, COLD, COLD_MD5).await.status(), 200);
    assert_eq!(delete_tags(&service, "tag-count", "key", None).await.status(), 204);
    assert_eq!(tagging_counts(&service, "/tag-count/key").await, [None, None]);
    // An explicitly empty tag set is stored, and counts as no tags.
    assert_eq!(put_tags(&service, "tag-count", "key", None, EMPTY, EMPTY_MD5).await.status(), 200);
    assert_eq!(tagging_counts(&service, "/tag-count/key").await, [None, None]);
}

/// Negative — an unreadable tag document does not fail the read; it reports no count.
#[tokio::test]
async fn n_corrupt_tags_leave_the_read_intact_without_a_count() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "tag-count").await;
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/tag-count/key", Bytes::from_static(b"body")))
            .await
            .status(),
        200
    );
    assert_eq!(put_tags(&service, "tag-count", "key", None, COLD, COLD_MD5).await.status(), 200);
    std::fs::write(only_tag_path(&root, "tag-count"), b"corrupt").expect("the exact tag authority is writable");
    assert_eq!(tagging_counts(&service, "/tag-count/key").await, [None, None]);
}
