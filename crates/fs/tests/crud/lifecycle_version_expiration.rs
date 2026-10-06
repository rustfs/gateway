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

//! Version-history expiration through the signed filesystem service.
//!
//! Responsible for: orphan markers, noncurrent age/retention, restart and preflight refusals.
//! NOT responsible for: transitions, object-lock support or the scheduler's cadence.
//! Upstream: persisted lifecycle rules and version records; downstream: the real lifecycle sweep.

use super::lifecycle_expiration::{expiring_service, put, put_policy};
use super::*;

const BOTH: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>markers</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>",
    "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule><Rule><ID>history",
    "</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><NoncurrentVersionExpiration><NoncurrentDays>",
    "1</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>",
);
const BOTH_MD5: &str = "BPyKAnig/HmFCPGezvCe4Q==";
const MARKERS: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>markers</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>",
    "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>",
    "</LifecycleConfiguration>",
);
const MARKERS_MD5: &str = "xQ/Ht9iZFxUJyTCkVxc/Qg==";
const DISABLED: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>markers</ID><Status>Disabled</Status><Filter><Prefix></Prefix></Filter>",
    "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule><Rule><ID>history",
    "</ID><Status>Disabled</Status><Filter><Prefix></Prefix></Filter><NoncurrentVersionExpiration>",
    "<NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>",
);
const DISABLED_MD5: &str = "qxKHq/VdtOk0TSYYfvcFJQ==";
const OTHER_PREFIX: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>markers</ID><Status>Enabled</Status><Filter><Prefix>other/</Prefix>",
    "</Filter><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule><Rule>",
    "<ID>history</ID><Status>Enabled</Status><Filter><Prefix>other/</Prefix></Filter>",
    "<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>",
    "</LifecycleConfiguration>",
);
const OTHER_PREFIX_MD5: &str = "zSToKTKrwwmailJ/Mx6kIw==";
const RETAIN_ONE: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>markers</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>",
    "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule><Rule><ID>history",
    "</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><NoncurrentVersionExpiration><NoncurrentDays>",
    "1</NoncurrentDays><NewerNoncurrentVersions>1</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule>",
    "</LifecycleConfiguration>",
);
const RETAIN_ONE_MD5: &str = "zfnaVfchtxe5Rz42AB6+Ag==";
const TAGGED: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>history</ID><Status>Enabled</Status><Filter><Tag><Key>class</Key><Value>",
    "archive</Value></Tag></Filter><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays>",
    "</NoncurrentVersionExpiration></Rule></LifecycleConfiguration>",
);
const TAGGED_MD5: &str = "CNwvuiEKHcyPhffTAPH4Rg==";

async fn enabled(service: &S3Service, bucket: &str) {
    create_bucket(service, bucket).await;
    assert_eq!(super::versioning::set_versioning(service, bucket, "Enabled").await.status(), 200);
}

fn id(response: &rustfs_gateway::WireResponse) -> String {
    header(response, "x-amz-version-id")
        .expect("a version id")
        .to_str()
        .expect("an ASCII id")
        .to_owned()
}

async fn mark(service: &S3Service, bucket: &str) -> String {
    let response = exchange(service, signed(http::Method::DELETE, &format!("/{bucket}/key"), Bytes::new())).await;
    assert_eq!(response.status(), 204);
    id(&response)
}

async fn named(service: &S3Service, bucket: &str, version: &str) -> rustfs_gateway::WireResponse {
    exchange(
        service,
        signed(http::Method::GET, &format!("/{bucket}/key?versionId={version}"), Bytes::new()),
    )
    .await
}

/// Positive: expire history, then the orphan marker, and preserve the deletion across restart.
#[tokio::test]
async fn history_and_orphan_marker_expire_after_the_debug_day() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    enabled(&initial, "lc-history").await;
    put_policy(&initial, "lc-history", BOTH, BOTH_MD5).await;
    let version = id(&put(&initial, "lc-history", "key", b"historic").await);
    let marker = mark(&initial, "lc-history").await;
    drop(initial);

    let (backend, running) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
    let expired = backend.expire_lifecycle_once().await.expect("a valid sweep")
        + backend.expire_lifecycle_once().await.expect("a second valid sweep");
    assert_eq!(expired, 0, "historical removal does not change the current-object expiration count");
    drop(running);
    drop(backend);
    let (_, reopened) = service(&root);
    assert_eq!(named(&reopened, "lc-history", &version).await.status(), 404);
    assert_eq!(named(&reopened, "lc-history", &marker).await.status(), 404);
}

/// Positive: an orphan marker needs no age threshold when the explicit marker action is enabled.
#[tokio::test]
async fn a_marker_without_history_expires_immediately() {
    let root = TestRoot::new();
    let (backend, running) = service(&root);
    enabled(&running, "lc-orphan").await;
    put_policy(&running, "lc-orphan", MARKERS, MARKERS_MD5).await;
    let marker = mark(&running, "lc-orphan").await;
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    assert_eq!(named(&running, "lc-orphan", &marker).await.status(), 404);
}

/// Negative: the marker action alone cannot discard a retained object version.
#[tokio::test]
async fn n_a_marker_with_history_is_not_orphaned() {
    let root = TestRoot::new();
    let (backend, running) = service(&root);
    enabled(&running, "lc-keep-history").await;
    put_policy(&running, "lc-keep-history", MARKERS, MARKERS_MD5).await;
    let version = id(&put(&running, "lc-keep-history", "key", b"historic").await);
    let marker = mark(&running, "lc-keep-history").await;
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    let retained = named(&running, "lc-keep-history", &version).await;
    assert_eq!(retained.status(), 200);
    assert_eq!(retained.body().as_ref(), b"historic");
    assert_eq!(named(&running, "lc-keep-history", &marker).await.status(), 405);
}

/// Negative: a current object is not an expired delete marker.
#[tokio::test]
async fn n_the_marker_action_keeps_a_current_object() {
    let root = TestRoot::new();
    let (backend, running) = service(&root);
    enabled(&running, "lc-keep-current").await;
    put_policy(&running, "lc-keep-current", MARKERS, MARKERS_MD5).await;
    let version = id(&put(&running, "lc-keep-current", "key", b"current").await);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    let retained = named(&running, "lc-keep-current", &version).await;
    assert_eq!(retained.status(), 200);
    assert_eq!(retained.body().as_ref(), b"current");
}

/// Negative: old object bytes do not make a newly noncurrent version old enough to expire.
#[tokio::test]
async fn n_noncurrent_age_starts_at_the_successor() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    enabled(&initial, "lc-successor").await;
    put_policy(&initial, "lc-successor", BOTH, BOTH_MD5).await;
    let version = id(&put(&initial, "lc-successor", "key", b"historic").await);
    drop(initial);
    let (backend, running) = expiring_service(&root, SIGNED_AT_SECONDS + 100);
    let marker = mark(&running, "lc-successor").await;
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    let retained = named(&running, "lc-successor", &version).await;
    assert_eq!(retained.status(), 200);
    assert_eq!(retained.body().as_ref(), b"historic");
    assert_eq!(named(&running, "lc-successor", &marker).await.status(), 405);
}

/// Negative: a newer-noncurrent retention count protects the newest historical object and marker.
#[tokio::test]
async fn n_the_retained_noncurrent_version_prevents_marker_expiration() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    enabled(&initial, "lc-retain").await;
    put_policy(&initial, "lc-retain", RETAIN_ONE, RETAIN_ONE_MD5).await;
    let first = id(&put(&initial, "lc-retain", "key", b"first").await);
    let second = id(&put(&initial, "lc-retain", "key", b"second").await);
    let newest = id(&put(&initial, "lc-retain", "key", b"keep").await);
    let marker = mark(&initial, "lc-retain").await;
    drop(initial);
    let (backend, running) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
    let expired = backend.expire_lifecycle_once().await.expect("a valid sweep")
        + backend.expire_lifecycle_once().await.expect("another valid sweep");
    assert_eq!(expired, 0, "historical removal does not change the current-object expiration count");
    assert_eq!(named(&running, "lc-retain", &first).await.status(), 404);
    assert_eq!(named(&running, "lc-retain", &second).await.status(), 404);
    let retained = named(&running, "lc-retain", &newest).await;
    assert_eq!(retained.status(), 200);
    assert_eq!(retained.body().as_ref(), b"keep");
    assert_eq!(named(&running, "lc-retain", &marker).await.status(), 405);
}

/// Negative: disabled, other-prefix and unmatched-tag rules leave both versions readable.
#[tokio::test]
async fn n_unmatched_rules_preserve_history_and_marker() {
    for (bucket, document, checksum) in [
        ("lc-disabled-history", DISABLED, DISABLED_MD5),
        ("lc-other-prefix", OTHER_PREFIX, OTHER_PREFIX_MD5),
        ("lc-missing-tag", TAGGED, TAGGED_MD5),
    ] {
        let root = TestRoot::new();
        let (_, initial) = service(&root);
        enabled(&initial, bucket).await;
        put_policy(&initial, bucket, document, checksum).await;
        let version = id(&put(&initial, bucket, "key", b"historic").await);
        let marker = mark(&initial, bucket).await;
        drop(initial);
        let (backend, running) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
        assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0, "{bucket}");
        let retained = named(&running, bucket, &version).await;
        assert_eq!(retained.status(), 200, "{bucket}");
        assert_eq!(retained.body().as_ref(), b"historic", "{bucket}");
        assert_eq!(named(&running, bucket, &marker).await.status(), 405, "{bucket}");
    }
}

/// Negative: a later corrupt policy aborts the preflight before an earlier marker is removed.
#[tokio::test]
async fn n_corrupt_policy_prevents_partial_marker_expiration() {
    let root = TestRoot::new();
    let (backend, running) = service(&root);
    for bucket in ["a-orphan", "z-broken"] {
        enabled(&running, bucket).await;
        put_policy(&running, bucket, MARKERS, MARKERS_MD5).await;
    }
    let marker = mark(&running, "a-orphan").await;
    std::fs::write(super::lifecycle::lifecycle_record(&root, "z-broken"), b"corrupt").expect("write a corrupt policy");
    assert!(backend.expire_lifecycle_once().await.is_err());
    assert_eq!(named(&running, "a-orphan", &marker).await.status(), 405);
}

/// Negative: the newest object stays current while an older noncurrent version expires.
#[tokio::test]
async fn n_noncurrent_expiration_keeps_the_current_object() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    enabled(&initial, "lc-current-history").await;
    put_policy(&initial, "lc-current-history", BOTH, BOTH_MD5).await;
    let old = id(&put(&initial, "lc-current-history", "key", b"old").await);
    let current = id(&put(&initial, "lc-current-history", "key", b"current").await);
    drop(initial);
    let (backend, running) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    assert_eq!(named(&running, "lc-current-history", &old).await.status(), 404);
    let retained = named(&running, "lc-current-history", &current).await;
    assert_eq!(retained.status(), 200);
    assert_eq!(retained.body().as_ref(), b"current");
}

/// Negative: a legacy null-version file still counts as history beneath a marker.
#[tokio::test]
async fn n_a_legacy_object_prevents_orphan_marker_cleanup() {
    let root = TestRoot::new();
    let (backend, running) = service(&root);
    enabled(&running, "lc-legacy-history").await;
    put_policy(&running, "lc-legacy-history", MARKERS, MARKERS_MD5).await;
    let legacy = legacy_object_path(&root, "lc-legacy-history", "key");
    std::fs::write(&legacy, b"legacy bytes").expect("a writable legacy object slot");
    let marker = mark(&running, "lc-legacy-history").await;
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    assert_eq!(named(&running, "lc-legacy-history", &marker).await.status(), 405);
    assert_eq!(std::fs::read(&legacy).expect("retained legacy bytes"), b"legacy bytes");
}

/// Negative: an unsafe legacy path aborts the whole plan before any orphan is removed.
#[cfg(unix)]
#[tokio::test]
async fn n_unsafe_legacy_history_prevents_partial_marker_cleanup() {
    let root = TestRoot::new();
    let (backend, running) = service(&root);
    for bucket in ["a-safe-marker", "z-unsafe-marker"] {
        enabled(&running, bucket).await;
        put_policy(&running, bucket, MARKERS, MARKERS_MD5).await;
    }
    let marker = mark(&running, "a-safe-marker").await;
    mark(&running, "z-unsafe-marker").await;
    let outside_root = TestRoot::new();
    let outside = outside_root.0.join("outside");
    std::fs::write(&outside, b"outside bytes").expect("write the external fixture");
    std::os::unix::fs::symlink(&outside, legacy_object_path(&root, "z-unsafe-marker", "key")).expect("a fixture symlink");
    assert!(backend.expire_lifecycle_once().await.is_err());
    assert_eq!(named(&running, "a-safe-marker", &marker).await.status(), 405);
    assert_eq!(std::fs::read(&outside).expect("the external fixture is intact"), b"outside bytes");
}

/// Negative: normal days round the noncurrent deadline up to UTC midnight, unlike debug days.
#[tokio::test]
async fn n_real_days_wait_until_the_rounded_midnight() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    enabled(&initial, "lc-midnight").await;
    put_policy(&initial, "lc-midnight", BOTH, BOTH_MD5).await;
    let version = id(&put(&initial, "lc-midnight", "key", b"historic").await);
    mark(&initial, "lc-midnight").await;
    drop(initial);
    let elapsed_day = SIGNED_AT_SECONDS + 86400;
    let backend =
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(elapsed_day))).expect("a test backend");
    let (backend, running) = service_with_backend(Arc::new(backend));
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    assert_eq!(named(&running, "lc-midnight", &version).await.status(), 200);
    drop(running);
    drop(backend);
    let midnight = (elapsed_day.div_euclid(86400) + 1) * 86400;
    let backend = FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(midnight))).expect("a test backend");
    let (backend, running) = service_with_backend(Arc::new(backend));
    let expired = backend.expire_lifecycle_once().await.expect("a valid sweep")
        + backend.expire_lifecycle_once().await.expect("another valid sweep");
    assert_eq!(expired, 0, "historical removal does not change the current-object expiration count");
    assert_eq!(named(&running, "lc-midnight", &version).await.status(), 404);
}

/// Negative: ambiguous version ordering fails preflight before any other key is removed.
#[tokio::test]
async fn n_duplicate_version_sequences_prevent_partial_expiration() {
    let root = TestRoot::new();
    let (backend, running) = expiring_service(&root, SIGNED_AT_SECONDS);
    for bucket in ["a-order-marker", "z-order-history"] {
        enabled(&running, bucket).await;
        put_policy(&running, bucket, BOTH, BOTH_MD5).await;
    }
    let marker = mark(&running, "a-order-marker").await;
    put(&running, "z-order-history", "key", b"old").await;
    put(&running, "z-order-history", "key", b"new").await;
    let directory = root.0.join(format!("b-{}", hex::encode("z-order-history"))).join("versions");
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .expect("version directories")
        .map(|entry| entry.expect("a version entry").path().join("record"))
        .collect();
    paths.sort();
    assert_eq!(paths.len(), 2);
    let first = std::fs::read_to_string(&paths[0]).expect("the first record");
    let second = std::fs::read_to_string(&paths[1]).expect("the second record");
    let sequence = first.lines().next().expect("the sequence line");
    let (_, remaining) = second.split_once('\n').expect("the remaining record");
    std::fs::write(&paths[1], format!("{sequence}\n{remaining}")).expect("a duplicate sequence fixture");
    assert!(backend.expire_lifecycle_once().await.is_err());
    assert_eq!(named(&running, "a-order-marker", &marker).await.status(), 405);
}

/// Negative: a corrupt lineage status cannot be ignored just because a key is a marker.
#[tokio::test]
async fn n_corrupt_versioning_status_prevents_partial_marker_cleanup() {
    let root = TestRoot::new();
    let (backend, running) = service(&root);
    for bucket in ["a-lineage-marker", "z-lineage-marker"] {
        enabled(&running, bucket).await;
        put_policy(&running, bucket, MARKERS, MARKERS_MD5).await;
    }
    let marker = mark(&running, "a-lineage-marker").await;
    mark(&running, "z-lineage-marker").await;
    let status = root
        .0
        .join(format!("b-{}", hex::encode("z-lineage-marker")))
        .join("versioning-status");
    std::fs::write(status, b"corrupt").expect("a corrupt lineage status fixture");
    assert!(backend.expire_lifecycle_once().await.is_err());
    assert_eq!(named(&running, "a-lineage-marker", &marker).await.status(), 405);
}
