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

//! Production lifecycle-transition evidence for the filesystem reference backend.
//!
//! Responsible for: proving one-shot current-object transition eligibility, persisted storage
//! class projection, and fail-closed preflight. NOT responsible for: scheduling, physical storage
//! tiers, expiration, or noncurrent-version actions. Upstream: persisted lifecycle and version
//! authorities. Downstream: the reference SUT lifecycle worker and crate verification gate.

use super::*;
use std::time::Duration;

pub(super) const DUE: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>transition</ID>",
    "<Filter><ObjectSizeGreaterThan>0</ObjectSizeGreaterThan></Filter><Status>Enabled</Status>",
    "<Transition><Days>1</Days><StorageClass>STANDARD_IA</StorageClass></Transition>",
    "</Rule></LifecycleConfiguration>"
);
pub(super) const DUE_MD5: &str = "sp/PIPFyK5jT4pPI0eh1BA==";
const ABSOLUTE_DATE: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>transition-date</ID>",
    "<Filter><ObjectSizeGreaterThan>0</ObjectSizeGreaterThan></Filter><Status>Enabled</Status>",
    "<Transition><Date>2026-01-03T00:00:00Z</Date><StorageClass>DEEP_ARCHIVE</StorageClass></Transition>",
    "</Rule></LifecycleConfiguration>"
);
const ABSOLUTE_DATE_MD5: &str = "/Ix/BwLMlrMFiVZpeFV+eA==";
const PREFIX_ONLY: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>transition-prefix</ID><Filter><And><Prefix>cold/</Prefix>",
    "<ObjectSizeGreaterThan>0</ObjectSizeGreaterThan></And></Filter>",
    "<Status>Enabled</Status><Transition><Days>1</Days><StorageClass>STANDARD_IA</StorageClass></Transition>",
    "</Rule></LifecycleConfiguration>"
);
const PREFIX_ONLY_MD5: &str = "/WK3IEFADgBkqcnVXceKbQ==";
const DISABLED: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>transition-disabled</ID>",
    "<Filter><ObjectSizeGreaterThan>0</ObjectSizeGreaterThan></Filter><Status>Disabled</Status>",
    "<Transition><Days>1</Days><StorageClass>STANDARD_IA</StorageClass></Transition>",
    "</Rule></LifecycleConfiguration>"
);
const DISABLED_MD5: &str = "Ra/CRC23/B/G7tjvFnCC3Q==";
const DEFAULT_SMALL: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>transition-small</ID><Filter><Prefix></Prefix></Filter>",
    "<Status>Enabled</Status><Transition><Days>1</Days><StorageClass>STANDARD_IA</StorageClass></Transition>",
    "</Rule></LifecycleConfiguration>"
);
const DEFAULT_SMALL_MD5: &str = "I5ZKiqN252oAb44lJTzLuw==";
const SMALL_GLACIER: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>transition-glacier</ID><Filter><Prefix></Prefix></Filter>",
    "<Status>Enabled</Status><Transition><Days>1</Days><StorageClass>GLACIER</StorageClass></Transition>",
    "</Rule></LifecycleConfiguration>"
);
const SMALL_GLACIER_MD5: &str = "V5HXHaFNf21p8Eoamw3vig==";
const UNKNOWN_CLASS: &str = concat!(
    "<LifecycleConfiguration><Rule><ID>transition-unknown</ID>",
    "<Filter><ObjectSizeGreaterThan>0</ObjectSizeGreaterThan></Filter><Status>Enabled</Status>",
    "<Transition><Days>1</Days><StorageClass>UNKNOWN_TIER</StorageClass></Transition>",
    "</Rule></LifecycleConfiguration>"
);
const UNKNOWN_CLASS_MD5: &str = "dTS9dzMSNgQ5lRbmD6Dgcg==";

pub(super) fn transitioning_service(root: &TestRoot, now: i64) -> (Arc<FsBackend>, S3Service) {
    let backend = FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(now)))
        .expect("a usable test root")
        .with_lifecycle_debug_interval(Duration::from_secs(1))
        .expect("a non-zero debug interval");
    service_with_backend(Arc::new(backend))
}

pub(super) async fn put_policy(
    service: &S3Service,
    bucket: &str,
    document: &'static str,
    checksum: &'static str,
    minimum: Option<&'static str>,
) {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-md5", http::HeaderValue::from_static(checksum));
    if let Some(minimum) = minimum {
        headers.insert("x-amz-transition-default-minimum-object-size", http::HeaderValue::from_static(minimum));
    }
    let response = exchange(
        service,
        signed_with_headers(
            http::Method::PUT,
            &format!("/{bucket}?lifecycle"),
            Bytes::from_static(document.as_bytes()),
            headers,
        ),
    )
    .await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
}

async fn get(service: &S3Service, bucket: &str, key: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::GET, &format!("/{bucket}/{key}"), Bytes::new())).await
}

async fn head(service: &S3Service, bucket: &str, key: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::HEAD, &format!("/{bucket}/{key}"), Bytes::new())).await
}

async fn list(service: &S3Service, bucket: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::GET, &format!("/{bucket}"), Bytes::new())).await
}

fn only_version_record(root: &TestRoot, bucket: &str) -> PathBuf {
    let versions = root.0.join(format!("b-{}", hex::encode(bucket.as_bytes()))).join("versions");
    std::fs::read_dir(versions)
        .expect("a version directory")
        .map(|entry| entry.expect("a version entry").path())
        .find(|path| path.file_name().is_some_and(|name| name.to_string_lossy().starts_with("v-")))
        .expect("one version record")
        .join("record")
}

/// Positive — a due current transition persists without changing object identity or bytes.
#[tokio::test]
async fn due_transition_survives_restart_and_projects_one_storage_class() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-transition").await;
    assert_eq!(
        super::multipart_versioning::set_versioning(&initial, "lc-transition", "Enabled")
            .await
            .status(),
        200
    );
    put_policy(&initial, "lc-transition", DUE, DUE_MD5, None).await;
    let stored = super::lifecycle_expiration::put(&initial, "lc-transition", "key", b"body").await;
    let version_id = header(&stored, "x-amz-version-id").expect("a version id").clone();
    let before = get(&initial, "lc-transition", "key").await;
    let before_etag = header(&before, "etag").expect("an entity tag").clone();
    let before_modified = header(&before, "last-modified").expect("a modification time").clone();
    drop(initial);

    let (backend, transitioned) = transitioning_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.transition_lifecycle_once().await.expect("a valid sweep"), 1);
    let fetched = get(&transitioned, "lc-transition", "key").await;
    assert_eq!(fetched.status(), 200);
    assert_eq!(fetched.body().as_ref(), b"body");
    assert_eq!(
        header(&fetched, "x-amz-storage-class"),
        Some(&http::HeaderValue::from_static("STANDARD_IA"))
    );
    assert_eq!(header(&fetched, "x-amz-version-id"), Some(&version_id));
    assert_eq!(header(&fetched, "etag"), Some(&before_etag));
    assert_eq!(header(&fetched, "last-modified"), Some(&before_modified));
    assert_eq!(
        header(&head(&transitioned, "lc-transition", "key").await, "x-amz-storage-class"),
        Some(&http::HeaderValue::from_static("STANDARD_IA"))
    );
    drop(transitioned);

    let (_, reopened) = service(&root);
    let listing = list(&reopened, "lc-transition").await;
    assert_eq!(element(listing.body(), "StorageClass").as_deref(), Some("STANDARD_IA"));
}

/// Positive — a Date action becomes due at its absolute midnight boundary.
#[tokio::test]
async fn absolute_date_transition_applies_at_the_named_instant() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-transition-date").await;
    put_policy(&initial, "lc-transition-date", ABSOLUTE_DATE, ABSOLUTE_DATE_MD5, None).await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "lc-transition-date", "key", b"body")
            .await
            .status(),
        200
    );
    drop(initial);

    let (backend, transitioned) = transitioning_service(&root, 1_767_398_400);
    assert_eq!(backend.transition_lifecycle_once().await.expect("a valid sweep"), 1);
    assert_eq!(
        header(&get(&transitioned, "lc-transition-date", "key").await, "x-amz-storage-class"),
        Some(&http::HeaderValue::from_static("DEEP_ARCHIVE"))
    );
}

/// Positive — the historical small-object mode still allows Glacier transitions below 128 KiB.
#[tokio::test]
async fn varies_by_storage_class_allows_a_small_glacier_transition() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-transition-glacier").await;
    put_policy(
        &initial,
        "lc-transition-glacier",
        SMALL_GLACIER,
        SMALL_GLACIER_MD5,
        Some("varies_by_storage_class"),
    )
    .await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "lc-transition-glacier", "key", b"tiny")
            .await
            .status(),
        200
    );
    drop(initial);

    let (backend, transitioned) = transitioning_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.transition_lifecycle_once().await.expect("a valid sweep"), 1);
    assert_eq!(
        header(&get(&transitioned, "lc-transition-glacier", "key").await, "x-amz-storage-class"),
        Some(&http::HeaderValue::from_static("GLACIER"))
    );
}

/// Negative — a transition whose age has not elapsed leaves the object in STANDARD.
#[tokio::test]
async fn n_not_yet_due_transition_remains_inert() {
    let root = TestRoot::new();
    let (backend, running) = transitioning_service(&root, SIGNED_AT_SECONDS);
    create_bucket(&running, "lc-transition-young").await;
    put_policy(&running, "lc-transition-young", DUE, DUE_MD5, None).await;
    assert_eq!(
        super::lifecycle_expiration::put(&running, "lc-transition-young", "key", b"young")
            .await
            .status(),
        200
    );

    assert_eq!(backend.transition_lifecycle_once().await.expect("a valid sweep"), 0);
    assert!(header(&get(&running, "lc-transition-young", "key").await, "x-amz-storage-class").is_none());
    assert_eq!(
        element(list(&running, "lc-transition-young").await.body(), "StorageClass").as_deref(),
        Some("STANDARD")
    );
}

/// Negative — the current default blocks transitions for objects smaller than 128 KiB.
#[tokio::test]
async fn n_default_minimum_blocks_a_small_object() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-transition-small").await;
    put_policy(&initial, "lc-transition-small", DEFAULT_SMALL, DEFAULT_SMALL_MD5, None).await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "lc-transition-small", "key", b"tiny")
            .await
            .status(),
        200
    );
    drop(initial);

    let (backend, running) = transitioning_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.transition_lifecycle_once().await.expect("a valid sweep"), 0);
    assert!(header(&get(&running, "lc-transition-small", "key").await, "x-amz-storage-class").is_none());
}

/// Negative — disabled transition rules never mutate matching objects.
#[tokio::test]
async fn n_disabled_transition_remains_inert() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-transition-disabled").await;
    put_policy(&initial, "lc-transition-disabled", DISABLED, DISABLED_MD5, None).await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "lc-transition-disabled", "key", b"body")
            .await
            .status(),
        200
    );
    drop(initial);

    let (backend, running) = transitioning_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.transition_lifecycle_once().await.expect("a valid sweep"), 0);
    assert!(header(&get(&running, "lc-transition-disabled", "key").await, "x-amz-storage-class").is_none());
}

/// Negative — a due action cannot cross its rule prefix.
#[tokio::test]
async fn n_prefix_mismatch_remains_in_standard() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-transition-prefix").await;
    put_policy(&initial, "lc-transition-prefix", PREFIX_ONLY, PREFIX_ONLY_MD5, None).await;
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "lc-transition-prefix", "keep/key", b"body")
            .await
            .status(),
        200
    );
    drop(initial);

    let (backend, running) = transitioning_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.transition_lifecycle_once().await.expect("a valid sweep"), 0);
    assert!(header(&get(&running, "lc-transition-prefix", "keep/key").await, "x-amz-storage-class").is_none());
}

/// Negative — an unsupported target aborts global preflight before another bucket changes.
#[tokio::test]
async fn n_unsupported_target_prevents_partial_transition() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    for (bucket, policy, checksum) in [
        ("a-transitionable", DUE, DUE_MD5),
        ("z-unsupported", UNKNOWN_CLASS, UNKNOWN_CLASS_MD5),
    ] {
        create_bucket(&initial, bucket).await;
        put_policy(&initial, bucket, policy, checksum, None).await;
        assert_eq!(
            super::lifecycle_expiration::put(&initial, bucket, "key", b"body")
                .await
                .status(),
            200
        );
    }
    drop(initial);

    let (backend, running) = transitioning_service(&root, SIGNED_AT_SECONDS + 1);
    assert!(backend.transition_lifecycle_once().await.is_err());
    assert!(header(&get(&running, "a-transitionable", "key").await, "x-amz-storage-class").is_none());
}

/// Negative — a corrupt persisted class aborts preflight before another bucket is rewritten.
#[tokio::test]
async fn n_corrupt_storage_class_prevents_partial_transition() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    for bucket in ["a-transitionable", "z-corrupt-class"] {
        create_bucket(&initial, bucket).await;
        put_policy(&initial, bucket, DUE, DUE_MD5, None).await;
        assert_eq!(
            super::lifecycle_expiration::put(&initial, bucket, "key", b"body")
                .await
                .status(),
            200
        );
    }
    let record = only_version_record(&root, "z-corrupt-class");
    let encoded = std::fs::read_to_string(&record).expect("a persisted version record");
    let mut lines = encoded.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 8, "the fixture targets only the storage-class field");
    lines[7] = "not-hex";
    std::fs::write(record, format!("{}\n", lines.join("\n"))).expect("the exact fixture record is writable");
    drop(initial);

    let (backend, running) = transitioning_service(&root, SIGNED_AT_SECONDS + 1);
    assert!(backend.transition_lifecycle_once().await.is_err());
    assert!(header(&get(&running, "a-transitionable", "key").await, "x-amz-storage-class").is_none());
}

/// Negative — a current-version transition never changes an older explicit version.
#[tokio::test]
async fn n_historical_version_remains_in_standard() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-transition-history").await;
    assert_eq!(
        super::multipart_versioning::set_versioning(&initial, "lc-transition-history", "Enabled")
            .await
            .status(),
        200
    );
    put_policy(&initial, "lc-transition-history", DUE, DUE_MD5, None).await;
    let old = super::lifecycle_expiration::put(&initial, "lc-transition-history", "key", b"old").await;
    let old_id = header(&old, "x-amz-version-id")
        .expect("an old version id")
        .to_str()
        .expect("an ASCII version id")
        .to_owned();
    assert_eq!(
        super::lifecycle_expiration::put(&initial, "lc-transition-history", "key", b"new")
            .await
            .status(),
        200
    );
    drop(initial);

    let (backend, running) = transitioning_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.transition_lifecycle_once().await.expect("a valid sweep"), 1);
    let old = exchange(
        &running,
        signed(http::Method::GET, &format!("/lc-transition-history/key?versionId={old_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(old.status(), 200);
    assert_eq!(old.body().as_ref(), b"old");
    assert!(header(&old, "x-amz-storage-class").is_none());
    assert_eq!(
        header(&get(&running, "lc-transition-history", "key").await, "x-amz-storage-class"),
        Some(&http::HeaderValue::from_static("STANDARD_IA"))
    );
    let versions = exchange(&running, signed(http::Method::GET, "/lc-transition-history?versions", Bytes::new())).await;
    let versions = std::str::from_utf8(versions.body()).expect("version listing XML is UTF-8");
    assert!(versions.contains("<StorageClass>STANDARD_IA</StorageClass>"));
    assert!(versions.contains("<StorageClass>STANDARD</StorageClass>"));
}
