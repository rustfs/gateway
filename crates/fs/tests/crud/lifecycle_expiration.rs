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

//! Production lifecycle-expiration evidence for the filesystem reference backend.
//!
//! Responsible for: proving one-shot expiration, debug-day timing, version-aware deletion, and
//! fail-closed rule selection. NOT responsible for: transition actions, tag persistence, or the
//! eventual CLI scheduler. Upstream: persisted lifecycle rules and current version records.
//! Downstream: the reference SUT lifecycle worker and crate verification gate.

use super::*;
use std::time::Duration;

pub(super) const EXPIRE_ALL: &str = concat!(
    "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration>",
    "<ID>expire-all</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>",
    "</Rule></LifecycleConfiguration>"
);
pub(super) const EXPIRE_ALL_MD5: &str = "5Y4m5g4gmXjRJtprF5EAXA==";
const PREFIX_ONLY: &str = concat!(
    "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration>",
    "<ID>prefix</ID><Filter><Prefix>expire/</Prefix></Filter><Status>Enabled</Status>",
    "</Rule></LifecycleConfiguration>"
);
const PREFIX_ONLY_MD5: &str = "DnUlJwn0zZSDrikMsnE8mA==";
const DISABLED: &str = concat!(
    "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration>",
    "<ID>disabled</ID><Filter><Prefix></Prefix></Filter><Status>Disabled</Status>",
    "</Rule></LifecycleConfiguration>"
);
const DISABLED_MD5: &str = "16u1mDbNZoXJvYcnJcm/Cg==";
pub(super) const TAG_FILTER: &str = concat!(
    "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration>",
    "<ID>tagged</ID><Filter><Tag><Key>class</Key><Value>cold</Value></Tag></Filter>",
    "<Status>Enabled</Status></Rule></LifecycleConfiguration>"
);
pub(super) const TAG_FILTER_MD5: &str = "jl1qkZQCtXbDvMqI6nKFmQ==";
const ABSOLUTE_DATE: &str = concat!(
    "<LifecycleConfiguration><Rule><Expiration><Date>2026-01-03T00:00:00Z</Date></Expiration>",
    "<ID>absolute</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>",
    "</Rule></LifecycleConfiguration>"
);
const ABSOLUTE_DATE_MD5: &str = "tl6Lle6lod/PTV3hK+KhIg==";
const SIZE_RANGE: &str = concat!(
    "<LifecycleConfiguration><Rule><Expiration><Days>1</Days></Expiration><ID>sized</ID>",
    "<Filter><And><Prefix></Prefix><ObjectSizeGreaterThan>4</ObjectSizeGreaterThan>",
    "<ObjectSizeLessThan>6</ObjectSizeLessThan></And></Filter><Status>Enabled</Status>",
    "</Rule></LifecycleConfiguration>"
);
const SIZE_RANGE_MD5: &str = "Xx+floLOQ0bsQ+8iTfI+Zg==";

pub(super) fn expiring_service(root: &TestRoot, now: i64) -> (Arc<FsBackend>, S3Service) {
    let backend = FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(now)))
        .expect("a usable test root")
        .with_lifecycle_debug_interval(Duration::from_secs(1))
        .expect("a non-zero debug interval");
    service_with_backend(Arc::new(backend))
}

pub(super) async fn put_policy(service: &S3Service, bucket: &str, document: &'static str, checksum: &'static str) {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-md5", http::HeaderValue::from_static(checksum));
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

pub(super) async fn put(service: &S3Service, bucket: &str, key: &str, body: &'static [u8]) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::PUT, &format!("/{bucket}/{key}"), Bytes::from_static(body))).await
}

pub(super) async fn get(service: &S3Service, bucket: &str, key: &str) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::GET, &format!("/{bucket}/{key}"), Bytes::new())).await
}

/// Positive — one debug-day expires an unversioned current object after restart.
#[tokio::test]
async fn one_debug_day_expires_an_unversioned_object() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-expire").await;
    put_policy(&initial, "lc-expire", EXPIRE_ALL, EXPIRE_ALL_MD5).await;
    assert_eq!(put(&initial, "lc-expire", "key", b"body").await.status(), 200);
    drop(initial);

    let (backend, reopened) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 1);
    assert_eq!(get(&reopened, "lc-expire", "key").await.status(), 404);
}

/// Positive — expiration in an enabled bucket adds a current delete marker and retains history.
#[tokio::test]
async fn versioned_expiration_retains_the_explicit_object_version() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-versioned").await;
    assert_eq!(
        super::multipart_versioning::set_versioning(&initial, "lc-versioned", "Enabled")
            .await
            .status(),
        200
    );
    put_policy(&initial, "lc-versioned", EXPIRE_ALL, EXPIRE_ALL_MD5).await;
    let stored = put(&initial, "lc-versioned", "key", b"historic").await;
    let version_id = header(&stored, "x-amz-version-id")
        .expect("an enabled version id")
        .to_str()
        .expect("an ASCII version id")
        .to_owned();
    drop(initial);

    let (backend, reopened) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 1);
    assert_eq!(get(&reopened, "lc-versioned", "key").await.status(), 404);
    let explicit = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/lc-versioned/key?versionId={version_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(explicit.status(), 200);
    assert_eq!(explicit.body().as_ref(), b"historic");
}

/// Positive — an absolute expiration date is evaluated against the injected wall clock.
#[tokio::test]
async fn absolute_date_expires_after_its_instant() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-date").await;
    put_policy(&initial, "lc-date", ABSOLUTE_DATE, ABSOLUTE_DATE_MD5).await;
    assert_eq!(put(&initial, "lc-date", "key", b"body").await.status(), 200);
    drop(initial);

    let (backend, reopened) = expiring_service(&root, 1_767_398_400);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 1);
    assert_eq!(get(&reopened, "lc-date", "key").await.status(), 404);
}

/// Negative — a matching object remains visible before one debug-day has elapsed.
#[tokio::test]
async fn n_not_yet_old_enough_remains_visible() {
    let root = TestRoot::new();
    let (backend, running) = expiring_service(&root, SIGNED_AT_SECONDS);
    create_bucket(&running, "lc-young").await;
    put_policy(&running, "lc-young", EXPIRE_ALL, EXPIRE_ALL_MD5).await;
    assert_eq!(put(&running, "lc-young", "key", b"young").await.status(), 200);

    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    assert_eq!(get(&running, "lc-young", "key").await.status(), 200);
}

/// Negative — an expired object outside a rule prefix remains visible.
#[tokio::test]
async fn n_prefix_mismatch_remains_visible() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-prefix").await;
    put_policy(&initial, "lc-prefix", PREFIX_ONLY, PREFIX_ONLY_MD5).await;
    assert_eq!(put(&initial, "lc-prefix", "keep/key", b"body").await.status(), 200);
    drop(initial);

    let (backend, reopened) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    assert_eq!(get(&reopened, "lc-prefix", "keep/key").await.status(), 200);
}

/// Negative — disabled rules never participate in expiration.
#[tokio::test]
async fn n_disabled_rule_remains_inert() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-disabled").await;
    put_policy(&initial, "lc-disabled", DISABLED, DISABLED_MD5).await;
    assert_eq!(put(&initial, "lc-disabled", "key", b"body").await.status(), 200);
    drop(initial);

    let (backend, reopened) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    assert_eq!(get(&reopened, "lc-disabled", "key").await.status(), 200);
}

/// Negative — an untagged object never satisfies a tag-filtered rule.
#[tokio::test]
async fn n_untagged_object_never_matches_a_tag_filter() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-tagged").await;
    put_policy(&initial, "lc-tagged", TAG_FILTER, TAG_FILTER_MD5).await;
    assert_eq!(put(&initial, "lc-tagged", "key", b"body").await.status(), 200);
    drop(initial);

    let (backend, reopened) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 0);
    assert_eq!(get(&reopened, "lc-tagged", "key").await.status(), 200);
}

/// Negative — lifecycle size boundaries are strict on both sides of a matching object.
#[tokio::test]
async fn n_size_boundaries_do_not_expire_equal_sized_objects() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "lc-size").await;
    put_policy(&initial, "lc-size", SIZE_RANGE, SIZE_RANGE_MD5).await;
    for (key, body) in [
        ("lower", b"four".as_slice()),
        ("match", b"fives".as_slice()),
        ("upper", b"sixes!".as_slice()),
    ] {
        assert_eq!(put(&initial, "lc-size", key, body).await.status(), 200);
    }
    drop(initial);

    let (backend, reopened) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert_eq!(backend.expire_lifecycle_once().await.expect("a valid sweep"), 1);
    assert_eq!(get(&reopened, "lc-size", "lower").await.status(), 200);
    assert_eq!(get(&reopened, "lc-size", "match").await.status(), 404);
    assert_eq!(get(&reopened, "lc-size", "upper").await.status(), 200);
}

/// Negative — a corrupt policy aborts preflight before any other bucket is modified.
#[tokio::test]
async fn n_corrupt_policy_prevents_partial_expiration() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    for bucket in ["a-expirable", "z-corrupt"] {
        create_bucket(&initial, bucket).await;
        put_policy(&initial, bucket, EXPIRE_ALL, EXPIRE_ALL_MD5).await;
    }
    assert_eq!(put(&initial, "a-expirable", "key", b"body").await.status(), 200);
    std::fs::write(super::lifecycle::lifecycle_record(&root, "z-corrupt"), b"corrupt")
        .expect("the exact policy authority is writable");
    drop(initial);

    let (backend, reopened) = expiring_service(&root, SIGNED_AT_SECONDS + 1);
    assert!(backend.expire_lifecycle_once().await.is_err());
    assert_eq!(get(&reopened, "a-expirable", "key").await.status(), 200);
}
