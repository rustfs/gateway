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

//! Signed production-service evidence for persistent object versioning.
//!
//! Responsible for: enabled/suspended transitions, opaque versions, delete markers, restart
//! persistence, deterministic census ordering, and pre-publication refusal of invalid legacy paths.
//! NOT responsible for: lifecycle, multipart version publication, copy, tags, or ordinary listing.
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

use super::*;

fn versioning_document(status: &str) -> Bytes {
    Bytes::from(format!(
        "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>{status}</Status></VersioningConfiguration>"
    ))
}

async fn create_bucket(service: &S3Service, bucket: &str) {
    assert_eq!(
        exchange(service, signed(http::Method::PUT, &format!("/{bucket}"), Bytes::new()))
            .await
            .status(),
        200
    );
}

async fn set_versioning(service: &S3Service, bucket: &str, status: &str) -> rustfs_gateway::WireResponse {
    let checksum = match status {
        "Enabled" => "QQFYoy/mRYV9PGZUfFi0Bw==",
        "Suspended" => "orZUUp7E9srl53Od8p1glA==",
        _ => "invalid-test-checksum",
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("content-md5"),
        http::HeaderValue::from_str(checksum).expect("a fixture checksum header"),
    );
    exchange(
        service,
        signed_with_headers(http::Method::PUT, &format!("/{bucket}?versioning"), versioning_document(status), headers),
    )
    .await
}

async fn put(service: &S3Service, bucket: &str, key: &str, body: &'static [u8]) -> rustfs_gateway::WireResponse {
    exchange(service, signed(http::Method::PUT, &format!("/{bucket}/{key}"), Bytes::from_static(body))).await
}

fn body(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn header_text<'a>(response: &'a rustfs_gateway::WireResponse, name: &str) -> Option<&'a str> {
    header(response, name).and_then(|value| value.to_str().ok())
}

/// Positive — enabled versions remain addressable, ordered, and durable across a reopen.
#[tokio::test]
async fn enabled_versions_and_delete_markers_survive_restart() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "archive").await;
    let enabled = set_versioning(&running, "archive", "Enabled").await;
    assert_eq!(enabled.status(), 200, "{}", body(&enabled));
    let configured = exchange(&running, signed(http::Method::GET, "/archive?versioning", Bytes::new())).await;
    assert_eq!(configured.status(), 200);
    assert!(body(&configured).contains("<Status>Enabled</Status>"));

    let first = put(&running, "archive", "report", b"first").await;
    let first_id = header_text(&first, "x-amz-version-id")
        .expect("enabled puts return an id")
        .to_owned();
    let second = put(&running, "archive", "report", b"second").await;
    let second_id = header_text(&second, "x-amz-version-id")
        .expect("enabled puts return an id")
        .to_owned();
    assert_ne!(first_id, second_id);
    assert_eq!(
        exchange(&running, signed(http::Method::GET, "/archive/report", Bytes::new()))
            .await
            .body()
            .as_ref(),
        b"second"
    );
    assert_eq!(
        exchange(
            &running,
            signed(http::Method::GET, &format!("/archive/report?versionId={first_id}"), Bytes::new(),),
        )
        .await
        .body()
        .as_ref(),
        b"first"
    );

    let census = exchange(&running, signed(http::Method::GET, "/archive?versions", Bytes::new())).await;
    let census_body = body(&census);
    assert_eq!(census.status(), 200, "{census_body}");
    assert!(census_body.find(&second_id) < census_body.find(&first_id));
    assert!(census_body.contains("<LastModified>2026-01-02T03:04:05.000Z</LastModified>"));

    let deleted = exchange(&running, signed(http::Method::DELETE, "/archive/report", Bytes::new())).await;
    assert_eq!(deleted.status(), 204);
    assert_eq!(header_text(&deleted, "x-amz-delete-marker"), Some("true"));
    let marker_id = header_text(&deleted, "x-amz-version-id").expect("a marker id").to_owned();
    drop(running);

    let (_, reopened) = service(&root);
    assert_eq!(
        exchange(&reopened, signed(http::Method::GET, "/archive/report", Bytes::new()))
            .await
            .status(),
        404
    );
    assert_eq!(
        exchange(
            &reopened,
            signed(http::Method::DELETE, &format!("/archive/report?versionId={marker_id}"), Bytes::new(),),
        )
        .await
        .status(),
        204
    );
    assert_eq!(
        exchange(&reopened, signed(http::Method::GET, "/archive/report", Bytes::new()))
            .await
            .body()
            .as_ref(),
        b"second"
    );
    let after_delete = put(&reopened, "archive", "report", b"third").await;
    assert_ne!(header_text(&after_delete, "x-amz-version-id").expect("a later version id"), marker_id);
}

/// Negative — an unconfigured backend omits Owner instead of serializing an empty owner record.
#[tokio::test]
async fn n_unconfigured_owner_is_absent_from_version_census() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "owner-absent").await;
    assert_eq!(set_versioning(&service, "owner-absent", "Enabled").await.status(), 200);
    assert_eq!(put(&service, "owner-absent", "key", b"body").await.status(), 200);

    let census = exchange(&service, signed(http::Method::GET, "/owner-absent?versions", Bytes::new())).await;
    let census_body = body(&census);
    assert_eq!(census.status(), 200, "{census_body}");
    assert!(!census_body.contains("<Owner>"), "{census_body}");
}

/// Positive — every object version and delete marker carries the backend's configured owner.
#[tokio::test]
async fn configured_owner_covers_every_version_and_delete_marker() {
    let root = TestRoot::new();
    let backend = Arc::new(
        FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS)))
            .expect("a usable test root")
            .with_owner("version-owner", "Version Owner"),
    );
    let (_, service) = service_with_backend(backend);
    create_bucket(&service, "owned-versions").await;
    assert_eq!(set_versioning(&service, "owned-versions", "Enabled").await.status(), 200);
    assert_eq!(put(&service, "owned-versions", "key", b"one").await.status(), 200);
    assert_eq!(put(&service, "owned-versions", "key", b"two").await.status(), 200);
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/owned-versions/key", Bytes::new()),)
            .await
            .status(),
        204
    );

    let census = exchange(&service, signed(http::Method::GET, "/owned-versions?versions", Bytes::new())).await;
    let census_body = body(&census);
    assert_eq!(census.status(), 200, "{census_body}");
    assert_eq!(census_body.matches("<ID>version-owner</ID>").count(), 3, "{census_body}");
    assert_eq!(
        census_body.matches("<DisplayName>Version Owner</DisplayName>").count(),
        3,
        "{census_body}"
    );
}

/// Positive — suspension replaces only the null version and preserves prior opaque versions.
#[tokio::test]
async fn suspension_keeps_opaque_history_and_replaces_null_current() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "suspended").await;
    assert_eq!(set_versioning(&service, "suspended", "Enabled").await.status(), 200);
    let historic = put(&service, "suspended", "key", b"historic").await;
    let historic_id = header_text(&historic, "x-amz-version-id").expect("an opaque id").to_owned();
    assert_eq!(set_versioning(&service, "suspended", "Suspended").await.status(), 200);
    assert_eq!(
        header_text(&put(&service, "suspended", "key", b"null-one").await, "x-amz-version-id"),
        Some("null")
    );
    assert_eq!(
        header_text(&put(&service, "suspended", "key", b"null-two").await, "x-amz-version-id"),
        Some("null")
    );
    let census = body(&exchange(&service, signed(http::Method::GET, "/suspended?versions", Bytes::new())).await);
    assert_eq!(census.matches("<VersionId>null</VersionId>").count(), 1);
    assert!(census.contains(&historic_id));
    assert_eq!(
        exchange(
            &service,
            signed(http::Method::GET, &format!("/suspended/key?versionId={historic_id}"), Bytes::new(),),
        )
        .await
        .body()
        .as_ref(),
        b"historic"
    );
}

/// Negative — an unknown explicit version fails as `NoSuchVersion` for GET and HEAD.
#[tokio::test]
async fn unknown_explicit_versions_fail_closed() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "missing").await;
    for method in [http::Method::GET, http::Method::HEAD] {
        let is_get = method == http::Method::GET;
        let response = exchange(&service, signed(method, "/missing/key?versionId=does-not-exist", Bytes::new())).await;
        assert_eq!(response.status(), 404);
        if is_get {
            assert!(body(&response).contains("<Code>NoSuchVersion</Code>"));
        } else {
            assert!(response.body().is_empty());
        }
    }
}

/// Negative — a delete marker cannot be read as an empty object.
#[tokio::test]
async fn explicit_delete_marker_get_is_method_not_allowed() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "markers").await;
    assert_eq!(set_versioning(&service, "markers", "Enabled").await.status(), 200);
    let marker = exchange(&service, signed(http::Method::DELETE, "/markers/key", Bytes::new())).await;
    let marker_id = header_text(&marker, "x-amz-version-id").expect("a marker id");
    let response = exchange(
        &service,
        signed(http::Method::GET, &format!("/markers/key?versionId={marker_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(response.status(), 405, "{}", body(&response));
    assert!(body(&response).contains("<Code>MethodNotAllowed</Code>"));
}

/// Negative — a version id minted for another key discloses no object bytes.
#[tokio::test]
async fn a_version_id_is_bound_to_its_key() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "binding").await;
    assert_eq!(set_versioning(&service, "binding", "Enabled").await.status(), 200);
    let stored = put(&service, "binding", "one", b"secret body").await;
    let id = header_text(&stored, "x-amz-version-id").expect("an opaque id");
    let response = exchange(&service, signed(http::Method::GET, &format!("/binding/two?versionId={id}"), Bytes::new())).await;
    assert_eq!(response.status(), 404);
    assert!(!body(&response).contains("secret body"));
}

/// Negative — a corrupt persisted status never silently disables version retention.
#[tokio::test]
async fn corrupt_persisted_status_fails_closed_after_restart() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "corrupt").await;
    assert_eq!(set_versioning(&running, "corrupt", "Enabled").await.status(), 200);
    drop(running);
    let bucket = root.0.join(format!("b-{}", hex::encode("corrupt")));
    std::fs::write(bucket.join("versioning-status"), b"Broken\n").expect("the exact fixture status is corruptible");
    let (_, reopened) = service(&root);
    let response = put(&reopened, "corrupt", "key", b"must-not-publish").await;
    assert_eq!(response.status(), 500);
    assert_eq!(
        exchange(&reopened, signed(http::Method::GET, "/corrupt/key", Bytes::new()))
            .await
            .status(),
        500
    );
}

/// Negative — a symlink cannot replace the persistent version record directory.
#[cfg(unix)]
#[tokio::test]
async fn symlinked_version_storage_is_refused() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "linked-versions").await;
    let versions = root.0.join(format!("b-{}", hex::encode("linked-versions"))).join("versions");
    std::fs::remove_dir(&versions).expect("the empty version directory is removable");
    symlink(&outside.0, &versions).expect("a test symlink");
    let response = put(&service, "linked-versions", "key", b"outside").await;
    assert_eq!(response.status(), 400);
    assert!(!outside.0.join("body").exists());
}

/// Negative — a legacy symlink is refused before a replacement null version becomes current.
#[cfg(unix)]
#[tokio::test]
async fn n_put_preflights_symlinked_legacy_path_before_publishing_null_version() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "legacy-link-put").await;
    assert_eq!(put(&service, "legacy-link-put", "key", b"previous").await.status(), 200);

    let outside_file = outside.0.join("outside");
    std::fs::write(&outside_file, b"outside sentinel").expect("the outside fixture is writable");
    let legacy = legacy_object_path(&root, "legacy-link-put", "key");
    symlink(&outside_file, &legacy).expect("the legacy fixture symlink is creatable");

    let failed = put(&service, "legacy-link-put", "key", b"must-not-publish").await;
    assert_eq!(failed.status(), 400, "{}", body(&failed));
    assert!(body(&failed).contains("<Code>InvalidRequest</Code>"));
    assert_eq!(
        std::fs::read(&outside_file).expect("the outside fixture remains readable"),
        b"outside sentinel"
    );

    let current = exchange(&service, signed(http::Method::GET, "/legacy-link-put/key", Bytes::new())).await;
    assert_eq!(current.status(), 200, "{}", body(&current));
    assert_eq!(current.body().as_ref(), b"previous");
}

/// Negative — another invalid legacy file type is refused without replacing the readable object.
#[tokio::test]
async fn n_put_preflights_non_file_legacy_path_before_publishing_null_version() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "legacy-directory-put").await;
    assert_eq!(put(&service, "legacy-directory-put", "key", b"previous").await.status(), 200);

    let legacy = legacy_object_path(&root, "legacy-directory-put", "key");
    std::fs::create_dir(&legacy).expect("the invalid legacy directory is creatable");
    let failed = put(&service, "legacy-directory-put", "key", b"must-not-publish").await;
    assert_eq!(failed.status(), 400, "{}", body(&failed));
    assert!(legacy.is_dir());

    let current = exchange(&service, signed(http::Method::GET, "/legacy-directory-put/key", Bytes::new())).await;
    assert_eq!(current.status(), 200, "{}", body(&current));
    assert_eq!(current.body().as_ref(), b"previous");
}

/// Negative — a publication failure after a safe preflight retains the prior readable version.
#[tokio::test]
async fn n_put_publication_failure_retains_the_previous_readable_object() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "legacy-publish-failure").await;
    assert_eq!(put(&service, "legacy-publish-failure", "key", b"previous").await.status(), 200);
    let legacy = legacy_object_path(&root, "legacy-publish-failure", "key");
    std::fs::write(&legacy, b"safe legacy bytes").expect("the safe legacy fixture is writable");

    let bucket = root.0.join(format!("b-{}", hex::encode("legacy-publish-failure")));
    let sequence = bucket.join("version-sequence");
    std::fs::remove_file(&sequence).expect("the sequence fixture is removable");
    std::fs::create_dir(&sequence).expect("the invalid sequence fixture is creatable");

    let failed = put(&service, "legacy-publish-failure", "key", b"must-not-publish").await;
    assert_eq!(failed.status(), 400, "{}", body(&failed));
    assert!(legacy.is_file());

    let current = exchange(&service, signed(http::Method::GET, "/legacy-publish-failure/key", Bytes::new())).await;
    assert_eq!(current.status(), 200, "{}", body(&current));
    assert_eq!(current.body().as_ref(), b"previous");
}

/// Positive — a safe legacy regular file is retired after its replacement is published.
#[tokio::test]
async fn put_retires_a_safe_legacy_file_after_publishing_its_replacement() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "legacy-regular-put").await;
    let legacy = legacy_object_path(&root, "legacy-regular-put", "key");
    std::fs::write(&legacy, b"legacy bytes").expect("the safe legacy fixture is writable");
    let before = exchange(&service, signed(http::Method::GET, "/legacy-regular-put/key", Bytes::new())).await;
    assert_eq!(before.status(), 200);
    assert_eq!(before.body().as_ref(), b"legacy bytes");

    let stored = put(&service, "legacy-regular-put", "key", b"replacement").await;
    assert_eq!(stored.status(), 200, "{}", body(&stored));
    assert!(!legacy.exists());
    let current = exchange(&service, signed(http::Method::GET, "/legacy-regular-put/key", Bytes::new())).await;
    assert_eq!(current.status(), 200);
    assert_eq!(current.body().as_ref(), b"replacement");
}
