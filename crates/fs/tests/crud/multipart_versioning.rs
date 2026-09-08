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

//! Production multipart-version publication evidence for the filesystem reference backend.
//!
//! Responsible for: proving that completed uploads enter the same Enabled/Suspended/null version
//! lineage as ordinary object writes, including refusal before unsafe legacy-path replacement.
//! NOT responsible for: minimum-part sizing, checksum negotiation, lifecycle, or upload-id minting.
//! Upstream: the shared CRUD service fixture and persistent version authority. Downstream: the
//! crate verification gate.

use super::*;

fn versioning_document(status: &str) -> Bytes {
    Bytes::from(format!(
        "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>{status}</Status></VersioningConfiguration>"
    ))
}

pub(super) async fn set_versioning(service: &S3Service, bucket: &str, status: &str) -> rustfs_gateway::WireResponse {
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

fn header_text<'a>(response: &'a rustfs_gateway::WireResponse, name: &str) -> Option<&'a str> {
    header(response, name).and_then(|value| value.to_str().ok())
}

fn completed_etag(response: &rustfs_gateway::WireResponse) -> String {
    element(response.body(), "ETag")
        .expect("completion returns an entity tag")
        .replace("&quot;", "")
        .trim_matches('"')
        .to_owned()
}

async fn complete_one(service: &S3Service, bucket: &str, key: &str, bytes: &'static [u8]) -> (String, String, String) {
    let upload_id = initiate(service, bucket, key).await;
    let part = upload_part(service, bucket, key, &upload_id, 1, bytes).await;
    let response = complete(service, bucket, key, &upload_id, &[(1, &part)]).await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    let version_id = header_text(&response, "x-amz-version-id")
        .expect("versioned multipart completion returns a version id")
        .to_owned();
    (version_id, completed_etag(&response), upload_id)
}

async fn start_one(service: &S3Service, bucket: &str, key: &str, bytes: &'static [u8]) -> (String, String) {
    let upload_id = initiate(service, bucket, key).await;
    let part = upload_part(service, bucket, key, &upload_id, 1, bytes).await;
    (upload_id, part)
}

fn bucket_path(root: &TestRoot, bucket: &str) -> PathBuf {
    root.0.join(format!("b-{}", hex::encode(bucket)))
}

/// Positive — enabled multipart versions retain their bytes and composite tags after restart.
#[tokio::test]
async fn enabled_multipart_versions_survive_restart() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "mpu-versions").await;
    assert_eq!(set_versioning(&running, "mpu-versions", "Enabled").await.status(), 200);

    let (first_id, first_tag, first_upload) = complete_one(&running, "mpu-versions", "key", b"first").await;
    let (second_id, second_tag, second_upload) = complete_one(&running, "mpu-versions", "key", b"second").await;
    assert_ne!(first_id, second_id);
    assert_ne!(first_id, "null");
    assert!(first_tag.ends_with("-1"));
    assert!(second_tag.ends_with("-1"));

    let (_, reopened) = service(&root);
    let current = exchange(&reopened, signed(http::Method::GET, "/mpu-versions/key", Bytes::new())).await;
    assert_eq!(current.status(), 200);
    assert_eq!(current.body().as_ref(), b"second");
    assert_eq!(header_text(&current, "etag"), Some(format!("\"{second_tag}\"").as_str()));
    assert_eq!(header_text(&current, "x-amz-version-id"), Some(second_id.as_str()));

    let first = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/mpu-versions/key?versionId={first_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(first.status(), 200, "{}", String::from_utf8_lossy(first.body()));
    assert_eq!(first.body().as_ref(), b"first");
    assert_eq!(header_text(&first, "etag"), Some(format!("\"{first_tag}\"").as_str()));

    let versions = exchange(&reopened, signed(http::Method::GET, "/mpu-versions?versions", Bytes::new())).await;
    let versions = String::from_utf8_lossy(versions.body());
    assert!(versions.contains(&first_id));
    assert!(versions.contains(&second_id));
    assert!(versions.contains(&first_tag));
    assert!(versions.contains(&second_tag));

    let uploads = exchange(&reopened, signed(http::Method::GET, "/mpu-versions?uploads", Bytes::new())).await;
    let uploads = String::from_utf8_lossy(uploads.body());
    assert!(!uploads.contains(&first_upload));
    assert!(!uploads.contains(&second_upload));
}

/// Positive — never-enabled and suspended buckets follow the same null-version rules as PUT.
#[tokio::test]
async fn never_enabled_and_suspended_completion_share_null_semantics() {
    let root = TestRoot::new();
    let (_, running) = service(&root);
    create_bucket(&running, "mpu-null").await;

    let (plain_upload, plain_part) = start_one(&running, "mpu-null", "plain", b"unversioned").await;
    let plain = complete(&running, "mpu-null", "plain", &plain_upload, &[(1, &plain_part)]).await;
    assert_eq!(plain.status(), 200, "{}", String::from_utf8_lossy(plain.body()));
    assert!(header_text(&plain, "x-amz-version-id").is_none());

    assert_eq!(set_versioning(&running, "mpu-null", "Enabled").await.status(), 200);
    let (historic_id, _, _) = complete_one(&running, "mpu-null", "key", b"historic").await;
    assert_eq!(set_versioning(&running, "mpu-null", "Suspended").await.status(), 200);
    let (first_null, _, _) = complete_one(&running, "mpu-null", "key", b"null-one").await;
    let (second_null, second_tag, _) = complete_one(&running, "mpu-null", "key", b"null-two").await;
    assert_eq!(first_null, "null");
    assert_eq!(second_null, "null");

    let (_, reopened) = service(&root);
    let plain = exchange(&reopened, signed(http::Method::GET, "/mpu-null/plain", Bytes::new())).await;
    assert_eq!(plain.status(), 200);
    assert_eq!(plain.body().as_ref(), b"unversioned");
    assert!(header_text(&plain, "x-amz-version-id").is_none());

    let current = exchange(&reopened, signed(http::Method::GET, "/mpu-null/key", Bytes::new())).await;
    assert_eq!(current.status(), 200);
    assert_eq!(current.body().as_ref(), b"null-two");
    assert_eq!(header_text(&current, "etag"), Some(format!("\"{second_tag}\"").as_str()));
    assert!(header_text(&current, "x-amz-version-id").is_none());

    let historic = exchange(
        &reopened,
        signed(http::Method::GET, &format!("/mpu-null/key?versionId={historic_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(historic.status(), 200);
    assert_eq!(historic.body().as_ref(), b"historic");

    let versions = exchange(&reopened, signed(http::Method::GET, "/mpu-null?versions", Bytes::new())).await;
    let versions = String::from_utf8_lossy(versions.body());
    assert_eq!(versions.matches("<VersionId>null</VersionId>").count(), 2);
    assert_eq!(versions.matches("<Key>key</Key>").count(), 2);
    assert!(versions.contains(&historic_id));
}

/// Negative — corrupt versioning state cannot retire an upload or publish around the authority.
#[tokio::test]
async fn n_corrupt_versioning_state_leaves_the_upload_retryable() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "mpu-corrupt").await;
    assert_eq!(set_versioning(&service, "mpu-corrupt", "Enabled").await.status(), 200);
    let (upload_id, part) = start_one(&service, "mpu-corrupt", "key", b"retryable").await;
    let status = bucket_path(&root, "mpu-corrupt").join("versioning-status");
    std::fs::write(&status, b"Broken\n").expect("the exact fixture status is corruptible");

    let failed = complete(&service, "mpu-corrupt", "key", &upload_id, &[(1, &part)]).await;
    assert_eq!(failed.status(), 500, "{}", String::from_utf8_lossy(failed.body()));
    std::fs::write(status, b"Enabled\n").expect("the exact fixture status is repairable");

    let absent = exchange(&service, signed(http::Method::GET, "/mpu-corrupt/key", Bytes::new())).await;
    assert_eq!(absent.status(), 404);
    let uploads = exchange(&service, signed(http::Method::GET, "/mpu-corrupt?uploads", Bytes::new())).await;
    assert!(String::from_utf8_lossy(uploads.body()).contains(&upload_id));

    let retried = complete(&service, "mpu-corrupt", "key", &upload_id, &[(1, &part)]).await;
    assert_eq!(retried.status(), 200, "{}", String::from_utf8_lossy(retried.body()));
}

/// Negative — completion refuses a symbolic link replacing the version-record authority.
#[cfg(unix)]
#[tokio::test]
async fn n_symlinked_version_authority_cannot_receive_a_completed_upload() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "mpu-link").await;
    assert_eq!(set_versioning(&service, "mpu-link", "Enabled").await.status(), 200);
    let (upload_id, part) = start_one(&service, "mpu-link", "key", b"outside").await;
    let versions = bucket_path(&root, "mpu-link").join("versions");
    std::fs::remove_dir(&versions).expect("the empty version directory is removable");
    symlink(&outside.0, &versions).expect("a test symlink");

    let failed = complete(&service, "mpu-link", "key", &upload_id, &[(1, &part)]).await;
    assert_eq!(failed.status(), 400, "{}", String::from_utf8_lossy(failed.body()));
    assert!(String::from_utf8_lossy(failed.body()).contains("<Code>InvalidRequest</Code>"));
    assert_eq!(
        std::fs::read_dir(&outside.0)
            .expect("the outside root remains readable")
            .count(),
        0
    );

    std::fs::remove_file(&versions).expect("the exact symlink is removable");
    std::fs::create_dir(&versions).expect("the authority directory is restorable");
    let uploads = exchange(&service, signed(http::Method::GET, "/mpu-link?uploads", Bytes::new())).await;
    assert!(String::from_utf8_lossy(uploads.body()).contains(&upload_id));
    assert_eq!(
        exchange(&service, signed(http::Method::GET, "/mpu-link/key", Bytes::new()))
            .await
            .status(),
        404
    );
}

/// Negative — invalid completion parts create no version and leave the upload visible.
#[tokio::test]
async fn n_invalid_part_creates_no_version_record() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "mpu-invalid").await;
    assert_eq!(set_versioning(&service, "mpu-invalid", "Enabled").await.status(), 200);
    let upload_id = initiate(&service, "mpu-invalid", "key").await;

    let failed = complete(&service, "mpu-invalid", "key", &upload_id, &[(1, "\"deadbeef\"")]).await;
    assert_eq!(failed.status(), 400, "{}", String::from_utf8_lossy(failed.body()));
    assert!(String::from_utf8_lossy(failed.body()).contains("<Code>InvalidPart</Code>"));

    let versions = exchange(&service, signed(http::Method::GET, "/mpu-invalid?versions", Bytes::new())).await;
    assert!(!String::from_utf8_lossy(versions.body()).contains("<Version>"));
    let uploads = exchange(&service, signed(http::Method::GET, "/mpu-invalid?uploads", Bytes::new())).await;
    assert!(String::from_utf8_lossy(uploads.body()).contains(&upload_id));
}

/// Negative — completion rejects a legacy symlink before replacing the readable null version.
#[cfg(unix)]
#[tokio::test]
async fn n_completion_preflights_symlinked_legacy_path_before_publishing_null_version() {
    use std::os::unix::fs::symlink;

    let root = TestRoot::new();
    let outside = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "mpu-legacy-link").await;
    let previous = exchange(
        &service,
        signed(http::Method::PUT, "/mpu-legacy-link/key", Bytes::from_static(b"previous")),
    )
    .await;
    assert_eq!(previous.status(), 200);
    let (upload_id, part) = start_one(&service, "mpu-legacy-link", "key", b"must-not-publish").await;

    let outside_file = outside.0.join("outside");
    std::fs::write(&outside_file, b"outside sentinel").expect("the outside fixture is writable");
    let legacy = legacy_object_path(&root, "mpu-legacy-link", "key");
    symlink(&outside_file, &legacy).expect("the legacy fixture symlink is creatable");

    let failed = complete(&service, "mpu-legacy-link", "key", &upload_id, &[(1, &part)]).await;
    assert_eq!(failed.status(), 400, "{}", String::from_utf8_lossy(failed.body()));
    assert!(String::from_utf8_lossy(failed.body()).contains("<Code>InvalidRequest</Code>"));
    assert_eq!(
        std::fs::read(&outside_file).expect("the outside fixture remains readable"),
        b"outside sentinel"
    );

    let current = exchange(&service, signed(http::Method::GET, "/mpu-legacy-link/key", Bytes::new())).await;
    assert_eq!(current.status(), 200);
    assert_eq!(current.body().as_ref(), b"previous");
    let uploads = exchange(&service, signed(http::Method::GET, "/mpu-legacy-link?uploads", Bytes::new())).await;
    assert!(String::from_utf8_lossy(uploads.body()).contains(&upload_id));
}
