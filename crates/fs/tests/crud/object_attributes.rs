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

//! Selected object attributes through signed requests and persisted representations.
//!
//! Responsible for: field selection, checksum projection, versions and honest partial capability.
//! NOT responsible for: multipart part-list storage or pagination.
//! Upstream: production GetObjectAttributes registration. Downstream: the filesystem gate.

use super::super::*;

const BUCKET: &str = "stored-checksum";
const BODY: &[u8] = b"attribute-body";

async fn attributes(
    service: &S3Service,
    bucket: &str,
    key: &str,
    selection: &str,
    version: Option<&str>,
) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-amz-object-attributes",
        http::HeaderValue::from_str(selection).expect("fixture attributes"),
    );
    let mut target = format!("/{bucket}/{key}?attributes");
    if let Some(version) = version {
        target.push_str(&format!("&versionId={version}"));
    }
    exchange(service, signed_with_headers(http::Method::GET, &target, Bytes::new(), headers)).await
}

async fn put(service: &S3Service, key: &str, body: &'static [u8]) -> rustfs_gateway::WireResponse {
    let response = exchange(service, signed(http::Method::PUT, &format!("/{BUCKET}/{key}"), Bytes::from_static(body))).await;
    assert_eq!(response.status(), 200);
    response
}

fn text<'a>(response: &'a rustfs_gateway::WireResponse, name: &str) -> Option<&'a str> {
    header(response, name).and_then(|value| value.to_str().ok())
}

#[tokio::test]
async fn selected_metadata_survives_restart() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-storage-class", http::HeaderValue::from_static("REDUCED_REDUNDANCY"));
    let stored = exchange(
        &initial,
        signed_with_headers(http::Method::PUT, &format!("/{BUCKET}/object"), Bytes::from_static(BODY), headers),
    )
    .await;
    assert_eq!(stored.status(), 200);
    let tag = text(&stored, "etag").expect("stored ETag").trim_matches('"').to_owned();
    let before = exchange(&initial, signed(http::Method::HEAD, &format!("/{BUCKET}/object"), Bytes::new())).await;
    assert_eq!(before.status(), 200);
    let modified = text(&before, "last-modified").expect("stored time").to_owned();
    drop(initial);
    let (_, reopened) = service(&root);
    let response = attributes(&reopened, BUCKET, "object", "ETag,ObjectSize,StorageClass", None).await;
    assert_eq!(response.status(), 200);
    assert_eq!(element(response.body(), "ETag"), Some(tag));
    assert_eq!(element(response.body(), "ObjectSize"), Some(BODY.len().to_string()));
    assert_eq!(element(response.body(), "StorageClass").as_deref(), Some("REDUCED_REDUNDANCY"));
    assert_eq!(text(&response, "last-modified"), Some(modified.as_str()));
    assert_eq!(text(&response, "x-amz-version-id"), None);
}

#[tokio::test]
async fn stored_checksums_are_selected_without_a_checksum_mode_header() {
    use rustfs_gateway::ChecksumAlgorithm;
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    for algorithm in [ChecksumAlgorithm::Crc32, ChecksumAlgorithm::Sha256] {
        let value = super::checksum(algorithm, super::BODY);
        assert_eq!(super::put_checksum(&initial, algorithm.wire_name(), value).await.status(), 200);
    }
    use super::super::multipart_checksums::{complete_checksum, completion_with_checksum, initiate_checksum, put_checksum_part};
    let value = super::checksum(ChecksumAlgorithm::Crc32, BODY);
    let begun = initiate_checksum(&initial, BUCKET, "composite", "CRC32", "COMPOSITE").await;
    let id = element(begun.body(), "UploadId").expect("upload id");
    let part = put_checksum_part(&initial, BUCKET, "composite", &id, 1, value, BODY).await;
    let xml = completion_with_checksum(
        1,
        text(&part, "etag").expect("part ETag"),
        ChecksumAlgorithm::Crc32,
        value.render_base64(),
    );
    assert_eq!(complete_checksum(&initial, BUCKET, "composite", &id, xml).await.status(), 200);
    drop(initial);
    let (_, reopened) = service(&root);
    let response = attributes(&reopened, BUCKET, "composite", "Checksum", None).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        element(response.body(), "ChecksumCRC32").as_deref(),
        Some(
            rustfs_gateway::ChecksumSpec::composite_of(&[value])
                .expect("one part")
                .render_base64()
        )
    );
    assert_eq!(element(response.body(), "ChecksumType").as_deref(), Some("COMPOSITE"));
    for (algorithm, field) in [
        (ChecksumAlgorithm::Crc32, "ChecksumCRC32"),
        (ChecksumAlgorithm::Sha256, "ChecksumSHA256"),
    ] {
        let response = attributes(&reopened, BUCKET, algorithm.wire_name(), "Checksum", None).await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            element(response.body(), field).as_deref(),
            Some(super::checksum(algorithm, super::BODY).render_base64())
        );
        assert!(element(response.body(), "ChecksumType").is_none());
    }
}

#[tokio::test]
async fn explicit_version_attributes_do_not_follow_a_later_overwrite() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, BUCKET).await;
    assert_eq!(
        super::super::multipart_versioning::set_versioning(&initial, BUCKET, "Enabled")
            .await
            .status(),
        200
    );
    let stored = put(&initial, "object", BODY).await;
    let version = text(&stored, "x-amz-version-id").expect("version").to_owned();
    let tag = text(&stored, "etag").expect("ETag").trim_matches('"').to_owned();
    put(&initial, "object", b"new").await;
    drop(initial);
    let (_, reopened) = service(&root);
    let old = attributes(&reopened, BUCKET, "object", "ETag,ObjectSize", Some(&version)).await;
    assert_eq!(old.status(), 200);
    assert_eq!(element(old.body(), "ObjectSize"), Some(BODY.len().to_string()));
    assert_eq!(element(old.body(), "ETag"), Some(tag));
    assert_eq!(text(&old, "x-amz-version-id"), Some(version.as_str()));
    let current = attributes(&reopened, BUCKET, "object", "ObjectSize", None).await;
    assert_eq!(current.status(), 200);
    assert_eq!(element(current.body(), "ObjectSize").as_deref(), Some("3"));
}

#[tokio::test]
async fn n_unselected_groups_do_not_leak() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    let value = super::checksum(rustfs_gateway::ChecksumAlgorithm::Crc32, super::BODY);
    assert_eq!(super::put_checksum(&service, "object", value).await.status(), 200);
    let fields = ["ETag", "ObjectSize", "StorageClass", "Checksum"];
    for selected in fields {
        let response = attributes(&service, BUCKET, "object", selected, None).await;
        assert_eq!(response.status(), 200);
        for field in fields {
            assert_eq!(element(response.body(), field).is_some(), field == selected, "{selected}: {field}");
        }
        assert!(element(response.body(), "ObjectParts").is_none());
    }
}

#[tokio::test]
async fn n_plain_objects_do_not_invent_parts_or_checksums() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    put(&service, "object", b"").await;
    let response = attributes(&service, BUCKET, "object", "ObjectParts,Checksum,ObjectSize", None).await;
    assert_eq!(response.status(), 200);
    assert_eq!(element(response.body(), "ObjectSize").as_deref(), Some("0"));
    assert!(element(response.body(), "ObjectParts").is_none());
    assert!(element(response.body(), "ChecksumCRC32").is_none());
    assert!(element(response.body(), "ChecksumSHA256").is_none());
    assert!(element(response.body(), "ChecksumType").is_none());
    assert!(std::str::from_utf8(response.body()).expect("XML").contains("<Checksum"));
}

#[tokio::test]
async fn n_absent_objects_buckets_and_versions_are_not_empty_metadata() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    put(&service, "object", BODY).await;
    for (bucket, key, version, code) in [
        ("missing", "object", None, "NoSuchBucket"),
        (BUCKET, "missing", None, "NoSuchKey"),
        (BUCKET, "object", Some("missing"), "NoSuchVersion"),
    ] {
        let response = attributes(&service, bucket, key, "ETag", version).await;
        assert_eq!(response.status(), 404);
        assert_eq!(element(response.body(), "Code").as_deref(), Some(code));
    }
}

#[tokio::test]
async fn n_delete_markers_do_not_become_object_attributes() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    assert_eq!(
        super::super::multipart_versioning::set_versioning(&service, BUCKET, "Enabled")
            .await
            .status(),
        200
    );
    put(&service, "object", BODY).await;
    let deleted = exchange(&service, signed(http::Method::DELETE, &format!("/{BUCKET}/object"), Bytes::new())).await;
    assert_eq!(deleted.status(), 204);
    let version = text(&deleted, "x-amz-version-id").expect("marker version");
    for (selected, status, code) in [(None, 404, "NoSuchKey"), (Some(version), 405, "MethodNotAllowed")] {
        let response = attributes(&service, BUCKET, "object", "ETag", selected).await;
        assert_eq!(response.status(), status);
        assert_eq!(element(response.body(), "Code").as_deref(), Some(code));
        assert_eq!(text(&response, "x-amz-delete-marker"), Some("true"));
    }
}

#[tokio::test]
async fn n_multipart_detail_is_refused_until_original_part_numbers_are_stored() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    let id = initiate(&service, BUCKET, "object").await;
    let part = upload_part(&service, BUCKET, "object", &id, 5, BODY).await;
    let xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>5</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        part
    );
    assert_eq!(
        exchange(
            &service,
            signed(http::Method::POST, &format!("/{BUCKET}/object?uploadId={id}"), Bytes::from(xml))
        )
        .await
        .status(),
        200
    );
    assert_eq!(attributes(&service, BUCKET, "object", "ObjectParts", None).await.status(), 501);
    let response = attributes(&service, BUCKET, "object", "ObjectSize", None).await;
    assert_eq!(response.status(), 200);
    assert_eq!(element(response.body(), "ObjectSize"), Some(BODY.len().to_string()));
}

#[tokio::test]
async fn n_unknown_groups_do_not_select_known_fields() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, BUCKET).await;
    put(&service, "object", BODY).await;
    let response = attributes(&service, BUCKET, "object", "Unknown", None).await;
    assert_eq!(response.status(), 200);
    for field in ["ETag", "ObjectSize", "StorageClass", "Checksum", "ObjectParts"] {
        assert!(element(response.body(), field).is_none());
    }
    let mixed = attributes(&service, BUCKET, "object", "ETag,Unknown", None).await;
    assert_eq!(mixed.status(), 200);
    assert!(element(mixed.body(), "ETag").is_some());
    assert!(element(mixed.body(), "ObjectSize").is_none());
}
