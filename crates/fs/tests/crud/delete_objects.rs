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

//! Signed production-service evidence for `DeleteObjects` (rustfs/gateway#721).
//!
//! Responsible for: every requested key being reported exactly once, the same outcome a single
//! `DeleteObject` would have had — removal when unversioned, a delete marker when enabled, an
//! explicit version removed by id — quiet mode reporting only failures, and a missing bucket or a
//! body without its required integrity header refusing the whole request.
//! NOT responsible for: the XML grammar or the 1000-key ceiling, which the framework enforces.
//! Upstream: the shared CRUD service fixture. Downstream: the crate verification gate.

use md5::{Digest as _, Md5};

use super::*;

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let triple = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (index, byte)| acc | (u32::from(*byte) << (16 - 8 * index)));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[((triple >> (18 - 6 * index)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn delete_document(entries: &[(&str, Option<&str>)], quiet: bool) -> Bytes {
    let mut body = String::from("<Delete>");
    if quiet {
        body.push_str("<Quiet>true</Quiet>");
    }
    for (key, version_id) in entries {
        body.push_str(&format!("<Object><Key>{key}</Key>"));
        if let Some(version_id) = version_id {
            body.push_str(&format!("<VersionId>{version_id}</VersionId>"));
        }
        body.push_str("</Object>");
    }
    body.push_str("</Delete>");
    Bytes::from(body)
}

async fn delete_objects(service: &S3Service, bucket: &str, body: Bytes) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "content-md5",
        http::HeaderValue::from_str(&base64(&Md5::digest(&body))).expect("a base64 digest"),
    );
    exchange(
        service,
        signed_with_headers(http::Method::POST, &format!("/{bucket}?delete"), body, headers),
    )
    .await
}

async fn put(service: &S3Service, target: &str) -> rustfs_gateway::WireResponse {
    let response = exchange(service, signed(http::Method::PUT, target, Bytes::from_static(b"bytes"))).await;
    assert_eq!(response.status(), 200, "{}", String::from_utf8_lossy(response.body()));
    response
}

async fn status_of(service: &S3Service, target: &str) -> u16 {
    exchange(service, signed(http::Method::HEAD, target, Bytes::new()))
        .await
        .status()
        .as_u16()
}

fn body_text(response: &rustfs_gateway::WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

async fn enable_versioning(service: &S3Service, bucket: &str) {
    let enabled = super::multipart_versioning::set_versioning(service, bucket, "Enabled").await;
    assert_eq!(enabled.status(), 200, "{}", body_text(&enabled));
}

/// Positive — every key is removed and reported once, including one that never existed, and the
/// emptied bucket can then be deleted (the `rb --recursive` path mint's `s3cmd` suite takes).
#[tokio::test]
async fn every_key_is_removed_and_reported_once() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "batch").await;
    put(&service, "/batch/a").await;
    put(&service, "/batch/nested/b").await;
    let response = delete_objects(
        &service,
        "batch",
        delete_document(&[("a", None), ("nested/b", None), ("never-written", None)], false),
    )
    .await;
    assert_eq!(response.status(), 200, "{}", body_text(&response));
    let text = body_text(&response);
    assert_eq!(text.matches("<Deleted>").count(), 3, "{text}");
    for key in ["a", "nested/b", "never-written"] {
        assert_eq!(text.matches(&format!("<Key>{key}</Key>")).count(), 1, "{text}");
    }
    assert!(!text.contains("<Error>"), "{text}");
    assert!(!text.contains("<DeleteMarker>"), "an unversioned removal mints no marker: {text}");
    assert_eq!(status_of(&service, "/batch/a").await, 404);
    assert_eq!(status_of(&service, "/batch/nested/b").await, 404);
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/batch", Bytes::new()))
            .await
            .status(),
        204
    );
}

/// Negative — quiet mode reports no successes, and still removes every key.
#[tokio::test]
async fn quiet_mode_reports_no_successes() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "quiet").await;
    put(&service, "/quiet/a").await;
    let response = delete_objects(&service, "quiet", delete_document(&[("a", None)], true)).await;
    assert_eq!(response.status(), 200, "{}", body_text(&response));
    let text = body_text(&response);
    assert!(!text.contains("<Deleted>"), "{text}");
    assert!(!text.contains("<Error>"), "{text}");
    assert_eq!(status_of(&service, "/quiet/a").await, 404);
}

/// Negative — in an enabled bucket a batch delete hides the key behind a delete marker rather than
/// removing its bytes, and reports the marker's id.
#[tokio::test]
async fn an_enabled_bucket_gains_delete_markers() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "batch-versions").await;
    enable_versioning(&service, "batch-versions").await;
    let stored = put(&service, "/batch-versions/doc").await;
    let version = header(&stored, "x-amz-version-id")
        .expect("a version id")
        .to_str()
        .expect("ASCII")
        .to_owned();
    let response = delete_objects(&service, "batch-versions", delete_document(&[("doc", None)], false)).await;
    let text = body_text(&response);
    assert_eq!(response.status(), 200, "{text}");
    assert_eq!(element(response.body(), "DeleteMarker").as_deref(), Some("true"), "{text}");
    let marker = element(response.body(), "DeleteMarkerVersionId").expect("the marker's id");
    assert_ne!(marker, version);
    assert_eq!(status_of(&service, "/batch-versions/doc").await, 404);
    assert_eq!(
        status_of(&service, &format!("/batch-versions/doc?versionId={version}")).await,
        200,
        "the object's bytes survive behind the marker"
    );
}

/// Negative — an explicit version is removed by id, and removing a marker by id says so.
#[tokio::test]
async fn explicit_versions_are_removed_by_id() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "batch-explicit").await;
    enable_versioning(&service, "batch-explicit").await;
    let stored = put(&service, "/batch-explicit/doc").await;
    let version = header(&stored, "x-amz-version-id")
        .expect("a version id")
        .to_str()
        .expect("ASCII")
        .to_owned();
    let marked = delete_objects(&service, "batch-explicit", delete_document(&[("doc", None)], false)).await;
    let marker = element(marked.body(), "DeleteMarkerVersionId").expect("the marker's id");

    let response = delete_objects(
        &service,
        "batch-explicit",
        delete_document(&[("doc", Some(&marker)), ("doc", Some(&version))], false),
    )
    .await;
    let text = body_text(&response);
    assert_eq!(response.status(), 200, "{text}");
    assert_eq!(text.matches("<Deleted>").count(), 2, "{text}");
    assert_eq!(text.matches(&format!("<VersionId>{version}</VersionId>")).count(), 1, "{text}");
    assert_eq!(
        text.matches(&format!("<DeleteMarkerVersionId>{marker}</DeleteMarkerVersionId>"))
            .count(),
        1,
        "{text}"
    );
    assert_eq!(text.matches("<DeleteMarker>true</DeleteMarker>").count(), 1, "{text}");
    assert_eq!(status_of(&service, &format!("/batch-explicit/doc?versionId={version}")).await, 404);
    assert_eq!(
        exchange(&service, signed(http::Method::DELETE, "/batch-explicit", Bytes::new()))
            .await
            .status(),
        204,
        "no version is left behind"
    );
}

/// Negative — a batch against a bucket that does not exist is refused as a whole.
#[tokio::test]
async fn a_missing_bucket_refuses_the_whole_batch() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let response = delete_objects(&service, "absent", delete_document(&[("a", None)], false)).await;
    assert_eq!(response.status(), 404, "{}", body_text(&response));
    assert!(body_text(&response).contains("<Code>NoSuchBucket</Code>"));
}

/// Negative — a batch without `Content-MD5` or a checksum header is refused before any key goes.
#[tokio::test]
async fn a_batch_without_an_integrity_header_deletes_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "unsigned-batch").await;
    put(&service, "/unsigned-batch/a").await;
    let response = exchange(
        &service,
        signed(http::Method::POST, "/unsigned-batch?delete", delete_document(&[("a", None)], false)),
    )
    .await;
    assert_eq!(response.status(), 400, "{}", body_text(&response));
    assert_eq!(status_of(&service, "/unsigned-batch/a").await, 200);
}

/// Negative — a storage failure on one key is that key's error entry, not the batch's failure,
/// and the other keys are still removed.
#[tokio::test]
async fn one_failing_key_does_not_fail_the_batch() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "partial").await;
    put(&service, "/partial/good").await;
    // A legacy object path that is a directory rather than a regular file is refused as unsafe by
    // the single-key deletion, which makes a deterministic per-key failure.
    std::fs::create_dir_all(legacy_object_path(&root, "partial", "bad")).expect("an unsafe legacy path");
    let response = delete_objects(&service, "partial", delete_document(&[("good", None), ("bad", None)], false)).await;
    let text = body_text(&response);
    assert_eq!(response.status(), 200, "{text}");
    assert_eq!(text.matches("<Deleted>").count(), 1, "{text}");
    assert_eq!(text.matches("<Error>").count(), 1, "{text}");
    assert!(text.contains("<Error><Key>bad</Key>"), "{text}");
    assert!(text.contains("<Code>InvalidRequest</Code>"), "{text}");
    assert_eq!(status_of(&service, "/partial/good").await, 404);
}
