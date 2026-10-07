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

//! Stored full-object checksums on the filesystem reference backend.
//!
//! Responsible for: signed checksum writes, restart reads and copy projection.
//! NOT responsible for: multipart part boundaries or GetObjectAttributes.
//! Upstream: the production registry and persisted object records. Downstream: the FS verification gate.

use super::multipart_checksums::checksum;
use super::multipart_trailer_checksums::{Trailer, trailer_part_request};
use super::*;
use rustfs_gateway::{ChecksumAlgorithm, ChecksumSpec};

const BODY: &[u8] = b"checksum-persistence-control";

async fn put_checksum(service: &S3Service, key: &str, value: ChecksumSpec) -> rustfs_gateway::WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static(value.algorithm().header_name()),
        http::HeaderValue::from_str(value.render_base64()).expect("a fixture checksum"),
    );
    exchange(
        service,
        signed_with_headers(http::Method::PUT, &format!("/stored-checksum/{key}"), Bytes::from_static(BODY), headers),
    )
    .await
}

fn mode_header() -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-checksum-mode", http::HeaderValue::from_static("ENABLED"));
    headers
}

#[tokio::test]
async fn put_returns_the_supplied_full_object_checksum() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "stored-checksum").await;
    for algorithm in [ChecksumAlgorithm::Crc32, ChecksumAlgorithm::Sha256] {
        let value = checksum(algorithm, BODY);
        let response = put_checksum(&service, algorithm.wire_name(), value).await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            header(&response, algorithm.header_name()).and_then(|v| v.to_str().ok()),
            Some(value.render_base64())
        );
    }
}

#[tokio::test]
async fn restarted_get_and_enabled_head_return_the_stored_checksum() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "stored-checksum").await;
    let algorithms = [
        ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc32c,
        ChecksumAlgorithm::Crc64Nvme,
        ChecksumAlgorithm::Sha1,
        ChecksumAlgorithm::Sha256,
        ChecksumAlgorithm::Sha512,
        ChecksumAlgorithm::Md5,
        ChecksumAlgorithm::XxHash64,
        ChecksumAlgorithm::XxHash3,
        ChecksumAlgorithm::XxHash128,
    ];
    for algorithm in algorithms {
        assert_eq!(
            put_checksum(&initial, algorithm.wire_name(), checksum(algorithm, BODY))
                .await
                .status(),
            200
        );
    }
    drop(initial);
    let (_, restarted) = service(&root);
    for algorithm in algorithms {
        let value = checksum(algorithm, BODY);
        for method in [http::Method::GET, http::Method::HEAD] {
            let target = format!("/stored-checksum/{}", algorithm.wire_name());
            let response = exchange(&restarted, signed_with_headers(method, &target, Bytes::new(), mode_header())).await;
            assert_eq!(response.status(), 200);
            assert_eq!(
                header(&response, algorithm.header_name()).and_then(|v| v.to_str().ok()),
                Some(value.render_base64())
            );
        }
    }
}

#[tokio::test]
async fn copy_preserves_or_recalculates_the_stored_checksum() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "stored-checksum").await;
    assert_eq!(
        put_checksum(&initial, "source", checksum(ChecksumAlgorithm::Crc32, BODY))
            .await
            .status(),
        200
    );
    for algorithm in [ChecksumAlgorithm::Crc32, ChecksumAlgorithm::Sha256] {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-copy-source", http::HeaderValue::from_static("stored-checksum/source"));
        if algorithm == ChecksumAlgorithm::Sha256 {
            headers.insert("x-amz-checksum-algorithm", http::HeaderValue::from_static("SHA256"));
        }
        let target = format!("/stored-checksum/copy-{}", algorithm.wire_name());
        let copied = exchange(&initial, signed_with_headers(http::Method::PUT, &target, Bytes::new(), headers)).await;
        assert_eq!(copied.status(), 200, "{}", String::from_utf8_lossy(copied.body()));
        let element_name = if algorithm == ChecksumAlgorithm::Crc32 {
            "ChecksumCRC32"
        } else {
            "ChecksumSHA256"
        };
        let expected = checksum(algorithm, BODY);
        assert_eq!(element(copied.body(), element_name).as_deref(), Some(expected.render_base64()));
        let (_, restarted) = service(&root);
        let read = exchange(&restarted, signed_with_headers(http::Method::GET, &target, Bytes::new(), mode_header())).await;
        assert_eq!(read.status(), 200);
        assert_eq!(read.body(), BODY);
        assert_eq!(
            header(&read, algorithm.header_name()).and_then(|v| v.to_str().ok()),
            Some(expected.render_base64())
        );
    }
}

#[tokio::test]
async fn n_reads_without_checksum_mode_do_not_expose_the_checksum() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "stored-checksum").await;
    assert_eq!(
        put_checksum(&service, "object", checksum(ChecksumAlgorithm::Crc32, BODY))
            .await
            .status(),
        200
    );
    for method in [http::Method::GET, http::Method::HEAD] {
        let response = exchange(&service, signed(method, "/stored-checksum/object", Bytes::new())).await;
        assert_eq!(response.status(), 200);
        assert!(header(&response, "x-amz-checksum-crc32").is_none());
    }
}

#[tokio::test]
async fn n_a_range_does_not_report_the_whole_object_checksum() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "stored-checksum").await;
    assert_eq!(
        put_checksum(&service, "object", checksum(ChecksumAlgorithm::Crc32, BODY))
            .await
            .status(),
        200
    );
    let mut headers = mode_header();
    headers.insert(http::header::RANGE, http::HeaderValue::from_static("bytes=0-3"));
    for method in [http::Method::GET, http::Method::HEAD] {
        let response = exchange(
            &service,
            signed_with_headers(method.clone(), "/stored-checksum/object", Bytes::new(), headers.clone()),
        )
        .await;
        // Preserve this reference backend's existing range status; native RustFS answers HEAD 200.
        assert_eq!(response.status(), 206);
        if method == http::Method::GET {
            assert_eq!(response.body(), &BODY[..4]);
        }
        assert!(header(&response, "x-amz-checksum-crc32").is_none());
    }
}

#[tokio::test]
async fn n_a_plain_overwrite_does_not_reuse_the_old_checksum() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "stored-checksum").await;
    assert_eq!(
        put_checksum(&initial, "object", checksum(ChecksumAlgorithm::Crc32, BODY))
            .await
            .status(),
        200
    );
    let plain = exchange(
        &initial,
        signed(http::Method::PUT, "/stored-checksum/object", Bytes::from_static(b"replacement")),
    )
    .await;
    assert_eq!(plain.status(), 200);
    assert!(header(&plain, "x-amz-checksum-crc32").is_none());
    drop(initial);
    let (_, restarted) = service(&root);
    let response = exchange(
        &restarted,
        signed_with_headers(http::Method::GET, "/stored-checksum/object", Bytes::new(), mode_header()),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.body().as_ref(), b"replacement");
    assert!(header(&response, "x-amz-checksum-crc32").is_none());
}

#[tokio::test]
async fn n_a_bad_checksum_never_replaces_the_object_or_its_checksum() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "stored-checksum").await;
    let expected = checksum(ChecksumAlgorithm::Crc32, BODY);
    assert_eq!(put_checksum(&service, "object", expected).await.status(), 200);
    for bad in ["AAAAAA==", "not-base64", "AAAA"] {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-checksum-crc32", http::HeaderValue::from_static(bad));
        let refused = exchange(
            &service,
            signed_with_headers(
                http::Method::PUT,
                "/stored-checksum/object",
                Bytes::from_static(b"rejected bytes"),
                headers,
            ),
        )
        .await;
        assert_eq!(refused.status(), 400);
        let stored = exchange(
            &service,
            signed_with_headers(http::Method::GET, "/stored-checksum/object", Bytes::new(), mode_header()),
        )
        .await;
        assert_eq!(stored.status(), 200);
        assert_eq!(stored.body(), BODY);
        assert_eq!(
            header(&stored, "x-amz-checksum-crc32").and_then(|v| v.to_str().ok()),
            Some(expected.render_base64())
        );
    }
}

pub(super) fn one_record(root: &TestRoot) -> PathBuf {
    let versions = root.0.join(format!("b-{}", hex::encode("stored-checksum"))).join("versions");
    std::fs::read_dir(versions)
        .expect("the fixture version directory")
        .next()
        .expect("one fixture version")
        .expect("a readable directory entry")
        .path()
        .join("record")
}

#[tokio::test]
async fn a_named_checksum_section_can_be_read_after_restart() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "stored-checksum").await;
    assert_eq!(
        exchange(&initial, signed(http::Method::PUT, "/stored-checksum/object", Bytes::from_static(BODY)))
            .await
            .status(),
        200
    );
    drop(initial);
    let path = one_record(&root);
    let original = std::fs::read_to_string(&path).expect("the old record");
    assert_eq!(original.lines().count(), 8, "a plain write keeps the pre-section record format");
    let expected = checksum(ChecksumAlgorithm::Crc32, BODY);
    std::fs::write(&path, format!("{original}checksum/1 1\nCRC32 {}\n", expected.render_base64())).expect("a fixture section");
    let (_, restarted) = service(&root);
    let response = exchange(
        &restarted,
        signed_with_headers(http::Method::GET, "/stored-checksum/object", Bytes::new(), mode_header()),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), BODY);
    assert_eq!(
        header(&response, "x-amz-checksum-crc32").and_then(|v| v.to_str().ok()),
        Some(expected.render_base64())
    );
}

#[tokio::test]
async fn n_malformed_checksum_sections_are_not_silently_discarded() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "stored-checksum").await;
    assert_eq!(
        exchange(&initial, signed(http::Method::PUT, "/stored-checksum/object", Bytes::from_static(BODY)))
            .await
            .status(),
        200
    );
    drop(initial);
    let path = one_record(&root);
    let original = std::fs::read_to_string(&path).expect("the old record");
    for section in [
        "checksum/1 0\n",
        "checksum/1 2\nCRC32 AAAAAA==\n",
        "checksum/1 1\nUNKNOWN AAAAAA==\n",
        "checksum/1 1\nCRC32 not-base64\n",
        "checksum/1 1\nCRC32 AAAA\n",
        "checksum/1 1\nCRC32 AAAAAA==\nchecksum/1 1\nCRC32 AAAAAA==\n",
        "checksum/1 1\nCRC32 AAAAAA==\nheaders/1 0\n",
    ] {
        std::fs::write(&path, format!("{original}{section}")).expect("a malformed fixture section");
        let (_, restarted) = service(&root);
        let response = exchange(
            &restarted,
            signed_with_headers(http::Method::GET, "/stored-checksum/object", Bytes::new(), mode_header()),
        )
        .await;
        assert_eq!(response.status(), 500, "{section}");
    }
}

#[tokio::test]
async fn n_copy_rejects_an_unknown_checksum_algorithm_without_writing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "stored-checksum").await;
    assert_eq!(
        put_checksum(&service, "source", checksum(ChecksumAlgorithm::Crc32, BODY))
            .await
            .status(),
        200
    );
    let mut headers = http::HeaderMap::new();
    headers.insert("x-amz-copy-source", http::HeaderValue::from_static("stored-checksum/source"));
    headers.insert("x-amz-checksum-algorithm", http::HeaderValue::from_static("UNKNOWN"));
    let response = exchange(
        &service,
        signed_with_headers(http::Method::PUT, "/stored-checksum/destination", Bytes::new(), headers),
    )
    .await;
    assert_eq!(response.status(), 400);
    assert_eq!(element(response.body(), "Code").as_deref(), Some("InvalidArgument"));
    let missing = exchange(&service, signed(http::Method::GET, "/stored-checksum/destination", Bytes::new())).await;
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn a_verified_trailer_checksum_survives_restart() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "stored-checksum").await;
    let value = checksum(ChecksumAlgorithm::Crc32, BODY);
    let response = exchange(
        &initial,
        trailer_part_request(
            "/stored-checksum/object",
            BODY,
            "x-amz-checksum-crc32",
            &Trailer::Field("x-amz-checksum-crc32", value.render_base64()),
            &[],
        ),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        header(&response, "x-amz-checksum-crc32").and_then(|v| v.to_str().ok()),
        Some(value.render_base64())
    );
    drop(initial);
    let (_, restarted) = service(&root);
    let read = exchange(
        &restarted,
        signed_with_headers(http::Method::GET, "/stored-checksum/object", Bytes::new(), mode_header()),
    )
    .await;
    assert_eq!(read.status(), 200);
    assert_eq!(read.body(), BODY);
    assert_eq!(
        header(&read, "x-amz-checksum-crc32").and_then(|v| v.to_str().ok()),
        Some(value.render_base64())
    );
}

#[tokio::test]
async fn n_a_missing_or_wrong_trailer_never_replaces_the_object() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "stored-checksum").await;
    let value = checksum(ChecksumAlgorithm::Crc32, BODY);
    assert_eq!(put_checksum(&service, "object", value).await.status(), 200);
    for trailer in [Trailer::Absent, Trailer::Field("x-amz-checksum-crc32", "AAAAAA==")] {
        let refused = exchange(
            &service,
            trailer_part_request("/stored-checksum/object", b"rejected bytes", "x-amz-checksum-crc32", &trailer, &[]),
        )
        .await;
        assert_eq!(refused.status(), 400);
        let read = exchange(
            &service,
            signed_with_headers(http::Method::GET, "/stored-checksum/object", Bytes::new(), mode_header()),
        )
        .await;
        assert_eq!(read.status(), 200);
        assert_eq!(read.body(), BODY);
        assert_eq!(
            header(&read, "x-amz-checksum-crc32").and_then(|v| v.to_str().ok()),
            Some(value.render_base64())
        );
    }
}

#[tokio::test]
async fn n_a_new_version_never_borrows_a_historical_checksum() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "stored-checksum").await;
    assert_eq!(
        super::versioning::set_versioning(&initial, "stored-checksum", "Enabled")
            .await
            .status(),
        200
    );
    let value = checksum(ChecksumAlgorithm::Crc32, BODY);
    let first = put_checksum(&initial, "object", value).await;
    assert_eq!(first.status(), 200);
    let version = header(&first, "x-amz-version-id")
        .expect("a version id")
        .to_str()
        .expect("a text id");
    let replaced = exchange(
        &initial,
        signed(http::Method::PUT, "/stored-checksum/object", Bytes::from_static(b"replacement")),
    )
    .await;
    assert_eq!(replaced.status(), 200);
    drop(initial);
    let (_, restarted) = service(&root);
    for method in [http::Method::GET, http::Method::HEAD] {
        let old = exchange(
            &restarted,
            signed_with_headers(
                method.clone(),
                &format!("/stored-checksum/object?versionId={version}"),
                Bytes::new(),
                mode_header(),
            ),
        )
        .await;
        assert_eq!(old.status(), 200);
        assert_eq!(
            header(&old, "x-amz-checksum-crc32").and_then(|v| v.to_str().ok()),
            Some(value.render_base64())
        );
        let current = exchange(
            &restarted,
            signed_with_headers(method, "/stored-checksum/object", Bytes::new(), mode_header()),
        )
        .await;
        assert_eq!(current.status(), 200);
        assert!(header(&current, "x-amz-checksum-crc32").is_none());
    }
}

#[tokio::test]
async fn n_an_upload_record_cannot_claim_a_stored_object_checksum() {
    let root = TestRoot::new();
    let (_, initial) = service(&root);
    create_bucket(&initial, "stored-checksum").await;
    let initiated = exchange(&initial, signed(http::Method::POST, "/stored-checksum/object?uploads", Bytes::new())).await;
    assert_eq!(initiated.status(), 200);
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    drop(initial);
    let path = super::multipart_checksums::upload_record(&root, "stored-checksum", &upload_id);
    let original = std::fs::read_to_string(&path).expect("the upload record");
    std::fs::write(&path, format!("{original}checksum/1 1\nCRC32 AAAAAA==\n")).expect("an invalid upload section");
    let (_, restarted) = service(&root);
    let response = exchange(&restarted, signed(http::Method::GET, "/stored-checksum?uploads", Bytes::new())).await;
    assert_eq!(response.status(), 500);
}
