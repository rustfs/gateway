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

//! Object-level server-managed encryption, recorded and reported as RustFS reports it.
//!
//! Responsible for: the algorithm and KMS key id a write names, or the bucket default it falls
//! back to, stored with the version and answered by the write and by every later `GET` and
//! `HEAD`, across restart, multipart and copy; the writes RustFS refuses (a KMS write with no key
//! and no KMS, an algorithm its write path cannot apply) storing nothing; reads that name an
//! encryption header refused; and an object written without either answering none.
//! NOT responsible for: the framework's managed-channel header rules or the SSE-C transport gate
//! (`crates/core` `sse` tests), or the bucket document (`bucket_encryption`).
//! Upstream: the fs backend through the production `S3Service`. Downstream: nothing.

use super::*;
use rustfs_gateway::WireResponse;

const SSE: &str = "x-amz-server-side-encryption";
const SSE_KEY: &str = "x-amz-server-side-encryption-aws-kms-key-id";
const AES256_DEFAULT: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
const AES256_DEFAULT_MD5: &str = "6vzSAkrj6gUU1ZdQlOJRWQ==";
const KMS_DEFAULT: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>fool-me-again</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
const KMS_DEFAULT_MD5: &str = "/1DqIrC/TcZcHGf2VS5+SA==";

fn headers(pairs: &[(&'static str, &str)]) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for (name, value) in pairs {
        map.insert(*name, http::HeaderValue::from_str(value).expect("a header value"));
    }
    map
}

async fn send(
    service: &S3Service,
    method: http::Method,
    target: &str,
    body: &'static [u8],
    pairs: &[(&'static str, &str)],
) -> WireResponse {
    exchange(service, signed_with_headers(method, target, Bytes::from_static(body), headers(pairs))).await
}

async fn set_default(service: &S3Service, bucket: &str, document: &'static str, md5: &str) {
    let response = send(
        service,
        http::Method::PUT,
        &format!("/{bucket}?encryption"),
        document.as_bytes(),
        &[("content-md5", md5)],
    )
    .await;
    assert_eq!(response.status(), 200, "{}", text(&response));
}

fn text(response: &WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn reported<'a>(response: &'a WireResponse, name: &str) -> Option<&'a str> {
    header(response, name).and_then(|value| value.to_str().ok())
}

/// The algorithm and key id a `GET` and a `HEAD` of `target` report.
async fn read_back(service: &S3Service, target: &str) -> [(Option<String>, Option<String>); 2] {
    let mut answers = [(None, None), (None, None)];
    for (slot, method) in answers.iter_mut().zip([http::Method::GET, http::Method::HEAD]) {
        let response = send(service, method, target, b"", &[]).await;
        assert_eq!(response.status(), 200, "{}", text(&response));
        *slot = (
            reported(&response, SSE).map(ToOwned::to_owned),
            reported(&response, SSE_KEY).map(ToOwned::to_owned),
        );
    }
    answers
}

fn both(algorithm: &str, key: Option<&str>) -> [(Option<String>, Option<String>); 2] {
    let one = (Some(algorithm.to_owned()), key.map(ToOwned::to_owned));
    [one.clone(), one]
}

/// Positive — an explicit SSE-S3 write is reported by the write, by `GET` and `HEAD`, and again
/// after a restart.
#[tokio::test]
async fn an_explicit_sse_s3_write_is_reported_by_every_read_and_survives_restart() {
    let root = TestRoot::new();
    let (_, first) = service(&root);
    create_bucket(&first, "sse").await;

    let written = send(&first, http::Method::PUT, "/sse/obj", b"hello", &[(SSE, "AES256")]).await;
    assert_eq!(written.status(), 200, "{}", text(&written));
    assert_eq!(reported(&written, SSE), Some("AES256"));
    assert_eq!(read_back(&first, "/sse/obj").await, both("AES256", None));
    drop(first);

    let (_, restarted) = service(&root);
    assert_eq!(read_back(&restarted, "/sse/obj").await, both("AES256", None));
}

/// Positive — an explicit SSE-KMS write reports its algorithm and the key id it named.
#[tokio::test]
async fn an_explicit_sse_kms_write_reports_its_key_id() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "sse").await;

    let written = send(
        &service,
        http::Method::PUT,
        "/sse/obj",
        b"hello",
        &[(SSE, "aws:kms"), (SSE_KEY, "testkey-1")],
    )
    .await;
    assert_eq!(written.status(), 200, "{}", text(&written));
    assert_eq!(reported(&written, SSE), Some("aws:kms"));
    assert_eq!(reported(&written, SSE_KEY), Some("testkey-1"));
    assert_eq!(read_back(&service, "/sse/obj").await, both("aws:kms", Some("testkey-1")));
}

/// Positive — a write naming nothing takes the bucket default: SSE-S3, then SSE-KMS with the
/// default's key id.
#[tokio::test]
async fn a_write_naming_nothing_takes_the_bucket_default() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "sse").await;

    set_default(&service, "sse", AES256_DEFAULT, AES256_DEFAULT_MD5).await;
    let written = send(&service, http::Method::PUT, "/sse/s3", b"hello", &[]).await;
    assert_eq!(reported(&written, SSE), Some("AES256"), "{}", text(&written));
    assert_eq!(read_back(&service, "/sse/s3").await, both("AES256", None));

    set_default(&service, "sse", KMS_DEFAULT, KMS_DEFAULT_MD5).await;
    let written = send(&service, http::Method::PUT, "/sse/kms", b"hello", &[]).await;
    assert_eq!(reported(&written, SSE), Some("aws:kms"), "{}", text(&written));
    assert_eq!(reported(&written, SSE_KEY), Some("fool-me-again"), "{}", text(&written));
    assert_eq!(read_back(&service, "/sse/kms").await, both("aws:kms", Some("fool-me-again")));
    // The object written under the first default keeps what it was written with.
    assert_eq!(read_back(&service, "/sse/s3").await, both("AES256", None));
}

/// Positive — a multipart upload under a bucket default is reported at initiation, completion and
/// on every read of the completed object.
#[tokio::test]
async fn a_multipart_upload_takes_the_default_at_initiation_and_reports_it_throughout() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "sse").await;
    set_default(&service, "sse", AES256_DEFAULT, AES256_DEFAULT_MD5).await;

    let initiated = send(&service, http::Method::POST, "/sse/big?uploads", b"", &[]).await;
    assert_eq!(initiated.status(), 200, "{}", text(&initiated));
    assert_eq!(reported(&initiated, SSE), Some("AES256"));
    let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
    let part = upload_part(&service, "sse", "big", &upload_id, 1, b"only part").await;
    let completed = complete(&service, "sse", "big", &upload_id, &[(1, part.as_str())]).await;
    assert_eq!(completed.status(), 200, "{}", text(&completed));
    assert_eq!(reported(&completed, SSE), Some("AES256"));
    assert_eq!(read_back(&service, "/sse/big").await, both("AES256", None));
}

/// Positive and control — a copy takes the encryption its own request names, not the source's: an
/// explicit SSE-S3 copy reports it, and a plain copy of an encrypted source into a bucket with no
/// default reports none.
#[tokio::test]
async fn a_copy_takes_its_own_request_encryption_not_the_sources() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "sse").await;
    assert_eq!(
        send(&service, http::Method::PUT, "/sse/src", b"hello", &[(SSE, "aws:kms"), (SSE_KEY, "k")])
            .await
            .status(),
        200
    );

    let encrypted = send(
        &service,
        http::Method::PUT,
        "/sse/enc",
        b"",
        &[("x-amz-copy-source", "/sse/src"), (SSE, "AES256")],
    )
    .await;
    assert_eq!(encrypted.status(), 200, "{}", text(&encrypted));
    assert_eq!(reported(&encrypted, SSE), Some("AES256"));
    assert_eq!(read_back(&service, "/sse/enc").await, both("AES256", None));

    let plain = send(&service, http::Method::PUT, "/sse/plain", b"", &[("x-amz-copy-source", "/sse/src")]).await;
    assert_eq!(plain.status(), 200, "{}", text(&plain));
    assert_eq!(reported(&plain, SSE), None);
    assert_eq!(read_back(&service, "/sse/plain").await, [(None, None), (None, None)]);
}

/// Control — an object written with no encryption into a bucket with no default reports none, so
/// the positive cases above are not an answer this backend gives to every object.
#[tokio::test]
async fn an_unencrypted_write_reports_no_encryption() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "sse").await;

    let written = send(&service, http::Method::PUT, "/sse/obj", b"hello", &[]).await;
    assert_eq!(written.status(), 200, "{}", text(&written));
    assert_eq!(reported(&written, SSE), None);
    assert_eq!(read_back(&service, "/sse/obj").await, [(None, None), (None, None)]);
}

/// Negative — an SSE-KMS write that names no key id, explicitly or through a default: RustFS
/// would ask its KMS for the default key, and this backend has none, so the write is refused and
/// nothing is stored.
#[tokio::test]
async fn a_kms_write_without_a_key_id_is_refused_and_stores_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "sse").await;

    let refused = send(&service, http::Method::PUT, "/sse/obj", b"hello", &[(SSE, "aws:kms")]).await;
    assert_eq!(refused.status(), 500, "{}", text(&refused));
    assert!(text(&refused).contains("<Code>InternalError</Code>"), "{}", text(&refused));
    assert_eq!(send(&service, http::Method::GET, "/sse/obj", b"", &[]).await.status(), 404);
}

/// Negative — algorithms the shared contract admits but RustFS's write path cannot apply are
/// `InvalidArgument`, and nothing is stored.
#[tokio::test]
async fn an_algorithm_rustfs_cannot_apply_is_invalid_argument_and_stores_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "sse").await;

    for algorithm in ["aws:kms:dsse", "aws:fsx"] {
        let refused = send(&service, http::Method::PUT, "/sse/obj", b"hello", &[(SSE, algorithm)]).await;
        assert_eq!(refused.status(), 400, "{algorithm}: {}", text(&refused));
        assert!(text(&refused).contains("<Code>InvalidArgument</Code>"), "{algorithm}: {}", text(&refused));
        assert_eq!(send(&service, http::Method::GET, "/sse/obj", b"", &[]).await.status(), 404);
    }
}

/// Negative — a `GET` or `HEAD` naming a managed algorithm is `400 InvalidArgument`, as RustFS
/// answers it, whether or not the object was written encrypted.
#[tokio::test]
async fn a_read_naming_an_encryption_algorithm_is_invalid_argument() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "sse").await;
    assert_eq!(
        send(&service, http::Method::PUT, "/sse/enc", b"hello", &[(SSE, "AES256")])
            .await
            .status(),
        200
    );
    assert_eq!(send(&service, http::Method::PUT, "/sse/plain", b"hello", &[]).await.status(), 200);

    for target in ["/sse/enc", "/sse/plain"] {
        for method in [http::Method::GET, http::Method::HEAD] {
            let refused = send(&service, method.clone(), target, b"", &[(SSE, "AES256")]).await;
            assert_eq!(refused.status(), 400, "{method} {target}: {}", text(&refused));
        }
    }
}

/// Negative — a KMS key id beside no algorithm never reaches storage.
#[tokio::test]
async fn a_key_id_without_an_algorithm_stores_nothing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "sse").await;

    let refused = send(&service, http::Method::PUT, "/sse/obj", b"hello", &[(SSE_KEY, "testkey-1")]).await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert_eq!(send(&service, http::Method::GET, "/sse/obj", b"", &[]).await.status(), 404);
}

/// Positive and control — `UploadPart` and `UploadPartCopy` report the encryption the upload was
/// initiated under (s3-tests `test_copy_part_enc`), and nothing for an unencrypted upload.
#[tokio::test]
async fn part_writes_report_the_uploads_encryption() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "sse").await;
    assert_eq!(send(&service, http::Method::PUT, "/sse/src", b"source", &[]).await.status(), 200);

    for (key, initiation, expected) in [("enc", &[(SSE, "AES256")][..], Some("AES256")), ("plain", &[][..], None)] {
        let initiated = send(&service, http::Method::POST, &format!("/sse/{key}?uploads"), b"", initiation).await;
        let upload_id = element(initiated.body(), "UploadId").expect("an upload id");
        let part = send(
            &service,
            http::Method::PUT,
            &format!("/sse/{key}?partNumber=1&uploadId={upload_id}"),
            b"part",
            &[],
        )
        .await;
        assert_eq!(part.status(), 200, "{}", text(&part));
        assert_eq!(reported(&part, SSE), expected, "{key}: UploadPart");
        let copied = send(
            &service,
            http::Method::PUT,
            &format!("/sse/{key}?partNumber=2&uploadId={upload_id}"),
            b"",
            &[("x-amz-copy-source", "/sse/src")],
        )
        .await;
        assert_eq!(copied.status(), 200, "{}", text(&copied));
        assert_eq!(reported(&copied, SSE), expected, "{key}: UploadPartCopy");
    }
}
