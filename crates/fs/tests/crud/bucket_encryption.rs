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

//! The default-encryption family through the production registry, answered as RustFS answers it.
//!
//! Responsible for: the configuration stored and read back, the absent-configuration `404`, the
//! idempotent `204` delete, the missing-bucket refusals, and the documents RustFS refuses beyond
//! the shared contract (an algorithm it cannot apply, a rule with no default, a KMS default with
//! no key id and no KMS to supply one), none of which is stored.
//! NOT responsible for: the shared document contract (`crates/core` `encryption_tests`) or object
//! writes under a default, which a later slice owns.
//! Upstream: the fs backend through the production `S3Service`. Downstream: nothing.

use super::*;
use rustfs_gateway::WireResponse;

const AES256: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
const AES256_MD5: &str = "6vzSAkrj6gUU1ZdQlOJRWQ==";
const KMS: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>fool-me-again</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
const KMS_MD5: &str = "/1DqIrC/TcZcHGf2VS5+SA==";
const KMS_NO_KEY: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
const KMS_NO_KEY_MD5: &str = "/+vrqlLuIVZHlxmsgTdYIA==";
const DSSE: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms:dsse</SSEAlgorithm><KMSMasterKeyID>fool-me-again</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
const DSSE_MD5: &str = "eek/XE9PQO1Pygq15v91Cg==";
const AES256_WITH_KEY: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm><KMSMasterKeyID>fool-me-again</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
const AES256_WITH_KEY_MD5: &str = "Ewnxz8aaMjJ27tG4BXZEUA==";
const NO_DEFAULT: &str = "<ServerSideEncryptionConfiguration><Rule><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";
const NO_DEFAULT_MD5: &str = "Zn0OSiV/D92cS0c8O98+dA==";
const NO_RULE: &str = "<ServerSideEncryptionConfiguration></ServerSideEncryptionConfiguration>";
const NO_RULE_MD5: &str = "E8w172JdK+yTjeUgOZnhRQ==";

async fn put(service: &S3Service, target: &str, body: &'static str, md5: &str) -> WireResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert("content-md5", http::HeaderValue::from_str(md5).expect("a header value"));
    exchange(
        service,
        signed_with_headers(http::Method::PUT, target, Bytes::from_static(body.as_bytes()), headers),
    )
    .await
}

async fn get(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, signed(http::Method::GET, target, Bytes::new())).await
}

async fn delete(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, signed(http::Method::DELETE, target, Bytes::new())).await
}

fn text(response: &WireResponse) -> String {
    String::from_utf8_lossy(response.body()).into_owned()
}

fn assert_absent(response: &WireResponse) {
    assert_eq!(response.status(), 404, "{}", text(response));
    assert!(
        text(response).contains("<Code>ServerSideEncryptionConfigurationNotFoundError</Code>"),
        "{}",
        text(response)
    );
}

/// Positive — an SSE-S3 default is stored and read back; a delete leaves the bucket with none
/// again, and deleting what is absent is the same quiet `204`, before and after.
#[tokio::test]
async fn an_sse_s3_default_is_stored_read_back_and_deleted() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "enc").await;

    assert_absent(&get(&service, "/enc?encryption").await);
    let absent_delete = delete(&service, "/enc?encryption").await;
    assert_eq!(absent_delete.status(), 204, "{}", text(&absent_delete));

    let written = put(&service, "/enc?encryption", AES256, AES256_MD5).await;
    assert_eq!(written.status(), 200, "{}", text(&written));
    let read = get(&service, "/enc?encryption").await;
    assert_eq!(read.status(), 200, "{}", text(&read));
    assert_eq!(element(read.body(), "SSEAlgorithm").as_deref(), Some("AES256"), "{}", text(&read));
    assert_eq!(element(read.body(), "KMSMasterKeyID"), None, "{}", text(&read));

    for _ in 0..2 {
        let deleted = delete(&service, "/enc?encryption").await;
        assert_eq!(deleted.status(), 204, "{}", text(&deleted));
    }
    assert_absent(&get(&service, "/enc?encryption").await);
}

/// Positive — an SSE-KMS default keeps the key id it named, survives a restart, and a later write
/// replaces it rather than adding a rule.
#[tokio::test]
async fn an_sse_kms_default_keeps_its_key_id_and_is_replaced_by_the_next_write() {
    let root = TestRoot::new();
    let (_, first) = service(&root);
    create_bucket(&first, "enc").await;

    assert_eq!(put(&first, "/enc?encryption", KMS, KMS_MD5).await.status(), 200);
    drop(first);
    let (_, restarted) = service(&root);
    let read = get(&restarted, "/enc?encryption").await;
    assert_eq!(read.status(), 200, "{}", text(&read));
    assert_eq!(element(read.body(), "SSEAlgorithm").as_deref(), Some("aws:kms"), "{}", text(&read));
    assert_eq!(
        element(read.body(), "KMSMasterKeyID").as_deref(),
        Some("fool-me-again"),
        "{}",
        text(&read)
    );

    assert_eq!(put(&restarted, "/enc?encryption", AES256, AES256_MD5).await.status(), 200);
    let replaced = get(&restarted, "/enc?encryption").await;
    assert_eq!(text(&replaced).matches("<Rule>").count(), 1, "{}", text(&replaced));
    assert_eq!(element(replaced.body(), "SSEAlgorithm").as_deref(), Some("AES256"), "{}", text(&replaced));
}

/// Negative — all three operations on a bucket that does not exist are `NoSuchBucket`, and the
/// write creates nothing.
#[tokio::test]
async fn every_operation_on_a_missing_bucket_is_no_such_bucket() {
    let root = TestRoot::new();
    let (_, service) = service(&root);

    for response in [
        put(&service, "/ghost?encryption", AES256, AES256_MD5).await,
        get(&service, "/ghost?encryption").await,
        delete(&service, "/ghost?encryption").await,
    ] {
        assert_eq!(response.status(), 404, "{}", text(&response));
        assert!(text(&response).contains("<Code>NoSuchBucket</Code>"), "{}", text(&response));
    }
    assert!(
        !root.0.join(format!("b-{}", hex::encode("ghost"))).exists(),
        "a refused write creates no bucket"
    );
}

/// Negative — what the shared contract refuses: a KMS key id beside `AES256`.
#[tokio::test]
async fn a_kms_key_beside_aes256_is_invalid_argument_and_not_stored() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "enc").await;

    let refused = put(&service, "/enc?encryption", AES256_WITH_KEY, AES256_WITH_KEY_MD5).await;
    assert_eq!(refused.status(), 400, "{}", text(&refused));
    assert!(text(&refused).contains("<Code>InvalidArgument</Code>"), "{}", text(&refused));
    assert_absent(&get(&service, "/enc?encryption").await);
}

/// Negative — what RustFS refuses beyond the shared contract, each `MalformedXML` and none stored:
/// an algorithm its write path cannot apply (`aws:kms:dsse`), a rule with no default to apply, and
/// a document with no rule.
#[tokio::test]
async fn documents_rustfs_cannot_honour_are_malformed_xml_and_not_stored() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "enc").await;

    for (body, md5) in [(DSSE, DSSE_MD5), (NO_DEFAULT, NO_DEFAULT_MD5), (NO_RULE, NO_RULE_MD5)] {
        let refused = put(&service, "/enc?encryption", body, md5).await;
        assert_eq!(refused.status(), 400, "{body}: {}", text(&refused));
        assert!(text(&refused).contains("<Code>MalformedXML</Code>"), "{body}: {}", text(&refused));
        assert_absent(&get(&service, "/enc?encryption").await);
    }
}

/// Negative — an SSE-KMS default that names no key: RustFS fills in its KMS's default key, and a
/// RustFS with no KMS configured refuses the write. This backend has no KMS, so it refuses, and
/// stores nothing.
#[tokio::test]
async fn a_kms_default_without_a_key_id_is_refused_without_a_kms() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "enc").await;

    let refused = put(&service, "/enc?encryption", KMS_NO_KEY, KMS_NO_KEY_MD5).await;
    assert_eq!(refused.status(), 500, "{}", text(&refused));
    assert!(text(&refused).contains("<Code>InternalError</Code>"), "{}", text(&refused));
    assert_absent(&get(&service, "/enc?encryption").await);
}

/// Negative — the configuration leaves with its bucket: a bucket re-created under the same name
/// starts without one.
#[tokio::test]
async fn a_recreated_bucket_starts_without_a_configuration() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "enc").await;
    assert_eq!(put(&service, "/enc?encryption", AES256, AES256_MD5).await.status(), 200);

    let removed = exchange(&service, signed(http::Method::DELETE, "/enc", Bytes::new())).await;
    assert_eq!(removed.status(), 204, "{}", text(&removed));
    create_bucket(&service, "enc").await;
    assert_absent(&get(&service, "/enc?encryption").await);
}
