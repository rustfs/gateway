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

//! Bucket-policy conditions on `s3:x-amz-server-side-encryption`, end to end and signed
//! (rustfs/gateway#979).
//!
//! Responsible for: the `Null`, `StringEquals` and `StringNotEquals` operators on the request's
//! encryption header deciding a `Deny`, the operators of one block combining with AND, a refused
//! write publishing nothing, and an operator value the evaluator cannot read staying unsupported.
//! NOT responsible for: the `s3:x-amz-acl` conditions (`policy_tests`) or the evaluator's unit
//! rules (`rustfs_gateway_fs::policy::evaluate` tests).
//! Upstream: the parent module's two-identity assembly and `policy_tests`' fixture bucket.
//! Downstream: nothing.

use super::policy_tests::{policed, put_policy};
use super::*;

const SSE_NULL_TRUE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"Null":{"s3:x-amz-server-side-encryption":"true"}}}]}"#;
const SSE_NULL_TRUE_MD5: &str = "YylmY149iZ4AvAKaeH552Q==";
const SSE_NULL_FALSE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"Null":{"s3:x-amz-server-side-encryption":"false"}}}]}"#;
const SSE_NULL_FALSE_MD5: &str = "Y9YaIreUqYwRi9y1sdE5eA==";
const SSE_NOT_AES: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringNotEquals":{"s3:x-amz-server-side-encryption":"AES256"}}}]}"#;
const SSE_NOT_AES_MD5: &str = "IntXDevxEC49NotlQNQFpg==";
const SSE_EQ_KMS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringEquals":{"s3:x-amz-server-side-encryption":"aws:kms"}}}]}"#;
const SSE_EQ_KMS_MD5: &str = "GyidqD4+1iDTPR1CaVPF6A==";
const SSE_NULL_MAYBE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"Null":{"s3:x-amz-server-side-encryption":"maybe"}}}]}"#;
const SSE_NULL_MAYBE_MD5: &str = "6GJXgc6b0OZ7UsjXejvQIA==";
const SSE_BOTH: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringNotEquals":{"s3:x-amz-server-side-encryption":"AES256"},"Null":{"s3:x-amz-acl":"false"}}}]}"#;
const SSE_BOTH_MD5: &str = "C3P69rO+D+u+NyGlxmZrTQ==";

const AES: &[(&str, &str)] = &[("x-amz-server-side-encryption", "AES256")];
const KMS: &[(&str, &str)] = &[
    ("x-amz-server-side-encryption", "aws:kms"),
    ("x-amz-server-side-encryption-aws-kms-key-id", "testkey-1"),
];

/// An owner PUT of `key` with `extra` headers must answer `expected`; a refusal publishes nothing.
async fn owner_put(service: &S3Service, key: &str, extra: &[(&str, &str)], expected: u16) {
    let target = format!("/policed/{key}");
    let response = exchange(
        service,
        signed(MAIN_KEY, MAIN_SECRET, http::Method::PUT, &target, Bytes::from_static(b"sse"), extra),
    )
    .await;
    assert_eq!(response.status(), expected, "{key}: {}", body_of(&response));
    let read = exchange(service, as_main(http::Method::HEAD, &target, Bytes::new())).await;
    assert_eq!(read.status(), if expected == 403 { 404 } else { 200 }, "{key} after {expected}");
}

async fn with_policy(document: &'static str, md5: &str) -> (TestRoot, S3Service) {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    let written = put_policy(&service, document, md5).await;
    assert_eq!(written.status(), 204, "{}", body_of(&written));
    (root, service)
}

/// Negative and positive — `Null: true` denies a write that names no encryption, and only that
/// (s3-tests `test_bucket_policy_put_obj_s3_noenc`).
#[tokio::test]
async fn a_null_true_deny_refuses_only_unencrypted_writes() {
    let (_root, service) = with_policy(SSE_NULL_TRUE, SSE_NULL_TRUE_MD5).await;
    owner_put(&service, "plain", &[], 403).await;
    owner_put(&service, "aes", AES, 200).await;
    owner_put(&service, "kms", KMS, 200).await;
}

/// Negative and positive — `Null: false` is the mirror image: it denies a write that does name one.
#[tokio::test]
async fn a_null_false_deny_refuses_only_encrypted_writes() {
    let (_root, service) = with_policy(SSE_NULL_FALSE, SSE_NULL_FALSE_MD5).await;
    owner_put(&service, "plain", &[], 200).await;
    owner_put(&service, "aes", AES, 403).await;
}

/// Negative — `StringNotEquals` denies another algorithm and, as AWS evaluates a negated operator
/// on an absent key, a write naming none (s3-tests `test_bucket_policy_put_obj_s3_kms`).
#[tokio::test]
async fn a_string_not_equals_deny_refuses_other_and_absent_algorithms() {
    let (_root, service) = with_policy(SSE_NOT_AES, SSE_NOT_AES_MD5).await;
    owner_put(&service, "kms", KMS, 403).await;
    owner_put(&service, "plain", &[], 403).await;
    owner_put(&service, "aes", AES, 200).await;
}

/// Negative — `StringEquals` denies exactly the named algorithm, and an absent key never matches.
#[tokio::test]
async fn a_string_equals_deny_refuses_exactly_the_named_algorithm() {
    let (_root, service) = with_policy(SSE_EQ_KMS, SSE_EQ_KMS_MD5).await;
    owner_put(&service, "kms", KMS, 403).await;
    owner_put(&service, "aes", AES, 200).await;
    owner_put(&service, "plain", &[], 200).await;
}

/// Negative — two operators in one block must both match: the encryption clause alone is not
/// enough to deny.
#[tokio::test]
async fn operators_in_one_block_combine_with_and() {
    let (_root, service) = with_policy(SSE_BOTH, SSE_BOTH_MD5).await;
    owner_put(&service, "plain-no-acl", &[], 200).await;
    owner_put(&service, "plain-acl", &[("x-amz-acl", "private")], 403).await;
    owner_put(&service, "aes-acl", &[("x-amz-acl", "private"), AES[0]], 200).await;
}

/// Negative — a `Null` value that is not a boolean stays unsupported: the Deny neither matches nor
/// is turned into an unconditional refusal (the documented fail-open cost of an unsupported Deny).
#[tokio::test]
async fn a_null_operator_with_a_non_boolean_value_stays_unsupported() {
    let (_root, service) = with_policy(SSE_NULL_MAYBE, SSE_NULL_MAYBE_MD5).await;
    owner_put(&service, "plain", &[], 200).await;
    owner_put(&service, "aes", AES, 200).await;
}
