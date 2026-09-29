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

//! The MinIO clients' checksum-less writes as the RustFS-profile launcher serves them
//! (rustfs/gateway#916, and rustfs/backlog#1677 ruling R5 for every other write).
//!
//! Responsible for: a `PutBucketPolicy` and a `PutBucketVersioning` with no integrity header —
//! what minio-go, minio-js and `mc anonymous set` send — being stored, while a present
//! `Content-MD5` is still verified; and the lifecycle and public-access-block writes, which every
//! MinIO SDK checksums, being stored without one too, as legacy RustFS stores them.
//! NOT responsible for: the default AWS-model requirement, which the conformance corpus pins
//! (`c-bucketconfig-0039`), the MinIO waiver's own closed set (`rustfs_gateway::client_quirks`
//! and `crates/gateway/tests/checksum_omissions.rs`), or the other checksum-required writes
//! (`checksum_omission_tests.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

const POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::minio/*"}]}"#;
const VERSIONING: &str = "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
const LIFECYCLE: &str = "<LifecycleConfiguration><Rule><ID>r</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>";
const BLOCK: &str =
    "<PublicAccessBlockConfiguration><BlockPublicPolicy>true</BlockPublicPolicy></PublicAccessBlockConfiguration>";
/// The base64 MD5 of `wrong`, which is none of the documents above.
const WRONG_MD5: &str = "K9opmNmw7hl9oUKgRH9nJQ==";

async fn put(service: &S3Service, target: &str, body: &'static str, extra: &[(&str, &str)]) -> WireResponse {
    let request = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        target,
        Bytes::from_static(body.as_bytes()),
        extra,
    );
    exchange(service, request).await
}

async fn get(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

async fn minio_bucket(root: &TestRoot) -> S3Service {
    let options = two_identity_options(root, &[]);
    let (_backend, service) = assembled(&options);
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/minio", Bytes::new()))
            .await
            .status(),
        200
    );
    service
}

/// Positive — minio-go's and minio-js's `SetBucketPolicy` (and so `mc anonymous set`) send no
/// integrity header; the policy is stored and reads back verbatim.
#[tokio::test]
async fn a_policy_without_a_checksum_is_stored() {
    let root = TestRoot::new();
    let service = minio_bucket(&root).await;

    let written = put(&service, "/minio?policy", POLICY, &[]).await;
    assert!(matches!(written.status().as_u16(), 200 | 204), "{}", body_of(&written));
    let read = get(&service, "/minio?policy").await;
    assert_eq!(read.status(), 200, "{}", body_of(&read));
    assert_eq!(body_of(&read), POLICY);
}

/// Positive — minio-js's `setBucketVersioning` sends no integrity header either.
#[tokio::test]
async fn versioning_without_a_checksum_is_stored() {
    let root = TestRoot::new();
    let service = minio_bucket(&root).await;

    let written = put(&service, "/minio?versioning", VERSIONING, &[]).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    let read = get(&service, "/minio?versioning").await;
    assert!(body_of(&read).contains("<Status>Enabled</Status>"), "{}", body_of(&read));
}

/// Negative — the waiver drops the requirement, not the verification: a `Content-MD5` that does
/// not match the policy is still `BadDigest`, and nothing is stored.
#[tokio::test]
async fn a_present_but_wrong_checksum_is_still_refused() {
    let root = TestRoot::new();
    let service = minio_bucket(&root).await;

    let refused = put(&service, "/minio?policy", POLICY, &[("content-md5", WRONG_MD5)]).await;
    assert_eq!(refused.status(), 400, "{}", body_of(&refused));
    assert!(body_of(&refused).contains("<Code>BadDigest</Code>"), "{}", body_of(&refused));
    assert_eq!(get(&service, "/minio?policy").await.status(), 404);
}

/// Positive — legacy RustFS requires a checksum on no write, so the lifecycle and
/// public-access-block writes are stored without one as well.
///
/// This case asserted a `400 InvalidRequest` until rustfs/backlog#1677 ruling R5: that answer was
/// the MinIO waiver's closed set, not RustFS's. Legacy RustFS reads no `Content-MD5` in either
/// handler (rustfs/rustfs@e870a6d25b `rustfs/src/storage/ecfs.rs:1424`, `:1483`), and a legacy
/// RustFS build answered both writes with no integrity header `200` and stored them. The waiver's
/// closed set is still held, at the assembly, by `crates/gateway/tests/checksum_omissions.rs`
/// (`n_the_two_client_waivers_alone_leave_every_other_write_required`).
#[tokio::test]
async fn other_checksum_required_writes_are_stored_without_a_checksum_as_legacy_rustfs_stores_them() {
    let root = TestRoot::new();
    let service = minio_bucket(&root).await;

    for (target, body, stored) in [
        ("/minio?lifecycle", LIFECYCLE, "<ID>r</ID>"),
        ("/minio?publicAccessBlock", BLOCK, "<BlockPublicPolicy>true</BlockPublicPolicy>"),
    ] {
        let written = put(&service, target, body, &[]).await;
        assert_eq!(written.status(), 200, "{target}: {}", body_of(&written));
        let read = get(&service, target).await;
        assert!(body_of(&read).contains(stored), "{target}: {}", body_of(&read));
    }
}
