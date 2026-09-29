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

//! The s3cmd ACL checksum waiver as the RustFS-profile launcher serves it (rustfs/gateway#912).
//!
//! Responsible for: the `PutObjectAcl` that `s3cmd cp` sends after copying and the
//! `PutBucketAcl`/`PutObjectAcl` of `s3cmd setacl` — an `AccessControlPolicy` body with no
//! integrity header — reaching the backend and getting RustFS's own answer, while a present
//! `Content-MD5` is still verified; and s3cmd's lifecycle write reaching it without one too, as
//! legacy RustFS serves every write (rustfs/backlog#1677, ruling R5).
//! NOT responsible for: the default AWS-model requirement, which the conformance corpus pins,
//! the s3cmd waiver's own closed set (`rustfs_gateway::client_quirks` and
//! `crates/gateway/tests/checksum_omissions.rs`), or what the backend does with an ACL
//! (`rustfs_gateway_fs::acl`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

/// The document s3cmd writes back: the owner's single `FULL_CONTROL` grant it just read.
const POLICY_DOCUMENT: &str = "<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>s3gate-main</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>s3gate-main</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>";
const LIFECYCLE: &str = "<LifecycleConfiguration><Rule><ID>r</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>";
/// The base64 MD5 of `wrong`, which is not the document above.
const WRONG_MD5: &str = "K9opmNmw7hl9oUKgRH9nJQ==";
const XML: (&str, &str) = ("content-type", "application/xml");

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

async fn s3cmd_object(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/s3cmd", Bytes::new()))
            .await
            .status(),
        200
    );
    let object = exchange(&service, as_main(http::Method::PUT, "/s3cmd/k", Bytes::from_static(b"copied"))).await;
    assert_eq!(object.status(), 200, "{}", body_of(&object));
    service
}

/// Positive — the ACL documents s3cmd sends with no integrity header reach the backend and get
/// RustFS's `501 NotImplemented`, which `s3cmd cp` tolerates, instead of the codec's `400`.
#[tokio::test]
async fn an_acl_document_without_a_checksum_reaches_the_backend() {
    let root = TestRoot::new();
    let service = s3cmd_object(&root).await;

    for target in ["/s3cmd/k?acl", "/s3cmd?acl"] {
        let answered = put(&service, target, POLICY_DOCUMENT, &[XML]).await;
        assert_eq!(answered.status(), 501, "{target}: {}", body_of(&answered));
        assert!(
            body_of(&answered).contains("<Code>NotImplemented</Code>"),
            "{target}: {}",
            body_of(&answered)
        );
    }
}

/// Positive — a canned ACL with no body and no integrity header is accepted, as RustFS accepts it.
#[tokio::test]
async fn a_canned_acl_without_a_checksum_is_accepted() {
    let root = TestRoot::new();
    let service = s3cmd_object(&root).await;

    for target in ["/s3cmd/k?acl", "/s3cmd?acl"] {
        let answered = put(&service, target, "", &[("x-amz-acl", "private")]).await;
        assert_eq!(answered.status(), 200, "{target}: {}", body_of(&answered));
    }
}

/// Negative — the waiver drops the requirement, not the verification: a `Content-MD5` that does
/// not match the document is still `BadDigest` on both operations.
#[tokio::test]
async fn n_a_present_but_wrong_checksum_is_still_refused() {
    let root = TestRoot::new();
    let service = s3cmd_object(&root).await;

    for target in ["/s3cmd/k?acl", "/s3cmd?acl"] {
        let refused = put(&service, target, POLICY_DOCUMENT, &[XML, ("content-md5", WRONG_MD5)]).await;
        assert_eq!(refused.status(), 400, "{target}: {}", body_of(&refused));
        assert!(body_of(&refused).contains("<Code>BadDigest</Code>"), "{target}: {}", body_of(&refused));
    }
}

/// Positive — a checksum-required write outside the ACL pair is stored without a checksum too,
/// because legacy RustFS requires one on no write.
///
/// This case asserted a `400 InvalidRequest` until rustfs/backlog#1677 ruling R5: that answer was
/// the s3cmd waiver's closed set, not RustFS's. Legacy RustFS reads no `Content-MD5` in its
/// lifecycle handler (rustfs/rustfs@e870a6d25b `rustfs/src/storage/ecfs.rs:1424`), and a legacy
/// RustFS build answered the write with no integrity header `200` and stored it. The waiver's
/// closed set is still held, at the assembly, by `crates/gateway/tests/checksum_omissions.rs`
/// (`n_the_two_client_waivers_alone_leave_every_other_write_required`).
#[tokio::test]
async fn other_checksum_required_writes_are_stored_without_a_checksum_as_legacy_rustfs_stores_them() {
    let root = TestRoot::new();
    let service = s3cmd_object(&root).await;

    let written = put(&service, "/s3cmd?lifecycle", LIFECYCLE, &[]).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    let read = exchange(&service, as_main(http::Method::GET, "/s3cmd?lifecycle", Bytes::new())).await;
    assert!(body_of(&read).contains("<ID>r</ID>"), "{}", body_of(&read));
}
