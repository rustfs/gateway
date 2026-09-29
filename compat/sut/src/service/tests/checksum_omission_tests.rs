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

//! Every checksum-required write the RustFS-profile launcher serves, with no integrity claim and
//! with a wrong one (rustfs/backlog#1677, ruling R5).
//!
//! Responsible for: each of the eleven `httpChecksumRequired` operations the reference backend
//! registers being stored with no `Content-MD5` or `x-amz-checksum-*` at all, as legacy RustFS
//! stores it, and — the data-layer half — a claim that does not match the body being refused with
//! nothing stored and nothing deleted.
//! NOT responsible for: the seven checksum-required operations the reference backend does not
//! register (the assembly-level cases in `crates/gateway/tests/checksum_omissions.rs` cover all
//! eighteen), or why a mismatched `x-amz-checksum-*` is `BadDigest` here, which is
//! `ServiceBuilder::answer_checksum_failures_with_bad_digest`'s (rustfs/gateway#1057).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed: a legacy RustFS build (`RUSTFS_S3_STACK=legacy`) answered all
//! eighteen writes with no integrity header `200`/`204` and stored them, and did the same with a
//! `Content-MD5` or `x-amz-checksum-crc32` that did not match the body (it compares neither on
//! these operations). The launcher keeps the first answer and refuses the second.

use super::*;

const XMLNS: &str = "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
/// The base64 MD5 and CRC32 of `wrong`, which is none of the bodies below.
const WRONG_MD5: &str = "K9opmNmw7hl9oUKgRH9nJQ==";
const WRONG_CRC32: &str = "J8WdGg==";

/// One checksum-required write: the target, an extra header it needs, its body, and where and
/// what to read back to see whether it was stored — none for a canned ACL, which the reference
/// backend accepts and answers from the owner's grant whatever was written.
struct Write {
    target: &'static str,
    extra: Option<(&'static str, &'static str)>,
    body: String,
    read_back: Option<(&'static str, &'static str)>,
}

fn writes() -> Vec<Write> {
    vec![
        Write {
            target: "/omit?cors",
            extra: None,
            body: format!(
                "<CORSConfiguration {XMLNS}><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>https://omit.example</AllowedOrigin></CORSRule></CORSConfiguration>"
            ),
            read_back: Some(("/omit?cors", "https://omit.example")),
        },
        Write {
            target: "/omit?encryption",
            extra: None,
            body: format!(
                "<ServerSideEncryptionConfiguration {XMLNS}><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"
            ),
            read_back: Some(("/omit?encryption", "<SSEAlgorithm>AES256</SSEAlgorithm>")),
        },
        Write {
            target: "/omit?lifecycle",
            extra: None,
            body: format!(
                "<LifecycleConfiguration {XMLNS}><Rule><ID>omitted-rule</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
            ),
            read_back: Some(("/omit?lifecycle", "<ID>omitted-rule</ID>")),
        },
        Write {
            target: "/omit?policy",
            extra: None,
            body: r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::omit/*"}]}"#
                .to_owned(),
            read_back: Some(("/omit?policy", "arn:aws:s3:::omit/*")),
        },
        Write {
            target: "/omit?tagging",
            extra: None,
            body: format!("<Tagging {XMLNS}><TagSet><Tag><Key>bucket-tag</Key><Value>b</Value></Tag></TagSet></Tagging>"),
            read_back: Some(("/omit?tagging", "<Key>bucket-tag</Key>")),
        },
        Write {
            target: "/omit?versioning",
            extra: None,
            body: format!("<VersioningConfiguration {XMLNS}><Status>Suspended</Status></VersioningConfiguration>"),
            read_back: Some(("/omit?versioning", "<Status>Suspended</Status>")),
        },
        Write {
            target: "/omit/k?tagging",
            extra: None,
            body: format!("<Tagging {XMLNS}><TagSet><Tag><Key>object-tag</Key><Value>o</Value></Tag></TagSet></Tagging>"),
            read_back: Some(("/omit/k?tagging", "<Key>object-tag</Key>")),
        },
        Write {
            target: "/omit?publicAccessBlock",
            extra: None,
            body: format!(
                "<PublicAccessBlockConfiguration {XMLNS}><BlockPublicPolicy>true</BlockPublicPolicy></PublicAccessBlockConfiguration>"
            ),
            read_back: Some(("/omit?publicAccessBlock", "<BlockPublicPolicy>true</BlockPublicPolicy>")),
        },
        Write {
            target: "/omit?acl",
            extra: Some(("x-amz-acl", "public-read")),
            body: String::new(),
            read_back: None,
        },
        Write {
            target: "/omit/k?acl",
            extra: Some(("x-amz-acl", "public-read")),
            body: String::new(),
            read_back: None,
        },
    ]
}

/// The `DeleteObjects` body that deletes `victim`.
fn delete_victim() -> String {
    format!("<Delete {XMLNS}><Object><Key>victim</Key></Object></Delete>")
}

async fn send(service: &S3Service, method: http::Method, target: &str, body: String, extra: &[(&str, &str)]) -> WireResponse {
    let request = signed(MAIN_KEY, MAIN_SECRET, method, target, Bytes::from(body), extra);
    exchange(service, request).await
}

async fn read(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

/// The launcher with a bucket `omit` holding `k` and `victim`.
async fn omit_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    for (target, body) in [("/omit", ""), ("/omit/k", "object"), ("/omit/victim", "doomed")] {
        let made = exchange(&service, as_main(http::Method::PUT, target, Bytes::from_static(body.as_bytes()))).await;
        assert_eq!(made.status(), 200, "{target}: {}", body_of(&made));
    }
    service
}

fn code_of(response: &WireResponse) -> Option<String> {
    let body = body_of(response);
    let start = body.find("<Code>")? + "<Code>".len();
    let end = body[start..].find("</Code>")? + start;
    Some(body[start..end].to_owned())
}

/// Positive — every checksum-required write the backend serves is stored with no integrity claim,
/// and reads back as written.
#[tokio::test]
async fn every_checksum_required_write_is_stored_without_a_checksum() {
    let root = TestRoot::new();
    let service = omit_bucket(&root).await;

    for write in writes() {
        let extra: Vec<(&str, &str)> = write.extra.into_iter().collect();
        let written = send(&service, http::Method::PUT, write.target, write.body, &extra).await;
        assert!(written.status().is_success(), "{}: {}", write.target, body_of(&written));
        if let Some((target, stored)) = write.read_back {
            let read = read(&service, target).await;
            assert!(body_of(&read).contains(stored), "{target}: {}", body_of(&read));
        }
    }
}

/// Positive — `DeleteObjects` with no integrity claim deletes the key it names.
#[tokio::test]
async fn delete_objects_without_a_checksum_deletes_the_named_key() {
    let root = TestRoot::new();
    let service = omit_bucket(&root).await;

    let deleted = send(&service, http::Method::POST, "/omit?delete", delete_victim(), &[]).await;
    assert_eq!(deleted.status(), 200, "{}", body_of(&deleted));
    assert!(body_of(&deleted).contains("<Deleted><Key>victim</Key>"), "{}", body_of(&deleted));
    assert_eq!(read(&service, "/omit/victim").await.status(), 404);
}

/// Negative — a `Content-MD5` that does not match is `400 BadDigest` on every write, and nothing
/// it carried is stored. Legacy RustFS stores these bodies; the launcher does not.
#[tokio::test]
async fn n_a_content_md5_that_does_not_match_stores_nothing() {
    let root = TestRoot::new();
    let service = omit_bucket(&root).await;

    for write in writes() {
        let mut extra: Vec<(&str, &str)> = write.extra.into_iter().collect();
        extra.push(("content-md5", WRONG_MD5));
        let refused = send(&service, http::Method::PUT, write.target, write.body, &extra).await;
        assert_eq!(
            (refused.status().as_u16(), code_of(&refused).as_deref()),
            (400, Some("BadDigest")),
            "{}: {}",
            write.target,
            body_of(&refused)
        );
        if let Some((target, stored)) = write.read_back {
            let read = read(&service, target).await;
            assert!(!body_of(&read).contains(stored), "{target}: {}", body_of(&read));
        }
    }
}

/// Negative — the same for an `x-amz-checksum-*` header that does not match: `400 BadDigest`
/// before the backend, nothing stored.
#[tokio::test]
async fn n_a_checksum_header_that_does_not_match_stores_nothing() {
    let root = TestRoot::new();
    let service = omit_bucket(&root).await;

    for write in writes() {
        let mut extra: Vec<(&str, &str)> = write.extra.into_iter().collect();
        extra.extend([
            ("x-amz-checksum-crc32", WRONG_CRC32),
            ("x-amz-sdk-checksum-algorithm", "CRC32"),
        ]);
        let refused = send(&service, http::Method::PUT, write.target, write.body, &extra).await;
        assert_eq!(
            (refused.status().as_u16(), code_of(&refused).as_deref()),
            (400, Some("BadDigest")),
            "{}: {}",
            write.target,
            body_of(&refused)
        );
        if let Some((target, stored)) = write.read_back {
            let read = read(&service, target).await;
            assert!(!body_of(&read).contains(stored), "{target}: {}", body_of(&read));
        }
    }
}

/// Negative — a `DeleteObjects` whose claim does not match its key list deletes nothing, whichever
/// spelling the claim uses. Legacy RustFS deletes the key.
#[tokio::test]
async fn n_delete_objects_with_a_claim_that_does_not_match_deletes_nothing() {
    let root = TestRoot::new();
    let service = omit_bucket(&root).await;

    for claim in [
        vec![("content-md5", WRONG_MD5)],
        vec![
            ("x-amz-checksum-crc32", WRONG_CRC32),
            ("x-amz-sdk-checksum-algorithm", "CRC32"),
        ],
    ] {
        let refused = send(&service, http::Method::POST, "/omit?delete", delete_victim(), &claim).await;
        assert_eq!(
            (refused.status().as_u16(), code_of(&refused).as_deref()),
            (400, Some("BadDigest")),
            "{claim:?}: {}",
            body_of(&refused)
        );
        let survivor = read(&service, "/omit/victim").await;
        assert_eq!(survivor.status(), 200, "{claim:?}");
        assert_eq!(body_of(&survivor), "doomed");
    }
}
