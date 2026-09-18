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

//! The bucket-policy family through the production registry, answered as RustFS answers it.
//!
//! Responsible for: the policy stored and read back verbatim, `NoSuchBucketPolicy` and
//! `NoSuchPublicAccessBlockConfiguration` for what is absent, both classes of `MalformedPolicy`,
//! the public-access block refusing a public policy, `IsPublic` from the stored statements, the
//! four switches stored with the omitted ones `false`, and the records leaving with the bucket.
//! NOT responsible for: statement evaluation (`policy/evaluate_tests.rs`) or enforcement, which
//! the launcher's authorizer owns and `compat-sut`'s `policy_tests` drive.
//! Upstream: the fs backend through the production `S3Service`. Downstream: nothing.

use super::*;
use rustfs_gateway::WireResponse;

const PUBLIC_READ: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pol/*"}]}"#;
const PUBLIC_READ_MD5: &str = "3BERnKlBswT0tFbebP/rPg==";
const PUBLIC_LIST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::pol"}]}"#;
const PUBLIC_LIST_MD5: &str = "OWt0dhKbwUfvTNBavXw2yA==";
const NAMED_READ: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["another-account"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::pol/*"}]}"#;
const NAMED_READ_MD5: &str = "Lac4Nv3wVRL+BVgaRK0FaQ==";
const NO_PRINCIPAL: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::pol/*"}]}"#;
const NO_PRINCIPAL_MD5: &str = "GbjVn+pT2B+IxtVLBoGJuA==";
const NOT_JSON: &str = r#"{"Version":"#;
const NOT_JSON_MD5: &str = "eJ2VBxb3RVvGkYTLXMo7bg==";
const BLOCK_PUBLIC_POLICY: &str =
    "<PublicAccessBlockConfiguration><BlockPublicPolicy>true</BlockPublicPolicy></PublicAccessBlockConfiguration>";
const BLOCK_PUBLIC_POLICY_MD5: &str = "yxnb++Lt7UGHbQ3ig0g7SA==";
const RESTRICT_ONLY: &str = concat!(
    "<PublicAccessBlockConfiguration><BlockPublicPolicy>false</BlockPublicPolicy>",
    "<RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>"
);
const RESTRICT_ONLY_MD5: &str = "NZx1axnQN8TtWuV4OY4Rkg==";

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

/// Positive — a stored policy reads back byte for byte, the status follows the statements, and a
/// delete leaves the bucket with no policy again; the second delete is as quiet as the first.
#[tokio::test]
async fn a_policy_is_stored_verbatim_read_back_and_deleted() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "pol").await;

    let absent = get(&service, "/pol?policy").await;
    assert_eq!(absent.status(), 404, "{}", text(&absent));
    assert!(text(&absent).contains("<Code>NoSuchBucketPolicy</Code>"), "{}", text(&absent));

    let written = put(&service, "/pol?policy", PUBLIC_READ, PUBLIC_READ_MD5).await;
    assert_eq!(written.status(), 200, "{}", text(&written));
    let read = get(&service, "/pol?policy").await;
    assert_eq!(read.status(), 200, "{}", text(&read));
    assert_eq!(text(&read), PUBLIC_READ, "the document is stored verbatim");

    for _ in 0..2 {
        let deleted = delete(&service, "/pol?policy").await;
        assert_eq!(deleted.status(), 204, "{}", text(&deleted));
    }
    let gone = get(&service, "/pol?policy").await;
    assert_eq!(gone.status(), 404, "{}", text(&gone));
}

/// Positive — `IsPublic` is RustFS's: true only when the policy lets an anonymous caller list the
/// bucket or write to it. A public object read is not public by that test; a public list is; and
/// a bucket with no policy answers `false` with `200`, not a not-found.
#[tokio::test]
async fn the_policy_status_is_public_only_for_anonymous_listing_or_writing() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "pol").await;

    let none = get(&service, "/pol?policyStatus").await;
    assert_eq!(none.status(), 200, "{}", text(&none));
    assert_eq!(element(none.body(), "IsPublic").as_deref(), Some("false"));

    assert_eq!(put(&service, "/pol?policy", PUBLIC_READ, PUBLIC_READ_MD5).await.status(), 200);
    let read_only = get(&service, "/pol?policyStatus").await;
    assert_eq!(element(read_only.body(), "IsPublic").as_deref(), Some("false"), "{}", text(&read_only));

    assert_eq!(put(&service, "/pol?policy", PUBLIC_LIST, PUBLIC_LIST_MD5).await.status(), 200);
    let listable = get(&service, "/pol?policyStatus").await;
    assert_eq!(element(listable.body(), "IsPublic").as_deref(), Some("true"), "{}", text(&listable));
}

/// Negative — both classes of a bad document are `MalformedPolicy`: the shared contract's (not
/// JSON) and RustFS's statement rules (no principal). Neither is stored.
#[tokio::test]
async fn n_a_malformed_document_is_refused_by_either_rule_set_and_not_stored() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "pol").await;
    for (body, md5, rule) in [
        (NOT_JSON, NOT_JSON_MD5, "the shared contract"),
        (NO_PRINCIPAL, NO_PRINCIPAL_MD5, "RustFS's rules"),
    ] {
        let refused = put(&service, "/pol?policy", body, md5).await;
        assert_eq!(refused.status(), 400, "{rule}: {}", text(&refused));
        assert!(text(&refused).contains("<Code>MalformedPolicy</Code>"), "{rule}: {}", text(&refused));
    }
    assert!(text(&put(&service, "/pol?policy", NO_PRINCIPAL, NO_PRINCIPAL_MD5).await).contains("names no principal"));
    assert_eq!(get(&service, "/pol?policy").await.status(), 404, "nothing was stored");
}

/// Negative — with `BlockPublicPolicy` on, a policy that grants everyone is `AccessDenied` and
/// not stored; a policy that names an account is still accepted, and so is the public one once the
/// block is deleted.
#[tokio::test]
async fn n_the_public_access_block_refuses_a_public_policy() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "pol").await;
    let blocked = put(&service, "/pol?publicAccessBlock", BLOCK_PUBLIC_POLICY, BLOCK_PUBLIC_POLICY_MD5).await;
    assert_eq!(blocked.status(), 200, "{}", text(&blocked));

    let refused = put(&service, "/pol?policy", PUBLIC_READ, PUBLIC_READ_MD5).await;
    assert_eq!(refused.status(), 403, "{}", text(&refused));
    assert!(text(&refused).contains("<Code>AccessDenied</Code>"), "{}", text(&refused));
    assert_eq!(get(&service, "/pol?policy").await.status(), 404, "nothing was stored");
    let named = put(&service, "/pol?policy", NAMED_READ, NAMED_READ_MD5).await;
    assert_eq!(named.status(), 200, "a named principal is not the public: {}", text(&named));

    let unblocked = delete(&service, "/pol?publicAccessBlock").await;
    assert_eq!(unblocked.status(), 204, "{}", text(&unblocked));
    assert_eq!(put(&service, "/pol?policy", PUBLIC_READ, PUBLIC_READ_MD5).await.status(), 200);
}

/// Positive — the block stores the four switches, the omitted ones read back `false`, and an absent
/// block is `NoSuchPublicAccessBlockConfiguration`; a `BlockPublicPolicy` of `false` blocks nothing.
#[tokio::test]
async fn the_public_access_block_stores_every_switch_and_omitted_ones_are_false() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    create_bucket(&service, "pol").await;
    let absent = get(&service, "/pol?publicAccessBlock").await;
    assert_eq!(absent.status(), 404, "{}", text(&absent));
    assert!(
        text(&absent).contains("<Code>NoSuchPublicAccessBlockConfiguration</Code>"),
        "{}",
        text(&absent)
    );

    assert_eq!(
        put(&service, "/pol?publicAccessBlock", RESTRICT_ONLY, RESTRICT_ONLY_MD5)
            .await
            .status(),
        200
    );
    let read = get(&service, "/pol?publicAccessBlock").await;
    assert_eq!(read.status(), 200, "{}", text(&read));
    assert_eq!(element(read.body(), "BlockPublicAcls").as_deref(), Some("false"));
    assert_eq!(element(read.body(), "IgnorePublicAcls").as_deref(), Some("false"));
    assert_eq!(element(read.body(), "BlockPublicPolicy").as_deref(), Some("false"));
    assert_eq!(element(read.body(), "RestrictPublicBuckets").as_deref(), Some("true"));
    assert_eq!(
        put(&service, "/pol?policy", PUBLIC_READ, PUBLIC_READ_MD5).await.status(),
        200,
        "only BlockPublicPolicy refuses a public policy"
    );
}

/// Negative — a missing bucket is `NoSuchBucket` on every member of the family, and a bucket's
/// policy and block leave with the bucket: a recreated bucket of the same name has neither.
#[tokio::test]
async fn n_the_records_belong_to_the_bucket() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    for target in ["/missing?policy", "/missing?policyStatus", "/missing?publicAccessBlock"] {
        let read = get(&service, target).await;
        assert_eq!(read.status(), 404, "{target}: {}", text(&read));
        assert!(text(&read).contains("<Code>NoSuchBucket</Code>"), "{target}: {}", text(&read));
        let deleted = delete(&service, target.replace("policyStatus", "policy").as_str()).await;
        assert_eq!(deleted.status(), 404, "{target}: {}", text(&deleted));
    }
    assert_eq!(put(&service, "/missing?policy", PUBLIC_READ, PUBLIC_READ_MD5).await.status(), 404);

    create_bucket(&service, "pol").await;
    assert_eq!(put(&service, "/pol?policy", PUBLIC_READ, PUBLIC_READ_MD5).await.status(), 200);
    assert_eq!(
        put(&service, "/pol?publicAccessBlock", RESTRICT_ONLY, RESTRICT_ONLY_MD5)
            .await
            .status(),
        200
    );
    let removed = delete(&service, "/pol").await;
    assert_eq!(
        removed.status(),
        204,
        "a bucket with a policy and a block is still empty: {}",
        text(&removed)
    );
    create_bucket(&service, "pol").await;
    assert_eq!(get(&service, "/pol?policy").await.status(), 404, "the policy left with the bucket");
    assert_eq!(
        get(&service, "/pol?publicAccessBlock").await.status(),
        404,
        "the block left with the bucket"
    );
}
