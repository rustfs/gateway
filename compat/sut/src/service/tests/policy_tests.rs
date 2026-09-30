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

//! The bucket policy as the launcher enforces it, end to end and signed.
//!
//! Responsible for: the stored policy changing what the authorizer answers — an anonymous read
//! let through by a public statement, the other identity let through by a statement naming its
//! owner id, the owner refused by a `Deny`, and the surface staying refused where the policy says
//! nothing — plus the policy family's own answers on the wire: `NoSuchBucketPolicy`,
//! `MalformedPolicy`, the public-access block refusing a public policy, and the status read.
//! NOT responsible for: the statement grammar (`rustfs_gateway_fs::policy::evaluate` tests) or
//! the storage handlers alone (`crates/fs/tests/crud/bucket_policy.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

const PUBLIC_READ: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policed/*"}]}"#;
const PUBLIC_READ_MD5: &str = "ouGcIOtfCBshpi+mj/AR2A==";
const ALT_READ: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::policed/*"}]}"#;
const ALT_READ_MD5: &str = "nsxVKCJkFxMyyEPAQMlatQ==";
const DENY_SECRET: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policed/secret"}]}"#;
const DENY_SECRET_MD5: &str = "Wl5HVLvqQ4jcGsdcAO2G0Q==";
const PUBLIC_LIST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::policed"}]}"#;
const PUBLIC_LIST_MD5: &str = "OY2tUCKN/p4Ao1pQu5702w==";
const PUBLIC_READ_AND_LIST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policed/*"},{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::policed"}]}"#;
const PUBLIC_READ_AND_LIST_MD5: &str = "HpAJItYX01i1f2/C7Tlsug==";
const NO_ACTION: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Resource":"arn:aws:s3:::policed/*"}]}"#;
const NO_ACTION_MD5: &str = "nUNaz76I4w7q5lKbKmG9SQ==";
const NOT_JSON: &str = "{not json";
const NOT_JSON_MD5: &str = "PcRGF8B0DzdJj1csMZaT5A==";
const BLOCK_PUBLIC_POLICY: &str =
    "<PublicAccessBlockConfiguration><BlockPublicPolicy>true</BlockPublicPolicy></PublicAccessBlockConfiguration>";
const BLOCK_PUBLIC_POLICY_MD5: &str = "yxnb++Lt7UGHbQ3ig0g7SA==";

fn anonymous(method: http::Method, target: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(method)
        .uri(target)
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid unsigned request")
}

/// Writes `document` as the bucket policy. A write the assembly accepts answers `204 No Content`:
/// the RustFS profile writes the policy write's head as legacy RustFS does (its writer answers
/// `PutBucketPolicy` with `204`, observed on a legacy RustFS build; rustfs/gateway#1148), where the
/// model's head, which every other assembly keeps, is `200`.
pub(super) async fn put_policy(service: &S3Service, document: &'static str, md5: &str) -> WireResponse {
    let request = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/policed?policy",
        Bytes::from_static(document.as_bytes()),
        &[("content-md5", md5)],
    );
    exchange(service, request).await
}

async fn status(service: &S3Service) -> String {
    let response = exchange(service, as_main(http::Method::GET, "/policed?policyStatus", Bytes::new())).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    body_of(&response)
}

pub(super) async fn policed(service: &S3Service) {
    assert_eq!(
        exchange(service, as_main(http::Method::PUT, "/policed", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(service, as_main(http::Method::PUT, "/policed/open", Bytes::from_static(b"open")))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(service, as_main(http::Method::PUT, "/policed/secret", Bytes::from_static(b"secret")))
            .await
            .status(),
        200
    );
}

/// Negative control first, then the grant: without a policy the anonymous read and the other
/// identity's read are refused by ownership; a public `s3:GetObject` statement lets both read the
/// object and still refuses what it did not name — a write, and a listing.
#[tokio::test]
async fn a_public_read_statement_opens_the_object_to_everyone_and_nothing_else() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    policed(&service).await;

    assert_eq!(
        exchange(&service, anonymous(http::Method::GET, "/policed/open"))
            .await
            .status(),
        403
    );
    assert_eq!(
        exchange(&service, as_alt(http::Method::GET, "/policed/open", Bytes::new()))
            .await
            .status(),
        403
    );
    let missing = exchange(&service, as_main(http::Method::GET, "/policed?policy", Bytes::new())).await;
    assert_eq!(missing.status(), 404, "{}", body_of(&missing));
    assert!(body_of(&missing).contains("<Code>NoSuchBucketPolicy</Code>"));

    let written = put_policy(&service, PUBLIC_READ, PUBLIC_READ_MD5).await;
    assert_eq!(written.status(), 204, "{}", body_of(&written));

    let anon = exchange(&service, anonymous(http::Method::GET, "/policed/open")).await;
    assert_eq!(anon.status(), 200, "{}", body_of(&anon));
    assert_eq!(anon.body().as_ref(), b"open");
    assert_eq!(
        exchange(&service, as_alt(http::Method::GET, "/policed/open", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, anonymous(http::Method::PUT, "/policed/new"))
            .await
            .status(),
        403
    );
    assert_eq!(
        exchange(&service, anonymous(http::Method::GET, "/policed?list-type=2"))
            .await
            .status(),
        403
    );
    assert_eq!(
        exchange(&service, as_alt(http::Method::PUT, "/policed/new", Bytes::from_static(b"x")))
            .await
            .status(),
        403
    );

    let read_back = exchange(&service, as_main(http::Method::GET, "/policed?policy", Bytes::new())).await;
    assert_eq!(read_back.status(), 200);
    assert_eq!(read_back.body().as_ref(), PUBLIC_READ.as_bytes(), "the document is read back verbatim");

    // Deleting the policy restores the ownership-only answer.
    assert_eq!(
        exchange(&service, as_main(http::Method::DELETE, "/policed?policy", Bytes::new()))
            .await
            .status(),
        204
    );
    assert_eq!(
        exchange(&service, anonymous(http::Method::GET, "/policed/open"))
            .await
            .status(),
        403
    );
}

/// Negative — a statement naming the other identity's owner id admits that identity and nobody
/// anonymous; the principal is the published owner id, the string the ACL owner and
/// `x-amz-expected-bucket-owner` report.
#[tokio::test]
async fn n_a_named_principal_admits_that_identity_and_not_the_public() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    policed(&service).await;
    assert_eq!(put_policy(&service, ALT_READ, ALT_READ_MD5).await.status(), 204);
    assert_eq!(
        exchange(&service, as_alt(http::Method::GET, "/policed/open", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, anonymous(http::Method::GET, "/policed/open"))
            .await
            .status(),
        403
    );
    assert_eq!(
        exchange(&service, as_alt(http::Method::PUT, "/policed/new", Bytes::from_static(b"x")))
            .await
            .status(),
        403
    );
}

/// Negative — a `Deny` binds the owner too, and only for what it names: the owner still reads
/// the other key, and ownership still refuses the guest everything (RustFS's `Deny` first,
/// owner second, `Allow` third).
#[tokio::test]
async fn n_a_deny_refuses_the_owner_what_it_names() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    policed(&service).await;
    assert_eq!(put_policy(&service, DENY_SECRET, DENY_SECRET_MD5).await.status(), 204);
    let refused = exchange(&service, as_main(http::Method::GET, "/policed/secret", Bytes::new())).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert_eq!(
        exchange(&service, as_main(http::Method::GET, "/policed/open", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service, as_alt(http::Method::GET, "/policed/open", Bytes::new()))
            .await
            .status(),
        403
    );
}

/// Negative — a write the shared syntax contract refuses and one RustFS's statement rules refuse
/// are both `MalformedPolicy`, and neither is stored: the read afterwards is still `404`.
#[tokio::test]
async fn n_a_malformed_policy_is_refused_and_not_stored() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    policed(&service).await;
    for (document, md5) in [(NOT_JSON, NOT_JSON_MD5), (NO_ACTION, NO_ACTION_MD5)] {
        let refused = put_policy(&service, document, md5).await;
        assert_eq!(refused.status(), 400, "{}", body_of(&refused));
        assert!(body_of(&refused).contains("<Code>MalformedPolicy</Code>"), "{}", body_of(&refused));
    }
    assert_eq!(
        exchange(&service, as_main(http::Method::GET, "/policed?policy", Bytes::new()))
            .await
            .status(),
        404
    );
}

/// Negative — with `BlockPublicPolicy` set, a policy granting everyone is `AccessDenied`, as
/// RustFS answers it, while a policy naming one account is still stored; the block reads back
/// with every switch present, and a bucket without one is its own `404`.
#[tokio::test]
async fn n_block_public_policy_refuses_a_public_policy_only() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    policed(&service).await;
    let absent = exchange(&service, as_main(http::Method::GET, "/policed?publicAccessBlock", Bytes::new())).await;
    assert_eq!(absent.status(), 404, "{}", body_of(&absent));
    assert!(body_of(&absent).contains("<Code>NoSuchPublicAccessBlockConfiguration</Code>"));

    let blocked = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/policed?publicAccessBlock",
        Bytes::from_static(BLOCK_PUBLIC_POLICY.as_bytes()),
        &[("content-md5", BLOCK_PUBLIC_POLICY_MD5)],
    );
    assert_eq!(exchange(&service, blocked).await.status(), 200);
    let read = exchange(&service, as_main(http::Method::GET, "/policed?publicAccessBlock", Bytes::new())).await;
    let text = body_of(&read);
    assert_eq!(read.status(), 200, "{text}");
    assert!(text.contains("<BlockPublicPolicy>true</BlockPublicPolicy>"), "{text}");
    assert!(
        text.contains("<BlockPublicAcls>false</BlockPublicAcls>"),
        "an omitted switch reads back false: {text}"
    );

    let refused = put_policy(&service, PUBLIC_READ, PUBLIC_READ_MD5).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert!(body_of(&refused).contains("<Code>AccessDenied</Code>"));
    assert_eq!(put_policy(&service, ALT_READ, ALT_READ_MD5).await.status(), 204);

    assert_eq!(
        exchange(&service, as_main(http::Method::DELETE, "/policed?publicAccessBlock", Bytes::new()))
            .await
            .status(),
        204
    );
    assert_eq!(put_policy(&service, PUBLIC_READ, PUBLIC_READ_MD5).await.status(), 204);
}

/// Negative — `IsPublic` is computed as RustFS computes it: `false` with no policy and with a
/// policy that opens only object reads, `true` once anonymous listing is allowed.
#[tokio::test]
async fn n_the_policy_status_is_public_only_when_anonymous_listing_or_writing_is_allowed() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    policed(&service).await;
    assert!(status(&service).await.contains("<IsPublic>false</IsPublic>"), "no policy is not public");
    assert_eq!(put_policy(&service, PUBLIC_READ, PUBLIC_READ_MD5).await.status(), 204);
    assert!(
        status(&service).await.contains("<IsPublic>false</IsPublic>"),
        "object reads alone are not RustFS's public"
    );
    assert_eq!(put_policy(&service, PUBLIC_LIST, PUBLIC_LIST_MD5).await.status(), 204);
    assert!(status(&service).await.contains("<IsPublic>true</IsPublic>"));
    assert_eq!(
        exchange(&service, anonymous(http::Method::GET, "/policed?list-type=2"))
            .await
            .status(),
        200
    );
}

/// Negative — the missing-key visibility question is `s3:ListBucket` on the *bucket*: a policy
/// that grants everyone the read and the listing makes an anonymous read of a missing key
/// `404 NoSuchKey`, and a policy that grants only object reads keeps it `403`, because the caller
/// may not learn what the bucket holds. The bucket-shaped question is judged without the key it was asked alongside.
#[tokio::test]
async fn n_a_public_listing_reveals_a_missing_key_and_a_public_read_alone_does_not() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    policed(&service).await;

    assert_eq!(put_policy(&service, PUBLIC_READ, PUBLIC_READ_MD5).await.status(), 204);
    let hidden = exchange(&service, anonymous(http::Method::GET, "/policed/missing")).await;
    assert_eq!(hidden.status(), 403, "{}", body_of(&hidden));

    assert_eq!(
        put_policy(&service, PUBLIC_READ_AND_LIST, PUBLIC_READ_AND_LIST_MD5)
            .await
            .status(),
        204
    );
    let revealed = exchange(&service, anonymous(http::Method::GET, "/policed/missing")).await;
    assert_eq!(revealed.status(), 404, "{}", body_of(&revealed));
    assert!(body_of(&revealed).contains("<Code>NoSuchKey</Code>"), "{}", body_of(&revealed));
}

/// Negative — a policy record that cannot be read is not an absent one: the owner's own request
/// is refused rather than answered by ownership alone, and an anonymous one too. A corrupt record
/// fails closed; deleting the policy through the API restores the ownership answer.
#[tokio::test]
async fn n_an_unreadable_policy_fails_closed_for_everyone() {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let (_backend, service) = assembled(&options);
    policed(&service).await;
    assert_eq!(put_policy(&service, PUBLIC_READ, PUBLIC_READ_MD5).await.status(), 204);

    let record = std::fs::read_dir(&root.0)
        .expect("the data root")
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("policy"))
        .find(|path| path.is_file())
        .expect("the stored policy record");
    std::fs::write(&record, b"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Maybe\"}]}").expect("a corrupt record");

    let owner = exchange(&service, as_main(http::Method::GET, "/policed/open", Bytes::new())).await;
    assert_ne!(
        owner.status(),
        200,
        "the owner is not let through an unreadable policy: {}",
        body_of(&owner)
    );
    let anon = exchange(&service, anonymous(http::Method::GET, "/policed/open")).await;
    assert_ne!(anon.status(), 200, "{}", body_of(&anon));

    std::fs::remove_file(&record).expect("the record is removable");
    assert_eq!(
        exchange(&service, as_main(http::Method::GET, "/policed/open", Bytes::new()))
            .await
            .status(),
        200,
        "without a record the owner's request is ownership's to allow again"
    );
}

// Evidence: https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies-condition-keys.html
// StringEquals on s3:x-amz-acl selects the supplied canned ACL; an absent header does not match.
const ACL_CONDITION_DENY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*"},{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringEquals":{"s3:x-amz-acl":"public-read"}}}]}"#;
const ACL_CONDITION_DENY_MD5: &str = "6fEcg7hwCl11r9ChfNKxEQ==";
const ACL_CONDITION_ALLOW: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringEquals":{"s3:x-amz-acl":"public-read"}}}]}"#;
const ACL_CONDITION_ALLOW_MD5: &str = "A74Zv2TFL+w9iUlsF1uz4A==";

/// Each refused PUT is followed by an owner GET, so an error response cannot hide publication.
/// Each accepted PUT is read back too, proving the same observer can see an existing object.
async fn acl_condition_put(service: &S3Service, key: &str, acl: Option<&str>, owner: bool, expected: u16) {
    let target = format!("/policed/{key}");
    let headers: Vec<_> = acl.map(|value| ("x-amz-acl", value)).into_iter().collect();
    let (access_key, secret) = if owner {
        (MAIN_KEY, MAIN_SECRET)
    } else {
        (ALT_KEY, ALT_SECRET)
    };
    let response = exchange(
        service,
        signed(
            access_key,
            secret,
            http::Method::PUT,
            &target,
            Bytes::from_static(b"conditional write"),
            &headers,
        ),
    )
    .await;
    assert_eq!(response.status(), expected, "{key}: {}", body_of(&response));
    let read = exchange(service, as_main(http::Method::GET, &target, Bytes::new())).await;
    if expected == 403 {
        assert!(body_of(&response).contains("<Code>AccessDenied</Code>"), "{}", body_of(&response));
        assert_eq!(read.status(), 404, "a refused PUT must not publish {key}: {}", body_of(&read));
        assert!(body_of(&read).contains("<Code>NoSuchKey</Code>"), "{}", body_of(&read));
    } else {
        assert_eq!(read.status(), 200, "{key}: {}", body_of(&read));
        assert_eq!(read.body().as_ref(), b"conditional write");
    }
}

/// Matching Deny outranks both ownership and an unconditional Allow. Missing or different
/// headers leave the owner allowed; the condition must not become an unconditional denial.
#[tokio::test]
async fn n_acl_condition_deny_refuses_matching_owner_and_granted_guest_without_publication() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    let written = put_policy(&service, ACL_CONDITION_DENY, ACL_CONDITION_DENY_MD5).await;
    assert_eq!(written.status(), 204, "{}", body_of(&written));
    acl_condition_put(&service, "deny-owner", Some("public-read"), true, 403).await;
    acl_condition_put(&service, "deny-guest", Some("public-read"), false, 403).await;
    acl_condition_put(&service, "deny-other-value", Some("private"), true, 200).await;
    acl_condition_put(&service, "deny-absent", None, true, 200).await;
}

/// A conditional Allow needs the actual matching header. A different value or no header leaves
/// the other identity refused, and the matching positive control proves the grant is evaluated.
#[tokio::test]
async fn n_acl_condition_allow_requires_matching_header_and_preserves_rejected_key_absence() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    let written = put_policy(&service, ACL_CONDITION_ALLOW, ACL_CONDITION_ALLOW_MD5).await;
    assert_eq!(written.status(), 204, "{}", body_of(&written));
    acl_condition_put(&service, "allow-other-value", Some("private"), false, 403).await;
    acl_condition_put(&service, "allow-absent", None, false, 403).await;
    acl_condition_put(&service, "allow-matching", Some("public-read"), false, 200).await;
}

const ACL_CONDITION_ARRAY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringEquals":{"s3:x-amz-acl":["authenticated-read","public-read"]}}}]}"#;
const ACL_CONDITION_ARRAY_MD5: &str = "K5eRbM1j2uke1+q1gDi2Gg==";
const ACL_CONDITION_CASE: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringEquals":{"s3:x-amz-acl":"PUBLIC-READ"}}}]}"#;
const ACL_CONDITION_CASE_MD5: &str = "zir38/Byz4GdewBDooJlrg==";
const ACL_CONDITION_WILDCARD: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringEquals":{"s3:x-amz-acl":"public-*"}}}]}"#;
const ACL_CONDITION_WILDCARD_MD5: &str = "vdshezNIJjGuTlV6tNyWVg==";
const ACL_CONDITION_OTHER_KEY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringEquals":{"s3:x-amz-grant-read":"public-read"}}}]}"#;
const ACL_CONDITION_OTHER_KEY_MD5: &str = "I6RWB9mr2d953Gs3xexocQ==";
const ACL_CONDITION_MIXED_KEYS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringEquals":{"s3:x-amz-acl":"public-read","s3:x-amz-grant-read":"public-read"}}}]}"#;
const ACL_CONDITION_MIXED_KEYS_MD5: &str = "COgyalz0sOhFYBqzFHadPA==";
const ACL_CONDITION_MIXED_OPERATORS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringEquals":{"s3:x-amz-acl":"public-read"},"Null":{"s3:x-amz-grant-read":"false"}}}]}"#;
const ACL_CONDITION_MIXED_OPERATORS_MD5: &str = "RBDv2ndr6fXy3UZqiP3pbg==";
const ACL_CONDITION_UNSUPPORTED_OPERATOR: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringLike":{"s3:x-amz-acl":"public-read"}}}]}"#;
const ACL_CONDITION_UNSUPPORTED_OPERATOR_MD5: &str = "DLYwi8hS+MzIr7nuETRDEg==";

/// StringEquals is exact, its value array is an OR, and a block with unsupported pieces must
/// not accidentally grant access by evaluating only the recognized piece.
#[tokio::test]
async fn n_acl_condition_exact_array_and_unsupported_block_controls() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    for (key, document, md5, expected) in [
        ("array", ACL_CONDITION_ARRAY, ACL_CONDITION_ARRAY_MD5, 200),
        ("case", ACL_CONDITION_CASE, ACL_CONDITION_CASE_MD5, 403),
        ("wildcard", ACL_CONDITION_WILDCARD, ACL_CONDITION_WILDCARD_MD5, 403),
        ("other-key", ACL_CONDITION_OTHER_KEY, ACL_CONDITION_OTHER_KEY_MD5, 403),
        ("mixed-keys", ACL_CONDITION_MIXED_KEYS, ACL_CONDITION_MIXED_KEYS_MD5, 403),
        ("mixed-operators", ACL_CONDITION_MIXED_OPERATORS, ACL_CONDITION_MIXED_OPERATORS_MD5, 403),
        (
            "unsupported-operator",
            ACL_CONDITION_UNSUPPORTED_OPERATOR,
            ACL_CONDITION_UNSUPPORTED_OPERATOR_MD5,
            403,
        ),
    ] {
        let written = put_policy(&service, document, md5).await;
        assert_eq!(written.status(), 204, "{}", body_of(&written));
        acl_condition_put(&service, key, Some("public-read"), false, expected).await;
    }
}

#[tokio::test]
async fn n_acl_condition_unavailable_request_facts_fail_closed_but_absent_policy_preserves_owner() {
    use rustfs_gateway::{
        Authorizer, AuthzRequest, BucketName, Decision, Identity, PolicySnapshot, RequestContext, RequestNow, ResourceShape,
        TargetOrigin,
    };
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let backend = Arc::new(open_backend(&options).expect("a usable root"));
    let owners = Arc::new(BucketOwners::default());
    let service = build_service(&options, &backend, &owners).expect("a complete assembly");
    policed(&service).await;
    let authorizer = crate::policy_authorizer::PolicyAuthorizer::new(
        Arc::clone(&backend),
        Arc::clone(&owners),
        options.accounts.clone(),
        crate::service::capability_names(&backend),
    );
    let identity = Identity::new(MAIN_KEY).expect("a valid identity");
    let bucket = BucketName::new("policed").expect("a valid bucket");
    let policy = PolicySnapshot::of(Arc::new(()));
    let context = RequestContext::new(RequestNow::from_unix_seconds(0), &policy);
    let request = AuthzRequest {
        operation: "PutObject",
        action: "s3:PutObject",
        resource: ResourceShape::Object,
        bucket: Some(&bucket),
        key: None,
        copy_source_identity: None,
        version_id: None,
        route_action: "s3:PutObject",
        route_bucket: Some(&bucket),
        route_key: None,
        identity: Some(&identity),
        target_origin: TargetOrigin::Path,
        subject: None,
    };
    assert_eq!(authorizer.authorize_route(&context, &request).await, Decision::Allow);
    assert_eq!(
        put_policy(&service, ACL_CONDITION_DENY, ACL_CONDITION_DENY_MD5)
            .await
            .status(),
        204
    );
    assert_eq!(
        authorizer.authorize_route(&context, &request).await,
        Decision::Indeterminate,
        "an unavailable request header set is not proof that a conditional Deny does not match"
    );
}

const ACL_CONDITION_UPPERCASE_KEY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["s3gate-alt"]},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policed/*","Condition":{"StringEquals":{"S3:X-AMZ-ACL":"public-read"}}}]}"#;
const ACL_CONDITION_UPPERCASE_KEY_MD5: &str = "kp20C9+qyUlYWgXSvU5CGA==";

/// This backend follows RustFS's canonical condition-key spelling; unsupported condition blocks
/// must not grant access just because their spelling would be recognized by another evaluator.
#[tokio::test]
async fn n_acl_condition_uppercase_key_is_not_a_supported_grant() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    let written = put_policy(&service, ACL_CONDITION_UPPERCASE_KEY, ACL_CONDITION_UPPERCASE_KEY_MD5).await;
    assert_eq!(written.status(), 204, "{}", body_of(&written));
    acl_condition_put(&service, "uppercase-key", Some("public-read"), false, 403).await;
}

#[tokio::test]
async fn n_acl_condition_duplicate_signed_header_cannot_bypass_owner_deny() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    policed(&service).await;
    assert_eq!(
        put_policy(&service, ACL_CONDITION_DENY, ACL_CONDITION_DENY_MD5)
            .await
            .status(),
        204
    );
    let request = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/policed/duplicate-acl",
        Bytes::from_static(b"must not publish"),
        &[("x-amz-acl", "private"), ("x-amz-acl", "public-read")],
    );
    assert_eq!(
        request.headers().get_all("x-amz-acl").iter().count(),
        2,
        "both signed lines reach the service"
    );
    let response = exchange(&service, request).await;
    assert_eq!(response.status(), 403, "{}", body_of(&response));
    assert!(body_of(&response).contains("<Code>AccessDenied</Code>"), "{}", body_of(&response));
    let absent = exchange(&service, as_main(http::Method::GET, "/policed/duplicate-acl", Bytes::new())).await;
    assert_eq!(absent.status(), 404, "{}", body_of(&absent));
    assert!(body_of(&absent).contains("<Code>NoSuchKey</Code>"));
}

#[path = "policy_tests/filtered_headers.rs"]
mod filtered_headers;
