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

//! Responsible for: ACL policy decisions using post-filter accepted headers while signatures use original headers.
//! NOT responsible for: other policy operators or filter implementations.
//! Upstream: the production signer, policy authorizer and filesystem handlers; downstream: response and stored-object observations.

use super::*;
use rustfs_gateway::{Credentials, RegionSet, ServiceBuilder, SigV4Authenticator, StaticCredentials, WireHead, wire_filter};

enum Rewrite {
    Set(http::HeaderValue),
    Remove,
    Preserve,
}

async fn fixture(document: &'static str, md5: &str, rewrite: Rewrite) -> (TestRoot, S3Service, S3Service) {
    let root = TestRoot::new();
    let options = two_identity_options(&root, &[]);
    let backend = Arc::new(open_backend(&options).expect("a usable root"));
    let owners = Arc::new(BucketOwners::default());
    let original = build_service(&options, &backend, &owners).expect("the production assembly");
    policed(&original).await;
    assert_eq!(put_policy(&original, document, md5).await.status(), 200);
    let mut credentials = StaticCredentials::new();
    for account in options.accounts.all() {
        credentials =
            credentials.with(Credentials::new(&account.access_key, account.secret_key.as_bytes()).expect("fixture credentials"));
    }
    let authorizer = crate::policy_authorizer::PolicyAuthorizer::new(
        Arc::clone(&backend),
        owners,
        options.accounts.clone(),
        crate::service::capability_names(&backend),
    );
    let builder = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(
            Arc::new(credentials),
            RegionSet::new(["us-east-1"]).expect("a region"),
        ))
        .authorizer(authorizer)
        .stage_filter(wire_filter(move |head: &mut WireHead<'_>| {
            let name = http::HeaderName::from_static("x-amz-acl");
            match &rewrite {
                Rewrite::Set(value) => head.set_header(name, value.clone())?,
                Rewrite::Remove => head.remove_header(&name)?,
                Rewrite::Preserve => {
                    head.set_header(http::HeaderName::from_static("x-filter-observed"), http::HeaderValue::from_static("yes"))?
                }
            }
            Ok(())
        }));
    let filtered = backend
        .register_crud(builder)
        .build()
        .expect("a filtered CRUD assembly using the production authorizer");
    (root, original, filtered)
}

async fn check_write(original: &S3Service, filtered: &S3Service, owner: bool, headers: &[(&str, &str)], expected: u16) {
    let (key, secret) = if owner {
        (MAIN_KEY, MAIN_SECRET)
    } else {
        (ALT_KEY, ALT_SECRET)
    };
    let request = signed(
        key,
        secret,
        http::Method::PUT,
        "/policed/filtered",
        Bytes::from_static(b"filtered body"),
        headers,
    );
    let response = exchange(filtered, request).await;
    assert_eq!(response.status(), expected, "{}", body_of(&response));
    let read = exchange(original, as_main(http::Method::GET, "/policed/filtered", Bytes::new())).await;
    if expected == 200 {
        assert_eq!(read.status(), 200, "{}", body_of(&read));
        assert_eq!(read.body().as_ref(), b"filtered body");
    } else {
        if expected == 403 {
            assert!(body_of(&response).contains("<Code>AccessDenied</Code>"), "{}", body_of(&response));
        }
        assert_eq!(read.status(), 404, "a rejected filtered request must not publish: {}", body_of(&read));
        assert!(body_of(&read).contains("<Code>NoSuchKey</Code>"));
    }
}

#[tokio::test]
async fn n_acl_condition_filter_rewrites_change_both_deny_and_allow_decisions() {
    for (document, md5, owner, sent, accepted, expected) in [
        (ACL_CONDITION_DENY, ACL_CONDITION_DENY_MD5, true, "private", "public-read", 403),
        (ACL_CONDITION_DENY, ACL_CONDITION_DENY_MD5, true, "public-read", "private", 200),
        (ACL_CONDITION_ALLOW, ACL_CONDITION_ALLOW_MD5, false, "private", "public-read", 200),
        (ACL_CONDITION_ALLOW, ACL_CONDITION_ALLOW_MD5, false, "public-read", "private", 403),
    ] {
        let (_root, original, filtered) = fixture(document, md5, Rewrite::Set(http::HeaderValue::from_static(accepted))).await;
        check_write(&original, &filtered, owner, &[("x-amz-acl", sent)], expected).await;
    }
}

#[tokio::test]
async fn n_acl_condition_filter_insert_and_removal_use_observed_presence() {
    let (_root, original, filtered) = fixture(
        ACL_CONDITION_DENY,
        ACL_CONDITION_DENY_MD5,
        Rewrite::Set(http::HeaderValue::from_static("public-read")),
    )
    .await;
    check_write(&original, &filtered, true, &[], 403).await;
    let (_root, original, filtered) = fixture(ACL_CONDITION_DENY, ACL_CONDITION_DENY_MD5, Rewrite::Remove).await;
    check_write(&original, &filtered, true, &[("x-amz-acl", "public-read")], 200).await;
}

#[tokio::test]
async fn n_acl_condition_filter_keeps_duplicate_refusal_but_replacement_removes_duplicates() {
    let headers = [("x-amz-acl", "private"), ("x-amz-acl", "public-read")];
    let (_root, original, filtered) = fixture(ACL_CONDITION_DENY, ACL_CONDITION_DENY_MD5, Rewrite::Preserve).await;
    check_write(&original, &filtered, true, &headers, 403).await;
    // WireHead::set_header replaces every value; the accepted request now has one private ACL.
    let (_root, original, filtered) = fixture(
        ACL_CONDITION_DENY,
        ACL_CONDITION_DENY_MD5,
        Rewrite::Set(http::HeaderValue::from_static("private")),
    )
    .await;
    check_write(&original, &filtered, true, &headers, 200).await;
}

#[tokio::test]
async fn n_acl_condition_filter_unreadable_value_is_refused_before_publication() {
    let (_root, original, filtered) = fixture(
        ACL_CONDITION_DENY,
        ACL_CONDITION_DENY_MD5,
        Rewrite::Set(http::HeaderValue::from_bytes(&[0xff]).expect("opaque bytes")),
    )
    .await;
    check_write(&original, &filtered, true, &[("x-amz-acl", "private")], 400).await;
}
