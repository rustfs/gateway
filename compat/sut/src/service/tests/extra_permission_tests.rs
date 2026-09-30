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

//! The header-conditional extra permissions, enforced as legacy RustFS enforces them, through the
//! served RustFS-profile assembly and a stored bucket policy.
//!
//! Responsible for: an object-lock header on a write requiring `s3:PutObjectRetention` /
//! `s3:PutObjectLegalHold` (a principal lacking it is refused and nothing is stored); a
//! governance-bypass header on a delete requiring `s3:BypassGovernanceRetention` (nothing is
//! deleted without it); and the RustFS profile serving a tagging or ACL write on the base
//! `s3:PutObject` alone, as legacy RustFS does — with the tag readable afterward.
//! NOT responsible for: the question the gateway asks (the gateway runtime suite) or the backend's
//! own object-lock support.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

const BUCKET: &str = "extra-perms";

fn alt_may(actions: &[&str]) -> String {
    let actions = actions
        .iter()
        .map(|action| format!("\"{action}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":["{ALT_OWNER}"]}},"Action":[{actions}],"Resource":"arn:aws:s3:::{BUCKET}/*"}}]}}"#
    )
}

async fn allow_alt(service: &S3Service, actions: &[&str]) {
    let document = alt_may(actions);
    let written = exchange(
        service,
        as_main(http::Method::PUT, &format!("/{BUCKET}?policy"), Bytes::from(document.into_bytes())),
    )
    .await;
    assert_eq!(written.status(), 204, "{}", body_of(&written));
}

async fn made_bucket(service: &S3Service) {
    let made = exchange(service, as_main(http::Method::PUT, &format!("/{BUCKET}"), Bytes::new())).await;
    assert_eq!(made.status(), 200, "{}", body_of(&made));
}

/// A signed `PUT` of `body` as the second identity, carrying `extra` headers.
fn alt_put(key: &str, extra: &[(&str, &str)], body: &[u8]) -> http::Request<Bytes> {
    signed(
        ALT_KEY,
        ALT_SECRET,
        http::Method::PUT,
        &format!("/{BUCKET}/{key}"),
        Bytes::copy_from_slice(body),
        extra,
    )
}

/// Whether the object exists, read as the owner.
async fn owner_sees(service: &S3Service, key: &str) -> bool {
    exchange(service, as_main(http::Method::GET, &format!("/{BUCKET}/{key}"), Bytes::new()))
        .await
        .status()
        == 200
}

/// Negative — a write setting an object-lock retention or legal-hold header needs the matching
/// action on top of `s3:PutObject`: the base permission alone is refused, and nothing is stored.
#[tokio::test]
async fn a_lock_header_write_needs_its_action_and_stores_nothing_without_it() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    made_bucket(&service).await;
    allow_alt(&service, &["s3:PutObject"]).await;

    for (key, header, value) in [
        ("retained", "x-amz-object-lock-mode", "GOVERNANCE"),
        ("held", "x-amz-object-lock-legal-hold", "ON"),
    ] {
        let refused = exchange(&service, alt_put(key, &[(header, value)], b"secret")).await;
        assert_eq!(refused.status(), 403, "{header}: {}", body_of(&refused));
        assert!(!owner_sees(&service, key).await, "{header}: the refused write stored an object");
    }

    // With the retention permission the write is admitted by authorization (it is no longer a 403);
    // the backend's own object-lock handling then decides the rest.
    allow_alt(&service, &["s3:PutObject", "s3:PutObjectRetention"]).await;
    let admitted = exchange(&service, alt_put("retained", &[("x-amz-object-lock-mode", "GOVERNANCE")], b"secret")).await;
    assert_ne!(
        admitted.status(),
        403,
        "the retention permission admits the write: {}",
        body_of(&admitted)
    );
}

/// Positive — the RustFS profile serves a tagging write on `s3:PutObject` alone, as legacy RustFS
/// does, and the tag is stored: the object is readable and its tag set comes back.
#[tokio::test]
async fn the_rustfs_profile_stores_a_tagging_write_on_the_base_permission() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    made_bucket(&service).await;
    allow_alt(&service, &["s3:PutObject"]).await;

    let written = exchange(&service, alt_put("tagged", &[("x-amz-tagging", "team=data")], b"body")).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    assert!(owner_sees(&service, "tagged").await, "the tagged write stored an object");
    let tags = exchange(&service, as_main(http::Method::GET, &format!("/{BUCKET}/tagged?tagging"), Bytes::new())).await;
    assert_eq!(tags.status(), 200, "{}", body_of(&tags));
    assert!(
        body_of(&tags).contains("<Key>team</Key>"),
        "the stored tag is readable: {}",
        body_of(&tags)
    );
    assert!(body_of(&tags).contains("<Value>data</Value>"));
}

/// Positive — the RustFS profile serves an ACL-header write on `s3:PutObject` alone, and stores the
/// object, as legacy RustFS does (its access hook reads but never acts on the ACL header).
#[tokio::test]
async fn the_rustfs_profile_stores_an_acl_header_write_on_the_base_permission() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    made_bucket(&service).await;
    allow_alt(&service, &["s3:PutObject"]).await;

    let written = exchange(&service, alt_put("acled", &[("x-amz-acl", "private")], b"body")).await;
    assert_eq!(written.status(), 200, "{}", body_of(&written));
    assert!(owner_sees(&service, "acled").await);
}

/// Negative — a delete carrying `x-amz-bypass-governance-retention: true` needs
/// `s3:BypassGovernanceRetention`: the delete permission alone is refused, the object stays, and
/// the RustFS profile never waives the bypass action.
#[tokio::test]
async fn a_governance_bypass_delete_needs_the_bypass_action_and_deletes_nothing_without_it() {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    made_bucket(&service).await;
    let stored = exchange(
        &service,
        as_main(http::Method::PUT, &format!("/{BUCKET}/keep"), Bytes::from_static(b"keep")),
    )
    .await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));

    allow_alt(&service, &["s3:DeleteObject"]).await;
    let refused = exchange(
        &service,
        signed(
            ALT_KEY,
            ALT_SECRET,
            http::Method::DELETE,
            &format!("/{BUCKET}/keep"),
            Bytes::new(),
            &[("x-amz-bypass-governance-retention", "true")],
        ),
    )
    .await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert!(owner_sees(&service, "keep").await, "the refused bypass delete removed the object");

    // A delete without the bypass header needs only the delete permission.
    let plain = exchange(&service, as_alt(http::Method::DELETE, &format!("/{BUCKET}/keep"), Bytes::new())).await;
    assert_eq!(plain.status(), 204, "{}", body_of(&plain));
    assert!(!owner_sees(&service, "keep").await, "the plain delete removed the object");
}
