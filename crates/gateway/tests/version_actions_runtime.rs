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

//! A request naming one object version is authorised against the version action, end to end.
//!
//! Responsible for: the route stage asking a `?versionId=` read, delete, tag or ACL request the
//! operation's version action — and only it — before any handler runs, the version riding along
//! on the question, and the RustFS profile's `authorize_versions_as_legacy_rustfs`, which asks
//! the unversioned action where legacy RustFS asks it and nowhere else.
//! NOT responsible for: which operation declares which version action (the core integration
//! suite) or evaluating a policy (a deployment's authorizer).
//! Upstream: the facade pipeline. Downstream: nothing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::{Handler, HandlerResult, Operation, Req, Resp, ServiceBuilder, decide_with, dto};

use crate::support::{exchange, signed, signed_target_with_body_and_headers, signed_with, wired_at_signed_time};

/// Counts the handlers that ran, whatever the operation.
struct Reached(Arc<AtomicUsize>);

impl<O: Operation> Handler<O> for Reached
where
    O::Output: Default,
{
    async fn call(&self, _request: Req<O>) -> HandlerResult<O> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(O::Output::default()))
    }
}

/// Every route-stage question: its action and the version it named.
type Asked = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A service allowing exactly `allowed` actions, recording every question asked.
fn service(allowed: &'static [&'static str], legacy_versions: bool) -> (rustfs_gateway::S3Service, Arc<AtomicUsize>, Asked) {
    let reached = Arc::new(AtomicUsize::new(0));
    let asked: Asked = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&asked);
    let backend = Arc::new(Reached(Arc::clone(&reached)));
    let builder: ServiceBuilder = wired_at_signed_time()
        .authorizer(decide_with(move |request| {
            recorded
                .lock()
                .expect("uncontended")
                .push((request.action.to_owned(), request.version_id.map(str::to_owned)));
            if allowed.contains(&request.action) {
                rustfs_gateway::Decision::Allow
            } else {
                rustfs_gateway::Decision::Deny
            }
        }))
        .register::<dto::GetObject, _>(Arc::clone(&backend))
        .register::<dto::HeadObject, _>(Arc::clone(&backend))
        .register::<dto::DeleteObject, _>(Arc::clone(&backend))
        .register::<dto::GetObjectAttributes, _>(Arc::clone(&backend))
        .register::<dto::GetObjectTagging, _>(Arc::clone(&backend))
        .register::<dto::PutObjectTagging, _>(Arc::clone(&backend))
        .register::<dto::DeleteObjectTagging, _>(Arc::clone(&backend))
        .register::<dto::GetObjectAcl, _>(Arc::clone(&backend))
        .register::<dto::PutObjectAcl, _>(Arc::clone(&backend))
        .register::<dto::GetObjectRetention, _>(backend);
    let builder = if legacy_versions {
        builder.authorize_versions_as_legacy_rustfs()
    } else {
        builder
    };
    (builder.build().expect("a complete assembly"), reached, asked)
}

/// Sends `request` to a service allowing `allowed`, and answers the status and how many handlers
/// ran.
async fn outcome(allowed: &'static [&'static str], legacy_versions: bool, request: http::Request<Bytes>) -> (u16, usize) {
    let (service, reached, _) = service(allowed, legacy_versions);
    let (status, _) = exchange(&service, request).await;
    (status.as_u16(), reached.load(Ordering::SeqCst))
}

const TAGGING: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";

/// A signed `PUT ?tagging` carrying a valid tag document and its digest.
fn put_tagging(target: &str) -> http::Request<Bytes> {
    let md5 = crate::tagging_reachability::content_md5(TAGGING);
    signed_target_with_body_and_headers(http::Method::PUT, target, &[("content-md5", md5.as_str())], Bytes::from_static(TAGGING))
}

/// A signed `PUT ?acl` carrying a canned ACL and the digest of its empty body.
fn put_acl(target: &str) -> http::Request<Bytes> {
    let md5 = crate::tagging_reachability::content_md5(b"");
    signed_with(http::Method::PUT, target, &[("x-amz-acl", "private"), ("content-md5", md5.as_str())])
}

/// Negative — a principal allowed only the current object cannot read a named version: the read
/// is refused before any handler runs, on both profiles (legacy RustFS asks the version action
/// too, GHSA-3ppv).
#[tokio::test]
async fn n_a_version_read_needs_the_version_action_not_the_object_action() {
    for legacy in [false, true] {
        assert_eq!(
            outcome(&["s3:GetObject"], legacy, signed(http::Method::GET, "/bucket/key?versionId=v1")).await,
            (403, 0),
            "legacy profile: {legacy}"
        );
    }
}

/// Positive — the version action alone reaches a named version, and the question names it.
#[tokio::test]
async fn a_version_read_is_asked_the_version_action_about_that_version() {
    let (service, reached, asked) = service(&["s3:GetObjectVersion"], false);
    let (status, body) = exchange(&service, signed(http::Method::GET, "/bucket/key?versionId=v%2F1")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 1);
    let asked = asked.lock().expect("uncontended");
    assert!(
        asked
            .iter()
            .all(|(action, version)| action == "s3:GetObjectVersion" && version.as_deref() == Some("v/1")
                || action == "s3:ListBucket"),
        "{asked:?}"
    );
    assert!(asked.iter().any(|(action, _)| action == "s3:GetObjectVersion"), "{asked:?}");
}

/// Negative — the version action is not the object action: it does not reach the current object.
#[tokio::test]
async fn n_the_version_action_does_not_read_the_current_object() {
    assert_eq!(
        outcome(&["s3:GetObjectVersion"], false, signed(http::Method::GET, "/bucket/key")).await,
        (403, 0)
    );
}

/// Negative — an empty `versionId` still names a version, as legacy RustFS reads it (`Some("")`
/// asks `s3:GetObjectVersion`, `rustfs/src/storage/access.rs:1050-1056` on rustfs/rustfs
/// `d60dfbb826`): the object action alone does not reach it.
#[tokio::test]
async fn n_an_empty_version_id_still_needs_the_version_action() {
    for target in ["/bucket/key?versionId=", "/bucket/key?versionId"] {
        assert_eq!(
            outcome(&["s3:GetObject"], false, signed(http::Method::GET, target)).await,
            (403, 0),
            "{target}"
        );
    }
}

/// Negative — a principal allowed to delete objects cannot remove a version for good: the delete
/// naming a version is refused before any handler runs, on both profiles.
#[tokio::test]
async fn n_a_version_delete_needs_the_version_delete_action() {
    for legacy in [false, true] {
        assert_eq!(
            outcome(&["s3:DeleteObject"], legacy, signed(http::Method::DELETE, "/bucket/key?versionId=v1")).await,
            (403, 0),
            "legacy profile: {legacy}"
        );
    }
}

/// Positive — the version delete action removes the named version; the object delete still works
/// without one.
#[tokio::test]
async fn the_version_delete_action_reaches_the_version_delete() {
    assert_eq!(
        outcome(
            &["s3:DeleteObjectVersion"],
            false,
            signed(http::Method::DELETE, "/bucket/key?versionId=v1")
        )
        .await,
        (204, 1)
    );
    assert_eq!(
        outcome(&["s3:DeleteObject"], false, signed(http::Method::DELETE, "/bucket/key")).await,
        (204, 1)
    );
}

/// Negative — the version delete action does not delete the current object.
#[tokio::test]
async fn n_the_version_delete_action_does_not_delete_the_current_object() {
    assert_eq!(
        outcome(&["s3:DeleteObjectVersion"], false, signed(http::Method::DELETE, "/bucket/key")).await,
        (403, 0)
    );
}

/// Negative — attributes of a named version need the version action.
#[tokio::test]
async fn n_version_attributes_need_the_version_action() {
    let request = signed_with(
        http::Method::GET,
        "/bucket/key?attributes&versionId=v1",
        &[("x-amz-object-attributes", "ETag")],
    );
    assert_eq!(outcome(&["s3:GetObject"], false, request).await, (403, 0));
}

/// Negative — by default a `HEAD`, tag or ACL request naming a version needs the version action.
#[tokio::test]
async fn n_version_head_tag_and_acl_requests_need_the_version_action_by_default() {
    let cases: [(&'static [&'static str], http::Request<Bytes>); 6] = [
        (&["s3:GetObject"], signed(http::Method::HEAD, "/bucket/key?versionId=v1")),
        (&["s3:GetObjectTagging"], signed(http::Method::GET, "/bucket/key?tagging&versionId=v1")),
        (&["s3:PutObjectTagging"], put_tagging("/bucket/key?tagging&versionId=v1")),
        (
            &["s3:DeleteObjectTagging"],
            signed(http::Method::DELETE, "/bucket/key?tagging&versionId=v1"),
        ),
        (&["s3:GetObjectAcl"], signed(http::Method::GET, "/bucket/key?acl&versionId=v1")),
        (&["s3:PutObjectAcl"], put_acl("/bucket/key?acl&versionId=v1")),
    ];
    for (allowed, request) in cases {
        let target = request.uri().to_string();
        assert_eq!(outcome(allowed, false, request).await, (403, 0), "{target}");
    }
}

/// Positive — the RustFS profile asks a `HEAD`, tag or ACL request naming a version the
/// unversioned action, as legacy RustFS does (`rustfs/src/storage/access.rs:2839`, `:2787`,
/// `:3260`, `:2466`, `:2721`, `:3202` on rustfs/rustfs `d60dfbb826`), with the version on the
/// question.
#[tokio::test]
async fn the_rustfs_profile_asks_legacy_rustfs_unversioned_actions_for_head_tag_and_acl() {
    let cases: [(&'static [&'static str], http::Request<Bytes>, &str); 6] = [
        (&["s3:GetObject"], signed(http::Method::HEAD, "/bucket/key?versionId=v1"), "s3:GetObject"),
        (
            &["s3:GetObjectTagging"],
            signed(http::Method::GET, "/bucket/key?tagging&versionId=v1"),
            "s3:GetObjectTagging",
        ),
        (
            &["s3:PutObjectTagging"],
            put_tagging("/bucket/key?tagging&versionId=v1"),
            "s3:PutObjectTagging",
        ),
        (
            &["s3:DeleteObjectTagging"],
            signed(http::Method::DELETE, "/bucket/key?tagging&versionId=v1"),
            "s3:DeleteObjectTagging",
        ),
        (
            &["s3:GetObjectAcl"],
            signed(http::Method::GET, "/bucket/key?acl&versionId=v1"),
            "s3:GetObjectAcl",
        ),
        (&["s3:PutObjectAcl"], put_acl("/bucket/key?acl&versionId=v1"), "s3:PutObjectAcl"),
    ];
    for (allowed, request, action) in cases {
        let target = request.uri().to_string();
        let (service, reached, asked) = service(allowed, true);
        let (status, body) = exchange(&service, request).await;
        assert_ne!(status, 403, "{target}: {body}");
        assert_eq!(reached.load(Ordering::SeqCst), 1, "{target}");
        let asked = asked.lock().expect("uncontended");
        assert!(
            asked
                .iter()
                .any(|(asked, version)| asked == action && version.as_deref() == Some("v1")),
            "{target}: {asked:?}"
        );
        assert!(!asked.iter().any(|(asked, _)| asked.contains("Version")), "{target}: {asked:?}");
    }
}

/// Negative — the RustFS profile's version action for a `HEAD`, tag or ACL request is the
/// unversioned one only: the version actions alone reach none of them there.
#[tokio::test]
async fn n_the_rustfs_profile_does_not_accept_the_version_action_in_their_place() {
    let cases: [(&'static [&'static str], http::Request<Bytes>); 3] = [
        (&["s3:GetObjectVersion"], signed(http::Method::HEAD, "/bucket/key?versionId=v1")),
        (
            &["s3:GetObjectVersionTagging"],
            signed(http::Method::GET, "/bucket/key?tagging&versionId=v1"),
        ),
        (&["s3:GetObjectVersionAcl"], signed(http::Method::GET, "/bucket/key?acl&versionId=v1")),
    ];
    for (allowed, request) in cases {
        let target = request.uri().to_string();
        assert_eq!(outcome(allowed, true, request).await, (403, 0), "{target}");
    }
}

/// Negative — an operation AWS authorises with one action whatever version it names asks that
/// action for a version too, on both profiles.
#[tokio::test]
async fn n_retention_is_asked_its_own_action_for_a_version() {
    for legacy in [false, true] {
        assert_eq!(
            outcome(
                &["s3:GetObjectVersion"],
                legacy,
                signed(http::Method::GET, "/bucket/key?retention&versionId=v1")
            )
            .await,
            (403, 0),
            "legacy profile: {legacy}"
        );
        let (service, reached, asked) = service(&["s3:GetObjectRetention"], legacy);
        let (status, body) = exchange(&service, signed(http::Method::GET, "/bucket/key?retention&versionId=v1")).await;
        assert_ne!(status, 403, "{body}");
        assert_eq!(reached.load(Ordering::SeqCst), 1);
        assert!(
            asked
                .lock()
                .expect("uncontended")
                .iter()
                .all(|(action, _)| action == "s3:GetObjectRetention"),
        );
    }
}
