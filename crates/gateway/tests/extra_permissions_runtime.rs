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

//! A write carrying an object-lock, tagging, ACL or governance-bypass header is authorized against
//! the extra action AWS requires, end to end, before any handler runs.
//!
//! Responsible for: the route stage asking `s3:PutObjectRetention` / `s3:PutObjectLegalHold` for an
//! object-lock header, `s3:PutObjectTagging` / `s3:PutObjectAcl` for a tagging / ACL header and
//! `s3:BypassGovernanceRetention` for a `x-amz-bypass-governance-retention: true` header — each on
//! top of the base action — and the RustFS profile waiving the tagging and ACL ones legacy RustFS
//! does not ask.
//! NOT responsible for: which operation declares which extra (the core spec suite) or a policy
//! (a deployment's authorizer).
//! Upstream: the facade pipeline. Downstream: nothing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::{ETag, Handler, HandlerError, HandlerResult, Operation, Req, Resp, ServiceBuilder, decide_with, dto};

use crate::support::{exchange, signed_target_with_body_and_headers, signed_with, wired_at_signed_time};

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

/// A `PutObject` backend that answers a well-formed output (a required `ETag`), so a positive case
/// reaches a `200` rather than an output-encoding refusal after authorization passes.
struct PutBackend(Arc<AtomicUsize>);

impl Handler<dto::PutObject> for PutBackend {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        // Drain the streaming body, as any real PutObject handler does: leaving it unread makes the
        // pipeline answer `IncompleteBody` instead of the operation's success.
        if let Some(body) = request.into_input().body {
            let mut body = body.into_body();
            while let Some(frame) = body.frame().await {
                frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
            }
        }
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::PutObjectOutput {
            e_tag: ETag::new("5d41402abc4b2a76b9719d911017c592").expect("a well-formed tag"),
            ..Default::default()
        }))
    }
}

type Asked = Arc<Mutex<Vec<String>>>;

fn service(allowed: &'static [&'static str], legacy_headers: bool) -> (rustfs_gateway::S3Service, Arc<AtomicUsize>, Asked) {
    let reached = Arc::new(AtomicUsize::new(0));
    let asked: Asked = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&asked);
    let backend = Arc::new(Reached(Arc::clone(&reached)));
    let builder: ServiceBuilder = wired_at_signed_time()
        .authorizer(decide_with(move |request| {
            recorded.lock().expect("uncontended").push(request.action.to_owned());
            if allowed.contains(&request.action) {
                rustfs_gateway::Decision::Allow
            } else {
                rustfs_gateway::Decision::Deny
            }
        }))
        .register::<dto::PutObject, _>(Arc::new(PutBackend(Arc::clone(&reached))))
        .register::<dto::DeleteObject, _>(Arc::clone(&backend))
        .register::<dto::PutObjectRetention, _>(backend);
    let builder = if legacy_headers {
        builder.authorize_header_permissions_as_legacy_rustfs()
    } else {
        builder
    };
    (builder.build().expect("a complete assembly"), reached, asked)
}

const RETENTION: &[u8] = b"<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2035-01-01T00:00:00Z</RetainUntilDate></Retention>";

/// A signed `PUT /bucket/key` carrying `extra` headers and a one-byte body (so the write is not a
/// zero-length upload the generic profile answers `411`).
fn put(extra: &[(&str, &str)]) -> http::Request<Bytes> {
    let mut headers = extra.to_vec();
    headers.push(("content-length", "1"));
    signed_target_with_body_and_headers(http::Method::PUT, "/bucket/key", &headers, Bytes::from_static(b"x"))
}

/// Sends `request` to a service allowing `allowed`; answers the status and how many handlers ran.
async fn outcome(allowed: &'static [&'static str], legacy_headers: bool, request: http::Request<Bytes>) -> (u16, usize) {
    let (service, reached, _) = service(allowed, legacy_headers);
    let (status, _) = exchange(&service, request).await;
    (status.as_u16(), reached.load(Ordering::SeqCst))
}

/// Negative — a `PutObject` setting a retention header needs `s3:PutObjectRetention` on top of
/// `s3:PutObject`: the base permission alone is refused before any handler runs.
#[tokio::test]
async fn n_a_retention_header_needs_the_retention_action() {
    for header in ["x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date"] {
        let value = if header.ends_with("mode") {
            "GOVERNANCE"
        } else {
            "2035-01-01T00:00:00Z"
        };
        assert_eq!(outcome(&["s3:PutObject"], false, put(&[(header, value)])).await, (403, 0), "{header}");
    }
    // Both permissions present: the write reaches the handler.
    assert_eq!(
        outcome(
            &["s3:PutObject", "s3:PutObjectRetention"],
            false,
            put(&[
                ("x-amz-object-lock-mode", "GOVERNANCE"),
                ("x-amz-object-lock-retain-until-date", "2035-01-01T00:00:00Z")
            ]),
        )
        .await,
        (200, 1)
    );
}

/// Negative — a legal-hold header needs `s3:PutObjectLegalHold`, an `OFF` value included, as legacy
/// RustFS reads it.
#[tokio::test]
async fn n_a_legal_hold_header_needs_the_legal_hold_action() {
    for value in ["ON", "OFF"] {
        assert_eq!(
            outcome(&["s3:PutObject"], false, put(&[("x-amz-object-lock-legal-hold", value)])).await,
            (403, 0),
            "{value}"
        );
    }
    assert_eq!(
        outcome(
            &["s3:PutObject", "s3:PutObjectLegalHold"],
            false,
            put(&[("x-amz-object-lock-legal-hold", "ON")]),
        )
        .await,
        (200, 1)
    );
}

/// Negative — a tagging or ACL header needs its action on the generic profile (AWS-exact), and the
/// base permission alone is refused.
#[tokio::test]
async fn n_a_tagging_or_acl_header_needs_its_action_on_the_generic_profile() {
    assert_eq!(outcome(&["s3:PutObject"], false, put(&[("x-amz-tagging", "k=v")])).await, (403, 0));
    assert_eq!(outcome(&["s3:PutObject"], false, put(&[("x-amz-acl", "private")])).await, (403, 0));
    assert_eq!(
        outcome(&["s3:PutObject"], false, put(&[("x-amz-grant-read", "id=abc")])).await,
        (403, 0),
        "a grant header triggers the ACL action too"
    );
    assert_eq!(
        outcome(&["s3:PutObject", "s3:PutObjectTagging"], false, put(&[("x-amz-tagging", "k=v")])).await,
        (200, 1)
    );
    assert_eq!(
        outcome(&["s3:PutObject", "s3:PutObjectAcl"], false, put(&[("x-amz-acl", "private")])).await,
        (200, 1)
    );
}

/// Positive — the RustFS profile waives the tagging and ACL actions, as legacy RustFS does: the
/// base permission alone stores a tagged or ACL-bearing write. The lock actions are still required.
#[tokio::test]
async fn the_rustfs_profile_waives_the_tagging_and_acl_actions_but_not_the_lock_ones() {
    let (service, reached, asked) = service(&["s3:PutObject"], true);
    for extra in [
        ("x-amz-tagging", "k=v"),
        ("x-amz-acl", "private"),
        ("x-amz-grant-read", "id=abc"),
    ] {
        assert_eq!(exchange(&service, put(&[extra])).await.0, 200, "{extra:?}");
    }
    assert!(
        !asked
            .lock()
            .expect("uncontended")
            .iter()
            .any(|a| a == "s3:PutObjectTagging" || a == "s3:PutObjectAcl"),
        "the RustFS profile never asks the waived actions"
    );
    assert_eq!(reached.load(Ordering::SeqCst), 3);
    // The lock actions are still asked and required on the RustFS profile.
    assert_eq!(
        outcome(&["s3:PutObject"], true, put(&[("x-amz-object-lock-mode", "GOVERNANCE")])).await,
        (403, 0)
    );
}

/// Negative — a header-less write requires only `s3:PutObject`: no extra action is asked.
#[tokio::test]
async fn n_a_header_less_write_asks_only_the_base_action() {
    let (service, reached, asked) = service(&["s3:PutObject"], false);
    assert_eq!(exchange(&service, put(&[])).await.0, 200);
    // The route and input stages both ask the base action; no extra action is asked.
    assert!(asked.lock().expect("uncontended").iter().all(|a| a == "s3:PutObject"), "{asked:?}");
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

/// Negative — an empty lock header sets nothing on a `PutObject`, so it asks no lock action and the
/// base permission alone stores the write. Only a form field counts as set for being sent, empty
/// or not (rustfs/gateway#1167, `post_object_lock_and_key_fields.rs`); the header keeps the
/// trigger's own non-empty rule.
#[tokio::test]
async fn n_an_empty_lock_header_asks_no_lock_action() {
    for legacy_headers in [false, true] {
        for header in ["x-amz-object-lock-mode", "x-amz-object-lock-legal-hold"] {
            let (service, reached, asked) = service(&["s3:PutObject"], legacy_headers);
            assert_eq!(exchange(&service, put(&[(header, "")])).await.0, 200, "{legacy_headers} {header}");
            let asked = asked.lock().expect("uncontended").clone();
            assert!(asked.iter().all(|a| a == "s3:PutObject"), "{legacy_headers} {header}: {asked:?}");
            assert_eq!(reached.load(Ordering::SeqCst), 1, "{legacy_headers} {header}");
        }
    }
}

/// Negative — a `DeleteObject` with `x-amz-bypass-governance-retention: true` needs
/// `s3:BypassGovernanceRetention`; a `false` (or absent) value asks only the delete action.
#[tokio::test]
async fn n_a_governance_bypass_delete_needs_the_bypass_action() {
    let bypass = signed_with(http::Method::DELETE, "/bucket/key", &[("x-amz-bypass-governance-retention", "true")]);
    assert_eq!(outcome(&["s3:DeleteObject"], false, bypass).await, (403, 0));
    let bypass = signed_with(http::Method::DELETE, "/bucket/key", &[("x-amz-bypass-governance-retention", "true")]);
    assert_eq!(
        outcome(&["s3:DeleteObject", "s3:BypassGovernanceRetention"], false, bypass).await,
        (204, 1)
    );

    let not_true = signed_with(http::Method::DELETE, "/bucket/key", &[("x-amz-bypass-governance-retention", "false")]);
    let (service, reached, asked) = service(&["s3:DeleteObject"], false);
    assert_eq!(exchange(&service, not_true).await.0, 204);
    assert!(
        !asked
            .lock()
            .expect("uncontended")
            .iter()
            .any(|a| a == "s3:BypassGovernanceRetention")
    );
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

/// Negative — the governance-bypass permission is never waived: the RustFS profile requires it too.
#[tokio::test]
async fn n_the_bypass_action_is_not_waived_by_the_rustfs_profile() {
    let bypass = signed_with(http::Method::DELETE, "/bucket/key", &[("x-amz-bypass-governance-retention", "true")]);
    assert_eq!(outcome(&["s3:DeleteObject"], true, bypass).await, (403, 0));
}

/// Negative — a `PutObjectRetention` bypassing governance needs the bypass action on top of
/// `s3:PutObjectRetention`.
#[tokio::test]
async fn n_a_retention_change_bypassing_governance_needs_the_bypass_action() {
    let request = signed_target_with_body_and_headers(
        http::Method::PUT,
        "/bucket/key?retention",
        &[("x-amz-bypass-governance-retention", "true")],
        Bytes::from_static(RETENTION),
    );
    assert_eq!(outcome(&["s3:PutObjectRetention"], false, request).await, (403, 0));
    let request = signed_target_with_body_and_headers(
        http::Method::PUT,
        "/bucket/key?retention",
        &[("x-amz-bypass-governance-retention", "true")],
        Bytes::from_static(RETENTION),
    );
    assert_ne!(
        outcome(&["s3:PutObjectRetention", "s3:BypassGovernanceRetention"], false, request)
            .await
            .0,
        403
    );
}
