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

//! The P10-01 proof, ADR-0025 half: one route per custom-auth class and one bound-bucket route,
//! through the assembled service.
//!
//! Responsible for: the class operations agreeing with the recorded inventory; any-of admitting
//! either action and refusing neither; an own-account read asked about the caller under its label
//! and never skipped; a contextual read allowed about the caller's own account and refused about
//! another's, with the subject decoded once and refused when ambiguous; the bound bucket reaching
//! the governor, both authorizer stages and the handler, and an invalid one refused before
//! authorisation exactly where S3 refuses it; the stale `NotImplemented` route split by its query.
//! NOT responsible for: the rule functions themselves (`rustfs-gateway-core`'s unit tests), the
//! all-of rule and the anonymous-subject guard through a floor that admits anonymous requests
//! (`crates/gateway/tests/action_rules_runtime.rs`), or the ADR-0024 routes (`super::tests`).
//! Upstream: the parent module, `super::tests`' helpers, the recorded inventory. Downstream:
//! nothing.

use rustfs_gateway::AuthzRequest;
use rustfs_gateway_core::dialect::{BucketParam, DialectError};
use rustfs_gateway_core::{ActionRule, Subject, SubjectRule};

use super::classes::{
    GET_BUCKET_QUOTA, GET_BUCKET_QUOTA_ACTION, GET_BUCKET_QUOTA_TEMPLATE, GET_USER_INFO, GET_USER_INFO_ACTION,
    GET_USER_INFO_PATH, LIST_POOLS, LIST_POOLS_ACTIONS, LIST_POOLS_PATH, REQUIREMENTS, SELF_ACCOUNT_INFO,
    SELF_ACCOUNT_INFO_ACTION, SELF_ACCOUNT_INFO_PATH, SERVICE_PATH, SERVICE_RESTART, SERVICE_RESTART_ACTION, USER_SUBJECT,
};
use super::tests::{HAND_OFF, REGION, assert_refused_before_the_handler, only, route_calls, routed, send, send_with};
use super::{Assembled, AuthzCall, Options, REPLICATION_METRICS_SHADOWS, admin_dialect, admin_dialect_bound, assemble};
use crate::operation_diff::s3s_0_17_0::context::{ACCESS_KEY, ContextRequest, PATH_HOST};
use crate::{RouteMethod, rustfs_admin_route_inventory};

const SOMEONE_ELSE: &str = "someone-else";

fn get(path: &str, query: &str) -> ContextRequest {
    ContextRequest::get(PATH_HOST, path, query).signed(REGION)
}

fn calls_for<'a>(calls: &'a [AuthzCall], operation: &str, stage: &str) -> Vec<&'a AuthzCall> {
    calls
        .iter()
        .filter(|call| call.operation == operation && call.stage == stage)
        .collect()
}

fn json_of(assembled: &Assembled, request: &ContextRequest) -> serde_json::Value {
    let answer = send(assembled, request);
    assert_eq!(answer.status, 200, "{}", answer.text());
    serde_json::from_slice(&answer.body).expect("a JSON body")
}

/// A deployment authorizer for `user-info`: an explicit grant of the admin action, or the caller
/// reading its own account (RustFS evaluates the latter deny-only; here nothing denies).
fn own_account_or(admin: bool) -> impl Fn(&AuthzRequest<'_>) -> bool + Send + Sync + 'static {
    move |request| {
        let own = match (request.subject, request.identity) {
            (Some(subject), Some(identity)) => subject.name() == Some(identity.access_key_id()),
            _ => false,
        };
        request.action == GET_USER_INFO_ACTION && (admin || own)
    }
}

fn assert_refused_before_authorisation(assembled: &Assembled, request: &ContextRequest, status: u16, code: &str) {
    let answer = send(assembled, request);
    assert_refused_before_the_handler(assembled, &answer, status);
    assert!(answer.text().contains(code), "{}", answer.text());
    assert!(assembled.calls().is_empty(), "the authorizer was asked: {:?}", assembled.calls());
}

// ── the rows and the inventory ────────────────────────────────────────────────────────────────

/// Positive — each class operation sits on a recorded route of that class, with its alias, and
/// declares the rule its class was ruled onto.
#[test]
fn the_class_operations_declare_what_the_inventory_records() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    for (method, path, class) in [
        (RouteMethod::Get, LIST_POOLS_PATH, "MultipleActions"),
        (RouteMethod::Get, SELF_ACCOUNT_INFO_PATH, "CredentialOnly"),
        (RouteMethod::Get, GET_USER_INFO_PATH, "ContextualAuthorization"),
        (RouteMethod::Get, GET_BUCKET_QUOTA_TEMPLATE, "S3Action"),
        (RouteMethod::Post, SERVICE_PATH, "NotImplemented"),
    ] {
        let route = inventory.route(method, path).expect("a recorded route");
        assert_eq!(route.auth_detail.as_deref(), Some(class), "{path}");
        assert!(route.minio_admin_alias, "{path}");
    }
    let quota = inventory
        .route(RouteMethod::Get, GET_BUCKET_QUOTA_TEMPLATE)
        .expect("a recorded route");
    assert_eq!(quota.path_params, ["bucket"]);
    assert_eq!(REQUIREMENTS[0].rule(), ActionRule::AnyOf(LIST_POOLS_ACTIONS));
    assert_eq!(REQUIREMENTS[1].subject(), Some(SubjectRule::Caller));
    assert_eq!(REQUIREMENTS[2].subject(), Some(USER_SUBJECT));
    assert_eq!(REQUIREMENTS[3].subject(), None);
}

/// Positive — every class row and alias reaches its operation; the service command only with the
/// one `action` value it serves.
#[test]
fn each_class_request_reaches_its_operation() {
    let dialect = admin_dialect();
    for (method, target, operation) in [
        ("GET", LIST_POOLS_PATH, Some(LIST_POOLS)),
        ("GET", "/minio/admin/v3/pools/list", Some(LIST_POOLS)),
        ("GET", SELF_ACCOUNT_INFO_PATH, Some(SELF_ACCOUNT_INFO)),
        ("GET", "/minio/admin/v3/user-info?accessKey=a", Some(GET_USER_INFO)),
        ("GET", "/rustfs/admin/v3/quota/photos", Some(GET_BUCKET_QUOTA)),
        ("GET", "/minio/admin/v3/quota/photos", Some(GET_BUCKET_QUOTA)),
        ("POST", "/rustfs/admin/v3/service?action=restart", Some(SERVICE_RESTART)),
        ("POST", "/minio/admin/v3/service?action=restart", Some(SERVICE_RESTART)),
        ("POST", "/rustfs/admin/v3/service?action=stop", None),
        ("POST", SERVICE_PATH, None),
        ("GET", "/rustfs/admin/v3/quota/photos/extra", None),
    ] {
        assert_eq!(routed(Some(&dialect), method, target), operation, "{method} {target}");
    }
}

// ── MultipleActions ───────────────────────────────────────────────────────────────────────────

/// Positive — either action admits the listing; both are asked, in order, and the input stage
/// re-asks the one that was allowed.
#[test]
fn either_pools_action_admits_the_listing() {
    for held in LIST_POOLS_ACTIONS {
        let assembled = assemble(HAND_OFF, only(held));
        json_of(&assembled, &get(LIST_POOLS_PATH, ""));
        let calls = assembled.calls();
        let asked: Vec<&str> = calls_for(&calls, LIST_POOLS, "route")
            .iter()
            .map(|call| call.action.as_str())
            .collect();
        assert_eq!(asked, LIST_POOLS_ACTIONS, "holding {held}");
        let input = calls_for(&calls, LIST_POOLS, "input");
        assert_eq!(input.len(), 1);
        assert_eq!(input[0].action, *held);
        assert!(calls.iter().all(|call| call.bucket.is_none() && call.subject.is_none()));
    }
}

/// Negative — a caller holding neither pools action is refused before the handler, after both
/// were asked.
#[test]
fn n_a_caller_with_neither_pools_action_is_refused() {
    let assembled = assemble(HAND_OFF, only("admin:ListTier"));
    let answer = send(&assembled, &get(LIST_POOLS_PATH, ""));
    assert_refused_before_the_handler(&assembled, &answer, 403);
    assert_eq!(route_calls(&assembled.calls()).len(), 2);
}

// ── CredentialOnly ────────────────────────────────────────────────────────────────────────────

/// Positive — the own-account read is still an authorizer question: its label, about the caller.
#[test]
fn the_own_account_read_is_asked_about_the_caller() {
    let assembled = assemble(HAND_OFF, |request| {
        request.action == SELF_ACCOUNT_INFO_ACTION && request.subject == Some(&Subject::Caller) && !request.is_anonymous()
    });
    let body = json_of(&assembled, &get(SELF_ACCOUNT_INFO_PATH, "accessKey=someone-else"));
    assert_eq!(body["subject"], serde_json::Value::Null);
    let calls = assembled.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls
            .iter()
            .all(|call| call.subject == Some(None) && call.caller.as_deref() == Some(ACCESS_KEY))
    );
    assert_eq!(assembled.backend.seen()[0].subject, Some(None));
}

/// Negative — no policy check is skipped: an authorizer that refuses the label refuses the read.
#[test]
fn n_an_own_account_read_the_authorizer_refuses_is_refused() {
    let assembled = assemble(HAND_OFF, |request| request.action != SELF_ACCOUNT_INFO_ACTION);
    let answer = send(&assembled, &get(SELF_ACCOUNT_INFO_PATH, ""));
    assert_refused_before_the_handler(&assembled, &answer, 403);
}

/// Negative — an anonymous own-account read never reaches the authorizer, even with anonymous
/// admission delegated to it.
#[test]
fn n_an_anonymous_own_account_read_is_refused_before_the_authorizer() {
    let assembled = assemble(
        Options {
            secret_hand_off: false,
            delegate_anonymous: true,
        },
        |_| true,
    );
    let answer = send(&assembled, &ContextRequest::get(PATH_HOST, SELF_ACCOUNT_INFO_PATH, ""));
    assert_refused_before_the_handler(&assembled, &answer, 403);
    assert!(assembled.calls().is_empty());
}

// ── ContextualAuthorization ───────────────────────────────────────────────────────────────────

/// Positive — a caller reads its own account without the admin action; the authorizer and the
/// handler were handed the same decoded subject.
#[test]
fn a_caller_reads_its_own_user_info_without_the_admin_action() {
    let assembled = assemble(HAND_OFF, own_account_or(false));
    let body = json_of(&assembled, &get(GET_USER_INFO_PATH, &format!("accessKey={ACCESS_KEY}")));
    assert_eq!(body["subject"], ACCESS_KEY);
    let calls = assembled.calls();
    assert!(calls.iter().all(|call| call.subject == Some(Some(ACCESS_KEY.to_owned()))));
    assert_eq!(assembled.backend.seen()[0].subject, Some(Some(ACCESS_KEY.to_owned())));
}

/// Negative — the contextual mismatch: another account, without the admin action, is refused.
#[test]
fn n_another_accounts_user_info_is_refused_without_the_admin_action() {
    let assembled = assemble(HAND_OFF, own_account_or(false));
    let answer = send(&assembled, &get(GET_USER_INFO_PATH, &format!("accessKey={SOMEONE_ELSE}")));
    assert_refused_before_the_handler(&assembled, &answer, 403);
    assert_eq!(route_calls(&assembled.calls())[0].subject, Some(Some(SOMEONE_ELSE.to_owned())));
}

/// Positive — the admin action admits another account.
#[test]
fn the_admin_action_admits_another_accounts_user_info() {
    let assembled = assemble(HAND_OFF, own_account_or(true));
    let body = json_of(&assembled, &get(GET_USER_INFO_PATH, &format!("accessKey={SOMEONE_ELSE}")));
    assert_eq!(body["subject"], SOMEONE_ELSE);
}

/// Negative — no account, a repeated one, an escaped spelling of the parameter (which the handler's
/// own parse would read as the parameter), an ambiguous `+` or a malformed escape is a `400` before
/// anything is authenticated or authorised. Unsigned on purpose: the refusal precedes the
/// signature, so it cannot depend on one.
#[test]
fn n_an_absent_or_ambiguous_account_is_refused_before_authorisation() {
    let assembled = assemble(HAND_OFF, own_account_or(true));
    for query in [
        String::new(),
        "accessKey=".to_owned(),
        format!("accessKey={ACCESS_KEY}&accessKey={SOMEONE_ELSE}"),
        format!("access%4Bey={SOMEONE_ELSE}"),
        format!("accessKey={ACCESS_KEY}&access%4Bey={SOMEONE_ELSE}"),
        "accessKey=a+b".to_owned(),
        "accessKey=a%zz".to_owned(),
    ] {
        let request = ContextRequest::get(PATH_HOST, GET_USER_INFO_PATH, &query);
        assert_refused_before_authorisation(&assembled, &request, 400, "InvalidArgument");
    }
}

// ── S3Action and the bound bucket ─────────────────────────────────────────────────────────────

/// Positive — the template's bucket is the resource at the governor, both stages and the handler,
/// canonical row and alias alike.
#[test]
fn the_bound_bucket_is_the_authorisation_bucket() {
    for path in ["/rustfs/admin/v3/quota/photos", "/minio/admin/v3/quota/photos"] {
        let assembled = assemble(HAND_OFF, only(GET_BUCKET_QUOTA_ACTION));
        let body = json_of(&assembled, &get(path, ""));
        assert_eq!(body["bucket"], "photos");
        let calls = assembled.calls();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(
            calls
                .iter()
                .all(|call| call.bucket.as_deref() == Some("photos") && call.key.is_none())
        );
        let seen = &assembled.backend.seen()[0];
        assert_eq!(seen.bucket.as_deref(), Some("photos"));
        assert_eq!(seen.params, [("bucket".to_owned(), "photos".to_owned())]);
        let governed = assembled.governed.lock().expect("uncontended").clone();
        assert_eq!(governed, [(GET_BUCKET_QUOTA.to_owned(), Some("photos".to_owned()))]);
    }
}

/// Negative — a claimed row's path is not a bucket surface: a quota request carrying `Origin` never
/// reads its bound bucket's CORS document, while an S3 request to the same bucket does (the
/// control that shows the observer sees reads at all).
#[test]
fn n_a_claimed_request_never_consults_the_bound_buckets_cors() {
    let origin = |headers: &mut http::HeaderMap| {
        headers.insert("origin", http::HeaderValue::from_static("https://console.example"));
    };
    let assembled = assemble(HAND_OFF, |_| true);
    let admin = send_with(&assembled, &get("/rustfs/admin/v3/quota/photos", ""), origin);
    assert_eq!(admin.status, 200, "{}", admin.text());
    assert!(assembled.cors_loaded.lock().expect("uncontended").is_empty());
    let s3 = send_with(&assembled, &get("/photos", ""), origin);
    assert_eq!(s3.status, 200, "{}", s3.text());
    assert_eq!(*assembled.cors_loaded.lock().expect("uncontended"), ["photos"]);
}

/// Negative — the wrong action on the right bucket is refused.
#[test]
fn n_a_quota_read_without_its_s3_action_is_refused() {
    let assembled = assemble(HAND_OFF, only("admin:SetBucketQuota"));
    let answer = send(&assembled, &get("/rustfs/admin/v3/quota/photos", ""));
    assert_refused_before_the_handler(&assembled, &answer, 403);
    let route = route_calls(&assembled.calls())[0].clone();
    assert_eq!(
        (route.action.as_str(), route.bucket.as_deref()),
        (GET_BUCKET_QUOTA_ACTION, Some("photos"))
    );
}

/// Negative — a bucket parameter S3 would refuse as `/{bucket}` is refused here with the same
/// status and code, before the governor or the authorizer is asked; an escaped spelling included.
#[test]
fn n_an_invalid_bucket_parameter_is_refused_as_s3_refuses_it() {
    let long = "a".repeat(64);
    for bucket in [
        "ab",
        "Bad_Bucket",
        "%70hotos",
        "192.168.1.1",
        "a..b",
        "-photos",
        long.as_str(),
    ] {
        let assembled = assemble(HAND_OFF, |_| true);
        let admin = send(&assembled, &get(&format!("/rustfs/admin/v3/quota/{bucket}"), ""));
        assert_refused_before_the_handler(&assembled, &admin, 400);
        assert!(admin.text().contains("InvalidBucketName"), "{bucket}: {}", admin.text());
        let s3 = send(&assembled, &get(&format!("/{bucket}"), ""));
        assert_eq!(s3.status, admin.status, "{bucket}: {}", s3.text());
        assert!(s3.text().contains("InvalidBucketName"), "{bucket}: {}", s3.text());
        assert!(assembled.calls().is_empty(), "{bucket}: {:?}", assembled.calls());
        assert!(assembled.governed.lock().expect("uncontended").is_empty(), "{bucket}");
    }
}

/// Negative — without the binding a bucket operation cannot be claimed, and a binding to a
/// parameter the template lacks is refused.
#[test]
fn n_the_quota_route_needs_its_binding_and_the_binding_needs_its_parameter() {
    let by_query = Some(BucketParam::Query("bucket"));
    let unbound = admin_dialect_bound(REPLICATION_METRICS_SHADOWS, None, by_query).expect_err("an unbound bucket operation");
    assert!(unbound.iter().any(|error| matches!(
        error,
        DialectError::ClaimedOperationNamesAResource { name, .. } if *name == GET_BUCKET_QUOTA
    )));
    let misbound = admin_dialect_bound(REPLICATION_METRICS_SHADOWS, Some(BucketParam::Path("tier")), by_query)
        .expect_err("a parameter the rows lack");
    assert!(misbound.iter().any(|error| matches!(
        error,
        DialectError::ClaimedBucketParam { name, param: "tier", .. } if *name == GET_BUCKET_QUOTA
    )));
}

// ── NotImplemented, as implemented ────────────────────────────────────────────────────────────

/// Positive — the restart command is authorised by its own action.
#[test]
fn the_restart_command_is_authorised_by_its_own_action() {
    let assembled = assemble(HAND_OFF, only(SERVICE_RESTART_ACTION));
    json_of(
        &assembled,
        &ContextRequest::post(PATH_HOST, SERVICE_PATH, "action=restart").signed(REGION),
    );
}

/// Negative — another service action's grant does not admit a restart.
#[test]
fn n_a_caller_with_another_service_action_is_refused() {
    let assembled = assemble(HAND_OFF, only("admin:ServiceStop"));
    let request = ContextRequest::post(PATH_HOST, SERVICE_PATH, "action=restart").signed(REGION);
    let answer = send(&assembled, &request);
    assert_refused_before_the_handler(&assembled, &answer, 403);
}

/// Negative — any other `action` is the claim's own `501`, before anything is authorised.
#[test]
fn n_an_unserved_service_action_is_the_claims_501() {
    let assembled = assemble(HAND_OFF, |_| true);
    for query in ["action=stop", "action=bogus", ""] {
        let request = ContextRequest::post(PATH_HOST, SERVICE_PATH, query).signed(REGION);
        assert_refused_before_authorisation(&assembled, &request, 501, "NotImplemented");
    }
}
