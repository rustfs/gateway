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

//! The P10-01 proof, ADR-0026 half: the three bulk access-key routes about a set of accounts, and
//! the quota route whose bucket is in the query, through the assembled service.
//!
//! Responsible for: the operations agreeing with the recorded inventory; a caller naming nobody
//! asked about itself; a named account asked about and handed to the handler, an unauthorized
//! one refused, and several unsignable today; every account allowed only with the broader action, which
//! no per-account grant can stand in for; a duplicated, malformed, contradictory or oversized set
//! refused before authorisation; and the query-bound bucket reaching the governor, both authorizer
//! stages and the handler, refused exactly as `/{bucket}` is when invalid and with a `400` naming
//! the parameter when absent, empty or repeated.
//! NOT responsible for: the rule functions (`rustfs-gateway-core`'s unit tests), the anonymous
//! guard through a floor that admits anonymous requests (`crates/gateway/tests/action_rules_runtime.rs`),
//! or the ADR-0025 routes (`super::class_tests`).
//! Upstream: the parent module, `super::tests`' helpers, the recorded inventory. Downstream:
//! nothing.

use rustfs_gateway::AuthzRequest;
use rustfs_gateway_core::dialect::{BucketParam, DialectError};
use rustfs_gateway_core::op::ResourceShape;
use rustfs_gateway_core::{MAX_SUBJECTS, Subject};
use rustfs_gateway_sig::RequestNow;

use super::classes::{
    GET_BUCKET_QUOTA_ACTION, GET_BUCKET_QUOTA_BY_QUERY, GET_BUCKET_QUOTA_BY_QUERY_PATH, LIST_ACCESS_KEYS_ACTION,
    LIST_ACCESS_KEYS_BULK, LIST_ACCESS_KEYS_BULK_PATH, LIST_ACCESS_KEYS_LDAP_BULK, LIST_ACCESS_KEYS_LDAP_BULK_PATH,
    LIST_ACCESS_KEYS_OPENID_BULK, LIST_ACCESS_KEYS_OPENID_BULK_PATH, LIST_USERS_ACTION, REQUIREMENTS, USERS_SUBJECTS,
};
use super::tests::{HAND_OFF, REGION, assert_refused_before_the_handler, only, route_calls, routed, send, send_with};
use super::{Assembled, AuthzCall, REPLICATION_METRICS_SHADOWS, admin_dialect, admin_dialect_bound, assemble};
use crate::operation_diff::s3s_f3e17541::context::{ACCESS_KEY, ContextRequest, PATH_HOST};
use crate::{RouteMethod, rustfs_admin_route_inventory};

/// The three bulk listings, which are ruled alike.
const BULK_PATHS: [(&str, &str); 3] = [
    (LIST_ACCESS_KEYS_BULK_PATH, LIST_ACCESS_KEYS_BULK),
    (LIST_ACCESS_KEYS_LDAP_BULK_PATH, LIST_ACCESS_KEYS_LDAP_BULK),
    (LIST_ACCESS_KEYS_OPENID_BULK_PATH, LIST_ACCESS_KEYS_OPENID_BULK),
];

fn get(path: &str, query: &str) -> ContextRequest {
    ContextRequest::get(PATH_HOST, path, query).signed(REGION)
}

fn json_of(assembled: &Assembled, request: &ContextRequest) -> serde_json::Value {
    let answer = send(assembled, request);
    assert_eq!(answer.status, 200, "{}", answer.text());
    serde_json::from_slice(&answer.body).expect("a JSON body")
}

fn assert_refused_before_authorisation(assembled: &Assembled, request: &ContextRequest, status: u16, code: &str) {
    let answer = send(assembled, request);
    assert_refused_before_the_handler(assembled, &answer, status);
    assert!(answer.text().contains(code), "{}", answer.text());
    assert!(assembled.calls().is_empty(), "the authorizer was asked: {:?}", assembled.calls());
    assert!(assembled.governed.lock().expect("uncontended").is_empty());
}

/// `(action, subject)` of every route-stage question, the subject as `AuthzCall` renders it.
fn route_questions(calls: &[AuthzCall]) -> Vec<(String, Option<Option<String>>)> {
    route_calls(calls)
        .into_iter()
        .map(|call| (call.action.clone(), call.subject.clone()))
        .collect()
}

fn about(name: &str) -> Option<Option<String>> {
    Some(Some(name.to_owned()))
}

/// A deployment authorizer for the bulk listings: the listing action about the caller's own
/// account (RustFS evaluates it deny-only; here nothing denies) and about each account in
/// `readable`; and, only when `everyone`, both actions about no subject — a grant that is not
/// scoped to any one account.
fn keys_of(readable: &'static [&'static str], everyone: bool) -> impl Fn(&AuthzRequest<'_>) -> bool + Send + Sync + 'static {
    move |request| match (request.action, request.subject) {
        (LIST_ACCESS_KEYS_ACTION, Some(Subject::Caller)) => true,
        (LIST_ACCESS_KEYS_ACTION, Some(subject)) => subject.name().is_some_and(|name| readable.contains(&name)),
        (LIST_ACCESS_KEYS_ACTION | LIST_USERS_ACTION, None) => everyone,
        _ => false,
    }
}

// ── the rows and the inventory ────────────────────────────────────────────────────────────────

/// Positive — each operation sits on its recorded route, with its alias, and declares its rule.
#[test]
fn the_set_and_query_operations_declare_what_the_inventory_records() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    for (path, class) in [
        (LIST_ACCESS_KEYS_BULK_PATH, "MultipleActions"),
        (LIST_ACCESS_KEYS_LDAP_BULK_PATH, "MultipleActions"),
        (LIST_ACCESS_KEYS_OPENID_BULK_PATH, "MultipleActions"),
        (GET_BUCKET_QUOTA_BY_QUERY_PATH, "S3Action"),
    ] {
        let route = inventory.route(RouteMethod::Get, path).expect("a recorded route");
        assert_eq!(route.auth_detail.as_deref(), Some(class), "{path}");
        assert!(route.minio_admin_alias, "{path}");
        assert!(route.path_params.is_empty(), "{path}");
    }
    for requirement in &REQUIREMENTS[5..8] {
        assert_eq!(requirement.subject(), Some(USERS_SUBJECTS));
        assert_eq!(requirement.everyone_action(), Some(LIST_USERS_ACTION));
        assert_eq!(requirement.actions(), [LIST_ACCESS_KEYS_ACTION]);
    }
    assert_eq!(REQUIREMENTS[8].subject(), None);
    assert_eq!(REQUIREMENTS[8].resource, ResourceShape::Bucket);
}

/// Positive — every row and alias reaches its operation whatever its query; a sibling path does not.
#[test]
fn each_set_and_query_request_reaches_its_operation() {
    let dialect = admin_dialect();
    for (target, operation) in [
        ("/rustfs/admin/v3/list-access-keys-bulk?users=a", Some(LIST_ACCESS_KEYS_BULK)),
        ("/minio/admin/v3/list-access-keys-bulk", Some(LIST_ACCESS_KEYS_BULK)),
        ("/rustfs/admin/v3/idp/ldap/list-access-keys-bulk", Some(LIST_ACCESS_KEYS_LDAP_BULK)),
        (
            "/minio/admin/v3/idp/openid/list-access-keys-bulk?all=true",
            Some(LIST_ACCESS_KEYS_OPENID_BULK),
        ),
        ("/rustfs/admin/v3/get-bucket-quota?bucket=photos", Some(GET_BUCKET_QUOTA_BY_QUERY)),
        ("/minio/admin/v3/get-bucket-quota", Some(GET_BUCKET_QUOTA_BY_QUERY)),
        ("/rustfs/admin/v3/idp/saml/list-access-keys-bulk", None),
    ] {
        assert_eq!(routed(Some(&dialect), "GET", target), operation, "{target}");
    }
}

// ── a set of accounts ─────────────────────────────────────────────────────────────────────────

/// Positive — naming nobody lists the caller's own keys: one question, about the caller.
#[test]
fn a_caller_naming_nobody_is_asked_about_itself() {
    for (path, _) in BULK_PATHS {
        let assembled = assemble(HAND_OFF, keys_of(&[], false));
        let body = json_of(&assembled, &get(path, "listType=all"));
        assert_eq!(body["subjects"], "caller", "{path}");
        assert_eq!(
            route_questions(&assembled.calls()),
            [(LIST_ACCESS_KEYS_ACTION.to_owned(), Some(None))],
            "{path}"
        );
    }
}

/// Positive — a named account is asked about, and the handler is handed the set exactly as it was
/// judged; the input stage re-asks the same question.
#[test]
fn a_named_account_is_asked_about_and_handed_to_the_handler() {
    for (path, operation) in BULK_PATHS {
        let assembled = assemble(HAND_OFF, keys_of(&["alice"], false));
        let body = json_of(&assembled, &get(path, "users=alice"));
        assert_eq!(body["operation"], operation);
        assert_eq!(body["subjects"], serde_json::json!(["alice"]));
        assert_eq!(body["subject"], serde_json::Value::Null, "a set has no one subject");
        let calls = assembled.calls();
        assert_eq!(route_questions(&calls), [(LIST_ACCESS_KEYS_ACTION.to_owned(), about("alice"))], "{path}");
        let input: Vec<&AuthzCall> = calls.iter().filter(|call| call.stage == "input").collect();
        assert_eq!(input.len(), 1, "{calls:?}");
        assert_eq!(input[0].subject, about("alice"));
    }
}

/// Negative — an account the caller may not read is refused before the handler, after it was
/// asked about.
#[test]
fn n_an_unauthorized_named_account_refuses_the_request() {
    for (path, _) in BULK_PATHS {
        let assembled = assemble(HAND_OFF, keys_of(&["alice"], false));
        let answer = send(&assembled, &get(path, "users=bob"));
        assert_refused_before_the_handler(&assembled, &answer, 403);
        assert_eq!(route_questions(&assembled.calls()), [(LIST_ACCESS_KEYS_ACTION.to_owned(), about("bob"))]);
    }
}

/// Negative — a request naming several accounts cannot be signed today: SigV4 canonicalisation,
/// which the signer and the verifier share, refuses a repeated query parameter (s3s#176), so such
/// a request fails closed before anything reads the set. That one refused account refuses a set is
/// proven in `rustfs-gateway-core`'s `authz::plan` tests; admitting the repeated parameter is
/// ADR-0026's open item.
#[test]
fn n_a_request_naming_several_accounts_cannot_be_signed_today() {
    let several = get(LIST_ACCESS_KEYS_BULK_PATH, "users=alice&users=bob");
    let error = several
        .wire_headers(RequestNow::capture())
        .expect_err("a repeated parameter is unsignable");
    assert!(error.contains("AuthorizationHeaderMalformed"), "{error}");
    assert!(
        get(LIST_ACCESS_KEYS_BULK_PATH, "users=alice")
            .wire_headers(RequestNow::capture())
            .is_ok()
    );
}

/// Positive — every account, with the broader action: both actions asked about no subject, and
/// the handler is told every account.
#[test]
fn every_account_is_listed_with_the_broader_action() {
    for (path, _) in BULK_PATHS {
        let assembled = assemble(HAND_OFF, keys_of(&[], true));
        let body = json_of(&assembled, &get(path, "all=true"));
        assert_eq!(body["subjects"], "everyone", "{path}");
        assert_eq!(
            route_questions(&assembled.calls()),
            [
                (LIST_ACCESS_KEYS_ACTION.to_owned(), None),
                (LIST_USERS_ACTION.to_owned(), None)
            ],
            "{path}"
        );
    }
}

/// Negative — every account without the broader action is refused; so is every account for a
/// caller whose grants are all scoped to accounts, however many accounts they name, and for a
/// caller granted the broader action only about some account.
#[test]
fn n_every_account_without_the_broader_action_is_refused() {
    let listing_only = |request: &AuthzRequest<'_>| request.action == LIST_ACCESS_KEYS_ACTION;
    let scoped_broader = |request: &AuthzRequest<'_>| {
        request.action == LIST_ACCESS_KEYS_ACTION || (request.action == LIST_USERS_ACTION && request.subject.is_some())
    };
    for (path, _) in BULK_PATHS {
        let assembled = assemble(HAND_OFF, listing_only);
        assert_refused_before_the_handler(&assembled, &send(&assembled, &get(path, "all=true")), 403);
        assert_eq!(
            route_questions(&assembled.calls()),
            [
                (LIST_ACCESS_KEYS_ACTION.to_owned(), None),
                (LIST_USERS_ACTION.to_owned(), None)
            ]
        );
        let per_account = assemble(HAND_OFF, keys_of(&["alice", "bob", ACCESS_KEY], false));
        assert_refused_before_the_handler(&per_account, &send(&per_account, &get(path, "all=true")), 403);
        let scoped = assemble(HAND_OFF, scoped_broader);
        assert_refused_before_the_handler(&scoped, &send(&scoped, &get(path, "all=true")), 403);
    }
}

/// Negative — a duplicated, empty, malformed, contradictory or oversized set, or a flag that is not
/// exactly `true` or `false`, is a `400` before anything is authenticated or authorised. Unsigned
/// on purpose: the refusal precedes the signature, so it cannot depend on one.
#[test]
fn n_a_duplicated_malformed_contradictory_or_oversized_set_is_refused_before_authorisation() {
    let oversized = (0..=MAX_SUBJECTS)
        .map(|index| format!("users=u{index}"))
        .collect::<Vec<_>>()
        .join("&");
    let assembled = assemble(HAND_OFF, |_| true);
    for query in [
        "users=alice&users=alice",
        "users=",
        "users",
        "users=alice&users=",
        "users=a+b",
        "users=a%zz",
        "all=true&users=alice",
        "users=alice&all=true",
        "all=yes",
        "all=1",
        "all=true&all=true",
        oversized.as_str(),
    ] {
        let request = ContextRequest::get(PATH_HOST, LIST_ACCESS_KEYS_BULK_PATH, query);
        assert_refused_before_authorisation(&assembled, &request, 400, "InvalidArgument");
    }
}

// ── the bucket named in the query ─────────────────────────────────────────────────────────────

/// Positive — the query's bucket is the resource at the governor, both stages and the handler,
/// canonical row and alias alike; no template value is extracted.
#[test]
fn the_query_bucket_is_the_authorisation_bucket() {
    for path in [GET_BUCKET_QUOTA_BY_QUERY_PATH, "/minio/admin/v3/get-bucket-quota"] {
        let assembled = assemble(HAND_OFF, only(GET_BUCKET_QUOTA_ACTION));
        let body = json_of(&assembled, &get(path, "bucket=photos"));
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
        assert!(seen.params.is_empty());
        let governed = assembled.governed.lock().expect("uncontended").clone();
        assert_eq!(governed, [(GET_BUCKET_QUOTA_BY_QUERY.to_owned(), Some("photos".to_owned()))]);
    }
}

/// Negative — the wrong action on the right bucket is refused.
#[test]
fn n_a_quota_read_by_query_without_its_s3_action_is_refused() {
    let assembled = assemble(HAND_OFF, only("admin:SetBucketQuota"));
    let answer = send(&assembled, &get(GET_BUCKET_QUOTA_BY_QUERY_PATH, "bucket=photos"));
    assert_refused_before_the_handler(&assembled, &answer, 403);
    let route = route_calls(&assembled.calls())[0].clone();
    assert_eq!(
        (route.action.as_str(), route.bucket.as_deref()),
        (GET_BUCKET_QUOTA_ACTION, Some("photos"))
    );
}

/// Negative — a bucket S3 would refuse as `/{bucket}` is refused in the query with the same status
/// and code, before the governor or the authorizer is asked; an escaped spelling included.
#[test]
fn n_an_invalid_query_bucket_is_refused_as_s3_refuses_it() {
    let long = "a".repeat(64);
    for bucket in [
        "ab",
        "Bad_Bucket",
        "%70hotos",
        "192.168.1.1",
        "a..b",
        "-photos",
        "pho+tos",
        long.as_str(),
    ] {
        let assembled = assemble(HAND_OFF, |_| true);
        let admin = send(&assembled, &get(GET_BUCKET_QUOTA_BY_QUERY_PATH, &format!("bucket={bucket}")));
        assert_refused_before_the_handler(&assembled, &admin, 400);
        assert!(admin.text().contains("InvalidBucketName"), "{bucket}: {}", admin.text());
        let s3 = send(&assembled, &get(&format!("/{bucket}"), ""));
        assert_eq!(s3.status, admin.status, "{bucket}: {}", s3.text());
        assert!(assembled.calls().is_empty(), "{bucket}: {:?}", assembled.calls());
        assert!(assembled.governed.lock().expect("uncontended").is_empty(), "{bucket}");
    }
}

/// Negative — no bucket, an empty one, or two, is a `400` naming the parameter before anything is
/// authenticated or authorised: never a service-level request, never the first of two.
#[test]
fn n_an_absent_empty_or_repeated_bucket_parameter_is_refused_before_authorisation() {
    let assembled = assemble(HAND_OFF, |_| true);
    for query in [
        "",
        "bucket=",
        "bucket",
        "other=photos",
        "bucket=photos&bucket=videos",
        "bucket=photos&bucket=photos",
    ] {
        let request = ContextRequest::get(PATH_HOST, GET_BUCKET_QUOTA_BY_QUERY_PATH, query);
        assert_refused_before_authorisation(&assembled, &request, 400, "InvalidArgument");
    }
}

/// Negative — a claimed request never reads the query-bound bucket's CORS document, while an S3
/// request to that bucket does (the control that shows the observer sees reads at all).
#[test]
fn n_a_query_bound_request_never_consults_the_buckets_cors() {
    let origin = |headers: &mut http::HeaderMap| {
        headers.insert("origin", http::HeaderValue::from_static("https://console.example"));
    };
    let assembled = assemble(HAND_OFF, |_| true);
    let admin = send_with(&assembled, &get(GET_BUCKET_QUOTA_BY_QUERY_PATH, "bucket=photos"), origin);
    assert_eq!(admin.status, 200, "{}", admin.text());
    assert!(assembled.cors_loaded.lock().expect("uncontended").is_empty());
    let s3 = send_with(&assembled, &get("/photos", ""), origin);
    assert_eq!(s3.status, 200, "{}", s3.text());
    assert_eq!(*assembled.cors_loaded.lock().expect("uncontended"), ["photos"]);
}

/// Negative — without its binding the bucket operation cannot be claimed; a template binding its
/// rows cannot satisfy, or a query parameter that is not a plain key, is refused.
#[test]
fn n_the_query_route_needs_its_binding() {
    let quota = Some(BucketParam::Path("bucket"));
    let refused = |by_query| admin_dialect_bound(REPLICATION_METRICS_SHADOWS, quota, by_query).expect_err("a bad binding");
    assert!(refused(None).iter().any(|error| matches!(
        error,
        DialectError::ClaimedOperationNamesAResource { name, .. } if *name == GET_BUCKET_QUOTA_BY_QUERY
    )));
    for binding in [BucketParam::Path("bucket"), BucketParam::Query("buc ket")] {
        assert!(
            refused(Some(binding)).iter().any(|error| matches!(
                error,
                DialectError::ClaimedBucketParam { name, .. } if *name == GET_BUCKET_QUOTA_BY_QUERY
            )),
            "{binding:?}"
        );
    }
}
