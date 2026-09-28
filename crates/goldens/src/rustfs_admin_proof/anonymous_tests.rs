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

//! The P10-01 proof, ADR-0026's anonymous half: RustFS's four OIDC bootstrap routes, through the
//! assembled service.
//!
//! Responsible for: the operations agreeing with the recorded inventory; exactly those four
//! admitting anonymous requests, by the predicate the start-up posture report prints; an anonymous
//! bootstrap request reaching its handler only after the authorizer allowed it, with no bucket and
//! no subject; a signed one judged as its caller; and every other admin operation in the same
//! claim still refusing an anonymous caller before the authorizer.
//! NOT responsible for: rendering the posture line (`rustfs-gateway`'s `posture` unit tests), the
//! overlay's anonymous acknowledgement (`rustfs-gateway-core`'s dialect tests), or what RustFS's
//! handlers do with the provider's redirect.
//! Upstream: the parent module, `super::tests`' helpers, the recorded inventory. Downstream:
//! nothing.

use rustfs_gateway_core::op::Operation;
use rustfs_gateway_sig::{OperationFloor, SecurityFloor};

use super::classes::{
    OIDC_AUTHORIZE, OIDC_AUTHORIZE_TEMPLATE, OIDC_BOOTSTRAP, OIDC_CALLBACK, OIDC_CALLBACK_TEMPLATE, OIDC_LIST_PROVIDERS,
    OIDC_LIST_PROVIDERS_PATH, OIDC_LOGOUT, OIDC_LOGOUT_PATH,
};
use super::tests::{HAND_OFF, REGION, assert_refused_before_the_handler, only, route_calls, send};
use super::{
    AddServiceAccount, GetBucketQuota, GetBucketQuotaByQuery, GetTier, GetUserInfo, ListAccessKeysBulk, ListAccessKeysLdapBulk,
    ListAccessKeysOpenidBulk, ListPools, OidcAuthorize, OidcCallback, OidcListProviders, OidcLogout, ReplicationMetricsV2,
    SelfAccountInfo, ServerInfo, ServiceRestart, assemble,
};
use crate::operation_diff::s3s_0_17_0::context::{ACCESS_KEY, ContextRequest, PATH_HOST};
use crate::{RouteMethod, rustfs_admin_route_inventory};

/// Every bootstrap request, concretely, with the operation it reaches.
const REQUESTS: [(&str, &str); 5] = [
    (OIDC_LIST_PROVIDERS_PATH, OIDC_LIST_PROVIDERS),
    ("/minio/admin/v3/oidc/providers", OIDC_LIST_PROVIDERS),
    ("/rustfs/admin/v3/oidc/authorize/github", OIDC_AUTHORIZE),
    ("/rustfs/admin/v3/oidc/callback/github", OIDC_CALLBACK),
    (OIDC_LOGOUT_PATH, OIDC_LOGOUT),
];

fn anonymous(path: &str) -> ContextRequest {
    ContextRequest::get(PATH_HOST, path, "")
}

/// Every operation the proof registers, with its floor.
fn floors() -> Vec<(&'static str, &'static OperationFloor)> {
    macro_rules! floors {
        ($($operation:ty),* $(,)?) => {
            vec![$((<$operation>::NAME, <$operation>::floor())),*]
        };
    }
    floors![
        ServerInfo,
        AddServiceAccount,
        GetTier,
        ReplicationMetricsV2,
        ListPools,
        SelfAccountInfo,
        GetUserInfo,
        GetBucketQuota,
        ServiceRestart,
        ListAccessKeysBulk,
        ListAccessKeysLdapBulk,
        ListAccessKeysOpenidBulk,
        GetBucketQuotaByQuery,
        OidcListProviders,
        OidcAuthorize,
        OidcCallback,
        OidcLogout,
    ]
}

// ── the rows and the inventory ────────────────────────────────────────────────────────────────

/// Positive — each bootstrap operation sits on a recorded anonymous route, with its alias.
#[test]
fn the_bootstrap_operations_declare_what_the_inventory_records() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    for path in [
        OIDC_LIST_PROVIDERS_PATH,
        OIDC_AUTHORIZE_TEMPLATE,
        OIDC_CALLBACK_TEMPLATE,
        OIDC_LOGOUT_PATH,
    ] {
        let route = inventory.route(RouteMethod::Get, path).expect("a recorded route");
        assert_eq!(route.auth_detail.as_deref(), Some("OidcBootstrap"), "{path}");
        assert!(route.router_admits_anonymous, "{path}");
        assert!(route.minio_admin_alias, "{path}");
    }
}

/// Positive and negative — exactly the four bootstrap operations admit anonymous requests, each by
/// its own opt-in, under the predicate the `SECURITY_POSTURE` line prints; every other proof
/// operation stays privileged.
#[test]
fn exactly_the_bootstrap_operations_admit_anonymous_requests() {
    let floor = SecurityFloor::new();
    let mut admitted: Vec<&str> = floors()
        .into_iter()
        .filter(|(_, operation)| floor.admits_anonymous(operation))
        .map(|(name, _)| name)
        .collect();
    admitted.sort_unstable();
    assert_eq!(admitted, OIDC_BOOTSTRAP);
    for (name, operation) in floors() {
        assert!(operation.privileged(), "{name}");
        assert_eq!(operation.allows_anonymous(), OIDC_BOOTSTRAP.contains(&name), "{name}");
    }
}

// ── through the service ───────────────────────────────────────────────────────────────────────

/// Positive — an anonymous bootstrap request reaches its handler after the authorizer allowed it,
/// asked about its own label, with no caller, no bucket and no subject.
#[test]
fn an_anonymous_bootstrap_request_reaches_its_handler_after_the_authorizer_allows_it() {
    for (path, operation) in REQUESTS {
        let assembled = assemble(HAND_OFF, |request| request.is_anonymous() && OIDC_BOOTSTRAP.contains(&request.action));
        let answer = send(&assembled, &anonymous(path));
        assert_eq!(answer.status, 200, "{path}: {}", answer.text());
        let calls = assembled.calls();
        assert!(!calls.is_empty(), "{path}: the authorizer was skipped");
        assert!(
            calls.iter().all(|call| call.operation == operation
                && call.action == operation
                && call.caller.is_none()
                && call.bucket.is_none()
                && call.subject.is_none()),
            "{path}: {calls:?}"
        );
        let seen = &assembled.backend.seen()[0];
        assert_eq!((seen.operation, seen.caller.as_deref()), (operation, None), "{path}");
    }
}

/// Positive — the provider named in the path reaches the handler decoded, as a typed value.
#[test]
fn the_provider_reaches_the_handler_as_a_typed_value() {
    let assembled = assemble(HAND_OFF, |request| request.action == OIDC_AUTHORIZE);
    let answer = send(&assembled, &anonymous("/rustfs/admin/v3/oidc/authorize/git%2Dhub"));
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(assembled.backend.seen()[0].params, [("provider_id".to_owned(), "git-hub".to_owned())]);
}

/// Negative — anonymous admission is not an authorisation: an authorizer that refuses the label
/// refuses the request, after being asked.
#[test]
fn n_the_authorizer_still_decides_an_anonymous_bootstrap_request() {
    for (path, _) in REQUESTS {
        let assembled = assemble(HAND_OFF, |_| false);
        let answer = send(&assembled, &anonymous(path));
        assert_refused_before_the_handler(&assembled, &answer, 403);
        assert_eq!(route_calls(&assembled.calls()).len(), 1, "{path}");
    }
}

/// Positive — a signed bootstrap request is judged as its caller.
#[test]
fn a_signed_bootstrap_request_is_judged_as_its_caller() {
    let assembled = assemble(HAND_OFF, only(OIDC_LIST_PROVIDERS));
    let answer = send(&assembled, &ContextRequest::get(PATH_HOST, OIDC_LIST_PROVIDERS_PATH, "").signed(REGION));
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert!(
        assembled
            .calls()
            .iter()
            .all(|call| call.caller.as_deref() == Some(ACCESS_KEY))
    );
}

/// Negative — the opt-in is per operation: an anonymous caller is still refused before the
/// authorizer by every other admin operation in the same claim, and a bootstrap path the dialect
/// does not serve is the claim's `501`.
#[test]
fn n_an_anonymous_request_elsewhere_in_the_claim_is_refused_before_the_authorizer() {
    let assembled = assemble(HAND_OFF, |_| true);
    for (path, query) in [
        ("/rustfs/admin/v3/pools/list", ""),
        ("/rustfs/admin/v3/user-info", "accessKey=someone"),
        ("/rustfs/admin/v3/list-access-keys-bulk", "all=true"),
        ("/rustfs/admin/v3/get-bucket-quota", "bucket=photos"),
    ] {
        let answer = send(&assembled, &ContextRequest::get(PATH_HOST, path, query));
        assert_refused_before_the_handler(&assembled, &answer, 403);
        assert!(assembled.calls().is_empty(), "{path}: {:?}", assembled.calls());
    }
    let unserved = send(&assembled, &anonymous("/rustfs/admin/v3/oidc/config"));
    assert_refused_before_the_handler(&assembled, &unserved, 501);
    assert!(assembled.calls().is_empty());
}
