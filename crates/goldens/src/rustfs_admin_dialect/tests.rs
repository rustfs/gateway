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

//! The generated RustFS admin dialect, bound to the inventory and driven route by route.
//!
//! Responsible for: every declared operation agreeing with its inventory row in both directions,
//! the pending census adding up to the rest of the inventory, and, for every row of every
//! operation, SigV4 and then exactly the declared action asked about no bucket and exactly the
//! declared account (none, the caller, or the one the query names), the decoded path parameters,
//! the same accounts and — only on the sealed rows — the caller's secret in the handler; refusal
//! before the handler when that action is denied, when only other actions are allowed, when the
//! request is unsigned, forged, from an unknown key, or presigned, and when a parameter value is
//! malformed.
//! NOT responsible for: the harness (`super`), the subject rules' own refusals and forms
//! (`subject_tests`), routing without a service, or the generator.
//! Upstream: `super`, the recorded inventory. Downstream: nothing.

use std::collections::{BTreeMap, BTreeSet};

use rustfs_gateway_core::SubjectRule;
use rustfs_gateway_dialect_rustfs_admin::{BodyKind, PENDING, ROUTES, RouteRecord, STAYING};

use super::{
    Exchange, actions, assemble, assemble_on, declared, expected_bucket, expected_subject, expected_subjects, in_lanes,
    in_lanes_on, is_catch_all, param, paths, presigned, rustfs_profile_floor, signed, templates, unsigned, value_of, wire,
    with_segment,
};
use crate::migration_inventory::rustfs_admin_routes::{AdminAuthMode, RequestBodyUse, ResponseBodyUse};
use crate::operation_diff::s3s_0_17_0::context::ACCESS_KEY;
use crate::rustfs_admin_route_inventory;

const fn request_kind(recorded: RequestBodyUse) -> BodyKind {
    match recorded {
        RequestBodyUse::Buffered => BodyKind::Buffered,
        RequestBodyUse::Streamed => BodyKind::Streamed,
        RequestBodyUse::HandedOn => BodyKind::HandedOn,
        RequestBodyUse::NotRead => BodyKind::NotRead,
    }
}

const fn response_kind(recorded: ResponseBodyUse) -> BodyKind {
    match recorded {
        ResponseBodyUse::Buffered => BodyKind::Buffered,
        ResponseBodyUse::Streamed => BodyKind::Streamed,
    }
}

fn refused_before_the_handler(exchange: &Exchange, at: &str) {
    assert_eq!(exchange.status, 403, "{at}: {}", exchange.body);
    assert!(exchange.reached.is_empty(), "{at}: a handler ran: {:?}", exchange.reached);
}

fn refused_without_asking(exchange: &Exchange, at: &str) {
    refused_before_the_handler(exchange, at);
    assert!(exchange.asked.is_empty(), "{at}: the authorizer was asked {:?}", exchange.asked);
}

/// Every `(record, path)` pair: every row of every operation, with its parameters filled in.
fn rows() -> impl Iterator<Item = (&'static RouteRecord, String)> {
    ROUTES
        .iter()
        .flat_map(|record| paths(record).into_iter().map(move |path| (record, path)))
}

/// Every `(record, template, segment index, parameter)` of every one-segment parameter of every
/// templated row (ADR-0024); a catch-all is `refresh_tests.rs`'s (ADR-0036).
fn parameters() -> impl Iterator<Item = (&'static RouteRecord, &'static str, usize, &'static str)> {
    ROUTES.iter().flat_map(|record| {
        templates(record).into_iter().flat_map(move |template| {
            template
                .split('/')
                .enumerate()
                .filter(|(_, segment)| !is_catch_all(segment))
                .filter_map(move |(index, segment)| param(segment).map(|name| (record, template, index, name)))
        })
    })
}

// ── the inventory ───────────────────────────────────────────────────────────────────────────

/// Positive — every route of a migrated group is declared as its inventory row records it:
/// group, alias, handler, body kinds, secret, and the recorded action or ADR-0025's ruling of its
/// custom class; a `/iceberg/v1` compat row is the alias of its `/_iceberg/v1` route and no
/// operation of its own (ADR-0031 (b)); and every declared operation is bound to exactly one
/// canonical inventory route.
#[test]
fn every_migrated_route_is_declared_as_the_inventory_records_it() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    let migrated: BTreeSet<&str> = ROUTES
        .iter()
        .map(|record| record.group)
        .chain(STAYING.iter().map(|route| route.group))
        .collect();
    let mut canonical = 0;
    let mut compat = 0;
    let mut staying = 0;
    for route in inventory
        .routes()
        .iter()
        .filter(|route| migrated.contains(route.group.as_str()))
    {
        let at = route.key();
        if STAYING
            .iter()
            .any(|stays| stays.method == route.method.as_str() && stays.path == route.path && stays.group == route.group)
        {
            // It stays with RustFS for its recorded reason (ADR-0032 (b)), and is no operation.
            assert!(
                !ROUTES
                    .iter()
                    .any(|record| record.method == route.method.as_str() && record.path == route.path),
                "{at}: a staying route is declared"
            );
            staying += 1;
            continue;
        }
        if route.path.starts_with("/iceberg/v1/") {
            let by_alias: Vec<&RouteRecord> = ROUTES
                .iter()
                .filter(|record| record.method == route.method.as_str() && record.alias == Some(route.path.as_str()))
                .collect();
            assert_eq!(by_alias.len(), 1, "{at}: a compat row is exactly one operation's alias");
            assert!(
                !ROUTES.iter().any(|record| record.path == route.path),
                "{at}: a compat row is no operation"
            );
            assert_eq!(by_alias[0].rustfs_handler, route.handler, "{at}");
            compat += 1;
            continue;
        }
        let records: Vec<&RouteRecord> = ROUTES
            .iter()
            .filter(|record| record.method == route.method.as_str() && record.path == route.path)
            .collect();
        assert!(!records.is_empty(), "{at} is not declared");
        let alias = if route.minio_admin_alias {
            Some(route.path.replacen("/rustfs/admin/", "/minio/admin/", 1))
        } else {
            route
                .path
                .starts_with("/_iceberg/v1/")
                .then(|| route.path.replacen("/_iceberg/", "/iceberg/", 1))
        };
        for record in &records {
            assert_eq!(record.group, route.group, "{at}");
            assert_eq!(record.alias.map(str::to_owned), alias, "{at}");
            assert_eq!(record.rustfs_handler, route.handler, "{at}");
            assert_eq!(record.request_body, request_kind(route.request_body), "{at}");
            assert_eq!(record.response_body, response_kind(route.response_body), "{at}");
            assert_eq!(record.caller_secret, route.caller_secret_body.needs_caller_secret(), "{at}");
            match route.auth_mode {
                AdminAuthMode::Sigv4Admin => {
                    assert_eq!(Some(record.action), route.iam_action_wire.as_deref(), "{at}");
                    assert_eq!((record.ruled, record.query, records.len()), (None, None, 1), "{at}");
                }
                AdminAuthMode::Custom => assert_eq!(record.ruled, route.auth_detail.as_deref(), "{at}"),
                AdminAuthMode::Anonymous => {
                    // Only the OIDC bootstrap is declared anonymous, under its own label (ADR-0026 (f)).
                    assert_eq!(route.auth_detail.as_deref(), Some("OidcBootstrap"), "{at}");
                    assert_eq!(record.ruled, route.auth_detail.as_deref(), "{at}");
                    assert!(record.action.starts_with("rustfs:"), "{at}: {}", record.action);
                }
            }
            assert_eq!(record.anonymous, matches!(route.auth_mode, AdminAuthMode::Anonymous), "{at}");
        }
        canonical += records.len();
    }
    assert_eq!(canonical, ROUTES.len(), "a declared operation has no inventory route");
    assert_eq!(compat, 50, "every table-catalog route has its compat row");
    assert_eq!((staying, STAYING.len()), (7, 7), "every staying route is an inventory route");
}

/// Positive — the pending groups are exactly the inventory's other groups, each with its
/// inventory route count, so the migrated groups plus the pending ones are the whole inventory.
#[test]
fn the_pending_groups_are_the_rest_of_the_inventory() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    let migrated: BTreeSet<&str> = ROUTES
        .iter()
        .map(|record| record.group)
        .chain(STAYING.iter().map(|route| route.group))
        .collect();
    let mut rest: BTreeMap<&str, u16> = BTreeMap::new();
    for route in inventory.routes() {
        if !migrated.contains(route.group.as_str()) {
            *rest.entry(route.group.as_str()).or_default() += 1;
        }
    }
    let pending: BTreeMap<&str, u16> = PENDING.iter().map(|pending| (pending.group, pending.routes)).collect();
    assert_eq!(pending, rest);
    // Every declared canonical route, plus every alias that is itself an inventory row (the
    // `/iceberg/v1` compat rows), plus every pending route, is the inventory.
    let declared_routes: BTreeSet<(&str, &str)> = ROUTES
        .iter()
        .flat_map(|record| {
            std::iter::once((record.method, record.path)).chain(
                record
                    .alias
                    .filter(|alias| alias.starts_with("/iceberg/v1/"))
                    .map(|alias| (record.method, alias)),
            )
        })
        .collect();
    let pending_routes: usize = PENDING.iter().map(|pending| usize::from(pending.routes)).sum();
    assert_eq!(declared_routes.len() + pending_routes + STAYING.len(), inventory.routes().len());
}

// ── every row through the assembled service ─────────────────────────────────────────────────

/// Positive — every row of every operation, signed, is authorised by exactly its declared
/// actions (every one, in order, for an any-of rule, whose answers the facade combines) about its
/// bound bucket or none (ADR-0030) and no key, for the signing caller, and about exactly its declared account: none, the
/// caller for an own-account operation, or the account the query names for a named-account or
/// set operation; and reaches exactly its own handler, which is handed each path parameter
/// decoded, the same accounts (one subject only for a single-subject rule), and the caller's
/// secret only when its row is sealed, and the same bucket or none.
#[test]
fn every_row_is_authorised_by_exactly_its_declared_action() {
    let assembled = assemble(declared);
    for (record, template) in ROUTES
        .iter()
        .flat_map(|record| templates(record).into_iter().map(move |template| (record, template)))
    {
        let path = with_segment(template, None, "");
        let at = format!("{} {path} ({})", record.method, record.operation);
        let exchange = assembled.exchange(wire(&signed(record, &path)));
        assert_eq!(exchange.status, 200, "{at}: {}", exchange.body);
        assert_eq!(exchange.reached, [record.operation], "{at}");
        // A HEAD answer carries no body; the handler's reach is recorded above.
        assert!(
            record.method == "HEAD" || exchange.body.contains(record.operation),
            "{at}: {}",
            exchange.body
        );
        let params: Vec<(String, String)> = template
            .split('/')
            .filter_map(param)
            .map(|name| (name.to_owned(), value_of(name)))
            .collect();
        let handed = &exchange.handed[0];
        assert_eq!(handed.params, params, "{at}");
        assert_eq!(handed.bucket, expected_bucket(record), "{at}");
        assert_eq!(handed.holds_secret, record.caller_secret, "{at}");
        assert_eq!(handed.subjects, expected_subjects(record), "{at}");
        let single = matches!(record.subject, Some(SubjectRule::Caller | SubjectRule::Query { .. }));
        assert_eq!(handed.has_one_subject, single, "{at}");
        let about = expected_subject(record);
        let expected = actions(record);
        let asked_at_route: Vec<&str> = exchange
            .asked
            .iter()
            .filter(|asked| asked.stage == "route")
            .map(|asked| asked.action.as_str())
            .collect();
        assert_eq!(asked_at_route, expected, "{at}");
        for asked in &exchange.asked {
            assert_eq!(asked.operation, record.operation, "{at}");
            assert!(expected.contains(&asked.action.as_str()), "{at}: {asked:?}");
            assert_eq!(asked.caller.as_deref(), Some(ACCESS_KEY), "{at}");
            assert_eq!((asked.bucket.clone(), asked.key.as_deref()), (expected_bucket(record), None), "{at}");
            assert_eq!(asked.subject, about, "{at}");
        }
    }
}

/// Positive and negative — with the authenticator handing the secret over, exactly the
/// sixty-six rows of the thirty-three sealed operations hold it, and it is the caller's; no other
/// row's handler holds any secret.
#[test]
fn the_caller_secret_reaches_exactly_the_sealed_rows() {
    let assembled = assemble(declared);
    let mut holders = BTreeSet::new();
    for (record, path) in rows() {
        let exchange = assembled.exchange(wire(&signed(record, &path)));
        let handed = exchange.handed.first().unwrap_or_else(|| panic!("{path}: {}", exchange.body));
        assert_eq!(handed.holds_secret, record.caller_secret, "{path}");
        assert_eq!(handed.secret_is_the_callers, record.caller_secret, "{path}");
        if handed.holds_secret {
            holders.insert((record.method, path));
        }
    }
    assert_eq!(holders.len(), 66, "{holders:?}");
    assert_eq!(holders.iter().filter(|(_, path)| path.starts_with("/minio/admin/")).count(), 33);
}

/// Positive — each any-of row is authorised by any one of its actions alone: `datausageinfo`,
/// both policy-entities routes, both pools routes and `usage/{bucket}`.
#[test]
fn every_any_of_row_is_authorised_by_either_action() {
    let any_of: Vec<&RouteRecord> = ROUTES.iter().filter(|record| actions(record).len() > 1).collect();
    let names: Vec<&str> = any_of.iter().map(|record| record.operation).collect();
    assert_eq!(
        names,
        [
            "rustfs:GetV3Datausageinfo",
            "rustfs:GetV3IdpBuiltinPolicyEntities",
            "rustfs:GetV3IdpLdapPolicyEntities",
            "rustfs:GetV3PoolsList",
            "rustfs:GetV3PoolsStatus",
            "rustfs:GetV3UsageByBucket"
        ]
    );
    for record in any_of {
        for allowed in actions(record) {
            let assembled = assemble(move |_, action| action == allowed);
            for path in paths(record) {
                let exchange = assembled.exchange(wire(&signed(record, &path)));
                assert_eq!(exchange.status, 200, "{allowed} {path}: {}", exchange.body);
                assert_eq!(exchange.reached, [record.operation]);
            }
        }
    }
}

/// Negative — every row whose declared action is denied is refused before its handler, after
/// asking about that action.
#[test]
fn n_a_row_whose_action_is_denied_is_refused_before_its_handler() {
    in_lanes(
        |_, _| false,
        &rows().collect::<Vec<_>>(),
        |assembled, (record, path)| {
            let at = format!("{} {path}", record.method);
            let exchange = assembled.exchange(wire(&signed(record, path)));
            refused_before_the_handler(&exchange, &at);
            // A HEAD response carries no body to read the code from.
            assert!(
                record.method == "HEAD" || exchange.body.contains("<Code>AccessDenied</Code>"),
                "{at}: {}",
                exchange.body
            );
            assert_eq!(
                exchange.asked.first().map(|asked| asked.action.as_str()),
                Some(actions(record)[0]),
                "{at}"
            );
        },
    );
}

/// Negative — allowing every action but a row's own does not authorise it: the decision is the
/// declared action's, not any admin permission's.
#[test]
fn n_every_other_action_does_not_authorise_a_row() {
    let policy = |operation: &str, action: &str| !declared(operation, action);
    in_lanes(policy, &rows().collect::<Vec<_>>(), |assembled, (record, path)| {
        let exchange = assembled.exchange(wire(&signed(record, path)));
        refused_before_the_handler(&exchange, &format!("{} {path}", record.method));
    });
}

/// Negative — an unsigned request for any row, its account included, is refused without asking
/// the authorizer.
#[test]
fn n_an_unsigned_row_is_refused_without_asking() {
    let privileged: Vec<_> = rows().filter(|(record, _)| !record.anonymous).collect();
    assert_eq!(privileged.len(), 618 - 8, "every row but the four bootstrap operations' eight");
    in_lanes(
        |_, _| true,
        &privileged,
        |assembled, (record, path)| {
            let exchange = assembled.exchange(unsigned(record, path));
            refused_without_asking(&exchange, &format!("{} {path}", record.method));
        },
    );
}

/// Positive and negative — exactly the eight rows of RustFS's four OIDC bootstrap operations admit
/// an unsigned request: the authorizer is asked the operation's own label with no identity, no
/// bucket and no account, and the handler runs only when it allows; when it denies, the request is
/// refused before the handler; and a signed request for the same row is judged as its caller
/// (ADR-0026 (f), ADR-0032).
#[test]
fn an_anonymous_bootstrap_row_is_admitted_only_by_the_authorizer() {
    let bootstrap: Vec<_> = rows().filter(|(record, _)| record.anonymous).collect();
    let names: BTreeSet<&str> = bootstrap.iter().map(|(record, _)| record.operation).collect();
    assert_eq!((bootstrap.len(), names.len()), (8, 4));
    for (record, path) in &bootstrap {
        let at = format!("{} {path}", record.method);
        let allowed = assemble(|_, _| true).exchange(unsigned(record, path));
        assert_eq!(allowed.status, 200, "{at}: {}", allowed.body);
        assert_eq!(allowed.reached, [record.operation], "{at}");
        assert!(!allowed.asked.is_empty(), "{at}: the authorizer was not asked");
        for asked in &allowed.asked {
            assert_eq!((asked.action.as_str(), asked.caller.as_deref()), (record.action, None), "{at}");
            assert_eq!((asked.bucket.as_deref(), asked.subject.clone()), (None, None), "{at}");
        }
        assert!(!allowed.handed[0].holds_secret, "{at}");

        let denied = assemble(|_, _| false).exchange(unsigned(record, path));
        assert_eq!(denied.status, 403, "{at}: {}", denied.body);
        assert!(denied.reached.is_empty() && !denied.asked.is_empty(), "{at}");

        let signed_in = assemble(|_, _| true).exchange(wire(&signed(record, path)));
        assert_eq!(signed_in.status, 200, "{at}: {}", signed_in.body);
        assert!(
            signed_in
                .asked
                .iter()
                .all(|asked| asked.caller.as_deref() == Some(ACCESS_KEY)),
            "{at}"
        );
    }
}

/// Negative — a forged signature or an unknown access key is refused without asking the
/// authorizer.
///
/// The assembly's framework rates leave room for the whole burst, so the verifier, not the
/// framework limiter (`SlowDown`), answers every row; the assertion below holds that apart.
#[test]
fn n_a_forged_or_unknown_key_row_is_refused_without_asking() {
    in_lanes(
        |_, _| true,
        &rows().collect::<Vec<_>>(),
        |assembled, (record, path)| {
            for request in [signed(record, path).forged(), signed(record, path).unknown_key()] {
                let exchange = assembled.exchange(wire(&request));
                let at = format!("{} {path}", record.method);
                refused_without_asking(&exchange, &at);
                assert!(!exchange.body.contains("<Code>SlowDown</Code>"), "{at}: {}", exchange.body);
            }
        },
    );
}

/// Negative — a presigned request for any row no query selects, its account included, is refused
/// at the floor, as `AccessDenied`, without asking the authorizer.
#[test]
fn n_a_presigned_row_is_refused_without_asking() {
    let presignable: Vec<_> = rows().filter(|(record, _)| record.query.is_none()).collect();
    assert_eq!(presignable.len(), 610, "every row but the service command's eight");
    in_lanes(
        |_, _| true,
        &presignable,
        |assembled, (record, path)| {
            let at = format!("{} {path}", record.method);
            let exchange = assembled.exchange(presigned(record, path));
            refused_without_asking(&exchange, &at);
            // A HEAD response carries no body to read the code from.
            assert!(
                record.method == "HEAD" || exchange.body.contains("<Code>AccessDenied</Code>"),
                "{at}: {}",
                exchange.body
            );
        },
    );
}

/// Negative — a signed request whose parameter value does not decode to a plain segment (an
/// invalid UTF-8 escape, a control character) is a `400 InvalidArgument` naming the parameter,
/// and one whose value is a dot segment or an encoded separator reaches no row (the claim's
/// `501`); both before the authorizer is asked or any handler runs.
#[test]
fn n_a_malformed_parameter_value_is_refused_before_authorising() {
    let cases: Vec<_> = parameters()
        .flat_map(|(record, template, index, name)| {
            [("%ff", 400), ("a%01b", 400), ("%c3%28", 400), ("%2e%2e", 501), ("a%2Fb", 501)]
                .map(|(raw, status)| (record, with_segment(template, Some(index), raw), name, raw, status))
        })
        .collect();
    assert_eq!(cases.len(), 5 * 2 * 189, "189 parameters across 102 templates, each with its alias");
    in_lanes(
        |_, _| true,
        &cases,
        |assembled, (record, path, name, raw, status)| {
            let at = format!("{} {path}", record.method);
            let exchange = assembled.exchange(wire(&signed(record, path)));
            assert_eq!(exchange.status, *status, "{at}: {}", exchange.body);
            assert!(exchange.reached.is_empty(), "{at}: a handler ran");
            assert!(exchange.asked.is_empty(), "{at}: the authorizer was asked {:?}", exchange.asked);
            if *status == 400 && record.method != "HEAD" {
                assert!(exchange.body.contains("<Code>InvalidArgument</Code>"), "{at}: {}", exchange.body);
                assert!(exchange.body.contains(name), "{at}: {}", exchange.body);
                assert!(!exchange.body.contains(raw), "{at}: the value is echoed: {}", exchange.body);
            }
        },
    );
}

// ── named divergences ──────────────────────────────────────────────────────────────────────────

/// A presigned URL on a RustFS admin route, correctly signed: legacy RustFS verifies a presigned
/// URL on any request before it routes it and serves the admin route to the verified credential
/// (`GET /rustfs/admin/v3/info` presigned by the root credential answered `200` with the server
/// information, observed against rustfs/rustfs `e870a6d25b`). The gateway refuses it at the floor,
/// as `AccessDenied` and without asking the authorizer, under the RustFS profile's floor too —
/// which admits a presigned URL on every standard operation and on no privileged one. Kept on
/// security grounds (MinIO #5411 was a presigned URL edited to reach an admin operation); the same
/// rows header-signed are served behind the same floor.
///
/// Ruling: `rd-adm-0001`
#[test]
fn a_presigned_admin_request_is_refused_under_the_rustfs_profile_floor() {
    let presignable: Vec<_> = rows().filter(|(record, _)| record.query.is_none()).collect();
    assert_eq!(presignable.len(), 596, "every row but the service command's eight");
    in_lanes_on(
        &rustfs_profile_floor(),
        |_, _| true,
        &presignable,
        |assembled, (record, path)| {
            let at = format!("{} {path}", record.method);
            let exchange = assembled.exchange(presigned(record, path));
            refused_without_asking(&exchange, &at);
            assert!(
                record.method == "HEAD" || exchange.body.contains("<Code>AccessDenied</Code>"),
                "{at}: {}",
                exchange.body
            );
        },
    );
    let served = assemble_on(rustfs_profile_floor(), |_, _| true);
    let info: Vec<_> = presignable
        .iter()
        .filter(|(record, _)| record.path == "/rustfs/admin/v3/info")
        .collect();
    assert!(!info.is_empty(), "the server-information row is presignable");
    for (record, path) in info {
        let exchange = served.exchange(wire(&signed(record, path)));
        assert_eq!(exchange.status, 200, "{} {path}: {}", record.method, exchange.body);
    }
}
