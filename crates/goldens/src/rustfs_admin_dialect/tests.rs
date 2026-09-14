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
//! operation, SigV4 and then exactly the declared action asked about no bucket and no account;
//! refusal before the handler when that action is denied, when only other actions are allowed,
//! and when the request is unsigned, forged, from an unknown key, or presigned.
//! NOT responsible for: the harness (`super`), routing without a service, or the generator.
//! Upstream: `super`, the recorded inventory. Downstream: nothing.

use std::collections::{BTreeMap, BTreeSet};

use rustfs_gateway_dialect_rustfs_admin::{BodyKind, PENDING, ROUTES, RouteRecord};

use super::{Exchange, actions, assemble, declared, paths, presigned, signed, unsigned, wire};
use crate::migration_inventory::rustfs_admin_routes::{AdminAuthMode, RequestBodyUse, ResponseBodyUse};
use crate::operation_diff::s3s_f3e17541::context::ACCESS_KEY;
use crate::rustfs_admin_route_inventory;

const DATA_USAGE: &str = "rustfs:GetV3Datausageinfo";

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

/// Every `(record, path)` pair: every row of every operation.
fn rows() -> impl Iterator<Item = (&'static RouteRecord, &'static str)> {
    ROUTES
        .iter()
        .flat_map(|record| paths(record).into_iter().map(move |path| (record, path)))
}

// ── the inventory ───────────────────────────────────────────────────────────────────────────

/// Positive — every route of a migrated group is declared as its inventory row records it:
/// group, alias, handler, body kinds, secret, and the recorded action or ADR-0025's ruling of its
/// custom class; and every declared operation is bound to exactly one inventory route.
#[test]
fn every_migrated_route_is_declared_as_the_inventory_records_it() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    let migrated: BTreeSet<&str> = ROUTES.iter().map(|record| record.group).collect();
    let mut bound = 0;
    for route in inventory
        .routes()
        .iter()
        .filter(|route| migrated.contains(route.group.as_str()))
    {
        let at = route.key();
        let records: Vec<&RouteRecord> = ROUTES
            .iter()
            .filter(|record| record.method == route.method.as_str() && record.path == route.path)
            .collect();
        assert!(!records.is_empty(), "{at} is not declared");
        let alias = route
            .minio_admin_alias
            .then(|| route.path.replacen("/rustfs/admin/", "/minio/admin/", 1));
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
                AdminAuthMode::Anonymous => panic!("{at}: an anonymous route was declared"),
            }
        }
        bound += records.len();
    }
    assert_eq!(bound, ROUTES.len(), "a declared operation has no inventory route");
}

/// Positive — the pending groups are exactly the inventory's other groups, each with its
/// inventory route count, so groups 1 and 2 plus the pending ones are the whole inventory.
#[test]
fn the_pending_groups_are_the_rest_of_the_inventory() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    let migrated: BTreeSet<&str> = ROUTES.iter().map(|record| record.group).collect();
    let mut rest: BTreeMap<&str, u16> = BTreeMap::new();
    for route in inventory.routes() {
        if !migrated.contains(route.group.as_str()) {
            *rest.entry(route.group.as_str()).or_default() += 1;
        }
    }
    let pending: BTreeMap<&str, u16> = PENDING.iter().map(|pending| (pending.group, pending.routes)).collect();
    assert_eq!(pending, rest);
    let declared_routes: BTreeSet<(&str, &str)> = ROUTES.iter().map(|record| (record.method, record.path)).collect();
    let pending_routes: usize = PENDING.iter().map(|pending| usize::from(pending.routes)).sum();
    assert_eq!(declared_routes.len() + pending_routes, inventory.routes().len());
}

// ── every row through the assembled service ─────────────────────────────────────────────────

/// Positive — every row of every operation, signed, is authorised by exactly its declared
/// actions (both, in order, for the any-of rule, whose answers the facade combines) about no
/// bucket, no key and no account, for the signing caller, and reaches exactly its own handler.
#[test]
fn every_row_is_authorised_by_exactly_its_declared_action() {
    let assembled = assemble(declared);
    for (record, path) in rows() {
        let at = format!("{} {path} ({})", record.method, record.operation);
        let exchange = assembled.exchange(wire(&signed(record, path)));
        assert_eq!(exchange.status, 200, "{at}: {}", exchange.body);
        assert_eq!(exchange.reached, [record.operation], "{at}");
        assert!(exchange.body.contains(record.operation), "{at}: {}", exchange.body);
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
            assert_eq!(
                (asked.bucket.as_deref(), asked.key.as_deref(), asked.about_an_account),
                (None, None, false),
                "{at}"
            );
        }
    }
}

/// Positive — the one any-of row is authorised by either of its two actions alone.
#[test]
fn the_any_of_row_is_authorised_by_either_action() {
    let record = ROUTES
        .iter()
        .find(|record| record.operation == DATA_USAGE)
        .expect("the data-usage record");
    assert_eq!(actions(record), ["admin:DataUsageInfo", "s3:ListBucket"]);
    for allowed in ["admin:DataUsageInfo", "s3:ListBucket"] {
        let assembled = assemble(move |_, action| action == allowed);
        for path in paths(record) {
            let exchange = assembled.exchange(wire(&signed(record, path)));
            assert_eq!(exchange.status, 200, "{allowed} {path}: {}", exchange.body);
            assert_eq!(exchange.reached, [DATA_USAGE]);
        }
    }
}

/// Negative — every row whose declared action is denied is refused before its handler, after
/// asking about that action.
#[test]
fn n_a_row_whose_action_is_denied_is_refused_before_its_handler() {
    let assembled = assemble(|_, _| false);
    for (record, path) in rows() {
        let at = format!("{} {path}", record.method);
        let exchange = assembled.exchange(wire(&signed(record, path)));
        refused_before_the_handler(&exchange, &at);
        assert!(exchange.body.contains("<Code>AccessDenied</Code>"), "{at}: {}", exchange.body);
        assert_eq!(
            exchange.asked.first().map(|asked| asked.action.as_str()),
            Some(actions(record)[0]),
            "{at}"
        );
    }
}

/// Negative — allowing every action but a row's own does not authorise it: the decision is the
/// declared action's, not any admin permission's.
#[test]
fn n_every_other_action_does_not_authorise_a_row() {
    let assembled = assemble(|operation, action| !declared(operation, action));
    for (record, path) in rows() {
        let exchange = assembled.exchange(wire(&signed(record, path)));
        refused_before_the_handler(&exchange, &format!("{} {path}", record.method));
    }
}

/// Negative — an unsigned request for any row is refused without asking the authorizer.
#[test]
fn n_an_unsigned_row_is_refused_without_asking() {
    let assembled = assemble(|_, _| true);
    for (record, path) in rows() {
        let exchange = assembled.exchange(unsigned(record, path));
        refused_without_asking(&exchange, &format!("{} {path}", record.method));
    }
}

/// Negative — a forged signature or an unknown access key is refused without asking the
/// authorizer.
///
/// One fresh service per row: the facade's own framework limiter throttles a client that keeps
/// failing authentication (`SlowDown`, before and independent of the deployment's governor), which
/// is its job and would otherwise answer the later rows of this burst instead of the verifier.
#[test]
fn n_a_forged_or_unknown_key_row_is_refused_without_asking() {
    for (record, path) in rows() {
        let assembled = assemble(|_, _| true);
        for request in [signed(record, path).forged(), signed(record, path).unknown_key()] {
            let exchange = assembled.exchange(wire(&request));
            let at = format!("{} {path}", record.method);
            refused_without_asking(&exchange, &at);
            assert!(!exchange.body.contains("<Code>SlowDown</Code>"), "{at}: {}", exchange.body);
        }
    }
}

/// Negative — a presigned request for any row no query selects is refused at the floor, as
/// `AccessDenied`, without asking the authorizer.
#[test]
fn n_a_presigned_row_is_refused_without_asking() {
    let assembled = assemble(|_, _| true);
    let mut refused = 0;
    for (record, path) in rows().filter(|(record, _)| record.query.is_none()) {
        let at = format!("{} {path}", record.method);
        let exchange = assembled.exchange(presigned(record, path));
        refused_without_asking(&exchange, &at);
        assert!(exchange.body.contains("<Code>AccessDenied</Code>"), "{at}: {}", exchange.body);
        refused += 1;
    }
    assert_eq!(refused, 88, "every row but the service command's eight");
}
