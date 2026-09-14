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

//! The crate's one test target: every declared row reaches its operation with the dialect and no
//! admin operation without it, every near miss reaches none, and every operation declares what
//! its record says.
//!
//! Responsible for: routing every row of every operation through core's router, and every
//! operation's declared facts against its record and against each other.
//! NOT responsible for: authentication and authorisation through an assembled service, or the
//! binding to the recorded inventory (`rustfs-gateway-goldens`'s `rustfs_admin_dialect`).
//! Upstream: this crate's public surface and `rustfs-gateway-core`'s router. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::{BTreeMap, BTreeSet};

use http::Request;
use rustfs_gateway_core::dialect::{ClaimedRow, Dialect};
use rustfs_gateway_core::op::ResourceShape;
use rustfs_gateway_core::registry::{HandlerDeadlineClass, RouterBuilder};
use rustfs_gateway_core::route::{HostClass, Predicate, RouteRequestParts, TargetKind};
use rustfs_gateway_dialect_rustfs_admin::{
    AdminOperation, CLAIMS, OVERLAY, OperationFold, PENDING, ROUTES, RouteRecord, fold_every_operation, rustfs_admin_dialect,
};
use rustfs_gateway_http::{Limits, WireRequest};

const HOST: &str = "s3.example.com";
const METHODS: &[&str] = &["GET", "HEAD", "PUT", "POST", "DELETE", "PATCH"];

/// What a path-style host resolver says a path addresses.
fn path_style_target(path: &str) -> TargetKind {
    match path.trim_start_matches('/') {
        "" => TargetKind::Service,
        rest if rest.contains('/') => TargetKind::Object,
        _ => TargetKind::Bucket,
    }
}

/// A router with `dialect` installed or none, as a function from `method target` to the
/// operation it reaches.
fn resolver(dialect: Option<&Dialect>) -> impl Fn(&str, &str) -> Option<&'static str> + '_ {
    let mut builder = RouterBuilder::new();
    if let Some(dialect) = dialect {
        builder = builder.dialect(dialect);
    }
    let router = builder.build().expect("the table builds");
    move |method, target| {
        let request = Request::builder()
            .method(method)
            .uri(format!("http://{HOST}{target}"))
            .header("host", HOST)
            .body(())
            .expect("a fixture request");
        let wire = WireRequest::accept(request, &Limits::default()).expect("an acceptable fixture request");
        let path = wire.raw_path().as_str();
        let parts = RouteRequestParts {
            method: wire.method(),
            path,
            target: path_style_target(path),
            host_class: HostClass::Standard,
            arn_form: None,
            query: wire.query(),
            headers: wire.headers(),
            host_named_bucket: false,
        };
        router.resolve(&parts).map(|entry| entry.op_name)
    }
}

fn dialect() -> Dialect {
    rustfs_admin_dialect().expect("the generated record and declarations agree")
}

/// The query a record's operation is selected by, as a request suffix.
fn query(record: &RouteRecord) -> String {
    record
        .query
        .map_or_else(String::new, |(key, value)| format!("?{key}={value}"))
}

/// Every path a record's operation is served at: the canonical one, then the alias.
fn paths(record: &RouteRecord) -> Vec<&'static str> {
    std::iter::once(record.path).chain(record.alias).collect()
}

/// What each operation declares, read through its own trait implementations.
struct Declared {
    name: &'static str,
    rows: &'static [ClaimedRow],
    precedence: u16,
    group: &'static str,
    action: Option<String>,
    resource: Option<ResourceShape>,
    privileged: bool,
    anonymous: bool,
    presigned: bool,
    secret: bool,
    deadline: Option<HandlerDeadlineClass>,
}

struct Collect;

impl OperationFold for Collect {
    type Carry = Vec<Declared>;

    fn step<O: AdminOperation>(&mut self, mut carry: Vec<Declared>) -> Vec<Declared> {
        let spec = O::spec();
        let floor = O::floor();
        carry.push(Declared {
            name: O::NAME,
            rows: O::rows(),
            precedence: O::PRECEDENCE,
            group: O::GROUP,
            action: spec.auth.map(|auth| auth.render()),
            resource: spec.auth.map(|auth| auth.resource),
            privileged: floor.privileged(),
            anonymous: floor.allows_anonymous(),
            presigned: floor.allowed_schemes().allows_presigned(),
            secret: spec.receives_caller_secret(),
            deadline: spec.deadline_class(),
        });
        carry
    }
}

fn declared() -> Vec<Declared> {
    fold_every_operation(&mut Collect, Vec::new())
}

// ── routing ──────────────────────────────────────────────────────────────────────────────────

/// Positive — every row of every operation, canonical and alias alike, reaches that operation.
#[test]
fn every_declared_row_reaches_its_operation() {
    let dialect = dialect();
    let resolve = resolver(Some(&dialect));
    let mut rows = 0;
    for record in ROUTES {
        for path in paths(record) {
            let target = format!("{path}{}", query(record));
            assert_eq!(resolve(record.method, &target), Some(record.operation), "{} {target}", record.method);
            rows += 1;
        }
    }
    assert_eq!(rows, 96, "48 operations, each with its MinIO alias");
}

/// Negative — without the dialect, no row reaches any admin operation.
#[test]
fn n_without_the_dialect_no_row_reaches_an_admin_operation() {
    let resolve = resolver(None);
    for record in ROUTES {
        for path in paths(record) {
            let target = format!("{path}{}", query(record));
            let reached = resolve(record.method, &target);
            assert!(
                reached.is_none_or(|name| !name.starts_with("rustfs:")),
                "{} {target}: {reached:?}",
                record.method
            );
        }
    }
}

/// Negative — inside the claims, a method no operation declares for a path reaches no operation.
#[test]
fn n_a_method_no_row_declares_reaches_no_operation() {
    let dialect = dialect();
    let resolve = resolver(Some(&dialect));
    let declared: BTreeSet<(&str, &str)> = ROUTES.iter().map(|record| (record.method, record.path)).collect();
    let mut refused = 0;
    for record in ROUTES {
        for method in METHODS.iter().filter(|method| !declared.contains(&(**method, record.path))) {
            for path in paths(record) {
                let target = format!("{path}{}", query(record));
                assert_eq!(resolve(method, &target), None, "{method} {target}");
                refused += 1;
            }
        }
    }
    assert!(refused > 400, "{refused}");
}

/// Negative — the service command reaches an operation only through one of its four ruled
/// actions, spelled exactly.
#[test]
fn n_the_service_command_without_a_ruled_action_reaches_no_operation() {
    let dialect = dialect();
    let resolve = resolver(Some(&dialect));
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        for query in [
            "",
            "?action=",
            "?action=Restart",
            "?action=reboot",
            "?actions=restart",
            "?action=restart%20",
        ] {
            let target = format!("{prefix}/v3/service{query}");
            assert_eq!(resolve("POST", &target), None, "{target}");
        }
        for (action, name) in [
            ("restart", "rustfs:PostV3ServiceRestart"),
            ("stop", "rustfs:PostV3ServiceStop"),
            ("freeze", "rustfs:PostV3ServiceFreeze"),
            ("unfreeze", "rustfs:PostV3ServiceUnfreeze"),
        ] {
            assert_eq!(resolve("POST", &format!("{prefix}/v3/service?action={action}")), Some(name));
        }
    }
}

/// Negative — a near miss of every row reaches no admin operation: a trailing slash, one more
/// segment, the last segment's case changed, and the same path one character outside the claim.
#[test]
fn n_a_near_miss_of_a_row_reaches_no_admin_operation() {
    let dialect = dialect();
    let resolve = resolver(Some(&dialect));
    for record in ROUTES {
        let query = query(record);
        for path in paths(record) {
            let (head, last) = path.rsplit_once('/').expect("a path with segments");
            for near in [
                format!("{path}/{query}"),
                format!("{path}/x{query}"),
                format!("{head}/{}{query}", last.to_ascii_uppercase()),
            ] {
                assert_eq!(resolve(record.method, &near), None, "{} {near}", record.method);
            }
            let outside = format!(
                "{}x{}{query}",
                &path[..path.find("/admin").expect("an admin path") + 6],
                &path[path.find("/admin").expect("an admin path") + 6..]
            );
            let reached = resolve(record.method, &outside);
            assert!(
                reached.is_none_or(|name| !name.starts_with("rustfs:")),
                "{} {outside}: {reached:?}",
                record.method
            );
        }
    }
}

// ── the declarations ─────────────────────────────────────────────────────────────────────────

/// Positive — every operation declares what its record says: name, group, action, rows,
/// selector, secret, and a service-level resource under the `Standard` deadline.
#[test]
fn every_operation_declares_what_its_record_says() {
    let declared = declared();
    assert_eq!(declared.len(), ROUTES.len());
    for (operation, record) in declared.iter().zip(ROUTES) {
        let name = record.operation;
        assert_eq!(operation.name, name);
        assert_eq!(operation.group, record.group, "{name}");
        assert_eq!(operation.action.as_deref(), Some(record.action), "{name}");
        assert_eq!(operation.resource, Some(ResourceShape::Service), "{name}");
        assert_eq!(operation.secret, record.caller_secret, "{name}");
        assert_eq!(operation.deadline, Some(HandlerDeadlineClass::Standard), "{name}");
        let templates: Vec<&str> = operation.rows.iter().map(|row| row.template).collect();
        assert_eq!(templates, paths(record), "{name}");
        for row in operation.rows {
            match (row.selector, record.query) {
                ([Predicate::Method(method)], None) => assert_eq!(method.as_str(), record.method, "{name}"),
                ([Predicate::Method(method), Predicate::QueryEquals(key, value)], Some((k, v))) => {
                    assert_eq!((method.as_str(), *key, *value), (record.method, k, v), "{name}");
                }
                (selector, query) => panic!("{name}: selector {selector:?} for query {query:?}"),
            }
        }
    }
}

/// Negative — no operation is reachable without a header signature, none is handed the caller's
/// secret, and none is authorised by a vendor label: every migrated route is an IAM check.
#[test]
fn n_no_operation_is_reachable_without_a_header_signature() {
    for operation in declared() {
        let name = operation.name;
        assert!(operation.privileged, "{name}");
        assert!(!operation.anonymous, "{name}");
        assert!(!operation.presigned, "{name}");
        assert!(!operation.secret, "{name}");
        assert!(operation.action.is_some_and(|action| !action.contains("rustfs:")), "{name}");
    }
}

/// Positive and negative — names are unique, precedences strictly increase, and the overlay
/// records every operation exactly once, in the same order.
#[test]
fn names_and_precedences_are_unique_and_the_overlay_is_complete() {
    let declared = declared();
    let names: BTreeSet<&str> = declared.iter().map(|operation| operation.name).collect();
    assert_eq!(names.len(), declared.len());
    assert!(declared.windows(2).all(|pair| pair[0].precedence < pair[1].precedence));
    let recorded: Vec<(&str, u16)> = OVERLAY.operations.iter().map(|row| (row.name, row.precedence)).collect();
    let declared: Vec<(&str, u16)> = declared
        .iter()
        .map(|operation| (operation.name, operation.precedence))
        .collect();
    assert_eq!(recorded, declared);
    assert!(
        OVERLAY
            .operations
            .iter()
            .all(|row| !row.anonymous && !row.evidence.is_empty())
    );
}

/// Positive — the dialect assembles, claiming exactly the two admin prefixes.
#[test]
fn the_dialect_assembles_with_its_two_claims() {
    let _ = dialect();
    let prefixes: Vec<&str> = CLAIMS.iter().map(|claim| claim.prefix).collect();
    assert_eq!(prefixes, ["/rustfs/admin", "/minio/admin"]);
}

/// Positive — ADR-0024's groups 1 and 2 are declared, each inventory route once (the service
/// command as its four forms), and every other group is pending with the rest of the routes.
#[test]
fn groups_one_and_two_are_declared_and_the_rest_are_pending() {
    let mut by_group: BTreeMap<&str, BTreeSet<(&str, &str)>> = BTreeMap::new();
    for record in ROUTES {
        by_group.entry(record.group).or_default().insert((record.method, record.path));
        assert_eq!(record.order, if record.group == "system" { 1 } else { 2 }, "{}", record.operation);
    }
    let counts: Vec<(&str, usize)> = by_group.iter().map(|(group, routes)| (*group, routes.len())).collect();
    assert_eq!(
        counts,
        [
            ("bucket_meta", 4),
            ("cluster_snapshot", 1),
            ("diagnostics", 12),
            ("extensions", 2),
            ("gateway_key_inventory", 1),
            ("inspect_archive", 1),
            ("module_switch", 2),
            ("object_data_cache", 2),
            ("plugins_catalog", 1),
            ("profile_admin", 6),
            ("rebalance", 3),
            ("system", 9),
            ("tls_debug", 1),
        ]
    );
    assert_eq!(ROUTES.len(), 48);
    assert!(
        PENDING
            .iter()
            .all(|pending| pending.order > 2 && !by_group.contains_key(pending.group))
    );
    assert_eq!(PENDING.len(), 25);
    assert_eq!(PENDING.iter().map(|pending| usize::from(pending.routes)).sum::<usize>(), 356 - 45);
}
