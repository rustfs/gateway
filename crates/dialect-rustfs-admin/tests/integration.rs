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
//! admin operation without it, every other request reaches exactly what an independent model of
//! the rows says, and every operation declares what its record says.
//!
//! Responsible for: routing every row of every operation through core's router — with concrete
//! values for template parameters, and against a matcher written here from ADR-0024's rule — and
//! every operation's declared facts against its record and against each other.
//! NOT responsible for: authentication, authorisation, parameter decoding and the caller's secret
//! through an assembled service, or the binding to the recorded inventory
//! (`rustfs-gateway-goldens`'s `rustfs_admin_dialect`).
//! Upstream: this crate's public surface and `rustfs-gateway-core`'s router. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use http::Request;
use rustfs_gateway_core::codec::ResponseBody;
use rustfs_gateway_core::dialect::{BucketParam, ClaimedRow, Dialect};
use rustfs_gateway_core::op::ResourceShape;
use rustfs_gateway_core::registry::{HandlerDeadlineClass, RouterBuilder};
use rustfs_gateway_core::route::{HostClass, Predicate, RouteRequestParts, ShadowingDecl, TargetKind};
use rustfs_gateway_core::{Everyone, SubjectRule, WhenAbsent};
use rustfs_gateway_dialect_rustfs_admin::admin::{self, AdminResponse};
use rustfs_gateway_dialect_rustfs_admin::{
    AdminOperation, BodyKind, CLAIMS, OVERLAY, OperationFold, ROUTES, RouteRecord, fold_every_operation, rustfs_admin_dialect,
};
use rustfs_gateway_http::{Limits, WireRequest};

#[path = "integration/census.rs"]
mod census;

#[path = "integration/sts_form.rs"]
mod sts_form;

const HOST: &str = "s3.example.com";
const METHODS: &[&str] = &[
    "GET", "HEAD", "PUT", "POST", "DELETE", "PATCH", "OPTIONS", "TRACE", "FROB", "CONNECT", "get",
];

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

/// Every template a record's operation is served at: the canonical one, then the alias.
fn templates(record: &RouteRecord) -> Vec<&'static str> {
    std::iter::once(record.path).chain(record.alias).collect()
}

/// The parameter a template segment names, if it is one.
fn param(segment: &str) -> Option<&str> {
    segment.strip_prefix('{').and_then(|inner| inner.strip_suffix('}'))
}

/// `template` with every parameter given a concrete value, its name then `-1`.
fn concrete(template: &str) -> String {
    template
        .split('/')
        .map(|segment| param(segment).map_or_else(|| segment.to_owned(), |name| format!("{}-1", name.trim_start_matches('*'))))
        .collect::<Vec<_>>()
        .join("/")
}

/// Every concrete path a record's operation is served at.
fn paths(record: &RouteRecord) -> Vec<String> {
    templates(record).into_iter().map(concrete).collect()
}

/// ADR-0024's rule for a plain value, written here without core: the same number of segments,
/// each literal equal, each parameter any non-empty segment.
fn template_matches(template: &str, path: &str) -> bool {
    let (template, path): (Vec<&str>, Vec<&str>) = (template.split('/').collect(), path.split('/').collect());
    let catch_all = template.last().is_some_and(|segment| segment.starts_with("{*"));
    (template.len() == path.len() || (catch_all && path.len() > template.len()))
        && template
            .iter()
            .zip(&path)
            .enumerate()
            .all(|(index, (segment, value))| match param(segment) {
                Some(name) if name.starts_with('*') => !path[index..].join("/").is_empty(),
                Some(_) => !value.is_empty(),
                None => segment == value,
            })
}

/// The operation a request must reach: the first record, in precedence order, of its method
/// whose template matches its path and whose query, when it has one, is exactly the request's.
fn expected(method: &str, path: &str, query: &str) -> Option<&'static str> {
    ROUTES
        .iter()
        .find(|record| {
            record.method == method
                && templates(record).iter().any(|template| template_matches(template, path))
                && record.query.is_none_or(|(key, value)| query == format!("?{key}={value}"))
        })
        .map(|record| record.operation)
        .or_else(|| fallback(path))
}

/// ADR-0039's literal prefix boundary, independent of the generated fallback templates.
fn fallback(path: &str) -> Option<&'static str> {
    ["/rustfs/admin", "/minio/admin"].into_iter().find_map(|prefix| {
        let rest = path.strip_prefix(prefix)?;
        if rest == "/v4" || rest.starts_with("/v4/") {
            Some("rustfs:AdminV4Fallback")
        } else if rest.is_empty() || rest.starts_with('/') {
            Some("rustfs:AdminFallback")
        } else {
            None
        }
    })
}

/// What each operation declares, read through its own trait implementations.
struct Declared {
    name: &'static str,
    rows: &'static [ClaimedRow],
    shadows: &'static [ShadowingDecl],
    precedence: u16,
    group: &'static str,
    action: Option<String>,
    subject: Option<SubjectRule>,
    resource: Option<ResourceShape>,
    bucket: Option<BucketParam>,
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
            shadows: O::shadows(),
            precedence: O::PRECEDENCE,
            group: O::GROUP,
            action: spec.auth.map(|auth| auth.render()),
            subject: spec.auth.and_then(|auth| auth.subject()),
            resource: spec.auth.map(|auth| auth.resource),
            bucket: O::BUCKET,
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

/// Positive — every row of every operation, canonical and alias alike, reaches that operation,
/// with a concrete value in every template parameter.
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
    assert_eq!(
        rows, 622,
        "312 operations, each with its MinIO or compat alias but the two profiling triggers"
    );
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

/// Negative — every method on every row's path reaches exactly what the model says: a method no
/// row of that shape declares reaches its authenticated fallback (or no operation outside the
/// admin claims), and a literal row is never answered by a template of another method.
#[test]
fn n_every_method_on_every_row_reaches_only_what_the_rows_say() {
    let dialect = dialect();
    let resolve = resolver(Some(&dialect));
    let mut refused = 0;
    for record in ROUTES {
        for path in paths(record) {
            let query = query(record);
            for method in METHODS {
                let want = expected(method, &path, &query);
                assert_eq!(resolve(method, &format!("{path}{query}")), want, "{method} {path}{query}");
                refused += usize::from(want.is_none() || want == fallback(&path));
            }
        }
    }
    assert!(refused > 1000, "{refused}");
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
            assert_eq!(resolve("POST", &target), Some("rustfs:AdminFallback"), "{target}");
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

/// Negative — a near miss of every row never reaches that row's operation, and reaches exactly
/// what the model says (a sibling template or authenticated fallback): a trailing slash, one more segment, the
/// last literal segment's case changed; and the same path one character outside the claim
/// reaches no admin operation.
#[test]
fn n_a_near_miss_of_a_row_reaches_no_admin_operation() {
    let dialect = dialect();
    let resolve = resolver(Some(&dialect));
    for record in ROUTES {
        let query = query(record);
        for template in templates(record) {
            let path = concrete(template);
            let mut segments: Vec<String> = path.split('/').map(str::to_owned).collect();
            let last_literal = template
                .split('/')
                .collect::<Vec<_>>()
                .iter()
                .rposition(|segment| param(segment).is_none() && !segment.is_empty())
                .expect("a literal segment");
            segments[last_literal] = segments[last_literal].to_ascii_uppercase();
            for near in [format!("{path}/"), format!("{path}/x"), segments.join("/")] {
                let reached = resolve(record.method, &format!("{near}{query}"));
                if expected(record.method, &near, &query) != Some(record.operation) {
                    assert_ne!(reached, Some(record.operation), "{} {near}", record.method);
                } else {
                    assert_eq!(reached, Some(record.operation), "{} {near}", record.method);
                }
                // A near miss of a claim's own segment (`/profile/CPU`) is outside the claim and
                // is S3's; the model speaks only for the dialect's operations.
                let admin = reached.filter(|name| name.starts_with("rustfs:"));
                assert_eq!(admin, expected(record.method, &near, &query), "{} {near}", record.method);
            }
            // Past the claim's second segment: `/rustfs/admin`, `/minio/admin`, `/_iceberg/v1` or `/iceberg/v1`.
            let at = ["/admin", "/v1", "/cpu", "/memory"]
                .iter()
                .find_map(|marker| path.find(marker).map(|index| index + marker.len()))
                .expect("a claimed path");
            let outside = format!("{}x{}{query}", &path[..at], &path[at..]);
            let reached = resolve(record.method, &outside);
            assert!(
                reached.is_none_or(|name| !name.starts_with("rustfs:")),
                "{} {outside}: {reached:?}",
                record.method
            );
        }
    }
}

/// Negative — an empty parameter cannot select its row. Native admin parameters retain raw
/// dots and encoded separators (ADR-0040); table-catalog parameters retain their strict boundary.
#[test]
fn n_parameter_boundaries_preserve_raw_admin_data_and_strict_catalog_values() {
    let dialect = dialect();
    let resolve = resolver(Some(&dialect));
    let mut refused = 0;
    let mut elsewhere = Vec::new();
    for record in ROUTES {
        for template in templates(record) {
            let segments: Vec<&str> = template.split('/').collect();
            for (index, _) in segments.iter().enumerate().filter(|(_, segment)| param(segment).is_some()) {
                for bad in [
                    "%2e", "%2E", "%2e%2e", "%2E%2e", ".%2e", "a%2Fb", "a%2fb", "a%5Cb", "a%5cb", "",
                ] {
                    let mut path: Vec<String> = segments.iter().map(|segment| concrete(segment)).collect();
                    path[index] = bad.to_owned();
                    let path = path.join("/");
                    let target = format!("{path}{}", query(record));
                    let reached = resolve(record.method, &target);
                    if bad.is_empty() {
                        // Nothing in the parameter may spell another row's path; the model says which.
                        assert_ne!(reached, Some(record.operation), "{} {target}", record.method);
                        assert_eq!(reached, expected(record.method, &path, &query(record)), "{} {target}", record.method);
                        if let Some(other) = reached.filter(|other| Some(*other) != fallback(&path)) {
                            elsewhere.push((record.operation, path, other));
                        }
                    } else if record.path.starts_with("/rustfs/admin/") || segments[index].starts_with("{*") {
                        assert_eq!(reached, Some(record.operation), "{} {target}", record.method);
                    } else {
                        assert_eq!(reached, None, "{} {target}", record.method);
                    }
                    refused += 1;
                }
            }
        }
    }
    assert_eq!(
        refused,
        10 * 2 * 190,
        "190 parameters across 102 templates, each with its alias; catch-all values included"
    );
    assert_eq!(
        elsewhere,
        [
            ("rustfs:PostV3HealByBucket", "/rustfs/admin/v3/heal/".to_owned(), "rustfs:PostV3Heal"),
            ("rustfs:PostV3HealByBucket", "/minio/admin/v3/heal/".to_owned(), "rustfs:PostV3Heal"),
        ]
    );
}

/// Positive and negative — RustFS registers `POST heal/` with its trailing `/`, and so does the
/// row: exactly that path reaches it, canonical and alias alike; the path without the `/`, with a
/// second `/`, or with a bucket reaches something else or nothing (ADR-0030).
#[test]
fn the_trailing_slash_heal_row_matches_exactly_its_path() {
    let dialect = dialect();
    let resolve = resolver(Some(&dialect));
    let refused = [("POST", ""), ("POST", "//"), ("GET", "/"), ("POST", "/photos/")];
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        let heal = |method: &str, rest: &str| resolve(method, &format!("{prefix}/v3/heal{rest}"));
        assert_eq!(heal("POST", "/"), Some("rustfs:PostV3Heal"), "{prefix}");
        assert_eq!(heal("POST", "/photos"), Some("rustfs:PostV3HealByBucket"), "{prefix}");
        assert_eq!(heal("POST", "/photos/logs"), Some("rustfs:PostV3HealByBucketByPrefix"), "{prefix}");
        assert_eq!(
            heal("POST", "/%2f"),
            Some("rustfs:PostV3HealByBucket"),
            "{prefix}: validation follows routing"
        );
        for (method, rest) in refused {
            assert_eq!(heal(method, rest), Some("rustfs:AdminFallback"), "{prefix} {method} {rest}");
        }
    }
    let heal = ROUTES.iter().find(|record| record.operation == "rustfs:PostV3Heal");
    assert_eq!(
        heal.map(|record| (record.alias, record.bucket)),
        Some((Some("/minio/admin/v3/heal/"), None))
    );
}

/// Positive and negative — `POST tier/clear` stands in front of `POST tier/{tiername}` and is
/// one of the two declared shadowings (the other is the table catalog's `buckets/{warehouse}`, ADR-0031): `clear` is the clear command, every other name is a tier, and
/// the other methods on `tier/clear` reach their tier templates.
#[test]
fn the_literal_tier_clear_stands_in_front_of_the_tier_template() {
    let declared = declared();
    let mut shadows = Vec::new();
    for operation in &declared {
        let mut fallback_shadows = Vec::new();
        for decl in operation.shadows {
            assert_eq!(decl.winner, operation.name);
            assert!(!decl.evidence.is_empty());
            if ["rustfs:AdminFallback", "rustfs:AdminV4Fallback"].contains(&decl.shadowed) {
                fallback_shadows.push(decl.shadowed);
            } else {
                shadows.push((operation.name, decl.winner, decl.shadowed, !decl.evidence.is_empty()));
            }
        }
        let path = ROUTES
            .iter()
            .find(|record| record.operation == operation.name)
            .expect("native record")
            .path;
        let wanted = if path.starts_with("/rustfs/admin/v4/") {
            vec!["rustfs:AdminV4Fallback", "rustfs:AdminFallback"]
        } else if path.starts_with("/rustfs/admin/") {
            vec!["rustfs:AdminFallback"]
        } else {
            vec![]
        };
        assert_eq!(fallback_shadows, wanted, "{}", operation.name);
    }
    assert_eq!(
        shadows,
        [
            (
                "rustfs:GetIcebergBucketsByWarehouse",
                "rustfs:GetIcebergBucketsByWarehouse",
                "rustfs:GetIcebergByWarehouseNamespaces",
                true
            ),
            ("rustfs:PostV3TierClear", "rustfs:PostV3TierClear", "rustfs:PostV3TierByTiername", true),
        ]
    );
    let dialect = dialect();
    let resolve = resolver(Some(&dialect));
    for prefix in ["/rustfs/admin", "/minio/admin"] {
        assert_eq!(resolve("POST", &format!("{prefix}/v3/tier/clear")), Some("rustfs:PostV3TierClear"));
        for tier in ["clears", "CLEAR", "clea", "hot", "clear%20"] {
            let target = format!("{prefix}/v3/tier/{tier}");
            assert_eq!(resolve("POST", &target), Some("rustfs:PostV3TierByTiername"), "{target}");
        }
        assert_eq!(resolve("GET", &format!("{prefix}/v3/tier/clear")), Some("rustfs:GetV3TierByTier"));
        assert_eq!(
            resolve("DELETE", &format!("{prefix}/v3/tier/clear")),
            Some("rustfs:DeleteV3TierByTiername")
        );
    }
}

// ── the declarations ─────────────────────────────────────────────────────────────────────────

/// Negative — no operation but the four OIDC bootstrap ones is reachable without a header
/// signature, none through a presigned URL, and only an own-account or a bootstrap operation is
/// authorised by a vendor label: every other migrated route is an IAM check.
#[test]
fn n_no_operation_is_reachable_without_a_header_signature() {
    let mut anonymous = Vec::new();
    for (operation, record) in declared().into_iter().zip(ROUTES) {
        let name = operation.name;
        assert!(operation.privileged, "{name}");
        assert_eq!(operation.anonymous, record.anonymous, "{name}");
        assert!(!operation.presigned, "{name}");
        if operation.anonymous {
            anonymous.push(name);
            assert_eq!(operation.subject, None, "{name}");
        }
        let own_label = operation.subject == Some(SubjectRule::Caller) || operation.anonymous;
        let action = operation.action.unwrap_or_default();
        assert_eq!(action.starts_with("rustfs:"), own_label, "{name}: {action}");
        assert_eq!(action.matches("rustfs:").count(), usize::from(own_label), "{name}: {action}");
    }
    // Exactly RustFS's four OIDC bootstrap routes admit an anonymous request (ADR-0026 (f), ADR-0032).
    assert_eq!(
        anonymous,
        [
            "rustfs:GetV3OidcAuthorizeByProviderId",
            "rustfs:GetV3OidcCallbackByProviderId",
            "rustfs:GetV3OidcLogout",
            "rustfs:GetV3OidcProviders",
        ]
    );
}

/// Positive — exactly ADR-0025's and ADR-0026's order-4 subjects are declared: nine own-account
/// operations, nine about one query-named account (four refusing an absent one), and the three
/// bulk listings about each `users` account, `admin:ListUsers` for `all`.
#[test]
fn the_subject_rules_are_the_order_four_rulings() {
    let declared = declared();
    let with = |wanted: &dyn Fn(SubjectRule) -> bool| {
        declared
            .iter()
            .filter(|operation| operation.subject.is_some_and(wanted))
            .map(|operation| operation.name)
            .collect::<Vec<_>>()
    };
    assert_eq!(with(&|rule| rule == SubjectRule::Caller).len(), 9);
    let refused = with(&|rule| {
        matches!(
            rule,
            SubjectRule::Query {
                when_absent: WhenAbsent::Refuse,
                ..
            }
        )
    });
    assert_eq!(
        refused,
        [
            "rustfs:DeleteV3DeleteServiceAccount",
            "rustfs:DeleteV3DeleteServiceAccounts",
            "rustfs:GetV3InfoServiceAccount",
            "rustfs:GetV3UserInfo",
            "rustfs:PostV3UpdateServiceAccount",
            "rustfs:PutV3AddUser",
        ]
    );
    let caller = with(&|rule| {
        matches!(
            rule,
            SubjectRule::Query {
                when_absent: WhenAbsent::Caller,
                ..
            }
        )
    });
    assert_eq!(
        caller,
        [
            "rustfs:GetV3IdpLdapListAccessKeys",
            "rustfs:GetV3InfoAccessKey",
            "rustfs:GetV3ListServiceAccounts"
        ]
    );
    let bulk = SubjectRule::Set {
        param: "users",
        everyone: Some(Everyone {
            param: "all",
            action: "admin:ListUsers",
        }),
    };
    assert_eq!(
        with(&|rule| rule == bulk),
        [
            "rustfs:GetV3IdpLdapListAccessKeysBulk",
            "rustfs:GetV3IdpOpenidListAccessKeysBulk",
            "rustfs:GetV3ListAccessKeysBulk"
        ]
    );
    assert_eq!(declared.iter().filter(|operation| operation.subject.is_some()).count(), 21);
}

/// Negative — a subject parameter selects nothing: every row of a subject-ruled operation reaches
/// that operation whatever account, set, flag or malformed value its query carries, because the
/// facade, not the router, reads and refuses it.
#[test]
fn n_a_subject_parameter_does_not_change_the_route() {
    let dialect = dialect();
    let resolve = resolver(Some(&dialect));
    let mut checked = 0;
    for record in ROUTES.iter().filter(|record| record.subject.is_some()) {
        for path in paths(record) {
            for query in [
                "?accessKey=other",
                "?user=a&userDN=b",
                "?users=a&users=b",
                "?all=true&users=a",
                "?accessKey=%ff",
            ] {
                assert_eq!(resolve(record.method, &format!("{path}{query}")), Some(record.operation), "{path}{query}");
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 21 * 2 * 5);
}

/// Positive and negative — exactly the thirty-one operations whose body RustFS seals opt in to
/// the caller's secret, eight of order 3, twenty-one of order 4 and two of order 5 (xtask pins each
/// name against the inventory); every other operation is never handed it.
#[test]
fn only_the_sealed_operations_hold_the_caller_secret() {
    let holders: Vec<(&str, u8)> = declared()
        .iter()
        .zip(ROUTES)
        .filter(|(operation, _)| operation.secret)
        .map(|(operation, record)| (operation.name, record.order))
        .collect();
    assert_eq!(holders.len(), 33);
    assert_eq!(holders.iter().filter(|(_, order)| *order == 3).count(), 8);
    assert_eq!(holders.iter().filter(|(_, order)| *order == 4).count(), 21);
    assert_eq!(holders.iter().filter(|(_, order)| *order == 5).count(), 4);
    for name in [
        "rustfs:GetV3Config",
        "rustfs:PutV3SiteReplicationEdit",
        "rustfs:PostV3AccountPassword",
        "rustfs:GetV3ListAccessKeysBulk",
        "rustfs:PutV3AddUser",
        "rustfs:PutV3OnDemandMigrationByBucket",
        "rustfs:PostV3OnDemandMigrationByBucketBackfill",
    ] {
        assert!(holders.iter().any(|(holder, _)| *holder == name), "{name}");
    }
    for name in [
        "rustfs:GetV3AccountInfo",
        "rustfs:GetV3UserInfo",
        "rustfs:GetV3IdpLdapListAccessKeysBulk",
    ] {
        assert!(!holders.iter().any(|(holder, _)| *holder == name), "{name}");
    }
}

/// Positive — the dialect assembles, claiming exactly the two admin prefixes, the two
/// table-catalog prefixes and the two profiling triggers (ADR-0024, ADR-0031, ADR-0032).
#[test]
fn the_dialect_assembles_with_its_six_claims() {
    let _ = dialect();
    let prefixes: Vec<&str> = CLAIMS.iter().map(|claim| claim.prefix).collect();
    assert_eq!(
        prefixes,
        [
            "/rustfs/admin",
            "/minio/admin",
            "/_iceberg/v1",
            "/iceberg/v1",
            "/profile/cpu",
            "/profile/memory"
        ]
    );
}

// ── the answer ───────────────────────────────────────────────────────────────────────────────

/// Negative — a handler's answer cannot set a framing header or override its content type, a
/// value HTTP cannot carry is dropped rather than sent, and an empty answer carries no body.
#[test]
fn n_an_answer_cannot_set_framing_headers() {
    let answer = AdminResponse::json("{}")
        .with_header("content-length", "999")
        .with_header("Transfer-Encoding", "chunked")
        .with_header("connection", "close")
        .with_header("content-type", "text/html")
        .with_header("x-bad", "a\r\nb")
        .with_header("content-disposition", "attachment; filename=\"a.zip\"");
    let encoded = admin::encode(answer, 200).expect("an answer encodes");
    let names: BTreeSet<&str> = encoded.headers.keys().map(http::HeaderName::as_str).collect();
    assert_eq!(names, BTreeSet::from(["content-disposition", "content-type"]));
    assert_eq!(
        encoded.headers.get("content-type").map(http::HeaderValue::as_bytes),
        Some(&b"application/json"[..])
    );
    assert!(matches!(&encoded.body, ResponseBody::Complete(bytes) if bytes.as_slice() == b"{}"));
    let empty = admin::encode(AdminResponse::empty(), 200).expect("an empty answer encodes");
    assert!(empty.headers.is_empty());
    assert!(matches!(empty.body, ResponseBody::Empty));
}

/// Positive — the admin routes legacy RustFS reads as bodyless however the client frames them are
/// declared to read no body, so the gateway requires no length of them and leaves a chunked
/// transfer unread, as legacy RustFS does. Its `EmptyBodyContentLengthCompatLayer`
/// (`rustfs/src/server/layer.rs:688-808`, rustfs/rustfs `e870a6d25b`) forces `Content-Length: 0`
/// and drops `Transfer-Encoding` on these eight routes, their MinIO aliases, and every admin `GET`;
/// of the `GET`s only `kms/backup` is declared to read a body, which a chunked `GET` hands it
/// where legacy RustFS would hand it none (rustfs/gateway#1120).
#[test]
fn the_routes_legacy_rustfs_reads_as_bodyless_read_no_body() {
    const BODYLESS: [(&str, &str); 8] = [
        ("PUT", "/rustfs/admin/v3/set-user-status"),
        ("PUT", "/rustfs/admin/v3/set-group-status"),
        ("PUT", "/rustfs/admin/v3/restore-config-history-kv"),
        ("POST", "/rustfs/admin/v3/rebalance/start"),
        ("POST", "/rustfs/admin/v3/rebalance/stop"),
        ("POST", "/rustfs/admin/v3/background-heal/status"),
        ("POST", "/rustfs/admin/v3/pools/decommission"),
        ("POST", "/rustfs/admin/v3/pools/cancel"),
    ];
    /// Each operation's name and the body mode its codec gives the pipeline.
    struct BodyModes;
    impl OperationFold for BodyModes {
        type Carry = Vec<(&'static str, rustfs_gateway_core::codec::RequestBodyMode)>;
        fn step<O: AdminOperation>(&mut self, mut carry: Self::Carry) -> Self::Carry {
            carry.push((O::NAME, O::REQUEST_BODY));
            carry
        }
    }
    let modes = fold_every_operation(&mut BodyModes, Vec::new());
    for (method, path) in BODYLESS {
        let record = ROUTES
            .iter()
            .find(|record| record.method == method && record.path == path)
            .unwrap_or_else(|| panic!("{method} {path} is not declared"));
        assert_eq!(record.request_body, BodyKind::NotRead, "{method} {path}");
        let mode = modes
            .iter()
            .find(|(name, _)| *name == record.operation)
            .map(|(_, mode)| *mode);
        assert_eq!(
            mode,
            Some(rustfs_gateway_core::codec::RequestBodyMode::None),
            "{method} {path}: the codec reads no body"
        );
        assert!(
            record.alias.is_some_and(|alias| alias.starts_with("/minio/admin/")),
            "{method} {path}: legacy RustFS serves and normalizes the MinIO alias too"
        );
    }
    let reading: Vec<&str> = ROUTES
        .iter()
        .filter(|record| record.method == "GET" && record.request_body != BodyKind::NotRead)
        .map(|record| record.path)
        .collect();
    assert_eq!(reading, ["/rustfs/admin/v3/kms/backup"]);
}
