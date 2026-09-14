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

//! The generator's rules: every committed file is what the inventory generates, and every route
//! the generator has no rule for is refused.
//!
//! Responsible for: the drift check the gate runs, the naming rule, the service route's four
//! forms, the caller-secret mapping, and each refusal.
//! NOT responsible for: the inventory's validity (goldens' strict reader) or what the generated
//! operations do (the dialect crate's tests and goldens' `rustfs_admin_dialect`).
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::{
    FIRST_PRECEDENCE, FORMAT, Inventory, Plan, RULINGS, Route, Ruling, Source, drift, generate, plan, repo_root, snake, type_name,
};

fn route(method: &str, path: &str, group: &str, auth_mode: &str, action: Option<&str>) -> Route {
    Route {
        method: method.to_owned(),
        path: path.to_owned(),
        group: group.to_owned(),
        path_params: Vec::new(),
        minio_admin_alias: true,
        query_discriminators: Vec::new(),
        auth_mode: auth_mode.to_owned(),
        iam_action_wire: action.map(str::to_owned),
        auth_detail: (auth_mode == "custom").then(|| "NotImplemented".to_owned()),
        handler: "Handler".to_owned(),
        handler_file: "rustfs/src/admin/handlers/system.rs".to_owned(),
        caller_secret_body: "none".to_owned(),
        request_body: "not-read".to_owned(),
        response_body: "buffered".to_owned(),
    }
}

fn planned(routes: Vec<Route>, rulings: &[Ruling]) -> Plan {
    let inventory = Inventory {
        format: FORMAT.to_owned(),
        source: Source { commit: "c".to_owned() },
        routes,
    };
    match plan(&inventory, rulings) {
        Ok(plan) => plan,
        Err(error) => panic!("refused: {error}"),
    }
}

fn refusal(routes: Vec<Route>, rulings: &[Ruling]) -> String {
    let inventory = Inventory {
        format: FORMAT.to_owned(),
        source: Source { commit: "c".to_owned() },
        routes,
    };
    match plan(&inventory, rulings) {
        Ok(plan) => panic!("planned {} operation(s)", plan.declared.len()),
        Err(error) => error,
    }
}

/// The ruling for `POST service` alone.
fn service_ruling() -> &'static [Ruling] {
    let index = RULINGS
        .iter()
        .position(|ruling| ruling.path == "/rustfs/admin/v3/service")
        .expect("the service ruling");
    &RULINGS[index..=index]
}

fn service_route() -> Route {
    route("POST", "/rustfs/admin/v3/service", "system", "custom", None)
}

/// Positive — every committed generated file is exactly what the recorded inventory generates,
/// and no file under `ops/` is committed without being generated. This is the drift check.
#[test]
fn the_committed_dialect_is_what_the_inventory_generates() {
    let root = repo_root();
    let files = generate(&root).expect("the recorded inventory generates");
    assert_eq!(drift(&root, &files), Vec::<String>::new());
    assert_eq!(files.len(), 50, "48 operations, the module list and the table");
}

/// Positive — a name is the method, each path word after the admin prefix, and the query value.
#[test]
fn names_follow_the_method_the_path_and_the_query() {
    assert_eq!(type_name("GET", "/rustfs/admin/v3/info", None).as_deref(), Some("GetV3Info"));
    assert_eq!(
        type_name("POST", "/rustfs/admin/v3/service", Some(("action", "unfreeze"))).as_deref(),
        Some("PostV3ServiceUnfreeze")
    );
    assert_eq!(
        type_name("GET", "/rustfs/admin/debug/pprof/profile", None).as_deref(),
        Some("GetDebugPprofProfile")
    );
    assert_eq!(snake("PostV3SpeedtestClientDevnull"), "post_v3_speedtest_client_devnull");
}

/// Negative — a path outside the admin prefix, or with a character a type name cannot carry, has
/// no name.
#[test]
fn n_a_path_without_a_type_name_has_none() {
    assert_eq!(type_name("GET", "/minio/admin/v3/info", None), None);
    assert_eq!(type_name("GET", "/rustfs/admin/v3/{tier}", None), None);
    assert_eq!(type_name("GET", "/rustfs/admin/v3/a+b", None), None);
}

/// Positive — a plain route is declared with its recorded action, its alias and the first
/// precedence; a route of a later group is counted as pending, not declared.
#[test]
fn a_plain_route_is_declared_and_a_later_group_is_pending() {
    let plan = planned(
        vec![
            route("GET", "/rustfs/admin/v3/info", "system", "sigv4-admin", Some("admin:ServerInfo")),
            route("GET", "/rustfs/admin/v3/kms/status", "kms", "sigv4-admin", Some("admin:KMSKeyStatus")),
        ],
        &[],
    );
    assert_eq!(plan.declared.len(), 1);
    let declared = &plan.declared[0];
    assert_eq!(declared.name, "rustfs:GetV3Info");
    assert_eq!(declared.alias.as_deref(), Some("/minio/admin/v3/info"));
    assert_eq!(declared.rule.render(), "admin:ServerInfo");
    assert_eq!(declared.precedence, FIRST_PRECEDENCE);
    assert!(!declared.caller_secret);
    assert_eq!(plan.pending, vec![("kms".to_owned(), 3, 1)]);
}

/// Positive — `POST service` becomes its four query forms, `freeze` and `unfreeze` sharing
/// `admin:ServiceFreeze` (ADR-0025).
#[test]
fn the_service_route_splits_into_its_four_query_forms() {
    let plan = planned(vec![service_route()], service_ruling());
    let forms: Vec<String> = plan
        .declared
        .iter()
        .map(|declared| format!("{} {:?} {}", declared.name, declared.query, declared.rule.render()))
        .collect();
    assert_eq!(
        forms,
        [
            "rustfs:PostV3ServiceRestart Some((\"action\", \"restart\")) admin:ServiceRestart",
            "rustfs:PostV3ServiceStop Some((\"action\", \"stop\")) admin:ServiceStop",
            "rustfs:PostV3ServiceFreeze Some((\"action\", \"freeze\")) admin:ServiceFreeze",
            "rustfs:PostV3ServiceUnfreeze Some((\"action\", \"unfreeze\")) admin:ServiceFreeze",
        ]
    );
}

/// Positive and negative — a route whose body RustFS seals opts in to the caller's secret; one
/// that does not, does not.
#[test]
fn only_a_sealed_route_opts_in_to_the_caller_secret() {
    let mut sealed = route("PUT", "/rustfs/admin/v3/sealed", "system", "sigv4-admin", Some("admin:X"));
    sealed.caller_secret_body = "request-on-minio-alias".to_owned();
    let plain = route("PUT", "/rustfs/admin/v3/plain", "system", "sigv4-admin", Some("admin:X"));
    let plan = planned(vec![sealed, plain], &[]);
    assert!(plan.declared[0].caller_secret);
    assert!(!plan.declared[1].caller_secret);
}

/// Negative — a custom-auth or anonymous route with no ruling is refused, never declared under a
/// guessed action.
#[test]
fn n_a_route_without_a_rule_is_refused() {
    assert!(refusal(vec![service_route()], &[]).contains("custom route in a migrated group has no ruling"));
    assert!(
        refusal(vec![route("GET", "/rustfs/admin/v3/x", "system", "anonymous", None)], &[])
            .contains("anonymous route in a migrated group has no ruling")
    );
    assert!(refusal(vec![route("GET", "/rustfs/admin/v3/x", "system", "sigv4-admin", None)], &[]).contains("records no action"));
}

/// Negative — a ruling nothing needs, a ruling on a route the inventory authorises itself, and a
/// ruling whose route changed class are refused.
#[test]
fn n_a_stale_ruling_is_refused() {
    assert!(refusal(Vec::new(), service_ruling()).contains("names no custom-auth route"));
    let authorised = route("POST", "/rustfs/admin/v3/service", "system", "sigv4-admin", Some("admin:ServiceRestart"));
    assert!(refusal(vec![authorised], service_ruling()).contains("authorises itself"));
    let mut changed = service_route();
    changed.auth_detail = Some("MultipleActions".to_owned());
    assert!(refusal(vec![changed], service_ruling()).contains("now records"));
}

/// Negative — a template, a query discriminator, an unplaced group, a path outside the admin
/// prefix, an unknown body or secret class, and two routes deriving one name are refused.
#[test]
fn n_a_route_outside_the_generators_rules_is_refused() {
    let mut templated = route("GET", "/rustfs/admin/v3/tier/{tier}", "system", "sigv4-admin", Some("admin:ListTier"));
    templated.path_params = vec!["tier".to_owned()];
    assert!(refusal(vec![templated], &[]).contains("templated"));
    let mut queried = route("GET", "/rustfs/admin/v3/x", "system", "sigv4-admin", Some("admin:X"));
    queried.query_discriminators = vec![serde_json::json!({"key": "x"})];
    assert!(refusal(vec![queried], &[]).contains("query-discriminated"));
    assert!(
        refusal(vec![route("GET", "/rustfs/admin/v3/x", "nowhere", "sigv4-admin", Some("admin:X"))], &[])
            .contains("no place in the plan")
    );
    assert!(refusal(vec![route("GET", "/health/x", "system", "sigv4-admin", Some("admin:X"))], &[]).contains("not under"));
    let mut body = route("GET", "/rustfs/admin/v3/x", "system", "sigv4-admin", Some("admin:X"));
    body.request_body = "chunked".to_owned();
    assert!(refusal(vec![body], &[]).contains("unknown body kind"));
    let mut secret = route("GET", "/rustfs/admin/v3/x", "system", "sigv4-admin", Some("admin:X"));
    secret.caller_secret_body = "always".to_owned();
    assert!(refusal(vec![secret], &[]).contains("unknown caller-secret class"));
    let twice = vec![
        route("GET", "/rustfs/admin/v3/top-locks", "system", "sigv4-admin", Some("admin:X")),
        route("GET", "/rustfs/admin/v3/top/locks", "system", "sigv4-admin", Some("admin:X")),
    ];
    assert!(refusal(twice, &[]).contains("two routes derive the operation rustfs:GetV3TopLocks"));
}
