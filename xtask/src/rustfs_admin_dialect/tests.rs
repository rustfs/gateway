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
//! forms, the pools rulings, template parameters, literal-over-parameter shadowing, the
//! caller-secret mapping, and each refusal.
//! NOT responsible for: the inventory's validity (goldens' strict reader) or what the generated
//! operations do (the dialect crate's tests and goldens' `rustfs_admin_dialect`).
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::{
    FIRST_PRECEDENCE, FORMAT, INVENTORY, Inventory, Plan, RULINGS, Route, Ruling, Source, drift, generate, plan, repo_root,
    snake, type_name,
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

/// A `sigv4-admin` route of a migrated group whose template names `params`.
fn templated(method: &str, path: &str, params: &[&str]) -> Route {
    let mut route = route(method, path, "tier", "sigv4-admin", Some("admin:SetTier"));
    route.path_params = params.iter().map(|param| (*param).to_owned()).collect();
    route
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

/// The one ruling for `path`.
fn ruling_for(path: &str) -> &'static [Ruling] {
    let index = RULINGS
        .iter()
        .position(|ruling| ruling.path == path)
        .expect("a ruling for the path");
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
    assert_eq!(files.len(), 157, "155 operations, the module list and the table");
}

/// Positive — a name is the method, each path word after the admin prefix (a parameter as `By`
/// and its words), and the query value.
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
    assert_eq!(type_name("GET", "/rustfs/admin/v3/tier/{tier}", None).as_deref(), Some("GetV3TierByTier"));
    assert_eq!(
        type_name("DELETE", "/rustfs/admin/v3/audit/target/{target_type}/{target_name}/reset", None).as_deref(),
        Some("DeleteV3AuditTargetByTargetTypeByTargetNameReset")
    );
    assert_eq!(snake("PostV3SpeedtestClientDevnull"), "post_v3_speedtest_client_devnull");
}

/// Negative — a path outside the admin prefix, or with a character a type name cannot carry
/// (an affixed parameter among them), has no name.
#[test]
fn n_a_path_without_a_type_name_has_none() {
    assert_eq!(type_name("GET", "/minio/admin/v3/info", None), None);
    assert_eq!(type_name("GET", "/rustfs/admin/v3/object-zip-downloads/{id}.zip", None), None);
    assert_eq!(type_name("GET", "/rustfs/admin/v3/a+b", None), None);
}

/// Positive — a plain route is declared with its recorded action, its alias and the first
/// precedence; a route of a later group is counted as pending, not declared.
#[test]
fn a_plain_route_is_declared_and_a_later_group_is_pending() {
    let plan = planned(
        vec![
            route("GET", "/rustfs/admin/v3/kms/status", "kms", "sigv4-admin", Some("kms:ServiceControl")),
            route("GET", "/rustfs/admin/v3/list-users", "user", "sigv4-admin", Some("admin:ListUsers")),
        ],
        &[],
    );
    assert_eq!(plan.declared.len(), 1);
    let declared = &plan.declared[0];
    assert_eq!(declared.name, "rustfs:GetV3KmsStatus");
    assert_eq!(declared.alias.as_deref(), Some("/minio/admin/v3/kms/status"));
    assert_eq!(declared.rule.render(), "kms:ServiceControl");
    assert_eq!(declared.precedence, FIRST_PRECEDENCE);
    assert!(!declared.caller_secret && declared.params.is_empty() && declared.shadows.is_empty());
    assert_eq!(plan.pending, vec![("user".to_owned(), 4, 1)]);
}

/// Positive — `POST service` becomes its four query forms, `freeze` and `unfreeze` sharing
/// `admin:ServiceFreeze` (ADR-0025).
#[test]
fn the_service_route_splits_into_its_four_query_forms() {
    let plan = planned(vec![service_route()], ruling_for("/rustfs/admin/v3/service"));
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

/// Positive — both `MultipleActions` pools routes are any-of `admin:ServerInfo` and
/// `admin:Decommission`, in RustFS's order (ADR-0025).
#[test]
fn the_pools_routes_are_any_of_server_info_and_decommission() {
    for path in ["/rustfs/admin/v3/pools/list", "/rustfs/admin/v3/pools/status"] {
        let mut pools = route("GET", path, "pools", "custom", None);
        pools.auth_detail = Some("MultipleActions".to_owned());
        let plan = planned(vec![pools], ruling_for(path));
        let declared = &plan.declared[0];
        assert_eq!(declared.rule.render(), "anyOf(admin:ServerInfo, admin:Decommission)", "{path}");
        assert_eq!(declared.ruled.as_deref(), Some("MultipleActions"), "{path}");
    }
}

/// Positive and negative — a route whose body RustFS seals opts in to the caller's secret, in
/// each of the three sealed classes; one that does not, does not.
#[test]
fn only_a_sealed_route_opts_in_to_the_caller_secret() {
    let mut routes = Vec::new();
    for (index, class) in [
        "request-on-minio-alias",
        "response-on-minio-alias",
        "request-and-response-on-minio-alias",
        "none",
    ]
    .into_iter()
    .enumerate()
    {
        let mut sealed = route(
            "PUT",
            &format!("/rustfs/admin/v3/sealed{index}"),
            "system",
            "sigv4-admin",
            Some("admin:X"),
        );
        sealed.caller_secret_body = class.to_owned();
        routes.push(sealed);
    }
    let secrets: Vec<bool> = planned(routes, &[])
        .declared
        .iter()
        .map(|declared| declared.caller_secret)
        .collect();
    assert_eq!(secrets, [true, true, true, false]);
}

/// Positive — in the recorded inventory, exactly the eight sealed routes of order 3 opt in to
/// the caller's secret, and no route of orders 1 and 2 does.
#[test]
fn the_recorded_opt_ins_are_exactly_the_sealed_order_three_routes() {
    let recorded = std::fs::read_to_string(repo_root().join(INVENTORY)).expect("the inventory");
    let inventory: Inventory = serde_json::from_str(&recorded).expect("the inventory parses");
    let plan = plan(&inventory, RULINGS).expect("the recorded inventory plans");
    let sealed: Vec<&str> = plan
        .declared
        .iter()
        .filter(|declared| declared.caller_secret)
        .map(|declared| declared.name.as_str())
        .collect();
    assert_eq!(
        sealed,
        [
            "rustfs:DeleteV3DelConfigKv",
            "rustfs:GetV3Config",
            "rustfs:GetV3GetConfigKv",
            "rustfs:GetV3ListConfigHistoryKv",
            "rustfs:PostV3StartJob",
            "rustfs:PutV3Config",
            "rustfs:PutV3SetConfigKv",
            "rustfs:PutV3SiteReplicationEdit",
        ]
    );
    assert!(
        plan.declared
            .iter()
            .filter(|declared| declared.order < 3)
            .all(|declared| !declared.caller_secret)
    );
}

/// Positive — a templated route is declared at its template, service-level, with its
/// parameters in path order.
#[test]
fn a_templated_route_is_declared_with_its_parameters() {
    let plan = planned(
        vec![templated(
            "PUT",
            "/rustfs/admin/v3/audit/target/{target_type}/{target_name}",
            &["target_type", "target_name"],
        )],
        &[],
    );
    let declared = &plan.declared[0];
    assert_eq!(declared.name, "rustfs:PutV3AuditTargetByTargetTypeByTargetName");
    assert_eq!(declared.params, ["target_type", "target_name"]);
    assert_eq!(
        declared.alias.as_deref(),
        Some("/minio/admin/v3/audit/target/{target_type}/{target_name}")
    );
}

/// Negative — a bucket parameter, an affixed parameter, a parameter that is not a lowercase
/// identifier, a repeated one, and a template the inventory's list disagrees with are refused.
#[test]
fn n_a_template_outside_the_rule_is_refused() {
    for (path, params, why) in [
        ("/rustfs/admin/v3/quota/{bucket}", &["bucket"][..], "waits for ADR-0025's bucket binding"),
        (
            "/rustfs/admin/v3/tables/{warehouse}",
            &["warehouse"][..],
            "waits for ADR-0025's bucket binding",
        ),
        ("/rustfs/admin/v3/zip/{id}.zip", &["id"][..], "shares its segment"),
        ("/rustfs/admin/v3/tier/{Tier}", &["Tier"][..], "not a lowercase identifier"),
        ("/rustfs/admin/v3/tier/{tier-name}", &["tier-name"][..], "not a lowercase identifier"),
        ("/rustfs/admin/v3/tier/{}", &[""][..], "not a lowercase identifier"),
        ("/rustfs/admin/v3/{a}/{a}", &["a", "a"][..], "appears twice"),
        ("/rustfs/admin/v3/tier/{tier}", &[][..], "the inventory []"),
        ("/rustfs/admin/v3/tier/{a}/{b}", &["b", "a"][..], "the template names"),
    ] {
        let error = refusal(vec![templated("GET", path, params)], &[]);
        assert!(error.contains(why), "{path}: {error}");
    }
}

/// Positive — a literal segment stands in front of the parameter it meets, and only the earlier
/// literal's operation declares it; a different method, a different length or a different
/// literal overlaps nothing.
#[test]
fn a_literal_stands_in_front_of_the_parameter_it_meets() {
    let plan = planned(
        vec![
            templated("POST", "/rustfs/admin/v3/tier/clear", &[]),
            templated("DELETE", "/rustfs/admin/v3/tier/{tiername}", &["tiername"]),
            templated("POST", "/rustfs/admin/v3/tier/{tiername}", &["tiername"]),
            templated("POST", "/rustfs/admin/v3/tier/{tiername}/x", &["tiername"]),
            templated("POST", "/rustfs/admin/v3/tiers/{tiername}", &["tiername"]),
        ],
        &[],
    );
    let shadows: Vec<(&str, &str, &str, &str)> = plan
        .declared
        .iter()
        .flat_map(|declared| {
            declared.shadows.iter().map(move |shadow| {
                (
                    declared.name.as_str(),
                    shadow.shadowed.as_str(),
                    shadow.literal.as_str(),
                    shadow.param.as_str(),
                )
            })
        })
        .collect();
    assert_eq!(shadows, [("rustfs:PostV3TierClear", "rustfs:PostV3TierByTiername", "clear", "tiername")]);
}

/// Negative — an overlap whose literal comes later in the inventory, one no literal orders, and
/// one where each route has a literal the other meets with a parameter are refused.
#[test]
fn n_an_overlap_the_rule_cannot_order_is_refused() {
    let later = vec![
        templated("POST", "/rustfs/admin/v3/tier/{tiername}", &["tiername"]),
        templated("POST", "/rustfs/admin/v3/tier/clear", &[]),
    ];
    assert!(refusal(later, &[]).contains("a literal must come before the parameter it meets"));
    let same = vec![
        templated("GET", "/rustfs/admin/v3/tier/{a}", &["a"]),
        templated("GET", "/rustfs/admin/v3/tier/{b}", &["b"]),
    ];
    assert!(refusal(same, &[]).contains("no literal segment orders them"));
    let crossed = vec![
        templated("GET", "/rustfs/admin/v3/a/{x}/c", &["x"]),
        templated("GET", "/rustfs/admin/v3/a/b/{y}", &["y"]),
    ];
    assert!(refusal(crossed, &[]).contains("no literal segment orders them"));
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
    let service = ruling_for("/rustfs/admin/v3/service");
    assert!(refusal(Vec::new(), service).contains("names no custom-auth route"));
    let authorised = route("POST", "/rustfs/admin/v3/service", "system", "sigv4-admin", Some("admin:ServiceRestart"));
    assert!(refusal(vec![authorised], service).contains("authorises itself"));
    let mut changed = service_route();
    changed.auth_detail = Some("MultipleActions".to_owned());
    assert!(refusal(vec![changed], service).contains("now records"));
}

/// Negative — a query discriminator, an unplaced group, a path outside the admin prefix, an
/// unknown body or secret class, and two routes deriving one name are refused.
#[test]
fn n_a_route_outside_the_generators_rules_is_refused() {
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
