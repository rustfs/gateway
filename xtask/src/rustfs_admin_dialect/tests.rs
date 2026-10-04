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
//! caller-secret mapping, the order-4 subject rulings (own-account, named-account, account set),
//! and each refusal; the order-5 bucket bindings are `bucket_tests.rs`'s.
//! NOT responsible for: the inventory's validity (goldens' strict reader) or what the generated
//! operations do (the dialect crate's tests and goldens' `rustfs_admin_dialect`).
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::rulings::{About, Absent, Form, Ruled};
use super::{
    FIRST_PRECEDENCE, FORMAT, INVENTORY, Inventory, Plan, QUERY_BUCKETS, RULINGS, Route, Ruling, STAYS, SURFACES, Source,
    Surface, drift, generate, plan, repo_root, snake, type_name,
};

/// The admin API surface and the table catalog's.
const ADMIN: &Surface = &SURFACES[0];
const ICEBERG: &Surface = &SURFACES[1];

pub(super) fn route(method: &str, path: &str, group: &str, auth_mode: &str, action: Option<&str>) -> Route {
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
pub(super) fn templated(method: &str, path: &str, params: &[&str]) -> Route {
    let mut route = route(method, path, "tier", "sigv4-admin", Some("admin:SetTier"));
    route.path_params = params.iter().map(|param| (*param).to_owned()).collect();
    route
}

pub(super) fn inventory(routes: Vec<Route>) -> Inventory {
    Inventory {
        format: FORMAT.to_owned(),
        source: Source { commit: "c".to_owned() },
        routes,
    }
}

pub(super) fn planned(routes: Vec<Route>, rulings: &[Ruling]) -> Plan {
    planned_with(routes, rulings, &[])
}

/// The plan of `routes` under `rulings` and `query_buckets`.
pub(super) fn planned_with(routes: Vec<Route>, rulings: &[Ruling], query_buckets: &[(&str, &str, &'static str)]) -> Plan {
    match plan(&inventory(routes), rulings, query_buckets, &[]) {
        Ok(plan) => plan,
        Err(error) => panic!("refused: {error}"),
    }
}

pub(super) fn refusal(routes: Vec<Route>, rulings: &[Ruling]) -> String {
    refusal_with(routes, rulings, &[])
}

/// Why `routes` under `rulings` and `query_buckets` are refused.
pub(super) fn refusal_with(routes: Vec<Route>, rulings: &[Ruling], query_buckets: &[(&str, &str, &'static str)]) -> String {
    match plan(&inventory(routes), rulings, query_buckets, &[]) {
        Ok(plan) => panic!("planned {} operation(s)", plan.declared.len()),
        Err(error) => error,
    }
}

/// The one ruling for `path`.
pub(super) fn ruling_for(path: &str) -> &'static [Ruling] {
    let index = RULINGS
        .iter()
        .position(|ruling| ruling.path == path)
        .expect("a ruling for the path");
    &RULINGS[index..=index]
}

pub(super) fn service_route() -> Route {
    route("POST", "/rustfs/admin/v3/service", "system", "custom", None)
}

/// Positive — every committed generated file is exactly what the recorded inventory generates,
/// and no file under `ops/` is committed without being generated. This is the drift check.
#[test]
fn the_committed_dialect_is_what_the_inventory_generates() {
    let root = repo_root();
    let files = generate(&root).expect("the recorded inventory generates");
    assert_eq!(drift(&root, &files), Vec::<String>::new());
    assert_eq!(files.len(), 317, "312 operations, the module list and the table's four files");
}

/// Negative — a file committed under a wholly generated directory without being generated, in
/// `table/` as in `ops/`, is drift.
#[test]
fn n_an_extra_file_in_a_generated_directory_is_drift() {
    let root = repo_root();
    let mut files = generate(&root).expect("the recorded inventory generates");
    for dropped in [
        "crates/dialect-rustfs-admin/src/table/fold.rs",
        "crates/dialect-rustfs-admin/src/ops/get_v3_info.rs",
    ] {
        let source = files.remove(std::path::Path::new(dropped)).expect("a generated file");
        assert_eq!(drift(&root, &files), [format!("{dropped} is not generated")]);
        files.insert(dropped.into(), source);
    }
}

/// Positive — a name is the method, each path word after the admin prefix (a parameter as `By`
/// and its words), and the query value.
#[test]
fn names_follow_the_method_the_path_and_the_query() {
    assert_eq!(type_name("GET", ADMIN, "/rustfs/admin/v3/info", None).as_deref(), Some("GetV3Info"));
    assert_eq!(
        type_name("POST", ADMIN, "/rustfs/admin/v3/service", Some(("action", "unfreeze"))).as_deref(),
        Some("PostV3ServiceUnfreeze")
    );
    assert_eq!(
        type_name("GET", ADMIN, "/rustfs/admin/debug/pprof/profile", None).as_deref(),
        Some("GetDebugPprofProfile")
    );
    assert_eq!(
        type_name("GET", ADMIN, "/rustfs/admin/v3/tier/{tier}", None).as_deref(),
        Some("GetV3TierByTier")
    );
    assert_eq!(
        type_name("DELETE", ADMIN, "/rustfs/admin/v3/audit/target/{target_type}/{target_name}/reset", None).as_deref(),
        Some("DeleteV3AuditTargetByTargetTypeByTargetNameReset")
    );
    assert_eq!(snake("PostV3SpeedtestClientDevnull"), "post_v3_speedtest_client_devnull");
    assert_eq!(
        type_name("GET", ICEBERG, "/_iceberg/v1/config", None).as_deref(),
        Some("GetIcebergConfig")
    );
    assert_eq!(
        type_name("POST", ICEBERG, "/_iceberg/v1/{warehouse}/namespaces/{namespace}/tables/{table}", None).as_deref(),
        Some("PostIcebergByWarehouseNamespacesByNamespaceTablesByTable")
    );
    assert_eq!(type_name("GET", ICEBERG, "/iceberg/v1/config", None), None);
    assert_eq!(type_name("GET", ADMIN, "/_iceberg/v1/config", None), None);
}

/// Negative — a path outside the admin prefix, or with a character a type name cannot carry
/// (an affixed parameter among them), has no name.
#[test]
fn n_a_path_without_a_type_name_has_none() {
    assert_eq!(type_name("GET", ADMIN, "/minio/admin/v3/info", None), None);
    assert_eq!(type_name("GET", ADMIN, "/rustfs/admin/v3/object-zip-downloads/{id}.zip", None), None);
    assert_eq!(type_name("GET", ADMIN, "/rustfs/admin/v3/a+b", None), None);
}

/// Positive — a plain route is declared with its recorded action, its alias and the first
/// precedence; a route of a later group is counted as pending, not declared.
#[test]
fn a_plain_route_is_declared_and_a_later_group_is_pending() {
    // Every group is migrated today, so the later group is pending only under an earlier order.
    let routes = vec![
        route("GET", "/rustfs/admin/v3/kms/status", "kms", "sigv4-admin", Some("kms:ServiceControl")),
        route("GET", "/rustfs/admin/v3/oidc/status", "oidc", "sigv4-admin", Some("admin:ServerInfo")),
    ];
    let plan = super::plan_through(3, &inventory(routes), &[], &[], &[]).expect("the fixture plans");
    assert_eq!(plan.declared.len(), 1);
    let declared = &plan.declared[0];
    assert_eq!(declared.name, "rustfs:GetV3KmsStatus");
    assert_eq!(declared.alias.as_deref(), Some("/minio/admin/v3/kms/status"));
    assert_eq!(declared.rule.render(), "kms:ServiceControl");
    assert_eq!(declared.precedence, FIRST_PRECEDENCE);
    assert!(!declared.caller_secret && declared.params.is_empty() && declared.shadows.is_empty());
    assert!(declared.rule.about.is_none() && declared.bucket.is_none());
    assert_eq!(plan.pending, vec![("oidc".to_owned(), 7, 1)]);
}

/// A custom-auth route of an order-4 group, classed `detail`.
pub(super) fn custom(method: &str, path: &str, detail: &str) -> Route {
    let mut route = route(method, path, "user", "custom", None);
    route.auth_detail = Some(detail.to_owned());
    route
}

/// The recorded inventory's plan.
pub(super) fn recorded_plan() -> Plan {
    let recorded = std::fs::read_to_string(repo_root().join(INVENTORY)).expect("the inventory");
    let inventory: Inventory = serde_json::from_str(&recorded).expect("the inventory parses");
    plan(&inventory, RULINGS, QUERY_BUCKETS, STAYS).expect("the recorded inventory plans")
}

/// Positive — the own-account routes are about the caller under their vendor label, the
/// named-account routes about their query parameter with their absence, and the bulk listings
/// about each `users` account with `admin:ListUsers` for `all`; each spelled as core renders it,
/// and each expression carrying the module's `SUBJECT`.
#[test]
fn a_subject_ruling_is_declared_about_its_subject() {
    for (method, path, detail, rendered, expression) in [
        (
            "GET",
            "/rustfs/admin/v3/account/info",
            "CredentialOnly",
            "rustfs:SelfAccountInfo about caller",
            "SubjectRule::Caller",
        ),
        (
            "GET",
            "/rustfs/admin/v3/user-info",
            "ContextualAuthorization",
            "admin:GetUser about query(accessKey|access-key, absent=refused)",
            "SubjectRule::Query { param: \"accessKey\", aliases: &[\"access-key\"], when_absent: WhenAbsent::Refuse }",
        ),
        (
            "GET",
            "/rustfs/admin/v3/list-service-accounts",
            "ContextualAuthorization",
            "admin:ListServiceAccounts about query(user, absent=caller)",
            "SubjectRule::Query { param: \"user\", aliases: &[], when_absent: WhenAbsent::Caller }",
        ),
        (
            "GET",
            "/rustfs/admin/v3/list-access-keys-bulk",
            "MultipleActions",
            "admin:ListServiceAccounts about each(users, everyone=all ⇒ admin:ListUsers)",
            "SubjectRule::Set { param: \"users\", everyone: Some(Everyone { param: \"all\", action: \"admin:ListUsers\" }) }",
        ),
    ] {
        let plan = planned(vec![custom(method, path, detail)], ruling_for(path));
        let declared = &plan.declared[0];
        assert_eq!(declared.rule.render(), rendered, "{path}");
        assert_eq!(declared.rule.subject_expression().as_deref(), Some(expression), "{path}");
        assert!(
            declared
                .rule
                .expression("ResourceShape::Service")
                .ends_with(".about_subject(SUBJECT)"),
            "{path}"
        );
        assert_eq!(declared.ruled.as_deref(), Some(detail), "{path}");
    }
}

/// Positive — in the recorded inventory, exactly the order-4 custom-auth routes carry a subject
/// rule: nine own-account, nine named-account (four refusing an absent account, where RustFS
/// answers `400`), and the three bulk listings; `list-remote-targets` is plain
/// `admin:GetBucketTarget`, and the two policy-entities routes are any-of the three listings.
#[test]
fn the_recorded_subject_rulings_are_exactly_the_order_four_custom_routes() {
    let plan = recorded_plan();
    let about: Vec<(&str, String)> = plan
        .declared
        .iter()
        .filter(|declared| declared.rule.about.is_some())
        .map(|declared| (declared.name.as_str(), declared.rule.render()))
        .collect();
    assert!(
        plan.declared
            .iter()
            .filter(|declared| declared.rule.about.is_some())
            .all(|declared| declared.order == 4)
    );
    let own: Vec<&str> = about
        .iter()
        .filter(|(_, rule)| rule.ends_with(" about caller"))
        .map(|(_, rule)| rule.trim_end_matches(" about caller"))
        .collect();
    assert_eq!(
        own,
        [
            "rustfs:SelfAccountInfo",
            "rustfs:AccountMfaStatus",
            "rustfs:AccountInfo",
            "rustfs:MfaChallenge",
            "rustfs:AccountMfaActivate",
            "rustfs:AccountMfaDisable",
            "rustfs:AccountMfaEnroll",
            "rustfs:AccountMfaRecoveryCodes",
            "rustfs:ChangeOwnPassword",
        ]
    );
    let named: Vec<(&str, &str)> = about
        .iter()
        .filter(|(_, rule)| rule.contains(" about query("))
        .map(|(name, rule)| (*name, rule.as_str()))
        .collect();
    assert_eq!(
        named,
        [
            (
                "rustfs:DeleteV3DeleteServiceAccount",
                "admin:RemoveServiceAccount about query(accessKey|access-key, absent=refused)"
            ),
            (
                "rustfs:DeleteV3DeleteServiceAccounts",
                "admin:RemoveServiceAccount about query(accessKey|access-key, absent=refused)"
            ),
            (
                "rustfs:GetV3IdpLdapListAccessKeys",
                "admin:ListServiceAccounts about query(userDN|user-dn|user, absent=caller)"
            ),
            (
                "rustfs:GetV3InfoAccessKey",
                "admin:ListServiceAccounts about query(accessKey|access-key, absent=caller)"
            ),
            (
                "rustfs:GetV3InfoServiceAccount",
                "admin:ListServiceAccounts about query(accessKey|access-key, absent=refused)"
            ),
            (
                "rustfs:GetV3ListServiceAccounts",
                "admin:ListServiceAccounts about query(user, absent=caller)"
            ),
            ("rustfs:GetV3UserInfo", "admin:GetUser about query(accessKey|access-key, absent=refused)"),
            (
                "rustfs:PostV3UpdateServiceAccount",
                "admin:UpdateServiceAccount about query(accessKey|access-key, absent=refused)"
            ),
            (
                "rustfs:PutV3AddUser",
                "admin:CreateUser about query(accessKey|access-key, absent=refused)"
            ),
        ]
    );
    let sets: Vec<&str> = about
        .iter()
        .filter(|(_, rule)| rule.contains(" about each("))
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(
        sets,
        [
            "rustfs:GetV3IdpLdapListAccessKeysBulk",
            "rustfs:GetV3IdpOpenidListAccessKeysBulk",
            "rustfs:GetV3ListAccessKeysBulk",
        ]
    );
    assert_eq!(about.len(), 21);
    let rule_of = |name: &str| {
        plan.declared
            .iter()
            .find(|declared| declared.name == name)
            .map(|declared| declared.rule.render())
    };
    assert_eq!(rule_of("rustfs:GetV3ListRemoteTargets").as_deref(), Some("admin:GetBucketTarget"));
    for name in ["rustfs:GetV3IdpBuiltinPolicyEntities", "rustfs:GetV3IdpLdapPolicyEntities"] {
        assert_eq!(
            rule_of(name).as_deref(),
            Some("anyOf(admin:ListGroups, admin:ListUsers, admin:ListUserPolicies)"),
            "{name}"
        );
    }
}

/// Negative — a rule outside ADR-0025's and ADR-0026's shapes is refused at generation, never
/// written: an own-account operation under an IAM action, another vendor's label or two actions;
/// a vendor label on any other operation; a subject parameter or alias outside the unreserved set
/// or equal to the form's selecting key, and an alias repeating a spelling (ADR-0029); and a set whose flag is its own parameter, whose
/// every-account action is malformed, a vendor label, or already asked about each account.
#[test]
fn n_a_subject_rule_outside_the_adrs_shapes_is_refused() {
    const fn form(rule: Ruled, about: About) -> Form {
        Form {
            query: None,
            rule,
            about: Some(about),
            anonymous: false,
        }
    }
    const CALLER_ADMIN: &[Form] = &[form(Ruled::One("admin:GetUser"), About::Caller)];
    const CALLER_FOREIGN: &[Form] = &[form(Ruled::One("minio:Self"), About::Caller)];
    const CALLER_TWO: &[Form] = &[form(Ruled::AnyOf(&["rustfs:A", "rustfs:B"]), About::Caller)];
    const LABEL_UNOWNED: &[Form] = &[Form {
        query: None,
        rule: Ruled::One("rustfs:Anything"),
        about: None,
        anonymous: false,
    }];
    const LABEL_NAMED: &[Form] = &[form(
        Ruled::One("rustfs:Anything"),
        About::Query {
            param: "accessKey",
            aliases: &[],
            absent: Absent::Refuse,
        },
    )];
    const BAD_PARAM: &[Form] = &[form(
        Ruled::One("admin:GetUser"),
        About::Query {
            param: "access key",
            aliases: &[],
            absent: Absent::Refuse,
        },
    )];
    const SELECTOR_PARAM: &[Form] = &[Form {
        query: Some(("accessKey", "x")),
        rule: Ruled::One("admin:GetUser"),
        about: Some(About::Query {
            param: "accessKey",
            aliases: &[],
            absent: Absent::Caller,
        }),
        anonymous: false,
    }];
    const BAD_ALIAS: &[Form] = &[form(
        Ruled::One("admin:GetUser"),
        About::Query {
            param: "accessKey",
            aliases: &["access key"],
            absent: Absent::Refuse,
        },
    )];
    const ALIAS_IS_PARAM: &[Form] = &[form(
        Ruled::One("admin:GetUser"),
        About::Query {
            param: "accessKey",
            aliases: &["accessKey"],
            absent: Absent::Refuse,
        },
    )];
    const ALIAS_TWICE: &[Form] = &[form(
        Ruled::One("admin:GetUser"),
        About::Query {
            param: "userDN",
            aliases: &["user", "user"],
            absent: Absent::Caller,
        },
    )];
    const SELECTOR_ALIAS: &[Form] = &[Form {
        query: Some(("access-key", "x")),
        rule: Ruled::One("admin:GetUser"),
        about: Some(About::Query {
            param: "accessKey",
            aliases: &["access-key"],
            absent: Absent::Caller,
        }),
        anonymous: false,
    }];
    const FLAG_IS_PARAM: &[Form] = &[form(
        Ruled::One("admin:ListServiceAccounts"),
        About::Set {
            param: "users",
            everyone: Some(("users", "admin:ListUsers")),
        },
    )];
    const FLAG_ACTION_MALFORMED: &[Form] = &[form(
        Ruled::One("admin:ListServiceAccounts"),
        About::Set {
            param: "users",
            everyone: Some(("all", "ListUsers")),
        },
    )];
    const FLAG_ACTION_LABEL: &[Form] = &[form(
        Ruled::One("admin:ListServiceAccounts"),
        About::Set {
            param: "users",
            everyone: Some(("all", "rustfs:Everyone")),
        },
    )];
    const FLAG_ACTION_ASKED: &[Form] = &[form(
        Ruled::One("admin:ListServiceAccounts"),
        About::Set {
            param: "users",
            everyone: Some(("all", "admin:ListServiceAccounts")),
        },
    )];
    for (forms, why) in [
        (CALLER_ADMIN, "own-account operation names exactly one action"),
        (CALLER_FOREIGN, "own-account operation names exactly one action"),
        (CALLER_TWO, "own-account operation names exactly one action"),
        (LABEL_UNOWNED, "authorises only an own-account operation"),
        (LABEL_NAMED, "authorises only an own-account operation"),
        (BAD_PARAM, "unreserved characters"),
        (SELECTOR_PARAM, "not the query key that selects the form"),
        (BAD_ALIAS, "unreserved characters"),
        (ALIAS_IS_PARAM, "spellings are distinct from one another"),
        (ALIAS_TWICE, "spellings are distinct from one another"),
        (SELECTOR_ALIAS, "not the query key that selects the form"),
        (FLAG_IS_PARAM, "an unreserved parameter of its own"),
        (FLAG_ACTION_MALFORMED, "an IAM action spelled"),
        (FLAG_ACTION_LABEL, "an IAM action spelled"),
        (FLAG_ACTION_ASKED, "no named-account question already asks"),
    ] {
        let rulings = [Ruling {
            method: "GET",
            path: "/rustfs/admin/v3/x",
            auth_detail: "CredentialOnly",
            forms,
        }];
        let error = refusal(vec![custom("GET", "/rustfs/admin/v3/x", "CredentialOnly")], &rulings);
        assert!(error.contains(why), "{why}: {error}");
    }
}

/// Negative — a vendor label recorded by the inventory for a `sigv4-admin` route is refused: only a
/// ruling can make an operation own-account.
#[test]
fn n_an_inventory_action_in_the_vendor_namespace_is_refused() {
    let labelled = route("GET", "/rustfs/admin/v3/x", "system", "sigv4-admin", Some("rustfs:X"));
    assert!(refusal(vec![labelled], &[]).contains("authorises only an own-account operation"));
    let malformed = route("GET", "/rustfs/admin/v3/x", "system", "sigv4-admin", Some("admin"));
    assert!(refusal(vec![malformed], &[]).contains("spelled `service:Action`"));
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

/// Positive — in the recorded inventory, exactly the eight sealed routes of order 3 and the
/// twenty-one of order 4 opt in to the caller's secret, and no route of orders 1 and 2 does.
#[test]
fn the_recorded_opt_ins_are_exactly_the_sealed_routes() {
    let plan = recorded_plan();
    let sealed = |order: u8| -> Vec<&str> {
        plan.declared
            .iter()
            .filter(|declared| declared.caller_secret && declared.order == order)
            .map(|declared| declared.name.as_str())
            .collect()
    };
    assert_eq!(
        sealed(3),
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
    assert_eq!(
        sealed(4),
        [
            "rustfs:GetV3IdpBuiltinPolicyEntities",
            "rustfs:GetV3IdpLdapPolicyEntities",
            "rustfs:GetV3InfoAccessKey",
            "rustfs:GetV3InfoServiceAccount",
            "rustfs:GetV3ListAccessKeysBulk",
            "rustfs:GetV3ListServiceAccounts",
            "rustfs:GetV3ListUsers",
            "rustfs:GetV3TemporaryAccountInfo",
            "rustfs:PostV3AccountMfaActivate",
            "rustfs:PostV3AccountMfaDisable",
            "rustfs:PostV3AccountMfaRecoveryCodes",
            "rustfs:PostV3AccountPassword",
            "rustfs:PostV3IdpBuiltinPolicyAttach",
            "rustfs:PostV3IdpBuiltinPolicyDetach",
            "rustfs:PostV3ReplicationDiff",
            "rustfs:PostV3UpdateServiceAccount",
            "rustfs:PutV3AddServiceAccount",
            "rustfs:PutV3AddServiceAccounts",
            "rustfs:PutV3AddUser",
            "rustfs:PutV3SetRemoteTarget",
            "rustfs:PutV3SetUserSecretKey",
        ]
    );
    assert!(sealed(1).is_empty() && sealed(2).is_empty());
}

/// Positive — a templated route is declared at its template, service-level, with its
/// different literal overlaps nothing.
#[test]
fn a_literal_stands_in_front_of_the_parameter_it_meets() {
    let plan = planned(
        vec![
            templated("POST", "/rustfs/admin/v3/tier/clear", &[]),
            templated("DELETE", "/rustfs/admin/v3/tier/{tiername}", &["tiername"]),
            templated("POST", "/rustfs/admin/v3/tier/{tiername}", &["tiername"]),
            templated("POST", "/rustfs/admin/v3/tier/{tiername}/x", &["tiername"]),
            templated("POST", "/rustfs/admin/v3/tiers/{tiername}", &["tiername"]),
            templated("GET", "/rustfs/admin/v3/buckets/{warehouse}", &["warehouse"]),
            templated("GET", "/rustfs/admin/v3/{warehouse}/namespaces", &["warehouse"]),
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
    assert_eq!(
        shadows,
        [
            ("rustfs:PostV3TierClear", "rustfs:PostV3TierByTiername", "clear", "tiername"),
            (
                "rustfs:GetV3BucketsByWarehouse",
                "rustfs:GetV3ByWarehouseNamespaces",
                "buckets",
                "warehouse"
            ),
        ]
    );
}

/// Negative — an overlap whose literal comes later in the inventory, one no literal orders, and
/// a crossed pair whose first divergence favours the later route are refused (ADR-0031 (d)).
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
    let crossed_later = vec![
        templated("GET", "/rustfs/admin/v3/a/{x}/c", &["x"]),
        templated("GET", "/rustfs/admin/v3/a/b/{y}", &["y"]),
    ];
    assert!(refusal(crossed_later, &[]).contains("a literal must come before the parameter it meets"));
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
    assert!(
        refusal(vec![route("GET", "/health/x", "system", "sigv4-admin", Some("admin:X"))], &[])
            .contains("under no surface the dialect serves")
    );
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
