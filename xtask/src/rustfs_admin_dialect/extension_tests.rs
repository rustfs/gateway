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

//! The generator's S3-shaped extension rows (rustfs/backlog#2753): what the recorded inventory
//! plans, what a module renders, and every refusal.
//!
//! Responsible for: the eight recorded rows' names, order, actions, discriminators and declared
//! overlaps; the rendered module's row, floor, codec and record; and the refusals — a route
//! without a ruling, a stale ruling, a row the inventory records differently, a rule, target,
//! method, key, action or name outside the grammar, two routes deriving one operation, and a row
//! that would sit behind a standard row.
//! NOT responsible for: the committed output (the drift test in `tests.rs`), or routing (the
//! dialect crate's tests).
//! Upstream: `super::extension` and `super::plan`. Downstream: nothing; a leaf test module.

use super::extension::{ExtensionRoute, FIRST_PRECEDENCE, QueryDiscriminator, admit_presigned, admit_versioned};
use super::rulings::{EXTENSIONS, PRESIGNED_EXTENSIONS, VERSIONED_EXTENSIONS};
use super::tests::{inventory, recorded_plan, route};
use super::{Plan, plan};

fn ext(name: &str, method: &str, target: &str, key: &str, rule: &str, action: &str) -> ExtensionRoute {
    ExtensionRoute {
        name: name.to_owned(),
        method: method.to_owned(),
        target: target.to_owned(),
        query_discriminator: QueryDiscriminator {
            key: key.to_owned(),
            rule: rule.to_owned(),
        },
        auth_mode: "custom".to_owned(),
        auth_detail: "SignatureRequiredThenHandlerCheck".to_owned(),
        iam_action: "SomeAction".to_owned(),
        iam_action_wire: action.to_owned(),
    }
}

fn check() -> ExtensionRoute {
    ext(
        "Ext::Check",
        "GET",
        "bucket",
        "replication-check",
        "equals:",
        "s3:PutReplicationConfiguration",
    )
}

/// The plan of `extensions` under `rulings`, with one ordinary route so the plan is not empty.
fn planned(extensions: Vec<ExtensionRoute>, rulings: &[(&str, &str)]) -> Result<Plan, String> {
    let mut inventory = inventory(vec![route("GET", "/rustfs/admin/v3/x", "system", "sigv4-admin", Some("admin:X"))]);
    inventory.extension_routes = extensions;
    plan(&inventory, &[], &[], &[], &[], rulings)
}

fn refusal(extensions: Vec<ExtensionRoute>, rulings: &[(&str, &str)]) -> String {
    match planned(extensions, rulings) {
        Ok(plan) => panic!("planned {} extension row(s)", plan.extensions.len()),
        Err(error) => error,
    }
}

/// Positive — the recorded inventory plans eight rows in its order, each named by its ruling,
/// at consecutive precedences from the first, under its IAM action and discriminator.
#[test]
fn the_recorded_extension_routes_plan_as_eight_rows_in_rustfs_order() {
    let plan = recorded_plan();
    let rows: Vec<(&str, &str, u16, &str, &str, &str, &str)> = plan
        .extensions
        .iter()
        .map(|row| {
            (
                row.name.as_str(),
                row.operation.as_str(),
                row.precedence,
                row.method.as_str(),
                row.key.as_str(),
                row.rule.as_str(),
                row.action.as_str(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                "ReplicationExtRoute::ResetStart",
                "rustfs:ResetBucketReplication",
                80,
                "PUT",
                "replication-reset",
                "equals:",
                "s3:ResetBucketReplicationState"
            ),
            (
                "ReplicationExtRoute::ResetStatus",
                "rustfs:GetReplicationResetStatus",
                81,
                "GET",
                "replication-reset-status",
                "equals:",
                "s3:ResetBucketReplicationState"
            ),
            (
                "ReplicationExtRoute::MetricsV2",
                "rustfs:GetReplicationMetricsV2",
                82,
                "GET",
                "replication-metrics",
                "equals:2",
                "s3:GetReplicationConfiguration"
            ),
            (
                "ReplicationExtRoute::MetricsV1",
                "rustfs:GetReplicationMetrics",
                83,
                "GET",
                "replication-metrics",
                "equals:",
                "s3:GetReplicationConfiguration"
            ),
            (
                "ReplicationExtRoute::Check",
                "rustfs:CheckReplication",
                84,
                "GET",
                "replication-check",
                "equals:",
                "s3:PutReplicationConfiguration"
            ),
            (
                "MiscExtRoute::ObjectLambda[object]",
                "rustfs:InvokeObjectLambda",
                85,
                "GET",
                "lambdaArn",
                "present",
                "s3:GetObject"
            ),
            (
                "MiscExtRoute::ListenNotification[service]",
                "rustfs:ListenNotification",
                86,
                "GET",
                "events",
                "present",
                "s3:ListenNotification"
            ),
            (
                "MiscExtRoute::ListenNotification[bucket]",
                "rustfs:ListenBucketNotification",
                87,
                "GET",
                "events",
                "present",
                "s3:ListenBucketNotification"
            ),
        ]
    );
    assert_eq!(plan.extensions[0].precedence, FIRST_PRECEDENCE);
    assert_eq!(EXTENSIONS.len(), 8);
    let stems: Vec<&str> = plan.extensions.iter().map(|row| row.stem.as_str()).collect();
    assert_eq!(
        stems,
        [
            "reset_bucket_replication",
            "get_replication_reset_status",
            "get_replication_metrics_v2",
            "get_replication_metrics",
            "check_replication",
            "invoke_object_lambda",
            "listen_notification",
            "listen_bucket_notification",
        ]
    );
}

/// Positive and negative — each row declares every standard row of its method and target a
/// request can satisfy together with it, and every later extension row of that cell it can be
/// named with; two values of one key never overlap, and another cell is never declared.
#[test]
fn an_extension_row_shadows_its_cell_and_the_later_rows_it_can_be_named_with() {
    let plan = recorded_plan();
    let shadows = |operation: &str| -> Vec<String> {
        plan.extensions
            .iter()
            .find(|row| row.operation == operation)
            .expect("a planned row")
            .shadows
            .iter()
            .map(|shadowed| shadowed.op.clone())
            .collect()
    };
    let counts: Vec<usize> = plan.extensions.iter().map(|row| row.shadows.len()).collect();
    assert_eq!(counts, [16, 38, 36, 36, 35, 10, 2, 34]);
    let status = shadows("rustfs:GetReplicationResetStatus");
    for standard in [
        "GetBucketReplication",
        "GetBucketAcl",
        "ListObjectsV2",
        "ListObjects",
        "CreateSession",
    ] {
        assert!(status.contains(&standard.to_owned()), "{standard}");
    }
    assert_eq!(
        status[34..],
        [
            "rustfs:GetReplicationMetricsV2",
            "rustfs:GetReplicationMetrics",
            "rustfs:CheckReplication",
            "rustfs:ListenBucketNotification",
        ]
    );
    let v2 = shadows("rustfs:GetReplicationMetricsV2");
    assert!(
        !v2.contains(&"rustfs:GetReplicationMetrics".to_owned()),
        "two values of one key never meet"
    );
    assert_eq!(v2[34..], ["rustfs:CheckReplication", "rustfs:ListenBucketNotification"]);
    assert_eq!(shadows("rustfs:ListenNotification"), ["ListDirectoryBuckets", "ListBuckets"]);
    let reset = shadows("rustfs:ResetBucketReplication");
    assert!(reset.contains(&"PutBucketReplication".to_owned()) && reset.contains(&"CreateBucket".to_owned()));
    assert!(reset.iter().all(|op| !op.starts_with("rustfs:") && !op.starts_with("Get")));
    let lambda = shadows("rustfs:InvokeObjectLambda");
    assert!(lambda.contains(&"GetObject".to_owned()) && lambda.contains(&"ListParts".to_owned()));
    assert!(lambda.iter().all(|op| !op.contains("Bucket")));
    assert!(
        shadows("rustfs:ListenBucketNotification")
            .iter()
            .all(|op| !op.starts_with("rustfs:")),
        "the last row of its cell shadows no extension"
    );
    let reasons: Vec<&str> = plan.extensions[4]
        .shadows
        .iter()
        .map(|shadowed| shadowed.reason.as_str())
        .collect();
    assert!(
        reasons[..34]
            .iter()
            .all(|reason| reason.starts_with("RustFS's admin router claims a GET of a bucket"))
    );
    assert!(reasons[34].starts_with("RustFS's admin router tries the `replication-check` discriminator before the `events` one"));
}

/// Positive — the rendered module carries the row, the privileged floor, the bodyless codec, the
/// overlay row with core's rendering of the selector, and the inventory record.
#[test]
fn an_extension_module_renders_its_row_floor_codec_and_record() {
    let plan = recorded_plan();
    let rendered = plan.extensions[2].render("// license\n");
    for expected in [
        "pub const NAME: &str = \"rustfs:GetReplicationMetricsV2\";",
        "AuthRequirement::new(\"s3:GetReplicationConfiguration\", ResourceShape::Bucket)",
        "Predicate::Method(http::Method::GET), Predicate::Target(TargetKind::Bucket), Predicate::QueryEquals(\"replication-metrics\", \"2\")",
        "precedence: 82,",
        "path_shape: \"/{Bucket}\",",
        "static FLOOR: OperationFloor = admin::floor(NAME);",
        "const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;",
        "impl ExtensionOperation for GetReplicationMetricsV2 {",
        "selector: \"Method(GET) ∧ Target(Bucket) ∧ QueryEquals(\\\"replication-metrics\\\", \\\"2\\\")\",",
        "evidence: &[ROUTER, record::EXTENSION_ISSUE, record::ISSUE],",
        "name: \"ReplicationExtRoute::MetricsV2\",",
        "target: \"bucket\",",
        "query: (\"replication-metrics\", \"equals:2\"),",
        "shadowed: \"rustfs:CheckReplication\"",
        "rustfs/src/admin/router.rs\";",
    ] {
        assert!(rendered.contains(expected), "{expected}\n{rendered}");
    }
    assert_eq!(rendered.matches("ShadowingDecl {").count(), 36);
    assert!(!rendered.contains("anonymous: true"));
    let lambda = plan.extensions[5].render("");
    assert!(lambda.contains("Predicate::QueryPresent(\"lambdaArn\")") && lambda.contains("ResourceShape::Object"));
    assert!(lambda.contains("path_shape: \"/{Bucket}/{Key+}\","));
    let listen = plan.extensions[6].render("");
    assert!(listen.contains("ResourceShape::Service") && listen.contains("path_shape: \"/\","));
}

/// Positive and negative — only the object lambda, the one route a RustFS client is shown to
/// presign, renders the presign-admitting floor and its evidence; the other seven keep the
/// privileged, header-only floor (ADR-0024 (f), rustfs/gateway#1576).
#[test]
fn only_the_presigned_ruling_renders_the_presigned_floor() {
    let plan = recorded_plan();
    assert_eq!(PRESIGNED_EXTENSIONS.len(), 1);
    for extended in &plan.extensions {
        let rendered = extended.render("");
        let presigned = extended.name == "MiscExtRoute::ObjectLambda[object]";
        assert_eq!(
            rendered.contains("static FLOOR: OperationFloor = admin::presigned_floor(NAME);"),
            presigned,
            "{}",
            extended.name
        );
        assert_eq!(
            rendered.contains("static FLOOR: OperationFloor = admin::floor(NAME);"),
            !presigned,
            "{}",
            extended.name
        );
        assert_eq!(
            rendered.contains("pub const PRESIGNED_EVIDENCE: &str = \"https://"),
            presigned,
            "{}",
            extended.name
        );
    }
    let lambda = plan.extensions[5].render("");
    assert!(lambda.contains("with `lambdaArn` inside the signed query"), "{lambda}");
    assert!(lambda.contains(&format!("{:?}", PRESIGNED_EXTENSIONS[0].1)), "{lambda}");
}

/// Positive and negative — only the object lambda, whose RustFS handler asks
/// `s3:GetObjectVersion` of a request naming a version, renders a version requirement; the other
/// seven keep their one action (rustfs/gateway#1576).
#[test]
fn only_the_version_ruling_renders_a_version_requirement() {
    let plan = recorded_plan();
    assert_eq!(VERSIONED_EXTENSIONS, &[("MiscExtRoute::ObjectLambda[object]", "s3:GetObjectVersion")]);
    for extended in &plan.extensions {
        let rendered = extended.render("");
        let versioned = extended.name == "MiscExtRoute::ObjectLambda[object]";
        assert_eq!(
            rendered.contains(".with_version_requirement(&VERSION_AUTH)"),
            versioned,
            "{}",
            extended.name
        );
        assert_eq!(
            rendered.contains(
                "pub static VERSION_AUTH: AuthRequirement = AuthRequirement::new(\"s3:GetObjectVersion\", ResourceShape::Object);"
            ),
            versioned,
            "{}",
            extended.name
        );
    }
}

/// Negative — a version ruling that names no extension route, names one twice, names an action
/// outside `s3:`, or names a route that addresses no object is refused; a bound one applies.
#[test]
fn n_a_stale_repeated_foreign_or_objectless_version_ruling_is_refused() {
    let refused = |rulings: &[(&str, &str)]| {
        let mut plan = recorded_plan();
        admit_versioned(&mut plan.extensions, rulings).expect_err("a refused ruling")
    };
    let lambda = "MiscExtRoute::ObjectLambda[object]";
    assert!(
        refused(&[("Ext::Gone", "s3:GetObjectVersion")]).contains("the version ruling for Ext::Gone names no extension route")
    );
    assert!(refused(&[(lambda, "s3:GetObjectVersion")]).contains("has two version rulings"));
    assert!(refused(&[(lambda, "rustfs:GetObjectVersion")]).contains("not an `s3:Action`"));
    assert!(refused(&[(lambda, "GetObjectVersion")]).contains("not an `s3:Action`"));
    assert!(
        refused(&[("ReplicationExtRoute::Check", "s3:GetObjectVersion")])
            .contains("the version ruling for ReplicationExtRoute::Check names a route that addresses no object")
    );
    let plan = recorded_plan();
    let check = plan
        .extensions
        .iter()
        .position(|extended| extended.name == lambda)
        .expect("a row");
    assert_eq!(plan.extensions[check].version_action.as_deref(), Some("s3:GetObjectVersion"));
}

/// Negative — a presigned ruling that names no extension route, names one twice, or cites no
/// `https://` evidence is refused, and the refused routes keep no presigned ruling.
#[test]
fn n_a_stale_repeated_or_unevidenced_presigned_ruling_is_refused() {
    let evidence = "https://example.invalid/e2e";
    let refused = |rulings: &[(&str, &str)]| {
        let mut plan = recorded_plan();
        admit_presigned(&mut plan.extensions, rulings).expect_err("a refused ruling")
    };
    assert!(refused(&[("Ext::Gone", evidence)]).contains("the presigned ruling for Ext::Gone names no extension route"));
    assert!(
        refused(&[
            ("ReplicationExtRoute::Check", evidence),
            ("ReplicationExtRoute::Check", evidence)
        ])
        .contains("the extension route ReplicationExtRoute::Check has two presigned rulings")
    );
    assert!(
        refused(&[("ReplicationExtRoute::Check", "http://example.invalid/e2e")])
            .contains("the presigned ruling for ReplicationExtRoute::Check cites no https:// evidence")
    );
    let mut plan = recorded_plan();
    let check = plan
        .extensions
        .iter()
        .position(|extended| extended.name == "ReplicationExtRoute::Check")
        .expect("a row");
    assert!(plan.extensions[check].presigned.is_none());
    admit_presigned(&mut plan.extensions, &[("ReplicationExtRoute::Check", evidence)]).expect("a bound ruling");
    assert_eq!(plan.extensions[check].presigned.as_deref(), Some(evidence));
}

/// Negative — an inventory extension route no ruling names, and a ruling no inventory route
/// names, are each refused.
#[test]
fn n_an_unruled_route_and_a_stale_ruling_are_refused() {
    assert!(
        refusal(vec![check()], &[]).contains("extension route Ext::Check: an extension route the generator has no ruling for")
    );
    assert!(refusal(Vec::new(), &[("Ext::Gone", "Gone")]).contains("the extension route Ext::Gone is not in the inventory"));
    assert_eq!(planned(Vec::new(), &[]).expect("no rows plan").extensions.len(), 0);
}

/// Negative — a route the inventory now records with another authentication mode or class is
/// refused, so a changed row reopens the ruling.
#[test]
fn n_an_extension_route_the_inventory_records_differently_is_refused() {
    let rulings = &[("Ext::Check", "CheckReplication")];
    let mut anonymous = check();
    anonymous.auth_mode = "anonymous".to_owned();
    assert!(refusal(vec![anonymous], rulings).contains("the inventory now records \"anonymous\""));
    let mut class = check();
    class.auth_detail = "CredentialOnly".to_owned();
    assert!(refusal(vec![class], rulings).contains("the inventory now records \"custom\" \"CredentialOnly\""));
    let mut unnamed = check();
    unnamed.iam_action = String::new();
    assert!(refusal(vec![unnamed], rulings).contains("names no RustFS action"));
}

/// Negative — a rule, target, method, key, action or operation name outside the grammar is refused.
#[test]
fn n_a_row_outside_the_grammar_is_refused() {
    let rulings = &[("Ext::Check", "CheckReplication")];
    let with = |mutate: &dyn Fn(&mut ExtensionRoute)| {
        let mut route = check();
        mutate(&mut route);
        refusal(vec![route], rulings)
    };
    assert!(with(&|r| r.query_discriminator.rule = "prefix:v".to_owned()).contains("not `present` or `equals:<value>`"));
    assert!(with(&|r| r.query_discriminator.rule = "equals".to_owned()).contains("not `present` or `equals:<value>`"));
    assert!(with(&|r| r.target = "key".to_owned()).contains("not service, bucket or object"));
    assert!(with(&|r| r.target = "Bucket".to_owned()).contains("not service, bucket or object"));
    assert!(with(&|r| r.method = "PATCH".to_owned()).contains("not one an extension row can spell"));
    assert!(with(&|r| r.method = "get".to_owned()).contains("not one an extension row can spell"));
    assert!(with(&|r| r.query_discriminator.key = "a b".to_owned()).contains("unreserved characters"));
    assert!(with(&|r| r.query_discriminator.key = String::new()).contains("unreserved characters"));
    assert!(with(&|r| r.iam_action_wire = "rustfs:CheckReplication".to_owned()).contains("IAM action spelled"));
    assert!(with(&|r| r.iam_action_wire = "NoService".to_owned()).contains("IAM action spelled"));
    assert!(refusal(vec![check()], &[("Ext::Check", "checkReplication")]).contains("not a capitalised identifier"));
    assert!(refusal(vec![check()], &[("Ext::Check", "Check-Replication")]).contains("not a capitalised identifier"));
    assert!(refusal(vec![check()], &[("Ext::Check", "")]).contains("not a capitalised identifier"));
}

/// Negative — two routes naming one operation are refused, and so is an extension operation
/// whose stem an ordinary route already derives.
#[test]
fn n_two_routes_deriving_one_operation_are_refused() {
    let twice = vec![
        check(),
        ext("Ext::Other", "GET", "bucket", "other-check", "equals:", "s3:GetReplicationConfiguration"),
    ];
    let rulings = &[("Ext::Check", "CheckReplication"), ("Ext::Other", "CheckReplication")];
    assert!(refusal(twice, rulings).contains("two routes derive the operation rustfs:CheckReplication"));
    // The ordinary route `GET /rustfs/admin/v3/x` is `GetV3X`; an extension named the same is refused.
    assert!(refusal(vec![check()], &[("Ext::Check", "GetV3X")]).contains("two routes derive the operation rustfs:GetV3X"));
}

/// Negative — a row whose precedence would reach a standard row of its cell is refused: an
/// extension row is ahead of every standard row of its method and target.
#[test]
fn n_an_extension_row_behind_a_standard_row_is_refused() {
    // Eleven service rows take precedences 80..=90, and `ListDirectoryBuckets` sits at 90.
    let routes: Vec<ExtensionRoute> = (0..11)
        .map(|index| {
            ext(
                &format!("Ext::E{index}"),
                "GET",
                "service",
                &format!("key{index}"),
                "present",
                "s3:ListAllMyBuckets",
            )
        })
        .collect();
    let rulings: Vec<(String, String)> = (0..11).map(|index| (format!("Ext::E{index}"), format!("E{index}"))).collect();
    let rulings: Vec<(&str, &str)> = rulings.iter().map(|(name, ty)| (name.as_str(), ty.as_str())).collect();
    let refused = refusal(routes, &rulings);
    assert!(
        refused.contains("rustfs:E10: its row at 90 is behind the standard row ListDirectoryBuckets at 90"),
        "{refused}"
    );
}
