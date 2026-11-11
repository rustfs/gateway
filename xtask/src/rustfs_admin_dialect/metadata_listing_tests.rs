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

//! The generator's two metadata listing rows (rustfs/gateway#1588): RustFS's metadata route's
//! `?versions&metadata=true` and `?list-type=2&metadata=true` listings, planned ahead of the
//! admin router's extension rows and rendered on the standard listing floor.
//!
//! Responsible for: the recorded plan's two rows — names, precedences, both query rules, action,
//! claimer and floor — the admin router's eight rows keeping their precedences, every overlap the
//! two declare and its reason, the rendered module, and the refusals: a claimer the generator
//! does not know, a claimer and authorisation class that do not belong together, a further rule
//! outside the grammar or on the discriminator's own key, and a presigned ruling on a listing.
//! NOT responsible for: the admin router's eight rows (`extension_tests.rs`), the committed
//! output (the drift test in `tests.rs`), or routing (the dialect crate's tests).
//! Upstream: `super::extension` and `super::plan`. Downstream: nothing; a leaf test module.

use super::extension::{ExtensionRoute, QueryDiscriminator, admit_presigned};
use super::tests::{inventory, recorded_plan, route};
use super::{Plan, plan};

const VERSIONS: &str = "rustfs:ListObjectVersionsWithMetadata";
const V2: &str = "rustfs:ListObjectsV2WithMetadata";
const METADATA_ROUTE: &str = "rustfs/src/app/metadata_route.rs";

fn rule(key: &str, rule: &str) -> QueryDiscriminator {
    QueryDiscriminator {
        key: key.to_owned(),
        rule: rule.to_owned(),
    }
}

/// A metadata listing route as the inventory records one.
fn listing(name: &str, key: &str, value_rule: &str, action: &str) -> ExtensionRoute {
    ExtensionRoute {
        name: name.to_owned(),
        method: "GET".to_owned(),
        target: "bucket".to_owned(),
        query_discriminator: rule(key, value_rule),
        query_requires: vec![rule("metadata", "equals:true")],
        claimed_by: Some(METADATA_ROUTE.to_owned()),
        auth_mode: "custom".to_owned(),
        auth_detail: "SignedOrAnonymousThenBucketListing".to_owned(),
        iam_action: "ListBucketAction".to_owned(),
        iam_action_wire: action.to_owned(),
    }
}

fn v2() -> ExtensionRoute {
    listing("Meta::V2", "list-type", "equals:2", "s3:ListBucket")
}

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

/// Positive — the recorded plan starts with the two metadata listing rows at 78 and 79, versions
/// first as RustFS's selector tries it, and the admin router's eight rows keep 80 through 87.
#[test]
fn the_metadata_listing_rows_plan_first_and_move_no_admin_router_row() {
    let plan = recorded_plan();
    let rows: Vec<(&str, &str, u16, &str, &str, &str)> = plan
        .extensions
        .iter()
        .take(2)
        .map(|row| {
            (
                row.name.as_str(),
                row.operation.as_str(),
                row.precedence,
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
                "MetadataOperation::ListObjectVersions",
                VERSIONS,
                78,
                "versions",
                "present",
                "s3:ListBucketVersions"
            ),
            ("MetadataOperation::ListObjectsV2", V2, 79, "list-type", "equals:2", "s3:ListBucket"),
        ]
    );
    let admin: Vec<u16> = plan.extensions.iter().skip(2).map(|row| row.precedence).collect();
    assert_eq!(admin, [80, 81, 82, 83, 84, 85, 86, 87]);
    assert_eq!(plan.extensions.len(), 10);
}

/// Positive and negative — each listing row shadows every standard `GET` bucket row and every
/// admin-router `GET` bucket row; the versions row also shadows the V2 row, and neither shadows a
/// row of another method or target.
#[test]
fn a_metadata_listing_row_shadows_its_cell_and_every_later_listing_and_admin_row() {
    let plan = recorded_plan();
    let shadows = |operation: &str| -> Vec<(String, String)> {
        plan.extensions
            .iter()
            .find(|row| row.operation == operation)
            .expect("a planned row")
            .shadows
            .iter()
            .map(|shadowed| (shadowed.op.clone(), shadowed.reason.clone()))
            .collect()
    };
    let versions = shadows(VERSIONS);
    let v2 = shadows(V2);
    let names = |rows: &[(String, String)]| rows.iter().map(|(op, _)| op.clone()).collect::<Vec<_>>();
    for standard in [
        "ListObjectsV2",
        "ListObjectVersions",
        "ListObjects",
        "GetBucketAcl",
        "GetBucketReplication",
    ] {
        assert!(names(&versions).contains(&standard.to_owned()), "{standard}");
        assert!(names(&v2).contains(&standard.to_owned()), "{standard}");
    }
    let later =
        |rows: &[(String, String)]| -> Vec<String> { names(rows).into_iter().filter(|op| op.starts_with("rustfs:")).collect() };
    let admin = [
        "rustfs:GetReplicationResetStatus",
        "rustfs:GetReplicationMetricsV2",
        "rustfs:GetReplicationMetrics",
        "rustfs:CheckReplication",
        "rustfs:ListenBucketNotification",
    ];
    assert_eq!(later(&v2), admin);
    let mut expected = vec![V2.to_owned()];
    expected.extend(admin.iter().map(|op| (*op).to_owned()));
    assert_eq!(later(&versions), expected);
    for op in [
        "rustfs:ResetBucketReplication",
        "rustfs:InvokeObjectLambda",
        "rustfs:ListenNotification",
    ] {
        assert!(!names(&versions).contains(&op.to_owned()) && !names(&v2).contains(&op.to_owned()), "{op}");
    }
    let reason = |rows: &[(String, String)], op: &str| -> String {
        rows.iter()
            .find(|(name, _)| name == op)
            .map(|(_, reason)| reason.clone())
            .expect("declared")
    };
    assert!(
        reason(&versions, V2)
            .starts_with("RustFS's metadata route tries the `versions` discriminator before the `list-type` one"),
        "{}",
        reason(&versions, V2)
    );
    assert!(reason(&v2, "rustfs:CheckReplication").starts_with("RustFS asks its metadata route before its admin router"));
    assert!(reason(&v2, "ListObjectsV2").starts_with(
        "RustFS's metadata route claims a GET of a bucket whose query's first `list-type` value is `2`, and whose \
         query's first `metadata` value is `true`, before its admin router and its S3 service"
    ));
}

/// Positive — the rendered module carries both query rules, the standard listing floor, the
/// listing action, the metadata route as evidence and the record's further rule.
#[test]
fn a_metadata_listing_module_renders_both_rules_and_the_listing_floor() {
    let plan = recorded_plan();
    let rendered = plan.extensions[1].render("");
    for expected in [
        "pub const NAME: &str = \"rustfs:ListObjectsV2WithMetadata\";",
        "AuthRequirement::new(\"s3:ListBucket\", ResourceShape::Bucket)",
        "Predicate::Method(http::Method::GET), Predicate::Target(TargetKind::Bucket), \
         Predicate::QueryEquals(\"list-type\", \"2\"), Predicate::QueryEquals(\"metadata\", \"true\")",
        "selector: \"Method(GET) ∧ Target(Bucket) ∧ QueryEquals(\\\"list-type\\\", \\\"2\\\") ∧ QueryEquals(\\\"metadata\\\", \\\"true\\\")\",",
        "precedence: 79,",
        "static FLOOR: OperationFloor = admin::listing_floor(NAME);",
        "const REQUEST_BODY: RequestBodyMode = RequestBodyMode::None;",
        "requires: &[(\"metadata\", \"equals:true\")],",
        "query: (\"list-type\", \"equals:2\"),",
        "rustfs/src/app/metadata_route.rs\";",
        "evidence: &[ROUTER, record::METADATA_LISTING_ISSUE, record::ISSUE],",
        "`GET /{Bucket}?list-type=2&metadata=true`",
    ] {
        assert!(rendered.contains(expected), "{expected}\n{rendered}");
    }
    for absent in [
        "admin::floor(NAME)",
        "admin::presigned_floor(NAME)",
        "rustfs/src/admin/router.rs",
        "VERSION_AUTH",
    ] {
        assert!(!rendered.contains(absent), "{absent}\n{rendered}");
    }
    let versions = plan.extensions[0].render("");
    assert!(versions.contains("Predicate::QueryPresent(\"versions\"), Predicate::QueryEquals(\"metadata\", \"true\")"));
    assert!(versions.contains("AuthRequirement::new(\"s3:ListBucketVersions\", ResourceShape::Bucket)"));
    // An admin-router row keeps its one rule, its floor and an empty further-rule list.
    let check = plan.extensions[6].render("");
    assert!(check.contains("requires: &[],") && check.contains("admin::floor(NAME)"), "{check}");
}

/// Negative — a claimer the generator has no row shape for is refused.
#[test]
fn n_an_unknown_claimer_is_refused() {
    let mut route = v2();
    route.claimed_by = Some("rustfs/src/app/other_route.rs".to_owned());
    let refused = refusal(vec![route], &[("Meta::V2", "ListObjectsV2WithMetadata")]);
    assert!(refused.contains("is not a claimer the generator knows"), "{refused}");
}

/// Negative — a claimer and an authorisation class that do not belong together are refused, both
/// ways: the metadata route's listing class on the admin router, and the admin class on a listing.
#[test]
fn n_a_claimer_with_the_other_claimers_auth_class_is_refused() {
    let rulings = &[("Meta::V2", "ListObjectsV2WithMetadata")];
    let mut admin_class = v2();
    admin_class.auth_detail = "SignatureRequiredThenHandlerCheck".to_owned();
    let refused = refusal(vec![admin_class], rulings);
    assert!(refused.contains("\"SignatureRequiredThenHandlerCheck\""), "{refused}");
    let mut on_router = v2();
    on_router.claimed_by = None;
    let refused = refusal(vec![on_router], rulings);
    assert!(refused.contains("\"SignedOrAnonymousThenBucketListing\""), "{refused}");
}

/// Negative — a further rule outside the grammar, on a reserved key, or on the discriminator's own
/// key is refused.
#[test]
fn n_a_further_rule_outside_the_grammar_is_refused() {
    let rulings = &[("Meta::V2", "ListObjectsV2WithMetadata")];
    let with = |requires: Vec<QueryDiscriminator>| {
        let mut route = v2();
        route.query_requires = requires;
        refusal(vec![route], rulings)
    };
    assert!(with(vec![rule("metadata", "prefix:t")]).contains("not `present` or `equals:<value>`"));
    assert!(with(vec![rule("meta data", "equals:true")]).contains("unreserved characters"));
    assert!(with(vec![rule("", "equals:true")]).contains("unreserved characters"));
    assert!(with(vec![rule("list-type", "equals:2")]).contains("names the query key \"list-type\" twice"));
    assert!(
        with(vec![rule("metadata", "equals:true"), rule("metadata", "present")])
            .contains("names the query key \"metadata\" twice")
    );
}

/// Negative — two listing rows whose further rules cannot hold together do not overlap, and a
/// listing row never shadows an earlier row.
#[test]
fn n_rows_whose_rules_cannot_meet_declare_no_overlap() {
    let mut other = listing("Meta::Other", "versions", "present", "s3:ListBucketVersions");
    other.query_requires = vec![rule("metadata", "equals:false")];
    let plan = planned(
        vec![other, v2()],
        &[("Meta::Other", "OtherListing"), ("Meta::V2", "ListObjectsV2WithMetadata")],
    )
    .expect("two rows plan");
    assert!(plan.extensions[0].shadows.iter().all(|shadowed| shadowed.op != V2));
    assert!(
        plan.extensions[1]
            .shadows
            .iter()
            .all(|shadowed| !shadowed.op.starts_with("rustfs:"))
    );
}

/// Negative — a presigned ruling on a listing row is refused: its floor is the standard listing
/// floor, and a presign-admitting vendor floor is for the admin router's routes only (ADR-0049).
#[test]
fn n_a_presigned_ruling_on_a_listing_row_is_refused() {
    let mut plan = recorded_plan();
    let refused = admit_presigned(
        &mut plan.extensions,
        &[("MetadataOperation::ListObjectsV2", "https://example.com/evidence")],
    )
    .expect_err("refused");
    assert!(refused.contains("is on the standard listing floor"), "{refused}");
}
