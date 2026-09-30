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

//! The generator's catch-all rule (ADR-0036) and the inventory refreshed from RustFS main
//! (ADR-0037): a trailing `{*name}` is declared, named and cited, or refused with its reason, an
//! overlap through one is refused, and the recorded plan declares RustFS main's new routes with the
//! facts RustFS gives them and none of the route it removed.
//!
//! Responsible for: those assertions. NOT responsible for: the fixtures and the drift check
//! (`tests.rs`), the bucket rules (`bucket_tests.rs`), or what the generated operations do (the
//! dialect crate's tests and goldens' `rustfs_admin_dialect`).
//! Upstream: `super` and `super::tests`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::render::render_operation;
use super::tests::{planned, recorded_plan, refusal, templated};
use super::{Bound, INVENTORY, Inventory, repo_root};

/// RustFS main's heal catch-all, as the inventory records it (`route_policy.rs:355` at
/// `3268c42e`).
const HEAL_REST: &str = "/rustfs/admin/v3/heal/{bucket}/{*prefix}";

fn heal(path: &str, params: &[&str]) -> super::Route {
    let mut route = templated("POST", path, params);
    route.group = "heal".to_owned();
    route.iam_action_wire = Some("admin:Heal".to_owned());
    route
}

// ── the catch-all (ADR-0036) ─────────────────────────────────────────────────────────────────

/// Positive — a template ending in `{*name}` is declared with the name its handler reads, the
/// bucket beside it bound, the catch-all recorded, the name derived as for a parameter, and its
/// module citing ADR-0036 and saying what the handler must not do.
#[test]
fn a_catch_all_template_is_declared_with_its_name_and_its_bucket() {
    let plan = planned(vec![heal(HEAL_REST, &["bucket", "*prefix"])], &[]);
    let declared = &plan.declared[0];
    assert_eq!(declared.name, "rustfs:PostV3HealByBucketByPrefix");
    assert_eq!(declared.params, ["bucket", "prefix"]);
    assert_eq!(declared.catch_all.as_deref(), Some("prefix"));
    assert_eq!(declared.bucket, Some(Bound::Path("bucket".to_owned())));
    assert_eq!(declared.alias.as_deref(), Some("/minio/admin/v3/heal/{bucket}/{*prefix}"));
    let source = render_operation(declared);
    assert!(source.contains("record::ADR_0036"), "{source}");
    assert!(source.contains("is a catch-all (ADR-0036)"), "{source}");
    assert!(source.contains("must not decode it again"), "{source}");
    // A one-segment `{prefix}` is no catch-all and cites nothing about one.
    let plan = planned(vec![heal("/rustfs/admin/v3/heal/{bucket}/{prefix}", &["bucket", "prefix"])], &[]);
    assert_eq!(plan.declared[0].catch_all, None);
    assert!(!render_operation(&plan.declared[0]).contains("ADR_0036"));
}

/// Negative — a catch-all that is not the last segment, whose name is not a lowercase identifier,
/// that would be the bucket, that repeats another parameter, or that the inventory spells another
/// way is refused, never declared.
#[test]
fn n_a_catch_all_outside_its_rule_is_refused() {
    for (path, params, why) in [
        ("/rustfs/admin/v3/heal/{*prefix}/x", &["*prefix"][..], "is not the last segment"),
        ("/rustfs/admin/v3/heal/{*prefix}/", &["*prefix"][..], "is not the last segment"),
        ("/rustfs/admin/v3/heal/{*Prefix}", &["*Prefix"][..], "is not a lowercase identifier"),
        ("/rustfs/admin/v3/heal/{*}", &["*"][..], "is not a lowercase identifier"),
        ("/rustfs/admin/v3/heal/{**prefix}", &["**prefix"][..], "is not a lowercase identifier"),
        ("/rustfs/admin/v3/heal/{*bucket}", &["*bucket"][..], "would be a bucket"),
        ("/rustfs/admin/v3/heal/{*warehouse}", &["*warehouse"][..], "would be a bucket"),
        ("/rustfs/admin/v3/heal/{prefix}/{*prefix}", &["prefix", "*prefix"][..], "appears twice"),
        ("/rustfs/admin/v3/heal/{bucket}/{*prefix}", &["bucket", "prefix"][..], "the inventory"),
    ] {
        let error = refusal(vec![heal(path, params)], &[]);
        assert!(error.contains(why), "{path}: {error}");
    }
}

/// Negative and positive — a route that meets a catch-all's path is refused, as is a catch-all
/// that reaches another's paths, because no generator rule orders them; RustFS's three heal routes
/// meet nowhere, and neither does another method on the same path.
#[test]
fn n_an_overlap_through_a_catch_all_is_refused() {
    for other in [
        heal("/rustfs/admin/v3/heal/{bucket}/status", &["bucket"]),
        heal("/rustfs/admin/v3/heal/{bucket}/{kind}", &["bucket", "kind"]),
        heal("/rustfs/admin/v3/heal/{bucket}/a/b/", &["bucket"]),
        heal("/rustfs/admin/v3/heal/{bucket}/x/{*rest}", &["bucket", "*rest"]),
        heal("/rustfs/admin/v3/{*all}", &["*all"]),
    ] {
        let path = other.path.clone();
        let error = refusal(vec![heal(HEAL_REST, &["bucket", "*prefix"]), other], &[]);
        assert!(error.contains("overlap through a catch-all"), "{path}: {error}");
    }
    let plan = planned(
        vec![
            heal("/rustfs/admin/v3/heal/", &[]),
            heal("/rustfs/admin/v3/heal/{bucket}", &["bucket"]),
            heal(HEAL_REST, &["bucket", "*prefix"]),
            {
                let mut read = heal("/rustfs/admin/v3/heal/{bucket}/status", &["bucket"]);
                read.method = "GET".to_owned();
                read
            },
        ],
        &[],
    );
    assert_eq!(plan.declared.len(), 4);
    assert!(plan.declared.iter().all(|declared| declared.shadows.is_empty()));
}

// ── the refresh from RustFS main (ADR-0037) ──────────────────────────────────────────────────

/// Positive — the recorded inventory is RustFS main's at `3268c42e`, and its plan declares the
/// integrity group at order 5: every `{bucket}` route bound, `job_id` service-level, each route's
/// own admin action, and only the two writes reading a body and holding the caller's secret, as
/// the variants of RustFS's one handler do (`integrity.rs:40-158`).
#[test]
fn the_recorded_integrity_group_is_order_five_with_only_its_writes_sealed() {
    let recorded = std::fs::read_to_string(repo_root().join(INVENTORY)).expect("the inventory");
    let inventory: Inventory = serde_json::from_str(&recorded).expect("the inventory parses");
    assert_eq!(inventory.source.commit, "3268c42e00b375859b4535d53fe219b02d7bfe31");
    let plan = recorded_plan();
    let integrity: Vec<String> = plan
        .declared
        .iter()
        .filter(|declared| declared.group == "integrity")
        .map(|declared| {
            format!(
                "{} {} order={} bucket={:?} params={:?} secret={} body={} {}",
                declared.name,
                declared.rule.render(),
                declared.order,
                declared.bucket,
                declared.params,
                declared.caller_secret,
                declared.request_body,
                declared.handler,
            )
        })
        .collect();
    assert_eq!(
        integrity,
        [
            "rustfs:GetV3IntegrityReadiness admin:ServerInfo order=5 bucket=None params=[] secret=false body=NotRead \
             Handler(Route::Readiness)",
            "rustfs:GetV3IntegrityByBucketInventory admin:InspectData order=5 bucket=Some(Path(\"bucket\")) \
             params=[\"bucket\"] secret=false body=NotRead Handler(Route::Inventory)",
            "rustfs:GetV3IntegrityByBucketJobsByJobId admin:DescribeBatchJob order=5 bucket=Some(Path(\"bucket\")) \
             params=[\"bucket\", \"job_id\"] secret=false body=NotRead Handler(Route::Status)",
            "rustfs:PostV3IntegrityByBucketJobs admin:StartBatchJob order=5 bucket=Some(Path(\"bucket\")) \
             params=[\"bucket\"] secret=true body=Buffered Handler(Route::Create)",
            "rustfs:PostV3IntegrityByBucketJobsByJobIdControl admin:StartBatchJob order=5 bucket=Some(Path(\"bucket\")) \
             params=[\"bucket\", \"job_id\"] secret=true body=Buffered Handler(Route::Control)",
        ]
    );
}

/// Positive and negative — the recorded plan declares RustFS main's other new routes with their
/// own actions, keeps the heal operation's name on its catch-all, and declares no operation for
/// the `v3/metrics` route RustFS renamed to `v3/realtime` (ADR-0037 (c), (d)).
#[test]
fn the_recorded_refresh_declares_rustfs_mains_routes_and_none_it_removed() {
    let plan = recorded_plan();
    let find = |name: &str| plan.declared.iter().find(|declared| declared.name == name);
    let realtime = find("rustfs:GetV3Realtime").expect("realtime is declared");
    assert_eq!(
        (realtime.path.as_str(), realtime.rule.render(), realtime.response_body, realtime.order),
        ("/rustfs/admin/v3/realtime", "admin:GetMetrics".to_owned(), "Streamed", 1)
    );
    assert!(find("rustfs:GetV3Metrics").is_none());
    assert!(plan.declared.iter().all(|declared| !declared.path.ends_with("/v3/metrics")));
    let subscriptions = find("rustfs:GetV3TargetByTargetTypeByTargetNameSubscriptions").expect("subscriptions");
    assert_eq!(
        (subscriptions.rule.render(), subscriptions.params.clone(), subscriptions.bucket.clone()),
        (
            "admin:GetBucketTarget".to_owned(),
            vec!["target_type".to_owned(), "target_name".to_owned()],
            None
        )
    );
    let backfill = find("rustfs:PostIcebergByWarehouseCatalogWarehouseIndexBackfill").expect("backfill");
    assert_eq!(
        (backfill.rule.render(), backfill.alias.as_deref(), backfill.bucket.clone(), backfill.order),
        (
            "admin:MigrateTableCatalog".to_owned(),
            Some("/iceberg/v1/{warehouse}/catalog/warehouse-index/backfill"),
            Some(Bound::Path("warehouse".to_owned())),
            6
        )
    );
    let heal = find("rustfs:PostV3HealByBucketByPrefix").expect("the heal catch-all");
    assert_eq!(
        (heal.path.as_str(), heal.catch_all.as_deref(), heal.params.clone()),
        (HEAL_REST, Some("prefix"), vec!["bucket".to_owned(), "prefix".to_owned()])
    );
    assert_eq!(plan.declared.iter().filter(|declared| declared.catch_all.is_some()).count(), 1);
}
