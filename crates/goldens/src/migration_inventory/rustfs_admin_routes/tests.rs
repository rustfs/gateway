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

//! Proves the recorded RustFS admin route inventory is read strictly and refused on every drift.
//!
//! Responsible for: the recorded document validating, its census equalling what its rows add up
//! to, and each way the document can drift — shape, format, commit, order, a self-contradicting
//! row, a count — being refused by name. NOT responsible for: whether the rows describe RustFS
//! (the generator's `--check` re-reads a checkout for that), or the proof slice.
//! Upstream: `rustfs_admin_routes.rs` and the recorded JSON. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use serde_json::Value;

use super::{
    AdminAuthMode, BodySealing, INVENTORY_FORMAT, RECORDED, RUSTFS_SOURCE_COMMIT, RouteInventoryError, RouteMethod,
    derive_census, parse_inventory, rustfs_admin_route_inventory,
};

fn recorded() -> Value {
    serde_json::from_str(RECORDED).expect("the recorded inventory is JSON")
}

fn reparse(value: &Value) -> Result<super::RustfsAdminRouteInventory, RouteInventoryError> {
    parse_inventory(&value.to_string())
}

fn route_mut(value: &mut Value, index: usize) -> &mut serde_json::Map<String, Value> {
    value["routes"][index].as_object_mut().expect("a route is an object")
}

/// The index of the first route whose auth mode is `mode`.
fn first_with_mode(value: &Value, mode: &str) -> usize {
    value["routes"]
        .as_array()
        .expect("routes is an array")
        .iter()
        .position(|route| route["auth_mode"] == mode)
        .expect("the recorded inventory holds every mode")
}

// ── the recorded document ─────────────────────────────────────────────────────────────────────

/// Positive — the recorded inventory validates, and every count in it is what its rows add up to.
#[test]
fn the_recorded_inventory_is_what_its_rows_add_up_to() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    assert_eq!(inventory.source().commit, RUSTFS_SOURCE_COMMIT);
    assert_eq!(inventory.census(), &derive_census(inventory.routes(), inventory.extension_routes()));
    assert_eq!(inventory.census().routes, inventory.routes().len());
    let rendered = inventory.render();
    assert!(rendered.contains(RUSTFS_SOURCE_COMMIT), "{rendered}");
    assert!(rendered.contains(&format!("routes={} ", inventory.routes().len())), "{rendered}");
}

/// Positive — the three rows the proof slice binds to say what the proof relies on.
#[test]
fn the_proof_rows_carry_the_facts_the_proof_slice_relies_on() {
    let inventory = rustfs_admin_route_inventory().expect("the recorded inventory validates");
    let info = inventory
        .route(RouteMethod::Get, "/rustfs/admin/v3/info")
        .expect("server info is registered");
    assert_eq!(info.auth_mode, AdminAuthMode::Sigv4Admin);
    assert_eq!(info.iam_action_wire.as_deref(), Some("admin:ServerInfo"));
    assert_eq!(info.caller_secret_body, BodySealing::None);

    let add = inventory
        .route(RouteMethod::Put, "/rustfs/admin/v3/add-service-account")
        .expect("add service account is registered");
    assert_eq!(add.auth_mode, AdminAuthMode::Sigv4Admin);
    assert_eq!(add.iam_action_wire.as_deref(), Some("admin:CreateServiceAccount"));
    assert!(add.minio_admin_alias);
    assert_eq!(add.caller_secret_body, BodySealing::RequestAndResponseOnMinioAlias);

    let metrics = inventory
        .extension_route("ReplicationExtRoute::MetricsV2")
        .expect("replication metrics v2 is claimed by query");
    assert_eq!(metrics.target, "bucket");
    assert_eq!(metrics.query_discriminator.key, "replication-metrics");
    assert_eq!(metrics.query_discriminator.rule, "equals:2");
    assert_eq!(metrics.iam_action_wire, "s3:GetReplicationConfiguration");
}

// ── shape, format and commit ──────────────────────────────────────────────────────────────────

/// Negative — a field the reader does not know is a refusal, not a field silently dropped.
#[test]
fn n_an_unknown_route_field_is_refused() {
    let mut value = recorded();
    route_mut(&mut value, 0).insert("owner".to_owned(), Value::from("nobody"));
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Shape(reason)) if reason.contains("owner")));
}

/// Negative — a field the reader needs is a refusal when it is missing.
#[test]
fn n_a_missing_route_field_is_refused() {
    let mut value = recorded();
    route_mut(&mut value, 0).remove("caller_secret_body");
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Shape(reason)) if reason.contains("caller_secret_body")));
}

/// Negative — an auth mode outside the recorded vocabulary is a refusal.
#[test]
fn n_an_unknown_auth_mode_is_refused() {
    let mut value = recorded();
    route_mut(&mut value, 0).insert("auth_mode".to_owned(), Value::from("bearer-token"));
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Shape(_))));
}

/// Negative — another row shape is a refusal even when every row still parses.
#[test]
fn n_another_format_marker_is_refused() {
    let mut value = recorded();
    value["format"] = Value::from("rustfs-admin-route-inventory/2");
    assert_eq!(
        reparse(&value).err(),
        Some(RouteInventoryError::Format("rustfs-admin-route-inventory/2".to_owned()))
    );
    assert_ne!(INVENTORY_FORMAT, "rustfs-admin-route-inventory/2");
}

/// Negative — rows from another RustFS commit are refused until the pin moves with them.
#[test]
fn n_rows_from_another_commit_are_refused() {
    let mut value = recorded();
    value["source"]["commit"] = Value::from("62cc19e937c8cac4a14f4a353405a19d19319bd7");
    assert!(matches!(reparse(&value), Err(RouteInventoryError::SourceCommit(_))));
}

// ── order ─────────────────────────────────────────────────────────────────────────────────────

/// Negative — two rows swapped are refused: a regenerated inventory diffs route by route.
#[test]
fn n_rows_out_of_order_are_refused() {
    let mut value = recorded();
    value["routes"].as_array_mut().expect("routes").swap(0, 1);
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Order(_))));
}

/// Negative — one route recorded twice is refused, even with the census moved to match.
#[test]
fn n_a_repeated_route_is_refused() {
    let mut value = recorded();
    let first = value["routes"][0].clone();
    value["routes"].as_array_mut().expect("routes").insert(1, first);
    value["census"]["routes"] = Value::from(value["routes"].as_array().expect("routes").len());
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Order(_))));
}

// ── rows that contradict themselves ───────────────────────────────────────────────────────────

/// Negative — an admin-action route without its action is refused.
#[test]
fn n_an_admin_route_without_its_action_is_refused() {
    let mut value = recorded();
    let index = first_with_mode(&value, "sigv4-admin");
    route_mut(&mut value, index).insert("iam_action".to_owned(), Value::Null);
    route_mut(&mut value, index).insert("iam_action_wire".to_owned(), Value::Null);
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Row { .. })));
}

/// Negative — an anonymous route that names an action is refused: one policy row cannot be both.
#[test]
fn n_an_anonymous_route_naming_an_action_is_refused() {
    let mut value = recorded();
    let index = first_with_mode(&value, "anonymous");
    route_mut(&mut value, index).insert("iam_action".to_owned(), Value::from("ServerInfoAdminAction"));
    route_mut(&mut value, index).insert("iam_action_wire".to_owned(), Value::from("admin:ServerInfo"));
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Row { .. })));
}

/// Negative — a custom route with a reason the route policy does not have is refused.
#[test]
fn n_a_custom_route_with_an_unknown_reason_is_refused() {
    let mut value = recorded();
    let index = first_with_mode(&value, "custom");
    route_mut(&mut value, index).insert("auth_detail".to_owned(), Value::from("TrustMe"));
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Row { .. })));
}

/// Negative — an action without a `service:Action` spelling cannot be matched by a policy.
#[test]
fn n_an_action_without_a_wire_spelling_is_refused() {
    let mut value = recorded();
    let index = first_with_mode(&value, "sigv4-admin");
    route_mut(&mut value, index).insert("iam_action_wire".to_owned(), Value::from("ServerInfo"));
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Row { .. })));
}

/// Negative — the MinIO alias flag is read off the path, not asserted beside it.
#[test]
fn n_an_alias_flag_that_disagrees_with_the_path_is_refused() {
    let mut value = recorded();
    let flipped = !value["routes"][0]["minio_admin_alias"].as_bool().expect("a flag");
    route_mut(&mut value, 0).insert("minio_admin_alias".to_owned(), Value::from(flipped));
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Row { .. })));
}

/// Negative — path parameters are read off the path too.
#[test]
fn n_path_parameters_that_disagree_with_the_path_are_refused() {
    let mut value = recorded();
    route_mut(&mut value, 0).insert("path_params".to_owned(), Value::from(vec!["invented"]));
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Row { .. })));
}

/// Negative — a path-table route cannot carry a query discriminator: the RustFS path router has
/// none, and a row saying otherwise would send a migration looking for one.
#[test]
fn n_a_path_table_route_with_a_query_discriminator_is_refused() {
    let mut value = recorded();
    let discriminator = serde_json::json!([{"key": "action", "rule": "present"}]);
    route_mut(&mut value, 0).insert("query_discriminators".to_owned(), discriminator);
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Row { .. })));
}

/// Negative — an extension route with a rule outside `present` / `equals:` is refused.
#[test]
fn n_an_extension_route_with_an_unknown_rule_is_refused() {
    let mut value = recorded();
    value["extension_routes"][0]["query_discriminator"]["rule"] = Value::from("prefix:v");
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Row { .. })));
}

// ── counts ────────────────────────────────────────────────────────────────────────────────────

/// Negative — a hand-edited total is refused: the census is what the rows add up to.
#[test]
fn n_a_hand_edited_total_is_refused() {
    let mut value = recorded();
    value["census"]["routes"] = Value::from(318);
    assert!(matches!(reparse(&value), Err(RouteInventoryError::Census { field: "routes", .. })));
}

/// Negative — a count moved between two modes, the total unchanged, is still refused.
#[test]
fn n_a_count_moved_between_modes_is_refused() {
    let mut value = recorded();
    let modes = value["census"]["by_auth_mode"].as_object_mut().expect("by_auth_mode");
    let admin = modes["sigv4-admin"].as_u64().expect("a count");
    let custom = modes["custom"].as_u64().expect("a count");
    modes.insert("sigv4-admin".to_owned(), Value::from(admin - 1));
    modes.insert("custom".to_owned(), Value::from(custom + 1));
    assert!(matches!(
        reparse(&value),
        Err(RouteInventoryError::Census {
            field: "by_auth_mode",
            ..
        })
    ));
}

/// Negative — a row dropped with every count moved to match still disagrees with RustFS's own
/// registration matrix, whose per-helper call counts are recorded beside the rows.
#[test]
fn n_a_row_dropped_with_the_census_rewritten_is_refused() {
    let mut value = recorded();
    value["routes"].as_array_mut().expect("routes").remove(0);
    let inventory: super::RustfsAdminRouteInventory = serde_json::from_value(value.clone()).expect("still the shape");
    let census = derive_census(inventory.routes(), inventory.extension_routes());
    value["census"] = serde_json::to_value(CensusJson::from(&census)).expect("a census serialises");
    assert!(matches!(
        reparse(&value),
        Err(RouteInventoryError::Census {
            field: "source.matrix_helper_calls",
            ..
        })
    ));
}

/// The census as the recorded JSON spells it, for rewriting one in a test.
#[derive(serde::Serialize)]
struct CensusJson {
    routes: usize,
    extension_routes: usize,
    by_auth_mode: std::collections::BTreeMap<String, usize>,
    by_auth_detail: std::collections::BTreeMap<String, usize>,
    by_surface: std::collections::BTreeMap<String, usize>,
    by_group: std::collections::BTreeMap<String, usize>,
    by_caller_secret_body: std::collections::BTreeMap<String, usize>,
    by_request_body: std::collections::BTreeMap<String, usize>,
    by_response_body: std::collections::BTreeMap<String, usize>,
    with_path_params: usize,
    with_minio_admin_alias: usize,
    router_admits_anonymous: usize,
    distinct_iam_actions: usize,
}

impl From<&super::InventoryCensus> for CensusJson {
    fn from(census: &super::InventoryCensus) -> Self {
        Self {
            routes: census.routes,
            extension_routes: census.extension_routes,
            by_auth_mode: census.by_auth_mode.clone(),
            by_auth_detail: census.by_auth_detail.clone(),
            by_surface: census.by_surface.clone(),
            by_group: census.by_group.clone(),
            by_caller_secret_body: census.by_caller_secret_body.clone(),
            by_request_body: census.by_request_body.clone(),
            by_response_body: census.by_response_body.clone(),
            with_path_params: census.with_path_params,
            with_minio_admin_alias: census.with_minio_admin_alias,
            router_admits_anonymous: census.router_admits_anonymous,
            distinct_iam_actions: census.distinct_iam_actions,
        }
    }
}
