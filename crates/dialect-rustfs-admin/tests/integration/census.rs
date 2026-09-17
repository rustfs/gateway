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

//! The dialect's census against ADR-0024's plan: which groups are declared at which order, which
//! are pending, and which operations bind a bucket (ADR-0030, ADR-0031).
//!
//! Responsible for: those assertions over `ROUTES`, `PENDING` and the assembled dialect.
//! NOT responsible for: routing (`super`), or the binding to the inventory (goldens).
//! Upstream: `super`. Downstream: nothing.

use std::collections::{BTreeMap, BTreeSet};

use rustfs_gateway_core::dialect::BucketParam;
use rustfs_gateway_dialect_rustfs_admin::{PENDING, ROUTES, RouteRecord, STAYING};

use super::{dialect, param};

/// Positive and negative — exactly the seventeen `{bucket}` and 48 `{warehouse}` templates bind
/// their bucket (`BucketParam::Path`) and exactly the two compat quota routes bind a `bucket` query
/// parameter (`BucketParam::Query`), all of orders 5 and 6; every other operation, `{prefix}`
/// templates included, stays service-level; and every claimed entry carries its operation's
/// binding, canonical row and alias alike (ADR-0025 (c), ADR-0026 (e), ADR-0027, ADR-0030, ADR-0031).
#[test]
fn exactly_the_bucket_and_warehouse_routes_bind_their_bucket() {
    let templated: Vec<&RouteRecord> = ROUTES.iter().filter(|record| record.path.contains('{')).collect();
    assert_eq!(templated.len(), 96);
    let mut by_path = 0;
    let mut by_query = 0;
    for record in ROUTES {
        let names_bucket = record
            .path
            .split('/')
            .filter_map(param)
            .find(|segment| ["bucket", "warehouse"].contains(segment));
        let expected = match (names_bucket, record.path) {
            (Some("bucket"), _) => Some(BucketParam::Path("bucket")),
            (Some(_), _) => Some(BucketParam::Path("warehouse")),
            (None, "/rustfs/admin/v3/get-bucket-quota" | "/rustfs/admin/v3/set-bucket-quota") => {
                Some(BucketParam::Query("bucket"))
            }
            (None, _) => None,
        };
        assert_eq!(record.bucket, expected, "{}", record.operation);
        match record.bucket {
            Some(BucketParam::Path(_)) => by_path += 1,
            Some(BucketParam::Query(_)) => by_query += 1,
            None => {}
        }
        if record.bucket.is_some() {
            assert!(matches!(record.order, 5 | 6), "{}", record.operation);
            assert!(!record.anonymous, "{}", record.operation);
        }
    }
    assert_eq!((by_path, by_query), (17 + 48, 2));
    let dialect = dialect();
    let mut entries = 0;
    for operation in dialect.claimed_operations() {
        let record = ROUTES
            .iter()
            .find(|record| record.operation == operation.name())
            .expect("a record per claimed operation");
        for entry in operation.entries() {
            assert_eq!(entry.bucket_param(), record.bucket, "{}", record.operation);
            entries += 1;
        }
    }
    assert_eq!(entries, 604);
}

/// Positive — every order of ADR-0024's plan is declared, each inventory route once (the service
/// command as its four forms; the table catalog's compat rows as aliases), no group is pending, and
/// exactly seven routes stay with RustFS, each with its recorded reason (ADR-0032).
#[test]
fn every_order_is_declared_and_seven_routes_stay_with_rustfs() {
    let order_seven = ["oidc", "sts"];
    let order_five = [
        "durability_handler",
        "heal",
        "on_demand_migration",
        "quota_handler",
        "usage_prefix",
    ];
    let order_four = ["account", "idp_compat", "mfa", "replication_handler", "user"];
    let order_three = [
        "audit",
        "batch_job",
        "config_admin",
        "ilm_transition",
        "kms",
        "plugins_instances",
        "pools",
        "scanner",
        "site_replication",
        "tier",
    ];
    let mut by_group: BTreeMap<&str, BTreeSet<(&str, &str)>> = BTreeMap::new();
    for record in ROUTES {
        by_group.entry(record.group).or_default().insert((record.method, record.path));
        let order = match record.group {
            "system" => 1,
            group if order_three.contains(&group) => 3,
            group if order_four.contains(&group) => 4,
            group if order_five.contains(&group) => 5,
            "table_catalog" => 6,
            group if order_seven.contains(&group) => 7,
            "health" => 8,
            _ => 2,
        };
        assert_eq!(record.order, order, "{}", record.operation);
    }
    let counts: Vec<(&str, usize)> = by_group.iter().map(|(group, routes)| (*group, routes.len())).collect();
    assert_eq!(
        counts,
        [
            ("account", 2),
            ("audit", 3),
            ("batch_job", 5),
            ("bucket_meta", 4),
            ("cluster_snapshot", 1),
            ("config_admin", 9),
            ("diagnostics", 12),
            ("durability_handler", 3),
            ("extensions", 2),
            ("gateway_key_inventory", 1),
            ("heal", 5),
            ("health", 2),
            ("idp_compat", 13),
            ("ilm_transition", 11),
            ("inspect_archive", 1),
            ("kms", 35),
            ("mfa", 8),
            ("module_switch", 2),
            ("object_data_cache", 2),
            ("oidc", 8),
            ("on_demand_migration", 6),
            ("plugins_catalog", 1),
            ("plugins_instances", 4),
            ("pools", 6),
            ("profile_admin", 6),
            ("quota_handler", 7),
            ("rebalance", 3),
            ("replication_handler", 6),
            ("scanner", 5),
            ("site_replication", 22),
            ("sts", 1),
            ("system", 9),
            ("table_catalog", 49),
            ("tier", 7),
            ("tls_debug", 1),
            ("usage_prefix", 1),
            ("user", 37),
        ]
    );
    assert_eq!(ROUTES.len(), 303);
    assert!(PENDING.is_empty(), "{PENDING:?}");
    // 251 admin and profiling routes declared, the 98 table-catalog routes as 49 operations with
    // 49 alias rows, and seven routes that stay with RustFS: the whole inventory (ADR-0032).
    let staying: Vec<(&str, &str, &str)> = STAYING.iter().map(|route| (route.group, route.method, route.path)).collect();
    assert_eq!(
        staying,
        [
            ("health", "GET", "/health"),
            ("health", "GET", "/health/ready"),
            ("object_zip_download", "GET", "/rustfs/admin/v3/object-zip-downloads/{id}.zip"),
            ("health", "HEAD", "/health"),
            ("health", "HEAD", "/health/ready"),
            ("sts", "POST", "/"),
            ("object_zip_download", "POST", "/rustfs/admin/v3/object-zip-downloads"),
        ]
    );
    assert!(STAYING.iter().all(|route| route.reason.contains("ADR-00")));
    assert!(STAYING.iter().all(|route| {
        !ROUTES
            .iter()
            .any(|record| record.method == route.method && record.path == route.path)
    }));
    let declared: usize = by_group.values().map(BTreeSet::len).sum();
    assert_eq!(declared + 49 + STAYING.len(), 356);
}
