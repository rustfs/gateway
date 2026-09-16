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

//! The generator's order-5 rules (ADR-0030): a `{bucket}` template parameter and a listed query
//! parameter bind the operation's bucket, a trailing `/` is kept and meets no parameter, a query
//! bucket outside the rule is refused, and the recorded inventory binds exactly the order-5 routes.
//!
//! Responsible for: those assertions. NOT responsible for: the fixtures and the drift check
//! (`tests.rs`), or what the generated operations do (the dialect crate's tests and goldens'
//! `rustfs_admin_dialect`).
//! Upstream: `super` and `super::tests`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::Bound;
use super::render::render_operation;
use super::tests::{custom, planned, planned_with, recorded_plan, refusal_with, ruling_for, service_route, templated};

/// Positive — a `{bucket}` template binds its bucket (`BucketParam::Path`) and declares
/// `ResourceShape::Bucket`, the bucket stays among the decoded parameters, and the overlay row
/// records the binding after the rows; a listed query parameter binds it as `BucketParam::Query`;
/// any other template stays service-level (ADR-0025 (c), ADR-0026 (e), ADR-0027, ADR-0030).
#[test]
fn a_bucket_parameter_or_a_listed_query_parameter_is_the_operations_bucket() {
    let plan = planned_with(
        vec![
            templated("POST", "/rustfs/admin/v3/heal/{bucket}/{prefix}", &["bucket", "prefix"]),
            templated("PUT", "/rustfs/admin/v3/set-bucket-quota", &[]),
            templated("GET", "/rustfs/admin/v3/tier/{tiername}", &["tiername"]),
        ],
        &[],
        &[("PUT", "/rustfs/admin/v3/set-bucket-quota", "bucket")],
    );
    let [by_path, by_query, service] = plan.declared.as_slice() else {
        panic!("three operations, got {}", plan.declared.len());
    };
    assert_eq!(by_path.bucket, Some(Bound::Path("bucket".to_owned())));
    assert_eq!(by_path.params, ["bucket", "prefix"]);
    assert_eq!(
        by_path.rule.expression("ResourceShape::Bucket"),
        "AuthRequirement::new(\"admin:SetTier\", ResourceShape::Bucket)"
    );
    let source = render_operation(by_path);
    assert!(
        source.contains("pub const BUCKET: BucketParam = BucketParam::Path(\"bucket\");"),
        "{source}"
    );
    assert!(source.contains("const BUCKET: Option<BucketParam> = Some(BUCKET);"), "{source}");
    assert!(source.contains("resource: ResourceShape::Bucket,"), "{source}");
    assert!(source.contains("bucket: Some(BUCKET),"), "{source}");
    assert!(source.contains("∧ Method(POST) ⇒ BucketParam(\\\"bucket\\\")\","), "{source}");
    assert!(source.contains("Its other path parameter (`prefix`) names no bucket"), "{source}");
    assert!(source.contains("record::ADR_0030"), "{source}");
    assert_eq!(by_query.bucket, Some(Bound::Query("bucket")));
    let source = render_operation(by_query);
    assert!(
        source.contains("pub const BUCKET: BucketParam = BucketParam::Query(\"bucket\");"),
        "{source}"
    );
    assert!(source.contains("⇒ BucketQuery(\\\"bucket\\\")\","), "{source}");
    assert!(source.contains("record::ADR_0026, record::ADR_0030"), "{source}");
    assert_eq!(service.bucket, None);
    let source = render_operation(service);
    assert!(
        source.contains("resource: ResourceShape::Service,") && source.contains("bucket: None,"),
        "{source}"
    );
    assert!(!source.contains("BucketParam") && !source.contains("ADR_0030"), "{source}");
}

/// Positive — a route RustFS registers with a trailing `/` keeps it: the template ends in an empty
/// literal, the name drops it, the alias keeps it, no parameter is read, and the module says so;
/// it meets no parameter, so it and `heal/{bucket}` declare no shadowing (ADR-0030).
#[test]
fn a_trailing_slash_is_kept_and_meets_no_parameter() {
    let plan = planned(
        vec![
            templated("POST", "/rustfs/admin/v3/heal/", &[]),
            templated("POST", "/rustfs/admin/v3/heal/{bucket}", &["bucket"]),
        ],
        &[],
    );
    let [heal, by_bucket] = plan.declared.as_slice() else {
        panic!("two operations, got {}", plan.declared.len());
    };
    assert_eq!((heal.name.as_str(), heal.stem.as_str()), ("rustfs:PostV3Heal", "post_v3_heal"));
    assert_eq!(heal.alias.as_deref(), Some("/minio/admin/v3/heal/"));
    assert!(heal.params.is_empty() && heal.bucket.is_none() && heal.shadows.is_empty());
    assert!(by_bucket.shadows.is_empty());
    let source = render_operation(heal);
    assert!(source.contains("template: \"/rustfs/admin/v3/heal/\""), "{source}");
    assert!(source.contains("RustFS registers this route with its trailing `/`"), "{source}");
    assert!(source.contains("record::ADR_0030"), "{source}");
}

/// Negative — a route naming its bucket both in the template and in the query, a query bucket
/// spelled outside the unreserved set, one that is the query key selecting the form, one a
/// subject rule also reads, and one listed for no migrated route are refused.
#[test]
fn n_a_query_bucket_outside_the_rule_is_refused() {
    let twice = refusal_with(
        vec![templated("GET", "/rustfs/admin/v3/quota/{bucket}", &["bucket"])],
        &[],
        &[("GET", "/rustfs/admin/v3/quota/{bucket}", "bucket")],
    );
    assert!(twice.contains("names its bucket twice"), "{twice}");
    let spelled = refusal_with(
        vec![templated("GET", "/rustfs/admin/v3/get-bucket-quota", &[])],
        &[],
        &[("GET", "/rustfs/admin/v3/get-bucket-quota", "bucket name")],
    );
    assert!(spelled.contains("RFC 3986 unreserved characters"), "{spelled}");
    let selects = refusal_with(
        vec![service_route()],
        ruling_for("/rustfs/admin/v3/service"),
        &[("POST", "/rustfs/admin/v3/service", "action")],
    );
    assert!(selects.contains("not the query key that selects the form"), "{selects}");
    let shared = refusal_with(
        vec![custom("GET", "/rustfs/admin/v3/user-info", "ContextualAuthorization")],
        ruling_for("/rustfs/admin/v3/user-info"),
        &[("GET", "/rustfs/admin/v3/user-info", "access-key")],
    );
    assert!(shared.contains("read from different query parameters"), "{shared}");
    let stale = refusal_with(
        vec![service_route()],
        ruling_for("/rustfs/admin/v3/service"),
        &[("GET", "/rustfs/admin/v3/get-bucket-quota", "bucket")],
    );
    assert!(stale.contains("names no route of a migrated group"), "{stale}");
}

/// Positive — in the recorded inventory, exactly the seventeen order-5 `{bucket}` routes bind their
/// bucket by template and exactly the two compat quota routes by query; the `{prefix}` beside a
/// bucket stays service-level; and the four quota rulings plus `usage/{bucket}` are the only
/// order-5 custom-auth routes (ADR-0030).
#[test]
fn the_recorded_bucket_bindings_are_exactly_the_order_five_ones() {
    let plan = recorded_plan();
    let by_path: Vec<&str> = plan
        .declared
        .iter()
        .filter(|declared| matches!(declared.bucket, Some(Bound::Path(_))))
        .map(|declared| declared.name.as_str())
        .collect();
    assert_eq!(by_path.len(), 17, "{by_path:?}");
    let by_query: Vec<&str> = plan
        .declared
        .iter()
        .filter(|declared| matches!(declared.bucket, Some(Bound::Query(_))))
        .map(|declared| declared.name.as_str())
        .collect();
    assert_eq!(by_query, ["rustfs:GetV3GetBucketQuota", "rustfs:PutV3SetBucketQuota"]);
    for declared in &plan.declared {
        let names_bucket = declared.params.iter().any(|param| param == "bucket");
        assert_eq!(names_bucket, matches!(declared.bucket, Some(Bound::Path(_))), "{}", declared.name);
        if declared.bucket.is_some() {
            assert_eq!(declared.order, 5, "{}", declared.name);
        }
        if declared.name == "rustfs:PostV3HealByBucketByPrefix" {
            assert_eq!(declared.params, ["bucket", "prefix"]);
        }
    }
    let ruled: Vec<(&str, &str)> = plan
        .declared
        .iter()
        .filter(|declared| declared.order == 5 && declared.ruled.is_some())
        .map(|declared| (declared.name.as_str(), declared.rule.render()))
        .map(|(name, rendered)| (name, Box::leak(rendered.into_boxed_str()) as &str))
        .collect();
    assert_eq!(
        ruled,
        [
            ("rustfs:GetV3GetBucketQuota", "s3:GetBucketQuota"),
            ("rustfs:GetV3QuotaStatsByBucket", "s3:GetBucketQuota"),
            ("rustfs:GetV3QuotaByBucket", "s3:GetBucketQuota"),
            ("rustfs:GetV3UsageByBucket", "anyOf(admin:DataUsageInfo, s3:ListBucket)"),
            ("rustfs:PostV3QuotaCheckByBucket", "s3:GetBucketQuota"),
        ]
    );
    assert_eq!(plan.declared.len(), 243);
    assert_eq!(
        plan.pending,
        [
            ("health".to_owned(), 8, 6),
            ("object_zip_download".to_owned(), 7, 2),
            ("oidc".to_owned(), 7, 8),
            ("sts".to_owned(), 7, 2),
            ("table_catalog".to_owned(), 6, 98),
        ]
    );
}
