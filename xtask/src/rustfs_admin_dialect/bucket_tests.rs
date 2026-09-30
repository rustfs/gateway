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

//! The generator's template, bucket and surface rules (ADR-0027, ADR-0030, ADR-0031): a template's
//! parameters are read or refused, a `{bucket}` or `{warehouse}` parameter and a listed query
//! parameter bind the operation's bucket, a trailing `/` is kept and meets no parameter, a query
//! bucket outside the rule is refused, a `/iceberg/v1` compat row is its `/_iceberg/v1` route's
//! alias, and the recorded inventory binds exactly those routes.
//!
//! Responsible for: those assertions. NOT responsible for: the fixtures and the drift check
//! (`tests.rs`), or what the generated operations do (the dialect crate's tests and goldens'
//! `rustfs_admin_dialect`).
//! Upstream: `super` and `super::tests`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::render::render_operation;
use super::rulings::{About, Form, Ruled, Ruling};
use super::tests::{
    custom, inventory, planned, planned_with, recorded_plan, refusal, refusal_with, route, ruling_for, service_route, templated,
};
use super::{Bound, Route};

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

/// Negative — two bucket parameters, an empty segment that is not a trailing `/`, an affixed
/// parameter, a parameter that is not a lowercase identifier, a repeated one, and a template the
/// inventory's list disagrees with are refused.
#[test]
fn n_a_template_outside_the_rule_is_refused() {
    for (path, params, why) in [
        (
            "/rustfs/admin/v3/tables/{warehouse}/{bucket}",
            &["warehouse", "bucket"][..],
            "two parameters name a bucket",
        ),
        ("/rustfs/admin/v3/heal//", &[][..], "an empty segment that is not a trailing '/'"),
        ("/rustfs/admin/v3//heal", &[][..], "an empty segment that is not a trailing '/'"),
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
/// literal's operation declares it; a crossed pair is ordered by its first divergence, as
/// RustFS's `matchit` orders it (ADR-0031 (d)); a different method, a different length or a
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

/// Positive — in the recorded inventory, exactly the twenty-one order-5 `{bucket}` routes (the
/// seventeen of ADR-0030 and four of the `integrity` group RustFS main added, ADR-0037) and the 49
/// order-6 `{warehouse}` routes bind their bucket by template and exactly the two compat quota
/// routes by query; the `{*prefix}` beside a bucket stays service-level; and the four quota rulings
/// plus `usage/{bucket}` are the only order-5 custom-auth routes (ADR-0030, ADR-0031).
#[test]
fn the_recorded_bucket_bindings_are_exactly_the_order_five_ones() {
    let plan = recorded_plan();
    let by_path: Vec<&str> = plan
        .declared
        .iter()
        .filter(|declared| matches!(declared.bucket, Some(Bound::Path(_))))
        .map(|declared| declared.name.as_str())
        .collect();
    assert_eq!(by_path.len(), 21 + 49, "{by_path:?}");
    let by_query: Vec<&str> = plan
        .declared
        .iter()
        .filter(|declared| matches!(declared.bucket, Some(Bound::Query(_))))
        .map(|declared| declared.name.as_str())
        .collect();
    assert_eq!(by_query, ["rustfs:GetV3GetBucketQuota", "rustfs:PutV3SetBucketQuota"]);
    for declared in &plan.declared {
        let names_bucket = declared.params.iter().any(|param| param == "bucket" || param == "warehouse");
        assert_eq!(names_bucket, matches!(declared.bucket, Some(Bound::Path(_))), "{}", declared.name);
        if declared.bucket.is_some() {
            assert!(matches!(declared.order, 5 | 6), "{}", declared.name);
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
    assert_eq!(plan.declared.len(), 310);
    assert!(plan.pending.is_empty(), "{:?}", plan.pending);
}

/// Positive — in the recorded inventory, the 50 table-catalog operations are the `/_iceberg/v1`
/// routes, each with its `/iceberg/v1` compat row as alias, named after the surface; the two
/// `config` routes are service-level and every other one binds `{warehouse}`; and the one
/// shadowing is `buckets/{warehouse}` in front of `{warehouse}/namespaces` (ADR-0031).
#[test]
fn the_recorded_table_catalog_is_one_operation_per_surface_pair() {
    let plan = recorded_plan();
    let catalog: Vec<&super::Declared> = plan.declared.iter().filter(|declared| declared.order == 6).collect();
    assert_eq!(catalog.len(), 50);
    for declared in &catalog {
        assert!(declared.path.starts_with("/_iceberg/v1/"), "{}", declared.name);
        assert_eq!(
            declared.alias.as_deref(),
            Some(declared.path.replacen("/_iceberg/", "/iceberg/", 1).as_str()),
            "{}",
            declared.name
        );
        assert!(
            declared.name.starts_with("rustfs:") && declared.name.contains("Iceberg"),
            "{}",
            declared.name
        );
        let warehouse = declared.params.iter().any(|param| param == "warehouse");
        assert_eq!(
            declared.bucket,
            warehouse.then(|| Bound::Path("warehouse".to_owned())),
            "{}",
            declared.name
        );
        assert_eq!(!warehouse, declared.path == "/_iceberg/v1/config", "{}", declared.name);
    }
    let shadows: Vec<(&str, &str)> = catalog
        .iter()
        .flat_map(|declared| {
            declared
                .shadows
                .iter()
                .map(move |shadow| (declared.name.as_str(), shadow.shadowed.as_str()))
        })
        .collect();
    assert_eq!(
        shadows,
        [("rustfs:GetIcebergBucketsByWarehouse", "rustfs:GetIcebergByWarehouseNamespaces")]
    );
    let source = render_operation(catalog[0]);
    assert!(source.contains("record::ADR_0031"), "{source}");
}

/// Positive and negative — a `/_iceberg/v1` route is declared once with its `/iceberg/v1` twin as
/// alias, and the twin itself is no operation; a canonical route without its twin, a twin that
/// differs in a fact, or a twin without its canonical route is refused (ADR-0031 (b)).
#[test]
fn n_a_compat_row_is_the_alias_of_an_identical_canonical_route_or_refused() {
    let canonical = || {
        route(
            "GET",
            "/_iceberg/v1/config",
            "table_catalog",
            "sigv4-admin",
            Some("admin:GetTableCatalog"),
        )
    };
    let twin = || {
        let mut twin = canonical();
        twin.path = "/iceberg/v1/config".to_owned();
        twin.minio_admin_alias = false;
        twin
    };
    let mut only = canonical();
    only.minio_admin_alias = false;
    let plan = planned(vec![only.clone(), twin()], &[]);
    let [declared] = plan.declared.as_slice() else {
        panic!("one operation, got {}", plan.declared.len());
    };
    assert_eq!(
        (declared.name.as_str(), declared.alias.as_deref()),
        ("rustfs:GetIcebergConfig", Some("/iceberg/v1/config"))
    );
    assert!(refusal(vec![only.clone()], &[]).contains("RustFS serves no identical route under /iceberg/v1/"));
    assert!(refusal(vec![twin()], &[]).contains("whose canonical route the inventory does not record"));
    let mut differs = twin();
    differs.iam_action_wire = Some("admin:ServerInfo".to_owned());
    assert!(refusal(vec![only, differs], &[]).contains("RustFS serves no identical route under /iceberg/v1/"));
}

/// Positive and negative — a route the inventory records as anonymous is declared only under a
/// ruling that opts in, with its own label, no account, the anonymous floor and an overlay row that
/// acknowledges it; an opt-in on a custom-auth route, a missing opt-in on an anonymous one, an IAM
/// action, an any-of rule or an account on an anonymous ruling are refused (ADR-0026 (f),
/// ADR-0032 (a)).
#[test]
fn n_an_anonymous_operation_is_the_inventorys_and_the_rulings_together() {
    fn anonymous(path: &str) -> Route {
        let mut route = route("GET", path, "oidc", "anonymous", None);
        route.auth_detail = Some("OidcBootstrap".to_owned());
        route
    }
    let providers = "/rustfs/admin/v3/oidc/providers";
    let plan = planned(vec![anonymous(providers)], ruling_for(providers));
    let declared = &plan.declared[0];
    assert!(declared.rule.anonymous && declared.rule.about.is_none());
    assert_eq!(declared.rule.render(), "rustfs:ListOidcProviders");
    let source = render_operation(declared);
    assert!(
        source.contains("static FLOOR: OperationFloor = admin::anonymous_floor(NAME);"),
        "{source}"
    );
    assert!(source.contains("    anonymous: true,\n    evidence:"), "{source}");
    assert!(source.contains("    anonymous: true,\n    rustfs_handler:"), "{source}");
    assert!(
        source.contains("record::ADR_0032") && source.contains("It admits anonymous requests"),
        "{source}"
    );

    // A privileged operation says so in all three places.
    let info = render_operation(&planned(vec![templated("GET", "/rustfs/admin/v3/info", &[])], &[]).declared[0]);
    assert!(
        info.contains("admin::floor(NAME)") && !info.contains("anonymous: true") && !info.contains("ADR_0032"),
        "{info}"
    );

    const fn form(rule: Ruled, about: Option<About>, anonymous: bool) -> Form {
        Form {
            query: None,
            rule,
            about,
            anonymous,
        }
    }
    const OPTS_IN: &[Form] = &[form(Ruled::One("rustfs:GetUser"), None, true)];
    const FORGETS: &[Form] = &[form(Ruled::One("rustfs:ListOidcProviders"), None, false)];
    const IAM: &[Form] = &[form(Ruled::One("admin:ServerInfo"), None, true)];
    const ANY_OF: &[Form] = &[form(Ruled::AnyOf(&["rustfs:A", "rustfs:B"]), None, true)];
    const ABOUT: &[Form] = &[form(Ruled::One("rustfs:ListOidcProviders"), Some(About::Caller), true)];
    let ruled = |auth_detail: &'static str, path: &'static str, forms: &'static [Form]| {
        vec![Ruling {
            method: "GET",
            path,
            auth_detail,
            forms,
        }]
    };
    let user_info = "/rustfs/admin/v3/user-info";
    let on_custom = refusal(
        vec![custom("GET", user_info, "ContextualAuthorization")],
        &ruled("ContextualAuthorization", user_info, OPTS_IN),
    );
    assert!(on_custom.contains("exactly when the inventory records an anonymous route"), "{on_custom}");
    let forgets = refusal(vec![anonymous(providers)], &ruled("OidcBootstrap", providers, FORGETS));
    assert!(forgets.contains("exactly when the inventory records an anonymous route"), "{forgets}");
    for forms in [IAM, ANY_OF, ABOUT] {
        let shaped = refusal(vec![anonymous(providers)], &ruled("OidcBootstrap", providers, forms));
        assert!(shaped.contains("an anonymous operation names exactly one action"), "{shaped}");
    }
    let unruled = refusal(vec![anonymous(providers)], &[]);
    assert!(unruled.contains("anonymous route in a migrated group has no ruling"), "{unruled}");
}

/// Positive and negative — a route listed as staying with RustFS is declared as no operation and
/// recorded with its group and reason; a listed route the fully migrated inventory does not record
/// is refused; and the recorded plan keeps exactly seven routes with RustFS (ADR-0032 (b)).
#[test]
fn n_a_staying_route_is_recorded_and_never_declared() {
    let stays: &[(&str, &str, &'static str)] = &[("GET", "/health", "the probe layer (ADR-0026 (h))")];
    let routes = || {
        vec![
            route("GET", "/health", "health", "anonymous", None),
            route("GET", "/profile/cpu", "health", "sigv4-admin", Some("admin:Profiling")),
        ]
    };
    let mut fixture = routes();
    fixture[1].minio_admin_alias = false;
    let plan = super::plan(&inventory(fixture), &[], &[], stays).expect("the staying route plans");
    assert_eq!(plan.declared.len(), 1);
    assert_eq!(
        (plan.declared[0].name.as_str(), plan.declared[0].alias.as_deref()),
        ("rustfs:GetProfileCpu", None)
    );
    assert_eq!(
        plan.staying,
        [(
            "GET".to_owned(),
            "/health".to_owned(),
            "health".to_owned(),
            "the probe layer (ADR-0026 (h))"
        )]
    );
    let mut only_profile = routes();
    only_profile.remove(0);
    only_profile[0].minio_admin_alias = false;
    let stale = super::plan(&inventory(only_profile), &[], &[], stays)
        .err()
        .expect("a stale staying route");
    assert!(stale.contains("the staying route GET /health is not in the inventory"), "{stale}");

    let recorded = recorded_plan();
    let staying: Vec<(&str, &str)> = recorded
        .staying
        .iter()
        .map(|(method, path, ..)| (method.as_str(), path.as_str()))
        .collect();
    assert_eq!(
        staying,
        [
            ("GET", "/health"),
            ("GET", "/health/ready"),
            ("GET", "/rustfs/admin/v3/object-zip-downloads/{id}.zip"),
            ("HEAD", "/health"),
            ("HEAD", "/health/ready"),
            ("POST", "/"),
            ("POST", "/rustfs/admin/v3/object-zip-downloads"),
        ]
    );
    let anonymous: Vec<&str> = recorded
        .declared
        .iter()
        .filter(|declared| declared.rule.anonymous)
        .map(|declared| declared.name.as_str())
        .collect();
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
