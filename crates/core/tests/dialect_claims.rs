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

//! Path-prefix claims, path templates and alias rows at the core seam (ADR-0024).
//!
//! Responsible for: the shared fixtures; that a claim captures
//! exactly the path-style requests inside its prefix and nothing else; that a template matches one
//! segment per parameter and never across a separator; that one operation may carry several rows;
//! that claimed rows owe no declaration against S3 rows and still owe one against each other; and
//! the typed values a matched template extracts.
//! NOT responsible for: the refusals (`dialect_claims_refusals.rs`), the facade pipeline — service-level authorisation, the per-operation secret
//! hand-off and the posture report are `crates/gateway/tests/dialect_claims_runtime.rs`'s — or the
//! S3-table dialect rules (`dialect.rs`).
//! Upstream: `support`. Downstream: nothing.

use crate::support;

use http::Method;
use rustfs_gateway_core::dialect::{
    ClaimedRoute, ClaimedRow, Dialect, DialectError, DialectOverlay, OverlayRow, render_claimed_rows,
};
use rustfs_gateway_core::dispatch::{NO_CLAIMED_ROUTE_MESSAGE, Router, RouterBuildError};
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::{BuildError, HandlerDeadlineClass, OperationSpec, RouterBuilder};
use rustfs_gateway_core::route::{
    ArnForm, HostClass, PathClaim, PathParamError, PathTemplate, Predicate, RouteBuildError, ShadowingDecl,
};
use rustfs_gateway_sig::{OperationFloor, SigService};
use support::Req as RouteReq;

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────

pub(crate) const EVIDENCE: &[&str] = &["https://github.com/rustfs/backlog/issues/1744"];
pub(crate) const REASON: &str = "The vendor serves its admin API under this prefix, ahead of its S3 service.";

pub(crate) const ADMIN: PathClaim = PathClaim {
    prefix: "/acme/admin",
    reason: REASON,
    evidence: EVIDENCE,
};
pub(crate) const COMPAT: PathClaim = PathClaim {
    prefix: "/compat/admin",
    reason: REASON,
    evidence: EVIDENCE,
};

/// One fixture operation per index; one `impl Operation` covers all of them.
pub(crate) struct Vendor<const N: usize>;

pub(crate) const INFO: usize = 0;
pub(crate) const ADD_USER: usize = 1;
pub(crate) const GET_USER: usize = 2;
pub(crate) const USER_STATS: usize = 3;
pub(crate) const BUCKET_SHAPED: usize = 4;
pub(crate) const OBJECT_ROW: usize = 5;

pub(crate) const NAMES: [&str; 6] = [
    "acme:Info",
    "acme:AddUser",
    "acme:GetUser",
    "acme:UserStats",
    "acme:BucketQuota",
    "acme:ObjectRow",
];

pub(crate) const fn spec(name: &'static str, resource: ResourceShape) -> OperationSpec {
    OperationSpec::builder(name, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new("admin:Thing", resource))
        .build()
}

pub(crate) static SPECS: [OperationSpec; 6] = [
    spec(NAMES[0], ResourceShape::Service),
    spec(NAMES[1], ResourceShape::Service),
    spec(NAMES[2], ResourceShape::Service),
    spec(NAMES[3], ResourceShape::Service),
    spec(NAMES[4], ResourceShape::Bucket),
    spec(NAMES[5], ResourceShape::Object),
];

pub(crate) static FLOORS: [OperationFloor; 6] = [
    OperationFloor::custom(NAMES[0], SigService::S3),
    OperationFloor::custom(NAMES[1], SigService::S3),
    OperationFloor::custom(NAMES[2], SigService::S3),
    OperationFloor::custom(NAMES[3], SigService::S3),
    OperationFloor::custom(NAMES[4], SigService::S3),
    OperationFloor::custom(NAMES[5], SigService::S3),
];

impl<const N: usize> Operation for Vendor<N> {
    const NAME: &'static str = NAMES[N];
    type Input = ();
    type Output = ();
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPECS[N]
    }

    fn floor() -> &'static OperationFloor {
        &FLOORS[N]
    }
}

pub(crate) static GET: &[Predicate] = &[Predicate::Method(Method::GET)];
pub(crate) static PUT: &[Predicate] = &[Predicate::Method(Method::PUT)];

pub(crate) static INFO_ROWS: &[ClaimedRow] = &[
    ClaimedRow {
        template: "/acme/admin/v1/info",
        selector: GET,
    },
    ClaimedRow {
        template: "/compat/admin/v1/info",
        selector: GET,
    },
];
pub(crate) static ADD_USER_ROWS: &[ClaimedRow] = &[
    ClaimedRow {
        template: "/acme/admin/v1/add-user",
        selector: PUT,
    },
    ClaimedRow {
        template: "/compat/admin/v1/add-user",
        selector: PUT,
    },
];
pub(crate) static GET_USER_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/acme/admin/v1/user/{name}",
    selector: GET,
}];
pub(crate) static USER_STATS_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/acme/admin/v1/user/stats",
    selector: GET,
}];

/// The one overlap inside the claim: the literal row stands in front of the template.
pub(crate) static STATS_OVER_USER: &[ShadowingDecl] = &[ShadowingDecl {
    winner: "acme:UserStats",
    shadowed: "acme:GetUser",
    reason: "The literal statistics path is not a user named `stats`.",
    evidence: EVIDENCE,
}];

pub(crate) fn leak<T>(items: Vec<T>) -> &'static [T] {
    Box::leak(items.into_boxed_slice())
}

pub(crate) fn text(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

pub(crate) fn overlay_row(name: &'static str, precedence: u16, rows: &[ClaimedRow], resource: ResourceShape) -> OverlayRow {
    OverlayRow {
        name,
        precedence,
        selector: text(render_claimed_rows(rows)),
        action: "admin:Thing",
        resource,
        success_status: 200,
        anonymous: false,
        evidence: EVIDENCE,
    }
}

pub(crate) fn overlay(claims: Vec<PathClaim>, rows: Vec<OverlayRow>) -> &'static DialectOverlay {
    Box::leak(Box::new(DialectOverlay {
        name: "acme",
        vendor: "acme",
        operations: leak(rows),
        claims: leak(claims),
    }))
}

pub(crate) fn claimed(precedence: u16, rows: &'static [ClaimedRow], shadows: &'static [ShadowingDecl]) -> ClaimedRoute {
    ClaimedRoute {
        precedence,
        rows,
        shadows,
        bucket_param: None,
    }
}

/// The reviewed four-operation dialect: two aliased literals, a template, and the literal in front
/// of it.
pub(crate) fn acme() -> Dialect {
    let record = overlay(
        vec![ADMIN, COMPAT],
        vec![
            overlay_row(NAMES[INFO], 10, INFO_ROWS, ResourceShape::Service),
            overlay_row(NAMES[ADD_USER], 11, ADD_USER_ROWS, ResourceShape::Service),
            overlay_row(NAMES[GET_USER], 20, GET_USER_ROWS, ResourceShape::Service),
            overlay_row(NAMES[USER_STATS], 15, USER_STATS_ROWS, ResourceShape::Service),
        ],
    );
    Dialect::assemble(record)
        .declare_claimed::<Vendor<INFO>>(claimed(10, INFO_ROWS, &[]))
        .declare_claimed::<Vendor<ADD_USER>>(claimed(11, ADD_USER_ROWS, &[]))
        .declare_claimed::<Vendor<GET_USER>>(claimed(20, GET_USER_ROWS, &[]))
        .declare_claimed::<Vendor<USER_STATS>>(claimed(15, USER_STATS_ROWS, STATS_OVER_USER))
        .build()
        .expect("the reviewed fixture dialect assembles")
}

/// One claimed operation under `claims`, with an overlay that records exactly what is declared.
pub(crate) fn only<const N: usize>(claims: Vec<PathClaim>, rows: Vec<ClaimedRow>) -> Result<Dialect, Vec<DialectError>> {
    let rows = leak(rows);
    let record = overlay(claims, vec![overlay_row(NAMES[N], 10, rows, SPECS[N].auth.expect("an action").resource)]);
    Dialect::assemble(record)
        .declare_claimed::<Vendor<N>>(claimed(10, rows, &[]))
        .build()
}

pub(crate) fn refusals(result: Result<Dialect, Vec<DialectError>>) -> Vec<DialectError> {
    match result {
        Ok(dialect) => panic!("the dialect assembled: {:?}", dialect.name()),
        Err(errors) => errors,
    }
}

pub(crate) fn router(dialects: &[&Dialect]) -> Router {
    let mut builder = RouterBuilder::new();
    for dialect in dialects {
        builder = builder.dialect(dialect);
    }
    builder.build().expect("the router builds")
}

pub(crate) fn route_refusal(dialects: &[&Dialect]) -> RouteBuildError {
    let mut builder = RouterBuilder::new();
    for dialect in dialects {
        builder = builder.dialect(dialect);
    }
    match builder.build() {
        Err(BuildError::Route(RouterBuildError::Route(error))) => error,
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("the router built"),
    }
}

pub(crate) fn routed(router: &Router, request: &RouteReq) -> Option<&'static str> {
    let parts = request.parts();
    let compiled = router.resolve(&parts).map(|entry| entry.op_name);
    let readable = router.resolve_readable(&parts).map(|entry| entry.op_name);
    assert_eq!(compiled, readable, "the compiled and readable routers disagree");
    compiled
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// Positive — an operation's canonical row and its alias under a second claim reach it.
#[test]
fn a_claimed_row_and_its_alias_reach_one_operation() {
    let router = router(&[&acme()]);
    assert_eq!(routed(&router, &RouteReq::new("GET /acme/admin/v1/info")), Some("acme:Info"));
    assert_eq!(routed(&router, &RouteReq::new("GET /compat/admin/v1/info")), Some("acme:Info"));
    assert_eq!(routed(&router, &RouteReq::new("PUT /acme/admin/v1/add-user")), Some("acme:AddUser"));
    assert_eq!(routed(&router, &RouteReq::new("PUT /compat/admin/v1/add-user")), Some("acme:AddUser"));
    // Whatever the query carries: inside the claim, the S3 subresources do not exist.
    assert_eq!(routed(&router, &RouteReq::new("GET /acme/admin/v1/info?tagging&acl")), Some("acme:Info"));
}

/// Positive — a template reaches its operation, and the dispatch names the row it matched.
#[test]
fn a_template_reaches_its_operation_and_the_dispatch_names_the_row() {
    let router = router(&[&acme()]);
    let request = RouteReq::new("GET /acme/admin/v1/user/alice");
    assert_eq!(routed(&router, &request), Some("acme:GetUser"));
    let parts = request.parts();
    let claimed = router.claims().lookup(&parts);
    let entry = claimed.entry().expect("a claimed row");
    assert_eq!(entry.template().as_str(), "/acme/admin/v1/user/{name}");
    assert_eq!(entry.claim().prefix, "/acme/admin");
}

/// Positive — the literal row declared in front of the template wins for its own path.
#[test]
fn a_declared_literal_row_wins_over_the_template_it_overlaps() {
    let router = router(&[&acme()]);
    assert_eq!(routed(&router, &RouteReq::new("GET /acme/admin/v1/user/stats")), Some("acme:UserStats"));
    assert_eq!(routed(&router, &RouteReq::new("GET /acme/admin/v1/user/statsx")), Some("acme:GetUser"));
}

/// Positive — typed values: decoded once, parsed on request.
#[test]
fn a_matched_template_extracts_typed_values() {
    let template = PathTemplate::parse("/acme/admin/v1/job/{job}/part/{part}").expect("a template");
    let params = template.extract("/acme/admin/v1/job/nightly%20run/part/42").expect("a match");
    assert_eq!(params.get("job"), Some("nightly run"));
    assert_eq!(params.parse::<u32>("part"), Ok(42));
    assert_eq!(params.iter().map(|(name, _)| name).collect::<Vec<_>>(), ["job", "part"]);
}

/// Positive — claimed rows owe nothing to the S3 table: the only declaration in the whole
/// dialect is the one between two of its own rows, and the router lists both claims.
#[test]
fn claimed_rows_owe_no_declaration_against_the_s3_table() {
    let dialect = acme();
    let declarations: usize = dialect
        .claimed_operations()
        .iter()
        .map(|operation| operation.shadows().len())
        .sum();
    assert_eq!(declarations, 1);
    let router = router(&[&dialect]);
    let prefixes: Vec<_> = router
        .claims()
        .claims()
        .iter()
        .map(|installed| (installed.dialect, installed.claim.prefix))
        .collect();
    assert_eq!(prefixes, [("acme", "/acme/admin"), ("acme", "/compat/admin")]);
}

// ── what a claim captures ────────────────────────────────────────────────────────────────────

/// Negative — outside its prefix a claim changes nothing: every request routes exactly as it does
/// with no dialect installed.
#[test]
fn n_a_claim_never_captures_s3_traffic_outside_its_prefix() {
    let with = router(&[&acme()]);
    let without = router(&[]);
    for line in [
        "GET /acme",
        "GET /acme/",
        "GET /acme?location",
        "PUT /acme",
        "GET /acme/adminx",
        "GET /acme/admin.txt",
        "GET /acme/other/v1/info",
        "GET /photos/acme/admin/v1/info",
        "PUT /photos/a.png",
        "DELETE /acme/administrator/v1/info",
        "GET /Acme/admin/v1/info",
        "GET /acme/%61dmin/v1/info",
        "GET /acme%2Fadmin/v1/info",
        "GET /",
    ] {
        let request = RouteReq::new(line);
        let expected = routed(&without, &request);
        assert!(expected.is_some(), "{line} is an S3 request");
        assert_eq!(routed(&with, &request), expected, "{line}");
    }
}

/// Negative — a virtual-hosted request's path is a key: the claim never reads it.
#[test]
fn n_a_virtual_hosted_request_is_never_captured() {
    let with = router(&[&acme()]);
    let without = router(&[]);
    let request = RouteReq::new("GET /acme/admin/v1/info").virtual_hosted();
    assert_eq!(routed(&with, &request), routed(&without, &request));
    assert_eq!(routed(&with, &request), Some("GetObject"));
}

/// Negative — a claim applies on the standard endpoint only, never to an ARN in the bucket
/// position or a reserved or alternative face.
#[test]
fn n_a_non_standard_face_or_an_arn_is_never_captured() {
    let with = router(&[&acme()]);
    let without = router(&[]);
    let mut requests = vec![RouteReq::new("GET /acme/admin/v1/info").arn(ArnForm::AccessPoint)];
    for class in [
        HostClass::Accelerate,
        HostClass::Dualstack,
        HostClass::ObjectLambda,
        HostClass::Website,
    ] {
        requests.push(RouteReq::new("GET /acme/admin/v1/info").host_class(class));
    }
    for request in requests {
        assert_eq!(routed(&with, &request), routed(&without, &request));
    }
}

/// Negative — inside the claim, a request no row accepts names no operation at all: it is never
/// handed to the S3 table, and the refusal is the claim's own.
#[test]
fn n_an_unmatched_request_inside_a_claim_never_reaches_s3() {
    let router = router(&[&acme()]);
    for line in [
        "GET /acme/admin",
        "GET /acme/admin/",
        "GET /acme/admin/v1",
        "GET /acme/admin/v1/nope",
        "PUT /acme/admin/v1/info",
        "DELETE /compat/admin/v1/info",
        "GET /acme/admin/v1/info/",
        "GET /acme/admin/v1/%69nfo",
    ] {
        let request = RouteReq::new(line);
        assert_eq!(routed(&router, &request), None, "{line}");
        let refusal = router.dispatch(&request.parts()).expect_err("no row accepts it");
        assert_eq!(refusal.message(), NO_CLAIMED_ROUTE_MESSAGE, "{line}");
    }
}

/// Negative — a parameter is one segment: a separator, an encoded separator, an empty value or a
/// dot segment in any spelling never matches.
#[test]
fn n_a_template_never_matches_across_segments() {
    let router = router(&[&acme()]);
    for line in [
        "GET /acme/admin/v1/user/a/b",
        "GET /acme/admin/v1/user/a%2Fb",
        "GET /acme/admin/v1/user/a%2fb",
        "GET /acme/admin/v1/user/a%5Cb",
        "GET /acme/admin/v1/user/a%5cb",
        "GET /acme/admin/v1/user/a\\b",
        "GET /acme/admin/v1/user/",
        "GET /acme/admin/v1/user",
        "GET /acme/admin/v1/user/.",
        "GET /acme/admin/v1/user/..",
        "GET /acme/admin/v1/user/%2e%2e",
        "GET /acme/admin/v1/user/.%2E",
        "GET /acme/admin/v1/user/%2E",
    ] {
        let Ok(parts) = std::panic::catch_unwind(|| RouteReq::new(line)) else {
            continue;
        };
        assert_eq!(routed(&router, &parts), None, "{line}");
    }
    let template = PathTemplate::parse("/acme/admin/v1/user/{name}").expect("a template");
    assert!(!template.matches("/acme/admin/v1/user/a/b"));
    assert!(!template.matches("/acme/admin/v1/user/a%2Fb"));
    assert!(template.matches("/acme/admin/v1/user/a.b"));
    assert!(template.matches("/acme/admin/v1/user/..."));
}

// ── typed extraction ─────────────────────────────────────────────────────────────────────────

/// Negative — an extracted value is never a separator, a control byte or undecodable, a missing
/// parameter is named, and an unparsable one is refused without echoing its value.
#[test]
fn n_extraction_refuses_every_value_a_handler_must_not_see() {
    let template = PathTemplate::parse("/acme/admin/v1/user/{name}").expect("a template");
    for raw in ["%00", "a%0Ab", "%ff", "%zz", "a%4", "%2e"] {
        let path = format!("/acme/admin/v1/user/{raw}");
        let error = template.extract(&path).expect_err(raw);
        assert!(
            matches!(error, PathParamError::Invalid { name: "name", .. } | PathParamError::Mismatch),
            "{raw}: {error:?}"
        );
        assert!(!error.to_string().contains(raw), "the refusal echoes the value: {error}");
    }
    assert_eq!(template.extract("/acme/admin/v1/other/x").err(), Some(PathParamError::Mismatch));
    let params = template.extract("/acme/admin/v1/user/alice").expect("a match");
    assert_eq!(params.get("missing"), None);
    assert_eq!(params.parse::<u8>("missing"), Err(PathParamError::Missing { name: "missing" }));
    assert_eq!(params.parse::<u8>("name"), Err(PathParamError::Unparsable { name: "name" }));
}

/// Negative — the secret hand-off is off for every operation unless it opts in, standard or not.
#[test]
fn n_no_operation_receives_the_caller_secret_unless_it_opts_in() {
    for spec in [
        rustfs_gateway_types::dto::GetObject::spec(),
        rustfs_gateway_types::dto::PutObject::spec(),
        rustfs_gateway_types::dto::ListBuckets::spec(),
    ] {
        assert!(!spec.receives_caller_secret(), "{}", spec.name);
    }
    for spec in &SPECS {
        assert!(!spec.receives_caller_secret(), "{}", spec.name);
    }
    static OPTED_IN: OperationSpec = spec("acme:Sealed", ResourceShape::Service).hand_caller_secret_to_handler();
    assert!(OPTED_IN.receives_caller_secret());
}

// ── the catch-all (ADR-0036) ─────────────────────────────────────────────────────────────────

/// One catch-all row: everything below `logs/`.
pub(crate) static LOGS_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/acme/admin/v1/logs/{*path}",
    selector: GET,
}];

/// Positive and negative — a catch-all row reaches its operation for any rest of one byte or more,
/// across segments, and extracts that rest decoded once; a path that ends at the separator before
/// the catch-all, or before that separator, or another method, is the claim's own refusal.
#[test]
fn a_catch_all_row_reaches_its_operation_across_segments() {
    let dialect = only::<GET_USER>(vec![ADMIN], LOGS_ROWS.to_vec()).expect("a catch-all row assembles");
    let router = router(&[&dialect]);
    for (line, value) in [
        ("GET /acme/admin/v1/logs/a", "a"),
        ("GET /acme/admin/v1/logs/a/b/c", "a/b/c"),
        ("GET /acme/admin/v1/logs/a/", "a/"),
        ("GET /acme/admin/v1/logs//a", "/a"),
        ("GET /acme/admin/v1/logs/a%2Fb/c%20d", "a/b/c d"),
        ("GET /acme/admin/v1/logs/100%25", "100%"),
    ] {
        let request = RouteReq::new(line);
        assert_eq!(routed(&router, &request), Some(NAMES[GET_USER]), "{line}");
        let parts = request.parts();
        let claimed = router.claims().lookup(&parts);
        let entry = claimed.entry().expect("a claimed row");
        let params = entry.template().extract(parts.path).expect(line);
        assert_eq!(params.get("path"), Some(value), "{line}");
    }
    for line in [
        "GET /acme/admin/v1/logs/",
        "GET /acme/admin/v1/logs",
        "GET /acme/admin/v1/logsx/a",
        "PUT /acme/admin/v1/logs/a",
        "DELETE /acme/admin/v1/logs/a/b",
    ] {
        let request = RouteReq::new(line);
        assert_eq!(routed(&router, &request), None, "{line}");
        let refusal = router.dispatch(&request.parts()).expect_err("no row accepts it");
        assert_eq!(refusal.message(), NO_CLAIMED_ROUTE_MESSAGE, "{line}");
    }
}
