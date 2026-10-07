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

//! A dialect's form claims (ADR-0041): what one covers once installed, on every host, and every
//! refusal of one, each pinned to its own variant.
//!
//! Responsible for: the requests a form claim takes away from path claims and the S3 table, the
//! media-type and path spellings it does and does not cover, the dispatch it produces, the claim
//! grammar, an overlay row that does not record the claim, a non-service resource, and overlaps
//! inside one dialect, across two, and with a path claim.
//! NOT responsible for: what the facade does with a form-claimed request (authentication, the body,
//! the answer) — `crates/goldens/src/rustfs_admin_dialect/sts_tests.rs` — or path claims
//! (`dialect_claims.rs`, `dialect_claims_refusals.rs`).
//! Upstream: `dialect_claims`'s fixtures. Downstream: nothing.

use http::Method;
use rustfs_gateway_core::dialect::{
    ClaimedRow, Dialect, DialectError, DialectOverlay, FormRoute, OverlayRow, render_claimed_rows,
};
use rustfs_gateway_core::dispatch::NO_ROUTE_MESSAGE;
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec, RouterBuilder};
use rustfs_gateway_core::route::{
    ClaimLookup, FormClaim, FormClaimRejection, HostClass, PathClaim, Predicate, RouteBuildError, TargetKind,
};
use rustfs_gateway_sig::{OperationFloor, SigService};

use crate::dialect_claims::{EVIDENCE, REASON, leak, route_refusal, routed, router, text};
use crate::support::Req as RouteReq;

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────

const FORM: &str = "application/x-www-form-urlencoded";

const TOKEN_CLAIM: FormClaim = FormClaim {
    path: "/",
    reason: REASON,
    evidence: EVIDENCE,
};

/// One fixture operation per index.
struct Form<const N: usize>;

const TOKEN: usize = 0;
const SECOND: usize = 1;
const BUCKETED: usize = 2;
const PATHED: usize = 3;

const NAMES: [&str; 4] = ["acme:Token", "acme:SecondToken", "acme:BucketToken", "acme:PathToken"];

const fn spec(name: &'static str, resource: ResourceShape) -> OperationSpec {
    OperationSpec::builder(name, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new("acme:IssueToken", resource))
        .build()
}

static SPECS: [OperationSpec; 4] = [
    spec(NAMES[0], ResourceShape::Service),
    spec(NAMES[1], ResourceShape::Service),
    spec(NAMES[2], ResourceShape::Bucket),
    spec(NAMES[3], ResourceShape::Service),
];

static FLOORS: [OperationFloor; 4] = [
    OperationFloor::custom(NAMES[0], SigService::Sts),
    OperationFloor::custom(NAMES[1], SigService::Sts),
    OperationFloor::custom(NAMES[2], SigService::Sts),
    OperationFloor::custom(NAMES[3], SigService::Sts),
];

impl<const N: usize> Operation for Form<N> {
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

/// A handler that answers nothing in particular: dispatch only checks that one is registered.
struct Issuer;

impl rustfs_gateway_core::Handler<Form<TOKEN>> for Issuer {
    async fn call(&self, _request: rustfs_gateway_core::Req<Form<TOKEN>>) -> rustfs_gateway_core::HandlerResult<Form<TOKEN>> {
        Ok(rustfs_gateway_core::Resp::new(()))
    }
}

fn row(name: &'static str, claim: &FormClaim, resource: ResourceShape) -> OverlayRow {
    OverlayRow {
        name,
        precedence: 1,
        selector: text(claim.render()),
        action: "acme:IssueToken",
        resource,
        success_status: 200,
        anonymous: false,
        evidence: EVIDENCE,
    }
}

fn overlay(name: &'static str, claims: Vec<PathClaim>, rows: Vec<OverlayRow>) -> &'static DialectOverlay {
    Box::leak(Box::new(DialectOverlay {
        name,
        vendor: "acme",
        operations: leak(rows),
        claims: leak(claims),
    }))
}

fn claim(path: &'static str) -> &'static FormClaim {
    Box::leak(Box::new(FormClaim {
        path,
        reason: REASON,
        evidence: EVIDENCE,
    }))
}

/// One operation behind `claim`, under a dialect named `name`, its overlay recording the claim.
fn behind<const N: usize>(name: &'static str, claim: &'static FormClaim) -> Result<Dialect, Vec<DialectError>> {
    let record = overlay(name, Vec::new(), vec![row(NAMES[N], claim, SPECS[N].auth.expect("an action").resource)]);
    Dialect::assemble(record)
        .declare_form::<Form<N>>(FormRoute { precedence: 1, claim })
        .build()
}

fn token_dialect() -> Dialect {
    behind::<TOKEN>("acme-sts", &TOKEN_CLAIM).expect("the reviewed form dialect assembles")
}

fn refused(result: Result<Dialect, Vec<DialectError>>) -> Vec<DialectError> {
    match result {
        Ok(dialect) => panic!("the dialect assembled: {:?}", dialect.name()),
        Err(errors) => errors,
    }
}

fn post(path: &str, content_type: &str) -> RouteReq {
    RouteReq::new(&format!("POST {path}")).header("content-type", content_type)
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// Positive — the claim takes its `POST` path-style, virtual-hosted and on any endpoint face, and
/// whatever the query names: the S3 table never sees it.
#[test]
fn a_form_claim_takes_its_post_on_every_host_and_query() {
    let router = router(&[&token_dialect()]);
    for request in [
        post("/", FORM),
        post("/?delete", FORM),
        post("/?uploads&x-id=DeleteObjects", FORM),
        post("/", FORM).virtual_hosted().target(TargetKind::Bucket),
        post("/?delete", FORM).virtual_hosted().target(TargetKind::Bucket),
        post("/", FORM).host_class(HostClass::S3Express),
    ] {
        assert_eq!(routed(&router, &request), Some("acme:Token"));
        assert!(matches!(router.claims().lookup(&request.parts()), ClaimLookup::Form { .. }));
    }
}

/// Positive — legacy RustFS's reading of the media type: case, parameters and surrounding spaces
/// and tabs do not matter.
#[test]
fn a_form_claim_reads_the_media_type_case_insensitively_before_its_parameters() {
    let router = router(&[&token_dialect()]);
    for content_type in [
        "APPLICATION/X-WWW-FORM-URLENCODED",
        "Application/X-Www-Form-Urlencoded; charset=utf-8",
        "application/x-www-form-urlencoded ;charset=UTF-8",
        "\tapplication/x-www-form-urlencoded\t",
    ] {
        assert_eq!(routed(&router, &post("/", content_type)), Some("acme:Token"), "{content_type:?}");
    }
}

/// Positive — under legacy RustFS's operation selection the claim is still asked first: a
/// virtual-hosted `POST /?delete` that selection reads as `DeleteObjects` is the claim's.
#[test]
fn a_form_claim_is_asked_before_legacy_rustfs_operation_selection() {
    let legacy = RouterBuilder::new()
        .selecting(rustfs_gateway_core::route::Selection::RustfsLegacy)
        .dialect(&token_dialect())
        .build()
        .expect("the router builds");
    let without = RouterBuilder::new()
        .selecting(rustfs_gateway_core::route::Selection::RustfsLegacy)
        .build()
        .expect("the bare router builds");
    let request = post("/?delete", FORM).virtual_hosted().target(TargetKind::Bucket);
    assert_eq!(without.resolve(&request.parts()).map(|entry| entry.op_name), Some("DeleteObjects"));
    assert_eq!(legacy.resolve(&request.parts()).map(|entry| entry.op_name), Some("acme:Token"));
    assert_eq!(legacy.resolve_readable(&request.parts()).map(|entry| entry.op_name), Some("acme:Token"));
}

/// Positive — the dispatch names the form claim and its dialect, and no claimed row.
#[test]
fn a_form_claimed_dispatch_names_the_claim_and_no_row() {
    let router = RouterBuilder::new()
        .dialect(&token_dialect())
        .handle_without_codec::<Form<TOKEN>, _>(std::sync::Arc::new(Issuer))
        .build()
        .expect("the router builds");
    let request = post("/?delete", FORM).virtual_hosted().target(TargetKind::Bucket);
    let dispatched = router.dispatch(&request.parts()).expect("the form claim dispatches");
    assert_eq!(dispatched.entry.op_name, "acme:Token");
    assert!(dispatched.claimed.is_none(), "a form claim has no claimed row");
    let form = dispatched.form.expect("the covering form claim");
    assert_eq!((form.dialect(), *form.claim()), ("acme-sts", TOKEN_CLAIM));
    assert_eq!(router.claims().forms().len(), 1);
}

// ── negative: what a form claim does not cover ──────────────────────────────────────────────

/// Negative — another path, another method, or no form media type is not covered, and goes to S3
/// routing exactly as without the dialect.
#[test]
fn n_a_form_claim_covers_nothing_but_its_post_and_media_type() {
    let with = router(&[&token_dialect()]);
    let without = RouterBuilder::new().build().expect("the bare router builds");
    let outside = [
        post("//", FORM),
        post("/%2F", FORM),
        post("/bucket", FORM),
        post("/bucket/key", FORM),
        RouteReq::new("PUT /").header("content-type", FORM),
        RouteReq::new("GET /").header("content-type", FORM),
        RouteReq::new("DELETE /?delete").header("content-type", FORM),
        RouteReq::new("POST /"),
        post("/", "application/x-www-form-urlencoded-x"),
        post("/", "application/x-www-form"),
        post("/", "multipart/form-data; boundary=x"),
        post("/", "text/plain"),
        post("/", ";application/x-www-form-urlencoded"),
        post("/", ""),
    ];
    for request in outside {
        assert!(!with.claims().lookup(&request.parts()).is_inside());
        assert_eq!(routed(&with, &request), routed(&without, &request));
    }
}

/// Negative — only the first `Content-Type` value is read, as legacy RustFS reads one. The router's
/// own reading: the facade's request acceptance refuses a repeated or non-UTF-8 `Content-Type`
/// before routing (ADR-0041, "Known differences").
#[test]
fn n_only_the_first_content_type_value_names_the_media_type() {
    let router = router(&[&token_dialect()]);
    let second_only = RouteReq::new("POST /")
        .header("content-type", "text/plain")
        .header("content-type", FORM);
    assert!(!router.claims().lookup(&second_only.parts()).is_inside());
    let first = post("/", FORM).header("content-type", "text/plain");
    assert_eq!(routed(&router, &first), Some("acme:Token"));
}

/// Negative — a value that is not visible ASCII names no media type, even when its text before the
/// first `;` would.
#[test]
fn n_a_content_type_that_is_not_visible_ascii_is_not_covered() {
    let router = router(&[&token_dialect()]);
    let request = RouteReq::new("POST /").header_bytes("content-type", b"application/x-www-form-urlencoded; charset=\xe9");
    assert!(!router.claims().lookup(&request.parts()).is_inside());
}

/// Negative — without the dialect the same `POST` is S3's, and names no operation at the service.
#[test]
fn n_without_the_dialect_the_post_is_s3_routing() {
    let router = RouterBuilder::new().build().expect("the bare router builds");
    let refusal = router.dispatch(&post("/", FORM).parts()).expect_err("no S3 operation");
    assert_eq!(refusal.message(), NO_ROUTE_MESSAGE);
}

// ── negative: refusals ──────────────────────────────────────────────────────────────────────

/// Negative — every grammar rule, each to its own rejection. A one-segment path is the bucket
/// position: a claim there would take a bucket's own `POST`s (`?delete`) from S3 on every host.
#[test]
fn n_a_malformed_form_claim_is_refused_with_its_reason() {
    let cases: [(&'static str, FormClaimRejection); 9] = [
        ("relative", FormClaimRejection::NotAbsolute),
        ("", FormClaimRejection::NotAbsolute),
        ("/sts/", FormClaimRejection::TrailingSlash),
        ("//", FormClaimRejection::TrailingSlash),
        ("/sts//token", FormClaimRejection::EmptySegment),
        ("/sts/../token", FormClaimRejection::DotSegment),
        ("/sts/t%6Fken", FormClaimRejection::ForbiddenCharacter),
        ("/sts", FormClaimRejection::ShadowsABucket),
        ("/photos.example", FormClaimRejection::ShadowsABucket),
    ];
    for (path, expected) in cases {
        let errors = refused(behind::<TOKEN>("acme-sts", claim(path)));
        assert_eq!(
            errors,
            vec![DialectError::RefusedFormClaim {
                name: "acme:Token",
                rejection: expected
            }],
            "{path:?}"
        );
    }
}

/// Negative — a form claim nobody explained or sourced is refused.
#[test]
fn n_an_unsourced_or_unexplained_form_claim_is_refused() {
    for (reason, evidence, expected) in [
        (" ", EVIDENCE, FormClaimRejection::NoReason),
        (REASON, &[][..], FormClaimRejection::NoEvidence),
        (REASON, &[" "][..], FormClaimRejection::NoEvidence),
    ] {
        let unsourced = Box::leak(Box::new(FormClaim {
            path: "/",
            reason,
            evidence,
        }));
        assert_eq!(unsourced.rejection(), Some(expected));
        let errors = refused(behind::<TOKEN>("acme-sts", unsourced));
        assert_eq!(
            errors,
            vec![DialectError::RefusedFormClaim {
                name: "acme:Token",
                rejection: expected
            }]
        );
    }
}

/// Negative — the overlay row must record the claim itself, as rendered.
#[test]
fn n_an_overlay_row_that_does_not_record_the_claim_is_refused() {
    let mut record_row = row(NAMES[TOKEN], &TOKEN_CLAIM, ResourceShape::Service);
    record_row.selector = "FormClaim(POST \"/sts/token\")";
    let record = overlay("acme-sts", Vec::new(), vec![record_row]);
    let errors = refused(
        Dialect::assemble(record)
            .declare_form::<Form<TOKEN>>(FormRoute {
                precedence: 1,
                claim: &TOKEN_CLAIM,
            })
            .build(),
    );
    assert_eq!(
        errors,
        vec![DialectError::SelectorMismatch {
            name: "acme:Token",
            declared: TOKEN_CLAIM.render(),
            overlay: "FormClaim(POST \"/sts/token\")",
        }]
    );
    assert_eq!(TOKEN_CLAIM.render(), "FormClaim(POST \"/\")");
}

/// Negative — behind a form claim the path names no bucket or key, so a bucket resource is refused.
#[test]
fn n_a_form_claimed_operation_naming_a_bucket_is_refused() {
    let errors = refused(behind::<BUCKETED>("acme-sts", &TOKEN_CLAIM));
    assert_eq!(
        errors,
        vec![DialectError::ClaimedOperationNamesAResource {
            name: "acme:BucketToken",
            resource: ResourceShape::Bucket,
        }]
    );
}

/// Negative — two operations of one dialect behind one path are refused.
#[test]
fn n_two_form_claims_of_one_dialect_that_overlap_are_refused() {
    let record = overlay(
        "acme-sts",
        Vec::new(),
        vec![
            row(NAMES[TOKEN], &TOKEN_CLAIM, ResourceShape::Service),
            row(NAMES[SECOND], &TOKEN_CLAIM, ResourceShape::Service),
        ],
    );
    let errors = refused(
        Dialect::assemble(record)
            .declare_form::<Form<TOKEN>>(FormRoute {
                precedence: 1,
                claim: &TOKEN_CLAIM,
            })
            .declare_form::<Form<SECOND>>(FormRoute {
                precedence: 1,
                claim: &TOKEN_CLAIM,
            })
            .build(),
    );
    assert_eq!(
        errors,
        vec![DialectError::OverlappingFormClaims {
            name: "acme:SecondToken",
            earlier: "acme:Token",
        }]
    );
}

/// Negative — two dialects whose form claims overlap refuse the router, while different paths do
/// not.
#[test]
fn n_form_claims_from_two_dialects_that_overlap_refuse_the_router() {
    let first = token_dialect();
    let second = behind::<SECOND>("acme-sts-two", &TOKEN_CLAIM).expect("assembles alone");
    assert_eq!(
        route_refusal(&[&first, &second]),
        RouteBuildError::OverlappingFormClaims {
            first: "acme:Token",
            second: "acme:SecondToken",
        }
    );
    let elsewhere = behind::<SECOND>("acme-sts-two", claim("/sts/token")).expect("assembles alone");
    let router = router(&[&first, &elsewhere]);
    assert_eq!(routed(&router, &post("/sts/token", FORM)), Some("acme:SecondToken"));
    assert_eq!(routed(&router, &post("/", FORM)), Some("acme:Token"));
    let without = RouterBuilder::new().build().expect("the bare router builds");
    for request in [post("/sts", FORM), post("/sts/token/more", FORM), post("/sts/token/", FORM)] {
        assert_eq!(routed(&router, &request), routed(&without, &request));
    }
}

/// Negative — a form claim whose path a path claim covers refuses the router: one path, one owner.
#[test]
fn n_a_form_claim_inside_a_path_claim_refuses_the_router() {
    static ROWS: &[ClaimedRow] = &[ClaimedRow {
        template: "/acme/admin/v1/info",
        selector: &[Predicate::Method(Method::GET)],
    }];
    let admin = PathClaim {
        prefix: "/acme/admin",
        reason: REASON,
        evidence: EVIDENCE,
    };
    let record = overlay(
        "acme-admin",
        vec![admin],
        vec![OverlayRow {
            name: "acme:Info",
            precedence: 10,
            selector: text(render_claimed_rows(ROWS)),
            action: "admin:Thing",
            resource: ResourceShape::Service,
            success_status: 200,
            anonymous: false,
            evidence: EVIDENCE,
        }],
    );
    let admin_dialect = Dialect::assemble(record)
        .declare_claimed::<crate::dialect_claims::Vendor<{ crate::dialect_claims::INFO }>>(crate::dialect_claims::claimed(
            10,
            ROWS,
            &[],
        ))
        .build()
        .expect("the path dialect assembles");
    let inside = behind::<PATHED>("acme-sts", claim("/acme/admin/token")).expect("assembles alone");
    assert_eq!(
        route_refusal(&[&admin_dialect, &inside]),
        RouteBuildError::FormClaimInsideClaim {
            op_name: "acme:PathToken",
            claim: "/acme/admin",
        }
    );
}
