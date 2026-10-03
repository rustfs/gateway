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

//! Every refusal of a path-prefix claim, a template or a claimed row (ADR-0024), each pinned to its
//! own variant so deleting one check turns exactly one test red.
//!
//! Responsible for: claim grammar and depth, overlapping and unused claims, claims across two
//! dialects, an S3-table row inside a claim, template grammar, templates outside the claims, row
//! selectors, empty and repeated routes, resource shapes, alias rows missing from the overlay, and
//! overlap between claimed rows.
//! NOT responsible for: what a claim captures once it is installed (`dialect_claims.rs`).
//! Upstream: `dialect_claims`'s fixtures. Downstream: nothing.

use http::Method;
use rustfs_gateway_core::dialect::{ClaimedRow, Dialect, DialectError, DialectOverlay, DialectRoute, OverlayRow};
use rustfs_gateway_core::op::ResourceShape;
use rustfs_gateway_core::route::{
    ArnForm, ClaimRejection, HostClass, PathClaim, PathTemplate, Predicate, RouteBuildError, ShadowingDecl, TargetKind,
    TemplateRejection,
};

use crate::dialect_claims::{
    ADMIN, BUCKET_SHAPED, COMPAT, EVIDENCE, GET, GET_USER, GET_USER_ROWS, INFO, INFO_ROWS, NAMES, OBJECT_ROW, REASON,
    STATS_OVER_USER, USER_STATS, USER_STATS_ROWS, Vendor, acme, claimed, only, overlay, overlay_row, refusals, route_refusal,
    text,
};

// ── claim refusals ───────────────────────────────────────────────────────────────────────────

fn claim_refusal(prefix: &'static str, reason: &'static str, evidence: &'static [&'static str]) -> ClaimRejection {
    let claim = PathClaim {
        prefix,
        reason,
        evidence,
    };
    let rows = vec![ClaimedRow {
        template: text(format!("{prefix}/v1/info")),
        selector: GET,
    }];
    let errors = refusals(only::<INFO>(vec![claim], rows));
    errors
        .iter()
        .find_map(|error| match error {
            DialectError::RefusedClaim { rejection, .. } => Some(*rejection),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no claim refusal for {prefix:?}: {errors:?}"))
}

/// Negative — a claim shallower than two segments names a bucket, and is refused: `/health` and
/// `/rustfs` would take the whole bucket of that name away from S3.
#[test]
fn n_a_claim_that_would_shadow_a_bucket_is_refused() {
    for prefix in ["/health", "/rustfs", "/minio", "/iceberg", "/_iceberg", "/"] {
        assert_eq!(claim_refusal(prefix, REASON, EVIDENCE), ClaimRejection::ShadowsABucket, "{prefix}");
    }
}

/// Negative — every other malformed spelling of a claim, each with its own reason.
#[test]
fn n_a_malformed_claim_is_refused_with_its_reason() {
    for (prefix, expected) in [
        ("acme/admin", ClaimRejection::NotAbsolute),
        ("/acme/admin/", ClaimRejection::TrailingSlash),
        ("/acme//admin", ClaimRejection::EmptySegment),
        ("/acme/./admin", ClaimRejection::DotSegment),
        ("/acme/../admin", ClaimRejection::DotSegment),
        ("/acme/%61dmin", ClaimRejection::ForbiddenCharacter),
        ("/acme/{x}", ClaimRejection::ForbiddenCharacter),
        ("/acme/ad min", ClaimRejection::ForbiddenCharacter),
    ] {
        assert_eq!(claim_refusal(prefix, REASON, EVIDENCE), expected, "{prefix}");
    }
}

/// Negative — a claim nobody sourced or explained is refused.
#[test]
fn n_an_unsourced_or_unexplained_claim_is_refused() {
    assert_eq!(claim_refusal("/acme/admin", REASON, &[]), ClaimRejection::NoEvidence);
    assert_eq!(claim_refusal("/acme/admin", REASON, &[" "]), ClaimRejection::NoEvidence);
    assert_eq!(claim_refusal("/acme/admin", "  ", EVIDENCE), ClaimRejection::NoReason);
}

/// Negative — two claims of one dialect that could cover one path are refused, nested or equal.
#[test]
fn n_overlapping_claims_in_one_dialect_are_refused() {
    let nested = PathClaim {
        prefix: "/acme/admin/v1",
        ..ADMIN
    };
    for pair in [vec![ADMIN, nested], vec![ADMIN, ADMIN]] {
        let rows = vec![ClaimedRow {
            template: "/acme/admin/v1/info",
            selector: GET,
        }];
        let errors = refusals(only::<INFO>(pair, rows));
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, DialectError::OverlappingClaims { .. })),
            "{errors:?}"
        );
    }
}

/// Negative — a claim no row uses would swallow its namespace to answer nothing, and is refused.
#[test]
fn n_a_claim_no_row_uses_is_refused() {
    let rows = vec![ClaimedRow {
        template: "/acme/admin/v1/info",
        selector: GET,
    }];
    let errors = refusals(only::<INFO>(vec![ADMIN, COMPAT], rows));
    assert!(
        errors.iter().any(|error| matches!(
            error,
            DialectError::UnusedClaim {
                prefix: "/compat/admin",
                ..
            }
        )),
        "{errors:?}"
    );
}

/// Negative — two dialects whose claims could cover one path refuse the router.
#[test]
fn n_claims_from_two_dialects_that_overlap_refuse_the_router() {
    let nested = PathClaim {
        prefix: "/acme/admin/v2",
        ..ADMIN
    };
    let other = only::<INFO>(
        vec![nested],
        vec![ClaimedRow {
            template: "/acme/admin/v2/info",
            selector: GET,
        }],
    )
    .expect("a second dialect on its own");
    let error = route_refusal(&[&acme(), &other]);
    assert!(matches!(error, RouteBuildError::OverlappingClaims { .. }), "{error:?}");
}

static INSIDE_CLAIM_SELECTOR: &[Predicate] = &[
    Predicate::Method(Method::GET),
    Predicate::Target(TargetKind::Object),
    Predicate::PathLiteral("/acme/admin/v1/legacy"),
];

/// Negative — an S3-table row on a path literal inside a claim would be dead, and is refused.
#[test]
fn n_an_s3_table_row_inside_a_claim_refuses_the_router() {
    static OVERLAY: DialectOverlay = DialectOverlay {
        name: "legacy",
        vendor: "acme",
        operations: &[OverlayRow {
            name: "acme:ObjectRow",
            precedence: 60,
            selector: "Method(GET) ∧ Target(Object) ∧ PathLiteral(\"/acme/admin/v1/legacy\")",
            action: "admin:Thing",
            resource: ResourceShape::Object,
            success_status: 200,
            anonymous: false,
            evidence: EVIDENCE,
        }],
        claims: &[],
    };
    let legacy = Dialect::assemble(&OVERLAY)
        .declare::<Vendor<OBJECT_ROW>>(DialectRoute {
            precedence: 60,
            selector: INSIDE_CLAIM_SELECTOR,
            path_shape: "/acme/admin/v1/legacy",
            shadows: &[],
        })
        .build()
        .expect("the S3-table row assembles on its own");
    let error = route_refusal(&[&acme(), &legacy]);
    assert!(
        matches!(
            error,
            RouteBuildError::RowInsideClaim {
                op_name: "acme:ObjectRow",
                ..
            }
        ),
        "{error:?}"
    );
}

// ── template and row refusals ────────────────────────────────────────────────────────────────

/// Negative — every malformed template, each with its own reason.
#[test]
fn n_a_malformed_template_is_refused_with_its_reason() {
    for (template, expected) in [
        ("acme/admin/v1/x", TemplateRejection::NotAbsolute),
        ("/acme/admin/v1/x//", TemplateRejection::EmptySegment),
        ("/acme/admin//x", TemplateRejection::EmptySegment),
        ("/acme/admin/v1/..", TemplateRejection::DotSegment),
        ("/acme/admin/v1/%78", TemplateRejection::ForbiddenCharacter),
        ("/acme/admin/v1/{Name}", TemplateRejection::MalformedParameter),
        ("/acme/admin/v1/{}", TemplateRejection::MalformedParameter),
        ("/acme/admin/v1/{a}{b}", TemplateRejection::MalformedParameter),
        ("/acme/admin/v1/{id}.zip", TemplateRejection::ParameterWithAffix),
        ("/acme/admin/v1/{a}/{a}", TemplateRejection::DuplicateParameter),
    ] {
        assert_eq!(PathTemplate::parse(template).err(), Some(expected), "{template}");
        let errors = refusals(only::<INFO>(
            vec![ADMIN],
            vec![ClaimedRow {
                template: text(template.to_owned()),
                selector: GET,
            }],
        ));
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, DialectError::MalformedTemplate { rejection, .. } if *rejection == expected)),
            "{template}: {errors:?}"
        );
    }
}

/// Negative — a template outside every claim of its dialect, or with a parameter where the claim
/// names a literal, is refused.
#[test]
fn n_a_template_outside_the_dialects_claims_is_refused() {
    for template in [
        "/other/admin/v1/info",
        "/acme/{scope}/v1/info",
        "/acme/adminx/v1/info",
        "/acme",
    ] {
        let errors = refusals(only::<INFO>(vec![ADMIN], vec![ClaimedRow { template, selector: GET }]));
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, DialectError::TemplateOutsideClaims { .. })),
            "{template}: {errors:?}"
        );
    }
}

/// Negative — a claimed row names exactly one method and nothing the claim already decides.
#[test]
fn n_a_claimed_row_selector_that_restates_the_claim_is_refused() {
    static TARGET: &[Predicate] = &[Predicate::Method(Method::GET), Predicate::Target(TargetKind::Object)];
    static LITERAL: &[Predicate] = &[Predicate::Method(Method::GET), Predicate::PathLiteral("/acme/admin/v1/info")];
    static FACE: &[Predicate] = &[Predicate::Method(Method::GET), Predicate::HostClass(HostClass::Standard)];
    static ARN: &[Predicate] = &[Predicate::Method(Method::GET), Predicate::ArnForm(ArnForm::AccessPoint)];
    static NO_METHOD: &[Predicate] = &[Predicate::QueryPresent("x")];
    static TWO_METHODS: &[Predicate] = &[Predicate::Method(Method::GET), Predicate::Method(Method::PUT)];
    for selector in [TARGET, LITERAL, FACE, ARN, NO_METHOD, TWO_METHODS, &[]] {
        let errors = refusals(only::<INFO>(
            vec![ADMIN],
            vec![ClaimedRow {
                template: "/acme/admin/v1/info",
                selector,
            }],
        ));
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, DialectError::ClaimedRowSelector { .. })),
            "{selector:?}: {errors:?}"
        );
    }
}

/// Negative — a claimed route with no rows, or the same row twice, is refused.
#[test]
fn n_an_empty_or_repeated_claimed_route_is_refused() {
    let errors = refusals(only::<INFO>(vec![ADMIN], Vec::new()));
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, DialectError::EmptyClaimedRoute { .. })),
        "{errors:?}"
    );
    let row = ClaimedRow {
        template: "/acme/admin/v1/info",
        selector: GET,
    };
    let errors = refusals(only::<INFO>(vec![ADMIN], vec![row, row]));
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, DialectError::DuplicateClaimedRow { .. })),
        "{errors:?}"
    );
}

/// Negative — inside a claim the path is not S3 addressing, so a claimed operation that names a
/// bucket or object resource would be authorised against a resource nothing supplies.
#[test]
fn n_a_claimed_operation_that_names_a_bucket_or_object_is_refused() {
    let rows = vec![ClaimedRow {
        template: "/acme/admin/v1/quota",
        selector: GET,
    }];
    let errors = refusals(only::<BUCKET_SHAPED>(vec![ADMIN], rows.clone()));
    assert!(
        errors.iter().any(|error| matches!(
            error,
            DialectError::ClaimedOperationNamesAResource {
                resource: ResourceShape::Bucket,
                ..
            }
        )),
        "{errors:?}"
    );
    let errors = refusals(only::<OBJECT_ROW>(vec![ADMIN], rows));
    assert!(
        errors.iter().any(|error| matches!(
            error,
            DialectError::ClaimedOperationNamesAResource {
                resource: ResourceShape::Object,
                ..
            }
        )),
        "{errors:?}"
    );
}

/// Negative — the overlay records every row, alias included: dropping the alias from the record
/// is a selector mismatch, not a quietly unreviewed row.
#[test]
fn n_an_alias_row_the_overlay_does_not_record_is_refused() {
    let record = overlay(
        vec![ADMIN, COMPAT],
        vec![overlay_row(NAMES[INFO], 10, &INFO_ROWS[..1], ResourceShape::Service)],
    );
    let errors = refusals(
        Dialect::assemble(record)
            .declare_claimed::<Vendor<INFO>>(claimed(10, INFO_ROWS, &[]))
            .build(),
    );
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, DialectError::SelectorMismatch { .. })),
        "{errors:?}"
    );
}

/// Negative — one operation declared as an S3-table row and as a claimed route is declared twice.
#[test]
fn n_an_operation_declared_both_ways_is_declared_twice() {
    static SELECTOR: &[Predicate] = &[
        Predicate::Method(Method::GET),
        Predicate::Target(TargetKind::Bucket),
        Predicate::QueryPresent("acme-info"),
    ];
    let record = overlay(vec![ADMIN], vec![overlay_row(NAMES[INFO], 10, &INFO_ROWS[..1], ResourceShape::Service)]);
    let errors = refusals(
        Dialect::assemble(record)
            .declare_claimed::<Vendor<INFO>>(claimed(10, &INFO_ROWS[..1], &[]))
            .declare::<Vendor<INFO>>(DialectRoute {
                precedence: 10,
                selector: SELECTOR,
                path_shape: "/{Bucket}",
                shadows: &[],
            })
            .build(),
    );
    assert!(
        errors
            .iter()
            .any(|error| matches!(error, DialectError::DeclaredTwice { name: "acme:Info" })),
        "{errors:?}"
    );
}

// ── overlap between claimed rows ─────────────────────────────────────────────────────────────

fn stats_and_user(stats_precedence: u16, shadows: &'static [ShadowingDecl]) -> Dialect {
    let record = overlay(
        vec![ADMIN],
        vec![
            overlay_row(NAMES[GET_USER], 20, GET_USER_ROWS, ResourceShape::Service),
            overlay_row(NAMES[USER_STATS], stats_precedence, USER_STATS_ROWS, ResourceShape::Service),
        ],
    );
    Dialect::assemble(record)
        .declare_claimed::<Vendor<GET_USER>>(claimed(20, GET_USER_ROWS, &[]))
        .declare_claimed::<Vendor<USER_STATS>>(claimed(stats_precedence, USER_STATS_ROWS, shadows))
        .build()
        .expect("the record and the declarations agree")
}

/// Negative — two claimed rows that accept one request at one precedence conflict.
#[test]
fn n_claimed_rows_overlapping_at_one_precedence_conflict() {
    let error = route_refusal(&[&stats_and_user(20, &[])]);
    let RouteBuildError::Conflict { witness, .. } = error else {
        panic!("{error:?}");
    };
    assert_eq!(witness.path, "/acme/admin/v1/user/stats");
}

/// Negative — across precedences the overlap still needs a declaration inside the claim.
#[test]
fn n_an_undeclared_overlap_between_claimed_rows_is_refused() {
    let error = route_refusal(&[&stats_and_user(15, &[])]);
    assert!(
        matches!(&error, RouteBuildError::UndeclaredShadowing { winner, shadowed, .. }
            if winner.op_name == "acme:UserStats" && shadowed.op_name == "acme:GetUser"),
        "{error:?}"
    );
}

/// Negative — a declaration whose winner is behind the row it claims to shadow is stale.
#[test]
fn n_a_stale_declaration_between_claimed_rows_is_refused() {
    let error = route_refusal(&[&stats_and_user(25, STATS_OVER_USER)]);
    assert!(matches!(error, RouteBuildError::StaleShadowing { .. }), "{error:?}");
}

// ── overlap with a catch-all (ADR-0036) ──────────────────────────────────────────────────────

/// A literal row and a catch-all row it sits inside, both under `logs/`.
static TODAY_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/acme/admin/v1/logs/today",
    selector: GET,
}];
static ALL_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/acme/admin/v1/{*rest}",
    selector: GET,
}];
static TODAY_OVER_LOGS: &[ShadowingDecl] = &[ShadowingDecl {
    winner: "acme:UserStats",
    shadowed: "acme:GetUser",
    reason: "Today's log is its own operation; every other path below `logs/` is a log.",
    evidence: EVIDENCE,
}];

/// `acme:UserStats` on `winner_rows` at `winner_precedence` and `acme:GetUser` on `shadowed_rows`
/// at 20.
fn over_a_catch_all(
    winner_rows: &'static [ClaimedRow],
    winner_precedence: u16,
    shadowed_rows: &'static [ClaimedRow],
    shadows: &'static [ShadowingDecl],
) -> Dialect {
    let record = overlay(
        vec![ADMIN],
        vec![
            overlay_row(NAMES[GET_USER], 20, shadowed_rows, ResourceShape::Service),
            overlay_row(NAMES[USER_STATS], winner_precedence, winner_rows, ResourceShape::Service),
        ],
    );
    Dialect::assemble(record)
        .declare_claimed::<Vendor<GET_USER>>(claimed(20, shadowed_rows, &[]))
        .declare_claimed::<Vendor<USER_STATS>>(claimed(winner_precedence, winner_rows, shadows))
        .build()
        .expect("the record and the declarations agree")
}

/// Negative — a literal row inside a catch-all's reach overlaps it, and so do two catch-alls one of
/// which reaches the other's paths: at one precedence they conflict on a witness both match, and
/// across precedences the overlap needs a declaration inside the claim (ADR-0036).
#[test]
fn n_an_undeclared_overlap_with_a_catch_all_is_refused() {
    for (winner_rows, shadowed_rows, witness) in [
        (TODAY_ROWS, crate::dialect_claims::LOGS_ROWS, "/acme/admin/v1/logs/today"),
        (crate::dialect_claims::LOGS_ROWS, ALL_ROWS, "/acme/admin/v1/logs/p"),
        (TODAY_ROWS, ALL_ROWS, "/acme/admin/v1/logs/today"),
    ] {
        let error = route_refusal(&[&over_a_catch_all(winner_rows, 20, shadowed_rows, &[])]);
        let RouteBuildError::Conflict { witness: found, .. } = error else {
            panic!("{error:?}");
        };
        assert_eq!(found.path, witness);
        let error = route_refusal(&[&over_a_catch_all(winner_rows, 15, shadowed_rows, &[])]);
        assert!(
            matches!(&error, RouteBuildError::UndeclaredShadowing { winner, shadowed, .. }
                if winner.op_name == "acme:UserStats" && shadowed.op_name == "acme:GetUser"),
            "{witness}: {error:?}"
        );
    }
}

/// Positive — declared in front, the literal answers its own path and the catch-all keeps every
/// other one below it, the longer paths under the literal included.
#[test]
fn a_declared_literal_stands_in_front_of_a_catch_all() {
    let router = crate::dialect_claims::router(&[&over_a_catch_all(
        TODAY_ROWS,
        15,
        crate::dialect_claims::LOGS_ROWS,
        TODAY_OVER_LOGS,
    )]);
    for (line, name) in [
        ("GET /acme/admin/v1/logs/today", "acme:UserStats"),
        ("GET /acme/admin/v1/logs/today/", "acme:GetUser"),
        ("GET /acme/admin/v1/logs/today/x", "acme:GetUser"),
        ("GET /acme/admin/v1/logs/yesterday", "acme:GetUser"),
        ("GET /acme/admin/v1/logs/Today", "acme:GetUser"),
    ] {
        let request = crate::support::Req::new(line);
        assert_eq!(crate::dialect_claims::routed(&router, &request), Some(name), "{line}");
    }
}
