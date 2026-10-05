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

//! All-method claimed rows and their unchanged routing boundaries (ADR-0038).
//!
//! Responsible for: method omission, constrained matches, claim containment and reviewed overlaps.
//! NOT responsible for: authentication or an admin fallback response.
//! Upstream: the existing dialect fixtures and core router. Downstream: no production code.

use crate::dialect_claims::*;
use crate::support::Req;
use http::Method;
use rustfs_gateway_core::ResourceShape;
use rustfs_gateway_core::dialect::{ClaimedRow, Dialect, DialectError};
use rustfs_gateway_core::route::{ArnForm, HostClass, Predicate, RouteBuildError, ShadowingDecl};

static ANY_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/acme/admin/v4/info",
    selector: &[],
}];
static EXACT_ROWS: &[ClaimedRow] = &[ClaimedRow {
    template: "/acme/admin/v4/info",
    selector: GET,
}];
static DECLARATION: &[ShadowingDecl] = &[ShadowingDecl {
    winner: "acme:UserStats",
    shadowed: "acme:GetUser",
    reason: "The exact method is served before the all-method fallback.",
    evidence: EVIDENCE,
}];

fn pair(
    first: &'static [ClaimedRow],
    precedence: u16,
    second: &'static [ClaimedRow],
    shadows: &'static [ShadowingDecl],
) -> Dialect {
    let record = overlay(
        vec![ADMIN],
        vec![
            overlay_row(NAMES[USER_STATS], precedence, first, ResourceShape::Service),
            overlay_row(NAMES[GET_USER], 20, second, ResourceShape::Service),
        ],
    );
    Dialect::assemble(record)
        .declare_claimed::<Vendor<USER_STATS>>(claimed(precedence, first, shadows))
        .declare_claimed::<Vendor<GET_USER>>(claimed(20, second, &[]))
        .build()
        .expect("both claimed selectors are valid")
}

#[test]
fn all_methods_reach_the_declared_path_and_alias() {
    let dialect = only::<INFO>(
        vec![ADMIN, COMPAT],
        vec![
            ANY_ROWS[0],
            ClaimedRow {
                template: "/compat/admin/v4/info",
                selector: &[],
            },
        ],
    )
    .expect("an omitted method is unconstrained");
    let router = router(&[&dialect]);
    for method in [
        "GET", "HEAD", "PUT", "POST", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "FROB", "get",
    ] {
        for path in ["/acme/admin/v4/info", "/compat/admin/v4/info"] {
            let line = format!("{method} {path}");
            assert_eq!(routed(&router, &Req::new(&line)), Some(NAMES[INFO]), "{line}");
        }
    }
}

#[test]
fn a_declared_exact_method_leaves_other_methods_to_the_fallback() {
    let router = router(&[&pair(EXACT_ROWS, 10, ANY_ROWS, DECLARATION)]);
    for (method, operation) in [
        ("GET", NAMES[USER_STATS]),
        ("PUT", NAMES[GET_USER]),
        ("FROB", NAMES[GET_USER]),
        ("get", NAMES[GET_USER]),
    ] {
        assert_eq!(routed(&router, &Req::new(&format!("{method} /acme/admin/v4/info"))), Some(operation));
    }
}

#[test]
fn n_all_methods_still_require_every_query_and_header_predicate() {
    static FILTER: &[Predicate] = &[
        Predicate::QueryEquals("mode", "probe"),
        Predicate::QueryAbsent("deny"),
        Predicate::HeaderPrefix("x-route", "yes"),
    ];
    let dialect = only::<INFO>(
        vec![ADMIN],
        vec![ClaimedRow {
            template: "/acme/admin/v4/info",
            selector: FILTER,
        }],
    )
    .expect("a methodless constrained row");
    let router = router(&[&dialect]);
    for method in ["GET", "FROB"] {
        let request = format!("{method} /acme/admin/v4/info");
        assert_eq!(
            routed(&router, &Req::new(&format!("{request}?mode=probe")).header("x-route", "yes-more")),
            Some(NAMES[INFO])
        );
        for (query, header) in [
            ("", "yes"),
            ("?mode=wrong", "yes"),
            ("?mode=probe&deny", "yes"),
            ("?mode=probe", "no"),
        ] {
            assert_eq!(routed(&router, &Req::new(&format!("{request}{query}")).header("x-route", header)), None);
        }
        assert_eq!(routed(&router, &Req::new(&format!("{request}?mode=probe"))), None);
    }
}

#[test]
fn n_all_methods_cannot_escape_their_claim_or_template() {
    let dialect = only::<INFO>(vec![ADMIN], ANY_ROWS.to_vec()).expect("an all-method row");
    let router = router(&[&dialect]);
    for request in [
        Req::new("FROB /acme/admin/v4/info/extra"),
        Req::new("FROB /acme/admin/v4/other"),
        Req::new("FROB /acme/adminx/v4/info"),
        Req::new("FROB /compat/admin/v4/info"),
        Req::new("FROB /acme/admin/v4/info").virtual_hosted(),
        Req::new("FROB /acme/admin/v4/info").host_class(HostClass::Website),
        Req::new("FROB /acme/admin/v4/info").arn(ArnForm::AccessPoint),
    ] {
        assert_eq!(routed(&router, &request), None);
    }
}

#[test]
fn n_all_method_overlaps_conflict_in_both_declaration_orders() {
    for (first, second) in [(ANY_ROWS, EXACT_ROWS), (EXACT_ROWS, ANY_ROWS), (ANY_ROWS, ANY_ROWS)] {
        let error = route_refusal(&[&pair(first, 20, second, &[])]);
        let RouteBuildError::Conflict { witness, .. } = error else {
            panic!("{error:?}");
        };
        assert_eq!(witness.path, "/acme/admin/v4/info");
        assert_eq!(witness.method, Method::GET);
    }
}

#[test]
fn n_all_method_overlaps_need_a_declaration_in_both_precedence_orders() {
    for (first, second, expected_total) in [(ANY_ROWS, EXACT_ROWS, true), (EXACT_ROWS, ANY_ROWS, false)] {
        let error = route_refusal(&[&pair(first, 10, second, &[])]);
        let RouteBuildError::UndeclaredShadowing { total, .. } = error else {
            panic!("{error:?}");
        };
        assert_eq!(total, expected_total, "only the all-method winner completely hides the exact method");
    }
}

#[test]
fn n_method_omission_does_not_permit_repeated_methods_or_claim_dimensions() {
    for selector in [
        vec![Predicate::Method(Method::GET), Predicate::Method(Method::GET)],
        vec![Predicate::Method(Method::GET), Predicate::Method(Method::PUT)],
        vec![Predicate::Target(rustfs_gateway_core::route::TargetKind::Object)],
        vec![Predicate::PathLiteral("/acme/admin/v4/info")],
        vec![Predicate::HostClass(HostClass::Standard)],
        vec![Predicate::ArnForm(ArnForm::AccessPoint)],
    ] {
        let errors = refusals(only::<INFO>(
            vec![ADMIN],
            vec![ClaimedRow {
                template: "/acme/admin/v4/info",
                selector: leak(selector),
            }],
        ));
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, DialectError::ClaimedRowSelector { .. })),
            "{errors:?}"
        );
    }
}

#[test]
fn a_methodless_query_presence_row_still_requires_the_query() {
    static QUERY: &[Predicate] = &[Predicate::QueryPresent("x")];
    let dialect = only::<INFO>(
        vec![ADMIN],
        vec![ClaimedRow {
            template: "/acme/admin/v4/info",
            selector: QUERY,
        }],
    )
    .expect("a query predicate does not require a method predicate");
    let router = router(&[&dialect]);
    for method in ["GET", "FROB"] {
        assert_eq!(routed(&router, &Req::new(&format!("{method} /acme/admin/v4/info?x"))), Some(NAMES[INFO]));
        assert_eq!(routed(&router, &Req::new(&format!("{method} /acme/admin/v4/info"))), None);
    }
}
