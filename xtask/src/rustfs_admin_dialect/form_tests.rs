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

//! The generator's form routes (ADR-0041): a listed route is planned behind its form claim and
//! rendered from the inventory's facts, and every way the inventory can stop matching the ruling is
//! refused.
//!
//! Responsible for: those assertions. NOT responsible for: the fixtures (`tests.rs`), or what the
//! generated operation does (the dialect crate's `sts_form` tests and goldens'
//! `rustfs_admin_dialect::sts_tests`).
//! Upstream: `super`, `super::form` and `super::tests`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::form::{EVIDENCE, STEM};
use super::rulings::FORMS;
use super::tests::{inventory, recorded_plan, route};
use super::{Route, plan};

/// RustFS's STS route as the inventory records it.
fn sts() -> Route {
    let mut sts = route("POST", "/", "sts", "anonymous", None);
    sts.auth_detail = Some("StsFormPost".to_owned());
    sts.minio_admin_alias = false;
    sts.handler = "AssumeRoleHandle".to_owned();
    sts.handler_file = "rustfs/src/admin/handlers/sts.rs".to_owned();
    sts.request_body = "buffered".to_owned();
    sts
}

const STS_FORM: &[(&str, &str, &str)] = &[("POST", "/", "StsFormPost")];

/// Positive — a listed form route is planned behind its form claim, as no declared operation and no
/// staying route, and rendered from the inventory's handler, file and commit with the floor, the
/// vendor label and the Legacy-compat record ADR-0041 decides; the recorded inventory has exactly
/// the STS endpoint.
#[test]
fn a_form_route_is_planned_and_rendered_behind_its_form_claim() {
    let plan = plan(&inventory(vec![sts()]), &[], &[], &[], STS_FORM).expect("the form route plans");
    assert!(plan.declared.is_empty());
    assert!(plan.staying.is_empty());
    assert_eq!(plan.forms.len(), 1);
    let formed = &plan.forms[0];
    assert_eq!(
        (
            formed.method.as_str(),
            formed.path.as_str(),
            formed.group.as_str(),
            formed.handler.as_str()
        ),
        ("POST", "/", "sts", "AssumeRoleHandle")
    );
    let source = formed.render(super::render::LICENSE);
    for expected in [
        "pub const NAME: &str = \"rustfs:StsFormPost\";",
        "AuthRequirement::new(\"rustfs:AssumeRoleHandle\", ResourceShape::Service)",
        "    path: \"/\",\n    reason:",
        "OperationFloor::builtin(NAME, SigService::Sts).allow_anonymous_after_listing_in_the_posture_report()",
        "Legacy-compat (rustfs/backlog#2684)",
        "const REQUEST_BODY: RequestBodyMode = RequestBodyMode::Full;",
        "selector: \"FormClaim(POST \\\"/\\\")\",",
        "anonymous: true,",
        "\"https://github.com/rustfs/rustfs/blob/c/rustfs/src/admin/handlers/sts.rs\"",
        "\"https://github.com/rustfs/rustfs/blob/c/rustfs/src/server/layer.rs\"",
        EVIDENCE,
    ] {
        assert!(source.contains(expected), "{expected}\n{source}");
    }
    assert!(!source.contains("OperationFloor::custom"), "the floor is not privileged");
    assert_eq!(STEM, "sts_form_post");

    let recorded = recorded_plan();
    let formed: Vec<(&str, &str, &str)> = recorded
        .forms
        .iter()
        .map(|formed| (formed.method.as_str(), formed.path.as_str(), formed.handler.as_str()))
        .collect();
    assert_eq!(formed, [("POST", "/", "AssumeRoleHandle")]);
    assert_eq!(FORMS, STS_FORM);
    assert!(
        !recorded
            .staying
            .iter()
            .any(|(method, path, ..)| method == "POST" && path == "/")
    );
}

/// Negative — a listed form route the fully migrated inventory does not record is refused.
#[test]
fn n_a_stale_form_route_is_refused() {
    let mut other = route("GET", "/profile/cpu", "health", "sigv4-admin", Some("admin:Profiling"));
    other.minio_admin_alias = false;
    let stale = plan(&inventory(vec![other]), &[], &[], &[], STS_FORM)
        .err()
        .expect("a stale form route");
    assert!(stale.contains("the form route POST / is not in the inventory"), "{stale}");
}

/// Negative — an inventory row that no longer matches the ruling reopens it: another auth mode or
/// class, a body read differently, a caller secret, or a route other than RustFS's STS endpoint.
#[test]
fn n_a_form_route_the_inventory_records_differently_is_refused() {
    let mut signed = sts();
    signed.auth_mode = "custom".to_owned();
    let mut reclassed = sts();
    reclassed.auth_detail = Some("CredentialOnly".to_owned());
    let mut streamed = sts();
    streamed.request_body = "streamed".to_owned();
    let mut sealed = sts();
    sealed.caller_secret_body = "request-on-minio-alias".to_owned();
    for (changed, why) in [
        (signed, "ruled as an anonymous \"StsFormPost\" route"),
        (reclassed, "ruled as an anonymous \"StsFormPost\" route"),
        (streamed, "no longer records a buffered request and response"),
        (sealed, "no longer records a buffered request and response"),
    ] {
        let refused = plan(&inventory(vec![changed]), &[], &[], &[], STS_FORM)
            .err()
            .expect("a changed row is refused");
        assert!(refused.contains(why), "{refused}");
    }
    let mut elsewhere = sts();
    elsewhere.path = "/sts".to_owned();
    let refused = plan(&inventory(vec![elsewhere]), &[], &[], &[], &[("POST", "/sts", "StsFormPost")])
        .err()
        .expect("only the STS endpoint");
    assert!(refused.contains("only RustFS's STS endpoint"), "{refused}");
}
