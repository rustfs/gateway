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

//! The `case.applies_to.profiles` gate under the `rustfs` profile.
//!
//! Responsible for: proving a case that names only `rustfs` is skipped under `aws` with the gate
//! named and selected under `rustfs`, that a `minio`-only case is skipped under `rustfs`, and that
//! the frozen schema still refuses the spelling in a case file — the gate is reached through a
//! synthetic `Case` because the schema's enum is closed, and that closure is pinned here rather
//! than assumed.
//! NOT responsible for: the profile's behaviour, which lives in the target.
//! Upstream: `super`. Downstream: Cargo's test harness.

use super::*;
use crate::schema::Schema;
use crate::sut::{Profile, Unwired};
use std::path::PathBuf;

fn case_declaring(profiles: &[&str]) -> Case {
    let list = profiles.iter().map(|p| format!("\"{p}\"")).collect::<Vec<_>>().join(", ");
    let document =
        crate::toml::parse(&format!("[case]\nid = \"c-probe-0001\"\napplies_to = {{ profiles = [{list}] }}\n")).expect("parses");
    Case {
        id: "c-probe-0001".to_owned(),
        domain: "probe".to_owned(),
        path: PathBuf::from("/nowhere/c-probe-0001.toml"),
        relative: "cases/probe/c-probe-0001.toml".to_owned(),
        document: Some(document),
        diagnostics: Vec::new(),
    }
}

fn under(profile: Profile) -> RunOptions {
    RunOptions {
        profile,
        ..RunOptions::default()
    }
}

#[test]
fn a_rustfs_only_case_is_skipped_under_aws_with_the_gate_named() {
    let reason = inapplicable(&case_declaring(&["rustfs"]), &under(Profile::Aws), &Unwired).expect("skipped");
    assert!(reason.contains("[rustfs]") && reason.contains("`aws`"), "{reason}");
}

#[test]
fn a_rustfs_only_case_is_selected_under_rustfs() {
    assert_eq!(inapplicable(&case_declaring(&["rustfs"]), &under(Profile::Rustfs), &Unwired), None);
}

/// Negative — the `rustfs` profile must not inherit MinIO's cases.
#[test]
fn a_minio_only_case_is_skipped_under_rustfs() {
    let reason = inapplicable(&case_declaring(&["minio"]), &under(Profile::Rustfs), &Unwired).expect("skipped");
    assert!(reason.contains("[minio]") && reason.contains("`rustfs`"), "{reason}");
}

#[test]
fn a_case_naming_no_profile_is_selected_under_rustfs() {
    let document = crate::toml::parse("[case]\nid = \"c-probe-0001\"\n").expect("parses");
    let case = Case {
        document: Some(document),
        ..case_declaring(&["aws"])
    };
    assert_eq!(inapplicable(&case, &under(Profile::Rustfs), &Unwired), None);
}

/// Negative — the frozen schema's enum is closed. A case file cannot name `rustfs` until the
/// Breaking Change process widens `conformance/case.schema.json`; this test goes red the day it
/// does, so the synthetic cases above stop being the only way to reach the gate.
#[test]
fn the_frozen_schema_refuses_a_case_file_naming_the_rustfs_profile() {
    let root = Corpus::discover_root().expect("the repository corpus");
    let schema = Schema::compile(&std::fs::read_to_string(root.join("case.schema.json")).expect("the schema")).expect("compiles");
    let minio_only = std::fs::read_to_string(root.join("cases/naming/c-naming-0025.toml")).expect("a minio-only case");
    assert!(minio_only.contains("profiles = [\"minio\"]"), "the control case moved");
    let control = crate::toml::parse(&minio_only).expect("parses");
    assert!(schema.validate(&control).is_empty(), "the control case must validate");
    let widened = crate::toml::parse(&minio_only.replace("profiles = [\"minio\"]", "profiles = [\"rustfs\"]")).expect("parses");
    let violations = schema.validate(&widened);
    assert!(
        violations.iter().any(|violation| violation.to_string().contains("profiles")),
        "the schema accepted `rustfs`: {violations:?}"
    );
}
