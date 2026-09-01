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

//! Stable process contracts for P7 repository automation.
//!
//! Responsible for: checking exit classes, compact semantic output, case-id routing, and
//! diagnostics. NOT responsible for: the slow workspace and bootstrap time budgets, which CI owns.
//! Upstream: the xtask binary. Downstream: agents and CI.

use std::process::{Command, Output};

const BOOTSTRAP_SOURCE: &str = include_str!("../src/bootstrap.rs");
const VERIFY_MAP_GUARD: &str = include_str!("../../scripts/check_verify_map_generated.sh");

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("xtask must start: {error}"))
}

#[test]
fn spec_and_generated_verification_map_are_clean() {
    let output = xtask(&["spec", "verify"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("0 differ"));
}

#[test]
fn semantic_diff_is_never_more_than_fifty_lines() {
    let output = xtask(&["codegen", "diff", "--semantic"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).lines().count() <= 50);
}

#[test]
fn a_case_id_can_drive_route_explain() {
    let output = xtask(&["route", "explain", "--json", "c-object-0001"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"selected\":\"GetObject\""));
}

#[test]
fn headers_participate_in_route_explain() {
    let output = xtask(&[
        "route",
        "explain",
        "--json",
        "PUT /target/key",
        "--header",
        "x-amz-copy-source:/source/key",
    ]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"selected\":\"CopyObject\""));
}

#[test]
fn case_headers_participate_in_route_explain() {
    let output = xtask(&["route", "explain", "--json", "c-authz-1002"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"selected\":\"CopyObject\""));
}

#[test]
fn a_failed_verification_has_the_diagnostic_triplet() {
    let output = xtask(&["verify", "--crate", "not-a-real-crate"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    for key in ["what:", "where:", "rule:"] {
        assert!(stderr.contains(key), "missing {key}: {stderr}");
    }
}

#[test]
fn every_assembly_rule_reports_its_real_test_coverage() {
    for rule in rustfs_gateway::RuleRef::ALL {
        let output = xtask(&["why", rule.as_str()]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(rule.as_str()), "{stdout}");
        let has_direct_case = !stdout.contains("CASES     NONE");
        assert_eq!(output.status.success(), has_direct_case, "{stdout}");
    }
}

#[test]
fn bootstrap_checks_generated_output_once_without_rewriting_it() {
    assert_eq!(
        BOOTSTRAP_SOURCE.matches("codegen::verify_generated()").count(),
        1,
        "bootstrap must verify generated output exactly once"
    );
    assert!(
        !BOOTSTRAP_SOURCE.contains("codegen::regenerate()"),
        "zero-diff verification makes immediate regeneration duplicate work"
    );
    let verify = BOOTSTRAP_SOURCE
        .find("codegen::verify_generated()")
        .expect("bootstrap must verify generated output");
    let compile = BOOTSTRAP_SOURCE
        .find("cargo test could not start")
        .expect("bootstrap must still compile the workspace tests");
    assert!(verify < compile, "generated output must be verified before test compilation");
}

#[test]
fn generated_map_guard_does_not_build_the_ir_validator() {
    assert!(
        VERIFY_MAP_GUARD.contains("run --quiet --package xtask --no-default-features -- codegen --check"),
        "the generated-map guard must compile only its codegen path"
    );
}
