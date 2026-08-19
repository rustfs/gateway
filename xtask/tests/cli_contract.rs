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

//! Process-boundary contracts for repository automation.
//!
//! Responsible for: stable exit codes and the JSON route-explanation surface.
//! NOT responsible for: generation semantics, which the codegen crate tests directly.
//! Upstream: the xtask binary. Downstream: CI and agents invoking `cargo xtask`.

use std::process::{Command, Output};

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("xtask must start: {error}"))
}

#[test]
fn route_explain_json_names_the_selected_operation() {
    let output = xtask(&["route", "explain", "--json", "GET /bucket?list-type=2&prefix=a"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"selected\":\"ListObjectsV2\""), "{stdout}");
    assert!(stdout.contains("\"candidates\":"), "{stdout}");
    assert!(stdout.contains("\"predicates\":"), "{stdout}");
}

#[test]
fn an_unknown_operation_is_a_usage_error_with_a_candidate() {
    let output = xtask(&["verify", "--op", "GetObjekt"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("GetObject"), "{stderr}");
}

#[test]
fn a_missing_crate_json_failure_uses_only_the_json_channel() {
    let output = xtask(&["verify", "--json", "--crate", "not-a-real-crate"]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "{\"command\":\"verify\",\"ok\":false,\"what\":\"workspace package could not be resolved\",\"where\":\"crate not-a-real-crate\"}\n"
    );
    assert!(output.stderr.is_empty(), "{}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn a_missing_crate_plain_failure_stays_on_stderr() {
    let output = xtask(&["verify", "--crate", "not-a-real-crate"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{}", String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("what: workspace package could not be resolved"), "{stderr}");
    assert!(stderr.contains("where: crate not-a-real-crate"), "{stderr}");
    assert!(stderr.contains("no exact workspace package `not-a-real-crate`"), "{stderr}");
}

#[test]
fn a_standard_operation_cannot_be_scaffolded() {
    let output = xtask(&["new-op", "GetObject"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("NameCollision"));
}

#[test]
fn model_verify_runs_the_pinned_model_checker() {
    let output = xtask(&["model", "verify"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("upstream is the official aws/api-models-aws repository"), "{stdout}");
    assert!(stdout.contains("ok in "), "{stdout}");
}

#[test]
fn model_verify_rejects_extra_arguments() {
    let output = xtask(&["model", "verify", "extra"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("accepts no arguments"));
}

#[test]
fn model_drift_forwards_the_candidate_path() {
    let output = xtask(&["model", "drift", "--against", "model"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("semantic diff is empty"));
}

#[test]
fn model_drift_propagates_tool_failures() {
    let output = xtask(&["model", "drift", "--against", "missing-model-candidate"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stderr.is_empty());
}

#[test]
fn security_posture_dry_run_reports_standard_operation_floors() {
    let output = xtask(&["security-posture", "--dry-run"]);

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "SECURITY_POSTURE anonymous_reachable_ops=[] custom_verifier=none sigv2_policy=HeaderOnly presigned_allowed_ops=[GetObject] aws_signature_verifier=built-in\n"
    );
}

#[test]
fn security_posture_requires_dry_run_without_extra_arguments() {
    for args in [&["security-posture"][..], &["security-posture", "--dry-run", "extra"]] {
        let output = xtask(args);
        assert_eq!(output.status.code(), Some(2), "args={args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("security-posture accepts exactly --dry-run"),
            "args={args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn usage_names_every_p7_command() {
    let output = xtask(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for command in [
        "verify --op",
        "verify --all",
        "  model verify ",
        "  model drift --against",
        "route explain",
        "security-posture --dry-run",
        "new-op",
        "bootstrap",
    ] {
        assert!(stderr.contains(command), "usage omitted {command}: {stderr}");
    }
}

#[test]
fn help_output_matches_its_golden() {
    let output = xtask(&["--help"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), include_str!("golden/help.txt"));
}
