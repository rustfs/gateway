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

//! Responsible for: unit contracts for bounded verification selection and process scheduling.
//! NOT responsible for: defining production verification scopes or process supervision.
//! Upstream: `super`. Downstream: the xtask unit-test runner.

use std::fs;

use super::*;

#[test]
fn full_gate_steps_start_before_either_is_awaited() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock must be after the Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("gateway-parallel-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).expect("test directory must be creatable");
    let ready = root.join("ready");
    let first = root.join("first");
    let second = root.join("second");
    let wait_for = |own: &std::path::Path, peer: &std::path::Path| {
        vec![
            "-c".to_owned(),
            format!(
                "test -f '{}' || exit 1; touch '{}'; for _ in $(seq 1 200); do test -f '{}' && exit 0; sleep 0.01; done; exit 1",
                ready.display(),
                own.display(),
                peer.display()
            ),
        ]
    };
    let setup = (
        "sh".to_owned(),
        vec!["-c".to_owned(), format!("touch '{}'", ready.display())],
        "setup".to_owned(),
    );
    let commands = vec![
        ("sh".to_owned(), wait_for(&first, &second), "first".to_owned()),
        ("sh".to_owned(), wait_for(&second, &first), "second".to_owned()),
    ];

    let outputs = run_setup_then_concurrently(&setup, &commands, &root);

    assert!(
        outputs
            .iter()
            .all(|(_, output)| output.as_ref().is_ok_and(|output| output.status.success()))
    );
    fs::remove_dir_all(root).expect("test directory must be removable");
}

#[test]
fn the_facade_accepts_its_current_and_legacy_crate_names() {
    assert_eq!(package_name("rustfs-gateway"), "rustfs-gateway");
    assert_eq!(package_name("s3gate"), "rustfs-gateway");
}

#[test]
fn an_exact_workspace_package_wins_before_prefix_compatibility() {
    let packages = vec!["ext-field-spike".to_owned(), "rustfs-gateway-ext-field-spike".to_owned()];

    assert_eq!(resolve_package_name("ext-field-spike", &packages), Ok("ext-field-spike".to_owned()));
}

#[test]
fn a_missing_workspace_package_is_not_passed_to_cargo() {
    assert_eq!(
        resolve_package_name("absent", &["rustfs-gateway-core".to_owned()]),
        Err(PackageResolutionError::Missing {
            requested: "absent".to_owned(),
            compatible: "rustfs-gateway-absent".to_owned(),
        })
    );
}

#[test]
fn an_ambiguous_workspace_package_is_rejected() {
    let packages = vec!["duplicate".to_owned(), "duplicate".to_owned()];

    let error = PackageResolutionError::Ambiguous {
        requested: "duplicate".to_owned(),
        matches: vec!["duplicate".to_owned(), "duplicate".to_owned()],
    };
    assert_eq!(resolve_package_name("duplicate", &packages), Err(error));
    assert_eq!(
        package_resolution_failure_json(
            "duplicate",
            &PackageResolutionError::Ambiguous {
                requested: "duplicate".to_owned(),
                matches: vec!["duplicate".to_owned(), "duplicate".to_owned()],
            }
        ),
        "{\"command\":\"verify\",\"ok\":false,\"what\":\"workspace package could not be resolved\",\"where\":\"crate duplicate\"}"
    );
}

#[test]
fn a_legacy_short_name_still_resolves_to_the_prefixed_package() {
    assert_eq!(
        resolve_package_name("core", &["rustfs-gateway-core".to_owned()]),
        Ok("rustfs-gateway-core".to_owned())
    );
}

#[test]
fn conformance_fast_scope_keeps_integration_contracts_in_the_workspace_gate() {
    let steps = crate_steps("rustfs-gateway-conformance");

    assert!(steps[0].iter().any(|arg| arg == "--lib"));
    assert!(steps[1].iter().any(|arg| arg == "--all-targets"));
}

#[test]
fn core_fast_scope_runs_both_runtime_targets_concurrently() {
    let batches = crate_step_batches("rustfs-gateway-core");
    let steps = &batches[0];

    assert_eq!(batches.len(), 1);
    assert_eq!(steps.len(), 2);
    assert_eq!(
        steps[0],
        [
            "test",
            "-p",
            "rustfs-gateway-core",
            "--lib",
            "--test",
            "integration",
            "--",
            "--skip",
            "compile_fail::compile_time_contracts_are_not_openable",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
    );
    assert_eq!(
        steps[1],
        ["clippy", "-p", "rustfs-gateway-core", "--all-targets", "--", "-D", "warnings",]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
}

#[test]
fn facade_fast_scope_keeps_heavy_contracts_in_the_workspace_gate() {
    let batches = crate_step_batches("rustfs-gateway");

    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].len(), 2);
    assert_eq!(batches[0][1][0], "clippy");
    assert_eq!(standalone_crate_case("rustfs-gateway"), None);
    assert_eq!(
        batches[0][0],
        [
            "test",
            "-p",
            "rustfs-gateway",
            "--",
            "--skip",
            "compile_fail::gateway_compile_fail_contracts_are_enforced",
            "--skip",
            GATEWAY_RSS_TEST,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
    );
    assert!(
        include_str!("../../../crates/conformance/src/cli.rs").contains("fn feedback_case_c_object_0001()"),
        "the workspace-only representative conformance case must remain active"
    );
    assert!(
        include_str!("../../../crates/gateway/tests/cors_runtime.rs")
            .contains("fn a_million_unique_keys_keep_rss_within_the_entry_budget()"),
        "the workspace-only RSS contract must remain an active test"
    );
}

#[test]
fn server_fast_scope_keeps_thousand_connection_load_in_the_workspace_gate() {
    let batches = crate_step_batches("rustfs-gateway-server");

    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].len(), 2);
    assert_eq!(
        batches[0][0],
        [
            "test",
            "-p",
            "rustfs-gateway-server",
            "--",
            "--skip",
            "c_lim_0006_a_srv_0008_one_thousand_connections_stay_inside_the_rss_budget",
            "--skip",
            "c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
    );
    assert_eq!(batches[0][1][0], "clippy");
    assert!(
        include_str!("../../../crates/server/tests/server_load.rs")
            .contains("fn c_lim_0006_a_srv_0008_one_thousand_connections_stay_inside_the_rss_budget()"),
        "the workspace-only c-lim-0006 load contract must remain active"
    );
    assert!(
        include_str!("../../../crates/server/tests/server_load.rs")
            .contains("fn c_lim_0061_a_srv_0026_one_thousand_slow_readers_close_without_starving_healthy_traffic()"),
        "the workspace-only c-lim-0061 load contract must remain active"
    );
}

#[test]
fn facade_case_does_not_start_a_nested_cargo_process() {
    let steps = crate_steps("rustfs-gateway");

    assert_eq!(steps.len(), 2);
    assert_eq!(crate_case("rustfs-gateway"), Some("c-object-0001"));
    assert_eq!(
        conformance_test_step("c-object-0001"),
        vec![
            "test",
            "-p",
            "rustfs-gateway-conformance",
            "--lib",
            "cli::tests::feedback_case_c_object_0001",
            "--",
            "--exact",
        ]
    );
}
