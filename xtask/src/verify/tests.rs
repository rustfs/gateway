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

use super::*;

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
fn xtask_fast_scope_reuses_the_workspace_feature_graph_for_every_target() {
    let steps = crate_steps("xtask");

    assert_eq!(
        steps[0],
        ["test", "--workspace", "--bin", "xtask", "--test", "xtask-integration"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        steps[1],
        [
            "clippy",
            "--workspace",
            "--bin",
            "xtask",
            "--test",
            "xtask-integration",
            "--",
            "-D",
            "warnings",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
    );
}

#[test]
fn conformance_fast_scope_keeps_integration_contracts_in_the_workspace_gate() {
    let steps = crate_steps("rustfs-gateway-conformance");

    assert_eq!(
        steps,
        vec![
            ["test", "-p", "rustfs-gateway-conformance", "--lib"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            ["clippy", "-p", "rustfs-gateway-conformance", "--lib", "--", "-D", "warnings"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        ]
    );
}

#[test]
fn sig_fast_scope_keeps_statistical_timing_contracts_in_the_workspace_gate() {
    let batches = crate_step_batches("rustfs-gateway-sig");
    let timing = include_str!("../../../crates/sig/tests/timing.rs");
    let statistical_tests = [
        "c_sig_0552_sigv2_difference_position_does_not_change_the_latency",
        "c_sig_0111_an_unknown_key_costs_the_same_as_a_bad_signature",
        "a_match_and_a_mismatch_cost_the_same",
        "c_sig_0107_and_0108_the_position_of_the_difference_does_not_change_the_latency",
    ];

    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].len(), 2);
    let test_step = &batches[0][0];
    for test in statistical_tests {
        assert!(timing.contains(&format!("fn {test}")), "the workspace timing contract must remain active");
    }
    assert_eq!(
        test_step,
        &[
            "test",
            "-p",
            "rustfs-gateway-sig",
            "--",
            "--skip",
            "timing::c_sig_0552_sigv2_difference_position_does_not_change_the_latency",
            "--skip",
            "timing::c_sig_0111_an_unknown_key_costs_the_same_as_a_bad_signature",
            "--skip",
            "timing::a_match_and_a_mismatch_cost_the_same",
            "--skip",
            "timing::c_sig_0107_and_0108_the_position_of_the_difference_does_not_change_the_latency",
            "--exact",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
    );
    assert_eq!(standalone_crate_case("rustfs-gateway-sig"), Some("c-sig-0001"));
    assert_eq!(batches[0][1][0], "clippy");
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
            "--lib",
            "--test",
            "integration",
            "--",
            "--skip",
            "compile_fail::gateway_compile_fail_contracts_are_enforced",
            "--skip",
            GATEWAY_RSS_TEST,
            "--skip",
            GATEWAY_ADDRESS_TABLE_TEST,
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
    assert!(
        include_str!("../../../crates/gateway/src/ext/governor/allocation_tests.rs")
            .contains("fn c_gov_0013_a_million_addresses_do_not_grow_memory()"),
        "the workspace-only address-table contract must remain an active test"
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
            "--skip",
            "c_lim_0037_ten_thousand_half_open_connections_preserve_other_ip_p99",
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
    assert!(
        include_str!("../../../crates/server/tests/server_load/per_ip.rs")
            .contains("fn c_lim_0037_ten_thousand_half_open_connections_preserve_other_ip_p99()"),
        "the workspace-only c-lim-0037 load contract must remain active"
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

fn killed_step(compiled_crates: usize) -> KilledStep {
    KilledStep {
        step: "crate rustfs-gateway-fs step 1".to_owned(),
        command: "cargo test -p rustfs-gateway-fs".to_owned(),
        compiled_crates,
    }
}

/// A run that finished was timed, so its number is evidence and must survive.
#[test]
fn a_measured_overrun_keeps_the_time_the_work_actually_took() {
    let failure = BudgetFailure::Overran {
        elapsed: Duration::from_secs_f64(32.88),
    };

    assert_eq!(failure.what(), "verification exceeded its feedback budget");
    assert_eq!(
        failure.rule("a crate verification loop must finish within 30 seconds"),
        "a crate verification loop must finish within 30 seconds; observed 32.88s"
    );
    assert!(failure.notes().is_empty(), "{:?}", failure.notes());
}

/// A run killed at `started + budget` was never timed. Reporting `started.elapsed()` there prints
/// the deadline back as an observation, which is why eighteen issues all quoted 30.00s.
#[test]
fn a_run_killed_at_the_deadline_reports_no_observation_at_all() {
    let killed = [killed_step(0)];

    let failure = BudgetFailure::KilledAtDeadline {
        budget: Duration::from_secs(30),
        killed: &killed,
    };

    assert_eq!(failure.what(), "verification was killed at its feedback budget");
    assert_ne!(
        failure.what(),
        BudgetFailure::Overran {
            elapsed: Duration::from_secs(30)
        }
        .what(),
        "the kill and the measurement must not share one verdict"
    );
    let rule = failure.rule("a crate verification loop must finish within 30 seconds");
    assert_eq!(
        rule,
        "a crate verification loop must finish within 30 seconds; killed at the 30s deadline, so what the work costs was never measured"
    );
    assert!(!rule.contains("observed"), "{rule}");
    assert_eq!(
        failure.notes(),
        vec![
            "crate rustfs-gateway-fs step 1 was still running at the deadline; measure its real cost with: cargo test -p rustfs-gateway-fs"
        ]
    );
}

/// The dominant cost inside a busted crate budget is a cold build the gate did not produce. A
/// killed step that compiled crates says so; the case above proves one that compiled none does not.
#[test]
fn a_build_inside_the_budget_is_reported_as_a_build_rather_than_as_the_work() {
    let killed = [killed_step(63)];

    let failure = BudgetFailure::KilledAtDeadline {
        budget: Duration::from_secs(30),
        killed: &killed,
    };

    assert_eq!(
        failure.what(),
        "verification was killed at its feedback budget after a build ran inside it"
    );
    assert_eq!(
        failure.rule("a crate verification loop must finish within 30 seconds"),
        "a crate verification loop must finish within 30 seconds; killed at the 30s deadline after 63 crate compilations inside it, so what the work costs was never measured"
    );
    assert!(
        failure
            .notes()
            .iter()
            .any(|note| note.contains("compiled 63 crates inside the budget")),
        "{:?}",
        failure.notes()
    );
}

/// The rerun command is the one thing a killed run can honestly offer: run it with no deadline over
/// it and the cost becomes knowable.
#[test]
fn a_killed_step_is_named_with_the_command_that_would_measure_it() {
    let commands = vec![(
        env!("CARGO").to_owned(),
        vec!["test".to_owned(), "-p".to_owned(), "rustfs-gateway-fs".to_owned()],
        "crate rustfs-gateway-fs step 1".to_owned(),
    )];

    let killed = killed_steps(
        &commands,
        &[CancelledStep {
            index: 0,
            compiled_crates: 63,
        }],
    );

    assert_eq!(killed.len(), 1);
    assert_eq!(killed[0].step, "crate rustfs-gateway-fs step 1");
    assert_eq!(killed[0].command, "cargo test -p rustfs-gateway-fs");
    assert_eq!(killed[0].compiled_crates, 63);
}
