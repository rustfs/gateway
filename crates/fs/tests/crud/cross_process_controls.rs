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

//! Run private, real-backend process controls in a dedicated test executable.
//!
//! Responsible for: isolating process launches from unrelated parallel unit tests.
//! NOT responsible for: replacing the process controls with a model or production API.
//! Upstream: Cargo's integration test runner; downstream: the crate's private test driver.

#[test]
fn run_private_cross_process_controls() {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let executable = std::env::current_exe().expect("locate the integration executable");
    let target = executable
        .ancestors()
        .find(|path| path.join("CACHEDIR.TAG").is_file())
        .expect("locate the Cargo target directory");
    let output = std::process::Command::new(cargo)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "test",
            "--locked",
            "--offline",
            "-p",
            "rustfs-gateway-fs",
            "--lib",
            "--",
            "--exact",
            "versioning::tests::cross_process_tests::cross_process_controls_driver",
            "--nocapture",
        ])
        .env("CARGO_TARGET_DIR", target)
        .env("GATEWAY_RUN_PROCESS_CONTROLS", "1")
        .output()
        .expect("launch the private process controls");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "private process controls failed: {stdout} {stderr}");
    for control in [
        "an_explicit_cross_process_lock_protects_the_actual_version_update",
        "an_explicit_cross_process_lock_allows_an_unprotected_delete_after_release",
        "n_processes_must_not_allocate_the_same_version_sequence",
        "cancelled_queued_reservation_stops_before_lock_release",
        "process_exit_releases_sequence_reservation_lock",
        "aborted_started_reservation_retains_lock_until_counter_published",
        "sequence_rename_failure_does_not_report_success",
        "sequence_sync_failure_does_not_report_success",
        "deletion_cannot_pass_an_inflight_protection_update",
        "unprotected_deletion_completes_after_the_boundary_is_released",
        "cancelled_queued_deletion_does_not_remove_the_version",
        "started_deletion_keeps_the_boundary_after_request_cancellation",
    ] {
        assert!(stdout.contains(&format!("completed: {control}")), "missing process control: {control}");
    }
}
