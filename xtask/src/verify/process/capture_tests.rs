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

//! Deadline capture reporting controls using real supervised child output.
//!
//! Responsible for: retaining failed-stage evidence and identifying unreadable captures.
//! NOT responsible for: changing deadlines or measuring gate performance.
//! Upstream: the verification process supervisor. Downstream: child-process test fixtures.

use super::*;

fn capture_report(mode: &str) -> String {
    let output = test_executable("verify::process::tests::capture_tests::capture_report_helper")
        .env("GATEWAY_CAPTURE_REPORT_MODE", mode)
        .output()
        .expect("capture reporting helper must start");
    assert!(output.status.success(), "helper failed: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stderr).expect("fixture diagnostics must be text")
}

#[test]
fn deadline_does_not_discard_test_progress_from_stdout() {
    let report = capture_report("deadline");
    assert!(report.contains("test retained_progress ... ok"), "cancelled stdout disappeared: {report}");
}

#[test]
fn deadline_during_spawn_keeps_already_running_child_output() {
    let report = capture_report("startup-deadline");
    assert!(
        report.contains("test retained_progress ... ok"),
        "startup cancellation lost output: {report}"
    );
}

#[test]
fn deadline_does_not_discard_nested_build_identities_from_stderr() {
    let report = capture_report("deadline");
    assert!(
        report.contains("Compiling nested-contract v1.2.3"),
        "compilation identity disappeared: {report}"
    );
    assert!(report.contains("Checking nested-check v4.5.6"), "check identity disappeared: {report}");
}

#[test]
fn missing_stdout_is_reported_as_unreadable() {
    let report = capture_report("missing-stdout");
    assert!(
        report.contains("could not read captured stdout for capture fixture"),
        "missing capture was silent: {report}"
    );
}

#[test]
fn missing_stderr_is_reported_as_unreadable() {
    let report = capture_report("missing-stderr");
    assert!(
        report.contains("could not read captured stderr for capture fixture"),
        "missing capture was silent: {report}"
    );
}

#[test]
fn successful_capture_is_not_replayed_as_a_deadline_failure() {
    let report = capture_report("success");
    assert!(
        !report.contains("retained_progress") && !report.contains("nested-contract"),
        "successful output was replayed: {report}"
    );
}

#[test]
fn startup_deadline_does_not_relabel_a_completed_success_as_killed() {
    let _ = capture_report("completed-startup-success");
}

#[test]
fn startup_deadline_does_not_discard_a_completed_failure() {
    let _ = capture_report("completed-startup-failure");
}

fn assert_exited_startup_result(code: i32) {
    let root = test_root("completed-before-startup-deadline");
    let marker = root.join("ready");
    let pid_file = root.join("child.pid");
    let commands = vec![
        shell(
            vec![
                "-c".to_owned(),
                format!(
                    "echo $$ > '{}'; printf 'completed child'; touch '{}'; exit {code}",
                    pid_file.display(),
                    marker.display()
                ),
            ],
            "completed fixture",
        ),
        shell(vec!["-c".to_owned(), "exit 0".to_owned()], "must not start"),
    ];
    let now = Instant::now();
    let deadline = now + Duration::from_secs(3600);
    let spawning = std::cell::Cell::new(false);
    let batch = run_with_clock(&commands, &root, Some(deadline), &|| {
        if spawning.replace(true) {
            wait_for_file(&marker);
            let pid = fs::read_to_string(&pid_file).expect("ready child must publish its pid");
            assert!(!descendant_can_execute(pid.trim()), "first child must have actually exited");
            deadline
        } else {
            now
        }
    });
    fs::remove_dir_all(root).expect("fixture directory must be removable");
    let completed = batch
        .results
        .into_iter()
        .map(|(step, result)| result.map(|output| (step, output.status.code(), output.stdout)))
        .collect::<io::Result<Vec<_>>>()
        .expect("completed fixture capture must remain readable");
    assert_eq!(
        (batch.timed_out, batch.cancelled.len(), completed),
        (true, 0, vec![("completed fixture".to_owned(), Some(code), b"completed child".to_vec())]),
        "startup expiry must retain completed output and its real exit status without calling it killed"
    );
}

#[test]
fn capture_report_helper() {
    let Ok(mode) = std::env::var("GATEWAY_CAPTURE_REPORT_MODE") else {
        return;
    };
    if mode == "completed-startup-success" || mode == "completed-startup-failure" {
        assert_exited_startup_result(if mode == "completed-startup-success" { 0 } else { 7 });
        return;
    }
    let root = test_root("deadline-capture");
    let marker = root.join("ready");
    let tail = if mode == "success" { "exit 0" } else { "exec sleep 30" };
    let script = format!(
        "printf 'test retained_progress ... ok\\n'; printf '   Compiling nested-contract v1.2.3\\n   Checking nested-check v4.5.6\\n' >&2; touch '{}'; {tail}",
        marker.display()
    );
    if mode == "startup-deadline" {
        let commands = vec![
            shell(vec!["-c".to_owned(), script], "capture fixture"),
            shell(vec!["-c".to_owned(), "exit 0".to_owned()], "must not start"),
        ];
        let now = Instant::now();
        let deadline = now + Duration::from_secs(3600);
        let spawning = std::cell::Cell::new(false);
        let batch = run_with_clock(&commands, &root, Some(deadline), &|| {
            if spawning.replace(true) {
                wait_for_file(&marker);
                deadline
            } else {
                now
            }
        });
        assert!(batch.timed_out, "startup deadline must terminate the first child");
        fs::remove_dir_all(root).expect("fixture directory must be removable");
        return;
    }
    let mut supervisor = test_supervisor(capture_root().expect("capture directory must be creatable"));
    supervisor
        .spawn(0, "sh", &["-c".to_owned(), script], "capture fixture", &root)
        .expect("capture fixture must start");
    wait_for_file(&marker);
    if mode == "missing-stdout" {
        fs::remove_file(&supervisor.children[0].stdout).expect("stdout capture must exist before removal");
    }
    if mode == "missing-stderr" {
        fs::remove_file(&supervisor.children[0].stderr).expect("stderr capture must exist before removal");
    }
    // The child publishes readiness only after writing both streams. Expire after that
    // observation, so scheduler delay cannot erase the evidence this fixture tests.
    let deadline = if mode == "success" { None } else { Some(Instant::now()) };
    let batch = supervisor.wait(deadline);
    if mode == "success" {
        assert!(all_succeeded(&batch, 1), "the success control did not complete");
    } else {
        assert!(batch.timed_out, "the deadline control did not terminate its child");
    }
    drop(supervisor);
    fs::remove_dir_all(root).expect("fixture directory must be removable");
}
