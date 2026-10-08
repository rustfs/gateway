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

//! Responsible for: the loop shape a crate's step batches become, and the controls that each loop
//! is held to a deadline of its own. NOT responsible for: process-supervisor internals, which
//! `process/tests.rs` owns. Upstream: `loops`. Downstream: real shell children timed by a scripted
//! clock, each control in its own test process so none of them queues on the supervisor lock the
//! real-time process controls in this binary wait for.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use super::*;

const BUDGET: Duration = Duration::from_secs(30);
const ISOLATED_CONTROL: &str = "GATEWAY_VERIFY_LOOP_CONTROL";

fn owned(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|argument| (*argument).to_owned()).collect()
}

fn labels(feedback_loop: &FeedbackLoop) -> Vec<Vec<&str>> {
    feedback_loop
        .batches
        .iter()
        .map(|batch| batch.iter().map(|(_, _, label)| label.as_str()).collect())
        .collect()
}

#[test]
fn n_a_single_batch_is_one_loop_under_its_bare_subject() {
    let loops = feedback_loops(&[vec![owned(&["test"]), owned(&["clippy"])]], "crate x", None);

    assert_eq!(loops.len(), 1);
    assert_eq!(loops[0].subject, "crate x", "a one-loop crate must keep the output it always printed");
    assert_eq!(labels(&loops[0]), [vec!["crate x step 1", "crate x step 2"]]);
}

#[test]
fn n_the_conformance_case_runs_first_and_only_in_the_first_loop() {
    let loops = feedback_loops(
        &[
            vec![owned(&["test"]), owned(&["clippy"])],
            vec![owned(&["test", "--test", "socket_timing"])],
        ],
        "crate x",
        Some("c-object-0001"),
    );

    assert_eq!(loops.len(), 2);
    assert_eq!(loops[0].subject, "crate x, loop 1 of 2");
    assert_eq!(loops[1].subject, "crate x, loop 2 of 2");
    assert_eq!(
        labels(&loops[0]),
        [
            vec!["crate x, loop 1 of 2 conformance case c-object-0001"],
            vec!["crate x, loop 1 of 2 step 1", "crate x, loop 1 of 2 step 2"],
        ]
    );
    assert_eq!(labels(&loops[1]), [vec!["crate x, loop 2 of 2 step 3"]]);
    assert_eq!(loops[1].batches[0][0].1, owned(&["test", "--test", "socket_timing"]));
}

/// Runs a control in its own test process, as the full-gate controls do and for the same reason:
/// the supervisor serialises every batch in a process behind one lock that the real-time process
/// controls in this binary wait on. The child must report the one control it ran.
fn isolated(name: &str, control: impl FnOnce()) {
    if std::env::var(ISOLATED_CONTROL).as_deref() == Ok(name) {
        control();
        return;
    }
    let output = Command::new(std::env::current_exe().expect("test executable must be available"))
        .args([format!("verify::loops::tests::{name}"), "--exact".to_owned()])
        .env(ISOLATED_CONTROL, name)
        .output()
        .expect("the isolated control must start");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}{}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("test result: ok. 1 passed"), "the isolated control did not run: {stdout}");
}

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("test clock must be after the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("gateway-verify-loops-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("test directory must be creatable");
        Self(root)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A clock that moves only when a loop's command says so: each marker that exists moves "now" to
/// its offset from `base`, so a deadline passes at a point a command has proven it reached.
struct ScriptedClock {
    base: Instant,
    marks: Vec<(PathBuf, Duration)>,
}

impl ScriptedClock {
    fn now(&self) -> Instant {
        let offset = self
            .marks
            .iter()
            .filter(|(marker, _)| marker.exists())
            .map(|(_, offset)| *offset)
            .max()
            .unwrap_or(Duration::ZERO);
        self.base + offset
    }
}

/// A one-command loop that moves the clock by touching `marker`.
///
/// With `held`, the command then stays alive for two hundred supervisor polls before it touches
/// `held` itself, so a deadline the move passed is seen while it runs: a killed command never
/// writes `held`, and one that was waited for always does. That is what tells a kill at the
/// deadline from an overrun measured after the fact.
fn moving_loop(subject: &str, marker: &Path, held: Option<&Path>) -> FeedbackLoop {
    let hold = held.map_or_else(String::new, |held| {
        format!(
            "; i=0; while [ $i -lt 200 ]; do sleep 0.01; i=$((i + 1)); done; touch '{}'",
            held.display()
        )
    });
    FeedbackLoop {
        subject: subject.to_owned(),
        batches: vec![vec![(
            "sh".to_owned(),
            vec!["-c".to_owned(), format!("touch '{}'{hold}", marker.display())],
            format!("{subject} step"),
        )]],
    }
}

fn options(started: Instant) -> RunOptions<'static> {
    RunOptions {
        json: false,
        operation_cases: None,
        started: Some(started),
        conformance_case: None,
    }
}

/// rustfs/gateway#1264: the facade's socket-timing suites run as a second loop under 30 seconds of
/// their own. The first loop ends 29s in, inside its budget; the second runs 2s, inside its own but
/// past the deadline it would have had if both shared one.
#[test]
fn a_later_loop_is_measured_from_its_own_start() {
    isolated("a_later_loop_is_measured_from_its_own_start", || {
        let fixture = Fixture::new("own-start");
        let (first, second) = (fixture.path("first"), fixture.path("second"));
        let clock = ScriptedClock {
            base: Instant::now(),
            marks: vec![
                (first.clone(), BUDGET - Duration::from_secs(1)),
                (second.clone(), BUDGET + Duration::from_secs(1)),
            ],
        };
        let held = fixture.path("second-held");
        let loops = [
            moving_loop("probe, loop 1 of 2", &first, None),
            moving_loop("probe, loop 2 of 2", &second, Some(&held)),
        ];

        let exit = run_loops(&loops, BUDGET, "rule", options(clock.base), &|| clock.now());

        assert!(held.exists(), "the second loop was killed at a deadline it shared with the first");
        assert_eq!(exit, ExitCode::SUCCESS, "a loop inside its own budget was charged for the loop before it");
    });
}

#[test]
fn n_a_first_loop_past_its_budget_fails_and_starts_no_later_loop() {
    isolated("n_a_first_loop_past_its_budget_fails_and_starts_no_later_loop", || {
        let fixture = Fixture::new("first-over");
        let (first, second) = (fixture.path("first"), fixture.path("second"));
        let clock = ScriptedClock {
            base: Instant::now(),
            marks: vec![(first.clone(), BUDGET + Duration::from_secs(1))],
        };
        let held = fixture.path("first-held");
        let loops = [
            moving_loop("probe, loop 1 of 2", &first, Some(&held)),
            moving_loop("probe, loop 2 of 2", &second, None),
        ];

        let exit = run_loops(&loops, BUDGET, "rule", options(clock.base), &|| clock.now());

        assert_eq!(exit, ExitCode::FAILURE, "a first loop past its budget passed");
        assert!(!held.exists(), "the first loop ran on past its deadline instead of being killed");
        assert!(!second.exists(), "a loop started after the one before it failed its budget");
    });
}

#[test]
fn n_a_later_loop_past_its_own_budget_fails() {
    isolated("n_a_later_loop_past_its_own_budget_fails", || {
        let fixture = Fixture::new("later-over");
        let (first, second) = (fixture.path("first"), fixture.path("second"));
        let clock = ScriptedClock {
            base: Instant::now(),
            marks: vec![
                (first.clone(), BUDGET - Duration::from_secs(1)),
                (second.clone(), BUDGET * 2 + Duration::from_secs(1)),
            ],
        };
        let held = fixture.path("second-held");
        let loops = [
            moving_loop("probe, loop 1 of 2", &first, None),
            moving_loop("probe, loop 2 of 2", &second, Some(&held)),
        ];

        let exit = run_loops(&loops, BUDGET, "rule", options(clock.base), &|| clock.now());

        assert!(second.exists(), "the second loop never ran");
        assert_eq!(exit, ExitCode::FAILURE, "a later loop past its own budget passed");
        assert!(!held.exists(), "a later loop ran on past its own deadline instead of being killed");
    });
}
