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

//! Responsible for: the full gate's shared-deadline, stage-ordering, descendant-cleanup, and
//! stage-attribution controls. NOT responsible for: process-supervisor internals, which
//! `process/tests.rs` owns. Upstream: `full_gate`. Downstream: real shell children timed by a
//! scripted clock, so no control depends on how fast a loaded host runs them.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::SystemTime;

use super::*;

const BUDGET: Duration = Duration::from_secs(600);

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("test clock must be after the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("gateway-full-gate-{label}-{}-{nonce}", std::process::id()));
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

/// A clock that moves only when a child says so.
///
/// Each marker that exists moves "now" to its offset from `base`; with no marker it stands still.
/// A deadline therefore expires at a point a child has proven it reached — never at a wall-clock
/// instant that a loaded host can reach before the child has started, or long after it finished.
struct ScriptedClock {
    base: Instant,
    marks: Vec<(PathBuf, Duration)>,
}

impl ScriptedClock {
    fn frozen() -> Self {
        Self::moved_by(Vec::new())
    }

    /// A frozen clock an hour ahead of the real one, so a deadline it has passed is still in the
    /// real clock's future: only a supervisor that reads this clock sees the deadline as expired.
    fn ahead_of_the_real_clock() -> Self {
        Self {
            base: Instant::now() + Duration::from_secs(3600),
            marks: Vec::new(),
        }
    }

    fn moved_by(marks: Vec<(PathBuf, Duration)>) -> Self {
        Self {
            base: Instant::now(),
            marks,
        }
    }

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

fn shell(script: &str, step: &str) -> GateCommand {
    ("sh".to_owned(), vec!["-c".to_owned(), script.to_owned()], step.to_owned())
}

fn stage(name: &str, commands: Vec<GateCommand>) -> Stage {
    Stage {
        name: name.to_owned(),
        commands,
    }
}

/// Starts a descendant in the command's process group, publishes its pid, touches `marker` to move
/// the clock, and waits for it. The descendant blocks until the test writes `release` and then
/// touches `escaped`. It gives up by itself after a thousand polls, so an implementation that never
/// kills it fails the control instead of hanging it.
fn held_descendant(marker: &str) -> String {
    format!(
        "( i=0; while [ ! -f release ] && [ $i -lt 1000 ]; do sleep 0.01; i=$((i + 1)); done; touch escaped ) & \
         printf '%s' \"$!\" > descendant.pid; touch {marker}; wait"
    )
}

fn process_alive(pid: &str) -> bool {
    Command::new("/bin/kill")
        .args(["-0", pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Releases the descendant and observes which of the two things happens first.
///
/// A surviving descendant reaches `escaped` within one poll of its release; a killed one is gone.
/// Neither outcome is inferred from elapsed time. The minute-long bound exists only so that a
/// wedged host fails the suite rather than hanging it.
fn assert_descendant_was_killed(fixture: &Fixture) {
    let pid = fs::read_to_string(fixture.path("descendant.pid")).expect("the descendant must have published its pid");
    fs::write(fixture.path("release"), b"").expect("the release marker must be writable");
    for _ in 0..6000 {
        assert!(!fixture.path("escaped").exists(), "the deadline left a descendant of the stage running");
        if !process_alive(pid.trim()) {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("descendant {} neither exited nor escaped after its release", pid.trim());
}

fn cancelled(run: &GateRun) -> Vec<usize> {
    run.batch.cancelled.iter().map(|step| step.index).collect()
}

#[test]
fn every_stage_runs_and_a_stage_starts_all_its_commands_before_awaiting_one() {
    let fixture = Fixture::new("stages");
    let clock = ScriptedClock::frozen();
    let barrier = |own: &str, peer: &str| {
        format!(
            "test -f build || exit 1; touch {own}; for _ in $(seq 1 1000); do test -f {peer} && exit 0; sleep 0.01; done; exit 1"
        )
    };
    let stages = [
        stage("build", vec![shell("touch build", "build")]),
        stage(
            "tests",
            vec![
                shell(&barrier("first", "second"), "first"),
                shell(&barrier("second", "first"), "second"),
            ],
        ),
    ];

    let run = run_stages(&stages, &fixture.0, BUDGET, &|| clock.now());

    assert!(
        succeeded(&run.batch) && run.batch.results.len() == 2,
        "the second stage's commands did not both run to success"
    );
    assert_eq!(run.stage, 1, "the gate stopped before its last stage");
    assert_eq!(run.finished, [Duration::ZERO], "the finished build was not measured by the gate's clock");
    assert_eq!(run.elapsed, Duration::ZERO, "the gate was not measured by its clock");
}

#[test]
fn an_expired_gate_starts_no_stage() {
    let fixture = Fixture::new("expired");
    let clock = ScriptedClock::ahead_of_the_real_clock();
    let stages = [
        stage("build", vec![shell("touch build", "build")]),
        stage("tests", vec![shell("touch tests", "tests")]),
    ];

    let run = run_stages(&stages, &fixture.0, Duration::ZERO, &|| clock.now());

    assert!(run.batch.timed_out, "an expired gate was not reported as timed out");
    assert_eq!(run.stage, 0, "an expired gate blamed a later stage");
    assert!(run.finished.is_empty(), "an expired gate reported a finished stage");
    assert!(!fixture.path("build").exists(), "an expired gate started its first stage");
    assert!(!fixture.path("tests").exists(), "an expired gate started a later stage");
}

#[test]
fn a_deadline_in_the_first_stage_kills_its_process_group_and_starts_no_later_stage() {
    let fixture = Fixture::new("first-stage");
    let clock = ScriptedClock::moved_by(vec![(fixture.path("expire"), BUDGET * 2)]);
    let stages = [
        stage("build", vec![shell(&held_descendant("expire"), "build")]),
        stage("tests", vec![shell("touch tests", "tests")]),
    ];

    let run = run_stages(&stages, &fixture.0, BUDGET, &|| clock.now());

    assert!(run.batch.timed_out, "the build ran on past the gate's deadline");
    assert_eq!(run.stage, 0, "the deadline was blamed on a stage that never started");
    assert_eq!(cancelled(&run), [0], "the killed build step was not reported");
    assert!(run.finished.is_empty(), "a killed stage was reported as finished");
    assert!(!fixture.path("tests").exists(), "a later stage started after the deadline");
    assert_descendant_was_killed(&fixture);
}

#[test]
fn a_deadline_in_a_later_stage_kills_that_stage_s_process_group() {
    let fixture = Fixture::new("later-stage");
    let clock = ScriptedClock::moved_by(vec![(fixture.path("expire"), BUDGET * 2)]);
    let stages = [
        stage("build", vec![shell("touch build", "build")]),
        stage("tests", vec![shell(&held_descendant("expire"), "tests")]),
    ];

    let run = run_stages(&stages, &fixture.0, BUDGET, &|| clock.now());

    assert!(run.batch.timed_out, "the later stage ran on past the gate's deadline");
    assert_eq!(run.stage, 1, "the deadline was blamed on the stage that had finished");
    assert_eq!(cancelled(&run), [0], "the killed step was not reported against its own stage");
    assert_eq!(run.finished.len(), 1, "the finished build was not measured");
    assert_descendant_was_killed(&fixture);
}

#[test]
fn time_spent_in_an_earlier_stage_is_not_given_back_to_a_later_one() {
    let fixture = Fixture::new("shared-deadline");
    let spent = BUDGET - Duration::from_secs(10);
    let late = BUDGET + Duration::from_secs(10);
    let clock = ScriptedClock::moved_by(vec![(fixture.path("spent"), spent), (fixture.path("late"), late)]);
    let stages = [
        stage("build", vec![shell("touch spent", "build")]),
        stage("tests", vec![shell(&held_descendant("late"), "tests")]),
    ];

    let run = run_stages(&stages, &fixture.0, BUDGET, &|| clock.now());

    // A deadline renewed for the later stage, or extended by what the build took, is still
    // hundreds of seconds away when the clock reads `late`.
    assert!(run.batch.timed_out, "the later stage was given back the build's time");
    assert_eq!(run.stage, 1, "the deadline was blamed on the stage that had finished");
    assert_eq!(run.finished, [spent], "the build's time is not what the gate's clock measured");
    assert_eq!(run.elapsed, late, "the gate's time is not what its clock measured when it stopped");
    assert_descendant_was_killed(&fixture);
}

#[test]
fn a_failed_stage_starts_no_later_stage() {
    let fixture = Fixture::new("failed-stage");
    let clock = ScriptedClock::frozen();
    let stages = [
        stage("build", vec![shell("printf build-error >&2; exit 7", "build")]),
        stage("tests", vec![shell("touch tests", "tests")]),
    ];

    let run = run_stages(&stages, &fixture.0, BUDGET, &|| clock.now());

    assert!(!run.batch.timed_out, "a failed build was reported as a timeout");
    assert_eq!(run.stage, 0, "the failure was blamed on a stage that never started");
    assert_eq!(run.batch.results.len(), 1);
    let output = run.batch.results[0].1.as_ref().expect("the build must have run");
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stderr, b"build-error", "the failed build's diagnostics were lost");
    assert!(!fixture.path("tests").exists(), "a later stage ran after the build failed");
}

fn timed_out_run(stage: usize, finished: Vec<Duration>, elapsed: Duration) -> GateRun {
    GateRun {
        stage,
        batch: Batch {
            results: Vec::new(),
            timed_out: true,
            interrupted: false,
            cancelled: Vec::new(),
        },
        finished,
        elapsed,
    }
}

fn full_gate_stages() -> [Stage; 2] {
    [
        stage("workspace test build", Vec::new()),
        stage("workspace tests and guard self-test", Vec::new()),
    ]
}

/// A deadline that ran out in the build is the build's, and nothing finished to be measured.
#[test]
fn a_deadline_in_the_build_is_attributed_to_the_build() {
    let run = timed_out_run(0, Vec::new(), Duration::from_secs_f64(600.04));

    let (where_, notes) = timeout_report(&run, &full_gate_stages(), "workspace tests and build guards");

    assert_eq!(where_, "workspace tests and build guards: workspace test build stage");
    assert_eq!(
        notes,
        ["the deadline ran out during workspace test build; the gate was stopped 600.04s after it started"]
    );
}

/// Once the build finished, its time is a measurement: the report keeps it, names the stage the
/// deadline stopped, and prints when the gate actually stopped rather than the budget.
#[test]
fn a_deadline_after_the_build_reports_what_the_build_measured() {
    let run = timed_out_run(1, vec![Duration::from_secs_f64(412.3)], Duration::from_secs_f64(600.04));

    let (where_, notes) = timeout_report(&run, &full_gate_stages(), "workspace tests and build guards");

    assert_eq!(where_, "workspace tests and build guards: workspace tests and guard self-test stage");
    assert_eq!(
        notes,
        [
            "workspace test build finished in 412.30s",
            "the deadline ran out during workspace tests and guard self-test; the gate was stopped 600.04s after it started",
        ]
    );
}
