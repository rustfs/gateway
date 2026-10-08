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

//! Responsible for: the full gate's per-stage and shared-deadline, stage-ordering,
//! descendant-cleanup, and stage-attribution controls. NOT responsible for: process-supervisor
//! internals, which
//! `process/tests.rs` owns. Upstream: `full_gate`. Downstream: real shell children timed by a
//! scripted clock, each control in its own test process, so no control depends on how fast a
//! loaded host runs them or adds a holder to the supervisor lock the process controls queue on.

use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::SystemTime;

use super::super::GateResult;
use super::*;

const BUDGET: Duration = Duration::from_secs(480);
const ISOLATED_CONTROL: &str = "GATEWAY_FULL_GATE_CONTROL";

/// Runs a control in its own test process.
///
/// The supervisor serialises every batch in a process behind one lock, and the process-supervisor
/// controls in this binary wait on it under real-time deadlines as short as a second
/// (rustfs/gateway#455, #497). A child process has a lock of its own, so these controls never
/// lengthen that queue. The child must report the one control it ran: a filter that matched
/// nothing would otherwise pass here.
fn isolated(name: &str, control: impl FnOnce()) {
    if std::env::var(ISOLATED_CONTROL).as_deref() == Ok(name) {
        control();
        return;
    }
    let output = Command::new(std::env::current_exe().expect("test executable must be available"))
        .args([format!("verify::full_gate::tests::{name}"), "--exact".to_owned()])
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

fn stage(name: &str, deadline: Deadline, commands: Vec<GateCommand>) -> Stage {
    Stage {
        name: name.to_owned(),
        commands,
        deadline,
    }
}

fn reading(elapsed: Duration, charged: Duration) -> StageClock {
    StageClock {
        elapsed,
        charged,
        budget: BUDGET,
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
    isolated("every_stage_runs_and_a_stage_starts_all_its_commands_before_awaiting_one", || {
        let fixture = Fixture::new("stages");
        let clock = ScriptedClock::frozen();
        let barrier = |own: &str, peer: &str| {
            format!(
                "test -f build || exit 1; touch {own}; for _ in $(seq 1 1000); do test -f {peer} && exit 0; sleep 0.01; done; exit 1"
            )
        };
        let stages = [
            stage("build", Deadline::Own(BUDGET), vec![shell("touch build", "build")]),
            stage(
                "tests",
                Deadline::Previous,
                vec![
                    shell(&barrier("first", "second"), "first"),
                    shell(&barrier("second", "first"), "second"),
                ],
            ),
        ];

        let run = run_stages(&stages, &fixture.0, &|| clock.now());

        assert!(
            succeeded(&run.batch) && run.batch.results.len() == 2,
            "the second stage's commands did not both run to success"
        );
        assert_eq!(run.stage, 1, "the gate stopped before its last stage");
        let still = reading(Duration::ZERO, Duration::ZERO);
        assert_eq!(run.clocks, [still, still], "the stages were not measured by the gate's clock");
        assert_eq!(run.elapsed, Duration::ZERO, "the gate was not measured by its clock");
    });
}

#[test]
fn an_expired_deadline_starts_no_stage() {
    isolated("an_expired_deadline_starts_no_stage", || {
        let fixture = Fixture::new("expired");
        let clock = ScriptedClock::ahead_of_the_real_clock();
        let stages = [
            stage("build", Deadline::Own(Duration::ZERO), vec![shell("touch build", "build")]),
            stage("tests", Deadline::Previous, vec![shell("touch tests", "tests")]),
        ];

        let run = run_stages(&stages, &fixture.0, &|| clock.now());

        assert!(run.batch.timed_out, "an expired deadline was not reported as timed out");
        assert_eq!(run.stage, 0, "an expired deadline blamed a later stage");
        assert_eq!(run.clocks.len(), 1, "a stage after the expired one was measured");
        // A command that was started is either killed on the supervisor's first poll or has already
        // succeeded, so an empty cancellation list is what proves nothing was started.
        assert!(cancelled(&run).is_empty(), "an expired deadline started a command and killed it");
        assert!(!fixture.path("build").exists(), "an expired deadline started its stage");
        assert!(!fixture.path("tests").exists(), "an expired deadline started a later stage");
    });
}

/// A stage that claims the previous stage's deadline when there is none has no budget to run in.
/// It fails closed: nothing starts, and it never runs without a deadline.
#[test]
fn a_first_stage_that_claims_a_previous_deadline_starts_nothing() {
    isolated("a_first_stage_that_claims_a_previous_deadline_starts_nothing", || {
        let fixture = Fixture::new("no-previous");
        let clock = ScriptedClock::ahead_of_the_real_clock();
        let stages = [stage("build", Deadline::Previous, vec![shell("touch build", "build")])];

        let run = run_stages(&stages, &fixture.0, &|| clock.now());

        assert!(run.batch.timed_out, "a stage with no deadline to inherit was not stopped");
        assert!(cancelled(&run).is_empty(), "a stage with no deadline to inherit was started");
        assert!(!fixture.path("build").exists(), "a stage with no deadline to inherit ran");
        assert_eq!(
            run.clocks,
            [StageClock {
                budget: Duration::ZERO,
                ..reading(Duration::ZERO, Duration::ZERO)
            }]
        );
    });
}

#[test]
fn a_deadline_in_the_first_stage_kills_its_process_group_and_starts_no_later_stage() {
    isolated("a_deadline_in_the_first_stage_kills_its_process_group_and_starts_no_later_stage", || {
        let fixture = Fixture::new("first-stage");
        let clock = ScriptedClock::moved_by(vec![(fixture.path("expire"), BUDGET * 2)]);
        let stages = [
            stage("build", Deadline::Own(BUDGET), vec![shell(&held_descendant("expire"), "build")]),
            stage("tests", Deadline::Own(BUDGET), vec![shell("touch tests", "tests")]),
        ];

        let run = run_stages(&stages, &fixture.0, &|| clock.now());

        assert!(run.batch.timed_out, "the build ran on past its deadline");
        assert_eq!(run.stage, 0, "the deadline was blamed on a stage that never started");
        assert_eq!(cancelled(&run), [0], "the killed build step was not reported");
        assert_eq!(run.clocks.len(), 1, "a stage after the killed one was measured");
        assert!(
            !fixture.path("tests").exists(),
            "a later stage with its own deadline started after a kill"
        );
        assert_descendant_was_killed(&fixture);
    });
}

#[test]
fn a_deadline_in_a_later_stage_kills_that_stage_s_process_group() {
    isolated("a_deadline_in_a_later_stage_kills_that_stage_s_process_group", || {
        let fixture = Fixture::new("later-stage");
        let clock = ScriptedClock::moved_by(vec![(fixture.path("expire"), BUDGET * 2)]);
        let stages = [
            stage("build", Deadline::Own(BUDGET), vec![shell("touch build", "build")]),
            stage("tests", Deadline::Previous, vec![shell(&held_descendant("expire"), "tests")]),
        ];

        let run = run_stages(&stages, &fixture.0, &|| clock.now());

        assert!(run.batch.timed_out, "the later stage ran on past its deadline");
        assert_eq!(run.stage, 1, "the deadline was blamed on the stage that had finished");
        assert_eq!(cancelled(&run), [0], "the killed step was not reported against its own stage");
        assert_eq!(run.clocks.len(), 2, "the finished build was not measured");
        assert_descendant_was_killed(&fixture);
    });
}

#[test]
fn a_shared_deadline_gives_no_time_back_to_the_stage_that_inherits_it() {
    isolated("a_shared_deadline_gives_no_time_back_to_the_stage_that_inherits_it", || {
        let fixture = Fixture::new("shared-deadline");
        let spent = BUDGET - Duration::from_secs(10);
        let late = BUDGET + Duration::from_secs(10);
        let clock = ScriptedClock::moved_by(vec![(fixture.path("spent"), spent), (fixture.path("late"), late)]);
        let stages = [
            stage("build", Deadline::Own(BUDGET), vec![shell("touch spent", "build")]),
            stage("tests", Deadline::Previous, vec![shell(&held_descendant("late"), "tests")]),
        ];

        let run = run_stages(&stages, &fixture.0, &|| clock.now());

        // A deadline renewed for the inheriting stage, or extended by what the build took, is still
        // hundreds of seconds away when the clock reads `late`.
        assert!(run.batch.timed_out, "the inheriting stage was given back the build's time");
        assert_eq!(run.stage, 1, "the deadline was blamed on the stage that had finished");
        assert_eq!(
            run.clocks,
            [reading(spent, spent), reading(late - spent, late)],
            "the shared budget was not charged with both stages"
        );
        assert_eq!(run.elapsed, late, "the gate's time is not what its clock measured when it stopped");
        assert_descendant_was_killed(&fixture);
    });
}

/// The fix for rustfs/gateway#1247: a stage with a deadline of its own starts its own clock. Here
/// the guard stage finishes past the point a single gate-wide deadline would have killed it.
#[test]
fn a_stage_with_its_own_deadline_is_not_charged_for_an_earlier_stage() {
    isolated("a_stage_with_its_own_deadline_is_not_charged_for_an_earlier_stage", || {
        let fixture = Fixture::new("own-deadline");
        let spent = BUDGET - Duration::from_secs(10);
        let beyond = spent + BUDGET - Duration::from_secs(10);
        let clock = ScriptedClock::moved_by(vec![(fixture.path("spent"), spent), (fixture.path("beyond"), beyond)]);
        let stages = [
            stage("tests", Deadline::Own(BUDGET), vec![shell("touch spent", "tests")]),
            stage("guard", Deadline::Own(BUDGET), vec![shell("touch beyond", "guard")]),
        ];

        let run = run_stages(&stages, &fixture.0, &|| clock.now());

        assert!(succeeded(&run.batch), "the guard stage was charged for the tests' time");
        assert_eq!(run.stage, 1, "the gate stopped before its last stage");
        assert_eq!(
            run.clocks,
            [reading(spent, spent), reading(beyond - spent, beyond - spent)],
            "each stage was not measured against its own budget"
        );
        assert_eq!(run.elapsed, beyond, "the gate's time is not what its clock measured");
    });
}

#[test]
fn a_stage_with_its_own_deadline_is_still_killed_at_it() {
    isolated("a_stage_with_its_own_deadline_is_still_killed_at_it", || {
        let fixture = Fixture::new("own-deadline-kill");
        let spent = BUDGET - Duration::from_secs(10);
        let late = spent + BUDGET + Duration::from_secs(10);
        let clock = ScriptedClock::moved_by(vec![(fixture.path("spent"), spent), (fixture.path("late"), late)]);
        let stages = [
            stage("tests", Deadline::Own(BUDGET), vec![shell("touch spent", "tests")]),
            stage("guard", Deadline::Own(BUDGET), vec![shell(&held_descendant("late"), "guard")]),
        ];

        let run = run_stages(&stages, &fixture.0, &|| clock.now());

        assert!(run.batch.timed_out, "the guard stage ran on past its own deadline");
        assert_eq!(run.stage, 1, "the deadline was blamed on the stage that had finished");
        assert_eq!(cancelled(&run), [0], "the killed guard step was not reported");
        assert_eq!(
            run.clocks[1],
            reading(late - spent, late - spent),
            "the killed stage was not measured from its own start"
        );
        assert_eq!(run.elapsed, late, "the gate's time is not what its clock measured when it stopped");
        assert_descendant_was_killed(&fixture);
    });
}

/// A stage can finish between two supervisor polls after its deadline passed. It is then over its
/// budget without having been killed, and the gate must stop there rather than start the next
/// stage on a fresh deadline. The clock moves only once the stage's process has been reaped, so
/// the supervisor sees a finished stage, never an expired one.
#[test]
fn a_stage_that_finishes_past_its_own_budget_starts_no_later_stage() {
    isolated("a_stage_that_finishes_past_its_own_budget_starts_no_later_stage", || {
        let fixture = Fixture::new("overrun");
        let base = Instant::now();
        let late = BUDGET + Duration::from_secs(10);
        let (marker, pid) = (fixture.path("late"), fixture.path("stage.pid"));
        let clock = || {
            let reaped = marker.exists() && fs::read_to_string(&pid).is_ok_and(|pid| !process_alive(pid.trim()));
            base + if reaped { late } else { Duration::ZERO }
        };
        let stages = [
            stage(
                "tests",
                Deadline::Own(BUDGET),
                vec![shell("printf '%s' \"$$\" > stage.pid; touch late", "tests")],
            ),
            stage("guard", Deadline::Own(BUDGET), vec![shell("touch guard", "guard")]),
        ];

        let run = run_stages(&stages, &fixture.0, &clock);

        assert!(succeeded(&run.batch), "the stage was killed rather than finishing late");
        assert_eq!(run.stage, 0, "the gate went on past a stage that overran its budget");
        assert_eq!(run.clocks, [reading(late, late)], "the overrun was not measured");
        assert!(!fixture.path("guard").exists(), "a later stage started after an overrun");
        assert_eq!(overrun(&run.clocks), Some(0), "the overrun stage is not the verdict");
    });
}

#[test]
fn a_failed_stage_starts_no_later_stage() {
    isolated("a_failed_stage_starts_no_later_stage", || {
        let fixture = Fixture::new("failed-stage");
        let clock = ScriptedClock::frozen();
        let stages = [
            stage("build", Deadline::Own(BUDGET), vec![shell("printf build-error >&2; exit 7", "build")]),
            stage("tests", Deadline::Own(BUDGET), vec![shell("touch tests", "tests")]),
        ];

        let run = run_stages(&stages, &fixture.0, &|| clock.now());

        assert!(!run.batch.timed_out, "a failed build was reported as a timeout");
        assert_eq!(run.stage, 0, "the failure was blamed on a stage that never started");
        assert_eq!(run.batch.results.len(), 1);
        let output = run.batch.results[0].1.as_ref().expect("the build must have run");
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stderr, b"build-error", "the failed build's diagnostics were lost");
        assert!(!fixture.path("tests").exists(), "a later stage ran after the build failed");
    });
}

fn secs(seconds: f64) -> Duration {
    Duration::from_secs_f64(seconds)
}

fn gate_run(stage: usize, batch: Batch, clocks: Vec<StageClock>, elapsed: f64) -> GateRun {
    GateRun {
        stage,
        batch,
        clocks,
        elapsed: secs(elapsed),
    }
}

fn batch(timed_out: bool, results: Vec<GateResult>) -> Batch {
    Batch {
        results,
        timed_out,
        interrupted: false,
        cancelled: Vec::new(),
    }
}

fn full_gate_stages() -> [Stage; 3] {
    [
        stage("workspace test build", Deadline::Own(BUDGET), Vec::new()),
        stage("workspace tests", Deadline::Previous, Vec::new()),
        stage("guard self-test", Deadline::Own(BUDGET), Vec::new()),
    ]
}

const SUBJECT: &str = "workspace tests and build guards";

/// A deadline that ran out in the build is the build's, and nothing finished to be measured.
#[test]
fn a_deadline_in_the_build_is_attributed_to_the_build() {
    let run = gate_run(0, batch(true, Vec::new()), vec![reading(secs(480.04), secs(480.04))], 480.04);

    assert_eq!(
        stage_subject(SUBJECT, &full_gate_stages(), run.stage),
        "workspace tests and build guards: workspace test build stage"
    );
    assert_eq!(
        stage_notes(&run, &full_gate_stages()),
        [
            "the deadline ran out during workspace test build, 480.04s into its 480s budget; the gate was stopped 480.04s after it started"
        ]
    );
}

/// Once the build finished, its time is a measurement: the report keeps it, names the stage the
/// deadline stopped and the budget it shares, and prints when the stage was actually stopped.
#[test]
fn a_deadline_in_the_tests_reports_the_build_against_the_budget_they_share() {
    let clocks = vec![reading(secs(0.51), secs(0.51)), reading(secs(479.53), secs(480.04))];
    let run = gate_run(1, batch(true, Vec::new()), clocks, 480.04);

    assert_eq!(
        stage_subject(SUBJECT, &full_gate_stages(), run.stage),
        "workspace tests and build guards: workspace tests stage"
    );
    assert_eq!(
        stage_notes(&run, &full_gate_stages()),
        [
            "workspace test build finished in 0.51s, 0.51s into its 480s budget",
            "the deadline ran out during workspace tests, 480.04s into the 480s budget it shares with workspace test build; the gate was stopped 480.04s after it started",
        ]
    );
}

/// The receipt rustfs/gateway#1247 was filed over named the gate's 600s, which the guard stage
/// never had to itself. The guard's deadline is now its own, and the report says how far into it
/// the stage was stopped as well as how long the whole gate had run.
#[test]
fn a_deadline_in_the_guard_is_reported_against_the_guard_s_own_budget() {
    let clocks = vec![
        reading(secs(0.51), secs(0.51)),
        reading(secs(227.36), secs(227.87)),
        reading(secs(480.01), secs(480.01)),
    ];
    let run = gate_run(2, batch(true, Vec::new()), clocks, 707.88);

    assert_eq!(
        stage_subject(SUBJECT, &full_gate_stages(), run.stage),
        "workspace tests and build guards: guard self-test stage"
    );
    assert_eq!(
        stage_notes(&run, &full_gate_stages()),
        [
            "workspace test build finished in 0.51s, 0.51s into its 480s budget",
            "workspace tests finished in 227.36s, 227.87s into the 480s budget it shares with workspace test build",
            "the deadline ran out during guard self-test, 480.01s into its 480s budget; the gate was stopped 707.88s after it started",
        ]
    );
}

#[test]
fn a_passing_gate_reports_every_stage_against_its_own_budget() {
    let clocks = vec![
        reading(secs(0.51), secs(0.51)),
        reading(secs(227.36), secs(227.87)),
        reading(secs(322.14), secs(322.14)),
    ];
    let run = gate_run(2, batch(false, Vec::new()), clocks, 550.01);

    assert_eq!(
        stage_notes(&run, &full_gate_stages()),
        [
            "workspace test build finished in 0.51s, 0.51s into its 480s budget",
            "workspace tests finished in 227.36s, 227.87s into the 480s budget it shares with workspace test build",
            "guard self-test finished in 322.14s, 322.14s into its 480s budget",
        ]
    );
    assert_eq!(overrun(&run.clocks), None, "a gate whose every stage fit was judged over budget");
}

/// A failed stage did not finish its work, so it is not reported as having finished it.
#[test]
fn a_failed_stage_is_not_reported_as_finished() {
    let failed = Output {
        status: ExitStatus::from_raw(7 << 8),
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let clocks = vec![reading(secs(0.51), secs(0.51)), reading(secs(12.0), secs(12.51))];
    let run = gate_run(1, batch(false, vec![("workspace tests".to_owned(), Ok(failed))]), clocks, 12.51);

    assert_eq!(
        stage_notes(&run, &full_gate_stages()),
        ["workspace test build finished in 0.51s, 0.51s into its 480s budget"]
    );
}

/// Every stage is judged against its own budget: an earlier stage over its budget is the verdict
/// even if a later one fit, and a stage that used exactly its budget is not over it.
#[test]
fn an_overrun_is_found_in_whichever_stage_had_it() {
    let over = reading(secs(1.0), BUDGET + Duration::from_millis(1));
    let fit = reading(secs(1.0), secs(1.0));
    let exact = reading(secs(1.0), BUDGET);

    assert_eq!(overrun(&[over, fit]), Some(0));
    assert_eq!(overrun(&[fit, over]), Some(1));
    assert_eq!(overrun(&[fit, exact]), None);
    assert_eq!(overrun(&[]), None);
}

/// A kill and an overrun are each judged against the budget of the stage that had them: the guard
/// stage's kill quotes the guard's 480s, not a gate-wide number, and nothing fails a passing gate.
#[test]
fn a_budget_verdict_names_the_stage_that_failed_and_quotes_its_budget() {
    let guard = StageClock {
        budget: Duration::from_secs(300),
        ..reading(secs(300.01), secs(300.01))
    };
    let workspace = reading(secs(1.0), secs(1.0));
    let killed = gate_run(2, batch(true, Vec::new()), vec![workspace, workspace, guard], 302.01);
    let Some((2, failure)) = budget_failure(&killed, &[]) else {
        panic!("the guard stage's kill was not its verdict");
    };
    assert_eq!(
        failure.rule("r"),
        "r; killed at the 300s deadline, so what the work costs was never measured"
    );

    let over = reading(secs(1.0), BUDGET + Duration::from_secs(1));
    let overran = gate_run(0, batch(false, Vec::new()), vec![over], 481.0);
    let Some((0, failure)) = budget_failure(&overran, &[]) else {
        panic!("the overrun stage was not the verdict");
    };
    assert_eq!(failure.rule("r"), "r; observed 481.00s");

    let fit = gate_run(1, batch(false, Vec::new()), vec![reading(secs(1.0), secs(1.0)); 2], 2.0);
    assert!(budget_failure(&fit, &[]).is_none(), "a gate whose every stage fit failed its budget");
}
