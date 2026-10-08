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

//! The full gate's stages, run in order, each under the deadline it declares.
//!
//! Responsible for: starting each stage only after every earlier stage succeeded within its budget,
//! opening a fresh supervised deadline for a stage that declares its own and handing an inheriting
//! stage the deadline already in force so time spent under it is never given back, and reporting
//! every started stage against its budget: what the finished stages measured, and which stage the
//! deadline ran out in.
//! NOT responsible for: choosing the gate's commands or budgets, or supervising processes.
//! Upstream: `cargo xtask verify` and `cargo xtask verify --all`. Downstream: the process
//! supervisor, which kills a stage's whole process group at the deadline.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use super::budget::{BudgetFailure, KilledStep};
use super::process::{self, Batch};
use super::{GateCommand, budget_diagnostic, diagnostic, killed_steps, print_cargo_failure, print_json_failure, print_success};

/// Commands that start together once every earlier stage has succeeded.
pub(super) struct Stage {
    pub(super) name: String,
    pub(super) commands: Vec<GateCommand>,
    pub(super) deadline: Deadline,
}

/// The deadline a stage runs under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Deadline {
    /// A deadline of its own, this long after the stage starts: time an earlier stage spent is
    /// neither charged to this stage nor handed to it.
    Own(Duration),
    /// The deadline the previous stage ran under: time the previous stage spent is not given back.
    Previous,
}

/// What the gate's clock measured for one stage it started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StageClock {
    /// From the stage's start until its batch returned, kills and reaping included.
    elapsed: Duration,
    /// From the start of the deadline the stage ran under until its batch returned. Larger than
    /// `elapsed` when the stage inherited a deadline an earlier stage opened.
    charged: Duration,
    /// The budget of the deadline the stage ran under.
    budget: Duration,
}

/// Where a gate stopped, and what its clock measured on the way there.
struct GateRun {
    /// Index of the last stage that was started; `batch` is that stage's.
    stage: usize,
    /// The last stage's batch. Its step and cancellation indices refer to that stage's commands.
    batch: Batch,
    /// One reading per started stage, in order. Every one before `stage` finished and succeeded.
    clocks: Vec<StageClock>,
    /// Measured wall time from the gate's start until `batch` returned, kills and reaping included.
    elapsed: Duration,
}

/// Runs `stages` in order, each under its own deadline, and renders the outcome as the gate's exit.
pub(super) fn verify(stages: &[Stage], current_dir: &Path, subject: &str, rule: &str, json: bool) -> ExitCode {
    let run = run_stages(stages, current_dir, &Instant::now);
    report(run, stages, subject, rule, json)
}

fn run_stages(stages: &[Stage], current_dir: &Path, clock: &dyn Fn() -> Instant) -> GateRun {
    let started = clock();
    // When the deadline in force opened, and its budget.
    let mut open: Option<(Instant, Duration)> = None;
    let mut clocks = Vec::new();
    for (index, stage) in stages.iter().enumerate() {
        let stage_started = clock();
        let (opened, budget) = match stage.deadline {
            Deadline::Own(budget) => *open.insert((stage_started, budget)),
            // With no earlier deadline to inherit there is no time to run in: fail closed rather
            // than run without a deadline.
            Deadline::Previous => *open.get_or_insert((stage_started, Duration::ZERO)),
        };
        let batch = process::run_with_clock(&stage.commands, current_dir, Some(opened + budget), clock);
        let now = clock();
        clocks.push(StageClock {
            elapsed: now.saturating_duration_since(stage_started),
            charged: now.saturating_duration_since(opened),
            budget,
        });
        // A stage can finish between two supervisor polls after its deadline passed: over budget
        // without being killed. The next stage would start on a fresh deadline, so stop here.
        if index + 1 == stages.len() || !succeeded(&batch) || overrun(&clocks).is_some() {
            return GateRun {
                stage: index,
                batch,
                clocks,
                elapsed: now.saturating_duration_since(started),
            };
        }
    }
    GateRun {
        stage: 0,
        batch: Batch {
            results: Vec::new(),
            timed_out: false,
            interrupted: false,
            cancelled: Vec::new(),
        },
        clocks,
        elapsed: clock().saturating_duration_since(started),
    }
}

fn succeeded(batch: &Batch) -> bool {
    !batch.timed_out
        && !batch.interrupted
        && batch
            .results
            .iter()
            .all(|(_, output)| output.as_ref().is_ok_and(|output| output.status.success()))
}

fn report(run: GateRun, stages: &[Stage], subject: &str, rule: &str, json: bool) -> ExitCode {
    if run.batch.interrupted {
        return diagnostic("verification interrupted", subject, rule);
    }
    for note in stage_notes(&run, stages) {
        eprintln!("verify: {note}");
    }
    let results = if run.batch.timed_out {
        &[][..]
    } else {
        run.batch.results.as_slice()
    };
    for (step, output) in results {
        match output {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                print_cargo_failure(output);
                print_json_failure(json, "verification command failed", step);
                return diagnostic(
                    "verification command failed",
                    step,
                    &format!("{rule}; command exited with {}", output.status),
                );
            }
            Err(error) => {
                return diagnostic("verification command could not start", step, &format!("{rule}; {error}"));
            }
        }
    }
    let commands = stages.get(run.stage).map_or(&[][..], |stage| stage.commands.as_slice());
    let killed = killed_steps(commands, &run.batch.cancelled);
    if let Some((index, failure)) = budget_failure(&run, &killed) {
        return budget_diagnostic(failure, &stage_subject(subject, stages, index), rule);
    }
    print_success(subject, run.elapsed, json, None);
    ExitCode::SUCCESS
}

/// The stage that failed its budget, and how: killed at its deadline, or finished past it.
///
/// Either verdict quotes the budget of the deadline that stage ran under, never another stage's.
fn budget_failure<'a>(run: &GateRun, killed: &'a [KilledStep]) -> Option<(usize, BudgetFailure<'a>)> {
    if run.batch.timed_out {
        let budget = run.clocks.get(run.stage).map_or(Duration::ZERO, |clock| clock.budget);
        return Some((run.stage, BudgetFailure::KilledAtDeadline { budget, killed }));
    }
    overrun(&run.clocks).map(|index| {
        let elapsed = run.clocks[index].charged;
        (index, BudgetFailure::Overran { elapsed })
    })
}

/// The first stage that finished further into its deadline than its budget allows.
fn overrun(clocks: &[StageClock]) -> Option<usize> {
    clocks.iter().position(|clock| clock.charged > clock.budget)
}

/// The `where` line for a verdict on one stage.
fn stage_subject(subject: &str, stages: &[Stage], index: usize) -> String {
    stages
        .get(index)
        .map_or_else(|| subject.to_owned(), |stage| format!("{subject}: {} stage", stage.name))
}

/// One line per stage the gate started, each against the budget of the deadline it ran under.
///
/// A stage that finished is a measurement and is printed as one. The stage the deadline stopped is
/// named with how far into its budget it was stopped, kills and reaping included, and when the gate
/// gave up: neither is what that stage's work would have cost. A failed stage gets no line; its
/// diagnostic follows.
fn stage_notes(run: &GateRun, stages: &[Stage]) -> Vec<String> {
    let mut notes = Vec::new();
    for (index, (stage, clock)) in stages.iter().zip(&run.clocks).enumerate() {
        let budget = budget_phrase(stages, index, clock.budget);
        let charged = clock.charged.as_secs_f64();
        if index < run.stage || succeeded(&run.batch) {
            notes.push(format!(
                "{} finished in {:.2}s, {charged:.2}s into {budget}",
                stage.name,
                clock.elapsed.as_secs_f64()
            ));
        } else if run.batch.timed_out {
            notes.push(format!(
                "the deadline ran out during {}, {charged:.2}s into {budget}; the gate was stopped {:.2}s after it started",
                stage.name,
                run.elapsed.as_secs_f64()
            ));
        }
    }
    notes
}

/// Names the budget a stage ran under, and the stage that opened it when that was another one.
fn budget_phrase(stages: &[Stage], index: usize, budget: Duration) -> String {
    let budget = budget.as_secs();
    let opener = stages[..=index]
        .iter()
        .rposition(|stage| matches!(stage.deadline, Deadline::Own(_)));
    match opener {
        Some(opener) if opener != index => format!("the {budget}s budget it shares with {}", stages[opener].name),
        _ => format!("its {budget}s budget"),
    }
}

#[cfg(all(test, unix))]
mod tests;
