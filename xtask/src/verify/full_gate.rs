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

//! The full gate's stages, run in order under one deadline.
//!
//! Responsible for: starting each stage only after every earlier stage succeeded, handing every
//! stage the same supervised deadline so time an earlier stage spent is never given back, and
//! reporting which stage the deadline ran out in together with what the finished stages measured.
//! NOT responsible for: choosing the gate's commands or its budget, or supervising processes.
//! Upstream: `cargo xtask verify` and `cargo xtask verify --all`. Downstream: the process
//! supervisor, which kills a stage's whole process group at the deadline.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use super::budget::BudgetFailure;
use super::process::{self, Batch};
use super::{GateCommand, budget_diagnostic, diagnostic, killed_steps, print_cargo_failure, print_json_failure, print_success};

/// Commands that start together once every earlier stage has succeeded.
pub(super) struct Stage {
    pub(super) name: String,
    pub(super) commands: Vec<GateCommand>,
}

/// Where a gate stopped, and what its clock measured on the way there.
struct GateRun {
    /// Index of the last stage that was started; `batch` is that stage's.
    stage: usize,
    /// The last stage's batch. Its step and cancellation indices refer to that stage's commands.
    batch: Batch,
    /// Measured wall time of each earlier stage, every one of which finished and succeeded.
    finished: Vec<Duration>,
    /// Measured wall time from the gate's start until `batch` returned, kills and reaping included.
    elapsed: Duration,
}

/// Runs `stages` under one `budget` and renders the outcome as the gate's exit.
pub(super) fn verify(stages: &[Stage], current_dir: &Path, budget: Duration, subject: &str, rule: &str, json: bool) -> ExitCode {
    let run = run_stages(stages, current_dir, budget, &Instant::now);
    report(run, stages, budget, subject, rule, json)
}

fn run_stages(stages: &[Stage], current_dir: &Path, budget: Duration, clock: &dyn Fn() -> Instant) -> GateRun {
    let started = clock();
    // One deadline for every stage: a stage that starts late inherits what is left, not a budget.
    let deadline = started + budget;
    let mut finished = Vec::new();
    for (index, stage) in stages.iter().enumerate() {
        let stage_started = clock();
        let batch = process::run_with_clock(&stage.commands, current_dir, Some(deadline), clock);
        let now = clock();
        if index + 1 == stages.len() || !succeeded(&batch) {
            return GateRun {
                stage: index,
                batch,
                finished,
                elapsed: now.saturating_duration_since(started),
            };
        }
        finished.push(now.saturating_duration_since(stage_started));
    }
    GateRun {
        stage: 0,
        batch: Batch {
            results: Vec::new(),
            timed_out: false,
            interrupted: false,
            cancelled: Vec::new(),
        },
        finished,
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

fn report(run: GateRun, stages: &[Stage], budget: Duration, subject: &str, rule: &str, json: bool) -> ExitCode {
    if run.batch.interrupted {
        return diagnostic("verification interrupted", subject, rule);
    }
    if run.batch.timed_out {
        let (where_, notes) = timeout_report(&run, stages, subject);
        for note in notes {
            eprintln!("verify: {note}");
        }
        let commands = stages.get(run.stage).map_or(&[][..], |stage| stage.commands.as_slice());
        let killed = killed_steps(commands, &run.batch.cancelled);
        return budget_diagnostic(BudgetFailure::KilledAtDeadline { budget, killed: &killed }, &where_, rule);
    }
    for (step, output) in run.batch.results {
        match output {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                print_cargo_failure(&output);
                print_json_failure(json, "verification command failed", &step);
                return diagnostic(
                    "verification command failed",
                    &step,
                    &format!("{rule}; command exited with {}", output.status),
                );
            }
            Err(error) => {
                return diagnostic("verification command could not start", &step, &format!("{rule}; {error}"));
            }
        }
    }
    if run.elapsed > budget {
        return budget_diagnostic(BudgetFailure::Overran { elapsed: run.elapsed }, subject, rule);
    }
    print_success(subject, run.elapsed, json, None);
    ExitCode::SUCCESS
}

/// The `where` line and the notes for a gate the deadline stopped.
///
/// A finished stage ran to completion, so its time is a measurement and is printed as one. The
/// stage the deadline stopped is named, with the time the gate actually stopped at — kills and
/// reaping included — which is when the gate gave up, not what that stage's work would have cost.
fn timeout_report(run: &GateRun, stages: &[Stage], subject: &str) -> (String, Vec<String>) {
    let mut notes: Vec<String> = stages
        .iter()
        .zip(&run.finished)
        .map(|(stage, elapsed)| format!("{} finished in {:.2}s", stage.name, elapsed.as_secs_f64()))
        .collect();
    let Some(stage) = stages.get(run.stage) else {
        return (subject.to_owned(), notes);
    };
    notes.push(format!(
        "the deadline ran out during {}; the gate was stopped {:.2}s after it started",
        stage.name,
        run.elapsed.as_secs_f64()
    ));
    (format!("{subject}: {} stage", stage.name), notes)
}

#[cfg(all(test, unix))]
mod tests;
