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

//! The feedback loops a crate or operation verification runs, each under a deadline of its own.
//!
//! Responsible for: turning step batches into loops, running each loop's batches in order under one
//! deadline `budget` after that loop starts, and reporting each loop's measured time or failure.
//! NOT responsible for: choosing steps, building ahead of the deadline, or supervising children.
//! Upstream: crate and operation verification. Downstream: the process supervisor.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use super::budget::{BudgetFailure, builds_inside_budget};
use super::{
    GateCommand, RunOptions, budget_diagnostic, conformance_test_step, diagnostic, killed_steps, print_cargo_failure,
    print_json_failure, print_success, process,
};

/// One feedback loop: batches of concurrently started commands, run in order under one deadline.
pub(super) struct FeedbackLoop {
    /// What the loop's diagnostics and its `passed in` line name.
    pub(super) subject: String,
    pub(super) batches: Vec<Vec<GateCommand>>,
}

/// Each step batch becomes a loop of its own; the crate's conformance case runs first, in the first.
///
/// A crate with one batch keeps its bare subject, so its output reads as it always has. A crate
/// with more names each loop, because each one prints its own measurement.
pub(super) fn feedback_loops(
    step_batches: &[Vec<Vec<String>>],
    subject: &str,
    conformance_case: Option<&str>,
) -> Vec<FeedbackLoop> {
    let count = step_batches.len();
    let mut step_number = 0;
    step_batches
        .iter()
        .enumerate()
        .map(|(index, steps)| {
            let subject = if count > 1 {
                format!("{subject}, loop {} of {count}", index + 1)
            } else {
                subject.to_owned()
            };
            let mut batches = Vec::new();
            if index == 0
                && let Some(case) = conformance_case
            {
                batches.push(vec![(
                    env!("CARGO").to_owned(),
                    conformance_test_step(case),
                    format!("{subject} conformance case {case}"),
                )]);
            }
            batches.push(
                steps
                    .iter()
                    .map(|step| {
                        step_number += 1;
                        (env!("CARGO").to_owned(), step.clone(), format!("{subject} step {step_number}"))
                    })
                    .collect(),
            );
            FeedbackLoop { subject, batches }
        })
        .collect()
}

pub(super) fn run_step_batches(
    step_batches: &[Vec<Vec<String>>],
    budget: Duration,
    subject: &str,
    rule: &str,
    options: RunOptions<'_>,
) -> ExitCode {
    let loops = feedback_loops(step_batches, subject, options.conformance_case);
    run_loops(&loops, budget, rule, options, &Instant::now)
}

/// Runs `loops` in order, each under a deadline of its own, `budget` after that loop started.
///
/// The first loop starts at `started` — the launcher's clock, past the prebuild — and each later
/// one when the loop before it passed, so no loop is charged for another's work. A loop that fails
/// or runs out of time ends the run before the next one starts.
pub(super) fn run_loops(
    loops: &[FeedbackLoop],
    budget: Duration,
    rule: &str,
    options: RunOptions<'_>,
    clock: &dyn Fn() -> Instant,
) -> ExitCode {
    let RunOptions {
        json,
        operation_cases,
        started,
        ..
    } = options;
    let mut loop_started = started.unwrap_or_else(clock);
    for feedback_loop in loops {
        let subject = feedback_loop.subject.as_str();
        for commands in &feedback_loop.batches {
            let batch = process::run_with_clock(commands, Path::new("."), Some(loop_started + budget), clock);
            if batch.interrupted {
                return diagnostic("verification interrupted", subject, rule);
            }
            if batch.timed_out {
                let killed = killed_steps(commands, &batch.cancelled);
                return budget_diagnostic(BudgetFailure::KilledAtDeadline { budget, killed: &killed }, subject, rule);
            }
            for note in builds_inside_budget(commands, &batch.results) {
                eprintln!("verify: {note}");
            }
            for (_, output) in batch.results {
                match output {
                    Ok(output) if output.status.success() => {}
                    Ok(output) => {
                        print_cargo_failure(&output);
                        print_json_failure(json, "verification command failed", subject);
                        return diagnostic(
                            "verification command failed",
                            subject,
                            &format!("{rule}; cargo exited with {}", output.status),
                        );
                    }
                    Err(error) => return diagnostic("cargo could not be started", subject, &format!("{rule}; {error}")),
                }
            }
        }
        let finished = clock();
        let elapsed = finished.saturating_duration_since(loop_started);
        if elapsed > budget {
            return budget_diagnostic(BudgetFailure::Overran { elapsed }, subject, rule);
        }
        print_success(subject, elapsed, json, operation_cases);
        loop_started = finished;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests;
