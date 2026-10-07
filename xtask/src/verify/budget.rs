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

//! Wording for a verification run that failed its feedback budget, or that built inside it.
//!
//! Responsible for: keeping a run that was killed at its deadline distinguishable from a run that
//! finished and was timed, and attributing a build inside the budget to the prebuild that should
//! have run it. NOT responsible for: enforcing the deadline, choosing commands, or deciding what a
//! crate should cost.
//! Upstream: bounded verification. Downstream: the `what` / `where` / `rule` diagnostic lines.

use std::time::Duration;

use super::{GateCommand, GateResult, process, rerun_command};

/// One command that was still running when the deadline killed it.
pub(super) struct KilledStep {
    /// The step label the batch gave the command.
    pub(super) step: String,
    /// The command line that reruns this step with no deadline over it.
    pub(super) command: String,
    /// How many crates cargo reported compiling before the kill.
    pub(super) compiled_crates: usize,
}

/// Why a bounded run failed its budget.
///
/// The two variants are not two wordings of one fact. `Overran` ran to completion and was timed,
/// so its number is a measurement. `KilledAtDeadline` was killed *at* `started + budget` and never
/// finished, so `started.elapsed()` there is the deadline the supervisor just enforced, not the
/// cost of the work. Printing that as `observed` is what made eighteen issues quote the budget
/// back at themselves as if it were evidence (rustfs/gateway#642), so this variant reports no
/// duration at all: what the work costs is not known, and the honest report says so.
pub(super) enum BudgetFailure<'a> {
    /// The work finished, and finishing took longer than the budget allowed.
    Overran { elapsed: Duration },
    /// The work was killed at the deadline, so its cost was never observed.
    KilledAtDeadline { budget: Duration, killed: &'a [KilledStep] },
}

impl BudgetFailure<'_> {
    /// The `what` line: which of the two failures this is, and whether a build ran inside it.
    pub(super) fn what(&self) -> &'static str {
        match self {
            Self::Overran { .. } => "verification exceeded its feedback budget",
            Self::KilledAtDeadline { killed, .. } if compiled_crates(killed) == 0 => {
                "verification was killed at its feedback budget"
            }
            Self::KilledAtDeadline { .. } => "verification was killed at its feedback budget after a build ran inside it",
        }
    }

    /// The `rule` line: the contract that was broken, plus a number only when one was measured.
    pub(super) fn rule(&self, rule: &str) -> String {
        match self {
            Self::Overran { elapsed } => format!("{rule}; observed {:.2}s", elapsed.as_secs_f64()),
            Self::KilledAtDeadline { budget, killed } => {
                let budget = budget.as_secs();
                match compiled_crates(killed) {
                    0 => format!("{rule}; killed at the {budget}s deadline, so what the work costs was never measured"),
                    crates => format!(
                        "{rule}; killed at the {budget}s deadline after {crates} crate compilations inside it, so what the work costs was never measured"
                    ),
                }
            }
        }
    }

    /// Lines naming what was still in flight and the command that would measure it.
    pub(super) fn notes(&self) -> Vec<String> {
        let Self::KilledAtDeadline { killed, .. } = self else {
            return Vec::new();
        };
        let mut notes = Vec::new();
        for step in *killed {
            notes.push(format!(
                "{} was still running at the deadline; measure its real cost with: {}",
                step.step, step.command
            ));
            notes.extend(build_inside_budget(&step.step, &step.command, step.compiled_crates));
        }
        notes
    }
}

/// Notes for every finished step of a batch that compiled crates inside the budget.
///
/// A loop that finished used to report nothing here, so a build inside the budget was visible only
/// when it cost a kill: the first `verify --crate` after an edit relinted the crate's workspace
/// closure inside the 30 seconds and still read as a clean pass (rustfs/gateway#1264).
pub(super) fn builds_inside_budget(commands: &[GateCommand], results: &[GateResult]) -> Vec<String> {
    results
        .iter()
        .filter_map(|(step, output)| {
            let (program, args, _) = commands.iter().find(|(_, _, label)| label == step)?;
            let compiled_crates = output.as_ref().map_or(0, |output| process::build_line_count(&output.stderr));
            Some(build_inside_budget(step, &rerun_command(program, args), compiled_crates))
        })
        .flatten()
        .collect()
}

/// Lines for a loop step that compiled crates inside the budget, whether it then finished or was
/// killed.
///
/// The prebuild runs every command the loop runs, minus the run, so a crate compiled inside the
/// budget is one the prebuild did not cover. That is a defect in xtask, not a cost of the crate:
/// the note says so and names the command, so the issue it prompts is filed against the tooling
/// (rustfs/gateway#1264, #1336 and #1367 were each filed against a crate instead).
fn build_inside_budget(step: &str, command: &str, compiled_crates: usize) -> Vec<String> {
    if compiled_crates == 0 {
        return Vec::new();
    }
    vec![
        format!("{step} compiled {compiled_crates} crates inside the budget; the deadline covered a build, not just the work"),
        format!(
            "{step} built what the prebuild did not cover; that is an xtask defect, not this crate's cost: file an xtask issue naming `{command}`"
        ),
    ]
}

fn compiled_crates(killed: &[KilledStep]) -> usize {
    killed.iter().map(|step| step.compiled_crates).sum()
}
