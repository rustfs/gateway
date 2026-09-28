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

//! The `decode-diff` and `encode-diff` runners: a whole input set through the diff, judged by the
//! register, with an exit status that says which kind of failure it was.
//!
//! Responsible for: the command line both binaries share; running the recorded corpus
//! (`--corpus`) or the built-in matrix (`--builtin`); stratified sampling (`--per-bucket N`: the
//! first N entries of every operation, in file order); the time budget (`--budget-seconds`); the
//! report; and the exit statuses — [`EXIT_ENVIRONMENT`] when there is nothing to measure (an empty
//! or missing corpus is never "zero differences"), [`EXIT_HARNESS`], then [`EXIT_DIFFERENCES`] when
//! a difference is unregistered, and only then [`EXIT_BUDGET`] when the run outgrew its budget (a
//! slow run with a difference reports the difference, not advice to sample it away). A partial
//! head capture is judged only when both stacks route it to its recorded operation: a header the
//! recorder did not see can change the route, so any other route is a capture artifact, counted
//! as a skip.
//! NOT responsible for: finding or judging a difference (`decode.rs`, `encode.rs`, `known.rs`).
//! Upstream: `corpus.rs`, `samples`. Downstream: `src/bin/*.rs`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use rustfs_gateway::{MonotonicClock, SystemMonotonic};

use crate::corpus::{self, Adjustment};
use crate::known::{KnownDiffs, Verdict};
use crate::{Differ, Finding};

/// Every input was compared and every difference is registered.
pub const EXIT_PASSED: u8 = 0;
/// At least one difference no register entry accepts.
pub const EXIT_DIFFERENCES: u8 = 1;
/// Nothing to measure, or the inputs could not be read: an environment problem, never a pass.
pub const EXIT_ENVIRONMENT: u8 = 2;
/// The harness itself failed on an input.
pub const EXIT_HARNESS: u8 = 3;
/// The run took longer than its budget: split it (`--per-bucket`) in the pull-request gate and
/// run the full set nightly, rather than letting the gate grow.
pub const EXIT_BUDGET: u8 = 4;

/// Which inputs to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inputs {
    /// The recorded corpus under this directory.
    Corpus(PathBuf),
    /// The built-in matrix.
    Builtin,
}

/// The command line both runners take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// What to run.
    pub inputs: Inputs,
    /// Keep the first this many entries of every operation.
    pub per_bucket: Option<usize>,
    /// Fail with [`EXIT_BUDGET`] when the run takes longer.
    pub budget: Option<Duration>,
}

const USAGE: &str = "usage: <runner> (--corpus DIR | --builtin) [--per-bucket N] [--budget-seconds S]";

impl Options {
    /// Reads the arguments after the program name.
    ///
    /// # Errors
    ///
    /// A usage message naming what was wrong.
    pub fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut inputs = None;
        let (mut per_bucket, mut budget) = (None, None);
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            let mut value = |name: &str| arguments.next().ok_or_else(|| format!("{name} needs a value\n{USAGE}"));
            match argument.as_str() {
                "--corpus" => inputs = Some(Inputs::Corpus(PathBuf::from(value("--corpus")?))),
                "--builtin" => inputs = Some(Inputs::Builtin),
                "--per-bucket" => {
                    let count = value("--per-bucket")?;
                    per_bucket = Some(
                        count
                            .parse()
                            .map_err(|_| format!("--per-bucket {count:?} is not a count\n{USAGE}"))?,
                    );
                }
                "--budget-seconds" => {
                    let seconds = value("--budget-seconds")?;
                    let seconds: u64 = seconds
                        .parse()
                        .map_err(|_| format!("--budget-seconds {seconds:?} is not a number of seconds\n{USAGE}"))?;
                    budget = Some(Duration::from_secs(seconds));
                }
                other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
            }
        }
        Ok(Self {
            inputs: inputs.ok_or_else(|| format!("name the inputs\n{USAGE}"))?,
            per_bucket,
            budget,
        })
    }
}

/// What a run measured.
#[derive(Debug, Default)]
pub struct Report {
    /// Inputs compared.
    pub compared: usize,
    /// Inputs not sent, by reason.
    pub skipped: BTreeMap<String, usize>,
    /// Adjustments made to recorded inputs, by kind.
    pub adjusted: BTreeMap<String, usize>,
    /// Unregistered differences, with the input they came from.
    pub failures: Vec<(String, Finding)>,
    /// Registered differences, by register id.
    pub known: BTreeMap<String, usize>,
    /// Inputs the harness failed on, with the reason.
    pub harness: Vec<(String, String)>,
    /// Operations with inputs of which none was compared: every one was skipped.
    pub uncompared: Vec<String>,
    /// How long the run took.
    pub elapsed: Duration,
}

impl Report {
    fn judge(&mut self, id: &str, verdict: Verdict) {
        self.compared += 1;
        for (_, known) in verdict.known {
            *self.known.entry(known).or_default() += 1;
        }
        for finding in verdict.failures {
            self.failures.push((id.to_owned(), finding));
        }
    }

    /// The exit status, and the text to print.
    #[must_use]
    pub fn conclude(&self, kind: &str, budget: Option<Duration>) -> (u8, String) {
        let mut text = String::new();
        let _ = writeln!(
            text,
            "{kind}: {} compared, {} skipped, {} unregistered difference(s), {} registered, {} harness failure(s), in {:.1}s",
            self.compared,
            self.skipped.values().sum::<usize>(),
            self.failures.len(),
            self.known.values().sum::<usize>(),
            self.harness.len(),
            self.elapsed.as_secs_f64()
        );
        for (reason, count) in &self.skipped {
            let _ = writeln!(text, "  skipped {count}: {reason}");
        }
        for (adjustment, count) in &self.adjusted {
            let _ = writeln!(text, "  adjusted {count}: {adjustment}");
        }
        for (id, count) in &self.known {
            let _ = writeln!(text, "  registered {id}: {count}");
        }
        for (input, finding) in &self.failures {
            let _ = writeln!(text, "UNREGISTERED {input}: {finding}");
        }
        for (input, reason) in &self.harness {
            let _ = writeln!(text, "HARNESS {input}: {reason}");
        }
        for operation in &self.uncompared {
            let _ = writeln!(text, "UNCOMPARED {operation}: every input was skipped; nothing measures this operation");
        }
        if self.compared == 0 {
            let _ = writeln!(text, "ENVIRONMENT: nothing was compared; an empty input set is not a pass");
            return (EXIT_ENVIRONMENT, text);
        }
        if !self.harness.is_empty() {
            return (EXIT_HARNESS, text);
        }
        if !self.failures.is_empty() {
            return (EXIT_DIFFERENCES, text);
        }
        if let Some(budget) = budget.filter(|budget| self.elapsed > *budget) {
            let _ = writeln!(
                text,
                "OUT OF BUDGET: {:.1}s exceeds {}s; sample the pull-request gate with --per-bucket and run the full set nightly",
                self.elapsed.as_secs_f64(),
                budget.as_secs()
            );
            return (EXIT_BUDGET, text);
        }
        (EXIT_PASSED, text)
    }
}

/// One decode input.
struct Input {
    /// Its stable id.
    id: String,
    /// The operation it samples under: the corpus bucket, or a built-in row's family.
    operation: String,
    /// A partial head capture: compared only when both stacks route it to `operation`.
    partial: bool,
    /// The request, or why it is skipped.
    request: Result<(crate::RawRequest, Vec<Adjustment>), String>,
}

/// Why a recorded request of an operation the diff does not project is not judged: the gateway
/// harness registers no handler for it, so every such request would be a 501 against s3s's route.
const NOT_DIFFED: &str = "an operation the decode diff does not project";

/// Why a partial capture that both stacks do not route to its recorded operation is not judged.
const PARTIAL_ROUTED_AWAY: &str =
    "partial head capture routed away from its recorded operation (a header the recorder did not see can change the route)";

fn register() -> Result<KnownDiffs, String> {
    KnownDiffs::checked_in().map_err(|error| format!("the known-diffs register: {error}"))
}

/// Runs the decode diff over `options.inputs`.
///
/// # Errors
///
/// The inputs or the register cannot be read, or the stacks do not build: an environment failure.
pub fn decode(options: &Options) -> Result<Report, String> {
    let register = register()?;
    let differ = Differ::new()?;
    let clock = SystemMonotonic::new();
    let started = clock.monotonic();
    let mut report = Report::default();
    let inputs: Vec<Input> = match &options.inputs {
        Inputs::Corpus(root) => {
            if !root.is_dir() {
                return Err(format!("the corpus {} does not exist", root.display()));
            }
            corpus::load(root)?
                .into_iter()
                .map(|entry| Input {
                    id: entry.id,
                    operation: entry.operation,
                    partial: entry.partial,
                    request: entry.request.map_err(|skip| skip.to_string()),
                })
                .collect()
        }
        Inputs::Builtin => crate::samples::requests()
            .into_iter()
            .map(|row| Input {
                id: row.name.to_owned(),
                operation: row.name.split('-').next().unwrap_or(row.name).to_owned(),
                partial: false,
                request: Ok((row.request, Vec::new())),
            })
            .collect(),
    };
    // The sample counts only inputs that are sent, so an operation whose first entries are
    // skipped is still compared; one no input of which was compared is named in the report.
    let mut compared_per_operation: BTreeMap<String, usize> = BTreeMap::new();
    for input in inputs {
        if matches!(options.inputs, Inputs::Corpus(_)) && !crate::DIFFED_OPERATIONS.contains(&input.operation.as_str()) {
            *report
                .skipped
                .entry(format!("{NOT_DIFFED} ({})", input.operation))
                .or_default() += 1;
            continue;
        }
        let compared = compared_per_operation.entry(input.operation.clone()).or_default();
        let (request, adjustments) = match input.request {
            Ok(request) => request,
            Err(reason) => {
                *report.skipped.entry(reason).or_default() += 1;
                continue;
            }
        };
        if options.per_bucket.is_some_and(|limit| *compared >= limit) {
            *report.skipped.entry("outside the per-bucket sample".to_owned()).or_default() += 1;
            continue;
        }
        let diff = match differ.diff(&request) {
            Ok(diff) => diff,
            Err(error) => {
                report.harness.push((input.id, error));
                continue;
            }
        };
        let recorded = Some(&input.operation);
        if input.partial && (diff.operation.gateway.as_ref() != recorded || diff.operation.s3s.as_ref() != recorded) {
            *report.skipped.entry(PARTIAL_ROUTED_AWAY.to_owned()).or_default() += 1;
            continue;
        }
        *compared += 1;
        for adjustment in adjustments {
            *report.adjusted.entry(adjustment.to_string()).or_default() += 1;
        }
        report.judge(&input.id, register.verdict_for(&request, diff.findings()));
    }
    report.uncompared = compared_per_operation
        .into_iter()
        .filter(|(_, compared)| *compared == 0)
        .map(|(operation, _)| operation)
        .collect();
    report.elapsed = Duration::from_millis(clock.monotonic().saturating_millis_since(started));
    Ok(report)
}

/// Runs the encode diff over `options.inputs`.
///
/// # Errors
///
/// As [`decode`]. A corpus carries no output samples today (the recorder records requests), so
/// `--corpus` is an environment failure that says so rather than a run over nothing.
pub fn encode(options: &Options) -> Result<Report, String> {
    let register = register()?;
    if let Inputs::Corpus(root) = &options.inputs {
        return Err(format!(
            "the corpus {} carries no output samples: its recordings hold requests only (rustfs/backlog#1763); run --builtin",
            root.display()
        ));
    }
    let differ = Differ::new()?;
    let clock = SystemMonotonic::new();
    let started = clock.monotonic();
    let mut report = Report::default();
    let mut kept_per_operation: BTreeMap<&'static str, usize> = BTreeMap::new();
    for row in crate::samples::outputs() {
        if let Some(limit) = options.per_bucket {
            let kept = kept_per_operation.entry((row.sample.output)().operation()).or_default();
            if *kept >= limit {
                *report.skipped.entry("outside the per-bucket sample".to_owned()).or_default() += 1;
                continue;
            }
            *kept += 1;
        }
        match differ.encode(&row.sample) {
            Ok(diff) => report.judge(&row.sample.name, register.verdict(diff.findings())),
            Err(error) => report.harness.push((row.sample.name.clone(), error)),
        }
    }
    report.elapsed = Duration::from_millis(clock.monotonic().saturating_millis_since(started));
    Ok(report)
}

/// The whole of a runner's `main`: parse, run, print, exit.
#[must_use]
pub fn main(kind: &str, run: fn(&Options) -> Result<Report, String>) -> u8 {
    let options = match Options::parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(usage) => {
            eprintln!("{usage}");
            return EXIT_ENVIRONMENT;
        }
    };
    match run(&options) {
        Ok(report) => {
            let (status, text) = report.conclude(kind, options.budget);
            print!("{text}");
            status
        }
        Err(error) => {
            eprintln!("ENVIRONMENT: {error}");
            EXIT_ENVIRONMENT
        }
    }
}
