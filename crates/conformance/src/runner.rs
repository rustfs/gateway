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

//! The execution engine: corpus in, one verdict per case out.
//!
//! Responsible for: selecting cases, interpolating captures into a request before it is signed,
//! driving the exchanges in order, and turning what came back into a verdict with its reason
//! attached. Every case reaches a conclusion — a case that could not run is skipped *with a
//! reason*, never dropped, because "not run" and "run and red" are different facts and a report
//! that conflates them is worse than no report.
//! NOT responsible for: judging an assertion (`crate::expect`), performing I/O (`crate::sut`), or
//! rendering (`crate::report`).
//! Upstream: `crate::corpus`, `crate::lint`, `crate::expect`, `crate::sut`. Downstream:
//! `crate::cli`.

use crate::corpus::{Case, Corpus};
use crate::diagnostic::{Diagnostic, Severity};
use crate::expect::{self, GoldenSource};
use crate::interpolate::{self, Captures};
use crate::lint;
use crate::report::{CaseOutcome, Phase, Report, Verdict};
use crate::sut::{ExchangePlan, Profile, Sut, SutError, Transport};
use crate::value::Value;

/// How a run is configured.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Glob over the corpus-relative path, e.g. `etag/` or `*mpu*`.
    pub filter: Option<String>,
    /// The assembly path to inject.
    pub transport: Transport,
    /// The profile the target claims, which gates `case.applies_to.profiles`.
    pub profile: Profile,
    /// Whether to include cases tagged `slow`.
    pub include_slow: bool,
    /// Stop after the corpus checks, without touching a target.
    pub validate_only: bool,
}

impl Default for RunOptions {
    fn default() -> RunOptions {
        RunOptions {
            filter: None,
            transport: Transport::Hyper,
            profile: Profile::Aws,
            include_slow: true,
            validate_only: false,
        }
    }
}

struct CorpusGoldens<'a>(&'a Corpus);

impl GoldenSource for CorpusGoldens<'_> {
    fn read_golden(&self, relative: &str) -> Result<Vec<u8>, String> {
        self.0.read_relative(relative).map_err(|error| error.message)
    }
}

/// Loads the corpus, applies the conventions, and returns it ready to run.
///
/// # Errors
///
/// Propagates a corpus-level failure, which is an environment problem rather than a case failure.
pub fn prepare_corpus(root: &std::path::Path) -> Result<Corpus, crate::corpus::CorpusError> {
    let mut corpus = Corpus::load(root)?;
    lint::lint(&mut corpus);
    Ok(corpus)
}

/// Runs the corpus against `sut`.
#[must_use]
pub fn run(corpus: &Corpus, sut: &mut dyn Sut, options: &RunOptions) -> Report {
    let goldens = CorpusGoldens(corpus);
    let mut outcomes = Vec::new();
    let mut notes = Vec::new();
    let mut filtered_out = 0;
    for case in corpus.cases() {
        if !selected(case, options) {
            filtered_out += 1;
            continue;
        }
        outcomes.push(run_case(case, sut, options, &goldens, &mut notes));
    }
    Report {
        target: sut.describe(),
        transport: options.transport.as_str().to_owned(),
        profile: options.profile.as_str().to_owned(),
        outcomes,
        filtered_out,
        notes,
        polarity: lint::polarity_balance(corpus),
    }
}

fn selected(case: &Case, options: &RunOptions) -> bool {
    if !options.include_slow && case.is_slow() {
        return false;
    }
    match &options.filter {
        None => true,
        Some(pattern) => glob_contains(pattern, &case.relative) || glob_contains(pattern, &case.id),
    }
}

fn run_case(
    case: &Case,
    sut: &mut dyn Sut,
    options: &RunOptions,
    goldens: &dyn GoldenSource,
    notes: &mut Vec<String>,
) -> CaseOutcome {
    let mut outcome = skeleton(case);
    outcome.diagnostics.clone_from(&case.diagnostics);

    // Loading and the corpus conventions come first: a case that is not internally consistent
    // cannot produce a meaningful verdict against any implementation.
    if case.document.is_none() {
        outcome.verdict = Verdict::Failed;
        outcome.phase = Phase::Load;
        return outcome;
    }
    if outcome.diagnostics.iter().any(|d| d.severity == Severity::Deny) {
        outcome.verdict = Verdict::Failed;
        outcome.phase = if outcome.diagnostics.iter().any(|d| d.rule.starts_with("schema/")) {
            Phase::Schema
        } else {
            Phase::Convention
        };
        return outcome;
    }
    if options.validate_only {
        outcome.verdict = Verdict::Passed;
        outcome.phase = Phase::Convention;
        return outcome;
    }
    if let Some(reason) = inapplicable(case, options) {
        outcome.verdict = Verdict::Skipped;
        outcome.phase = Phase::Convention;
        outcome.skip_reason = Some(reason);
        return outcome;
    }

    outcome.phase = Phase::Execute;
    let document = case.document.as_ref().unwrap_or(&Value::Bool(false));
    let mut captures: Captures = match sut.prepare(&case.id, document.get("setup")) {
        Ok(captures) => captures,
        Err(error) => return not_run(outcome, &error, notes),
    };

    let timeout_ms = document.path("case/timeout_ms").and_then(Value::as_integer);
    for exchange in case.exchanges() {
        let Some(request) = exchange.request else { continue };
        let request = match interpolate_value(request, &captures) {
            Ok(request) => request,
            Err(message) => {
                outcome.diagnostics.push(Diagnostic::deny(
                    "runner/interpolation",
                    &format!("{}/request", exchange.pointer),
                    message,
                ));
                outcome.verdict = Verdict::Failed;
                return outcome;
            }
        };
        let plan = ExchangePlan {
            case_id: &case.id,
            index: exchange.index,
            request,
            clock: document.get("clock"),
            connection: document.get("connection"),
            timeout_ms,
            transport: options.transport,
            profile: options.profile,
        };
        let observed = match sut.exchange(&plan) {
            Ok(observed) => observed,
            Err(error) => return not_run(outcome, &error, notes),
        };
        let Some(expectation) = exchange.expect else { continue };
        let judgement = expect::judge(expectation, &observed, &format!("{}/expect", exchange.pointer), goldens);
        for mut diagnostic in judgement.diagnostics {
            diagnostic.message = format!("exchange {}: {}", exchange.label(), diagnostic.message);
            outcome.diagnostics.push(diagnostic);
        }
        captures.extend(judgement.captures);
    }
    if let Err(error) = sut.finish(&case.id) {
        outcome
            .diagnostics
            .push(Diagnostic::warn("runner/cleanup", "", error.to_string()));
    }

    outcome.verdict = if outcome.diagnostics.iter().any(|d| d.severity == Severity::Deny) {
        Verdict::Failed
    } else {
        Verdict::Passed
    };
    outcome
}

/// Turns a target-level failure into a skip that states its reason.
///
/// The long-form explanation — what the facade would have to expose — is a property of the run
/// rather than of each case, so it goes into the report's notes once instead of onto every line.
fn not_run(mut outcome: CaseOutcome, error: &SutError, notes: &mut Vec<String>) -> CaseOutcome {
    outcome.verdict = Verdict::Skipped;
    outcome.skip_reason = Some(match error {
        SutError::NotWired { reason, missing } => {
            for item in missing {
                let note = format!("the facade must expose: {item}");
                if !notes.contains(&note) {
                    notes.push(note);
                }
            }
            reason.clone()
        }
        SutError::Environment(reason) => format!("environment: {reason}"),
    });
    outcome
}

fn skeleton(case: &Case) -> CaseOutcome {
    let evidence = case
        .document
        .as_ref()
        .and_then(|document| document.path("case/evidence"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("url"))
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    CaseOutcome {
        id: case.id.clone(),
        domain: case.domain.clone(),
        relative: case.relative.clone(),
        title: case.meta_str("title").map(ToOwned::to_owned),
        verdict: Verdict::Skipped,
        phase: Phase::Load,
        skip_reason: None,
        diagnostics: Vec::new(),
        quirks: case.quirks().into_iter().map(ToOwned::to_owned).collect(),
        evidence,
    }
}

/// Applicability gates the case declares. A gated-out case is skipped with the gate named.
fn inapplicable(case: &Case, options: &RunOptions) -> Option<String> {
    let applies = case.document.as_ref()?.path("case/applies_to")?;
    if let Some(profiles) = applies.string_array("profiles")
        && !profiles.is_empty()
        && !profiles.contains(&options.profile.as_str())
    {
        return Some(format!(
            "case.applies_to.profiles is [{}] and this run claims `{}`",
            profiles.join(", "),
            options.profile.as_str()
        ));
    }
    None
}

fn interpolate_value(value: &Value, captures: &Captures) -> Result<Value, String> {
    match value {
        Value::String(text) => interpolate::interpolate(text, captures)
            .map(Value::String)
            .map_err(|error| error.to_string()),
        Value::Array(items) => items
            .iter()
            .map(|item| interpolate_value(item, captures))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Table(entries) => entries
            .iter()
            .map(|(key, item)| interpolate_value(item, captures).map(|item| (key.clone(), item)))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Table),
        other => Ok(other.clone()),
    }
}

/// Matches `pattern` anywhere in `text`, with `*` and `?` wildcards.
///
/// Substring semantics on purpose: the documented invocation is `--filter 'etag/'`, and requiring
/// `*etag/*` there would be a trap rather than a feature.
#[must_use]
pub fn glob_contains(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    (0..=text.len()).any(|start| glob_prefix(&pattern, &text[start..]))
}

fn glob_prefix(pattern: &[char], text: &[char]) -> bool {
    match pattern.split_first() {
        None => true,
        Some(('*', rest)) => (0..=text.len()).any(|skip| glob_prefix(rest, &text[skip..])),
        Some(('?', rest)) => !text.is_empty() && glob_prefix(rest, &text[1..]),
        Some((literal, rest)) => text.first() == Some(literal) && glob_prefix(rest, &text[1..]),
    }
}

#[cfg(test)]
mod tests;
