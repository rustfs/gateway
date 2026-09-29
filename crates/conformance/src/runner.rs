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
//! Responsible for: selecting cases, interpolating captures into a request before it is signed and
//! into an expectation before it is judged, driving the exchanges in order, and turning what came
//! back into a verdict with its reason attached. Every case reaches a conclusion — a case that
//! could not run is skipped *with a reason*, never dropped, because "not run" and "run and red"
//! are different facts and a report that conflates them is worse than no report.
//!
//! Both sides are interpolated by the same total walk over the document
//! (`interpolate_value`), which discriminates on the shape of a [`Value`] and never on a field
//! name. That is deliberate: a substitution that had to be opted into field by field would
//! eventually miss one, and an assertion that *looks* substituted and is not is worse than one
//! that plainly is not — it reads as measured where nothing was measured.
//! NOT responsible for: judging an assertion (`crate::expect`), performing I/O (`crate::sut`), or
//! rendering (`crate::report`).
//! Upstream: `crate::corpus`, `crate::lint`, `crate::expect`, `crate::sut`. Downstream:
//! `crate::cli`.

use crate::corpus::{Case, Corpus};
use crate::diagnostic::{Diagnostic, Severity};
use crate::expect::{self, GoldenSource};
use crate::interpolate::{self, Captures};
use crate::keys;
use crate::lint;
use crate::report::{CaseOutcome, Phase, Report, Verdict};
use crate::sut::{ExchangePlan, Profile, Sut, SutError, Transport};
use crate::value::Value;

mod deadline;
mod reference;
#[cfg(test)]
use deadline::valid_expiry;
use deadline::{case_deadline, expiry_error, timeout_verdict};
pub use reference::reference_report;

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
    /// Run only every `count`-th selected case starting at `index`, so the corpus can be spread
    /// over several workers that together cover it exactly once.
    pub shard: Option<Shard>,
}

/// One worker's share of the selected cases: the `index`-th of `count`, by selection order.
///
/// The partition is over the cases the filter and the `slow` rule already selected, numbered in
/// corpus order, so `n` shards with the same options run disjoint sets whose union is the whole
/// selection — which is what lets `diff-transports` be split across CI runners without any case
/// running twice or not at all (rustfs/gateway#641).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shard {
    /// Which share this is, from `0` to `count - 1`.
    pub index: usize,
    /// How many shares the selection is cut into.
    pub count: usize,
}

impl Shard {
    /// Parses the `<index>/<count>` spelling the command line uses.
    ///
    /// # Errors
    ///
    /// Returns the reason when the text is not two integers separated by `/`, the count is zero,
    /// or the index is not below the count.
    pub fn parse(text: &str) -> Result<Shard, String> {
        let Some((index, count)) = text.split_once('/') else {
            return Err(format!("`--shard` needs `<index>/<count>`, got `{text}`"));
        };
        let index: usize = index
            .parse()
            .map_err(|_| format!("`--shard` index must be an unsigned integer, got `{index}`"))?;
        let count: usize = count
            .parse()
            .map_err(|_| format!("`--shard` count must be an unsigned integer, got `{count}`"))?;
        if count == 0 {
            return Err("`--shard` count must be at least 1".to_owned());
        }
        if index >= count {
            return Err(format!("`--shard` index {index} is not below its count {count}"));
        }
        Ok(Shard { index, count })
    }

    /// Whether the `ordinal`-th selected case belongs to this share.
    #[must_use]
    pub fn owns(self, ordinal: usize) -> bool {
        ordinal % self.count == self.index
    }
}

impl Default for RunOptions {
    fn default() -> RunOptions {
        RunOptions {
            filter: None,
            transport: Transport::Hyper,
            profile: Profile::Aws,
            include_slow: true,
            validate_only: false,
            shard: None,
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
    keys::note_unhonoured(&mut corpus);
    Ok(corpus)
}

/// Runs the corpus against `sut`.
#[must_use]
pub fn run(corpus: &Corpus, sut: &mut dyn Sut, options: &RunOptions) -> Report {
    let goldens = CorpusGoldens(corpus);
    let mut outcomes = Vec::new();
    let mut notes = Vec::new();
    if options.validate_only {
        notes.push("validate: schema check only — no cases were executed".to_owned());
    }
    let mut filtered_out = 0;
    let mut left_to_other_shards = 0;
    let mut ordinal = 0;
    for case in corpus.cases() {
        if !selected(case, options) {
            filtered_out += 1;
            continue;
        }
        let owned = options.shard.is_none_or(|shard| shard.owns(ordinal));
        ordinal += 1;
        if !owned {
            left_to_other_shards += 1;
            continue;
        }
        outcomes.push(run_case(case, sut, options, &goldens, &mut notes));
    }
    if let Some(shard) = options.shard {
        // Said on the report, so a partial run can never read as the whole corpus.
        notes.push(format!(
            "shard {}/{}: {} selected case(s) ran here, {left_to_other_shards} belong to the other shards",
            shard.index,
            shard.count,
            outcomes.len()
        ));
    }
    Report {
        target: sut.describe(),
        transport: options.transport.as_str().to_owned(),
        profile: options.profile.as_str().to_owned(),
        outcomes,
        filtered_out,
        left_to_other_shards,
        notes,
        polarity: lint::polarity_balance(corpus),
        validate_only: options.validate_only,
    }
}

pub(crate) fn selected(case: &Case, options: &RunOptions) -> bool {
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
    // `Verdict::Validated`, never `Verdict::Passed`. Nothing below this line ran, so the case has
    // no observation to have been judged against: recording the verdict an executed case gets is
    // reporting an intention as an observation, and it made four separate mutations of a new case
    // — a wrong status, a wrong error code, a required header flipped, a header moved to
    // `headers_absent` — all read green through `conformance validate --filter '<case-id>'`.
    if options.validate_only {
        outcome.verdict = Verdict::Validated;
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
    let mut captures: Captures = match sut.prepare(&case.id, document.read("setup")) {
        Ok(captures) => captures,
        Err(error) => return not_run(outcome, &error, notes),
    };

    let timeout_ms = case
        .meta()
        .and_then(|meta| meta.read("caseMeta.timeout_ms"))
        .and_then(Value::as_integer);
    // Restarted at the first dispatch: preparing a request is the harness's work, and on a loaded
    // host it must not expire the case before the target is asked anything (rustfs/gateway#928).
    let mut started = std::time::Instant::now();
    let mut dispatched = false;
    // The harness's own waiting, measured where it happens and kept out of the target's budget.
    let mut harness_wait_ms: u64 = 0;
    let mut measured_expiry = None;
    let mut outcome = 'prepared: {
        if !timeout_ms.is_some_and(|value| value > 0)
            && case
                .meta()
                .and_then(|meta| meta.read("caseMeta.schema_version"))
                .and_then(Value::as_integer)
                .is_some_and(|version| version >= 4)
            && case.exchanges().iter().any(|exchange| {
                exchange
                    .request
                    .and_then(|request| request.read("requestSpec.h2_frames"))
                    .is_some()
                    && exchange
                        .expect
                        .and_then(|expect| expect.read("expect.kind"))
                        .and_then(Value::as_str)
                        == Some("hang")
            })
        {
            outcome.diagnostics.push(Diagnostic::deny(
                "runner/deadline-expiry",
                "/case/timeout_ms",
                "scripted HTTP/2 Hang requires an explicit positive case.timeout_ms",
            ));
            outcome.verdict = Verdict::Failed;
            break 'prepared outcome;
        }
        let concurrent = document
            .read("connection")
            .and_then(|connection| connection.read("connection.concurrent"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if concurrent {
            started = std::time::Instant::now();
            if let Err(error) = run_concurrent_exchanges(
                case,
                sut,
                options,
                goldens,
                &mut outcome,
                &mut captures,
                document,
                timeout_ms,
                case_deadline(started, timeout_ms, harness_wait_ms),
                &mut harness_wait_ms,
            ) {
                break 'prepared not_run(outcome, &error, notes);
            }
        } else {
            for exchange in case.exchanges() {
                // The pause a multi-exchange case asks for between two requests. Honoured by actually
                // waiting: a declared pause that the runner skipped would put the second request on the
                // wire at a moment the case did not describe.
                if let Some(delay_ms) = exchange.delay_ms.filter(|delay| *delay > 0) {
                    let paused = std::time::Instant::now();
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms.unsigned_abs()));
                    harness_wait_ms =
                        harness_wait_ms.saturating_add(u64::try_from(paused.elapsed().as_millis()).unwrap_or(u64::MAX));
                }
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
                        break 'prepared outcome;
                    }
                };
                for attempt in 0..exchange.repeat {
                    if !dispatched {
                        started = std::time::Instant::now();
                        dispatched = true;
                    }
                    if measured_expiry.is_some()
                        || case_deadline(started, timeout_ms, harness_wait_ms).is_some_and(|end| std::time::Instant::now() >= end)
                    {
                        outcome.diagnostics.push(Diagnostic::deny(
                            "runner/timeout",
                            "/case/timeout_ms",
                            "a later exchange cannot restart an already expired case deadline",
                        ));
                        outcome.verdict = Verdict::Failed;
                        break 'prepared outcome;
                    }
                    let deadline = case_deadline(started, timeout_ms, harness_wait_ms);
                    let plan = ExchangePlan {
                        case_id: &case.id,
                        index: exchange.index,
                        request: request.clone(),
                        clock: document.read("clock"),
                        connection: document.read("connection"),
                        timeout_ms: deadline
                            .map(|end| {
                                i64::try_from(end.saturating_duration_since(std::time::Instant::now()).as_millis())
                                    .unwrap_or(i64::MAX)
                            })
                            .or(timeout_ms),
                        deadline,
                        transport: options.transport,
                        profile: options.profile,
                    };
                    let observed = match sut.exchange(&plan) {
                        Ok(observed) => observed,
                        Err(error) => break 'prepared not_run(outcome, &error, notes),
                    };
                    let returned_at = std::time::Instant::now();
                    if let Some(message) = expiry_error(case, &plan, &observed, returned_at) {
                        outcome
                            .diagnostics
                            .push(Diagnostic::deny("runner/deadline-expiry", "/case/timeout_ms", message));
                    } else if let Some(receipt) = &observed.deadline_expiry {
                        let wait =
                            harness_wait_ms.saturating_add(u64::try_from(receipt.harness_wait.as_millis()).unwrap_or(u64::MAX));
                        measured_expiry = Some((receipt.deadline, wait));
                    }
                    harness_wait_ms = harness_wait_ms.saturating_add(observed.harness_wait_ms);
                    // A transport that had to produce part of the record some way other than by measuring
                    // it says so here, and the case carries the warning. A green line whose assertion
                    // could not have failed is the defect this suite keeps regrowing.
                    for note in &observed.notes {
                        outcome.diagnostics.push(Diagnostic::warn(
                            "harness/by-construction",
                            &format!("{}/expect", exchange.pointer),
                            format!("exchange {}, attempt {}: {note}", exchange.label(), attempt + 1),
                        ));
                    }
                    let Some(expectation) = exchange.expect else { continue };
                    // The expectation is interpolated on the same terms as the request, and for the same
                    // reason: an assertion naming `${capture.x}` that reached the comparison unsubstituted
                    // would be judged against the literal reference. On a `contains` that reads as a red
                    // case; on a `not_contains` it reads as a green one and can never fail. Substitution
                    // happens here rather than once per exchange because `captures` grows as the exchanges
                    // run, and an expectation may only name a value an *earlier* exchange bound — this
                    // exchange's own `expect.capture` is collected below, after the judgement.
                    let expectation = match interpolate_value(expectation, &captures) {
                        Ok(expectation) => expectation,
                        Err(message) => {
                            outcome.diagnostics.push(Diagnostic::deny(
                                "runner/interpolation",
                                &format!("{}/expect", exchange.pointer),
                                message,
                            ));
                            outcome.verdict = Verdict::Failed;
                            break 'prepared outcome;
                        }
                    };
                    let judgement = expect::judge(&expectation, &observed, &format!("{}/expect", exchange.pointer), goldens);
                    for mut diagnostic in judgement.diagnostics {
                        diagnostic.message =
                            format!("exchange {}, attempt {}: {}", exchange.label(), attempt + 1, diagnostic.message);
                        outcome.diagnostics.push(diagnostic);
                    }
                    captures.extend(judgement.captures);
                }
            }
        }
        outcome.verdict = if outcome.diagnostics.iter().any(|d| d.severity == Severity::Deny) {
            Verdict::Failed
        } else {
            Verdict::Passed
        };
        outcome
    };
    if let Err(error) = sut.finish(&case.id) {
        outcome
            .diagnostics
            .push(Diagnostic::deny("runner/cleanup", "", error.to_string()));
        outcome.verdict = Verdict::Failed;
    }
    // `case.timeout_ms` is a whole-case budget on the *target*, and the schema says exceeding it
    // is a case failure of kind `hang` rather than an environment error. Enforced here rather than
    // in a transport, because a transport that has itself hung is not in a position to report it.
    // The harness's own waiting is subtracted first: authored pacing, stalls, teardown delays, the
    // pauses between exchanges, and the window spent observing the connection after each answer
    // are the harness's instruments, and a scheduler that overshoots one of them has not observed
    // the target hanging (rustfs/gateway#426).
    if let Some(limit) = timeout_ms {
        // A validated expiry is the target's stopping boundary. Assertion evaluation, the
        // post-response probe, and cleanup after it cannot move that measured boundary.
        let (ended, wait) = measured_expiry.unwrap_or_else(|| (std::time::Instant::now(), harness_wait_ms));
        let elapsed = u64::try_from(ended.saturating_duration_since(started).as_millis()).unwrap_or(u64::MAX);
        if let Some(message) = timeout_verdict(elapsed, wait, limit) {
            outcome
                .diagnostics
                .push(Diagnostic::deny("runner/timeout", "/case/timeout_ms", message));
            outcome.verdict = Verdict::Failed;
        }
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn run_concurrent_exchanges(
    case: &Case,
    sut: &mut dyn Sut,
    options: &RunOptions,
    goldens: &dyn GoldenSource,
    outcome: &mut CaseOutcome,
    captures: &mut Captures,
    document: &Value,
    timeout_ms: Option<i64>,
    deadline: Option<std::time::Instant>,
    harness_wait_ms: &mut u64,
) -> Result<(), SutError> {
    let exchanges = case.exchanges();
    if exchanges.len() < 2 {
        outcome.diagnostics.push(Diagnostic::deny(
            "runner/concurrent-arity",
            "/connection/concurrent",
            "a concurrent batch requires at least two exchanges",
        ));
        return Ok(());
    }

    let mut requests = Vec::with_capacity(exchanges.len());
    for exchange in &exchanges {
        if exchange.repeat != 1 {
            outcome.diagnostics.push(Diagnostic::deny(
                "runner/concurrent-repeat",
                &exchange.pointer,
                "a concurrent exchange must declare repeat = 1; repetition creates a serial history",
            ));
        }
        if exchange.delay_ms.is_some_and(|delay| delay != 0) {
            outcome.diagnostics.push(Diagnostic::deny(
                "runner/concurrent-delay",
                &exchange.pointer,
                "a concurrent exchange cannot declare delay_ms; every request is released together",
            ));
        }
        let Some(request) = exchange.request else { continue };
        match interpolate_value(request, captures) {
            Ok(request) => requests.push(request),
            Err(message) => outcome.diagnostics.push(Diagnostic::deny(
                "runner/interpolation",
                &format!("{}/request", exchange.pointer),
                message,
            )),
        }
    }
    if outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Deny)
    {
        return Ok(());
    }

    let plans: Vec<ExchangePlan<'_>> = exchanges
        .iter()
        .zip(requests)
        .map(|(exchange, request)| ExchangePlan {
            case_id: &case.id,
            index: exchange.index,
            request,
            clock: document.read("clock"),
            connection: document.read("connection"),
            timeout_ms,
            deadline,
            transport: options.transport,
            profile: options.profile,
        })
        .collect();
    let observations = sut.exchange_concurrent(&plans)?;
    if observations.len() != exchanges.len() {
        outcome.diagnostics.push(Diagnostic::deny(
            "runner/concurrent-observation-count",
            "/connection/concurrent",
            format!(
                "the batch declared {} exchanges but the target returned {} observations; all {} observations are required",
                exchanges.len(),
                observations.len(),
                exchanges.len()
            ),
        ));
        return Ok(());
    }

    let returned_at = std::time::Instant::now();
    let mut batch_captures = Captures::new();
    for ((exchange, observed), plan) in exchanges.iter().zip(observations).zip(&plans) {
        if let Some(message) = expiry_error(case, plan, &observed, returned_at) {
            outcome
                .diagnostics
                .push(Diagnostic::deny("runner/deadline-expiry", &exchange.pointer, message));
        }
        *harness_wait_ms = harness_wait_ms.saturating_add(observed.harness_wait_ms);
        for note in &observed.notes {
            outcome.diagnostics.push(Diagnostic::warn(
                "harness/by-construction",
                &format!("{}/expect", exchange.pointer),
                format!("exchange {}: {note}", exchange.label()),
            ));
        }
        let Some(expectation) = exchange.expect else { continue };
        let expectation = match interpolate_value(expectation, captures) {
            Ok(expectation) => expectation,
            Err(message) => {
                outcome.diagnostics.push(Diagnostic::deny(
                    "runner/interpolation",
                    &format!("{}/expect", exchange.pointer),
                    message,
                ));
                continue;
            }
        };
        let judgement = expect::judge(&expectation, &observed, &format!("{}/expect", exchange.pointer), goldens);
        for mut diagnostic in judgement.diagnostics {
            diagnostic.message = format!("exchange {}: {}", exchange.label(), diagnostic.message);
            outcome.diagnostics.push(diagnostic);
        }
        batch_captures.extend(judgement.captures);
    }
    captures.extend(batch_captures);
    Ok(())
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
        .and_then(|document| document.read("case"))
        .and_then(|meta| meta.read("caseMeta.evidence"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.read("evidence.url"))
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    CaseOutcome {
        id: case.id.clone(),
        domain: case.domain.clone(),
        relative: case.relative.clone(),
        title: case.title().map(ToOwned::to_owned),
        verdict: Verdict::Skipped,
        phase: Phase::Load,
        skip_reason: None,
        diagnostics: Vec::new(),
        quirks: case.quirks().into_iter().map(ToOwned::to_owned).collect(),
        evidence,
    }
}

/// Whether this run reaches the target over TLS. There is no socket, so it does not.
const RUN_OVER_TLS: bool = false;

/// Whether a `case.applies_to.tls` gate excludes a run with this TLS state.
fn tls_gate_excludes(gate: &str, over_tls: bool) -> bool {
    match gate {
        "required" => !over_tls,
        "forbidden" => over_tls,
        _ => false,
    }
}

/// Applicability gates the case declares. A gated-out case is skipped with the gate named.
pub(crate) fn inapplicable(case: &Case, options: &RunOptions) -> Option<String> {
    let applies = case.meta()?.read("caseMeta.applies_to")?;
    if let Some(profiles) = applies.read_strings("caseMeta.applies_to.profiles")
        && !profiles.is_empty()
        && !profiles.contains(&options.profile.as_str())
    {
        return Some(format!(
            "case.applies_to.profiles is [{}] and this run claims `{}`",
            profiles.join(", "),
            options.profile.as_str()
        ));
    }
    if let Some(versions) = applies.read_strings("caseMeta.applies_to.http_versions")
        && !versions.is_empty()
    {
        // Applicability describes the authored requests, not a transport capability. A matching
        // declaration still reaches the selected target's protocol support checks during execution.
        for exchange in case.exchanges() {
            let version = exchange
                .request
                .and_then(|request| request.read("requestSpec.http_version"))
                .and_then(Value::as_str)
                .unwrap_or("http/1.1");
            if !versions.contains(&version) {
                return Some(format!(
                    "case.applies_to.http_versions is [{}] but exchange {} requests `{version}`",
                    versions.join(", "),
                    exchange.label()
                ));
            }
        }
    }
    if let Some(gate) = applies.read("caseMeta.applies_to.tls").and_then(Value::as_str)
        && tls_gate_excludes(gate, RUN_OVER_TLS)
    {
        return Some(format!(
            "case.applies_to.tls is `{gate}` and this run is {}",
            if RUN_OVER_TLS { "over TLS" } else { "in cleartext" }
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
            .map(|(key, item)| {
                // A table key is a header name, a capture name or a schema field — never a place a
                // value is substituted, in either half of an exchange. Refusing it is what keeps
                // this walk *total*: every `${` in a case is now either substituted or reported,
                // and there is no third outcome where a reference sits in a position nothing
                // touches and reads afterwards as though it had been resolved.
                if key.contains("${") {
                    return Err(format!(
                        "`{key}` uses `${{...}}` in a field name; substitution applies to values only, \
                         and a reference left in a name is not a reference the runner resolved"
                    ));
                }
                interpolate_value(item, captures).map(|item| (key.clone(), item))
            })
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
mod budget_tests;
#[cfg(test)]
mod h2_receipt_tests;
#[cfg(test)]
mod http_version_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod shard_tests;
#[cfg(test)]
mod tests;
