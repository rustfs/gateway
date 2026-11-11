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

//! The gate that says the corpus is executable, from outside the crate.
//!
//! Responsible for: proving that the whole repository corpus loads, satisfies the frozen schema,
//! satisfies the conventions, and reaches a stated conclusion — through the public API only, the
//! same way a foreign implementation would use this crate. The unit tests can reach internals;
//! this one deliberately cannot, so a refactor that breaks the product surface breaks here.
//! Also the home of the corpus-wide half of the baseline contract: every case carries a row, and
//! the whole corpus is run against those rows on the assembled service, with the authored HTTP/2
//! frame scripts the in-process target refuses run on the production Hyper driver instead.
//! NOT responsible for: any individual assertion; those are unit-tested next to the engine. Nor
//! for per-domain wiring (`tests/domain_wiring.rs`) or a family's own size, polarity and
//! known-red set (the family ledgers).
//! Upstream: the published API of `rustfs_gateway_conformance`, and `conformance/baseline.json`.
//! Downstream: nothing.
//!
//! # Why the baseline gate lives here and not only in a CI shell step
//!
//! rustfs/gateway#192: `cargo xtask conformance run --baseline conformance/baseline.json` is
//! treated throughout this repository as the no-regression gate, and CI never ran it — the word
//! `baseline` did not appear anywhere in `.github/`. Six real regressions from `fb06bbd` lived
//! fifteen days behind four green merges. A `#[test]` is the cheapest place to fix that for good:
//! it is inside `cargo test --workspace`, which is behind the branch-protected `Test` check and
//! already budgeted, so the gate cannot be added to CI and then quietly not required — which is
//! how `e2e` ended up non-blocking in the repository this suite was written to replace.

use rustfs_gateway_conformance::corpus::Corpus;
use rustfs_gateway_conformance::diagnostic::Diagnostic;
use rustfs_gateway_conformance::report::{Baseline, CaseOutcome, Phase, Verdict};
use rustfs_gateway_conformance::runner::{self, RunOptions};
use rustfs_gateway_conformance::sut::Unwired;

fn corpus() -> Corpus {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    runner::prepare_corpus(&root).expect("the corpus loads")
}

fn baseline() -> Baseline {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let source = std::fs::read_to_string(root.join("baseline.json")).expect("the baseline is checked in");
    Baseline::from_json(&source).expect("the baseline parses")
}

fn format_regression(outcome: &CaseOutcome) -> String {
    let mut line = format!("{} ({}) is {}", outcome.id, outcome.relative, outcome.verdict.as_str());
    for failure in outcome.failures() {
        let message = failure
            .message
            .strip_prefix("exchange ")
            .and_then(|value| value.rsplit_once(", attempt "))
            .and_then(|(_, value)| value.split_once(": "))
            .filter(|(attempt, _)| !attempt.is_empty() && attempt.bytes().all(|byte| byte.is_ascii_digit()))
            .map_or(failure.message.as_str(), |(_, message)| message);
        let detail = match failure.rule.as_str() {
            "expect/socket_read_after" => {
                let labels = message
                    .strip_prefix("receive-side termination: expected ")
                    .and_then(|message| message.split_once(", observed "));
                match labels {
                    Some((
                        expected @ ("eof" | "reset" | "no_termination_observed" | "invalid"),
                        actual @ ("eof" | "reset" | "no_termination_observed" | "not_measured"),
                    )) => {
                        format!("receive-side termination: expected {expected}, observed {actual}")
                    }
                    _ => "detail unavailable".to_owned(),
                }
            }
            "expect/h2_control_frames" => match message {
                message @ ("expected control frames must be an array"
                | "this transport did not measure HTTP/2 control frames"
                | "expected HTTP/2 control frame has an unsupported type or invalid fields"
                | "received HTTP/2 control frames differ in count, order, or fields"
                | "an asserted connection-level WINDOW_UPDATE grant was not received") => message.to_owned(),
                _ => "detail unavailable".to_owned(),
            },
            "runner/timeout" => "deadline exceeded".to_owned(),
            "expect/kind" => "outcome mismatch".to_owned(),
            _ => continue,
        };
        line.push_str(&format!(" | [{}]: {detail}", failure.rule));
    }
    line
}

fn diagnostic_fixture(diagnostics: Vec<Diagnostic>) -> CaseOutcome {
    CaseOutcome {
        id: "c-h2-0007".to_owned(),
        domain: "h2".to_owned(),
        relative: "cases/h2/c-h2-0007.toml".to_owned(),
        title: None,
        verdict: Verdict::Failed,
        phase: Phase::Execute,
        skip_reason: None,
        transport_limited: false,
        diagnostics,
        quirks: Vec::new(),
        evidence: Vec::new(),
    }
}

#[test]
fn regression_report_includes_bounded_socket_detail_but_not_warnings() {
    let outcome = diagnostic_fixture(vec![
        Diagnostic::deny(
            "expect/socket_read_after",
            "/expect/socket_read_after",
            "receive-side termination: expected eof, observed reset",
        ),
        Diagnostic::warn("expect/socket_read_after", "/expect/socket_read_after", "private-warning-marker"),
    ]);
    assert_eq!(
        format_regression(&outcome),
        "c-h2-0007 (cases/h2/c-h2-0007.toml) is failed | [expect/socket_read_after]: receive-side termination: expected eof, observed reset"
    );
}

#[test]
fn regression_report_redacts_unrecognized_socket_message() {
    let outcome = diagnostic_fixture(vec![Diagnostic::deny(
        "expect/socket_read_after",
        "/expect/socket_read_after",
        "private-message-marker",
    )]);
    assert_eq!(
        format_regression(&outcome),
        "c-h2-0007 (cases/h2/c-h2-0007.toml) is failed | [expect/socket_read_after]: detail unavailable"
    );
}

#[test]
fn regression_report_includes_bounded_control_frame_detail() {
    let outcome = diagnostic_fixture(vec![Diagnostic::deny(
        "expect/h2_control_frames",
        "/expect/h2_control_frames",
        "received HTTP/2 control frames differ in count, order, or fields",
    )]);
    assert_eq!(
        format_regression(&outcome),
        "c-h2-0007 (cases/h2/c-h2-0007.toml) is failed | [expect/h2_control_frames]: received HTTP/2 control frames differ in count, order, or fields"
    );
}

#[test]
fn regression_report_handles_real_runner_socket_prefix() {
    let outcome = diagnostic_fixture(vec![Diagnostic::deny(
        "expect/socket_read_after",
        "/expect/socket_read_after",
        "exchange #1, attempt 1: receive-side termination: expected eof, observed reset",
    )]);
    assert_eq!(
        format_regression(&outcome),
        "c-h2-0007 (cases/h2/c-h2-0007.toml) is failed | [expect/socket_read_after]: receive-side termination: expected eof, observed reset"
    );
}

#[test]
fn regression_report_does_not_echo_runner_exchange_name() {
    let outcome = diagnostic_fixture(vec![Diagnostic::deny(
        "expect/socket_read_after",
        "/expect/socket_read_after",
        "exchange #1 private-prefix-marker, attempt 1: receive-side termination: expected eof, observed reset",
    )]);
    assert_eq!(
        format_regression(&outcome),
        "c-h2-0007 (cases/h2/c-h2-0007.toml) is failed | [expect/socket_read_after]: receive-side termination: expected eof, observed reset"
    );
}

#[test]
fn regression_report_handles_colon_in_runner_exchange_name() {
    let outcome = diagnostic_fixture(vec![Diagnostic::deny(
        "expect/socket_read_after",
        "/expect/socket_read_after",
        "exchange #1 private-prefix: marker, attempt 1: receive-side termination: expected eof, observed reset",
    )]);
    assert_eq!(
        format_regression(&outcome),
        "c-h2-0007 (cases/h2/c-h2-0007.toml) is failed | [expect/socket_read_after]: receive-side termination: expected eof, observed reset"
    );
}

#[test]
fn regression_report_handles_runner_control_frame_prefix() {
    let outcome = diagnostic_fixture(vec![Diagnostic::deny(
        "expect/h2_control_frames",
        "/expect/h2_control_frames",
        "exchange #1, attempt 1: received HTTP/2 control frames differ in count, order, or fields",
    )]);
    assert_eq!(
        format_regression(&outcome),
        "c-h2-0007 (cases/h2/c-h2-0007.toml) is failed | [expect/h2_control_frames]: received HTTP/2 control frames differ in count, order, or fields"
    );
}

#[test]
fn regression_report_redacts_timeout_message() {
    let outcome = diagnostic_fixture(vec![Diagnostic::deny(
        "runner/timeout",
        "/case/timeout_ms",
        "private-timeout-marker",
    )]);
    assert_eq!(
        format_regression(&outcome),
        "c-h2-0007 (cases/h2/c-h2-0007.toml) is failed | [runner/timeout]: deadline exceeded"
    );
}

#[test]
fn regression_report_redacts_untrusted_outcome_kind() {
    let outcome = diagnostic_fixture(vec![Diagnostic::deny(
        "expect/kind",
        "/expect/kind",
        "exchange #1, attempt 1: private-kind-marker",
    )]);
    assert_eq!(
        format_regression(&outcome),
        "c-h2-0007 (cases/h2/c-h2-0007.toml) is failed | [expect/kind]: outcome mismatch"
    );
}

/// **The baseline is complete: every case in the corpus carries a row.**
///
/// The ruling rustfs/gateway#192 asks for, written as an assertion rather than as prose. When this
/// was measured on `119570e` the corpus held 711 cases and the baseline 245 rows, and four family
/// ledgers — copy, list, multipart, conditional/range — each carried a private copy of this same
/// check for their own directory while the other twenty-one domains had none. Those four keep
/// theirs, because a family ledger is meant to stand on its own; this is the one that covers the
/// domains no ledger speaks for. It takes no allowlist: the one allowlist that existed
/// (`NOT_YET_IN_THE_BASELINE` in `range_cond_family.rs`) is how "not this branch's to refresh"
/// became 466 unrecorded cases.
///
/// It is worth enforcing only because a row now does something. Until
/// [`rustfs_gateway_conformance::report::Report::regressions`] compared the whole verdict ladder,
/// a `passed` row and a missing row took the identical branch, and backfilling would have been
/// bookkeeping. Now a recorded `passed` that turns into a skip is a regression, so the row is the
/// claim that the case executes.
#[test]
fn every_case_in_the_corpus_carries_a_baseline_row() {
    let corpus = corpus();
    let baseline = baseline();
    let unrecorded: Vec<&str> = corpus
        .cases()
        .iter()
        .filter(|case| baseline.expected(&case.id).is_none())
        .map(|case| case.id.as_str())
        .collect();
    assert!(
        unrecorded.is_empty(),
        "{} case(s) have no row in conformance/baseline.json. Add one per case — a case with no \
         row is a case whose verdict nothing has ever written down: {unrecorded:?}",
        unrecorded.len()
    );
}

/// **No row in the baseline names a case the corpus no longer has.**
///
/// The other direction of the same table. A row for a deleted case is a tolerance nothing can
/// spend, and a `failed` row for a deleted case is worse than useless: re-adding the id later
/// silently inherits permission to fail.
#[test]
fn no_baseline_row_names_a_case_the_corpus_does_not_have() {
    let corpus = corpus();
    let held: std::collections::BTreeSet<&str> = corpus.cases().iter().map(|case| case.id.as_str()).collect();
    let baseline = baseline();
    let orphans: Vec<&str> = baseline.ids().filter(|id| !held.contains(id)).collect();
    assert!(orphans.is_empty(), "baseline rows for cases that no longer exist: {orphans:?}");
}

/// **The whole corpus runs against the assembled service and regresses against nothing.**
///
/// This is the gate rustfs/gateway#192 says CI never ran. Two assertions, because either alone is
/// satisfiable by an accident: a run in which nothing executed has no regressions either, so the
/// executed count is asserted first and against a floor derived from the corpus itself rather
/// than a number that would need editing every time a case is added.
#[test]
fn the_whole_corpus_holds_the_verdicts_the_baseline_records() {
    let corpus = corpus();
    // The same evaluation `conformance baseline` renders the file from (rustfs/gateway#985).
    let report = runner::reference_report(&corpus, &RunOptions::default());

    let executed = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict != Verdict::Skipped)
        .count();
    assert!(
        executed * 10 >= report.outcomes.len() * 9,
        "only {executed} of {} cases reached a verdict; a run that stopped executing has no \
         regressions either",
        report.outcomes.len()
    );

    let baseline = baseline();
    let regressions: Vec<String> = report
        .regressions(Some(&baseline))
        .iter()
        .map(|outcome| format_regression(outcome))
        .collect();
    assert!(
        regressions.is_empty(),
        "{} case(s) regressed against conformance/baseline.json:\n{}",
        regressions.len(),
        regressions.join("\n")
    );

    // rustfs/gateway#985: a refresh renders this same evaluation, so refresh-then-gate is green —
    // judged against its own rendering it has neither a regression nor an improvement — and the
    // committed file is exactly what a refresh writes today. One evaluation serves both halves.
    let refreshed = Baseline::from_json(&Baseline::render(&report)).expect("the rendering parses");
    assert!(report.regressions(Some(&refreshed)).is_empty(), "a refresh regresses against itself");
    assert!(report.improvements(Some(&refreshed)).is_empty(), "a refresh improves on itself");
    let differing: std::collections::BTreeSet<&str> = refreshed
        .ids()
        .chain(baseline.ids())
        .filter(|id| refreshed.expected(id) != baseline.expected(id))
        .collect();
    assert!(
        differing.is_empty(),
        "conformance/baseline.json differs from `conformance baseline` for {differing:?}"
    );
}

#[test]
fn the_whole_corpus_is_internally_consistent() {
    let corpus = corpus();
    let mut sut = Unwired;
    let options = RunOptions {
        validate_only: true,
        ..RunOptions::default()
    };
    let report = runner::run(&corpus, &mut sut, &options);

    assert!(!report.outcomes.is_empty(), "the corpus is empty");
    let rejected: Vec<String> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict != Verdict::Validated)
        .map(|outcome| {
            let reasons: Vec<String> = outcome.failures().iter().map(ToString::to_string).collect();
            format!("{} ({}): {}", outcome.id, outcome.relative, reasons.join(" | "))
        })
        .collect();
    assert!(rejected.is_empty(), "cases the runner refuses to load:\n{}", rejected.join("\n"));
}

#[test]
fn every_case_reaches_a_conclusion_and_a_skip_states_its_reason() {
    let corpus = corpus();
    let mut sut = Unwired;
    let report = runner::run(&corpus, &mut sut, &RunOptions::default());

    assert_eq!(report.outcomes.len(), corpus.cases().len(), "a case was dropped rather than concluded");
    for outcome in &report.outcomes {
        match outcome.verdict {
            Verdict::Skipped => assert!(
                outcome.skip_reason.is_some(),
                "{} was skipped with no reason; `did not run` and `ran and was red` must stay distinguishable",
                outcome.id
            ),
            // `Validated` is not reachable here — this run is not validate-only, and its target
            // executes nothing anyway. The invariant it would state is asserted where a target
            // does answer: `runner::tests::a_run_that_executes_records_a_pass_not_a_validation`.
            Verdict::Passed | Verdict::Failed | Verdict::Validated => {}
        }
    }
}

#[test]
fn the_corpus_keeps_negative_cases_in_the_majority() {
    let corpus = corpus();
    let mut sut = Unwired;
    let report = runner::run(&corpus, &mut sut, &RunOptions::default());
    let (negative, positive) = report.polarity;
    assert!(negative >= positive, "{negative} negative versus {positive} positive");
}

#[test]
fn the_reports_a_ci_system_consumes_are_well_formed() {
    let corpus = corpus();
    let mut sut = Unwired;
    let report = runner::run(&corpus, &mut sut, &RunOptions::default());

    let junit = report.render_junit();
    assert!(junit.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite "));
    assert_eq!(junit.matches("<testcase ").count(), report.outcomes.len());

    let json = report.render_json();
    let parsed = rustfs_gateway_conformance::json::parse(&json).expect("the JSON report parses");
    let cases = parsed.path("cases").and_then(|value| value.as_array().map(<[_]>::len));
    assert_eq!(cases, Some(report.outcomes.len()));
}

/// **Negative — the frozen schema pairs each fault point with the fields that point can carry.**
///
/// `code` is what a continuation reports. A continuation that stops making progress reports
/// nothing, so a case naming a code for one would be naming a code no implementation could ever
/// produce — and it would sit in the corpus reading like an assertion. The schema is where that is
/// caught, because it is the only check that runs before the case is loaded at all.
///
/// Both directions, over the real `conformance/case.schema.json` rather than a fragment: the
/// dropped `required: ["code"]` that widening the `at` enum needed is exactly the kind of edit that
/// silently makes the *other* point's code optional, after which `c-mpu-0001` could lose its
/// `InvalidPart` and still load.
#[test]
fn a_fault_point_may_only_carry_the_fields_that_point_has() {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let source = std::fs::read_to_string(root.join("case.schema.json")).expect("the frozen schema is checked in");
    let schema = rustfs_gateway_conformance::schema::Schema::compile(&source).expect("the frozen schema compiles");

    let case = |fault: &str| {
        format!(
            "[case]\nid = \"c-x-0001\"\nschema_version = 1\ntitle = \"a fault point carries its own fields\"\n\
             rationale = \"The point named by a fault decides which other fields exist, and this document is \
             here only to be measured against the frozen schema.\"\npolarity = \"negative\"\nquirks = []\n\
             [[case.evidence]]\nurl = \"https://example.invalid/\"\nsummary = \"a synthetic document\"\nkind = \"aws-doc\"\n\
             [setup.fault]\n{fault}\n\
             [request]\nmethod = \"POST\"\ntarget = \"/b?uploads\"\n[expect]\nkind = \"response\"\nstatus = 200\n"
        )
    };
    let violations = |fault: &str| {
        let document = rustfs_gateway_conformance::toml::parse(&case(fault)).expect("valid TOML");
        schema
            .validate(&document)
            .into_iter()
            .map(|violation| format!("{}: {}", violation.pointer, violation.message))
            .collect::<Vec<_>>()
    };

    const OP: &str = "operation = \"CompleteMultipartUpload\"\n";
    for (fault, admitted, why) in [
        // The two legal shapes.
        ("at = \"after_commit\"\ncode = \"InvalidPart\"", true, "a reported failure with its code"),
        ("at = \"no_progress_after_commit\"", true, "a stall with no code"),
        // A reported failure with no code to report.
        (
            "at = \"after_commit\"",
            false,
            "`after_commit` without a code: the case would arm a fault that reports nothing",
        ),
        // A stall carrying a code nothing will ever report.
        (
            "at = \"no_progress_after_commit\"\ncode = \"InvalidPart\"",
            false,
            "`no_progress_after_commit` with a code: the case would name a code no implementation can produce",
        ),
        // And a point that does not exist at all.
        ("at = \"before_commit\"\ncode = \"InvalidPart\"", false, "an undeclared fault point"),
    ] {
        let found = violations(&format!("{OP}{fault}"));
        assert_eq!(found.is_empty(), admitted, "{why}: {found:?}");
    }
}
