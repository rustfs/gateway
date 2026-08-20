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
//! NOT responsible for: any individual assertion; those are unit-tested next to the engine.
//! Upstream: the published API of `rustfs_gateway_conformance`. Downstream: nothing.

use rustfs_gateway_conformance::corpus::Corpus;
use rustfs_gateway_conformance::report::Verdict;
use rustfs_gateway_conformance::runner::{self, RunOptions};
use rustfs_gateway_conformance::sut::Unwired;

fn corpus() -> Corpus {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    runner::prepare_corpus(&root).expect("the corpus loads")
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
        .filter(|outcome| outcome.verdict != Verdict::Passed)
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
            Verdict::Passed | Verdict::Failed => {}
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
