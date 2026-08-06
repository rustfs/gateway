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
