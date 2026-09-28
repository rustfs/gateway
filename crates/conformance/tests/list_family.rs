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

//! The ledger of the list family, and the one case the family was blocked on.
//!
//! Responsible for: pinning the list family as a *closed* set — forty-six identifiers with no gap
//! and no duplicate, twenty-four negative against twenty-two positive, every one of them carrying
//! a verdict in the checked-in baseline — and for proving the family executes against the
//! in-process target with no regression and with `c-list-0021` green. A family whose size, polarity
//! and baseline membership are only ever counted by a human is a family that silently loses a case:
//! a file that disappears, a positive quietly added, or a new case that never reaches the ratchet
//! all read exactly like nothing happened.
//! NOT responsible for: what any individual list case asserts — that lives in the case file — or
//! for the corpus-wide invariants, which `tests/corpus.rs` already owns.
//! Upstream: the published API of `rustfs_gateway_conformance`, and `conformance/baseline.json`.
//! Downstream: nothing.

use rustfs_gateway_conformance::corpus::{Case, Corpus};
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::{Baseline, Verdict};
use rustfs_gateway_conformance::runner::{self, RunOptions};

/// The size of the family. A number, not a range: the point of the guard is that growing or
/// shrinking the family is a decision somebody writes down, and this is where they write it.
const FAMILY_SIZE: usize = 47;

/// The polarity split, in the order `AGENTS.md` states the rule: negatives must outnumber
/// positives, and here they do by exactly three.
const NEGATIVE: usize = 25;
const POSITIVE: usize = 22;

fn corpus() -> Corpus {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    runner::prepare_corpus(&root).expect("the corpus loads")
}

fn family(corpus: &Corpus) -> Vec<&Case> {
    corpus
        .cases()
        .iter()
        .filter(|case| case.relative.starts_with("cases/list/"))
        .collect()
}

fn baseline() -> Baseline {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let source = std::fs::read_to_string(root.join("baseline.json")).expect("the baseline is checked in");
    Baseline::from_json(&source).expect("the baseline parses")
}

/// The list family is a closed ledger: forty-seven identifiers, contiguous, each in its own file.
///
/// A gap means a case was deleted — which `AGENTS.md` lists as a silently dropped guarantee — and a
/// duplicate means two files claim one identifier, after which only one of them is ever reported.
#[test]
fn the_list_family_is_a_closed_ledger_of_forty_seven_identifiers() {
    let corpus = corpus();
    let cases = family(&corpus);

    let mut ids: Vec<&str> = cases.iter().map(|case| case.id.as_str()).collect();
    ids.sort_unstable();
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "two list cases share an identifier: {ids:?}");
    assert_eq!(ids.len(), FAMILY_SIZE, "the list family holds {} cases, not {FAMILY_SIZE}", ids.len());

    let expected: Vec<String> = (1..=FAMILY_SIZE).map(|n| format!("c-list-{n:04}")).collect();
    let observed: Vec<&str> = ids;
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    assert_eq!(
        observed, expected,
        "the list identifiers are not the contiguous run 0001..{FAMILY_SIZE:04}"
    );
}

/// The family keeps negatives in the majority, and it does so by a number rather than by a
/// direction.
///
/// The corpus-wide check in `tests/corpus.rs` compares two totals over six hundred cases, so a
/// family that flipped every one of its own cases to positive would still leave it green.
#[test]
fn the_list_family_keeps_twenty_five_negative_against_twenty_two_positive() {
    let corpus = corpus();
    let cases = family(&corpus);

    let negative = cases.iter().filter(|case| case.polarity() == Some("negative")).count();
    let positive = cases.iter().filter(|case| case.polarity() == Some("positive")).count();
    assert_eq!(negative + positive, FAMILY_SIZE, "a list case declares no polarity at all");
    assert_eq!(negative, NEGATIVE, "the list family has {negative} negative cases, not {NEGATIVE}");
    assert_eq!(positive, POSITIVE, "the list family has {positive} positive cases, not {POSITIVE}");
    assert!(negative > positive, "negatives no longer outnumber positives in the list family");
}

/// Every list case reaches the ratchet.
///
/// A case the baseline does not name is a case whose failure would be a *new* failure the first
/// time anybody looked, and the ratchet only tightens over ids it already knows about.
#[test]
fn every_list_case_carries_a_verdict_in_the_baseline() {
    let corpus = corpus();
    let baseline = baseline();
    let unrecorded: Vec<&str> = family(&corpus)
        .iter()
        .filter(|case| baseline.expected(&case.id).is_none())
        .map(|case| case.id.as_str())
        .collect();
    assert!(unrecorded.is_empty(), "list cases absent from the baseline: {unrecorded:?}");
}

/// The family executes, and `c-list-0021` — the one case the family was blocked on — is green.
///
/// Both halves are asserted because either alone is satisfiable by an accident: a run in which
/// every list case was skipped has no regressions, and a run with no regressions says nothing about
/// a case the baseline records as failing. The baseline still records `c-list-0021` as failed, so
/// its verdict here is checked directly rather than through the ratchet, which tolerates it.
#[test]
fn the_list_family_runs_green_with_the_blocked_case_recovered() {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = InProcess::new(root);
    let options = RunOptions {
        filter: Some("list/".to_owned()),
        ..RunOptions::default()
    };
    let report = runner::run(&corpus, &mut sut, &options);
    let baseline = baseline();

    assert_eq!(report.outcomes.len(), FAMILY_SIZE, "the filter did not select the whole family");
    let executed = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict != Verdict::Skipped)
        .count();
    assert_eq!(
        executed,
        FAMILY_SIZE,
        "{} list case(s) were skipped rather than run",
        FAMILY_SIZE - executed
    );

    let regressions: Vec<&str> = report
        .regressions(Some(&baseline))
        .iter()
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(regressions.is_empty(), "list regressions against the baseline: {regressions:?}");

    let blocked = report
        .outcomes
        .iter()
        .find(|outcome| outcome.id == "c-list-0021")
        .expect("c-list-0021 is selected by the list filter");
    assert_eq!(
        blocked.verdict,
        Verdict::Passed,
        "c-list-0021: {:?}",
        blocked.failures().iter().map(ToString::to_string).collect::<Vec<_>>()
    );
}
