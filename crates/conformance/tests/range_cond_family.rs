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

//! The ledger of the conditional and range families, and the one case still blocked on a capability.
//!
//! Responsible for: pinning the two families as *closed* sets — twenty-eight conditional
//! identifiers with no gap and no duplicate, twenty range identifiers whose two gaps are accounted
//! for rather than lost, thirty-two negative against sixteen positive, every one of them carrying a
//! verdict in the checked-in baseline — and for proving both families execute against the
//! in-process target with no regression, with `c-range-0007` green, and with `c-cond-0013` the only
//! case that does not run and skipped for a reason it states. A family whose size, polarity and
//! baseline membership are only ever counted by a human is a family that silently loses a case, and
//! a skip with no stated reason is indistinguishable from a case nobody wrote.
//! NOT responsible for: what any individual case asserts — that lives in the case file — or for the
//! corpus-wide invariants, which `tests/corpus.rs` already owns.
//! Upstream: the published API of `rustfs_gateway_conformance`, and `conformance/baseline.json`.
//! Downstream: nothing.

use rustfs_gateway_conformance::corpus::{Case, Corpus};
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::{Baseline, Report, Verdict};
use rustfs_gateway_conformance::runner::{self, RunOptions};

/// The size of each family. Numbers, not ranges: growing or shrinking a family is a decision
/// somebody writes down, and this is where they write it.
const COND_SIZE: usize = 28;
const RANGE_SIZE: usize = 20;

/// The polarity split, in the order `AGENTS.md` states the rule: negatives must outnumber
/// positives.
const COND_NEGATIVE: usize = 19;
const COND_POSITIVE: usize = 9;
const RANGE_NEGATIVE: usize = 13;
const RANGE_POSITIVE: usize = 7;

/// The two range identifiers that are deliberately not case files.
///
/// Both assert something a data-file case cannot reach — that the *encoded* head of a real
/// `GetObject` adapter carries the typed part outcome and the typed count — so they live as
/// executable direct cases, which is the form `scripts/check_quirk_ledger.sh` accepts as evidence
/// for a wired quirk. Naming them here is what stops the gap in the file numbering from reading
/// like two deleted cases.
const RANGE_DIRECT_CASES: [&str; 2] = ["c-range-0020", "c-range-0021"];

/// Where those two live. Read as text rather than executed: this file proves the identifiers are
/// still accounted for somewhere a reader can find, not that the assertions inside them hold —
/// `cargo test --workspace` runs them, and that is the right place for it.
const DIRECT_CASE_FILE: &str = "../gateway/tests/precondition_contract.rs";

fn corpus() -> Corpus {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    runner::prepare_corpus(&root).expect("the corpus loads")
}

fn family<'a>(corpus: &'a Corpus, prefix: &str) -> Vec<&'a Case> {
    corpus
        .cases()
        .iter()
        .filter(|case| case.relative.starts_with(prefix))
        .collect()
}

fn baseline() -> Baseline {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let source = std::fs::read_to_string(root.join("baseline.json")).expect("the baseline is checked in");
    Baseline::from_json(&source).expect("the baseline parses")
}

fn run(filter: &str) -> Report {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = InProcess::new(root);
    let options = RunOptions {
        filter: Some(filter.to_owned()),
        ..RunOptions::default()
    };
    runner::run(&corpus, &mut sut, &options)
}

fn identifiers(cases: &[&Case]) -> Vec<String> {
    let mut ids: Vec<String> = cases.iter().map(|case| case.id.clone()).collect();
    ids.sort();
    ids
}

/// The conditional family is a closed ledger: twenty-eight identifiers, contiguous, one per file.
///
/// A gap means a case was deleted — which `AGENTS.md` lists as a silently dropped guarantee — and a
/// duplicate means two files claim one identifier, after which only one of them is ever reported.
#[test]
fn the_conditional_family_is_a_closed_ledger_of_twenty_eight_identifiers() {
    let corpus = corpus();
    let ids = identifiers(&family(&corpus, "cases/cond/"));

    let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "two conditional cases share an identifier: {ids:?}");
    assert_eq!(ids.len(), COND_SIZE, "the conditional family holds {} cases, not {COND_SIZE}", ids.len());

    let expected: Vec<String> = (1..=COND_SIZE).map(|n| format!("c-cond-{n:04}")).collect();
    assert_eq!(
        ids, expected,
        "the conditional identifiers are not the contiguous run 0001..{COND_SIZE:04}"
    );
}

/// The range family is a closed ledger too, and its two gaps are named rather than merely absent.
///
/// `c-range-0020` and `c-range-0021` are executable direct cases instead of case files. Asserting
/// only "twenty files exist" would stay green if a *third* identifier vanished into the same gap,
/// so the run is checked against the file set and the two absentees against the file that holds
/// them.
#[test]
fn the_range_family_is_a_closed_ledger_whose_two_gaps_are_accounted_for() {
    let corpus = corpus();
    let ids = identifiers(&family(&corpus, "cases/range/"));

    let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "two range cases share an identifier: {ids:?}");
    assert_eq!(ids.len(), RANGE_SIZE, "the range family holds {} case files, not {RANGE_SIZE}", ids.len());

    let highest = 22;
    let expected: Vec<String> = (1..=highest)
        .map(|n| format!("c-range-{n:04}"))
        .filter(|id| !RANGE_DIRECT_CASES.contains(&id.as_str()))
        .collect();
    assert_eq!(
        ids, expected,
        "the range case files are not the run 0001..{highest:04} minus {RANGE_DIRECT_CASES:?}"
    );

    let direct = std::fs::read_to_string(DIRECT_CASE_FILE).expect("the direct-case file is checked in");
    for id in RANGE_DIRECT_CASES {
        assert!(direct.contains(id), "{id} is neither a case file nor named in {DIRECT_CASE_FILE}");
    }
}

/// Both families keep negatives in the majority, and they do so by numbers rather than by a
/// direction.
///
/// The corpus-wide check in `tests/corpus.rs` compares two totals over six hundred cases, so a
/// family that flipped every one of its own cases to positive would still leave it green.
#[test]
fn both_families_keep_negatives_in_the_majority_by_a_written_down_margin() {
    let corpus = corpus();
    for (prefix, size, negative, positive) in [
        ("cases/cond/", COND_SIZE, COND_NEGATIVE, COND_POSITIVE),
        ("cases/range/", RANGE_SIZE, RANGE_NEGATIVE, RANGE_POSITIVE),
    ] {
        let cases = family(&corpus, prefix);
        let observed_negative = cases.iter().filter(|case| case.polarity() == Some("negative")).count();
        let observed_positive = cases.iter().filter(|case| case.polarity() == Some("positive")).count();
        assert_eq!(
            observed_negative + observed_positive,
            size,
            "a case under {prefix} declares no polarity at all"
        );
        assert_eq!(
            observed_negative, negative,
            "{prefix} has {observed_negative} negative cases, not {negative}"
        );
        assert_eq!(
            observed_positive, positive,
            "{prefix} has {observed_positive} positive cases, not {positive}"
        );
        assert!(
            observed_negative > observed_positive,
            "negatives no longer outnumber positives under {prefix}"
        );
    }
}

/// Every case in both families reaches the ratchet.
///
/// A case the baseline does not name is a case nothing has ever written a verdict down for, and
/// the ratchet only tightens over ids it already knows about.
///
/// This carried a two-id allowlist — `c-range-0019` and `c-range-0022`, both authored after the
/// last refresh — on the reasoning that `conformance/baseline.json` was regenerated on somebody
/// else's cadence and widening it here was the move `scripts/check_baseline_ratchet.sh` exists to
/// prevent. rustfs/gateway#192 settled that: the baseline is complete, a row is written in the
/// same commit as its case, and the corpus-wide guard in `tests/corpus.rs` now says so for all
/// twenty-six domains. Both ids are recorded, so the allowlist is gone rather than empty — an
/// allowlist nobody has to add to is one everybody adds to.
#[test]
fn every_conditional_and_range_case_carries_a_verdict_in_the_baseline() {
    let corpus = corpus();
    let baseline = baseline();
    let unrecorded: Vec<&str> = ["cases/cond/", "cases/range/"]
        .into_iter()
        .flat_map(|prefix| family(&corpus, prefix))
        .filter(|case| baseline.expected(&case.id).is_none())
        .map(|case| case.id.as_str())
        .collect();
    assert!(unrecorded.is_empty(), "cases absent from the baseline: {unrecorded:?}");
}

/// The range family runs green, and `c-range-0007` — the case the family was blocked on — is one of
/// the cases that ran.
///
/// Three assertions, because each alone is satisfiable by an accident: a run in which every range
/// case was skipped has no regressions; a run with no regressions says nothing about a case the
/// baseline still records as failing; and a filter that selected nothing has no skips either.
#[test]
fn the_range_family_runs_green_with_the_blocked_case_recovered() {
    let report = run("cases/range/");
    let baseline = baseline();

    assert_eq!(report.outcomes.len(), RANGE_SIZE, "the filter did not select the whole range family");
    let skipped: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Skipped)
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(skipped.is_empty(), "range case(s) were skipped rather than run: {skipped:?}");

    let regressions: Vec<&str> = report
        .regressions(Some(&baseline))
        .iter()
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(regressions.is_empty(), "range regressions against the baseline: {regressions:?}");

    let blocked = report
        .outcomes
        .iter()
        .find(|outcome| outcome.id == "c-range-0007")
        .expect("c-range-0007 is selected by the range filter");
    assert_eq!(
        blocked.verdict,
        Verdict::Passed,
        "c-range-0007: {:?}",
        blocked.failures().iter().map(ToString::to_string).collect::<Vec<_>>()
    );
}

/// The conditional family runs green, `c-cond-0027` is one of the cases that ran, and exactly one
/// case does not run.
///
/// `c-cond-0027` is checked by name because the baseline still records it as failing, so the
/// ratchet tolerates either verdict for it: without this assertion, its regression would be
/// invisible here. `c-cond-0013` is checked by name for the opposite reason — it is the only case
/// in either family that a target cannot execute, and a *second* skip appearing would otherwise be
/// absorbed silently.
#[test]
fn the_conditional_family_runs_green_with_one_case_a_target_cannot_execute() {
    let report = run("cases/cond/");
    let baseline = baseline();

    assert_eq!(report.outcomes.len(), COND_SIZE, "the filter did not select the whole conditional family");

    let skipped: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Skipped)
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert_eq!(skipped, ["c-cond-0013"], "the set of conditional cases a target cannot execute changed");

    let regressions: Vec<&str> = report
        .regressions(Some(&baseline))
        .iter()
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(regressions.is_empty(), "conditional regressions against the baseline: {regressions:?}");

    let sides = report
        .outcomes
        .iter()
        .find(|outcome| outcome.id == "c-cond-0027")
        .expect("c-cond-0027 is selected by the conditional filter");
    assert_eq!(
        sides.verdict,
        Verdict::Passed,
        "c-cond-0027: {:?}",
        sides.failures().iter().map(ToString::to_string).collect::<Vec<_>>()
    );
}

/// The one case that does not run says why, and says it in terms of the capability it needs.
///
/// This is the assertion that keeps the skip honest. A skip carrying no reason reads exactly like a
/// case nobody wrote; a skip whose reason is "not implemented" reads like a defect. `c-cond-0013`
/// needs two writes that genuinely race, and the reason has to keep naming that, because the day
/// somebody makes the case pass by removing the race is the day the case stops meaning anything.
#[test]
fn the_racing_conditional_create_states_the_capability_it_is_waiting_for() {
    let report = run("c-cond-0013");
    let outcome = report.outcomes.first().expect("c-cond-0013 is selected by its own id");

    assert_eq!(outcome.verdict, Verdict::Skipped, "c-cond-0013 no longer skips");
    let reason = outcome.skip_reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("connection.pipeline"),
        "the skip does not name the capability it needs: {reason:?}"
    );
    assert!(
        reason.contains("race") || reason.contains("cannot race"),
        "the skip does not say the race is what is missing: {reason:?}"
    );
}
