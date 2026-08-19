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

//! The `copy/` family as a closed ledger, executed rather than merely loaded.
//!
//! Responsible for: pinning the copy family as a *closed* set — thirty-eight identifiers with no
//! gap and no duplicate, twenty negative against eighteen positive, every one of them carrying a
//! verdict in the checked-in baseline — and for proving the family really runs against the
//! in-process target, that all thirty-eight are green, and that the last one to become so did not
//! buy its verdict by moving the boundary the family's other cases stand on.
//! NOT responsible for: what any individual copy case asserts — that lives in the case file — or
//! for the corpus-wide invariants, which `tests/corpus.rs` already owns, or for the `--baseline`
//! ratchet, which is a release-time comparison over the whole corpus rather than a per-family gate.
//! See `crates/conformance/MAP.md`.
//! Upstream: the published API of `rustfs_gateway_conformance`, and `conformance/baseline.json`.
//! Downstream: nothing.
//!
//! # Why this file exists at all
//!
//! Before it, `copy/` was green in `cargo xtask conformance run` and reached by nothing in `cargo
//! test --workspace`: `tests/` held a ledger for `list/`, one for `object/` and a hand-assembled
//! harness for `?tagging`, and no copy equivalent. A family only the manual run reaches is a family
//! whose regression is discovered at release time, and — the sharper half — a family that could be
//! unwired from the in-process registry without any test going red, because `Unwired` answers every
//! case with a skip and a skip and a pass are the same colour in a summary line.
//!
//! # Why the counts are equalities and not floors
//!
//! `tests/object.rs` deliberately uses a floor, because the cases it exempts are owned by other
//! branches and would turn `main` red the moment one of them merged. The copy family is in the
//! opposite position: it is complete, and its one red case is blocked on a decision this family
//! itself owns (see below). So an equality is the right shape — nothing outside this issue can move
//! these numbers, and anything that does move them is a decision somebody has to write down here.

use rustfs_gateway_conformance::corpus::{Case, Corpus};
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::{Baseline, Report, Verdict};
use rustfs_gateway_conformance::runner::{self, RunOptions};

/// The size of the family: the thirty-eight cases enumerated in rustfs/backlog#1686 §7.
const FAMILY_SIZE: usize = 38;

/// The polarity split, in the order `AGENTS.md` states the rule: negatives outnumber positives.
const NEGATIVE: usize = 20;
const POSITIVE: usize = 18;

/// How many of the family are green. All of them.
const GREEN: usize = FAMILY_SIZE;

/// The case the family was blocked on, and the reason the block was a real one.
///
/// `c-copy-0038` asks for a copy that fails *after* its response head is committed: status `200`,
/// body an `<Error>` document. Until `setup.fault` existed the corpus could not describe that
/// fault. `setup.objects.absent = true` says the source did not exist when the request began, and a
/// source that did not exist when the request began is discovered before the copy starts — which is
/// exactly what [`COUPLED`] pins as a `404 NoSuchKey`. The cheap way to turn this case green was
/// therefore to move the source lookup after the commit point, and that would have turned
/// `c-copy-0034` into a `200` and moved the source-authorization boundary — the GHSA-mx42/wfxj
/// surface — past the point where the answer can still be withheld.
///
/// It is green now because the case says when the copy fails instead of the fixture being rearranged
/// until it does. The two verdicts stay one decision, which is why they are still asserted together:
/// see [`the_recovered_case_is_green_without_moving_the_boundary_that_keeps_a_missing_source_a_404`].
const RECOVERED: &str = "c-copy-0038";

/// The case whose verdict is the price [`RECOVERED`] must not pay.
const COUPLED: &str = "c-copy-0034";

fn corpus() -> Corpus {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    runner::prepare_corpus(&root).expect("the corpus loads")
}

fn family(corpus: &Corpus) -> Vec<&Case> {
    corpus
        .cases()
        .iter()
        .filter(|case| case.relative.starts_with("cases/copy/"))
        .collect()
}

fn baseline() -> Baseline {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let source = std::fs::read_to_string(root.join("baseline.json")).expect("the baseline is checked in");
    Baseline::from_json(&source).expect("the baseline parses")
}

fn run_copy_domain() -> Report {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = InProcess::new(root);
    let options = RunOptions {
        filter: Some("copy/".to_owned()),
        ..RunOptions::default()
    };
    runner::run(&corpus, &mut sut, &options)
}

fn reasons(report: &Report, id: &str) -> Vec<String> {
    report
        .outcomes
        .iter()
        .find(|outcome| outcome.id == id)
        .unwrap_or_else(|| panic!("{id} is selected by the copy filter"))
        .failures()
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// Negative — the copy family is a closed ledger: thirty-eight identifiers, contiguous, one file
/// each.
///
/// A gap means a case was deleted, which `AGENTS.md` lists as a silently dropped guarantee; a
/// duplicate means two files claim one identifier, after which only one of them is ever reported.
#[test]
fn the_copy_family_is_a_closed_ledger_of_thirty_eight_identifiers() {
    let corpus = corpus();
    let cases = family(&corpus);

    let mut ids: Vec<&str> = cases.iter().map(|case| case.id.as_str()).collect();
    ids.sort_unstable();
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "two copy cases share an identifier: {ids:?}");
    assert_eq!(ids.len(), FAMILY_SIZE, "the copy family holds {} cases, not {FAMILY_SIZE}", ids.len());

    let expected: Vec<String> = (1..=FAMILY_SIZE).map(|n| format!("c-copy-{n:04}")).collect();
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    assert_eq!(ids, expected, "the copy identifiers are not the contiguous run 0001..{FAMILY_SIZE:04}");
}

/// Negative — the family keeps negatives in the majority, by a number rather than by a direction.
///
/// The corpus-wide check in `tests/corpus.rs` compares two totals over six hundred cases, so a
/// family that flipped every one of its own cases to positive would still leave it green.
#[test]
fn the_copy_family_keeps_twenty_negative_against_eighteen_positive() {
    let corpus = corpus();
    let cases = family(&corpus);

    let negative = cases.iter().filter(|case| case.polarity() == Some("negative")).count();
    let positive = cases.iter().filter(|case| case.polarity() == Some("positive")).count();
    assert_eq!(negative + positive, FAMILY_SIZE, "a copy case declares no polarity at all");
    assert_eq!(negative, NEGATIVE, "the copy family has {negative} negative cases, not {NEGATIVE}");
    assert_eq!(positive, POSITIVE, "the copy family has {positive} positive cases, not {POSITIVE}");
    assert!(negative > positive, "negatives no longer outnumber positives in the copy family");
}

/// Negative — every copy case reaches the ratchet.
///
/// A case the baseline does not name is a case whose failure would be a *new* failure the first
/// time anybody looked, and the ratchet only tightens over ids it already knows about.
#[test]
fn every_copy_case_carries_a_verdict_in_the_baseline() {
    let corpus = corpus();
    let baseline = baseline();
    let unrecorded: Vec<&str> = family(&corpus)
        .iter()
        .filter(|case| baseline.expected(&case.id).is_none())
        .map(|case| case.id.as_str())
        .collect();
    assert!(unrecorded.is_empty(), "copy cases absent from the baseline: {unrecorded:?}");
}

/// Positive — the family executes against the assembled service, and thirty-seven of the
/// thirty-eight are green.
///
/// Three separate things are asserted because each is satisfiable without the others, and the
/// combination is what "the family passes" is usually taken to mean:
///
/// * the filter selects the whole family — otherwise a narrowed filter proves whatever is left;
/// * no case is *skipped* — an unwired registry answers every case with a skip, and a summary line
///   renders that identically to a family with nothing wrong with it;
/// * exactly thirty-seven passed, and exactly one failed, and it is the one named below — a count
///   alone would let a newly-green case pay for a newly-red one.
#[test]
fn the_copy_family_runs_with_thirty_seven_green_and_nothing_skipped() {
    let report = run_copy_domain();

    assert_eq!(report.outcomes.len(), FAMILY_SIZE, "the filter did not select the whole family");
    let skipped: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Skipped)
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(
        skipped.is_empty(),
        "copy cases skipped rather than run — is the family wired? {skipped:?}"
    );

    let passed = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Passed)
        .count();
    let failed: Vec<String> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Failed)
        .map(|outcome| {
            let why: Vec<String> = outcome.failures().iter().map(ToString::to_string).collect();
            format!("{}: {}", outcome.id, why.join(" | "))
        })
        .collect();

    assert!(
        failed.is_empty(),
        "the copy family has {} red cases, not none:\n{}",
        failed.len(),
        failed.join("\n")
    );
    assert_eq!(passed, GREEN, "{passed} copy cases are green, not {GREEN}");
}

/// Negative — the family does not regress against the checked-in ratchet.
///
/// Distinct from the count above: the counts say how many are green, this says *which*, against the
/// verdicts the repository has already agreed to. A family could hold its totals while swapping a
/// green case for a red one.
#[test]
fn the_copy_family_holds_the_verdicts_the_baseline_records() {
    let report = run_copy_domain();
    let baseline = baseline();
    let regressions: Vec<&str> = report
        .regressions(Some(&baseline))
        .iter()
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(regressions.is_empty(), "copy regressions against the baseline: {regressions:?}");
}

/// Negative — the recovered case is green, and it did not buy that verdict from [`COUPLED`].
///
/// Asserted as a pair on purpose, and for the same reason the pair existed while `c-copy-0038` was
/// red. That case wants a refusal delivered *after* the head is committed. There were two ways to
/// get one: describe a fault that happens at that point, or move an existing check down past the
/// commit so that an ordinary refusal arrives late. The second is a one-line change to the fixture,
/// it makes `c-copy-0038` green, and it silently relocates the source lookup — and with it the
/// source-authorization boundary, the GHSA-mx42/wfxj surface — past the point where the answer can
/// still be withheld. `c-copy-0034` is what that costs: a copy whose source is not there must be a
/// `404` decided *before* the copy starts, not a `200` carrying an `<Error>`.
///
/// So a green `c-copy-0038` on its own proves nothing about which of the two happened. The pair
/// does: the only arrangement that satisfies both is a fault that occurs after a commit the other
/// case never reaches.
#[test]
fn the_recovered_case_is_green_without_moving_the_boundary_that_keeps_a_missing_source_a_404() {
    let report = run_copy_domain();

    let recovered = reasons(&report, RECOVERED);
    assert!(
        recovered.is_empty(),
        "{RECOVERED} is red — the post-commit fault seam no longer delivers a failure inside a \
         success: {recovered:?}"
    );

    let coupled = reasons(&report, COUPLED);
    assert!(
        coupled.is_empty(),
        "{COUPLED} is red: a missing copy source no longer answers 404 before the copy starts, \
         which is the boundary {RECOVERED} must be green *without* moving: {coupled:?}"
    );
}
