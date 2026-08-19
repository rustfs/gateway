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

//! The `lifecycle/` family as a closed ledger, executed rather than merely loaded.
//!
//! Responsible for: pinning the lifecycle family as a *closed* set — thirty identifiers with no
//! gap and no duplicate, eighteen negative against twelve positive, all three operations of the
//! family reached — for proving the family really runs against the in-process target with every
//! case green and none skipped, and for the binding rustfs/backlog#1719 §8 asks for and no
//! command in this repository provides: every quirk the lifecycle overlay declares is claimed by
//! at least one case, and every quirk a case claims is one the overlay declares.
//! NOT responsible for: what any individual lifecycle case asserts — that lives in the case file
//! — or for the corpus-wide invariants, which `tests/corpus.rs` owns, or for the `--baseline`
//! ratchet over the whole corpus, or for the codec-level round-trip identity, which
//! `crates/core/tests/lifecycle_roundtrip.rs` owns because it is a property over documents nobody
//! wrote rather than a verdict on documents somebody did. See `crates/conformance/MAP.md`.
//! Upstream: the published API of `rustfs_gateway_conformance`, and
//! `model/overlays/quirks/lifecycle.toml`. Downstream: nothing.
//!
//! # Why this file exists at all
//!
//! Before it, `lifecycle/` was green in `cargo xtask conformance run` and reached by nothing in
//! `cargo test --workspace`. A family only the manual run reaches is a family whose regression is
//! found at release time, and — the sharper half — a family that could be unwired from the
//! in-process registry without any test going red, because `Unwired` answers every case with a
//! skip and a skip and a pass are the same colour in a summary line. `crates/conformance/tests/
//! bucket_lifecycle.rs` does not close that hole despite its name: it registers exactly one
//! lifecycle operation, to prove a recreated bucket inherits no document, and asserts nothing
//! about the corpus.
//!
//! # Why the quirk binding is here and not in a mutation run
//!
//! rustfs/backlog#1719 §9 names `cargo xtask conformance mutate --family lifecycle` and expects
//! "every quirk kills at least one case, no UNCOVERED". That subcommand does not exist. The
//! *coverage* half of what it would report is decidable without it, deterministically, from the
//! corpus and the overlay: a quirk no case claims is a protocol exception this suite asserts
//! nothing about, and a case claiming a quirk id that the overlay does not declare is a citation
//! to nothing. Neither is what a mutation run proves — a claimed quirk is not a killed mutant —
//! so this is written as the weaker check it is, and the family's mutation evidence stays with
//! the pull request that adds each assertion.
//!
//! # Why the counts are equalities and not floors
//!
//! `tests/object.rs` uses a floor, because the cases it exempts are owned by other branches and
//! would turn `main` red the moment one of them merged. The lifecycle family is in the opposite
//! position: it is complete and wholly green, nothing outside this issue can move these numbers,
//! and anything that does move them is a decision somebody has to write down here.

use std::collections::BTreeSet;

use rustfs_gateway_conformance::corpus::{Case, Corpus};
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::{Baseline, Report, Verdict};
use rustfs_gateway_conformance::runner::{self, RunOptions};

/// The size of the family: the twenty-nine cases landed with the family in rustfs/gateway#24,
/// plus the body-digest negative that only became expressible once `verify_body_digest` had a
/// production caller.
const FAMILY_SIZE: usize = 30;

/// The polarity split, in the order `AGENTS.md` states the rule: negatives outnumber positives.
const NEGATIVE: usize = 18;
const POSITIVE: usize = 12;

/// Every quirk `model/overlays/quirks/lifecycle.toml` declares, in id order.
///
/// Written out rather than parsed out of the overlay on purpose. The overlay is a Protected File:
/// reading it here would let a quirk be deleted and this test would follow it down in the same
/// commit, which is the shape of a check that cannot fail. A quirk removed from the overlay has
/// to break this list, and breaking it is what forces the removal to be argued rather than
/// noticed.
const DECLARED_QUIRKS: &[&str] = &[
    "q-lc-0001",
    "q-lc-0002",
    "q-lc-0003",
    "q-lc-0004",
    "q-lc-0005",
    "q-lc-0006",
    "q-lc-0007",
    "q-lc-0008",
    "q-lc-0009",
    "q-lc-0010",
    "q-lc-0011",
    "q-lc-0012",
    "q-lc-0013",
    "q-lc-0014",
];

/// The three operations of the family. A family whose cases all exercise one operation is a
/// family with two untested operations and a green summary line.
const OPERATIONS: &[&str] = &[
    "DeleteBucketLifecycle",
    "GetBucketLifecycleConfiguration",
    "PutBucketLifecycleConfiguration",
];

fn corpus() -> Corpus {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    runner::prepare_corpus(&root).expect("the corpus loads")
}

fn family(corpus: &Corpus) -> Vec<&Case> {
    corpus
        .cases()
        .iter()
        .filter(|case| case.relative.starts_with("cases/lifecycle/"))
        .collect()
}

fn run_lifecycle_domain() -> Report {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = InProcess::new(root);
    let options = RunOptions {
        filter: Some("lifecycle/".to_owned()),
        ..RunOptions::default()
    };
    runner::run(&corpus, &mut sut, &options)
}

/// Negative — the lifecycle family is a closed ledger: thirty identifiers, contiguous, one file
/// each.
///
/// A gap means a case was deleted, which `AGENTS.md` lists as a silently dropped guarantee; a
/// duplicate means two files claim one identifier, after which only one of them is ever reported.
#[test]
fn the_lifecycle_family_is_a_closed_ledger_of_thirty_identifiers() {
    let corpus = corpus();
    let cases = family(&corpus);

    let mut ids: Vec<&str> = cases.iter().map(|case| case.id.as_str()).collect();
    ids.sort_unstable();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "two lifecycle cases share an identifier: {ids:?}");
    assert_eq!(
        ids.len(),
        FAMILY_SIZE,
        "the lifecycle family holds {} cases, not {FAMILY_SIZE}",
        ids.len()
    );

    let expected: Vec<String> = (1..=FAMILY_SIZE).map(|n| format!("c-lifecycle-{n:04}")).collect();
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    assert_eq!(ids, expected, "the lifecycle identifiers are not contiguous from 0001");
}

/// Negative — the family keeps negatives in the majority, which is the corpus rule applied to one
/// family rather than to the whole corpus, where a large well-balanced neighbour can pay for it.
#[test]
fn the_lifecycle_family_keeps_eighteen_negative_against_twelve_positive() {
    let corpus = corpus();
    let cases = family(&corpus);

    let negative = cases.iter().filter(|case| case.polarity() == Some("negative")).count();
    let positive = cases.iter().filter(|case| case.polarity() == Some("positive")).count();

    assert_eq!(negative + positive, FAMILY_SIZE, "a lifecycle case declares no polarity");
    assert_eq!(negative, NEGATIVE, "{negative} negative lifecycle cases, not {NEGATIVE}");
    assert_eq!(positive, POSITIVE, "{positive} positive lifecycle cases, not {POSITIVE}");
    assert!(negative > positive, "the lifecycle family stopped leading with its refusals");
}

/// Negative — all three operations of the family are exercised.
///
/// The read and the delete are one case each away from being untested: most of the family writes
/// documents, and a suite that only writes would stay green through a read that answered the
/// wrong root or a delete that answered 200.
#[test]
fn every_operation_of_the_lifecycle_family_is_exercised() {
    let corpus = corpus();
    let cases = family(&corpus);

    for operation in OPERATIONS {
        let count = cases
            .iter()
            .filter(|case| case.meta().and_then(|meta| meta.read("caseMeta.operation")?.as_str()) == Some(operation))
            .count();
        assert!(count > 0, "no lifecycle case names {operation} as its operation under test");
    }
}

/// Positive — the family executes against the assembled service, all thirty green, none skipped.
///
/// Three separate things are asserted, because each is satisfiable without the others and the
/// combination is what "the family passes" is usually taken to mean:
///
/// * the filter selects the whole family — otherwise a narrowed filter proves whatever is left;
/// * no case is *skipped* — an unwired registry answers every case with a skip, and a summary
///   line renders that identically to a family with nothing wrong with it;
/// * every case passed, named individually on failure so the report says which and why.
#[test]
fn the_lifecycle_family_runs_wholly_green_and_nothing_is_skipped() {
    let report = run_lifecycle_domain();

    assert_eq!(report.outcomes.len(), FAMILY_SIZE, "the filter did not select the whole family");

    let skipped: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Skipped)
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(
        skipped.is_empty(),
        "lifecycle cases skipped rather than run — is the family wired into the in-process registry? {skipped:?}"
    );

    let failed: Vec<String> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Failed)
        .map(|outcome| {
            let why: Vec<String> = outcome.failures().iter().map(ToString::to_string).collect();
            format!("{}: {}", outcome.id, why.join(" | "))
        })
        .collect();
    assert!(failed.is_empty(), "red lifecycle cases:\n{}", failed.join("\n"));
}

/// Negative — the family does not regress against the checked-in ratchet.
///
/// Distinct from the count above: the count says how many are green, this says *which*, against
/// the verdicts the repository has already agreed to. A family could hold its totals while
/// swapping a green case for a red one.
///
/// Only the regression direction is asserted. The reverse — every case appearing in the baseline
/// — is deliberately not, because `conformance/baseline.json` is regenerated by the release
/// ratchet rather than by the branch that adds a case, so a case is legitimately absent from it
/// for as long as it takes that regeneration to run.
#[test]
fn the_lifecycle_family_holds_the_verdicts_the_baseline_records() {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let source = std::fs::read_to_string(root.join("baseline.json")).expect("the baseline is checked in");
    let baseline = Baseline::from_json(&source).expect("the baseline parses");

    let report = run_lifecycle_domain();
    let regressions: Vec<&str> = report
        .regressions(Some(&baseline))
        .iter()
        .map(|outcome| outcome.id.as_str())
        .collect();

    assert!(regressions.is_empty(), "lifecycle cases regressed against the baseline: {regressions:?}");
}

/// Negative — every quirk the overlay declares is claimed by at least one case.
///
/// A quirk with no case is a protocol exception the repository has written down and asserts
/// nothing about: the evidence is on file, the divergence is documented, and the behaviour is
/// free to change without a single test going red. That is worse than an undocumented
/// divergence, because it reads as covered.
#[test]
fn every_lifecycle_quirk_is_claimed_by_a_case() {
    let corpus = corpus();
    let claimed: BTreeSet<&str> = family(&corpus).iter().flat_map(|case| case.quirks()).collect();

    let unclaimed: Vec<&str> = DECLARED_QUIRKS
        .iter()
        .copied()
        .filter(|quirk| !claimed.contains(quirk))
        .collect();
    assert!(
        unclaimed.is_empty(),
        "lifecycle quirks no case claims, so nothing in this suite would go red if they stopped \
         being true: {unclaimed:?}"
    );
}

/// Negative — the other direction: no case cites a quirk the overlay does not declare.
///
/// The pair is written as two tests rather than one because they fail for opposite reasons and a
/// combined message would send the reader to the wrong file. This half catches a citation to
/// nothing: a typo in a quirk id reads exactly like a real reference, and `cargo xtask why` would
/// answer with silence rather than an error.
#[test]
fn n_no_lifecycle_case_cites_a_quirk_the_overlay_does_not_declare() {
    let corpus = corpus();
    let declared: BTreeSet<&str> = DECLARED_QUIRKS.iter().copied().collect();

    let dangling: Vec<String> = family(&corpus)
        .iter()
        .flat_map(|case| {
            case.quirks()
                .into_iter()
                .filter(|quirk| !declared.contains(quirk))
                .map(|quirk| format!("{}: {quirk}", case.id))
                .collect::<Vec<String>>()
        })
        .collect();

    assert!(
        dangling.is_empty(),
        "lifecycle cases citing quirk ids the overlay does not declare:\n{}",
        dangling.join("\n")
    );
}
