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

//! The ledger of the multipart family, and the three entity-tag cases it was blocked on.
//!
//! Responsible for: pinning the multipart family as a *closed* set — forty-eight identifiers with
//! no gap and no duplicate, thirty-one negative against seventeen positive, every one of them
//! carrying a verdict in the checked-in baseline — and for proving the family executes against the
//! in-process target with no regression, with `c-mpu-0002`, `c-mpu-0003` and `c-mpu-0018` green,
//! and with no case skipping that was not already skipping. A family whose size, polarity and
//! baseline membership are only ever counted by a human is a family that silently loses a case,
//! and a case that quietly turns into a skip reads exactly like one that passed.
//! NOT responsible for: what any individual multipart case asserts — that lives in the case file —
//! or for the corpus-wide invariants, which `tests/corpus.rs` already owns.
//! Upstream: the published API of `rustfs_gateway_conformance`, and `conformance/baseline.json`.
//! Downstream: nothing.

use rustfs_gateway_conformance::corpus::{Case, Corpus};
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::{Baseline, Verdict};
use rustfs_gateway_conformance::runner::{self, RunOptions};

/// The size of the family. A number, not a range: the point of the guard is that growing or
/// shrinking the family is a decision somebody writes down, and this is where they write it.
const FAMILY_SIZE: usize = 48;

/// The polarity split, in the order `AGENTS.md` states the rule: negatives must outnumber
/// positives, and here they do by fourteen.
const NEGATIVE: usize = 31;
const POSITIVE: usize = 17;

/// The three cases this family was blocked on, all three of them about the entity tag a multipart
/// upload publishes. The baseline still records them as failing, so their verdicts are checked
/// directly rather than through the ratchet, which tolerates a recorded failure.
const RECOVERED: [&str; 3] = ["c-mpu-0002", "c-mpu-0003", "c-mpu-0018"];

/// The cases the in-process target cannot execute, each for a reason the runner prints with the
/// skip. Two ask for a fresh connection per exchange, one for a malformed request head that only a
/// socket can write, and one for a request the in-process target has no way to shape.
///
/// The set is an upper bound rather than an equality: a case recovered by a transport that grows a
/// capability must not fail this guard, while a case that quietly *starts* skipping must. Skips may
/// only go down.
const KNOWN_SKIPS: [&str; 4] = ["c-mpu-0027", "c-mpu-0039", "c-mpu-0043", "c-mpu-0045"];

fn corpus() -> Corpus {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    runner::prepare_corpus(&root).expect("the corpus loads")
}

fn family(corpus: &Corpus) -> Vec<&Case> {
    corpus
        .cases()
        .iter()
        .filter(|case| case.relative.starts_with("cases/mpu/"))
        .collect()
}

fn baseline() -> Baseline {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let source = std::fs::read_to_string(root.join("baseline.json")).expect("the baseline is checked in");
    Baseline::from_json(&source).expect("the baseline parses")
}

/// The multipart family is a closed ledger: forty-eight identifiers, contiguous, each in its own
/// file.
///
/// A gap means a case was deleted — which `AGENTS.md` lists as a silently dropped guarantee — and a
/// duplicate means two files claim one identifier, after which only one of them is ever reported.
#[test]
fn the_multipart_family_is_a_closed_ledger_of_forty_eight_identifiers() {
    let corpus = corpus();
    let cases = family(&corpus);

    let mut ids: Vec<&str> = cases.iter().map(|case| case.id.as_str()).collect();
    ids.sort_unstable();
    let unique: std::collections::BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "two multipart cases share an identifier: {ids:?}");
    assert_eq!(
        ids.len(),
        FAMILY_SIZE,
        "the multipart family holds {} cases, not {FAMILY_SIZE}",
        ids.len()
    );

    let expected: Vec<String> = (1..=FAMILY_SIZE).map(|n| format!("c-mpu-{n:04}")).collect();
    let observed: Vec<&str> = ids;
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    assert_eq!(
        observed, expected,
        "the multipart identifiers are not the contiguous run 0001..{FAMILY_SIZE:04}"
    );
}

/// The family keeps negatives in the majority, and it does so by a number rather than by a
/// direction.
///
/// The corpus-wide check in `tests/corpus.rs` compares two totals over six hundred cases, so a
/// family that flipped every one of its own cases to positive would still leave it green.
#[test]
fn the_multipart_family_keeps_thirty_one_negative_against_seventeen_positive() {
    let corpus = corpus();
    let cases = family(&corpus);

    let negative = cases.iter().filter(|case| case.polarity() == Some("negative")).count();
    let positive = cases.iter().filter(|case| case.polarity() == Some("positive")).count();
    assert_eq!(negative + positive, FAMILY_SIZE, "a multipart case declares no polarity at all");
    assert_eq!(negative, NEGATIVE, "the multipart family has {negative} negative cases, not {NEGATIVE}");
    assert_eq!(positive, POSITIVE, "the multipart family has {positive} positive cases, not {POSITIVE}");
    assert!(negative > positive, "negatives no longer outnumber positives in the multipart family");
}

/// Every multipart case reaches the ratchet.
///
/// A case the baseline does not name is a case whose failure would be a *new* failure the first
/// time anybody looked, and the ratchet only tightens over ids it already knows about.
#[test]
fn every_multipart_case_carries_a_verdict_in_the_baseline() {
    let corpus = corpus();
    let baseline = baseline();
    let unrecorded: Vec<&str> = family(&corpus)
        .iter()
        .filter(|case| baseline.expected(&case.id).is_none())
        .map(|case| case.id.as_str())
        .collect();
    assert!(unrecorded.is_empty(), "multipart cases absent from the baseline: {unrecorded:?}");
}

/// The family executes, and the three entity-tag cases it was blocked on are green.
///
/// Each half is asserted because none of them alone is worth anything: a run in which every
/// multipart case was skipped has no regressions, a run with no regressions says nothing about a
/// case the baseline records as failing, and a green verdict on a case that never ran is the shape
/// this repository keeps regrowing. The baseline still records all three of `RECOVERED` as failed,
/// so their verdicts are read directly.
#[test]
fn the_multipart_family_runs_green_with_the_entity_tag_cases_recovered() {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = InProcess::new(root);
    let options = RunOptions {
        filter: Some("mpu/".to_owned()),
        ..RunOptions::default()
    };
    let report = runner::run(&corpus, &mut sut, &options);
    let baseline = baseline();

    assert_eq!(report.outcomes.len(), FAMILY_SIZE, "the filter did not select the whole family");

    let skipped: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Skipped)
        .map(|outcome| outcome.id.as_str())
        .collect();
    let unexpected: Vec<&&str> = skipped.iter().filter(|id| !KNOWN_SKIPS.contains(id)).collect();
    assert!(
        unexpected.is_empty(),
        "multipart case(s) newly skipping rather than running: {unexpected:?}"
    );

    let regressions: Vec<&str> = report
        .regressions(Some(&baseline))
        .iter()
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(regressions.is_empty(), "multipart regressions against the baseline: {regressions:?}");

    for id in RECOVERED {
        let recovered = report
            .outcomes
            .iter()
            .find(|outcome| outcome.id == id)
            .unwrap_or_else(|| panic!("{id} is selected by the multipart filter"));
        assert_eq!(
            recovered.verdict,
            Verdict::Passed,
            "{id}: {:?}",
            recovered.failures().iter().map(ToString::to_string).collect::<Vec<_>>()
        );
    }
}
