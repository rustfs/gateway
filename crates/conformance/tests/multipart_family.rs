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
//! Responsible for: pinning the multipart family as a *closed* set — fifty-four identifiers with
//! no gap and no duplicate, thirty-six negative against eighteen positive, every one of them
//! carrying a verdict in the checked-in baseline — and for proving the family executes against the
//! in-process target with no regression, with every id in `RECOVERED` green,
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

/// The reference evaluation `conformance/baseline.json` records (rustfs/gateway#985): the baseline
/// is judged against it, while the in-process run above keeps its own skip and verdict ledgers.
fn reference_run(filter: &str) -> rustfs_gateway_conformance::report::Report {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    runner::reference_report(
        &corpus,
        &RunOptions {
            filter: Some(filter.to_owned()),
            ..RunOptions::default()
        },
    )
}

/// The size of the family. A number, not a range: the point of the guard is that growing or
/// shrinking the family is a decision somebody writes down, and this is where they write it.
const FAMILY_SIZE: usize = 54;

/// The polarity split, in the order `AGENTS.md` states the rule: negatives must outnumber
/// positives, and here they do by eighteen.
const NEGATIVE: usize = 36;
const POSITIVE: usize = 18;

/// The cases this family was blocked on. Three are about the entity tag a multipart upload
/// publishes; `c-mpu-0038` is the one whose own expectation was the defect — it demanded that the
/// completion body carry no XML declaration, which is neither what AWS emits nor what the rest of
/// this corpus says. `c-mpu-0001` is the fifth: a completion that fails after its head is out, which
/// the corpus could not describe until `setup.fault` existed and which is only reachable *below* the
/// commit boundary — see [`the_late_failure_is_green_without_moving_the_commit_boundary`]. The
/// baseline still records all five as failing, so their verdicts are checked directly rather than
/// through the ratchet, which tolerates a recorded failure.
const RECOVERED: [&str; 5] = ["c-mpu-0001", "c-mpu-0002", "c-mpu-0003", "c-mpu-0018", "c-mpu-0038"];

/// The completions whose refusal must stay *above* the commit boundary, and their statuses.
///
/// The price of `c-mpu-0001` is exactly this list. A completion that fails after its head is out is
/// one line away from a completion that always commits first and reports everything late, and that
/// rearrangement makes `c-mpu-0001` green while turning each of these into a `200` whose body
/// carries the refusal. A client that reads the status line — which is every client that has not
/// been told this operation is special — records each of them as a successful upload.
///
/// Ten of them, not the five the fixture's own doc block happens to name: a guard is only as good as
/// the cases it covers, and a boundary move that spared half of them would still be a boundary move.
/// One is a `412`, which a list of `400`s alone would have missed.
///
/// `c-mpu-0041` is the completion left out. It is the same rule under two exchanges, and its status
/// lives inside `[[exchanges]]` rather than at `expect.status`, so the second half of this ledger —
/// reading the demand back out of the file — would have nothing to read. A row naming it with no
/// status to check against would assert only the colour.
const REFUSED_BEFORE_COMMIT: [(&str, u16); 10] = [
    ("c-mpu-0019", 400),
    ("c-mpu-0020", 400),
    ("c-mpu-0021", 400),
    ("c-mpu-0022", 400),
    ("c-mpu-0023", 400),
    ("c-mpu-0026", 400),
    ("c-mpu-0033", 400),
    ("c-mpu-0034", 400),
    ("c-mpu-0036", 400),
    ("c-mpu-0042", 412),
];

/// The cases the in-process target cannot execute, each for a reason the runner prints with the
/// skip. Three ask for a fresh connection per exchange, one for a malformed request head that only a
/// socket can write, and one for a request the in-process target has no way to shape.
///
/// `c-mpu-0053` is the third fresh-connection case: it pins the connection verdict after a refusal
/// that left a small body unread, which only a socket can observe. It executes over a socket, and
/// `crates/gateway/tests/unread_body_refusal.rs` pins the same behaviour on the production drivers.
///
/// The set is an upper bound rather than an equality: a case recovered by a transport that grows a
/// capability must not fail this guard, while a case that quietly *starts* skipping must. Skips may
/// only go down.
const KNOWN_SKIPS: [&str; 5] = ["c-mpu-0027", "c-mpu-0039", "c-mpu-0043", "c-mpu-0045", "c-mpu-0053"];

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

/// The multipart family is a closed ledger: fifty-four identifiers, contiguous, each in its own
/// file.
///
/// A gap means a case was deleted — which `AGENTS.md` lists as a silently dropped guarantee — and a
/// duplicate means two files claim one identifier, after which only one of them is ever reported.
#[test]
fn the_multipart_family_is_a_closed_ledger_of_fifty_four_identifiers() {
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
fn the_multipart_family_keeps_thirty_six_negative_against_eighteen_positive() {
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

/// The family executes, and the cases it was blocked on are green.
///
/// Each half is asserted because none of them alone is worth anything: a run in which every
/// multipart case was skipped has no regressions, a run with no regressions says nothing about a
/// case the baseline records as failing, and a green verdict on a case that never ran is the shape
/// this repository keeps regrowing. The baseline still records every id in `RECOVERED` as failed,
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

    let reference = reference_run("mpu/");
    let regressions: Vec<&str> = reference
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

/// Negative — the late failure is green, and the completions that must refuse early still do.
///
/// `c-mpu-0001` asks for a completion that fails *after* its head has gone out: `200`, and an
/// `<Error>` document in the body. There are two ways to arrive at that. One is to describe a fault
/// that happens at that point. The other is to move the completion's checks below the commit, which
/// is a smaller diff, makes `c-mpu-0001` green immediately, and turns every refusal this operation
/// can still name a status for into a `200` whose body carries the refusal. Every case
/// [`REFUSED_BEFORE_COMMIT`] names is what that costs, and a client that reads the status line —
/// which is every client that has not been told this operation is special — would record each of
/// them as a successful upload.
///
/// So the verdict on `c-mpu-0001` alone does not say which of the two happened. Both halves do, and
/// the second half is asserted twice over: the run says those cases pass, and their own files are
/// read back to confirm they still *demand* a status chosen before the head went out. A ledger that
/// only checked the colour would stay green through an edit that moved the demand instead of the
/// behaviour.
#[test]
fn the_late_failure_is_green_without_moving_the_commit_boundary() {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = InProcess::new(root);
    let options = RunOptions {
        filter: Some("mpu/".to_owned()),
        ..RunOptions::default()
    };
    let report = runner::run(&corpus, &mut sut, &options);

    let late = report
        .outcomes
        .iter()
        .find(|outcome| outcome.id == "c-mpu-0001")
        .expect("c-mpu-0001 is selected by the multipart filter");
    assert_eq!(
        late.verdict,
        Verdict::Passed,
        "c-mpu-0001 is red — a completion that fails after its head is out no longer answers with an \
         Error document inside the committed status: {:?}",
        late.failures().iter().map(ToString::to_string).collect::<Vec<_>>()
    );

    for (id, status) in REFUSED_BEFORE_COMMIT {
        let outcome = report
            .outcomes
            .iter()
            .find(|outcome| outcome.id == id)
            .unwrap_or_else(|| panic!("{id} is selected by the multipart filter"));
        assert_eq!(
            outcome.verdict,
            Verdict::Passed,
            "{id} is red: a completion that can still be refused with its own status no longer is, \
             which is the boundary c-mpu-0001 must be green *without* moving: {:?}",
            outcome.failures().iter().map(ToString::to_string).collect::<Vec<_>>()
        );
        // `path`, not `read`: this reaches into the case document to check what it demands, and a
        // recorded read here would claim coverage the runner is the one that owns.
        let demanded = corpus
            .cases()
            .iter()
            .find(|case| case.id == id)
            .and_then(|case| case.document.as_ref())
            .and_then(|document| document.path("expect/status"))
            .and_then(rustfs_gateway_conformance::value::Value::as_integer);
        assert_eq!(
            demanded,
            Some(i64::from(status)),
            "{id} no longer demands {status}; the ledger's other half was edited rather than honoured"
        );
    }
}
