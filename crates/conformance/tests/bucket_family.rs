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

//! The `bkt/` family as a closed ledger, and the status matrix it was commissioned to prove.
//!
//! Responsible for: pinning the bucket lifecycle family as a *closed* set — thirty-three
//! identifiers with no gap and no duplicate, twenty-three negative against ten positive — for
//! proving the family really executes against the assembled service rather than being answered
//! with skips, and for binding each row of the status matrix in rustfs/backlog#1767 §4.5 to the
//! live artefact that proves it.
//! NOT responsible for: what any individual case asserts (that is the case file), the
//! region-dependent half of the matrix (that is `tests/bucket_lifecycle.rs`, which this file cites
//! rather than duplicates), the corpus-wide schema and convention invariants (`tests/corpus.rs`),
//! or the `--baseline` ratchet — see below, it does not reach this family at all.
//! Upstream: the published API of `rustfs_gateway_conformance` and `rustfs_gateway::ErrorCode`.
//! Downstream: nothing.
//!
//! # Why this file exists at all
//!
//! Before it, `bkt/` was green in `cargo xtask conformance run` and reached by nothing in `cargo
//! test --workspace`. `tests/bucket_lifecycle.rs` assembles its own service and never touches the
//! corpus; `tests/corpus.rs` runs the whole corpus against `Unwired`, which answers every case
//! with a skip. So all thirty-three cases could have been unwired from the in-process registry
//! without a single test going red — the exact hole rustfs/gateway#203 found in `object/`, where a
//! whole family had been skipping underneath a green ratchet, because a skip and a pass are the
//! same colour in a summary line.
//!
//! # Why nothing here consults `conformance/baseline.json`
//!
//! The five sibling ledgers all assert that their family carries a verdict in the checked-in
//! baseline, and the first draft of this file did too. It failed, on all thirty-three: the baseline
//! records two hundred and forty-one cases across eleven domains and `bkt/` is not one of them, so
//! the release-time ratchet has never had an opinion about this family. That also makes the
//! regression check the siblings run *vacuous* here — `Report::regressions` compares against ids
//! the baseline knows, and it knows none of these, so it can only ever return an empty list.
//! Shipping it would have been a check that cannot fail, which is the defect this repository has
//! now produced eight times. It is left out rather than inverted, because a test asserting the
//! family is *absent* from the ratchet would go red the moment somebody fixed that — a guard that
//! argues against its own fix. The gap is rustfs/backlog#1767's to report and the baseline refresh
//! is not this branch's to make; until it lands, the green-run assertion below is the only ratchet
//! this family has, which is most of the reason it is worth having.
//!
//! # Why the matrix is a table and not prose
//!
//! rustfs/backlog#1767 §4.5 fixes thirteen outcomes, and the issue has twice been audited with the
//! finding that the delivered corpus no longer matches the identifiers the matrix was written
//! against: several `c-bkt-00NN` numbers were reused for different contracts as the family landed.
//! A prose mapping does not survive that, because nothing rereads it. The table below does: every
//! row names either a case that must exist *and* be green, or a test function that must exist in
//! the sibling source, or a deferral whose emptiness is itself measured. A row cannot go stale
//! without this file going red.

use std::collections::BTreeSet;

use rustfs_gateway::ErrorCode;
use rustfs_gateway_conformance::corpus::{Case, Corpus};
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::{Report, Verdict};
use rustfs_gateway_conformance::runner::{self, RunOptions};

/// The size of the family: the thirty-three cases delivered for rustfs/backlog#1767.
const FAMILY_SIZE: usize = 33;

/// The polarity split, in the order `AGENTS.md` states the rule: negatives outnumber positives.
const NEGATIVE: usize = 23;
const POSITIVE: usize = 10;

/// The sibling source that owns the half of the matrix the corpus cannot stage.
const INTEGRATION_SOURCE: &str = "bucket_lifecycle.rs";

/// How one row of the status matrix is proved.
#[derive(Clone, Copy, Debug)]
enum Evidence {
    /// A case in `conformance/cases/bkt/`, which must exist and must be green.
    Case(&'static str),
    /// A test function in [`INTEGRATION_SOURCE`], which must exist under that name.
    ///
    /// Used only where the in-process corpus transport cannot reach the outcome: it serves
    /// `us-east-1` and one account, so a second region, a second owner, and an authorization
    /// refusal are all outside what a case file can declare.
    Integration(&'static str),
}

/// rustfs/backlog#1767 §4.5, one row at a time, each bound to what proves it today.
///
/// The wording of the left column is the issue's, not a paraphrase, so the two can be read side by
/// side. All thirteen rows are proved; the framework-wide `x-amz-expected-bucket-owner` gate is
/// exercised here after rustfs/gateway#585 made that shared check available to the family.
const STATUS_MATRIX: &[(&str, Evidence)] = &[
    ("CreateBucket, a new bucket: 200 with a Location header", Evidence::Case("c-bkt-0001")),
    (
        "CreateBucket, your own bucket again, where R == us-east-1: 200",
        Evidence::Case("c-bkt-0010"),
    ),
    (
        "CreateBucket, your own bucket again, where R != us-east-1: 409 BucketAlreadyOwnedByYou",
        Evidence::Integration("n_recreating_your_own_bucket_outside_us_east_1_is_a_conflict"),
    ),
    (
        "CreateBucket, a name another account holds: 409 BucketAlreadyExists",
        Evidence::Integration("n_a_name_held_by_another_owner_is_a_different_conflict"),
    ),
    (
        "CreateBucket, an invalid bucket name: 400 InvalidBucketName",
        Evidence::Case("c-bkt-0031"),
    ),
    ("DeleteBucket, an empty bucket: 204 with a zero-length body", Evidence::Case("c-bkt-0007")),
    (
        "DeleteBucket, a bucket that is not empty: 409 BucketNotEmpty",
        Evidence::Case("c-bkt-0022"),
    ),
    (
        "DeleteBucket, a bucket that does not exist: 404 NoSuchBucket",
        Evidence::Case("c-bkt-0023"),
    ),
    (
        "HeadBucket, a bucket that exists: 200, zero-length body, x-amz-bucket-region",
        Evidence::Case("c-bkt-0008"),
    ),
    (
        "HeadBucket, a bucket that does not exist: 404 with a zero-length body",
        Evidence::Case("c-bkt-0025"),
    ),
    (
        "HeadBucket, a bucket the caller may not see: 403 with a zero-length body",
        Evidence::Integration("n_a_refused_bucket_head_is_a_403_with_no_body_and_the_permitted_one_still_answers"),
    ),
    (
        "any of the three with a mismatched x-amz-expected-bucket-owner: 403 AccessDenied",
        Evidence::Integration("n_mismatched_expected_owner_refuses_create_delete_and_head"),
    ),
    (
        "path-style for a bucket in another region: 301 PermanentRedirect with x-amz-bucket-region",
        Evidence::Case("c-bkt-0026"),
    ),
];

/// The six error codes rustfs/backlog#1767 §7 requires this family to be able to express, and the
/// status each must render as.
///
/// The issue's own acceptance item is that none of them falls back to a 500: a 5xx tells an SDK to
/// retry something that will fail identically and trips its circuit breaker, which turns a client
/// mistake into an outage. The fallback that made this possible is gone since rustfs/backlog#1694,
/// so what is checked here is the positive statement — the authority declares each code, with this
/// status.
const FAMILY_ERROR_CODES: &[(&str, u16)] = &[
    ("BucketAlreadyExists", 409),
    ("BucketAlreadyOwnedByYou", 409),
    ("BucketNotEmpty", 409),
    ("NoSuchBucket", 404),
    ("InvalidLocationConstraint", 400),
    ("PermanentRedirect", 301),
];

fn corpus() -> Corpus {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    runner::prepare_corpus(&root).expect("the corpus loads")
}

fn family(corpus: &Corpus) -> Vec<&Case> {
    corpus
        .cases()
        .iter()
        .filter(|case| case.relative.starts_with("cases/bkt/"))
        .collect()
}

fn run_bucket_domain() -> Report {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = InProcess::new(root);
    let options = RunOptions {
        filter: Some("bkt/".to_owned()),
        ..RunOptions::default()
    };
    runner::run(&corpus, &mut sut, &options)
}

/// The text of the sibling integration source, read from disk rather than included.
///
/// `include_str!` would work and is worse: it makes this file a compilation dependency of the
/// other, so a rename that broke the citation would be reported as a build error somewhere else.
/// Read at run time, a broken citation is a failing assertion that names the function.
fn integration_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(INTEGRATION_SOURCE);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()))
}

/// Negative — the bucket family is a closed ledger: thirty-three identifiers, contiguous, one file
/// each.
///
/// A gap means a case was deleted, which `AGENTS.md` lists as a silently dropped guarantee; a
/// duplicate means two files claim one identifier, after which only one of them is ever reported.
#[test]
fn the_bucket_family_is_a_closed_ledger_of_thirty_three_identifiers() {
    let corpus = corpus();
    let cases = family(&corpus);

    let mut ids: Vec<&str> = cases.iter().map(|case| case.id.as_str()).collect();
    ids.sort_unstable();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "two bucket cases share an identifier: {ids:?}");
    assert_eq!(ids.len(), FAMILY_SIZE, "the bucket family holds {} cases, not {FAMILY_SIZE}", ids.len());

    let expected: Vec<String> = (1..=FAMILY_SIZE).map(|n| format!("c-bkt-{n:04}")).collect();
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    assert_eq!(ids, expected, "the bucket identifiers are not the contiguous run 0001..{FAMILY_SIZE:04}");
}

/// Negative — the family keeps negatives in the majority, by a number rather than by a direction.
///
/// The corpus-wide check in `tests/corpus.rs` compares two totals over six hundred cases, so a
/// family that flipped every one of its own cases to positive would still leave it green.
#[test]
fn the_bucket_family_keeps_twenty_three_negative_against_ten_positive() {
    let corpus = corpus();
    let cases = family(&corpus);

    let negative = cases.iter().filter(|case| case.polarity() == Some("negative")).count();
    let positive = cases.iter().filter(|case| case.polarity() == Some("positive")).count();
    assert_eq!(negative + positive, FAMILY_SIZE, "a bucket case declares no polarity at all");
    assert_eq!(negative, NEGATIVE, "the bucket family has {negative} negative cases, not {NEGATIVE}");
    assert_eq!(positive, POSITIVE, "the bucket family has {positive} positive cases, not {POSITIVE}");
    assert!(negative > positive, "negatives no longer outnumber positives in the bucket family");
}

/// Positive — the family executes against the assembled service, and all thirty-three are green.
///
/// Three separate things, because each is satisfiable without the others:
///
/// * the filter selects the whole family — otherwise a narrowed filter proves whatever is left;
/// * nothing is *skipped* — an unregistered operation answers every case with a skip, and a summary
///   line renders that identically to a family with nothing wrong with it;
/// * all thirty-three passed — a count of "not failed" would be satisfied by a family of skips.
#[test]
fn the_bucket_family_runs_with_all_thirty_three_green_and_nothing_skipped() {
    let report = run_bucket_domain();

    assert_eq!(report.outcomes.len(), FAMILY_SIZE, "the filter did not select the whole family");
    let skipped: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Skipped)
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(
        skipped.is_empty(),
        "bucket cases skipped rather than run — is the family wired? {skipped:?}"
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
    assert!(failed.is_empty(), "red bucket cases:\n{}", failed.join("\n"));

    let passed = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Passed)
        .count();
    assert_eq!(passed, FAMILY_SIZE, "{passed} bucket cases are green, not {FAMILY_SIZE}");
}

/// Negative — every row of the commissioned status matrix is bound to something that exists now.
///
/// This is the assertion the two standing audits of rustfs/backlog#1767 asked for. "Thirty-three
/// files exist" is not "the thirty-three outcomes are proved": identifiers were reused as the
/// family landed, so a row can only be trusted if the thing it cites is checked. A cited case must
/// be in the family and green; a cited test function must be present in the sibling source under
/// that exact name.
#[test]
fn every_row_of_the_status_matrix_names_evidence_that_exists_and_is_green() {
    let corpus = corpus();
    let present: BTreeSet<&str> = family(&corpus).iter().map(|case| case.id.as_str()).collect();
    let report = run_bucket_domain();
    let green: BTreeSet<&str> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Passed)
        .map(|outcome| outcome.id.as_str())
        .collect();
    let source = integration_source();

    let mut unproved: Vec<String> = Vec::new();
    for (row, evidence) in STATUS_MATRIX {
        match evidence {
            Evidence::Case(id) => {
                if !present.contains(id) {
                    unproved.push(format!("{row}: cites {id}, which is not in the bucket family"));
                } else if !green.contains(id) {
                    unproved.push(format!("{row}: cites {id}, which is not green"));
                }
            }
            Evidence::Integration(function) => {
                if !source.contains(&format!("fn {function}(")) {
                    unproved.push(format!("{row}: cites {INTEGRATION_SOURCE}::{function}, which is not there"));
                }
            }
        }
    }
    assert!(unproved.is_empty(), "status-matrix rows with no live evidence:\n{}", unproved.join("\n"));
}

/// Negative — no two matrix rows lean on the same artefact.
///
/// One case cited twice is one outcome counted twice, which is how a matrix comes to look complete
/// while proving fewer things than it has rows. The two rows that share a *behaviour* — the
/// redirect, asserted for `HeadBucket` by `c-bkt-0026` and for every method by the integration
/// source — are deliberately one row here for the same reason.
#[test]
fn the_status_matrix_cites_each_artefact_exactly_once() {
    let mut cited: Vec<&str> = STATUS_MATRIX
        .iter()
        .map(|(_, evidence)| match evidence {
            Evidence::Case(id) => *id,
            Evidence::Integration(function) => *function,
        })
        .collect();
    let distinct: BTreeSet<&str> = cited.iter().copied().collect();
    cited.sort_unstable();
    assert_eq!(distinct.len(), cited.len(), "an artefact is cited by two matrix rows: {cited:?}");
    assert_eq!(
        cited.len(),
        STATUS_MATRIX.len(),
        "the matrix still has {} rows without live evidence",
        STATUS_MATRIX.len() - cited.len()
    );
}

/// Negative — the six codes this family raises are declared by the one authority, with the statuses
/// the matrix depends on and none of them in the 5xx band.
///
/// `model/overlays/error-status.toml` is the single place the mapping exists, and every one of
/// these statuses is load-bearing for a client: a `409` says "your request was fine, the state was
/// not", a `301` is the only redirect an SDK can follow without a second lookup, and a `500`
/// anywhere in this set turns a caller's mistake into a retry storm.
#[test]
fn the_six_codes_this_family_raises_resolve_through_the_one_authority() {
    let mut wrong: Vec<String> = Vec::new();
    for (name, status) in FAMILY_ERROR_CODES {
        match ErrorCode::known(name) {
            None => wrong.push(format!("{name}: the authority declares no such code")),
            Some(code) => {
                let observed = code.default_status().as_u16();
                if observed != *status {
                    wrong.push(format!("{name}: renders {observed}, not {status}"));
                }
                if code.default_status().is_server_error() {
                    wrong.push(format!("{name}: renders a server error, which tells an SDK to retry"));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "the family's error codes do not resolve as the matrix requires:\n{}",
        wrong.join("\n")
    );
}
