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

//! The `tagging/` family as a closed ledger of semantic claims, executed rather than merely loaded.
//!
//! Responsible for: pinning the tagging family as a *closed* set — twenty-nine identifiers with no
//! gap and no duplicate, twenty negative against nine positive, every operation of the family
//! reached — for proving the family really runs against the in-process target with every case
//! green and none skipped, for the quirk binding in both directions, and for the ledger
//! rustfs/backlog#1717 asks for: one row per semantic claim the issue makes, each naming the
//! artefact that proves it, with no row proved by nothing and no artefact cited twice.
//! NOT responsible for: what any individual case asserts — that lives in the case file — nor for
//! the corpus-wide invariants (`tests/corpus.rs`), the per-domain wiring gate
//! (`tests/domain_wiring.rs`), the finer-grained fixture-state inspection (`tests/tagging.rs`), or
//! the codec-level round-trip identity, which `crates/core/tests/tagging_roundtrip.rs` owns
//! because it is a property over documents nobody wrote rather than a verdict on documents
//! somebody did. See `crates/conformance/MAP.md`.
//! Upstream: the published API of `rustfs_gateway_conformance`, and
//! `model/overlays/quirks/tagging.toml`. Downstream: nothing.
//!
//! # Why a status matrix and not only three counts
//!
//! rustfs/backlog#1717's closeout audit asked for a deterministic "semantic claim → case +
//! assertion" ledger rather than a case count, and the difference is not bookkeeping. A count says
//! how many guarantees exist; it cannot say *which*, so a family can hold its totals while trading
//! the version-isolation claim for a second duplicate-key claim. Each row here is the issue's own
//! sentence, and the artefact beside it is what would go red if that sentence stopped being true.
//!
//! # What this file does not claim about skips
//!
//! `tests/domain_wiring.rs` gates every domain's skips as an upper bound, so a branch that
//! recovers a skipped case never turns it red. This family allows none at all, and pins that as an
//! equality — the two disagree only in the direction that lets a recovery land without touching
//! the shared table, which is deliberate and is the shape rustfs/gateway#207 asked for.
//!
//! # Why the counts are equalities and not floors
//!
//! The family is complete and wholly green, nothing outside this issue can move these numbers, and
//! anything that does move them is a decision somebody has to write down here.

use std::collections::BTreeSet;

use rustfs_gateway_conformance::corpus::{Case, Corpus};
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::{Baseline, Report, Verdict};
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

/// The size of the family: the twenty landed with the family in rustfs/gateway#22, the five
/// version-resolution cases of rustfs/gateway#197, and the four this closeout adds — the body
/// digest that only became expressible once `verify_body_digest` had a production caller, the two
/// halves of the empty-`<TagSet/>` ruling, and the supplementary-plane length differential.
const FAMILY_SIZE: usize = 29;

/// The polarity split, in the order `AGENTS.md` states the rule: negatives outnumber positives.
const NEGATIVE: usize = 20;
const POSITIVE: usize = 9;

/// Every quirk `model/overlays/quirks/tagging.toml` declares, in id order.
///
/// Written out rather than parsed out of the overlay on purpose. The overlay is a Protected File:
/// reading it here would let a quirk be deleted and this test would follow it down in the same
/// commit, which is the shape of a check that cannot fail.
const DECLARED_QUIRKS: &[&str] = &[
    "q-tag-wrapped-0088",
    "q-tag-bucket-unconfigured-0089",
    "q-tag-object-unconfigured-0090",
    "q-tag-delete-idempotent-0091",
    "q-tag-md5-required-0092",
    "q-tag-header-form-0093",
    "q-tag-limits-0094",
    "q-tag-count-omit-0095",
];

/// The six operations of the family. A family whose cases all exercise one operation is a family
/// with five untested operations and a green summary line.
const OPERATIONS: &[&str] = &[
    "DeleteBucketTagging",
    "DeleteObjectTagging",
    "GetBucketTagging",
    "GetObjectTagging",
    "PutBucketTagging",
    "PutObjectTagging",
];

/// The two operations of *other* families that carry the packed header channel of this one.
///
/// Named separately because they are not this family's operations and must not be counted as
/// coverage of them — but a tagging suite that reached neither would be asserting nothing about
/// `x-amz-tagging`, which is half the surface the shared contract validates.
const HEADER_CHANNEL_OPERATIONS: &[&str] = &["GetObject", "PutObject"];

/// How one row of the status matrix is proved.
#[derive(Clone, Copy, Debug)]
enum Evidence {
    /// A case in `conformance/cases/tagging/`, which must exist and must be green.
    Case(&'static str),
    /// A test function in [`FIXTURE_SOURCE`], which must exist under that name.
    Fixture(&'static str),
    /// A test function in [`CODEC_SOURCE`], which must exist under that name.
    Codec(&'static str),
}

/// The finer-grained harness beside this one, in the same directory.
const FIXTURE_SOURCE: &str = "tagging.rs";

/// The codec-level property, which lives in `crates/core` because that is where the codecs are.
const CODEC_SOURCE: &str = "../../core/tests/tagging_roundtrip.rs";

/// Every semantic claim rustfs/backlog#1717 makes about this family, and what proves it.
///
/// The row text is the claim, not the case title, so the two can be read side by side and a case
/// retitled without weakening does not read as a moved guarantee. A row proved by nothing has no
/// spelling here: this family has no deferrals left, and adding one would mean adding the variant
/// back along with the issue that owns it.
const STATUS_MATRIX: &[(&str, Evidence)] = &[
    // ── the wire form ──
    ("The tag collection is wrapped: <TagSet> encloses <Tag>", Evidence::Case("c-tagging-0001")),
    (
        "A body rooted at TagSet rather than Tagging is MalformedXML",
        Evidence::Case("c-tagging-0018"),
    ),
    (
        "A Tagging document with no TagSet element at all is MalformedXML and nothing is stored",
        Evidence::Case("c-tagging-0027"),
    ),
    (
        "Any tag set written by the read codec is read back by the write codec, on both scopes",
        Evidence::Codec("a_tag_set_survives_encode_then_decode_on_both_scopes"),
    ),
    (
        "A tag whose value is empty survives a read-modify-write rather than being dropped",
        Evidence::Codec("a_tag_with_an_empty_value_survives_a_read_modify_write"),
    ),
    (
        "An invented wrapper around the tags hides them from the decoder rather than being seen through",
        Evidence::Codec("n_a_second_wrapper_around_the_tags_hides_them"),
    ),
    // ── the two unconfigured answers ──
    (
        "GetBucketTagging on a bucket that never had a set is 404 NoSuchTagSet",
        Evidence::Case("c-tagging-0006"),
    ),
    (
        "GetObjectTagging on an object that was never tagged is 200 with an empty TagSet",
        Evidence::Case("c-tagging-0007"),
    ),
    (
        "A tagging read of a key that is not there is NoSuchKey, not an empty tag set",
        Evidence::Fixture("n_a_tagging_read_of_a_missing_key_is_not_an_empty_tag_set"),
    ),
    // ── the empty document ──
    (
        "PutBucketTagging with an empty TagSet clears the set, after which the read is NoSuchTagSet",
        Evidence::Case("c-tagging-0005"),
    ),
    (
        "PutObjectTagging with an empty TagSet clears the tags, after which the read is an empty 200",
        Evidence::Case("c-tagging-0028"),
    ),
    (
        "The empty document the read codec writes is one the write codec accepts",
        Evidence::Codec("an_empty_tag_set_survives_the_round_trip"),
    ),
    // ── the deletes ──
    (
        "DeleteBucketTagging is a bare 204 and the read afterwards is NoSuchTagSet",
        Evidence::Case("c-tagging-0002"),
    ),
    (
        "DeleteBucketTagging on an unconfigured bucket is the same empty 204",
        Evidence::Case("c-tagging-0010"),
    ),
    (
        "The object lifecycle round-trips: write, read, delete, empty read",
        Evidence::Case("c-tagging-0004"),
    ),
    (
        "A tagging delete removes the labels and not the object",
        Evidence::Fixture("n_a_tagging_delete_does_not_delete_the_object"),
    ),
    // ── integrity ──
    (
        "PutBucketTagging without an integrity header is 400 InvalidRequest",
        Evidence::Case("c-tagging-0008"),
    ),
    (
        "PutObjectTagging without an integrity header is 400 InvalidRequest",
        Evidence::Case("c-tagging-0009"),
    ),
    (
        "A Content-MD5 naming bytes other than the ones that arrived is 400 BadDigest and stores nothing",
        Evidence::Case("c-tagging-0026"),
    ),
    // ── the limits, shared by both channels ──
    ("An eleventh object tag is 400 InvalidTag", Evidence::Case("c-tagging-0011")),
    ("A fifty-first bucket tag is 400 InvalidTag", Evidence::Case("c-tagging-0012")),
    (
        "A key past 128 units and a value past 256 units are each 400 InvalidTag",
        Evidence::Case("c-tagging-0013"),
    ),
    (
        "The unit those ceilings count is the UTF-16 code unit, not the scalar value",
        Evidence::Case("c-tagging-0029"),
    ),
    ("Two tags under one key are 400 InvalidTag", Evidence::Case("c-tagging-0014")),
    (
        "A character outside the documented alphabet is 400 InvalidTag",
        Evidence::Case("c-tagging-0015"),
    ),
    // ── the packed header channel ──
    (
        "The x-amz-tagging header is form-decoded, so a%20b=c%2Bd is the pair 'a b' and 'c+d'",
        Evidence::Case("c-tagging-0003"),
    ),
    (
        "A header segment without '=' is refused and the object is not stored",
        Evidence::Case("c-tagging-0016"),
    ),
    ("A header repeating a key is 400 InvalidArgument", Evidence::Case("c-tagging-0017")),
    (
        "An empty key in the header channel is refused",
        Evidence::Fixture("n_an_empty_tag_key_in_the_inline_tag_set_is_refused"),
    ),
    (
        "GetObject on a tagged object carries x-amz-tagging-count",
        Evidence::Case("c-tagging-0019"),
    ),
    (
        "GetObject on an untagged object omits x-amz-tagging-count entirely",
        Evidence::Case("c-tagging-0020"),
    ),
    // ── the version dimension ──
    (
        "A tag set written to one version is read back from that version and from no other",
        Evidence::Case("c-tagging-0021"),
    ),
    (
        "Deleting one version's tag set leaves another version's standing",
        Evidence::Case("c-tagging-0022"),
    ),
    (
        "A versionId that was never minted is 404 NoSuchVersion, not the newest version's set",
        Evidence::Case("c-tagging-0023"),
    ),
    (
        "A versionId naming a delete marker is 405, not NoSuchKey",
        Evidence::Case("c-tagging-0024"),
    ),
    (
        "A version id minted for one key is not a version of another key",
        Evidence::Case("c-tagging-0025"),
    ),
    (
        "The tagging answers report no version id on an unversioned bucket",
        Evidence::Fixture("n_the_tagging_answers_do_not_report_a_version_on_an_unversioned_bucket"),
    ),
    // ── the band itself ──
    (
        "A tagging read answers the tag set and not the object",
        Evidence::Fixture("n_a_tagging_read_does_not_answer_with_the_object"),
    ),
    (
        "A tagging write replaces the labels and not the object's bytes",
        Evidence::Fixture("n_a_tagging_write_does_not_replace_the_object"),
    ),
    (
        "A copy-source header does not turn a tagging write into a copy",
        Evidence::Fixture("n_a_copy_source_header_does_not_turn_a_tagging_write_into_a_copy"),
    ),
];

fn corpus() -> Corpus {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    runner::prepare_corpus(&root).expect("the corpus loads")
}

fn family(corpus: &Corpus) -> Vec<&Case> {
    corpus
        .cases()
        .iter()
        .filter(|case| case.relative.starts_with("cases/tagging/"))
        .collect()
}

fn run_tagging_domain() -> Report {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = InProcess::new(root);
    let options = RunOptions {
        filter: Some("tagging/".to_owned()),
        ..RunOptions::default()
    };
    runner::run(&corpus, &mut sut, &options)
}

/// Reads a sibling test source from disk.
///
/// Deliberately `std::fs` and not `include_str!`: a citation to a function that no longer exists
/// must fail *this* test with a message naming the row, not turn into a build error in a file the
/// reader was not looking at.
fn source_of(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()))
}

/// Negative — the tagging family is a closed ledger: twenty-nine identifiers, contiguous, one file
/// each.
///
/// A gap means a case was deleted, which `AGENTS.md` lists as a silently dropped guarantee; a
/// duplicate means two files claim one identifier, after which only one of them is ever reported.
#[test]
fn the_tagging_family_is_a_closed_ledger_of_twenty_nine_identifiers() {
    let corpus = corpus();
    let cases = family(&corpus);

    let mut ids: Vec<&str> = cases.iter().map(|case| case.id.as_str()).collect();
    ids.sort_unstable();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "two tagging cases share an identifier: {ids:?}");
    assert_eq!(ids.len(), FAMILY_SIZE, "the tagging family holds {} cases, not {FAMILY_SIZE}", ids.len());

    let expected: Vec<String> = (1..=FAMILY_SIZE).map(|n| format!("c-tagging-{n:04}")).collect();
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    assert_eq!(ids, expected, "the tagging identifiers are not contiguous from 0001");
}

/// Negative — the family keeps negatives in the majority, which is the corpus rule applied to one
/// family rather than to the whole corpus, where a large well-balanced neighbour can pay for it.
#[test]
fn the_tagging_family_keeps_twenty_negative_against_nine_positive() {
    let corpus = corpus();
    let cases = family(&corpus);

    let negative = cases.iter().filter(|case| case.polarity() == Some("negative")).count();
    let positive = cases.iter().filter(|case| case.polarity() == Some("positive")).count();

    assert_eq!(negative + positive, FAMILY_SIZE, "a tagging case declares no polarity");
    assert_eq!(negative, NEGATIVE, "{negative} negative tagging cases, not {NEGATIVE}");
    assert_eq!(positive, POSITIVE, "{positive} positive tagging cases, not {POSITIVE}");
    assert!(negative > positive, "the tagging family stopped leading with its refusals");
}

/// Negative — all six operations of the family are exercised, and so is each side of the packed
/// header channel.
#[test]
fn every_operation_of_the_tagging_family_is_exercised() {
    let corpus = corpus();
    let cases = family(&corpus);
    let named = |operation: &str| {
        cases
            .iter()
            .filter(|case| case.meta().and_then(|meta| meta.read("caseMeta.operation")?.as_str()) == Some(operation))
            .count()
    };

    for operation in OPERATIONS {
        assert!(named(operation) > 0, "no tagging case names {operation} as its operation under test");
    }
    for operation in HEADER_CHANNEL_OPERATIONS {
        assert!(
            named(operation) > 0,
            "no tagging case reaches {operation}, so the x-amz-tagging channel is unasserted here"
        );
    }
}

/// Negative — every row of the status matrix is proved by an artefact that exists.
///
/// The three arms fail for different reasons and each names its own repair: a case id that is not
/// in the corpus, a fixture test that was renamed, a codec test that was deleted. Without this the
/// matrix is prose, and prose about coverage is exactly the thing this repository has been wrong
/// about seven times.
#[test]
fn every_row_of_the_status_matrix_is_proved_by_an_artefact_that_exists() {
    let corpus = corpus();
    let ids: BTreeSet<&str> = family(&corpus).iter().map(|case| case.id.as_str()).collect();
    let fixture = source_of(FIXTURE_SOURCE);
    let codec = source_of(CODEC_SOURCE);

    for (claim, evidence) in STATUS_MATRIX {
        match evidence {
            Evidence::Case(id) => assert!(ids.contains(id), "{claim}: cites {id}, which the corpus does not hold"),
            Evidence::Fixture(function) => assert!(
                fixture.contains(&format!("fn {function}(")),
                "{claim}: cites {FIXTURE_SOURCE}::{function}, which is not there"
            ),
            Evidence::Codec(function) => assert!(
                codec.contains(&format!("fn {function}(")),
                "{claim}: cites {CODEC_SOURCE}::{function}, which is not there"
            ),
        }
    }
}

/// Negative — the matrix cites each artefact at most once, and reaches every case in the family.
///
/// Two claims in one test because they are the two halves of "the ledger is a bijection over the
/// corpus". A repeated citation is a row that looks proved and is really the neighbouring row's
/// proof read twice; an uncited case is a guarantee the ledger does not know it has, which is how
/// a case gets deleted without anybody noticing the sentence it was carrying.
#[test]
fn the_status_matrix_cites_each_artefact_once_and_reaches_every_case() {
    let corpus = corpus();
    let held: BTreeSet<&str> = family(&corpus).iter().map(|case| case.id.as_str()).collect();

    let mut cited: BTreeSet<&str> = BTreeSet::new();
    for (claim, evidence) in STATUS_MATRIX {
        let name = match evidence {
            Evidence::Case(id) => *id,
            Evidence::Fixture(function) | Evidence::Codec(function) => *function,
        };
        assert!(cited.insert(name), "{claim}: {name} already proves another row");
    }

    let uncited: Vec<&str> = held.iter().copied().filter(|id| !cited.contains(id)).collect();
    assert!(
        uncited.is_empty(),
        "tagging cases the ledger names no claim for, so deleting one would break no row: {uncited:?}"
    );
}

/// Positive — the family executes against the assembled service, all twenty-nine green, none
/// skipped.
///
/// Four separate things are asserted, because each is satisfiable without the others: the filter
/// selects the whole family, no case is skipped (an unwired registry answers every case with a
/// skip, which renders like a pass in a summary line), every case passed, and the number that
/// passed is the whole family rather than merely "not failed".
#[test]
fn the_tagging_family_runs_wholly_green_and_nothing_is_skipped() {
    let report = run_tagging_domain();

    assert_eq!(report.outcomes.len(), FAMILY_SIZE, "the filter did not select the whole family");

    let skipped: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Skipped)
        .map(|outcome| outcome.id.as_str())
        .collect();
    assert!(
        skipped.is_empty(),
        "tagging cases skipped rather than run — is the family wired into the in-process registry? {skipped:?}"
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
    assert!(failed.is_empty(), "red tagging cases:\n{}", failed.join("\n"));

    let passed = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Passed)
        .count();
    assert_eq!(passed, FAMILY_SIZE, "{passed} tagging cases passed, not {FAMILY_SIZE}");
}

/// Negative — the family does not regress against the checked-in ratchet.
///
/// Only the regression direction is asserted. The reverse — every case appearing in the baseline —
/// is deliberately not, because `conformance/baseline.json` is regenerated by the release ratchet
/// rather than by the branch that adds a case.
#[test]
fn the_tagging_family_holds_the_verdicts_the_baseline_records() {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let source = std::fs::read_to_string(root.join("baseline.json")).expect("the baseline is checked in");
    let baseline = Baseline::from_json(&source).expect("the baseline parses");

    let reference = reference_run("tagging/");
    let regressions: Vec<&str> = reference
        .regressions(Some(&baseline))
        .iter()
        .map(|outcome| outcome.id.as_str())
        .collect();

    assert!(regressions.is_empty(), "tagging cases regressed against the baseline: {regressions:?}");
}

/// Negative — every quirk the overlay declares is claimed by at least one case.
///
/// A quirk with no case is a protocol exception the repository has written down and asserts
/// nothing about: the evidence is on file, the divergence is documented, and the behaviour is free
/// to change without a single test going red.
#[test]
fn every_tagging_quirk_is_claimed_by_a_case() {
    let corpus = corpus();
    let claimed: BTreeSet<&str> = family(&corpus).iter().flat_map(|case| case.quirks()).collect();

    let unclaimed: Vec<&str> = DECLARED_QUIRKS
        .iter()
        .copied()
        .filter(|quirk| !claimed.contains(quirk))
        .collect();
    assert!(
        unclaimed.is_empty(),
        "tagging quirks no case claims, so nothing in this suite would go red if they stopped \
         being true: {unclaimed:?}"
    );
}

/// Negative — the other direction: no case cites a quirk the overlay does not declare.
///
/// Two tests rather than one because they fail for opposite reasons and a combined message would
/// send the reader to the wrong file. This half catches a citation to nothing: a typo in a quirk
/// id reads exactly like a real reference, and `cargo xtask why` would answer with silence rather
/// than an error.
#[test]
fn n_no_tagging_case_cites_a_quirk_the_overlay_does_not_declare() {
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
        "tagging cases citing quirk ids the overlay does not declare:\n{}",
        dangling.join("\n")
    );
}
