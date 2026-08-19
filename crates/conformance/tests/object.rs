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

//! The `object/` domain, executed rather than merely loaded.
//!
//! Responsible for: making the object data-plane corpus a verdict `cargo test` reaches, and naming
//! the cases that are allowed to be red together with the issue that owns each one. Without this
//! file the object cases are schema-checked by `corpus.rs` and run by nobody: `Unwired` gives every
//! case a skip, and a skip and a pass are the same colour in a summary line.
//! NOT responsible for: what any individual case asserts — that is the case file — or for the
//! `--baseline` comparison, which is a release-time ratchet over the whole corpus rather than a
//! per-family gate. See `crates/conformance/MAP.md`.
//! Upstream: the published API of `rustfs_gateway_conformance`. Downstream: nothing.
//!
//! # Why the known-red set is a floor and not an equality
//!
//! Asserting the exact set would be the stronger check and it is the wrong one here: the cases in
//! it are owned by other branches, so the moment one of them merges this file goes red on `main`
//! for a change that improved the tree. The regression direction — a case that was green going red
//! — is the one that has to stop a build, and that is what the subset assertion catches. The
//! opposite direction is caught by `MINIMUM_GREEN`, which has to be raised whenever a case is
//! fixed, and by the corpus-wide `--baseline` run.

use rustfs_gateway_conformance::corpus::Corpus;
use rustfs_gateway_conformance::inprocess::InProcess;
use rustfs_gateway_conformance::report::{Report, Verdict};
use rustfs_gateway_conformance::runner::{self, RunOptions};

/// Cases in `object/` that may be red, each with the issue that owns the defect behind it.
///
/// A case earns a row here only with an owner. "Known failure" without one is how a corpus rots:
/// the row outlives the reason, and nobody can tell a case waiting on a merge from a case nobody
/// ever intends to fix.
const OWNED_ELSEWHERE: &[(&str, &str)] = &[
    // The size-cap refusal already arrives mid-body — `request_progress.body_fully_sent` is false —
    // but the connection stays open afterwards, so the unread remainder of the request body is left
    // on a socket the server intends to reuse. `c-mpu-0045` and the 411 arm fail the same way, so
    // the defect is one shared rule about refusals that do not drain, not three cases.
    ("c-object-0015", "rustfs/backlog#1680"),
];

/// The number of `object/` cases that must be green.
///
/// A floor rather than a count of the corpus, so that adding a case cannot silently be paid for by
/// letting an existing one go red: the two would cancel in a total. Raise it when a case is fixed.
const MINIMUM_GREEN: usize = 28;

fn run_object_domain() -> Report {
    let root = Corpus::discover_root().expect("a corpus sits next to this crate");
    let corpus = runner::prepare_corpus(&root).expect("the corpus loads");
    let mut sut = InProcess::new(root);
    let options = RunOptions {
        filter: Some("object/".to_owned()),
        ..RunOptions::default()
    };
    runner::run(&corpus, &mut sut, &options)
}

/// Positive — every object case that is not owned by another branch is green, and enough of them
/// are green that the target cannot have been quietly unwired.
#[test]
fn the_object_domain_is_green_apart_from_the_cases_another_branch_owns() {
    let report = run_object_domain();
    assert!(!report.outcomes.is_empty(), "the object domain selected no cases");

    let owned: Vec<&str> = OWNED_ELSEWHERE.iter().map(|(id, _)| *id).collect();
    let unexpected: Vec<String> = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Failed)
        .filter(|outcome| !owned.contains(&outcome.id.as_str()))
        .map(|outcome| {
            let reasons: Vec<String> = outcome.failures().iter().map(ToString::to_string).collect();
            format!("{}: {}", outcome.id, reasons.join(" | "))
        })
        .collect();
    assert!(unexpected.is_empty(), "object cases red with no owning issue:\n{}", unexpected.join("\n"));

    let green = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.verdict == Verdict::Passed)
        .count();
    assert!(
        green >= MINIMUM_GREEN,
        "{green} object cases are green, the floor is {MINIMUM_GREEN}; \
         a case went red or the target is unwired"
    );
}

/// Negative — the known-red list is not a place to park a case nobody looks at.
///
/// Two directions, because a list of exemptions that is never re-read is the same defect as no
/// list at all: an id that names no case has outlived the case, and an id whose case is green has
/// outlived its reason and is now hiding the fact that a rule is being asserted for free.
#[test]
fn every_case_owned_elsewhere_still_exists_and_is_still_red() {
    let report = run_object_domain();
    for (id, owner) in OWNED_ELSEWHERE {
        let outcome = report
            .outcomes
            .iter()
            .find(|outcome| outcome.id == *id)
            .unwrap_or_else(|| panic!("{id} is listed as owned by {owner} but names no case"));
        assert_eq!(
            outcome.verdict,
            Verdict::Failed,
            "{id} is listed as owned by {owner} and is no longer red; \
             drop the row and raise MINIMUM_GREEN"
        );
    }
}

/// Negative — the case this issue owns is red for the reason recorded against it, not for some
/// other reason that happens to share a colour.
///
/// `c-object-0015` is the one entry above whose defect is not on another branch, so it is the one
/// this file may pin to its cause. Failing for the wrong reason reads in a report exactly like
/// failing for the right one, and an exemption that tolerates any failure would let the size cap
/// itself break without anyone noticing.
#[test]
fn the_size_cap_case_is_red_only_on_the_connection_it_leaves_open() {
    let report = run_object_domain();
    let outcome = report
        .outcomes
        .iter()
        .find(|outcome| outcome.id == "c-object-0015")
        .expect("c-object-0015 is in the corpus");
    let reasons: Vec<String> = outcome.failures().iter().map(ToString::to_string).collect();
    assert_eq!(reasons.len(), 1, "c-object-0015 fails on more than the connection: {reasons:?}");
    assert!(
        reasons[0].contains("connection_after"),
        "c-object-0015 is red for something other than the connection it leaves open: {reasons:?}"
    );
}
