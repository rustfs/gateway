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
//! the cases that are allowed to be red together with the reason each one still is. Without this
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

/// Cases in `object/` that may be red, each with the reason that keeps them so.
///
/// A case earns a row here only with a named reason. "Known failure" without one is how a corpus
/// rots: the row outlives the reason, and nobody can tell a case waiting on a merge from a case
/// nobody ever intends to fix.
///
/// Not every reason is a defect, and the difference matters when reading a red line. The row below
/// used to be one — the refusal left the connection open — and is now the other: the case is
/// answered, correctly, by a transport this file does not use.
const OWNED_ELSEWHERE: &[(&str, &str)] = &[
    // Not a defect any more, and not one this file can retire either. The size-cap refusal arrives
    // mid-body and now ends the connection, and `c-object-0015` passes over `--transport conn` —
    // `wired::a_refusal_that_did_not_drain_the_body_ends_the_connection_over_a_socket` is where that
    // is asserted. What stays red here is the one assertion an in-process service cannot answer at
    // all: it is a value rather than a peer, so `connection_after` is `open` by construction. The
    // case is not skipped, because skipping it would also throw away the assertions this transport
    // does measure — `request_progress.body_fully_sent` among them, which is the evidence
    // rustfs/backlog#1680 §7 binds `c-obj-0052` to.
    ("c-object-0015", "the in-process transport has no socket to observe"),
];

/// The number of `object/` cases that must be green.
///
/// A floor rather than a count of the corpus, so that adding a case cannot silently be paid for by
/// letting an existing one go red: the two would cancel in a total. Raise it when a case is fixed.
const MINIMUM_GREEN: usize = 40;

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

/// Negative — the one red case is red for the reason recorded against it, not for some other
/// reason that happens to share a colour.
///
/// Failing for the wrong reason reads in a report exactly like failing for the right one, and an
/// exemption that tolerated any failure would let the size cap itself break without anyone
/// noticing. The pin is tighter than it was: the row above no longer records a defect, so the
/// *only* thing this case may be red on is the assertion this transport cannot answer. A second
/// failure appearing here is a regression in the size cap, in the refusal timing, or in the body
/// the refusal returns — none of which the socket run would necessarily separate out.
///
/// The other half of the pin is in `wired.rs`, and the two are the two directions of one claim:
/// green over a socket, red here, and red here on nothing but the socket.
#[test]
fn the_size_cap_case_is_red_only_where_this_transport_cannot_look() {
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
        "c-object-0015 is red for something other than the socket this transport has not got: {reasons:?}"
    );
}

/// Negative — the new write-framing case is in this domain and is not silently absent from it.
///
/// `c-object-0030` needs a raw request head, so it is skipped here rather than judged, and a skip
/// and an id nobody loaded look identical in a summary line. This is the assertion that separates
/// them: the case is selected by the domain filter, and the reason it is not judged is the one
/// stated rather than any other.
#[test]
fn the_undeclared_length_case_is_selected_and_skipped_for_its_stated_reason() {
    let report = run_object_domain();
    let outcome = report
        .outcomes
        .iter()
        .find(|outcome| outcome.id == "c-object-0030")
        .expect("c-object-0030 is in the object domain");
    assert_eq!(outcome.verdict, Verdict::Skipped);
    let reason = outcome.skip_reason.as_deref().unwrap_or_default();
    assert!(reason.contains("raw_head_utf8"), "{reason}");
}
