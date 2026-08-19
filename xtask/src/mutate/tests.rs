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

//! The verdict a mutated run is allowed to carry.
//!
//! Responsible for: pinning the order of the three guards that stand in front of `SURVIVED`, so
//! that a mutation which never reached the gateway can never be reported as a gap in the corpus.
//! NOT responsible for: applying a mutation, building, or running the suite.
//! Upstream: `super::classify`. Downstream: nothing.
//!
//! Every guard here is stated as a case where a naive implementation would report a *kill* or a
//! *survivor* and the honest answer is neither. That is the whole subject: this repository has
//! repeatedly shipped checks whose green came from somewhere other than the thing measured, and a
//! mutation gate is the worst possible place to add another.

use std::collections::BTreeMap;

use super::{Measurement, Outcome, classify};

fn verdicts(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(id, verdict)| ((*id).to_owned(), (*verdict).to_owned()))
        .collect()
}

fn baseline() -> BTreeMap<String, String> {
    verdicts(&[("c-lifecycle-0001", "passed"), ("c-lifecycle-0002", "passed")])
}

/// Applied, built, measured — the shape in which the verdicts are the only variable.
fn measured(pairs: &[(&str, &str)]) -> Measurement {
    Measurement {
        artifacts_changed: true,
        compiled: true,
        library_rebuilt: true,
        verdicts: Some(verdicts(pairs)),
    }
}

#[test]
fn a_case_the_rule_names_going_red_is_a_kill() {
    let outcome = classify(
        &baseline(),
        &["c-lifecycle-0001".to_owned()],
        &measured(&[("c-lifecycle-0001", "failed"), ("c-lifecycle-0002", "passed")]),
    );
    assert_eq!(
        outcome,
        Outcome::Killed {
            by: vec!["c-lifecycle-0001".to_owned()],
            declared: true,
        }
    );
}

#[test]
fn n_a_kill_by_a_case_the_rule_does_not_name_is_reported_as_unnamed() {
    let outcome = classify(
        &baseline(),
        &["c-lifecycle-0009".to_owned()],
        &measured(&[("c-lifecycle-0001", "failed"), ("c-lifecycle-0002", "passed")]),
    );
    assert_eq!(
        outcome,
        Outcome::Killed {
            by: vec!["c-lifecycle-0001".to_owned()],
            declared: false,
        },
        "a rule killed only by cases its ledger row never names is a binding this run cannot credit"
    );
}

#[test]
fn n_identical_artefacts_are_inert_and_never_a_survivor() {
    let outcome = classify(
        &baseline(),
        &[],
        &Measurement {
            artifacts_changed: false,
            compiled: true,
            library_rebuilt: true,
            verdicts: Some(verdicts(&[("c-lifecycle-0001", "passed"), ("c-lifecycle-0002", "passed")])),
        },
    );
    assert!(matches!(outcome, Outcome::Inert(_)), "{outcome:?}");
}

#[test]
fn n_a_tree_that_does_not_compile_is_not_a_case_kill() {
    let outcome = classify(
        &baseline(),
        &["c-lifecycle-0001".to_owned()],
        &Measurement {
            artifacts_changed: true,
            compiled: false,
            library_rebuilt: false,
            verdicts: None,
        },
    );
    assert_eq!(outcome, Outcome::KilledByCompile, "the compiler noticing is not the corpus noticing");
}

#[test]
fn n_a_library_that_was_not_rebuilt_is_inert_even_when_a_case_looks_red() {
    // The red verdict here is deliberately impossible: if no production code was rebuilt, the
    // gateway that answered these cases is the baseline gateway. A classifier that read the
    // verdicts first would report a kill for a mutation that never ran.
    let outcome = classify(
        &baseline(),
        &["c-lifecycle-0001".to_owned()],
        &Measurement {
            artifacts_changed: true,
            compiled: true,
            library_rebuilt: false,
            verdicts: Some(verdicts(&[("c-lifecycle-0001", "failed"), ("c-lifecycle-0002", "passed")])),
        },
    );
    assert!(matches!(outcome, Outcome::Inert(_)), "{outcome:?}");
}

#[test]
fn n_a_run_with_no_report_is_not_measured() {
    let outcome = classify(
        &baseline(),
        &[],
        &Measurement {
            artifacts_changed: true,
            compiled: true,
            library_rebuilt: true,
            verdicts: None,
        },
    );
    assert!(matches!(outcome, Outcome::NotMeasured(_)), "{outcome:?}");
}

#[test]
fn n_a_run_that_measured_fewer_cases_is_not_measured_even_when_one_went_red() {
    // The `81 filtered out` shape: the suite stopped executing part of itself, and the part it did
    // execute happens to contain a failure. Counting that as a kill would let the executor lose
    // cases without anyone noticing.
    let outcome = classify(
        &baseline(),
        &["c-lifecycle-0001".to_owned()],
        &measured(&[("c-lifecycle-0001", "failed")]),
    );
    match outcome {
        Outcome::NotMeasured(why) => assert!(why.contains("1 verdicts against 2"), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn n_everything_green_after_a_real_mutation_is_the_finding_not_a_pass() {
    let outcome = classify(
        &baseline(),
        &["c-lifecycle-0001".to_owned()],
        &measured(&[("c-lifecycle-0001", "passed"), ("c-lifecycle-0002", "passed")]),
    );
    assert_eq!(outcome, Outcome::Survived);
}

#[test]
fn n_a_case_already_red_at_baseline_cannot_be_a_kill() {
    let mut baseline = baseline();
    baseline.insert("c-lifecycle-0003".to_owned(), "failed".to_owned());
    let outcome = classify(
        &baseline,
        &["c-lifecycle-0003".to_owned()],
        &measured(&[
            ("c-lifecycle-0001", "passed"),
            ("c-lifecycle-0002", "passed"),
            ("c-lifecycle-0003", "failed"),
        ]),
    );
    assert_eq!(outcome, Outcome::Survived, "a case that was already red proves nothing about this rule");
}

#[test]
fn n_a_case_turning_green_under_the_mutation_is_not_a_kill() {
    let mut baseline = baseline();
    baseline.insert("c-lifecycle-0003".to_owned(), "failed".to_owned());
    let outcome = classify(
        &baseline,
        &[],
        &measured(&[
            ("c-lifecycle-0001", "passed"),
            ("c-lifecycle-0002", "passed"),
            ("c-lifecycle-0003", "passed"),
        ]),
    );
    assert_eq!(outcome, Outcome::Survived);
}

#[test]
fn n_a_case_that_vanished_from_the_mutated_run_counts_against_the_rule() {
    // Not a missing measurement — the count is unchanged — but a case that was green and is now
    // absent is a case the mutation stopped the suite from executing, which is a real change.
    let outcome = classify(
        &baseline(),
        &["c-lifecycle-0002".to_owned()],
        &measured(&[("c-lifecycle-0001", "passed"), ("c-lifecycle-0099", "passed")]),
    );
    assert_eq!(
        outcome,
        Outcome::Killed {
            by: vec!["c-lifecycle-0002".to_owned()],
            declared: true,
        }
    );
}

#[test]
fn n_only_a_kill_by_a_named_case_lets_the_command_exit_zero() {
    let unnamed = Outcome::Killed {
        by: vec!["c-lifecycle-0001".to_owned()],
        declared: false,
    };
    assert!(!unnamed.is_pass(), "an uncredited kill leaves a ledger row unproven");
    assert!(!Outcome::KilledByCompile.is_pass());
    assert!(!Outcome::Survived.is_pass());
    assert!(!Outcome::Inert(String::new()).is_pass());
    assert!(!Outcome::Unplannable(String::new()).is_pass());
    assert!(!Outcome::Unsupported(String::new()).is_pass());
    assert!(!Outcome::NotMeasured(String::new()).is_pass());
    assert!(
        Outcome::Killed {
            by: vec!["c-lifecycle-0001".to_owned()],
            declared: true,
        }
        .is_pass()
    );
}

#[test]
fn n_a_baseline_with_nothing_green_can_prove_no_survivor() {
    // Narrowing the corpus onto cases the baseline already records as failing would otherwise make
    // every rule a survivor without a single assertion having been consulted.
    let outcome = classify(
        &verdicts(&[("c-etag-0001", "failed")]),
        &["c-etag-0001".to_owned()],
        &measured(&[("c-etag-0001", "failed")]),
    );
    match outcome {
        Outcome::NotMeasured(why) => assert!(why.contains("green at baseline"), "{why}"),
        other => panic!("{other:?}"),
    }
}
