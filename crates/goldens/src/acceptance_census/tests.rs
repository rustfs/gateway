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

//! Fail-closed mutation tests for the P9-01 acceptance census.
//!
//! Responsible for: proving every census disposition, binding and runtime probe goes red when
//! it is broken on purpose. NOT responsible for: declaring case rows or evaluating evidence,
//! which stay in the parent module. Upstream: `super`'s registry and runtime observations.
//! Downstream: nothing; this module is test-only.

use std::sync::OnceLock;

use super::*;

fn observations() -> &'static RuntimeObservations {
    static OBSERVATIONS: OnceLock<RuntimeObservations> = OnceLock::new();
    OBSERVATIONS.get_or_init(|| RuntimeObservations::collect().expect("real corpus and D1-D5 observations pass"))
}

/// The issue that held `g-d1-003` before it was narrowed to evidence.
const ISSUE_2104: &str = "https://github.com/rustfs/backlog/issues/2104";

#[test]
fn production_registry_is_the_exact_runtime_linked_39_case_set() {
    let report =
        validate_registry(&production_registry(), observations()).expect("the exact 39 acceptance cases must be registered");
    assert_eq!(report.cases().len(), 39);
    assert_eq!(report.passed_count(), 39);
    assert_eq!(report.blocked_count(), 0);
    assert_eq!(require_acceptance_closure(), Ok(report.clone()));
    assert!(!report.render().contains("approved persisted-metadata source absent"));
    assert!(!report.render().contains("blocked issue="));
}

fn without_accepted(digest: &str) -> RuntimeObservations {
    let full = observations();
    let accepted = full
        .accepted
        .iter()
        .filter(|(_, candidate)| candidate != digest)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(accepted.len() + 1, full.accepted.len(), "{digest} must be one accepted sample");
    RuntimeObservations {
        corpus: full.corpus.clone(),
        accepted,
        families: full.families.clone(),
        sources: full.sources.clone(),
    }
}

/// `g-d1-003` is held by its own witnesses: losing either top-level-subtree sample from the
/// accepted D1-D5 set turns the row red, even though other Lifecycle samples still carry the
/// `unknown-top-level` variant label.
#[test]
fn n_g_d1_003_goes_red_without_either_accepted_witness() {
    for digest in crate::lifecycle::UNKNOWN_TOP_LEVEL_SUBTREES {
        let observed = without_accepted(digest);
        assert!(
            observed
                .evaluate(RuntimeProbe::Variant(ConfigKind::Lifecycle, CorpusVariant::UnknownTopLevel), "variant")
                .is_ok(),
            "the variant label alone would still read covered"
        );
        assert_eq!(
            validate_registry(&production_registry(), &observed),
            Err(AcceptanceCensusError::ProbeFailed {
                id: "g-d1-003",
                reason: format!("lifecycle witness {digest} is not an accepted D1-D5 sample"),
            })
        );
    }
}

/// A witness digest carried by a refused sample, or by another family, is not evidence.
#[test]
fn n_accepted_sample_probe_requires_family_and_disposition() {
    let full = observations();
    // Refused samples are in the corpus but never in the accepted set the probe reads, which is
    // what keeps a nested-unknown refusal from being cited as `g-d1-003` evidence.
    for refused in crate::lifecycle::corpus_evidence().rejected {
        let digest = refused.sample.origin.sha256;
        assert!(
            !full.accepted.iter().any(|(_, candidate)| *candidate == digest),
            "refused {} reads as accepted",
            refused.sample.notes
        );
    }
    let before = crate::lifecycle::UNKNOWN_TOP_LEVEL_SUBTREES[0];
    let mut relabeled = without_accepted(before);
    relabeled.accepted.push((ConfigKind::Replication, before.to_owned()));
    assert!(
        relabeled
            .evaluate(
                RuntimeProbe::AcceptedSamples(ConfigKind::Lifecycle, crate::lifecycle::UNKNOWN_TOP_LEVEL_SUBTREES),
                "x"
            )
            .is_err()
    );
    assert!(
        full.evaluate(RuntimeProbe::AcceptedSamples(ConfigKind::Lifecycle, &[]), "x")
            .is_err(),
        "an empty witness list must not pass"
    );
    let unexecuted = RuntimeObservations {
        families: full
            .families
            .iter()
            .copied()
            .filter(|kind| *kind != ConfigKind::Lifecycle)
            .collect(),
        ..full.clone()
    };
    assert!(
        unexecuted
            .evaluate(
                RuntimeProbe::AcceptedSamples(ConfigKind::Lifecycle, crate::lifecycle::UNKNOWN_TOP_LEVEL_SUBTREES),
                "x"
            )
            .is_err()
    );
}

/// The resolved specification blocker cannot come back as a blocked row.
#[test]
fn n_g_d1_003_cannot_be_blocked_on_its_resolved_issue() {
    let mut rows = production_registry();
    *rows.iter_mut().find(|row| row.id == "g-d1-003").unwrap() = CaseDeclaration::blocked("g-d1-003", ISSUE_2104);
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::InvalidBlocker("g-d1-003"))
    );
}

/// Swapping the witness probe for the broader variant label is a binding change, not a pass.
#[test]
fn n_g_d1_003_probe_cannot_be_widened_to_a_variant_label() {
    let mut rows = production_registry();
    rows.iter_mut().find(|row| row.id == "g-d1-003").unwrap().probe =
        Some(RuntimeProbe::Variant(ConfigKind::Lifecycle, CorpusVariant::UnknownTopLevel));
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::WrongBinding("g-d1-003"))
    );
}

/// Removing a collected source must turn its passing full-corpus cases red.
#[test]
fn source_absence_does_not_leave_full_corpus_cases_passing() {
    let absent = RuntimeObservations {
        corpus: observations().corpus.clone(),
        accepted: observations().accepted.clone(),
        families: observations().families.clone(),
        sources: Err(PersistenceSourceError::SourceAbsent(PersistenceSource::HistoricalWriterMatrix)),
    };
    assert_eq!(absent.absent_source(), Some(PersistenceSource::HistoricalWriterMatrix));
    assert_eq!(
        validate_registry(&production_registry(), &absent),
        Err(AcceptanceCensusError::BlockedCasePassed("g-d4-001"))
    );
}

#[test]
fn n_collected_source_cannot_keep_a_stale_blocker() {
    let mut rows = production_registry();
    *rows.iter_mut().find(|row| row.id == "g-d4-001").unwrap() = CaseDeclaration::blocked("g-d4-001", ISSUE_2096);
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::InvalidBlocker("g-d4-001"))
    );
}

/// A broken registration must not arrive dressed as a known-incomplete row.
#[test]
fn n_non_absence_provenance_failure_is_not_a_blocker() {
    let error = PersistenceSourceError::WitnessNotInCorpus {
        source: PersistenceSource::MinioMigrationExport,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
    };
    assert!(!matches!(error, PersistenceSourceError::SourceAbsent(_)));
    assert_eq!(required_blocker("g-d4-001", observations()), None);
}

/// A census over the exact 39 IDs with the named rows blocked. Only the strict verdict reads it;
/// production evidence cannot produce a fully resolved census while its blockers are open.
fn synthetic_census(blocked: &[&'static str], absent_source: Option<&'static str>) -> AcceptanceCensusReport {
    AcceptanceCensusReport {
        cases: EXPECTED_CASE_IDS
            .into_iter()
            .map(|id| AcceptanceCaseReport {
                id,
                status: if blocked.contains(&id) {
                    AcceptanceCaseStatus::Blocked { issue: ISSUE_2104 }
                } else {
                    AcceptanceCaseStatus::Passed
                },
                source_ref: "synthetic",
            })
            .collect(),
        absent_source,
    }
}

#[test]
fn fully_resolved_synthetic_census_closes() {
    let resolved = synthetic_census(&[], None);
    assert_eq!((resolved.passed_count(), resolved.blocked_count()), (39, 0));
    assert_eq!(closure_verdict(resolved.clone()), Ok(resolved));
}

#[test]
fn n_one_blocked_case_holds_closure() {
    assert_eq!(
        closure_verdict(synthetic_census(&["g-d1-003"], None)),
        Err(AcceptanceCensusError::ClosureBlocked(vec!["g-d1-003"]))
    );
}

/// A missing source is never turned into a pass, even when every row reads passed.
#[test]
fn n_absent_source_holds_closure_even_when_every_case_passed() {
    assert_eq!(
        closure_verdict(synthetic_census(&[], Some("d-prime-historical-writer-matrix"))),
        Err(AcceptanceCensusError::ApprovedSourceAbsent {
            source: "d-prime-historical-writer-matrix",
            cases: vec!["g-d4-001", "g-d5-001"],
        })
    );
}

#[test]
fn n_absent_source_is_named_ahead_of_blocked_cases() {
    assert!(matches!(
        closure_verdict(synthetic_census(&["g-d1-003"], Some("d-prime-historical-writer-matrix"))),
        Err(AcceptanceCensusError::ApprovedSourceAbsent { .. })
    ));
}

/// The `g-d2-001` and `g-d3-001` rows claim every persisted family, so their probe has to go
/// red the moment one family stops executing D1-D5. Without this the two rows would read like
/// the blocked rows they replaced: a status with nothing behind it.
#[test]
fn all_family_rows_fail_closed_when_one_family_stops_executing() {
    let full = observations();
    let truncated = RuntimeObservations {
        corpus: full.corpus.clone(),
        accepted: full.accepted.clone(),
        families: full
            .families
            .iter()
            .copied()
            .filter(|kind| *kind != ConfigKind::Replication)
            .collect(),
        sources: full.sources.clone(),
    };
    for id in ["g-d2-001", "g-d3-001", "g-d4-001", "g-d5-001"] {
        let row = production_registry()
            .into_iter()
            .find(|row| row.id == id)
            .expect("the all-family byte-write and rollback rows are registered");
        assert_eq!(row.status, "passed");
        assert_eq!(row.probe, Some(RuntimeProbe::AllFamilies));
        assert!(
            truncated.evaluate(RuntimeProbe::AllFamilies, row.source_ref).is_err(),
            "{id} must go red when one persisted family stops executing D1-D5"
        );
        assert!(full.evaluate(RuntimeProbe::AllFamilies, row.source_ref).is_ok());
    }
}

#[test]
fn missing_case_mutation_fails_closed() {
    let mut rows = production_registry();
    rows.retain(|row| row.id != "g-d1-001");
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::MissingCase("g-d1-001"))
    );
}

#[test]
fn duplicate_case_mutation_fails_closed() {
    let mut rows = production_registry();
    rows.push(rows[0]);
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::DuplicateCase("g-d1-001"))
    );
}

#[test]
fn extra_case_mutation_fails_closed() {
    let mut rows = production_registry();
    rows[0].id = "g-d6-001";
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::ExtraCase("g-d6-001"))
    );
}

#[test]
fn unknown_status_mutation_fails_closed() {
    let mut rows = production_registry();
    rows[0].status = "deferred";
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::UnknownStatus {
            id: "g-d1-001",
            status: "deferred",
        })
    );
}

/// A row that must be blocked cannot read passed. With every source present no row must be, so
/// both directions are shown on the same registry: it validates against the real observation and
/// fails as `BlockedCasePassed` once the source it depends on is withdrawn.
#[test]
fn blocked_as_pass_mutation_fails_closed() {
    let absent = RuntimeObservations {
        sources: Err(PersistenceSourceError::SourceAbsent(PersistenceSource::HistoricalWriterMatrix)),
        ..observations().clone()
    };
    let rows = production_registry();
    assert!(validate_registry(&rows, observations()).is_ok());
    assert_eq!(
        validate_registry(&rows, &absent),
        Err(AcceptanceCensusError::BlockedCasePassed("g-d4-001"))
    );
}

#[test]
fn runtime_probe_mutation_fails_closed() {
    let mut rows = production_registry();
    rows[0].probe = Some(RuntimeProbe::Variant(ConfigKind::Accelerate, CorpusVariant::TimestampPrecision));
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::ProbeFailed {
            id: "g-d1-001",
            reason: "accelerate variant timestamp-precision was not observed through corpus plus D1-D5".to_owned(),
        })
    );
}

#[test]
fn vacuous_callback_mutation_fails_closed() {
    let mut rows = production_registry();
    let row = rows
        .iter_mut()
        .find(|row| row.id == "g-d1-002")
        .expect("the replication unknown-top-level case is registered");
    row.probe = Some(RuntimeProbe::AllFamilies);
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::WrongBinding("g-d1-002"))
    );
}

#[test]
fn wrong_external_binding_mutation_fails_closed() {
    let mut rows = production_registry();
    let row = rows
        .iter_mut()
        .find(|row| row.id == "g-key-001")
        .expect("the persisted metadata key case is registered");
    row.probe = Some(RuntimeProbe::External {
        repository: "rustfs/rustfs",
        revision: RUSTFS_REVISION,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000",
    });
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::WrongBinding("g-key-001"))
    );
}
