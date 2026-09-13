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

#[test]
fn production_registry_is_the_exact_runtime_linked_39_case_set() {
    let report =
        validate_registry(&production_registry(), observations()).expect("the exact 39 acceptance cases must be registered");
    assert_eq!(report.cases().len(), 39);
    assert_eq!(report.passed_count(), 38);
    assert_eq!(report.blocked_count(), 1);
    assert_eq!(require_acceptance_closure(), Err(AcceptanceCensusError::ClosureBlocked(vec!["g-d1-003"])));
    assert!(!report.render().contains("approved persisted-metadata source absent"));
}

/// Removing a collected source must turn its passing full-corpus cases red.
#[test]
fn source_absence_does_not_leave_full_corpus_cases_passing() {
    let absent = RuntimeObservations {
        corpus: observations().corpus.clone(),
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

#[test]
fn blocked_as_pass_mutation_fails_closed() {
    let mut rows = production_registry();
    let blocked = rows
        .iter_mut()
        .find(|row| row.id == "g-d1-003")
        .expect("the specification blocker is registered");
    blocked.status = "passed";
    blocked.probe = Some(RuntimeProbe::AllFamilies);
    blocked.issue = None;
    assert_eq!(
        validate_registry(&rows, observations()),
        Err(AcceptanceCensusError::BlockedCasePassed("g-d1-003"))
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
