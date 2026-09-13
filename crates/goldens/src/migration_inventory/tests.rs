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

//! Fail-closed tests for the decided `persisted-doctype` refusal.
//!
//! Responsible for: proving the real inventory in full, and that every way the decision can stop
//! holding — a revision that refuses, a decoder that reads or answers differently, a lost
//! tolerance, a writer sample with a declaration, fixture drift — is refused by name. NOT
//! responsible for: family D1-D5. Upstream: `super`. Downstream: none; test-only.

use rustfs_gateway_types::compat::{parse_s3s_replication, parse_s3s_versioning};
use rustfs_gateway_types::persistence::{parse_replication, parse_versioning};

use super::*;

/// The reproducer rustfs/gateway#469 was opened with.
const ISSUE_469_REPRODUCER: &[u8] = b"<!DOCTYPE ReplicationConfiguration [<!ELEMENT x ANY>]><ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>";

fn real_witnesses() -> Vec<DoctypeWitness> {
    let families = all_family_corpus_evidence().expect("the corpus builds");
    let bases = families
        .iter()
        .map(|family| {
            let base = family
                .samples()
                .find(|(bytes, _, accepted)| {
                    *accepted && bytes.first() == Some(&b'<') && bytes.get(1).is_some_and(u8::is_ascii_alphabetic)
                })
                .map(|(bytes, _, _)| bytes.to_vec())
                .expect("every family has an accepted document");
            (family.kind(), base)
        })
        .collect::<Vec<_>>();
    witnesses(&bases.iter().map(|(kind, base)| (*kind, base.as_slice())).collect::<Vec<_>>())
}

fn real_old(oracle: OracleRevision, kind: ConfigKind, bytes: &[u8]) -> OldReading {
    with_oracle(oracle, || old_reading(kind, bytes))
}

#[test]
fn every_family_and_form_matches_the_recorded_decision() {
    let report = build_migration_inventory().expect("the decided refusal holds");
    assert_eq!(report.refused(), 13 * 8 - 4);
    assert_eq!(report.tolerated(), 4);
    assert_eq!(
        report.render(),
        "migration inventory: decided-refusals=1\n\
         refusal persisted-doctype decision=https://github.com/rustfs/gateway/issues/469 witnesses=104 refused=100 tolerated=4 \
         old=reads under baseline s3s@9c4690d8, rollback s3s@bdcb6259, candidate s3s@f3e17541 new=Xml(DocTypeDeclaration) \
         writer-samples-with-doctype=0 boundary-fixtures=10 ingress=bucket-metadata-import-archive \
         remediation=re-put-configuration-through-s3-api\n"
    );
}

#[test]
fn n_the_issue_469_reproducer_is_read_by_every_revision_and_refused_by_name() {
    for oracle in OracleRevision::ALL {
        assert!(
            with_oracle(oracle, || parse_s3s_replication(ISSUE_469_REPRODUCER)).is_ok(),
            "{oracle} skips the internal subset"
        );
    }
    let error = parse_replication(ISSUE_469_REPRODUCER).expect_err("the production decoder refuses active DTD syntax");
    assert_eq!(format!("{error:?}"), NAMED_ERROR);
}

#[test]
fn n_a_referenced_entity_is_refused_on_both_sides() {
    let referenced = b"<!DOCTYPE VersioningConfiguration [<!ENTITY e \"Enabled\">]><VersioningConfiguration><Status>&e;</Status></VersioningConfiguration>";
    for oracle in OracleRevision::ALL {
        assert!(
            with_oracle(oracle, || parse_s3s_versioning(referenced)).is_err(),
            "{oracle} cannot resolve a declared entity"
        );
    }
    assert_eq!(format!("{:?}", parse_versioning(referenced).expect_err("refused")), NAMED_ERROR);
}

#[test]
fn n_a_revision_that_refuses_a_witness_makes_the_entry_stale() {
    let refusing_candidate = |oracle: OracleRevision, kind: ConfigKind, bytes: &[u8]| {
        if oracle == OracleRevision::Candidate {
            OldReading::Refused
        } else {
            real_old(oracle, kind, bytes)
        }
    };
    assert!(matches!(
        check_witnesses(&real_witnesses(), refusing_candidate, new_refusal),
        Err(MigrationInventoryError::StaleRefusal {
            oracle: OracleRevision::Candidate,
            ..
        })
    ));
}

#[test]
fn n_a_decoder_that_reads_an_active_declaration_violates_the_decision() {
    assert_eq!(
        check_witnesses(&real_witnesses(), real_old, |_, _| None),
        Err(MigrationInventoryError::DecisionViolated {
            kind: ConfigKind::Versioning,
            form: DoctypeForm::Inert,
            observed: None,
        })
    );
    let witnesses = real_witnesses()
        .into_iter()
        .filter(|witness| witness.form != DoctypeForm::Inert)
        .collect::<Vec<_>>();
    assert_eq!(
        check_witnesses(&witnesses, real_old, |_, _| None),
        Err(MigrationInventoryError::DecisionViolated {
            kind: ConfigKind::Versioning,
            form: DoctypeForm::WrongRoot,
            observed: None,
        })
    );
}

#[test]
fn n_a_decoder_that_refuses_with_another_error_violates_the_decision() {
    assert_eq!(
        check_witnesses(&real_witnesses(), real_old, |_, _| Some("Xml(DepthExceeded)".to_owned())),
        Err(MigrationInventoryError::DecisionViolated {
            kind: ConfigKind::Versioning,
            form: DoctypeForm::Inert,
            observed: Some("Xml(DepthExceeded)".to_owned()),
        })
    );
}

#[test]
fn n_a_decoder_that_refuses_a_tolerated_inert_declaration_loses_the_tolerance() {
    let witnesses = real_witnesses()
        .into_iter()
        .filter(|witness| witness.kind == ConfigKind::Replication)
        .collect::<Vec<_>>();
    assert_eq!(
        check_witnesses(&witnesses, real_old, |_, _| Some(NAMED_ERROR.to_owned())),
        Err(MigrationInventoryError::ToleranceLost {
            kind: ConfigKind::Replication,
            observed: NAMED_ERROR.to_owned(),
        })
    );
}

#[test]
fn n_a_writer_sample_carrying_a_declaration_is_refused() {
    let origin = SampleOrigin {
        source: "d-prime historical writer".to_owned(),
        producer: "rustfs".to_owned(),
        version: "1.0.0-rc.6".to_owned(),
        sha256: "00".repeat(32),
    };
    assert_eq!(
        audit_samples([(ConfigKind::Tagging, b"<!DOCTYPE Tagging><Tagging/>".as_slice(), &origin)]),
        Err(MigrationInventoryError::WriterSampleCarriesDoctype {
            kind: ConfigKind::Tagging,
            sha256: "00".repeat(32),
            producer: "rustfs".to_owned(),
        })
    );
    let lowercase = SampleOrigin {
        producer: "minio".to_owned(),
        ..origin
    };
    assert!(matches!(
        audit_samples([(ConfigKind::Tagging, b"<!doctype Tagging><Tagging/>".as_slice(), &lowercase)]),
        Err(MigrationInventoryError::WriterSampleCarriesDoctype { .. })
    ));
}

#[test]
fn n_boundary_fixture_drift_is_refused() {
    let fixture = SampleOrigin {
        source: "P9 Accelerate persistence matrix".to_owned(),
        producer: BOUNDARY_FIXTURE_PRODUCERS[0].to_owned(),
        version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
        sha256: "11".repeat(32),
    };
    assert_eq!(
        audit_samples([(ConfigKind::Accelerate, b"<!DOCTYPE A><A/>".as_slice(), &fixture)]),
        Err(MigrationInventoryError::BoundaryFixtureCountDrift {
            expected: BOUNDARY_FIXTURES_WITH_DOCTYPE,
            found: 1,
        })
    );
}
