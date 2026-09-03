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

//! Fail-closed mutation tests for the approved persisted-metadata source census.
//!
//! Responsible for: proving each refusal goes red when the registry is broken on purpose, and
//! proving the census reports a *different* verdict once the absent source is registered — a
//! one-directional control would be satisfied by a census stuck on "absent".
//! NOT responsible for: declaring the production registry, which stays in the parent module.
//! Upstream: `super`'s registry and the real corpus. Downstream: nothing; this module is
//! test-only.

use std::sync::OnceLock;

use super::*;
use crate::build_persistence_corpus_report;

/// A digest the real corpus carries, recorded by MinIO at the pinned migration release.
const MINIO_WITNESS: &str = "18887b7a076a3429d80f1a04fed3c772d296ec968d478d382f78cba01704d0fb";
/// A digest the real corpus carries with no writer-tier claim attached to it.
const FIXTURE_WITNESS: &str = "d02252be7653043d28995e397c4953a0a405f287426d914ade100a3c7d1ea1b5";

fn corpus() -> &'static CorpusReport {
    static CORPUS: OnceLock<CorpusReport> = OnceLock::new();
    CORPUS.get_or_init(|| build_persistence_corpus_report().expect("the real persisted XML corpus builds"))
}

fn registry() -> Vec<SourceRegistration> {
    SOURCE_REGISTRY.to_vec()
}

fn row(registry: &mut [SourceRegistration], source: PersistenceSource) -> &mut SourceRegistration {
    registry
        .iter_mut()
        .find(|row| row.source == source)
        .expect("the production registry declares this source")
}

/// The control the whole census rests on: the harness must be able to tell "the historical
/// writer matrix has not been collected" from "it has". Both directions are asserted here,
/// against the real corpus, so neither answer can be the only one the code can produce.
#[test]
fn absent_and_present_source_produce_different_verdicts() {
    assert_eq!(
        validate_sources(&registry(), corpus()),
        Err(PersistenceSourceError::SourceAbsent(PersistenceSource::HistoricalWriterMatrix)),
        "source (d') is not collected yet, and the census must say so by name"
    );

    let mut collected = registry();
    collected.push(SourceRegistration {
        source: PersistenceSource::HistoricalWriterMatrix,
        writer: Some("minio"),
        version: Some("RELEASE.2025-07-23T15-54-02Z"),
        witness_digests: &[MINIO_WITNESS],
        reference: "mutation control standing in for a collected historical writer sample",
    });
    let report = validate_sources(&collected, corpus()).expect("every approved source is now registered and backed");
    assert_eq!(report.rows().len(), PersistenceSource::ALL.len());
    assert!(
        report
            .render()
            .contains("d-prime-historical-writer-matrix: writer=minio@RELEASE.2025-07-23T15-54-02Z")
    );
    assert!(report.render().contains("4/4 approved sources present"));
}

#[test]
fn n_withdrawing_the_minio_migration_source_fails_closed() {
    let mut mutant = registry();
    mutant.retain(|row| row.source != PersistenceSource::MinioMigrationExport);
    assert_eq!(
        validate_sources(&mutant, corpus()),
        Err(PersistenceSourceError::SourceAbsent(PersistenceSource::MinioMigrationExport))
    );
}

#[test]
fn n_duplicate_source_registration_fails_closed() {
    let mut mutant = registry();
    mutant.push(mutant[0]);
    assert_eq!(
        validate_sources(&mutant, corpus()),
        Err(PersistenceSourceError::DuplicateSource(PersistenceSource::RepositoryFixture))
    );
}

#[test]
fn n_writer_tier_without_a_writer_fails_closed() {
    let mut mutant = registry();
    row(&mut mutant, PersistenceSource::MinioMigrationExport).writer = None;
    assert!(matches!(
        validate_sources(&mutant, corpus()),
        Err(PersistenceSourceError::UntraceableWriter {
            source: PersistenceSource::MinioMigrationExport,
            ..
        })
    ));
}

#[test]
fn n_writer_outside_the_shared_allowlist_fails_closed() {
    let mut mutant = registry();
    row(&mut mutant, PersistenceSource::MinioMigrationExport).writer = Some("customer-cluster");
    let Err(PersistenceSourceError::UntraceableWriter { source, reason }) = validate_sources(&mutant, corpus()) else {
        panic!("a writer this project cannot run must not be admitted");
    };
    assert_eq!(source, PersistenceSource::MinioMigrationExport);
    assert!(reason.contains("not in the allowlist"), "{reason}");
}

/// `latest`, `unknown` and `various` all read like versions and pin nothing. A sample whose
/// writer version cannot be traced may not be admitted — rustfs/backlog#1733 §8 rule 5.
#[test]
fn n_inexact_writer_versions_fail_closed() {
    for inexact in ["latest", "unknown", "various", "RELEASE.", "1", "v1", ""] {
        let mut mutant = registry();
        row(&mut mutant, PersistenceSource::MinioMigrationExport).version = Some(inexact);
        let Err(PersistenceSourceError::UntraceableWriter { reason, .. }) = validate_sources(&mutant, corpus()) else {
            panic!("`{inexact}` is not an exact version and must be refused");
        };
        assert!(reason.contains("not an exact version"), "{reason}");
    }
}

#[test]
fn exact_writer_versions_are_admitted() {
    for exact in [
        "RELEASE.2025-07-23T15-54-02Z",
        "1.2.3",
        "v0.1.0-alpha.1",
        "c876df53f5097618b1817568a471cbb8b4f26ee8",
    ] {
        assert!(rustfs_gateway_corpus::store::check_writer("rustfs", exact).is_ok(), "{exact}");
    }
}

#[test]
fn n_writer_on_a_tier_that_carries_none_fails_closed() {
    let mut mutant = registry();
    let fixture = row(&mut mutant, PersistenceSource::RepositoryFixture);
    fixture.writer = Some("rustfs");
    fixture.version = Some("1.2.3");
    assert_eq!(
        validate_sources(&mutant, corpus()),
        Err(PersistenceSourceError::UnexpectedWriter(PersistenceSource::RepositoryFixture))
    );
}

#[test]
fn n_registration_without_a_witness_digest_fails_closed() {
    let mut mutant = registry();
    row(&mut mutant, PersistenceSource::ClientMatrix).witness_digests = &[];
    assert_eq!(
        validate_sources(&mutant, corpus()),
        Err(PersistenceSourceError::NoWitness(PersistenceSource::ClientMatrix))
    );
}

/// The registry is a claim about bytes. Without this the rows could name anything at all and
/// the census would still be green, which is the paper-claim failure mode.
#[test]
fn n_witness_digest_absent_from_the_corpus_fails_closed() {
    const ABSENT: &[&str] = &["0000000000000000000000000000000000000000000000000000000000000000"];
    let mut mutant = registry();
    row(&mut mutant, PersistenceSource::ClientMatrix).witness_digests = ABSENT;
    assert_eq!(
        validate_sources(&mutant, corpus()),
        Err(PersistenceSourceError::WitnessNotInCorpus {
            source: PersistenceSource::ClientMatrix,
            sha256: ABSENT[0],
        })
    );
}

/// A registration may not claim a writer the witnessed sample does not itself record.
#[test]
fn n_witness_recorded_under_a_different_writer_fails_closed() {
    let mut mutant = registry();
    row(&mut mutant, PersistenceSource::MinioMigrationExport).writer = Some("rustfs");
    let Err(PersistenceSourceError::WitnessWriterMismatch { source, recorded, .. }) = validate_sources(&mutant, corpus()) else {
        panic!("the MinIO migration samples record MinIO, not RustFS");
    };
    assert_eq!(source, PersistenceSource::MinioMigrationExport);
    assert_eq!(recorded, "MinIO@RELEASE.2025-07-23T15-54-02Z");
}

#[test]
fn n_witness_recorded_at_a_different_writer_version_fails_closed() {
    let mut mutant = registry();
    row(&mut mutant, PersistenceSource::MinioMigrationExport).version = Some("RELEASE.2024-01-01T00-00-00Z");
    assert!(matches!(
        validate_sources(&mutant, corpus()),
        Err(PersistenceSourceError::WitnessWriterMismatch {
            source: PersistenceSource::MinioMigrationExport,
            ..
        })
    ));
}

/// Containment, not a count: every registered witness digest has to be a real corpus sample, or
/// each test above would be checking the registry against itself.
///
/// The length is pinned to the corpus report's own accepted/rejected totals rather than to a
/// floor. A floor cannot tell a full census from one that quietly lost half its rows, and
/// `samples()` returning a subset is exactly how the witness checks above would stop meaning
/// anything while still reading green.
#[test]
fn witness_digests_name_real_corpus_samples() {
    let digests = corpus()
        .samples()
        .iter()
        .map(|sample| sample.sha256.as_str())
        .collect::<Vec<_>>();
    assert!(digests.contains(&MINIO_WITNESS));
    assert!(digests.contains(&FIXTURE_WITNESS));
    for digest in SOURCE_REGISTRY.iter().flat_map(|row| row.witness_digests) {
        assert!(digests.contains(digest), "registered witness {digest} is not a corpus sample");
    }

    let totals = corpus()
        .render()
        .lines()
        .find_map(|line| line.strip_prefix("total: ").map(str::to_owned))
        .expect("the corpus report renders a total line");
    let counted = |field: &str| -> usize {
        totals
            .split_whitespace()
            .find_map(|token| token.strip_prefix(field))
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("the total line names {field}: {totals}"))
    };
    assert_eq!(digests.len(), counted("accepted=") + counted("rejected="));
}
