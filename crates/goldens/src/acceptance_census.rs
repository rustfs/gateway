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

//! Runtime-linked closure census for the P9-01 acceptance cases.
//!
//! Responsible for: binding the exact 39 acceptance IDs to observed runtime or pinned external
//! evidence while keeping specification blockers explicit. NOT responsible for: replacing the
//! family-owned D1-D5 assertions or treating blocked work as passing. Upstream: the aggregate
//! corpus/four-way runners and pinned RustFS evidence. Downstream: the final P9-01 closure audit.

use core::fmt;
use std::collections::BTreeSet;

use crate::{
    ConfigKind, CorpusVariant, PersistenceSource, PersistenceSourceError, PersistenceSourceReport,
    build_persistence_corpus_report, require_persistence_sources, run_four_way_all,
};

const RUSTFS_REVISION: &str = "bb3784136204a632b5b9b9cbef49d58f03df8bb6";
const ISSUE_2104: &str = "https://github.com/rustfs/backlog/issues/2104";
const ISSUE_2096: &str = "https://github.com/rustfs/backlog/issues/2096";

/// The acceptance cases whose Given is the full corpus, and which therefore cannot be claimed
/// while an approved source of that corpus is missing. rustfs/backlog#1733 §7.4 and §7.5.
const SOURCE_DEPENDENT_CASES: [&str; 2] = ["g-d4-001", "g-d5-001"];
const EXPECTED_CASE_IDS: [&str; 39] = [
    "g-d1-001",
    "g-d1-002",
    "g-d1-003",
    "g-d1-004",
    "g-d1-005",
    "g-d1-006",
    "g-d1-007",
    "g-d1-008",
    "g-d2-001",
    "g-d2-002",
    "g-d2-003",
    "g-d2-004",
    "g-d2-005",
    "g-d2-006",
    "g-d2-007",
    "g-d2-008",
    "g-d2-009",
    "g-d3-001",
    "g-d3-002",
    "g-d3-003",
    "g-d3-004",
    "g-d3-005",
    "g-d4-001",
    "g-d4-002",
    "g-d4-003",
    "g-d4-004",
    "g-d4-005",
    "g-d5-001",
    "g-d5-002",
    "g-d5-003",
    "g-d5-004",
    "g-d5-005",
    "g-key-001",
    "g-key-002",
    "g-key-003",
    "g-key-004",
    "g-zip-001",
    "g-zip-002",
    "g-zip-003",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeProbe {
    AllFamilies,
    Family(ConfigKind),
    Variant(ConfigKind, CorpusVariant),
    External {
        repository: &'static str,
        revision: &'static str,
        sha256: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaseDeclaration {
    id: &'static str,
    status: &'static str,
    probe: Option<RuntimeProbe>,
    issue: Option<&'static str>,
    source_ref: &'static str,
}

impl CaseDeclaration {
    const fn passed(id: &'static str, probe: RuntimeProbe, source_ref: &'static str) -> Self {
        Self {
            id,
            status: "passed",
            probe: Some(probe),
            issue: None,
            source_ref,
        }
    }

    const fn blocked(id: &'static str, issue: &'static str) -> Self {
        Self {
            id,
            status: "blocked",
            probe: None,
            issue: Some(issue),
            source_ref: issue,
        }
    }

    const fn external(id: &'static str, source_ref: &'static str, sha256: &'static str) -> Self {
        Self::passed(
            id,
            RuntimeProbe::External {
                repository: "rustfs/rustfs",
                revision: RUSTFS_REVISION,
                sha256,
            },
            source_ref,
        )
    }
}

/// One truthfully classified Section 7 acceptance case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceCaseReport {
    id: &'static str,
    status: AcceptanceCaseStatus,
    source_ref: &'static str,
}

impl AcceptanceCaseReport {
    /// Stable Section 7 case identifier.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// Direct observation or explicit blocking issue.
    #[must_use]
    pub const fn status(&self) -> &AcceptanceCaseStatus {
        &self.status
    }

    /// Concrete gateway source or pinned external evidence reference.
    #[must_use]
    pub const fn source_ref(&self) -> &'static str {
        self.source_ref
    }
}

/// Closure disposition for one acceptance case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptanceCaseStatus {
    /// The bound runtime or external evidence was validated.
    Passed,
    /// The case cannot be claimed complete until the linked backlog issue is resolved.
    Blocked {
        /// Exact rustfs/backlog issue URL.
        issue: &'static str,
    },
}

/// Validated exact-set report for all 39 Section 7 cases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceCensusReport {
    cases: Vec<AcceptanceCaseReport>,
    absent_source: Option<&'static str>,
}

impl AcceptanceCensusReport {
    /// All 39 case rows in task order.
    #[must_use]
    pub fn cases(&self) -> &[AcceptanceCaseReport] {
        &self.cases
    }

    /// Number of rows backed by validated direct evidence.
    #[must_use]
    pub fn passed_count(&self) -> usize {
        self.cases
            .iter()
            .filter(|case| case.status == AcceptanceCaseStatus::Passed)
            .count()
    }

    /// Number of rows kept explicitly blocked.
    #[must_use]
    pub fn blocked_count(&self) -> usize {
        self.cases.len() - self.passed_count()
    }

    /// Deterministic human-readable closure report.
    #[must_use]
    pub fn render(&self) -> String {
        let mut output = format!(
            "P9-01 acceptance census: passed={} blocked={} total={}\n",
            self.passed_count(),
            self.blocked_count(),
            self.cases.len()
        );
        for case in &self.cases {
            match case.status {
                AcceptanceCaseStatus::Passed => {
                    output.push_str(&format!("{}: passed source={}\n", case.id, case.source_ref));
                }
                AcceptanceCaseStatus::Blocked { issue } => {
                    output.push_str(&format!("{}: blocked issue={}\n", case.id, issue));
                }
            }
        }
        if let Some(source) = self.absent_source {
            output.push_str(&format!("approved persisted-metadata source absent: {source}\n"));
        }
        output
    }
}

/// Fail-closed census construction or closure error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptanceCensusError {
    /// An expected Section 7 ID was not registered.
    MissingCase(&'static str),
    /// An ID was registered more than once.
    DuplicateCase(&'static str),
    /// A registry row used an ID outside the exact Section 7 set.
    ExtraCase(&'static str),
    /// A row used a disposition other than `passed` or `blocked`.
    UnknownStatus {
        /// Affected case ID.
        id: &'static str,
        /// Unrecognized disposition.
        status: &'static str,
    },
    /// A known specification blocker was mutated into a passing row.
    BlockedCasePassed(&'static str),
    /// A row was blocked by the wrong issue or an unblocked row was relabeled blocked.
    InvalidBlocker(&'static str),
    /// A row no longer names its exact runtime callback or pinned external evidence.
    WrongBinding(&'static str),
    /// A runtime or external evidence probe failed.
    ProbeFailed {
        /// Affected case ID.
        id: &'static str,
        /// Exact failed observation.
        reason: String,
    },
    /// The census itself is valid, but final closure is blocked by these cases.
    ClosureBlocked(Vec<&'static str>),
    /// An approved persisted-metadata source is absent, so the full-corpus cases cannot be
    /// claimed. Named rather than folded into [`Self::ClosureBlocked`]: "we have not collected
    /// this source yet" and "these cases are still specification-blocked" are different states
    /// and must not read the same.
    ApprovedSourceAbsent {
        /// Slug of the absent source.
        source: &'static str,
        /// Acceptance cases whose Given is the full corpus.
        cases: Vec<&'static str>,
    },
    /// A registered persisted-metadata source has invalid writer provenance or an unbacked
    /// witness digest. This is never a blocker; it is a broken registration.
    SourceProvenance(String),
    /// Aggregate corpus or D1-D5 execution failed before row evaluation.
    Observation(String),
}

impl fmt::Display for AcceptanceCensusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AcceptanceCensusError {}

#[derive(Clone, Debug)]
struct RuntimeObservations {
    corpus: String,
    families: Vec<ConfigKind>,
    sources: Result<PersistenceSourceReport, PersistenceSourceError>,
}

impl RuntimeObservations {
    fn collect() -> Result<Self, AcceptanceCensusError> {
        let corpus_report =
            build_persistence_corpus_report().map_err(|error| AcceptanceCensusError::Observation(error.to_string()))?;
        let corpus = corpus_report.render();
        let sources = require_persistence_sources(&corpus_report);
        // An absent source is a state this census reports on. Any other provenance failure is a
        // broken registration, and reporting it as a blocker would hide it behind a row that
        // already reads as "known incomplete".
        if let Err(error) = &sources
            && !error.is_source_absent()
        {
            return Err(AcceptanceCensusError::SourceProvenance(error.to_string()));
        }
        let four_way = run_four_way_all().map_err(|error| AcceptanceCensusError::Observation(error.to_string()))?;
        Ok(Self {
            corpus,
            families: four_way.families.into_iter().map(|family| family.kind).collect(),
            sources,
        })
    }

    /// The approved source the corpus is missing, when that is why closure is held.
    const fn absent_source(&self) -> Option<PersistenceSource> {
        match &self.sources {
            Err(PersistenceSourceError::SourceAbsent(source)) => Some(*source),
            _ => None,
        }
    }

    fn evaluate(&self, probe: RuntimeProbe, source_ref: &str) -> Result<(), String> {
        match probe {
            RuntimeProbe::AllFamilies => {
                if self.families.len() == ConfigKind::ALL.len() && ConfigKind::ALL.iter().all(|kind| self.families.contains(kind))
                {
                    Ok(())
                } else {
                    Err(format!("observed {:?}, expected {:?}", self.families, ConfigKind::ALL))
                }
            }
            RuntimeProbe::Family(kind) => {
                if self.families.contains(&kind) {
                    Ok(())
                } else {
                    Err(format!("{} did not execute through D1-D5", kind.report_name()))
                }
            }
            RuntimeProbe::Variant(kind, variant) => {
                let prefix = format!("{}: ", kind.report_name());
                let token = variant_report_name(variant);
                let covered = self
                    .corpus
                    .lines()
                    .find(|line| line.starts_with(&prefix))
                    .is_some_and(|line| {
                        line.split_once("variants=")
                            .is_some_and(|(_, variants)| variants.split(',').any(|candidate| candidate == token))
                    });
                if covered && self.families.contains(&kind) {
                    Ok(())
                } else {
                    Err(format!(
                        "{} variant {token} was not observed through corpus plus D1-D5",
                        kind.report_name()
                    ))
                }
            }
            RuntimeProbe::External {
                repository,
                revision,
                sha256,
            } => {
                if repository != "rustfs/rustfs" {
                    return Err(format!("unexpected external repository {repository}"));
                }
                if !is_lower_hex(revision, 40) || !is_lower_hex(sha256, 64) {
                    return Err("external revision and file digest must be lowercase pinned hex".to_owned());
                }
                if source_ref.contains("generated/") || source_ref.trim().is_empty() {
                    return Err("external source_ref must be non-generated and non-empty".to_owned());
                }
                Ok(())
            }
        }
    }
}

/// Builds the exact 39-case census while preserving unresolved cases as `Blocked`.
///
/// # Errors
///
/// Returns the first registry, runtime observation, or external binding failure.
pub fn build_acceptance_census() -> Result<AcceptanceCensusReport, AcceptanceCensusError> {
    Ok(census_with_observations()?.0)
}

fn census_with_observations() -> Result<(AcceptanceCensusReport, RuntimeObservations), AcceptanceCensusError> {
    let observations = RuntimeObservations::collect()?;
    let report = validate_registry(&production_registry(), &observations)?;
    Ok((report, observations))
}

/// Requires every registered case to have passed direct evidence.
///
/// # Errors
///
/// Returns [`AcceptanceCensusError::ApprovedSourceAbsent`] while an approved persisted-metadata
/// source has not been collected, [`AcceptanceCensusError::ClosureBlocked`] while any
/// specification blocker remains, or the same fail-closed validation errors as
/// [`build_acceptance_census`].
pub fn require_acceptance_closure() -> Result<AcceptanceCensusReport, AcceptanceCensusError> {
    let (report, observations) = census_with_observations()?;
    if let Some(source) = observations.absent_source() {
        return Err(AcceptanceCensusError::ApprovedSourceAbsent {
            source: source.slug(),
            cases: SOURCE_DEPENDENT_CASES.to_vec(),
        });
    }
    let blocked = report
        .cases
        .iter()
        .filter_map(|case| match case.status {
            AcceptanceCaseStatus::Passed => None,
            AcceptanceCaseStatus::Blocked { .. } => Some(case.id),
        })
        .collect::<Vec<_>>();
    if blocked.is_empty() {
        Ok(report)
    } else {
        Err(AcceptanceCensusError::ClosureBlocked(blocked))
    }
}

fn production_registry() -> Vec<CaseDeclaration> {
    use ConfigKind::{Lifecycle, ObjectLock, Replication, Tagging, Versioning};
    use CorpusVariant::{
        AlternateOrder, BodyLiteral, Bom, DuplicateField, EmptyElement, Extension, LargeValue, MissingField, Namespace, Unicode,
        UnknownAttribute, UnknownScalar, UnknownTopLevel,
    };

    vec![
        CaseDeclaration::passed("g-d1-001", RuntimeProbe::AllFamilies, "crates/goldens/src/source_a_census.rs::validate"),
        CaseDeclaration::passed(
            "g-d1-002",
            RuntimeProbe::Variant(Replication, UnknownTopLevel),
            "crates/goldens/src/replication.rs::UNKNOWN_TOP_LEVEL",
        ),
        CaseDeclaration::blocked("g-d1-003", ISSUE_2104),
        CaseDeclaration::passed(
            "g-d1-004",
            RuntimeProbe::Family(Lifecycle),
            "crates/goldens/src/lifecycle.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d1-005",
            RuntimeProbe::Variant(Versioning, BodyLiteral),
            "crates/goldens/src/versioning.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d1-006",
            RuntimeProbe::Variant(Tagging, Bom),
            "crates/goldens/src/tagging.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d1-007",
            RuntimeProbe::Variant(Tagging, Unicode),
            "crates/goldens/src/tagging.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d1-008",
            RuntimeProbe::Variant(Tagging, LargeValue),
            "crates/goldens/src/tagging.rs::corpus_evidence",
        ),
        CaseDeclaration::passed("g-d2-001", RuntimeProbe::AllFamilies, "crates/goldens/src/four_way.rs::run_four_way_all"),
        CaseDeclaration::passed(
            "g-d2-002",
            RuntimeProbe::Variant(Tagging, EmptyElement),
            "crates/goldens/src/tagging.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d2-003",
            RuntimeProbe::Variant(Lifecycle, AlternateOrder),
            "crates/goldens/src/lifecycle.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d2-004",
            RuntimeProbe::Family(Lifecycle),
            "crates/goldens/src/lifecycle.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d2-005",
            RuntimeProbe::Family(Lifecycle),
            "crates/goldens/src/lifecycle.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d2-006",
            RuntimeProbe::Variant(Versioning, Namespace),
            "crates/goldens/src/versioning.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d2-007",
            RuntimeProbe::Variant(ObjectLock, MissingField),
            "crates/goldens/src/object_lock.rs::corpus_evidence",
        ),
        CaseDeclaration::external(
            "g-d2-008",
            "crates/ecstore/src/store/mod.rs::ENABLED_VERSIONING_CONFIG",
            "ac3966d7b1da55987199602ffbe66d5d506b874dbfd2c041627e9ebfedf407b8",
        ),
        CaseDeclaration::external(
            "g-d2-009",
            "crates/ecstore/src/store/mod.rs::ENABLED_OBJECT_LOCK_CONFIG",
            "ac3966d7b1da55987199602ffbe66d5d506b874dbfd2c041627e9ebfedf407b8",
        ),
        CaseDeclaration::passed("g-d3-001", RuntimeProbe::AllFamilies, "crates/goldens/src/four_way.rs::run_four_way_all"),
        CaseDeclaration::passed(
            "g-d3-002",
            RuntimeProbe::Family(Lifecycle),
            "crates/goldens/src/lifecycle.rs::corpus_evidence",
        ),
        CaseDeclaration::external(
            "g-d3-003",
            "crates/ecstore/src/bucket/metadata_sys.rs::g_d3_003_new_writer_replication_loads_without_fail_closed_state",
            "1f71a45dba84034653cf40293a5ffb258e3de8971d7bf13770ab1d0aeb7a5c9d",
        ),
        CaseDeclaration::external(
            "g-d3-004",
            "crates/ecstore/src/bucket/metadata_sys.rs::g_d3_004_new_writer_metadata_blob_keeps_legacy_header_and_configs",
            "1f71a45dba84034653cf40293a5ffb258e3de8971d7bf13770ab1d0aeb7a5c9d",
        ),
        CaseDeclaration::external(
            "g-d3-005",
            "rustfs/src/admin/handlers/bucket_meta.rs::g_d3_005_new_writer_backup_payloads_pass_old_import_validators",
            "db41d64e021753e2efd4743de471674b451ef6e92ee3883695abb73603462eb8",
        ),
        CaseDeclaration::passed("g-d4-001", RuntimeProbe::AllFamilies, "crates/goldens/src/historical_writer.rs::append"),
        CaseDeclaration::passed(
            "g-d4-002",
            RuntimeProbe::Variant(Replication, UnknownAttribute),
            "crates/goldens/src/replication.rs::replication_corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d4-003",
            RuntimeProbe::Variant(Lifecycle, AlternateOrder),
            "crates/goldens/src/lifecycle.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d4-004",
            RuntimeProbe::Variant(ObjectLock, DuplicateField),
            "crates/goldens/src/object_lock.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d4-005",
            RuntimeProbe::Variant(Replication, UnknownScalar),
            "crates/goldens/src/replication.rs::replication_corpus_evidence",
        ),
        CaseDeclaration::passed("g-d5-001", RuntimeProbe::AllFamilies, "crates/goldens/src/historical_writer.rs::append"),
        CaseDeclaration::passed(
            "g-d5-002",
            RuntimeProbe::Variant(Versioning, Extension),
            "crates/goldens/src/versioning.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d5-003",
            RuntimeProbe::Variant(ObjectLock, MissingField),
            "crates/goldens/src/object_lock.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d5-004",
            RuntimeProbe::Variant(Lifecycle, MissingField),
            "crates/goldens/src/lifecycle.rs::corpus_evidence",
        ),
        CaseDeclaration::passed(
            "g-d5-005",
            RuntimeProbe::Family(Replication),
            "crates/goldens/src/replication/writable_fields.rs::g_d5_005_every_replication_writable_path_reaches_a_real_dto_field",
        ),
        CaseDeclaration::external(
            "g-key-001",
            "crates/filemeta/src/filemeta.rs::persisted_metadata_keys_are_byte_stable",
            "fd8b110021434941d00e6506f6346be48257f8489276833cf7d0503db8fd5614",
        ),
        CaseDeclaration::external(
            "g-key-002",
            "crates/ecstore/src/bucket/object_lock/objectlock.rs::persisted_compliance_lock_metadata_remains_effective",
            "53f42a1df3e84eb5c631743ee3368a0bec8bd8c2300ba8dc8fc12c1574696209",
        ),
        CaseDeclaration::external(
            "g-key-003",
            "crates/filemeta/src/filemeta.rs::restored_object_keeps_using_data_dir",
            "fd8b110021434941d00e6506f6346be48257f8489276833cf7d0503db8fd5614",
        ),
        CaseDeclaration::external(
            "g-key-004",
            "crates/filemeta/src/filemeta.rs::transition_complete_object_does_not_use_data_dir",
            "fd8b110021434941d00e6506f6346be48257f8489276833cf7d0503db8fd5614",
        ),
        CaseDeclaration::external(
            "g-zip-001",
            "rustfs/src/admin/handlers/bucket_meta.rs::g_zip_001_002_003_use_real_admin_archive_and_persistence_paths",
            "db41d64e021753e2efd4743de471674b451ef6e92ee3883695abb73603462eb8",
        ),
        CaseDeclaration::external(
            "g-zip-002",
            "rustfs/src/admin/handlers/bucket_meta.rs::g_zip_001_002_003_use_real_admin_archive_and_persistence_paths",
            "db41d64e021753e2efd4743de471674b451ef6e92ee3883695abb73603462eb8",
        ),
        CaseDeclaration::external(
            "g-zip-003",
            "rustfs/src/admin/handlers/bucket_meta.rs::g_zip_001_002_003_use_real_admin_archive_and_persistence_paths",
            "db41d64e021753e2efd4743de471674b451ef6e92ee3883695abb73603462eb8",
        ),
    ]
}

fn validate_registry(
    rows: &[CaseDeclaration],
    observations: &RuntimeObservations,
) -> Result<AcceptanceCensusReport, AcceptanceCensusError> {
    let expected = EXPECTED_CASE_IDS.into_iter().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for row in rows {
        if !expected.contains(row.id) {
            return Err(AcceptanceCensusError::ExtraCase(row.id));
        }
        if !seen.insert(row.id) {
            return Err(AcceptanceCensusError::DuplicateCase(row.id));
        }
    }
    for id in EXPECTED_CASE_IDS {
        if !seen.contains(id) {
            return Err(AcceptanceCensusError::MissingCase(id));
        }
    }

    let canonical = production_registry();
    let mut reports = Vec::with_capacity(rows.len());
    for row in rows {
        let required_blocker = required_blocker(row.id, observations);
        let status = match row.status {
            "passed" => {
                if required_blocker.is_some() {
                    return Err(AcceptanceCensusError::BlockedCasePassed(row.id));
                }
                let probe = row.probe.ok_or(AcceptanceCensusError::ProbeFailed {
                    id: row.id,
                    reason: "passed row has no evidence probe".to_owned(),
                })?;
                observations
                    .evaluate(probe, row.source_ref)
                    .map_err(|reason| AcceptanceCensusError::ProbeFailed { id: row.id, reason })?;
                AcceptanceCaseStatus::Passed
            }
            "blocked" => {
                let issue = row.issue.ok_or(AcceptanceCensusError::InvalidBlocker(row.id))?;
                if required_blocker != Some(issue) || row.probe.is_some() {
                    return Err(AcceptanceCensusError::InvalidBlocker(row.id));
                }
                AcceptanceCaseStatus::Blocked { issue }
            }
            status => return Err(AcceptanceCensusError::UnknownStatus { id: row.id, status }),
        };
        if row.source_ref.trim().is_empty() || row.source_ref.contains("generated/") {
            return Err(AcceptanceCensusError::ProbeFailed {
                id: row.id,
                reason: "source_ref must be non-generated and non-empty".to_owned(),
            });
        }
        if canonical.iter().find(|expected| expected.id == row.id) != Some(row) {
            return Err(AcceptanceCensusError::WrongBinding(row.id));
        }
        reports.push(AcceptanceCaseReport {
            id: row.id,
            status,
            source_ref: row.source_ref,
        });
    }
    reports.sort_by_key(|report| EXPECTED_CASE_IDS.iter().position(|candidate| *candidate == report.id));
    Ok(AcceptanceCensusReport {
        cases: reports,
        absent_source: observations.absent_source().map(PersistenceSource::slug),
    })
}

/// The issue a row may legitimately be blocked on, given what was actually observed.
///
/// `g-d4-001` and `g-d5-001` are blocked on rustfs/backlog#2096 only while an approved corpus
/// source is genuinely absent. The moment the historical writer matrix lands, this returns
/// `None` for them and a still-blocked row becomes [`AcceptanceCensusError::InvalidBlocker`] —
/// which is what stops "source absent" and "source present" from producing the same verdict.
fn required_blocker(id: &str, observations: &RuntimeObservations) -> Option<&'static str> {
    match id {
        "g-d1-003" => Some(ISSUE_2104),
        id if SOURCE_DEPENDENT_CASES.contains(&id) => observations.absent_source().map(|_| ISSUE_2096),
        _ => None,
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn variant_report_name(variant: CorpusVariant) -> &'static str {
    match variant {
        CorpusVariant::Canonical => "canonical",
        CorpusVariant::EmptyElement => "empty-element",
        CorpusVariant::MissingField => "missing-field",
        CorpusVariant::UnknownTopLevel => "unknown-top-level",
        CorpusVariant::UnknownNested => "unknown-nested",
        CorpusVariant::UnknownAttribute => "unknown-attribute",
        CorpusVariant::Namespace => "namespace",
        CorpusVariant::AlternateOrder => "alternate-order",
        CorpusVariant::DuplicateField => "duplicate-field",
        CorpusVariant::UnknownScalar => "unknown-scalar",
        CorpusVariant::LargeValue => "large-value",
        CorpusVariant::Bom => "bom",
        CorpusVariant::Crlf => "crlf",
        CorpusVariant::Unicode => "unicode",
        CorpusVariant::TimestampPrecision => "timestamp-precision",
        CorpusVariant::Extension => "extension",
        CorpusVariant::BodyLiteral => "body-literal",
        CorpusVariant::AttributeOrder => "attribute-order",
        CorpusVariant::MalformedDocument => "malformed-document",
    }
}

#[cfg(test)]
mod tests;
