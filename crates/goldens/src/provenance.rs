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

//! The closed set of approved persisted-metadata corpus sources, and the fail-closed census
//! that refuses to report closure while one of them is absent.
//!
//! Responsible for: naming the four approved sources of rustfs/backlog#1733 §4.4, requiring a
//! writer name and an exact writer version on the two tiers that carry one, and binding every
//! registered source to concrete corpus bytes by digest. NOT responsible for: collecting
//! samples, owning family evidence, or running D1-D5 — an absent source is reported here, never
//! repaired here. Upstream: the family-owned corpus report and the writer vocabulary in
//! `rustfs_gateway_corpus::store`. Downstream: the P9-01 acceptance census and its closure gate.
//!
//! The reason this module exists at all is that "not enough samples yet" and "every approved
//! source is present and passing" produce the same green line from a harness that only counts
//! samples. rustfs/backlog#2096 removed source (d) — real-customer cluster export — and replaced
//! it with (d′), a historical writer matrix this project runs itself; the replacement is only
//! worth anything if its absence is loud.

use std::collections::BTreeSet;

use rustfs_gateway_corpus::store::check_writer;

use crate::{CorpusReport, minio_migration, source_a_lifecycle, source_b_mc};

/// One approved source of persisted-metadata corpus bytes.
///
/// The set is closed on purpose. rustfs/backlog#1763 forbids production traffic and
/// rustfs/backlog#2096 removed customer cluster exports, so a byte whose source is not one of
/// these four has no admissible provenance and must not enter the corpus.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PersistenceSource {
    /// (a) A fixture already committed to a RustFS or gateway repository.
    RepositoryFixture,
    /// (b) A capture taken by driving a real S3 client against a disposable cluster.
    ClientMatrix,
    /// (c) A MinIO cluster this project stands up, writes to, then migrates and exports.
    ///
    /// Still the most valuable tier: it is the only source that produces MinIO's
    /// `DelMarkerExpiration` extension and its bare-literal body shapes.
    MinioMigrationExport,
    /// (d′) Metadata written by historical writer binaries this project runs itself.
    ///
    /// Replaces the withdrawn source (d), real-customer cluster export. Structural shape is a
    /// function of the writer, not of the customer, so the coverage target here is *writer
    /// versions*, not sample volume.
    HistoricalWriterMatrix,
}

impl PersistenceSource {
    /// Every approved source, in §4.4 order.
    pub const ALL: [Self; 4] = [
        Self::RepositoryFixture,
        Self::ClientMatrix,
        Self::MinioMigrationExport,
        Self::HistoricalWriterMatrix,
    ];

    /// Stable report label for this source.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::RepositoryFixture => "a-repository-fixture",
            Self::ClientMatrix => "b-client-matrix",
            Self::MinioMigrationExport => "c-minio-migration-export",
            Self::HistoricalWriterMatrix => "d-prime-historical-writer-matrix",
        }
    }

    /// Whether admission requires a named writer at an exact version.
    ///
    /// True for the two tiers whose evidence *is* the writer: (c) and (d′) exist to capture what
    /// a specific MinIO or RustFS build writes, so a sample that cannot name that build proves
    /// nothing about it. (a) and (b) are traced to a repository path or a client capture
    /// instead, and §8 rule 5 already refuses an untraceable sample in either.
    #[must_use]
    pub const fn requires_writer(self) -> bool {
        matches!(self, Self::MinioMigrationExport | Self::HistoricalWriterMatrix)
    }
}

/// One registered source of persisted-metadata corpus bytes.
///
/// Crate-internal: a caller outside this crate reads the census, it does not register a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceRegistration {
    /// Which approved source this row admits bytes under.
    pub(crate) source: PersistenceSource,
    /// Writer that produced the bytes, spelled as in `WRITER_ALLOWLIST`. Required by (c)/(d′).
    pub(crate) writer: Option<&'static str>,
    /// Exact writer version. Required by (c)/(d′).
    pub(crate) version: Option<&'static str>,
    /// Digests of samples that witness this source in the built corpus.
    ///
    /// These prove the source is *present*, not that it is complete: a registration that names
    /// no digest, or a digest the corpus does not contain, is a paper claim and is refused.
    pub(crate) witness_digests: &'static [&'static str],
    /// Where the registered bytes come from, for a reader auditing the row.
    pub(crate) reference: &'static str,
}

/// Every persisted-metadata source this repository currently admits bytes under.
///
/// (d′) has no row yet. Collecting it means running historical RustFS and MinIO binaries and is
/// its own task; until it lands, [`require_persistence_sources`] refuses closure by name.
const MINIO_MIGRATION_WITNESSES: &[&str] = &[
    minio_migration::LIFECYCLE_SHA256,
    minio_migration::OBJECT_LOCK_SHA256,
    minio_migration::REPLICATION_SHA256,
    minio_migration::VERSIONING_SHA256,
    minio_migration::BUCKET_ENCRYPTION_SHA256,
    minio_migration::TAGGING_SHA256,
    minio_migration::NOTIFICATION_SHA256,
];

const SOURCE_REGISTRY: &[SourceRegistration] = &[
    SourceRegistration {
        source: PersistenceSource::RepositoryFixture,
        writer: None,
        version: None,
        witness_digests: &[source_a_lifecycle::LIFECYCLE_SHA256],
        reference: "crates/goldens/src/source_a_lifecycle.rs::lifecycle_case",
    },
    SourceRegistration {
        source: PersistenceSource::ClientMatrix,
        writer: None,
        version: None,
        witness_digests: &[source_b_mc::CORS_SHA256],
        reference: "crates/goldens/src/source_b_mc.rs::cors_case",
    },
    SourceRegistration {
        source: PersistenceSource::MinioMigrationExport,
        writer: Some("minio"),
        version: Some(minio_migration::VERSION),
        witness_digests: MINIO_MIGRATION_WITNESSES,
        reference: "crates/goldens/src/minio_migration.rs",
    },
];

/// One validated source row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReport {
    /// Approved source this row admits bytes under.
    pub source: PersistenceSource,
    /// Writer identity, when the tier carries one.
    pub writer: Option<(&'static str, &'static str)>,
    /// Number of corpus samples matched by this row's witness digests.
    pub witnessed_samples: usize,
}

/// Validated persisted-metadata source registrations, with absent sources rendered explicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistenceSourceReport {
    rows: Vec<SourceReport>,
}

impl PersistenceSourceReport {
    /// Validated source rows, in §4.4 order.
    #[must_use]
    pub fn rows(&self) -> &[SourceReport] {
        &self.rows
    }

    /// Deterministic human-readable source census.
    #[must_use]
    pub fn render(&self) -> String {
        let mut output = format!(
            "persisted metadata sources: {}/{} approved sources present\n",
            self.rows.len(),
            PersistenceSource::ALL.len()
        );
        for row in &self.rows {
            let writer = row
                .writer
                .map_or_else(|| "writer=n/a".to_owned(), |(name, version)| format!("writer={name}@{version}"));
            output.push_str(&format!("{}: {writer} witnessed={}\n", row.source.slug(), row.witnessed_samples));
        }
        for source in PersistenceSource::ALL {
            if !self.rows.iter().any(|row| row.source == source) {
                output.push_str(&format!("{}: absent\n", source.slug()));
            }
        }
        output
    }
}

/// Why the approved-source census could not be validated.
///
/// Every variant names the source it is about. A diagnosis that says only "blocked" costs the
/// next reader the whole investigation again, and a harness that cannot tell "the source is
/// absent" from "the source is present and passing" is the check-that-cannot-fail this
/// repository keeps writing guards against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistenceSourceError {
    /// An approved source has no registration at all. The harness must not pass without it.
    SourceAbsent(PersistenceSource),
    /// A source was registered more than once.
    DuplicateSource(PersistenceSource),
    /// A tier that requires a writer named none, or named one outside the writer allowlist, or
    /// named a version that pins no reproducible build.
    UntraceableWriter {
        /// Source whose registration is untraceable.
        source: PersistenceSource,
        /// The refusal from the shared writer vocabulary.
        reason: String,
    },
    /// A tier that carries no writer identity declared one anyway.
    UnexpectedWriter(PersistenceSource),
    /// A registration named no witness digest, so nothing binds it to real bytes.
    NoWitness(PersistenceSource),
    /// A registration named a digest the built corpus does not contain.
    WitnessNotInCorpus {
        /// Source whose registration is unbacked.
        source: PersistenceSource,
        /// The digest that matched no corpus sample.
        sha256: &'static str,
    },
    /// A witnessed sample does not record the writer its source registration claims.
    WitnessWriterMismatch {
        /// Source whose registration disagrees with the sample.
        source: PersistenceSource,
        /// The witness digest.
        sha256: &'static str,
        /// The writer identity the sample itself records.
        recorded: String,
    },
}

impl core::fmt::Display for PersistenceSourceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SourceAbsent(source) => write!(
                formatter,
                "approved persisted-metadata source {} is absent; the harness fails closed rather than \
                 passing on the remaining samples",
                source.slug()
            ),
            Self::DuplicateSource(source) => write!(formatter, "{} is registered more than once", source.slug()),
            Self::UntraceableWriter { source, reason } => write!(formatter, "{}: {reason}", source.slug()),
            Self::UnexpectedWriter(source) => {
                write!(formatter, "{} carries no writer identity but declared one", source.slug())
            }
            Self::NoWitness(source) => write!(formatter, "{} names no witness digest", source.slug()),
            Self::WitnessNotInCorpus { source, sha256 } => {
                write!(formatter, "{} names witness {sha256}, which no corpus sample carries", source.slug())
            }
            Self::WitnessWriterMismatch {
                source,
                sha256,
                recorded,
            } => write!(formatter, "{} claims its writer, but witness {sha256} records {recorded}", source.slug()),
        }
    }
}

impl PersistenceSourceError {
    /// Whether this is an approved source nobody has collected yet, rather than a registration
    /// that is broken.
    ///
    /// One definition, because every caller has to make the same split and two copies of it
    /// would eventually disagree: an uncollected source is a state the census reports, and
    /// anything else is a defect in the registry that must not arrive dressed as one.
    #[must_use]
    pub const fn is_source_absent(&self) -> bool {
        matches!(self, Self::SourceAbsent(_))
    }
}

impl std::error::Error for PersistenceSourceError {}

/// Reports validated present sources and explicitly renders absent approved sources.
///
/// This is a coverage report, not a closure decision. Use [`require_persistence_sources`]
/// when every approved source must be present.
///
/// # Errors
///
/// Returns any invalid registration or witness failure; absent sources remain visible in the report.
pub fn build_persistence_source_report(corpus: &CorpusReport) -> Result<PersistenceSourceReport, PersistenceSourceError> {
    source_report(SOURCE_REGISTRY, corpus)
}

/// Validates every approved persisted-metadata source against the built corpus.
///
/// # Errors
///
/// Returns the first source-scoped failure, naming the source. An absent approved source is a
/// failure, not a smaller report.
pub fn require_persistence_sources(corpus: &CorpusReport) -> Result<PersistenceSourceReport, PersistenceSourceError> {
    validate_sources(SOURCE_REGISTRY, corpus)
}

/// The same census over an explicit registry, so a mutation test can register or withdraw a
/// source and observe that the verdict actually changes.
fn validate_sources(
    registry: &[SourceRegistration],
    corpus: &CorpusReport,
) -> Result<PersistenceSourceReport, PersistenceSourceError> {
    let report = source_report(registry, corpus)?;
    for source in PersistenceSource::ALL {
        if !report.rows.iter().any(|row| row.source == source) {
            return Err(PersistenceSourceError::SourceAbsent(source));
        }
    }
    Ok(report)
}

fn source_report(
    registry: &[SourceRegistration],
    corpus: &CorpusReport,
) -> Result<PersistenceSourceReport, PersistenceSourceError> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::with_capacity(PersistenceSource::ALL.len());
    for registration in registry {
        if !seen.insert(registration.source) {
            return Err(PersistenceSourceError::DuplicateSource(registration.source));
        }
        rows.push(validate_registration(registration, corpus)?);
    }
    rows.sort_by_key(|row| row.source);
    Ok(PersistenceSourceReport { rows })
}

fn validate_registration(
    registration: &SourceRegistration,
    corpus: &CorpusReport,
) -> Result<SourceReport, PersistenceSourceError> {
    let source = registration.source;
    let writer = match (source.requires_writer(), registration.writer, registration.version) {
        (true, Some(name), Some(version)) => {
            check_writer(name, version).map_err(|reason| PersistenceSourceError::UntraceableWriter { source, reason })?;
            Some((name, version))
        }
        (true, _, _) => {
            return Err(PersistenceSourceError::UntraceableWriter {
                source,
                reason: "the tier requires a writer name and an exact writer version, and one is missing".to_owned(),
            });
        }
        (false, None, None) => None,
        (false, _, _) => return Err(PersistenceSourceError::UnexpectedWriter(source)),
    };

    if registration.witness_digests.is_empty() || registration.reference.trim().is_empty() {
        return Err(PersistenceSourceError::NoWitness(source));
    }

    let mut witnessed = 0;
    for digest in registration.witness_digests {
        let matches = corpus
            .samples()
            .iter()
            .filter(|sample| sample.sha256 == *digest)
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return Err(PersistenceSourceError::WitnessNotInCorpus { source, sha256: digest });
        }
        if let Some((name, version)) = writer {
            for sample in &matches {
                if !sample.producer.eq_ignore_ascii_case(name) || sample.version != version {
                    return Err(PersistenceSourceError::WitnessWriterMismatch {
                        source,
                        sha256: digest,
                        recorded: format!("{}@{}", sample.producer, sample.version),
                    });
                }
            }
        }
        witnessed += matches.len();
    }

    Ok(SourceReport {
        source,
        writer,
        witnessed_samples: witnessed,
    })
}

#[cfg(test)]
mod tests;
