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

//! Per-revision migration admission: the whole corpus measured under every pinned s3s oracle.
//!
//! Responsible for: running the aggregate D1-D5 execution and re-reading every rejected corpus
//! sample under each [`OracleRevision`], then matching every refusal boundary that moved against
//! the registered findings in both directions. NOT responsible for: the 39-case P9-01 census, which
//! stays baseline evidence; defining samples; or deciding production decoder behavior.
//! Upstream: `four_way::run_four_way_all`, the family corpus evidence, and the compat revision
//! selector. Downstream: `corpus-report` and its strict migration gate.
//!
//! The rejected corpus is defined against the baseline: every rejected sample is one the baseline
//! and the production decoder both refuse. A later revision that reads such a sample makes the
//! production decoder stricter than that revision, which is a D4 gap for exactly the builds an
//! operator migrates from or rolls back to.
//!
//! The accepted corpus has one per-revision rule. A sample first written by a later revision
//! (today: `Rule/BlockedEncryptionTypes`, s3s `bdcb6259` and later, rustfs/gateway#740) runs
//! D1-D5 under that revision and every later one, and is measured as a widening under an earlier
//! one. Every revision must account for the same samples, and each must widen exactly the samples
//! it predates — so a selector stuck on the baseline cannot pass as a later revision.

use core::fmt;

use rustfs_gateway_types::compat::{
    CompatCodecError, OracleRevision, parse_s3s_accelerate, parse_s3s_bucket_encryption, parse_s3s_bucket_logging,
    parse_s3s_cors, parse_s3s_lifecycle, parse_s3s_notification, parse_s3s_object_lock, parse_s3s_public_access_block,
    parse_s3s_replication, parse_s3s_request_payment, parse_s3s_tagging, parse_s3s_versioning, parse_s3s_website, with_oracle,
};
use rustfs_gateway_types::cors_tagging::{parse_cors, parse_tagging};
use rustfs_gateway_types::persistence::{
    parse_accelerate, parse_bucket_encryption, parse_bucket_logging, parse_lifecycle, parse_notification, parse_object_lock,
    parse_public_access_block, parse_replication, parse_request_payment, parse_versioning, parse_website,
};

use crate::{ConfigKind, FourWayRunError, FourWayRunReport, all_family_corpus_evidence, bucket_encryption, run_four_way_all};

/// Every refusal boundary known to move under a non-baseline revision. Each entry is a finding
/// with a tracking issue, not an exemption: while one is listed, strict admission stays held.
///
/// Empty since rustfs/gateway#740 made the production decoder carry `BlockedEncryptionTypes`:
/// its witness moved from the rejected corpus to the revision-scoped accepted samples.
const FINDINGS: [OracleFinding; 0] = [];

/// What the selected old revision did with one rejected corpus sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OldReading {
    /// The old codec refused the bytes, as the rejected corpus requires.
    Refused,
    /// The old codec read the bytes.
    Read,
}

impl fmt::Display for OldReading {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused => formatter.write_str("refuses"),
            Self::Read => formatter.write_str("reads"),
        }
    }
}

/// One rejected corpus sample whose refusal did not hold under a revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleDivergence {
    /// Persisted XML family of the sample.
    pub kind: ConfigKind,
    /// SHA-256 of the sample bytes.
    pub sha256: String,
    /// What the revision did instead of refusing.
    pub old: OldReading,
}

/// A registered, still-open refusal boundary that moved under one or more revisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleFinding {
    /// Stable finding identifier.
    pub id: &'static str,
    /// Every revision under which the boundary moves; each must reproduce it.
    pub revisions: &'static [OracleRevision],
    /// Persisted XML family of the witness sample.
    pub kind: ConfigKind,
    /// SHA-256 of the rejected witness sample.
    pub sha256: &'static str,
    /// The exact reading each listed revision must observe.
    pub old: OldReading,
    /// Issue that owns the resolution.
    pub tracking: &'static str,
}

/// One revision's observed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleObservation {
    /// Revision every old codec answered from.
    pub oracle: OracleRevision,
    /// The aggregate D1-D5 execution under this revision.
    pub four_way: FourWayRunReport,
    /// Rejected corpus samples re-read under this revision.
    pub rejected_reread: usize,
    /// Rejected samples this revision did not refuse.
    pub divergences: Vec<OracleDivergence>,
}

/// Validated admission evidence across every pinned revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleAdmissionReport {
    observations: Vec<OracleObservation>,
    open: Vec<(OracleRevision, OracleFinding)>,
}

impl OracleAdmissionReport {
    /// One observation per revision, baseline first.
    #[must_use]
    pub fn observations(&self) -> &[OracleObservation] {
        &self.observations
    }

    /// Every registered finding each revision reproduced.
    #[must_use]
    pub fn open_findings(&self) -> &[(OracleRevision, OracleFinding)] {
        &self.open
    }

    /// Renders one line per revision and one per open finding.
    #[must_use]
    pub fn render(&self) -> String {
        let mut output = format!(
            "oracle admission: revisions={} open-findings={}\n",
            self.observations.len(),
            self.open.len()
        );
        for observation in &self.observations {
            output.push_str(&format!(
                "oracle {} build={}: d1-d5 samples={} widened={} families={} rejected-reread={} moved-refusals={}\n",
                observation.oracle,
                observation.oracle.rustfs_build(),
                observation.four_way.sample_count,
                observation.four_way.widened_count,
                observation.four_way.families.len(),
                observation.rejected_reread,
                observation.divergences.len(),
            ));
        }
        for (oracle, finding) in &self.open {
            output.push_str(&format!(
                "finding {} oracle={oracle} family={} sample={} old={} new=refuses tracking={}\n",
                finding.id,
                finding.kind.report_name(),
                finding.sha256,
                finding.old,
                finding.tracking,
            ));
        }
        output
    }
}

/// Admission evidence that is invalid, or valid but still held by open findings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleAdmissionError {
    /// D1-D5 failed on an accepted sample under one revision.
    FourWay {
        /// Revision the failure was observed under.
        oracle: OracleRevision,
        /// The first family-scoped failure.
        error: FourWayRunError,
    },
    /// The corpus could not be rebuilt under one revision.
    Corpus {
        /// Revision the corpus was rebuilt under.
        oracle: OracleRevision,
        /// The coverage failure.
        reason: String,
    },
    /// The production decoder read a rejected sample: the corpus contract itself is broken.
    NewDecoderRead {
        /// Revision selected while the sample was re-read.
        oracle: OracleRevision,
        /// Persisted XML family of the sample.
        kind: ConfigKind,
        /// SHA-256 of the sample.
        sha256: String,
    },
    /// A revision was observed zero times or more than once.
    RevisionNotObservedOnce(OracleRevision),
    /// A revision executed a different D1-D5 sample set than the baseline.
    SampleCountDrift {
        /// Revision whose counts differ.
        oracle: OracleRevision,
        /// Per-family counts under the baseline.
        expected: Vec<(ConfigKind, usize)>,
        /// Per-family counts under `oracle`.
        found: Vec<(ConfigKind, usize)>,
    },
    /// A revision widened a different number of samples in a family than it predates: a widening
    /// counted as a D1-D5 pass, or a revision measured with another revision's codec.
    WideningDrift {
        /// Revision whose widening count differs.
        oracle: OracleRevision,
        /// Family whose count differs.
        kind: ConfigKind,
        /// Revision-scoped samples of the family the revision predates.
        expected: usize,
        /// Samples the revision widened.
        found: usize,
    },
    /// A moved refusal boundary no finding registers.
    UnregisteredDivergence {
        /// Revision that read the sample.
        oracle: OracleRevision,
        /// The unregistered observation.
        divergence: OracleDivergence,
    },
    /// A registered finding its revision no longer reproduces.
    StaleFinding {
        /// Revision the finding names.
        oracle: OracleRevision,
        /// The finding that was not reproduced.
        id: &'static str,
    },
    /// A revision reproduced a finding with a different reading than registered.
    ReadingMismatch {
        /// Revision that read the sample.
        oracle: OracleRevision,
        /// The finding whose reading differs.
        id: &'static str,
        /// Registered reading.
        registered: OldReading,
        /// Observed reading.
        observed: OldReading,
    },
    /// Every observation is valid, and registered findings still hold admission.
    FindingsOpen(Vec<(OracleRevision, &'static str, &'static str)>),
}

impl fmt::Display for OracleAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FourWay { oracle, error } => write!(formatter, "D1-D5 failed under {oracle}: {error}"),
            Self::Corpus { oracle, reason } => write!(formatter, "corpus rebuild failed under {oracle}: {reason}"),
            Self::NewDecoderRead { oracle, kind, sha256 } => write!(
                formatter,
                "production decoder read rejected {} sample {sha256} (selected {oracle})",
                kind.report_name()
            ),
            Self::RevisionNotObservedOnce(oracle) => write!(formatter, "{oracle} must be observed exactly once"),
            Self::SampleCountDrift { oracle, expected, found } => {
                write!(formatter, "{oracle} executed D1-D5 counts {found:?}, baseline executed {expected:?}")
            }
            Self::WideningDrift {
                oracle,
                kind,
                expected,
                found,
            } => write!(
                formatter,
                "{oracle} widened {found} {} samples, but predates exactly {expected}",
                kind.report_name()
            ),
            Self::UnregisteredDivergence { oracle, divergence } => write!(
                formatter,
                "{oracle} {} rejected {} sample {} and no finding registers it",
                divergence.old,
                divergence.kind.report_name(),
                divergence.sha256
            ),
            Self::StaleFinding { oracle, id } => write!(formatter, "{oracle} no longer reproduces finding {id}"),
            Self::ReadingMismatch {
                oracle,
                id,
                registered,
                observed,
            } => write!(formatter, "{oracle} {observed} for finding {id}, registered as {registered}"),
            Self::FindingsOpen(open) => {
                write!(formatter, "oracle admission held by {} open findings:", open.len())?;
                for (oracle, id, tracking) in open {
                    write!(formatter, " {oracle} {id} ({tracking})")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for OracleAdmissionError {}

/// Observes every pinned revision and validates the moved refusal boundaries against the registered
/// findings, keeping open findings visible rather than failing on them.
///
/// # Errors
///
/// Returns the first D1-D5, corpus, count, unregistered, stale, or mismatched observation.
pub fn build_oracle_admission() -> Result<OracleAdmissionReport, OracleAdmissionError> {
    let observations = OracleRevision::ALL.into_iter().map(observe).collect::<Result<Vec<_>, _>>()?;
    validate(&observations, &FINDINGS)
}

/// Requires valid admission evidence with no open finding under any revision.
///
/// # Errors
///
/// Returns [`OracleAdmissionError::FindingsOpen`] while any registered finding is reproduced, or
/// the same fail-closed validation errors as [`build_oracle_admission`].
pub fn require_oracle_admission() -> Result<OracleAdmissionReport, OracleAdmissionError> {
    admission_verdict(build_oracle_admission()?)
}

fn admission_verdict(report: OracleAdmissionReport) -> Result<OracleAdmissionReport, OracleAdmissionError> {
    if report.open.is_empty() {
        Ok(report)
    } else {
        Err(OracleAdmissionError::FindingsOpen(
            report
                .open
                .iter()
                .map(|(oracle, finding)| (*oracle, finding.id, finding.tracking))
                .collect(),
        ))
    }
}

fn observe(oracle: OracleRevision) -> Result<OracleObservation, OracleAdmissionError> {
    with_oracle(oracle, || {
        let four_way = run_four_way_all().map_err(|error| OracleAdmissionError::FourWay { oracle, error })?;
        let families = all_family_corpus_evidence().map_err(|error| OracleAdmissionError::Corpus {
            oracle,
            reason: error.to_string(),
        })?;
        let mut rejected_reread = 0;
        let mut divergences = Vec::new();
        for family in &families {
            let kind = family.kind();
            for (bytes, sha256) in family.rejected_samples() {
                rejected_reread += 1;
                if new_refusal(kind, bytes).is_none() {
                    return Err(OracleAdmissionError::NewDecoderRead {
                        oracle,
                        kind,
                        sha256: sha256.to_owned(),
                    });
                }
                let old = old_reading(kind, bytes);
                if old != OldReading::Refused {
                    divergences.push(OracleDivergence {
                        kind,
                        sha256: sha256.to_owned(),
                        old,
                    });
                }
            }
        }
        Ok(OracleObservation {
            oracle,
            four_way,
            rejected_reread,
            divergences,
        })
    })
}

fn reading<T>(result: Result<T, CompatCodecError>) -> OldReading {
    match result {
        Ok(_) => OldReading::Read,
        Err(_) => OldReading::Refused,
    }
}

/// What the selected old revision does with `bytes` as a `kind` document.
pub(crate) fn old_reading(kind: ConfigKind, bytes: &[u8]) -> OldReading {
    match kind {
        ConfigKind::Accelerate => reading(parse_s3s_accelerate(bytes)),
        ConfigKind::Versioning => reading(parse_s3s_versioning(bytes)),
        ConfigKind::ObjectLock => reading(parse_s3s_object_lock(bytes)),
        ConfigKind::Lifecycle => reading(parse_s3s_lifecycle(bytes)),
        ConfigKind::BucketEncryption => reading(parse_s3s_bucket_encryption(bytes)),
        ConfigKind::Notification => reading(parse_s3s_notification(bytes)),
        ConfigKind::PublicAccessBlock => reading(parse_s3s_public_access_block(bytes)),
        ConfigKind::RequestPayment => reading(parse_s3s_request_payment(bytes)),
        ConfigKind::Cors => reading(parse_s3s_cors(bytes)),
        ConfigKind::Tagging => reading(parse_s3s_tagging(bytes)),
        ConfigKind::Logging => reading(parse_s3s_bucket_logging(bytes)),
        ConfigKind::Website => reading(parse_s3s_website(bytes)),
        ConfigKind::Replication => reading(parse_s3s_replication(bytes)),
    }
}

/// How the production decoder refuses `bytes` as a `kind` document, rendered with `Debug`, or
/// `None` when it reads them.
pub(crate) fn new_refusal(kind: ConfigKind, bytes: &[u8]) -> Option<String> {
    fn refusal<T, E: fmt::Debug>(result: Result<T, E>) -> Option<String> {
        result.err().map(|error| format!("{error:?}"))
    }

    match kind {
        ConfigKind::Accelerate => refusal(parse_accelerate(bytes)),
        ConfigKind::Versioning => refusal(parse_versioning(bytes)),
        ConfigKind::ObjectLock => refusal(parse_object_lock(bytes)),
        ConfigKind::Lifecycle => refusal(parse_lifecycle(bytes)),
        ConfigKind::BucketEncryption => refusal(parse_bucket_encryption(bytes)),
        ConfigKind::Notification => refusal(parse_notification(bytes)),
        ConfigKind::PublicAccessBlock => refusal(parse_public_access_block(bytes)),
        ConfigKind::RequestPayment => refusal(parse_request_payment(bytes)),
        ConfigKind::Cors => refusal(parse_cors(bytes)),
        ConfigKind::Tagging => refusal(parse_tagging(bytes)),
        ConfigKind::Logging => refusal(parse_bucket_logging(bytes)),
        ConfigKind::Website => refusal(parse_website(bytes)),
        ConfigKind::Replication => refusal(parse_replication(bytes)),
    }
}

/// Every accepted sample a revision accounted for, per family: run through D1-D5 or widened.
fn family_counts(report: &FourWayRunReport) -> Vec<(ConfigKind, usize)> {
    report
        .families
        .iter()
        .map(|family| (family.kind, family.sample_count + family.widened))
        .collect()
}

/// The per-revision rule: a revision widens exactly the revision-scoped samples it predates.
fn widening_drift(observation: &OracleObservation) -> Option<OracleAdmissionError> {
    observation.four_way.families.iter().find_map(|family| {
        let expected = match family.kind {
            ConfigKind::BucketEncryption => bucket_encryption::widened_under(observation.oracle),
            _ => 0,
        };
        (family.widened != expected).then_some(OracleAdmissionError::WideningDrift {
            oracle: observation.oracle,
            kind: family.kind,
            expected,
            found: family.widened,
        })
    })
}

/// Validates observations against a registry, separate from observation so every rejection can be
/// proved with synthetic registries and relabelled observations.
fn validate(
    observations: &[OracleObservation],
    registry: &[OracleFinding],
) -> Result<OracleAdmissionReport, OracleAdmissionError> {
    for oracle in OracleRevision::ALL {
        if observations.iter().filter(|observation| observation.oracle == oracle).count() != 1 {
            return Err(OracleAdmissionError::RevisionNotObservedOnce(oracle));
        }
    }
    let expected = observations
        .iter()
        .find(|observation| observation.oracle == OracleRevision::Baseline)
        .map(|baseline| family_counts(&baseline.four_way))
        .ok_or(OracleAdmissionError::RevisionNotObservedOnce(OracleRevision::Baseline))?;
    let mut open = Vec::new();
    for observation in observations {
        let oracle = observation.oracle;
        let found = family_counts(&observation.four_way);
        if found != expected {
            return Err(OracleAdmissionError::SampleCountDrift { oracle, expected, found });
        }
        if let Some(drift) = widening_drift(observation) {
            return Err(drift);
        }
        for divergence in &observation.divergences {
            let finding = registry
                .iter()
                .find(|finding| {
                    finding.revisions.contains(&oracle) && finding.kind == divergence.kind && finding.sha256 == divergence.sha256
                })
                .ok_or_else(|| OracleAdmissionError::UnregisteredDivergence {
                    oracle,
                    divergence: divergence.clone(),
                })?;
            if finding.old != divergence.old {
                return Err(OracleAdmissionError::ReadingMismatch {
                    oracle,
                    id: finding.id,
                    registered: finding.old,
                    observed: divergence.old,
                });
            }
            open.push((oracle, *finding));
        }
        for finding in registry.iter().filter(|finding| finding.revisions.contains(&oracle)) {
            let reproduced = observation
                .divergences
                .iter()
                .any(|divergence| divergence.kind == finding.kind && divergence.sha256 == finding.sha256);
            if !reproduced {
                return Err(OracleAdmissionError::StaleFinding { oracle, id: finding.id });
            }
        }
    }
    Ok(OracleAdmissionReport {
        observations: observations.to_vec(),
        open,
    })
}

#[cfg(test)]
mod tests;
