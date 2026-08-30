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

//! Concrete persisted-XML corpus evidence and fail-closed coverage validation.
//!
//! Responsible for: deriving coverage only from traceable accepted and rejected sample bytes.
//! NOT responsible for: owning family samples, running codecs, or claiming aggregate completeness.
//! Upstream: family-owned sample collections. Downstream: later family wiring and report slices.

use core::fmt;

use crate::{ConfigKind, GoldenSample, SampleOrigin, validate_sample};

#[cfg(test)]
mod backup_zip;

const MINIMUM_SAMPLES_PER_FAMILY: usize = 8;

/// A protocol-relevant shape represented by one concrete corpus sample.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CorpusVariant {
    /// A representative canonical value.
    Canonical,
    /// An explicit empty element or wrapper.
    EmptyElement,
    /// A required field is absent.
    MissingField,
    /// An unknown top-level element is present.
    UnknownTopLevel,
    /// An unknown nested element is present.
    UnknownNested,
    /// An unknown XML attribute is present.
    UnknownAttribute,
    /// An XML namespace declaration is present.
    Namespace,
    /// Known elements appear in a noncanonical but old-readable order.
    AlternateOrder,
    /// A scalar or wrapper is duplicated.
    DuplicateField,
    /// A string-like enum carries an unknown value.
    UnknownScalar,
    /// A value exercises the persistence-sized input boundary.
    LargeValue,
    /// The document begins with a byte-order mark.
    Bom,
    /// The document uses CRLF line endings.
    Crlf,
    /// A text value contains non-ASCII Unicode.
    Unicode,
    /// A timestamp exercises historical fractional-second precision.
    TimestampPrecision,
    /// A historical MinIO extension is present.
    Extension,
    /// A historical bare-literal body shape is present.
    BodyLiteral,
    /// Equivalent attributes appear in a different order.
    AttributeOrder,
    /// The byte stream is not a well-formed XML document.
    MalformedDocument,
}

impl CorpusVariant {
    const fn report_name(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::EmptyElement => "empty-element",
            Self::MissingField => "missing-field",
            Self::UnknownTopLevel => "unknown-top-level",
            Self::UnknownNested => "unknown-nested",
            Self::UnknownAttribute => "unknown-attribute",
            Self::Namespace => "namespace",
            Self::AlternateOrder => "alternate-order",
            Self::DuplicateField => "duplicate-field",
            Self::UnknownScalar => "unknown-scalar",
            Self::LargeValue => "large-value",
            Self::Bom => "bom",
            Self::Crlf => "crlf",
            Self::Unicode => "unicode",
            Self::TimestampPrecision => "timestamp-precision",
            Self::Extension => "extension",
            Self::BodyLiteral => "body-literal",
            Self::AttributeOrder => "attribute-order",
            Self::MalformedDocument => "malformed-document",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CorpusDisposition {
    Accepted,
    Rejected,
}

/// A traceable raw sample that both old and new family parsers must reject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedGoldenSample {
    /// Persisted XML family.
    pub kind: ConfigKind,
    /// Original bytes handed to both parsers.
    pub bytes: Vec<u8>,
    /// Traceable origin and SHA-256 of `bytes`.
    pub origin: SampleOrigin,
    /// Why this rejected boundary belongs in the corpus.
    pub notes: String,
}

/// One validated, type-erased corpus observation derived from concrete sample bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusCaseEvidence {
    kind: ConfigKind,
    disposition: CorpusDisposition,
    bytes: Vec<u8>,
    origin: SampleOrigin,
    variants: Vec<CorpusVariant>,
}

impl CorpusCaseEvidence {
    /// Derives accepted evidence from the same [`GoldenSample`] a family passes to D1-D5.
    ///
    /// # Errors
    ///
    /// Returns an invalid-evidence error for stale or incomplete provenance, or a missing-variant
    /// error when the concrete case has no coverage classification.
    pub fn accepted<T>(sample: &GoldenSample<T>, variants: &[CorpusVariant]) -> Result<Self, CorpusCoverageError> {
        validate_sample(sample.kind, sample).map_err(|error| CorpusCoverageError::InvalidEvidence {
            kind: sample.kind,
            reason: error.to_string(),
        })?;
        Self::from_parts(sample.kind, CorpusDisposition::Accepted, &sample.bytes, &sample.origin, variants)
    }

    /// Derives rejected evidence from concrete bytes carrying the same provenance contract as an
    /// accepted golden sample.
    ///
    /// # Errors
    ///
    /// Returns an invalid-evidence error for stale or incomplete provenance, or a missing-variant
    /// error when the concrete case has no coverage classification.
    pub fn rejected(sample: &RejectedGoldenSample, variants: &[CorpusVariant]) -> Result<Self, CorpusCoverageError> {
        let traceability_probe = GoldenSample {
            kind: sample.kind,
            bytes: sample.bytes.clone(),
            value: (),
            origin: sample.origin.clone(),
            notes: sample.notes.clone(),
        };
        validate_sample(sample.kind, &traceability_probe).map_err(|error| CorpusCoverageError::InvalidEvidence {
            kind: sample.kind,
            reason: error.to_string(),
        })?;
        Self::from_parts(sample.kind, CorpusDisposition::Rejected, &sample.bytes, &sample.origin, variants)
    }

    fn from_parts(
        kind: ConfigKind,
        disposition: CorpusDisposition,
        bytes: &[u8],
        origin: &SampleOrigin,
        variants: &[CorpusVariant],
    ) -> Result<Self, CorpusCoverageError> {
        if variants.is_empty() {
            return Err(CorpusCoverageError::MissingCaseVariant(kind));
        }
        Ok(Self {
            kind,
            disposition,
            bytes: bytes.to_vec(),
            origin: origin.clone(),
            variants: variants.to_vec(),
        })
    }
}

/// Concrete evidence owned by one persisted XML family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamilyCorpusEvidence {
    kind: ConfigKind,
    required_variants: Vec<CorpusVariant>,
    cases: Vec<CorpusCaseEvidence>,
}

impl FamilyCorpusEvidence {
    /// Groups concrete accepted and rejected cases under one family and its required variants.
    #[must_use]
    pub fn new(kind: ConfigKind, required_variants: Vec<CorpusVariant>, cases: Vec<CorpusCaseEvidence>) -> Self {
        Self {
            kind,
            required_variants,
            cases,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoverageRow {
    kind: ConfigKind,
    accepted: usize,
    rejected: usize,
    bytes: usize,
    variants: Vec<CorpusVariant>,
}

/// Validated coverage derived only from concrete family-owned cases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusReport {
    rows: Vec<CoverageRow>,
    requested_families: usize,
}

impl CorpusReport {
    /// Total concrete sample bytes across all validated families.
    #[must_use]
    pub fn total_size_bytes(&self) -> usize {
        self.rows.iter().map(|row| row.bytes).sum()
    }

    /// Renders deterministic accepted, rejected, and variant coverage for the requested families.
    #[must_use]
    pub fn render(&self) -> String {
        let mut output = format!(
            "persisted XML corpus: {}/{} requested families covered\n",
            self.rows.len(),
            self.requested_families
        );
        for row in &self.rows {
            let variants = row
                .variants
                .iter()
                .map(|variant| variant.report_name())
                .collect::<Vec<_>>()
                .join(",");
            output.push_str(&format!(
                "{}: accepted={} rejected={} bytes={} variants={}\n",
                row.kind.report_name(),
                row.accepted,
                row.rejected,
                row.bytes,
                variants
            ));
        }
        let accepted = self.rows.iter().map(|row| row.accepted).sum::<usize>();
        let rejected = self.rows.iter().map(|row| row.rejected).sum::<usize>();
        output.push_str(&format!(
            "total: families={} accepted={accepted} rejected={rejected} bytes={}\n",
            self.rows.len(),
            self.total_size_bytes()
        ));
        output
    }
}

/// A deterministic reason concrete corpus evidence is invalid or incomplete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorpusCoverageError {
    /// A requested family has no concrete evidence group.
    MissingFamily(ConfigKind),
    /// A family has more than one evidence group.
    DuplicateFamily(ConfigKind),
    /// The requested family list contains a duplicate.
    DuplicateRequestedFamily(ConfigKind),
    /// Evidence was supplied for a family the caller did not request.
    UnexpectedFamily(ConfigKind),
    /// A case belongs to a different family than its evidence group.
    CaseFamilyMismatch {
        /// Family owning the evidence group.
        expected: ConfigKind,
        /// Family recorded on the concrete case.
        found: ConfigKind,
    },
    /// A family has no old-readable accepted case.
    MissingAccepted(ConfigKind),
    /// A family has no pinned rejected case.
    MissingRejected(ConfigKind),
    /// A family has fewer than eight concrete accepted and rejected cases combined.
    TooFewSamples {
        /// Incomplete family.
        kind: ConfigKind,
        /// Number of concrete cases found.
        found: usize,
    },
    /// No concrete case carries a required family variant.
    MissingVariant {
        /// Incomplete family.
        kind: ConfigKind,
        /// Missing variant.
        variant: CorpusVariant,
    },
    /// Two cases in one family contain identical concrete bytes.
    DuplicateSample {
        /// Family containing the duplicate.
        kind: ConfigKind,
        /// SHA-256 recorded for the duplicate bytes.
        sha256: String,
    },
    /// Concrete bytes have stale or incomplete provenance.
    InvalidEvidence {
        /// Family recorded on the sample.
        kind: ConfigKind,
        /// Provenance validation failure.
        reason: String,
    },
    /// A concrete case has no coverage variant.
    MissingCaseVariant(ConfigKind),
}

impl fmt::Display for CorpusCoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFamily(kind) => write!(formatter, "{} has no concrete corpus evidence", kind.report_name()),
            Self::DuplicateFamily(kind) => write!(formatter, "{} has duplicate evidence groups", kind.report_name()),
            Self::DuplicateRequestedFamily(kind) => {
                write!(formatter, "{} is requested more than once", kind.report_name())
            }
            Self::UnexpectedFamily(kind) => write!(formatter, "{} was not requested", kind.report_name()),
            Self::CaseFamilyMismatch { expected, found } => {
                write!(formatter, "{} evidence contains a {} case", expected.report_name(), found.report_name())
            }
            Self::MissingAccepted(kind) => write!(formatter, "{} has no accepted case", kind.report_name()),
            Self::MissingRejected(kind) => write!(formatter, "{} has no rejected case", kind.report_name()),
            Self::TooFewSamples { kind, found } => write!(
                formatter,
                "{} has {found} concrete cases; at least {MINIMUM_SAMPLES_PER_FAMILY} are required",
                kind.report_name()
            ),
            Self::MissingVariant { kind, variant } => {
                write!(formatter, "{} is missing required variant {}", kind.report_name(), variant.report_name())
            }
            Self::DuplicateSample { kind, sha256 } => {
                write!(formatter, "{} repeats sample {sha256}", kind.report_name())
            }
            Self::InvalidEvidence { kind, reason } => {
                write!(formatter, "{} has invalid evidence: {reason}", kind.report_name())
            }
            Self::MissingCaseVariant(kind) => write!(formatter, "{} has an unclassified case", kind.report_name()),
        }
    }
}

impl std::error::Error for CorpusCoverageError {}

/// Builds coverage for an explicit set of requested families from concrete family-owned cases.
///
/// This framework does not provide a global registry. Later wiring must pass every family and the
/// same sample collections used by its D1-D5 and refusal tests before aggregate completeness can be
/// claimed.
///
/// # Errors
///
/// Returns a fail-closed coverage error for missing, duplicate, unexpected, mislabeled, duplicated,
/// under-counted, single-polarity, or required-variant-incomplete evidence.
pub fn build_corpus_report(
    requested: &[ConfigKind],
    families: &[FamilyCorpusEvidence],
) -> Result<CorpusReport, CorpusCoverageError> {
    for (index, kind) in requested.iter().enumerate() {
        if requested[..index].contains(kind) {
            return Err(CorpusCoverageError::DuplicateRequestedFamily(*kind));
        }
    }
    for (index, family) in families.iter().enumerate() {
        if families[..index].iter().any(|candidate| candidate.kind == family.kind) {
            return Err(CorpusCoverageError::DuplicateFamily(family.kind));
        }
        if !requested.contains(&family.kind) {
            return Err(CorpusCoverageError::UnexpectedFamily(family.kind));
        }
    }

    let mut rows = Vec::with_capacity(requested.len());
    for kind in requested {
        let family = families
            .iter()
            .find(|family| family.kind == *kind)
            .ok_or(CorpusCoverageError::MissingFamily(*kind))?;
        let mut accepted = 0;
        let mut rejected = 0;
        let mut bytes = 0;
        let mut variants = Vec::new();
        for (index, case) in family.cases.iter().enumerate() {
            if case.kind != *kind {
                return Err(CorpusCoverageError::CaseFamilyMismatch {
                    expected: *kind,
                    found: case.kind,
                });
            }
            if family.cases[..index].iter().any(|candidate| candidate.bytes == case.bytes) {
                return Err(CorpusCoverageError::DuplicateSample {
                    kind: *kind,
                    sha256: case.origin.sha256.clone(),
                });
            }
            match case.disposition {
                CorpusDisposition::Accepted => accepted += 1,
                CorpusDisposition::Rejected => rejected += 1,
            }
            bytes += case.bytes.len();
            for variant in &case.variants {
                if !variants.contains(variant) {
                    variants.push(*variant);
                }
            }
        }
        if accepted == 0 {
            return Err(CorpusCoverageError::MissingAccepted(*kind));
        }
        if rejected == 0 {
            return Err(CorpusCoverageError::MissingRejected(*kind));
        }
        let total = accepted + rejected;
        if total < MINIMUM_SAMPLES_PER_FAMILY {
            return Err(CorpusCoverageError::TooFewSamples {
                kind: *kind,
                found: total,
            });
        }
        for required in &family.required_variants {
            if !variants.contains(required) {
                return Err(CorpusCoverageError::MissingVariant {
                    kind: *kind,
                    variant: *required,
                });
            }
        }
        variants.sort_unstable();
        rows.push(CoverageRow {
            kind: *kind,
            accepted,
            rejected,
            bytes,
            variants,
        });
    }
    Ok(CorpusReport {
        rows,
        requested_families: requested.len(),
    })
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{GoldenSample, SampleOrigin};

    fn origin(bytes: &[u8], label: &str) -> SampleOrigin {
        SampleOrigin {
            source: format!("framework fixture {label}"),
            producer: "corpus framework test".to_owned(),
            version: "test-v1".to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    }

    fn accepted(index: usize) -> GoldenSample<()> {
        let bytes = format!("<VersioningConfiguration><Accepted>{index}</Accepted></VersioningConfiguration>").into_bytes();
        GoldenSample {
            kind: crate::ConfigKind::Versioning,
            origin: origin(&bytes, &format!("accepted-{index}")),
            bytes,
            value: (),
            notes: format!("accepted framework case {index}"),
        }
    }

    fn rejected(index: usize) -> RejectedGoldenSample {
        let bytes = format!("<VersioningConfiguration><Rejected>{index}</Rejected></VersioningConfiguration>").into_bytes();
        RejectedGoldenSample {
            kind: crate::ConfigKind::Versioning,
            origin: origin(&bytes, &format!("rejected-{index}")),
            bytes,
            notes: format!("rejected framework case {index}"),
        }
    }

    fn family() -> FamilyCorpusEvidence {
        let accepted_samples = (0..5).map(accepted).collect::<Vec<_>>();
        let rejected_samples = (0..4).map(rejected).collect::<Vec<_>>();
        let mut cases = accepted_samples
            .iter()
            .enumerate()
            .map(|(index, sample)| {
                let variants = if index == 0 {
                    &[CorpusVariant::Canonical, CorpusVariant::Namespace][..]
                } else {
                    &[CorpusVariant::Canonical][..]
                };
                CorpusCaseEvidence::accepted(sample, variants).expect("accepted evidence has valid provenance")
            })
            .collect::<Vec<_>>();
        cases.extend(rejected_samples.iter().enumerate().map(|(index, sample)| {
            let variants = if index == 1 {
                &[CorpusVariant::MissingField][..]
            } else {
                &[CorpusVariant::DuplicateField][..]
            };
            CorpusCaseEvidence::rejected(sample, variants).expect("rejected evidence has valid provenance")
        }));
        FamilyCorpusEvidence::new(
            crate::ConfigKind::Versioning,
            vec![
                CorpusVariant::Canonical,
                CorpusVariant::Namespace,
                CorpusVariant::DuplicateField,
                CorpusVariant::MissingField,
            ],
            cases,
        )
    }

    #[test]
    fn report_counts_and_variants_come_from_concrete_cases() {
        let family = family();
        let expected_bytes = family.cases.iter().map(|case| case.bytes.len()).sum::<usize>();
        let report =
            build_corpus_report(&[crate::ConfigKind::Versioning], &[family]).expect("the concrete framework fixture is complete");
        assert_eq!(report.rows.len(), 1);
        assert_eq!(report.rows[0].accepted, 5);
        assert_eq!(report.rows[0].rejected, 4);
        assert_eq!(report.total_size_bytes(), expected_bytes);
        assert_eq!(
            report.render(),
            format!(
                "persisted XML corpus: 1/1 requested families covered\nversioning: accepted=5 rejected=4 bytes={expected_bytes} variants=canonical,missing-field,namespace,duplicate-field\ntotal: families=1 accepted=5 rejected=4 bytes={expected_bytes}\n"
            )
        );
    }

    #[test]
    fn n_missing_family_fails_closed() {
        assert!(matches!(
            build_corpus_report(&[crate::ConfigKind::Versioning], &[]),
            Err(CorpusCoverageError::MissingFamily(crate::ConfigKind::Versioning))
        ));
    }

    #[test]
    fn n_duplicate_family_fails_closed() {
        let evidence = family();
        assert!(matches!(
            build_corpus_report(&[crate::ConfigKind::Versioning], &[evidence.clone(), evidence]),
            Err(CorpusCoverageError::DuplicateFamily(crate::ConfigKind::Versioning))
        ));
    }

    #[test]
    fn n_duplicate_requested_family_fails_closed() {
        assert!(matches!(
            build_corpus_report(&[crate::ConfigKind::Versioning, crate::ConfigKind::Versioning], &[family()]),
            Err(CorpusCoverageError::DuplicateRequestedFamily(crate::ConfigKind::Versioning))
        ));
    }

    #[test]
    fn n_unrequested_family_fails_closed() {
        assert!(matches!(
            build_corpus_report(&[crate::ConfigKind::ObjectLock], &[family()]),
            Err(CorpusCoverageError::UnexpectedFamily(crate::ConfigKind::Versioning))
        ));
    }

    #[test]
    fn n_mislabeled_concrete_case_fails_closed() {
        let mut mutant = family();
        mutant.cases[0].kind = crate::ConfigKind::ObjectLock;
        assert!(matches!(
            build_corpus_report(&[crate::ConfigKind::Versioning], &[mutant]),
            Err(CorpusCoverageError::CaseFamilyMismatch {
                expected: crate::ConfigKind::Versioning,
                found: crate::ConfigKind::ObjectLock
            })
        ));
    }

    #[test]
    fn n_removing_every_accepted_case_fails_closed() {
        let mut mutant = family();
        mutant.cases.retain(|case| case.disposition == CorpusDisposition::Rejected);
        assert!(matches!(
            build_corpus_report(&[crate::ConfigKind::Versioning], &[mutant]),
            Err(CorpusCoverageError::MissingAccepted(crate::ConfigKind::Versioning))
        ));
    }

    #[test]
    fn n_removing_every_rejected_case_fails_closed() {
        let mut mutant = family();
        mutant.cases.retain(|case| case.disposition == CorpusDisposition::Accepted);
        assert!(matches!(
            build_corpus_report(&[crate::ConfigKind::Versioning], &[mutant]),
            Err(CorpusCoverageError::MissingRejected(crate::ConfigKind::Versioning))
        ));
    }

    #[test]
    fn n_removing_concrete_cases_below_the_minimum_fails_closed() {
        let mut mutant = family();
        mutant.cases.truncate(7);
        assert!(matches!(
            build_corpus_report(&[crate::ConfigKind::Versioning], &[mutant]),
            Err(CorpusCoverageError::TooFewSamples { found: 7, .. })
        ));
    }

    #[test]
    fn n_removing_the_only_case_for_a_required_variant_fails_closed() {
        let mut mutant = family();
        mutant.cases.retain(|case| !case.variants.contains(&CorpusVariant::Namespace));
        assert!(matches!(
            build_corpus_report(&[crate::ConfigKind::Versioning], &[mutant]),
            Err(CorpusCoverageError::MissingVariant {
                variant: CorpusVariant::Namespace,
                ..
            })
        ));
    }

    #[test]
    fn n_duplicating_concrete_sample_bytes_fails_closed() {
        let mut mutant = family();
        mutant.cases.push(mutant.cases[0].clone());
        assert!(matches!(
            build_corpus_report(&[crate::ConfigKind::Versioning], &[mutant]),
            Err(CorpusCoverageError::DuplicateSample { .. })
        ));
    }

    #[test]
    fn n_stale_accepted_sha_is_rejected_before_registration() {
        let mut sample = accepted(0);
        sample.origin.sha256 = "0".repeat(64);
        assert!(matches!(
            CorpusCaseEvidence::accepted(&sample, &[CorpusVariant::Canonical]),
            Err(CorpusCoverageError::InvalidEvidence { .. })
        ));
    }

    #[test]
    fn n_stale_rejected_sha_is_rejected_before_registration() {
        let mut sample = rejected(0);
        sample.origin.sha256 = "0".repeat(64);
        assert!(matches!(
            CorpusCaseEvidence::rejected(&sample, &[CorpusVariant::DuplicateField]),
            Err(CorpusCoverageError::InvalidEvidence { .. })
        ));
    }

    #[test]
    fn n_case_without_a_variant_is_rejected_before_registration() {
        assert!(matches!(
            CorpusCaseEvidence::accepted(&accepted(0), &[]),
            Err(CorpusCoverageError::MissingCaseVariant(crate::ConfigKind::Versioning))
        ));
    }
}
