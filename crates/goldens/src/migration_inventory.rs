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

//! Decided migration refusals: persisted bytes every admitted s3s revision reads, which the
//! production decoders refuse on purpose.
//!
//! Responsible for: re-proving each decided refusal on every run. Every admitted revision must
//! still read each witness, or the entry is stale. The production decoder must refuse each witness
//! with the entry's named error, or the decision was broken. No writer-produced corpus sample may
//! carry the refused syntax, or the claim that no writer emits it is false.
//! NOT responsible for: open findings, which `oracle_admission.rs` holds against closure, or
//! production decoding. Upstream: the family corpus evidence, the compat revision selector and the
//! production decoders. Downstream: `corpus-report`, and an operator's pre-migration scan.
//!
//! # `persisted-doctype` (rustfs/gateway#469)
//!
//! Every admitted revision (s3s `9c4690d8`, `bdcb6259`, `f3e17541`) skips a document type
//! declaration of any shape before the root: internal subsets with element, entity or parameter
//! entity declarations, `SYSTEM` and `PUBLIC` external identifiers, a name that is not the root,
//! and even the lowercase `<!doctype`. It fails only when a declared entity is referenced. The
//! production decoders refuse all of it with `Xml(DocTypeDeclaration)`. The single exception is
//! the inert `<!DOCTYPE Root>` that Accelerate, Request Payment, Notification and Replication
//! already strip, and that exception stays exactly as narrow as it is.
//!
//! The refusal is kept because accepting a DTD means parsing DTD syntax: quoted literals that may
//! contain `]>`, comments, processing instructions, parameter entities and conditional sections,
//! all on the persisted read path. That new attack surface would serve no writer. The s3s
//! serializer every RustFS build writes with never emits a declaration, and no writer-produced
//! sample in the corpus carries one. The only ingress is an operator-supplied bucket-metadata
//! import archive. RustFS stores its entries verbatim after an s3s parse
//! (`rustfs/src/admin/handlers/bucket_meta.rs`, `validated_config!`), so a hand-edited archive
//! can persist a declaration. After migration that configuration fails closed with the named
//! error; re-putting it through the S3 API writes it without one.

use core::fmt;

use rustfs_gateway_types::compat::{OracleRevision, with_oracle};

use crate::oracle_admission::{OldReading, new_refusal, old_reading};
use crate::{ConfigKind, SampleOrigin, all_family_corpus_evidence};

/// Issue that records the decision.
const DECISION: &str = "https://github.com/rustfs/gateway/issues/469";

/// The error every refused witness must produce, as the production decoders render it.
const NAMED_ERROR: &str = "Xml(DocTypeDeclaration)";

/// Families whose production decoder already strips exactly `<!DOCTYPE Root>`.
const INERT_TOLERATED: [ConfigKind; 4] = [
    ConfigKind::Accelerate,
    ConfigKind::RequestPayment,
    ConfigKind::Notification,
    ConfigKind::Replication,
];

/// Producers of the synthetic oracle-boundary fixtures: the only corpus samples allowed to carry a
/// declaration, because they exist to pin the inert-form tolerance above.
const BOUNDARY_FIXTURE_PRODUCERS: [&str; 2] = ["pinned s3s XML behavior", "s3s pinned persistence codec"];

/// Boundary fixtures that carry a declaration today. Pinned so that adding one is a reviewed change.
const BOUNDARY_FIXTURES_WITH_DOCTYPE: usize = 10;

/// One document type declaration shape every admitted revision skips.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctypeForm {
    /// `<!DOCTYPE Root>`.
    Inert,
    /// `<!DOCTYPE Other>`, naming an element that is not the root.
    WrongRoot,
    /// An internal subset declaring an element.
    SubsetElement,
    /// An internal subset declaring a general entity that is never referenced.
    SubsetEntity,
    /// An internal subset declaring a parameter entity.
    SubsetParameterEntity,
    /// A `SYSTEM` external identifier naming a local file.
    System,
    /// A `PUBLIC` external identifier.
    Public,
    /// `<!doctype Root>`, which is not XML but is skipped all the same.
    Lowercase,
}

impl DoctypeForm {
    /// Every measured form.
    pub const ALL: [Self; 8] = [
        Self::Inert,
        Self::WrongRoot,
        Self::SubsetElement,
        Self::SubsetEntity,
        Self::SubsetParameterEntity,
        Self::System,
        Self::Public,
        Self::Lowercase,
    ];

    /// Stable report label.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Inert => "inert",
            Self::WrongRoot => "wrong-root",
            Self::SubsetElement => "subset-element",
            Self::SubsetEntity => "subset-entity",
            Self::SubsetParameterEntity => "subset-parameter-entity",
            Self::System => "system",
            Self::Public => "public",
            Self::Lowercase => "lowercase",
        }
    }

    fn declaration(self, root: &str) -> String {
        match self {
            Self::Inert => format!("<!DOCTYPE {root}>"),
            Self::WrongRoot => "<!DOCTYPE Other>".to_owned(),
            Self::SubsetElement => format!("<!DOCTYPE {root} [<!ELEMENT x ANY>]>"),
            Self::SubsetEntity => format!("<!DOCTYPE {root} [<!ENTITY e \"v\">]>"),
            Self::SubsetParameterEntity => format!("<!DOCTYPE {root} [<!ENTITY % p \"x\">]>"),
            Self::System => format!("<!DOCTYPE {root} SYSTEM \"file:///etc/passwd\">"),
            Self::Public => format!("<!DOCTYPE {root} PUBLIC \"-//x//y\" \"http://example.invalid/r.dtd\">"),
            Self::Lowercase => format!("<!doctype {root}>"),
        }
    }

    fn tolerated_by(self, kind: ConfigKind) -> bool {
        matches!(self, Self::Inert) && INERT_TOLERATED.contains(&kind)
    }
}

/// One declaration prefixed to a family's first accepted corpus document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctypeWitness {
    /// Persisted XML family.
    pub kind: ConfigKind,
    /// Declaration shape.
    pub form: DoctypeForm,
    /// The declaration followed by the unmodified accepted document.
    pub bytes: Vec<u8>,
}

/// Validated decided-refusal evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationInventoryReport {
    refused: usize,
    tolerated: usize,
    boundary_fixtures: usize,
}

impl MigrationInventoryReport {
    /// Witnesses every revision reads and the production decoder refuses with the named error.
    #[must_use]
    pub const fn refused(&self) -> usize {
        self.refused
    }

    /// Inert-form witnesses both sides read.
    #[must_use]
    pub const fn tolerated(&self) -> usize {
        self.tolerated
    }

    /// Renders the inventory, one line per decided refusal.
    #[must_use]
    pub fn render(&self) -> String {
        let revisions = OracleRevision::ALL.map(|oracle| oracle.to_string()).join(", ");
        format!(
            "migration inventory: decided-refusals=1\n\
             refusal persisted-doctype decision={DECISION} witnesses={} refused={} tolerated={} \
             old=reads under {revisions} new={NAMED_ERROR} writer-samples-with-doctype=0 boundary-fixtures={} \
             ingress=bucket-metadata-import-archive remediation=re-put-configuration-through-s3-api\n",
            self.refused + self.tolerated,
            self.refused,
            self.tolerated,
            self.boundary_fixtures,
        )
    }
}

/// A decided refusal that no longer holds as recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MigrationInventoryError {
    /// The corpus could not be built.
    Corpus(String),
    /// A family has no accepted document to prefix a declaration to.
    NoWitnessBase(ConfigKind),
    /// An admitted revision refuses a witness, so the entry no longer describes that revision.
    StaleRefusal {
        /// Revision that refused.
        oracle: OracleRevision,
        /// Family of the witness.
        kind: ConfigKind,
        /// Declaration shape.
        form: DoctypeForm,
    },
    /// The production decoder read a refused witness, or refused it with another error.
    DecisionViolated {
        /// Family of the witness.
        kind: ConfigKind,
        /// Declaration shape.
        form: DoctypeForm,
        /// The other error, or `None` when the decoder read the witness.
        observed: Option<String>,
    },
    /// The production decoder refused the inert form a family tolerates.
    ToleranceLost {
        /// Family whose tolerance moved.
        kind: ConfigKind,
        /// The refusal observed.
        observed: String,
    },
    /// A sample not produced by a boundary fixture carries a declaration.
    WriterSampleCarriesDoctype {
        /// Family of the sample.
        kind: ConfigKind,
        /// SHA-256 of the sample.
        sha256: String,
        /// Producer the sample names.
        producer: String,
    },
    /// The number of boundary fixtures carrying a declaration moved.
    BoundaryFixtureCountDrift {
        /// Pinned count.
        expected: usize,
        /// Observed count.
        found: usize,
    },
}

impl fmt::Display for MigrationInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corpus(reason) => write!(formatter, "corpus unavailable: {reason}"),
            Self::NoWitnessBase(kind) => write!(formatter, "{} has no accepted document to witness with", kind.report_name()),
            Self::StaleRefusal { oracle, kind, form } => write!(
                formatter,
                "{oracle} refuses {} {} witness; persisted-doctype no longer describes it",
                kind.report_name(),
                form.slug()
            ),
            Self::DecisionViolated { kind, form, observed } => write!(
                formatter,
                "production {} decoder answered {} witness with {} instead of {NAMED_ERROR} ({DECISION})",
                kind.report_name(),
                form.slug(),
                observed.as_deref().unwrap_or("a successful read")
            ),
            Self::ToleranceLost { kind, observed } => write!(
                formatter,
                "production {} decoder refuses the tolerated inert declaration with {observed}",
                kind.report_name()
            ),
            Self::WriterSampleCarriesDoctype { kind, sha256, producer } => write!(
                formatter,
                "{} sample {sha256} from {producer} carries a document type declaration",
                kind.report_name()
            ),
            Self::BoundaryFixtureCountDrift { expected, found } => write!(
                formatter,
                "{found} boundary fixtures carry a document type declaration, {expected} are pinned"
            ),
        }
    }
}

impl std::error::Error for MigrationInventoryError {}

/// Re-proves every decided refusal against the real corpus, revisions and decoders.
///
/// # Errors
///
/// Returns the first stale, violated, or unsupported inventory observation.
pub fn build_migration_inventory() -> Result<MigrationInventoryReport, MigrationInventoryError> {
    let families = all_family_corpus_evidence().map_err(|error| MigrationInventoryError::Corpus(error.to_string()))?;
    let mut bases = Vec::with_capacity(families.len());
    let mut samples = Vec::new();
    for family in &families {
        let base = family
            .samples()
            .find(|(bytes, _, accepted)| {
                *accepted && bytes.first() == Some(&b'<') && bytes.get(1).is_some_and(u8::is_ascii_alphabetic)
            })
            .map(|(bytes, _, _)| bytes)
            .ok_or(MigrationInventoryError::NoWitnessBase(family.kind()))?;
        bases.push((family.kind(), base));
        samples.extend(family.samples().map(|(bytes, origin, _)| (family.kind(), bytes, origin)));
    }
    let (refused, tolerated) = check_witnesses(
        &witnesses(&bases),
        |oracle, kind, bytes| with_oracle(oracle, || old_reading(kind, bytes)),
        new_refusal,
    )?;
    let boundary_fixtures = audit_samples(samples)?;
    Ok(MigrationInventoryReport {
        refused,
        tolerated,
        boundary_fixtures,
    })
}

/// Prefixes every form to each family's base document, whose root names the declaration.
fn witnesses(bases: &[(ConfigKind, &[u8])]) -> Vec<DoctypeWitness> {
    let mut witnesses = Vec::with_capacity(bases.len() * DoctypeForm::ALL.len());
    for (kind, base) in bases {
        let end = base
            .iter()
            .position(|byte| matches!(byte, b' ' | b'>' | b'/' | b'\t' | b'\r' | b'\n'))
            .unwrap_or(base.len());
        let root = String::from_utf8_lossy(base.get(1..end).unwrap_or_default());
        for form in DoctypeForm::ALL {
            let mut bytes = form.declaration(&root).into_bytes();
            bytes.extend_from_slice(base);
            witnesses.push(DoctypeWitness {
                kind: *kind,
                form,
                bytes,
            });
        }
    }
    witnesses
}

/// Returns `(refused, tolerated)` once every witness matches the recorded decision.
fn check_witnesses(
    witnesses: &[DoctypeWitness],
    old: impl Fn(OracleRevision, ConfigKind, &[u8]) -> OldReading,
    new: impl Fn(ConfigKind, &[u8]) -> Option<String>,
) -> Result<(usize, usize), MigrationInventoryError> {
    let (mut refused, mut tolerated) = (0, 0);
    for witness in witnesses {
        let (kind, form) = (witness.kind, witness.form);
        for oracle in OracleRevision::ALL {
            if old(oracle, kind, &witness.bytes) != OldReading::Read {
                return Err(MigrationInventoryError::StaleRefusal { oracle, kind, form });
            }
        }
        let observed = new(kind, &witness.bytes);
        if form.tolerated_by(kind) {
            if let Some(observed) = observed {
                return Err(MigrationInventoryError::ToleranceLost { kind, observed });
            }
            tolerated += 1;
        } else if observed.as_deref() == Some(NAMED_ERROR) {
            refused += 1;
        } else {
            return Err(MigrationInventoryError::DecisionViolated { kind, form, observed });
        }
    }
    Ok((refused, tolerated))
}

/// Returns the number of boundary fixtures carrying a declaration once no other sample does.
fn audit_samples<'a>(
    samples: impl IntoIterator<Item = (ConfigKind, &'a [u8], &'a SampleOrigin)>,
) -> Result<usize, MigrationInventoryError> {
    let mut boundary_fixtures = 0;
    for (kind, bytes, origin) in samples {
        if !bytes.windows(9).any(|window| window.eq_ignore_ascii_case(b"<!doctype")) {
            continue;
        }
        if !BOUNDARY_FIXTURE_PRODUCERS.contains(&origin.producer.as_str()) {
            return Err(MigrationInventoryError::WriterSampleCarriesDoctype {
                kind,
                sha256: origin.sha256.clone(),
                producer: origin.producer.clone(),
            });
        }
        boundary_fixtures += 1;
    }
    if boundary_fixtures == BOUNDARY_FIXTURES_WITH_DOCTYPE {
        Ok(boundary_fixtures)
    } else {
        Err(MigrationInventoryError::BoundaryFixtureCountDrift {
            expected: BOUNDARY_FIXTURES_WITH_DOCTYPE,
            found: boundary_fixtures,
        })
    }
}

#[cfg(test)]
mod tests;
