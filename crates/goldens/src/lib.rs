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

//! Persistence compatibility evidence for migrations away from s3s.
//!
//! Responsible for: proving old/new read, byte-write, rollback-read, permissiveness, and behavior
//! compatibility against traceable persisted samples. NOT responsible for: serving HTTP or
//! implementing either codec under test. Upstream: the temporary `compat-s3s` oracle and the
//! production persistence codecs. Downstream: migration gates that must fail closed before a
//! persistence writer changes.
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use core::fmt;

use sha2::{Digest, Sha256};

mod accelerate_payment;
mod acceptance_census;
mod bucket_encryption;
mod corpus;
mod cors;
mod ecstore_source_a;
mod four_way;
mod historical_writer;
mod lifecycle;
mod logging;
mod minio_migration;
mod notification;
mod object_lock;
mod provenance;
mod public_access_block;
mod replication;
mod source_a_boundary;
mod source_a_census;
mod source_a_create_defaults;
mod source_a_lifecycle;
mod source_a_new_writer;
mod source_b_js_v3;
mod source_b_js_v3_pab;
mod source_b_js_v3_website;
mod source_b_mc;
mod source_b_rclone;
mod tagging;
mod versioning;
mod website;

pub use accelerate_payment::{assert_accelerate_four_way, assert_request_payment_four_way};
pub use acceptance_census::{
    AcceptanceCaseReport, AcceptanceCaseStatus, AcceptanceCensusError, AcceptanceCensusReport, build_acceptance_census,
    require_acceptance_closure,
};
pub use bucket_encryption::assert_bucket_encryption_four_way;
pub use corpus::{
    CorpusCaseEvidence, CorpusCoverageError, CorpusReport, CorpusSampleProvenance, CorpusVariant, FamilyCorpusEvidence,
    RejectedGoldenSample, build_corpus_report,
};
pub use cors::assert_cors_four_way;
pub use four_way::{FourWayFamilyReport, FourWayRunError, FourWayRunReport, run_four_way_all, run_four_way_core_shard};
pub use lifecycle::assert_lifecycle_four_way;
pub use logging::assert_bucket_logging_four_way;
pub use notification::assert_notification_four_way;
pub use object_lock::assert_object_lock_four_way;
pub use provenance::{
    PersistenceSource, PersistenceSourceError, PersistenceSourceReport, SourceReport, build_persistence_source_report,
    require_persistence_sources,
};
pub use public_access_block::assert_public_access_block_four_way;
pub use replication::assert_replication_four_way;
pub use tagging::assert_tagging_four_way;
pub use versioning::assert_versioning_four_way;
pub use website::assert_website_four_way;

/// A persistence configuration family covered by the golden harness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigKind {
    /// Bucket Transfer Acceleration metadata.
    Accelerate,
    /// Bucket versioning metadata.
    Versioning,
    /// Bucket Object Lock metadata.
    ObjectLock,
    /// Bucket Lifecycle metadata.
    Lifecycle,
    /// Bucket default-encryption metadata.
    BucketEncryption,
    /// Bucket event-notification metadata.
    Notification,
    /// Bucket public-access-block metadata.
    PublicAccessBlock,
    /// Bucket requester-pays metadata.
    RequestPayment,
    /// Bucket CORS metadata.
    Cors,
    /// Bucket tagging metadata.
    Tagging,
    /// Bucket access-log delivery metadata.
    Logging,
    /// Bucket static-website metadata.
    Website,
    /// Bucket replication metadata.
    Replication,
}

impl ConfigKind {
    /// Every named persisted XML configuration family in stable report order.
    pub const ALL: [Self; 13] = [
        Self::Versioning,
        Self::ObjectLock,
        Self::Lifecycle,
        Self::Cors,
        Self::Tagging,
        Self::Accelerate,
        Self::RequestPayment,
        Self::BucketEncryption,
        Self::PublicAccessBlock,
        Self::Notification,
        Self::Logging,
        Self::Website,
        Self::Replication,
    ];

    /// Stable report label for this persisted XML family.
    #[must_use]
    pub const fn report_name(self) -> &'static str {
        match self {
            Self::Accelerate => "accelerate",
            Self::Versioning => "versioning",
            Self::ObjectLock => "object-lock",
            Self::Lifecycle => "lifecycle",
            Self::BucketEncryption => "bucket-encryption",
            Self::Notification => "notification",
            Self::PublicAccessBlock => "public-access-block",
            Self::RequestPayment => "request-payment",
            Self::Cors => "cors",
            Self::Tagging => "tagging",
            Self::Logging => "logging",
            Self::Website => "website",
            Self::Replication => "replication",
        }
    }
}

/// A traceable source for one persisted sample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleOrigin {
    /// Corpus source class or repository-relative fixture path.
    pub source: String,
    /// Client, server, or fixture generator that produced the bytes.
    pub producer: String,
    /// Producer version, commit, or fixture revision.
    pub version: String,
    /// Lowercase SHA-256 of the unmodified sample bytes.
    pub sha256: String,
}

/// Historical bytes plus the value whose old/new serialized form must agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoldenSample<T> {
    /// Configuration family.
    pub kind: ConfigKind,
    /// Original persisted bytes. They are never normalized before either parser sees them.
    pub bytes: Vec<u8>,
    /// Semantic value used for the old/new byte-write and rollback assertions.
    pub value: T,
    /// Traceability metadata.
    pub origin: SampleOrigin,
    /// Why this sample belongs in the corpus.
    pub notes: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedCorpusCase<T> {
    pub(crate) sample: GoldenSample<T>,
    pub(crate) variants: Vec<CorpusVariant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RejectedCorpusCase {
    pub(crate) sample: RejectedGoldenSample,
    pub(crate) variants: Vec<CorpusVariant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConcreteFamilyCorpus<T> {
    pub(crate) kind: ConfigKind,
    pub(crate) required_variants: Vec<CorpusVariant>,
    pub(crate) accepted: Vec<AcceptedCorpusCase<T>>,
    pub(crate) rejected: Vec<RejectedCorpusCase>,
}

impl<T> ConcreteFamilyCorpus<T> {
    pub(crate) fn framework(&self) -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
        let mut cases = self
            .accepted
            .iter()
            .map(|case| CorpusCaseEvidence::accepted(&case.sample, &case.variants))
            .collect::<Result<Vec<_>, _>>()?;
        cases.extend(
            self.rejected
                .iter()
                .map(|case| CorpusCaseEvidence::rejected(&case.sample, &case.variants))
                .collect::<Result<Vec<_>, _>>()?,
        );
        Ok(FamilyCorpusEvidence::new(self.kind, self.required_variants.clone(), cases))
    }
}

/// Builds the concrete corpus report for every persisted XML configuration family.
///
/// # Errors
///
/// Returns a fail-closed coverage error when any family-owned case has invalid provenance,
/// duplicated bytes, missing polarity, or an incomplete required-variant set.
pub fn build_persistence_corpus_report() -> Result<CorpusReport, CorpusCoverageError> {
    let families = all_family_corpus_evidence()?;
    source_a_census::validate(&families).map_err(|reason| CorpusCoverageError::InvalidEvidence {
        kind: ConfigKind::Cors,
        reason: format!("source-(a) union census: {reason}"),
    })?;
    build_corpus_report(&ConfigKind::ALL, &families)
}

fn all_family_corpus_evidence() -> Result<Vec<FamilyCorpusEvidence>, CorpusCoverageError> {
    let mut families = base_family_corpus_evidence()?;
    historical_writer::append(&mut families).map_err(|(kind, error)| CorpusCoverageError::InvalidEvidence {
        kind,
        reason: error.to_string(),
    })?;
    Ok(families)
}

fn base_family_corpus_evidence() -> Result<Vec<FamilyCorpusEvidence>, CorpusCoverageError> {
    let migration_error = |kind: ConfigKind, error: GoldenFailure| CorpusCoverageError::InvalidEvidence {
        kind,
        reason: error.to_string(),
    };
    let versioning_sample =
        minio_migration::versioning_sample().map_err(|error| migration_error(ConfigKind::Versioning, error))?;
    let mut versioning = versioning::corpus_evidence().framework()?;
    versioning.push_accepted(&versioning_sample, &[CorpusVariant::Canonical, CorpusVariant::Namespace])?;
    let bucket_encryption_sample =
        minio_migration::bucket_encryption_sample().map_err(|error| migration_error(ConfigKind::BucketEncryption, error))?;
    let mut bucket_encryption = bucket_encryption::bucket_encryption_corpus_evidence()?;
    bucket_encryption.push_accepted(&bucket_encryption_sample, &[CorpusVariant::Canonical, CorpusVariant::Namespace])?;
    let tagging_sample = minio_migration::tagging_sample().map_err(|error| migration_error(ConfigKind::Tagging, error))?;
    let mut tagging = tagging::corpus_evidence()?;
    tagging.push_accepted(&tagging_sample, &[CorpusVariant::Canonical])?;
    let notification_sample =
        minio_migration::notification_sample().map_err(|error| migration_error(ConfigKind::Notification, error))?;
    let mut notification = notification::notification_corpus_evidence()?;
    notification.push_accepted(
        &notification_sample,
        &[
            CorpusVariant::Canonical,
            CorpusVariant::Namespace,
            CorpusVariant::EmptyElement,
        ],
    )?;
    let lifecycle_sample = minio_migration::lifecycle_sample().map_err(|error| migration_error(ConfigKind::Lifecycle, error))?;
    let mut lifecycle = lifecycle::corpus_evidence().framework()?;
    lifecycle.push_accepted(
        &lifecycle_sample,
        &[
            CorpusVariant::Canonical,
            CorpusVariant::EmptyElement,
            CorpusVariant::TimestampPrecision,
        ],
    )?;
    let object_lock_sample =
        minio_migration::object_lock_sample().map_err(|error| migration_error(ConfigKind::ObjectLock, error))?;
    let mut object_lock = object_lock::corpus_evidence().framework()?;
    object_lock.push_accepted(&object_lock_sample, &[CorpusVariant::Canonical])?;
    let replication_sample =
        minio_migration::replication_sample().map_err(|error| migration_error(ConfigKind::Replication, error))?;
    let mut replication = replication::replication_corpus_evidence()?;
    replication.push_accepted(&replication_sample, &[CorpusVariant::Canonical, CorpusVariant::EmptyElement])?;
    Ok(vec![
        versioning,
        object_lock,
        lifecycle,
        cors::corpus_evidence()?,
        tagging,
        accelerate_payment::accelerate_corpus_evidence()?,
        accelerate_payment::request_payment_corpus_evidence()?,
        bucket_encryption,
        public_access_block::public_access_block_corpus_evidence()?,
        notification,
        logging::bucket_logging_corpus_evidence()?,
        website::website_corpus_evidence()?,
        replication,
    ])
}

/// Builds the complete persisted XML corpus report under its original pilot-era name.
///
/// # Errors
///
/// Returns the same fail-closed coverage errors as [`build_persistence_corpus_report`].
pub fn build_pilot_corpus_report() -> Result<CorpusReport, CorpusCoverageError> {
    build_persistence_corpus_report()
}

/// The input check or compatibility direction that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// The sample is missing provenance or its recorded digest does not match its bytes.
    Input,
    /// D1: the new parser reads historical bytes into the same structure as s3s.
    D1CompatibleRead,
    /// D2: the new and s3s serializers emit byte-identical persistence data.
    D2ByteWrite,
    /// D3: s3s can parse the new serializer's bytes back into the same structure.
    D3RollbackRead,
    /// D4: the new parser is not stricter for a document accepted by s3s.
    D4NotStricter,
    /// D5: the old and new parsed values have the same runtime behavior.
    D5Behavior,
}

/// A fail-closed input or D1-D5 result with byte-diff context where applicable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoldenFailure {
    /// Failed input check or compatibility direction.
    pub direction: Direction,
    /// First differing byte offset for a byte comparison.
    pub offset: Option<usize>,
    /// Old-side value, provenance field, error, or byte context.
    pub left: String,
    /// New-side value, required condition, error, or byte context.
    pub right: String,
}

impl fmt::Display for GoldenFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} failed{}: old={} new={}",
            self.direction,
            self.offset.map_or_else(String::new, |offset| format!(" at byte {offset}")),
            self.left,
            self.right
        )
    }
}

impl std::error::Error for GoldenFailure {}

/// Independent old/new codec operations consumed by the generic harness.
pub trait FourWayCodec {
    /// Configuration family accepted by this codec.
    const KIND: ConfigKind;

    /// Common value handed independently to both serializers.
    type Value: Clone + fmt::Debug + Eq;
    /// Parsed value retained in the old implementation's own observation shape.
    type OldParsed: fmt::Debug;
    /// Parsed value retained in the new implementation's own observation shape.
    type NewParsed: fmt::Debug;
    /// Common structural projection used only for D1 and D3 comparisons.
    type Structure: Clone + fmt::Debug + Eq;
    /// Family-specific runtime behavior projected independently from each parser.
    type Behavior: fmt::Debug + Eq;

    /// Parses persisted bytes with the pinned old codec.
    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String>;
    /// Parses persisted bytes with the production new codec.
    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String>;
    /// Projects an old parsed value into the common D1/D3 structure.
    fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure;
    /// Projects a new parsed value into the common D1 structure.
    fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure;
    /// Projects a serializer input into the D3 expected structure.
    fn expected_structure(&self, value: &Self::Value) -> Self::Structure;
    /// Serializes a value with the pinned old codec.
    fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String>;
    /// Serializes a value with the production new codec.
    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String>;
    /// Computes runtime behavior through the old implementation's interpretation.
    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior;
    /// Computes runtime behavior through the new implementation's interpretation.
    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior;
}

/// Runs provenance validation and D1-D5 against one historical sample.
///
/// Missing observations fail. D4 is evaluated before structural equality so a new parser refusal
/// cannot be mislabeled as a D1 diff. Old and new parsed values stay separate until each has made
/// its own structural and behavior projection.
///
/// # Errors
///
/// Returns [`GoldenFailure`] for invalid provenance or the first failed direction, with a ±64-byte
/// hex and printable context for D2.
pub fn assert_four_way<C: FourWayCodec>(codec: &C, sample: &GoldenSample<C::Value>) -> Result<(), GoldenFailure> {
    validate_sample(C::KIND, sample)?;
    let old_parsed = codec.old_parse(&sample.bytes).map_err(|error| GoldenFailure {
        direction: Direction::D1CompatibleRead,
        offset: None,
        left: error,
        right: "old corpus input must be readable".to_owned(),
    })?;
    let new_parsed = codec.new_parse(&sample.bytes).map_err(|error| GoldenFailure {
        direction: Direction::D4NotStricter,
        offset: None,
        left: format!("old parser accepted: {old_parsed:?}"),
        right: error,
    })?;
    let old_structure = codec.old_structure(&old_parsed);
    let new_structure = codec.new_structure(&new_parsed);
    if old_structure != new_structure {
        return Err(value_failure(Direction::D1CompatibleRead, &old_structure, &new_structure));
    }

    let old_bytes = codec.old_serialize(&sample.value).map_err(|error| GoldenFailure {
        direction: Direction::D2ByteWrite,
        offset: None,
        left: error,
        right: "old serializer must produce the oracle bytes".to_owned(),
    })?;
    let new_bytes = codec.new_serialize(&sample.value).map_err(|error| GoldenFailure {
        direction: Direction::D2ByteWrite,
        offset: None,
        left: format_bytes(&old_bytes, 0),
        right: error,
    })?;
    if old_bytes != new_bytes {
        return Err(byte_failure(Direction::D2ByteWrite, &old_bytes, &new_bytes));
    }

    let rollback = codec.old_parse(&new_bytes).map_err(|error| GoldenFailure {
        direction: Direction::D3RollbackRead,
        offset: None,
        left: format!("expected value: {:?}", sample.value),
        right: error,
    })?;
    let rollback_structure = codec.old_structure(&rollback);
    let expected_structure = codec.expected_structure(&sample.value);
    if rollback_structure != expected_structure {
        return Err(value_failure(Direction::D3RollbackRead, &expected_structure, &rollback_structure));
    }

    let old_behavior = codec.old_behavior(&old_parsed);
    let new_behavior = codec.new_behavior(&new_parsed);
    if old_behavior != new_behavior {
        return Err(value_failure(Direction::D5Behavior, &old_behavior, &new_behavior));
    }
    Ok(())
}

fn validate_sample<T>(expected_kind: ConfigKind, sample: &GoldenSample<T>) -> Result<(), GoldenFailure> {
    if sample.kind != expected_kind {
        return Err(GoldenFailure {
            direction: Direction::Input,
            offset: None,
            left: format!("{:?}", sample.kind),
            right: format!("expected {:?}", expected_kind),
        });
    }
    for (name, value) in [
        ("source", sample.origin.source.as_str()),
        ("producer", sample.origin.producer.as_str()),
        ("version", sample.origin.version.as_str()),
        ("notes", sample.notes.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(GoldenFailure {
                direction: Direction::Input,
                offset: None,
                left: name.to_owned(),
                right: "traceability field must be non-empty".to_owned(),
            });
        }
    }
    let actual = hex::encode(Sha256::digest(&sample.bytes));
    if sample.origin.sha256 != actual {
        return Err(GoldenFailure {
            direction: Direction::Input,
            offset: None,
            left: sample.origin.sha256.clone(),
            right: actual,
        });
    }
    Ok(())
}

fn value_failure(direction: Direction, old: &impl fmt::Debug, new: &impl fmt::Debug) -> GoldenFailure {
    GoldenFailure {
        direction,
        offset: None,
        left: format!("{old:?}"),
        right: format!("{new:?}"),
    }
}

fn byte_failure(direction: Direction, old: &[u8], new: &[u8]) -> GoldenFailure {
    let common = old.len().min(new.len());
    let offset = old.iter().zip(new).position(|(left, right)| left != right).unwrap_or(common);
    GoldenFailure {
        direction,
        offset: Some(offset),
        left: format_bytes(old, offset),
        right: format_bytes(new, offset),
    }
}

fn format_bytes(bytes: &[u8], offset: usize) -> String {
    let start = offset.saturating_sub(64);
    let end = bytes.len().min(offset.saturating_add(65));
    let context = &bytes[start..end];
    let hex = context.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ");
    let printable = context
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect::<String>();
    format!("range {start}..{end}; hex [{hex}]; text [{printable}]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_persisted_xml_family_publishes_real_corpus_evidence() {
        let versioning = crate::versioning::corpus_evidence();
        let object_lock = crate::object_lock::corpus_evidence();
        let lifecycle = crate::lifecycle::corpus_evidence();
        assert!(versioning.rejected.len() > versioning.accepted.len());
        assert!(object_lock.rejected.len() > object_lock.accepted.len());
        assert!(lifecycle.rejected.len() > lifecycle.accepted.len());
        let report =
            build_persistence_corpus_report().expect("all thirteen persisted XML families have concrete corpus coverage");
        assert!(report.render().contains("13/13 requested families covered"));
    }

    #[test]
    fn provider_provenance_mutation_fails_closed() {
        let mut family = crate::versioning::corpus_evidence();
        family.accepted[0].sample.origin.sha256.replace_range(..1, "0");
        assert!(matches!(
            family.framework(),
            Err(CorpusCoverageError::InvalidEvidence {
                kind: ConfigKind::Versioning,
                ..
            })
        ));
    }

    #[test]
    fn provider_duplicate_row_mutation_fails_closed() {
        let mut family = crate::object_lock::corpus_evidence();
        family.rejected.push(family.rejected[0].clone());
        let evidence = family.framework().expect("each real row remains traceable");
        assert!(matches!(
            build_corpus_report(&[ConfigKind::ObjectLock], &[evidence]),
            Err(CorpusCoverageError::DuplicateSample {
                kind: ConfigKind::ObjectLock,
                ..
            })
        ));
    }

    #[test]
    fn provider_required_variant_mutation_fails_closed() {
        let mut family = crate::lifecycle::corpus_evidence();
        family
            .accepted
            .retain(|case| !case.variants.contains(&CorpusVariant::TimestampPrecision));
        family
            .rejected
            .retain(|case| !case.variants.contains(&CorpusVariant::TimestampPrecision));
        let evidence = family.framework().expect("remaining real rows remain traceable");
        assert_eq!(
            build_corpus_report(&[ConfigKind::Lifecycle], &[evidence]),
            Err(CorpusCoverageError::MissingVariant {
                kind: ConfigKind::Lifecycle,
                variant: CorpusVariant::TimestampPrecision,
            })
        );
    }
}
