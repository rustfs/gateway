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

use rustfs_gateway_types::compat::{S3sVersioningObservation, parse_s3s_versioning, serialize_s3s_versioning};
use rustfs_gateway_types::persistence::{PersistedVersioningConfiguration, parse_versioning, serialize_versioning};
use sha2::{Digest, Sha256};

mod accelerate_payment;
mod bucket_encryption;
mod corpus;
mod cors;
mod lifecycle;
mod logging;
mod notification;
mod object_lock;
mod public_access_block;
mod replication;
mod tagging;
mod website;

pub use accelerate_payment::{assert_accelerate_four_way, assert_request_payment_four_way};
pub use bucket_encryption::assert_bucket_encryption_four_way;
pub use corpus::{
    CorpusCaseEvidence, CorpusCoverageError, CorpusReport, CorpusVariant, FamilyCorpusEvidence, RejectedGoldenSample,
    build_corpus_report,
};
pub use cors::assert_cors_four_way;
pub use lifecycle::assert_lifecycle_four_way;
pub use logging::assert_bucket_logging_four_way;
pub use notification::assert_notification_four_way;
pub use object_lock::assert_object_lock_four_way;
pub use public_access_block::assert_public_access_block_four_way;
pub use replication::assert_replication_four_way;
pub use tagging::assert_tagging_four_way;
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct VersioningBehaviorProjection {
    versioning_enabled: bool,
    versioning_status: Option<String>,
    mfa_delete: Option<String>,
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

/// Runs the real pinned-s3s versus gateway persistence Versioning pilot.
///
/// # Errors
///
/// Returns an invalid-provenance or first D1-D5 failure.
pub fn assert_versioning_four_way(sample: &GoldenSample<PersistedVersioningConfiguration>) -> Result<(), GoldenFailure> {
    assert_four_way(&VersioningCodec, sample)
}

#[derive(Clone, Copy, Debug)]
struct VersioningCodec;

impl FourWayCodec for VersioningCodec {
    const KIND: ConfigKind = ConfigKind::Versioning;

    type Value = PersistedVersioningConfiguration;
    type OldParsed = S3sVersioningObservation;
    type NewParsed = PersistedVersioningConfiguration;
    type Structure = PersistedVersioningConfiguration;
    type Behavior = VersioningBehaviorProjection;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_versioning(bytes).map_err(|error| error.to_string())
    }

    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_versioning(bytes).map_err(|error| error.to_string())
    }

    fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
        value.structure.clone()
    }

    fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
        value.clone()
    }

    fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
        value.clone()
    }

    fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        serialize_s3s_versioning(value).map_err(|error| error.to_string())
    }

    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_versioning(value))
    }

    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        VersioningBehaviorProjection {
            versioning_enabled: value.versioning_enabled,
            versioning_status: value.versioning_status.clone(),
            mfa_delete: value.mfa_delete.clone(),
        }
    }

    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        VersioningBehaviorProjection {
            versioning_enabled: value.versioning_enabled(),
            versioning_status: value.status.clone(),
            mfa_delete: value.mfa_delete.clone(),
        }
    }
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

    const HISTORICAL: &[u8] = br#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>"#;
    const ALL_FIELDS: &[u8] = br#"<VersioningConfiguration><ExcludeFolders>true</ExcludeFolders><ExcludedPrefixes><Prefix>a</Prefix></ExcludedPrefixes><ExcludedPrefixes><Prefix>b</Prefix></ExcludedPrefixes><MfaDelete>Disabled</MfaDelete><Status>Enabled</Status></VersioningConfiguration>"#;
    const UNKNOWN_SUSPENDED: &[u8] = br#"<VersioningConfiguration><FutureTopLevel>future</FutureTopLevel><Status>Suspended</Status></VersioningConfiguration>"#;
    const EMPTY: &[u8] = br#"<VersioningConfiguration></VersioningConfiguration>"#;
    const DUPLICATE_STATUS: &[u8] =
        br#"<VersioningConfiguration><Status>Enabled</Status><Status>Suspended</Status></VersioningConfiguration>"#;
    const EMPTY_STATUS: &[u8] = br#"<VersioningConfiguration><Status></Status></VersioningConfiguration>"#;

    fn base_value() -> PersistedVersioningConfiguration {
        PersistedVersioningConfiguration {
            mfa_delete: Some("Enabled".to_owned()),
            ..PersistedVersioningConfiguration::default()
        }
    }

    fn sample() -> GoldenSample<PersistedVersioningConfiguration> {
        GoldenSample {
            kind: ConfigKind::Versioning,
            bytes: HISTORICAL.to_vec(),
            value: base_value(),
            origin: SampleOrigin {
                source: "rustfs/crates/ecstore/src/services/tier/warm_backend_wasabi.rs".to_owned(),
                producer: "RustFS Wasabi response fixture".to_owned(),
                version: "rustfs@1c8088d0b2af0a1afc8df128014b2176037a0622".to_owned(),
                sha256: "2b687cc0f956f0b0d1ebe8511d637316c7869637191ad02a9373a9b858f20b8f".to_owned(),
            },
            notes: "repository fixture that is old-readable with a namespace and canonicalizes without one".to_owned(),
        }
    }

    fn synthetic(
        bytes: &[u8],
        sha256: &str,
        value: PersistedVersioningConfiguration,
        notes: &str,
    ) -> GoldenSample<PersistedVersioningConfiguration> {
        GoldenSample {
            kind: ConfigKind::Versioning,
            bytes: bytes.to_vec(),
            value,
            origin: SampleOrigin {
                source: "P9 Versioning pilot matrix".to_owned(),
                producer: "pinned s3s XML behavior".to_owned(),
                version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
                sha256: sha256.to_owned(),
            },
            notes: notes.to_owned(),
        }
    }

    #[test]
    fn four_way_versioning_pilot_passes_all_five_directions() {
        assert_versioning_four_way(&sample()).expect("the independent old and new codecs agree");
    }

    #[test]
    fn every_versioning_field_keeps_the_old_byte_order() {
        let value = PersistedVersioningConfiguration {
            status: Some("Enabled".to_owned()),
            mfa_delete: Some("Disabled".to_owned()),
            exclude_folders: Some(true),
            excluded_prefixes: Some(vec![Some("a".to_owned()), Some("b".to_owned())]),
        };
        let case = synthetic(
            ALL_FIELDS,
            "d24bc9199f709a4195e25df7b01e9246566289d289e969871dbe05f4ab1a8fc2",
            value,
            "all fields make D2 observe extension flattening and order",
        );
        assert_versioning_four_way(&case).expect("the full old shape remains byte-identical");
    }

    #[test]
    fn old_readable_unknown_element_and_suspended_status_stay_readable() {
        let value = PersistedVersioningConfiguration {
            status: Some("Suspended".to_owned()),
            ..PersistedVersioningConfiguration::default()
        };
        let case = synthetic(
            UNKNOWN_SUSPENDED,
            "39c0bba117e8b64307f4ddc56d4150c28eb8b70db0c007150896c7cdd40ca437",
            value,
            "unknown top-level element must not make the new persistence parser stricter",
        );
        assert_versioning_four_way(&case).expect("unknown old-readable content remains readable");
    }

    #[test]
    fn old_readable_metadata_above_the_http_body_limit_stays_readable() {
        let prefix = "p".repeat(1024 * 1024);
        let bytes = format!(
            "<VersioningConfiguration><ExcludedPrefixes><Prefix>{prefix}</Prefix></ExcludedPrefixes></VersioningConfiguration>"
        )
        .into_bytes();
        let digest = hex::encode(Sha256::digest(&bytes));
        let value = PersistedVersioningConfiguration {
            excluded_prefixes: Some(vec![Some(prefix)]),
            ..PersistedVersioningConfiguration::default()
        };
        let case = synthetic(
            &bytes,
            &digest,
            value,
            "old-readable persistence metadata must not inherit the smaller HTTP request-body limit",
        );
        assert_versioning_four_way(&case).expect("the persistence parser is no stricter than the old codec");
    }

    #[test]
    fn empty_document_preserves_never_configured_state() {
        let case = synthetic(
            EMPTY,
            "ac87a5732e533b964cf009668f3c9cdddd6e11b6c88b8944ce3ebb9070655f5d",
            PersistedVersioningConfiguration::default(),
            "absence is distinct from Suspended",
        );
        assert_versioning_four_way(&case).expect("empty document means never configured on both sides");
    }

    #[test]
    fn duplicate_status_is_rejected_by_both_real_parsers() {
        let old = VersioningCodec
            .old_parse(DUPLICATE_STATUS)
            .expect_err("old parser rejects duplicate fields");
        let new = VersioningCodec
            .new_parse(DUPLICATE_STATUS)
            .expect_err("new parser must reject the same duplicate");
        assert!(old.contains("duplicate field"), "unexpected old refusal: {old}");
        assert!(new.contains("duplicate scalar field"), "unexpected new refusal: {new}");
    }

    #[test]
    fn explicit_empty_status_is_not_absence() {
        let value = PersistedVersioningConfiguration {
            status: Some(String::new()),
            ..PersistedVersioningConfiguration::default()
        };
        let case = synthetic(
            EMPTY_STATUS,
            "835f380c356b1a7de54b9e0cf8a2019b8e6826ff922c6d0ebaadc0e3c5759946",
            value,
            "paired empty Status must stay present",
        );
        assert_versioning_four_way(&case).expect("empty and absent remain distinct");
    }

    struct Mutant {
        panic_on_old_parse: bool,
        old_byte_drift: bool,
        reject_new_output_in_old: bool,
        reject_historical_in_new: bool,
        new_structure_drift: bool,
        new_behavior_drift: bool,
    }

    impl FourWayCodec for Mutant {
        const KIND: ConfigKind = ConfigKind::Versioning;

        type Value = PersistedVersioningConfiguration;
        type OldParsed = S3sVersioningObservation;
        type NewParsed = PersistedVersioningConfiguration;
        type Structure = PersistedVersioningConfiguration;
        type Behavior = VersioningBehaviorProjection;

        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_on_old_parse, "input validation must run before the old parser");
            let canonical = VersioningCodec.new_serialize(&base_value())?;
            if self.reject_new_output_in_old && bytes == canonical {
                return Err("mutation: rollback parser rejects the new output".to_owned());
            }
            VersioningCodec.old_parse(bytes)
        }

        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.reject_historical_in_new && bytes == HISTORICAL {
                return Err("mutation: new parser is stricter".to_owned());
            }
            let mut parsed = VersioningCodec.new_parse(bytes)?;
            if self.new_structure_drift {
                parsed.mfa_delete = Some("Disabled".to_owned());
            }
            Ok(parsed)
        }

        fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
            VersioningCodec.old_structure(value)
        }

        fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
            VersioningCodec.new_structure(value)
        }

        fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
            VersioningCodec.expected_structure(value)
        }

        fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            let mut bytes = VersioningCodec.old_serialize(value)?;
            if self.old_byte_drift {
                bytes.push(b' ');
            }
            Ok(bytes)
        }

        fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            VersioningCodec.new_serialize(value)
        }

        fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
            VersioningCodec.old_behavior(value)
        }

        fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
            let mut projection = VersioningCodec.new_behavior(value);
            if self.new_behavior_drift {
                projection.versioning_enabled = !projection.versioning_enabled;
            }
            projection
        }
    }

    fn mutant() -> Mutant {
        Mutant {
            panic_on_old_parse: false,
            old_byte_drift: false,
            reject_new_output_in_old: false,
            reject_historical_in_new: false,
            new_structure_drift: false,
            new_behavior_drift: false,
        }
    }

    #[test]
    fn d2_detects_one_byte_serializer_drift() {
        let mut codec = mutant();
        codec.old_byte_drift = true;
        let failure = assert_four_way(&codec, &sample()).expect_err("D2 must reject one changed byte");
        assert_eq!(failure.direction, Direction::D2ByteWrite);
        assert!(failure.offset.is_some());
    }

    #[test]
    fn d3_detects_an_old_parser_that_rejects_new_output() {
        let mut codec = mutant();
        codec.reject_new_output_in_old = true;
        let failure = assert_four_way(&codec, &sample()).expect_err("D3 must prove rollback readability");
        assert_eq!(failure.direction, Direction::D3RollbackRead);
    }

    #[test]
    fn d4_detects_a_new_parser_that_rejects_old_readable_input() {
        let mut codec = mutant();
        codec.reject_historical_in_new = true;
        let failure = assert_four_way(&codec, &sample()).expect_err("D4 must reject a stricter parser");
        assert_eq!(failure.direction, Direction::D4NotStricter);
    }

    #[test]
    fn d1_detects_structure_drift_after_both_parsers_accept() {
        let mut codec = mutant();
        codec.new_structure_drift = true;
        let failure = assert_four_way(&codec, &sample()).expect_err("D1 must compare parsed structures");
        assert_eq!(failure.direction, Direction::D1CompatibleRead);
    }

    #[test]
    fn old_unreadable_corpus_input_fails_instead_of_skipping() {
        let mut invalid = sample();
        invalid.bytes = b"<not-versioning>".to_vec();
        invalid.origin.sha256 = hex::encode(Sha256::digest(&invalid.bytes));
        let failure = assert_four_way(&mutant(), &invalid).expect_err("missing old observation must fail closed");
        assert_eq!(failure.direction, Direction::D1CompatibleRead);
    }

    #[test]
    fn d5_detects_behavior_drift_after_structure_matches() {
        let mut codec = mutant();
        codec.new_behavior_drift = true;
        let failure = assert_four_way(&codec, &sample()).expect_err("D5 must use independent behavior projections");
        assert_eq!(failure.direction, Direction::D5Behavior);
    }

    #[test]
    fn missing_provenance_fails_before_any_codec_observation() {
        let mut invalid = sample();
        invalid.origin.source.clear();
        let failure = assert_four_way(&mutant(), &invalid).expect_err("missing source must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }

    #[test]
    fn stale_sample_digest_fails_before_any_codec_observation() {
        let mut invalid = sample();
        invalid.origin.sha256.replace_range(..1, "0");
        let failure = assert_four_way(&mutant(), &invalid).expect_err("stale digest must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }

    #[test]
    fn sample_kind_mismatch_fails_before_any_codec_observation() {
        let mut invalid = sample();
        invalid.kind = ConfigKind::ObjectLock;
        let mut codec = mutant();
        codec.panic_on_old_parse = true;
        let failure = assert_four_way(&codec, &invalid).expect_err("a mislabeled sample must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }
}
