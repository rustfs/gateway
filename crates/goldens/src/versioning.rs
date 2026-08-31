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

//! Versioning persistence compatibility and concrete corpus evidence.
//!
//! Responsible for: binding independent Versioning codecs to D1-D5 and owning every concrete
//! accepted and rejected Versioning corpus case. NOT responsible for: HTTP policy or other bucket
//! configuration families. Upstream: pinned-s3s and production persistence codecs. Downstream:
//! migration goldens and concrete corpus reports.

use rustfs_gateway_types::compat::{S3sVersioningObservation, parse_s3s_versioning, serialize_s3s_versioning};
use rustfs_gateway_types::persistence::{PersistedVersioningConfiguration, parse_versioning, serialize_versioning};
use sha2::{Digest, Sha256};

use crate::{
    AcceptedCorpusCase, ConcreteFamilyCorpus, ConfigKind, CorpusVariant, FourWayCodec, GoldenFailure, GoldenSample,
    RejectedCorpusCase, RejectedGoldenSample, SampleOrigin, assert_four_way,
};

const HISTORICAL: &[u8] = br#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>"#;
const ALL_FIELDS: &[u8] = br#"<VersioningConfiguration><ExcludeFolders>true</ExcludeFolders><ExcludedPrefixes><Prefix>a</Prefix></ExcludedPrefixes><ExcludedPrefixes><Prefix>b</Prefix></ExcludedPrefixes><MfaDelete>Disabled</MfaDelete><Status>Enabled</Status></VersioningConfiguration>"#;
const UNKNOWN_SUSPENDED: &[u8] =
    br#"<VersioningConfiguration><FutureTopLevel>future</FutureTopLevel><Status>Suspended</Status></VersioningConfiguration>"#;
const BODY_LITERAL_PERSISTED: &[u8] = br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#;
const BARE_BODY_LITERAL: &[u8] = b"Enabled";
const EMPTY: &[u8] = br#"<VersioningConfiguration></VersioningConfiguration>"#;
const EMPTY_STATUS: &[u8] = br#"<VersioningConfiguration><Status></Status></VersioningConfiguration>"#;
const UNKNOWN_STATUS: &[u8] = br#"<VersioningConfiguration><Status>Paused</Status></VersioningConfiguration>"#;
const MALFORMED_UNKNOWN_STATUS: &[u8] =
    br#"<VersioningConfiguration><Status>Paused & Pending</Status></VersioningConfiguration>"#;
const DUPLICATE_STATUS: &[u8] =
    br#"<VersioningConfiguration><Status>Enabled</Status><Status>Suspended</Status></VersioningConfiguration>"#;
const OLD_UNREADABLE: &[u8] = b"<not-versioning>";
const MISMATCHED_CLOSE: &[u8] = b"<VersioningConfiguration><Status>Enabled</MfaDelete></VersioningConfiguration>";
const WRONG_ROOT: &[u8] = b"<Other></Other>";
const TWO_ROOTS: &[u8] = b"<VersioningConfiguration></VersioningConfiguration><Other></Other>";
const INVALID_UTF8: &[u8] = b"\xff";
const EMPTY_INPUT: &[u8] = b"";

#[derive(Clone, Debug, Eq, PartialEq)]
struct VersioningBehaviorProjection {
    versioning_enabled: bool,
    versioning_status: Option<String>,
    mfa_delete: Option<String>,
}

/// Runs the real pinned-s3s versus gateway persistence Versioning pilot.
///
/// # Errors
///
/// Returns an invalid-provenance or first D1-D5 failure.
pub fn assert_versioning_four_way(sample: &GoldenSample<PersistedVersioningConfiguration>) -> Result<(), GoldenFailure> {
    assert_four_way(&VersioningCodec, sample)
}

pub(crate) fn run_versioning_corpus_four_way() -> Result<usize, GoldenFailure> {
    let corpus = corpus_evidence();
    for case in &corpus.accepted {
        assert_versioning_four_way(&case.sample)?;
    }
    Ok(corpus.accepted.len())
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

fn base_value() -> PersistedVersioningConfiguration {
    PersistedVersioningConfiguration {
        mfa_delete: Some("Enabled".to_owned()),
        ..PersistedVersioningConfiguration::default()
    }
}

fn accepted(
    bytes: &[u8],
    sha256: &str,
    value: PersistedVersioningConfiguration,
    notes: &str,
    variants: &[CorpusVariant],
) -> AcceptedCorpusCase<PersistedVersioningConfiguration> {
    AcceptedCorpusCase {
        sample: GoldenSample {
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
        },
        variants: variants.to_vec(),
    }
}

fn historical() -> AcceptedCorpusCase<PersistedVersioningConfiguration> {
    AcceptedCorpusCase {
        sample: GoldenSample {
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
        },
        variants: vec![CorpusVariant::Canonical, CorpusVariant::Namespace],
    }
}

fn rejected(bytes: &[u8], notes: &str, variants: &[CorpusVariant]) -> RejectedCorpusCase {
    RejectedCorpusCase {
        sample: RejectedGoldenSample {
            kind: ConfigKind::Versioning,
            bytes: bytes.to_vec(),
            origin: SampleOrigin {
                source: "P9 Versioning refusal matrix".to_owned(),
                producer: "pinned s3s XML behavior".to_owned(),
                version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
                sha256: hex::encode(Sha256::digest(bytes)),
            },
            notes: notes.to_owned(),
        },
        variants: variants.to_vec(),
    }
}

pub(crate) fn corpus_evidence() -> ConcreteFamilyCorpus<PersistedVersioningConfiguration> {
    let prefix = "p".repeat(1024 * 1024);
    let large_bytes = format!(
        "<VersioningConfiguration><ExcludedPrefixes><Prefix>{prefix}</Prefix></ExcludedPrefixes></VersioningConfiguration>"
    )
    .into_bytes();
    let large_digest = hex::encode(Sha256::digest(&large_bytes));
    ConcreteFamilyCorpus {
        kind: ConfigKind::Versioning,
        required_variants: vec![
            CorpusVariant::Canonical,
            CorpusVariant::EmptyElement,
            CorpusVariant::MissingField,
            CorpusVariant::UnknownTopLevel,
            CorpusVariant::BodyLiteral,
            CorpusVariant::Namespace,
            CorpusVariant::DuplicateField,
            CorpusVariant::LargeValue,
            CorpusVariant::Extension,
        ],
        accepted: vec![
            historical(),
            accepted(
                ALL_FIELDS,
                "d24bc9199f709a4195e25df7b01e9246566289d289e969871dbe05f4ab1a8fc2",
                PersistedVersioningConfiguration {
                    status: Some("Enabled".to_owned()),
                    mfa_delete: Some("Disabled".to_owned()),
                    exclude_folders: Some(true),
                    excluded_prefixes: Some(vec![Some("a".to_owned()), Some("b".to_owned())]),
                },
                "all fields make D2 observe extension flattening and order",
                &[CorpusVariant::Canonical, CorpusVariant::Extension],
            ),
            accepted(
                UNKNOWN_SUSPENDED,
                "39c0bba117e8b64307f4ddc56d4150c28eb8b70db0c007150896c7cdd40ca437",
                PersistedVersioningConfiguration {
                    status: Some("Suspended".to_owned()),
                    ..PersistedVersioningConfiguration::default()
                },
                "unknown top-level element must not make the new persistence parser stricter",
                &[CorpusVariant::UnknownTopLevel],
            ),
            accepted(
                UNKNOWN_STATUS,
                "c59f6c3dd6288e8cd2714b710b890d92170c2526f5a90781ef974565f806e465",
                PersistedVersioningConfiguration {
                    status: Some("Paused".to_owned()),
                    ..PersistedVersioningConfiguration::default()
                },
                "g-d5-002 unknown Status is old-readable and must remain disabled in both behavior projections",
                &[CorpusVariant::Extension],
            ),
            accepted(
                BODY_LITERAL_PERSISTED,
                "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a",
                PersistedVersioningConfiguration {
                    status: Some("Enabled".to_owned()),
                    ..PersistedVersioningConfiguration::default()
                },
                "pinned MinIO-compatible HTTP decoding of the bare Enabled body persists this canonical old-readable XML",
                &[CorpusVariant::BodyLiteral],
            ),
            accepted(
                &large_bytes,
                &large_digest,
                PersistedVersioningConfiguration {
                    excluded_prefixes: Some(vec![Some(prefix)]),
                    ..PersistedVersioningConfiguration::default()
                },
                "old-readable persistence metadata must not inherit the smaller HTTP request-body limit",
                &[CorpusVariant::LargeValue, CorpusVariant::Extension],
            ),
            accepted(
                EMPTY,
                "ac87a5732e533b964cf009668f3c9cdddd6e11b6c88b8944ce3ebb9070655f5d",
                PersistedVersioningConfiguration::default(),
                "absence is distinct from Suspended",
                &[CorpusVariant::EmptyElement],
            ),
            accepted(
                EMPTY_STATUS,
                "835f380c356b1a7de54b9e0cf8a2019b8e6826ff922c6d0ebaadc0e3c5759946",
                PersistedVersioningConfiguration {
                    status: Some(String::new()),
                    ..PersistedVersioningConfiguration::default()
                },
                "paired empty Status must stay present",
                &[CorpusVariant::EmptyElement],
            ),
        ],
        rejected: vec![
            rejected(DUPLICATE_STATUS, "duplicate Status", &[CorpusVariant::DuplicateField]),
            rejected(
                MALFORMED_UNKNOWN_STATUS,
                "an unknown Status does not relax XML well-formedness",
                &[CorpusVariant::Extension],
            ),
            rejected(
                BARE_BODY_LITERAL,
                "the HTTP compatibility decoder accepts this literal, but persistence receives its canonical XML output",
                &[CorpusVariant::BodyLiteral],
            ),
            rejected(OLD_UNREADABLE, "unclosed wrong root", &[CorpusVariant::MissingField]),
            rejected(MISMATCHED_CLOSE, "mismatched scalar close tag", &[CorpusVariant::BodyLiteral]),
            rejected(WRONG_ROOT, "wrong root", &[CorpusVariant::MissingField]),
            rejected(TWO_ROOTS, "two document roots", &[CorpusVariant::DuplicateField]),
            rejected(INVALID_UTF8, "invalid UTF-8", &[CorpusVariant::Canonical]),
            rejected(EMPTY_INPUT, "missing document", &[CorpusVariant::MissingField]),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Direction;

    fn base_sample() -> GoldenSample<PersistedVersioningConfiguration> {
        corpus_evidence().accepted[0].sample.clone()
    }

    fn accepted_sample(bytes: &[u8]) -> GoldenSample<PersistedVersioningConfiguration> {
        corpus_evidence()
            .accepted
            .into_iter()
            .find(|case| case.sample.bytes == bytes)
            .expect("provider retains the accepted Versioning case")
            .sample
    }

    fn rejected_sample(bytes: &[u8]) -> RejectedGoldenSample {
        corpus_evidence()
            .rejected
            .into_iter()
            .find(|case| case.sample.bytes == bytes)
            .expect("provider retains the rejected Versioning case")
            .sample
    }

    #[test]
    fn four_way_versioning_pilot_passes_all_five_directions() {
        assert_versioning_four_way(&base_sample()).expect("the independent old and new codecs agree");
    }

    #[test]
    fn every_versioning_field_keeps_the_old_byte_order() {
        assert_versioning_four_way(&accepted_sample(ALL_FIELDS)).expect("the full old shape remains byte-identical");
    }

    #[test]
    fn old_readable_unknown_element_and_suspended_status_stay_readable() {
        assert_versioning_four_way(&accepted_sample(UNKNOWN_SUSPENDED)).expect("unknown old-readable content remains readable");
    }

    #[test]
    fn old_readable_metadata_above_the_http_body_limit_stays_readable() {
        let sample = corpus_evidence()
            .accepted
            .into_iter()
            .find(|case| case.variants.contains(&CorpusVariant::LargeValue))
            .expect("provider retains the large Versioning case")
            .sample;
        assert_versioning_four_way(&sample).expect("the persistence parser is no stricter than the old codec");
    }

    #[test]
    fn empty_document_preserves_never_configured_state() {
        assert_versioning_four_way(&accepted_sample(EMPTY)).expect("empty document means never configured on both sides");
    }

    #[test]
    fn duplicate_status_is_rejected_by_both_real_parsers() {
        let sample = rejected_sample(DUPLICATE_STATUS);
        let old = VersioningCodec
            .old_parse(&sample.bytes)
            .expect_err("old parser rejects duplicate fields");
        let new = VersioningCodec
            .new_parse(&sample.bytes)
            .expect_err("new parser must reject the same duplicate");
        assert!(old.contains("duplicate field"), "unexpected old refusal: {old}");
        assert!(new.contains("duplicate scalar field"), "unexpected new refusal: {new}");
    }

    #[test]
    fn explicit_empty_status_is_not_absence() {
        assert_versioning_four_way(&accepted_sample(EMPTY_STATUS)).expect("empty and absent remain distinct");
    }

    #[test]
    fn unknown_status_keeps_the_same_disabled_behavior_projection() {
        let sample = accepted_sample(UNKNOWN_STATUS);
        let old = VersioningCodec
            .old_parse(&sample.bytes)
            .expect("the pinned old string newtype accepts an unknown status");
        let new = VersioningCodec
            .new_parse(&sample.bytes)
            .expect("the production persistence parser accepts the same unknown status");
        let old_behavior = VersioningCodec.old_behavior(&old);
        let new_behavior = VersioningCodec.new_behavior(&new);

        assert_eq!(old_behavior.versioning_status.as_deref(), Some("Paused"));
        assert!(!old_behavior.versioning_enabled);
        assert_eq!(old_behavior, new_behavior);
        assert_versioning_four_way(&sample).expect("g-d5-002 requires all five directions over the persisted row");
    }

    #[test]
    fn malformed_unknown_status_is_rejected_by_both_real_parsers() {
        let sample = rejected_sample(MALFORMED_UNKNOWN_STATUS);
        assert!(VersioningCodec.old_parse(&sample.bytes).is_err());
        assert!(VersioningCodec.new_parse(&sample.bytes).is_err());
    }

    #[test]
    fn minio_body_literal_value_has_old_persistence_bytes() {
        let case = corpus_evidence()
            .accepted
            .into_iter()
            .find(|case| case.variants.contains(&CorpusVariant::BodyLiteral))
            .expect("g-d1-005 requires an accepted body-literal-derived sample");
        assert_eq!(
            serialize_s3s_versioning(&case.sample.value).expect("the pinned old persistence writer accepts the value"),
            case.sample.bytes,
            "the evidence must be observed old-writer output, not an arbitrary row tagged BodyLiteral"
        );
        assert_versioning_four_way(&case.sample).expect("both persistence codecs accept the observed old-writer bytes");
    }

    #[test]
    fn versioning_sample_matrix_passes_all_five_directions() {
        for case in corpus_evidence().accepted {
            assert_versioning_four_way(&case.sample)
                .unwrap_or_else(|error| panic!("Versioning sample failed ({}): {error}", case.sample.notes));
        }
    }

    #[test]
    fn versioning_refusal_matrix_is_shared_with_corpus_evidence() {
        for case in corpus_evidence().rejected {
            assert!(
                VersioningCodec.old_parse(&case.sample.bytes).is_err(),
                "old accepted {}",
                case.sample.notes
            );
            assert!(
                VersioningCodec.new_parse(&case.sample.bytes).is_err(),
                "new accepted {}",
                case.sample.notes
            );
        }
    }

    struct Mutant {
        panic_on_old_parse: bool,
        old_byte_drift: bool,
        reject_new_output_in_old: bool,
        reject_historical_in_new: bool,
        new_structure_drift: bool,
        old_behavior_drift: bool,
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
            let mut projection = VersioningCodec.old_behavior(value);
            if self.old_behavior_drift {
                projection.versioning_enabled = !projection.versioning_enabled;
            }
            projection
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
            old_behavior_drift: false,
            new_behavior_drift: false,
        }
    }

    #[test]
    fn d1_detects_structure_drift_after_both_parsers_accept() {
        let mut codec = mutant();
        codec.new_structure_drift = true;
        assert_eq!(
            assert_four_way(&codec, &base_sample())
                .expect_err("D1 must compare parsed structures")
                .direction,
            Direction::D1CompatibleRead
        );
    }

    #[test]
    fn d2_detects_one_byte_serializer_drift() {
        let mut codec = mutant();
        codec.old_byte_drift = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D2 must reject one changed byte");
        assert_eq!(failure.direction, Direction::D2ByteWrite);
        assert!(failure.offset.is_some());
    }

    #[test]
    fn d3_detects_an_old_parser_that_rejects_new_output() {
        let mut codec = mutant();
        codec.reject_new_output_in_old = true;
        assert_eq!(
            assert_four_way(&codec, &base_sample())
                .expect_err("D3 must prove rollback readability")
                .direction,
            Direction::D3RollbackRead
        );
    }

    #[test]
    fn d4_detects_a_new_parser_that_rejects_old_readable_input() {
        let mut codec = mutant();
        codec.reject_historical_in_new = true;
        assert_eq!(
            assert_four_way(&codec, &base_sample())
                .expect_err("D4 must reject a stricter parser")
                .direction,
            Direction::D4NotStricter
        );
    }

    #[test]
    fn d5_detects_old_behavior_drift_for_an_unknown_status() {
        let mut codec = mutant();
        codec.old_behavior_drift = true;
        assert_eq!(
            assert_four_way(&codec, &accepted_sample(UNKNOWN_STATUS))
                .expect_err("D5 must reject the pinned-old decision drifting to enabled")
                .direction,
            Direction::D5Behavior
        );
    }

    #[test]
    fn d5_detects_new_behavior_drift_for_an_unknown_status() {
        let mut codec = mutant();
        codec.new_behavior_drift = true;
        assert_eq!(
            assert_four_way(&codec, &accepted_sample(UNKNOWN_STATUS))
                .expect_err("D5 must reject the production decision drifting to enabled")
                .direction,
            Direction::D5Behavior
        );
    }

    #[test]
    fn old_unreadable_corpus_input_fails_instead_of_skipping() {
        let rejected = rejected_sample(OLD_UNREADABLE);
        let invalid = GoldenSample {
            kind: rejected.kind,
            bytes: rejected.bytes,
            value: base_value(),
            origin: rejected.origin,
            notes: rejected.notes,
        };
        assert_eq!(
            assert_four_way(&mutant(), &invalid)
                .expect_err("missing old observation must fail closed")
                .direction,
            Direction::D1CompatibleRead
        );
    }

    #[test]
    fn missing_provenance_fails_before_any_codec_observation() {
        let mut invalid = base_sample();
        invalid.origin.source.clear();
        assert_eq!(
            assert_four_way(&mutant(), &invalid)
                .expect_err("missing source must fail closed")
                .direction,
            Direction::Input
        );
    }

    #[test]
    fn stale_sample_digest_fails_before_any_codec_observation() {
        let mut invalid = base_sample();
        invalid.origin.sha256.replace_range(..1, "0");
        assert_eq!(
            assert_four_way(&mutant(), &invalid)
                .expect_err("stale digest must fail closed")
                .direction,
            Direction::Input
        );
    }

    #[test]
    fn sample_kind_mismatch_fails_before_any_codec_observation() {
        let mut invalid = base_sample();
        invalid.kind = ConfigKind::ObjectLock;
        let mut codec = mutant();
        codec.panic_on_old_parse = true;
        assert_eq!(
            assert_four_way(&codec, &invalid)
                .expect_err("a mislabeled sample must fail closed")
                .direction,
            Direction::Input
        );
    }
}
