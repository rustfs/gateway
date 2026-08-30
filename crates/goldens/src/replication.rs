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

//! Replication persistence compatibility evidence.
//!
//! Responsible for: binding independent pinned-s3s and production Replication codecs to D1-D5.
//! NOT responsible for: replication policy validation, execution, or other configuration families.
//! Upstream: types persistence and compat seams. Downstream: the P9 migration golden gate.

use rustfs_gateway_types::compat::{S3sReplicationObservation, parse_s3s_replication, serialize_s3s_replication};
use rustfs_gateway_types::persistence::{
    PersistedReplicationConfiguration, ReplicationBehaviorProjection, parse_replication, serialize_replication,
};

use crate::{
    ConfigKind, CorpusCaseEvidence, CorpusCoverageError, CorpusVariant, FamilyCorpusEvidence, FourWayCodec, GoldenFailure,
    GoldenSample, RejectedGoldenSample, SampleOrigin, assert_four_way,
};

const MINIMAL: &[u8] = b"<ReplicationConfiguration><Role>arn:aws:iam::123456789012:role/replication</Role><Rule><Destination><Bucket>arn:aws:s3:::target</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>";
const NAMESPACE: &[u8] = br#"<ReplicationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Role>arn:aws:iam::123456789012:role/replication</Role><Rule><Destination><Bucket>arn:aws:s3:::target</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>"#;
const UNKNOWN_TOP: &[u8] = b"<ReplicationConfiguration><FutureTopLevel>future</FutureTopLevel><Role>arn:aws:iam::123456789012:role/replication</Role><Rule><Destination><Bucket>arn:aws:s3:::target</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>";
const ALTERNATE_ORDER: &[u8] = b"<ReplicationConfiguration><Rule><Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::target</Bucket></Destination></Rule><Role>arn:aws:iam::123456789012:role/replication</Role></ReplicationConfiguration>";
const UNKNOWN_STATUS: &[u8] = b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Paused</Status></Rule></ReplicationConfiguration>";
const FILTER_PREFIX: &[u8] = b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status></Rule></ReplicationConfiguration>";
const FILTER_TAG: &[u8] = "<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Filter><Tag><Key>café</Key><Value>ice-🧊</Value></Tag></Filter><Status>Enabled</Status></Rule></ReplicationConfiguration>".as_bytes();
const BOM_CRLF: &[u8] = b"\xef\xbb\xbf<ReplicationConfiguration>\r\n<Role>role</Role>\r\n<Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule>\r\n</ReplicationConfiguration>";
const UNKNOWN_ATTRIBUTE: &[u8] = br#"<ReplicationConfiguration data-version="old"><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>"#;
const EMPTY_DELETE_MARKER: &[u8] = b"<ReplicationConfiguration><Role>role</Role><Rule><DeleteMarkerReplication></DeleteMarkerReplication><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>";
const INERT_DOCTYPE: &[u8] = b"<!DOCTYPE ReplicationConfiguration><ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>";

type AcceptedReplicationCase = (GoldenSample<PersistedReplicationConfiguration>, &'static [CorpusVariant]);
type RejectedReplicationCase = (RejectedGoldenSample, &'static [CorpusVariant]);

fn origin(sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: "repository replication persistence fixture".to_owned(),
        producer: "s3s pinned persistence codec".to_owned(),
        version: "9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn accepted(bytes: &[u8], sha256: &str, notes: &str, variants: &'static [CorpusVariant]) -> AcceptedReplicationCase {
    let value = parse_s3s_replication(bytes)
        .expect("hard-coded accepted fixture is old-readable")
        .structure; // Every caller passes a pinned accepted fixture.
    (
        GoldenSample {
            kind: ConfigKind::Replication,
            bytes: bytes.to_vec(),
            value,
            origin: origin(sha256),
            notes: notes.to_owned(),
        },
        variants,
    )
}

fn rejected(bytes: &[u8], sha256: &str, notes: &str, variants: &'static [CorpusVariant]) -> RejectedReplicationCase {
    (
        RejectedGoldenSample {
            kind: ConfigKind::Replication,
            bytes: bytes.to_vec(),
            origin: origin(sha256),
            notes: notes.to_owned(),
        },
        variants,
    )
}

fn namespace_case() -> AcceptedReplicationCase {
    accepted(
        NAMESPACE,
        "0634a9dfb3c1a94a10cacd0136dbdcfb09cc1ab6a14c45c9629eb37044b4706c",
        "historical namespace declaration is ignored by the persistence codec",
        &[CorpusVariant::Namespace],
    )
}

fn accepted_cases() -> Vec<AcceptedReplicationCase> {
    let large_role = format!(
        "<ReplicationConfiguration><Role>{}</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>",
        "x".repeat(8 * 1024)
    )
    .into_bytes();
    vec![
        accepted(
            MINIMAL,
            "1ebe6a8e64f2bd34a20d2e292d3c8a9c091c4e6bfa56c4c4c8d80ced64eb6436",
            "minimal required role, destination, and rule status",
            &[CorpusVariant::Canonical],
        ),
        namespace_case(),
        accepted(
            UNKNOWN_TOP,
            "4f58abf329d86ecc601fc9bfc39a38b6f166811f01474630371e67eb35140e06",
            "unknown top-level element retained as an old-readable boundary",
            &[CorpusVariant::UnknownTopLevel],
        ),
        accepted(
            ALTERNATE_ORDER,
            "1c4cf86cfff7cd282a7ccf78b0035f9368dd8f82d57c69f47888cb84ed23befd",
            "known elements in historical noncanonical order",
            &[CorpusVariant::AlternateOrder],
        ),
        accepted(
            UNKNOWN_STATUS,
            "bbf4497532438e0297d27c0ef3df3e99fda33a750999914ab91a8c23966b9274",
            "unknown string-newtype status remains readable and disabled",
            &[CorpusVariant::UnknownScalar],
        ),
        accepted(
            FILTER_PREFIX,
            "d8ec3893294e9c4fd76a4764402e91ca30f06f9211078bfdc2aa61fa7f118018",
            "prefix filter behavior",
            &[CorpusVariant::Canonical],
        ),
        accepted(
            FILTER_TAG,
            "5a9de4bcf4106037b511ed0702de7d479a6c94da4d52bfce8ad4705ae9b65ec6",
            "non-ASCII tag value remains codepoint-exact",
            &[CorpusVariant::Unicode],
        ),
        accepted(
            BOM_CRLF,
            "cd2f215c0d9b1223bb51baa21a20a4ccb7974bc901a3db1ebb1f96586c563ba2",
            "BOM and CRLF historical bytes",
            &[CorpusVariant::Bom, CorpusVariant::Crlf],
        ),
        accepted(
            UNKNOWN_ATTRIBUTE,
            "47dfbb126c43286fd520f9c77cd094fbaa10d034f52160849217c0b1581f89bc",
            "unknown root attribute remains old-readable",
            &[CorpusVariant::UnknownAttribute],
        ),
        accepted(
            EMPTY_DELETE_MARKER,
            "47c092aa3c288300b53dc2d29daccd3491541d1505c052168b4836c21208bf22",
            "historical delete-marker wrapper may omit its optional status",
            &[CorpusVariant::EmptyElement],
        ),
        accepted(
            INERT_DOCTYPE,
            "cc20e97385758fb57c158d4b43a0530e0cad40afbda8f3ab6cdf93ef8d0746b9",
            "historical inert document type declaration remains old-readable",
            &[CorpusVariant::Extension],
        ),
        accepted(
            &large_role,
            "438c0844bb4fc9ccdf1b763aa145b58ff5e7a593e948ae38b9c359fce070e0b3",
            "role value at the required 8 KiB boundary",
            &[CorpusVariant::LargeValue],
        ),
    ]
}

fn rejected_cases() -> Vec<RejectedReplicationCase> {
    vec![
        rejected(b"<ReplicationConfiguration><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>", "cc9817241291561b5cbaec52f7a605858de2eeefb34d35fb084119c927ab20aa", "missing Role", &[CorpusVariant::MissingField]),
        rejected(b"<ReplicationConfiguration><Role>role</Role></ReplicationConfiguration>", "83f845efa79fbac076928fad0234d72ff2bcaef9672f8950706e96422a957d1c", "missing Rule", &[CorpusVariant::MissingField]),
        rejected(b"<ReplicationConfiguration><Role>role</Role><Rule><Status>Enabled</Status></Rule></ReplicationConfiguration>", "4766770008bd87d7ac645bb94c41e9be6cab34bf9bfffd951162fe132322381c", "missing Destination", &[CorpusVariant::MissingField]),
        rejected(b"<ReplicationConfiguration><Role>role</Role><Rule><Destination></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>", "5c2a6291d47a64618c2bb020ea807fe136f6c9e30ce8690dc541997616bc3444", "missing Destination.Bucket", &[CorpusVariant::MissingField]),
        rejected(b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination></Rule></ReplicationConfiguration>", "0e6c1f332cf6db585dbe36197c8192b6b300022e305dc9ca2e003de687e9d916", "missing Rule.Status", &[CorpusVariant::MissingField]),
        rejected(b"<ReplicationConfiguration><Role>one</Role><Role>two</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>", "95a14926feb8c6b654301f8ff7901864e29131dddd73f92979b3c5adb98ea6c0", "duplicate Role", &[CorpusVariant::DuplicateField]),
        rejected(b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>one</Bucket><Bucket>two</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>", "1b05fd826d04b6dde8a07d05cfec99da45ebbc3e49d1d92067b70d8b5ed99e9c", "duplicate Destination.Bucket", &[CorpusVariant::DuplicateField]),
        rejected(b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status><Status>Disabled</Status></Rule></ReplicationConfiguration>", "88cf06cad3d6a96115126011b88f7725c91fbf4f1874d40dfa459e8a7d21f1bb", "duplicate Rule.Status", &[CorpusVariant::DuplicateField]),
        rejected(b"<ReplicationConfiguration><Role>role</Role><Rule><Future>value</Future><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>", "b780a8093262d85f773b3ce2f0f85cbca754abd87fa6ce5091d61116556f79a0", "unknown nested Rule child", &[CorpusVariant::UnknownNested]),
        rejected(b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket><ReplicationTime><Status>Enabled</Status></ReplicationTime></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>", "00c32f59adc4adf9d0a48e1785e5cf33c8beddf861e2d9cd6f9c1eaa6a68b070", "missing ReplicationTime.Time", &[CorpusVariant::MissingField]),
        rejected(b"<ReplicationConfiguration><Role><Future>role</Future></Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>", "b3e8b6d1e9cab292b1f953bc665a61149ca74990cc208f2e3db46e2dad66140a", "unknown nested Role child", &[CorpusVariant::UnknownNested]),
        rejected(b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Priority>not-an-int</Priority><Status>Enabled</Status></Rule></ReplicationConfiguration>", "19443eabdac5dd6bd1e48a034245753d7a04ad59b6af7dbddaef0b75733bf845", "invalid Priority scalar", &[CorpusVariant::UnknownScalar]),
        rejected(b"<WrongRoot></WrongRoot>", "ec4479e283c2fa7e1dcc960b277dfd81dc72c53822c55ac73dadb05682c9980f", "wrong Replication root", &[CorpusVariant::MissingField]),
        rejected(b"<ReplicationConfiguration>", "0e2ade2505d1e75517dcce1e88dd515380ba174bf1fca9d3f9b7b147629d9ccf", "unterminated Replication document", &[CorpusVariant::MissingField]),
        rejected(b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty Replication document", &[CorpusVariant::EmptyElement, CorpusVariant::MissingField]),
    ]
}

/// Builds Replication corpus coverage from the exact cases used by codec tests.
///
/// # Errors
///
/// Returns an error when provenance is stale or a concrete case lacks a variant.
pub(crate) fn replication_corpus_evidence() -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
    let mut cases = Vec::new();
    for (sample, variants) in accepted_cases() {
        cases.push(CorpusCaseEvidence::accepted(&sample, variants)?);
    }
    for (sample, variants) in rejected_cases() {
        cases.push(CorpusCaseEvidence::rejected(&sample, variants)?);
    }
    Ok(FamilyCorpusEvidence::new(
        ConfigKind::Replication,
        vec![
            CorpusVariant::Canonical,
            CorpusVariant::EmptyElement,
            CorpusVariant::MissingField,
            CorpusVariant::UnknownTopLevel,
            CorpusVariant::UnknownNested,
            CorpusVariant::UnknownAttribute,
            CorpusVariant::Namespace,
            CorpusVariant::AlternateOrder,
            CorpusVariant::DuplicateField,
            CorpusVariant::UnknownScalar,
            CorpusVariant::LargeValue,
            CorpusVariant::Bom,
            CorpusVariant::Crlf,
            CorpusVariant::Unicode,
            CorpusVariant::Extension,
        ],
        cases,
    ))
}

#[derive(Clone, Copy, Debug)]
struct ReplicationCodec;

impl FourWayCodec for ReplicationCodec {
    const KIND: ConfigKind = ConfigKind::Replication;

    type Value = PersistedReplicationConfiguration;
    type OldParsed = S3sReplicationObservation;
    type NewParsed = PersistedReplicationConfiguration;
    type Structure = PersistedReplicationConfiguration;
    type Behavior = ReplicationBehaviorProjection;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_replication(bytes).map_err(|error| error.to_string())
    }

    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_replication(bytes).map_err(|error| error.to_string())
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
        serialize_s3s_replication(value).map_err(|error| error.to_string())
    }

    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        serialize_replication(value).map_err(|error| error.to_string())
    }

    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        value.behavior.clone()
    }

    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        value.behavior()
    }
}

/// Runs pinned-old versus production Replication persistence evidence.
///
/// # Errors
///
/// Returns invalid provenance or the first D1-D5 failure.
pub fn assert_replication_four_way(sample: &GoldenSample<PersistedReplicationConfiguration>) -> Result<(), GoldenFailure> {
    assert_four_way(&ReplicationCodec, sample)
}

pub(crate) fn run_replication_corpus_four_way() -> Result<usize, GoldenFailure> {
    let cases = accepted_cases();
    for (sample, _) in &cases {
        assert_replication_four_way(sample)?;
    }
    Ok(cases.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustfs_gateway_types::persistence::{
        PersistedAccessControlTranslation, PersistedEncryptionConfiguration, PersistedOptionalReplicationStatus,
        PersistedReplicationAnd, PersistedReplicationDestination, PersistedReplicationFilter, PersistedReplicationMetrics,
        PersistedReplicationRule, PersistedReplicationStatus, PersistedReplicationTag, PersistedReplicationTime,
        PersistedReplicationTimeValue, PersistedSourceSelectionCriteria,
    };

    fn minimal() -> PersistedReplicationConfiguration {
        PersistedReplicationConfiguration {
            role: "arn:aws:iam::123456789012:role/replication".to_owned(),
            rules: vec![PersistedReplicationRule {
                delete_marker_replication: None,
                delete_replication: None,
                destination: PersistedReplicationDestination {
                    bucket: "arn:aws:s3:::target".to_owned(),
                    ..PersistedReplicationDestination::default()
                },
                existing_object_replication: None,
                filter: None,
                id: None,
                prefix: None,
                priority: None,
                source_selection_criteria: None,
                status: "Enabled".to_owned(),
            }],
        }
    }

    fn full() -> PersistedReplicationConfiguration {
        PersistedReplicationConfiguration {
            role: "arn:aws:iam::123456789012:role/full-replication".to_owned(),
            rules: vec![PersistedReplicationRule {
                delete_marker_replication: Some(PersistedOptionalReplicationStatus {
                    status: Some("Enabled".to_owned()),
                }),
                delete_replication: Some(PersistedReplicationStatus {
                    status: "Disabled".to_owned(),
                }),
                destination: PersistedReplicationDestination {
                    account: Some("123456789012".to_owned()),
                    access_control_translation: Some(PersistedAccessControlTranslation {
                        owner: "Destination".to_owned(),
                    }),
                    bucket: "arn:aws:s3:::archive".to_owned(),
                    encryption_configuration: Some(PersistedEncryptionConfiguration {
                        replica_kms_key_id: Some("arn:aws:kms:us-east-1:123456789012:key/example".to_owned()),
                    }),
                    metrics: Some(PersistedReplicationMetrics {
                        event_threshold: Some(PersistedReplicationTimeValue { minutes: Some(15) }),
                        status: "Enabled".to_owned(),
                    }),
                    replication_time: Some(PersistedReplicationTime {
                        status: "Enabled".to_owned(),
                        time: PersistedReplicationTimeValue { minutes: Some(15) },
                    }),
                    storage_class: Some("GLACIER".to_owned()),
                },
                existing_object_replication: Some(PersistedReplicationStatus {
                    status: "Enabled".to_owned(),
                }),
                filter: Some(PersistedReplicationFilter {
                    and: Some(PersistedReplicationAnd {
                        prefix: Some("logs/".to_owned()),
                        tags: Some(vec![
                            PersistedReplicationTag {
                                key: Some("env".to_owned()),
                                value: Some("prod".to_owned()),
                            },
                            PersistedReplicationTag {
                                key: Some("tier".to_owned()),
                                value: Some("cold".to_owned()),
                            },
                        ]),
                    }),
                    prefix: None,
                    tag: None,
                }),
                id: Some("full-rule".to_owned()),
                prefix: Some("legacy/".to_owned()),
                priority: Some(7),
                source_selection_criteria: Some(PersistedSourceSelectionCriteria {
                    replica_modifications: Some(PersistedReplicationStatus {
                        status: "Enabled".to_owned(),
                    }),
                    sse_kms_encrypted_objects: Some(PersistedReplicationStatus {
                        status: "Enabled".to_owned(),
                    }),
                }),
                status: "Enabled".to_owned(),
            }],
        }
    }

    fn base_sample() -> GoldenSample<PersistedReplicationConfiguration> {
        namespace_case().0
    }

    #[test]
    fn minimal_replication_is_readable_by_both_codecs() {
        let old = parse_s3s_replication(MINIMAL).expect("pinned old parser accepts minimal replication");
        let new = parse_replication(MINIMAL).expect("production parser accepts minimal replication");
        assert_eq!(old.structure, new);
        assert_eq!(new, minimal());
    }

    #[test]
    fn empty_metrics_and_rtc_wrappers_preserve_presence() {
        let bytes = b"<ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket><Metrics><EventThreshold></EventThreshold><Status>Enabled</Status></Metrics><ReplicationTime><Status>Enabled</Status><Time></Time></ReplicationTime></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>";
        let old = parse_s3s_replication(bytes).expect("pinned old parser accepts empty minutes wrappers");
        let new = parse_replication(bytes).expect("production parser accepts empty minutes wrappers");
        assert_eq!(new, old.structure);
        assert_eq!(
            serialize_replication(&new).expect("production writer preserves wrappers"),
            serialize_s3s_replication(&new).expect("pinned old writer preserves wrappers")
        );
    }

    #[test]
    fn pinned_old_serializer_defines_full_replication_bytes() {
        let value = full();
        let old = serialize_s3s_replication(&value).expect("pinned old serializer accepts full replication");
        let new = serialize_replication(&value).expect("production serializer accepts full replication");
        assert_eq!(new, old);
        let old_round_trip = parse_s3s_replication(&new).expect("pinned old parser reads production bytes");
        assert_eq!(old_round_trip.structure, value);
        let new_behavior = value.behavior();
        assert_eq!(old_round_trip.behavior, new_behavior);
        assert_eq!(new_behavior.rules[0].replica_modifications_status.as_deref(), Some("Enabled"));
        assert_eq!(new_behavior.rules[0].sse_kms_encrypted_objects_status.as_deref(), Some("Enabled"));
    }

    #[test]
    fn inert_doctype_boundary_matches_the_pinned_old_parser() {
        let accepted: [&[u8]; 4] = [
            INERT_DOCTYPE,
            b" \n<!DOCTYPE ReplicationConfiguration><ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>",
            b"<!DOCTYPE ReplicationConfiguration   ><ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>",
            br#"<?xml version="1.0"?><!DOCTYPE ReplicationConfiguration><ReplicationConfiguration><Role>role</Role><Rule><Destination><Bucket>bucket</Bucket></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>"#,
        ];
        for bytes in accepted {
            let old = parse_s3s_replication(bytes).expect("pinned old parser accepts the inert declaration");
            let new = parse_replication(bytes).expect("production parser preserves the old-readable boundary");
            assert_eq!(new, old.structure);
        }
    }

    #[test]
    fn twelve_traceable_replication_samples_pass_d1_through_d5() {
        for (case, _) in accepted_cases() {
            assert_replication_four_way(&case).expect("Replication sample passes D1-D5");
        }
    }

    #[test]
    fn rejected_documents_match_the_old_parser_more_often_than_the_positive_matrix() {
        for (case, _) in rejected_cases() {
            assert!(parse_s3s_replication(&case.bytes).is_err(), "old decoder rejects {}", case.notes);
            assert!(parse_replication(&case.bytes).is_err(), "new decoder matches old refusal {}", case.notes);
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct ReplicationMutant {
        old_byte_drift: bool,
        rollback_refusal: bool,
        stricter_new: bool,
        structure_drift: bool,
        behavior_drift: bool,
        panic_old_parse: bool,
    }

    impl FourWayCodec for ReplicationMutant {
        const KIND: ConfigKind = ConfigKind::Replication;
        type Value = PersistedReplicationConfiguration;
        type OldParsed = S3sReplicationObservation;
        type NewParsed = PersistedReplicationConfiguration;
        type Structure = PersistedReplicationConfiguration;
        type Behavior = ReplicationBehaviorProjection;

        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_old_parse, "wrong kind must fail before observation");
            if self.rollback_refusal && bytes == MINIMAL {
                return Err("mutation: old rollback parser rejects new output".to_owned());
            }
            ReplicationCodec.old_parse(bytes)
        }

        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.stricter_new && bytes == NAMESPACE {
                return Err("mutation: new parser rejects old-readable namespace".to_owned());
            }
            let mut parsed = ReplicationCodec.new_parse(bytes)?;
            if self.structure_drift {
                parsed.role.clear();
            }
            Ok(parsed)
        }

        fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
            ReplicationCodec.old_structure(value)
        }

        fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
            ReplicationCodec.new_structure(value)
        }

        fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
            ReplicationCodec.expected_structure(value)
        }

        fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            let mut bytes = ReplicationCodec.old_serialize(value)?;
            if self.old_byte_drift {
                bytes.push(b' ');
            }
            Ok(bytes)
        }

        fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            ReplicationCodec.new_serialize(value)
        }

        fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
            ReplicationCodec.old_behavior(value)
        }

        fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
            let mut behavior = ReplicationCodec.new_behavior(value);
            if self.behavior_drift {
                behavior.rules[0].status.push_str("-mutated");
            }
            behavior
        }
    }

    #[test]
    fn mutations_make_every_direction_fail() {
        for (mutant, expected) in [
            (
                ReplicationMutant {
                    structure_drift: true,
                    ..ReplicationMutant::default()
                },
                crate::Direction::D1CompatibleRead,
            ),
            (
                ReplicationMutant {
                    old_byte_drift: true,
                    ..ReplicationMutant::default()
                },
                crate::Direction::D2ByteWrite,
            ),
            (
                ReplicationMutant {
                    rollback_refusal: true,
                    ..ReplicationMutant::default()
                },
                crate::Direction::D3RollbackRead,
            ),
            (
                ReplicationMutant {
                    stricter_new: true,
                    ..ReplicationMutant::default()
                },
                crate::Direction::D4NotStricter,
            ),
            (
                ReplicationMutant {
                    behavior_drift: true,
                    ..ReplicationMutant::default()
                },
                crate::Direction::D5Behavior,
            ),
        ] {
            let failure = assert_four_way(&mutant, &base_sample()).expect_err("mutant must be killed");
            assert_eq!(failure.direction, expected);
        }
    }

    #[test]
    fn wrong_family_fails_before_old_observation() {
        let mut invalid = base_sample();
        invalid.kind = ConfigKind::Lifecycle;
        let failure = assert_four_way(
            &ReplicationMutant {
                panic_old_parse: true,
                ..ReplicationMutant::default()
            },
            &invalid,
        )
        .expect_err("wrong family fails closed");
        assert_eq!(failure.direction, crate::Direction::Input);
    }

    #[test]
    fn replication_provider_report_is_derived_from_shared_concrete_cases() {
        let evidence = replication_corpus_evidence().expect("Replication corpus evidence is traceable");
        let report = crate::build_corpus_report(&[ConfigKind::Replication], &[evidence])
            .expect("Replication concrete cases satisfy the coverage contract");
        assert!(report.render().contains("replication: accepted=12 rejected=15"));
    }
}
