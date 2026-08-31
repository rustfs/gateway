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

//! Notification persistence compatibility evidence.
//!
//! Responsible for: D1-D5 evidence over independent old and new Notification codecs.
//! NOT responsible for: HTTP notification policy or delivering events to destinations.
//! Upstream: pinned-s3s observations and production persistence codecs. Downstream: the P9
//! migration golden gate.

use rustfs_gateway_types::compat::{S3sNotificationObservation, parse_s3s_notification, serialize_s3s_notification};
use rustfs_gateway_types::persistence::{
    NotificationBehaviorProjection, PersistedNotificationConfiguration, parse_notification, serialize_notification,
};

use crate::{
    ConfigKind, CorpusCaseEvidence, CorpusCoverageError, CorpusVariant, FamilyCorpusEvidence, FourWayCodec, GoldenFailure,
    GoldenSample, RejectedGoldenSample, assert_four_way,
};

/// Runs D1-D5 against pinned-old and production Notification persistence codecs.
///
/// # Errors
///
/// Returns invalid provenance or the first compatibility failure.
pub fn assert_notification_four_way(sample: &GoldenSample<PersistedNotificationConfiguration>) -> Result<(), GoldenFailure> {
    assert_four_way(&NotificationCodec, sample)
}

#[derive(Clone, Copy, Debug)]
struct NotificationCodec;

impl FourWayCodec for NotificationCodec {
    const KIND: ConfigKind = ConfigKind::Notification;

    type Value = PersistedNotificationConfiguration;
    type OldParsed = S3sNotificationObservation;
    type NewParsed = PersistedNotificationConfiguration;
    type Structure = PersistedNotificationConfiguration;
    type Behavior = NotificationBehaviorProjection;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_notification(bytes).map_err(|error| error.to_string())
    }

    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_notification(bytes).map_err(|error| error.to_string())
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
        serialize_s3s_notification(value).map_err(|error| error.to_string())
    }

    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_notification(value))
    }

    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        value.behavior.clone()
    }

    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        value.behavior()
    }
}

mod corpus_cases {
    use super::*;

    mod source_a;

    use rustfs_gateway_types::persistence::{
        PersistedEventBridgeConfiguration, PersistedFilterRule, PersistedLambdaFunctionConfiguration,
        PersistedNotificationConfigurationFilter, PersistedQueueConfiguration, PersistedS3KeyFilter, PersistedTopicConfiguration,
    };

    const EMPTY: &[u8] = b"<NotificationConfiguration></NotificationConfiguration>";
    #[cfg(test)]
    const QUEUE_CANONICAL: &[u8] = b"<NotificationConfiguration><QueueConfiguration><Event>s3:ObjectCreated:*</Event><Id>queue-1</Id><Queue>arn:queue</Queue></QueueConfiguration></NotificationConfiguration>";
    const QUEUE_NAMESPACE: &[u8] = br#"<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><QueueConfiguration><Queue>arn:queue</Queue><Id>queue-1</Id><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>"#;
    const UNKNOWN_TOP: &[u8] = b"<NotificationConfiguration><Future><Nested/></Future><QueueConfiguration><Event>s3:ObjectCreated:*</Event><Id>queue-1</Id><Queue>arn:queue</Queue></QueueConfiguration></NotificationConfiguration>";
    const BOM_CRLF: &[u8] = b"\xef\xbb\xbf<NotificationConfiguration>\r\n</NotificationConfiguration>";
    const TRAILING_TEXT: &[u8] = b"<NotificationConfiguration></NotificationConfiguration>trailing";
    const DOCTYPE: &[u8] = b"<!DOCTYPE NotificationConfiguration><NotificationConfiguration></NotificationConfiguration>";
    const NON_ASCII: &[u8] = "<NotificationConfiguration><TopicConfiguration><Event>s3:ObjectCreated:*</Event><Id>café</Id><Topic>data-🚀</Topic></TopicConfiguration></NotificationConfiguration>".as_bytes();
    const FILTER_EMPTY_KEY: &[u8] = b"<NotificationConfiguration><QueueConfiguration><Event>future:event</Event><Filter><S3Key></S3Key></Filter><Queue>future:queue</Queue></QueueConfiguration></NotificationConfiguration>";
    const FULL: &[u8] = concat!(
        "<NotificationConfiguration>",
        "<EventBridgeConfiguration></EventBridgeConfiguration>",
        "<CloudFunctionConfiguration>",
        "<Event>s3:ObjectCreated:*</Event><Event>future:event</Event>",
        "<Filter><S3Key>",
        "<FilterRule><Name>prefix</Name><Value>café/</Value></FilterRule>",
        "<FilterRule><Name>suffix</Name><Value>data-🚀</Value></FilterRule>",
        "</S3Key></Filter><Id>lambda-1</Id><CloudFunction>arn:lambda</CloudFunction>",
        "</CloudFunctionConfiguration>",
        "<QueueConfiguration><Event>s3:ObjectRemoved:*</Event>",
        "<Filter><S3Key><FilterRule><Value>.log</Value></FilterRule></S3Key></Filter>",
        "<Queue>arn:queue</Queue></QueueConfiguration>",
        "<TopicConfiguration><Event>s3:ReducedRedundancyLostObject</Event>",
        "<Filter></Filter><Id>topic-1</Id><Topic>arn:topic</Topic></TopicConfiguration>",
        "</NotificationConfiguration>"
    )
    .as_bytes();

    fn empty_value() -> PersistedNotificationConfiguration {
        PersistedNotificationConfiguration::default()
    }

    fn queue_value() -> PersistedNotificationConfiguration {
        PersistedNotificationConfiguration {
            queue_configurations: Some(vec![PersistedQueueConfiguration {
                events: vec!["s3:ObjectCreated:*".to_owned()],
                filter: None,
                id: Some("queue-1".to_owned()),
                queue_arn: "arn:queue".to_owned(),
            }]),
            ..PersistedNotificationConfiguration::default()
        }
    }

    fn non_ascii_value() -> PersistedNotificationConfiguration {
        PersistedNotificationConfiguration {
            topic_configurations: Some(vec![PersistedTopicConfiguration {
                events: vec!["s3:ObjectCreated:*".to_owned()],
                filter: None,
                id: Some("café".to_owned()),
                topic_arn: "data-🚀".to_owned(),
            }]),
            ..PersistedNotificationConfiguration::default()
        }
    }

    fn empty_key_value() -> PersistedNotificationConfiguration {
        PersistedNotificationConfiguration {
            queue_configurations: Some(vec![PersistedQueueConfiguration {
                events: vec!["future:event".to_owned()],
                filter: Some(PersistedNotificationConfigurationFilter {
                    key: Some(PersistedS3KeyFilter { filter_rules: None }),
                }),
                id: None,
                queue_arn: "future:queue".to_owned(),
            }]),
            ..PersistedNotificationConfiguration::default()
        }
    }

    fn full_value() -> PersistedNotificationConfiguration {
        PersistedNotificationConfiguration {
            event_bridge_configuration: Some(PersistedEventBridgeConfiguration),
            lambda_function_configurations: Some(vec![PersistedLambdaFunctionConfiguration {
                events: vec!["s3:ObjectCreated:*".to_owned(), "future:event".to_owned()],
                filter: Some(PersistedNotificationConfigurationFilter {
                    key: Some(PersistedS3KeyFilter {
                        filter_rules: Some(vec![
                            PersistedFilterRule {
                                name: Some("prefix".to_owned()),
                                value: Some("café/".to_owned()),
                            },
                            PersistedFilterRule {
                                name: Some("suffix".to_owned()),
                                value: Some("data-🚀".to_owned()),
                            },
                        ]),
                    }),
                }),
                id: Some("lambda-1".to_owned()),
                lambda_function_arn: "arn:lambda".to_owned(),
            }]),
            queue_configurations: Some(vec![PersistedQueueConfiguration {
                events: vec!["s3:ObjectRemoved:*".to_owned()],
                filter: Some(PersistedNotificationConfigurationFilter {
                    key: Some(PersistedS3KeyFilter {
                        filter_rules: Some(vec![PersistedFilterRule {
                            name: None,
                            value: Some(".log".to_owned()),
                        }]),
                    }),
                }),
                id: None,
                queue_arn: "arn:queue".to_owned(),
            }]),
            topic_configurations: Some(vec![PersistedTopicConfiguration {
                events: vec!["s3:ReducedRedundancyLostObject".to_owned()],
                filter: Some(PersistedNotificationConfigurationFilter { key: None }),
                id: Some("topic-1".to_owned()),
                topic_arn: "arn:topic".to_owned(),
            }]),
        }
    }

    fn large_value() -> PersistedNotificationConfiguration {
        PersistedNotificationConfiguration {
            queue_configurations: Some(vec![PersistedQueueConfiguration {
                events: vec!["s3:ObjectCreated:*".to_owned()],
                filter: None,
                id: Some("x".repeat(8 * 1024)),
                queue_arn: "arn:large".to_owned(),
            }]),
            ..PersistedNotificationConfiguration::default()
        }
    }

    fn large_bytes() -> Vec<u8> {
        format!(
            "<NotificationConfiguration><QueueConfiguration><Event>s3:ObjectCreated:*</Event><Id>{}</Id><Queue>arn:large</Queue></QueueConfiguration></NotificationConfiguration>",
            "x".repeat(8 * 1024)
        )
        .into_bytes()
    }

    fn origin(sha256: &str) -> crate::SampleOrigin {
        crate::SampleOrigin {
            source: "P9 Notification persistence matrix".to_owned(),
            producer: "pinned s3s XML behavior".to_owned(),
            version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
            sha256: sha256.to_owned(),
        }
    }

    fn sample(
        bytes: &[u8],
        sha256: &str,
        value: PersistedNotificationConfiguration,
        notes: &str,
    ) -> GoldenSample<PersistedNotificationConfiguration> {
        GoldenSample {
            kind: ConfigKind::Notification,
            bytes: bytes.to_vec(),
            value,
            origin: origin(sha256),
            notes: notes.to_owned(),
        }
    }

    fn base_sample() -> GoldenSample<PersistedNotificationConfiguration> {
        sample(
            QUEUE_NAMESPACE,
            "789ef2625afc08d9a1dd138a6f91be54517e6138881e1edaf684d1531b171af5",
            queue_value(),
            "namespace and noncanonical field order retain the queue route",
        )
    }

    type AcceptedNotificationCase = (GoldenSample<PersistedNotificationConfiguration>, &'static [CorpusVariant]);
    type RejectedNotificationCase = (RejectedGoldenSample, &'static [CorpusVariant]);

    fn accepted_cases() -> Vec<AcceptedNotificationCase> {
        let large = large_bytes();
        let mut cases: Vec<AcceptedNotificationCase> = vec![
            (
                sample(
                    EMPTY,
                    "cc76cb51b95cd4d2dc9e0c9830bc72aca7b449fc04acf9cc7eb7ed201e51fbde",
                    empty_value(),
                    "empty optional lists and EventBridge marker",
                ),
                &[CorpusVariant::EmptyElement],
            ),
            (
                sample(
                    FULL,
                    "3c65c739356d8d60f975899c9b6ba155c314cf7ac23eee31e60dde4876983d56",
                    full_value(),
                    "every destination, event, identifier, and filter decision",
                ),
                &[CorpusVariant::Canonical, CorpusVariant::Unicode],
            ),
            (base_sample(), &[CorpusVariant::Namespace, CorpusVariant::AlternateOrder]),
            (
                sample(
                    UNKNOWN_TOP,
                    "99f5ef0966b395b012db00742b195824ab7c4c65e7ae67ea7468278564e77f8c",
                    queue_value(),
                    "unknown root child is ignored by the old decoder",
                ),
                &[CorpusVariant::UnknownTopLevel],
            ),
            (
                sample(
                    BOM_CRLF,
                    "909196cfabf7dc4c4dcce2bc1b5aa0d1ebb4d6af62c7a7357edd6b2161f6e3a0",
                    empty_value(),
                    "BOM and CRLF historical bytes",
                ),
                &[CorpusVariant::Bom, CorpusVariant::Crlf],
            ),
            (
                sample(
                    TRAILING_TEXT,
                    "649005cf34ad2cdc41daa16e0155ca5dc345a8a348ae59383faa97ad2b49830e",
                    empty_value(),
                    "root-trailing text accepted by the old decoder",
                ),
                &[CorpusVariant::AlternateOrder],
            ),
            (
                sample(
                    DOCTYPE,
                    "fe33f85c93b845894c12c62fa9cd23ec5a25cc1d3467f9688a1e7fcba59266a2",
                    empty_value(),
                    "narrow inert root document type declaration",
                ),
                &[CorpusVariant::UnknownTopLevel],
            ),
            (
                sample(
                    NON_ASCII,
                    "ea2f383efcb1f85bc69bbf66704b997bd8bc7fcda3fe221d672e73f9f88903ec",
                    non_ascii_value(),
                    "Unicode and emoji destination decisions",
                ),
                &[CorpusVariant::Unicode],
            ),
            (
                sample(
                    FILTER_EMPTY_KEY,
                    "e3ac41132f328f8fd7965999d1a6d5a6a9299cee10e409d225b6ec3c4b45bbb3",
                    empty_key_value(),
                    "present key filter with absent rule list",
                ),
                &[CorpusVariant::EmptyElement],
            ),
            (
                sample(
                    &large,
                    "cb41a8754a537672e47d501b60db2685c2dd0e101f2ebedd4a650af149089bf5",
                    large_value(),
                    "old-readable identifier at the 8 KiB boundary",
                ),
                &[CorpusVariant::LargeValue],
            ),
        ];
        cases.extend(source_a::accepted_cases());
        cases
    }

    fn rejected(bytes: &[u8], sha256: &str, notes: &str, variants: &'static [CorpusVariant]) -> RejectedNotificationCase {
        (
            RejectedGoldenSample {
                kind: ConfigKind::Notification,
                bytes: bytes.to_vec(),
                origin: origin(sha256),
                notes: notes.to_owned(),
            },
            variants,
        )
    }

    fn rejected_cases() -> Vec<RejectedNotificationCase> {
        let mut cases = vec![
            rejected(b"<NotificationConfiguration><EventBridgeConfiguration/><EventBridgeConfiguration/></NotificationConfiguration>", "95c8796c8cbb1c769db034f1a1cd8c164e29dbb583bd78923b6bff8895b30c74", "duplicate EventBridge configuration", &[CorpusVariant::DuplicateField]),
            rejected(b"<NotificationConfiguration><EventBridgeConfiguration><Unknown/></EventBridgeConfiguration></NotificationConfiguration>", "a77da2808231406863b9303a0842525cb71d46e7a51a214caccc5ce6b523f200", "unknown EventBridge child", &[CorpusVariant::UnknownNested]),
            rejected(b"<NotificationConfiguration><QueueConfiguration><Queue>q</Queue></QueueConfiguration></NotificationConfiguration>", "386becafdffb2f5793f26d92854fed1a365e5856ef446b0615229c924139d2e7", "queue event missing", &[CorpusVariant::MissingField]),
            rejected(b"<NotificationConfiguration><QueueConfiguration><Event>a</Event></QueueConfiguration></NotificationConfiguration>", "432d80a8ab9e6c0959025003cb67ed470541b63935f71992f22d2d5c7271676e", "queue ARN missing", &[CorpusVariant::MissingField]),
            rejected(b"<NotificationConfiguration><CloudFunctionConfiguration><Event>a</Event></CloudFunctionConfiguration></NotificationConfiguration>", "5b18b6b219c40931b78001a9e3d91fd39a59e25a0a10153d483b4514ebcb2747", "Lambda ARN missing", &[CorpusVariant::MissingField]),
            rejected(b"<NotificationConfiguration><TopicConfiguration><Topic>t</Topic></TopicConfiguration></NotificationConfiguration>", "d4d1ca804cd9ebc0653a4939dad6baadc50d989b3237d7956e438db3bcf8ad32", "topic event missing", &[CorpusVariant::MissingField]),
            rejected(b"<NotificationConfiguration><QueueConfiguration><Event>a</Event><Id>1</Id><Id>2</Id><Queue>q</Queue></QueueConfiguration></NotificationConfiguration>", "8f5af95fd55c1c013c11811b4be54161e02d1aa38e81fb153b405893671986d1", "duplicate queue identifier", &[CorpusVariant::DuplicateField]),
            rejected(b"<NotificationConfiguration><QueueConfiguration><Event>a</Event><Filter/><Filter/><Queue>q</Queue></QueueConfiguration></NotificationConfiguration>", "ccf8932e4c97c74edcb83c0b5416b2388268a4e733e26d4a8c7898f7417f383a", "duplicate queue filter", &[CorpusVariant::DuplicateField]),
            rejected(b"<NotificationConfiguration><QueueConfiguration><Event>a</Event><Queue>q</Queue><Queue>q2</Queue></QueueConfiguration></NotificationConfiguration>", "5fedaf5337bdba8cb38ae204d8f7c8934b4b92edaefb5439ae2e0babd4b1ca08", "duplicate queue ARN", &[CorpusVariant::DuplicateField]),
            rejected(b"<NotificationConfiguration><QueueConfiguration><Event>a</Event><Unknown/><Queue>q</Queue></QueueConfiguration></NotificationConfiguration>", "8d5426ca22c1c4617ae78b1e902a3e35f35dab4945db9b5ef7660c91010c0eaf", "unknown queue child", &[CorpusVariant::UnknownNested]),
            rejected(b"<NotificationConfiguration><QueueConfiguration><Event>a</Event><Filter><Unknown/></Filter><Queue>q</Queue></QueueConfiguration></NotificationConfiguration>", "ec9ab32bec7f8a1542b3adc02195690fd3bd491c2f7895b5576e329e1c22f12e", "unknown filter child", &[CorpusVariant::UnknownNested]),
        ];
        cases.extend(source_a::rejected_cases());
        cases
    }

    pub(super) fn corpus_evidence() -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
        let mut cases = accepted_cases()
            .into_iter()
            .map(|(sample, variants)| CorpusCaseEvidence::accepted(&sample, variants))
            .collect::<Result<Vec<_>, _>>()?;
        cases.extend(
            rejected_cases()
                .into_iter()
                .map(|(sample, variants)| CorpusCaseEvidence::rejected(&sample, variants))
                .collect::<Result<Vec<_>, _>>()?,
        );
        Ok(FamilyCorpusEvidence::new(
            ConfigKind::Notification,
            vec![
                CorpusVariant::Canonical,
                CorpusVariant::EmptyElement,
                CorpusVariant::MissingField,
                CorpusVariant::UnknownTopLevel,
                CorpusVariant::UnknownNested,
                CorpusVariant::Namespace,
                CorpusVariant::AlternateOrder,
                CorpusVariant::DuplicateField,
                CorpusVariant::LargeValue,
                CorpusVariant::Bom,
                CorpusVariant::Crlf,
                CorpusVariant::Unicode,
            ],
            cases,
        ))
    }

    pub(super) fn run_four_way() -> Result<usize, GoldenFailure> {
        let cases = accepted_cases();
        for (sample, _) in &cases {
            super::assert_notification_four_way(sample)?;
        }
        Ok(cases.len())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn pinned_old_serializer_defines_exact_order_and_bytes() {
            assert_eq!(
                serialize_s3s_notification(&full_value()).expect("old serializer accepts the full Notification value"),
                FULL
            );
            assert_eq!(serialize_notification(&full_value()), FULL);
            assert_eq!(
                serialize_s3s_notification(&empty_value()).expect("old serializer accepts an empty wrapper"),
                EMPTY
            );
        }

        #[test]
        fn old_parser_boundaries_are_observed_before_candidate_parity() {
            for accepted in [
                EMPTY,
                FULL,
                QUEUE_NAMESPACE,
                UNKNOWN_TOP,
                BOM_CRLF,
                TRAILING_TEXT,
                DOCTYPE,
                NON_ASCII,
                FILTER_EMPTY_KEY,
            ] {
                let old = parse_s3s_notification(accepted).expect("old parser accepts the observed boundary");
                let new = parse_notification(accepted).expect("new parser accepts every selected old-readable boundary");
                assert_eq!(old.structure, new);
                assert_eq!(old.behavior, new.behavior());
            }
            let large = large_bytes();
            let old = parse_s3s_notification(&large).expect("old parser accepts an 8 KiB identifier");
            let new = parse_notification(&large).expect("new parser accepts the old-readable 8 KiB identifier");
            assert_eq!(old.structure, new);
            assert_eq!(old.behavior, new.behavior());
        }

        #[test]
        fn seventeen_traceable_samples_pass_d1_through_d5() {
            for (case, _) in accepted_cases() {
                assert_notification_four_way(&case).expect("Notification sample passes D1-D5");
            }
        }

        #[test]
        fn rejected_documents_match_the_old_parser_in_more_cases_than_the_positive_matrix() {
            for (index, (case, _)) in rejected_cases().into_iter().enumerate() {
                assert!(parse_s3s_notification(&case.bytes).is_err(), "old decoder rejects negative case {index}");
                assert!(
                    parse_notification(&case.bytes).is_err(),
                    "new decoder matches old refusal for case {index}"
                );
            }
        }

        #[derive(Clone, Copy, Debug, Default)]
        struct NotificationMutant {
            old_byte_drift: bool,
            rollback_refusal: bool,
            stricter_new: bool,
            structure_drift: bool,
            behavior_drift: bool,
            panic_old_parse: bool,
        }

        impl FourWayCodec for NotificationMutant {
            const KIND: ConfigKind = ConfigKind::Notification;
            type Value = PersistedNotificationConfiguration;
            type OldParsed = S3sNotificationObservation;
            type NewParsed = PersistedNotificationConfiguration;
            type Structure = PersistedNotificationConfiguration;
            type Behavior = NotificationBehaviorProjection;

            fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
                assert!(!self.panic_old_parse, "invalid input must fail before old observation");
                if self.rollback_refusal && bytes == QUEUE_CANONICAL {
                    return Err("mutation: old rollback parser rejects new output".to_owned());
                }
                NotificationCodec.old_parse(bytes)
            }
            fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
                if self.stricter_new && bytes == QUEUE_NAMESPACE {
                    return Err("mutation: new parser rejects old-readable namespace".to_owned());
                }
                let mut parsed = NotificationCodec.new_parse(bytes)?;
                if self.structure_drift {
                    parsed.queue_configurations = None;
                }
                Ok(parsed)
            }
            fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
                NotificationCodec.old_structure(value)
            }
            fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
                NotificationCodec.new_structure(value)
            }
            fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
                NotificationCodec.expected_structure(value)
            }
            fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
                let mut bytes = NotificationCodec.old_serialize(value)?;
                if self.old_byte_drift {
                    bytes.push(b' ');
                }
                Ok(bytes)
            }
            fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
                NotificationCodec.new_serialize(value)
            }
            fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
                NotificationCodec.old_behavior(value)
            }
            fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
                let mut behavior = NotificationCodec.new_behavior(value);
                if self.behavior_drift {
                    behavior.queue_routes[0].events.push("mutation:event".to_owned());
                }
                behavior
            }
        }

        #[test]
        fn deliberate_mutations_make_every_direction_fail_independently() {
            for (mutant, expected) in [
                (
                    NotificationMutant {
                        structure_drift: true,
                        ..NotificationMutant::default()
                    },
                    crate::Direction::D1CompatibleRead,
                ),
                (
                    NotificationMutant {
                        old_byte_drift: true,
                        ..NotificationMutant::default()
                    },
                    crate::Direction::D2ByteWrite,
                ),
                (
                    NotificationMutant {
                        rollback_refusal: true,
                        ..NotificationMutant::default()
                    },
                    crate::Direction::D3RollbackRead,
                ),
                (
                    NotificationMutant {
                        stricter_new: true,
                        ..NotificationMutant::default()
                    },
                    crate::Direction::D4NotStricter,
                ),
                (
                    NotificationMutant {
                        behavior_drift: true,
                        ..NotificationMutant::default()
                    },
                    crate::Direction::D5Behavior,
                ),
            ] {
                let failure = assert_four_way(&mutant, &base_sample()).expect_err("mutant must be killed");
                assert_eq!(failure.direction, expected);
            }
        }

        #[test]
        fn kind_and_provenance_fail_before_old_observation() {
            for mutate in [
                |sample: &mut GoldenSample<_>| sample.kind = ConfigKind::Versioning,
                |sample: &mut GoldenSample<_>| sample.origin.sha256.clear(),
                |sample: &mut GoldenSample<_>| sample.origin.source.clear(),
            ] {
                let mut invalid = base_sample();
                mutate(&mut invalid);
                let failure = assert_four_way(
                    &NotificationMutant {
                        panic_old_parse: true,
                        ..NotificationMutant::default()
                    },
                    &invalid,
                )
                .expect_err("invalid input must fail closed");
                assert_eq!(failure.direction, crate::Direction::Input);
            }
        }
    }
}

/// Builds Notification corpus coverage from the exact cases used by codec tests.
///
/// # Errors
///
/// Returns an error when provenance is stale or a concrete case lacks a required variant.
pub(crate) fn notification_corpus_evidence() -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
    corpus_cases::corpus_evidence()
}

pub(crate) fn run_notification_corpus_four_way() -> Result<usize, GoldenFailure> {
    corpus_cases::run_four_way()
}
