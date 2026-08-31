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

//! RustFS repository Notification persistence fixtures.
//!
//! Responsible for: preserving exact source-(a) XML bytes, test identifiers, aliases, and
//! revisions from RustFS Notification tests and metadata fixtures. NOT responsible for: defining
//! generic Notification corpus boundaries or codec behavior. Upstream: the pinned RustFS
//! repository revision. Downstream: the parent Notification D1-D5 and backup ZIP corpus.

use rustfs_gateway_types::compat::parse_s3s_notification;
#[cfg(test)]
use rustfs_gateway_types::persistence::parse_notification;

use crate::source_a_census::SourceARow;
use crate::{ConfigKind, CorpusVariant, GoldenSample, RejectedGoldenSample, SampleOrigin};

use super::{AcceptedNotificationCase, RejectedNotificationCase};

const SOURCE_PATH: &str = "crates/notify/src/rules/config_test.rs";
const SOURCE_REVISION: &str = "c876df53f5097618b1817568a471cbb8b4f26ee8";
const NEW_WRITER_SOURCE: &str = "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[BUCKET_NOTIFICATION_CONFIG]";
const NEW_WRITER_REVISION: &str = "ca46ae9e56c167998f7139f4d3cfd5914280f4aa";
const NEW_WRITER_NOTIFICATION: &[u8] = br#"<NotificationConfiguration/>"#;
const NEW_WRITER_NOTIFICATION_SHA256: &str = "c1f563b9bdb5fcdc9ef642ba79826762a94492d592ac89676fbc7e570b004c96";
const ECSTORE_CLOUDWATCH_SOURCE: &str = "crates/ecstore/src/bucket/metadata.rs::tests::marshal_msg_complete_example::notification_xml (alias: crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::notification_xml)";
const ECSTORE_CLOUDWATCH: &[u8] = br#"<NotificationConfiguration><CloudWatchConfiguration><Id>notification1</Id><Event>s3:ObjectCreated:*</Event><CloudWatchConfiguration><LogGroupName>test-log-group</LogGroupName></CloudWatchConfiguration></CloudWatchConfiguration></NotificationConfiguration>"#;
const ECSTORE_CLOUDWATCH_SHA256: &str = "60f422ed2bc9a9d19766165bd86398ca147c32912a4579f344891624a26e9832";

const BUG_AND_URL_ENCODED: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <QueueConfiguration>
        <Id>test-queue</Id>
        <Queue>arn:rustfs:sqs:ap-northeast-1:primary:webhook</Queue>
        <Event>s3:ObjectCreated:*</Event>
        <Filter>
            <S3Key>
                <FilterRule>
                    <Name>prefix</Name>
                    <Value>uploads/</Value>
                </FilterRule>
                <FilterRule>
                    <Name>suffix</Name>
                    <Value>.csv</Value>
                </FilterRule>
            </S3Key>
        </Filter>
    </QueueConfiguration>
</NotificationConfiguration>"#;

const PREFIX_ONLY: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <QueueConfiguration>
        <Id>test-queue</Id>
        <Queue>arn:rustfs:sqs:ap-northeast-1:primary:webhook</Queue>
        <Event>s3:ObjectCreated:*</Event>
        <Filter>
            <S3Key>
                <FilterRuleList>
                    <FilterRule>
                        <Name>prefix</Name>
                        <Value>images/</Value>
                    </FilterRule>
                </FilterRuleList>
            </S3Key>
        </Filter>
    </QueueConfiguration>
</NotificationConfiguration>"#;

const CAPITALIZED_FILTER_NAMES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <QueueConfiguration>
        <Id>test-queue</Id>
        <Queue>arn:rustfs:sqs:ap-northeast-1:primary:webhook</Queue>
        <Event>s3:ObjectCreated:*</Event>
        <Filter>
            <S3Key>
                <FilterRule>
                    <Name>Prefix</Name>
                    <Value>uploads/</Value>
                </FilterRule>
                <FilterRule>
                    <Name>Suffix</Name>
                    <Value>.csv</Value>
                </FilterRule>
            </S3Key>
        </Filter>
    </QueueConfiguration>
</NotificationConfiguration>"#;

const SUFFIX_ONLY: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <QueueConfiguration>
        <Id>test-queue</Id>
        <Queue>arn:rustfs:sqs:ap-northeast-1:primary:webhook</Queue>
        <Event>s3:ObjectCreated:*</Event>
        <Filter>
            <S3Key>
                <FilterRuleList>
                    <FilterRule>
                        <Name>suffix</Name>
                        <Value>.pdf</Value>
                    </FilterRule>
                </FilterRuleList>
            </S3Key>
        </Filter>
    </QueueConfiguration>
</NotificationConfiguration>"#;

const NO_FILTER: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <QueueConfiguration>
        <Id>test-queue</Id>
        <Queue>arn:rustfs:sqs:ap-northeast-1:primary:webhook</Queue>
        <Event>s3:ObjectCreated:*</Event>
    </QueueConfiguration>
</NotificationConfiguration>"#;

const SPECIFIC_EVENT: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <QueueConfiguration>
        <Id>test-queue</Id>
        <Queue>arn:rustfs:sqs:ap-northeast-1:primary:webhook</Queue>
        <Event>s3:ObjectCreated:Put</Event>
        <Filter>
            <S3Key>
                <FilterRule>
                    <Name>prefix</Name>
                    <Value>uploads/</Value>
                </FilterRule>
                <FilterRule>
                    <Name>suffix</Name>
                    <Value>.csv</Value>
                </FilterRule>
            </S3Key>
        </Filter>
    </QueueConfiguration>
</NotificationConfiguration>"#;

const MULTIPLE_QUEUES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <QueueConfiguration>
        <Id>csv-queue</Id>
        <Queue>arn:rustfs:sqs::primary:webhook-csv</Queue>
        <Event>s3:ObjectCreated:*</Event>
        <Filter>
            <S3Key>
                <FilterRule>
                    <Name>prefix</Name>
                    <Value>uploads/</Value>
                </FilterRule>
                <FilterRule>
                    <Name>suffix</Name>
                    <Value>.csv</Value>
                </FilterRule>
            </S3Key>
        </Filter>
    </QueueConfiguration>
    <QueueConfiguration>
        <Id>jpg-queue</Id>
        <Queue>arn:rustfs:sqs::primary:webhook-jpg</Queue>
        <Event>s3:ObjectCreated:*</Event>
        <Filter>
            <S3Key>
                <FilterRuleList>
                    <FilterRule>
                        <Name>prefix</Name>
                        <Value>images/</Value>
                    </FilterRule>
                    <FilterRule>
                        <Name>suffix</Name>
                        <Value>.jpg</Value>
                    </FilterRule>
                </FilterRuleList>
            </S3Key>
        </Filter>
    </QueueConfiguration>
</NotificationConfiguration>"#;

const COMPOUND_EVENT: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <QueueConfiguration>
        <Id>test-queue</Id>
        <Queue>arn:rustfs:sqs:ap-northeast-1:primary:webhook</Queue>
        <Event>s3:ObjectCreated:*</Event>
        <Filter>
            <S3Key>
                <FilterRuleList>
                    <FilterRule>
                        <Name>prefix</Name>
                        <Value>data/</Value>
                    </FilterRule>
                </FilterRuleList>
            </S3Key>
        </Filter>
    </QueueConfiguration>
</NotificationConfiguration>"#;

struct SourceAFixture {
    bytes: &'static [u8],
    sha256: &'static str,
    test_ids: &'static [&'static str],
    notes: &'static str,
    variants: &'static [CorpusVariant],
}

const FIXTURES: [SourceAFixture; 8] = [
    SourceAFixture {
        bytes: BUG_AND_URL_ENCODED,
        sha256: "6d8ad7df7053178be819bdf07ece233fb8b9d8d7a938ccdd2538261aeb3a7462",
        test_ids: &["test_bug_report_exact_scenario_xml", "test_url_encoded_keys"],
        notes: "RustFS bug-report fixture, aliased by its URL-encoded-key test",
        variants: &[CorpusVariant::Canonical],
    },
    SourceAFixture {
        bytes: PREFIX_ONLY,
        sha256: "3d158a352ffad11be2a693a96f30323300a49c01abb5c87aa27ce214b6935c57",
        test_ids: &["test_prefix_only_filter_xml"],
        notes: "RustFS prefix-only FilterRuleList fixture",
        variants: &[CorpusVariant::Canonical],
    },
    SourceAFixture {
        bytes: CAPITALIZED_FILTER_NAMES,
        sha256: "bda4c44ce912e6995e3b494705a46600deaa4a9b2943040cb8ecab4dc1549dbe",
        test_ids: &["test_capitalized_filter_names_xml"],
        notes: "RustFS capitalized prefix and suffix name fixture",
        variants: &[CorpusVariant::UnknownScalar],
    },
    SourceAFixture {
        bytes: SUFFIX_ONLY,
        sha256: "f1cbe0eb758ff2a6416d1e6acbafdc3b8a885c99139489d564d2291b0041f827",
        test_ids: &["test_suffix_only_filter_xml"],
        notes: "RustFS suffix-only FilterRuleList fixture",
        variants: &[CorpusVariant::Canonical],
    },
    SourceAFixture {
        bytes: NO_FILTER,
        sha256: "d984eebb4c4cecdcd81785592e31d576c2ae88b32c4fe4e5dae5e1b8bb7a814b",
        test_ids: &["test_no_filter_xml"],
        notes: "RustFS queue fixture without a Filter",
        variants: &[CorpusVariant::Canonical],
    },
    SourceAFixture {
        bytes: SPECIFIC_EVENT,
        sha256: "03be4d49be4600c44938b011807aa6fcc86fe7239d9146616110db9a2781d581",
        test_ids: &["test_specific_event_type_xml"],
        notes: "RustFS specific ObjectCreated:Put event fixture",
        variants: &[CorpusVariant::Canonical],
    },
    SourceAFixture {
        bytes: MULTIPLE_QUEUES,
        sha256: "813cdc05e81e0fbadb8a3f96d1189005ca2e44aac94083bfe98a8d9118206320",
        test_ids: &["test_multiple_queue_configs_xml"],
        notes: "RustFS two-queue routing fixture",
        variants: &[CorpusVariant::Canonical],
    },
    SourceAFixture {
        bytes: COMPOUND_EVENT,
        sha256: "c579c698faa21543dfcf82cf48264e36adb063ec01962195de23527e8857b3a9",
        test_ids: &["test_compound_event_expansion_integration"],
        notes: "RustFS compound ObjectCreated event fixture",
        variants: &[CorpusVariant::Canonical],
    },
];

const OLD_READABLE_SHA256: [&str; 4] = [
    "6d8ad7df7053178be819bdf07ece233fb8b9d8d7a938ccdd2538261aeb3a7462",
    "bda4c44ce912e6995e3b494705a46600deaa4a9b2943040cb8ecab4dc1549dbe",
    "d984eebb4c4cecdcd81785592e31d576c2ae88b32c4fe4e5dae5e1b8bb7a814b",
    "03be4d49be4600c44938b011807aa6fcc86fe7239d9146616110db9a2781d581",
];

const OLD_REJECTED_SHA256: [&str; 4] = [
    "3d158a352ffad11be2a693a96f30323300a49c01abb5c87aa27ce214b6935c57",
    "f1cbe0eb758ff2a6416d1e6acbafdc3b8a885c99139489d564d2291b0041f827",
    "813cdc05e81e0fbadb8a3f96d1189005ca2e44aac94083bfe98a8d9118206320",
    "c579c698faa21543dfcf82cf48264e36adb063ec01962195de23527e8857b3a9",
];

pub(crate) fn source_a_rows() -> Vec<SourceARow> {
    let mut rows = FIXTURES
        .iter()
        .flat_map(|fixture| {
            fixture.test_ids.iter().enumerate().map(move |(index, test_id)| {
                let source_ref = source_ref(test_id);
                if OLD_READABLE_SHA256.contains(&fixture.sha256) {
                    if index == 0 {
                        SourceARow::accepted_sample(ConfigKind::Notification, source_ref, fixture.sha256)
                    } else {
                        SourceARow::accepted_alias(ConfigKind::Notification, source_ref, fixture.sha256)
                    }
                } else {
                    SourceARow::refused_sample(ConfigKind::Notification, source_ref, fixture.sha256)
                }
            })
        })
        .collect::<Vec<_>>();
    rows.push(SourceARow::accepted_sample(
        ConfigKind::Notification,
        NEW_WRITER_SOURCE,
        NEW_WRITER_NOTIFICATION_SHA256,
    ));
    rows.push(SourceARow::accepted_sample(
        ConfigKind::Notification,
        "crates/ecstore/src/bucket/metadata.rs::tests::marshal_msg_complete_example::notification_xml",
        ECSTORE_CLOUDWATCH_SHA256,
    ));
    rows.push(SourceARow::accepted_alias(
        ConfigKind::Notification,
        "crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::notification_xml",
        ECSTORE_CLOUDWATCH_SHA256,
    ));
    rows
}

fn source_ref(test_id: &str) -> &'static str {
    match test_id {
        "test_bug_report_exact_scenario_xml" => "crates/notify/src/rules/config_test.rs::test_bug_report_exact_scenario_xml",
        "test_url_encoded_keys" => "crates/notify/src/rules/config_test.rs::test_url_encoded_keys",
        "test_prefix_only_filter_xml" => "crates/notify/src/rules/config_test.rs::test_prefix_only_filter_xml",
        "test_capitalized_filter_names_xml" => "crates/notify/src/rules/config_test.rs::test_capitalized_filter_names_xml",
        "test_suffix_only_filter_xml" => "crates/notify/src/rules/config_test.rs::test_suffix_only_filter_xml",
        "test_no_filter_xml" => "crates/notify/src/rules/config_test.rs::test_no_filter_xml",
        "test_specific_event_type_xml" => "crates/notify/src/rules/config_test.rs::test_specific_event_type_xml",
        "test_multiple_queue_configs_xml" => "crates/notify/src/rules/config_test.rs::test_multiple_queue_configs_xml",
        "test_compound_event_expansion_integration" => {
            "crates/notify/src/rules/config_test.rs::test_compound_event_expansion_integration"
        }
        _ => panic!("unregistered source-(a) Notification test identifier: {test_id}"),
    }
}

fn source(test_ids: &[&str]) -> String {
    match test_ids {
        [test_id] => format!("{SOURCE_PATH}::{test_id}"),
        [test_id, alias] => format!("{SOURCE_PATH}::{test_id} (alias: {alias})"),
        _ => format!("{SOURCE_PATH}::{}", test_ids.join(",")),
    }
}

fn origin(fixture: &SourceAFixture) -> SampleOrigin {
    SampleOrigin {
        source: source(fixture.test_ids),
        producer: "rustfs/rustfs repository test fixture".to_owned(),
        version: SOURCE_REVISION.to_owned(),
        sha256: fixture.sha256.to_owned(),
    }
}

pub(super) fn accepted_cases() -> Vec<AcceptedNotificationCase> {
    let mut cases = FIXTURES
        .iter()
        .filter(|fixture| OLD_READABLE_SHA256.contains(&fixture.sha256))
        .map(|fixture| {
            let value = parse_s3s_notification(fixture.bytes)
                .expect("pinned RustFS source-(a) fixture is old-readable")
                .structure; // The census test fixes the classification against the pinned old oracle.
            (
                GoldenSample {
                    kind: ConfigKind::Notification,
                    bytes: fixture.bytes.to_vec(),
                    value,
                    origin: origin(fixture),
                    notes: fixture.notes.to_owned(),
                },
                fixture.variants,
            )
        })
        .collect::<Vec<_>>();
    let value = parse_s3s_notification(NEW_WRITER_NOTIFICATION)
        .expect("the RustFS new-writer Notification fixture is old-readable")
        .structure;
    cases.push((
        GoldenSample {
            kind: ConfigKind::Notification,
            bytes: NEW_WRITER_NOTIFICATION.to_vec(),
            value,
            origin: SampleOrigin {
                source: NEW_WRITER_SOURCE.to_owned(),
                producer: "rustfs/rustfs new bucket-metadata writer fixture".to_owned(),
                version: NEW_WRITER_REVISION.to_owned(),
                sha256: NEW_WRITER_NOTIFICATION_SHA256.to_owned(),
            },
            notes: "RustFS new writer emits an empty self-closing Notification configuration".to_owned(),
        },
        &[CorpusVariant::EmptyElement],
    ));
    let value = parse_s3s_notification(ECSTORE_CLOUDWATCH)
        .expect("the RustFS ecstore CloudWatch fixture is old-readable")
        .structure;
    cases.push((
        GoldenSample {
            kind: ConfigKind::Notification,
            bytes: ECSTORE_CLOUDWATCH.to_vec(),
            value,
            origin: SampleOrigin {
                source: ECSTORE_CLOUDWATCH_SOURCE.to_owned(),
                producer: "rustfs/rustfs ecstore bucket-metadata test fixture".to_owned(),
                version: SOURCE_REVISION.to_owned(),
                sha256: ECSTORE_CLOUDWATCH_SHA256.to_owned(),
            },
            notes: "Both migration codecs accept and discard the unsupported CloudWatchConfiguration; this records parity, not CloudWatch support (rustfs/backlog#2109)".to_owned(),
        },
        &[CorpusVariant::UnknownTopLevel],
    ));
    cases
}

pub(super) fn rejected_cases() -> Vec<RejectedNotificationCase> {
    FIXTURES
        .iter()
        .filter(|fixture| OLD_REJECTED_SHA256.contains(&fixture.sha256))
        .map(|fixture| {
            (
                RejectedGoldenSample {
                    kind: ConfigKind::Notification,
                    bytes: fixture.bytes.to_vec(),
                    origin: origin(fixture),
                    notes: format!("{}; pinned old oracle rejects FilterRuleList", fixture.notes),
                },
                fixture.variants,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_a_old_oracle_classification_is_pinned() {
        let old_readable = FIXTURES
            .iter()
            .filter(|fixture| parse_s3s_notification(fixture.bytes).is_ok())
            .map(|fixture| fixture.sha256)
            .collect::<Vec<_>>();
        let old_rejected = FIXTURES
            .iter()
            .filter(|fixture| parse_s3s_notification(fixture.bytes).is_err())
            .map(|fixture| fixture.sha256)
            .collect::<Vec<_>>();
        assert_eq!(old_readable, OLD_READABLE_SHA256);
        assert_eq!(old_rejected, OLD_REJECTED_SHA256);
        for fixture in FIXTURES
            .iter()
            .filter(|fixture| OLD_REJECTED_SHA256.contains(&fixture.sha256))
        {
            assert!(parse_notification(fixture.bytes).is_err(), "new parser must match the pinned old refusal");
        }
    }

    #[test]
    fn source_a_fixtures_are_registered_once_by_unique_sha() {
        for fixture in &FIXTURES {
            if OLD_READABLE_SHA256.contains(&fixture.sha256) {
                let matches = super::super::accepted_cases()
                    .into_iter()
                    .filter(|(sample, _)| sample.origin.sha256 == fixture.sha256)
                    .collect::<Vec<_>>();
                assert_eq!(matches.len(), 1, "{} must have one accepted SHA registration", source(fixture.test_ids));
                let sample = &matches[0].0;
                assert_eq!(sample.bytes, fixture.bytes);
                assert_eq!(sample.origin.source, source(fixture.test_ids));
                assert_eq!(sample.origin.version, SOURCE_REVISION);
                super::super::super::assert_notification_four_way(sample)
                    .expect("old-readable RustFS source-(a) fixture passes Notification D1-D5");
            } else {
                let matches = super::super::rejected_cases()
                    .into_iter()
                    .filter(|(sample, _)| sample.origin.sha256 == fixture.sha256)
                    .collect::<Vec<_>>();
                assert_eq!(matches.len(), 1, "{} must have one rejected SHA registration", source(fixture.test_ids));
                let sample = &matches[0].0;
                assert_eq!(sample.bytes, fixture.bytes);
                assert_eq!(sample.origin.source, source(fixture.test_ids));
                assert_eq!(sample.origin.version, SOURCE_REVISION);
            }
        }
    }

    #[test]
    fn new_writer_notification_fixture_is_registered_once_by_exact_sha() {
        let matches = super::super::accepted_cases()
            .into_iter()
            .filter(|(sample, _)| sample.origin.sha256 == NEW_WRITER_NOTIFICATION_SHA256)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "the new-writer Notification SHA must be registered exactly once");
        let sample = &matches[0].0;
        assert_eq!(sample.bytes, NEW_WRITER_NOTIFICATION);
        assert_eq!(sample.origin.source, NEW_WRITER_SOURCE);
        assert_eq!(sample.origin.version, NEW_WRITER_REVISION);
        super::super::super::assert_notification_four_way(sample)
            .expect("the RustFS new-writer Notification fixture passes D1-D5");
    }

    #[test]
    fn ecstore_cloudwatch_fixture_is_measured_and_registered_as_accepted() {
        let old = parse_s3s_notification(ECSTORE_CLOUDWATCH)
            .expect("the pinned old parser accepts and discards CloudWatchConfiguration");
        let new =
            parse_notification(ECSTORE_CLOUDWATCH).expect("the new parser must preserve the pinned old acceptance boundary");
        assert_eq!(new, old.structure);
        assert!(!old.behavior.event_bridge_enabled);
        assert!(old.behavior.lambda_routes.is_empty());
        assert!(old.behavior.queue_routes.is_empty());
        assert!(old.behavior.topic_routes.is_empty());

        let matches = super::super::accepted_cases()
            .into_iter()
            .filter(|(sample, _)| sample.origin.sha256 == "60f422ed2bc9a9d19766165bd86398ca147c32912a4579f344891624a26e9832")
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "the ecstore CloudWatch SHA must have one accepted registration");
        let (sample, variants) = &matches[0];
        assert_eq!(sample.bytes, ECSTORE_CLOUDWATCH);
        assert_eq!(
            sample.origin.source,
            "crates/ecstore/src/bucket/metadata.rs::tests::marshal_msg_complete_example::notification_xml (alias: crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::notification_xml)"
        );
        assert_eq!(sample.origin.version, "c876df53f5097618b1817568a471cbb8b4f26ee8");
        assert_eq!(sample.origin.sha256, ECSTORE_CLOUDWATCH_SHA256);
        assert_eq!(*variants, &[CorpusVariant::UnknownTopLevel]);
        super::super::super::assert_notification_four_way(sample)
            .expect("the RustFS ecstore CloudWatch fixture passes D1-D5 discard parity");
    }
}
