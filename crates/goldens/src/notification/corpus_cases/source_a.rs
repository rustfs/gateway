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
//! revisions from the RustFS Notification rule tests. NOT responsible for: defining generic
//! Notification corpus boundaries or codec behavior. Upstream: the pinned RustFS repository
//! revision. Downstream: the parent Notification D1-D5 and backup ZIP corpus.

use rustfs_gateway_types::compat::parse_s3s_notification;
#[cfg(test)]
use rustfs_gateway_types::persistence::parse_notification;

use crate::{ConfigKind, CorpusVariant, GoldenSample, RejectedGoldenSample, SampleOrigin};

use super::{AcceptedNotificationCase, RejectedNotificationCase};

const SOURCE_PATH: &str = "crates/notify/src/rules/config_test.rs";
const SOURCE_REVISION: &str = "c876df53f5097618b1817568a471cbb8b4f26ee8";

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
    FIXTURES
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
        .collect()
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
}
