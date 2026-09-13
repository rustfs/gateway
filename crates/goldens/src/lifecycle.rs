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

//! Lifecycle persistence compatibility evidence.
//!
//! Responsible for: binding independent pinned-s3s and production Lifecycle codecs to D1-D5.
//! NOT responsible for: HTTP lifecycle policy validation, other configuration families, or CI.
//! Upstream: `rustfs-gateway-types` persistence and compat seams. Downstream: migration gates.
use crate::{
    AcceptedCorpusCase, ConcreteFamilyCorpus, ConfigKind, CorpusVariant, FourWayCodec, GoldenFailure, GoldenSample,
    RejectedCorpusCase, RejectedGoldenSample, SampleOrigin, assert_four_way,
};
use rustfs_gateway_types::compat::{S3sLifecycleObservation, parse_s3s_lifecycle, serialize_s3s_lifecycle};
use rustfs_gateway_types::persistence::{
    PersistedAbortIncompleteMultipartUpload, PersistedDelMarkerExpiration, PersistedLifecycleAnd,
    PersistedLifecycleConfiguration, PersistedLifecycleExpiration, PersistedLifecycleFilter, PersistedLifecycleRule,
    PersistedNoncurrentVersionExpiration, PersistedNoncurrentVersionTransition, PersistedTransition, parse_lifecycle,
    serialize_lifecycle,
};
use sha2::{Digest, Sha256};

mod source_b;
#[cfg(test)]
const MINIMAL: &[u8] = b"<LifecycleConfiguration><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const NAMESPACE: &[u8] = b"<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const UNKNOWN_TOP_LEVEL: &[u8] = b"<LifecycleConfiguration><FutureTopLevel>future</FutureTopLevel><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>";
/// `g-d1-003`, as narrowed by rustfs/backlog#2104: a whole unknown subtree beside `Rule`, not
/// inside it. Both the pinned s3s oracle and the persisted decoder skip it and still read every
/// known field that follows. Unknown content inside `Rule`, `Expiration` or `Filter` is refused by
/// both and stays in the refusal matrix below; nested leniency is not claimed here.
const UNKNOWN_SUBTREE_BEFORE_RULE: &[u8] = b"<LifecycleConfiguration><FutureBlock><Nested><Deeper>future</Deeper></Nested><Sibling/></FutureBlock><Rule><Expiration><Days>30</Days></Expiration><Filter><Prefix>logs/</Prefix></Filter><ID>keep</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const UNKNOWN_SUBTREE_AFTER_RULE: &[u8] = b"<LifecycleConfiguration><Rule><Expiration><Days>30</Days></Expiration><Filter><Prefix>logs/</Prefix></Filter><ID>keep</ID><Status>Enabled</Status></Rule><FutureBlock><Nested><Deeper>future</Deeper></Nested><Sibling/></FutureBlock></LifecycleConfiguration>";
/// Pinned witnesses the `g-d1-003` census row requires to be accepted D1-D5 samples.
pub(crate) const UNKNOWN_TOP_LEVEL_SUBTREES: &[&str] = &[
    "15b32d2d31933729bd8f3c566159f9a8002eb1682cb05212833cfa4b39dc2015",
    "f94f58b7683d6b5c222248468e90bec48571c22dc7bf8c0335dad6f039e90540",
];
const ALTERNATE_ORDER: &[u8] = b"<LifecycleConfiguration><Rule><Transition><StorageClass>GLACIER</StorageClass><Days>30</Days></Transition><Status>Disabled</Status><ID>alt</ID></Rule></LifecycleConfiguration>";
const UNKNOWN_STATUS: &[u8] = b"<LifecycleConfiguration><Rule><Status>FutureStatus</Status></Rule></LifecycleConfiguration>";
const SIX_DIGIT_TIMESTAMP: &[u8] = b"<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-30T12:34:56.123456Z</ExpiryUpdatedAt><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const EMPTY_WRAPPERS: &[u8] = b"<LifecycleConfiguration><Rule><AbortIncompleteMultipartUpload></AbortIncompleteMultipartUpload><DelMarkerExpiration></DelMarkerExpiration><Expiration></Expiration><Filter><And></And></Filter><NoncurrentVersionExpiration></NoncurrentVersionExpiration><NoncurrentVersionTransition></NoncurrentVersionTransition><Status>Enabled</Status><Transition></Transition></Rule></LifecycleConfiguration>";
fn minimal() -> PersistedLifecycleConfiguration {
    PersistedLifecycleConfiguration {
        rules: vec![PersistedLifecycleRule {
            abort_incomplete_multipart_upload: None,
            del_marker_expiration: None,
            expiration: None,
            filter: None,
            id: None,
            noncurrent_version_expiration: None,
            noncurrent_version_transitions: None,
            prefix: None,
            status: "Enabled".to_owned(),
            transitions: None,
        }],
        ..PersistedLifecycleConfiguration::default()
    }
}

/// The known fields both `UNKNOWN_SUBTREE_*` samples carry: ID, Status, Expiration.Days and
/// Filter.Prefix. A decoder that stops reading at the unknown subtree loses at least one of them.
fn fields_beside_unknown_subtree() -> PersistedLifecycleConfiguration {
    let mut value = minimal();
    value.rules[0].id = Some("keep".to_owned());
    value.rules[0].expiration = Some(PersistedLifecycleExpiration {
        days: Some(30),
        ..PersistedLifecycleExpiration::default()
    });
    value.rules[0].filter = Some(PersistedLifecycleFilter {
        prefix: Some("logs/".to_owned()),
        ..PersistedLifecycleFilter::default()
    });
    value
}

#[cfg(test)]
fn full(timestamp: &str) -> PersistedLifecycleConfiguration {
    use rustfs_gateway_types::persistence::PersistedLifecycleTag;
    PersistedLifecycleConfiguration {
        expiry_updated_at: Some(timestamp.to_owned()),
        rules: vec![PersistedLifecycleRule {
            abort_incomplete_multipart_upload: Some(PersistedAbortIncompleteMultipartUpload {
                days_after_initiation: Some(7),
            }),
            del_marker_expiration: Some(PersistedDelMarkerExpiration { days: Some(8) }),
            expiration: Some(PersistedLifecycleExpiration {
                date: Some("2026-09-01T00:00:00.000Z".to_owned()),
                days: Some(30),
                expired_object_all_versions: Some(true),
                expired_object_delete_marker: Some(false),
            }),
            filter: Some(PersistedLifecycleFilter {
                and: Some(PersistedLifecycleAnd {
                    object_size_greater_than: Some(-1),
                    object_size_less_than: Some(i64::MAX),
                    prefix: Some("archive/".to_owned()),
                    tags: Some(vec![
                        PersistedLifecycleTag {
                            key: Some("tier".to_owned()),
                            value: Some("café-🧊".to_owned()),
                        },
                        PersistedLifecycleTag {
                            key: Some(String::new()),
                            value: None,
                        },
                    ]),
                }),
                object_size_greater_than: Some(1),
                object_size_less_than: Some(2048),
                prefix: Some("logs/".to_owned()),
                tag: Some(PersistedLifecycleTag {
                    key: Some("env".to_owned()),
                    value: Some("prod".to_owned()),
                }),
            }),
            id: Some("all-fields".to_owned()),
            noncurrent_version_expiration: Some(PersistedNoncurrentVersionExpiration {
                newer_noncurrent_versions: Some(2),
                noncurrent_days: Some(60),
            }),
            noncurrent_version_transitions: Some(vec![PersistedNoncurrentVersionTransition {
                newer_noncurrent_versions: Some(3),
                noncurrent_days: Some(90),
                storage_class: Some("GLACIER".to_owned()),
            }]),
            prefix: Some("legacy/".to_owned()),
            status: "Enabled".to_owned(),
            transitions: Some(vec![PersistedTransition {
                date: Some("2026-10-01T00:00:00.123Z".to_owned()),
                days: Some(120),
                storage_class: Some("DEEP_ARCHIVE".to_owned()),
            }]),
        }],
    }
}

fn sample(bytes: &[u8], value: PersistedLifecycleConfiguration, notes: &str) -> GoldenSample<PersistedLifecycleConfiguration> {
    GoldenSample {
        kind: ConfigKind::Lifecycle,
        bytes: bytes.to_vec(),
        value,
        origin: SampleOrigin {
            source: "P9 Lifecycle persistence matrix".to_owned(),
            producer: "pinned s3s XML behavior".to_owned(),
            version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
        },
        notes: notes.to_owned(),
    }
}

fn rejected(bytes: &[u8], variants: &[CorpusVariant], notes: &str) -> RejectedCorpusCase {
    RejectedCorpusCase {
        sample: RejectedGoldenSample {
            kind: ConfigKind::Lifecycle,
            bytes: bytes.to_vec(),
            origin: SampleOrigin {
                source: "P9 Lifecycle refusal matrix".to_owned(),
                producer: "pinned s3s XML behavior".to_owned(),
                version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
                sha256: hex::encode(Sha256::digest(bytes)),
            },
            notes: notes.to_owned(),
        },
        variants: variants.to_vec(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LifecycleBehaviorProjection {
    enabled: Vec<bool>,
    whole_bucket: Vec<bool>,
}
fn rule_matches_whole_bucket(rule: &PersistedLifecycleRule) -> bool {
    let legacy_prefix_is_empty = rule.prefix.as_deref().is_none_or(str::is_empty);
    let filter_is_empty = rule.filter.as_ref().is_none_or(|filter| {
        let and_is_empty = filter.and.as_ref().is_none_or(|and| {
            and.object_size_greater_than.is_none()
                && and.object_size_less_than.is_none()
                && and.prefix.as_deref().is_none_or(str::is_empty)
                && and.tags.as_ref().is_none_or(Vec::is_empty)
        });
        and_is_empty
            && filter.object_size_greater_than.is_none()
            && filter.object_size_less_than.is_none()
            && filter.prefix.as_deref().is_none_or(str::is_empty)
            && filter.tag.is_none()
    });
    legacy_prefix_is_empty && filter_is_empty
}
#[derive(Clone, Copy, Debug)]
struct LifecycleCodec;

impl FourWayCodec for LifecycleCodec {
    const KIND: ConfigKind = ConfigKind::Lifecycle;

    type Value = PersistedLifecycleConfiguration;
    type OldParsed = S3sLifecycleObservation;
    type NewParsed = PersistedLifecycleConfiguration;
    type Structure = PersistedLifecycleConfiguration;
    type Behavior = LifecycleBehaviorProjection;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_lifecycle(bytes).map_err(|error| error.to_string())
    }

    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_lifecycle(bytes).map_err(|error| error.to_string())
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
        serialize_s3s_lifecycle(value).map_err(|error| error.to_string())
    }

    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        serialize_lifecycle(value).map_err(|error| error.to_string())
    }

    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        LifecycleBehaviorProjection {
            enabled: value.rule_enabled.clone(),
            whole_bucket: value.structure.rules.iter().map(rule_matches_whole_bucket).collect(),
        }
    }

    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        LifecycleBehaviorProjection {
            enabled: value.rules.iter().map(PersistedLifecycleRule::enabled).collect(),
            whole_bucket: value.rules.iter().map(rule_matches_whole_bucket).collect(),
        }
    }
}

/// Runs the real pinned-s3s versus gateway persistence Lifecycle oracle.
///
/// # Errors
///
/// Returns an invalid-provenance or first D1-D5 failure.
pub fn assert_lifecycle_four_way(sample: &GoldenSample<PersistedLifecycleConfiguration>) -> Result<(), GoldenFailure> {
    assert_four_way(&LifecycleCodec, sample)
}

pub(crate) fn run_lifecycle_corpus_four_way() -> Result<usize, GoldenFailure> {
    let corpus = corpus_evidence();
    for case in &corpus.accepted {
        assert_lifecycle_four_way(&case.sample)?;
    }
    Ok(corpus.accepted.len())
}

pub(crate) fn corpus_evidence() -> ConcreteFamilyCorpus<PersistedLifecycleConfiguration> {
    let mut alternate = minimal();
    alternate.rules[0].id = Some("alt".to_owned());
    alternate.rules[0].status = "Disabled".to_owned();
    alternate.rules[0].transitions = Some(vec![PersistedTransition {
        date: None,
        days: Some(30),
        storage_class: Some("GLACIER".to_owned()),
    }]);
    let mut fractional = minimal();
    fractional.expiry_updated_at = Some("2026-08-30T12:34:56.123Z".to_owned());
    let mut unknown_status = minimal();
    unknown_status.rules[0].status = "FutureStatus".to_owned();
    let mut wrappers = minimal();
    wrappers.rules[0].abort_incomplete_multipart_upload = Some(PersistedAbortIncompleteMultipartUpload::default());
    wrappers.rules[0].del_marker_expiration = Some(PersistedDelMarkerExpiration::default());
    wrappers.rules[0].expiration = Some(PersistedLifecycleExpiration::default());
    wrappers.rules[0].filter = Some(PersistedLifecycleFilter {
        and: Some(PersistedLifecycleAnd::default()),
        ..PersistedLifecycleFilter::default()
    });
    wrappers.rules[0].noncurrent_version_expiration = Some(PersistedNoncurrentVersionExpiration::default());
    wrappers.rules[0].noncurrent_version_transitions = Some(vec![PersistedNoncurrentVersionTransition::default()]);
    wrappers.rules[0].transitions = Some(vec![PersistedTransition::default()]);

    let mut accepted: Vec<_> = [
        (NAMESPACE, minimal(), vec![CorpusVariant::Namespace], "old-readable namespace declaration"),
        (
            UNKNOWN_TOP_LEVEL,
            minimal(),
            vec![CorpusVariant::UnknownTopLevel],
            "unknown top-level content remains old-readable",
        ),
        (
            UNKNOWN_SUBTREE_BEFORE_RULE,
            fields_beside_unknown_subtree(),
            vec![CorpusVariant::UnknownTopLevel],
            "unknown top-level subtree before Rule is skipped and later known fields are kept",
        ),
        (
            UNKNOWN_SUBTREE_AFTER_RULE,
            fields_beside_unknown_subtree(),
            vec![CorpusVariant::UnknownTopLevel],
            "unknown top-level subtree after Rule is skipped and earlier known fields are kept",
        ),
        (
            ALTERNATE_ORDER,
            alternate,
            vec![CorpusVariant::AlternateOrder],
            "old-readable noncanonical rule and transition order",
        ),
        (
            UNKNOWN_STATUS,
            unknown_status,
            vec![CorpusVariant::UnknownScalar],
            "old-readable unknown status remains inactive",
        ),
        (
            SIX_DIGIT_TIMESTAMP,
            fractional,
            vec![CorpusVariant::TimestampPrecision],
            "six-digit timestamp normalizes to milliseconds",
        ),
        (
            EMPTY_WRAPPERS,
            wrappers,
            vec![CorpusVariant::EmptyElement],
            "explicit empty action and filter wrappers remain present",
        ),
    ]
    .into_iter()
    .map(|(bytes, value, variants, notes)| AcceptedCorpusCase {
        sample: sample(bytes, value, notes),
        variants,
    })
    .collect();
    accepted.extend(source_b::cases());
    accepted.extend(crate::source_a_boundary::lifecycle_cases());
    accepted.push(crate::source_a_lifecycle::lifecycle_case());
    accepted.extend(crate::source_a_new_writer::lifecycle_cases());
    let mut refused = vec![
        rejected(b"<LifecycleConfiguration><Rule><Future>future</Future><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::UnknownNested], "unknown Rule child"),
        rejected(b"<LifecycleConfiguration><Rule><Status>Enabled</Status><Future>future</Future></Rule></LifecycleConfiguration>", &[CorpusVariant::UnknownNested], "unknown Rule child after Status"),
        rejected(b"<LifecycleConfiguration><Rule><FutureBlock><Nested><Deeper>future</Deeper></Nested><Sibling/></FutureBlock><Expiration><Days>30</Days></Expiration><Filter><Prefix>logs/</Prefix></Filter><ID>keep</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::UnknownNested], "unknown Rule subtree"),
        rejected(b"<LifecycleConfiguration><Rule><Expiration><Future>future</Future></Expiration><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::UnknownNested], "unknown Expiration child"),
        rejected(b"<LifecycleConfiguration><Rule><Filter><Future>future</Future></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::UnknownNested], "unknown Filter child"),
        rejected(b"<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-30T00:00:00Z</ExpiryUpdatedAt><ExpiryUpdatedAt>2026-08-30T00:00:00Z</ExpiryUpdatedAt><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::DuplicateField], "duplicate ExpiryUpdatedAt"),
        rejected(b"<LifecycleConfiguration><Rule><Expiration></Expiration><Expiration></Expiration><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::DuplicateField], "duplicate Expiration"),
        rejected(b"<LifecycleConfiguration><Rule><Status>Enabled</Status><Status>Disabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::DuplicateField], "duplicate Status"),
        rejected(b"<LifecycleConfiguration><Rule><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation><DaysAfterInitiation>2</DaysAfterInitiation></AbortIncompleteMultipartUpload><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::DuplicateField], "duplicate DaysAfterInitiation"),
        rejected(b"<LifecycleConfiguration><Rule><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker><ExpiredObjectDeleteMarker>false</ExpiredObjectDeleteMarker></Expiration><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::DuplicateField], "duplicate ExpiredObjectDeleteMarker"),
        rejected(b"<LifecycleConfiguration><Rule><Filter><And></And><And></And></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::DuplicateField], "duplicate Filter.And"),
        rejected(b"<LifecycleConfiguration><Rule><Filter><Prefix>a</Prefix><Prefix>b</Prefix></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::DuplicateField], "duplicate Filter.Prefix"),
        rejected(b"<LifecycleConfiguration><Rule><Filter><And><ObjectSizeGreaterThan>1</ObjectSizeGreaterThan><ObjectSizeGreaterThan>2</ObjectSizeGreaterThan></And></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::DuplicateField], "duplicate And.ObjectSizeGreaterThan"),
        rejected(b"<LifecycleConfiguration><Rule><Filter><Tag><Key>a</Key><Key>b</Key></Tag></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::DuplicateField], "duplicate Tag.Key"),
        rejected(b"<LifecycleConfiguration><Rule><Status>Enabled</Status><Transition><Date>2026-08-30T00:00:00Z</Date><Date>2026-08-31T00:00:00Z</Date></Transition></Rule></LifecycleConfiguration>", &[CorpusVariant::DuplicateField], "duplicate Transition.Date"),
        rejected(b"<LifecycleConfiguration></LifecycleConfiguration>", &[CorpusVariant::MissingField], "no rules"),
        rejected(b"<LifecycleConfiguration><Rule><ID>missing</ID></Rule></LifecycleConfiguration>", &[CorpusVariant::MissingField], "missing status"),
        rejected(b"<LifecycleConfiguration><Rule>", &[CorpusVariant::BodyLiteral], "malformed XML"),
    ];
    for (lexeme, notes) in [
        (" 1 ", "Days surrounding whitespace"),
        ("-2147483649", "Days below i32 minimum"),
        ("2147483648", "Days above i32 maximum"),
    ] {
        let bytes = format!("<LifecycleConfiguration><Rule><Expiration><Days>{lexeme}</Days></Expiration><Status>Enabled</Status></Rule></LifecycleConfiguration>").into_bytes();
        refused.push(rejected(&bytes, &[CorpusVariant::UnknownScalar], notes));
    }
    for (lexeme, notes) in [
        ("-9223372036854775809", "size below i64 minimum"),
        ("9223372036854775808", "size above i64 maximum"),
    ] {
        let bytes = format!("<LifecycleConfiguration><Rule><Filter><ObjectSizeGreaterThan>{lexeme}</ObjectSizeGreaterThan></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>").into_bytes();
        refused.push(rejected(&bytes, &[CorpusVariant::LargeValue], notes));
    }
    for lexeme in ["True", "1", " true "] {
        let bytes = format!("<LifecycleConfiguration><Rule><Expiration><ExpiredObjectDeleteMarker>{lexeme}</ExpiredObjectDeleteMarker></Expiration><Status>Enabled</Status></Rule></LifecycleConfiguration>").into_bytes();
        refused.push(rejected(&bytes, &[CorpusVariant::UnknownScalar], &format!("invalid boolean {lexeme:?}")));
    }
    for timestamp in ["tomorrow", "2026-02-30T00:00:00Z"] {
        let bytes = format!("<LifecycleConfiguration><ExpiryUpdatedAt>{timestamp}</ExpiryUpdatedAt><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>").into_bytes();
        refused.push(rejected(
            &bytes,
            &[CorpusVariant::TimestampPrecision],
            &format!("invalid timestamp {timestamp}"),
        ));
    }
    ConcreteFamilyCorpus {
        kind: ConfigKind::Lifecycle,
        required_variants: vec![
            CorpusVariant::Namespace,
            CorpusVariant::UnknownTopLevel,
            CorpusVariant::UnknownNested,
            CorpusVariant::AlternateOrder,
            CorpusVariant::UnknownScalar,
            CorpusVariant::TimestampPrecision,
            CorpusVariant::EmptyElement,
            CorpusVariant::DuplicateField,
            CorpusVariant::MissingField,
            CorpusVariant::LargeValue,
            CorpusVariant::BodyLiteral,
        ],
        accepted,
        rejected: refused,
    }
}

#[cfg(test)]
mod tests;
