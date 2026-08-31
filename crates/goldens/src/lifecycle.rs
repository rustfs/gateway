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

    let mut refused = vec![
        rejected(b"<LifecycleConfiguration><Rule><Future>future</Future><Status>Enabled</Status></Rule></LifecycleConfiguration>", &[CorpusVariant::UnknownNested], "unknown Rule child"),
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
mod tests {
    use super::*;

    fn base_sample() -> GoldenSample<PersistedLifecycleConfiguration> {
        corpus_evidence()
            .accepted
            .into_iter()
            .find(|case| case.sample.bytes == NAMESPACE)
            .expect("the corpus keeps its namespace D1-D5 row")
            .sample
    }

    #[test]
    fn pinned_and_production_lifecycle_codecs_are_both_real() {
        let old = parse_s3s_lifecycle(MINIMAL).expect("the pinned old parser accepts a minimal lifecycle document");
        let new = parse_lifecycle(MINIMAL).expect("the production parser accepts a minimal lifecycle document");
        assert_eq!(old.structure, new);
        assert_eq!(
            serialize_s3s_lifecycle(&minimal()).expect("the pinned old serializer accepts the minimal lifecycle value"),
            serialize_lifecycle(&minimal()).expect("the production serializer accepts the minimal lifecycle value")
        );
    }

    #[test]
    fn every_lifecycle_field_keeps_the_old_byte_order() {
        let value = full("2026-08-30T12:34:56.123Z");
        let old = serialize_s3s_lifecycle(&value).expect("the pinned old serializer accepts every Lifecycle field");
        let new = serialize_lifecycle(&value).expect("the production serializer accepts every Lifecycle field");
        assert_eq!(old, new);
        let old_read = parse_s3s_lifecycle(&old).expect("the pinned old parser reads its full output");
        let new_read = parse_lifecycle(&new).expect("the production parser reads its full output");
        assert_eq!(old_read.structure, value);
        assert_eq!(new_read, value);
    }

    #[test]
    fn expiry_updated_at_canonicalizes_zero_three_six_and_nine_fraction_digits_like_s3s() {
        for (timestamp, canonical) in [
            ("2026-08-30T12:34:56Z", "2026-08-30T12:34:56.000Z"),
            ("2026-08-30T12:34:56.123Z", "2026-08-30T12:34:56.123Z"),
            ("2026-08-30T12:34:56.123456Z", "2026-08-30T12:34:56.123Z"),
            ("2026-08-30T12:34:56.123456789Z", "2026-08-30T12:34:56.123Z"),
        ] {
            let value = PersistedLifecycleConfiguration {
                expiry_updated_at: Some(timestamp.to_owned()),
                ..minimal()
            };
            let old = serialize_s3s_lifecycle(&value).expect("the pinned old serializer accepts the timestamp");
            let new = serialize_lifecycle(&value).expect("the production serializer accepts the timestamp");
            assert_eq!(old, new, "timestamp precision drift for {timestamp}");
            assert!(
                old.windows(canonical.len()).any(|window| window == canonical.as_bytes()),
                "old serializer did not canonicalize {timestamp} to {canonical}"
            );
        }
    }

    #[test]
    fn lifecycle_sample_matrix_passes_all_five_directions() {
        for case in corpus_evidence().accepted {
            if let Err(error) = assert_lifecycle_four_way(&case.sample) {
                panic!("Lifecycle sample failed ({}): {error}", case.sample.notes);
            }
        }
    }

    #[test]
    fn nested_unknown_children_match_the_pinned_old_rejection_boundary() {
        for case in corpus_evidence()
            .rejected
            .into_iter()
            .filter(|case| case.variants.contains(&CorpusVariant::UnknownNested))
        {
            assert!(
                LifecycleCodec.old_parse(&case.sample.bytes).is_err(),
                "old parser accepted {}",
                case.sample.notes
            );
            assert!(
                LifecycleCodec.new_parse(&case.sample.bytes).is_err(),
                "new parser accepted {}",
                case.sample.notes
            );
        }
    }

    #[test]
    fn duplicate_optional_lifecycle_fields_are_rejected_by_both_real_parsers() {
        for case in corpus_evidence()
            .rejected
            .into_iter()
            .filter(|case| case.variants.contains(&CorpusVariant::DuplicateField))
        {
            assert!(
                LifecycleCodec.old_parse(&case.sample.bytes).is_err(),
                "old parser accepted {}",
                case.sample.notes
            );
            assert!(
                LifecycleCodec.new_parse(&case.sample.bytes).is_err(),
                "new parser accepted {}",
                case.sample.notes
            );
        }
    }

    #[test]
    fn integer_lexemes_and_widths_match_the_pinned_old_oracle() {
        for (description, lexeme, accepted) in [
            ("negative", "-1", true),
            ("explicit plus", "+1", true),
            ("i32 minimum", "-2147483648", true),
            ("i32 maximum", "2147483647", true),
        ] {
            let xml = format!(
                "<LifecycleConfiguration><Rule><Expiration><Days>{lexeme}</Days></Expiration><Status>Enabled</Status></Rule></LifecycleConfiguration>"
            );
            assert_eq!(LifecycleCodec.old_parse(xml.as_bytes()).is_ok(), accepted, "old Days {description}");
            assert_eq!(LifecycleCodec.new_parse(xml.as_bytes()).is_ok(), accepted, "new Days {description}");
        }
        for (description, lexeme, accepted) in [
            ("i64 minimum", "-9223372036854775808", true),
            ("i64 maximum", "9223372036854775807", true),
        ] {
            let xml = format!(
                "<LifecycleConfiguration><Rule><Filter><ObjectSizeGreaterThan>{lexeme}</ObjectSizeGreaterThan></Filter><Status>Enabled</Status></Rule></LifecycleConfiguration>"
            );
            assert_eq!(LifecycleCodec.old_parse(xml.as_bytes()).is_ok(), accepted, "old size {description}");
            assert_eq!(LifecycleCodec.new_parse(xml.as_bytes()).is_ok(), accepted, "new size {description}");
        }
        for case in corpus_evidence()
            .rejected
            .into_iter()
            .filter(|case| case.sample.notes.starts_with("Days ") || case.sample.notes.starts_with("size "))
        {
            assert!(
                LifecycleCodec.old_parse(&case.sample.bytes).is_err(),
                "old accepted {}",
                case.sample.notes
            );
            assert!(
                LifecycleCodec.new_parse(&case.sample.bytes).is_err(),
                "new accepted {}",
                case.sample.notes
            );
        }
    }

    #[test]
    fn boolean_and_timestamp_boundaries_match_the_pinned_old_oracle() {
        for (lexeme, accepted) in [("true", true), ("false", true)] {
            let xml = format!(
                "<LifecycleConfiguration><Rule><Expiration><ExpiredObjectDeleteMarker>{lexeme}</ExpiredObjectDeleteMarker></Expiration><Status>Enabled</Status></Rule></LifecycleConfiguration>"
            );
            assert_eq!(LifecycleCodec.old_parse(xml.as_bytes()).is_ok(), accepted, "old boolean {lexeme:?}");
            assert_eq!(LifecycleCodec.new_parse(xml.as_bytes()).is_ok(), accepted, "new boolean {lexeme:?}");
        }
        let old_space = LifecycleCodec
            .old_parse(b"<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-30 00:00:00Z</ExpiryUpdatedAt><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>")
            .expect("old parser accepts the RFC3339 space separator");
        let new_space = LifecycleCodec
            .new_parse(b"<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-30 00:00:00Z</ExpiryUpdatedAt><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>")
            .expect("new parser preserves the old space-separator boundary");
        assert_eq!(old_space.structure, new_space);
        assert_eq!(new_space.expiry_updated_at.as_deref(), Some("2026-08-30T00:00:00.000Z"));

        for case in corpus_evidence()
            .rejected
            .into_iter()
            .filter(|case| case.sample.notes.starts_with("invalid boolean") || case.sample.notes.starts_with("invalid timestamp"))
        {
            assert!(
                LifecycleCodec.old_parse(&case.sample.bytes).is_err(),
                "old accepted {}",
                case.sample.notes
            );
            assert!(
                LifecycleCodec.new_parse(&case.sample.bytes).is_err(),
                "new accepted {}",
                case.sample.notes
            );
        }
    }

    #[test]
    fn missing_rules_status_and_malformed_xml_fail_closed() {
        for case in corpus_evidence().rejected.into_iter().filter(|case| {
            case.variants.contains(&CorpusVariant::MissingField) || case.variants.contains(&CorpusVariant::BodyLiteral)
        }) {
            assert!(
                LifecycleCodec.old_parse(&case.sample.bytes).is_err(),
                "old accepted {}",
                case.sample.notes
            );
            assert!(
                LifecycleCodec.new_parse(&case.sample.bytes).is_err(),
                "new accepted {}",
                case.sample.notes
            );
        }
    }

    struct Mutant {
        old_byte_drift: bool,
        reject_new_output_in_old: bool,
        reject_historical_in_new: bool,
        new_structure_drift: bool,
        new_behavior_drift: bool,
        unknown_status_enabled: bool,
        panic_on_old_parse: bool,
    }

    impl FourWayCodec for Mutant {
        const KIND: ConfigKind = ConfigKind::Lifecycle;

        type Value = PersistedLifecycleConfiguration;
        type OldParsed = S3sLifecycleObservation;
        type NewParsed = PersistedLifecycleConfiguration;
        type Structure = PersistedLifecycleConfiguration;
        type Behavior = LifecycleBehaviorProjection;

        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_on_old_parse, "Lifecycle parser observation must not run");
            let canonical = LifecycleCodec.new_serialize(&minimal())?;
            if self.reject_new_output_in_old && bytes == canonical {
                return Err("mutation: rollback parser rejects new Lifecycle output".to_owned());
            }
            LifecycleCodec.old_parse(bytes)
        }

        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.reject_historical_in_new && bytes == NAMESPACE {
                return Err("mutation: new Lifecycle parser is stricter".to_owned());
            }
            let mut parsed = LifecycleCodec.new_parse(bytes)?;
            if self.new_structure_drift {
                parsed.rules[0].id = Some("drift".to_owned());
            }
            Ok(parsed)
        }

        fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
            LifecycleCodec.old_structure(value)
        }

        fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
            LifecycleCodec.new_structure(value)
        }

        fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
            LifecycleCodec.expected_structure(value)
        }

        fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            let mut bytes = LifecycleCodec.old_serialize(value)?;
            if self.old_byte_drift {
                bytes.push(b' ');
            }
            Ok(bytes)
        }

        fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            LifecycleCodec.new_serialize(value)
        }

        fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
            LifecycleCodec.old_behavior(value)
        }

        fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
            let mut behavior = LifecycleCodec.new_behavior(value);
            if self.new_behavior_drift {
                behavior.enabled[0] = !behavior.enabled[0];
            }
            if self.unknown_status_enabled {
                for (rule, enabled) in value.rules.iter().zip(&mut behavior.enabled) {
                    if rule.status != "Disabled" {
                        *enabled = true;
                    }
                }
            }
            behavior
        }
    }

    fn mutant() -> Mutant {
        Mutant {
            old_byte_drift: false,
            reject_new_output_in_old: false,
            reject_historical_in_new: false,
            new_structure_drift: false,
            new_behavior_drift: false,
            unknown_status_enabled: false,
            panic_on_old_parse: false,
        }
    }

    #[test]
    fn d1_detects_lifecycle_structure_drift() {
        let mut codec = mutant();
        codec.new_structure_drift = true;
        assert_eq!(
            assert_four_way(&codec, &base_sample())
                .expect_err("D1 must compare Lifecycle structures")
                .direction,
            crate::Direction::D1CompatibleRead
        );
    }

    #[test]
    fn d2_detects_lifecycle_serializer_drift() {
        let mut codec = mutant();
        codec.old_byte_drift = true;
        assert_eq!(
            assert_four_way(&codec, &base_sample())
                .expect_err("D2 must reject one changed byte")
                .direction,
            crate::Direction::D2ByteWrite
        );
    }

    #[test]
    fn d3_detects_lifecycle_rollback_refusal() {
        let mut codec = mutant();
        codec.reject_new_output_in_old = true;
        assert_eq!(
            assert_four_way(&codec, &base_sample())
                .expect_err("D3 must prove rollback readability")
                .direction,
            crate::Direction::D3RollbackRead
        );
    }

    #[test]
    fn d4_detects_a_stricter_lifecycle_parser() {
        let mut codec = mutant();
        codec.reject_historical_in_new = true;
        assert_eq!(
            assert_four_way(&codec, &base_sample())
                .expect_err("D4 must reject a stricter parser")
                .direction,
            crate::Direction::D4NotStricter
        );
    }

    #[test]
    fn d5_detects_lifecycle_behavior_drift() {
        let mut codec = mutant();
        codec.new_behavior_drift = true;
        assert_eq!(
            assert_four_way(&codec, &base_sample())
                .expect_err("D5 must compare Lifecycle behavior")
                .direction,
            crate::Direction::D5Behavior
        );
    }

    #[test]
    fn d5_rejects_treating_an_unknown_status_as_enabled() {
        let sample = corpus_evidence()
            .accepted
            .into_iter()
            .find(|case| case.sample.bytes == UNKNOWN_STATUS)
            .expect("the corpus keeps the unknown-status behavior row")
            .sample;
        let mut codec = mutant();
        codec.unknown_status_enabled = true;
        assert_eq!(
            assert_four_way(&codec, &sample)
                .expect_err("D5 must reject enabling an old-readable unknown status")
                .direction,
            crate::Direction::D5Behavior
        );
    }

    #[test]
    fn empty_and_restrictive_filters_project_the_same_scope_on_both_sides() {
        let old = LifecycleCodec
            .old_parse(EMPTY_WRAPPERS)
            .expect("the pinned old parser accepts an explicit empty filter");
        let new = LifecycleCodec
            .new_parse(EMPTY_WRAPPERS)
            .expect("the production parser accepts an explicit empty filter");
        let old_behavior = LifecycleCodec.old_behavior(&old);
        let new_behavior = LifecycleCodec.new_behavior(&new);
        assert_eq!(old_behavior, new_behavior);
        assert_eq!(old_behavior.whole_bucket, vec![true]);
        let mut filtered = minimal();
        filtered.rules[0].filter = Some(PersistedLifecycleFilter {
            prefix: Some("logs/".to_owned()),
            ..PersistedLifecycleFilter::default()
        });
        let filtered_bytes = LifecycleCodec
            .old_serialize(&filtered)
            .expect("the pinned old serializer accepts a restrictive filter");
        let old_filtered = LifecycleCodec
            .old_parse(&filtered_bytes)
            .expect("the pinned old parser reads a restrictive filter");
        let new_filtered = LifecycleCodec
            .new_parse(&filtered_bytes)
            .expect("the production parser reads a restrictive filter");
        let old_filtered_behavior = LifecycleCodec.old_behavior(&old_filtered);
        let new_filtered_behavior = LifecycleCodec.new_behavior(&new_filtered);
        assert_eq!(old_filtered_behavior, new_filtered_behavior);
        assert_eq!(old_filtered_behavior.whole_bucket, vec![false]);
    }

    #[test]
    fn wrong_family_label_fails_before_lifecycle_codec_observation() {
        let mut invalid = base_sample();
        invalid.kind = ConfigKind::ObjectLock;
        let mut codec = mutant();
        codec.panic_on_old_parse = true;
        assert_eq!(
            assert_four_way(&codec, &invalid)
                .expect_err("mislabeled Lifecycle sample must fail closed")
                .direction,
            crate::Direction::Input
        );
    }
}
