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

//! Object Lock persistence compatibility evidence.
//!
//! Responsible for: exercising the independent old and new Object Lock persistence codecs through
//! D1-D5. NOT responsible for: implementing either codec or serving Object Lock over HTTP.
//! Upstream: pinned-s3s compatibility observations and gateway persistence codecs. Downstream: the
//! migration golden gate.

mod source_b;

use rustfs_gateway_types::compat::{S3sObjectLockObservation, parse_s3s_object_lock, serialize_s3s_object_lock};
use rustfs_gateway_types::persistence::{
    PersistedDefaultRetention, PersistedObjectLockConfiguration, PersistedObjectLockRule, parse_object_lock,
    serialize_object_lock,
};
use sha2::{Digest, Sha256};

use crate::{
    AcceptedCorpusCase, ConcreteFamilyCorpus, ConfigKind, CorpusVariant, FourWayCodec, GoldenFailure, GoldenSample,
    RejectedCorpusCase, RejectedGoldenSample, SampleOrigin, assert_four_way,
};

const EMPTY: &[u8] = b"<ObjectLockConfiguration></ObjectLockConfiguration>";
pub(crate) const ENABLED_WITHOUT_RULE: &[u8] =
    b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
const EMPTY_RULE: &[u8] = b"<ObjectLockConfiguration><Rule></Rule></ObjectLockConfiguration>";
const EMPTY_DEFAULT_RETENTION: &[u8] =
    b"<ObjectLockConfiguration><Rule><DefaultRetention></DefaultRetention></Rule></ObjectLockConfiguration>";
const GOVERNANCE_DAYS: &[u8] = b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>";
const COMPLIANCE_YEARS: &[u8] = b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>7</Years></DefaultRetention></Rule></ObjectLockConfiguration>";
const NAMESPACE: &[u8] = br#"<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"#;
const UNKNOWN_TOP_LEVEL: &[u8] = b"<ObjectLockConfiguration><FutureTopLevel>future</FutureTopLevel><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
const UNKNOWN_ATTRIBUTES: &[u8] = b"<ObjectLockConfiguration future=\"top\"><Rule future=\"rule\"><DefaultRetention future=\"retention\"><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>";
const UNKNOWN_RULE_CHILD: &[u8] = b"<ObjectLockConfiguration><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention><FutureRule>future</FutureRule></Rule></ObjectLockConfiguration>";
const UNKNOWN_RETENTION_CHILD: &[u8] = b"<ObjectLockConfiguration><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days><FutureRetention>future</FutureRetention></DefaultRetention></Rule></ObjectLockConfiguration>";
const ALTERNATE_ORDER: &[u8] = b"<ObjectLockConfiguration><Rule><DefaultRetention><Years>2</Years><Mode>COMPLIANCE</Mode></DefaultRetention></Rule><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
const DUPLICATE_ENABLED: &[u8] = b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
const INVALID_DAYS: &[u8] =
    b"<ObjectLockConfiguration><Rule><DefaultRetention><Days>tomorrow</Days></DefaultRetention></Rule></ObjectLockConfiguration>";

fn retention(mode: &str, days: Option<i32>, years: Option<i32>) -> PersistedDefaultRetention {
    PersistedDefaultRetention {
        mode: Some(mode.to_owned()),
        days,
        years,
    }
}

fn enabled(rule: Option<PersistedDefaultRetention>) -> PersistedObjectLockConfiguration {
    PersistedObjectLockConfiguration {
        object_lock_enabled: Some("Enabled".to_owned()),
        rule: rule.map(|default_retention| PersistedObjectLockRule {
            default_retention: Some(default_retention),
        }),
    }
}

fn sample(bytes: &[u8], value: PersistedObjectLockConfiguration, notes: &str) -> GoldenSample<PersistedObjectLockConfiguration> {
    let notes = if bytes == ENABLED_WITHOUT_RULE {
        format!("{notes}; {}", crate::source_a_create_defaults::object_lock_alias_note())
    } else {
        notes.to_owned()
    };
    GoldenSample {
        kind: ConfigKind::ObjectLock,
        bytes: bytes.to_vec(),
        value,
        origin: SampleOrigin {
            source: "P9 Object Lock persistence matrix".to_owned(),
            producer: "pinned s3s XML behavior".to_owned(),
            version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
        },
        notes,
    }
}

fn rejected(bytes: &[u8], variants: &[CorpusVariant], notes: &str) -> RejectedCorpusCase {
    RejectedCorpusCase {
        sample: RejectedGoldenSample {
            kind: ConfigKind::ObjectLock,
            bytes: bytes.to_vec(),
            origin: SampleOrigin {
                source: "P9 Object Lock refusal matrix".to_owned(),
                producer: "pinned s3s XML behavior".to_owned(),
                version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
                sha256: hex::encode(Sha256::digest(bytes)),
            },
            notes: notes.to_owned(),
        },
        variants: variants.to_vec(),
    }
}

pub(crate) fn corpus_evidence() -> ConcreteFamilyCorpus<PersistedObjectLockConfiguration> {
    let mut accepted = vec![
        (
            EMPTY,
            PersistedObjectLockConfiguration::default(),
            vec![CorpusVariant::Canonical],
            "all optional fields absent",
        ),
        (
            EMPTY_RULE,
            PersistedObjectLockConfiguration {
                rule: Some(PersistedObjectLockRule { default_retention: None }),
                ..PersistedObjectLockConfiguration::default()
            },
            vec![CorpusVariant::EmptyElement],
            "explicit empty Rule remains structurally present",
        ),
        (
            EMPTY_DEFAULT_RETENTION,
            PersistedObjectLockConfiguration {
                rule: Some(PersistedObjectLockRule {
                    default_retention: Some(PersistedDefaultRetention::default()),
                }),
                ..PersistedObjectLockConfiguration::default()
            },
            vec![CorpusVariant::EmptyElement],
            "explicit empty DefaultRetention remains structurally present",
        ),
        (
            ENABLED_WITHOUT_RULE,
            enabled(None),
            vec![CorpusVariant::MissingField, CorpusVariant::BodyLiteral],
            "enabled without a retention rule; pinned MinIO-compatible bare Enabled body value persisted by the old writer",
        ),
        (
            GOVERNANCE_DAYS,
            enabled(Some(retention("GOVERNANCE", Some(30), None))),
            vec![CorpusVariant::Canonical],
            "day-based governance retention",
        ),
        (
            COMPLIANCE_YEARS,
            enabled(Some(retention("COMPLIANCE", None, Some(7)))),
            vec![CorpusVariant::Canonical],
            "year-based compliance retention",
        ),
        (
            NAMESPACE,
            enabled(None),
            vec![CorpusVariant::Namespace],
            "historical namespace declaration",
        ),
        (
            UNKNOWN_TOP_LEVEL,
            enabled(None),
            vec![CorpusVariant::UnknownTopLevel],
            "old-readable unknown top-level element",
        ),
        (
            UNKNOWN_ATTRIBUTES,
            PersistedObjectLockConfiguration {
                rule: Some(PersistedObjectLockRule {
                    default_retention: Some(retention("GOVERNANCE", Some(1), None)),
                }),
                ..PersistedObjectLockConfiguration::default()
            },
            vec![CorpusVariant::UnknownAttribute],
            "old-readable unknown attributes",
        ),
        (
            ALTERNATE_ORDER,
            enabled(Some(retention("COMPLIANCE", None, Some(2)))),
            vec![CorpusVariant::AlternateOrder],
            "old-readable noncanonical element order",
        ),
    ]
    .into_iter()
    .map(|(bytes, value, variants, notes)| AcceptedCorpusCase {
        sample: sample(bytes, value, notes),
        variants,
    })
    .collect::<Vec<_>>();
    for case in &mut accepted {
        if case.sample.bytes == ENABLED_WITHOUT_RULE {
            source_b::decorate_enabled_only_alias(&mut case.sample);
        }
    }
    accepted.extend(source_b::cases());

    let mut rejected_cases = vec![
        rejected(DUPLICATE_ENABLED, &[CorpusVariant::DuplicateField], "duplicate ObjectLockEnabled"),
        rejected(b"<ObjectLockConfiguration><Rule></Rule><Rule></Rule></ObjectLockConfiguration>", &[CorpusVariant::DuplicateField], "duplicate Rule"),
        rejected(b"<ObjectLockConfiguration><Rule><DefaultRetention></DefaultRetention><DefaultRetention></DefaultRetention></Rule></ObjectLockConfiguration>", &[CorpusVariant::DuplicateField], "duplicate DefaultRetention"),
        rejected(b"<ObjectLockConfiguration><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Mode>COMPLIANCE</Mode></DefaultRetention></Rule></ObjectLockConfiguration>", &[CorpusVariant::DuplicateField], "duplicate Mode"),
        rejected(b"<ObjectLockConfiguration><Rule><DefaultRetention><Days>1</Days><Days>2</Days></DefaultRetention></Rule></ObjectLockConfiguration>", &[CorpusVariant::DuplicateField], "duplicate Days"),
        rejected(b"<ObjectLockConfiguration><Rule><DefaultRetention><Years>1</Years><Years>2</Years></DefaultRetention></Rule></ObjectLockConfiguration>", &[CorpusVariant::DuplicateField], "duplicate Years"),
        rejected(UNKNOWN_RULE_CHILD, &[CorpusVariant::UnknownNested], "unknown Rule child"),
        rejected(UNKNOWN_RETENTION_CHILD, &[CorpusVariant::UnknownNested], "unknown DefaultRetention child"),
        rejected(INVALID_DAYS, &[CorpusVariant::UnknownScalar], "non-integer Days"),
    ];
    for field in ["Days", "Years"] {
        for (lexeme, note) in [
            (" 1 ", "surrounding whitespace"),
            ("-2147483649", "below i32 minimum"),
            ("2147483648", "above i32 maximum"),
        ] {
            let bytes = format!("<ObjectLockConfiguration><Rule><DefaultRetention><{field}>{lexeme}</{field}></DefaultRetention></Rule></ObjectLockConfiguration>").into_bytes();
            rejected_cases.push(rejected(&bytes, &[CorpusVariant::UnknownScalar], &format!("{field} {note}")));
        }
    }
    ConcreteFamilyCorpus {
        kind: ConfigKind::ObjectLock,
        required_variants: vec![
            CorpusVariant::Canonical,
            CorpusVariant::EmptyElement,
            CorpusVariant::MissingField,
            CorpusVariant::Namespace,
            CorpusVariant::UnknownTopLevel,
            CorpusVariant::UnknownNested,
            CorpusVariant::UnknownAttribute,
            CorpusVariant::AlternateOrder,
            CorpusVariant::DuplicateField,
            CorpusVariant::UnknownScalar,
            CorpusVariant::BodyLiteral,
        ],
        accepted,
        rejected: rejected_cases,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectLockBehaviorProjection {
    enabled: bool,
}

/// Runs the real pinned-s3s versus gateway persistence Object Lock evidence.
///
/// # Errors
///
/// Returns an invalid-provenance or first D1-D5 failure.
pub fn assert_object_lock_four_way(sample: &GoldenSample<PersistedObjectLockConfiguration>) -> Result<(), GoldenFailure> {
    assert_four_way(&ObjectLockCodec, sample)
}

pub(crate) fn run_object_lock_corpus_four_way() -> Result<usize, GoldenFailure> {
    let corpus = corpus_evidence();
    for case in &corpus.accepted {
        assert_object_lock_four_way(&case.sample)?;
    }
    Ok(corpus.accepted.len())
}

#[derive(Clone, Copy, Debug)]
struct ObjectLockCodec;

impl FourWayCodec for ObjectLockCodec {
    const KIND: ConfigKind = ConfigKind::ObjectLock;

    type Value = PersistedObjectLockConfiguration;
    type OldParsed = S3sObjectLockObservation;
    type NewParsed = PersistedObjectLockConfiguration;
    type Structure = PersistedObjectLockConfiguration;
    type Behavior = ObjectLockBehaviorProjection;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_object_lock(bytes).map_err(|error| error.to_string())
    }

    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_object_lock(bytes).map_err(|error| error.to_string())
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
        serialize_s3s_object_lock(value).map_err(|error| error.to_string())
    }

    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_object_lock(value))
    }

    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        ObjectLockBehaviorProjection {
            enabled: value.object_lock_enabled,
        }
    }

    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        // D5 deliberately calls the production decision seam. Structural equality alone cannot
        // prove that the runtime makes the same enabled/disabled decision as the old path.
        ObjectLockBehaviorProjection {
            enabled: value.object_lock_enabled(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Direction;

    fn base_sample() -> GoldenSample<PersistedObjectLockConfiguration> {
        corpus_evidence()
            .accepted
            .into_iter()
            .find(|case| case.sample.bytes == NAMESPACE)
            .expect("the corpus keeps its namespace D1-D5 row")
            .sample
    }

    #[test]
    fn minio_body_literal_value_has_old_persistence_bytes() {
        let case = corpus_evidence()
            .accepted
            .into_iter()
            .find(|case| case.variants.contains(&CorpusVariant::BodyLiteral))
            .expect("Object Lock requires an accepted body-literal-derived sample");
        assert_eq!(case.sample.bytes, ENABLED_WITHOUT_RULE);
        assert_eq!(case.sample.value, enabled(None));
        assert_eq!(
            serialize_s3s_object_lock(&case.sample.value).expect("the pinned old persistence writer accepts the value"),
            case.sample.bytes,
            "the evidence must be observed old-writer output, not an arbitrary row tagged BodyLiteral"
        );
        assert_object_lock_four_way(&case.sample)
            .expect("both persistence codecs accept the Object Lock body-literal-derived bytes");
    }

    #[test]
    fn pinned_old_parser_preserves_explicit_empty_object_lock_wrappers() {
        let empty_rule = parse_s3s_object_lock(EMPTY_RULE).expect("the pinned old parser accepts an explicit empty Rule");
        let empty_rule_value = PersistedObjectLockConfiguration {
            rule: Some(PersistedObjectLockRule { default_retention: None }),
            ..PersistedObjectLockConfiguration::default()
        };
        assert_eq!(empty_rule.structure, empty_rule_value);
        assert_eq!(
            serialize_s3s_object_lock(&empty_rule_value).expect("the pinned old serializer preserves an explicit empty Rule"),
            EMPTY_RULE
        );
        assert_eq!(serialize_object_lock(&empty_rule_value), EMPTY_RULE);

        let empty_retention = parse_s3s_object_lock(EMPTY_DEFAULT_RETENTION)
            .expect("the pinned old parser accepts an explicit empty DefaultRetention");
        let empty_retention_value = PersistedObjectLockConfiguration {
            rule: Some(PersistedObjectLockRule {
                default_retention: Some(PersistedDefaultRetention::default()),
            }),
            ..PersistedObjectLockConfiguration::default()
        };
        assert_eq!(empty_retention.structure, empty_retention_value);
        assert_eq!(
            serialize_s3s_object_lock(&empty_retention_value)
                .expect("the pinned old serializer preserves an explicit empty DefaultRetention"),
            EMPTY_DEFAULT_RETENTION
        );
        assert_eq!(serialize_object_lock(&empty_retention_value), EMPTY_DEFAULT_RETENTION);
    }

    #[test]
    fn object_lock_sample_matrix_passes_all_five_directions() {
        for case in corpus_evidence().accepted {
            if let Err(error) = assert_object_lock_four_way(&case.sample) {
                panic!("Object Lock sample failed ({}): {error}", case.sample.notes);
            }
        }
    }

    #[test]
    fn enabled_without_rule_keeps_structure_and_enabled_decision_distinct() {
        let old = ObjectLockCodec
            .old_parse(ENABLED_WITHOUT_RULE)
            .expect("old parser accepts bucket default");
        let new = ObjectLockCodec
            .new_parse(ENABLED_WITHOUT_RULE)
            .expect("new parser accepts bucket default");
        assert!(new.rule.is_none(), "absence of a retention rule is D1 structural evidence");
        assert_eq!(ObjectLockCodec.old_behavior(&old), ObjectLockCodec.new_behavior(&new));
        assert_eq!(ObjectLockCodec.new_behavior(&new), ObjectLockBehaviorProjection { enabled: true });
    }

    #[test]
    fn full_retention_keeps_the_old_byte_order() {
        let value = enabled(Some(PersistedDefaultRetention {
            mode: Some("GOVERNANCE".to_owned()),
            days: Some(30),
            years: Some(2),
        }));
        let old = ObjectLockCodec
            .old_serialize(&value)
            .expect("old serializer accepts the full value");
        let new = ObjectLockCodec
            .new_serialize(&value)
            .expect("new serializer accepts the full value");
        assert_eq!(old, new);
        assert_eq!(
            new,
            b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Days>30</Days><Mode>GOVERNANCE</Mode><Years>2</Years></DefaultRetention></Rule></ObjectLockConfiguration>"
        );
    }

    #[test]
    fn every_duplicate_known_object_lock_field_is_rejected_by_both_real_parsers() {
        for case in corpus_evidence()
            .rejected
            .into_iter()
            .filter(|case| case.variants.contains(&CorpusVariant::DuplicateField))
        {
            assert!(
                ObjectLockCodec.old_parse(&case.sample.bytes).is_err(),
                "old parser accepted {}",
                case.sample.notes
            );
            assert!(
                ObjectLockCodec.new_parse(&case.sample.bytes).is_err(),
                "new parser accepted {}",
                case.sample.notes
            );
        }
    }

    #[test]
    fn nested_unknown_children_expose_the_pinned_old_oracle_boundary() {
        for case in corpus_evidence()
            .rejected
            .into_iter()
            .filter(|case| case.variants.contains(&CorpusVariant::UnknownNested))
        {
            let bytes = &case.sample.bytes;
            assert!(
                ObjectLockCodec.old_parse(bytes).is_err(),
                "pinned old parser unexpectedly accepted {}",
                case.sample.notes
            );
            assert!(
                ObjectLockCodec.new_parse(bytes).is_err(),
                "new parser must preserve rejection of {}",
                case.sample.notes
            );
        }
    }

    #[test]
    fn retention_duration_lexemes_match_the_pinned_old_oracle() {
        let lexemes = [
            ("negative", "-1", Some(-1)),
            ("explicit plus", "+1", Some(1)),
            ("i32 minimum", "-2147483648", Some(i32::MIN)),
            ("i32 maximum", "2147483647", Some(i32::MAX)),
        ];
        for field in ["Days", "Years"] {
            for (description, lexeme, expected) in lexemes {
                let xml = format!(
                    "<ObjectLockConfiguration><Rule><DefaultRetention><{field}>{lexeme}</{field}></DefaultRetention></Rule></ObjectLockConfiguration>"
                );
                let old = ObjectLockCodec.old_parse(xml.as_bytes());
                let new = ObjectLockCodec.new_parse(xml.as_bytes());
                match expected {
                    Some(value) => {
                        let old = old.unwrap_or_else(|error| panic!("old rejected {field} {description}: {error}"));
                        let new = new.unwrap_or_else(|error| panic!("new rejected {field} {description}: {error}"));
                        let old_retention = old
                            .structure
                            .rule
                            .and_then(|rule| rule.default_retention)
                            .expect("accepted duration has its retention wrapper");
                        let new_retention = new
                            .rule
                            .and_then(|rule| rule.default_retention)
                            .expect("accepted duration has its retention wrapper");
                        let old_value = if field == "Days" {
                            old_retention.days
                        } else {
                            old_retention.years
                        };
                        let new_value = if field == "Days" {
                            new_retention.days
                        } else {
                            new_retention.years
                        };
                        assert_eq!(old_value, Some(value), "old {field} {description}");
                        assert_eq!(new_value, Some(value), "new {field} {description}");
                    }
                    None => unreachable!("the accepted lexeme matrix contains no refusal rows"),
                }
            }
        }
        for case in corpus_evidence().rejected.into_iter().filter(|case| {
            case.variants.contains(&CorpusVariant::UnknownScalar)
                && (case.sample.notes.starts_with("Days ") || case.sample.notes.starts_with("Years "))
        }) {
            assert!(
                ObjectLockCodec.old_parse(&case.sample.bytes).is_err(),
                "old accepted {}",
                case.sample.notes
            );
            assert!(
                ObjectLockCodec.new_parse(&case.sample.bytes).is_err(),
                "new accepted {}",
                case.sample.notes
            );
        }
    }

    #[test]
    fn invalid_duration_is_rejected_by_both_real_parsers() {
        let case = corpus_evidence()
            .rejected
            .into_iter()
            .find(|case| case.sample.bytes == INVALID_DAYS)
            .expect("the refusal corpus keeps the non-integer Days row");
        assert!(ObjectLockCodec.old_parse(&case.sample.bytes).is_err());
        assert!(ObjectLockCodec.new_parse(&case.sample.bytes).is_err());
    }

    struct Mutant {
        old_byte_drift: bool,
        reject_new_output_in_old: bool,
        reject_historical_in_new: bool,
        new_structure_drift: bool,
        new_behavior_drift: bool,
        panic_on_old_parse: bool,
    }

    impl FourWayCodec for Mutant {
        const KIND: ConfigKind = ConfigKind::ObjectLock;

        type Value = PersistedObjectLockConfiguration;
        type OldParsed = S3sObjectLockObservation;
        type NewParsed = PersistedObjectLockConfiguration;
        type Structure = PersistedObjectLockConfiguration;
        type Behavior = ObjectLockBehaviorProjection;

        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_on_old_parse, "Object Lock parser observation must not run");
            let canonical = ObjectLockCodec.new_serialize(&enabled(None))?;
            if self.reject_new_output_in_old && bytes == canonical {
                return Err("mutation: rollback parser rejects the new output".to_owned());
            }
            ObjectLockCodec.old_parse(bytes)
        }

        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.reject_historical_in_new && bytes == NAMESPACE {
                return Err("mutation: new parser is stricter".to_owned());
            }
            let mut parsed = ObjectLockCodec.new_parse(bytes)?;
            if self.new_structure_drift {
                parsed.object_lock_enabled = None;
            }
            Ok(parsed)
        }

        fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
            ObjectLockCodec.old_structure(value)
        }

        fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
            ObjectLockCodec.new_structure(value)
        }

        fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
            ObjectLockCodec.expected_structure(value)
        }

        fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            let mut bytes = ObjectLockCodec.old_serialize(value)?;
            if self.old_byte_drift {
                bytes.push(b' ');
            }
            Ok(bytes)
        }

        fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            ObjectLockCodec.new_serialize(value)
        }

        fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
            ObjectLockCodec.old_behavior(value)
        }

        fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
            let mut projection = ObjectLockCodec.new_behavior(value);
            if self.new_behavior_drift {
                projection.enabled = !projection.enabled;
            }
            projection
        }
    }

    fn mutant() -> Mutant {
        Mutant {
            old_byte_drift: false,
            reject_new_output_in_old: false,
            reject_historical_in_new: false,
            new_structure_drift: false,
            new_behavior_drift: false,
            panic_on_old_parse: false,
        }
    }

    #[test]
    fn d2_detects_object_lock_serializer_drift() {
        let mut codec = mutant();
        codec.old_byte_drift = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D2 must reject one changed byte");
        assert_eq!(failure.direction, Direction::D2ByteWrite);
    }

    #[test]
    fn d3_detects_object_lock_rollback_refusal() {
        let mut codec = mutant();
        codec.reject_new_output_in_old = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D3 must prove rollback readability");
        assert_eq!(failure.direction, Direction::D3RollbackRead);
    }

    #[test]
    fn d4_detects_a_stricter_object_lock_parser() {
        let mut codec = mutant();
        codec.reject_historical_in_new = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D4 must reject a stricter parser");
        assert_eq!(failure.direction, Direction::D4NotStricter);
    }

    #[test]
    fn d1_detects_object_lock_structure_drift() {
        let mut codec = mutant();
        codec.new_structure_drift = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D1 must compare parsed structures");
        assert_eq!(failure.direction, Direction::D1CompatibleRead);
    }

    #[test]
    fn d5_detects_object_lock_behavior_drift() {
        let mut codec = mutant();
        codec.new_behavior_drift = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D5 must compare independent behavior");
        assert_eq!(failure.direction, Direction::D5Behavior);
    }

    #[test]
    fn wrong_family_label_fails_before_object_lock_codec_observation() {
        let mut invalid = base_sample();
        invalid.kind = ConfigKind::Versioning;
        let mut codec = mutant();
        codec.panic_on_old_parse = true;
        let failure = assert_four_way(&codec, &invalid).expect_err("mislabeled Object Lock sample must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }
}
