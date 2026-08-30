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

use rustfs_gateway_types::compat::{S3sObjectLockObservation, parse_s3s_object_lock, serialize_s3s_object_lock};
use rustfs_gateway_types::persistence::{PersistedObjectLockConfiguration, parse_object_lock, serialize_object_lock};

use crate::{ConfigKind, FourWayCodec, GoldenFailure, GoldenSample, assert_four_way};

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
    use rustfs_gateway_types::persistence::{PersistedDefaultRetention, PersistedObjectLockRule};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{Direction, SampleOrigin};

    const EMPTY: &[u8] = b"<ObjectLockConfiguration></ObjectLockConfiguration>";
    const ENABLED_WITHOUT_RULE: &[u8] =
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
    const INVALID_DAYS: &[u8] = b"<ObjectLockConfiguration><Rule><DefaultRetention><Days>tomorrow</Days></DefaultRetention></Rule></ObjectLockConfiguration>";

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

    fn sample(
        bytes: &[u8],
        sha256: &str,
        value: PersistedObjectLockConfiguration,
        notes: &str,
    ) -> GoldenSample<PersistedObjectLockConfiguration> {
        GoldenSample {
            kind: ConfigKind::ObjectLock,
            bytes: bytes.to_vec(),
            value,
            origin: SampleOrigin {
                source: "P9 Object Lock persistence matrix".to_owned(),
                producer: "pinned s3s XML behavior".to_owned(),
                version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
                sha256: sha256.to_owned(),
            },
            notes: notes.to_owned(),
        }
    }

    fn base_sample() -> GoldenSample<PersistedObjectLockConfiguration> {
        sample(
            NAMESPACE,
            "df6ac0549ea2798014d483cff942654be46743dad3474af3b679ca143807ac99",
            enabled(None),
            "historical namespace bytes canonicalize without changing Object Lock behavior",
        )
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
        let cases = [
            sample(
                EMPTY,
                "9bfb72f1694f868f08f9f3aa7e2bdb31689a3640575e43b8c8b8ff7a0bdc454b",
                PersistedObjectLockConfiguration::default(),
                "all optional fields absent",
            ),
            sample(
                EMPTY_RULE,
                "94def8e5843449bdc01c7affce219c5628f7788a7a1fbb21d6c78bfb3a88273b",
                PersistedObjectLockConfiguration {
                    rule: Some(PersistedObjectLockRule { default_retention: None }),
                    ..PersistedObjectLockConfiguration::default()
                },
                "explicit empty Rule remains structurally present",
            ),
            sample(
                EMPTY_DEFAULT_RETENTION,
                "eeed78e82ddbb6505bd8d6ef1b8f2b8e17811c636e8ed815f3dfe80088dbf14a",
                PersistedObjectLockConfiguration {
                    rule: Some(PersistedObjectLockRule {
                        default_retention: Some(PersistedDefaultRetention::default()),
                    }),
                    ..PersistedObjectLockConfiguration::default()
                },
                "explicit empty DefaultRetention remains structurally present",
            ),
            sample(
                ENABLED_WITHOUT_RULE,
                "9cf16b957c9f7a738af95d6962500ebaae0e23d0138c811a8b6f39bcc941bbb2",
                enabled(None),
                "bucket-creation default keeps Object Lock enabled without inventing a retention rule",
            ),
            sample(
                GOVERNANCE_DAYS,
                "6ed57381ca9d593140b4fbbe04a8959a4a287453cad8fc0eb1f39d76f56bdc86",
                enabled(Some(retention("GOVERNANCE", Some(30), None))),
                "day-based governance retention",
            ),
            sample(
                COMPLIANCE_YEARS,
                "0843768a4fb162916b72d91e3c6dd616c42188d3c55d00ca0bc46e64ae305834",
                enabled(Some(retention("COMPLIANCE", None, Some(7)))),
                "year-based compliance retention",
            ),
            sample(
                NAMESPACE,
                "df6ac0549ea2798014d483cff942654be46743dad3474af3b679ca143807ac99",
                enabled(None),
                "historical namespace declaration",
            ),
            sample(
                UNKNOWN_TOP_LEVEL,
                "4fa90cd14d038f1733870bc2def87505d04950136f71c4bdb44c2c7d2d4146cb",
                enabled(None),
                "old-readable unknown top-level element",
            ),
            sample(
                UNKNOWN_ATTRIBUTES,
                "7648bd3868592907be4be7b8ad7aecf451047bbc17da8dbac9e5b53fddf2e515",
                PersistedObjectLockConfiguration {
                    rule: Some(PersistedObjectLockRule {
                        default_retention: Some(retention("GOVERNANCE", Some(1), None)),
                    }),
                    ..PersistedObjectLockConfiguration::default()
                },
                "old-readable unknown attributes at every structural level",
            ),
            sample(
                ALTERNATE_ORDER,
                "6be59d596d355f198c14b373f54d3812c4f3c7b9cffe5d841b3017b77a9f2a43",
                enabled(Some(retention("COMPLIANCE", None, Some(2)))),
                "old-readable noncanonical element order",
            ),
        ];
        for case in cases {
            if let Err(error) = assert_object_lock_four_way(&case) {
                panic!("Object Lock sample failed ({}): {error}", case.notes);
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
        let cases: [(&str, &[u8]); 6] = [
            ("ObjectLockEnabled", DUPLICATE_ENABLED),
            (
                "Rule",
                b"<ObjectLockConfiguration><Rule></Rule><Rule></Rule></ObjectLockConfiguration>",
            ),
            (
                "DefaultRetention",
                b"<ObjectLockConfiguration><Rule><DefaultRetention></DefaultRetention><DefaultRetention></DefaultRetention></Rule></ObjectLockConfiguration>",
            ),
            (
                "Mode",
                b"<ObjectLockConfiguration><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Mode>COMPLIANCE</Mode></DefaultRetention></Rule></ObjectLockConfiguration>",
            ),
            (
                "Days",
                b"<ObjectLockConfiguration><Rule><DefaultRetention><Days>1</Days><Days>2</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
            ),
            (
                "Years",
                b"<ObjectLockConfiguration><Rule><DefaultRetention><Years>1</Years><Years>2</Years></DefaultRetention></Rule></ObjectLockConfiguration>",
            ),
        ];
        for (field, bytes) in cases {
            assert!(ObjectLockCodec.old_parse(bytes).is_err(), "old parser accepted duplicate {field}");
            assert!(ObjectLockCodec.new_parse(bytes).is_err(), "new parser accepted duplicate {field}");
        }
    }

    #[test]
    fn nested_unknown_children_expose_the_pinned_old_oracle_boundary() {
        for (location, bytes, sha256) in [
            (
                "Rule",
                UNKNOWN_RULE_CHILD,
                "6458e6cb584f35e6167785042d0fb926f1df1e1255e1194a188dd7ad35919af4",
            ),
            (
                "DefaultRetention",
                UNKNOWN_RETENTION_CHILD,
                "278f82b4be46a3d909113e8efbe93acaddecc8d0f1645683196a3e0f3525962d",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(bytes)), sha256, "stale {location} negative-case digest");
            assert!(
                ObjectLockCodec.old_parse(bytes).is_err(),
                "pinned old parser unexpectedly accepted unknown child in {location}"
            );
            assert!(
                ObjectLockCodec.new_parse(bytes).is_err(),
                "new parser must preserve old rejection of unknown child in {location}"
            );
        }
    }

    #[test]
    fn retention_duration_lexemes_match_the_pinned_old_oracle() {
        let lexemes = [
            ("negative", "-1", Some(-1)),
            ("explicit plus", "+1", Some(1)),
            ("surrounding whitespace", " 1 ", None),
            ("i32 minimum", "-2147483648", Some(i32::MIN)),
            ("i32 maximum", "2147483647", Some(i32::MAX)),
            ("below i32 minimum", "-2147483649", None),
            ("above i32 maximum", "2147483648", None),
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
                    None => {
                        assert!(old.is_err(), "old accepted invalid {field} {description}");
                        assert!(new.is_err(), "new accepted invalid {field} {description}");
                    }
                }
            }
        }
    }

    #[test]
    fn invalid_duration_is_rejected_by_both_real_parsers() {
        assert!(ObjectLockCodec.old_parse(INVALID_DAYS).is_err());
        assert!(ObjectLockCodec.new_parse(INVALID_DAYS).is_err());
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
