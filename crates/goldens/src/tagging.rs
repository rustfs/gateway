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

//! Tagging persistence compatibility evidence.
//!
//! Responsible for: D1-D5 evidence over independently observed old and new Tagging codecs.
//! NOT responsible for: either codec implementation or tag authorization.
//! Upstream: pinned-s3s observations and gateway persistence codecs. Downstream: the migration
//! golden gate.

use rustfs_gateway_types::compat::{S3sTaggingObservation, parse_s3s_tagging, serialize_s3s_tagging};
use rustfs_gateway_types::cors_tagging::{PersistedTagging, parse_tagging, serialize_tagging};

use crate::{ConfigKind, FourWayCodec, GoldenFailure, GoldenSample, assert_four_way};

#[derive(Clone, Copy, Debug)]
struct TaggingCodec;

/// Runs D1-D5 against the pinned old and production Tagging persistence codecs.
///
/// # Errors
///
/// Returns an invalid-provenance or first D1-D5 failure.
pub fn assert_tagging_four_way(sample: &GoldenSample<PersistedTagging>) -> Result<(), GoldenFailure> {
    assert_four_way(&TaggingCodec, sample)
}

impl FourWayCodec for TaggingCodec {
    const KIND: ConfigKind = ConfigKind::Tagging;
    type Value = PersistedTagging;
    type OldParsed = S3sTaggingObservation;
    type NewParsed = PersistedTagging;
    type Structure = PersistedTagging;
    type Behavior = Vec<(Option<String>, Option<String>)>;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_tagging(bytes).map_err(|error| error.to_string())
    }
    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_tagging(bytes).map_err(|error| error.to_string())
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
        serialize_s3s_tagging(value).map_err(|error| error.to_string())
    }
    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_tagging(value))
    }
    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        value.tags.clone()
    }
    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        value.tag_projection()
    }
}

#[cfg(test)]
mod tests {
    use rustfs_gateway_types::cors_tagging::PersistedTag;

    use super::*;
    use crate::{Direction, SampleOrigin};

    const NON_ASCII: &[u8] = "<Tagging><TagSet><Tag><Key>café</Key><Value>data-🚀</Value></Tag></TagSet></Tagging>".as_bytes();
    const EMPTY: &[u8] = b"<Tagging><TagSet></TagSet></Tagging>";
    const EMPTY_TAG: &[u8] = b"<Tagging><TagSet><Tag></Tag></TagSet></Tagging>";
    const KEY_ONLY: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key></Tag></TagSet></Tagging>";
    const UNKNOWN_TOP: &[u8] =
        b"<Tagging><Future>future</Future><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";
    const UNKNOWN_SET: &[u8] =
        b"<Tagging><TagSet><Future>future</Future><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";
    const UNKNOWN_TAG: &[u8] =
        b"<Tagging><TagSet><Tag><Key>k</Key><Future>future</Future><Value>v</Value></Tag></TagSet></Tagging>";
    const UNKNOWN_ATTRIBUTES: &[u8] = b"<Tagging future=\"root\"><TagSet future=\"set\"><Tag future=\"tag\"><Key future=\"key\">k</Key><Value>v</Value></Tag></TagSet></Tagging>";
    const ALTERNATE_ORDER: &[u8] = b"<Tagging><TagSet><Tag><Value>v</Value><Key>k</Key></Tag></TagSet></Tagging>";

    fn tag(key: Option<&str>, value: Option<&str>) -> PersistedTag {
        PersistedTag {
            key: key.map(str::to_owned),
            value: value.map(str::to_owned),
        }
    }

    fn traced(bytes: &[u8], sha256: &str, value: PersistedTagging, notes: &str) -> GoldenSample<PersistedTagging> {
        GoldenSample {
            kind: ConfigKind::Tagging,
            bytes: bytes.to_vec(),
            value,
            origin: SampleOrigin {
                source: "P9 Tagging persistence matrix".to_owned(),
                producer: "pinned s3s XML behavior".to_owned(),
                version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
                sha256: sha256.to_owned(),
            },
            notes: notes.to_owned(),
        }
    }

    fn sample() -> GoldenSample<PersistedTagging> {
        traced(
            UNKNOWN_ATTRIBUTES,
            "eb18bcb791fea939a6145b87e0c8767a83cc17ec5b77586d4b367bb5b8cee6e5",
            PersistedTagging {
                tag_set: vec![tag(Some("café"), Some("data-🚀"))],
            },
            "old-readable attributes exercise D4 independently from canonical D2 bytes",
        )
    }

    #[test]
    fn tagging_sample_matrix_passes_all_five_directions() {
        let kv = || PersistedTagging {
            tag_set: vec![tag(Some("k"), Some("v"))],
        };
        let cases = [
            traced(
                NON_ASCII,
                "060a0ddb322306d508dd1b5792075fb46a1859309c501eecdfd9901b649f6118",
                PersistedTagging {
                    tag_set: vec![tag(Some("café"), Some("data-🚀"))],
                },
                "non-ASCII tag key and value",
            ),
            traced(
                EMPTY,
                "8335526089e36ac194a7ce0c192060008f43ba25a359c3ed96f3b3eedbb85d98",
                PersistedTagging::default(),
                "empty tag set wrapper",
            ),
            traced(
                EMPTY_TAG,
                "975f1fb93267886428d37ca30f2372279b62b7d038bb1a07ebdb497f2e5f518d",
                PersistedTagging {
                    tag_set: vec![tag(None, None)],
                },
                "empty tag preserves absent key and value",
            ),
            traced(
                KEY_ONLY,
                "698e9114e245b064bf99e17f47ff24ebb11bf50e793faba2ccc1cc54f9ccb5ea",
                PersistedTagging {
                    tag_set: vec![tag(Some("k"), None)],
                },
                "tag value absence remains distinct from empty text",
            ),
            traced(
                UNKNOWN_TOP,
                "2dc2b86dd4607c5144e9027ccf77e110547788c50b7ee0678954abd39e89c558",
                kv(),
                "old-readable unknown top-level element",
            ),
            traced(
                UNKNOWN_SET,
                "8413ecaa36d5fb11a51d46cbfc3cf1155113696dbd3e02a32c5a2f2556203a46",
                kv(),
                "old-readable unknown TagSet element",
            ),
            traced(
                UNKNOWN_ATTRIBUTES,
                "eb18bcb791fea939a6145b87e0c8767a83cc17ec5b77586d4b367bb5b8cee6e5",
                kv(),
                "old-readable attributes at every structural level",
            ),
            traced(
                ALTERNATE_ORDER,
                "d0938cc3f069f7b1c8effa0a521ded608b2721676aff3bd4ab97f6b18e075e25",
                kv(),
                "old-readable Value-before-Key order",
            ),
        ];
        for case in cases {
            assert_tagging_four_way(&case).unwrap_or_else(|error| panic!("Tagging {}: {error}", case.notes));
        }
    }

    #[test]
    fn missing_and_duplicate_tagging_structure_matches_the_old_refusal_boundary() {
        for (description, xml) in [
            ("missing TagSet", b"<Tagging></Tagging>".as_slice()),
            ("duplicate TagSet", b"<Tagging><TagSet></TagSet><TagSet></TagSet></Tagging>".as_slice()),
            (
                "duplicate Key",
                b"<Tagging><TagSet><Tag><Key>a</Key><Key>b</Key></Tag></TagSet></Tagging>".as_slice(),
            ),
            (
                "duplicate Value",
                b"<Tagging><TagSet><Tag><Value>a</Value><Value>b</Value></Tag></TagSet></Tagging>".as_slice(),
            ),
        ] {
            assert!(TaggingCodec.old_parse(xml).is_err(), "old parser accepted {description}");
            assert!(TaggingCodec.new_parse(xml).is_err(), "new parser accepted {description}");
        }
    }

    #[test]
    fn exact_old_tagging_wrappers_and_key_value_order_are_pinned() {
        let non_ascii = PersistedTagging {
            tag_set: vec![tag(Some("café"), Some("data-🚀"))],
        };
        assert_eq!(
            TaggingCodec
                .old_serialize(&non_ascii)
                .expect("old serializer accepts Unicode tags"),
            NON_ASCII
        );
        assert_eq!(TaggingCodec.new_serialize(&non_ascii).expect("new serializer is infallible"), NON_ASCII);
        assert_eq!(
            TaggingCodec
                .old_serialize(&PersistedTagging::default())
                .expect("old serializer accepts empty set"),
            EMPTY
        );
        assert_eq!(
            TaggingCodec
                .new_serialize(&PersistedTagging::default())
                .expect("new serializer is infallible"),
            EMPTY
        );
    }

    #[test]
    fn nested_unknown_tag_element_matches_the_old_refusal_boundary() {
        assert!(TaggingCodec.old_parse(UNKNOWN_TAG).is_err());
        assert!(TaggingCodec.new_parse(UNKNOWN_TAG).is_err());
    }

    #[test]
    fn bom_and_crlf_inputs_match_the_pinned_old_parser() {
        for (description, xml) in [
            (
                "UTF-8 BOM",
                b"\xef\xbb\xbf<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>".as_slice(),
            ),
            (
                "CRLF",
                b"<Tagging>\r\n<TagSet>\r\n<Tag><Key>k</Key><Value>v</Value></Tag>\r\n</TagSet>\r\n</Tagging>".as_slice(),
            ),
        ] {
            let old = TaggingCodec
                .old_parse(xml)
                .unwrap_or_else(|error| panic!("old rejected {description}: {error}"));
            let new = TaggingCodec
                .new_parse(xml)
                .unwrap_or_else(|error| panic!("new rejected {description}: {error}"));
            assert_eq!(old.structure, new);
        }
    }

    #[test]
    fn persisted_tagging_accepts_an_eight_kibibyte_unicode_value() {
        let long = "€".repeat(8 * 1024);
        let xml = format!("<Tagging><TagSet><Tag><Key>k</Key><Value>{long}</Value></Tag></TagSet></Tagging>");
        let old = TaggingCodec
            .old_parse(xml.as_bytes())
            .expect("old persistence parser accepts long tag");
        let new = TaggingCodec
            .new_parse(xml.as_bytes())
            .expect("new persistence parser accepts long tag");
        assert_eq!(old.structure, new);
        assert_eq!(new.tag_set[0].value.as_deref().map(str::len), Some(8 * 1024 * 3));
    }

    struct Mutant {
        d1: bool,
        d2: bool,
        d3: bool,
        d4: bool,
        d5: bool,
        panic_old: bool,
    }

    impl FourWayCodec for Mutant {
        const KIND: ConfigKind = ConfigKind::Tagging;
        type Value = PersistedTagging;
        type OldParsed = S3sTaggingObservation;
        type NewParsed = PersistedTagging;
        type Structure = PersistedTagging;
        type Behavior = Vec<(Option<String>, Option<String>)>;

        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_old, "codec observation must not run");
            if self.d3 && bytes == TaggingCodec.new_serialize(&sample().value)? {
                return Err("mutation: rollback refusal".to_owned());
            }
            TaggingCodec.old_parse(bytes)
        }
        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.d4 && bytes == UNKNOWN_ATTRIBUTES {
                return Err("mutation: stricter parser".to_owned());
            }
            let mut parsed = TaggingCodec.new_parse(bytes)?;
            if self.d1 {
                parsed.tag_set[0].key = None;
            }
            Ok(parsed)
        }
        fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
            TaggingCodec.old_structure(value)
        }
        fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
            TaggingCodec.new_structure(value)
        }
        fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
            TaggingCodec.expected_structure(value)
        }
        fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            let mut bytes = TaggingCodec.old_serialize(value)?;
            if self.d2 {
                bytes.push(b' ');
            }
            Ok(bytes)
        }
        fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            TaggingCodec.new_serialize(value)
        }
        fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
            TaggingCodec.old_behavior(value)
        }
        fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
            let mut behavior = TaggingCodec.new_behavior(value);
            if self.d5 {
                behavior.push((Some("mutation".to_owned()), None));
            }
            behavior
        }
    }

    fn mutant() -> Mutant {
        Mutant {
            d1: false,
            d2: false,
            d3: false,
            d4: false,
            d5: false,
            panic_old: false,
        }
    }

    #[test]
    fn every_tagging_direction_has_a_mutation_control() {
        for (direction, mutate) in [
            (Direction::D1CompatibleRead, 1),
            (Direction::D2ByteWrite, 2),
            (Direction::D3RollbackRead, 3),
            (Direction::D4NotStricter, 4),
            (Direction::D5Behavior, 5),
        ] {
            let mut codec = mutant();
            match mutate {
                1 => codec.d1 = true,
                2 => codec.d2 = true,
                3 => codec.d3 = true,
                4 => codec.d4 = true,
                5 => codec.d5 = true,
                _ => unreachable!(),
            }
            let failure = assert_four_way(&codec, &sample()).expect_err("mutation must make its direction red");
            assert_eq!(failure.direction, direction);
        }
    }

    #[test]
    fn wrong_family_fails_before_codec_observation() {
        let mut invalid = sample();
        invalid.kind = ConfigKind::Cors;
        let mut codec = mutant();
        codec.panic_old = true;
        let failure = assert_four_way(&codec, &invalid).expect_err("wrong kind must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }
}
