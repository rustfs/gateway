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

mod source_b;

use rustfs_gateway_types::compat::{S3sTaggingObservation, parse_s3s_tagging, serialize_s3s_tagging};
use rustfs_gateway_types::cors_tagging::{PersistedTag, PersistedTagging, parse_tagging, serialize_tagging};

use crate::{
    ConfigKind, CorpusCaseEvidence, CorpusCoverageError, CorpusVariant, FamilyCorpusEvidence, FourWayCodec, GoldenFailure,
    GoldenSample, RejectedGoldenSample, SampleOrigin, assert_four_way,
};

const NON_ASCII: &[u8] = "<Tagging><TagSet><Tag><Key>café</Key><Value>data-🚀</Value></Tag></TagSet></Tagging>".as_bytes();
const EMPTY: &[u8] = b"<Tagging><TagSet></TagSet></Tagging>";
const EMPTY_TAG: &[u8] = b"<Tagging><TagSet><Tag></Tag></TagSet></Tagging>";
const KEY_ONLY: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key></Tag></TagSet></Tagging>";
const UNKNOWN_TOP: &[u8] = b"<Tagging><Future>future</Future><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";
const UNKNOWN_SET: &[u8] = b"<Tagging><TagSet><Future>future</Future><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";
const UNKNOWN_TAG: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key><Future>future</Future><Value>v</Value></Tag></TagSet></Tagging>";
const UNKNOWN_ATTRIBUTES: &[u8] = b"<Tagging future=\"root\"><TagSet future=\"set\"><Tag future=\"tag\"><Key future=\"key\">k</Key><Value>v</Value></Tag></TagSet></Tagging>";
const ALTERNATE_ORDER: &[u8] = b"<Tagging><TagSet><Tag><Value>v</Value><Key>k</Key></Tag></TagSet></Tagging>";
const BOM: &[u8] = b"\xef\xbb\xbf<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";
const CRLF: &[u8] = b"<Tagging>\r\n<TagSet>\r\n<Tag><Key>k</Key><Value>v</Value></Tag>\r\n</TagSet>\r\n</Tagging>";
const NEW_WRITER_TAGGING: &[u8] =
    "<Tagging><TagSet><Tag><Key>environment</Key><Value>\u{6D4B}\u{8BD5}-\u{1F980}</Value></Tag></TagSet></Tagging>".as_bytes();
const NEW_WRITER_TAGGING_SHA256: &str = "e1c0bf5c6e7c7ae427dcdf6e0df463397fb3844504b25dbf5262f18a56505779";
const NEW_WRITER_TAGGING_SOURCE: &str =
    "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[6] (BUCKET_TAGGING_CONFIG)";
const NEW_WRITER_REVISION: &str = "ca46ae9e56c167998f7139f4d3cfd5914280f4aa";

type AcceptedTaggingCase = (GoldenSample<PersistedTagging>, &'static [CorpusVariant]);
type RejectedTaggingCase = (RejectedGoldenSample, &'static [CorpusVariant]);

fn tag(key: Option<&str>, value: Option<&str>) -> PersistedTag {
    PersistedTag {
        key: key.map(str::to_owned),
        value: value.map(str::to_owned),
    }
}

fn kv() -> PersistedTagging {
    PersistedTagging {
        tag_set: vec![tag(Some("k"), Some("v"))],
    }
}

fn origin(sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: "P9 Tagging persistence matrix".to_owned(),
        producer: "pinned s3s XML behavior".to_owned(),
        version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn accepted(
    bytes: Vec<u8>,
    sha256: &str,
    value: PersistedTagging,
    notes: &str,
    variants: &'static [CorpusVariant],
) -> AcceptedTaggingCase {
    (
        GoldenSample {
            kind: ConfigKind::Tagging,
            bytes,
            value,
            origin: origin(sha256),
            notes: notes.to_owned(),
        },
        variants,
    )
}

fn rejected(bytes: &[u8], sha256: &str, notes: &str, variants: &'static [CorpusVariant]) -> RejectedTaggingCase {
    (
        RejectedGoldenSample {
            kind: ConfigKind::Tagging,
            bytes: bytes.to_vec(),
            origin: origin(sha256),
            notes: notes.to_owned(),
        },
        variants,
    )
}

fn accepted_cases() -> Vec<AcceptedTaggingCase> {
    let large = "€".repeat(8 * 1024);
    let large_xml = format!("<Tagging><TagSet><Tag><Key>k</Key><Value>{large}</Value></Tag></TagSet></Tagging>");
    let mut cases = vec![
        accepted(
            NON_ASCII.to_vec(),
            "060a0ddb322306d508dd1b5792075fb46a1859309c501eecdfd9901b649f6118",
            PersistedTagging {
                tag_set: vec![tag(Some("café"), Some("data-🚀"))],
            },
            "non-ASCII tag key and value",
            &[CorpusVariant::Canonical, CorpusVariant::Unicode],
        ),
        accepted(
            EMPTY.to_vec(),
            "8335526089e36ac194a7ce0c192060008f43ba25a359c3ed96f3b3eedbb85d98",
            PersistedTagging::default(),
            "empty tag set wrapper",
            &[CorpusVariant::EmptyElement],
        ),
        accepted(
            EMPTY_TAG.to_vec(),
            "975f1fb93267886428d37ca30f2372279b62b7d038bb1a07ebdb497f2e5f518d",
            PersistedTagging {
                tag_set: vec![tag(None, None)],
            },
            "empty tag preserves absent key and value",
            &[CorpusVariant::EmptyElement, CorpusVariant::MissingField],
        ),
        accepted(
            KEY_ONLY.to_vec(),
            "698e9114e245b064bf99e17f47ff24ebb11bf50e793faba2ccc1cc54f9ccb5ea",
            PersistedTagging {
                tag_set: vec![tag(Some("k"), None)],
            },
            "tag value absence remains distinct from empty text",
            &[CorpusVariant::MissingField],
        ),
        accepted(
            UNKNOWN_TOP.to_vec(),
            "2dc2b86dd4607c5144e9027ccf77e110547788c50b7ee0678954abd39e89c558",
            kv(),
            "old-readable unknown top-level element",
            &[CorpusVariant::UnknownTopLevel],
        ),
        accepted(
            UNKNOWN_SET.to_vec(),
            "8413ecaa36d5fb11a51d46cbfc3cf1155113696dbd3e02a32c5a2f2556203a46",
            kv(),
            "old-readable unknown TagSet element",
            &[CorpusVariant::UnknownNested],
        ),
        accepted(
            UNKNOWN_ATTRIBUTES.to_vec(),
            "eb18bcb791fea939a6145b87e0c8767a83cc17ec5b77586d4b367bb5b8cee6e5",
            kv(),
            "old-readable attributes at every structural level",
            &[CorpusVariant::UnknownAttribute],
        ),
        accepted(
            ALTERNATE_ORDER.to_vec(),
            "d0938cc3f069f7b1c8effa0a521ded608b2721676aff3bd4ab97f6b18e075e25",
            kv(),
            "old-readable Value-before-Key order",
            &[CorpusVariant::AlternateOrder],
        ),
        accepted(
            BOM.to_vec(),
            "5a9b6714cef975abe9eee01caa71f677e034ba67116bbd34b8e751086dd87295",
            kv(),
            "UTF-8 byte-order mark",
            &[CorpusVariant::Bom],
        ),
        accepted(
            CRLF.to_vec(),
            "3ce4ffc4ed3786c8969303a28fdda86fa1ef25bc7fc6abef6788b0e57b28113d",
            kv(),
            "CRLF line endings",
            &[CorpusVariant::Crlf],
        ),
        accepted(
            large_xml.into_bytes(),
            "fac42b276894784523ecf2ebda80eaccacb5e8b54082cdde572698e967902cad",
            PersistedTagging {
                tag_set: vec![tag(Some("k"), Some(&large))],
            },
            "persistence-sized Unicode tag value",
            &[CorpusVariant::LargeValue, CorpusVariant::Unicode],
        ),
    ];
    cases.extend(source_b::cases());
    let value = parse_s3s_tagging(NEW_WRITER_TAGGING)
        .expect("the RustFS new-writer Tagging fixture is old-readable")
        .structure;
    cases.push((
        GoldenSample {
            kind: ConfigKind::Tagging,
            bytes: NEW_WRITER_TAGGING.to_vec(),
            value,
            origin: SampleOrigin {
                source: NEW_WRITER_TAGGING_SOURCE.to_owned(),
                producer: "rustfs/rustfs new bucket-metadata writer fixture".to_owned(),
                version: NEW_WRITER_REVISION.to_owned(),
                sha256: NEW_WRITER_TAGGING_SHA256.to_owned(),
            },
            notes: "RustFS new writer emits a Unicode environment tag".to_owned(),
        },
        &[CorpusVariant::Canonical, CorpusVariant::Unicode],
    ));
    for (bytes, sha256, source_refs) in crate::ecstore_source_a::fixture_bindings(ConfigKind::Tagging) {
        let value = parse_s3s_tagging(bytes)
            .expect("the RustFS ecstore Tagging fixture is old-readable")
            .structure;
        cases.push((
            GoldenSample {
                kind: ConfigKind::Tagging,
                bytes: bytes.to_vec(),
                value,
                origin: SampleOrigin {
                    source: crate::ecstore_source_a::provenance_source(source_refs),
                    producer: "rustfs/rustfs ecstore metadata test fixture".to_owned(),
                    version: crate::ecstore_source_a::SOURCE_REVISION.to_owned(),
                    sha256: sha256.to_owned(),
                },
                notes: "RustFS ecstore persists this Tagging document byte-exactly".to_owned(),
            },
            &[CorpusVariant::Canonical],
        ));
    }
    cases
}

fn rejected_cases() -> Vec<RejectedTaggingCase> {
    let mut cases = vec![
        rejected(
            b"<Tagging></Tagging>",
            "b957e31ebd9819ec59c3e5b020a4c28f13d66fecd3e2e6191296e6598de92311",
            "missing TagSet",
            &[CorpusVariant::MissingField],
        ),
        rejected(
            b"<Tagging><TagSet></TagSet><TagSet></TagSet></Tagging>",
            "704a85684c0e3f0c1898bfd2e5593b2adb56f6d9fad67b4b8a73f76f8de43f5e",
            "duplicate TagSet",
            &[CorpusVariant::DuplicateField],
        ),
        rejected(
            b"<Tagging><TagSet><Tag><Key>a</Key><Key>b</Key></Tag></TagSet></Tagging>",
            "389627cd77c0004f08e7cb3196f1e84d8f6783c98dfe5999e4daa4934107a390",
            "duplicate Key",
            &[CorpusVariant::DuplicateField],
        ),
        rejected(
            b"<Tagging><TagSet><Tag><Value>a</Value><Value>b</Value></Tag></TagSet></Tagging>",
            "c9fe91b601d06410efec0e4e3f0ce71c5957a877d9003c5e62b40171e9b50fae",
            "duplicate Value",
            &[CorpusVariant::DuplicateField],
        ),
        rejected(
            UNKNOWN_TAG,
            "632e2db3a5f85479319e37291266f272a91108ee4e0036fd67fd397aa00951d6",
            "unknown Tag element",
            &[CorpusVariant::UnknownNested],
        ),
        rejected(
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "empty document",
            &[CorpusVariant::MalformedDocument],
        ),
        rejected(
            b"<Wrong><TagSet></TagSet></Wrong>",
            "1abd8ef242b25a9b25bee3de9a9de2b140b4238110dbe0d053515983d6e9250d",
            "wrong root",
            &[CorpusVariant::MalformedDocument],
        ),
        rejected(
            b"<Tagging><TagSet>",
            "7eb91def4df99883d6deff30928a8d7ae75d587a442d48dd881964d034be25fd",
            "unclosed document",
            &[CorpusVariant::MalformedDocument],
        ),
        rejected(
            b"<Tagging><TagSet>\xff</TagSet></Tagging>",
            "88a94e2653afd96d8631134c4eafd975420bce331fcd01841765e80010b898fb",
            "invalid UTF-8",
            &[CorpusVariant::MalformedDocument],
        ),
        rejected(
            b"<Tagging bad=\"x><TagSet></TagSet></Tagging>",
            "1d4411b5ab953c36bfa3cffdf493c61deef3e41250b1b046e5372008b51ab5ff",
            "unterminated attribute",
            &[CorpusVariant::MalformedDocument],
        ),
        rejected(
            b"<Tagging><TagSet></Tagging>",
            "bffc2c8c5bc02a036ea20615282c0da08e3ae00bac2ca3927c28ccd37e8860b5",
            "mismatched closing tag",
            &[CorpusVariant::MalformedDocument],
        ),
        rejected(
            b"<Tagging><TagSet><Tag><Key>&bogus;</Key></Tag></TagSet></Tagging>",
            "f292bdd7948ce11bfccc27a9bc23da064d19ac3cabc78794a51a8c79d71a4e39",
            "invalid XML entity",
            &[CorpusVariant::MalformedDocument],
        ),
    ];
    cases.extend(source_b::rejected_cases());
    cases
}

/// Builds Tagging coverage from the same accepted and rejected cases used by the codec tests.
///
/// # Errors
///
/// Returns an error when a case has stale provenance or lacks a coverage classification.
pub(crate) fn corpus_evidence() -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
    let mut cases = Vec::new();
    for (sample, variants) in accepted_cases() {
        cases.push(CorpusCaseEvidence::accepted(&sample, variants)?);
    }
    for (sample, variants) in rejected_cases() {
        cases.push(CorpusCaseEvidence::rejected(&sample, variants)?);
    }
    Ok(FamilyCorpusEvidence::new(
        ConfigKind::Tagging,
        vec![
            CorpusVariant::Canonical,
            CorpusVariant::EmptyElement,
            CorpusVariant::MissingField,
            CorpusVariant::UnknownTopLevel,
            CorpusVariant::UnknownNested,
            CorpusVariant::UnknownAttribute,
            CorpusVariant::AlternateOrder,
            CorpusVariant::DuplicateField,
            CorpusVariant::LargeValue,
            CorpusVariant::Bom,
            CorpusVariant::Crlf,
            CorpusVariant::Unicode,
            CorpusVariant::MalformedDocument,
        ],
        cases,
    ))
}
const _: fn() -> Result<FamilyCorpusEvidence, CorpusCoverageError> = corpus_evidence;

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

pub(crate) fn run_tagging_corpus_four_way() -> Result<usize, GoldenFailure> {
    let cases = accepted_cases();
    for (sample, _) in &cases {
        assert_tagging_four_way(sample)?;
    }
    Ok(cases.len())
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
    use super::*;
    use crate::{Direction, build_corpus_report};

    fn sample() -> GoldenSample<PersistedTagging> {
        accepted_cases()
            .into_iter()
            .find(|(_, variants)| variants.contains(&CorpusVariant::UnknownAttribute))
            .expect("Tagging corpus has an unknown-attribute control")
            .0
    }

    #[test]
    fn tagging_sample_matrix_passes_all_five_directions() {
        for (case, _) in accepted_cases() {
            assert_tagging_four_way(&case).unwrap_or_else(|error| panic!("Tagging {}: {error}", case.notes));
        }
    }

    #[test]
    fn missing_and_duplicate_tagging_structure_matches_the_old_refusal_boundary() {
        for (case, _) in rejected_cases() {
            assert!(TaggingCodec.old_parse(&case.bytes).is_err(), "old parser accepted {}", case.notes);
            assert!(TaggingCodec.new_parse(&case.bytes).is_err(), "new parser accepted {}", case.notes);
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
        for (case, _) in accepted_cases()
            .into_iter()
            .filter(|(_, variants)| variants.contains(&CorpusVariant::Bom) || variants.contains(&CorpusVariant::Crlf))
        {
            assert_tagging_four_way(&case).unwrap_or_else(|error| panic!("Tagging {}: {error}", case.notes));
        }
    }

    #[test]
    fn persisted_tagging_accepts_an_eight_kibibyte_unicode_value() {
        let case = accepted_cases()
            .into_iter()
            .find(|(_, variants)| variants.contains(&CorpusVariant::LargeValue))
            .expect("Tagging corpus has a large-value control")
            .0;
        let old = TaggingCodec
            .old_parse(&case.bytes)
            .expect("old persistence parser accepts long tag");
        let new = TaggingCodec
            .new_parse(&case.bytes)
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

    #[test]
    fn tagging_report_is_derived_from_the_shared_concrete_cases() {
        let evidence = corpus_evidence().expect("Tagging corpus evidence is traceable");
        let report = build_corpus_report(&[ConfigKind::Tagging], &[evidence])
            .expect("Tagging concrete cases satisfy the coverage contract");
        assert!(report.render().contains("tagging: accepted=15 rejected=13"));
    }

    #[test]
    fn new_writer_tagging_fixture_is_registered_once_by_exact_sha() {
        let matches = accepted_cases()
            .into_iter()
            .filter(|(sample, _)| sample.origin.sha256 == NEW_WRITER_TAGGING_SHA256)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "the new-writer Tagging SHA must be registered exactly once");
        let sample = &matches[0].0;
        assert_eq!(sample.bytes, NEW_WRITER_TAGGING);
        assert_eq!(sample.origin.source, NEW_WRITER_TAGGING_SOURCE);
        assert_eq!(sample.origin.version, NEW_WRITER_REVISION);
        assert_tagging_four_way(sample).expect("the RustFS new-writer Tagging fixture passes D1-D5");
    }

    #[test]
    fn ecstore_tagging_fixtures_are_registered_once_by_exact_sha() {
        for (sha256, source) in [
            (
                "6a6c84a2c75d7125d9792de21a0fef4d7f65c8ce107709c1b68d2f8264ab90ba",
                "crates/ecstore/src/bucket/metadata.rs::tests::tagging_update_config_clears_parsed_config_on_delete::tagging_xml",
            ),
            (
                "7f46d946932dcb5747aefef2fe35536332a37d0df71354675804b484689dc826",
                "crates/ecstore/src/bucket/metadata.rs::tests::marshal_msg_complete_example::tagging_xml (aliases: crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::tagging_xml)",
            ),
        ] {
            let matches = accepted_cases()
                .into_iter()
                .filter(|(sample, _)| sample.origin.sha256 == sha256)
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "the ecstore Tagging SHA must be registered exactly once");
            let sample = &matches[0].0;
            assert_eq!(sample.origin.source, source);
            assert_eq!(sample.origin.version, "c876df53f5097618b1817568a471cbb8b4f26ee8");
            assert_tagging_four_way(sample).expect("the RustFS ecstore Tagging fixture passes D1-D5");
        }
    }
}
