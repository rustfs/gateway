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

//! Public Access Block persistence compatibility evidence.
//!
//! Responsible for: exercising independent old and new PAB persistence codecs through D1-D5.
//! NOT responsible for: access-policy evaluation or HTTP request validation. Upstream: pinned-s3s
//! observations and gateway persistence codecs. Downstream: migration gates.

use rustfs_gateway_types::compat::{
    S3sPublicAccessBlockObservation, parse_s3s_public_access_block, serialize_s3s_public_access_block,
};
use rustfs_gateway_types::persistence::{
    PersistedPublicAccessBlockConfiguration, parse_public_access_block, serialize_public_access_block,
};

use crate::{
    ConfigKind, CorpusCaseEvidence, CorpusCoverageError, CorpusVariant, FamilyCorpusEvidence, FourWayCodec, GoldenFailure,
    GoldenSample, RejectedGoldenSample, SampleOrigin, assert_four_way,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublicAccessBlockBehaviorProjection {
    switches: (bool, bool, bool, bool),
}

/// Runs pinned-s3s versus gateway persistence Public Access Block evidence.
///
/// # Errors
///
/// Returns invalid-provenance or the first D1-D5 failure.
pub fn assert_public_access_block_four_way(
    sample: &GoldenSample<PersistedPublicAccessBlockConfiguration>,
) -> Result<(), GoldenFailure> {
    assert_four_way(&PublicAccessBlockCodec, sample)
}

#[derive(Clone, Copy, Debug)]
struct PublicAccessBlockCodec;

impl FourWayCodec for PublicAccessBlockCodec {
    const KIND: ConfigKind = ConfigKind::PublicAccessBlock;

    type Value = PersistedPublicAccessBlockConfiguration;
    type OldParsed = S3sPublicAccessBlockObservation;
    type NewParsed = PersistedPublicAccessBlockConfiguration;
    type Structure = PersistedPublicAccessBlockConfiguration;
    type Behavior = PublicAccessBlockBehaviorProjection;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_public_access_block(bytes).map_err(|error| error.to_string())
    }

    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_public_access_block(bytes).map_err(|error| error.to_string())
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
        serialize_s3s_public_access_block(value).map_err(|error| error.to_string())
    }

    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_public_access_block(value))
    }

    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        PublicAccessBlockBehaviorProjection {
            switches: value.behavior,
        }
    }

    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        PublicAccessBlockBehaviorProjection {
            switches: value.effective_switches(),
        }
    }
}

const EMPTY: &[u8] = b"<PublicAccessBlockConfiguration></PublicAccessBlockConfiguration>";
const ALL_TRUE: &[u8] = b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><IgnorePublicAcls>true</IgnorePublicAcls><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>";
const MIXED: &[u8] = b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>";
const PARTIAL: &[u8] = b"<PublicAccessBlockConfiguration><BlockPublicPolicy>true</BlockPublicPolicy><IgnorePublicAcls>false</IgnorePublicAcls></PublicAccessBlockConfiguration>";
const NAMESPACE: &[u8] = br#"<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>"#;
const UNKNOWN_TOP_LEVEL: &[u8] = b"<PublicAccessBlockConfiguration><FutureTopLevel>future</FutureTopLevel><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>";
const UNKNOWN_ATTRIBUTES: &[u8] = b"<PublicAccessBlockConfiguration future=\"root\"><BlockPublicAcls future=\"switch\">true</BlockPublicAcls></PublicAccessBlockConfiguration>";
const ALTERNATE_ORDER: &[u8] = b"<PublicAccessBlockConfiguration><RestrictPublicBuckets>true</RestrictPublicBuckets><BlockPublicPolicy>false</BlockPublicPolicy><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicAcls>false</BlockPublicAcls></PublicAccessBlockConfiguration>";
const UPPERCASE_BOOLEANS: &[u8] = b"<PublicAccessBlockConfiguration><BlockPublicAcls>TRUE</BlockPublicAcls><IgnorePublicAcls>FALSE</IgnorePublicAcls></PublicAccessBlockConfiguration>";
const CRLF: &[u8] =
    b"<PublicAccessBlockConfiguration>\r\n<BlockPublicAcls>true</BlockPublicAcls>\r\n</PublicAccessBlockConfiguration>";

fn configuration(
    block_public_acls: Option<bool>,
    ignore_public_acls: Option<bool>,
    block_public_policy: Option<bool>,
    restrict_public_buckets: Option<bool>,
) -> PersistedPublicAccessBlockConfiguration {
    PersistedPublicAccessBlockConfiguration {
        block_public_acls,
        ignore_public_acls,
        block_public_policy,
        restrict_public_buckets,
    }
}

fn origin(sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: "P9 Public Access Block persistence matrix".to_owned(),
        producer: "pinned s3s XML behavior".to_owned(),
        version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn sample(
    bytes: &[u8],
    sha256: &str,
    value: PersistedPublicAccessBlockConfiguration,
    notes: &str,
) -> GoldenSample<PersistedPublicAccessBlockConfiguration> {
    GoldenSample {
        kind: ConfigKind::PublicAccessBlock,
        bytes: bytes.to_vec(),
        value,
        origin: origin(sha256),
        notes: notes.to_owned(),
    }
}

fn rejected(bytes: Vec<u8>, sha256: &str, notes: &str, variant: CorpusVariant) -> (RejectedGoldenSample, Vec<CorpusVariant>) {
    (
        RejectedGoldenSample {
            kind: ConfigKind::PublicAccessBlock,
            bytes,
            origin: origin(sha256),
            notes: notes.to_owned(),
        },
        vec![variant],
    )
}

fn public_access_block_accepted_samples() -> Vec<(GoldenSample<PersistedPublicAccessBlockConfiguration>, Vec<CorpusVariant>)> {
    vec![
        (
            sample(
                EMPTY,
                "df7a50f7496998b13b49459c73a76957b18a40a57b3d0d55a53bb244fea446c0",
                configuration(None, None, None, None),
                "all switches omitted and therefore behaviorally false",
            ),
            vec![CorpusVariant::EmptyElement],
        ),
        (
            sample(
                ALL_TRUE,
                "ea08b0fff9a3578a8e60f3da84d74dfdb9ddb7d970baa2d01641c68d6f363b2f",
                configuration(Some(true), Some(true), Some(true), Some(true)),
                "all four switches enabled in old serializer order",
            ),
            vec![CorpusVariant::Canonical],
        ),
        (
            sample(
                MIXED,
                "e9794bc46522b7509fa24e707a7dbcb3e8327bfab3086ce64042ed097e9a9903",
                configuration(Some(true), Some(false), Some(true), Some(false)),
                "all four switches with mixed decisions",
            ),
            vec![CorpusVariant::Canonical],
        ),
        (
            sample(
                PARTIAL,
                "63e0b248dc7eb3a88ac4b34e96ca3714e85c416042cfc2ad28bc9b0d65563e94",
                configuration(None, Some(false), Some(true), None),
                "omitted switches remain structurally absent but behaviorally false",
            ),
            vec![CorpusVariant::Canonical],
        ),
        (
            sample(
                NAMESPACE,
                "1a9a999e1f0d9c6cb9a544b75321a09b6436a9a31d30e26a536a0c9a3f9a17e9",
                configuration(Some(true), None, None, None),
                "old-readable namespace on a partial PAB document",
            ),
            vec![CorpusVariant::Namespace],
        ),
        (
            sample(
                UNKNOWN_TOP_LEVEL,
                "09d7c41d7f8228d11bb8005d030e1338bb771fa75de5781049fc979c5cb905c8",
                configuration(Some(true), None, None, None),
                "old-readable unknown root child",
            ),
            vec![CorpusVariant::UnknownTopLevel],
        ),
        (
            sample(
                UNKNOWN_ATTRIBUTES,
                "18db0ec9a2f8aac27208b495399758964dde2ca77c3106b072ab8992bd1f7818",
                configuration(Some(true), None, None, None),
                "old-readable attributes on the root and a switch",
            ),
            vec![CorpusVariant::UnknownAttribute],
        ),
        (
            sample(
                ALTERNATE_ORDER,
                "c8258d9467547f4a655972b0e9469df198ef90fcddd4ab9c82c9302ad6b8b74f",
                configuration(Some(false), Some(true), Some(false), Some(true)),
                "old-readable switches in reverse and interleaved order",
            ),
            vec![CorpusVariant::AlternateOrder],
        ),
        (
            sample(
                UPPERCASE_BOOLEANS,
                "2cca29af0f550d4f1acf27f0e3b000560b4549c4a22222a33204e95cad4f2349",
                configuration(Some(true), Some(false), None, None),
                "old boolean codec accepts exact uppercase lexical forms",
            ),
            vec![CorpusVariant::Canonical],
        ),
        (
            sample(
                CRLF,
                "e105bae955fbf2277374554e5337bb0bdac11547c160d6eda738856fbca563cf",
                configuration(Some(true), None, None, None),
                "old-readable CRLF whitespace around a switch",
            ),
            vec![CorpusVariant::Crlf],
        ),
    ]
}

fn public_access_block_rejected_samples() -> Vec<(RejectedGoldenSample, Vec<CorpusVariant>)> {
    let mut cases = Vec::new();
    for (lexeme, sha256) in [
        ("FaLsE", "469d3738e7172f6600c7c3932e810c04b8e0323ae3d40201b5ae3886b9e77a7c"),
        ("1", "8829bd727c1661e55ea9f7e5cec1c57b6f051737dc7b22e6a6e386e933a098f3"),
        (" true ", "30d2f401fda07d71faca8447dd2a6f66f73e0491abf01c494753ccb9cfbf97a6"),
        ("", "9021385f5dfbb8f89121ab0cf8f329a16308fa60d7cf60af107a24bcfd1a844e"),
    ] {
        cases.push(rejected(
            format!(
                "<PublicAccessBlockConfiguration><BlockPublicAcls>{lexeme}</BlockPublicAcls></PublicAccessBlockConfiguration>"
            )
            .into_bytes(),
            sha256,
            "invalid PAB boolean lexeme",
            CorpusVariant::UnknownScalar,
        ));
    }
    for (field, sha256) in [
        ("BlockPublicAcls", "400c98a17d436b05b63d806f0efc5cd7394bf96e973bf741941b6e8f96d759fc"),
        ("IgnorePublicAcls", "64c5b01a411da7b03573bc8920a3c16298581702d101c0a426fb8ff4ff7576fb"),
        ("BlockPublicPolicy", "5fa8a1b8a92f477efd9f77286d13f879a5e76702793cffe1cb58c315b0b69e35"),
        (
            "RestrictPublicBuckets",
            "d91af1f4620434d10d2914c9fde09330d577fa6c0685e4bdb6a769484b5a5c74",
        ),
    ] {
        cases.push(rejected(
            format!(
                "<PublicAccessBlockConfiguration><{field}>true</{field}><{field}>false</{field}></PublicAccessBlockConfiguration>"
            )
            .into_bytes(),
            sha256,
            "duplicate PAB switch",
            CorpusVariant::DuplicateField,
        ));
    }
    cases.extend([
        rejected(
            b"<NotPublicAccessBlockConfiguration></NotPublicAccessBlockConfiguration>".to_vec(),
            "868cdddef248319d7319bafd87ebef91e47f954186c58a8735adbe1ff1cc68d6",
            "wrong PAB root",
            CorpusVariant::MissingField,
        ),
        rejected(
            b"<PublicAccessBlockConfiguration><BlockPublicAcls>true".to_vec(),
            "5713e4b2953f129408fa7966af3de249cb134373f397ac98d04bd31ce0291c38",
            "truncated PAB document",
            CorpusVariant::MissingField,
        ),
        rejected(
            vec![0xff],
            "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89",
            "non-UTF-8 PAB document",
            CorpusVariant::Unicode,
        ),
    ]);
    cases
}

pub(crate) fn public_access_block_corpus_evidence() -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
    let mut cases = Vec::new();
    for (sample, variants) in public_access_block_accepted_samples() {
        cases.push(CorpusCaseEvidence::accepted(&sample, &variants)?);
    }
    for (sample, variants) in public_access_block_rejected_samples() {
        cases.push(CorpusCaseEvidence::rejected(&sample, &variants)?);
    }
    Ok(FamilyCorpusEvidence::new(
        ConfigKind::PublicAccessBlock,
        vec![
            CorpusVariant::Canonical,
            CorpusVariant::EmptyElement,
            CorpusVariant::MissingField,
            CorpusVariant::Namespace,
            CorpusVariant::UnknownTopLevel,
            CorpusVariant::UnknownAttribute,
            CorpusVariant::AlternateOrder,
            CorpusVariant::DuplicateField,
            CorpusVariant::UnknownScalar,
            CorpusVariant::Crlf,
            CorpusVariant::Unicode,
        ],
        cases,
    ))
}

const _: fn() -> Result<FamilyCorpusEvidence, CorpusCoverageError> = public_access_block_corpus_evidence;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Direction, build_corpus_report};

    #[test]
    fn family_owned_corpus_evidence_is_built_from_the_shared_case_objects() {
        let evidence = public_access_block_corpus_evidence().expect("PAB corpus evidence is traceable");
        build_corpus_report(&[ConfigKind::PublicAccessBlock], &[evidence])
            .expect("PAB corpus coverage is derived from the shared cases");
    }

    fn base_sample() -> GoldenSample<PersistedPublicAccessBlockConfiguration> {
        public_access_block_accepted_samples()
            .into_iter()
            .find_map(|(sample, variants)| variants.contains(&CorpusVariant::Namespace).then_some(sample))
            .expect("PAB matrix carries its namespace control")
    }

    #[test]
    fn public_access_block_sample_matrix_passes_all_five_directions() {
        for (case, _) in public_access_block_accepted_samples() {
            if let Err(error) = assert_public_access_block_four_way(&case) {
                panic!("Public Access Block sample failed ({}): {error}", case.notes);
            }
        }
    }

    #[test]
    fn pinned_pab_boolean_boundaries_are_exact() {
        let uppercase = public_access_block_accepted_samples()
            .into_iter()
            .find_map(|(sample, _)| (sample.bytes == UPPERCASE_BOOLEANS).then_some(sample))
            .expect("PAB matrix carries uppercase boolean controls");
        let old = PublicAccessBlockCodec
            .old_parse(&uppercase.bytes)
            .expect("old accepts uppercase boolean controls");
        let new = PublicAccessBlockCodec
            .new_parse(&uppercase.bytes)
            .expect("new accepts uppercase boolean controls");
        assert_eq!(old.structure.block_public_acls, Some(true));
        assert_eq!(old.structure.ignore_public_acls, Some(false));
        assert_eq!(new.block_public_acls, Some(true));
        assert_eq!(new.ignore_public_acls, Some(false));
        for (case, _) in public_access_block_rejected_samples()
            .into_iter()
            .filter(|(_, variants)| variants.contains(&CorpusVariant::UnknownScalar))
        {
            assert!(PublicAccessBlockCodec.old_parse(&case.bytes).is_err(), "old accepted {}", case.notes);
            assert!(PublicAccessBlockCodec.new_parse(&case.bytes).is_err(), "new accepted {}", case.notes);
        }
    }

    #[test]
    fn every_duplicate_pab_switch_is_rejected_by_both_parsers() {
        for (case, _) in public_access_block_rejected_samples()
            .into_iter()
            .filter(|(_, variants)| variants.contains(&CorpusVariant::DuplicateField))
        {
            assert!(PublicAccessBlockCodec.old_parse(&case.bytes).is_err(), "old accepted {}", case.notes);
            assert!(PublicAccessBlockCodec.new_parse(&case.bytes).is_err(), "new accepted {}", case.notes);
        }
    }

    #[test]
    fn full_pab_value_keeps_the_old_byte_order() {
        let value = configuration(Some(true), Some(true), Some(true), Some(true));
        let old = PublicAccessBlockCodec
            .old_serialize(&value)
            .expect("old serializer accepts full PAB value");
        let new = PublicAccessBlockCodec
            .new_serialize(&value)
            .expect("new serializer accepts full PAB value");
        assert_eq!(old, new);
        assert_eq!(old, ALL_TRUE);
    }

    #[test]
    fn wrong_pab_root_is_rejected_by_both_parsers() {
        for (case, _) in public_access_block_rejected_samples() {
            assert!(PublicAccessBlockCodec.old_parse(&case.bytes).is_err(), "old accepted {}", case.notes);
            assert!(PublicAccessBlockCodec.new_parse(&case.bytes).is_err(), "new accepted {}", case.notes);
        }
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
        const KIND: ConfigKind = ConfigKind::PublicAccessBlock;

        type Value = PersistedPublicAccessBlockConfiguration;
        type OldParsed = S3sPublicAccessBlockObservation;
        type NewParsed = PersistedPublicAccessBlockConfiguration;
        type Structure = PersistedPublicAccessBlockConfiguration;
        type Behavior = PublicAccessBlockBehaviorProjection;

        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_on_old_parse, "PAB codec observation must not run");
            let canonical = PublicAccessBlockCodec.new_serialize(&configuration(Some(true), None, None, None))?;
            if self.reject_new_output_in_old && bytes == canonical {
                return Err("mutation: rollback parser rejects new PAB output".to_owned());
            }
            PublicAccessBlockCodec.old_parse(bytes)
        }

        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.reject_historical_in_new && bytes == NAMESPACE {
                return Err("mutation: new PAB parser is stricter".to_owned());
            }
            let mut parsed = PublicAccessBlockCodec.new_parse(bytes)?;
            if self.new_structure_drift {
                parsed.block_public_acls = None;
            }
            Ok(parsed)
        }

        fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
            PublicAccessBlockCodec.old_structure(value)
        }

        fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
            PublicAccessBlockCodec.new_structure(value)
        }

        fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
            PublicAccessBlockCodec.expected_structure(value)
        }

        fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            let mut bytes = PublicAccessBlockCodec.old_serialize(value)?;
            if self.old_byte_drift {
                bytes.push(b' ');
            }
            Ok(bytes)
        }

        fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            PublicAccessBlockCodec.new_serialize(value)
        }

        fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
            PublicAccessBlockCodec.old_behavior(value)
        }

        fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
            let mut projection = PublicAccessBlockCodec.new_behavior(value);
            if self.new_behavior_drift {
                projection.switches.0 = !projection.switches.0;
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
    fn d1_detects_pab_structure_drift() {
        let mut codec = mutant();
        codec.new_structure_drift = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D1 must compare PAB structures");
        assert_eq!(failure.direction, Direction::D1CompatibleRead);
    }

    #[test]
    fn d2_detects_pab_byte_drift() {
        let mut codec = mutant();
        codec.old_byte_drift = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D2 must compare PAB bytes");
        assert_eq!(failure.direction, Direction::D2ByteWrite);
    }

    #[test]
    fn d3_detects_pab_rollback_refusal() {
        let mut codec = mutant();
        codec.reject_new_output_in_old = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D3 must prove PAB rollback reads");
        assert_eq!(failure.direction, Direction::D3RollbackRead);
    }

    #[test]
    fn d4_detects_a_stricter_pab_parser() {
        let mut codec = mutant();
        codec.reject_historical_in_new = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D4 must preserve old-readable PAB");
        assert_eq!(failure.direction, Direction::D4NotStricter);
    }

    #[test]
    fn d5_detects_pab_behavior_drift() {
        let mut codec = mutant();
        codec.new_behavior_drift = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D5 must compare PAB decisions");
        assert_eq!(failure.direction, Direction::D5Behavior);
    }

    #[test]
    fn wrong_family_label_fails_before_pab_codec_observation() {
        let mut invalid = base_sample();
        invalid.kind = ConfigKind::BucketEncryption;
        let mut codec = mutant();
        codec.panic_on_old_parse = true;
        let failure = assert_four_way(&codec, &invalid).expect_err("mislabeled PAB sample must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }
}
