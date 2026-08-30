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

//! Bucket Encryption persistence compatibility evidence.
//!
//! Responsible for: exercising independent old and new SSE persistence codecs through D1-D5.
//! NOT responsible for: validating HTTP policy or selecting encryption during object writes.
//! Upstream: pinned-s3s observations and gateway persistence codecs. Downstream: migration gates.

use rustfs_gateway_types::compat::{
    S3sBucketEncryptionObservation, parse_s3s_bucket_encryption, serialize_s3s_bucket_encryption,
};
use rustfs_gateway_types::persistence::{
    PersistedBucketEncryptionConfiguration, parse_bucket_encryption, serialize_bucket_encryption,
};

use crate::{ConfigKind, FourWayCodec, GoldenFailure, GoldenSample, assert_four_way};

#[derive(Clone, Debug, Eq, PartialEq)]
struct BucketEncryptionBehaviorProjection {
    rules: Vec<(Option<String>, Option<String>, Option<bool>)>,
}

/// Runs pinned-s3s versus gateway persistence Bucket Encryption evidence.
///
/// # Errors
///
/// Returns invalid-provenance or the first D1-D5 failure.
pub fn assert_bucket_encryption_four_way(
    sample: &GoldenSample<PersistedBucketEncryptionConfiguration>,
) -> Result<(), GoldenFailure> {
    assert_four_way(&BucketEncryptionCodec, sample)
}

#[derive(Clone, Copy, Debug)]
struct BucketEncryptionCodec;

impl FourWayCodec for BucketEncryptionCodec {
    const KIND: ConfigKind = ConfigKind::BucketEncryption;

    type Value = PersistedBucketEncryptionConfiguration;
    type OldParsed = S3sBucketEncryptionObservation;
    type NewParsed = PersistedBucketEncryptionConfiguration;
    type Structure = PersistedBucketEncryptionConfiguration;
    type Behavior = BucketEncryptionBehaviorProjection;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_bucket_encryption(bytes).map_err(|error| error.to_string())
    }

    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_bucket_encryption(bytes).map_err(|error| error.to_string())
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
        serialize_s3s_bucket_encryption(value).map_err(|error| error.to_string())
    }

    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_bucket_encryption(value))
    }

    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        BucketEncryptionBehaviorProjection {
            rules: value.behavior.clone(),
        }
    }

    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        BucketEncryptionBehaviorProjection {
            rules: value.encryption_behavior(),
        }
    }
}

#[cfg(test)]
mod tests {
    use rustfs_gateway_types::persistence::{PersistedBucketEncryptionRule, PersistedEncryptionByDefault};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{Direction, SampleOrigin};

    const EMPTY_RULE: &[u8] = b"<ServerSideEncryptionConfiguration><Rule></Rule></ServerSideEncryptionConfiguration>";
    const AES256: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
    const KMS_BUCKET_KEY: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><KMSMasterKeyID>kms-key</KMSMasterKeyID><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";
    const BUCKET_KEY_FALSE: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";
    const NAMESPACE: &[u8] = br#"<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule></Rule></ServerSideEncryptionConfiguration>"#;
    const UNKNOWN_TOP_LEVEL: &[u8] = b"<ServerSideEncryptionConfiguration><FutureTopLevel>future</FutureTopLevel><Rule></Rule></ServerSideEncryptionConfiguration>";
    const UNKNOWN_ATTRIBUTES: &[u8] = b"<ServerSideEncryptionConfiguration future=\"root\"><Rule future=\"rule\"><ApplyServerSideEncryptionByDefault future=\"default\"><SSEAlgorithm future=\"algorithm\">AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
    const ALTERNATE_ORDER: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><BucketKeyEnabled>true</BucketKeyEnabled><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>kms-key</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
    const MULTIPLE_RULES: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule><Rule><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";
    const UNKNOWN_ALGORITHM: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>future:sse</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";

    fn encryption_default(algorithm: &str, kms_key: Option<&str>) -> PersistedEncryptionByDefault {
        PersistedEncryptionByDefault {
            sse_algorithm: algorithm.to_owned(),
            kms_master_key_id: kms_key.map(str::to_owned),
        }
    }

    fn rule(default: Option<PersistedEncryptionByDefault>, bucket_key_enabled: Option<bool>) -> PersistedBucketEncryptionRule {
        PersistedBucketEncryptionRule {
            apply_server_side_encryption_by_default: default,
            bucket_key_enabled,
        }
    }

    fn configuration(rules: Vec<PersistedBucketEncryptionRule>) -> PersistedBucketEncryptionConfiguration {
        PersistedBucketEncryptionConfiguration { rules }
    }

    fn sample(
        bytes: &[u8],
        sha256: &str,
        value: PersistedBucketEncryptionConfiguration,
        notes: &str,
    ) -> GoldenSample<PersistedBucketEncryptionConfiguration> {
        assert_eq!(hex::encode(Sha256::digest(bytes)), sha256, "stale SSE sample digest");
        GoldenSample {
            kind: ConfigKind::BucketEncryption,
            bytes: bytes.to_vec(),
            value,
            origin: SampleOrigin {
                source: "P9 Bucket Encryption persistence matrix".to_owned(),
                producer: "pinned s3s XML behavior".to_owned(),
                version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
                sha256: sha256.to_owned(),
            },
            notes: notes.to_owned(),
        }
    }

    fn base_sample() -> GoldenSample<PersistedBucketEncryptionConfiguration> {
        sample(
            NAMESPACE,
            "8c92662634d2d1191664089ca7e152bfe975f2b70ed260a94136f7d3502de524",
            configuration(vec![rule(None, None)]),
            "old-readable namespace with an explicit empty rule",
        )
    }

    #[test]
    fn bucket_encryption_sample_matrix_passes_all_five_directions() {
        let aes = rule(Some(encryption_default("AES256", None)), None);
        let kms = rule(Some(encryption_default("aws:kms", Some("kms-key"))), Some(true));
        let cases = [
            sample(
                EMPTY_RULE,
                "38cc281d68379e358fbb4f9ebeca6a5513018a70b9b45149d2e4593048e10e3f",
                configuration(vec![rule(None, None)]),
                "explicit empty Rule is the minimum old-readable document",
            ),
            sample(
                AES256,
                "cb55d1d74144c5f9f50b3e22a249af0ddd47788c96474b0c341770f1e2d28419",
                configuration(vec![aes.clone()]),
                "AES256 default without KMS or bucket key",
            ),
            sample(
                KMS_BUCKET_KEY,
                "693378445b8e5745b67c4a7e027bf933f731f1a082fb0ae41b9aee5bd1b23dc2",
                configuration(vec![kms.clone()]),
                "KMS algorithm, key identifier, and enabled bucket key",
            ),
            sample(
                BUCKET_KEY_FALSE,
                "27af9808807e633bf5dab4c2666a5a3bd2324aa2097d8539d6c1bb01e028e099",
                configuration(vec![rule(None, Some(false))]),
                "explicit false bucket-key decision without a default algorithm",
            ),
            base_sample(),
            sample(
                UNKNOWN_TOP_LEVEL,
                "cec2f27f2e168d5649f1963146986062d968d03d1b46ed3baa94cfbcc28e8a57",
                configuration(vec![rule(None, None)]),
                "old-readable unknown root child before the required Rule",
            ),
            sample(
                UNKNOWN_ATTRIBUTES,
                "b701aa1267f0b80eb6705f4d1439e62e2c7d4f5045868ae0910d3fbd1c317daf",
                configuration(vec![aes.clone()]),
                "old-readable attributes at each structural level",
            ),
            sample(
                ALTERNATE_ORDER,
                "90ba60c24e212c6ed5a46a60ed0e2e75162c5c500707086cad6369f2f9bbd310",
                configuration(vec![kms]),
                "old-readable rule and nested fields in noncanonical order",
            ),
            sample(
                MULTIPLE_RULES,
                "283f72738e2bb4cd0bfe9dd84c288f7ea3c02001db43cfacc0db69284f8dbae7",
                configuration(vec![aes, rule(None, Some(true))]),
                "flattened Rule is an unbounded list rather than a duplicate field",
            ),
            sample(
                UNKNOWN_ALGORITHM,
                "3678a23ffb849464e60212c7362598d5b767d19a53d432261320475b3b9377ae",
                configuration(vec![rule(Some(encryption_default("future:sse", None)), None)]),
                "old string newtype preserves a future algorithm value",
            ),
        ];
        for case in cases {
            if let Err(error) = assert_bucket_encryption_four_way(&case) {
                panic!("Bucket Encryption sample failed ({}): {error}", case.notes);
            }
        }
    }

    #[test]
    fn required_sse_wrappers_match_the_pinned_old_refusals() {
        for (name, bytes) in [
            ("missing Rule", b"<ServerSideEncryptionConfiguration></ServerSideEncryptionConfiguration>".as_slice()),
            (
                "missing SSEAlgorithm",
                b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".as_slice(),
            ),
        ] {
            assert!(BucketEncryptionCodec.old_parse(bytes).is_err(), "old parser accepted {name}");
            assert!(BucketEncryptionCodec.new_parse(bytes).is_err(), "new parser accepted {name}");
        }
    }

    #[test]
    fn nested_unknown_sse_content_matches_the_old_refusal_boundary() {
        for (name, bytes) in [
            (
                "Rule child",
                b"<ServerSideEncryptionConfiguration><Rule><Future>v</Future></Rule></ServerSideEncryptionConfiguration>".as_slice(),
            ),
            (
                "default child",
                b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><Future>v</Future><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".as_slice(),
            ),
            (
                "newer blocked-encryption extension",
                b"<ServerSideEncryptionConfiguration><Rule><BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>".as_slice(),
            ),
        ] {
            assert!(BucketEncryptionCodec.old_parse(bytes).is_err(), "old parser accepted {name}");
            assert!(BucketEncryptionCodec.new_parse(bytes).is_err(), "new parser accepted {name}");
        }
    }

    #[test]
    fn every_duplicate_sse_scalar_or_wrapper_is_rejected_by_both_parsers() {
        let cases = [
            (
                "ApplyServerSideEncryptionByDefault",
                b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".as_slice(),
            ),
            (
                "BucketKeyEnabled",
                b"<ServerSideEncryptionConfiguration><Rule><BucketKeyEnabled>true</BucketKeyEnabled><BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>".as_slice(),
            ),
            (
                "SSEAlgorithm",
                b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".as_slice(),
            ),
            (
                "KMSMasterKeyID",
                b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><KMSMasterKeyID>a</KMSMasterKeyID><KMSMasterKeyID>b</KMSMasterKeyID><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".as_slice(),
            ),
        ];
        for (field, bytes) in cases {
            assert!(BucketEncryptionCodec.old_parse(bytes).is_err(), "old parser accepted duplicate {field}");
            assert!(BucketEncryptionCodec.new_parse(bytes).is_err(), "new parser accepted duplicate {field}");
        }
    }

    #[test]
    fn bucket_key_boolean_lexemes_match_the_old_oracle() {
        for (value, expected) in [("true", true), ("false", false), ("TRUE", true), ("FALSE", false)] {
            let bytes = format!(
                "<ServerSideEncryptionConfiguration><Rule><BucketKeyEnabled>{value}</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>"
            );
            let old = BucketEncryptionCodec
                .old_parse(bytes.as_bytes())
                .expect("old accepts lowercase bool");
            let new = BucketEncryptionCodec
                .new_parse(bytes.as_bytes())
                .expect("new accepts lowercase bool");
            assert_eq!(old.structure.rules[0].bucket_key_enabled, Some(expected));
            assert_eq!(new.rules[0].bucket_key_enabled, Some(expected));
        }
        for value in ["TrUe", "FaLsE", "1", " true ", ""] {
            let bytes = format!(
                "<ServerSideEncryptionConfiguration><Rule><BucketKeyEnabled>{value}</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>"
            );
            assert!(
                BucketEncryptionCodec.old_parse(bytes.as_bytes()).is_err(),
                "old accepted invalid bool {value:?}"
            );
            assert!(
                BucketEncryptionCodec.new_parse(bytes.as_bytes()).is_err(),
                "new accepted invalid bool {value:?}"
            );
        }
    }

    #[test]
    fn full_sse_value_keeps_the_old_byte_order() {
        let value = configuration(vec![rule(Some(encryption_default("aws:kms", Some("kms-key"))), Some(true))]);
        let old = BucketEncryptionCodec
            .old_serialize(&value)
            .expect("old serializer accepts full SSE value");
        let new = BucketEncryptionCodec
            .new_serialize(&value)
            .expect("new serializer accepts full SSE value");
        assert_eq!(old, new);
        assert_eq!(old, KMS_BUCKET_KEY);
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
        const KIND: ConfigKind = ConfigKind::BucketEncryption;

        type Value = PersistedBucketEncryptionConfiguration;
        type OldParsed = S3sBucketEncryptionObservation;
        type NewParsed = PersistedBucketEncryptionConfiguration;
        type Structure = PersistedBucketEncryptionConfiguration;
        type Behavior = BucketEncryptionBehaviorProjection;

        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_on_old_parse, "SSE codec observation must not run");
            let canonical = BucketEncryptionCodec.new_serialize(&configuration(vec![rule(None, None)]))?;
            if self.reject_new_output_in_old && bytes == canonical {
                return Err("mutation: rollback parser rejects new SSE output".to_owned());
            }
            BucketEncryptionCodec.old_parse(bytes)
        }

        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.reject_historical_in_new && bytes == NAMESPACE {
                return Err("mutation: new SSE parser is stricter".to_owned());
            }
            let mut parsed = BucketEncryptionCodec.new_parse(bytes)?;
            if self.new_structure_drift {
                parsed.rules.clear();
            }
            Ok(parsed)
        }

        fn old_structure(&self, value: &Self::OldParsed) -> Self::Structure {
            BucketEncryptionCodec.old_structure(value)
        }

        fn new_structure(&self, value: &Self::NewParsed) -> Self::Structure {
            BucketEncryptionCodec.new_structure(value)
        }

        fn expected_structure(&self, value: &Self::Value) -> Self::Structure {
            BucketEncryptionCodec.expected_structure(value)
        }

        fn old_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            let mut bytes = BucketEncryptionCodec.old_serialize(value)?;
            if self.old_byte_drift {
                bytes.push(b' ');
            }
            Ok(bytes)
        }

        fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
            BucketEncryptionCodec.new_serialize(value)
        }

        fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
            BucketEncryptionCodec.old_behavior(value)
        }

        fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
            let mut projection = BucketEncryptionCodec.new_behavior(value);
            if self.new_behavior_drift {
                projection.rules.push((Some("mutation".to_owned()), None, None));
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
    fn d1_detects_sse_structure_drift() {
        let mut codec = mutant();
        codec.new_structure_drift = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D1 must compare SSE structures");
        assert_eq!(failure.direction, Direction::D1CompatibleRead);
    }

    #[test]
    fn d2_detects_sse_byte_drift() {
        let mut codec = mutant();
        codec.old_byte_drift = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D2 must compare SSE bytes");
        assert_eq!(failure.direction, Direction::D2ByteWrite);
    }

    #[test]
    fn d3_detects_sse_rollback_refusal() {
        let mut codec = mutant();
        codec.reject_new_output_in_old = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D3 must prove SSE rollback reads");
        assert_eq!(failure.direction, Direction::D3RollbackRead);
    }

    #[test]
    fn d4_detects_a_stricter_sse_parser() {
        let mut codec = mutant();
        codec.reject_historical_in_new = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D4 must preserve old-readable SSE");
        assert_eq!(failure.direction, Direction::D4NotStricter);
    }

    #[test]
    fn d5_detects_sse_behavior_drift() {
        let mut codec = mutant();
        codec.new_behavior_drift = true;
        let failure = assert_four_way(&codec, &base_sample()).expect_err("D5 must compare SSE decisions");
        assert_eq!(failure.direction, Direction::D5Behavior);
    }

    #[test]
    fn wrong_family_label_fails_before_sse_codec_observation() {
        let mut invalid = base_sample();
        invalid.kind = ConfigKind::PublicAccessBlock;
        let mut codec = mutant();
        codec.panic_on_old_parse = true;
        let failure = assert_four_way(&codec, &invalid).expect_err("mislabeled SSE sample must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }
}
