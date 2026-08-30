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

//! Bucket Logging persistence compatibility evidence.
//!
//! Responsible for: exercising independent old and new Logging persistence codecs through D1-D5.
//! NOT responsible for: log delivery or HTTP request validation. Upstream: pinned-s3s observations
//! and gateway persistence codecs. Downstream: migration gates.

use rustfs_gateway_types::compat::{S3sBucketLoggingObservation, parse_s3s_bucket_logging, serialize_s3s_bucket_logging};
use rustfs_gateway_types::persistence::{
    PersistedBucketLoggingStatus, PersistedLoggingEnabled, parse_bucket_logging, serialize_bucket_logging,
};

use crate::{ConfigKind, FourWayCodec, GoldenFailure, GoldenSample, assert_four_way};

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoggingBehaviorProjection(Option<PersistedLoggingEnabled>);

/// Runs pinned-s3s versus gateway Bucket Logging persistence evidence.
///
/// # Errors
///
/// Returns invalid-provenance or the first D1-D5 failure.
pub fn assert_bucket_logging_four_way(sample: &GoldenSample<PersistedBucketLoggingStatus>) -> Result<(), GoldenFailure> {
    assert_four_way(&LoggingCodec, sample)
}

#[derive(Clone, Copy, Debug)]
struct LoggingCodec;

impl FourWayCodec for LoggingCodec {
    const KIND: ConfigKind = ConfigKind::Logging;
    type Value = PersistedBucketLoggingStatus;
    type OldParsed = S3sBucketLoggingObservation;
    type NewParsed = PersistedBucketLoggingStatus;
    type Structure = PersistedBucketLoggingStatus;
    type Behavior = LoggingBehaviorProjection;

    fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
        parse_s3s_bucket_logging(bytes).map_err(|e| e.to_string())
    }
    fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
        parse_bucket_logging(bytes).map_err(|e| e.to_string())
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
        serialize_s3s_bucket_logging(value).map_err(|e| e.to_string())
    }
    fn new_serialize(&self, value: &Self::Value) -> Result<Vec<u8>, String> {
        Ok(serialize_bucket_logging(value))
    }
    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        LoggingBehaviorProjection(value.behavior.clone())
    }
    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        LoggingBehaviorProjection(value.delivery_behavior())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Direction, SampleOrigin};
    use rustfs_gateway_types::persistence::{PersistedGrantee, PersistedLoggingGrant, PersistedTargetObjectKeyFormat};
    use sha2::{Digest, Sha256};

    const EMPTY: &[u8] = b"<BucketLoggingStatus></BucketLoggingStatus>";
    const BASIC: &[u8] = b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
    const NAMESPACE: &[u8] = br#"<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>"#;
    const UNKNOWN_TOP: &[u8] = b"<BucketLoggingStatus><FutureTopLevel>future</FutureTopLevel><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
    const ALTERNATE_ORDER: &[u8] = b"<BucketLoggingStatus><LoggingEnabled><TargetPrefix>access/</TargetPrefix><TargetBucket>logs</TargetBucket></LoggingEnabled></BucketLoggingStatus>";
    const EMPTY_PREFIX: &[u8] = b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix></TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
    const EMPTY_GRANTS: &[u8] = b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetGrants></TargetGrants><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
    const EMPTY_KEY_FORMAT: &[u8] = b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetObjectKeyFormat></TargetObjectKeyFormat><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
    const SIMPLE_PREFIX: &[u8] = b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetObjectKeyFormat><SimplePrefix></SimplePrefix></TargetObjectKeyFormat><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
    const PARTITIONED_PREFIX: &[u8] = b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>EventTime</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
    const FULL_GRANT: &[u8] = b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetGrants><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><DisplayName>delivery</DisplayName><ID>canonical-id</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></TargetGrants><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";

    fn enabled() -> PersistedLoggingEnabled {
        PersistedLoggingEnabled {
            target_bucket: "logs".to_owned(),
            target_grants: None,
            target_object_key_format: None,
            target_prefix: "access/".to_owned(),
        }
    }

    fn status(logging_enabled: Option<PersistedLoggingEnabled>) -> PersistedBucketLoggingStatus {
        PersistedBucketLoggingStatus { logging_enabled }
    }

    fn sample(
        bytes: &[u8],
        sha256: &str,
        value: PersistedBucketLoggingStatus,
        notes: &str,
    ) -> GoldenSample<PersistedBucketLoggingStatus> {
        assert_eq!(hex::encode(Sha256::digest(bytes)), sha256, "stale Logging sample digest");
        GoldenSample {
            kind: ConfigKind::Logging,
            bytes: bytes.to_vec(),
            value,
            origin: SampleOrigin {
                source: "P9 Bucket Logging persistence matrix".to_owned(),
                producer: "pinned s3s XML behavior".to_owned(),
                version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
                sha256: sha256.to_owned(),
            },
            notes: notes.to_owned(),
        }
    }

    fn base_sample() -> GoldenSample<PersistedBucketLoggingStatus> {
        sample(
            NAMESPACE,
            "b64ef0e8d537c54bd1bd8d853b26a09ccf3b41a907325d7e1355c91efddca4ee",
            status(Some(enabled())),
            "old-readable default namespace",
        )
    }

    #[test]
    fn logging_sample_matrix_passes_all_five_directions() {
        let mut empty_prefix = enabled();
        empty_prefix.target_prefix.clear();
        let mut empty_grants = enabled();
        empty_grants.target_grants = Some(Vec::new());
        let mut empty_format = enabled();
        empty_format.target_object_key_format = Some(PersistedTargetObjectKeyFormat::default());
        let mut simple = enabled();
        simple.target_object_key_format = Some(PersistedTargetObjectKeyFormat {
            partition_date_source: None,
            simple_prefix: true,
        });
        let mut partitioned = enabled();
        partitioned.target_object_key_format = Some(PersistedTargetObjectKeyFormat {
            partition_date_source: Some(Some("EventTime".to_owned())),
            simple_prefix: false,
        });
        let mut grant = enabled();
        grant.target_grants = Some(vec![PersistedLoggingGrant {
            grantee: Some(PersistedGrantee {
                display_name: Some("delivery".to_owned()),
                email_address: None,
                id: Some("canonical-id".to_owned()),
                grantee_type: "CanonicalUser".to_owned(),
                uri: None,
            }),
            permission: Some("FULL_CONTROL".to_owned()),
        }]);
        let cases = [
            sample(
                EMPTY,
                "793250b29f13f41065355f5dbacde7476e500a047882380079067dcc543dfde7",
                status(None),
                "logging disabled",
            ),
            sample(
                BASIC,
                "a7a16f7a97a8fc2e694fbfae2ac08bfc908ebdab8be432b8cefbcd0256c1d300",
                status(Some(enabled())),
                "basic destination",
            ),
            base_sample(),
            sample(
                UNKNOWN_TOP,
                "2911ec9b187e2363c7fa3911eaa1058a5d3ff193b6844184dd5d15e39ba0bf50",
                status(Some(enabled())),
                "unknown root child",
            ),
            sample(
                ALTERNATE_ORDER,
                "f4bbd84a110fb62fa8ecd185b90cd3b4bee9e9704bbc5f8bb12db4f9aed5db99",
                status(Some(enabled())),
                "noncanonical field order",
            ),
            sample(
                EMPTY_PREFIX,
                "fb8ad343565a5ae5e71746ac207b72f81d9944c8da06b91ca24c25c1662ab698",
                status(Some(empty_prefix)),
                "explicit empty prefix",
            ),
            sample(
                EMPTY_GRANTS,
                "8e0f8fafa51072dd8ce1fb45653622d80d6b29357f4f8d90859afe84bfdcbbaa",
                status(Some(empty_grants)),
                "present empty grants list",
            ),
            sample(
                EMPTY_KEY_FORMAT,
                "3cf25b8c7187447aa85fb53cfc19158c96eec57952bd6c91a7d3a3357174893c",
                status(Some(empty_format)),
                "present empty key format",
            ),
            sample(
                SIMPLE_PREFIX,
                "2e11977b5f4c6674825ca33bd5e37b6e414e9a94ba3ff3b07fbb29dd20e24093",
                status(Some(simple)),
                "simple prefix marker",
            ),
            sample(
                PARTITIONED_PREFIX,
                "ed7d11ff939f85b18d0321150bf5cc14aedb564f624db8d92a1f31fb287687f7",
                status(Some(partitioned)),
                "event-time partition",
            ),
            sample(
                FULL_GRANT,
                "bb90a0544c15d5620fb4865df48014d47ee2fd4b5aef1709507225e73c37fd4e",
                status(Some(grant)),
                "canonical-user full-control grant",
            ),
        ];
        for case in cases {
            if let Err(error) = assert_bucket_logging_four_way(&case) {
                panic!("Logging sample failed ({}): {error}", case.notes);
            }
        }
    }

    #[test]
    fn n_required_logging_members_match_the_old_refusals() {
        for (name, bytes) in [
            ("TargetBucket", b"<BucketLoggingStatus><LoggingEnabled><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice()),
            ("TargetPrefix", b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket></LoggingEnabled></BucketLoggingStatus>".as_slice()),
            ("Grantee.type", b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetGrants><Grant><Grantee></Grantee></Grant></TargetGrants><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice()),
            ("Grantee xsi:type namespace", b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetGrants><Grant><Grantee type=\"CanonicalUser\"></Grantee></Grant></TargetGrants><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice()),
        ] {
            assert!(LoggingCodec.old_parse(bytes).is_err(), "old accepted missing {name}");
            assert!(LoggingCodec.new_parse(bytes).is_err(), "new accepted missing {name}");
        }
    }

    #[test]
    fn n_nested_unknown_logging_content_matches_the_old_boundary() {
        let cases = [
            ("enabled", b"<BucketLoggingStatus><LoggingEnabled><Future>x</Future><TargetBucket>b</TargetBucket><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice()),
            ("grant", b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetGrants><Grant><Future>x</Future></Grant></TargetGrants><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice()),
            ("grantee", b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetGrants><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><Future>x</Future></Grantee></Grant></TargetGrants><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice()),
            ("format", b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetObjectKeyFormat><Future>x</Future></TargetObjectKeyFormat><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice()),
            ("partition", b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetObjectKeyFormat><PartitionedPrefix><Future>x</Future></PartitionedPrefix></TargetObjectKeyFormat><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice()),
            ("simple prefix", b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetObjectKeyFormat><SimplePrefix><Future>x</Future></SimplePrefix></TargetObjectKeyFormat><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice()),
        ];
        for (name, bytes) in cases {
            assert!(LoggingCodec.old_parse(bytes).is_err(), "old accepted nested unknown in {name}");
            assert!(LoggingCodec.new_parse(bytes).is_err(), "new accepted nested unknown in {name}");
        }
    }

    #[test]
    fn unknown_content_in_the_grants_list_wrapper_stays_old_readable() {
        let bytes = b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetGrants><Future>x</Future></TargetGrants><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
        assert!(LoggingCodec.old_parse(bytes).is_ok());
        assert!(LoggingCodec.new_parse(bytes).is_ok());
    }

    #[test]
    fn optional_and_open_logging_members_match_the_old_decoder() {
        let cases = [
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetGrants><Grant></Grant></TargetGrants><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice(),
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetObjectKeyFormat><PartitionedPrefix></PartitionedPrefix></TargetObjectKeyFormat><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice(),
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>FutureTime</PartitionDateSource></PartitionedPrefix><SimplePrefix></SimplePrefix></TargetObjectKeyFormat><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice(),
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>b</TargetBucket><TargetGrants><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"FutureType\"></Grantee><Permission>FUTURE</Permission></Grant></TargetGrants><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice(),
        ];
        for bytes in cases {
            let old = LoggingCodec.old_parse(bytes).expect("old accepts open or optional members");
            let new = LoggingCodec.new_parse(bytes).expect("new accepts open or optional members");
            assert_eq!(old.structure, new);
        }
    }

    #[test]
    fn n_duplicate_logging_wrappers_and_scalars_are_rejected() {
        let cases = [
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>a</TargetBucket><TargetPrefix>p</TargetPrefix></LoggingEnabled><LoggingEnabled><TargetBucket>b</TargetBucket><TargetPrefix>q</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice(),
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>a</TargetBucket><TargetBucket>b</TargetBucket><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice(),
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>a</TargetBucket><TargetPrefix>p</TargetPrefix><TargetPrefix>q</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice(),
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>a</TargetBucket><TargetGrants></TargetGrants><TargetGrants></TargetGrants><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice(),
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>a</TargetBucket><TargetObjectKeyFormat></TargetObjectKeyFormat><TargetObjectKeyFormat></TargetObjectKeyFormat><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice(),
            b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>a</TargetBucket><TargetObjectKeyFormat><PartitionedPrefix></PartitionedPrefix><PartitionedPrefix></PartitionedPrefix></TargetObjectKeyFormat><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>".as_slice(),
        ];
        for bytes in cases {
            assert!(LoggingCodec.old_parse(bytes).is_err());
            assert!(LoggingCodec.new_parse(bytes).is_err());
        }
    }

    #[test]
    fn n_wrong_logging_root_is_rejected() {
        let bytes = b"<WebsiteConfiguration></WebsiteConfiguration>";
        assert!(LoggingCodec.old_parse(bytes).is_err());
        assert!(LoggingCodec.new_parse(bytes).is_err());
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
        const KIND: ConfigKind = ConfigKind::Logging;
        type Value = PersistedBucketLoggingStatus;
        type OldParsed = S3sBucketLoggingObservation;
        type NewParsed = PersistedBucketLoggingStatus;
        type Structure = PersistedBucketLoggingStatus;
        type Behavior = LoggingBehaviorProjection;
        fn old_parse(&self, bytes: &[u8]) -> Result<Self::OldParsed, String> {
            assert!(!self.panic_on_old_parse, "Logging observation must not run");
            if self.reject_new_output_in_old && bytes == BASIC {
                return Err("mutation: rollback refusal".to_owned());
            }
            LoggingCodec.old_parse(bytes)
        }
        fn new_parse(&self, bytes: &[u8]) -> Result<Self::NewParsed, String> {
            if self.reject_historical_in_new && bytes == NAMESPACE {
                return Err("mutation: stricter parser".to_owned());
            }
            let mut parsed = LoggingCodec.new_parse(bytes)?;
            if self.new_structure_drift {
                parsed.logging_enabled = None;
            }
            Ok(parsed)
        }
        fn old_structure(&self, v: &Self::OldParsed) -> Self::Structure {
            LoggingCodec.old_structure(v)
        }
        fn new_structure(&self, v: &Self::NewParsed) -> Self::Structure {
            LoggingCodec.new_structure(v)
        }
        fn expected_structure(&self, v: &Self::Value) -> Self::Structure {
            LoggingCodec.expected_structure(v)
        }
        fn old_serialize(&self, v: &Self::Value) -> Result<Vec<u8>, String> {
            let mut b = LoggingCodec.old_serialize(v)?;
            if self.old_byte_drift {
                b.push(b' ');
            }
            Ok(b)
        }
        fn new_serialize(&self, v: &Self::Value) -> Result<Vec<u8>, String> {
            LoggingCodec.new_serialize(v)
        }
        fn old_behavior(&self, v: &Self::OldParsed) -> Self::Behavior {
            LoggingCodec.old_behavior(v)
        }
        fn new_behavior(&self, v: &Self::NewParsed) -> Self::Behavior {
            let mut b = LoggingCodec.new_behavior(v);
            if self.new_behavior_drift {
                b.0 = None;
            }
            b
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
    fn n_each_d1_d5_logging_mutant_is_killed() {
        let mut cases = Vec::new();
        let mut d1 = mutant();
        d1.new_structure_drift = true;
        cases.push(("D1", d1, Direction::D1CompatibleRead));
        let mut d2 = mutant();
        d2.old_byte_drift = true;
        cases.push(("D2", d2, Direction::D2ByteWrite));
        let mut d3 = mutant();
        d3.reject_new_output_in_old = true;
        cases.push(("D3", d3, Direction::D3RollbackRead));
        let mut d4 = mutant();
        d4.reject_historical_in_new = true;
        cases.push(("D4", d4, Direction::D4NotStricter));
        let mut d5 = mutant();
        d5.new_behavior_drift = true;
        cases.push(("D5", d5, Direction::D5Behavior));
        for (name, codec, expected) in cases {
            let failure = match assert_four_way(&codec, &base_sample()) {
                Err(failure) => failure,
                Ok(()) => panic!("{name} Logging mutant must be killed"),
            };
            assert_eq!(failure.direction, expected);
        }
    }

    #[test]
    fn n_wrong_family_label_fails_before_logging_observation() {
        let mut invalid = base_sample();
        invalid.kind = ConfigKind::Website;
        let mut codec = mutant();
        codec.panic_on_old_parse = true;
        let failure = assert_four_way(&codec, &invalid).expect_err("mislabeled Logging sample must fail closed");
        assert_eq!(failure.direction, Direction::Input);
    }
}
