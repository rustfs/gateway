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

//! The redacting `Debug` of the hand-written persisted types that hold a KMS key identifier.
//!
//! Responsible for: `PersistedEncryptionByDefault`, `PersistedEncryptionConfiguration` and
//! `S3sBucketEncryptionObservation` never printing a stored key id, directly or nested, in either
//! `{:?}` or `{:#?}`, while still printing presence, length and every non-secret member.
//! NOT responsible for: the generated dto's redaction, which `dto_tests` covers.
//! Upstream: `crate::persistence` and `crate::compat`. Downstream: the migration goldens, which
//! format these values with `{:?}` in their D1-D5 diagnostics.

#[cfg(any(feature = "compat-s3s", feature = "compat-s3s-f3e17541"))]
use crate::compat::S3sBucketEncryptionObservation;
use crate::persistence::{
    PersistedBucketEncryptionConfiguration, PersistedBucketEncryptionRule, PersistedEncryptionByDefault,
    PersistedEncryptionConfiguration, PersistedReplicationConfiguration, parse_bucket_encryption, parse_replication,
};

/// Spelled so that no other part of any rendering can contain it by accident.
const KEY_ID: &str = "arn:aws:kms:us-east-1:111122223333:key/SECRET";
const REPLICA_KEY_ID: &str = "replica-kms-key-must-never-be-logged";

fn both_renderings(value: &impl core::fmt::Debug) -> [String; 2] {
    [format!("{value:?}"), format!("{value:#?}")]
}

fn kms_default(key_id: Option<&str>) -> PersistedEncryptionByDefault {
    PersistedEncryptionByDefault {
        sse_algorithm: "aws:kms".to_owned(),
        kms_master_key_id: key_id.map(str::to_owned),
    }
}

#[test]
fn c_persist_n001_the_bucket_kms_key_id_never_appears_in_debug() {
    for rendered in both_renderings(&kms_default(Some(KEY_ID))) {
        assert!(!rendered.contains(KEY_ID), "a bucket KMS key id reached Debug: {rendered}");
        assert!(!rendered.contains("SECRET"), "part of a bucket KMS key id reached Debug: {rendered}");
    }
}

#[test]
fn c_persist_n002_a_present_key_id_renders_its_presence_and_length() {
    let rendered = format!("{:?}", kms_default(Some(KEY_ID)));
    assert_eq!(
        rendered,
        format!(
            "PersistedEncryptionByDefault {{ sse_algorithm: \"aws:kms\", kms_master_key_id: Some(<redacted {} bytes>) }}",
            KEY_ID.len()
        )
    );
}

#[test]
fn c_persist_n003_an_absent_key_id_renders_as_absent_not_as_a_placeholder() {
    let rendered = format!("{:?}", kms_default(None));
    assert!(rendered.contains("kms_master_key_id: None"), "{rendered}");
    assert!(!rendered.contains("redacted"), "an absent key id must not look present: {rendered}");
}

#[test]
fn c_persist_n004_two_key_ids_of_different_length_stay_distinguishable() {
    // A D1/D3 diagnostic prints both sides; "the lengths differ" must still be readable there.
    let short = format!("{:?}", kms_default(Some("k")));
    let long = format!("{:?}", kms_default(Some(KEY_ID)));
    assert_ne!(short, long);
    assert!(short.contains("Some(<redacted 1 bytes>)"), "{short}");
}

#[test]
fn c_persist_n005_a_parsed_configuration_never_prints_its_nested_key_id() {
    let bytes = format!(
        "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>{KEY_ID}</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>"
    );
    let parsed = parse_bucket_encryption(bytes.as_bytes()).expect("a stored KMS rule is readable");
    for rendered in both_renderings(&parsed) {
        assert!(!rendered.contains(KEY_ID), "a nested bucket KMS key id reached Debug: {rendered}");
        assert!(rendered.contains("aws:kms"), "the algorithm is still visible: {rendered}");
    }
    let rendered = format!("{parsed:?}");
    assert!(rendered.contains("bucket_key_enabled: Some(true)"), "{rendered}");
}

#[test]
fn c_persist_n006_the_replica_kms_key_id_never_appears_in_debug() {
    let direct = PersistedEncryptionConfiguration {
        replica_kms_key_id: Some(REPLICA_KEY_ID.to_owned()),
    };
    for rendered in both_renderings(&direct) {
        assert!(!rendered.contains(REPLICA_KEY_ID), "a replica KMS key id reached Debug: {rendered}");
    }
    assert_eq!(
        format!("{direct:?}"),
        format!(
            "PersistedEncryptionConfiguration {{ replica_kms_key_id: Some(<redacted {} bytes>) }}",
            REPLICA_KEY_ID.len()
        )
    );
    assert_eq!(
        format!("{:?}", PersistedEncryptionConfiguration::default()),
        "PersistedEncryptionConfiguration { replica_kms_key_id: None }"
    );

    let bytes = format!(
        "<ReplicationConfiguration><Role>arn:aws:iam::123456789012:role/replication</Role><Rule><Destination><Bucket>arn:aws:s3:::backup</Bucket><EncryptionConfiguration><ReplicaKmsKeyID>{REPLICA_KEY_ID}</ReplicaKmsKeyID></EncryptionConfiguration></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>"
    );
    let parsed: PersistedReplicationConfiguration =
        parse_replication(bytes.as_bytes()).expect("a stored replica KMS rule is readable");
    for rendered in both_renderings(&parsed) {
        assert!(
            !rendered.contains(REPLICA_KEY_ID),
            "a nested replica KMS key id reached Debug: {rendered}"
        );
        assert!(rendered.contains("arn:aws:s3:::backup"), "the destination is still visible: {rendered}");
    }
}

/// `q-repl-0010` names the destination account id beside the replica KMS key id: a configuration
/// secret the stored document echoes on the read and nothing else prints. The migration goldens
/// format parsed replication documents with `{:?}` in their D1-D5 diagnostics, so a derived `Debug`
/// on the destination would put every stored account id into a failing golden's report.
#[test]
fn c_persist_n008_the_replication_destination_account_never_appears_in_debug() {
    const ACCOUNT: &str = "731073107310";
    let bytes = format!(
        "<ReplicationConfiguration><Role>arn:aws:iam::123456789012:role/replication</Role><Rule><Destination><Account>{ACCOUNT}</Account><Bucket>arn:aws:s3:::backup</Bucket><StorageClass>STANDARD_IA</StorageClass></Destination><Status>Enabled</Status></Rule></ReplicationConfiguration>"
    );
    let parsed: PersistedReplicationConfiguration =
        parse_replication(bytes.as_bytes()).expect("a stored destination account is readable");
    for rendered in both_renderings(&parsed) {
        assert!(!rendered.contains(ACCOUNT), "a destination account id reached Debug: {rendered}");
        assert!(rendered.contains("arn:aws:s3:::backup"), "the destination is still visible: {rendered}");
        assert!(rendered.contains("STANDARD_IA"), "a non-secret sibling is still visible: {rendered}");
    }
    assert!(
        format!("{parsed:?}").contains(&format!("account: Some(<redacted {} bytes>)", ACCOUNT.len())),
        "presence and length stay readable: {parsed:?}"
    );

    let absent = format!("{:?}", crate::persistence::PersistedReplicationDestination::default());
    assert!(absent.contains("account: None"), "an absent account must not look present: {absent}");
}

#[test]
#[cfg(any(feature = "compat-s3s", feature = "compat-s3s-f3e17541"))]
fn c_persist_n007_the_old_codec_observation_redacts_its_behavior_tuple_too() {
    let structure = PersistedBucketEncryptionConfiguration {
        rules: vec![PersistedBucketEncryptionRule {
            apply_server_side_encryption_by_default: Some(kms_default(Some(KEY_ID))),
            bucket_key_enabled: Some(true),
            blocked_encryption_types: None,
        }],
    };
    let observation = S3sBucketEncryptionObservation {
        behavior: structure.encryption_behavior(),
        structure,
    };
    for rendered in both_renderings(&observation) {
        assert!(!rendered.contains(KEY_ID), "an observed KMS key id reached Debug: {rendered}");
    }
    let rendered = format!("{observation:?}");
    assert!(
        rendered.contains(&format!(
            "behavior: [(Some(\"aws:kms\"), Some(<redacted {} bytes>), Some(true), None)]",
            KEY_ID.len()
        )),
        "every other decision renders as the tuple's own Debug: {rendered}"
    );
}
