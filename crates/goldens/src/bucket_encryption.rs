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
    OracleRevision, S3sBucketEncryptionObservation, parse_s3s_bucket_encryption, selected_oracle, serialize_s3s_bucket_encryption,
};
use rustfs_gateway_types::persistence::{
    EncryptionRuleBehavior, PersistedBlockedEncryptionTypes, PersistedBucketEncryptionConfiguration,
    PersistedBucketEncryptionRule, PersistedEncryptionByDefault, parse_bucket_encryption, serialize_bucket_encryption,
};

use crate::{
    ConfigKind, CorpusCaseEvidence, CorpusCoverageError, CorpusVariant, Direction, FamilyCorpusEvidence, FourWayCodec,
    GoldenFailure, GoldenSample, RejectedGoldenSample, SampleOrigin, assert_four_way, byte_failure, validate_sample,
    value_failure,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct BucketEncryptionBehaviorProjection {
    rules: Vec<EncryptionRuleBehavior>,
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

pub(crate) fn run_bucket_encryption_corpus_four_way() -> Result<usize, GoldenFailure> {
    let cases = bucket_encryption_accepted_samples();
    for (sample, _) in &cases {
        assert_bucket_encryption_four_way(sample)?;
    }
    Ok(cases.len())
}

/// Whether `selected` is `since` or a later pinned revision, in [`OracleRevision::ALL`] order.
fn reached(selected: OracleRevision, since: OracleRevision) -> bool {
    let position = |oracle| OracleRevision::ALL.iter().position(|candidate| *candidate == oracle);
    position(selected) >= position(since)
}

/// Accepted samples the given revision predates: each is measured under it as a widening rather
/// than through D1-D5.
pub(crate) fn widened_under(oracle: OracleRevision) -> usize {
    revision_scoped_accepted_samples()
        .iter()
        .filter(|(since, _, _)| !reached(oracle, *since))
        .count()
}

/// Runs the revision-scoped accepted samples under the selected revision, returning how many ran
/// through D1-D5 and how many were measured as widenings.
///
/// A sample first written by a later revision runs the full D1-D5 under that revision and every
/// later one. Under an earlier revision D1-D5 is impossible by construction — that revision's
/// codec has no member for the bytes — so it is measured for exactly what holds instead: the old
/// codec refuses the bytes and cannot write the value, and the production codec reads the value
/// and writes the exact bytes. Counting that as a D1-D5 pass would fake one.
///
/// # Errors
///
/// Returns the first D1-D5 or widening failure.
pub(crate) fn run_revision_scoped_four_way() -> Result<(usize, usize), GoldenFailure> {
    let selected = selected_oracle();
    let (mut executed, mut widened) = (0, 0);
    for (since, sample, _) in revision_scoped_accepted_samples() {
        if reached(selected, since) {
            assert_bucket_encryption_four_way(&sample)?;
            executed += 1;
        } else {
            assert_widening(&BucketEncryptionCodec, &sample)?;
            widened += 1;
        }
    }
    Ok((executed, widened))
}

/// The widening assertion for a revision that predates `sample`.
fn assert_widening<C>(codec: &C, sample: &GoldenSample<C::Value>) -> Result<(), GoldenFailure>
where
    C: FourWayCodec,
{
    validate_sample(C::KIND, sample)?;
    if let Ok(read) = codec.old_parse(&sample.bytes) {
        return Err(GoldenFailure {
            direction: Direction::D1CompatibleRead,
            offset: None,
            left: format!("the selected revision read the sample: {read:?}"),
            right: "a sample the selected revision reads must run D1-D5, not count as a widening".to_owned(),
        });
    }
    let new_parsed = codec.new_parse(&sample.bytes).map_err(|error| GoldenFailure {
        direction: Direction::D4NotStricter,
        offset: None,
        left: "the production decoder must read what a later pinned revision writes".to_owned(),
        right: error,
    })?;
    let expected = codec.expected_structure(&sample.value);
    let observed = codec.new_structure(&new_parsed);
    if observed != expected {
        return Err(value_failure(Direction::D1CompatibleRead, &expected, &observed));
    }
    let new_bytes = codec.new_serialize(&sample.value).map_err(|error| GoldenFailure {
        direction: Direction::D2ByteWrite,
        offset: None,
        left: "the production writer must reproduce the later revision's bytes".to_owned(),
        right: error,
    })?;
    if new_bytes != sample.bytes {
        return Err(byte_failure(Direction::D2ByteWrite, &sample.bytes, &new_bytes));
    }
    if let Ok(bytes) = codec.old_serialize(&sample.value) {
        return Err(GoldenFailure {
            direction: Direction::D2ByteWrite,
            offset: None,
            left: String::from_utf8_lossy(&bytes).into_owned(),
            right: "the selected revision wrote a value it has no member for, so it dropped one".to_owned(),
        });
    }
    Ok(())
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

const EMPTY_RULE: &[u8] = b"<ServerSideEncryptionConfiguration><Rule></Rule></ServerSideEncryptionConfiguration>";
const AES256: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
const KMS_BUCKET_KEY: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><KMSMasterKeyID>kms-key</KMSMasterKeyID><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";
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
        blocked_encryption_types: None,
    }
}

fn configuration(rules: Vec<PersistedBucketEncryptionRule>) -> PersistedBucketEncryptionConfiguration {
    PersistedBucketEncryptionConfiguration { rules }
}

fn origin(sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: "P9 Bucket Encryption persistence matrix".to_owned(),
        producer: "pinned s3s XML behavior".to_owned(),
        version: "s3s@9c4690d8e73fc8d184031a19b2c4539ebc77d180".to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn sample(
    bytes: &[u8],
    sha256: &str,
    value: PersistedBucketEncryptionConfiguration,
    notes: &str,
) -> GoldenSample<PersistedBucketEncryptionConfiguration> {
    GoldenSample {
        kind: ConfigKind::BucketEncryption,
        bytes: bytes.to_vec(),
        value,
        origin: origin(sha256),
        notes: notes.to_owned(),
    }
}

fn rejected(bytes: Vec<u8>, sha256: &str, notes: &str, variant: CorpusVariant) -> (RejectedGoldenSample, Vec<CorpusVariant>) {
    (
        RejectedGoldenSample {
            kind: ConfigKind::BucketEncryption,
            bytes,
            origin: origin(sha256),
            notes: notes.to_owned(),
        },
        vec![variant],
    )
}

fn bucket_key_accepted_samples() -> Vec<(GoldenSample<PersistedBucketEncryptionConfiguration>, Vec<CorpusVariant>)> {
    [
        ("true", true, "fcd1915005f4fcb91eb15bde6c306e93c60b4b37d007bdec17ff35924cb6efdd"),
        ("false", false, "27af9808807e633bf5dab4c2666a5a3bd2324aa2097d8539d6c1bb01e028e099"),
        ("TRUE", true, "f9ae6ea13e59e3e9e02c3be25022607a7f323296614dcfbebbb7c4a541807ca5"),
        ("FALSE", false, "92b3a4d6c2497dcfdce798a3eeb2ec48ae7fcb311532d6c2cbf64e7f2601400e"),
    ]
    .into_iter()
    .map(|(lexeme, value, sha256)| {
        let bytes = format!(
            "<ServerSideEncryptionConfiguration><Rule><BucketKeyEnabled>{lexeme}</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>"
        );
        (
            sample(
                bytes.as_bytes(),
                sha256,
                configuration(vec![rule(None, Some(value))]),
                "old-readable bucket-key boolean lexeme",
            ),
            vec![CorpusVariant::Canonical],
        )
    })
    .collect()
}

fn bucket_encryption_accepted_samples() -> Vec<(GoldenSample<PersistedBucketEncryptionConfiguration>, Vec<CorpusVariant>)> {
    let aes = rule(Some(encryption_default("AES256", None)), None);
    let kms = rule(Some(encryption_default("aws:kms", Some("kms-key"))), Some(true));
    let mut cases = vec![
        (
            sample(
                EMPTY_RULE,
                "38cc281d68379e358fbb4f9ebeca6a5513018a70b9b45149d2e4593048e10e3f",
                configuration(vec![rule(None, None)]),
                "explicit empty Rule is the minimum old-readable document",
            ),
            vec![CorpusVariant::EmptyElement],
        ),
        (
            sample(
                AES256,
                "cb55d1d74144c5f9f50b3e22a249af0ddd47788c96474b0c341770f1e2d28419",
                configuration(vec![aes.clone()]),
                "AES256 default without KMS or bucket key",
            ),
            vec![CorpusVariant::Canonical],
        ),
        (
            sample(
                KMS_BUCKET_KEY,
                "693378445b8e5745b67c4a7e027bf933f731f1a082fb0ae41b9aee5bd1b23dc2",
                configuration(vec![kms.clone()]),
                "KMS algorithm, key identifier, and enabled bucket key",
            ),
            vec![CorpusVariant::Canonical],
        ),
        (
            sample(
                NAMESPACE,
                "8c92662634d2d1191664089ca7e152bfe975f2b70ed260a94136f7d3502de524",
                configuration(vec![rule(None, None)]),
                "old-readable namespace with an explicit empty rule",
            ),
            vec![CorpusVariant::Namespace],
        ),
        (
            sample(
                UNKNOWN_TOP_LEVEL,
                "cec2f27f2e168d5649f1963146986062d968d03d1b46ed3baa94cfbcc28e8a57",
                configuration(vec![rule(None, None)]),
                "old-readable unknown root child before the required Rule",
            ),
            vec![CorpusVariant::UnknownTopLevel],
        ),
        (
            sample(
                UNKNOWN_ATTRIBUTES,
                "b701aa1267f0b80eb6705f4d1439e62e2c7d4f5045868ae0910d3fbd1c317daf",
                configuration(vec![aes.clone()]),
                "old-readable attributes at each structural level",
            ),
            vec![CorpusVariant::UnknownAttribute],
        ),
        (
            sample(
                ALTERNATE_ORDER,
                "90ba60c24e212c6ed5a46a60ed0e2e75162c5c500707086cad6369f2f9bbd310",
                configuration(vec![kms]),
                "old-readable rule and nested fields in noncanonical order",
            ),
            vec![CorpusVariant::AlternateOrder],
        ),
        (
            sample(
                MULTIPLE_RULES,
                "283f72738e2bb4cd0bfe9dd84c288f7ea3c02001db43cfacc0db69284f8dbae7",
                configuration(vec![aes, rule(None, Some(true))]),
                "flattened Rule is an unbounded list rather than a duplicate field",
            ),
            vec![CorpusVariant::Canonical],
        ),
        (
            sample(
                UNKNOWN_ALGORITHM,
                "3678a23ffb849464e60212c7362598d5b767d19a53d432261320475b3b9377ae",
                configuration(vec![rule(Some(encryption_default("future:sse", None)), None)]),
                "old string newtype preserves a future algorithm value",
            ),
            vec![CorpusVariant::UnknownScalar],
        ),
    ];
    cases.extend(bucket_key_accepted_samples());
    cases
}

/// The `BlockedEncryptionTypes` witness RustFS rc.6 and `main` persist verbatim from a client's
/// `PutBucketEncryption` (rustfs/gateway#740).
const BLOCKED_SSE_C: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>";
/// Every Rule member at once, in the order s3s `bdcb6259` writes them, so D2 pins the member order.
const BLOCKED_FULL_ORDER: &[u8] = b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BlockedEncryptionTypes><EncryptionType>NONE</EncryptionType><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";

fn blocked_rule(
    default: Option<PersistedEncryptionByDefault>,
    entries: &[&str],
    bucket_key_enabled: Option<bool>,
) -> PersistedBucketEncryptionRule {
    PersistedBucketEncryptionRule {
        blocked_encryption_types: Some(PersistedBlockedEncryptionTypes {
            encryption_types: entries.iter().map(|entry| (*entry).to_owned()).collect(),
        }),
        ..rule(default, bucket_key_enabled)
    }
}

/// Accepted samples first written by a later pinned revision than the baseline, with that
/// revision. Their producer is the revision that writes them, never the baseline, which refuses
/// them.
fn revision_scoped_accepted_samples()
-> Vec<(OracleRevision, GoldenSample<PersistedBucketEncryptionConfiguration>, Vec<CorpusVariant>)> {
    let since = OracleRevision::Rollback;
    let scoped = |bytes: &[u8], sha256: &str, value, notes: &str| {
        let mut sample = sample(bytes, sha256, value, notes);
        sample.origin.version = format!("s3s@{}", since.revision());
        sample
    };
    vec![
        (
            since,
            scoped(
                BLOCKED_SSE_C,
                "62ea2d1b74fd4d569e03ee5b6f5e7131e22d2e3d857707fbd89bd55f3683bf47",
                configuration(vec![blocked_rule(None, &["SSE-C"], None)]),
                "SSE-C blocked for new writes, as RustFS rc.6 and main persist it (rustfs/gateway#740)",
            ),
            vec![CorpusVariant::Canonical],
        ),
        (
            since,
            scoped(
                BLOCKED_FULL_ORDER,
                "5067c9c583024151846c619b64219a26f3764bfb631efc05c34666908a9b378b",
                configuration(vec![blocked_rule(
                    Some(encryption_default("AES256", None)),
                    &["NONE", "SSE-C"],
                    Some(true),
                )]),
                "every Rule member in the s3s member order with a repeated flattened EncryptionType",
            ),
            vec![CorpusVariant::Canonical],
        ),
    ]
}

fn bucket_encryption_rejected_samples() -> Vec<(RejectedGoldenSample, Vec<CorpusVariant>)> {
    let raw = [
        (b"<ServerSideEncryptionConfiguration></ServerSideEncryptionConfiguration>".to_vec(), "f569568f0add3b5707c9b51dfeb88b84adc8f06e90d235374b80d5075c0c699a", "missing Rule", CorpusVariant::MissingField),
        (b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".to_vec(), "9be376a461453226ac09b3bc7ef2945155701ca14d08443b09aa0a136ae852f0", "missing SSEAlgorithm", CorpusVariant::MissingField),
        (b"<ServerSideEncryptionConfiguration><Rule><Future>v</Future></Rule></ServerSideEncryptionConfiguration>".to_vec(), "742b9b08e46369ad19d5046e0ffa3eb5cd0986e003b1fdbccb2e455e78cce8cb", "unknown Rule child", CorpusVariant::UnknownNested),
        (b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><Future>v</Future><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".to_vec(), "ec967c0d49c6c11e097d36dc0850f66e6b529ef3f0433ca45f8c206467d6eac9", "unknown default child", CorpusVariant::UnknownNested),
        (b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".to_vec(), "ab9086097aec1f918804bb9ad609858a7809292bbc0556279d3b09894716012e", "duplicate ApplyServerSideEncryptionByDefault", CorpusVariant::DuplicateField),
        (b"<ServerSideEncryptionConfiguration><Rule><BucketKeyEnabled>true</BucketKeyEnabled><BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>".to_vec(), "f09965caedc03a774e49df45e33a0254bbbe3b1c1c66f17b8db2d9d43400c48d", "duplicate BucketKeyEnabled", CorpusVariant::DuplicateField),
        (b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".to_vec(), "951efa211513b57224418c667d84415a431f9a2e1cf6bf6e263ba3cc935a5327", "duplicate SSEAlgorithm", CorpusVariant::DuplicateField),
        (b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><KMSMasterKeyID>a</KMSMasterKeyID><KMSMasterKeyID>b</KMSMasterKeyID><SSEAlgorithm>aws:kms</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>".to_vec(), "3ae78a8a43208b208e951c7b9e6914ba6c0dafa80464994b4cc97fd6e0475699", "duplicate KMSMasterKeyID", CorpusVariant::DuplicateField),
        (b"<NotServerSideEncryptionConfiguration></NotServerSideEncryptionConfiguration>".to_vec(), "37712921e071a26674ec3f6eb99ade6eb886d6e26fb4a7c573cf0ac7d0575d12", "wrong root", CorpusVariant::MissingField),
    ];
    let mut cases = raw
        .into_iter()
        .map(|(bytes, sha256, notes, variant)| rejected(bytes, sha256, notes, variant))
        .collect::<Vec<_>>();
    for (lexeme, sha256) in [
        ("TrUe", "f61f080a0bbee0be9914eda37663bc176b457d3db6a9a789934d1cdd5b9b6798"),
        ("FaLsE", "fb46634772c6c86affcf23c7c870257a869729004125ca67471a7f0d3b41835a"),
        ("1", "14a941613cb25549322af992da579c52bf2f819038f541bc35ea06ebe1c9d97c"),
        (" true ", "8084d86b5e214cc60862f6bce74078e50c591770eea5d596d062417ea72c6a38"),
        ("", "51cd7ed43995d032000d2ece6900aaa7b601530b66e73434e8846802582b305f"),
    ] {
        cases.push(rejected(format!("<ServerSideEncryptionConfiguration><Rule><BucketKeyEnabled>{lexeme}</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>").into_bytes(), sha256, "invalid bucket-key boolean lexeme", CorpusVariant::UnknownScalar));
    }
    cases
}

pub(crate) fn bucket_encryption_corpus_evidence() -> Result<FamilyCorpusEvidence, CorpusCoverageError> {
    let mut cases = Vec::new();
    for (sample, variants) in bucket_encryption_accepted_samples() {
        cases.push(CorpusCaseEvidence::accepted(&sample, &variants)?);
    }
    for (_, sample, variants) in revision_scoped_accepted_samples() {
        cases.push(CorpusCaseEvidence::accepted(&sample, &variants)?);
    }
    for (sample, variants) in bucket_encryption_rejected_samples() {
        cases.push(CorpusCaseEvidence::rejected(&sample, &variants)?);
    }
    Ok(FamilyCorpusEvidence::new(
        ConfigKind::BucketEncryption,
        vec![
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
        ],
        cases,
    ))
}

#[cfg(test)]
mod tests;
