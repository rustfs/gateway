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

//! D1-D5, widening and mutation tests for the Bucket Encryption persistence evidence.
//!
//! Responsible for: proving every accepted and rejected Bucket Encryption sample against both
//! codecs, the per-revision rule for the `BlockedEncryptionTypes` samples (rustfs/gateway#740),
//! and that each direction goes red under a deliberately broken codec. NOT responsible for:
//! the samples themselves or the oracle admission verdict. Upstream: `super`. Downstream: none;
//! test-only.

use super::*;
use crate::{Direction, build_corpus_report};

use rustfs_gateway_types::compat::with_oracle;

fn scoped_samples() -> Vec<GoldenSample<PersistedBucketEncryptionConfiguration>> {
    revision_scoped_accepted_samples()
        .into_iter()
        .map(|(_, sample, _)| sample)
        .collect()
}

/// rustfs/gateway#740: every revision that writes `BlockedEncryptionTypes` passes all five
/// directions on it, including the byte order D2 pins.
#[test]
fn revision_scoped_samples_pass_d1_to_d5_under_every_revision_that_writes_them() {
    for oracle in [OracleRevision::Rollback, OracleRevision::Candidate] {
        for sample in scoped_samples() {
            with_oracle(oracle, || assert_bucket_encryption_four_way(&sample))
                .unwrap_or_else(|error| panic!("{oracle} {}: {error}", sample.notes));
        }
        assert_eq!(with_oracle(oracle, run_revision_scoped_four_way), Ok((2, 0)), "{oracle}");
        assert_eq!(widened_under(oracle), 0, "{oracle}");
    }
}

/// The baseline predates the member: it refuses the bytes, so D1-D5 genuinely fails under it,
/// and the samples are measured as widenings instead of being counted as passes.
#[test]
fn n_the_baseline_cannot_pass_d1_to_d5_on_a_revision_scoped_sample_and_widens_it() {
    for sample in scoped_samples() {
        let failure = assert_bucket_encryption_four_way(&sample).expect_err("s3s 9c4690d8 refuses the member");
        assert_eq!(failure.direction, Direction::D1CompatibleRead, "{}", sample.notes);
        assert_widening(&BucketEncryptionCodec, &sample).expect("production reads and writes it exactly");
    }
    assert_eq!(run_revision_scoped_four_way(), Ok((0, 2)));
    assert_eq!(widened_under(OracleRevision::Baseline), 2);
}

#[test]
fn n_a_revision_that_reads_a_scoped_sample_cannot_count_it_as_a_widening() {
    for sample in scoped_samples() {
        let failure = with_oracle(OracleRevision::Rollback, || assert_widening(&BucketEncryptionCodec, &sample))
            .expect_err("a revision that reads the bytes owes D1-D5");
        assert_eq!(failure.direction, Direction::D1CompatibleRead);
    }
}

/// The bite of the fix: a production codec that skipped the wrapper as unknown would silently
/// unblock SSE-C. D1 catches it under the revisions that write it, and the widening catches it
/// under the baseline.
#[test]
fn n_a_production_decoder_that_drops_the_block_fails_under_every_revision() {
    let mut codec = mutant();
    codec.new_drops_block = true;
    for sample in scoped_samples() {
        for oracle in [OracleRevision::Rollback, OracleRevision::Candidate] {
            let failure = with_oracle(oracle, || assert_four_way(&codec, &sample)).expect_err("D1 compares the block");
            assert_eq!(failure.direction, Direction::D1CompatibleRead, "{oracle}");
        }
        let failure = assert_widening(&codec, &sample).expect_err("the widening compares the block");
        assert_eq!(failure.direction, Direction::D1CompatibleRead);
    }
}

#[test]
fn n_a_production_writer_that_drops_the_block_fails_d2() {
    let mut codec = mutant();
    codec.new_writes_without_block = true;
    for sample in scoped_samples() {
        let failure =
            with_oracle(OracleRevision::Candidate, || assert_four_way(&codec, &sample)).expect_err("D2 compares the bytes");
        assert_eq!(failure.direction, Direction::D2ByteWrite);
        let failure = assert_widening(&codec, &sample).expect_err("the widening compares the bytes");
        assert_eq!(failure.direction, Direction::D2ByteWrite);
    }
}

#[test]
fn family_owned_corpus_evidence_is_built_from_the_shared_case_objects() {
    let evidence = bucket_encryption_corpus_evidence().expect("SSE corpus evidence is traceable");
    build_corpus_report(&[ConfigKind::BucketEncryption], &[evidence])
        .expect("SSE corpus coverage is derived from the shared cases");
}

fn base_sample() -> GoldenSample<PersistedBucketEncryptionConfiguration> {
    bucket_encryption_accepted_samples()
        .into_iter()
        .find_map(|(sample, variants)| variants.contains(&CorpusVariant::Namespace).then_some(sample))
        .expect("SSE matrix carries its namespace control")
}

#[test]
fn bucket_encryption_sample_matrix_passes_all_five_directions() {
    for (case, _) in bucket_encryption_accepted_samples() {
        if let Err(error) = assert_bucket_encryption_four_way(&case) {
            panic!("Bucket Encryption sample failed ({}): {error}", case.notes);
        }
    }
}

#[test]
fn required_sse_wrappers_match_the_pinned_old_refusals() {
    for (case, _) in bucket_encryption_rejected_samples()
        .into_iter()
        .filter(|(_, variants)| variants.contains(&CorpusVariant::MissingField))
    {
        assert!(
            BucketEncryptionCodec.old_parse(&case.bytes).is_err(),
            "old parser accepted {}",
            case.notes
        );
        assert!(
            BucketEncryptionCodec.new_parse(&case.bytes).is_err(),
            "new parser accepted {}",
            case.notes
        );
    }
}

#[test]
fn nested_unknown_sse_content_matches_the_old_refusal_boundary() {
    for (case, _) in bucket_encryption_rejected_samples()
        .into_iter()
        .filter(|(_, variants)| variants.contains(&CorpusVariant::UnknownNested))
    {
        assert!(
            BucketEncryptionCodec.old_parse(&case.bytes).is_err(),
            "old parser accepted {}",
            case.notes
        );
        assert!(
            BucketEncryptionCodec.new_parse(&case.bytes).is_err(),
            "new parser accepted {}",
            case.notes
        );
    }
}

#[test]
fn every_duplicate_sse_scalar_or_wrapper_is_rejected_by_both_parsers() {
    for (case, _) in bucket_encryption_rejected_samples()
        .into_iter()
        .filter(|(_, variants)| variants.contains(&CorpusVariant::DuplicateField))
    {
        assert!(
            BucketEncryptionCodec.old_parse(&case.bytes).is_err(),
            "old parser accepted {}",
            case.notes
        );
        assert!(
            BucketEncryptionCodec.new_parse(&case.bytes).is_err(),
            "new parser accepted {}",
            case.notes
        );
    }
}

#[test]
fn bucket_key_boolean_lexemes_match_the_old_oracle() {
    for (case, _) in bucket_key_accepted_samples() {
        let expected = case.value.rules[0].bucket_key_enabled;
        let old = BucketEncryptionCodec
            .old_parse(&case.bytes)
            .expect("old accepts observed boolean lexeme");
        let new = BucketEncryptionCodec
            .new_parse(&case.bytes)
            .expect("new accepts observed boolean lexeme");
        assert_eq!(old.structure.rules[0].bucket_key_enabled, expected);
        assert_eq!(new.rules[0].bucket_key_enabled, expected);
    }
    for (case, _) in bucket_encryption_rejected_samples()
        .into_iter()
        .filter(|(_, variants)| variants.contains(&CorpusVariant::UnknownScalar))
    {
        assert!(BucketEncryptionCodec.old_parse(&case.bytes).is_err(), "old accepted {}", case.notes);
        assert!(BucketEncryptionCodec.new_parse(&case.bytes).is_err(), "new accepted {}", case.notes);
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
    /// The #740 regression: the production decoder skips `BlockedEncryptionTypes`.
    new_drops_block: bool,
    /// The same regression on the write side.
    new_writes_without_block: bool,
}

fn without_block(value: &PersistedBucketEncryptionConfiguration) -> PersistedBucketEncryptionConfiguration {
    let mut value = value.clone();
    for rule in &mut value.rules {
        rule.blocked_encryption_types = None;
    }
    value
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
        if self.new_drops_block {
            parsed = without_block(&parsed);
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
        if self.new_writes_without_block {
            return BucketEncryptionCodec.new_serialize(&without_block(value));
        }
        BucketEncryptionCodec.new_serialize(value)
    }

    fn old_behavior(&self, value: &Self::OldParsed) -> Self::Behavior {
        BucketEncryptionCodec.old_behavior(value)
    }

    fn new_behavior(&self, value: &Self::NewParsed) -> Self::Behavior {
        let mut projection = BucketEncryptionCodec.new_behavior(value);
        if self.new_behavior_drift {
            projection.rules.push((Some("mutation".to_owned()), None, None, None));
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
        new_drops_block: false,
        new_writes_without_block: false,
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

#[test]
fn n_a_d5_diagnostic_names_key_id_presence_and_length_never_the_key_id() {
    const OLD_KEY: &str = "old-kms-key-must-never-be-logged";
    const NEW_KEY: &str = "arn:aws:kms:us-east-1:111122223333:key/new-must-never-be-logged";
    let projection = |key: &str| BucketEncryptionBehaviorProjection {
        rules: vec![(Some("aws:kms".to_owned()), Some(key.to_owned()), Some(true), None)],
    };
    let failure = value_failure(Direction::D5Behavior, &projection(OLD_KEY), &projection(NEW_KEY));
    for side in [&failure.left, &failure.right] {
        assert!(!side.contains("must-never-be-logged"), "a KMS key id reached a D5 diagnostic: {side}");
        assert!(side.contains("aws:kms"), "the algorithm is still visible: {side}");
    }
    assert!(
        failure.left.contains(&format!("Some(<redacted {} bytes>)", OLD_KEY.len())),
        "{}",
        failure.left
    );
    assert!(
        failure.right.contains(&format!("Some(<redacted {} bytes>)", NEW_KEY.len())),
        "{}",
        failure.right
    );
}
