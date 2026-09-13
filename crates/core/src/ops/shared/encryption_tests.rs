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

//! Unit tests for the bucket-encryption semantic rules and the blocked-encryption-type run-time rule.
//!
//! Responsible for: the `encryption` module's document rules and `refuse_blocked_encryption_type`,
//! including the fixtures that build a framework SSE proof from a real `http::Request`.
//! NOT responsible for: codec or wire behavior, which the conformance encryption family covers.
//! Upstream: `encryption`. Downstream: none.

use super::*;
use rustfs_gateway_types::dto::{ServerSideEncryptionByDefault, ServerSideEncryptionRule, SseAlgorithm};

fn rule(algorithm: SseAlgorithm, key_id: Option<&str>) -> ServerSideEncryptionRule {
    ServerSideEncryptionRule {
        apply_server_side_encryption_by_default: Some(ServerSideEncryptionByDefault {
            sse_algorithm: algorithm,
            kms_master_key_id: key_id.map(str::to_owned),
        }),
        ..ServerSideEncryptionRule::default()
    }
}

fn config(rules: Vec<ServerSideEncryptionRule>) -> ServerSideEncryptionConfiguration {
    ServerSideEncryptionConfiguration { rules }
}

/// A plausible key ARN for the negative cases; asserted absent from every reason.
const KEY_ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

// ── positive ─────────────────────────────────────────────────────────────────────────────

#[test]
fn each_documented_algorithm_is_accepted_without_a_key_id() {
    for algorithm in [
        SseAlgorithm::AES256,
        SseAlgorithm::AWS_FSX,
        SseAlgorithm::AWS_KMS,
        SseAlgorithm::AWS_KMS_DSSE,
    ] {
        assert_eq!(validate_encryption(&config(vec![rule(algorithm.clone(), None)])), Ok(()), "{algorithm:?}");
    }
}

#[test]
fn a_key_id_beside_each_kms_algorithm_is_accepted() {
    for algorithm in [SseAlgorithm::AWS_KMS, SseAlgorithm::AWS_KMS_DSSE] {
        assert_eq!(
            validate_encryption(&config(vec![rule(algorithm.clone(), Some(KEY_ARN))])),
            Ok(()),
            "{algorithm:?}"
        );
    }
}

#[test]
fn a_rule_with_no_default_action_passes_because_the_model_makes_it_optional() {
    // `BucketKeyEnabled` or `BlockedEncryptionTypes` alone is a legal rule in the pinned
    // model; refusing it here would be stricter than the schema the document was written to.
    let entry = ServerSideEncryptionRule {
        bucket_key_enabled: Some(true),
        ..ServerSideEncryptionRule::default()
    };
    assert_eq!(validate_encryption(&config(vec![entry])), Ok(()));
}

#[test]
fn a_multi_rule_document_passes_on_purpose() {
    // `q-enc-0008`: nothing published bounds the rule list, and which rule an object write
    // applies is the encryption path's question, not the codec's.
    let document = config(vec![rule(SseAlgorithm::AES256, None), rule(SseAlgorithm::AWS_KMS, Some(KEY_ARN))]);
    assert_eq!(validate_encryption(&document), Ok(()));
}

// ── negative ─────────────────────────────────────────────────────────────────────────────

#[test]
fn n_an_out_of_set_algorithm_is_refused_as_malformed_xml() {
    for spelling in ["AES512", "aes256", "", "aws:kms:"] {
        let document = config(vec![rule(SseAlgorithm::custom(spelling.to_owned()), None)]);
        assert_eq!(
            validate_encryption(&document),
            Err(EncryptionRejection::AlgorithmUnknown),
            "spelling = {spelling:?}"
        );
    }
    assert_eq!(EncryptionRejection::AlgorithmUnknown.code(), ErrorCode::MALFORMED_XML);
}

#[test]
fn n_a_key_id_beside_aes256_is_refused_as_invalid_argument() {
    let document = config(vec![rule(SseAlgorithm::AES256, Some(KEY_ARN))]);
    assert_eq!(validate_encryption(&document), Err(EncryptionRejection::KmsKeyWithoutKmsAlgorithm));
    assert_eq!(EncryptionRejection::KmsKeyWithoutKmsAlgorithm.code(), ErrorCode::INVALID_ARGUMENT);
}

#[test]
fn n_a_key_id_beside_aws_fsx_is_refused_the_same_way() {
    // The boundary member: in the documented set, but not one of the two KMS spellings the
    // key id is allowed beside.
    let document = config(vec![rule(SseAlgorithm::AWS_FSX, Some(KEY_ARN))]);
    assert_eq!(validate_encryption(&document), Err(EncryptionRejection::KmsKeyWithoutKmsAlgorithm));
}

#[test]
fn n_an_unknown_algorithm_wins_over_its_own_key_id_conflict() {
    // Both checks broken in one action: the algorithm check runs first, so the refusal is
    // deterministic and never depends on the key id at all.
    let document = config(vec![rule(SseAlgorithm::custom("AES512"), Some(KEY_ARN))]);
    assert_eq!(validate_encryption(&document), Err(EncryptionRejection::AlgorithmUnknown));
}

#[test]
fn n_the_first_broken_rule_decides_the_refusal() {
    let document = config(vec![
        rule(SseAlgorithm::AES256, Some(KEY_ARN)),
        rule(SseAlgorithm::custom("AES512"), None),
    ]);
    assert_eq!(validate_encryption(&document), Err(EncryptionRejection::KmsKeyWithoutKmsAlgorithm));
}

#[test]
fn n_no_reason_carries_the_key_id_or_any_request_bytes() {
    // `q-enc-0009`: the constant reasons must hold even for the rejection the key id caused.
    for rejection in [
        EncryptionRejection::AlgorithmUnknown,
        EncryptionRejection::KmsKeyWithoutKmsAlgorithm,
    ] {
        assert!(!rejection.reason().contains(KEY_ARN));
        assert!(!rejection.reason().contains("arn:"));
    }
    let document = config(vec![rule(SseAlgorithm::AES256, Some(KEY_ARN))]);
    let rejection = validate_encryption(&document).expect_err("a KMS key beside AES256 is refused");
    assert!(!rejection.reason().contains(KEY_ARN));
    assert!(!rejection.reason().contains("1234abcd"));
}

#[test]
fn n_the_status_side_of_each_code_is_the_one_aws_answers() {
    // The family's whole error surface, pinned to the statuses AWS answers.
    assert_eq!(
        ErrorCode::SERVER_SIDE_ENCRYPTION_CONFIGURATION_NOT_FOUND
            .default_status()
            .as_u16(),
        404
    );
    assert_eq!(ErrorCode::MALFORMED_XML.default_status().as_u16(), 400);
    assert_eq!(ErrorCode::INVALID_ARGUMENT.default_status().as_u16(), 400);
}

// ── the blocked-encryption-type run-time rule (rustfs/gateway#740) ─────────────────────────

use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto::BlockedEncryptionTypes;

use crate::TargetKind;
use crate::codec::MetaView;
use crate::sse::{SseConfig, TransportSecurity, enforce};

/// The framework's proof for a request over TLS, with or without the customer-key trio.
fn proof(customer_key: bool) -> SseEnforced {
    let mut builder = http::Request::builder()
        .method("PUT")
        .uri("http://host.invalid/bucket/object")
        .header("host", "host.invalid");
    if customer_key {
        builder = builder
            .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
            .header(
                "x-amz-server-side-encryption-customer-key",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            )
            .header("x-amz-server-side-encryption-customer-key-md5", "tP/LI3N87DFaSk0aoqYgzg==");
    }
    let request = builder.body(()).expect("a well-formed fixture request");
    let accepted = WireRequest::accept(request, &Limits::default()).expect("an acceptable fixture request");
    let view = MetaView::of(&accepted, TargetKind::Object).expect("the path names an object");
    let Ok(proof) = enforce(&view, TransportSecurity::Encrypted, &SseConfig::strict()) else {
        panic!("a well-formed trio over TLS passes the gate");
    };
    assert_eq!(proof.customer_key_fingerprint().is_some(), customer_key);
    proof
}

fn blocking(entries: &[EncryptionType]) -> ServerSideEncryptionConfiguration {
    config(vec![ServerSideEncryptionRule {
        blocked_encryption_types: Some(BlockedEncryptionTypes {
            encryption_type: entries.to_vec(),
        }),
        ..ServerSideEncryptionRule::default()
    }])
}

#[test]
fn a_write_without_a_customer_key_is_never_refused_by_a_block() {
    let blocked = blocking(&[EncryptionType::SSE_C]);
    assert_eq!(refuse_blocked_encryption_type(Some(&blocked), &proof(false)), Ok(()));
}

#[test]
fn a_customer_key_is_served_where_the_bucket_blocks_nothing() {
    // `NONE` is the documented explicit unblock, an empty wrapper blocks nothing, and a bucket
    // with no document has no block: all three serve the same SSE-C write.
    let sse = proof(true);
    for document in [
        Some(blocking(&[EncryptionType::NONE])),
        Some(blocking(&[])),
        Some(config(vec![rule(SseAlgorithm::AES256, None)])),
        None,
    ] {
        assert_eq!(refuse_blocked_encryption_type(document.as_ref(), &sse), Ok(()), "{document:?}");
    }
}

#[test]
fn n_a_customer_key_write_into_an_sse_c_blocked_bucket_is_access_denied() {
    let rejection = refuse_blocked_encryption_type(Some(&blocking(&[EncryptionType::SSE_C])), &proof(true))
        .expect_err("AWS refuses an SSE-C write to a bucket that blocks SSE-C");
    assert_eq!(rejection, EncryptionRejection::EncryptionTypeBlocked);
    assert_eq!(rejection.code(), ErrorCode::ACCESS_DENIED);
    assert_eq!(rejection.code().default_status().as_u16(), 403);
}

#[test]
fn n_a_block_in_any_rule_or_beside_none_still_blocks() {
    let sse = proof(true);
    let beside_none = blocking(&[EncryptionType::NONE, EncryptionType::SSE_C]);
    let second_rule = config(vec![
        rule(SseAlgorithm::AES256, None),
        blocking(&[EncryptionType::SSE_C]).rules.remove(0),
    ]);
    for document in [beside_none, second_rule] {
        assert_eq!(
            refuse_blocked_encryption_type(Some(&document), &sse),
            Err(EncryptionRejection::EncryptionTypeBlocked),
            "{document:?}"
        );
    }
}

/// `c-encryption-0027`/`0028`: the wrapper takes `NONE | SSE-C` only. A value the shared
/// enumeration spells but this wrapper does not document is refused like an out-of-set
/// algorithm, and the two documented ones — alone, together, repeated, or an empty wrapper —
/// pass.
#[test]
fn n_a_blocked_type_outside_none_and_sse_c_is_refused_as_malformed_xml() {
    for spelling in ["AES256", "aws:kms", "aws:kms:dsse", "aws:fsx", "SSE-KMS", "sse-c", ""] {
        let document = blocking(&[EncryptionType::SSE_C, EncryptionType::custom(spelling)]);
        assert_eq!(
            validate_encryption(&document),
            Err(EncryptionRejection::EncryptionTypeUnknown),
            "{spelling:?}"
        );
    }
    assert_eq!(EncryptionRejection::EncryptionTypeUnknown.code(), ErrorCode::MALFORMED_XML);
    for entries in [
        vec![EncryptionType::NONE],
        vec![EncryptionType::SSE_C],
        vec![EncryptionType::NONE, EncryptionType::SSE_C, EncryptionType::SSE_C],
        Vec::new(),
    ] {
        assert_eq!(validate_encryption(&blocking(&entries)), Ok(()), "{entries:?}");
    }
}

#[test]
fn n_only_the_exact_sse_c_spelling_blocks() {
    for spelling in ["sse-c", "SSE_C", "SSEC", "AES256"] {
        assert!(!blocks_customer_keys(&blocking(&[EncryptionType::custom(spelling)])), "{spelling}");
    }
    assert!(blocks_customer_keys(&blocking(&[EncryptionType::custom("SSE-C")])));
}

/// The migration end of the chain: the exact bytes RustFS rc.6 and `main` persist, decoded by
/// the production persistence bridge, still refuse the write they block.
#[test]
fn n_the_persisted_rc6_witness_still_blocks_after_migration() {
    let stored = rustfs_gateway_types::persistence::parse_bucket_encryption_dto(
        b"<ServerSideEncryptionConfiguration><Rule><BlockedEncryptionTypes><EncryptionType>SSE-C</EncryptionType></BlockedEncryptionTypes></Rule></ServerSideEncryptionConfiguration>",
    )
    .expect("the persisted witness is readable");
    assert_eq!(
        refuse_blocked_encryption_type(Some(&stored), &proof(true)),
        Err(EncryptionRejection::EncryptionTypeBlocked)
    );
    assert!(!rejection_mentions_key(&EncryptionRejection::EncryptionTypeBlocked));
}

fn rejection_mentions_key(rejection: &EncryptionRejection) -> bool {
    let reason = rejection.reason();
    reason.contains("AAECAw") || reason.contains("tP/LI3")
}
