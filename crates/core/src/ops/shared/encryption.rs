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

//! The default-encryption configuration document: what a stored one is allowed to say.
//!
//! Shares: encryption
//! Members: DeleteBucketEncryption, GetBucketEncryption, PutBucketEncryption
//!
//! Responsible for: the semantic rules of a `ServerSideEncryptionConfiguration` document — the
//! closed `SSEAlgorithm` value set and the KMS-key-id/algorithm agreement rule — held once so
//! that every backend refuses the same documents with the same codes.
//! NOT responsible for: decoding the document (the generated codec, which is deliberately
//! lenient about unknown elements — `q-enc-0006`), storing it, or **applying** it. Whether an
//! object write is actually encrypted with the configured default, how object-level SSE headers
//! override it, and every other runtime half of SSE — the TLS gate on customer-provided keys,
//! key/key-MD5 agreement, multipart header consistency — is task P6-06's, with the operations
//! that carry SSE headers, and nothing here answers it.
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`. Downstream: the facade,
//! which re-exports every item here for backends; the `crates/conformance` fixture is the first
//! caller.
//!
//! # Why the write is stricter than the lifecycle family's, and no stricter than that
//!
//! Two pressures pull in opposite directions. A stored configuration is re-parsed by every
//! future release, and RustFS's persistence fails open — a configuration that stops parsing is
//! downgraded to "no configuration", which silently turns default encryption off. That argues
//! for leniency, and it is why unknown elements and extra rules pass (`q-enc-0006`,
//! `q-enc-0008`). But this is a *security* configuration: accepting an `SSEAlgorithm` nothing
//! can apply stores a promise no encryption path can keep, and the client that wrote it walks
//! away believing its data is protected. So the two checks below refuse exactly what AWS
//! documents as impossible — an out-of-set algorithm, a KMS key id beside a non-KMS algorithm
//! (`q-enc-0007`, `q-enc-0005`) — and nothing else.
//!
//! # The refusal messages are constant, and the key id never appears in one
//!
//! These reasons follow [`super::cors`]'s stance — never built from request bytes. Here that
//! rule carries extra weight: `KMSMasterKeyID` is marked sensitive in the model, and a refusal
//! that repeated it would copy a key identifier into an error body and every log line that
//! captures one (`q-enc-0009`). The stored document echoes the key id on the read — that is the
//! documented GET behaviour — but an error message never does.

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{ServerSideEncryptionConfiguration, SseAlgorithm};

/// Why a decoded encryption document was refused, with the code AWS answers.
///
/// Carried as data rather than as a rendered error so that a backend outside this workspace can
/// map it into its own error type; [`EncryptionRejection::code`] and
/// [`EncryptionRejection::reason`] are the two halves an S3 error document needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionRejection {
    /// An `SSEAlgorithm` outside the documented set. A default-encryption algorithm nothing can
    /// apply is a configuration that silently protects nothing, so the write refuses it.
    AlgorithmUnknown,
    /// A `KMSMasterKeyID` beside an algorithm that is not `aws:kms` or `aws:kms:dsse`: AWS
    /// documents the member as allowed if and only if the algorithm is one of those two.
    KmsKeyWithoutKmsAlgorithm,
}

impl EncryptionRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // A schema violation: the member's value set is closed and the document is outside it.
            EncryptionRejection::AlgorithmUnknown => ErrorCode::MALFORMED_XML,
            // A cross-member constraint on otherwise well-formed values.
            EncryptionRejection::KmsKeyWithoutKmsAlgorithm => ErrorCode::INVALID_ARGUMENT,
        }
    }

    /// A constant explanation, never built from request bytes — and in particular never carrying
    /// the key id the document named (`q-enc-0009`).
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            EncryptionRejection::AlgorithmUnknown => "SSEAlgorithm must be one of AES256, aws:fsx, aws:kms or aws:kms:dsse",
            EncryptionRejection::KmsKeyWithoutKmsAlgorithm => {
                "KMSMasterKeyID can only be used when SSEAlgorithm is aws:kms or aws:kms:dsse"
            }
        }
    }
}

/// Checks a decoded document against the family's semantic rules, first refusal wins.
///
/// Deliberately no stricter than AWS's documented refusals: an element this release does not
/// know is skipped by the decoder (`q-enc-0006`), a multi-rule document passes (`q-enc-0008`),
/// and a rule that names no `ApplyServerSideEncryptionByDefault` at all passes because the model
/// makes the member optional. Rules are checked in document order and members in the order the
/// wire carries them, so the same document is refused for the same reason on every backend.
///
/// # Errors
///
/// [`EncryptionRejection`] naming the first rule the document breaks.
pub fn validate_encryption(configuration: &ServerSideEncryptionConfiguration) -> Result<(), EncryptionRejection> {
    for rule in &configuration.rules {
        if let Some(by_default) = &rule.apply_server_side_encryption_by_default {
            if !by_default.sse_algorithm.is_known() {
                return Err(EncryptionRejection::AlgorithmUnknown);
            }
            let kms = by_default.sse_algorithm == SseAlgorithm::AWS_KMS || by_default.sse_algorithm == SseAlgorithm::AWS_KMS_DSSE;
            if by_default.kms_master_key_id.is_some() && !kms {
                return Err(EncryptionRejection::KmsKeyWithoutKmsAlgorithm);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `lifecycle`'s test module.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_types::dto::{ServerSideEncryptionByDefault, ServerSideEncryptionRule};

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
}
