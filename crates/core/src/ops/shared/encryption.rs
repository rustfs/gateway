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
//! closed `SSEAlgorithm` value set, the KMS-key-id/algorithm agreement rule and the documented
//! `NONE | SSE-C` set of `BlockedEncryptionTypes` — held once so that every backend refuses the
//! same documents with the same codes; and the document's one run-time rule,
//! [`refuse_blocked_encryption_type`], which the backend holding the document calls on every
//! object write (rustfs/gateway#740).
//! NOT responsible for: decoding the document (the generated codec, which refuses unknown
//! request elements — `q-enc-0006`), storing it, or **applying** its default action. Whether an
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
//! Two boundaries answer two different questions. A *stored* configuration is re-parsed by every
//! future release, and a reader that got stricter would silently turn default encryption off, so
//! persisted bytes are read by `rustfs_gateway_types::persistence`, which stays lenient about
//! unknown root elements. A *request* is the client asking for a protection now, and a setting
//! the gateway cannot store must not come back as a 200: the generated request codec refuses
//! unknown elements before this module runs (`q-enc-0006`, ADR-0007 `allow-registered`). What is
//! left here is semantic: accepting an `SSEAlgorithm` nothing can apply stores a promise no
//! encryption path can keep. So the two checks below refuse exactly what AWS documents as
//! impossible — an out-of-set algorithm, a KMS key id beside a non-KMS algorithm (`q-enc-0007`,
//! `q-enc-0005`) — and nothing else; extra rules still pass (`q-enc-0008`).
//!
//! # The refusal messages are constant, and the key id never appears in one
//!
//! These reasons follow [`super::cors`]'s stance — never built from request bytes. Here that
//! rule carries extra weight: `KMSMasterKeyID` is marked sensitive in the model, and a refusal
//! that repeated it would copy a key identifier into an error body and every log line that
//! captures one (`q-enc-0009`). The stored document echoes the key id on the read — that is the
//! documented GET behaviour — but an error message never does.

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{EncryptionType, ServerSideEncryptionConfiguration};

use crate::SseEnforced;
use crate::contracts::{
    DeleteAbsentPolicy, ENCRYPTION_ALGORITHMS, ENCRYPTION_DELETE_ABSENT_POLICY, ENCRYPTION_ERROR_SECRET_FLOW_POLICY,
    ENCRYPTION_KMS_KEY_ALGORITHMS, ENCRYPTION_RULE_MAX, EncryptionErrorSecretFlowPolicy,
};

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
    /// Mutation-only form that carries the rejected KMS key id into the reason.
    KmsKeyWithoutKmsAlgorithmWithValue(String),
    /// The configuration carries more rules than the current contract permits.
    TooManyRules,
    /// An object write uses an encryption type the bucket's stored document blocks. AWS answers
    /// `403 AccessDenied` for a PutObject, CopyObject, PostObject, multipart or replication write
    /// that names SSE-C while the bucket blocks it.
    EncryptionTypeBlocked,
    /// A `BlockedEncryptionTypes` entry outside the documented `NONE | SSE-C`. The generated enum
    /// is shared with other shapes and also spells `AES256` and the KMS algorithms, but a stored
    /// block no write path can enforce is a promise nothing keeps, so the write refuses it.
    EncryptionTypeUnknown,
}

impl EncryptionRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // A schema violation: the member's value set is closed and the document is outside it.
            EncryptionRejection::AlgorithmUnknown | EncryptionRejection::EncryptionTypeUnknown => ErrorCode::MALFORMED_XML,
            // A cross-member constraint on otherwise well-formed values.
            EncryptionRejection::KmsKeyWithoutKmsAlgorithm
            | EncryptionRejection::KmsKeyWithoutKmsAlgorithmWithValue(_)
            | EncryptionRejection::TooManyRules => ErrorCode::INVALID_ARGUMENT,
            // Documented as a 403 AccessDenied: the caller is not allowed this write on this bucket.
            EncryptionRejection::EncryptionTypeBlocked => ErrorCode::ACCESS_DENIED,
        }
    }

    /// A constant explanation, never built from request bytes — and in particular never carrying
    /// the key id the document named (`q-enc-0009`).
    #[must_use]
    pub fn reason(&self) -> &str {
        if let (
            EncryptionErrorSecretFlowPolicy::EchoRejectedValue,
            EncryptionRejection::KmsKeyWithoutKmsAlgorithmWithValue(value),
        ) = (ENCRYPTION_ERROR_SECRET_FLOW_POLICY, self)
        {
            return value;
        }
        match self {
            EncryptionRejection::AlgorithmUnknown => "SSEAlgorithm must be one of AES256, aws:fsx, aws:kms or aws:kms:dsse",
            EncryptionRejection::KmsKeyWithoutKmsAlgorithm | EncryptionRejection::KmsKeyWithoutKmsAlgorithmWithValue(_) => {
                "KMSMasterKeyID can only be used when SSEAlgorithm is aws:kms or aws:kms:dsse"
            }
            EncryptionRejection::TooManyRules => "The encryption configuration carries too many rules",
            EncryptionRejection::EncryptionTypeBlocked => {
                "The bucket's default encryption configuration blocks writes that use SSE-C"
            }
            EncryptionRejection::EncryptionTypeUnknown => "EncryptionType in BlockedEncryptionTypes must be NONE or SSE-C",
        }
    }

    fn kms_key_without_kms_algorithm(key_id: &str) -> Self {
        match ENCRYPTION_ERROR_SECRET_FLOW_POLICY {
            EncryptionErrorSecretFlowPolicy::ConstantReasons => EncryptionRejection::KmsKeyWithoutKmsAlgorithm,
            EncryptionErrorSecretFlowPolicy::EchoRejectedValue => {
                EncryptionRejection::KmsKeyWithoutKmsAlgorithmWithValue(key_id.to_owned())
            }
        }
    }
}

/// Whether deleting an already-absent encryption configuration is successful.
#[must_use]
pub const fn encryption_delete_absent_succeeds() -> bool {
    matches!(ENCRYPTION_DELETE_ABSENT_POLICY, DeleteAbsentPolicy::Succeed)
}

/// Checks a decoded document against the family's semantic rules, first refusal wins.
///
/// Deliberately no stricter than AWS's documented refusals: an element this release does not
/// know never gets here because the decoder refuses it (`q-enc-0006`), a multi-rule document
/// passes (`q-enc-0008`),
/// and a rule that names no `ApplyServerSideEncryptionByDefault` at all passes because the model
/// makes the member optional. Rules are checked in document order and members in the order the
/// wire carries them, so the same document is refused for the same reason on every backend.
///
/// # Errors
///
/// [`EncryptionRejection`] naming the first rule the document breaks.
pub fn validate_encryption(configuration: &ServerSideEncryptionConfiguration) -> Result<(), EncryptionRejection> {
    if ENCRYPTION_RULE_MAX.is_some_and(|max| configuration.rules.len() > max) {
        return Err(EncryptionRejection::TooManyRules);
    }
    for rule in &configuration.rules {
        if let Some(by_default) = &rule.apply_server_side_encryption_by_default {
            if !ENCRYPTION_ALGORITHMS.contains(&by_default.sse_algorithm.as_str()) {
                return Err(EncryptionRejection::AlgorithmUnknown);
            }
            let kms = ENCRYPTION_KMS_KEY_ALGORITHMS.contains(&by_default.sse_algorithm.as_str());
            if let Some(key_id) = &by_default.kms_master_key_id
                && !kms
            {
                return Err(EncryptionRejection::kms_key_without_kms_algorithm(key_id));
            }
        }
        if let Some(blocked) = &rule.blocked_encryption_types
            && blocked
                .encryption_type
                .iter()
                .any(|entry| ![EncryptionType::NONE.as_str(), EncryptionType::SSE_C.as_str()].contains(&entry.as_str()))
        {
            return Err(EncryptionRejection::EncryptionTypeUnknown);
        }
    }
    Ok(())
}

/// Whether any stored rule blocks SSE-C for new object writes.
///
/// Only the exact `SSE-C` spelling blocks. `NONE` is the documented explicit "block nothing", and
/// an entry this release does not know names no request it could refuse. A rule listing both
/// `NONE` and `SSE-C` blocks: a document that names SSE-C as blocked is never read as permission.
#[must_use]
pub fn blocks_customer_keys(configuration: &ServerSideEncryptionConfiguration) -> bool {
    configuration
        .rules
        .iter()
        .filter_map(|rule| rule.blocked_encryption_types.as_ref())
        .flat_map(|blocked| &blocked.encryption_type)
        .any(|entry| entry.as_str() == EncryptionType::SSE_C.as_str())
}

/// The stored document's one run-time rule, for the backend that holds the document.
///
/// A write whose request presented a customer-provided key for the object it writes — the
/// framework's [`SseEnforced`] proof, never a decoded header — into a bucket whose document blocks
/// SSE-C is refused. The framework holds no bucket state, so the backend calls this before it
/// stores anything, for every object write that can carry SSE-C: PutObject, CopyObject (the
/// target's key, not the copy source's), PostObject and CreateMultipartUpload. Reads are never
/// refused: AWS keeps objects already written with SSE-C readable.
///
/// # Errors
///
/// [`EncryptionRejection::EncryptionTypeBlocked`], which renders `403 AccessDenied`.
pub fn refuse_blocked_encryption_type(
    configuration: Option<&ServerSideEncryptionConfiguration>,
    sse: &SseEnforced,
) -> Result<(), EncryptionRejection> {
    if sse.customer_key_fingerprint().is_some() && configuration.is_some_and(blocks_customer_keys) {
        return Err(EncryptionRejection::EncryptionTypeBlocked);
    }
    Ok(())
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `lifecycle`'s test module.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
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
}
