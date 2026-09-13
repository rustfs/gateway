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
#[path = "encryption_tests.rs"]
// Test code is exempt from the no-expect rule; the allowance mirrors `lifecycle`'s test module.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
