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

//! Typed runtime vocabulary for generated protocol-contract inputs.
//!
//! Responsible for: declaring the closed runtime types that generated contract data selects.
//! NOT responsible for: choosing current values or implementing their consumers.
//! Upstream: generated contract data. Downstream: operation-family shared runtime modules.

mod cors;
mod precondition;
mod select_restore;

pub(crate) use cors::*;
pub(crate) use precondition::*;
pub(crate) use select_restore::*;

/// How a decoded ACL grantee obtains the discriminator carried by an unreadable XML attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum GranteeDiscriminatorPolicy {
    /// Derive the discriminator from the one identifying child member.
    IdentifyingMember,
    /// Leave the unreadable discriminator unset. Mutation-only alternative.
    LeaveUnset,
}

/// Which ACL input channels may coexist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum AclChannelPolicy {
    /// The body excludes all ACL headers while canned and grant headers may coexist.
    BodyXorHeaders,
    /// Refuse a canned ACL combined with explicit grant headers.
    RejectMixedHeaders,
}

/// Whether an ACL rejection may expose a value taken from the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum AclErrorSecretFlowPolicy {
    /// Rejection reasons are request-independent constants.
    ConstantReasons,
    /// Mutation alternative that exposes the rejected value.
    EchoRejectedValue,
}

/// How the optional owner in an ACL document is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum AclOwnerPolicy {
    /// Preserve a present owner and leave an absent owner absent.
    PreserveAsSent,
    /// Drop a present owner.
    Drop,
}

/// Result of deleting a configuration that is already absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum DeleteAbsentPolicy {
    /// The already-absent configuration is a successful deletion.
    Succeed,
    /// Report that the configuration was not found.
    ConfigurationNotFound,
}

/// Whether an encryption rejection may expose a key id taken from the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum EncryptionErrorSecretFlowPolicy {
    /// Rejection reasons are request-independent constants.
    ConstantReasons,
    /// Mutation alternative that exposes the rejected key id.
    EchoRejectedValue,
}

/// Relationship required between a retain-until instant and the caller's clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum ObjectLockTemporalRelation {
    /// The retain-until instant must be strictly later.
    StrictlyFuture,
    /// Mutation alternative that accepts any retain-until instant.
    AllowAny,
}

/// Bucket state required before an object-level lock write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum ObjectLockBucketStatePrecondition {
    /// Object lock must be enabled on the bucket.
    RequireEnabled,
    /// Mutation alternative that accepts an unlocked bucket.
    AllowDisabled,
}

/// Handling of `If-None-Match: *` on a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum ConditionalWildcardWritePolicy {
    /// Treat it as compare-and-create.
    CompareAndCreate,
    /// Ignore it.
    Ignore,
}

/// Precedence between a satisfied If-Match and If-Modified-Since.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum IfMatchDatePrecedence {
    /// Skip If-Modified-Since.
    SuppressModifiedSince,
    /// Evaluate If-Modified-Since.
    EvaluateModifiedSince,
}

/// Outcome of a missed If-None-Match beside a satisfied If-Unmodified-Since.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum IfNoneDatePrecedence {
    /// Answer NotModified.
    NotModified,
    /// Proceed with the request.
    Proceed,
}

/// Handling of If-Match and If-None-Match sent together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum ConditionConflictPolicy {
    /// Reject the request.
    Reject,
    /// Evaluate only If-Match.
    PreferIfMatch,
}

/// Whether the conditional entity-tag parser admits `*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum ConditionalWildcardParsePolicy {
    /// Accept the wildcard.
    Accept,
    /// Reject the wildcard.
    Reject,
}

/// Which representations supply CopyObject source and target validators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum CopyValidatorScopePolicy {
    /// Source-prefixed conditions use the source and ordinary conditions use the target.
    SeparateSourceAndTarget,
    /// Evaluate target conditions against the source. Mutation-only alternative.
    TargetUsesSource,
}

/// Entity-tag comparison strength used by If-Match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum EtagComparisonStrengthPolicy {
    /// Weak validators never satisfy the condition.
    Strong,
    /// Ignore validator weakness. Mutation-only alternative.
    Weak,
}

/// Outcome of a named If-Match value that misses the current entity tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum IfMatchMissOutcomePolicy {
    /// Refuse the request as a failed precondition.
    PreconditionFailed,
    /// Let the request proceed. Mutation-only alternative.
    Proceed,
}

/// Placement of a conditional-write guard relative to storage mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum ConditionalWriteOrderPolicy {
    /// Evaluate the guard before changing storage.
    GuardBeforeMutation,
    /// Evaluate the guard after changing storage. Mutation-only alternative.
    GuardAfterMutation,
}

/// Outcome of If-Match when no current representation exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum IfMatchAbsentPolicy {
    /// Refuse the request as a failed precondition.
    PreconditionFailed,
    /// Let the request proceed as a create. Mutation-only alternative.
    Proceed,
}

/// Namespace carried by the root of an S3 error document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum ErrorRootNamespacePolicy {
    /// Emit an unnamespaced `Error` root.
    Unnamespaced,
    /// Add the ordinary S3 document namespace. Mutation-only alternative.
    S3,
}

/// Whether a HEAD response carries content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum HeadBodyPolicy {
    /// Suppress the bytes while retaining the equivalent GET metadata.
    Suppress,
    /// Preserve the bytes. Mutation-only alternative.
    Preserve,
}

/// Whether a precondition failure names the condition that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum ConditionFailureDetailPolicy {
    /// Include the condition as an error-document detail.
    IncludeCondition,
    /// Omit the condition. Mutation-only alternative.
    OmitCondition,
}

/// Outcome of an unsatisfied copy-source If-Match condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum CopySourceIfMatchMissPolicy {
    /// Refuse the copy as a failed precondition.
    PreconditionFailed,
    /// Let the copy proceed. Mutation-only alternative.
    Proceed,
}

/// Placement of a copy-source guard relative to the target write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
pub(crate) enum CopySourceGuardOrderPolicy {
    /// Evaluate the source guard before writing the target.
    GuardBeforeTargetWrite,
    /// Write the target before evaluating the source guard. Mutation-only alternative.
    TargetWriteBeforeGuard,
}

/// The namespace attached to the root of an S3 error document.
#[must_use]
pub const fn error_root_namespace() -> Option<&'static str> {
    match ERROR_ROOT_NAMESPACE_POLICY {
        ErrorRootNamespacePolicy::Unnamespaced => None,
        ErrorRootNamespacePolicy::S3 => Some("http://s3.amazonaws.com/doc/2006-03-01/"),
    }
}

/// Whether HEAD response content is suppressed.
#[must_use]
pub(crate) const fn suppress_head_body() -> bool {
    matches!(HEAD_BODY_POLICY, HeadBodyPolicy::Suppress)
}

/// Whether precondition failures include the failed condition as a detail.
#[must_use]
pub(crate) const fn include_condition_failure_detail() -> bool {
    matches!(CONDITION_FAILURE_DETAIL_POLICY, ConditionFailureDetailPolicy::IncludeCondition)
}

/// Whether an unsatisfied copy-source If-Match condition lets the copy proceed.
#[must_use]
pub const fn copy_source_if_match_miss_proceeds() -> bool {
    matches!(COPY_SOURCE_IF_MATCH_MISS_POLICY, CopySourceIfMatchMissPolicy::Proceed)
}

/// Whether a copy-source guard runs before the target write.
#[must_use]
pub const fn copy_source_guards_before_target_write() -> bool {
    matches!(COPY_SOURCE_GUARD_ORDER_POLICY, CopySourceGuardOrderPolicy::GuardBeforeTargetWrite)
}

#[allow(
    missing_docs,
    reason = "the emitter writes data constants; the vocabulary is documented above"
)]
mod data {
    include!("../generated/contracts.rs");
}

pub(crate) use data::{
    ACL_BUCKET_CANNED_VALUES, ACL_CHANNEL_POLICY, ACL_ERROR_SECRET_FLOW_POLICY, ACL_GRANT_HEADER_KEYS,
    ACL_GRANT_HEADER_MAX_BYTES, ACL_GRANT_HEADER_MAX_ENTRIES, ACL_GRANT_KEYS_CASE_INSENSITIVE, ACL_GRANTEE_DISCRIMINATOR_POLICY,
    ACL_OBJECT_CANNED_VALUES, ACL_OWNER_POLICY, ACL_PERMISSION_VALUES, BARE_CONDITIONAL_ETAG_POLICY,
    COMPLETION_FAILURE_UPLOAD_POLICY, CONDITION_CONFLICT_POLICY, CONDITION_FAILURE_DETAIL_POLICY,
    CONDITIONAL_RACE_OUTCOME_POLICY, CONDITIONAL_WILDCARD_PARSE_POLICY, CONDITIONAL_WILDCARD_WRITE_POLICY,
    CONDITIONAL_WRITE_ORDER, COPY_RANGE_LENGTH_ARITHMETIC, COPY_SOURCE_GUARD_ORDER_POLICY, COPY_SOURCE_IF_MATCH_MISS_POLICY,
    COPY_VALIDATOR_SCOPE_POLICY, ENCRYPTION_ALGORITHMS, ENCRYPTION_DELETE_ABSENT_POLICY, ENCRYPTION_ERROR_SECRET_FLOW_POLICY,
    ENCRYPTION_KMS_KEY_ALGORITHMS, ENCRYPTION_RULE_MAX, ERROR_ROOT_NAMESPACE_POLICY, HEAD_BODY_POLICY, IF_MATCH_ABSENT_POLICY,
    IF_MATCH_COMPARISON_STRENGTH, IF_MATCH_DATE_PRECEDENCE, IF_MATCH_MISS_OUTCOME, IF_NONE_DATE_PRECEDENCE,
    IF_NONE_MATCH_COMPARISON_STRENGTH, IF_RANGE_MISS_POLICY, NOT_MODIFIED_BODY_POLICY, NOT_MODIFIED_ETAG_POLICY,
    NOT_MODIFIED_FRAMING_POLICY, OBJECT_LOCK_BUCKET_STATE_PRECONDITION, OBJECT_LOCK_DEFAULT_EXACTLY_ONE_PERIOD,
    OBJECT_LOCK_DEFAULT_MIN_PERIOD, OBJECT_LOCK_DEFAULT_REQUIRE_MODE, OBJECT_LOCK_ENABLED_VALUES, OBJECT_LOCK_LEGAL_HOLD_VALUES,
    OBJECT_LOCK_MODE_VALUES, OBJECT_LOCK_TEMPORAL_RELATION, PART_COUNT_HEADER_POLICY, PART_NUMBER_OUTCOME_POLICY,
    PARTIAL_CHECKSUM_POLICY, RANGE_PART_SELECTOR_CONFLICT_POLICY, RANGE_REQUESTED_DETAIL_POLICY, READ_RANGE_LENGTH_ARITHMETIC,
    UNSATISFIABLE_ACTUAL_SIZE_DETAIL_POLICY,
};

pub(crate) use data::{
    EVENT_CRC_ALGORITHM, EVENT_MESSAGE_CRC_COVERAGE, EVENT_PRELUDE_CRC_COVERAGE, RESTORE_ALREADY_RESTORED_OUTCOME,
    RESTORE_DAYS_MINIMUM, RESTORE_DAYS_SELECT_EXCLUSION, RESTORE_DIRECT_TIER_VALUE_SET, RESTORE_FORM_PRESENCE,
    RESTORE_GLACIER_TIER_VALUE_SET, RESTORE_HEADER_ABSENCE, RESTORE_HEADER_ONGOING_FORM, RESTORE_HEADER_PARSE_GRAMMAR,
    RESTORE_HEADER_RESTORED_FORM, RESTORE_IN_PROGRESS_OUTCOME, RESTORE_INITIATED_OUTCOME, RESTORE_NESTED_SELECT_VALIDATION,
    RESTORE_NOT_ARCHIVED_OUTCOME, RESTORE_ROOT_NAMESPACE_POLICY, RESTORE_SELECT_MEMBERS_REQUIRE_TYPE,
    RESTORE_SELECT_OUTPUT_REQUIRED, RESTORE_SELECT_PARAMETERS_REQUIRED, RESTORE_TYPE_VALUE_SET, RESTORE_VERSION_SELECTOR,
    SELECT_COMPRESSION_VALUES, SELECT_EVENT_MEDIA_TYPE, SELECT_EVENT_STATUS, SELECT_EVENT_TERMINATION,
    SELECT_EXPRESSION_ERROR_FLOW, SELECT_EXPRESSION_INSPECTION, SELECT_EXPRESSION_MAX_BYTES, SELECT_EXPRESSION_PRESENCE,
    SELECT_EXPRESSION_TYPE_VALUES, SELECT_INPUT_MISSING, SELECT_INPUT_MULTIPLE, SELECT_OUTPUT_MISSING, SELECT_OUTPUT_MULTIPLE,
    SELECT_RESPONSE_SHAPE, SELECT_ROOT_NAMESPACE_POLICY, SELECT_SCAN_BOUNDED, SELECT_SCAN_END_ONLY, SELECT_SCAN_RANGE_EMPTY,
    SELECT_SCAN_RANGE_ORDER, SELECT_SCAN_RANGE_SIGN, SELECT_SCAN_START_ONLY, SELECT_TYPE_ROUTE_PREDICATE,
};
