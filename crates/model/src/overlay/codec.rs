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

//! Typed mutable protocol decisions that stay outside the frozen operation IR schema.
//!
//! Responsible for: parsing current codec values and lowered-IR source paths together with their
//! mechanical mutation dimension. NOT responsible for: attaching quirk ids to fields or applying
//! mutations. Upstream: quirk overlay tables. Downstream: the overlay loader and codegen emitters.

use crate::error::{Error, Result};
use crate::toml_lite::Toml;

use super::MutationDimension;
use super::contract_values::{
    ConditionFailureDetailValue, ContractRule, ContractValue, CopySourceGuardOrderValue, CopySourceIfMatchMissValue,
    ErrorRootNamespaceValue, HeadBodyPolicyValue,
};
use super::cors_contract_inputs;
use super::naming_contract_inputs;
use super::precondition_contract_inputs;
use super::select_restore_contract_inputs;
use super::{opt_str, required_str};

/// A wire-form grammar selected by a quirk's typed codec value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireFormValue {
    /// An RFC 9110 entity tag.
    EntityTag,
    /// An opaque token previously issued by the service.
    OpaqueToken,
}

/// A tolerant header reading selected by a quirk's typed codec value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderToleranceValue {
    /// An invalid modification-date condition is ignored rather than refused.
    DateCondition,
}

/// How generated XML readers treat child elements they do not recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownElementPolicyValue {
    /// Ignore the child and continue decoding known members.
    Skip,
    /// Refuse the document as malformed XML.
    Reject,
}

/// Accepted spelling of a boolean carried as a wire string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BooleanSpellingValue {
    /// Accept `true` and `false` without regard to ASCII case.
    AsciiCaseInsensitive,
    /// Mutation alternative that accepts lower-case spellings only.
    LowercaseOnly,
}

/// The typed codec behavior carried by a protocol quirk.
///
/// This stays beside the overlay rather than in the frozen operation IR. Code generation consumes
/// it directly, so a mutation can replace one value in memory without changing the IR schema or
/// editing generated files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecValue {
    /// Grammar used to validate a string-shaped wire value.
    WireForm(WireFormValue),
    /// Inclusive bounds applied while decoding an integer.
    IntegerRange {
        /// Smallest accepted value.
        min: i32,
        /// Largest accepted value.
        max: i32,
    },
    /// Media type of a non-XML text payload.
    MediaType(String),
    /// Tolerant reading applied to a request header.
    HeaderTolerance(HeaderToleranceValue),
    /// Unknown-child policy applied by generated XML readers.
    UnknownElementPolicy(UnknownElementPolicyValue),
    /// Accepted spelling of a boolean wire value.
    BooleanSpelling(BooleanSpellingValue),
}

/// One typed codec rule and the dimension a mutation gate may change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecRule {
    /// Current wire behavior consumed by code generation.
    pub current: CodecValue,
    /// The mechanical mutation family for this value.
    pub mutation_dimension: MutationDimension,
}

/// One mutation rule whose current value is read from the lowered operation IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRule {
    /// The mechanical mutation family.
    pub mutation_dimension: MutationDimension,
    /// Stable paths into lowered operation IR; all paths are mutated as one protocol rule.
    pub sources: Vec<String>,
}

/// Which ACL input channels may coexist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclChannelPolicyValue {
    /// The XML body excludes every ACL header; canned and grant headers may coexist.
    BodyXorHeaders,
    /// Mutation alternative that also excludes canned and grant headers from each other.
    RejectMixedHeaders,
}

/// Whether ACL rejection reasons can carry values taken from the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSecretFlowValue {
    /// Return only request-independent constant reasons.
    ConstantReasons,
    /// Mutation alternative that exposes the rejected value.
    EchoRejectedValue,
}

/// How the optional owner in an ACL document is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclOwnerPolicyValue {
    /// Preserve a present owner and leave an absent owner absent.
    PreserveAsSent,
    /// Mutation alternative that drops a present owner.
    Drop,
}

/// Result of deleting a configuration that is already absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteAbsentPolicyValue {
    /// Treat the already-absent configuration as a successful deletion.
    Succeed,
    /// Mutation alternative that reports the configuration as not found.
    ConfigurationNotFound,
}

/// Temporal relationship required by an object-lock retention write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalRelationValue {
    /// The retain-until instant must be strictly later than the caller's clock.
    StrictlyFuture,
    /// Mutation alternative that accepts any retain-until instant.
    AllowAny,
}

/// Bucket state required before an object-level lock write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketStatePreconditionValue {
    /// The bucket must have object lock enabled.
    RequireEnabled,
    /// Mutation alternative that accepts an unlocked bucket.
    AllowDisabled,
}

/// Handling of `If-None-Match: *` on a conditional write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalWildcardWriteValue {
    /// Treat the wildcard as compare-and-create.
    CompareAndCreate,
    /// Mutation alternative that ignores the wildcard.
    Ignore,
}

/// Precedence between a satisfied If-Match and If-Modified-Since.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfMatchDatePrecedenceValue {
    /// A satisfied If-Match suppresses If-Modified-Since.
    SuppressModifiedSince,
    /// Mutation alternative that evaluates If-Modified-Since anyway.
    EvaluateModifiedSince,
}

/// Outcome of a missed If-None-Match beside a satisfied If-Unmodified-Since.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfNoneDatePrecedenceValue {
    /// Answer NotModified on a read.
    NotModified,
    /// Mutation alternative that proceeds with the read.
    Proceed,
}

/// Handling of If-Match and If-None-Match sent together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionConflictValue {
    /// Reject the conflicting request.
    Reject,
    /// Mutation alternative that evaluates only If-Match.
    PreferIfMatch,
}

/// Whether the entity-tag conditional parser admits `*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalWildcardParseValue {
    /// Parse the wildcard as a conditional value.
    Accept,
    /// Mutation alternative that rejects it.
    Reject,
}

/// Which representations supply validators for a copy's two condition channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyValidatorScopeValue {
    /// Source-prefixed conditions use the source and ordinary conditions use the target.
    SeparateSourceAndTarget,
    /// Mutation alternative that evaluates target conditions against the source.
    TargetUsesSource,
}

/// Entity-tag comparison strength used by If-Match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtagComparisonStrengthValue {
    /// Weak validators never satisfy the condition.
    Strong,
    /// Mutation alternative that ignores validator weakness.
    Weak,
}

/// Outcome of a named If-Match value that misses the current entity tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfMatchMissOutcomeValue {
    /// Refuse the request as a failed precondition.
    PreconditionFailed,
    /// Mutation alternative that lets the request proceed.
    Proceed,
}

/// Placement of a conditional-write guard relative to storage mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalWriteOrderValue {
    /// Evaluate the guard before changing storage.
    GuardBeforeMutation,
    /// Mutation alternative that evaluates the guard after changing storage.
    GuardAfterMutation,
}

/// Outcome of If-Match when no current representation exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfMatchAbsentPolicyValue {
    /// Refuse the request as a failed precondition.
    PreconditionFailed,
    /// Mutation alternative that lets the request proceed as a create.
    Proceed,
}

pub(super) fn contract_rule(table: &Toml, id: &str) -> Result<Option<ContractRule>> {
    let Some(value) = opt_str(table, "contract_value") else {
        return Ok(None);
    };
    let dimension = required_str(table, "mutation_dimension", &format!("quirk `{id}` contract rule"))?;
    if let Some(rule) = naming_contract_inputs::parse(&dimension, &value, id)? {
        return Ok(Some(rule));
    }
    if let Some(rule) = precondition_contract_inputs::parse(&dimension, &value)? {
        return Ok(Some(rule));
    }
    if let Some(rule) = cors_contract_inputs::parse(&dimension, &value)? {
        return Ok(Some(rule));
    }
    if let Some(rule) = select_restore_contract_inputs::parse(&dimension, &value, id)? {
        return Ok(Some(rule));
    }
    let (current, mutation_dimension) = match (dimension.as_str(), value.as_str()) {
        ("grantee_discriminator_policy", "derive_from_identifying_member") => (
            ContractValue::GranteeTypeFromIdentifyingMember,
            MutationDimension::GranteeDiscriminatorPolicy,
        ),
        ("grantee_discriminator_policy", "leave_unset") => {
            (ContractValue::GranteeTypeLeaveUnset, MutationDimension::GranteeDiscriminatorPolicy)
        }
        ("target_value_sets", "target_specific_canned_acls") => (
            ContractValue::AclTargetValueSets {
                bucket: required_string_array(table, "contract_bucket_values", id)?,
                object: required_string_array(table, "contract_object_values", id)?,
            },
            MutationDimension::TargetValueSets,
        ),
        ("acl_channel_matrix", "body_xor_headers") => (
            ContractValue::AclChannelPolicy(AclChannelPolicyValue::BodyXorHeaders),
            MutationDimension::AclChannelMatrix,
        ),
        ("acl_channel_matrix", "reject_mixed_headers") => (
            ContractValue::AclChannelPolicy(AclChannelPolicyValue::RejectMixedHeaders),
            MutationDimension::AclChannelMatrix,
        ),
        ("error_secret_flow", "constant_rejection_reasons") => (
            ContractValue::AclErrorSecretFlow(ErrorSecretFlowValue::ConstantReasons),
            MutationDimension::ErrorSecretFlow,
        ),
        ("error_secret_flow", "echo_rejected_value") => (
            ContractValue::AclErrorSecretFlow(ErrorSecretFlowValue::EchoRejectedValue),
            MutationDimension::ErrorSecretFlow,
        ),
        ("grant_header_grammar", "quoted_key_value_list") => (
            ContractValue::AclGrantHeaderGrammar {
                keys: required_string_array(table, "contract_keys", id)?,
                case_insensitive: required_bool(table, "contract_case_insensitive", id)?,
                max_bytes: required_u32(table, "contract_max_bytes", id)?,
                max_entries: required_u32(table, "contract_max_entries", id)?,
            },
            MutationDimension::GrantHeaderGrammar,
        ),
        ("permission_value_set", "closed_permissions") => (
            ContractValue::AclPermissionValueSet(required_string_array(table, "contract_values", id)?),
            MutationDimension::PermissionValueSet,
        ),
        ("owner_policy", "preserve_as_sent") => (
            ContractValue::AclOwnerPolicy(AclOwnerPolicyValue::PreserveAsSent),
            MutationDimension::OwnerPolicy,
        ),
        ("owner_policy", "drop") => (ContractValue::AclOwnerPolicy(AclOwnerPolicyValue::Drop), MutationDimension::OwnerPolicy),
        ("delete_absent_policy", "succeed_when_configuration_absent") => (
            ContractValue::EncryptionDeleteAbsentPolicy(DeleteAbsentPolicyValue::Succeed),
            MutationDimension::DeleteAbsentPolicy,
        ),
        ("delete_absent_policy", "configuration_not_found_when_absent") => (
            ContractValue::EncryptionDeleteAbsentPolicy(DeleteAbsentPolicyValue::ConfigurationNotFound),
            MutationDimension::DeleteAbsentPolicy,
        ),
        ("conditional_value_set", "kms_key_algorithms") => (
            ContractValue::EncryptionKmsKeyAlgorithms(required_string_array(table, "contract_values", id)?),
            MutationDimension::ConditionalValueSet,
        ),
        ("enum_strictness", "closed_encryption_algorithms") => (
            ContractValue::EncryptionAlgorithmValueSet(required_string_array(table, "contract_values", id)?),
            MutationDimension::EnumStrictness,
        ),
        ("list_max", "unbounded_encryption_rules") => (ContractValue::EncryptionRuleLimit(None), MutationDimension::ListMax),
        ("list_max", "max_one_encryption_rule") => (ContractValue::EncryptionRuleLimit(Some(1)), MutationDimension::ListMax),
        ("error_secret_flow", "constant_encryption_reasons") => (
            ContractValue::EncryptionErrorSecretFlow(ErrorSecretFlowValue::ConstantReasons),
            MutationDimension::ErrorSecretFlow,
        ),
        ("error_secret_flow", "echo_encryption_rejected_value") => (
            ContractValue::EncryptionErrorSecretFlow(ErrorSecretFlowValue::EchoRejectedValue),
            MutationDimension::ErrorSecretFlow,
        ),
        ("enum_strictness", "closed_object_lock_modes") => (
            ContractValue::ObjectLockModeValueSet(required_string_array(table, "contract_values", id)?),
            MutationDimension::EnumStrictness,
        ),
        ("enum_strictness", "closed_object_lock_enabled_values") => (
            ContractValue::ObjectLockEnabledValueSet(required_string_array(table, "contract_values", id)?),
            MutationDimension::EnumStrictness,
        ),
        ("member_constraint", "default_retention") => (
            ContractValue::ObjectLockDefaultRetention {
                require_mode: required_bool(table, "contract_require_mode", id)?,
                exactly_one_period: required_bool(table, "contract_exactly_one_period", id)?,
                min_period: required_i32(table, "contract_min_period", &format!("quirk `{id}` contract rule"))?,
            },
            MutationDimension::MemberConstraint,
        ),
        ("enum_strictness", "closed_legal_hold_statuses") => (
            ContractValue::ObjectLockLegalHoldValueSet(required_string_array(table, "contract_values", id)?),
            MutationDimension::EnumStrictness,
        ),
        ("temporal_relation", "strictly_future") => (
            ContractValue::ObjectLockTemporalRelation(TemporalRelationValue::StrictlyFuture),
            MutationDimension::TemporalRelation,
        ),
        ("temporal_relation", "allow_any") => (
            ContractValue::ObjectLockTemporalRelation(TemporalRelationValue::AllowAny),
            MutationDimension::TemporalRelation,
        ),
        ("bucket_state_precondition", "require_object_lock_enabled") => (
            ContractValue::ObjectLockBucketStatePrecondition(BucketStatePreconditionValue::RequireEnabled),
            MutationDimension::BucketStatePrecondition,
        ),
        ("bucket_state_precondition", "allow_disabled_bucket") => (
            ContractValue::ObjectLockBucketStatePrecondition(BucketStatePreconditionValue::AllowDisabled),
            MutationDimension::BucketStatePrecondition,
        ),
        ("conditional_wildcard_write", "compare_and_create") => (
            ContractValue::ConditionalWildcardWrite(ConditionalWildcardWriteValue::CompareAndCreate),
            MutationDimension::ConditionalWildcardWrite,
        ),
        ("conditional_wildcard_write", "ignore") => (
            ContractValue::ConditionalWildcardWrite(ConditionalWildcardWriteValue::Ignore),
            MutationDimension::ConditionalWildcardWrite,
        ),
        ("if_match_date_precedence", "suppress_modified_since") => (
            ContractValue::IfMatchDatePrecedence(IfMatchDatePrecedenceValue::SuppressModifiedSince),
            MutationDimension::IfMatchDatePrecedence,
        ),
        ("if_match_date_precedence", "evaluate_modified_since") => (
            ContractValue::IfMatchDatePrecedence(IfMatchDatePrecedenceValue::EvaluateModifiedSince),
            MutationDimension::IfMatchDatePrecedence,
        ),
        ("if_none_date_precedence", "not_modified") => (
            ContractValue::IfNoneDatePrecedence(IfNoneDatePrecedenceValue::NotModified),
            MutationDimension::IfNoneDatePrecedence,
        ),
        ("if_none_date_precedence", "proceed") => (
            ContractValue::IfNoneDatePrecedence(IfNoneDatePrecedenceValue::Proceed),
            MutationDimension::IfNoneDatePrecedence,
        ),
        ("condition_conflict_policy", "reject") => (
            ContractValue::ConditionConflict(ConditionConflictValue::Reject),
            MutationDimension::ConditionConflictPolicy,
        ),
        ("condition_conflict_policy", "prefer_if_match") => (
            ContractValue::ConditionConflict(ConditionConflictValue::PreferIfMatch),
            MutationDimension::ConditionConflictPolicy,
        ),
        ("conditional_wildcard_parse", "accept") => (
            ContractValue::ConditionalWildcardParse(ConditionalWildcardParseValue::Accept),
            MutationDimension::ConditionalWildcardParse,
        ),
        ("conditional_wildcard_parse", "reject") => (
            ContractValue::ConditionalWildcardParse(ConditionalWildcardParseValue::Reject),
            MutationDimension::ConditionalWildcardParse,
        ),
        ("copy_validator_scope", "separate_source_and_target") => (
            ContractValue::CopyValidatorScope(CopyValidatorScopeValue::SeparateSourceAndTarget),
            MutationDimension::CopyValidatorScope,
        ),
        ("copy_validator_scope", "target_uses_source") => (
            ContractValue::CopyValidatorScope(CopyValidatorScopeValue::TargetUsesSource),
            MutationDimension::CopyValidatorScope,
        ),
        ("etag_comparison_strength", "strong") => (
            ContractValue::EtagComparisonStrength(EtagComparisonStrengthValue::Strong),
            MutationDimension::EtagComparisonStrength,
        ),
        ("etag_comparison_strength", "weak") => (
            ContractValue::EtagComparisonStrength(EtagComparisonStrengthValue::Weak),
            MutationDimension::EtagComparisonStrength,
        ),
        ("if_match_miss_outcome", "precondition_failed") => (
            ContractValue::IfMatchMissOutcome(IfMatchMissOutcomeValue::PreconditionFailed),
            MutationDimension::IfMatchMissOutcome,
        ),
        ("if_match_miss_outcome", "proceed") => (
            ContractValue::IfMatchMissOutcome(IfMatchMissOutcomeValue::Proceed),
            MutationDimension::IfMatchMissOutcome,
        ),
        ("conditional_write_order", "guard_before_mutation") => (
            ContractValue::ConditionalWriteOrder(ConditionalWriteOrderValue::GuardBeforeMutation),
            MutationDimension::ConditionalWriteOrder,
        ),
        ("conditional_write_order", "guard_after_mutation") => (
            ContractValue::ConditionalWriteOrder(ConditionalWriteOrderValue::GuardAfterMutation),
            MutationDimension::ConditionalWriteOrder,
        ),
        ("if_match_absent_policy", "precondition_failed") => (
            ContractValue::IfMatchAbsentPolicy(IfMatchAbsentPolicyValue::PreconditionFailed),
            MutationDimension::IfMatchAbsentPolicy,
        ),
        ("if_match_absent_policy", "proceed") => (
            ContractValue::IfMatchAbsentPolicy(IfMatchAbsentPolicyValue::Proceed),
            MutationDimension::IfMatchAbsentPolicy,
        ),
        ("error_root_namespace", "unnamespaced") => (
            ContractValue::ErrorRootNamespace(ErrorRootNamespaceValue::Unnamespaced),
            MutationDimension::ErrorRootNamespace,
        ),
        ("error_root_namespace", "s3") => (
            ContractValue::ErrorRootNamespace(ErrorRootNamespaceValue::S3),
            MutationDimension::ErrorRootNamespace,
        ),
        ("head_body_policy", "suppress") => (
            ContractValue::HeadBodyPolicy(HeadBodyPolicyValue::Suppress),
            MutationDimension::HeadBodyPolicy,
        ),
        ("head_body_policy", "preserve") => (
            ContractValue::HeadBodyPolicy(HeadBodyPolicyValue::Preserve),
            MutationDimension::HeadBodyPolicy,
        ),
        ("condition_failure_detail", "include_condition") => (
            ContractValue::ConditionFailureDetail(ConditionFailureDetailValue::IncludeCondition),
            MutationDimension::ConditionFailureDetail,
        ),
        ("condition_failure_detail", "omit_condition") => (
            ContractValue::ConditionFailureDetail(ConditionFailureDetailValue::OmitCondition),
            MutationDimension::ConditionFailureDetail,
        ),
        ("copy_source_if_match_miss", "precondition_failed") => (
            ContractValue::CopySourceIfMatchMiss(CopySourceIfMatchMissValue::PreconditionFailed),
            MutationDimension::CopySourceIfMatchMiss,
        ),
        ("copy_source_if_match_miss", "proceed") => (
            ContractValue::CopySourceIfMatchMiss(CopySourceIfMatchMissValue::Proceed),
            MutationDimension::CopySourceIfMatchMiss,
        ),
        ("copy_source_guard_order", "guard_before_target_write") => (
            ContractValue::CopySourceGuardOrder(CopySourceGuardOrderValue::GuardBeforeTargetWrite),
            MutationDimension::CopySourceGuardOrder,
        ),
        ("copy_source_guard_order", "target_write_before_guard") => (
            ContractValue::CopySourceGuardOrder(CopySourceGuardOrderValue::TargetWriteBeforeGuard),
            MutationDimension::CopySourceGuardOrder,
        ),
        _ => {
            return Err(Error::Overlay(format!("quirk `{id}`: unknown runtime contract `{dimension}={value}`")));
        }
    };
    Ok(Some(ContractRule {
        current,
        mutation_dimension,
    }))
}

fn required_string_array(table: &Toml, key: &str, id: &str) -> Result<Vec<String>> {
    table
        .get(key)
        .ok_or_else(|| Error::Overlay(format!("quirk `{id}` contract rule: missing `{key}`")))?
        .string_array(&format!("quirk `{id}` contract rule.{key}"))
}

fn required_bool(table: &Toml, key: &str, id: &str) -> Result<bool> {
    table
        .get(key)
        .and_then(Toml::as_bool)
        .ok_or_else(|| Error::Overlay(format!("quirk `{id}` contract rule: missing boolean `{key}`")))
}

fn required_u32(table: &Toml, key: &str, id: &str) -> Result<u32> {
    table
        .get(key)
        .and_then(Toml::as_int)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| Error::Overlay(format!("quirk `{id}` contract rule: missing non-negative integer `{key}`")))
}

fn required_i32(table: &Toml, key: &str, what: &str) -> Result<i32> {
    table
        .get(key)
        .and_then(Toml::as_int)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| Error::Overlay(format!("{what}: missing or out-of-range `{key}`")))
}
