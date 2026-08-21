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

//! Generated runtime inputs for protocol contracts implemented outside the wire codec.
//!
//! Responsible for: rendering typed contract values consumed by core runtime modules.
//! NOT responsible for: declaring contract evidence or cases. Upstream: typed overlay contract rules.
//! Downstream: `rustfs-gateway-core` contract consumers.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rustfs_gateway_model::{
    AclChannelPolicyValue, AclOwnerPolicyValue, BucketStatePreconditionValue, ConditionConflictValue,
    ConditionFailureDetailValue, ConditionalWildcardParseValue, ConditionalWildcardWriteValue, ConditionalWriteOrderValue,
    ContractRule, ContractValue, CopySourceGuardOrderValue, CopySourceIfMatchMissValue, CopyValidatorScopeValue,
    DeleteAbsentPolicyValue, ErrorRootNamespaceValue, ErrorSecretFlowValue, EtagComparisonStrengthValue, HeadBodyPolicyValue,
    IfMatchAbsentPolicyValue, IfMatchDatePrecedenceValue, IfMatchMissOutcomeValue, IfNoneDatePrecedenceValue, MutationDimension,
    TemporalRelationValue,
};

use super::dto::LICENSE;

mod cors;
mod precondition;
mod select_restore;

/// Renders the core runtime contract module.
pub fn render(rules: &BTreeMap<String, ContractRule>) -> Result<String, String> {
    let mut out = String::from(LICENSE);
    out.push_str(
        "\n// Generated runtime protocol-contract inputs.\n\n\
         use super::{AclChannelPolicy, AclErrorSecretFlowPolicy, AclOwnerPolicy, BareConditionalEtagPolicy, CompletionFailureUploadPolicy, ConditionConflictPolicy, ConditionFailureDetailPolicy, ConditionalRaceOutcomePolicy, ConditionalWildcardParsePolicy, ConditionalWildcardWritePolicy, ConditionalWriteOrderPolicy, CopyRangeLengthArithmetic, CopySourceGuardOrderPolicy, CopySourceIfMatchMissPolicy, CopyValidatorScopePolicy, DeleteAbsentPolicy, EncryptionErrorSecretFlowPolicy, ErrorRootNamespacePolicy, EtagComparisonStrengthPolicy, GranteeDiscriminatorPolicy, HeadBodyPolicy, IfMatchAbsentPolicy, IfMatchDatePrecedence, IfMatchMissOutcomePolicy, IfNoneDatePrecedence, IfNoneMatchComparisonStrengthPolicy, IfRangeMissPolicy, NotModifiedBodyPolicy, NotModifiedEtagPolicy, NotModifiedFramingPolicy, ObjectLockBucketStatePrecondition, ObjectLockTemporalRelation, PartCountHeaderPolicy, PartialChecksumPolicy, PartNumberOutcomePolicy, RangePartSelectorConflictPolicy, RangeRequestedDetailPolicy, ReadRangeLengthArithmetic, UnsatisfiableActualSizeDetailPolicy};\n\n",
    );
    out.push_str("use super::cors::*;\n\n");
    out.push_str("use super::select_restore::*;\n\n");

    let discriminator = unique(rules, MutationDimension::GranteeDiscriminatorPolicy)?;
    let value = match discriminator {
        ContractValue::GranteeTypeFromIdentifyingMember => "GranteeDiscriminatorPolicy::IdentifyingMember",
        ContractValue::GranteeTypeLeaveUnset => "GranteeDiscriminatorPolicy::LeaveUnset",
        _ => return Err(wrong_type(MutationDimension::GranteeDiscriminatorPolicy)),
    };
    writeln!(
        out,
        "/// Current ACL grantee discriminator policy.\npub(crate) const ACL_GRANTEE_DISCRIMINATOR_POLICY: GranteeDiscriminatorPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let target_sets = unique(rules, MutationDimension::TargetValueSets)?;
    let ContractValue::AclTargetValueSets { bucket, object } = target_sets else {
        return Err(wrong_type(MutationDimension::TargetValueSets));
    };
    render_str_slice(&mut out, "ACL_BUCKET_CANNED_VALUES", "Canned ACL values accepted for buckets.", bucket);
    render_str_slice(&mut out, "ACL_OBJECT_CANNED_VALUES", "Canned ACL values accepted for objects.", object);

    let channel = unique(rules, MutationDimension::AclChannelMatrix)?;
    let value = match channel {
        ContractValue::AclChannelPolicy(AclChannelPolicyValue::BodyXorHeaders) => "AclChannelPolicy::BodyXorHeaders",
        ContractValue::AclChannelPolicy(AclChannelPolicyValue::RejectMixedHeaders) => "AclChannelPolicy::RejectMixedHeaders",
        _ => return Err(wrong_type(MutationDimension::AclChannelMatrix)),
    };
    writeln!(
        out,
        "/// Current ACL input-channel matrix.\npub(crate) const ACL_CHANNEL_POLICY: AclChannelPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let secret_flow = unique_kind(rules, MutationDimension::ErrorSecretFlow, |value| {
        matches!(value, ContractValue::AclErrorSecretFlow(_))
    })?;
    let value = match secret_flow {
        ContractValue::AclErrorSecretFlow(ErrorSecretFlowValue::ConstantReasons) => "AclErrorSecretFlowPolicy::ConstantReasons",
        ContractValue::AclErrorSecretFlow(ErrorSecretFlowValue::EchoRejectedValue) => {
            "AclErrorSecretFlowPolicy::EchoRejectedValue"
        }
        _ => return Err(wrong_type(MutationDimension::ErrorSecretFlow)),
    };
    writeln!(
        out,
        "/// Current ACL error secret-flow policy.\npub(crate) const ACL_ERROR_SECRET_FLOW_POLICY: AclErrorSecretFlowPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let grammar = unique(rules, MutationDimension::GrantHeaderGrammar)?;
    let ContractValue::AclGrantHeaderGrammar {
        keys,
        case_insensitive,
        max_bytes,
        max_entries,
    } = grammar
    else {
        return Err(wrong_type(MutationDimension::GrantHeaderGrammar));
    };
    render_str_slice(&mut out, "ACL_GRANT_HEADER_KEYS", "Accepted ACL grant-header keys.", keys);
    writeln!(
        out,
        "/// Whether ACL grant-header keys ignore ASCII case.\npub(crate) const ACL_GRANT_KEYS_CASE_INSENSITIVE: bool = {case_insensitive};\n\
         /// Maximum ACL grant-header length in bytes.\npub(crate) const ACL_GRANT_HEADER_MAX_BYTES: usize = {max_bytes};\n\
         /// Maximum grantees in one ACL grant header.\npub(crate) const ACL_GRANT_HEADER_MAX_ENTRIES: usize = {max_entries};"
    )
    .expect("writing to String cannot fail");

    let permissions = unique(rules, MutationDimension::PermissionValueSet)?;
    let ContractValue::AclPermissionValueSet(values) = permissions else {
        return Err(wrong_type(MutationDimension::PermissionValueSet));
    };
    render_str_slice(&mut out, "ACL_PERMISSION_VALUES", "Accepted ACL permission values.", values);

    let owner = unique(rules, MutationDimension::OwnerPolicy)?;
    let value = match owner {
        ContractValue::AclOwnerPolicy(AclOwnerPolicyValue::PreserveAsSent) => "AclOwnerPolicy::PreserveAsSent",
        ContractValue::AclOwnerPolicy(AclOwnerPolicyValue::Drop) => "AclOwnerPolicy::Drop",
        _ => return Err(wrong_type(MutationDimension::OwnerPolicy)),
    };
    writeln!(
        out,
        "/// Current ACL owner policy.\npub(crate) const ACL_OWNER_POLICY: AclOwnerPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let delete_absent = unique(rules, MutationDimension::DeleteAbsentPolicy)?;
    let value = match delete_absent {
        ContractValue::EncryptionDeleteAbsentPolicy(DeleteAbsentPolicyValue::Succeed) => "DeleteAbsentPolicy::Succeed",
        ContractValue::EncryptionDeleteAbsentPolicy(DeleteAbsentPolicyValue::ConfigurationNotFound) => {
            "DeleteAbsentPolicy::ConfigurationNotFound"
        }
        _ => return Err(wrong_type(MutationDimension::DeleteAbsentPolicy)),
    };
    writeln!(
        out,
        "/// Current absent-encryption delete policy.\npub(crate) const ENCRYPTION_DELETE_ABSENT_POLICY: DeleteAbsentPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let kms_algorithms = unique(rules, MutationDimension::ConditionalValueSet)?;
    let ContractValue::EncryptionKmsKeyAlgorithms(values) = kms_algorithms else {
        return Err(wrong_type(MutationDimension::ConditionalValueSet));
    };
    render_str_slice(
        &mut out,
        "ENCRYPTION_KMS_KEY_ALGORITHMS",
        "Algorithms that accept an encryption KMS key id.",
        values,
    );

    let algorithms = unique_kind(rules, MutationDimension::EnumStrictness, |value| {
        matches!(value, ContractValue::EncryptionAlgorithmValueSet(_))
    })?;
    let ContractValue::EncryptionAlgorithmValueSet(values) = algorithms else {
        return Err(wrong_type(MutationDimension::EnumStrictness));
    };
    render_str_slice(&mut out, "ENCRYPTION_ALGORITHMS", "Accepted default-encryption algorithms.", values);

    let rule_limit = unique(rules, MutationDimension::ListMax)?;
    let ContractValue::EncryptionRuleLimit(max) = rule_limit else {
        return Err(wrong_type(MutationDimension::ListMax));
    };
    let value = max.map_or_else(|| "None".to_owned(), |max| format!("Some({max})"));
    writeln!(
        out,
        "/// Maximum encryption rules, or no bound.\npub(crate) const ENCRYPTION_RULE_MAX: Option<usize> = {value};"
    )
    .expect("writing to String cannot fail");

    let secret_flow = unique_kind(rules, MutationDimension::ErrorSecretFlow, |value| {
        matches!(value, ContractValue::EncryptionErrorSecretFlow(_))
    })?;
    let value = match secret_flow {
        ContractValue::EncryptionErrorSecretFlow(ErrorSecretFlowValue::ConstantReasons) => {
            "EncryptionErrorSecretFlowPolicy::ConstantReasons"
        }
        ContractValue::EncryptionErrorSecretFlow(ErrorSecretFlowValue::EchoRejectedValue) => {
            "EncryptionErrorSecretFlowPolicy::EchoRejectedValue"
        }
        _ => return Err(wrong_type(MutationDimension::ErrorSecretFlow)),
    };
    writeln!(
        out,
        "/// Current encryption error secret-flow policy.\npub(crate) const ENCRYPTION_ERROR_SECRET_FLOW_POLICY: EncryptionErrorSecretFlowPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let modes = unique_kind(rules, MutationDimension::EnumStrictness, |value| {
        matches!(value, ContractValue::ObjectLockModeValueSet(_))
    })?;
    let ContractValue::ObjectLockModeValueSet(values) = modes else {
        return Err(wrong_type(MutationDimension::EnumStrictness));
    };
    render_str_slice(&mut out, "OBJECT_LOCK_MODE_VALUES", "Accepted object-lock retention modes.", values);

    let enabled = unique_kind(rules, MutationDimension::EnumStrictness, |value| {
        matches!(value, ContractValue::ObjectLockEnabledValueSet(_))
    })?;
    let ContractValue::ObjectLockEnabledValueSet(values) = enabled else {
        return Err(wrong_type(MutationDimension::EnumStrictness));
    };
    render_str_slice(&mut out, "OBJECT_LOCK_ENABLED_VALUES", "Accepted ObjectLockEnabled values.", values);

    let default = unique(rules, MutationDimension::MemberConstraint)?;
    let ContractValue::ObjectLockDefaultRetention {
        require_mode,
        exactly_one_period,
        min_period,
    } = default
    else {
        return Err(wrong_type(MutationDimension::MemberConstraint));
    };
    writeln!(
        out,
        "/// Whether default retention requires Mode.\npub(crate) const OBJECT_LOCK_DEFAULT_REQUIRE_MODE: bool = {require_mode};\n\
         /// Whether default retention requires exactly one period.\npub(crate) const OBJECT_LOCK_DEFAULT_EXACTLY_ONE_PERIOD: bool = {exactly_one_period};\n\
         /// Inclusive minimum default-retention period.\npub(crate) const OBJECT_LOCK_DEFAULT_MIN_PERIOD: i32 = {min_period};"
    )
    .expect("writing to String cannot fail");

    let statuses = unique_kind(rules, MutationDimension::EnumStrictness, |value| {
        matches!(value, ContractValue::ObjectLockLegalHoldValueSet(_))
    })?;
    let ContractValue::ObjectLockLegalHoldValueSet(values) = statuses else {
        return Err(wrong_type(MutationDimension::EnumStrictness));
    };
    render_str_slice(
        &mut out,
        "OBJECT_LOCK_LEGAL_HOLD_VALUES",
        "Accepted object-lock legal-hold statuses.",
        values,
    );

    let temporal = unique(rules, MutationDimension::TemporalRelation)?;
    let value = match temporal {
        ContractValue::ObjectLockTemporalRelation(TemporalRelationValue::StrictlyFuture) => {
            "ObjectLockTemporalRelation::StrictlyFuture"
        }
        ContractValue::ObjectLockTemporalRelation(TemporalRelationValue::AllowAny) => "ObjectLockTemporalRelation::AllowAny",
        _ => return Err(wrong_type(MutationDimension::TemporalRelation)),
    };
    writeln!(
        out,
        "/// Current object-lock retain-until relationship.\npub(crate) const OBJECT_LOCK_TEMPORAL_RELATION: ObjectLockTemporalRelation = {value};"
    )
    .expect("writing to String cannot fail");

    let bucket = unique(rules, MutationDimension::BucketStatePrecondition)?;
    let value = match bucket {
        ContractValue::ObjectLockBucketStatePrecondition(BucketStatePreconditionValue::RequireEnabled) => {
            "ObjectLockBucketStatePrecondition::RequireEnabled"
        }
        ContractValue::ObjectLockBucketStatePrecondition(BucketStatePreconditionValue::AllowDisabled) => {
            "ObjectLockBucketStatePrecondition::AllowDisabled"
        }
        _ => return Err(wrong_type(MutationDimension::BucketStatePrecondition)),
    };
    writeln!(
        out,
        "/// Current bucket-state precondition for object-level lock writes.\npub(crate) const OBJECT_LOCK_BUCKET_STATE_PRECONDITION: ObjectLockBucketStatePrecondition = {value};"
    )
    .expect("writing to String cannot fail");

    let wildcard_write = unique(rules, MutationDimension::ConditionalWildcardWrite)?;
    let value = match wildcard_write {
        ContractValue::ConditionalWildcardWrite(ConditionalWildcardWriteValue::CompareAndCreate) => {
            "ConditionalWildcardWritePolicy::CompareAndCreate"
        }
        ContractValue::ConditionalWildcardWrite(ConditionalWildcardWriteValue::Ignore) => {
            "ConditionalWildcardWritePolicy::Ignore"
        }
        _ => return Err(wrong_type(MutationDimension::ConditionalWildcardWrite)),
    };
    writeln!(
        out,
        "/// Current conditional-write wildcard policy.\npub(crate) const CONDITIONAL_WILDCARD_WRITE_POLICY: ConditionalWildcardWritePolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let if_match_date = unique(rules, MutationDimension::IfMatchDatePrecedence)?;
    let value = match if_match_date {
        ContractValue::IfMatchDatePrecedence(IfMatchDatePrecedenceValue::SuppressModifiedSince) => {
            "IfMatchDatePrecedence::SuppressModifiedSince"
        }
        ContractValue::IfMatchDatePrecedence(IfMatchDatePrecedenceValue::EvaluateModifiedSince) => {
            "IfMatchDatePrecedence::EvaluateModifiedSince"
        }
        _ => return Err(wrong_type(MutationDimension::IfMatchDatePrecedence)),
    };
    writeln!(
        out,
        "/// Current If-Match/date precedence.\npub(crate) const IF_MATCH_DATE_PRECEDENCE: IfMatchDatePrecedence = {value};"
    )
    .expect("writing to String cannot fail");

    let if_none_date = unique(rules, MutationDimension::IfNoneDatePrecedence)?;
    let value = match if_none_date {
        ContractValue::IfNoneDatePrecedence(IfNoneDatePrecedenceValue::NotModified) => "IfNoneDatePrecedence::NotModified",
        ContractValue::IfNoneDatePrecedence(IfNoneDatePrecedenceValue::Proceed) => "IfNoneDatePrecedence::Proceed",
        _ => return Err(wrong_type(MutationDimension::IfNoneDatePrecedence)),
    };
    writeln!(
        out,
        "/// Current If-None-Match/date precedence.\npub(crate) const IF_NONE_DATE_PRECEDENCE: IfNoneDatePrecedence = {value};"
    )
    .expect("writing to String cannot fail");

    let conflict = unique(rules, MutationDimension::ConditionConflictPolicy)?;
    let value = match conflict {
        ContractValue::ConditionConflict(ConditionConflictValue::Reject) => "ConditionConflictPolicy::Reject",
        ContractValue::ConditionConflict(ConditionConflictValue::PreferIfMatch) => "ConditionConflictPolicy::PreferIfMatch",
        _ => return Err(wrong_type(MutationDimension::ConditionConflictPolicy)),
    };
    writeln!(
        out,
        "/// Current conflicting-condition policy.\npub(crate) const CONDITION_CONFLICT_POLICY: ConditionConflictPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let wildcard_parse = unique(rules, MutationDimension::ConditionalWildcardParse)?;
    let value = match wildcard_parse {
        ContractValue::ConditionalWildcardParse(ConditionalWildcardParseValue::Accept) => {
            "ConditionalWildcardParsePolicy::Accept"
        }
        ContractValue::ConditionalWildcardParse(ConditionalWildcardParseValue::Reject) => {
            "ConditionalWildcardParsePolicy::Reject"
        }
        _ => return Err(wrong_type(MutationDimension::ConditionalWildcardParse)),
    };
    writeln!(
        out,
        "/// Current conditional wildcard parse policy.\npub(crate) const CONDITIONAL_WILDCARD_PARSE_POLICY: ConditionalWildcardParsePolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let copy_scope = unique(rules, MutationDimension::CopyValidatorScope)?;
    let value = match copy_scope {
        ContractValue::CopyValidatorScope(CopyValidatorScopeValue::SeparateSourceAndTarget) => {
            "CopyValidatorScopePolicy::SeparateSourceAndTarget"
        }
        ContractValue::CopyValidatorScope(CopyValidatorScopeValue::TargetUsesSource) => {
            "CopyValidatorScopePolicy::TargetUsesSource"
        }
        _ => return Err(wrong_type(MutationDimension::CopyValidatorScope)),
    };
    writeln!(
        out,
        "/// Current CopyObject validator scope.\npub(crate) const COPY_VALIDATOR_SCOPE_POLICY: CopyValidatorScopePolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let comparison = unique(rules, MutationDimension::EtagComparisonStrength)?;
    let value = match comparison {
        ContractValue::EtagComparisonStrength(EtagComparisonStrengthValue::Strong) => "EtagComparisonStrengthPolicy::Strong",
        ContractValue::EtagComparisonStrength(EtagComparisonStrengthValue::Weak) => "EtagComparisonStrengthPolicy::Weak",
        _ => return Err(wrong_type(MutationDimension::EtagComparisonStrength)),
    };
    writeln!(
        out,
        "/// Current If-Match comparison strength.\npub(crate) const IF_MATCH_COMPARISON_STRENGTH: EtagComparisonStrengthPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let miss = unique(rules, MutationDimension::IfMatchMissOutcome)?;
    let value = match miss {
        ContractValue::IfMatchMissOutcome(IfMatchMissOutcomeValue::PreconditionFailed) => {
            "IfMatchMissOutcomePolicy::PreconditionFailed"
        }
        ContractValue::IfMatchMissOutcome(IfMatchMissOutcomeValue::Proceed) => "IfMatchMissOutcomePolicy::Proceed",
        _ => return Err(wrong_type(MutationDimension::IfMatchMissOutcome)),
    };
    writeln!(
        out,
        "/// Current outcome of a named If-Match miss.\npub(crate) const IF_MATCH_MISS_OUTCOME: IfMatchMissOutcomePolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let write_order = unique(rules, MutationDimension::ConditionalWriteOrder)?;
    let value = match write_order {
        ContractValue::ConditionalWriteOrder(ConditionalWriteOrderValue::GuardBeforeMutation) => {
            "ConditionalWriteOrderPolicy::GuardBeforeMutation"
        }
        ContractValue::ConditionalWriteOrder(ConditionalWriteOrderValue::GuardAfterMutation) => {
            "ConditionalWriteOrderPolicy::GuardAfterMutation"
        }
        _ => return Err(wrong_type(MutationDimension::ConditionalWriteOrder)),
    };
    writeln!(
        out,
        "/// Current conditional-write guard placement.\npub(crate) const CONDITIONAL_WRITE_ORDER: ConditionalWriteOrderPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let absent = unique(rules, MutationDimension::IfMatchAbsentPolicy)?;
    let value = match absent {
        ContractValue::IfMatchAbsentPolicy(IfMatchAbsentPolicyValue::PreconditionFailed) => {
            "IfMatchAbsentPolicy::PreconditionFailed"
        }
        ContractValue::IfMatchAbsentPolicy(IfMatchAbsentPolicyValue::Proceed) => "IfMatchAbsentPolicy::Proceed",
        _ => return Err(wrong_type(MutationDimension::IfMatchAbsentPolicy)),
    };
    writeln!(
        out,
        "/// Current outcome of If-Match against an absent representation.\npub(crate) const IF_MATCH_ABSENT_POLICY: IfMatchAbsentPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let namespace = unique(rules, MutationDimension::ErrorRootNamespace)?;
    let value = match namespace {
        ContractValue::ErrorRootNamespace(ErrorRootNamespaceValue::Unnamespaced) => "ErrorRootNamespacePolicy::Unnamespaced",
        ContractValue::ErrorRootNamespace(ErrorRootNamespaceValue::S3) => "ErrorRootNamespacePolicy::S3",
        _ => return Err(wrong_type(MutationDimension::ErrorRootNamespace)),
    };
    writeln!(
        out,
        "/// Current namespace policy for S3 error roots.\npub(crate) const ERROR_ROOT_NAMESPACE_POLICY: ErrorRootNamespacePolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let head = unique(rules, MutationDimension::HeadBodyPolicy)?;
    let value = match head {
        ContractValue::HeadBodyPolicy(HeadBodyPolicyValue::Suppress) => "HeadBodyPolicy::Suppress",
        ContractValue::HeadBodyPolicy(HeadBodyPolicyValue::Preserve) => "HeadBodyPolicy::Preserve",
        _ => return Err(wrong_type(MutationDimension::HeadBodyPolicy)),
    };
    writeln!(
        out,
        "/// Current HEAD response-body policy.\npub(crate) const HEAD_BODY_POLICY: HeadBodyPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let detail = unique(rules, MutationDimension::ConditionFailureDetail)?;
    let value = match detail {
        ContractValue::ConditionFailureDetail(ConditionFailureDetailValue::IncludeCondition) => {
            "ConditionFailureDetailPolicy::IncludeCondition"
        }
        ContractValue::ConditionFailureDetail(ConditionFailureDetailValue::OmitCondition) => {
            "ConditionFailureDetailPolicy::OmitCondition"
        }
        _ => return Err(wrong_type(MutationDimension::ConditionFailureDetail)),
    };
    writeln!(
        out,
        "/// Current precondition-failure detail policy.\npub(crate) const CONDITION_FAILURE_DETAIL_POLICY: ConditionFailureDetailPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let source_miss = unique(rules, MutationDimension::CopySourceIfMatchMiss)?;
    let value = match source_miss {
        ContractValue::CopySourceIfMatchMiss(CopySourceIfMatchMissValue::PreconditionFailed) => {
            "CopySourceIfMatchMissPolicy::PreconditionFailed"
        }
        ContractValue::CopySourceIfMatchMiss(CopySourceIfMatchMissValue::Proceed) => "CopySourceIfMatchMissPolicy::Proceed",
        _ => return Err(wrong_type(MutationDimension::CopySourceIfMatchMiss)),
    };
    writeln!(
        out,
        "/// Current copy-source If-Match miss policy.\npub(crate) const COPY_SOURCE_IF_MATCH_MISS_POLICY: CopySourceIfMatchMissPolicy = {value};"
    )
    .expect("writing to String cannot fail");

    let source_order = unique(rules, MutationDimension::CopySourceGuardOrder)?;
    let value = match source_order {
        ContractValue::CopySourceGuardOrder(CopySourceGuardOrderValue::GuardBeforeTargetWrite) => {
            "CopySourceGuardOrderPolicy::GuardBeforeTargetWrite"
        }
        ContractValue::CopySourceGuardOrder(CopySourceGuardOrderValue::TargetWriteBeforeGuard) => {
            "CopySourceGuardOrderPolicy::TargetWriteBeforeGuard"
        }
        _ => return Err(wrong_type(MutationDimension::CopySourceGuardOrder)),
    };
    writeln!(
        out,
        "/// Current copy-source guard placement.\npub(crate) const COPY_SOURCE_GUARD_ORDER_POLICY: CopySourceGuardOrderPolicy = {value};"
    )
    .expect("writing to String cannot fail");
    precondition::render(rules, &mut out)?;
    cors::render(rules, &mut out)?;
    select_restore::render(rules, &mut out)?;
    Ok(out)
}

/// Renders the signature crate's generated canonicalization inputs.
pub fn render_signature(rules: &BTreeMap<String, ContractRule>) -> Result<String, String> {
    let mut out = String::from(LICENSE);
    out.push_str("\n// Generated signature protocol-contract inputs.\n\n");
    let host = unique(rules, MutationDimension::SignatureCanonicalHostPolicy)?;
    let ContractValue::SignaturePolicy(host) = host else {
        return Err(wrong_type(MutationDimension::SignatureCanonicalHostPolicy));
    };
    writeln!(
        out,
        "/// Whether canonical signing keeps the effective host's wire spelling.\npub(crate) const SIGNATURE_CANONICAL_HOST_RAW: bool = {host};"
    )
    .expect("writing to String cannot fail");

    let path = unique(rules, MutationDimension::SignaturePathFallbackPolicy)?;
    let ContractValue::SignaturePolicy(path) = path else {
        return Err(wrong_type(MutationDimension::SignaturePathFallbackPolicy));
    };
    writeln!(
        out,
        "/// Whether verification retains the original wire path as its second candidate.\npub(crate) const SIGNATURE_RAW_PATH_FALLBACK: bool = {path};"
    )
    .expect("writing to String cannot fail");

    let payload = unique(rules, MutationDimension::SignaturePayloadTokenPolicy)?;
    let ContractValue::SignaturePolicy(payload) = payload else {
        return Err(wrong_type(MutationDimension::SignaturePayloadTokenPolicy));
    };
    writeln!(
        out,
        "/// Whether canonical signing keeps the client's accepted payload token spelling.\npub(crate) const SIGNATURE_PAYLOAD_TOKEN_VERBATIM: bool = {payload};"
    )
    .expect("writing to String cannot fail");

    let included_query = unique(rules, MutationDimension::SigV2IncludedQueryPolicy)?;
    let ContractValue::SignaturePolicy(included_query) = included_query else {
        return Err(wrong_type(MutationDimension::SigV2IncludedQueryPolicy));
    };
    writeln!(
        out,
        "/// Whether SigV2 canonical resources include the reviewed subresource allowlist.\npub(crate) const SIGV2_INCLUDED_QUERY: bool = {included_query};"
    )
    .expect("writing to String cannot fail");

    let empty_date = unique(rules, MutationDimension::SigV2DateSlotPolicy)?;
    let ContractValue::SignaturePolicy(empty_date) = empty_date else {
        return Err(wrong_type(MutationDimension::SigV2DateSlotPolicy));
    };
    writeln!(
        out,
        "/// Whether SigV2 empties the Date slot when x-amz-date is present.\npub(crate) const SIGV2_EMPTY_DATE_ON_AMZ_DATE: bool = {empty_date};"
    )
    .expect("writing to String cannot fail");

    let expires_absolute = unique(rules, MutationDimension::SigV2ExpiresAbsolutePolicy)?;
    let ContractValue::SignaturePolicy(expires_absolute) = expires_absolute else {
        return Err(wrong_type(MutationDimension::SigV2ExpiresAbsolutePolicy));
    };
    writeln!(
        out,
        "/// Whether SigV2 presigned Expires is an absolute Unix second.\npub(crate) const SIGV2_EXPIRES_ABSOLUTE: bool = {expires_absolute};"
    )
    .expect("writing to String cannot fail");

    let query_not_covered = unique(rules, MutationDimension::SigV2QueryCoveragePolicy)?;
    let ContractValue::SignaturePolicy(query_not_covered) = query_not_covered else {
        return Err(wrong_type(MutationDimension::SigV2QueryCoveragePolicy));
    };
    writeln!(
        out,
        "/// Whether SigV2 omits arbitrary query parameters from its canonical resource.\npub(crate) const SIGV2_QUERY_NOT_COVERED: bool = {query_not_covered};"
    )
    .expect("writing to String cannot fail");
    Ok(out)
}

pub(super) fn unique(rules: &BTreeMap<String, ContractRule>, dimension: MutationDimension) -> Result<&ContractValue, String> {
    let mut matching = rules.values().filter(|rule| rule.mutation_dimension == dimension);
    let current = matching
        .next()
        .map(|rule| &rule.current)
        .ok_or_else(|| format!("runtime contracts: `{}` is missing its typed input", dimension.as_str()))?;
    if matching.next().is_some() {
        return Err(format!("runtime contracts: `{}` has more than one typed input", dimension.as_str()));
    }
    Ok(current)
}

fn unique_kind(
    rules: &BTreeMap<String, ContractRule>,
    dimension: MutationDimension,
    accepts: fn(&ContractValue) -> bool,
) -> Result<&ContractValue, String> {
    let mut matching = rules
        .values()
        .filter(|rule| rule.mutation_dimension == dimension && accepts(&rule.current));
    let current = matching
        .next()
        .map(|rule| &rule.current)
        .ok_or_else(|| format!("runtime contracts: `{}` is missing its typed input", dimension.as_str()))?;
    if matching.next().is_some() {
        return Err(format!(
            "runtime contracts: `{}` has duplicate typed inputs for one consumer",
            dimension.as_str()
        ));
    }
    Ok(current)
}

pub(super) fn wrong_type(dimension: MutationDimension) -> String {
    format!("runtime contracts: `{}` carries the wrong typed value", dimension.as_str())
}

fn render_str_slice(out: &mut String, name: &str, doc: &str, values: &[String]) {
    let values = values.iter().map(|value| format!("{value:?}")).collect::<Vec<_>>().join(", ");
    writeln!(out, "/// {doc}\npub(crate) const {name}: &[&str] = &[{values}];").expect("writing to String cannot fail");
}
