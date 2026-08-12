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

//! Mutation checks for typed runtime contract inputs.
//!
//! Responsible for: proving one changed typed value changes generated runtime data.
//! NOT responsible for: running the corresponding conformance case. Upstream: generated artifacts.
//! Downstream: the codegen test gate.

use rustfs_gateway_model::{
    BucketStatePreconditionValue, ConditionConflictValue, ConditionFailureDetailValue, ConditionalWildcardParseValue,
    ConditionalWildcardWriteValue, ConditionalWriteOrderValue, ContractValue, CopySourceGuardOrderValue,
    CopySourceIfMatchMissValue, CopyValidatorScopeValue, DeleteAbsentPolicyValue, ErrorRootNamespaceValue, ErrorSecretFlowValue,
    EtagComparisonStrengthValue, HeadBodyPolicyValue, IfMatchAbsentPolicyValue, IfMatchDatePrecedenceValue,
    IfMatchMissOutcomeValue, IfNoneDatePrecedenceValue, MutationDimension, TemporalRelationValue,
};

use super::codegen_tests::artifacts;

#[test]
fn encryption_runtime_contracts_each_change_the_generated_consumer_input() {
    let rules = artifacts().contract_rules;
    let current = crate::emit::runtime_contracts::render(&rules).expect("the current runtime contracts render");

    let mut deletion = rules.clone();
    deletion
        .values_mut()
        .find(|rule| rule.mutation_dimension == MutationDimension::DeleteAbsentPolicy)
        .expect("the absent-delete rule exists")
        .current = ContractValue::EncryptionDeleteAbsentPolicy(DeleteAbsentPolicyValue::ConfigurationNotFound);
    assert!(
        crate::emit::runtime_contracts::render(&deletion)
            .expect("the absent-delete mutant renders")
            .contains("DeleteAbsentPolicy::ConfigurationNotFound")
    );

    let mut kms = rules.clone();
    let rule = kms
        .values_mut()
        .find(|rule| rule.mutation_dimension == MutationDimension::ConditionalValueSet)
        .expect("the KMS conditional set exists");
    let ContractValue::EncryptionKmsKeyAlgorithms(values) = &mut rule.current else {
        panic!("the KMS conditional dimension carries its typed value");
    };
    values.retain(|value| value != "aws:kms");
    let mutant = crate::emit::runtime_contracts::render(&kms).expect("the KMS conditional mutant renders");
    assert!(current.contains("ENCRYPTION_KMS_KEY_ALGORITHMS"));
    assert!(!mutant.contains("ENCRYPTION_KMS_KEY_ALGORITHMS: &[&str] = &[\"aws:kms\","));

    let mut algorithms = rules.clone();
    let rule = algorithms
        .values_mut()
        .find(|rule| rule.mutation_dimension == MutationDimension::EnumStrictness)
        .expect("the encryption algorithm set exists");
    let ContractValue::EncryptionAlgorithmValueSet(values) = &mut rule.current else {
        panic!("the enum strictness dimension carries its typed value");
    };
    values.retain(|value| value != "aws:fsx");
    let mutant = crate::emit::runtime_contracts::render(&algorithms).expect("the algorithm-set mutant renders");
    assert!(current.contains("aws:fsx"));
    assert!(!mutant.contains("aws:fsx"));

    let mut limit = rules.clone();
    limit
        .values_mut()
        .find(|rule| rule.mutation_dimension == MutationDimension::ListMax)
        .expect("the encryption list limit exists")
        .current = ContractValue::EncryptionRuleLimit(Some(1));
    assert!(
        crate::emit::runtime_contracts::render(&limit)
            .expect("the list-limit mutant renders")
            .contains("ENCRYPTION_RULE_MAX: Option<usize> = Some(1)")
    );

    let mut secret = rules;
    secret
        .values_mut()
        .find(|rule| matches!(rule.current, ContractValue::EncryptionErrorSecretFlow(_)))
        .expect("the encryption error secret-flow rule exists")
        .current = ContractValue::EncryptionErrorSecretFlow(ErrorSecretFlowValue::EchoRejectedValue);
    assert!(
        crate::emit::runtime_contracts::render(&secret)
            .expect("the encryption secret-flow mutant renders")
            .contains("EncryptionErrorSecretFlowPolicy::EchoRejectedValue")
    );
}

#[test]
fn object_lock_runtime_contracts_each_change_the_generated_consumer_input() {
    let rules = artifacts().contract_rules;
    let current = crate::emit::runtime_contracts::render(&rules).expect("the current runtime contracts render");
    assert!(current.contains("OBJECT_LOCK_MODE_VALUES"));
    assert!(current.contains("OBJECT_LOCK_ENABLED_VALUES"));
    assert!(current.contains("OBJECT_LOCK_LEGAL_HOLD_VALUES"));
    assert!(current.contains("OBJECT_LOCK_DEFAULT_MIN_PERIOD: i32 = 1"));
    assert!(current.contains("ObjectLockTemporalRelation::StrictlyFuture"));
    assert!(current.contains("ObjectLockBucketStatePrecondition::RequireEnabled"));

    let mut modes = rules.clone();
    let rule = modes
        .values_mut()
        .find(|rule| matches!(rule.current, ContractValue::ObjectLockModeValueSet(_)))
        .expect("the object-lock mode rule exists");
    rule.current = ContractValue::ObjectLockModeValueSet(vec!["COMPLIANCE".to_owned()]);
    assert!(
        !crate::emit::runtime_contracts::render(&modes)
            .expect("the mode mutant renders")
            .contains("GOVERNANCE")
    );

    let mut enabled = rules.clone();
    let rule = enabled
        .values_mut()
        .find(|rule| matches!(rule.current, ContractValue::ObjectLockEnabledValueSet(_)))
        .expect("the object-lock enabled rule exists");
    rule.current = ContractValue::ObjectLockEnabledValueSet(vec!["Enabled".to_owned(), "Disabled".to_owned()]);
    assert!(
        crate::emit::runtime_contracts::render(&enabled)
            .expect("the enabled mutant renders")
            .contains("Disabled")
    );

    let mut default = rules.clone();
    let rule = default
        .values_mut()
        .find(|rule| matches!(rule.current, ContractValue::ObjectLockDefaultRetention { .. }))
        .expect("the default-retention rule exists");
    rule.current = ContractValue::ObjectLockDefaultRetention {
        require_mode: true,
        exactly_one_period: true,
        min_period: 0,
    };
    assert!(
        crate::emit::runtime_contracts::render(&default)
            .expect("the default mutant renders")
            .contains("MIN_PERIOD: i32 = 0")
    );

    let mut hold = rules.clone();
    let rule = hold
        .values_mut()
        .find(|rule| matches!(rule.current, ContractValue::ObjectLockLegalHoldValueSet(_)))
        .expect("the legal-hold rule exists");
    rule.current = ContractValue::ObjectLockLegalHoldValueSet(vec!["ON".to_owned(), "OFF".to_owned(), "on".to_owned()]);
    assert!(
        crate::emit::runtime_contracts::render(&hold)
            .expect("the legal-hold mutant renders")
            .contains("\"on\"")
    );

    let mut temporal = rules.clone();
    temporal
        .values_mut()
        .find(|rule| matches!(rule.current, ContractValue::ObjectLockTemporalRelation(_)))
        .expect("the temporal rule exists")
        .current = ContractValue::ObjectLockTemporalRelation(TemporalRelationValue::AllowAny);
    assert!(
        crate::emit::runtime_contracts::render(&temporal)
            .expect("the temporal mutant renders")
            .contains("ObjectLockTemporalRelation::AllowAny")
    );

    let mut bucket = rules;
    bucket
        .values_mut()
        .find(|rule| matches!(rule.current, ContractValue::ObjectLockBucketStatePrecondition(_)))
        .expect("the bucket-state rule exists")
        .current = ContractValue::ObjectLockBucketStatePrecondition(BucketStatePreconditionValue::AllowDisabled);
    assert!(
        crate::emit::runtime_contracts::render(&bucket)
            .expect("the bucket-state mutant renders")
            .contains("ObjectLockBucketStatePrecondition::AllowDisabled")
    );
}

#[test]
fn conditional_runtime_contracts_each_change_the_generated_consumer_input() {
    let rules = artifacts().contract_rules;

    let mutants = [
        (
            "q-cond-0041",
            ContractValue::ConditionalWildcardWrite(ConditionalWildcardWriteValue::Ignore),
            "ConditionalWildcardWritePolicy::Ignore",
        ),
        (
            "q-cond-0042",
            ContractValue::IfMatchDatePrecedence(IfMatchDatePrecedenceValue::EvaluateModifiedSince),
            "IfMatchDatePrecedence::EvaluateModifiedSince",
        ),
        (
            "q-cond-0043",
            ContractValue::IfNoneDatePrecedence(IfNoneDatePrecedenceValue::Proceed),
            "IfNoneDatePrecedence::Proceed",
        ),
        (
            "q-cond-0044",
            ContractValue::ConditionConflict(ConditionConflictValue::PreferIfMatch),
            "ConditionConflictPolicy::PreferIfMatch",
        ),
        (
            "q-cond-0045",
            ContractValue::ConditionalWildcardParse(ConditionalWildcardParseValue::Reject),
            "ConditionalWildcardParsePolicy::Reject",
        ),
        (
            "q-cond-copy-validator-scope-0107",
            ContractValue::CopyValidatorScope(CopyValidatorScopeValue::TargetUsesSource),
            "CopyValidatorScopePolicy::TargetUsesSource",
        ),
        (
            "q-cond-0046",
            ContractValue::EtagComparisonStrength(EtagComparisonStrengthValue::Weak),
            "EtagComparisonStrengthPolicy::Weak",
        ),
        (
            "q-cond-if-match-miss-0108",
            ContractValue::IfMatchMissOutcome(IfMatchMissOutcomeValue::Proceed),
            "IfMatchMissOutcomePolicy::Proceed",
        ),
        (
            "q-cond-write-order-0096",
            ContractValue::ConditionalWriteOrder(ConditionalWriteOrderValue::GuardAfterMutation),
            "ConditionalWriteOrderPolicy::GuardAfterMutation",
        ),
        (
            "q-cond-if-match-absent-0109",
            ContractValue::IfMatchAbsentPolicy(IfMatchAbsentPolicyValue::Proceed),
            "IfMatchAbsentPolicy::Proceed",
        ),
        (
            "q-error-root-unnamespaced-0110",
            ContractValue::ErrorRootNamespace(ErrorRootNamespaceValue::S3),
            "ErrorRootNamespacePolicy::S3",
        ),
        (
            "q-head-bodyless-0111",
            ContractValue::HeadBodyPolicy(HeadBodyPolicyValue::Preserve),
            "HeadBodyPolicy::Preserve",
        ),
        (
            "q-cond-failure-detail-0112",
            ContractValue::ConditionFailureDetail(ConditionFailureDetailValue::OmitCondition),
            "ConditionFailureDetailPolicy::OmitCondition",
        ),
        (
            "q-copy-source-if-match-miss-0113",
            ContractValue::CopySourceIfMatchMiss(CopySourceIfMatchMissValue::Proceed),
            "CopySourceIfMatchMissPolicy::Proceed",
        ),
        (
            "q-copy-source-guard-order-0114",
            ContractValue::CopySourceGuardOrder(CopySourceGuardOrderValue::TargetWriteBeforeGuard),
            "CopySourceGuardOrderPolicy::TargetWriteBeforeGuard",
        ),
    ];
    for (id, current, rendered) in mutants {
        let mut mutant = rules.clone();
        mutant.get_mut(id).expect("the conditional rule exists").current = current;
        assert!(
            crate::emit::runtime_contracts::render(&mutant)
                .expect("the conditional mutant renders")
                .contains(rendered),
            "{id} did not change its generated consumer input"
        );
    }
}

#[test]
fn precondition_contracts_have_one_typed_source_and_emit_every_consumer_input() {
    let rules = artifacts().contract_rules;
    let dimensions = [
        MutationDimension::NotModifiedEtagPolicy,
        MutationDimension::CompletionFailureUploadPolicy,
        MutationDimension::ConditionalRaceOutcome,
        MutationDimension::MultiRangePolicy,
        MutationDimension::ExplicitEndOverflowPolicy,
        MutationDimension::SuffixRangePolicy,
        MutationDimension::OversizeSuffixPolicy,
        MutationDimension::UnsatisfiableActualSizeDetail,
        MutationDimension::PartialChecksumPolicy,
        MutationDimension::PartNumberOutcome,
        MutationDimension::InvalidRangePolicy,
        MutationDimension::IfRangeMissPolicy,
        MutationDimension::IfNoneMatchComparisonStrength,
        MutationDimension::BareConditionalEtagPolicy,
        MutationDimension::NotModifiedBodyPolicy,
        MutationDimension::NotModifiedFramingPolicy,
        MutationDimension::RangeStartBound,
        MutationDimension::OpenEndedRangePolicy,
        MutationDimension::ReadRangeLengthArithmetic,
        MutationDimension::CopyRangeLengthArithmetic,
        MutationDimension::RangeRequestedDetail,
        MutationDimension::PartCountHeaderPolicy,
        MutationDimension::RangePartSelectorConflict,
    ];
    for dimension in dimensions {
        assert_eq!(
            rules.values().filter(|rule| rule.mutation_dimension == dimension).count(),
            1,
            "{} must have one typed source",
            dimension.as_str()
        );
    }

    let core = crate::emit::runtime_contracts::render(&rules).expect("the core precondition inputs render");
    for name in [
        "NOT_MODIFIED_ETAG_POLICY",
        "COMPLETION_FAILURE_UPLOAD_POLICY",
        "CONDITIONAL_RACE_OUTCOME_POLICY",
        "UNSATISFIABLE_ACTUAL_SIZE_DETAIL_POLICY",
        "PARTIAL_CHECKSUM_POLICY",
        "PART_NUMBER_OUTCOME_POLICY",
        "IF_RANGE_MISS_POLICY",
        "IF_NONE_MATCH_COMPARISON_STRENGTH",
        "BARE_CONDITIONAL_ETAG_POLICY",
        "NOT_MODIFIED_BODY_POLICY",
        "NOT_MODIFIED_FRAMING_POLICY",
        "READ_RANGE_LENGTH_ARITHMETIC",
        "COPY_RANGE_LENGTH_ARITHMETIC",
        "RANGE_REQUESTED_DETAIL_POLICY",
        "PART_COUNT_HEADER_POLICY",
        "RANGE_PART_SELECTOR_CONFLICT_POLICY",
    ] {
        assert!(core.contains(name), "missing generated core input {name}");
    }

    let range = crate::emit::range_contracts::render(&rules).expect("the types range inputs render");
    for name in [
        "MULTI_RANGE_POLICY",
        "EXPLICIT_END_OVERFLOW_POLICY",
        "SUFFIX_RANGE_POLICY",
        "OVERSIZE_SUFFIX_POLICY",
        "INVALID_RANGE_POLICY",
        "RANGE_START_BOUND",
        "OPEN_ENDED_RANGE_POLICY",
    ] {
        assert!(range.contains(name), "missing generated range input {name}");
    }
}

#[test]
fn cors_contracts_have_one_typed_source_and_emit_every_consumer_input() {
    let rules = artifacts().contract_rules;
    let dimensions = [
        MutationDimension::CorsAllowedMethodValueSet,
        MutationDimension::CorsAllowedMethodCasePolicy,
        MutationDimension::CorsOriginWildcardLimit,
        MutationDimension::CorsAllowedHeaderWildcardLimit,
        MutationDimension::CorsExposeHeaderWildcardLimit,
        MutationDimension::CorsDeleteAbsentPolicy,
        MutationDimension::CorsPreflightDispatchPolicy,
        MutationDimension::CorsPreflightBucketSource,
        MutationDimension::CorsPreflightAllowMethodsSource,
        MutationDimension::CorsPreflightMaxAgePolicy,
        MutationDimension::CorsPreflightExposePolicy,
        MutationDimension::CorsPreflightVaryPolicy,
        MutationDimension::CorsBareWildcardAnswer,
        MutationDimension::CorsPartialWildcardAnswer,
        MutationDimension::CorsWildcardCredentialsPolicy,
        MutationDimension::CorsExactOriginMatch,
        MutationDimension::CorsOriginWildcardMatch,
        MutationDimension::CorsActualAllowOriginPolicy,
        MutationDimension::CorsActualExposePolicy,
        MutationDimension::CorsActualVaryPolicy,
        MutationDimension::CorsActualPreflightHeaderPolicy,
        MutationDimension::CorsUnmatchedActualPolicy,
        MutationDimension::CorsRequestedHeaderCasePolicy,
        MutationDimension::CorsRequestedHeaderWildcardMatch,
        MutationDimension::CorsRequestedHeaderQuantifier,
        MutationDimension::CorsAllowHeadersAnswerSource,
        MutationDimension::CorsRuleOrderPolicy,
        MutationDimension::CorsRuleDimensionJoin,
        MutationDimension::CorsMatchedRuleValueSource,
        MutationDimension::CorsHeadersOnPostAuthError,
        MutationDimension::CorsPreflightRefusalProfile,
        MutationDimension::CorsSourceAbsencePolicy,
        MutationDimension::CorsInvalidTargetPolicy,
        MutationDimension::CorsOriginCharacterPolicy,
        MutationDimension::CorsOriginEmptyPolicy,
        MutationDimension::CorsOriginMaxBytes,
        MutationDimension::CorsOriginCardinality,
        MutationDimension::CorsRequestMethodCardinality,
        MutationDimension::CorsRequestHeadersCardinality,
        MutationDimension::CorsBareOptionsPolicy,
        MutationDimension::CorsPreflightRequiredHeaderPair,
        MutationDimension::CorsPreflightAuthorizationScope,
    ];
    for dimension in dimensions {
        assert_eq!(
            rules.values().filter(|rule| rule.mutation_dimension == dimension).count(),
            1,
            "{} must have one typed source",
            dimension.as_str()
        );
    }

    let rendered = crate::emit::runtime_contracts::render(&rules).expect("the CORS runtime inputs render");
    for name in [
        "CORS_ALLOWED_METHOD_VALUE_SET",
        "CORS_ALLOWED_METHOD_CASE_POLICY",
        "CORS_ORIGIN_WILDCARD_LIMIT",
        "CORS_ALLOWED_HEADER_WILDCARD_LIMIT",
        "CORS_EXPOSE_HEADER_WILDCARD_LIMIT",
        "CORS_DELETE_ABSENT_POLICY",
        "CORS_PREFLIGHT_DISPATCH_POLICY",
        "CORS_PREFLIGHT_BUCKET_SOURCE",
        "CORS_PREFLIGHT_ALLOW_METHODS_SOURCE",
        "CORS_PREFLIGHT_MAX_AGE_POLICY",
        "CORS_PREFLIGHT_EXPOSE_POLICY",
        "CORS_PREFLIGHT_VARY_POLICY",
        "CORS_BARE_WILDCARD_ANSWER",
        "CORS_PARTIAL_WILDCARD_ANSWER",
        "CORS_WILDCARD_CREDENTIALS_POLICY",
        "CORS_EXACT_ORIGIN_MATCH",
        "CORS_ORIGIN_WILDCARD_MATCH",
        "CORS_ACTUAL_ALLOW_ORIGIN_POLICY",
        "CORS_ACTUAL_EXPOSE_POLICY",
        "CORS_ACTUAL_VARY_POLICY",
        "CORS_ACTUAL_PREFLIGHT_HEADER_POLICY",
        "CORS_UNMATCHED_ACTUAL_POLICY",
        "CORS_REQUESTED_HEADER_CASE_POLICY",
        "CORS_REQUESTED_HEADER_WILDCARD_MATCH",
        "CORS_REQUESTED_HEADER_QUANTIFIER",
        "CORS_ALLOW_HEADERS_ANSWER_SOURCE",
        "CORS_RULE_ORDER_POLICY",
        "CORS_RULE_DIMENSION_JOIN",
        "CORS_MATCHED_RULE_VALUE_SOURCE",
        "CORS_HEADERS_ON_POST_AUTH_ERROR",
        "CORS_PREFLIGHT_REFUSAL_PROFILE",
        "CORS_SOURCE_ABSENCE_POLICY",
        "CORS_INVALID_TARGET_POLICY",
        "CORS_ORIGIN_CHARACTER_POLICY",
        "CORS_ORIGIN_EMPTY_POLICY",
        "CORS_ORIGIN_MAX_BYTES",
        "CORS_ORIGIN_CARDINALITY",
        "CORS_REQUEST_METHOD_CARDINALITY",
        "CORS_REQUEST_HEADERS_CARDINALITY",
        "CORS_BARE_OPTIONS_POLICY",
        "CORS_PREFLIGHT_REQUIRED_HEADER_PAIR",
        "CORS_PREFLIGHT_AUTHORIZATION_SCOPE",
    ] {
        assert!(rendered.contains(name), "missing generated CORS input {name}");
    }
}

#[test]
fn select_restore_contracts_have_one_typed_source_and_emit_every_consumer_input() {
    let rules = artifacts().contract_rules;
    let dimensions = [
        MutationDimension::RestoreInitiatedOutcome,
        MutationDimension::RestoreAlreadyRestoredOutcome,
        MutationDimension::RestoreInProgressOutcome,
        MutationDimension::RestoreHeaderOngoingForm,
        MutationDimension::RestoreHeaderRestoredForm,
        MutationDimension::RestoreHeaderAbsence,
        MutationDimension::RestoreHeaderParseGrammar,
        MutationDimension::RestoreNotArchivedOutcome,
        MutationDimension::RestoreDaysMinimum,
        MutationDimension::RestoreFormPresence,
        MutationDimension::RestoreDaysSelectExclusion,
        MutationDimension::RestoreSelectMembersRequireType,
        MutationDimension::RestoreSelectOutputRequired,
        MutationDimension::RestoreSelectParametersRequired,
        MutationDimension::RestoreNestedSelectValidation,
        MutationDimension::RestoreTypeValueSet,
        MutationDimension::RestoreGlacierTierValueSet,
        MutationDimension::RestoreDirectTierValueSet,
        MutationDimension::RestoreRootNamespacePolicy,
        MutationDimension::RestoreVersionSelector,
        MutationDimension::SelectTypeRoutePredicate,
        MutationDimension::SelectExpressionMaxBytes,
        MutationDimension::SelectExpressionPresence,
        MutationDimension::SelectExpressionErrorFlow,
        MutationDimension::SelectExpressionInspection,
        MutationDimension::SelectInputMultiple,
        MutationDimension::SelectInputMissing,
        MutationDimension::SelectOutputMultiple,
        MutationDimension::SelectOutputMissing,
        MutationDimension::SelectScanRangeEmpty,
        MutationDimension::SelectScanRangeOrder,
        MutationDimension::SelectScanRangeSign,
        MutationDimension::SelectScanBounded,
        MutationDimension::SelectScanStartOnly,
        MutationDimension::SelectScanEndOnly,
        MutationDimension::SelectExpressionTypeValues,
        MutationDimension::SelectCompressionValues,
        MutationDimension::SelectRootNamespacePolicy,
        MutationDimension::SelectResponseShape,
        MutationDimension::SelectEventStatus,
        MutationDimension::SelectEventMediaType,
        MutationDimension::EventPreludeCrcCoverage,
        MutationDimension::EventMessageCrcCoverage,
        MutationDimension::EventCrcAlgorithm,
        MutationDimension::SelectEventTermination,
    ];
    for dimension in dimensions {
        assert_eq!(
            rules.values().filter(|rule| rule.mutation_dimension == dimension).count(),
            1,
            "{} must have one typed source",
            dimension.as_str()
        );
    }

    let rendered = crate::emit::runtime_contracts::render(&rules).expect("the select/restore runtime inputs render");
    for name in [
        "RESTORE_INITIATED_OUTCOME",
        "RESTORE_ALREADY_RESTORED_OUTCOME",
        "RESTORE_IN_PROGRESS_OUTCOME",
        "RESTORE_HEADER_ONGOING_FORM",
        "RESTORE_HEADER_RESTORED_FORM",
        "RESTORE_HEADER_ABSENCE",
        "RESTORE_HEADER_PARSE_GRAMMAR",
        "RESTORE_NOT_ARCHIVED_OUTCOME",
        "RESTORE_DAYS_MINIMUM",
        "RESTORE_FORM_PRESENCE",
        "RESTORE_DAYS_SELECT_EXCLUSION",
        "RESTORE_SELECT_MEMBERS_REQUIRE_TYPE",
        "RESTORE_SELECT_OUTPUT_REQUIRED",
        "RESTORE_SELECT_PARAMETERS_REQUIRED",
        "RESTORE_NESTED_SELECT_VALIDATION",
        "RESTORE_TYPE_VALUE_SET",
        "RESTORE_GLACIER_TIER_VALUE_SET",
        "RESTORE_DIRECT_TIER_VALUE_SET",
        "RESTORE_ROOT_NAMESPACE_POLICY",
        "RESTORE_VERSION_SELECTOR",
        "SELECT_TYPE_ROUTE_PREDICATE",
        "SELECT_EXPRESSION_MAX_BYTES",
        "SELECT_EXPRESSION_PRESENCE",
        "SELECT_EXPRESSION_ERROR_FLOW",
        "SELECT_EXPRESSION_INSPECTION",
        "SELECT_INPUT_MULTIPLE",
        "SELECT_INPUT_MISSING",
        "SELECT_OUTPUT_MULTIPLE",
        "SELECT_OUTPUT_MISSING",
        "SELECT_SCAN_RANGE_EMPTY",
        "SELECT_SCAN_RANGE_ORDER",
        "SELECT_SCAN_RANGE_SIGN",
        "SELECT_SCAN_BOUNDED",
        "SELECT_SCAN_START_ONLY",
        "SELECT_SCAN_END_ONLY",
        "SELECT_EXPRESSION_TYPE_VALUES",
        "SELECT_COMPRESSION_VALUES",
        "SELECT_ROOT_NAMESPACE_POLICY",
        "SELECT_RESPONSE_SHAPE",
        "SELECT_EVENT_STATUS",
        "SELECT_EVENT_MEDIA_TYPE",
        "EVENT_PRELUDE_CRC_COVERAGE",
        "EVENT_MESSAGE_CRC_COVERAGE",
        "EVENT_CRC_ALGORITHM",
        "SELECT_EVENT_TERMINATION",
    ] {
        assert!(rendered.contains(name), "missing generated select/restore input {name}");
    }
}
