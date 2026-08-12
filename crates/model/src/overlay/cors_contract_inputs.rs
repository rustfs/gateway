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

//! Parser for bucket-CORS runtime contract inputs.
//!
//! Responsible for: converting stable CORS contract spellings into typed rules.
//! NOT responsible for: generic quirk validation or runtime behavior. Upstream: CORS quirk TOML. Downstream:
//! runtime-contract codegen.

use crate::error::Result;

use super::cors_contract_values::*;
use super::{ContractRule, ContractValue, MutationDimension};

pub(super) fn parse(dimension: &str, value: &str) -> Result<Option<ContractRule>> {
    let (current, mutation_dimension) = match (dimension, value) {
        ("cors_allowed_method_value_set", "s3_five") => (
            CorsContractValue::AllowedMethodValueSet(AllowedMethodValueSetValue::S3Five),
            MutationDimension::CorsAllowedMethodValueSet,
        ),
        ("cors_allowed_method_value_set", "include_patch") => (
            CorsContractValue::AllowedMethodValueSet(AllowedMethodValueSetValue::IncludePatch),
            MutationDimension::CorsAllowedMethodValueSet,
        ),
        ("cors_allowed_method_case_policy", "exact") => (
            CorsContractValue::AllowedMethodCasePolicy(AllowedMethodCasePolicyValue::Exact),
            MutationDimension::CorsAllowedMethodCasePolicy,
        ),
        ("cors_allowed_method_case_policy", "ascii_insensitive") => (
            CorsContractValue::AllowedMethodCasePolicy(AllowedMethodCasePolicyValue::AsciiInsensitive),
            MutationDimension::CorsAllowedMethodCasePolicy,
        ),
        ("cors_origin_wildcard_limit", "one") => (
            CorsContractValue::OriginWildcardLimit(OriginWildcardLimitValue::One),
            MutationDimension::CorsOriginWildcardLimit,
        ),
        ("cors_origin_wildcard_limit", "two") => (
            CorsContractValue::OriginWildcardLimit(OriginWildcardLimitValue::Two),
            MutationDimension::CorsOriginWildcardLimit,
        ),
        ("cors_allowed_header_wildcard_limit", "one") => (
            CorsContractValue::AllowedHeaderWildcardLimit(AllowedHeaderWildcardLimitValue::One),
            MutationDimension::CorsAllowedHeaderWildcardLimit,
        ),
        ("cors_allowed_header_wildcard_limit", "two") => (
            CorsContractValue::AllowedHeaderWildcardLimit(AllowedHeaderWildcardLimitValue::Two),
            MutationDimension::CorsAllowedHeaderWildcardLimit,
        ),
        ("cors_expose_header_wildcard_limit", "none") => (
            CorsContractValue::ExposeHeaderWildcardLimit(ExposeHeaderWildcardLimitValue::None),
            MutationDimension::CorsExposeHeaderWildcardLimit,
        ),
        ("cors_expose_header_wildcard_limit", "one") => (
            CorsContractValue::ExposeHeaderWildcardLimit(ExposeHeaderWildcardLimitValue::One),
            MutationDimension::CorsExposeHeaderWildcardLimit,
        ),
        ("cors_delete_absent_policy", "succeed") => (
            CorsContractValue::DeleteAbsentPolicy(CorsDeleteAbsentPolicyValue::Succeed),
            MutationDimension::CorsDeleteAbsentPolicy,
        ),
        ("cors_delete_absent_policy", "not_found") => (
            CorsContractValue::DeleteAbsentPolicy(CorsDeleteAbsentPolicyValue::NotFound),
            MutationDimension::CorsDeleteAbsentPolicy,
        ),
        ("cors_preflight_dispatch_policy", "bypass_pipeline") => (
            CorsContractValue::PreflightDispatchPolicy(PreflightDispatchPolicyValue::BypassPipeline),
            MutationDimension::CorsPreflightDispatchPolicy,
        ),
        ("cors_preflight_dispatch_policy", "route") => (
            CorsContractValue::PreflightDispatchPolicy(PreflightDispatchPolicyValue::Route),
            MutationDimension::CorsPreflightDispatchPolicy,
        ),
        ("cors_preflight_bucket_source", "resolved_target") => (
            CorsContractValue::PreflightBucketSource(PreflightBucketSourceValue::ResolvedTarget),
            MutationDimension::CorsPreflightBucketSource,
        ),
        ("cors_preflight_bucket_source", "raw_path") => (
            CorsContractValue::PreflightBucketSource(PreflightBucketSourceValue::RawPath),
            MutationDimension::CorsPreflightBucketSource,
        ),
        ("cors_preflight_allow_methods_source", "matched_rule") => (
            CorsContractValue::PreflightAllowMethodsSource(PreflightAllowMethodsSourceValue::MatchedRule),
            MutationDimension::CorsPreflightAllowMethodsSource,
        ),
        ("cors_preflight_allow_methods_source", "requested_only") => (
            CorsContractValue::PreflightAllowMethodsSource(PreflightAllowMethodsSourceValue::RequestedOnly),
            MutationDimension::CorsPreflightAllowMethodsSource,
        ),
        ("cors_preflight_max_age_policy", "include") => (
            CorsContractValue::PreflightMaxAgePolicy(PreflightMaxAgePolicyValue::Include),
            MutationDimension::CorsPreflightMaxAgePolicy,
        ),
        ("cors_preflight_max_age_policy", "omit") => (
            CorsContractValue::PreflightMaxAgePolicy(PreflightMaxAgePolicyValue::Omit),
            MutationDimension::CorsPreflightMaxAgePolicy,
        ),
        ("cors_preflight_expose_policy", "include") => (
            CorsContractValue::PreflightExposePolicy(PreflightExposePolicyValue::Include),
            MutationDimension::CorsPreflightExposePolicy,
        ),
        ("cors_preflight_expose_policy", "omit") => (
            CorsContractValue::PreflightExposePolicy(PreflightExposePolicyValue::Omit),
            MutationDimension::CorsPreflightExposePolicy,
        ),
        ("cors_preflight_vary_policy", "origin") => (
            CorsContractValue::PreflightVaryPolicy(PreflightVaryPolicyValue::Origin),
            MutationDimension::CorsPreflightVaryPolicy,
        ),
        ("cors_preflight_vary_policy", "omit") => (
            CorsContractValue::PreflightVaryPolicy(PreflightVaryPolicyValue::Omit),
            MutationDimension::CorsPreflightVaryPolicy,
        ),
        ("cors_bare_wildcard_answer", "literal_star") => (
            CorsContractValue::BareWildcardAnswer(BareWildcardAnswerValue::LiteralStar),
            MutationDimension::CorsBareWildcardAnswer,
        ),
        ("cors_bare_wildcard_answer", "reflect_origin") => (
            CorsContractValue::BareWildcardAnswer(BareWildcardAnswerValue::ReflectOrigin),
            MutationDimension::CorsBareWildcardAnswer,
        ),
        ("cors_partial_wildcard_answer", "reflect_origin") => (
            CorsContractValue::PartialWildcardAnswer(PartialWildcardAnswerValue::ReflectOrigin),
            MutationDimension::CorsPartialWildcardAnswer,
        ),
        ("cors_partial_wildcard_answer", "literal_star") => (
            CorsContractValue::PartialWildcardAnswer(PartialWildcardAnswerValue::LiteralStar),
            MutationDimension::CorsPartialWildcardAnswer,
        ),
        ("cors_wildcard_credentials_policy", "omit") => (
            CorsContractValue::WildcardCredentialsPolicy(WildcardCredentialsPolicyValue::Omit),
            MutationDimension::CorsWildcardCredentialsPolicy,
        ),
        ("cors_wildcard_credentials_policy", "allow") => (
            CorsContractValue::WildcardCredentialsPolicy(WildcardCredentialsPolicyValue::Allow),
            MutationDimension::CorsWildcardCredentialsPolicy,
        ),
        ("cors_exact_origin_match", "exact") => (
            CorsContractValue::ExactOriginMatch(ExactOriginMatchValue::Exact),
            MutationDimension::CorsExactOriginMatch,
        ),
        ("cors_exact_origin_match", "allow_any") => (
            CorsContractValue::ExactOriginMatch(ExactOriginMatchValue::AllowAny),
            MutationDimension::CorsExactOriginMatch,
        ),
        ("cors_origin_wildcard_match", "prefix_and_suffix") => (
            CorsContractValue::OriginWildcardMatch(OriginWildcardMatchValue::PrefixAndSuffix),
            MutationDimension::CorsOriginWildcardMatch,
        ),
        ("cors_origin_wildcard_match", "suffix_only") => (
            CorsContractValue::OriginWildcardMatch(OriginWildcardMatchValue::SuffixOnly),
            MutationDimension::CorsOriginWildcardMatch,
        ),
        ("cors_actual_allow_origin_policy", "include") => (
            CorsContractValue::ActualAllowOriginPolicy(ActualAllowOriginPolicyValue::Include),
            MutationDimension::CorsActualAllowOriginPolicy,
        ),
        ("cors_actual_allow_origin_policy", "omit") => (
            CorsContractValue::ActualAllowOriginPolicy(ActualAllowOriginPolicyValue::Omit),
            MutationDimension::CorsActualAllowOriginPolicy,
        ),
        ("cors_actual_expose_policy", "include") => (
            CorsContractValue::ActualExposePolicy(ActualExposePolicyValue::Include),
            MutationDimension::CorsActualExposePolicy,
        ),
        ("cors_actual_expose_policy", "omit") => (
            CorsContractValue::ActualExposePolicy(ActualExposePolicyValue::Omit),
            MutationDimension::CorsActualExposePolicy,
        ),
        ("cors_actual_vary_policy", "origin") => (
            CorsContractValue::ActualVaryPolicy(ActualVaryPolicyValue::Origin),
            MutationDimension::CorsActualVaryPolicy,
        ),
        ("cors_actual_vary_policy", "omit") => (
            CorsContractValue::ActualVaryPolicy(ActualVaryPolicyValue::Omit),
            MutationDimension::CorsActualVaryPolicy,
        ),
        ("cors_actual_preflight_header_policy", "omit") => (
            CorsContractValue::ActualPreflightHeaderPolicy(ActualPreflightHeaderPolicyValue::Omit),
            MutationDimension::CorsActualPreflightHeaderPolicy,
        ),
        ("cors_actual_preflight_header_policy", "include") => (
            CorsContractValue::ActualPreflightHeaderPolicy(ActualPreflightHeaderPolicyValue::Include),
            MutationDimension::CorsActualPreflightHeaderPolicy,
        ),
        ("cors_unmatched_actual_policy", "serve_without_cors") => (
            CorsContractValue::UnmatchedActualPolicy(UnmatchedActualPolicyValue::ServeWithoutCors),
            MutationDimension::CorsUnmatchedActualPolicy,
        ),
        ("cors_unmatched_actual_policy", "decorate") => (
            CorsContractValue::UnmatchedActualPolicy(UnmatchedActualPolicyValue::Decorate),
            MutationDimension::CorsUnmatchedActualPolicy,
        ),
        ("cors_requested_header_case_policy", "ascii_insensitive") => (
            CorsContractValue::RequestedHeaderCasePolicy(RequestedHeaderCasePolicyValue::AsciiInsensitive),
            MutationDimension::CorsRequestedHeaderCasePolicy,
        ),
        ("cors_requested_header_case_policy", "sensitive") => (
            CorsContractValue::RequestedHeaderCasePolicy(RequestedHeaderCasePolicyValue::Sensitive),
            MutationDimension::CorsRequestedHeaderCasePolicy,
        ),
        ("cors_requested_header_wildcard_match", "prefix_and_suffix") => (
            CorsContractValue::RequestedHeaderWildcardMatch(RequestedHeaderWildcardMatchValue::PrefixAndSuffix),
            MutationDimension::CorsRequestedHeaderWildcardMatch,
        ),
        ("cors_requested_header_wildcard_match", "literal") => (
            CorsContractValue::RequestedHeaderWildcardMatch(RequestedHeaderWildcardMatchValue::Literal),
            MutationDimension::CorsRequestedHeaderWildcardMatch,
        ),
        ("cors_requested_header_quantifier", "all") => (
            CorsContractValue::RequestedHeaderQuantifier(RequestedHeaderQuantifierValue::All),
            MutationDimension::CorsRequestedHeaderQuantifier,
        ),
        ("cors_requested_header_quantifier", "any") => (
            CorsContractValue::RequestedHeaderQuantifier(RequestedHeaderQuantifierValue::Any),
            MutationDimension::CorsRequestedHeaderQuantifier,
        ),
        ("cors_allow_headers_answer_source", "requested_headers") => (
            CorsContractValue::AllowHeadersAnswerSource(AllowHeadersAnswerSourceValue::RequestedHeaders),
            MutationDimension::CorsAllowHeadersAnswerSource,
        ),
        ("cors_allow_headers_answer_source", "stored_patterns") => (
            CorsContractValue::AllowHeadersAnswerSource(AllowHeadersAnswerSourceValue::StoredPatterns),
            MutationDimension::CorsAllowHeadersAnswerSource,
        ),
        ("cors_rule_order_policy", "first_matching") => (
            CorsContractValue::RuleOrderPolicy(CorsRuleOrderPolicyValue::FirstMatching),
            MutationDimension::CorsRuleOrderPolicy,
        ),
        ("cors_rule_order_policy", "last_matching") => (
            CorsContractValue::RuleOrderPolicy(CorsRuleOrderPolicyValue::LastMatching),
            MutationDimension::CorsRuleOrderPolicy,
        ),
        ("cors_rule_dimension_join", "same_rule") => (
            CorsContractValue::RuleDimensionJoin(CorsRuleDimensionJoinValue::SameRule),
            MutationDimension::CorsRuleDimensionJoin,
        ),
        ("cors_rule_dimension_join", "cross_rule") => (
            CorsContractValue::RuleDimensionJoin(CorsRuleDimensionJoinValue::CrossRule),
            MutationDimension::CorsRuleDimensionJoin,
        ),
        ("cors_matched_rule_value_source", "winner") => (
            CorsContractValue::MatchedRuleValueSource(CorsMatchedRuleValueSourceValue::Winner),
            MutationDimension::CorsMatchedRuleValueSource,
        ),
        ("cors_matched_rule_value_source", "first_rule") => (
            CorsContractValue::MatchedRuleValueSource(CorsMatchedRuleValueSourceValue::FirstRule),
            MutationDimension::CorsMatchedRuleValueSource,
        ),
        ("cors_headers_on_post_auth_error", "include") => (
            CorsContractValue::HeadersOnPostAuthError(HeadersOnPostAuthErrorValue::Include),
            MutationDimension::CorsHeadersOnPostAuthError,
        ),
        ("cors_headers_on_post_auth_error", "success_only") => (
            CorsContractValue::HeadersOnPostAuthError(HeadersOnPostAuthErrorValue::SuccessOnly),
            MutationDimension::CorsHeadersOnPostAuthError,
        ),
        ("cors_preflight_refusal_profile", "uniform") => (
            CorsContractValue::PreflightRefusalProfile(PreflightRefusalProfileValue::Uniform),
            MutationDimension::CorsPreflightRefusalProfile,
        ),
        ("cors_preflight_refusal_profile", "cause_specific") => (
            CorsContractValue::PreflightRefusalProfile(PreflightRefusalProfileValue::CauseSpecific),
            MutationDimension::CorsPreflightRefusalProfile,
        ),
        ("cors_source_absence_policy", "collapse") => (
            CorsContractValue::SourceAbsencePolicy(CorsSourceAbsencePolicyValue::Collapse),
            MutationDimension::CorsSourceAbsencePolicy,
        ),
        ("cors_source_absence_policy", "distinguish") => (
            CorsContractValue::SourceAbsencePolicy(CorsSourceAbsencePolicyValue::Distinguish),
            MutationDimension::CorsSourceAbsencePolicy,
        ),
        ("cors_invalid_target_policy", "uniform_refusal") => (
            CorsContractValue::InvalidTargetPolicy(CorsInvalidTargetPolicyValue::UniformRefusal),
            MutationDimension::CorsInvalidTargetPolicy,
        ),
        ("cors_invalid_target_policy", "route") => (
            CorsContractValue::InvalidTargetPolicy(CorsInvalidTargetPolicyValue::Route),
            MutationDimension::CorsInvalidTargetPolicy,
        ),
        ("cors_origin_character_policy", "visible_ascii") => (
            CorsContractValue::OriginCharacterPolicy(CorsOriginCharacterPolicyValue::VisibleAscii),
            MutationDimension::CorsOriginCharacterPolicy,
        ),
        ("cors_origin_character_policy", "allow_spaces") => (
            CorsContractValue::OriginCharacterPolicy(CorsOriginCharacterPolicyValue::AllowSpaces),
            MutationDimension::CorsOriginCharacterPolicy,
        ),
        ("cors_origin_empty_policy", "reject") => (
            CorsContractValue::OriginEmptyPolicy(CorsOriginEmptyPolicyValue::Reject),
            MutationDimension::CorsOriginEmptyPolicy,
        ),
        ("cors_origin_empty_policy", "allow") => (
            CorsContractValue::OriginEmptyPolicy(CorsOriginEmptyPolicyValue::Allow),
            MutationDimension::CorsOriginEmptyPolicy,
        ),
        ("cors_origin_max_bytes", "max_2048") => (
            CorsContractValue::OriginMaxBytes(CorsOriginMaxBytesValue::Max2048),
            MutationDimension::CorsOriginMaxBytes,
        ),
        ("cors_origin_max_bytes", "unbounded") => (
            CorsContractValue::OriginMaxBytes(CorsOriginMaxBytesValue::Unbounded),
            MutationDimension::CorsOriginMaxBytes,
        ),
        ("cors_origin_cardinality", "exactly_one") => (
            CorsContractValue::OriginCardinality(CorsOriginCardinalityValue::ExactlyOne),
            MutationDimension::CorsOriginCardinality,
        ),
        ("cors_origin_cardinality", "first") => (
            CorsContractValue::OriginCardinality(CorsOriginCardinalityValue::First),
            MutationDimension::CorsOriginCardinality,
        ),
        ("cors_request_method_cardinality", "exactly_one") => (
            CorsContractValue::RequestMethodCardinality(CorsRequestMethodCardinalityValue::ExactlyOne),
            MutationDimension::CorsRequestMethodCardinality,
        ),
        ("cors_request_method_cardinality", "first") => (
            CorsContractValue::RequestMethodCardinality(CorsRequestMethodCardinalityValue::First),
            MutationDimension::CorsRequestMethodCardinality,
        ),
        ("cors_request_headers_cardinality", "at_most_one") => (
            CorsContractValue::RequestHeadersCardinality(CorsRequestHeadersCardinalityValue::AtMostOne),
            MutationDimension::CorsRequestHeadersCardinality,
        ),
        ("cors_request_headers_cardinality", "first") => (
            CorsContractValue::RequestHeadersCardinality(CorsRequestHeadersCardinalityValue::First),
            MutationDimension::CorsRequestHeadersCardinality,
        ),
        ("cors_bare_options_policy", "route") => (
            CorsContractValue::BareOptionsPolicy(BareOptionsPolicyValue::Route),
            MutationDimension::CorsBareOptionsPolicy,
        ),
        ("cors_bare_options_policy", "refuse") => (
            CorsContractValue::BareOptionsPolicy(BareOptionsPolicyValue::Refuse),
            MutationDimension::CorsBareOptionsPolicy,
        ),
        ("cors_preflight_required_header_pair", "both") => (
            CorsContractValue::PreflightRequiredHeaderPair(PreflightRequiredHeaderPairValue::Both),
            MutationDimension::CorsPreflightRequiredHeaderPair,
        ),
        ("cors_preflight_required_header_pair", "either") => (
            CorsContractValue::PreflightRequiredHeaderPair(PreflightRequiredHeaderPairValue::Either),
            MutationDimension::CorsPreflightRequiredHeaderPair,
        ),
        ("cors_preflight_authorization_scope", "no_grant") => (
            CorsContractValue::PreflightAuthorizationScope(PreflightAuthorizationScopeValue::NoGrant),
            MutationDimension::CorsPreflightAuthorizationScope,
        ),
        ("cors_preflight_authorization_scope", "grant") => (
            CorsContractValue::PreflightAuthorizationScope(PreflightAuthorizationScopeValue::Grant),
            MutationDimension::CorsPreflightAuthorizationScope,
        ),
        _ => return Ok(None),
    };
    Ok(Some(ContractRule {
        current: ContractValue::Cors(current),
        mutation_dimension,
    }))
}
