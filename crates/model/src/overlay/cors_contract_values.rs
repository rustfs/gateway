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

//! Closed values for bucket-CORS runtime contracts.
//!
//! Responsible for: typed current and mutation alternatives for the CORS family.
//! NOT responsible for: parsing overlay strings or implementing runtime behavior. Upstream: quirk overlays.
//! Downstream: contract parsing and runtime-contract codegen.

macro_rules! two_value_policy {
    ($name:ident, $current:ident, $mutant:ident) => {
        #[doc = concat!("Typed values for the `", stringify!($name), "` contract.")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            #[doc = concat!("Current value: `", stringify!($current), "`.")]
            $current,
            #[doc = concat!("Mutation alternative: `", stringify!($mutant), "`.")]
            $mutant,
        }
    };
}

two_value_policy!(AllowedMethodValueSetValue, S3Five, IncludePatch);
two_value_policy!(AllowedMethodCasePolicyValue, Exact, AsciiInsensitive);
two_value_policy!(OriginWildcardLimitValue, One, Two);
two_value_policy!(AllowedHeaderWildcardLimitValue, One, Two);
two_value_policy!(ExposeHeaderWildcardLimitValue, None, One);
two_value_policy!(CorsDeleteAbsentPolicyValue, Succeed, NotFound);
two_value_policy!(PreflightDispatchPolicyValue, BypassPipeline, Route);
two_value_policy!(PreflightBucketSourceValue, ResolvedTarget, RawPath);
two_value_policy!(PreflightAllowMethodsSourceValue, MatchedRule, RequestedOnly);
two_value_policy!(PreflightMaxAgePolicyValue, Include, Omit);
two_value_policy!(PreflightExposePolicyValue, Include, Omit);
two_value_policy!(PreflightVaryPolicyValue, Origin, Omit);
two_value_policy!(BareWildcardAnswerValue, LiteralStar, ReflectOrigin);
two_value_policy!(PartialWildcardAnswerValue, ReflectOrigin, LiteralStar);
two_value_policy!(WildcardCredentialsPolicyValue, Omit, Allow);
two_value_policy!(ExactOriginMatchValue, Exact, AllowAny);
two_value_policy!(OriginWildcardMatchValue, PrefixAndSuffix, SuffixOnly);
two_value_policy!(ActualAllowOriginPolicyValue, Include, Omit);
two_value_policy!(ActualExposePolicyValue, Include, Omit);
two_value_policy!(ActualVaryPolicyValue, Origin, Omit);
two_value_policy!(ActualPreflightHeaderPolicyValue, Omit, Include);
two_value_policy!(UnmatchedActualPolicyValue, ServeWithoutCors, Decorate);
two_value_policy!(RequestedHeaderCasePolicyValue, AsciiInsensitive, Sensitive);
two_value_policy!(RequestedHeaderWildcardMatchValue, PrefixAndSuffix, Literal);
two_value_policy!(RequestedHeaderQuantifierValue, All, Any);
two_value_policy!(AllowHeadersAnswerSourceValue, RequestedHeaders, StoredPatterns);
two_value_policy!(CorsRuleOrderPolicyValue, FirstMatching, LastMatching);
two_value_policy!(CorsRuleDimensionJoinValue, SameRule, CrossRule);
two_value_policy!(CorsMatchedRuleValueSourceValue, Winner, FirstRule);
two_value_policy!(HeadersOnPostAuthErrorValue, Include, SuccessOnly);
two_value_policy!(PreflightRefusalProfileValue, Uniform, CauseSpecific);
two_value_policy!(CorsSourceAbsencePolicyValue, Collapse, Distinguish);
two_value_policy!(CorsInvalidTargetPolicyValue, UniformRefusal, Route);
two_value_policy!(CorsOriginCharacterPolicyValue, VisibleAscii, AllowSpaces);
two_value_policy!(CorsOriginEmptyPolicyValue, Reject, Allow);
two_value_policy!(CorsOriginMaxBytesValue, Max2048, Unbounded);
two_value_policy!(CorsOriginCardinalityValue, ExactlyOne, First);
two_value_policy!(CorsRequestMethodCardinalityValue, ExactlyOne, First);
two_value_policy!(CorsRequestHeadersCardinalityValue, AtMostOne, First);
two_value_policy!(BareOptionsPolicyValue, Route, Refuse);
two_value_policy!(PreflightRequiredHeaderPairValue, Both, Either);
two_value_policy!(PreflightAuthorizationScopeValue, NoGrant, Grant);

/// One typed value from the bucket-CORS contract family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorsContractValue {
    /// Allowed method vocabulary.
    AllowedMethodValueSet(AllowedMethodValueSetValue),
    /// Case handling for allowed methods.
    AllowedMethodCasePolicy(AllowedMethodCasePolicyValue),
    /// Wildcard limit for origins.
    OriginWildcardLimit(OriginWildcardLimitValue),
    /// Wildcard limit for allowed headers.
    AllowedHeaderWildcardLimit(AllowedHeaderWildcardLimitValue),
    /// Wildcard limit for exposed headers.
    ExposeHeaderWildcardLimit(ExposeHeaderWildcardLimitValue),
    /// Delete behavior when no CORS configuration exists.
    DeleteAbsentPolicy(CorsDeleteAbsentPolicyValue),
    /// Dispatch behavior for preflight requests.
    PreflightDispatchPolicy(PreflightDispatchPolicyValue),
    /// Bucket source used by preflight handling.
    PreflightBucketSource(PreflightBucketSourceValue),
    /// Source of the preflight allowed-methods answer.
    PreflightAllowMethodsSource(PreflightAllowMethodsSourceValue),
    /// Inclusion policy for preflight max age.
    PreflightMaxAgePolicy(PreflightMaxAgePolicyValue),
    /// Inclusion policy for preflight exposed headers.
    PreflightExposePolicy(PreflightExposePolicyValue),
    /// Inclusion policy for the preflight Vary header.
    PreflightVaryPolicy(PreflightVaryPolicyValue),
    /// Answer form for a bare origin wildcard.
    BareWildcardAnswer(BareWildcardAnswerValue),
    /// Answer form for a partial origin wildcard.
    PartialWildcardAnswer(PartialWildcardAnswerValue),
    /// Credential behavior for wildcard origins.
    WildcardCredentialsPolicy(WildcardCredentialsPolicyValue),
    /// Matching rule for exact origins.
    ExactOriginMatch(ExactOriginMatchValue),
    /// Matching rule for wildcard origins.
    OriginWildcardMatch(OriginWildcardMatchValue),
    /// Inclusion policy for the actual allow-origin header.
    ActualAllowOriginPolicy(ActualAllowOriginPolicyValue),
    /// Inclusion policy for actual exposed headers.
    ActualExposePolicy(ActualExposePolicyValue),
    /// Inclusion policy for the actual Vary header.
    ActualVaryPolicy(ActualVaryPolicyValue),
    /// Inclusion policy for preflight-only headers on actual requests.
    ActualPreflightHeaderPolicy(ActualPreflightHeaderPolicyValue),
    /// Behavior for actual requests with no matching rule.
    UnmatchedActualPolicy(UnmatchedActualPolicyValue),
    /// Case handling for requested headers.
    RequestedHeaderCasePolicy(RequestedHeaderCasePolicyValue),
    /// Wildcard matching rule for requested headers.
    RequestedHeaderWildcardMatch(RequestedHeaderWildcardMatchValue),
    /// Quantifier applied to requested headers.
    RequestedHeaderQuantifier(RequestedHeaderQuantifierValue),
    /// Source of the allow-headers answer.
    AllowHeadersAnswerSource(AllowHeadersAnswerSourceValue),
    /// Rule selection order.
    RuleOrderPolicy(CorsRuleOrderPolicyValue),
    /// Whether match dimensions may cross rules.
    RuleDimensionJoin(CorsRuleDimensionJoinValue),
    /// Source of values returned from the matching rule.
    MatchedRuleValueSource(CorsMatchedRuleValueSourceValue),
    /// CORS-header behavior on post-authorization errors.
    HeadersOnPostAuthError(HeadersOnPostAuthErrorValue),
    /// Error profile for preflight refusals.
    PreflightRefusalProfile(PreflightRefusalProfileValue),
    /// Treatment of missing CORS sources.
    SourceAbsencePolicy(CorsSourceAbsencePolicyValue),
    /// Treatment of invalid preflight targets.
    InvalidTargetPolicy(CorsInvalidTargetPolicyValue),
    /// Accepted origin characters.
    OriginCharacterPolicy(CorsOriginCharacterPolicyValue),
    /// Treatment of an empty origin value.
    OriginEmptyPolicy(CorsOriginEmptyPolicyValue),
    /// Maximum origin length.
    OriginMaxBytes(CorsOriginMaxBytesValue),
    /// Required origin-header cardinality.
    OriginCardinality(CorsOriginCardinalityValue),
    /// Required request-method-header cardinality.
    RequestMethodCardinality(CorsRequestMethodCardinalityValue),
    /// Required request-headers-header cardinality.
    RequestHeadersCardinality(CorsRequestHeadersCardinalityValue),
    /// Handling of an OPTIONS request without preflight headers.
    BareOptionsPolicy(BareOptionsPolicyValue),
    /// Required pair of preflight headers.
    PreflightRequiredHeaderPair(PreflightRequiredHeaderPairValue),
    /// Authorization scope granted to preflight requests.
    PreflightAuthorizationScope(PreflightAuthorizationScopeValue),
}

impl CorsContractValue {
    /// Returns the stable overlay spelling of the contained value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowedMethodValueSet(AllowedMethodValueSetValue::S3Five) => "s3_five",
            Self::AllowedMethodValueSet(AllowedMethodValueSetValue::IncludePatch) => "include_patch",
            Self::AllowedMethodCasePolicy(AllowedMethodCasePolicyValue::Exact) => "exact",
            Self::AllowedMethodCasePolicy(AllowedMethodCasePolicyValue::AsciiInsensitive) => "ascii_insensitive",
            Self::OriginWildcardLimit(OriginWildcardLimitValue::One) => "one",
            Self::OriginWildcardLimit(OriginWildcardLimitValue::Two) => "two",
            Self::AllowedHeaderWildcardLimit(AllowedHeaderWildcardLimitValue::One) => "one",
            Self::AllowedHeaderWildcardLimit(AllowedHeaderWildcardLimitValue::Two) => "two",
            Self::ExposeHeaderWildcardLimit(ExposeHeaderWildcardLimitValue::None) => "none",
            Self::ExposeHeaderWildcardLimit(ExposeHeaderWildcardLimitValue::One) => "one",
            Self::DeleteAbsentPolicy(CorsDeleteAbsentPolicyValue::Succeed) => "succeed",
            Self::DeleteAbsentPolicy(CorsDeleteAbsentPolicyValue::NotFound) => "not_found",
            Self::PreflightDispatchPolicy(PreflightDispatchPolicyValue::BypassPipeline) => "bypass_pipeline",
            Self::PreflightDispatchPolicy(PreflightDispatchPolicyValue::Route) => "route",
            Self::PreflightBucketSource(PreflightBucketSourceValue::ResolvedTarget) => "resolved_target",
            Self::PreflightBucketSource(PreflightBucketSourceValue::RawPath) => "raw_path",
            Self::PreflightAllowMethodsSource(PreflightAllowMethodsSourceValue::MatchedRule) => "matched_rule",
            Self::PreflightAllowMethodsSource(PreflightAllowMethodsSourceValue::RequestedOnly) => "requested_only",
            Self::PreflightMaxAgePolicy(PreflightMaxAgePolicyValue::Include) => "include",
            Self::PreflightMaxAgePolicy(PreflightMaxAgePolicyValue::Omit) => "omit",
            Self::PreflightExposePolicy(PreflightExposePolicyValue::Include) => "include",
            Self::PreflightExposePolicy(PreflightExposePolicyValue::Omit) => "omit",
            Self::PreflightVaryPolicy(PreflightVaryPolicyValue::Origin) => "origin",
            Self::PreflightVaryPolicy(PreflightVaryPolicyValue::Omit) => "omit",
            Self::BareWildcardAnswer(BareWildcardAnswerValue::LiteralStar) => "literal_star",
            Self::BareWildcardAnswer(BareWildcardAnswerValue::ReflectOrigin) => "reflect_origin",
            Self::PartialWildcardAnswer(PartialWildcardAnswerValue::ReflectOrigin) => "reflect_origin",
            Self::PartialWildcardAnswer(PartialWildcardAnswerValue::LiteralStar) => "literal_star",
            Self::WildcardCredentialsPolicy(WildcardCredentialsPolicyValue::Omit) => "omit",
            Self::WildcardCredentialsPolicy(WildcardCredentialsPolicyValue::Allow) => "allow",
            Self::ExactOriginMatch(ExactOriginMatchValue::Exact) => "exact",
            Self::ExactOriginMatch(ExactOriginMatchValue::AllowAny) => "allow_any",
            Self::OriginWildcardMatch(OriginWildcardMatchValue::PrefixAndSuffix) => "prefix_and_suffix",
            Self::OriginWildcardMatch(OriginWildcardMatchValue::SuffixOnly) => "suffix_only",
            Self::ActualAllowOriginPolicy(ActualAllowOriginPolicyValue::Include) => "include",
            Self::ActualAllowOriginPolicy(ActualAllowOriginPolicyValue::Omit) => "omit",
            Self::ActualExposePolicy(ActualExposePolicyValue::Include) => "include",
            Self::ActualExposePolicy(ActualExposePolicyValue::Omit) => "omit",
            Self::ActualVaryPolicy(ActualVaryPolicyValue::Origin) => "origin",
            Self::ActualVaryPolicy(ActualVaryPolicyValue::Omit) => "omit",
            Self::ActualPreflightHeaderPolicy(ActualPreflightHeaderPolicyValue::Omit) => "omit",
            Self::ActualPreflightHeaderPolicy(ActualPreflightHeaderPolicyValue::Include) => "include",
            Self::UnmatchedActualPolicy(UnmatchedActualPolicyValue::ServeWithoutCors) => "serve_without_cors",
            Self::UnmatchedActualPolicy(UnmatchedActualPolicyValue::Decorate) => "decorate",
            Self::RequestedHeaderCasePolicy(RequestedHeaderCasePolicyValue::AsciiInsensitive) => "ascii_insensitive",
            Self::RequestedHeaderCasePolicy(RequestedHeaderCasePolicyValue::Sensitive) => "sensitive",
            Self::RequestedHeaderWildcardMatch(RequestedHeaderWildcardMatchValue::PrefixAndSuffix) => "prefix_and_suffix",
            Self::RequestedHeaderWildcardMatch(RequestedHeaderWildcardMatchValue::Literal) => "literal",
            Self::RequestedHeaderQuantifier(RequestedHeaderQuantifierValue::All) => "all",
            Self::RequestedHeaderQuantifier(RequestedHeaderQuantifierValue::Any) => "any",
            Self::AllowHeadersAnswerSource(AllowHeadersAnswerSourceValue::RequestedHeaders) => "requested_headers",
            Self::AllowHeadersAnswerSource(AllowHeadersAnswerSourceValue::StoredPatterns) => "stored_patterns",
            Self::RuleOrderPolicy(CorsRuleOrderPolicyValue::FirstMatching) => "first_matching",
            Self::RuleOrderPolicy(CorsRuleOrderPolicyValue::LastMatching) => "last_matching",
            Self::RuleDimensionJoin(CorsRuleDimensionJoinValue::SameRule) => "same_rule",
            Self::RuleDimensionJoin(CorsRuleDimensionJoinValue::CrossRule) => "cross_rule",
            Self::MatchedRuleValueSource(CorsMatchedRuleValueSourceValue::Winner) => "winner",
            Self::MatchedRuleValueSource(CorsMatchedRuleValueSourceValue::FirstRule) => "first_rule",
            Self::HeadersOnPostAuthError(HeadersOnPostAuthErrorValue::Include) => "include",
            Self::HeadersOnPostAuthError(HeadersOnPostAuthErrorValue::SuccessOnly) => "success_only",
            Self::PreflightRefusalProfile(PreflightRefusalProfileValue::Uniform) => "uniform",
            Self::PreflightRefusalProfile(PreflightRefusalProfileValue::CauseSpecific) => "cause_specific",
            Self::SourceAbsencePolicy(CorsSourceAbsencePolicyValue::Collapse) => "collapse",
            Self::SourceAbsencePolicy(CorsSourceAbsencePolicyValue::Distinguish) => "distinguish",
            Self::InvalidTargetPolicy(CorsInvalidTargetPolicyValue::UniformRefusal) => "uniform_refusal",
            Self::InvalidTargetPolicy(CorsInvalidTargetPolicyValue::Route) => "route",
            Self::OriginCharacterPolicy(CorsOriginCharacterPolicyValue::VisibleAscii) => "visible_ascii",
            Self::OriginCharacterPolicy(CorsOriginCharacterPolicyValue::AllowSpaces) => "allow_spaces",
            Self::OriginEmptyPolicy(CorsOriginEmptyPolicyValue::Reject) => "reject",
            Self::OriginEmptyPolicy(CorsOriginEmptyPolicyValue::Allow) => "allow",
            Self::OriginMaxBytes(CorsOriginMaxBytesValue::Max2048) => "max_2048",
            Self::OriginMaxBytes(CorsOriginMaxBytesValue::Unbounded) => "unbounded",
            Self::OriginCardinality(CorsOriginCardinalityValue::ExactlyOne) => "exactly_one",
            Self::OriginCardinality(CorsOriginCardinalityValue::First) => "first",
            Self::RequestMethodCardinality(CorsRequestMethodCardinalityValue::ExactlyOne) => "exactly_one",
            Self::RequestMethodCardinality(CorsRequestMethodCardinalityValue::First) => "first",
            Self::RequestHeadersCardinality(CorsRequestHeadersCardinalityValue::AtMostOne) => "at_most_one",
            Self::RequestHeadersCardinality(CorsRequestHeadersCardinalityValue::First) => "first",
            Self::BareOptionsPolicy(BareOptionsPolicyValue::Route) => "route",
            Self::BareOptionsPolicy(BareOptionsPolicyValue::Refuse) => "refuse",
            Self::PreflightRequiredHeaderPair(PreflightRequiredHeaderPairValue::Both) => "both",
            Self::PreflightRequiredHeaderPair(PreflightRequiredHeaderPairValue::Either) => "either",
            Self::PreflightAuthorizationScope(PreflightAuthorizationScopeValue::NoGrant) => "no_grant",
            Self::PreflightAuthorizationScope(PreflightAuthorizationScopeValue::Grant) => "grant",
        }
    }
}
