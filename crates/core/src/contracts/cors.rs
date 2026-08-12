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

//! Runtime vocabulary and predicates for bucket-CORS contracts.
//!
//! Responsible for: closed policy types selected by generated contract data and the predicates
//! consumed by CORS validation, matching and response assembly.
//! NOT responsible for: selecting current values.
//! Upstream: generated contract constants. Downstream: core CORS and the gateway CORS pipeline.

macro_rules! two_value_policy {
    ($name:ident, $current:ident, $mutant:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
        pub(crate) enum $name {
            $current,
            $mutant,
        }
    };
}

two_value_policy!(AllowedMethodValueSetPolicy, S3Five, IncludePatch);
two_value_policy!(AllowedMethodCasePolicy, Exact, AsciiInsensitive);
two_value_policy!(OriginWildcardLimitPolicy, One, Two);
two_value_policy!(AllowedHeaderWildcardLimitPolicy, One, Two);
two_value_policy!(ExposeHeaderWildcardLimitPolicy, None, One);
two_value_policy!(CorsDeleteAbsentPolicy, Succeed, NotFound);
two_value_policy!(PreflightDispatchPolicy, BypassPipeline, Route);
two_value_policy!(PreflightBucketSourcePolicy, ResolvedTarget, RawPath);
two_value_policy!(PreflightAllowMethodsSourcePolicy, MatchedRule, RequestedOnly);
two_value_policy!(PreflightMaxAgePolicy, Include, Omit);
two_value_policy!(PreflightExposePolicy, Include, Omit);
two_value_policy!(PreflightVaryPolicy, Origin, Omit);
two_value_policy!(BareWildcardAnswerPolicy, LiteralStar, ReflectOrigin);
two_value_policy!(PartialWildcardAnswerPolicy, ReflectOrigin, LiteralStar);
two_value_policy!(WildcardCredentialsPolicy, Omit, Allow);
two_value_policy!(ExactOriginMatchPolicy, Exact, AllowAny);
two_value_policy!(OriginWildcardMatchPolicy, PrefixAndSuffix, SuffixOnly);
two_value_policy!(ActualAllowOriginPolicy, Include, Omit);
two_value_policy!(ActualExposePolicy, Include, Omit);
two_value_policy!(ActualVaryPolicy, Origin, Omit);
two_value_policy!(ActualPreflightHeaderPolicy, Omit, Include);
two_value_policy!(UnmatchedActualPolicy, ServeWithoutCors, Decorate);
two_value_policy!(RequestedHeaderCasePolicy, AsciiInsensitive, Sensitive);
two_value_policy!(RequestedHeaderWildcardMatchPolicy, PrefixAndSuffix, Literal);
two_value_policy!(RequestedHeaderQuantifierPolicy, All, Any);
two_value_policy!(AllowHeadersAnswerSourcePolicy, RequestedHeaders, StoredPatterns);
two_value_policy!(CorsRuleOrderPolicy, FirstMatching, LastMatching);
two_value_policy!(CorsRuleDimensionJoinPolicy, SameRule, CrossRule);
two_value_policy!(CorsMatchedRuleValueSourcePolicy, Winner, FirstRule);
two_value_policy!(HeadersOnPostAuthErrorPolicy, Include, SuccessOnly);
two_value_policy!(PreflightRefusalProfilePolicy, Uniform, CauseSpecific);
two_value_policy!(CorsSourceAbsencePolicy, Collapse, Distinguish);
two_value_policy!(CorsInvalidTargetPolicy, UniformRefusal, Route);
two_value_policy!(CorsOriginCharacterPolicy, VisibleAscii, AllowSpaces);
two_value_policy!(CorsOriginEmptyPolicy, Reject, Allow);
two_value_policy!(CorsOriginMaxBytesPolicy, Max2048, Unbounded);
two_value_policy!(CorsOriginCardinalityPolicy, ExactlyOne, First);
two_value_policy!(CorsRequestMethodCardinalityPolicy, ExactlyOne, First);
two_value_policy!(CorsRequestHeadersCardinalityPolicy, AtMostOne, First);
two_value_policy!(CorsBareOptionsPolicy, Route, Refuse);
two_value_policy!(PreflightRequiredHeaderPairPolicy, Both, Either);
two_value_policy!(PreflightAuthorizationScopePolicy, NoGrant, Grant);

use super::data::*;

pub(crate) fn cors_allowed_method_known(value: &str) -> bool {
    let known = ["GET", "PUT", "POST", "DELETE", "HEAD"];
    known.iter().any(|item| item.eq_ignore_ascii_case(value))
        || matches!(CORS_ALLOWED_METHOD_VALUE_SET, AllowedMethodValueSetPolicy::IncludePatch)
            && value.eq_ignore_ascii_case("PATCH")
}

pub(crate) fn cors_allowed_method_case_valid(value: &str) -> bool {
    matches!(CORS_ALLOWED_METHOD_CASE_POLICY, AllowedMethodCasePolicy::AsciiInsensitive)
        || ["GET", "PUT", "POST", "DELETE", "HEAD", "PATCH"].contains(&value)
}

pub(crate) const fn cors_origin_wildcard_limit() -> usize {
    match CORS_ORIGIN_WILDCARD_LIMIT {
        OriginWildcardLimitPolicy::One => 1,
        OriginWildcardLimitPolicy::Two => 2,
    }
}

pub(crate) const fn cors_allowed_header_wildcard_limit() -> usize {
    match CORS_ALLOWED_HEADER_WILDCARD_LIMIT {
        AllowedHeaderWildcardLimitPolicy::One => 1,
        AllowedHeaderWildcardLimitPolicy::Two => 2,
    }
}

pub(crate) const fn cors_expose_header_wildcard_limit() -> usize {
    match CORS_EXPOSE_HEADER_WILDCARD_LIMIT {
        ExposeHeaderWildcardLimitPolicy::None => 0,
        ExposeHeaderWildcardLimitPolicy::One => 1,
    }
}

#[must_use]
pub(crate) const fn cors_delete_absent_succeeds() -> bool {
    matches!(CORS_DELETE_ABSENT_POLICY, CorsDeleteAbsentPolicy::Succeed)
}

pub(crate) const fn cors_preflight_bypasses_pipeline() -> bool {
    matches!(CORS_PREFLIGHT_DISPATCH_POLICY, PreflightDispatchPolicy::BypassPipeline)
}

pub(crate) const fn cors_preflight_uses_resolved_target() -> bool {
    matches!(CORS_PREFLIGHT_BUCKET_SOURCE, PreflightBucketSourcePolicy::ResolvedTarget)
}

pub(crate) const fn cors_preflight_uses_matched_methods() -> bool {
    matches!(CORS_PREFLIGHT_ALLOW_METHODS_SOURCE, PreflightAllowMethodsSourcePolicy::MatchedRule)
}

pub(crate) const fn cors_preflight_includes_max_age() -> bool {
    matches!(CORS_PREFLIGHT_MAX_AGE_POLICY, PreflightMaxAgePolicy::Include)
}

pub(crate) const fn cors_preflight_includes_expose() -> bool {
    matches!(CORS_PREFLIGHT_EXPOSE_POLICY, PreflightExposePolicy::Include)
}

pub(crate) const fn cors_preflight_varies_on_origin() -> bool {
    matches!(CORS_PREFLIGHT_VARY_POLICY, PreflightVaryPolicy::Origin)
}

pub(crate) const fn cors_bare_wildcard_is_literal() -> bool {
    matches!(CORS_BARE_WILDCARD_ANSWER, BareWildcardAnswerPolicy::LiteralStar)
}

pub(crate) const fn cors_partial_wildcard_reflects() -> bool {
    matches!(CORS_PARTIAL_WILDCARD_ANSWER, PartialWildcardAnswerPolicy::ReflectOrigin)
}

pub(crate) const fn cors_wildcard_credentials_omitted() -> bool {
    matches!(CORS_WILDCARD_CREDENTIALS_POLICY, WildcardCredentialsPolicy::Omit)
}

pub(crate) const fn cors_exact_origin_match_is_exact() -> bool {
    matches!(CORS_EXACT_ORIGIN_MATCH, ExactOriginMatchPolicy::Exact)
}

pub(crate) const fn cors_origin_wildcard_checks_prefix() -> bool {
    matches!(CORS_ORIGIN_WILDCARD_MATCH, OriginWildcardMatchPolicy::PrefixAndSuffix)
}

pub(crate) const fn cors_actual_includes_allow_origin() -> bool {
    matches!(CORS_ACTUAL_ALLOW_ORIGIN_POLICY, ActualAllowOriginPolicy::Include)
}

pub(crate) const fn cors_actual_includes_expose() -> bool {
    matches!(CORS_ACTUAL_EXPOSE_POLICY, ActualExposePolicy::Include)
}

pub(crate) const fn cors_actual_varies_on_origin() -> bool {
    matches!(CORS_ACTUAL_VARY_POLICY, ActualVaryPolicy::Origin)
}

pub(crate) const fn cors_actual_omits_preflight_headers() -> bool {
    matches!(CORS_ACTUAL_PREFLIGHT_HEADER_POLICY, ActualPreflightHeaderPolicy::Omit)
}

pub(crate) const fn cors_unmatched_actual_has_no_headers() -> bool {
    matches!(CORS_UNMATCHED_ACTUAL_POLICY, UnmatchedActualPolicy::ServeWithoutCors)
}

pub(crate) const fn cors_requested_header_ignores_case() -> bool {
    matches!(CORS_REQUESTED_HEADER_CASE_POLICY, RequestedHeaderCasePolicy::AsciiInsensitive)
}

pub(crate) const fn cors_requested_header_uses_wildcard() -> bool {
    matches!(CORS_REQUESTED_HEADER_WILDCARD_MATCH, RequestedHeaderWildcardMatchPolicy::PrefixAndSuffix)
}

pub(crate) const fn cors_all_requested_headers_must_match() -> bool {
    matches!(CORS_REQUESTED_HEADER_QUANTIFIER, RequestedHeaderQuantifierPolicy::All)
}

pub(crate) const fn cors_allow_headers_echoes_request() -> bool {
    matches!(CORS_ALLOW_HEADERS_ANSWER_SOURCE, AllowHeadersAnswerSourcePolicy::RequestedHeaders)
}

pub(crate) const fn cors_first_matching_rule_wins() -> bool {
    matches!(CORS_RULE_ORDER_POLICY, CorsRuleOrderPolicy::FirstMatching)
}

pub(crate) const fn cors_match_dimensions_join_on_one_rule() -> bool {
    matches!(CORS_RULE_DIMENSION_JOIN, CorsRuleDimensionJoinPolicy::SameRule)
}

pub(crate) const fn cors_answer_uses_winning_rule() -> bool {
    matches!(CORS_MATCHED_RULE_VALUE_SOURCE, CorsMatchedRuleValueSourcePolicy::Winner)
}

pub(crate) const fn cors_headers_apply_to_post_auth_errors() -> bool {
    matches!(CORS_HEADERS_ON_POST_AUTH_ERROR, HeadersOnPostAuthErrorPolicy::Include)
}

pub(crate) const fn cors_preflight_refusal_is_uniform() -> bool {
    matches!(CORS_PREFLIGHT_REFUSAL_PROFILE, PreflightRefusalProfilePolicy::Uniform)
}

pub(crate) const fn cors_source_absence_is_collapsed() -> bool {
    matches!(CORS_SOURCE_ABSENCE_POLICY, CorsSourceAbsencePolicy::Collapse)
}

pub(crate) const fn cors_invalid_target_is_uniform_refusal() -> bool {
    matches!(CORS_INVALID_TARGET_POLICY, CorsInvalidTargetPolicy::UniformRefusal)
}

pub(crate) const fn cors_origin_requires_visible_ascii() -> bool {
    matches!(CORS_ORIGIN_CHARACTER_POLICY, CorsOriginCharacterPolicy::VisibleAscii)
}

pub(crate) const fn cors_origin_rejects_empty() -> bool {
    matches!(CORS_ORIGIN_EMPTY_POLICY, CorsOriginEmptyPolicy::Reject)
}

pub(crate) const fn cors_origin_max_bytes() -> Option<usize> {
    match CORS_ORIGIN_MAX_BYTES {
        CorsOriginMaxBytesPolicy::Max2048 => Some(2048),
        CorsOriginMaxBytesPolicy::Unbounded => None,
    }
}

pub(crate) const fn cors_origin_requires_exactly_one() -> bool {
    matches!(CORS_ORIGIN_CARDINALITY, CorsOriginCardinalityPolicy::ExactlyOne)
}

pub(crate) const fn cors_request_method_requires_exactly_one() -> bool {
    matches!(CORS_REQUEST_METHOD_CARDINALITY, CorsRequestMethodCardinalityPolicy::ExactlyOne)
}

pub(crate) const fn cors_request_headers_allow_at_most_one() -> bool {
    matches!(CORS_REQUEST_HEADERS_CARDINALITY, CorsRequestHeadersCardinalityPolicy::AtMostOne)
}

pub(crate) const fn cors_bare_options_is_routed() -> bool {
    matches!(CORS_BARE_OPTIONS_POLICY, CorsBareOptionsPolicy::Route)
}

pub(crate) const fn cors_preflight_requires_both_headers() -> bool {
    matches!(CORS_PREFLIGHT_REQUIRED_HEADER_PAIR, PreflightRequiredHeaderPairPolicy::Both)
}

pub(crate) const fn cors_preflight_grants_no_authorization() -> bool {
    matches!(CORS_PREFLIGHT_AUTHORIZATION_SCOPE, PreflightAuthorizationScopePolicy::NoGrant)
}
