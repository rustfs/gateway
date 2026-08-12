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

//! Parser for conditional and byte-range runtime-contract inputs.
//!
//! Responsible for: mapping one dimension/value pair to its typed contract value.
//! NOT responsible for: loading TOML or consuming the selected value. Upstream: the general contract parser.
//! Downstream: the overlay contract-rule table.

use crate::error::Result;

use super::MutationDimension;
use super::contract_values::{ContractRule, ContractValue};
use super::precondition_contract_values::*;

pub(super) fn parse(dimension: &str, value: &str) -> Result<Option<ContractRule>> {
    let Some((current, mutation_dimension)) = parse_value(dimension, value) else {
        return Ok(None);
    };
    Ok(Some(ContractRule {
        current,
        mutation_dimension,
    }))
}

fn parse_value(dimension: &str, value: &str) -> Option<(ContractValue, MutationDimension)> {
    let pair = match (dimension, value) {
        ("not_modified_etag_policy", "include_selected") => (
            ContractValue::NotModifiedEtagPolicy(NotModifiedEtagPolicyValue::IncludeSelected),
            MutationDimension::NotModifiedEtagPolicy,
        ),
        ("not_modified_etag_policy", "omit") => (
            ContractValue::NotModifiedEtagPolicy(NotModifiedEtagPolicyValue::Omit),
            MutationDimension::NotModifiedEtagPolicy,
        ),
        ("completion_failure_upload_policy", "retain") => (
            ContractValue::CompletionFailureUploadPolicy(CompletionFailureUploadPolicyValue::Retain),
            MutationDimension::CompletionFailureUploadPolicy,
        ),
        ("completion_failure_upload_policy", "consume") => (
            ContractValue::CompletionFailureUploadPolicy(CompletionFailureUploadPolicyValue::Consume),
            MutationDimension::CompletionFailureUploadPolicy,
        ),
        ("conditional_race_outcome", "conflict") => (
            ContractValue::ConditionalRaceOutcome(ConditionalRaceOutcomeValue::Conflict),
            MutationDimension::ConditionalRaceOutcome,
        ),
        ("conditional_race_outcome", "precondition_failed") => (
            ContractValue::ConditionalRaceOutcome(ConditionalRaceOutcomeValue::PreconditionFailed),
            MutationDimension::ConditionalRaceOutcome,
        ),
        ("multi_range_policy", "serve_whole") => (
            ContractValue::MultiRangePolicy(MultiRangePolicyValue::ServeWhole),
            MutationDimension::MultiRangePolicy,
        ),
        ("multi_range_policy", "reject") => (
            ContractValue::MultiRangePolicy(MultiRangePolicyValue::Reject),
            MutationDimension::MultiRangePolicy,
        ),
        ("explicit_end_overflow_policy", "clamp") => (
            ContractValue::ExplicitEndOverflowPolicy(ExplicitEndOverflowPolicyValue::Clamp),
            MutationDimension::ExplicitEndOverflowPolicy,
        ),
        ("explicit_end_overflow_policy", "unsatisfiable") => (
            ContractValue::ExplicitEndOverflowPolicy(ExplicitEndOverflowPolicyValue::Unsatisfiable),
            MutationDimension::ExplicitEndOverflowPolicy,
        ),
        ("suffix_range_policy", "supported") => (
            ContractValue::SuffixRangePolicy(SuffixRangePolicyValue::Supported),
            MutationDimension::SuffixRangePolicy,
        ),
        ("suffix_range_policy", "ignore") => (
            ContractValue::SuffixRangePolicy(SuffixRangePolicyValue::Ignore),
            MutationDimension::SuffixRangePolicy,
        ),
        ("oversize_suffix_policy", "clamp_to_whole_partial") => (
            ContractValue::OversizeSuffixPolicy(OversizeSuffixPolicyValue::ClampToWholePartial),
            MutationDimension::OversizeSuffixPolicy,
        ),
        ("oversize_suffix_policy", "unsatisfiable") => (
            ContractValue::OversizeSuffixPolicy(OversizeSuffixPolicyValue::Unsatisfiable),
            MutationDimension::OversizeSuffixPolicy,
        ),
        ("unsatisfiable_actual_size_detail", "include") => (
            ContractValue::UnsatisfiableActualSizeDetail(UnsatisfiableActualSizeDetailValue::Include),
            MutationDimension::UnsatisfiableActualSizeDetail,
        ),
        ("unsatisfiable_actual_size_detail", "omit") => (
            ContractValue::UnsatisfiableActualSizeDetail(UnsatisfiableActualSizeDetailValue::Omit),
            MutationDimension::UnsatisfiableActualSizeDetail,
        ),
        ("partial_checksum_policy", "suppress_whole_object") => (
            ContractValue::PartialChecksumPolicy(PartialChecksumPolicyValue::SuppressWholeObject),
            MutationDimension::PartialChecksumPolicy,
        ),
        ("partial_checksum_policy", "include_whole_object") => (
            ContractValue::PartialChecksumPolicy(PartialChecksumPolicyValue::IncludeWholeObject),
            MutationDimension::PartialChecksumPolicy,
        ),
        ("part_number_outcome", "partial_content") => (
            ContractValue::PartNumberOutcome(PartNumberOutcomeValue::PartialContent),
            MutationDimension::PartNumberOutcome,
        ),
        ("part_number_outcome", "serve_whole") => (
            ContractValue::PartNumberOutcome(PartNumberOutcomeValue::ServeWhole),
            MutationDimension::PartNumberOutcome,
        ),
        ("invalid_range_policy", "serve_whole") => (
            ContractValue::InvalidRangePolicy(InvalidRangePolicyValue::ServeWhole),
            MutationDimension::InvalidRangePolicy,
        ),
        ("invalid_range_policy", "reject") => (
            ContractValue::InvalidRangePolicy(InvalidRangePolicyValue::Reject),
            MutationDimension::InvalidRangePolicy,
        ),
        ("if_range_miss_policy", "serve_whole") => (
            ContractValue::IfRangeMissPolicy(IfRangeMissPolicyValue::ServeWhole),
            MutationDimension::IfRangeMissPolicy,
        ),
        ("if_range_miss_policy", "serve_partial") => (
            ContractValue::IfRangeMissPolicy(IfRangeMissPolicyValue::ServePartial),
            MutationDimension::IfRangeMissPolicy,
        ),
        ("if_none_match_comparison_strength", "weak") => (
            ContractValue::IfNoneMatchComparisonStrength(IfNoneMatchComparisonStrengthValue::Weak),
            MutationDimension::IfNoneMatchComparisonStrength,
        ),
        ("if_none_match_comparison_strength", "strong") => (
            ContractValue::IfNoneMatchComparisonStrength(IfNoneMatchComparisonStrengthValue::Strong),
            MutationDimension::IfNoneMatchComparisonStrength,
        ),
        ("bare_conditional_etag_policy", "accept_and_normalize") => (
            ContractValue::BareConditionalEtagPolicy(BareConditionalEtagPolicyValue::AcceptAndNormalize),
            MutationDimension::BareConditionalEtagPolicy,
        ),
        ("bare_conditional_etag_policy", "reject") => (
            ContractValue::BareConditionalEtagPolicy(BareConditionalEtagPolicyValue::Reject),
            MutationDimension::BareConditionalEtagPolicy,
        ),
        ("not_modified_body_policy", "suppress") => (
            ContractValue::NotModifiedBodyPolicy(NotModifiedBodyPolicyValue::Suppress),
            MutationDimension::NotModifiedBodyPolicy,
        ),
        ("not_modified_body_policy", "preserve") => (
            ContractValue::NotModifiedBodyPolicy(NotModifiedBodyPolicyValue::Preserve),
            MutationDimension::NotModifiedBodyPolicy,
        ),
        ("not_modified_framing_policy", "omit") => (
            ContractValue::NotModifiedFramingPolicy(NotModifiedFramingPolicyValue::Omit),
            MutationDimension::NotModifiedFramingPolicy,
        ),
        ("not_modified_framing_policy", "preserve") => (
            ContractValue::NotModifiedFramingPolicy(NotModifiedFramingPolicyValue::Preserve),
            MutationDimension::NotModifiedFramingPolicy,
        ),
        ("range_start_bound", "at_or_beyond_unsatisfiable") => (
            ContractValue::RangeStartBound(RangeStartBoundValue::AtOrBeyondUnsatisfiable),
            MutationDimension::RangeStartBound,
        ),
        ("range_start_bound", "past_end_only") => (
            ContractValue::RangeStartBound(RangeStartBoundValue::PastEndOnly),
            MutationDimension::RangeStartBound,
        ),
        ("open_ended_range_policy", "through_last") => (
            ContractValue::OpenEndedRangePolicy(OpenEndedRangePolicyValue::ThroughLast),
            MutationDimension::OpenEndedRangePolicy,
        ),
        ("open_ended_range_policy", "empty_at_last") => (
            ContractValue::OpenEndedRangePolicy(OpenEndedRangePolicyValue::EmptyAtLast),
            MutationDimension::OpenEndedRangePolicy,
        ),
        ("read_range_length_arithmetic", "inclusive") => (
            ContractValue::ReadRangeLengthArithmetic(ReadRangeLengthArithmeticValue::Inclusive),
            MutationDimension::ReadRangeLengthArithmetic,
        ),
        ("read_range_length_arithmetic", "exclusive") => (
            ContractValue::ReadRangeLengthArithmetic(ReadRangeLengthArithmeticValue::Exclusive),
            MutationDimension::ReadRangeLengthArithmetic,
        ),
        ("copy_range_length_arithmetic", "inclusive") => (
            ContractValue::CopyRangeLengthArithmetic(CopyRangeLengthArithmeticValue::Inclusive),
            MutationDimension::CopyRangeLengthArithmetic,
        ),
        ("copy_range_length_arithmetic", "exclusive") => (
            ContractValue::CopyRangeLengthArithmetic(CopyRangeLengthArithmeticValue::Exclusive),
            MutationDimension::CopyRangeLengthArithmetic,
        ),
        ("range_requested_detail", "verbatim") => (
            ContractValue::RangeRequestedDetail(RangeRequestedDetailValue::Verbatim),
            MutationDimension::RangeRequestedDetail,
        ),
        ("range_requested_detail", "normalized") => (
            ContractValue::RangeRequestedDetail(RangeRequestedDetailValue::Normalized),
            MutationDimension::RangeRequestedDetail,
        ),
        ("part_count_header_policy", "include_total") => (
            ContractValue::PartCountHeaderPolicy(PartCountHeaderPolicyValue::IncludeTotal),
            MutationDimension::PartCountHeaderPolicy,
        ),
        ("part_count_header_policy", "omit") => (
            ContractValue::PartCountHeaderPolicy(PartCountHeaderPolicyValue::Omit),
            MutationDimension::PartCountHeaderPolicy,
        ),
        ("range_part_selector_conflict", "reject") => (
            ContractValue::RangePartSelectorConflict(RangePartSelectorConflictValue::Reject),
            MutationDimension::RangePartSelectorConflict,
        ),
        ("range_part_selector_conflict", "prefer_part") => (
            ContractValue::RangePartSelectorConflict(RangePartSelectorConflictValue::PreferPart),
            MutationDimension::RangePartSelectorConflict,
        ),
        _ => return None,
    };
    Some(pair)
}
