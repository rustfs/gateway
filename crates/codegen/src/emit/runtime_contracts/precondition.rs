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

//! Runtime-contract emission for conditional and byte-range policies.
//!
//! Responsible for: mapping typed precondition values to core constants. NOT responsible for:
//! other contract families or file output. Upstream: model contract rules. Downstream: the core
//! generated contract module.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rustfs_gateway_model::{
    BareConditionalEtagPolicyValue, CompletionFailureUploadPolicyValue, ConditionalRaceOutcomeValue, ContractRule, ContractValue,
    CopyRangeLengthArithmeticValue, IfNoneMatchComparisonStrengthValue, IfRangeMissPolicyValue, MutationDimension,
    NotModifiedBodyPolicyValue, NotModifiedEtagPolicyValue, NotModifiedFramingPolicyValue, PartCountHeaderPolicyValue,
    PartNumberOutcomeValue, PartialChecksumPolicyValue, RangePartSelectorConflictValue, RangeRequestedDetailValue,
    ReadRangeLengthArithmeticValue, UnsatisfiableActualSizeDetailValue,
};

use super::{unique, wrong_type};

pub(super) fn render(rules: &BTreeMap<String, ContractRule>, out: &mut String) -> Result<(), String> {
    render_enum(
        out,
        "NOT_MODIFIED_ETAG_POLICY",
        "Not-modified entity-tag policy.",
        value(rules, MutationDimension::NotModifiedEtagPolicy, |v| match v {
            ContractValue::NotModifiedEtagPolicy(NotModifiedEtagPolicyValue::IncludeSelected) => {
                Some("NotModifiedEtagPolicy::IncludeSelected")
            }
            ContractValue::NotModifiedEtagPolicy(NotModifiedEtagPolicyValue::Omit) => Some("NotModifiedEtagPolicy::Omit"),
            _ => None,
        })?,
        "NotModifiedEtagPolicy",
    );
    render_enum(
        out,
        "COMPLETION_FAILURE_UPLOAD_POLICY",
        "Failed-completion upload policy.",
        value(rules, MutationDimension::CompletionFailureUploadPolicy, |v| match v {
            ContractValue::CompletionFailureUploadPolicy(CompletionFailureUploadPolicyValue::Retain) => {
                Some("CompletionFailureUploadPolicy::Retain")
            }
            ContractValue::CompletionFailureUploadPolicy(CompletionFailureUploadPolicyValue::Consume) => {
                Some("CompletionFailureUploadPolicy::Consume")
            }
            _ => None,
        })?,
        "CompletionFailureUploadPolicy",
    );
    render_enum(
        out,
        "CONDITIONAL_RACE_OUTCOME_POLICY",
        "Conditional-race outcome.",
        value(rules, MutationDimension::ConditionalRaceOutcome, |v| match v {
            ContractValue::ConditionalRaceOutcome(ConditionalRaceOutcomeValue::Conflict) => {
                Some("ConditionalRaceOutcomePolicy::Conflict")
            }
            ContractValue::ConditionalRaceOutcome(ConditionalRaceOutcomeValue::PreconditionFailed) => {
                Some("ConditionalRaceOutcomePolicy::PreconditionFailed")
            }
            _ => None,
        })?,
        "ConditionalRaceOutcomePolicy",
    );
    render_enum(
        out,
        "UNSATISFIABLE_ACTUAL_SIZE_DETAIL_POLICY",
        "Unsatisfiable actual-size detail policy.",
        value(rules, MutationDimension::UnsatisfiableActualSizeDetail, |v| match v {
            ContractValue::UnsatisfiableActualSizeDetail(UnsatisfiableActualSizeDetailValue::Include) => {
                Some("UnsatisfiableActualSizeDetailPolicy::Include")
            }
            ContractValue::UnsatisfiableActualSizeDetail(UnsatisfiableActualSizeDetailValue::Omit) => {
                Some("UnsatisfiableActualSizeDetailPolicy::Omit")
            }
            _ => None,
        })?,
        "UnsatisfiableActualSizeDetailPolicy",
    );
    render_enum(
        out,
        "PARTIAL_CHECKSUM_POLICY",
        "Partial-response checksum policy.",
        value(rules, MutationDimension::PartialChecksumPolicy, |v| match v {
            ContractValue::PartialChecksumPolicy(PartialChecksumPolicyValue::SuppressWholeObject) => {
                Some("PartialChecksumPolicy::SuppressWholeObject")
            }
            ContractValue::PartialChecksumPolicy(PartialChecksumPolicyValue::IncludeWholeObject) => {
                Some("PartialChecksumPolicy::IncludeWholeObject")
            }
            _ => None,
        })?,
        "PartialChecksumPolicy",
    );
    render_enum(
        out,
        "PART_NUMBER_OUTCOME_POLICY",
        "Part-number response outcome.",
        value(rules, MutationDimension::PartNumberOutcome, |v| match v {
            ContractValue::PartNumberOutcome(PartNumberOutcomeValue::PartialContent) => {
                Some("PartNumberOutcomePolicy::PartialContent")
            }
            ContractValue::PartNumberOutcome(PartNumberOutcomeValue::ServeWhole) => Some("PartNumberOutcomePolicy::ServeWhole"),
            _ => None,
        })?,
        "PartNumberOutcomePolicy",
    );
    render_enum(
        out,
        "IF_RANGE_MISS_POLICY",
        "If-Range miss policy.",
        value(rules, MutationDimension::IfRangeMissPolicy, |v| match v {
            ContractValue::IfRangeMissPolicy(IfRangeMissPolicyValue::ServeWhole) => Some("IfRangeMissPolicy::ServeWhole"),
            ContractValue::IfRangeMissPolicy(IfRangeMissPolicyValue::ServePartial) => Some("IfRangeMissPolicy::ServePartial"),
            _ => None,
        })?,
        "IfRangeMissPolicy",
    );
    render_enum(
        out,
        "IF_NONE_MATCH_COMPARISON_STRENGTH",
        "If-None-Match comparison strength.",
        value(rules, MutationDimension::IfNoneMatchComparisonStrength, |v| match v {
            ContractValue::IfNoneMatchComparisonStrength(IfNoneMatchComparisonStrengthValue::Weak) => {
                Some("IfNoneMatchComparisonStrengthPolicy::Weak")
            }
            ContractValue::IfNoneMatchComparisonStrength(IfNoneMatchComparisonStrengthValue::Strong) => {
                Some("IfNoneMatchComparisonStrengthPolicy::Strong")
            }
            _ => None,
        })?,
        "IfNoneMatchComparisonStrengthPolicy",
    );
    render_enum(
        out,
        "BARE_CONDITIONAL_ETAG_POLICY",
        "Bare conditional entity-tag policy.",
        value(rules, MutationDimension::BareConditionalEtagPolicy, |v| match v {
            ContractValue::BareConditionalEtagPolicy(BareConditionalEtagPolicyValue::AcceptAndNormalize) => {
                Some("BareConditionalEtagPolicy::AcceptAndNormalize")
            }
            ContractValue::BareConditionalEtagPolicy(BareConditionalEtagPolicyValue::Reject) => {
                Some("BareConditionalEtagPolicy::Reject")
            }
            _ => None,
        })?,
        "BareConditionalEtagPolicy",
    );
    render_enum(
        out,
        "NOT_MODIFIED_BODY_POLICY",
        "Not-modified content-byte policy.",
        value(rules, MutationDimension::NotModifiedBodyPolicy, |v| match v {
            ContractValue::NotModifiedBodyPolicy(NotModifiedBodyPolicyValue::Suppress) => Some("NotModifiedBodyPolicy::Suppress"),
            ContractValue::NotModifiedBodyPolicy(NotModifiedBodyPolicyValue::Preserve) => Some("NotModifiedBodyPolicy::Preserve"),
            _ => None,
        })?,
        "NotModifiedBodyPolicy",
    );
    render_enum(
        out,
        "NOT_MODIFIED_FRAMING_POLICY",
        "Not-modified framing policy.",
        value(rules, MutationDimension::NotModifiedFramingPolicy, |v| match v {
            ContractValue::NotModifiedFramingPolicy(NotModifiedFramingPolicyValue::Omit) => {
                Some("NotModifiedFramingPolicy::Omit")
            }
            ContractValue::NotModifiedFramingPolicy(NotModifiedFramingPolicyValue::Preserve) => {
                Some("NotModifiedFramingPolicy::Preserve")
            }
            _ => None,
        })?,
        "NotModifiedFramingPolicy",
    );
    render_enum(
        out,
        "READ_RANGE_LENGTH_ARITHMETIC",
        "Read-range length arithmetic.",
        value(rules, MutationDimension::ReadRangeLengthArithmetic, |v| match v {
            ContractValue::ReadRangeLengthArithmetic(ReadRangeLengthArithmeticValue::Inclusive) => {
                Some("ReadRangeLengthArithmetic::Inclusive")
            }
            ContractValue::ReadRangeLengthArithmetic(ReadRangeLengthArithmeticValue::Exclusive) => {
                Some("ReadRangeLengthArithmetic::Exclusive")
            }
            _ => None,
        })?,
        "ReadRangeLengthArithmetic",
    );
    render_enum(
        out,
        "COPY_RANGE_LENGTH_ARITHMETIC",
        "Copy-range length arithmetic.",
        value(rules, MutationDimension::CopyRangeLengthArithmetic, |v| match v {
            ContractValue::CopyRangeLengthArithmetic(CopyRangeLengthArithmeticValue::Inclusive) => {
                Some("CopyRangeLengthArithmetic::Inclusive")
            }
            ContractValue::CopyRangeLengthArithmetic(CopyRangeLengthArithmeticValue::Exclusive) => {
                Some("CopyRangeLengthArithmetic::Exclusive")
            }
            _ => None,
        })?,
        "CopyRangeLengthArithmetic",
    );
    render_enum(
        out,
        "RANGE_REQUESTED_DETAIL_POLICY",
        "Range-requested detail policy.",
        value(rules, MutationDimension::RangeRequestedDetail, |v| match v {
            ContractValue::RangeRequestedDetail(RangeRequestedDetailValue::Verbatim) => {
                Some("RangeRequestedDetailPolicy::Verbatim")
            }
            ContractValue::RangeRequestedDetail(RangeRequestedDetailValue::Normalized) => {
                Some("RangeRequestedDetailPolicy::Normalized")
            }
            _ => None,
        })?,
        "RangeRequestedDetailPolicy",
    );
    render_enum(
        out,
        "PART_COUNT_HEADER_POLICY",
        "Part-count header policy.",
        value(rules, MutationDimension::PartCountHeaderPolicy, |v| match v {
            ContractValue::PartCountHeaderPolicy(PartCountHeaderPolicyValue::IncludeTotal) => {
                Some("PartCountHeaderPolicy::IncludeTotal")
            }
            ContractValue::PartCountHeaderPolicy(PartCountHeaderPolicyValue::Omit) => Some("PartCountHeaderPolicy::Omit"),
            _ => None,
        })?,
        "PartCountHeaderPolicy",
    );
    render_enum(
        out,
        "RANGE_PART_SELECTOR_CONFLICT_POLICY",
        "Range and part-number conflict policy.",
        value(rules, MutationDimension::RangePartSelectorConflict, |v| match v {
            ContractValue::RangePartSelectorConflict(RangePartSelectorConflictValue::Reject) => {
                Some("RangePartSelectorConflictPolicy::Reject")
            }
            ContractValue::RangePartSelectorConflict(RangePartSelectorConflictValue::PreferPart) => {
                Some("RangePartSelectorConflictPolicy::PreferPart")
            }
            _ => None,
        })?,
        "RangePartSelectorConflictPolicy",
    );
    Ok(())
}

fn value(
    rules: &BTreeMap<String, ContractRule>,
    dimension: MutationDimension,
    map: impl FnOnce(&ContractValue) -> Option<&'static str>,
) -> Result<&'static str, String> {
    map(unique(rules, dimension)?).ok_or_else(|| wrong_type(dimension))
}

fn render_enum(out: &mut String, name: &str, docs: &str, value: &str, ty: &str) {
    writeln!(out, "/// {docs}\npub(crate) const {name}: {ty} = {value};").expect("writing to String cannot fail");
}
