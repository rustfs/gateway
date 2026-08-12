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

//! Strict parser for select and restore runtime-contract inputs.
//!
//! Responsible for: pairing every select/restore contract spelling with one typed current value
//! and one mutation dimension. NOT responsible for: consuming the value or loading TOML.
//! Upstream: the general contract parser. Downstream: runtime-contract code generation.

use crate::error::{Error, Result};

use super::MutationDimension;
use super::contract_values::{ContractRule, ContractValue};
use super::select_restore_contract_values::*;

pub(super) fn parse(dimension: &str, value: &str, id: &str) -> Result<Option<ContractRule>> {
    let Some((current, mutation_dimension)) = parse_value(dimension, value) else {
        if is_select_restore_dimension(dimension) {
            return Err(Error::Overlay(format!(
                "quirk `{id}`: unknown select/restore contract `{dimension}={value}`"
            )));
        }
        return Ok(None);
    };
    Ok(Some(ContractRule {
        current: ContractValue::SelectRestore(current),
        mutation_dimension,
    }))
}

macro_rules! pair {
    ($value_ty:ident::$value_variant:ident, $dimension:ident, $contract:ident) => {
        (
            SelectRestoreContractValue::$contract($value_ty::$value_variant),
            MutationDimension::$dimension,
        )
    };
}

fn parse_value(dimension: &str, value: &str) -> Option<(SelectRestoreContractValue, MutationDimension)> {
    Some(match (dimension, value) {
        ("restore_initiated_outcome", "success_202") => {
            pair!(RestoreInitiatedOutcomeValue::Success202, RestoreInitiatedOutcome, RestoreInitiatedOutcome)
        }
        ("restore_initiated_outcome", "success_200") => {
            pair!(RestoreInitiatedOutcomeValue::Success200, RestoreInitiatedOutcome, RestoreInitiatedOutcome)
        }
        ("restore_already_restored_outcome", "success_200") => pair!(
            RestoreAlreadyRestoredOutcomeValue::Success200,
            RestoreAlreadyRestoredOutcome,
            RestoreAlreadyRestoredOutcome
        ),
        ("restore_already_restored_outcome", "success_202") => pair!(
            RestoreAlreadyRestoredOutcomeValue::Success202,
            RestoreAlreadyRestoredOutcome,
            RestoreAlreadyRestoredOutcome
        ),
        ("restore_in_progress_outcome", "restore_already_in_progress") => pair!(
            RestoreInProgressOutcomeValue::RestoreAlreadyInProgress,
            RestoreInProgressOutcome,
            RestoreInProgressOutcome
        ),
        ("restore_in_progress_outcome", "success_202") => pair!(
            RestoreInProgressOutcomeValue::Success202,
            RestoreInProgressOutcome,
            RestoreInProgressOutcome
        ),
        ("restore_header_ongoing_form", "quoted_true") => pair!(
            RestoreHeaderOngoingFormValue::QuotedTrue,
            RestoreHeaderOngoingForm,
            RestoreHeaderOngoingForm
        ),
        ("restore_header_ongoing_form", "unquoted_true") => pair!(
            RestoreHeaderOngoingFormValue::UnquotedTrue,
            RestoreHeaderOngoingForm,
            RestoreHeaderOngoingForm
        ),
        ("restore_header_restored_form", "quoted_false_comma_space_expiry") => pair!(
            RestoreHeaderRestoredFormValue::QuotedFalseCommaSpaceExpiry,
            RestoreHeaderRestoredForm,
            RestoreHeaderRestoredForm
        ),
        ("restore_header_restored_form", "comma_without_space") => pair!(
            RestoreHeaderRestoredFormValue::CommaWithoutSpace,
            RestoreHeaderRestoredForm,
            RestoreHeaderRestoredForm
        ),
        ("restore_header_absence", "omit") => pair!(RestoreHeaderAbsenceValue::Omit, RestoreHeaderAbsence, RestoreHeaderAbsence),
        ("restore_header_absence", "emit_default") => {
            pair!(RestoreHeaderAbsenceValue::EmitDefault, RestoreHeaderAbsence, RestoreHeaderAbsence)
        }
        ("restore_header_parse_grammar", "strict_quoted_pairs") => pair!(
            RestoreHeaderParseGrammarValue::StrictQuotedPairs,
            RestoreHeaderParseGrammar,
            RestoreHeaderParseGrammar
        ),
        ("restore_header_parse_grammar", "accept_unquoted") => pair!(
            RestoreHeaderParseGrammarValue::AcceptUnquoted,
            RestoreHeaderParseGrammar,
            RestoreHeaderParseGrammar
        ),
        ("restore_not_archived_outcome", "invalid_object_state") => pair!(
            RestoreNotArchivedOutcomeValue::InvalidObjectState,
            RestoreNotArchivedOutcome,
            RestoreNotArchivedOutcome
        ),
        ("restore_not_archived_outcome", "success_noop") => pair!(
            RestoreNotArchivedOutcomeValue::SuccessNoop,
            RestoreNotArchivedOutcome,
            RestoreNotArchivedOutcome
        ),
        ("restore_days_minimum", "min_1") => pair!(RestoreDaysMinimumValue::Min1, RestoreDaysMinimum, RestoreDaysMinimum),
        ("restore_days_minimum", "min_0") => pair!(RestoreDaysMinimumValue::Min0, RestoreDaysMinimum, RestoreDaysMinimum),
        ("restore_form_presence", "require_days_or_select") => {
            pair!(RestoreFormPresenceValue::RequireDaysOrSelect, RestoreFormPresence, RestoreFormPresence)
        }
        ("restore_form_presence", "default_days") => {
            pair!(RestoreFormPresenceValue::DefaultDays, RestoreFormPresence, RestoreFormPresence)
        }
        ("restore_days_select_exclusion", "reject") => pair!(
            RestoreDaysSelectExclusionValue::Reject,
            RestoreDaysSelectExclusion,
            RestoreDaysSelectExclusion
        ),
        ("restore_days_select_exclusion", "prefer_select") => pair!(
            RestoreDaysSelectExclusionValue::PreferSelect,
            RestoreDaysSelectExclusion,
            RestoreDaysSelectExclusion
        ),
        ("restore_select_members_require_type", "reject") => pair!(
            RestoreSelectMembersRequireTypeValue::Reject,
            RestoreSelectMembersRequireType,
            RestoreSelectMembersRequireType
        ),
        ("restore_select_members_require_type", "allow") => pair!(
            RestoreSelectMembersRequireTypeValue::Allow,
            RestoreSelectMembersRequireType,
            RestoreSelectMembersRequireType
        ),
        ("restore_select_output_required", "require") => pair!(
            RestoreSelectOutputRequiredValue::Require,
            RestoreSelectOutputRequired,
            RestoreSelectOutputRequired
        ),
        ("restore_select_output_required", "allow_missing") => pair!(
            RestoreSelectOutputRequiredValue::AllowMissing,
            RestoreSelectOutputRequired,
            RestoreSelectOutputRequired
        ),
        ("restore_select_parameters_required", "require") => pair!(
            RestoreSelectParametersRequiredValue::Require,
            RestoreSelectParametersRequired,
            RestoreSelectParametersRequired
        ),
        ("restore_select_parameters_required", "allow_missing") => pair!(
            RestoreSelectParametersRequiredValue::AllowMissing,
            RestoreSelectParametersRequired,
            RestoreSelectParametersRequired
        ),
        ("restore_nested_select_validation", "shared") => pair!(
            RestoreNestedSelectValidationValue::Shared,
            RestoreNestedSelectValidation,
            RestoreNestedSelectValidation
        ),
        ("restore_nested_select_validation", "skip") => pair!(
            RestoreNestedSelectValidationValue::Skip,
            RestoreNestedSelectValidation,
            RestoreNestedSelectValidation
        ),
        ("restore_type_value_set", "select_only") => {
            pair!(RestoreTypeValueSetValue::SelectOnly, RestoreTypeValueSet, RestoreTypeValueSet)
        }
        ("restore_type_value_set", "open") => pair!(RestoreTypeValueSetValue::Open, RestoreTypeValueSet, RestoreTypeValueSet),
        ("restore_glacier_tier_value_set", "expedited_standard_bulk") => pair!(
            RestoreTierValueSetValue::ExpeditedStandardBulk,
            RestoreGlacierTierValueSet,
            RestoreGlacierTierValueSet
        ),
        ("restore_glacier_tier_value_set", "open") => {
            pair!(RestoreTierValueSetValue::Open, RestoreGlacierTierValueSet, RestoreGlacierTierValueSet)
        }
        ("restore_direct_tier_value_set", "expedited_standard_bulk") => pair!(
            RestoreTierValueSetValue::ExpeditedStandardBulk,
            RestoreDirectTierValueSet,
            RestoreDirectTierValueSet
        ),
        ("restore_direct_tier_value_set", "open") => {
            pair!(RestoreTierValueSetValue::Open, RestoreDirectTierValueSet, RestoreDirectTierValueSet)
        }
        ("restore_root_namespace_policy", "local_name") => pair!(
            RestoreRootNamespacePolicyValue::LocalName,
            RestoreRootNamespacePolicy,
            RestoreRootNamespacePolicy
        ),
        ("restore_root_namespace_policy", "qualified_name") => pair!(
            RestoreRootNamespacePolicyValue::QualifiedName,
            RestoreRootNamespacePolicy,
            RestoreRootNamespacePolicy
        ),
        ("restore_version_selector", "preserve") => {
            pair!(RestoreVersionSelectorValue::Preserve, RestoreVersionSelector, RestoreVersionSelector)
        }
        ("restore_version_selector", "drop") => {
            pair!(RestoreVersionSelectorValue::Drop, RestoreVersionSelector, RestoreVersionSelector)
        }
        ("select_type_route_predicate", "equals_2") => {
            pair!(SelectTypeRoutePredicateValue::Equals2, SelectTypeRoutePredicate, SelectTypeRoutePredicate)
        }
        ("select_type_route_predicate", "present_any_value") => pair!(
            SelectTypeRoutePredicateValue::PresentAnyValue,
            SelectTypeRoutePredicate,
            SelectTypeRoutePredicate
        ),
        ("select_expression_max_bytes", "max_262144") => pair!(
            SelectExpressionMaxBytesValue::Max262144,
            SelectExpressionMaxBytes,
            SelectExpressionMaxBytes
        ),
        ("select_expression_max_bytes", "unbounded") => pair!(
            SelectExpressionMaxBytesValue::Unbounded,
            SelectExpressionMaxBytes,
            SelectExpressionMaxBytes
        ),
        ("select_expression_presence", "nonempty") => pair!(
            SelectExpressionPresenceValue::Nonempty,
            SelectExpressionPresence,
            SelectExpressionPresence
        ),
        ("select_expression_presence", "allow_empty") => pair!(
            SelectExpressionPresenceValue::AllowEmpty,
            SelectExpressionPresence,
            SelectExpressionPresence
        ),
        ("select_expression_error_flow", "constant") => pair!(
            SelectExpressionErrorFlowValue::Constant,
            SelectExpressionErrorFlow,
            SelectExpressionErrorFlow
        ),
        ("select_expression_error_flow", "echo_rejected_value") => pair!(
            SelectExpressionErrorFlowValue::EchoRejectedValue,
            SelectExpressionErrorFlow,
            SelectExpressionErrorFlow
        ),
        ("select_expression_inspection", "length_only") => pair!(
            SelectExpressionInspectionValue::LengthOnly,
            SelectExpressionInspection,
            SelectExpressionInspection
        ),
        ("select_expression_inspection", "parse_or_log") => pair!(
            SelectExpressionInspectionValue::ParseOrLog,
            SelectExpressionInspection,
            SelectExpressionInspection
        ),
        ("select_input_multiple", "reject_conflict") => {
            pair!(SelectInputMultipleValue::RejectConflict, SelectInputMultiple, SelectInputMultiple)
        }
        ("select_input_multiple", "prefer_csv") => {
            pair!(SelectInputMultipleValue::PreferCsv, SelectInputMultiple, SelectInputMultiple)
        }
        ("select_input_missing", "reject_malformed") => {
            pair!(SelectInputMissingValue::RejectMalformed, SelectInputMissing, SelectInputMissing)
        }
        ("select_input_missing", "default_csv") => {
            pair!(SelectInputMissingValue::DefaultCsv, SelectInputMissing, SelectInputMissing)
        }
        ("select_output_multiple", "reject_conflict") => {
            pair!(SelectOutputMultipleValue::RejectConflict, SelectOutputMultiple, SelectOutputMultiple)
        }
        ("select_output_multiple", "prefer_csv") => {
            pair!(SelectOutputMultipleValue::PreferCsv, SelectOutputMultiple, SelectOutputMultiple)
        }
        ("select_output_missing", "reject_malformed") => {
            pair!(SelectOutputMissingValue::RejectMalformed, SelectOutputMissing, SelectOutputMissing)
        }
        ("select_output_missing", "default_csv") => {
            pair!(SelectOutputMissingValue::DefaultCsv, SelectOutputMissing, SelectOutputMissing)
        }
        ("select_scan_range_empty", "reject") => {
            pair!(SelectScanRangeEmptyValue::Reject, SelectScanRangeEmpty, SelectScanRangeEmpty)
        }
        ("select_scan_range_empty", "whole_object") => {
            pair!(SelectScanRangeEmptyValue::WholeObject, SelectScanRangeEmpty, SelectScanRangeEmpty)
        }
        ("select_scan_range_order", "end_gte_start") => {
            pair!(SelectScanRangeOrderValue::EndGteStart, SelectScanRangeOrder, SelectScanRangeOrder)
        }
        ("select_scan_range_order", "allow_inverted") => {
            pair!(SelectScanRangeOrderValue::AllowInverted, SelectScanRangeOrder, SelectScanRangeOrder)
        }
        ("select_scan_range_sign", "nonnegative") => {
            pair!(SelectScanRangeSignValue::Nonnegative, SelectScanRangeSign, SelectScanRangeSign)
        }
        ("select_scan_range_sign", "allow_negative") => {
            pair!(SelectScanRangeSignValue::AllowNegative, SelectScanRangeSign, SelectScanRangeSign)
        }
        ("select_scan_bounded", "inclusive_window") => {
            pair!(SelectScanBoundedValue::InclusiveWindow, SelectScanBounded, SelectScanBounded)
        }
        ("select_scan_bounded", "drop_range") => pair!(SelectScanBoundedValue::DropRange, SelectScanBounded, SelectScanBounded),
        ("select_scan_start_only", "from_start_to_end") => {
            pair!(SelectScanStartOnlyValue::FromStartToEnd, SelectScanStartOnly, SelectScanStartOnly)
        }
        ("select_scan_start_only", "whole_object") => {
            pair!(SelectScanStartOnlyValue::WholeObject, SelectScanStartOnly, SelectScanStartOnly)
        }
        ("select_scan_end_only", "suffix") => pair!(SelectScanEndOnlyValue::Suffix, SelectScanEndOnly, SelectScanEndOnly),
        ("select_scan_end_only", "prefix") => pair!(SelectScanEndOnlyValue::Prefix, SelectScanEndOnly, SelectScanEndOnly),
        ("select_expression_type_values", "sql_only") => pair!(
            SelectExpressionTypeValuesValue::SqlOnly,
            SelectExpressionTypeValues,
            SelectExpressionTypeValues
        ),
        ("select_expression_type_values", "open") => pair!(
            SelectExpressionTypeValuesValue::Open,
            SelectExpressionTypeValues,
            SelectExpressionTypeValues
        ),
        ("select_compression_values", "none_gzip_bzip2") => pair!(
            SelectCompressionValuesValue::NoneGzipBzip2,
            SelectCompressionValues,
            SelectCompressionValues
        ),
        ("select_compression_values", "open") => {
            pair!(SelectCompressionValuesValue::Open, SelectCompressionValues, SelectCompressionValues)
        }
        ("select_root_namespace_policy", "local_name") => pair!(
            SelectRootNamespacePolicyValue::LocalName,
            SelectRootNamespacePolicy,
            SelectRootNamespacePolicy
        ),
        ("select_root_namespace_policy", "qualified_name") => pair!(
            SelectRootNamespacePolicyValue::QualifiedName,
            SelectRootNamespacePolicy,
            SelectRootNamespacePolicy
        ),
        ("select_response_shape", "event_stream") => {
            pair!(SelectResponseShapeValue::EventStream, SelectResponseShape, SelectResponseShape)
        }
        ("select_response_shape", "settled_output") => {
            pair!(SelectResponseShapeValue::SettledOutput, SelectResponseShape, SelectResponseShape)
        }
        ("select_event_status", "success_200") => pair!(SelectEventStatusValue::Success200, SelectEventStatus, SelectEventStatus),
        ("select_event_status", "success_202") => pair!(SelectEventStatusValue::Success202, SelectEventStatus, SelectEventStatus),
        ("select_event_media_type", "application_vnd_amazon_event_stream") => pair!(
            SelectEventMediaTypeValue::ApplicationVndAmazonEventStream,
            SelectEventMediaType,
            SelectEventMediaType
        ),
        ("select_event_media_type", "octet_stream") => {
            pair!(SelectEventMediaTypeValue::OctetStream, SelectEventMediaType, SelectEventMediaType)
        }
        ("event_prelude_crc_coverage", "first_8") => {
            pair!(EventPreludeCrcCoverageValue::First8, EventPreludeCrcCoverage, EventPreludeCrcCoverage)
        }
        ("event_prelude_crc_coverage", "first_12") => {
            pair!(EventPreludeCrcCoverageValue::First12, EventPreludeCrcCoverage, EventPreludeCrcCoverage)
        }
        ("event_message_crc_coverage", "frame_without_crc") => pair!(
            EventMessageCrcCoverageValue::FrameWithoutCrc,
            EventMessageCrcCoverage,
            EventMessageCrcCoverage
        ),
        ("event_message_crc_coverage", "payload_only") => pair!(
            EventMessageCrcCoverageValue::PayloadOnly,
            EventMessageCrcCoverage,
            EventMessageCrcCoverage
        ),
        ("event_crc_algorithm", "crc32_iso_hdlc") => {
            pair!(EventCrcAlgorithmValue::Crc32IsoHdlc, EventCrcAlgorithm, EventCrcAlgorithm)
        }
        ("event_crc_algorithm", "crc32c") => pair!(EventCrcAlgorithmValue::Crc32c, EventCrcAlgorithm, EventCrcAlgorithm),
        ("select_event_termination", "records_stats_end") => pair!(
            SelectEventTerminationValue::RecordsStatsEnd,
            SelectEventTermination,
            SelectEventTermination
        ),
        ("select_event_termination", "omit_end") => {
            pair!(SelectEventTerminationValue::OmitEnd, SelectEventTermination, SelectEventTermination)
        }
        _ => return None,
    })
}

fn is_select_restore_dimension(dimension: &str) -> bool {
    matches!(
        dimension,
        "restore_initiated_outcome"
            | "restore_already_restored_outcome"
            | "restore_in_progress_outcome"
            | "restore_header_ongoing_form"
            | "restore_header_restored_form"
            | "restore_header_absence"
            | "restore_header_parse_grammar"
            | "restore_not_archived_outcome"
            | "restore_days_minimum"
            | "restore_form_presence"
            | "restore_days_select_exclusion"
            | "restore_select_members_require_type"
            | "restore_select_output_required"
            | "restore_select_parameters_required"
            | "restore_nested_select_validation"
            | "restore_type_value_set"
            | "restore_glacier_tier_value_set"
            | "restore_direct_tier_value_set"
            | "restore_root_namespace_policy"
            | "restore_version_selector"
            | "select_type_route_predicate"
            | "select_expression_max_bytes"
            | "select_expression_presence"
            | "select_expression_error_flow"
            | "select_expression_inspection"
            | "select_input_multiple"
            | "select_input_missing"
            | "select_output_multiple"
            | "select_output_missing"
            | "select_scan_range_empty"
            | "select_scan_range_order"
            | "select_scan_range_sign"
            | "select_scan_bounded"
            | "select_scan_start_only"
            | "select_scan_end_only"
            | "select_expression_type_values"
            | "select_compression_values"
            | "select_root_namespace_policy"
            | "select_response_shape"
            | "select_event_status"
            | "select_event_media_type"
            | "event_prelude_crc_coverage"
            | "event_message_crc_coverage"
            | "event_crc_algorithm"
            | "select_event_termination"
    )
}
