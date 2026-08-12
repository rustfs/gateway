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

//! Runtime-contract emission for select and restore policies.
//!
//! Responsible for: mapping each typed select/restore value to one generated core constant.
//! NOT responsible for: other contract families or runtime behavior. Upstream: model contract rules.
//! Downstream: the core generated contract module.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rustfs_gateway_model::*;

use super::{unique, wrong_type};

macro_rules! render_contract {
    ($rules:expr, $out:expr, $dimension:ident, $contract:ident, $value_ty:ident,
     $current:ident, $mutant:ident, $name:literal, $policy:ident, $docs:literal) => {{
        let rendered = match unique($rules, MutationDimension::$dimension)? {
            ContractValue::SelectRestore(SelectRestoreContractValue::$contract($value_ty::$current)) => {
                concat!(stringify!($policy), "::", stringify!($current))
            }
            ContractValue::SelectRestore(SelectRestoreContractValue::$contract($value_ty::$mutant)) => {
                concat!(stringify!($policy), "::", stringify!($mutant))
            }
            _ => return Err(wrong_type(MutationDimension::$dimension)),
        };
        writeln!($out, "/// {}\npub(crate) const {}: {} = {};", $docs, $name, stringify!($policy), rendered)
            .expect("writing to String cannot fail");
    }};
}

pub(super) fn render(rules: &BTreeMap<String, ContractRule>, out: &mut String) -> std::result::Result<(), String> {
    render_contract!(
        rules,
        out,
        RestoreInitiatedOutcome,
        RestoreInitiatedOutcome,
        RestoreInitiatedOutcomeValue,
        Success202,
        Success200,
        "RESTORE_INITIATED_OUTCOME",
        RestoreInitiatedOutcomePolicy,
        "Outcome for a newly initiated restore."
    );
    render_contract!(
        rules,
        out,
        RestoreAlreadyRestoredOutcome,
        RestoreAlreadyRestoredOutcome,
        RestoreAlreadyRestoredOutcomeValue,
        Success200,
        Success202,
        "RESTORE_ALREADY_RESTORED_OUTCOME",
        RestoreAlreadyRestoredOutcomePolicy,
        "Outcome for an already-restored object."
    );
    render_contract!(
        rules,
        out,
        RestoreInProgressOutcome,
        RestoreInProgressOutcome,
        RestoreInProgressOutcomeValue,
        RestoreAlreadyInProgress,
        Success202,
        "RESTORE_IN_PROGRESS_OUTCOME",
        RestoreInProgressOutcomePolicy,
        "Outcome while retrieval is in progress."
    );
    render_contract!(
        rules,
        out,
        RestoreHeaderOngoingForm,
        RestoreHeaderOngoingForm,
        RestoreHeaderOngoingFormValue,
        QuotedTrue,
        UnquotedTrue,
        "RESTORE_HEADER_ONGOING_FORM",
        RestoreHeaderOngoingFormPolicy,
        "Ongoing restore-header spelling."
    );
    render_contract!(
        rules,
        out,
        RestoreHeaderRestoredForm,
        RestoreHeaderRestoredForm,
        RestoreHeaderRestoredFormValue,
        QuotedFalseCommaSpaceExpiry,
        CommaWithoutSpace,
        "RESTORE_HEADER_RESTORED_FORM",
        RestoreHeaderRestoredFormPolicy,
        "Completed restore-header spelling."
    );
    render_contract!(
        rules,
        out,
        RestoreHeaderAbsence,
        RestoreHeaderAbsence,
        RestoreHeaderAbsenceValue,
        Omit,
        EmitDefault,
        "RESTORE_HEADER_ABSENCE",
        RestoreHeaderAbsencePolicy,
        "Absent restore-header policy."
    );
    render_contract!(
        rules,
        out,
        RestoreHeaderParseGrammar,
        RestoreHeaderParseGrammar,
        RestoreHeaderParseGrammarValue,
        StrictQuotedPairs,
        AcceptUnquoted,
        "RESTORE_HEADER_PARSE_GRAMMAR",
        RestoreHeaderParseGrammarPolicy,
        "Restore-header parser grammar."
    );
    render_contract!(
        rules,
        out,
        RestoreNotArchivedOutcome,
        RestoreNotArchivedOutcome,
        RestoreNotArchivedOutcomeValue,
        InvalidObjectState,
        SuccessNoop,
        "RESTORE_NOT_ARCHIVED_OUTCOME",
        RestoreNotArchivedOutcomePolicy,
        "Outcome for a non-archive object."
    );
    render_contract!(
        rules,
        out,
        RestoreDaysMinimum,
        RestoreDaysMinimum,
        RestoreDaysMinimumValue,
        Min1,
        Min0,
        "RESTORE_DAYS_MINIMUM",
        RestoreDaysMinimumPolicy,
        "Inclusive minimum restore duration."
    );
    render_contract!(
        rules,
        out,
        RestoreFormPresence,
        RestoreFormPresence,
        RestoreFormPresenceValue,
        RequireDaysOrSelect,
        DefaultDays,
        "RESTORE_FORM_PRESENCE",
        RestoreFormPresencePolicy,
        "Restore form-presence policy."
    );
    render_contract!(
        rules,
        out,
        RestoreDaysSelectExclusion,
        RestoreDaysSelectExclusion,
        RestoreDaysSelectExclusionValue,
        Reject,
        PreferSelect,
        "RESTORE_DAYS_SELECT_EXCLUSION",
        RestoreDaysSelectExclusionPolicy,
        "Days and select-form exclusion policy."
    );
    render_contract!(
        rules,
        out,
        RestoreSelectMembersRequireType,
        RestoreSelectMembersRequireType,
        RestoreSelectMembersRequireTypeValue,
        Reject,
        Allow,
        "RESTORE_SELECT_MEMBERS_REQUIRE_TYPE",
        RestoreSelectMembersRequireTypePolicy,
        "Select-member Type requirement."
    );
    render_contract!(
        rules,
        out,
        RestoreSelectOutputRequired,
        RestoreSelectOutputRequired,
        RestoreSelectOutputRequiredValue,
        Require,
        AllowMissing,
        "RESTORE_SELECT_OUTPUT_REQUIRED",
        RestoreSelectOutputRequiredPolicy,
        "Select-restore output-location requirement."
    );
    render_contract!(
        rules,
        out,
        RestoreSelectParametersRequired,
        RestoreSelectParametersRequired,
        RestoreSelectParametersRequiredValue,
        Require,
        AllowMissing,
        "RESTORE_SELECT_PARAMETERS_REQUIRED",
        RestoreSelectParametersRequiredPolicy,
        "Select-restore parameter requirement."
    );
    render_contract!(
        rules,
        out,
        RestoreNestedSelectValidation,
        RestoreNestedSelectValidation,
        RestoreNestedSelectValidationValue,
        Shared,
        Skip,
        "RESTORE_NESTED_SELECT_VALIDATION",
        RestoreNestedSelectValidationPolicy,
        "Nested select validation policy."
    );
    render_contract!(
        rules,
        out,
        RestoreTypeValueSet,
        RestoreTypeValueSet,
        RestoreTypeValueSetValue,
        SelectOnly,
        Open,
        "RESTORE_TYPE_VALUE_SET",
        RestoreTypeValueSetPolicy,
        "Restore Type value set."
    );
    render_contract!(
        rules,
        out,
        RestoreGlacierTierValueSet,
        RestoreGlacierTierValueSet,
        RestoreTierValueSetValue,
        ExpeditedStandardBulk,
        Open,
        "RESTORE_GLACIER_TIER_VALUE_SET",
        RestoreGlacierTierValueSetPolicy,
        "GlacierJobParameters tier set."
    );
    render_contract!(
        rules,
        out,
        RestoreDirectTierValueSet,
        RestoreDirectTierValueSet,
        RestoreTierValueSetValue,
        ExpeditedStandardBulk,
        Open,
        "RESTORE_DIRECT_TIER_VALUE_SET",
        RestoreDirectTierValueSetPolicy,
        "Direct restore tier set."
    );
    render_contract!(
        rules,
        out,
        RestoreRootNamespacePolicy,
        RestoreRootNamespacePolicy,
        RestoreRootNamespacePolicyValue,
        LocalName,
        QualifiedName,
        "RESTORE_ROOT_NAMESPACE_POLICY",
        RestoreRootNamespacePolicy,
        "Restore root namespace policy."
    );
    render_contract!(
        rules,
        out,
        RestoreVersionSelector,
        RestoreVersionSelector,
        RestoreVersionSelectorValue,
        Preserve,
        Drop,
        "RESTORE_VERSION_SELECTOR",
        RestoreVersionSelectorPolicy,
        "Restore version-selector policy."
    );
    render_contract!(
        rules,
        out,
        SelectTypeRoutePredicate,
        SelectTypeRoutePredicate,
        SelectTypeRoutePredicateValue,
        Equals2,
        PresentAnyValue,
        "SELECT_TYPE_ROUTE_PREDICATE",
        SelectTypeRoutePredicatePolicy,
        "Select route-version predicate."
    );
    render_contract!(
        rules,
        out,
        SelectExpressionMaxBytes,
        SelectExpressionMaxBytes,
        SelectExpressionMaxBytesValue,
        Max262144,
        Unbounded,
        "SELECT_EXPRESSION_MAX_BYTES",
        SelectExpressionMaxBytesPolicy,
        "Select expression byte ceiling."
    );
    render_contract!(
        rules,
        out,
        SelectExpressionPresence,
        SelectExpressionPresence,
        SelectExpressionPresenceValue,
        Nonempty,
        AllowEmpty,
        "SELECT_EXPRESSION_PRESENCE",
        SelectExpressionPresencePolicy,
        "Select expression presence policy."
    );
    render_contract!(
        rules,
        out,
        SelectExpressionErrorFlow,
        SelectExpressionErrorFlow,
        SelectExpressionErrorFlowValue,
        Constant,
        EchoRejectedValue,
        "SELECT_EXPRESSION_ERROR_FLOW",
        SelectExpressionErrorFlowPolicy,
        "Select expression refusal flow."
    );
    render_contract!(
        rules,
        out,
        SelectExpressionInspection,
        SelectExpressionInspection,
        SelectExpressionInspectionValue,
        LengthOnly,
        ParseOrLog,
        "SELECT_EXPRESSION_INSPECTION",
        SelectExpressionInspectionPolicy,
        "Select expression inspection policy."
    );
    render_contract!(
        rules,
        out,
        SelectInputMultiple,
        SelectInputMultiple,
        SelectInputMultipleValue,
        RejectConflict,
        PreferCsv,
        "SELECT_INPUT_MULTIPLE",
        SelectInputMultiplePolicy,
        "Multiple input-serialization policy."
    );
    render_contract!(
        rules,
        out,
        SelectInputMissing,
        SelectInputMissing,
        SelectInputMissingValue,
        RejectMalformed,
        DefaultCsv,
        "SELECT_INPUT_MISSING",
        SelectInputMissingPolicy,
        "Missing input-serialization policy."
    );
    render_contract!(
        rules,
        out,
        SelectOutputMultiple,
        SelectOutputMultiple,
        SelectOutputMultipleValue,
        RejectConflict,
        PreferCsv,
        "SELECT_OUTPUT_MULTIPLE",
        SelectOutputMultiplePolicy,
        "Multiple output-serialization policy."
    );
    render_contract!(
        rules,
        out,
        SelectOutputMissing,
        SelectOutputMissing,
        SelectOutputMissingValue,
        RejectMalformed,
        DefaultCsv,
        "SELECT_OUTPUT_MISSING",
        SelectOutputMissingPolicy,
        "Missing output-serialization policy."
    );
    render_contract!(
        rules,
        out,
        SelectScanRangeEmpty,
        SelectScanRangeEmpty,
        SelectScanRangeEmptyValue,
        Reject,
        WholeObject,
        "SELECT_SCAN_RANGE_EMPTY",
        SelectScanRangeEmptyPolicy,
        "Empty ScanRange policy."
    );
    render_contract!(
        rules,
        out,
        SelectScanRangeOrder,
        SelectScanRangeOrder,
        SelectScanRangeOrderValue,
        EndGteStart,
        AllowInverted,
        "SELECT_SCAN_RANGE_ORDER",
        SelectScanRangeOrderPolicy,
        "Bounded ScanRange ordering policy."
    );
    render_contract!(
        rules,
        out,
        SelectScanRangeSign,
        SelectScanRangeSign,
        SelectScanRangeSignValue,
        Nonnegative,
        AllowNegative,
        "SELECT_SCAN_RANGE_SIGN",
        SelectScanRangeSignPolicy,
        "ScanRange sign policy."
    );
    render_contract!(
        rules,
        out,
        SelectScanBounded,
        SelectScanBounded,
        SelectScanBoundedValue,
        InclusiveWindow,
        DropRange,
        "SELECT_SCAN_BOUNDED",
        SelectScanBoundedPolicy,
        "Bounded ScanRange selection policy."
    );
    render_contract!(
        rules,
        out,
        SelectScanStartOnly,
        SelectScanStartOnly,
        SelectScanStartOnlyValue,
        FromStartToEnd,
        WholeObject,
        "SELECT_SCAN_START_ONLY",
        SelectScanStartOnlyPolicy,
        "Start-only ScanRange selection policy."
    );
    render_contract!(
        rules,
        out,
        SelectScanEndOnly,
        SelectScanEndOnly,
        SelectScanEndOnlyValue,
        Suffix,
        Prefix,
        "SELECT_SCAN_END_ONLY",
        SelectScanEndOnlyPolicy,
        "End-only ScanRange selection policy."
    );
    render_contract!(
        rules,
        out,
        SelectExpressionTypeValues,
        SelectExpressionTypeValues,
        SelectExpressionTypeValuesValue,
        SqlOnly,
        Open,
        "SELECT_EXPRESSION_TYPE_VALUES",
        SelectExpressionTypeValuesPolicy,
        "Select expression-type set."
    );
    render_contract!(
        rules,
        out,
        SelectCompressionValues,
        SelectCompressionValues,
        SelectCompressionValuesValue,
        NoneGzipBzip2,
        Open,
        "SELECT_COMPRESSION_VALUES",
        SelectCompressionValuesPolicy,
        "Select compression set."
    );
    render_contract!(
        rules,
        out,
        SelectRootNamespacePolicy,
        SelectRootNamespacePolicy,
        SelectRootNamespacePolicyValue,
        LocalName,
        QualifiedName,
        "SELECT_ROOT_NAMESPACE_POLICY",
        SelectRootNamespacePolicy,
        "Select root namespace policy."
    );
    render_contract!(
        rules,
        out,
        SelectResponseShape,
        SelectResponseShape,
        SelectResponseShapeValue,
        EventStream,
        SettledOutput,
        "SELECT_RESPONSE_SHAPE",
        SelectResponseShapePolicy,
        "Select response-shape policy."
    );
    render_contract!(
        rules,
        out,
        SelectEventStatus,
        SelectEventStatus,
        SelectEventStatusValue,
        Success200,
        Success202,
        "SELECT_EVENT_STATUS",
        SelectEventStatusPolicy,
        "Select event-stream status."
    );
    render_contract!(
        rules,
        out,
        SelectEventMediaType,
        SelectEventMediaType,
        SelectEventMediaTypeValue,
        ApplicationVndAmazonEventStream,
        OctetStream,
        "SELECT_EVENT_MEDIA_TYPE",
        SelectEventMediaTypePolicy,
        "Select event-stream media type."
    );
    render_contract!(
        rules,
        out,
        EventPreludeCrcCoverage,
        EventPreludeCrcCoverage,
        EventPreludeCrcCoverageValue,
        First8,
        First12,
        "EVENT_PRELUDE_CRC_COVERAGE",
        EventPreludeCrcCoveragePolicy,
        "Event prelude CRC coverage."
    );
    render_contract!(
        rules,
        out,
        EventMessageCrcCoverage,
        EventMessageCrcCoverage,
        EventMessageCrcCoverageValue,
        FrameWithoutCrc,
        PayloadOnly,
        "EVENT_MESSAGE_CRC_COVERAGE",
        EventMessageCrcCoveragePolicy,
        "Event message CRC coverage."
    );
    render_contract!(
        rules,
        out,
        EventCrcAlgorithm,
        EventCrcAlgorithm,
        EventCrcAlgorithmValue,
        Crc32IsoHdlc,
        Crc32c,
        "EVENT_CRC_ALGORITHM",
        EventCrcAlgorithmPolicy,
        "Event-stream CRC algorithm."
    );
    render_contract!(
        rules,
        out,
        SelectEventTermination,
        SelectEventTermination,
        SelectEventTerminationValue,
        RecordsStatsEnd,
        OmitEnd,
        "SELECT_EVENT_TERMINATION",
        SelectEventTerminationPolicy,
        "Select event-stream termination policy."
    );
    Ok(())
}
