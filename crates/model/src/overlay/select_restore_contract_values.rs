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

//! Typed current and mutation values for RestoreObject and SelectObjectContent contracts.
//!
//! Responsible for: the closed value vocabulary selected by the select/restore overlay.
//! NOT responsible for: parsing spellings or implementing runtime behavior. Upstream: quirk TOML.
//! Downstream: runtime-contract codegen.

macro_rules! binary_policy {
    ($name:ident, $current:ident => $current_text:literal, $mutant:ident => $mutant_text:literal) => {
        #[doc = concat!("Typed values for the `", stringify!($name), "` contract.")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name {
            #[doc = concat!("Current value: `", stringify!($current), "`.")]
            $current,
            #[doc = concat!("Mutation alternative: `", stringify!($mutant), "`.")]
            $mutant,
        }

        impl $name {
            /// Returns the stable overlay spelling of this value.
            pub const fn as_str(self) -> &'static str {
                match self {
                    Self::$current => $current_text,
                    Self::$mutant => $mutant_text,
                }
            }
        }
    };
}

binary_policy!(RestoreInitiatedOutcomeValue, Success202 => "success_202", Success200 => "success_200");
binary_policy!(RestoreAlreadyRestoredOutcomeValue, Success200 => "success_200", Success202 => "success_202");
binary_policy!(RestoreInProgressOutcomeValue, RestoreAlreadyInProgress => "restore_already_in_progress", Success202 => "success_202");
binary_policy!(RestoreHeaderOngoingFormValue, QuotedTrue => "quoted_true", UnquotedTrue => "unquoted_true");
binary_policy!(RestoreHeaderRestoredFormValue, QuotedFalseCommaSpaceExpiry => "quoted_false_comma_space_expiry", CommaWithoutSpace => "comma_without_space");
binary_policy!(RestoreHeaderAbsenceValue, Omit => "omit", EmitDefault => "emit_default");
binary_policy!(RestoreHeaderParseGrammarValue, StrictQuotedPairs => "strict_quoted_pairs", AcceptUnquoted => "accept_unquoted");
binary_policy!(RestoreNotArchivedOutcomeValue, InvalidObjectState => "invalid_object_state", SuccessNoop => "success_noop");
binary_policy!(RestoreDaysMinimumValue, Min1 => "min_1", Min0 => "min_0");
binary_policy!(RestoreFormPresenceValue, RequireDaysOrSelect => "require_days_or_select", DefaultDays => "default_days");
binary_policy!(RestoreDaysSelectExclusionValue, Reject => "reject", PreferSelect => "prefer_select");
binary_policy!(RestoreSelectMembersRequireTypeValue, Reject => "reject", Allow => "allow");
binary_policy!(RestoreSelectOutputRequiredValue, Require => "require", AllowMissing => "allow_missing");
binary_policy!(RestoreSelectParametersRequiredValue, Require => "require", AllowMissing => "allow_missing");
binary_policy!(RestoreNestedSelectValidationValue, Shared => "shared", Skip => "skip");
binary_policy!(RestoreTypeValueSetValue, SelectOnly => "select_only", Open => "open");
binary_policy!(RestoreTierValueSetValue, ExpeditedStandardBulk => "expedited_standard_bulk", Open => "open");
binary_policy!(RestoreRootNamespacePolicyValue, LocalName => "local_name", QualifiedName => "qualified_name");
binary_policy!(RestoreVersionSelectorValue, Preserve => "preserve", Drop => "drop");
binary_policy!(SelectTypeRoutePredicateValue, Equals2 => "equals_2", PresentAnyValue => "present_any_value");
binary_policy!(SelectExpressionMaxBytesValue, Max262144 => "max_262144", Unbounded => "unbounded");
binary_policy!(SelectExpressionPresenceValue, Nonempty => "nonempty", AllowEmpty => "allow_empty");
binary_policy!(SelectExpressionErrorFlowValue, Constant => "constant", EchoRejectedValue => "echo_rejected_value");
binary_policy!(SelectExpressionInspectionValue, LengthOnly => "length_only", ParseOrLog => "parse_or_log");
binary_policy!(SelectInputMultipleValue, RejectConflict => "reject_conflict", PreferCsv => "prefer_csv");
binary_policy!(SelectInputMissingValue, RejectMalformed => "reject_malformed", DefaultCsv => "default_csv");
binary_policy!(SelectOutputMultipleValue, RejectConflict => "reject_conflict", PreferCsv => "prefer_csv");
binary_policy!(SelectOutputMissingValue, RejectMalformed => "reject_malformed", DefaultCsv => "default_csv");
binary_policy!(SelectScanRangeEmptyValue, Reject => "reject", WholeObject => "whole_object");
binary_policy!(SelectScanRangeOrderValue, EndGteStart => "end_gte_start", AllowInverted => "allow_inverted");
binary_policy!(SelectScanRangeSignValue, Nonnegative => "nonnegative", AllowNegative => "allow_negative");
binary_policy!(SelectScanBoundedValue, InclusiveWindow => "inclusive_window", DropRange => "drop_range");
binary_policy!(SelectScanStartOnlyValue, FromStartToEnd => "from_start_to_end", WholeObject => "whole_object");
binary_policy!(SelectScanEndOnlyValue, Suffix => "suffix", Prefix => "prefix");
binary_policy!(SelectExpressionTypeValuesValue, SqlOnly => "sql_only", Open => "open");
binary_policy!(SelectCompressionValuesValue, NoneGzipBzip2 => "none_gzip_bzip2", Open => "open");
binary_policy!(SelectRootNamespacePolicyValue, LocalName => "local_name", QualifiedName => "qualified_name");
binary_policy!(SelectResponseShapeValue, EventStream => "event_stream", SettledOutput => "settled_output");
binary_policy!(SelectEventStatusValue, Success200 => "success_200", Success202 => "success_202");
binary_policy!(SelectEventMediaTypeValue, ApplicationVndAmazonEventStream => "application_vnd_amazon_event_stream", OctetStream => "octet_stream");
binary_policy!(EventPreludeCrcCoverageValue, First8 => "first_8", First12 => "first_12");
binary_policy!(EventMessageCrcCoverageValue, FrameWithoutCrc => "frame_without_crc", PayloadOnly => "payload_only");
binary_policy!(EventCrcAlgorithmValue, Crc32IsoHdlc => "crc32_iso_hdlc", Crc32c => "crc32c");
binary_policy!(SelectEventTerminationValue, RecordsStatsEnd => "records_stats_end", OmitEnd => "omit_end");

/// One typed value from the select/restore contract family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectRestoreContractValue {
    /// Outcome of initiating a restore.
    RestoreInitiatedOutcome(RestoreInitiatedOutcomeValue),
    /// Outcome when the object is already restored.
    RestoreAlreadyRestoredOutcome(RestoreAlreadyRestoredOutcomeValue),
    /// Outcome while a restore is in progress.
    RestoreInProgressOutcome(RestoreInProgressOutcomeValue),
    /// Wire form of an ongoing restore header.
    RestoreHeaderOngoingForm(RestoreHeaderOngoingFormValue),
    /// Wire form of a completed restore header.
    RestoreHeaderRestoredForm(RestoreHeaderRestoredFormValue),
    /// Header behavior when restore state is absent.
    RestoreHeaderAbsence(RestoreHeaderAbsenceValue),
    /// Grammar accepted by the restore-header parser.
    RestoreHeaderParseGrammar(RestoreHeaderParseGrammarValue),
    /// Outcome for an object outside archive storage.
    RestoreNotArchivedOutcome(RestoreNotArchivedOutcomeValue),
    /// Minimum accepted restore duration.
    RestoreDaysMinimum(RestoreDaysMinimumValue),
    /// Required restore-request form.
    RestoreFormPresence(RestoreFormPresenceValue),
    /// Relationship between days and the select form.
    RestoreDaysSelectExclusion(RestoreDaysSelectExclusionValue),
    /// Whether select members require the SELECT type.
    RestoreSelectMembersRequireType(RestoreSelectMembersRequireTypeValue),
    /// Whether select output is required.
    RestoreSelectOutputRequired(RestoreSelectOutputRequiredValue),
    /// Whether select parameters are required.
    RestoreSelectParametersRequired(RestoreSelectParametersRequiredValue),
    /// Whether nested select parameters use shared validation.
    RestoreNestedSelectValidation(RestoreNestedSelectValidationValue),
    /// Accepted restore type values.
    RestoreTypeValueSet(RestoreTypeValueSetValue),
    /// Accepted glacier job tier values.
    RestoreGlacierTierValueSet(RestoreTierValueSetValue),
    /// Accepted direct tier values.
    RestoreDirectTierValueSet(RestoreTierValueSetValue),
    /// Namespace policy for the restore request root.
    RestoreRootNamespacePolicy(RestoreRootNamespacePolicyValue),
    /// Version selector handling for restore requests.
    RestoreVersionSelector(RestoreVersionSelectorValue),
    /// Route predicate for select requests.
    SelectTypeRoutePredicate(SelectTypeRoutePredicateValue),
    /// Maximum select-expression length.
    SelectExpressionMaxBytes(SelectExpressionMaxBytesValue),
    /// Presence rule for select expressions.
    SelectExpressionPresence(SelectExpressionPresenceValue),
    /// Error-flow rule for rejected expressions.
    SelectExpressionErrorFlow(SelectExpressionErrorFlowValue),
    /// Inspection rule for opaque expressions.
    SelectExpressionInspection(SelectExpressionInspectionValue),
    /// Rule for multiple input serialization formats.
    SelectInputMultiple(SelectInputMultipleValue),
    /// Rule for a missing input serialization format.
    SelectInputMissing(SelectInputMissingValue),
    /// Rule for multiple output serialization formats.
    SelectOutputMultiple(SelectOutputMultipleValue),
    /// Rule for a missing output serialization format.
    SelectOutputMissing(SelectOutputMissingValue),
    /// Rule for an empty scan range.
    SelectScanRangeEmpty(SelectScanRangeEmptyValue),
    /// Ordering rule for scan-range bounds.
    SelectScanRangeOrder(SelectScanRangeOrderValue),
    /// Sign rule for scan-range bounds.
    SelectScanRangeSign(SelectScanRangeSignValue),
    /// Semantics of a bounded scan range.
    SelectScanBounded(SelectScanBoundedValue),
    /// Semantics of a start-only scan range.
    SelectScanStartOnly(SelectScanStartOnlyValue),
    /// Semantics of an end-only scan range.
    SelectScanEndOnly(SelectScanEndOnlyValue),
    /// Accepted expression type values.
    SelectExpressionTypeValues(SelectExpressionTypeValuesValue),
    /// Accepted compression values.
    SelectCompressionValues(SelectCompressionValuesValue),
    /// Namespace policy for the select request root.
    SelectRootNamespacePolicy(SelectRootNamespacePolicyValue),
    /// Shape used for a select response.
    SelectResponseShape(SelectResponseShapeValue),
    /// Status used for a select event response.
    SelectEventStatus(SelectEventStatusValue),
    /// Media type used for a select event response.
    SelectEventMediaType(SelectEventMediaTypeValue),
    /// Byte range covered by the event prelude CRC.
    EventPreludeCrcCoverage(EventPreludeCrcCoverageValue),
    /// Byte range covered by the event message CRC.
    EventMessageCrcCoverage(EventMessageCrcCoverageValue),
    /// CRC algorithm used by event-stream messages.
    EventCrcAlgorithm(EventCrcAlgorithmValue),
    /// Required terminal event sequence.
    SelectEventTermination(SelectEventTerminationValue),
}

impl SelectRestoreContractValue {
    /// Returns the stable overlay spelling of the contained value.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RestoreInitiatedOutcome(value) => value.as_str(),
            Self::RestoreAlreadyRestoredOutcome(value) => value.as_str(),
            Self::RestoreInProgressOutcome(value) => value.as_str(),
            Self::RestoreHeaderOngoingForm(value) => value.as_str(),
            Self::RestoreHeaderRestoredForm(value) => value.as_str(),
            Self::RestoreHeaderAbsence(value) => value.as_str(),
            Self::RestoreHeaderParseGrammar(value) => value.as_str(),
            Self::RestoreNotArchivedOutcome(value) => value.as_str(),
            Self::RestoreDaysMinimum(value) => value.as_str(),
            Self::RestoreFormPresence(value) => value.as_str(),
            Self::RestoreDaysSelectExclusion(value) => value.as_str(),
            Self::RestoreSelectMembersRequireType(value) => value.as_str(),
            Self::RestoreSelectOutputRequired(value) => value.as_str(),
            Self::RestoreSelectParametersRequired(value) => value.as_str(),
            Self::RestoreNestedSelectValidation(value) => value.as_str(),
            Self::RestoreTypeValueSet(value) => value.as_str(),
            Self::RestoreGlacierTierValueSet(value) | Self::RestoreDirectTierValueSet(value) => value.as_str(),
            Self::RestoreRootNamespacePolicy(value) => value.as_str(),
            Self::RestoreVersionSelector(value) => value.as_str(),
            Self::SelectTypeRoutePredicate(value) => value.as_str(),
            Self::SelectExpressionMaxBytes(value) => value.as_str(),
            Self::SelectExpressionPresence(value) => value.as_str(),
            Self::SelectExpressionErrorFlow(value) => value.as_str(),
            Self::SelectExpressionInspection(value) => value.as_str(),
            Self::SelectInputMultiple(value) => value.as_str(),
            Self::SelectInputMissing(value) => value.as_str(),
            Self::SelectOutputMultiple(value) => value.as_str(),
            Self::SelectOutputMissing(value) => value.as_str(),
            Self::SelectScanRangeEmpty(value) => value.as_str(),
            Self::SelectScanRangeOrder(value) => value.as_str(),
            Self::SelectScanRangeSign(value) => value.as_str(),
            Self::SelectScanBounded(value) => value.as_str(),
            Self::SelectScanStartOnly(value) => value.as_str(),
            Self::SelectScanEndOnly(value) => value.as_str(),
            Self::SelectExpressionTypeValues(value) => value.as_str(),
            Self::SelectCompressionValues(value) => value.as_str(),
            Self::SelectRootNamespacePolicy(value) => value.as_str(),
            Self::SelectResponseShape(value) => value.as_str(),
            Self::SelectEventStatus(value) => value.as_str(),
            Self::SelectEventMediaType(value) => value.as_str(),
            Self::EventPreludeCrcCoverage(value) => value.as_str(),
            Self::EventMessageCrcCoverage(value) => value.as_str(),
            Self::EventCrcAlgorithm(value) => value.as_str(),
            Self::SelectEventTermination(value) => value.as_str(),
        }
    }
}
