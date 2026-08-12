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

//! Runtime vocabulary for select and restore protocol contracts.
//!
//! Responsible for: closed policy types selected by generated contract constants.
//! NOT responsible for: choosing current values or implementing request handling.
//! Upstream: generated contract data. Downstream: select, restore, event-stream and response consumers.

macro_rules! two_value_policy {
    ($name:ident, $current:ident, $mutant:ident) => {
        #[doc = concat!("Typed values for the `", stringify!($name), "` contract.")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[allow(dead_code, reason = "the unused variant is selected by the contract mutation gate")]
        pub(crate) enum $name {
            #[doc = concat!("Current value: `", stringify!($current), "`.")]
            $current,
            #[doc = concat!("Mutation alternative: `", stringify!($mutant), "`.")]
            $mutant,
        }
    };
}

two_value_policy!(RestoreInitiatedOutcomePolicy, Success202, Success200);
two_value_policy!(RestoreAlreadyRestoredOutcomePolicy, Success200, Success202);
two_value_policy!(RestoreInProgressOutcomePolicy, RestoreAlreadyInProgress, Success202);
two_value_policy!(RestoreHeaderOngoingFormPolicy, QuotedTrue, UnquotedTrue);
two_value_policy!(RestoreHeaderRestoredFormPolicy, QuotedFalseCommaSpaceExpiry, CommaWithoutSpace);
two_value_policy!(RestoreHeaderAbsencePolicy, Omit, EmitDefault);
two_value_policy!(RestoreHeaderParseGrammarPolicy, StrictQuotedPairs, AcceptUnquoted);
two_value_policy!(RestoreNotArchivedOutcomePolicy, InvalidObjectState, SuccessNoop);
two_value_policy!(RestoreDaysMinimumPolicy, Min1, Min0);
two_value_policy!(RestoreFormPresencePolicy, RequireDaysOrSelect, DefaultDays);
two_value_policy!(RestoreDaysSelectExclusionPolicy, Reject, PreferSelect);
two_value_policy!(RestoreSelectMembersRequireTypePolicy, Reject, Allow);
two_value_policy!(RestoreSelectOutputRequiredPolicy, Require, AllowMissing);
two_value_policy!(RestoreSelectParametersRequiredPolicy, Require, AllowMissing);
two_value_policy!(RestoreNestedSelectValidationPolicy, Shared, Skip);
two_value_policy!(RestoreTypeValueSetPolicy, SelectOnly, Open);
two_value_policy!(RestoreGlacierTierValueSetPolicy, ExpeditedStandardBulk, Open);
two_value_policy!(RestoreDirectTierValueSetPolicy, ExpeditedStandardBulk, Open);
two_value_policy!(RestoreRootNamespacePolicy, LocalName, QualifiedName);
two_value_policy!(RestoreVersionSelectorPolicy, Preserve, Drop);
two_value_policy!(SelectTypeRoutePredicatePolicy, Equals2, PresentAnyValue);
two_value_policy!(SelectExpressionMaxBytesPolicy, Max262144, Unbounded);
two_value_policy!(SelectExpressionPresencePolicy, Nonempty, AllowEmpty);
two_value_policy!(SelectExpressionErrorFlowPolicy, Constant, EchoRejectedValue);
two_value_policy!(SelectExpressionInspectionPolicy, LengthOnly, ParseOrLog);
two_value_policy!(SelectInputMultiplePolicy, RejectConflict, PreferCsv);
two_value_policy!(SelectInputMissingPolicy, RejectMalformed, DefaultCsv);
two_value_policy!(SelectOutputMultiplePolicy, RejectConflict, PreferCsv);
two_value_policy!(SelectOutputMissingPolicy, RejectMalformed, DefaultCsv);
two_value_policy!(SelectScanRangeEmptyPolicy, Reject, WholeObject);
two_value_policy!(SelectScanRangeOrderPolicy, EndGteStart, AllowInverted);
two_value_policy!(SelectScanRangeSignPolicy, Nonnegative, AllowNegative);
two_value_policy!(SelectScanBoundedPolicy, InclusiveWindow, DropRange);
two_value_policy!(SelectScanStartOnlyPolicy, FromStartToEnd, WholeObject);
two_value_policy!(SelectScanEndOnlyPolicy, Suffix, Prefix);
two_value_policy!(SelectExpressionTypeValuesPolicy, SqlOnly, Open);
two_value_policy!(SelectCompressionValuesPolicy, NoneGzipBzip2, Open);
two_value_policy!(SelectRootNamespacePolicy, LocalName, QualifiedName);
two_value_policy!(SelectResponseShapePolicy, EventStream, SettledOutput);
two_value_policy!(SelectEventStatusPolicy, Success200, Success202);
two_value_policy!(SelectEventMediaTypePolicy, ApplicationVndAmazonEventStream, OctetStream);
two_value_policy!(EventPreludeCrcCoveragePolicy, First8, First12);
two_value_policy!(EventMessageCrcCoveragePolicy, FrameWithoutCrc, PayloadOnly);
two_value_policy!(EventCrcAlgorithmPolicy, Crc32IsoHdlc, Crc32c);
two_value_policy!(SelectEventTerminationPolicy, RecordsStatsEnd, OmitEnd);
