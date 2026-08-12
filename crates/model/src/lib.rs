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

//! Smithy model parsing and the frozen rustfs-gateway IR.
//!
//! Responsible for: loading the pinned AWS Smithy model, stripping the traits that carry no wire
//! meaning, reading the hand-written overlays, and lowering both into IR documents shaped by
//! `spec/ir.schema.json`.
//! NOT responsible for: emitting Rust code or Markdown (that is `rustfs-gateway-codegen`), and no runtime
//! behaviour whatsoever.
//! Upstream: the pinned `model/` directory, including `model/overlays/`. Downstream: `rustfs-gateway-codegen`.
//!
//! Build-time only — never appears in a runtime dependency tree.
//!
//! ```text
//! model/s3.json ──strip──▶ smithy::Model ──┐
//!                                          ├──▶ lower::lower ──▶ ir::OperationIr
//! overlays/*.toml ──▶ overlay::Overlay ────┘
//! ```
//!
//! The crate carries no third-party dependency beyond `thiserror`: the workspace dependency set is
//! pinned and has no serde, so [`json`] and [`toml_lite`] are small hand-written readers.
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod ir;
pub mod json;
pub mod lower;
pub mod overlay;
pub mod smithy;
pub mod toml_lite;

#[cfg(test)]
mod tests;

pub use error::{Error, Result};
pub use ir::OperationIr;
pub use lower::{Lowered, lower};
pub use overlay::{
    AbsoluteOrUncPolicyValue, AclChannelPolicyValue, AclOwnerPolicyValue, BooleanSpellingValue, BucketStatePreconditionValue,
    CaseFoldingValue, ClientIngressForbiddenCodepointsValue, CodecRule, CodecValue, ConditionConflictValue,
    ConditionFailureDetailValue, ConditionalWildcardParseValue, ConditionalWildcardWriteValue, ConditionalWriteOrderValue,
    ContractRule, ContractValue, CopySourceGuardOrderValue, CopySourceIfMatchMissValue, CopyValidatorScopeValue,
    DecodedUtf8Value, DefaultBucketValidatorValue, DefaultSlashPolicyValue, DeleteAbsentPolicyValue, ErrorRootNamespaceValue,
    ErrorSecretFlowValue, EtagComparisonStrengthValue, HeadBodyPolicyValue, HeaderToleranceValue, IfMatchAbsentPolicyValue,
    IfMatchDatePrecedenceValue, IfMatchMissOutcomeValue, IfNoneDatePrecedenceValue, MutationDimension, Overlay,
    PercentDecodePassesValue, ResidualEncodedDangerousValue, RuleClassification, SourceRule, StoredLegacyControlPolicyValue,
    TemporalRelationValue, TraversalSegmentDelimitersValue, UnicodeNormalizationValue, UnknownElementPolicyValue,
    ValidatorAuthorityValue, ValidatorReplaceabilityValue, WireFormValue,
};
pub use overlay::{
    ActualAllowOriginPolicyValue, ActualExposePolicyValue, ActualPreflightHeaderPolicyValue, ActualVaryPolicyValue,
    AllowHeadersAnswerSourceValue, AllowedHeaderWildcardLimitValue, AllowedMethodCasePolicyValue, AllowedMethodValueSetValue,
    BareOptionsPolicyValue, BareWildcardAnswerValue, CorsContractValue, CorsDeleteAbsentPolicyValue,
    CorsInvalidTargetPolicyValue, CorsMatchedRuleValueSourceValue, CorsOriginCardinalityValue, CorsOriginCharacterPolicyValue,
    CorsOriginEmptyPolicyValue, CorsOriginMaxBytesValue, CorsRequestHeadersCardinalityValue, CorsRequestMethodCardinalityValue,
    CorsRuleDimensionJoinValue, CorsRuleOrderPolicyValue, CorsSourceAbsencePolicyValue, ExactOriginMatchValue,
    ExposeHeaderWildcardLimitValue, HeadersOnPostAuthErrorValue, OriginWildcardLimitValue, OriginWildcardMatchValue,
    PartialWildcardAnswerValue, PreflightAllowMethodsSourceValue, PreflightAuthorizationScopeValue, PreflightBucketSourceValue,
    PreflightDispatchPolicyValue, PreflightExposePolicyValue, PreflightMaxAgePolicyValue, PreflightRefusalProfileValue,
    PreflightRequiredHeaderPairValue, PreflightVaryPolicyValue, RequestedHeaderCasePolicyValue, RequestedHeaderQuantifierValue,
    RequestedHeaderWildcardMatchValue, UnmatchedActualPolicyValue, WildcardCredentialsPolicyValue,
};
pub use overlay::{
    BareConditionalEtagPolicyValue, CompletionFailureUploadPolicyValue, ConditionalRaceOutcomeValue,
    CopyRangeLengthArithmeticValue, ExplicitEndOverflowPolicyValue, IfNoneMatchComparisonStrengthValue, IfRangeMissPolicyValue,
    InvalidRangePolicyValue, MultiRangePolicyValue, NotModifiedBodyPolicyValue, NotModifiedEtagPolicyValue,
    NotModifiedFramingPolicyValue, OpenEndedRangePolicyValue, OversizeSuffixPolicyValue, PartCountHeaderPolicyValue,
    PartNumberOutcomeValue, PartialChecksumPolicyValue, RangePartSelectorConflictValue, RangeRequestedDetailValue,
    RangeStartBoundValue, ReadRangeLengthArithmeticValue, SuffixRangePolicyValue, UnsatisfiableActualSizeDetailValue,
};
pub use overlay::{
    EventCrcAlgorithmValue, EventMessageCrcCoverageValue, EventPreludeCrcCoverageValue, RestoreAlreadyRestoredOutcomeValue,
    RestoreDaysMinimumValue, RestoreDaysSelectExclusionValue, RestoreFormPresenceValue, RestoreHeaderAbsenceValue,
    RestoreHeaderOngoingFormValue, RestoreHeaderParseGrammarValue, RestoreHeaderRestoredFormValue, RestoreInProgressOutcomeValue,
    RestoreInitiatedOutcomeValue, RestoreNestedSelectValidationValue, RestoreNotArchivedOutcomeValue,
    RestoreRootNamespacePolicyValue, RestoreSelectMembersRequireTypeValue, RestoreSelectOutputRequiredValue,
    RestoreSelectParametersRequiredValue, RestoreTierValueSetValue, RestoreTypeValueSetValue, RestoreVersionSelectorValue,
    SelectCompressionValuesValue, SelectEventMediaTypeValue, SelectEventStatusValue, SelectEventTerminationValue,
    SelectExpressionErrorFlowValue, SelectExpressionInspectionValue, SelectExpressionMaxBytesValue,
    SelectExpressionPresenceValue, SelectExpressionTypeValuesValue, SelectInputMissingValue, SelectInputMultipleValue,
    SelectOutputMissingValue, SelectOutputMultipleValue, SelectResponseShapeValue, SelectRestoreContractValue,
    SelectRootNamespacePolicyValue, SelectScanBoundedValue, SelectScanEndOnlyValue, SelectScanRangeEmptyValue,
    SelectScanRangeOrderValue, SelectScanRangeSignValue, SelectScanStartOnlyValue, SelectTypeRoutePredicateValue,
};
pub use smithy::Model;
