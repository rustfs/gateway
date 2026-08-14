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

//! Closed values for runtime contracts outside the generated wire codec.
//!
//! Responsible for: the typed alternatives selected by conditional, copy-source, and naming
//! overlay rules. NOT responsible for: parsing those rules or consuming the selected values.
//! Upstream: quirk overlay TOML. Downstream: contract parsers and runtime contract codegen.

use super::MutationDimension;
use super::codec::{
    AclChannelPolicyValue, AclOwnerPolicyValue, BucketStatePreconditionValue, ConditionConflictValue,
    ConditionalWildcardParseValue, ConditionalWildcardWriteValue, ConditionalWriteOrderValue, CopyValidatorScopeValue,
    DeleteAbsentPolicyValue, ErrorSecretFlowValue, EtagComparisonStrengthValue, IfMatchAbsentPolicyValue,
    IfMatchDatePrecedenceValue, IfMatchMissOutcomeValue, IfNoneDatePrecedenceValue, TemporalRelationValue,
};
use super::cors_contract_values::CorsContractValue;
use super::precondition_contract_values::*;
use super::select_restore_contract_values::SelectRestoreContractValue;

/// Namespace carried by the root of an S3 error document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorRootNamespaceValue {
    /// Emit an unnamespaced `Error` root.
    Unnamespaced,
    /// Mutation alternative that adds the ordinary S3 document namespace.
    S3,
}

/// Whether a HEAD response carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadBodyPolicyValue {
    /// Suppress the bytes while retaining the equivalent GET metadata.
    Suppress,
    /// Mutation alternative that preserves the bytes.
    Preserve,
}

/// Whether a precondition failure names the condition that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionFailureDetailValue {
    /// Include the condition as an error-document detail.
    IncludeCondition,
    /// Mutation alternative that omits the condition.
    OmitCondition,
}

/// Outcome of an unsatisfied copy-source If-Match condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopySourceIfMatchMissValue {
    /// Refuse the copy as a failed precondition.
    PreconditionFailed,
    /// Mutation alternative that lets the copy proceed.
    Proceed,
}

/// Placement of a copy-source guard relative to the target write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopySourceGuardOrderValue {
    /// Evaluate the source guard before writing the target.
    GuardBeforeTargetWrite,
    /// Mutation alternative that writes the target before evaluating the source guard.
    TargetWriteBeforeGuard,
}

/// Default treatment of repeated slashes in an object key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultSlashPolicyValue {
    /// Preserve every slash as key data.
    AwsPreserve,
    /// Mutation alternative that collapses repeated slashes.
    Collapse,
}

/// Number of percent-decoding passes applied to one path label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PercentDecodePassesValue {
    /// Decode exactly once.
    Once,
    /// Mutation alternative that decodes repeatedly until stable.
    UntilStable,
}

/// Handling of invalid UTF-8 produced by percent decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedUtf8Value {
    /// Reject invalid UTF-8.
    Strict,
    /// Mutation alternative that replaces invalid bytes.
    Lossy,
}

/// Handling of dangerous encoded residue after the permitted decode pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidualEncodedDangerousValue {
    /// Reject encoded separators and encoded dot-dot.
    Reject,
    /// Mutation alternative that admits the residue as literal key text.
    Allow,
}

/// Separators that delimit a dot-dot traversal segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalSegmentDelimitersValue {
    /// Treat both slash and backslash as delimiters.
    SlashAndBackslash,
    /// Mutation alternative that treats only slash as a delimiter.
    SlashOnly,
}

/// Handling of absolute and UNC-shaped object keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsoluteOrUncPolicyValue {
    /// Reject keys that spell a location.
    Reject,
    /// Mutation alternative that admits those keys.
    Allow,
}

/// Default bucket-name validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultBucketValidatorValue {
    /// Apply the AWS general-purpose bucket rules.
    Aws,
    /// Mutation alternative that adds no rules above the safety floor.
    Permissive,
}

/// Whether callers can replace the default name validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorReplaceabilityValue {
    /// A custom validator replaces the AWS layer and may widen it.
    CustomMayWidenAwsLayer,
    /// Mutation alternative that ignores a custom validator.
    IgnoreCustom,
}

/// Authority of a caller-supplied validator relative to the naming floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorAuthorityValue {
    /// The floor runs first and a validator can only narrow it.
    NarrowOnlyAfterFloor,
    /// Mutation alternative that lets a validator bypass the floor.
    CustomMayBypassFloor,
}

/// Codepoints rejected when a client selects an object key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIngressForbiddenCodepointsValue {
    /// Reject NUL, every C0 control and DEL.
    NulC0AndDel,
    /// Mutation alternative that rejects NUL alone.
    NulOnly,
}

/// Representation policy for keys already present in storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredLegacyControlPolicyValue {
    /// Admit non-NUL legacy controls and escape them in XML listings.
    AllowNonNulAndEscapeOnXmlList,
    /// Mutation alternative that rejects every control character.
    RejectAllControls,
}

/// Unicode normalisation applied to object keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicodeNormalizationValue {
    /// Preserve the received codepoint sequence.
    None,
    /// Mutation alternative that applies NFC.
    Nfc,
}

/// Case folding applied to object keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseFoldingValue {
    /// Preserve case.
    None,
    /// Mutation alternative that lowercases the key.
    Lowercase,
}

/// A typed runtime contract value emitted into generated consumer inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractValue {
    /// Whether a signature canonicalization policy keeps its source spelling.
    SignaturePolicy(bool),
    /// A bucket-CORS runtime policy.
    Cors(CorsContractValue),
    /// A RestoreObject or SelectObjectContent runtime policy.
    SelectRestore(SelectRestoreContractValue),
    /// Derive an unreadable ACL grantee attribute from its identifying child member.
    GranteeTypeFromIdentifyingMember,
    /// Leave an unreadable ACL grantee attribute unset.
    GranteeTypeLeaveUnset,
    /// Canned ACL values accepted for bucket and object targets.
    AclTargetValueSets {
        /// Values accepted for a bucket ACL.
        bucket: Vec<String>,
        /// Values accepted for an object ACL.
        object: Vec<String>,
    },
    /// Which ACL input channels may coexist.
    AclChannelPolicy(AclChannelPolicyValue),
    /// Whether ACL refusal text may contain rejected request values.
    AclErrorSecretFlow(ErrorSecretFlowValue),
    /// Grammar and resource bounds for one explicit grant header.
    AclGrantHeaderGrammar {
        /// Accepted grantee keys in canonical lower-case spelling.
        keys: Vec<String>,
        /// Whether key matching ignores ASCII case.
        case_insensitive: bool,
        /// Maximum header length in bytes.
        max_bytes: u32,
        /// Maximum grantees in one header.
        max_entries: u32,
    },
    /// Closed permission values accepted in an ACL grant.
    AclPermissionValueSet(Vec<String>),
    /// How the optional owner is retained.
    AclOwnerPolicy(AclOwnerPolicyValue),
    /// Result of deleting an absent encryption configuration.
    EncryptionDeleteAbsentPolicy(DeleteAbsentPolicyValue),
    /// Algorithms beside which an encryption KMS key id is accepted.
    EncryptionKmsKeyAlgorithms(Vec<String>),
    /// Closed encryption algorithm set.
    EncryptionAlgorithmValueSet(Vec<String>),
    /// Maximum encryption rules; `None` means unbounded.
    EncryptionRuleLimit(Option<u32>),
    /// Whether encryption rejection reasons may carry the rejected key id.
    EncryptionErrorSecretFlow(ErrorSecretFlowValue),
    /// Closed object-lock mode set.
    ObjectLockModeValueSet(Vec<String>),
    /// Closed `ObjectLockEnabled` value set.
    ObjectLockEnabledValueSet(Vec<String>),
    /// Member constraints for a bucket's default retention.
    ObjectLockDefaultRetention {
        /// Whether `Mode` is required.
        require_mode: bool,
        /// Whether exactly one of `Days` and `Years` is required.
        exactly_one_period: bool,
        /// Inclusive minimum for either period.
        min_period: i32,
    },
    /// Closed legal-hold status set.
    ObjectLockLegalHoldValueSet(Vec<String>),
    /// Required relationship between retain-until and the caller's clock.
    ObjectLockTemporalRelation(TemporalRelationValue),
    /// Required bucket state for object-level lock writes.
    ObjectLockBucketStatePrecondition(BucketStatePreconditionValue),
    /// Handling of `If-None-Match: *` on a write.
    ConditionalWildcardWrite(ConditionalWildcardWriteValue),
    /// Precedence between If-Match and If-Modified-Since.
    IfMatchDatePrecedence(IfMatchDatePrecedenceValue),
    /// Precedence between If-None-Match and If-Unmodified-Since.
    IfNoneDatePrecedence(IfNoneDatePrecedenceValue),
    /// Handling of conflicting entity-tag conditions.
    ConditionConflict(ConditionConflictValue),
    /// Whether conditional entity-tag parsing accepts `*`.
    ConditionalWildcardParse(ConditionalWildcardParseValue),
    /// Which representations supply CopyObject validators.
    CopyValidatorScope(CopyValidatorScopeValue),
    /// Entity-tag comparison strength used by If-Match.
    EtagComparisonStrength(EtagComparisonStrengthValue),
    /// Outcome of a named If-Match miss.
    IfMatchMissOutcome(IfMatchMissOutcomeValue),
    /// Placement of a conditional-write guard relative to mutation.
    ConditionalWriteOrder(ConditionalWriteOrderValue),
    /// Outcome of If-Match against an absent representation.
    IfMatchAbsentPolicy(IfMatchAbsentPolicyValue),
    /// Namespace carried by an S3 error document root.
    ErrorRootNamespace(ErrorRootNamespaceValue),
    /// Whether HEAD responses carry content.
    HeadBodyPolicy(HeadBodyPolicyValue),
    /// Whether precondition failures name the failed condition.
    ConditionFailureDetail(ConditionFailureDetailValue),
    /// Outcome of an unsatisfied copy-source If-Match condition.
    CopySourceIfMatchMiss(CopySourceIfMatchMissValue),
    /// Placement of a copy-source guard relative to the target write.
    CopySourceGuardOrder(CopySourceGuardOrderValue),
    /// Default treatment of repeated slashes.
    DefaultSlashPolicy(DefaultSlashPolicyValue),
    /// Number of percent-decoding passes.
    PercentDecodePasses(PercentDecodePassesValue),
    /// Handling of decoded invalid UTF-8.
    DecodedUtf8(DecodedUtf8Value),
    /// Handling of dangerous encoded residue.
    ResidualEncodedDangerous(ResidualEncodedDangerousValue),
    /// Separators that delimit a traversal segment.
    TraversalSegmentDelimiters(TraversalSegmentDelimitersValue),
    /// Handling of absolute and UNC-shaped keys.
    AbsoluteOrUncPolicy(AbsoluteOrUncPolicyValue),
    /// Maximum object-key length in UTF-8 bytes.
    MaxUtf8Bytes(u32),
    /// Default bucket-name validator.
    DefaultBucketValidator(DefaultBucketValidatorValue),
    /// Whether a custom validator replaces the default.
    ValidatorReplaceability(ValidatorReplaceabilityValue),
    /// Authority of a custom validator relative to the floor.
    ValidatorAuthority(ValidatorAuthorityValue),
    /// Codepoints forbidden on client ingress.
    ClientIngressForbiddenCodepoints(ClientIngressForbiddenCodepointsValue),
    /// Representation policy for stored legacy controls.
    StoredLegacyControlPolicy(StoredLegacyControlPolicyValue),
    /// Unicode normalisation applied to object keys.
    UnicodeNormalization(UnicodeNormalizationValue),
    /// Case folding applied to object keys.
    CaseFolding(CaseFoldingValue),
    /// Validator carried by a not-modified response.
    NotModifiedEtagPolicy(NotModifiedEtagPolicyValue),
    /// Multipart-upload state after a failed completion.
    CompletionFailureUploadPolicy(CompletionFailureUploadPolicyValue),
    /// Outcome when a conditional write loses a race.
    ConditionalRaceOutcome(ConditionalRaceOutcomeValue),
    /// Handling of multiple byte ranges.
    MultiRangePolicy(MultiRangePolicyValue),
    /// Handling of an explicit end beyond the object.
    ExplicitEndOverflowPolicy(ExplicitEndOverflowPolicyValue),
    /// Whether suffix byte ranges are supported.
    SuffixRangePolicy(SuffixRangePolicyValue),
    /// Handling of an oversized suffix range.
    OversizeSuffixPolicy(OversizeSuffixPolicyValue),
    /// Actual-size detail on an unsatisfiable response.
    UnsatisfiableActualSizeDetail(UnsatisfiableActualSizeDetailValue),
    /// Checksum behavior for a partial response.
    PartialChecksumPolicy(PartialChecksumPolicyValue),
    /// Outcome of a valid part-number selection.
    PartNumberOutcome(PartNumberOutcomeValue),
    /// Handling of invalid byte-range syntax.
    InvalidRangePolicy(InvalidRangePolicyValue),
    /// Handling of an If-Range miss.
    IfRangeMissPolicy(IfRangeMissPolicyValue),
    /// Comparison strength used by If-None-Match.
    IfNoneMatchComparisonStrength(IfNoneMatchComparisonStrengthValue),
    /// Handling of a bare conditional entity tag.
    BareConditionalEtagPolicy(BareConditionalEtagPolicyValue),
    /// Content-byte policy for a not-modified response.
    NotModifiedBodyPolicy(NotModifiedBodyPolicyValue),
    /// Representation-framing policy for a not-modified response.
    NotModifiedFramingPolicy(NotModifiedFramingPolicyValue),
    /// First-byte boundary for an unsatisfiable range.
    RangeStartBound(RangeStartBoundValue),
    /// Resolution of an open-ended byte range.
    OpenEndedRangePolicy(OpenEndedRangePolicyValue),
    /// Content-length arithmetic for a read range.
    ReadRangeLengthArithmetic(ReadRangeLengthArithmeticValue),
    /// Span arithmetic for a copy range.
    CopyRangeLengthArithmetic(CopyRangeLengthArithmeticValue),
    /// Representation of the requested range in an error detail.
    RangeRequestedDetail(RangeRequestedDetailValue),
    /// Header policy for total part count.
    PartCountHeaderPolicy(PartCountHeaderPolicyValue),
    /// Handling of simultaneous range and part-number selectors.
    RangePartSelectorConflict(RangePartSelectorConflictValue),
}

/// One runtime contract and the mechanical dimension that changes its generated input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractRule {
    /// Current runtime behavior consumed by generated contract code.
    pub current: ContractValue,
    /// Mutation family for the runtime behavior.
    pub mutation_dimension: MutationDimension,
}
