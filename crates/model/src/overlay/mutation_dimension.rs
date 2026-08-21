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

//! Stable names for every mechanically mutable protocol dimension.
//!
//! Responsible for: the exhaustive dimension vocabulary shared by codec, source, and runtime
//! contract rules. NOT responsible for: parsing or consuming values. Upstream: overlay records.
//! Downstream: model validation, codegen, and mutation guards.

/// The mechanically mutable dimension carried by one typed protocol rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationDimension {
    /// Change whether the canonical host keeps its original wire spelling.
    SignatureCanonicalHostPolicy,
    /// Change whether verification retains the raw-path fallback candidate.
    SignaturePathFallbackPolicy,
    /// Change whether the canonical payload line keeps the client's accepted token spelling.
    SignaturePayloadTokenPolicy,
    /// Change whether SigV2 canonical resources include the subresource allowlist.
    SigV2IncludedQueryPolicy,
    /// Change whether SigV2 empties the Date slot when `x-amz-date` is present.
    SigV2DateSlotPolicy,
    /// Replace the grammar used to validate a wire string.
    WireForm,
    /// Move one or both inclusive integer bounds.
    IntegerRange,
    /// Replace the media type emitted for a text payload.
    MediaType,
    /// Toggle the tolerant reading of a request header.
    HeaderTolerance,
    /// Toggle whether generated XML readers skip or reject unknown children.
    UnknownElementPolicy,
    /// Swap adjacent XML siblings in a generated element sequence.
    ElementOrder,
    /// Replace an XML element name with a mechanically distinct spelling.
    ElementRename,
    /// Replace an XML attribute name without treating it as an element.
    AttributeRename,
    /// Change whether an empty XML value is emitted or omitted.
    EmptyElementRender,
    /// Toggle whether a field is required on the generated wire surface.
    Optionality,
    /// Change quoting in one entity-tag context.
    QuoteStrategy,
    /// Toggle whether an XML list has a wrapper element.
    WrapStrategy,
    /// Change the fields encoded under `encoding-type=url`.
    ElementEncoding,
    /// Change the predicate that suppresses a present output value.
    OmitStrategy,
    /// Change a scalar wire default.
    DefaultValue,
    /// Cycle a timestamp field through the supported wire formats.
    TimeFormat,
    /// Replace an operation's default success status.
    StatusMapping,
    /// Change how an unreadable ACL grantee discriminator is reconstructed.
    GranteeDiscriminatorPolicy,
    /// Change the canned ACL values accepted for buckets and objects.
    TargetValueSets,
    /// Change which ACL input channels may be combined.
    AclChannelMatrix,
    /// Change whether refusal text may contain rejected request values.
    ErrorSecretFlow,
    /// Change the grammar and bounds of explicit ACL grant headers.
    GrantHeaderGrammar,
    /// Change the closed ACL permission set.
    PermissionValueSet,
    /// Change how an ACL document's optional owner is retained.
    OwnerPolicy,
    /// Change the result of deleting an absent configuration.
    DeleteAbsentPolicy,
    /// Change the values allowed when a related member is present.
    ConditionalValueSet,
    /// Change whether a documented enumeration is treated as closed.
    EnumStrictness,
    /// Change the maximum number of entries accepted in a list.
    ListMax,
    /// Change the accepted spelling of a boolean wire value.
    BooleanSpellingPolicy,
    /// Change the member relationship required by a compound document.
    MemberConstraint,
    /// Change the temporal relationship required between two instants.
    TemporalRelation,
    /// Change the bucket state required before an object-level write.
    BucketStatePrecondition,
    /// Change wildcard handling on a conditional write.
    ConditionalWildcardWrite,
    /// Change precedence between If-Match and If-Modified-Since.
    IfMatchDatePrecedence,
    /// Change precedence between If-None-Match and If-Unmodified-Since.
    IfNoneDatePrecedence,
    /// Change handling of conflicting entity-tag conditions.
    ConditionConflictPolicy,
    /// Change whether conditional entity-tag parsing accepts the wildcard.
    ConditionalWildcardParse,
    /// Change which representation supplies CopyObject source and target validators.
    CopyValidatorScope,
    /// Change the entity-tag comparison strength used by If-Match.
    EtagComparisonStrength,
    /// Change the outcome of a named If-Match miss.
    IfMatchMissOutcome,
    /// Change whether a conditional write guards before or after mutating storage.
    ConditionalWriteOrder,
    /// Change the outcome of If-Match when no representation exists.
    IfMatchAbsentPolicy,
    /// Change whether the root of an S3 error document declares an XML namespace.
    ErrorRootNamespace,
    /// Change whether a HEAD response carries the body an equivalent GET would carry.
    HeadBodyPolicy,
    /// Change whether a precondition failure names the condition that failed.
    ConditionFailureDetail,
    /// Change the outcome of an unsatisfied copy-source If-Match condition.
    CopySourceIfMatchMiss,
    /// Change whether a copy-source guard runs before or after the target write.
    CopySourceGuardOrder,
    /// Change the default treatment of repeated slashes in object keys.
    DefaultSlashPolicy,
    /// Change how many percent-decoding passes are applied to an object key.
    PercentDecodePasses,
    /// Change how invalid UTF-8 produced by percent decoding is handled.
    DecodedUtf8,
    /// Change whether dangerous percent-encoded residue is rejected.
    ResidualEncodedDangerous,
    /// Change which separators delimit a traversal segment.
    TraversalSegmentDelimiters,
    /// Change whether absolute and UNC-shaped keys are rejected.
    AbsoluteOrUncPolicy,
    /// Change the maximum accepted object-key length in UTF-8 bytes.
    MaxUtf8Bytes,
    /// Change the default bucket-name validator.
    DefaultBucketValidator,
    /// Change whether a caller-supplied name validator replaces the default validator.
    ValidatorReplaceability,
    /// Change whether a caller-supplied validator may bypass the naming floor.
    ValidatorAuthority,
    /// Change the codepoints rejected on client key ingress.
    ClientIngressForbiddenCodepoints,
    /// Change whether stored legacy control characters remain representable.
    StoredLegacyControlPolicy,
    /// Change Unicode normalisation of object keys.
    UnicodeNormalization,
    /// Change case folding of object keys.
    CaseFolding,
    /// Change which validator is returned on a not-modified response.
    NotModifiedEtagPolicy,
    /// Change whether a failed completion retains its multipart upload.
    CompletionFailureUploadPolicy,
    /// Change the error outcome when a conditional write loses a race.
    ConditionalRaceOutcome,
    /// Change how multiple byte ranges are handled.
    MultiRangePolicy,
    /// Change how an explicit range end beyond the object is handled.
    ExplicitEndOverflowPolicy,
    /// Change whether suffix byte ranges are supported.
    SuffixRangePolicy,
    /// Change how an oversized suffix range is resolved.
    OversizeSuffixPolicy,
    /// Change whether an unsatisfiable response reports the actual size.
    UnsatisfiableActualSizeDetail,
    /// Change whether a partial response carries a whole-object checksum.
    PartialChecksumPolicy,
    /// Change the response outcome for a valid part-number selection.
    PartNumberOutcome,
    /// Change how an invalid byte-range grammar is handled.
    InvalidRangePolicy,
    /// Change how an If-Range miss affects range selection.
    IfRangeMissPolicy,
    /// Change the comparison strength used by If-None-Match.
    IfNoneMatchComparisonStrength,
    /// Change whether bare conditional entity tags are accepted and normalized.
    BareConditionalEtagPolicy,
    /// Change whether a not-modified response suppresses content bytes.
    NotModifiedBodyPolicy,
    /// Change whether a not-modified response suppresses representation framing.
    NotModifiedFramingPolicy,
    /// Change the first-byte boundary that makes a range unsatisfiable.
    RangeStartBound,
    /// Change how an open-ended byte range selects its final byte.
    OpenEndedRangePolicy,
    /// Change the arithmetic used for a read-range content length.
    ReadRangeLengthArithmetic,
    /// Change the arithmetic used for a copy-range span.
    CopyRangeLengthArithmetic,
    /// Change how the requested range is reported in an error detail.
    RangeRequestedDetail,
    /// Change whether part responses report the total part count.
    PartCountHeaderPolicy,
    /// Change how simultaneous range and part-number selectors are handled.
    RangePartSelectorConflict,
    /// Change the closed set of methods accepted in a CORS rule.
    CorsAllowedMethodValueSet,
    /// Change case handling for methods stored in a CORS rule.
    CorsAllowedMethodCasePolicy,
    /// Change the wildcard count accepted in an allowed origin.
    CorsOriginWildcardLimit,
    /// Change the wildcard count accepted in an allowed header.
    CorsAllowedHeaderWildcardLimit,
    /// Change the wildcard count accepted in an exposed header.
    CorsExposeHeaderWildcardLimit,
    /// Change the result of deleting an absent CORS configuration.
    CorsDeleteAbsentPolicy,
    /// Change whether a preflight bypasses the ordinary operation pipeline.
    CorsPreflightDispatchPolicy,
    /// Change which addressed bucket supplies a preflight's configuration.
    CorsPreflightBucketSource,
    /// Change where a preflight's allow-methods value comes from.
    CorsPreflightAllowMethodsSource,
    /// Change whether a preflight includes the matched rule's max age.
    CorsPreflightMaxAgePolicy,
    /// Change whether a preflight includes the matched rule's exposed headers.
    CorsPreflightExposePolicy,
    /// Change whether a preflight varies on Origin.
    CorsPreflightVaryPolicy,
    /// Change how a bare wildcard origin is rendered.
    CorsBareWildcardAnswer,
    /// Change how a partial wildcard origin is rendered.
    CorsPartialWildcardAnswer,
    /// Change whether wildcard origin matches may carry credentials.
    CorsWildcardCredentialsPolicy,
    /// Change matching of an exact allowed origin.
    CorsExactOriginMatch,
    /// Change matching of a wildcard allowed origin.
    CorsOriginWildcardMatch,
    /// Change whether an actual response includes allow-origin.
    CorsActualAllowOriginPolicy,
    /// Change whether an actual response includes exposed headers.
    CorsActualExposePolicy,
    /// Change whether an actual response varies on Origin.
    CorsActualVaryPolicy,
    /// Change whether actual responses include preflight-only headers.
    CorsActualPreflightHeaderPolicy,
    /// Change how an actual request from an unmatched origin is served.
    CorsUnmatchedActualPolicy,
    /// Change case handling when matching requested header names.
    CorsRequestedHeaderCasePolicy,
    /// Change wildcard handling when matching requested header names.
    CorsRequestedHeaderWildcardMatch,
    /// Change the quantifier applied to requested header names.
    CorsRequestedHeaderQuantifier,
    /// Change where Access-Control-Allow-Headers gets its value.
    CorsAllowHeadersAnswerSource,
    /// Change which matching CORS rule wins.
    CorsRuleOrderPolicy,
    /// Change whether match dimensions must hold on the same rule.
    CorsRuleDimensionJoin,
    /// Change which rule supplies answer values after matching.
    CorsMatchedRuleValueSource,
    /// Change whether post-authorisation errors carry CORS headers.
    CorsHeadersOnPostAuthError,
    /// Change whether all preflight refusals share one response profile.
    CorsPreflightRefusalProfile,
    /// Change whether absent and unavailable CORS sources are collapsed.
    CorsSourceAbsencePolicy,
    /// Change how an invalid preflight target is handled.
    CorsInvalidTargetPolicy,
    /// Change which characters are accepted in an Origin value.
    CorsOriginCharacterPolicy,
    /// Change whether an empty Origin is accepted.
    CorsOriginEmptyPolicy,
    /// Change the maximum accepted Origin length.
    CorsOriginMaxBytes,
    /// Change the accepted number of Origin fields.
    CorsOriginCardinality,
    /// Change the accepted number of request-method fields.
    CorsRequestMethodCardinality,
    /// Change the accepted number of requested-header fields.
    CorsRequestHeadersCardinality,
    /// Change how a bare OPTIONS request is dispatched.
    CorsBareOptionsPolicy,
    /// Change which CORS request headers are required for a preflight.
    CorsPreflightRequiredHeaderPair,
    /// Change whether a successful preflight grants request authorisation.
    CorsPreflightAuthorizationScope,
    /// Change the success status for a newly initiated restore.
    RestoreInitiatedOutcome,
    /// Change the success status for an already-restored object.
    RestoreAlreadyRestoredOutcome,
    /// Change the outcome of restoring while retrieval is in progress.
    RestoreInProgressOutcome,
    /// Change the ongoing restore-header spelling.
    RestoreHeaderOngoingForm,
    /// Change the completed restore-header spelling.
    RestoreHeaderRestoredForm,
    /// Change whether absent restore state emits a header.
    RestoreHeaderAbsence,
    /// Change the grammar accepted by the restore-header parser.
    RestoreHeaderParseGrammar,
    /// Change the outcome of restoring a non-archive object.
    RestoreNotArchivedOutcome,
    /// Change the inclusive minimum restore duration.
    RestoreDaysMinimum,
    /// Change whether a restore request must name one form.
    RestoreFormPresence,
    /// Change how Days beside the select form is handled.
    RestoreDaysSelectExclusion,
    /// Change whether select members require Type SELECT.
    RestoreSelectMembersRequireType,
    /// Change whether a select restore requires OutputLocation.
    RestoreSelectOutputRequired,
    /// Change whether a select restore requires SelectParameters.
    RestoreSelectParametersRequired,
    /// Change whether nested select parameters use the shared validator.
    RestoreNestedSelectValidation,
    /// Change the closed RestoreRequest Type set.
    RestoreTypeValueSet,
    /// Change the closed GlacierJobParameters tier set.
    RestoreGlacierTierValueSet,
    /// Change the closed direct RestoreRequest tier set.
    RestoreDirectTierValueSet,
    /// Change RestoreRequest root-name namespace matching.
    RestoreRootNamespacePolicy,
    /// Change whether the restore version selector reaches the handler.
    RestoreVersionSelector,
    /// Change the select-type route predicate.
    SelectTypeRoutePredicate,
    /// Change the select-expression byte ceiling.
    SelectExpressionMaxBytes,
    /// Change whether an empty select expression is accepted.
    SelectExpressionPresence,
    /// Change whether select refusals may echo the expression.
    SelectExpressionErrorFlow,
    /// Change how much of a select expression the framework inspects.
    SelectExpressionInspection,
    /// Change how multiple input serializations are handled.
    SelectInputMultiple,
    /// Change how a missing input serialization is handled.
    SelectInputMissing,
    /// Change how multiple output serializations are handled.
    SelectOutputMultiple,
    /// Change how a missing output serialization is handled.
    SelectOutputMissing,
    /// Change how an empty ScanRange is handled.
    SelectScanRangeEmpty,
    /// Change whether a bounded ScanRange must be ordered.
    SelectScanRangeOrder,
    /// Change whether ScanRange bounds must be non-negative.
    SelectScanRangeSign,
    /// Change the bytes selected by a two-bound ScanRange.
    SelectScanBounded,
    /// Change the bytes selected by a start-only ScanRange.
    SelectScanStartOnly,
    /// Change the bytes selected by an end-only ScanRange.
    SelectScanEndOnly,
    /// Change the closed select expression-type set.
    SelectExpressionTypeValues,
    /// Change the closed select compression set.
    SelectCompressionValues,
    /// Change SelectObjectContent root-name namespace matching.
    SelectRootNamespacePolicy,
    /// Change the response shape used by SelectObjectContent.
    SelectResponseShape,
    /// Change the successful select event-stream status.
    SelectEventStatus,
    /// Change the select event-stream media type.
    SelectEventMediaType,
    /// Change the bytes covered by the event prelude CRC.
    EventPreludeCrcCoverage,
    /// Change the bytes covered by the event message CRC.
    EventMessageCrcCoverage,
    /// Change the event-stream CRC algorithm.
    EventCrcAlgorithm,
    /// Change successful event-stream termination.
    SelectEventTermination,
}

impl MutationDimension {
    /// Stable spelling written to generated mutation tables.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignatureCanonicalHostPolicy => "signature_canonical_host_policy",
            Self::SignaturePathFallbackPolicy => "signature_path_fallback_policy",
            Self::SignaturePayloadTokenPolicy => "signature_payload_token_policy",
            Self::SigV2IncludedQueryPolicy => "sigv2_included_query_policy",
            Self::SigV2DateSlotPolicy => "sigv2_date_slot_policy",
            Self::WireForm => "wire_form",
            Self::IntegerRange => "integer_range",
            Self::MediaType => "media_type",
            Self::HeaderTolerance => "header_tolerance",
            Self::UnknownElementPolicy => "unknown_element_policy",
            Self::ElementOrder => "element_order",
            Self::ElementRename => "element_rename",
            Self::AttributeRename => "attribute_rename",
            Self::EmptyElementRender => "empty_element_render",
            Self::Optionality => "optionality",
            Self::QuoteStrategy => "quote_strategy",
            Self::WrapStrategy => "wrap_strategy",
            Self::ElementEncoding => "element_encoding",
            Self::OmitStrategy => "omit_strategy",
            Self::DefaultValue => "default_value",
            Self::TimeFormat => "time_format",
            Self::StatusMapping => "status_mapping",
            Self::GranteeDiscriminatorPolicy => "grantee_discriminator_policy",
            Self::TargetValueSets => "target_value_sets",
            Self::AclChannelMatrix => "acl_channel_matrix",
            Self::ErrorSecretFlow => "error_secret_flow",
            Self::GrantHeaderGrammar => "grant_header_grammar",
            Self::PermissionValueSet => "permission_value_set",
            Self::OwnerPolicy => "owner_policy",
            Self::DeleteAbsentPolicy => "delete_absent_policy",
            Self::ConditionalValueSet => "conditional_value_set",
            Self::EnumStrictness => "enum_strictness",
            Self::ListMax => "list_max",
            Self::BooleanSpellingPolicy => "boolean_spelling_policy",
            Self::MemberConstraint => "member_constraint",
            Self::TemporalRelation => "temporal_relation",
            Self::BucketStatePrecondition => "bucket_state_precondition",
            Self::ConditionalWildcardWrite => "conditional_wildcard_write",
            Self::IfMatchDatePrecedence => "if_match_date_precedence",
            Self::IfNoneDatePrecedence => "if_none_date_precedence",
            Self::ConditionConflictPolicy => "condition_conflict_policy",
            Self::ConditionalWildcardParse => "conditional_wildcard_parse",
            Self::CopyValidatorScope => "copy_validator_scope",
            Self::EtagComparisonStrength => "etag_comparison_strength",
            Self::IfMatchMissOutcome => "if_match_miss_outcome",
            Self::ConditionalWriteOrder => "conditional_write_order",
            Self::IfMatchAbsentPolicy => "if_match_absent_policy",
            Self::ErrorRootNamespace => "error_root_namespace",
            Self::HeadBodyPolicy => "head_body_policy",
            Self::ConditionFailureDetail => "condition_failure_detail",
            Self::CopySourceIfMatchMiss => "copy_source_if_match_miss",
            Self::CopySourceGuardOrder => "copy_source_guard_order",
            Self::DefaultSlashPolicy => "default_slash_policy",
            Self::PercentDecodePasses => "percent_decode_passes",
            Self::DecodedUtf8 => "decoded_utf8",
            Self::ResidualEncodedDangerous => "residual_encoded_dangerous",
            Self::TraversalSegmentDelimiters => "traversal_segment_delimiters",
            Self::AbsoluteOrUncPolicy => "absolute_or_unc_policy",
            Self::MaxUtf8Bytes => "max_utf8_bytes",
            Self::DefaultBucketValidator => "default_bucket_validator",
            Self::ValidatorReplaceability => "validator_replaceability",
            Self::ValidatorAuthority => "validator_authority",
            Self::ClientIngressForbiddenCodepoints => "client_ingress_forbidden_codepoints",
            Self::StoredLegacyControlPolicy => "stored_legacy_control_policy",
            Self::UnicodeNormalization => "unicode_normalization",
            Self::CaseFolding => "case_folding",
            Self::NotModifiedEtagPolicy => "not_modified_etag_policy",
            Self::CompletionFailureUploadPolicy => "completion_failure_upload_policy",
            Self::ConditionalRaceOutcome => "conditional_race_outcome",
            Self::MultiRangePolicy => "multi_range_policy",
            Self::ExplicitEndOverflowPolicy => "explicit_end_overflow_policy",
            Self::SuffixRangePolicy => "suffix_range_policy",
            Self::OversizeSuffixPolicy => "oversize_suffix_policy",
            Self::UnsatisfiableActualSizeDetail => "unsatisfiable_actual_size_detail",
            Self::PartialChecksumPolicy => "partial_checksum_policy",
            Self::PartNumberOutcome => "part_number_outcome",
            Self::InvalidRangePolicy => "invalid_range_policy",
            Self::IfRangeMissPolicy => "if_range_miss_policy",
            Self::IfNoneMatchComparisonStrength => "if_none_match_comparison_strength",
            Self::BareConditionalEtagPolicy => "bare_conditional_etag_policy",
            Self::NotModifiedBodyPolicy => "not_modified_body_policy",
            Self::NotModifiedFramingPolicy => "not_modified_framing_policy",
            Self::RangeStartBound => "range_start_bound",
            Self::OpenEndedRangePolicy => "open_ended_range_policy",
            Self::ReadRangeLengthArithmetic => "read_range_length_arithmetic",
            Self::CopyRangeLengthArithmetic => "copy_range_length_arithmetic",
            Self::RangeRequestedDetail => "range_requested_detail",
            Self::PartCountHeaderPolicy => "part_count_header_policy",
            Self::RangePartSelectorConflict => "range_part_selector_conflict",
            Self::CorsAllowedMethodValueSet => "cors_allowed_method_value_set",
            Self::CorsAllowedMethodCasePolicy => "cors_allowed_method_case_policy",
            Self::CorsOriginWildcardLimit => "cors_origin_wildcard_limit",
            Self::CorsAllowedHeaderWildcardLimit => "cors_allowed_header_wildcard_limit",
            Self::CorsExposeHeaderWildcardLimit => "cors_expose_header_wildcard_limit",
            Self::CorsDeleteAbsentPolicy => "cors_delete_absent_policy",
            Self::CorsPreflightDispatchPolicy => "cors_preflight_dispatch_policy",
            Self::CorsPreflightBucketSource => "cors_preflight_bucket_source",
            Self::CorsPreflightAllowMethodsSource => "cors_preflight_allow_methods_source",
            Self::CorsPreflightMaxAgePolicy => "cors_preflight_max_age_policy",
            Self::CorsPreflightExposePolicy => "cors_preflight_expose_policy",
            Self::CorsPreflightVaryPolicy => "cors_preflight_vary_policy",
            Self::CorsBareWildcardAnswer => "cors_bare_wildcard_answer",
            Self::CorsPartialWildcardAnswer => "cors_partial_wildcard_answer",
            Self::CorsWildcardCredentialsPolicy => "cors_wildcard_credentials_policy",
            Self::CorsExactOriginMatch => "cors_exact_origin_match",
            Self::CorsOriginWildcardMatch => "cors_origin_wildcard_match",
            Self::CorsActualAllowOriginPolicy => "cors_actual_allow_origin_policy",
            Self::CorsActualExposePolicy => "cors_actual_expose_policy",
            Self::CorsActualVaryPolicy => "cors_actual_vary_policy",
            Self::CorsActualPreflightHeaderPolicy => "cors_actual_preflight_header_policy",
            Self::CorsUnmatchedActualPolicy => "cors_unmatched_actual_policy",
            Self::CorsRequestedHeaderCasePolicy => "cors_requested_header_case_policy",
            Self::CorsRequestedHeaderWildcardMatch => "cors_requested_header_wildcard_match",
            Self::CorsRequestedHeaderQuantifier => "cors_requested_header_quantifier",
            Self::CorsAllowHeadersAnswerSource => "cors_allow_headers_answer_source",
            Self::CorsRuleOrderPolicy => "cors_rule_order_policy",
            Self::CorsRuleDimensionJoin => "cors_rule_dimension_join",
            Self::CorsMatchedRuleValueSource => "cors_matched_rule_value_source",
            Self::CorsHeadersOnPostAuthError => "cors_headers_on_post_auth_error",
            Self::CorsPreflightRefusalProfile => "cors_preflight_refusal_profile",
            Self::CorsSourceAbsencePolicy => "cors_source_absence_policy",
            Self::CorsInvalidTargetPolicy => "cors_invalid_target_policy",
            Self::CorsOriginCharacterPolicy => "cors_origin_character_policy",
            Self::CorsOriginEmptyPolicy => "cors_origin_empty_policy",
            Self::CorsOriginMaxBytes => "cors_origin_max_bytes",
            Self::CorsOriginCardinality => "cors_origin_cardinality",
            Self::CorsRequestMethodCardinality => "cors_request_method_cardinality",
            Self::CorsRequestHeadersCardinality => "cors_request_headers_cardinality",
            Self::CorsBareOptionsPolicy => "cors_bare_options_policy",
            Self::CorsPreflightRequiredHeaderPair => "cors_preflight_required_header_pair",
            Self::CorsPreflightAuthorizationScope => "cors_preflight_authorization_scope",
            Self::RestoreInitiatedOutcome => "restore_initiated_outcome",
            Self::RestoreAlreadyRestoredOutcome => "restore_already_restored_outcome",
            Self::RestoreInProgressOutcome => "restore_in_progress_outcome",
            Self::RestoreHeaderOngoingForm => "restore_header_ongoing_form",
            Self::RestoreHeaderRestoredForm => "restore_header_restored_form",
            Self::RestoreHeaderAbsence => "restore_header_absence",
            Self::RestoreHeaderParseGrammar => "restore_header_parse_grammar",
            Self::RestoreNotArchivedOutcome => "restore_not_archived_outcome",
            Self::RestoreDaysMinimum => "restore_days_minimum",
            Self::RestoreFormPresence => "restore_form_presence",
            Self::RestoreDaysSelectExclusion => "restore_days_select_exclusion",
            Self::RestoreSelectMembersRequireType => "restore_select_members_require_type",
            Self::RestoreSelectOutputRequired => "restore_select_output_required",
            Self::RestoreSelectParametersRequired => "restore_select_parameters_required",
            Self::RestoreNestedSelectValidation => "restore_nested_select_validation",
            Self::RestoreTypeValueSet => "restore_type_value_set",
            Self::RestoreGlacierTierValueSet => "restore_glacier_tier_value_set",
            Self::RestoreDirectTierValueSet => "restore_direct_tier_value_set",
            Self::RestoreRootNamespacePolicy => "restore_root_namespace_policy",
            Self::RestoreVersionSelector => "restore_version_selector",
            Self::SelectTypeRoutePredicate => "select_type_route_predicate",
            Self::SelectExpressionMaxBytes => "select_expression_max_bytes",
            Self::SelectExpressionPresence => "select_expression_presence",
            Self::SelectExpressionErrorFlow => "select_expression_error_flow",
            Self::SelectExpressionInspection => "select_expression_inspection",
            Self::SelectInputMultiple => "select_input_multiple",
            Self::SelectInputMissing => "select_input_missing",
            Self::SelectOutputMultiple => "select_output_multiple",
            Self::SelectOutputMissing => "select_output_missing",
            Self::SelectScanRangeEmpty => "select_scan_range_empty",
            Self::SelectScanRangeOrder => "select_scan_range_order",
            Self::SelectScanRangeSign => "select_scan_range_sign",
            Self::SelectScanBounded => "select_scan_bounded",
            Self::SelectScanStartOnly => "select_scan_start_only",
            Self::SelectScanEndOnly => "select_scan_end_only",
            Self::SelectExpressionTypeValues => "select_expression_type_values",
            Self::SelectCompressionValues => "select_compression_values",
            Self::SelectRootNamespacePolicy => "select_root_namespace_policy",
            Self::SelectResponseShape => "select_response_shape",
            Self::SelectEventStatus => "select_event_status",
            Self::SelectEventMediaType => "select_event_media_type",
            Self::EventPreludeCrcCoverage => "event_prelude_crc_coverage",
            Self::EventMessageCrcCoverage => "event_message_crc_coverage",
            Self::EventCrcAlgorithm => "event_crc_algorithm",
            Self::SelectEventTermination => "select_event_termination",
        }
    }
}
