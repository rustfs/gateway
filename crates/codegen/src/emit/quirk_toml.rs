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

//! `spec/quirks/*.toml` and `spec/contracts/*.toml`: disjoint typed protocol-rule tables.
//!
//! Responsible for: rendering common metadata plus the typed value and mutation dimension carried
//! by proven mutable quirks and runtime contracts. NOT responsible for: classifying records,
//! rendering deferred overlay facts, or deciding mutation alternatives. Upstream: the overlay.
//! Downstream: reviewers, `xtask why`, and the mutation gate.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::{EmptyValue, Field, OmitWhen, OperationIr, Quirk, Type};
use rustfs_gateway_model::json::Value;
use rustfs_gateway_model::{
    AbsoluteOrUncPolicyValue, AclChannelPolicyValue, AclOwnerPolicyValue, BooleanSpellingValue, BucketStatePreconditionValue,
    CaseFoldingValue, ClientIngressForbiddenCodepointsValue, CodecRule, CodecValue, ConditionConflictValue,
    ConditionFailureDetailValue, ConditionalWildcardParseValue, ConditionalWildcardWriteValue, ConditionalWriteOrderValue,
    ContractRule, ContractValue, CopySourceGuardOrderValue, CopySourceIfMatchMissValue, CopyValidatorScopeValue,
    DecodedUtf8Value, DefaultBucketValidatorValue, DefaultSlashPolicyValue, DeleteAbsentPolicyValue, ErrorRootNamespaceValue,
    ErrorSecretFlowValue, EtagComparisonStrengthValue, HeadBodyPolicyValue, HeaderToleranceValue, IfMatchAbsentPolicyValue,
    IfMatchDatePrecedenceValue, IfMatchMissOutcomeValue, IfNoneDatePrecedenceValue, PercentDecodePassesValue,
    ResidualEncodedDangerousValue, RuleClassification, SourceRule, StoredLegacyControlPolicyValue, TemporalRelationValue,
    TraversalSegmentDelimitersValue, UnicodeNormalizationValue, UnknownElementPolicyValue, ValidatorAuthorityValue,
    ValidatorReplaceabilityValue,
};

use super::{quote, string_list};

/// A typed current value read from one lowered-IR mutation source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceValue {
    /// One string value.
    Text(String),
    /// One ordered string list.
    TextList(Vec<String>),
    /// One boolean value.
    Bool(bool),
    /// One optional string value, where absence is itself the current rule.
    OptionalText(Option<String>),
    /// One signed integer value.
    Int(i64),
}

/// One resolved mutation source and the current value code generation consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSource {
    /// Stable path into lowered operation IR.
    pub path: String,
    /// Current value at that path.
    pub current: SourceValue,
}

/// Resolves every declared source against the same lowered IR passed to code generation.
pub fn resolve_sources(operations: &[OperationIr], rule: &SourceRule) -> Result<Vec<ResolvedSource>, String> {
    rule.sources.iter().map(|path| resolve_source(operations, path)).collect()
}

/// Reads the value one mutation source path names, without the path echoed back.
///
/// The mutation writer needs the reader's answer to prove it is about to overwrite the value the
/// ledger recorded rather than a value the two have drifted apart on.
///
/// # Errors
///
/// Returns the reason when the path names nothing resolvable.
pub fn resolve_at(operations: &[OperationIr], path: &str) -> Result<SourceValue, String> {
    resolve_source(operations, path).map(|resolved| resolved.current)
}

fn resolve_source(operations: &[OperationIr], path: &str) -> Result<ResolvedSource, String> {
    let parts: Vec<&str> = path.split('.').collect();
    let operation_name = parts.first().copied().ok_or_else(|| "empty mutation source".to_owned())?;
    let operation = operations
        .iter()
        .find(|operation| operation.operation == operation_name)
        .ok_or_else(|| format!("mutation source `{path}` names unknown operation `{operation_name}`"))?;
    let current = match parts.as_slice() {
        [_, "http", "success_status"] => SourceValue::Int(i64::from(operation.http.success_status)),
        [_, "errors", "not_configured"] => SourceValue::OptionalText(operation.errors.not_configured.clone()),
        [_, "checksum", "http_checksum_required"] => SourceValue::Bool(operation.checksum.http_checksum_required),
        [_, "xml", "element_order"] => SourceValue::TextList(operation.xml.element_order.clone()),
        [_, "xml", "unwrapped_output"] => SourceValue::Bool(operation.xml.unwrapped_output),
        [_, "xml", "url_encoded_fields"] => SourceValue::TextList(operation.xml.url_encoded_fields.clone()),
        [_, "xml", "response_root"] => SourceValue::Text(
            operation
                .xml
                .response_root
                .clone()
                .ok_or_else(|| format!("mutation source `{path}` has no current response root"))?,
        ),
        [_, "xml", "request_root"] => SourceValue::Text(
            operation
                .xml
                .request_root
                .clone()
                .ok_or_else(|| format!("mutation source `{path}` has no current request root"))?,
        ),
        [_, "xml", "empty_value", field] => SourceValue::Text(
            empty_value(&operation.xml.empty_value_policy, field, path)?
                .as_str()
                .to_owned(),
        ),
        [_, side @ ("input" | "output"), field, "required"] => {
            let field = operation_field(operation, side, field, path)?;
            SourceValue::Bool(field.required)
        }
        [_, side @ ("input" | "output"), field, property] => {
            let field = operation_field(operation, side, field, path)?;
            field_source(field, property, path)?
        }
        [_, "shapes", shape, "xml", "element_order"] => {
            let shape = operation
                .shapes
                .get(*shape)
                .ok_or_else(|| format!("mutation source `{path}` names an unknown shape"))?;
            SourceValue::TextList(shape.xml.element_order.clone())
        }
        [_, "shapes", shape, "xml", "empty_value", field] => {
            let shape = operation
                .shapes
                .get(*shape)
                .ok_or_else(|| format!("mutation source `{path}` names an unknown shape"))?;
            SourceValue::Text(empty_value(&shape.xml.empty_value_policy, field, path)?.as_str().to_owned())
        }
        [_, "shapes", shape, "xml", "attributes", index, "name"] => {
            let shape = operation
                .shapes
                .get(*shape)
                .ok_or_else(|| format!("mutation source `{path}` names an unknown shape"))?;
            let index = index
                .parse::<usize>()
                .map_err(|_| format!("mutation source `{path}` has a non-integer attribute index"))?;
            SourceValue::Text(
                shape
                    .xml
                    .attributes
                    .get(index)
                    .ok_or_else(|| format!("mutation source `{path}` names an unknown attribute"))?
                    .name
                    .clone(),
            )
        }
        [_, "shapes", shape, "fields", field, property] => {
            let shape = operation
                .shapes
                .get(*shape)
                .ok_or_else(|| format!("mutation source `{path}` names an unknown shape"))?;
            let field = shape
                .fields
                .iter()
                .find(|candidate| candidate.name == *field)
                .ok_or_else(|| format!("mutation source `{path}` names an unknown field"))?;
            field_source(field, property, path)?
        }
        _ => return Err(format!("mutation source `{path}` has an unsupported path shape")),
    };
    Ok(ResolvedSource {
        path: path.to_owned(),
        current,
    })
}

fn empty_value<'a>(values: &'a [(String, EmptyValue)], field: &str, path: &str) -> Result<&'a EmptyValue, String> {
    values
        .iter()
        .find(|(name, _)| name == field)
        .map(|(_, value)| value)
        .ok_or_else(|| format!("mutation source `{path}` has no empty-value policy"))
}

fn operation_field<'a>(operation: &'a OperationIr, side: &str, name: &str, path: &str) -> Result<&'a Field, String> {
    let fields = if side == "input" {
        &operation.input
    } else {
        &operation.output
    };
    fields
        .iter()
        .find(|candidate| candidate.name == name)
        .ok_or_else(|| format!("mutation source `{path}` names an unknown field"))
}

fn field_source(field: &Field, property: &str, path: &str) -> Result<SourceValue, String> {
    match property {
        "required" => Ok(SourceValue::Bool(field.required)),
        "wire_name" => field
            .wire_name
            .clone()
            .map(SourceValue::Text)
            .ok_or_else(|| format!("mutation source `{path}` has no current wire name")),
        "etag_render" => match field.ty {
            Type::ETag(render) => Ok(SourceValue::Text(render.as_str().to_owned())),
            _ => Err(format!("mutation source `{path}` is not an entity tag")),
        },
        "list_flattened" => match field.ty {
            Type::List { flattened, .. } => Ok(SourceValue::Bool(flattened)),
            _ => Err(format!("mutation source `{path}` is not a list")),
        },
        "omit_when" => Ok(SourceValue::OptionalText(field.omit_when.as_ref().map(omit_when))),
        "default_int" => match field.default {
            Some(Value::Int(value)) => Ok(SourceValue::Int(value)),
            _ => Err(format!("mutation source `{path}` has no current integer default")),
        },
        "default_string" => match &field.default {
            Some(Value::Str(value)) => Ok(SourceValue::Text(value.clone())),
            _ => Err(format!("mutation source `{path}` has no current string default")),
        },
        "timestamp_format" => match field.ty {
            Type::Timestamp(format) => Ok(SourceValue::Text(format.as_str().to_owned())),
            _ => Err(format!("mutation source `{path}` is not a timestamp")),
        },
        "wire_type" => match field.ty {
            Type::OpaqueString => Ok(SourceValue::Text("OpaqueString".to_owned())),
            _ => Err(format!("mutation source `{path}` is not an opaque string")),
        },
        _ => Err(format!("mutation source `{path}` names unsupported field property `{property}`")),
    }
}

fn omit_when(value: &OmitWhen) -> String {
    match value {
        OmitWhen::Empty => "Empty".to_owned(),
        OmitWhen::Default => "Default".to_owned(),
        OmitWhen::ValueEquals(value) => format!("ValueEquals({value})"),
        OmitWhen::RequestField { field, equals } => format!("RequestField({field}=={equals})"),
    }
}

/// Renders one quirk or contract record in the stable generated format.
pub fn render(
    quirk: &Quirk,
    codec_rule: Option<&CodecRule>,
    source_rule: Option<&SourceRule>,
    contract_rule: Option<&ContractRule>,
    sources: &[ResolvedSource],
    classification: RuleClassification,
) -> String {
    let mut out = String::from("# Generated by `cargo xtask codegen`; edit model/overlays instead.\n\n");
    let _ = writeln!(out, "id = {}", quote(&quirk.id));
    let _ = writeln!(out, "kind = {}", quote(&quirk.kind));
    let class = match classification {
        RuleClassification::Mutable => "mutable",
        RuleClassification::Contract => "contract",
    };
    let _ = writeln!(out, "classification = {}", quote(class));
    match codec_rule.map(|rule| &rule.current) {
        Some(CodecValue::IntegerRange { min, max }) => {
            let _ = writeln!(out, "codec_min = {min}");
            let _ = writeln!(out, "codec_max = {max}");
        }
        Some(CodecValue::MediaType(media)) => {
            let _ = writeln!(out, "codec_value = {}", quote(media));
        }
        Some(CodecValue::HeaderTolerance(HeaderToleranceValue::DateCondition)) => {
            out.push_str("codec_value = \"date_condition\"\n");
        }
        Some(CodecValue::UnknownElementPolicy(UnknownElementPolicyValue::Skip)) => {
            out.push_str("codec_value = \"skip\"\n");
        }
        Some(CodecValue::UnknownElementPolicy(UnknownElementPolicyValue::Reject)) => {
            out.push_str("codec_value = \"reject\"\n");
        }
        Some(CodecValue::BooleanSpelling(BooleanSpellingValue::AsciiCaseInsensitive)) => {
            out.push_str("codec_value = \"ascii_case_insensitive\"\n");
        }
        Some(CodecValue::BooleanSpelling(BooleanSpellingValue::LowercaseOnly)) => {
            out.push_str("codec_value = \"lowercase_only\"\n");
        }
        None => {}
    }
    match contract_rule.map(|rule| &rule.current) {
        Some(ContractValue::SignaturePolicy(true)) => match contract_rule.map(|rule| rule.mutation_dimension) {
            Some(rustfs_gateway_model::MutationDimension::SignatureCanonicalHostPolicy) => {
                out.push_str("contract_value = \"raw_host_bytes\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SignaturePathFallbackPolicy) => {
                out.push_str("contract_value = \"decoded_then_raw\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SignaturePayloadTokenPolicy) => {
                out.push_str("contract_value = \"verbatim_payload_token\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SigV2IncludedQueryPolicy) => {
                out.push_str("contract_value = \"include_subresources\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SigV2DateSlotPolicy) => {
                out.push_str("contract_value = \"empty_on_amz_date\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SigV2ExpiresAbsolutePolicy) => {
                out.push_str("contract_value = \"absolute_unix_second\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SigV2QueryCoveragePolicy) => {
                out.push_str("contract_value = \"ignore_unlisted_query\"\n")
            }
            _ => {}
        },
        Some(ContractValue::SignaturePolicy(false)) => match contract_rule.map(|rule| rule.mutation_dimension) {
            Some(rustfs_gateway_model::MutationDimension::SignatureCanonicalHostPolicy) => {
                out.push_str("contract_value = \"normalized_host\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SignaturePathFallbackPolicy) => {
                out.push_str("contract_value = \"decoded_only\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SignaturePayloadTokenPolicy) => {
                out.push_str("contract_value = \"digest_hex\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SigV2IncludedQueryPolicy) => {
                out.push_str("contract_value = \"omit_subresources\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SigV2DateSlotPolicy) => {
                out.push_str("contract_value = \"date_header_on_amz_date\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SigV2ExpiresAbsolutePolicy) => {
                out.push_str("contract_value = \"relative_lifetime\"\n")
            }
            Some(rustfs_gateway_model::MutationDimension::SigV2QueryCoveragePolicy) => {
                out.push_str("contract_value = \"include_unlisted_query\"\n")
            }
            _ => {}
        },
        Some(ContractValue::GranteeTypeFromIdentifyingMember) => {
            out.push_str("contract_value = \"derive_from_identifying_member\"\n");
        }
        Some(ContractValue::GranteeTypeLeaveUnset) => {
            out.push_str("contract_value = \"leave_unset\"\n");
        }
        Some(ContractValue::AclTargetValueSets { bucket, object }) => {
            out.push_str("contract_value = \"target_specific_canned_acls\"\n");
            let _ = writeln!(out, "contract_bucket_values = {}", string_list(bucket));
            let _ = writeln!(out, "contract_object_values = {}", string_list(object));
        }
        Some(ContractValue::AclChannelPolicy(AclChannelPolicyValue::BodyXorHeaders)) => {
            out.push_str("contract_value = \"body_xor_headers\"\n");
        }
        Some(ContractValue::AclChannelPolicy(AclChannelPolicyValue::RejectMixedHeaders)) => {
            out.push_str("contract_value = \"reject_mixed_headers\"\n");
        }
        Some(ContractValue::AclErrorSecretFlow(ErrorSecretFlowValue::ConstantReasons)) => {
            out.push_str("contract_value = \"constant_rejection_reasons\"\n");
        }
        Some(ContractValue::AclErrorSecretFlow(ErrorSecretFlowValue::EchoRejectedValue)) => {
            out.push_str("contract_value = \"echo_rejected_value\"\n");
        }
        Some(ContractValue::AclGrantHeaderGrammar {
            keys,
            case_insensitive,
            max_bytes,
            max_entries,
        }) => {
            out.push_str("contract_value = \"quoted_key_value_list\"\n");
            let _ = writeln!(out, "contract_keys = {}", string_list(keys));
            let _ = writeln!(out, "contract_case_insensitive = {case_insensitive}");
            let _ = writeln!(out, "contract_max_bytes = {max_bytes}");
            let _ = writeln!(out, "contract_max_entries = {max_entries}");
        }
        Some(ContractValue::AclPermissionValueSet(values)) => {
            out.push_str("contract_value = \"closed_permissions\"\n");
            let _ = writeln!(out, "contract_values = {}", string_list(values));
        }
        Some(ContractValue::AclOwnerPolicy(AclOwnerPolicyValue::PreserveAsSent)) => {
            out.push_str("contract_value = \"preserve_as_sent\"\n");
        }
        Some(ContractValue::AclOwnerPolicy(AclOwnerPolicyValue::Drop)) => {
            out.push_str("contract_value = \"drop\"\n");
        }
        Some(ContractValue::EncryptionDeleteAbsentPolicy(DeleteAbsentPolicyValue::Succeed)) => {
            out.push_str("contract_value = \"succeed_when_configuration_absent\"\n");
        }
        Some(ContractValue::EncryptionDeleteAbsentPolicy(DeleteAbsentPolicyValue::ConfigurationNotFound)) => {
            out.push_str("contract_value = \"configuration_not_found_when_absent\"\n");
        }
        Some(ContractValue::EncryptionKmsKeyAlgorithms(values)) => {
            out.push_str("contract_value = \"kms_key_algorithms\"\n");
            let _ = writeln!(out, "contract_values = {}", string_list(values));
        }
        Some(ContractValue::EncryptionAlgorithmValueSet(values)) => {
            out.push_str("contract_value = \"closed_encryption_algorithms\"\n");
            let _ = writeln!(out, "contract_values = {}", string_list(values));
        }
        Some(ContractValue::EncryptionRuleLimit(None)) => {
            out.push_str("contract_value = \"unbounded_encryption_rules\"\n");
        }
        Some(ContractValue::EncryptionRuleLimit(Some(1))) => {
            out.push_str("contract_value = \"max_one_encryption_rule\"\n");
        }
        Some(ContractValue::EncryptionRuleLimit(Some(max))) => {
            let _ = writeln!(out, "contract_value = \"max_{max}_encryption_rules\"");
        }
        Some(ContractValue::EncryptionErrorSecretFlow(ErrorSecretFlowValue::ConstantReasons)) => {
            out.push_str("contract_value = \"constant_encryption_reasons\"\n");
        }
        Some(ContractValue::EncryptionErrorSecretFlow(ErrorSecretFlowValue::EchoRejectedValue)) => {
            out.push_str("contract_value = \"echo_encryption_rejected_value\"\n");
        }
        Some(ContractValue::ObjectLockModeValueSet(values)) => {
            out.push_str("contract_value = \"closed_object_lock_modes\"\n");
            let _ = writeln!(out, "contract_values = {}", string_list(values));
        }
        Some(ContractValue::ObjectLockEnabledValueSet(values)) => {
            out.push_str("contract_value = \"closed_object_lock_enabled_values\"\n");
            let _ = writeln!(out, "contract_values = {}", string_list(values));
        }
        Some(ContractValue::ObjectLockDefaultRetention {
            require_mode,
            exactly_one_period,
            min_period,
        }) => {
            out.push_str("contract_value = \"default_retention\"\n");
            let _ = writeln!(out, "contract_require_mode = {require_mode}");
            let _ = writeln!(out, "contract_exactly_one_period = {exactly_one_period}");
            let _ = writeln!(out, "contract_min_period = {min_period}");
        }
        Some(ContractValue::ObjectLockLegalHoldValueSet(values)) => {
            out.push_str("contract_value = \"closed_legal_hold_statuses\"\n");
            let _ = writeln!(out, "contract_values = {}", string_list(values));
        }
        Some(ContractValue::ObjectLockTemporalRelation(TemporalRelationValue::StrictlyFuture)) => {
            out.push_str("contract_value = \"strictly_future\"\n");
        }
        Some(ContractValue::ObjectLockTemporalRelation(TemporalRelationValue::AllowAny)) => {
            out.push_str("contract_value = \"allow_any\"\n");
        }
        Some(ContractValue::ObjectLockBucketStatePrecondition(BucketStatePreconditionValue::RequireEnabled)) => {
            out.push_str("contract_value = \"require_object_lock_enabled\"\n");
        }
        Some(ContractValue::ObjectLockBucketStatePrecondition(BucketStatePreconditionValue::AllowDisabled)) => {
            out.push_str("contract_value = \"allow_disabled_bucket\"\n");
        }
        Some(ContractValue::ConditionalWildcardWrite(ConditionalWildcardWriteValue::CompareAndCreate)) => {
            out.push_str("contract_value = \"compare_and_create\"\n");
        }
        Some(ContractValue::ConditionalWildcardWrite(ConditionalWildcardWriteValue::Ignore)) => {
            out.push_str("contract_value = \"ignore\"\n");
        }
        Some(ContractValue::IfMatchDatePrecedence(IfMatchDatePrecedenceValue::SuppressModifiedSince)) => {
            out.push_str("contract_value = \"suppress_modified_since\"\n");
        }
        Some(ContractValue::IfMatchDatePrecedence(IfMatchDatePrecedenceValue::EvaluateModifiedSince)) => {
            out.push_str("contract_value = \"evaluate_modified_since\"\n");
        }
        Some(ContractValue::IfNoneDatePrecedence(IfNoneDatePrecedenceValue::NotModified)) => {
            out.push_str("contract_value = \"not_modified\"\n");
        }
        Some(ContractValue::IfNoneDatePrecedence(IfNoneDatePrecedenceValue::Proceed)) => {
            out.push_str("contract_value = \"proceed\"\n");
        }
        Some(ContractValue::ConditionConflict(ConditionConflictValue::Reject)) => {
            out.push_str("contract_value = \"reject\"\n");
        }
        Some(ContractValue::ConditionConflict(ConditionConflictValue::PreferIfMatch)) => {
            out.push_str("contract_value = \"prefer_if_match\"\n");
        }
        Some(ContractValue::ConditionalWildcardParse(ConditionalWildcardParseValue::Accept)) => {
            out.push_str("contract_value = \"accept\"\n");
        }
        Some(ContractValue::ConditionalWildcardParse(ConditionalWildcardParseValue::Reject)) => {
            out.push_str("contract_value = \"reject\"\n");
        }
        Some(ContractValue::CopyValidatorScope(CopyValidatorScopeValue::SeparateSourceAndTarget)) => {
            out.push_str("contract_value = \"separate_source_and_target\"\n");
        }
        Some(ContractValue::CopyValidatorScope(CopyValidatorScopeValue::TargetUsesSource)) => {
            out.push_str("contract_value = \"target_uses_source\"\n");
        }
        Some(ContractValue::EtagComparisonStrength(EtagComparisonStrengthValue::Strong)) => {
            out.push_str("contract_value = \"strong\"\n");
        }
        Some(ContractValue::EtagComparisonStrength(EtagComparisonStrengthValue::Weak)) => {
            out.push_str("contract_value = \"weak\"\n");
        }
        Some(ContractValue::IfMatchMissOutcome(IfMatchMissOutcomeValue::PreconditionFailed)) => {
            out.push_str("contract_value = \"precondition_failed\"\n");
        }
        Some(ContractValue::IfMatchMissOutcome(IfMatchMissOutcomeValue::Proceed)) => {
            out.push_str("contract_value = \"proceed\"\n");
        }
        Some(ContractValue::ConditionalWriteOrder(ConditionalWriteOrderValue::GuardBeforeMutation)) => {
            out.push_str("contract_value = \"guard_before_mutation\"\n");
        }
        Some(ContractValue::ConditionalWriteOrder(ConditionalWriteOrderValue::GuardAfterMutation)) => {
            out.push_str("contract_value = \"guard_after_mutation\"\n");
        }
        Some(ContractValue::IfMatchAbsentPolicy(IfMatchAbsentPolicyValue::PreconditionFailed)) => {
            out.push_str("contract_value = \"precondition_failed\"\n");
        }
        Some(ContractValue::IfMatchAbsentPolicy(IfMatchAbsentPolicyValue::Proceed)) => {
            out.push_str("contract_value = \"proceed\"\n");
        }
        Some(ContractValue::ErrorRootNamespace(ErrorRootNamespaceValue::Unnamespaced)) => {
            out.push_str("contract_value = \"unnamespaced\"\n");
        }
        Some(ContractValue::ErrorRootNamespace(ErrorRootNamespaceValue::S3)) => {
            out.push_str("contract_value = \"s3\"\n");
        }
        Some(ContractValue::HeadBodyPolicy(HeadBodyPolicyValue::Suppress)) => {
            out.push_str("contract_value = \"suppress\"\n");
        }
        Some(ContractValue::HeadBodyPolicy(HeadBodyPolicyValue::Preserve)) => {
            out.push_str("contract_value = \"preserve\"\n");
        }
        Some(ContractValue::ConditionFailureDetail(ConditionFailureDetailValue::IncludeCondition)) => {
            out.push_str("contract_value = \"include_condition\"\n");
        }
        Some(ContractValue::ConditionFailureDetail(ConditionFailureDetailValue::OmitCondition)) => {
            out.push_str("contract_value = \"omit_condition\"\n");
        }
        Some(ContractValue::CopySourceIfMatchMiss(CopySourceIfMatchMissValue::PreconditionFailed)) => {
            out.push_str("contract_value = \"precondition_failed\"\n");
        }
        Some(ContractValue::CopySourceIfMatchMiss(CopySourceIfMatchMissValue::Proceed)) => {
            out.push_str("contract_value = \"proceed\"\n");
        }
        Some(ContractValue::CopySourceGuardOrder(CopySourceGuardOrderValue::GuardBeforeTargetWrite)) => {
            out.push_str("contract_value = \"guard_before_target_write\"\n");
        }
        Some(ContractValue::CopySourceGuardOrder(CopySourceGuardOrderValue::TargetWriteBeforeGuard)) => {
            out.push_str("contract_value = \"target_write_before_guard\"\n");
        }
        Some(ContractValue::DefaultSlashPolicy(DefaultSlashPolicyValue::AwsPreserve)) => {
            out.push_str("contract_value = \"aws_preserve\"\n");
        }
        Some(ContractValue::DefaultSlashPolicy(DefaultSlashPolicyValue::Collapse)) => {
            out.push_str("contract_value = \"collapse\"\n");
        }
        Some(ContractValue::PercentDecodePasses(PercentDecodePassesValue::Once)) => {
            out.push_str("contract_value = \"once\"\n");
        }
        Some(ContractValue::PercentDecodePasses(PercentDecodePassesValue::UntilStable)) => {
            out.push_str("contract_value = \"until_stable\"\n");
        }
        Some(ContractValue::DecodedUtf8(DecodedUtf8Value::Strict)) => {
            out.push_str("contract_value = \"strict\"\n");
        }
        Some(ContractValue::DecodedUtf8(DecodedUtf8Value::Lossy)) => {
            out.push_str("contract_value = \"lossy\"\n");
        }
        Some(ContractValue::ResidualEncodedDangerous(ResidualEncodedDangerousValue::Reject)) => {
            out.push_str("contract_value = \"reject\"\n");
        }
        Some(ContractValue::ResidualEncodedDangerous(ResidualEncodedDangerousValue::Allow)) => {
            out.push_str("contract_value = \"allow\"\n");
        }
        Some(ContractValue::TraversalSegmentDelimiters(TraversalSegmentDelimitersValue::SlashAndBackslash)) => {
            out.push_str("contract_value = \"slash_and_backslash\"\n");
        }
        Some(ContractValue::TraversalSegmentDelimiters(TraversalSegmentDelimitersValue::SlashOnly)) => {
            out.push_str("contract_value = \"slash_only\"\n");
        }
        Some(ContractValue::AbsoluteOrUncPolicy(AbsoluteOrUncPolicyValue::Reject)) => {
            out.push_str("contract_value = \"reject\"\n");
        }
        Some(ContractValue::AbsoluteOrUncPolicy(AbsoluteOrUncPolicyValue::Allow)) => {
            out.push_str("contract_value = \"allow\"\n");
        }
        Some(ContractValue::MaxUtf8Bytes(bytes)) => {
            let _ = writeln!(out, "contract_value = {}", quote(&bytes.to_string()));
        }
        Some(ContractValue::DefaultBucketValidator(DefaultBucketValidatorValue::Aws)) => {
            out.push_str("contract_value = \"aws\"\n");
        }
        Some(ContractValue::DefaultBucketValidator(DefaultBucketValidatorValue::Permissive)) => {
            out.push_str("contract_value = \"permissive\"\n");
        }
        Some(ContractValue::ValidatorReplaceability(ValidatorReplaceabilityValue::CustomMayWidenAwsLayer)) => {
            out.push_str("contract_value = \"custom_may_widen_aws_layer\"\n");
        }
        Some(ContractValue::ValidatorReplaceability(ValidatorReplaceabilityValue::IgnoreCustom)) => {
            out.push_str("contract_value = \"ignore_custom\"\n");
        }
        Some(ContractValue::ValidatorAuthority(ValidatorAuthorityValue::NarrowOnlyAfterFloor)) => {
            out.push_str("contract_value = \"narrow_only_after_floor\"\n");
        }
        Some(ContractValue::ValidatorAuthority(ValidatorAuthorityValue::CustomMayBypassFloor)) => {
            out.push_str("contract_value = \"custom_may_bypass_floor\"\n");
        }
        Some(ContractValue::ClientIngressForbiddenCodepoints(ClientIngressForbiddenCodepointsValue::NulC0AndDel)) => {
            out.push_str("contract_value = \"nul_c0_del\"\n");
        }
        Some(ContractValue::ClientIngressForbiddenCodepoints(ClientIngressForbiddenCodepointsValue::NulOnly)) => {
            out.push_str("contract_value = \"nul_only\"\n");
        }
        Some(ContractValue::StoredLegacyControlPolicy(StoredLegacyControlPolicyValue::AllowNonNulAndEscapeOnXmlList)) => {
            out.push_str("contract_value = \"allow_non_nul_and_escape_on_xml_list\"\n");
        }
        Some(ContractValue::StoredLegacyControlPolicy(StoredLegacyControlPolicyValue::RejectAllControls)) => {
            out.push_str("contract_value = \"reject_all_controls\"\n");
        }
        Some(ContractValue::UnicodeNormalization(UnicodeNormalizationValue::None)) => {
            out.push_str("contract_value = \"none\"\n");
        }
        Some(ContractValue::UnicodeNormalization(UnicodeNormalizationValue::Nfc)) => {
            out.push_str("contract_value = \"nfc\"\n");
        }
        Some(ContractValue::CaseFolding(CaseFoldingValue::None)) => {
            out.push_str("contract_value = \"none\"\n");
        }
        Some(ContractValue::CaseFolding(CaseFoldingValue::Lowercase)) => {
            out.push_str("contract_value = \"lowercase\"\n");
        }
        Some(ContractValue::SelectRestore(value)) => {
            let _ = writeln!(out, "contract_value = {}", quote(value.as_str()));
        }
        Some(ContractValue::Cors(value)) => {
            let _ = writeln!(out, "contract_value = {}", quote(value.as_str()));
        }
        Some(ContractValue::NotModifiedEtagPolicy(rustfs_gateway_model::NotModifiedEtagPolicyValue::IncludeSelected)) => {
            out.push_str("contract_value = \"include_selected\"\n")
        }
        Some(ContractValue::NotModifiedEtagPolicy(rustfs_gateway_model::NotModifiedEtagPolicyValue::Omit)) => {
            out.push_str("contract_value = \"omit\"\n")
        }
        Some(ContractValue::CompletionFailureUploadPolicy(rustfs_gateway_model::CompletionFailureUploadPolicyValue::Retain)) => {
            out.push_str("contract_value = \"retain\"\n")
        }
        Some(ContractValue::CompletionFailureUploadPolicy(rustfs_gateway_model::CompletionFailureUploadPolicyValue::Consume)) => {
            out.push_str("contract_value = \"consume\"\n")
        }
        Some(ContractValue::ConditionalRaceOutcome(rustfs_gateway_model::ConditionalRaceOutcomeValue::Conflict)) => {
            out.push_str("contract_value = \"conflict\"\n")
        }
        Some(ContractValue::ConditionalRaceOutcome(rustfs_gateway_model::ConditionalRaceOutcomeValue::PreconditionFailed)) => {
            out.push_str("contract_value = \"precondition_failed\"\n")
        }
        Some(ContractValue::MultiRangePolicy(rustfs_gateway_model::MultiRangePolicyValue::ServeWhole)) => {
            out.push_str("contract_value = \"serve_whole\"\n")
        }
        Some(ContractValue::MultiRangePolicy(rustfs_gateway_model::MultiRangePolicyValue::Reject)) => {
            out.push_str("contract_value = \"reject\"\n")
        }
        Some(ContractValue::ExplicitEndOverflowPolicy(rustfs_gateway_model::ExplicitEndOverflowPolicyValue::Clamp)) => {
            out.push_str("contract_value = \"clamp\"\n")
        }
        Some(ContractValue::ExplicitEndOverflowPolicy(rustfs_gateway_model::ExplicitEndOverflowPolicyValue::Unsatisfiable)) => {
            out.push_str("contract_value = \"unsatisfiable\"\n")
        }
        Some(ContractValue::SuffixRangePolicy(rustfs_gateway_model::SuffixRangePolicyValue::Supported)) => {
            out.push_str("contract_value = \"supported\"\n")
        }
        Some(ContractValue::SuffixRangePolicy(rustfs_gateway_model::SuffixRangePolicyValue::Ignore)) => {
            out.push_str("contract_value = \"ignore\"\n")
        }
        Some(ContractValue::OversizeSuffixPolicy(rustfs_gateway_model::OversizeSuffixPolicyValue::ClampToWholePartial)) => {
            out.push_str("contract_value = \"clamp_to_whole_partial\"\n")
        }
        Some(ContractValue::OversizeSuffixPolicy(rustfs_gateway_model::OversizeSuffixPolicyValue::Unsatisfiable)) => {
            out.push_str("contract_value = \"unsatisfiable\"\n")
        }
        Some(ContractValue::UnsatisfiableActualSizeDetail(rustfs_gateway_model::UnsatisfiableActualSizeDetailValue::Include)) => {
            out.push_str("contract_value = \"include\"\n")
        }
        Some(ContractValue::UnsatisfiableActualSizeDetail(rustfs_gateway_model::UnsatisfiableActualSizeDetailValue::Omit)) => {
            out.push_str("contract_value = \"omit\"\n")
        }
        Some(ContractValue::PartialChecksumPolicy(rustfs_gateway_model::PartialChecksumPolicyValue::SuppressWholeObject)) => {
            out.push_str("contract_value = \"suppress_whole_object\"\n")
        }
        Some(ContractValue::PartialChecksumPolicy(rustfs_gateway_model::PartialChecksumPolicyValue::IncludeWholeObject)) => {
            out.push_str("contract_value = \"include_whole_object\"\n")
        }
        Some(ContractValue::PartNumberOutcome(rustfs_gateway_model::PartNumberOutcomeValue::PartialContent)) => {
            out.push_str("contract_value = \"partial_content\"\n")
        }
        Some(ContractValue::PartNumberOutcome(rustfs_gateway_model::PartNumberOutcomeValue::ServeWhole)) => {
            out.push_str("contract_value = \"serve_whole\"\n")
        }
        Some(ContractValue::InvalidRangePolicy(rustfs_gateway_model::InvalidRangePolicyValue::ServeWhole)) => {
            out.push_str("contract_value = \"serve_whole\"\n")
        }
        Some(ContractValue::InvalidRangePolicy(rustfs_gateway_model::InvalidRangePolicyValue::Reject)) => {
            out.push_str("contract_value = \"reject\"\n")
        }
        Some(ContractValue::IfRangeMissPolicy(rustfs_gateway_model::IfRangeMissPolicyValue::ServeWhole)) => {
            out.push_str("contract_value = \"serve_whole\"\n")
        }
        Some(ContractValue::IfRangeMissPolicy(rustfs_gateway_model::IfRangeMissPolicyValue::ServePartial)) => {
            out.push_str("contract_value = \"serve_partial\"\n")
        }
        Some(ContractValue::IfNoneMatchComparisonStrength(rustfs_gateway_model::IfNoneMatchComparisonStrengthValue::Weak)) => {
            out.push_str("contract_value = \"weak\"\n")
        }
        Some(ContractValue::IfNoneMatchComparisonStrength(rustfs_gateway_model::IfNoneMatchComparisonStrengthValue::Strong)) => {
            out.push_str("contract_value = \"strong\"\n")
        }
        Some(ContractValue::BareConditionalEtagPolicy(
            rustfs_gateway_model::BareConditionalEtagPolicyValue::AcceptAndNormalize,
        )) => out.push_str("contract_value = \"accept_and_normalize\"\n"),
        Some(ContractValue::BareConditionalEtagPolicy(rustfs_gateway_model::BareConditionalEtagPolicyValue::Reject)) => {
            out.push_str("contract_value = \"reject\"\n")
        }
        Some(ContractValue::NotModifiedBodyPolicy(rustfs_gateway_model::NotModifiedBodyPolicyValue::Suppress)) => {
            out.push_str("contract_value = \"suppress\"\n")
        }
        Some(ContractValue::NotModifiedBodyPolicy(rustfs_gateway_model::NotModifiedBodyPolicyValue::Preserve)) => {
            out.push_str("contract_value = \"preserve\"\n")
        }
        Some(ContractValue::NotModifiedFramingPolicy(rustfs_gateway_model::NotModifiedFramingPolicyValue::Omit)) => {
            out.push_str("contract_value = \"omit\"\n")
        }
        Some(ContractValue::NotModifiedFramingPolicy(rustfs_gateway_model::NotModifiedFramingPolicyValue::Preserve)) => {
            out.push_str("contract_value = \"preserve\"\n")
        }
        Some(ContractValue::RangeStartBound(rustfs_gateway_model::RangeStartBoundValue::AtOrBeyondUnsatisfiable)) => {
            out.push_str("contract_value = \"at_or_beyond_unsatisfiable\"\n")
        }
        Some(ContractValue::RangeStartBound(rustfs_gateway_model::RangeStartBoundValue::PastEndOnly)) => {
            out.push_str("contract_value = \"past_end_only\"\n")
        }
        Some(ContractValue::OpenEndedRangePolicy(rustfs_gateway_model::OpenEndedRangePolicyValue::ThroughLast)) => {
            out.push_str("contract_value = \"through_last\"\n")
        }
        Some(ContractValue::OpenEndedRangePolicy(rustfs_gateway_model::OpenEndedRangePolicyValue::EmptyAtLast)) => {
            out.push_str("contract_value = \"empty_at_last\"\n")
        }
        Some(ContractValue::ReadRangeLengthArithmetic(rustfs_gateway_model::ReadRangeLengthArithmeticValue::Inclusive)) => {
            out.push_str("contract_value = \"inclusive\"\n")
        }
        Some(ContractValue::ReadRangeLengthArithmetic(rustfs_gateway_model::ReadRangeLengthArithmeticValue::Exclusive)) => {
            out.push_str("contract_value = \"exclusive\"\n")
        }
        Some(ContractValue::CopyRangeLengthArithmetic(rustfs_gateway_model::CopyRangeLengthArithmeticValue::Inclusive)) => {
            out.push_str("contract_value = \"inclusive\"\n")
        }
        Some(ContractValue::CopyRangeLengthArithmetic(rustfs_gateway_model::CopyRangeLengthArithmeticValue::Exclusive)) => {
            out.push_str("contract_value = \"exclusive\"\n")
        }
        Some(ContractValue::RangeRequestedDetail(rustfs_gateway_model::RangeRequestedDetailValue::Verbatim)) => {
            out.push_str("contract_value = \"verbatim\"\n")
        }
        Some(ContractValue::RangeRequestedDetail(rustfs_gateway_model::RangeRequestedDetailValue::Normalized)) => {
            out.push_str("contract_value = \"normalized\"\n")
        }
        Some(ContractValue::PartCountHeaderPolicy(rustfs_gateway_model::PartCountHeaderPolicyValue::IncludeTotal)) => {
            out.push_str("contract_value = \"include_total\"\n")
        }
        Some(ContractValue::PartCountHeaderPolicy(rustfs_gateway_model::PartCountHeaderPolicyValue::Omit)) => {
            out.push_str("contract_value = \"omit\"\n")
        }
        Some(ContractValue::RangePartSelectorConflict(rustfs_gateway_model::RangePartSelectorConflictValue::Reject)) => {
            out.push_str("contract_value = \"reject\"\n")
        }
        Some(ContractValue::RangePartSelectorConflict(rustfs_gateway_model::RangePartSelectorConflictValue::PreferPart)) => {
            out.push_str("contract_value = \"prefer_part\"\n")
        }
        None => {}
    }
    let dimension = codec_rule
        .map(|rule| rule.mutation_dimension)
        .or_else(|| source_rule.map(|rule| rule.mutation_dimension))
        .or_else(|| contract_rule.map(|rule| rule.mutation_dimension));
    if let Some(dimension) = dimension {
        let _ = writeln!(out, "mutation_dimension = {}", quote(dimension.as_str()));
    }
    let _ = writeln!(out, "target = {}", quote(&quirk.target));
    let _ = writeln!(out, "summary = {}", quote(&quirk.summary));
    let _ = writeln!(out, "cases = {}", string_list(&quirk.cases));
    for source in sources {
        out.push_str("\n[[source]]\n");
        let _ = writeln!(out, "path = {}", quote(&source.path));
        match &source.current {
            SourceValue::Text(value) => {
                let _ = writeln!(out, "current = {}", quote(value));
            }
            SourceValue::TextList(values) => {
                let _ = writeln!(out, "current = {}", string_list(values));
            }
            SourceValue::Bool(value) => {
                let _ = writeln!(out, "current = {value}");
            }
            SourceValue::OptionalText(Some(value)) => {
                let _ = writeln!(out, "current = {}", quote(value));
            }
            SourceValue::OptionalText(None) => out.push_str("current_absent = true\n"),
            SourceValue::Int(value) => {
                let _ = writeln!(out, "current = {value}");
            }
        }
    }
    for evidence in &quirk.evidence {
        out.push_str("\n[[evidence]]\n");
        let _ = writeln!(out, "kind = {}", quote(&evidence.kind));
        let _ = writeln!(out, "ref = {}", quote(&evidence.reference));
        let _ = writeln!(out, "summary = {}", quote(&evidence.summary));
    }
    out
}
