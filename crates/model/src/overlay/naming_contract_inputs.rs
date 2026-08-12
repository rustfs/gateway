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

//! Strict parser for naming runtime-contract inputs.
//!
//! Responsible for: pairing each naming value with its mechanical mutation dimension.
//! NOT responsible for: consuming naming rules or parsing non-naming contracts. Upstream: quirk
//! overlay TOML. Downstream: [`super::codec::contract_rule`].

use crate::error::{Error, Result};

use super::MutationDimension;
use super::contract_values::{
    AbsoluteOrUncPolicyValue, CaseFoldingValue, ClientIngressForbiddenCodepointsValue, ContractRule, ContractValue,
    DecodedUtf8Value, DefaultBucketValidatorValue, DefaultSlashPolicyValue, PercentDecodePassesValue,
    ResidualEncodedDangerousValue, StoredLegacyControlPolicyValue, TraversalSegmentDelimitersValue, UnicodeNormalizationValue,
    ValidatorAuthorityValue, ValidatorReplaceabilityValue,
};

pub(super) fn parse(dimension: &str, value: &str, id: &str) -> Result<Option<ContractRule>> {
    let parsed = match (dimension, value) {
        ("default_slash_policy", "aws_preserve") => (
            ContractValue::DefaultSlashPolicy(DefaultSlashPolicyValue::AwsPreserve),
            MutationDimension::DefaultSlashPolicy,
        ),
        ("default_slash_policy", "collapse") => (
            ContractValue::DefaultSlashPolicy(DefaultSlashPolicyValue::Collapse),
            MutationDimension::DefaultSlashPolicy,
        ),
        ("percent_decode_passes", "once") => (
            ContractValue::PercentDecodePasses(PercentDecodePassesValue::Once),
            MutationDimension::PercentDecodePasses,
        ),
        ("percent_decode_passes", "until_stable") => (
            ContractValue::PercentDecodePasses(PercentDecodePassesValue::UntilStable),
            MutationDimension::PercentDecodePasses,
        ),
        ("decoded_utf8", "strict") => (ContractValue::DecodedUtf8(DecodedUtf8Value::Strict), MutationDimension::DecodedUtf8),
        ("decoded_utf8", "lossy") => (ContractValue::DecodedUtf8(DecodedUtf8Value::Lossy), MutationDimension::DecodedUtf8),
        ("residual_encoded_dangerous", "reject") => (
            ContractValue::ResidualEncodedDangerous(ResidualEncodedDangerousValue::Reject),
            MutationDimension::ResidualEncodedDangerous,
        ),
        ("residual_encoded_dangerous", "allow") => (
            ContractValue::ResidualEncodedDangerous(ResidualEncodedDangerousValue::Allow),
            MutationDimension::ResidualEncodedDangerous,
        ),
        ("traversal_segment_delimiters", "slash_and_backslash") => (
            ContractValue::TraversalSegmentDelimiters(TraversalSegmentDelimitersValue::SlashAndBackslash),
            MutationDimension::TraversalSegmentDelimiters,
        ),
        ("traversal_segment_delimiters", "slash_only") => (
            ContractValue::TraversalSegmentDelimiters(TraversalSegmentDelimitersValue::SlashOnly),
            MutationDimension::TraversalSegmentDelimiters,
        ),
        ("absolute_or_unc_policy", "reject") => (
            ContractValue::AbsoluteOrUncPolicy(AbsoluteOrUncPolicyValue::Reject),
            MutationDimension::AbsoluteOrUncPolicy,
        ),
        ("absolute_or_unc_policy", "allow") => (
            ContractValue::AbsoluteOrUncPolicy(AbsoluteOrUncPolicyValue::Allow),
            MutationDimension::AbsoluteOrUncPolicy,
        ),
        ("max_utf8_bytes", bytes) => {
            let bytes = bytes.parse::<u32>().map_err(|_| {
                Error::Overlay(format!("quirk `{id}`: max_utf8_bytes contract value must be an unsigned integer"))
            })?;
            (ContractValue::MaxUtf8Bytes(bytes), MutationDimension::MaxUtf8Bytes)
        }
        ("default_bucket_validator", "aws") => (
            ContractValue::DefaultBucketValidator(DefaultBucketValidatorValue::Aws),
            MutationDimension::DefaultBucketValidator,
        ),
        ("default_bucket_validator", "permissive") => (
            ContractValue::DefaultBucketValidator(DefaultBucketValidatorValue::Permissive),
            MutationDimension::DefaultBucketValidator,
        ),
        ("validator_replaceability", "custom_may_widen_aws_layer") => (
            ContractValue::ValidatorReplaceability(ValidatorReplaceabilityValue::CustomMayWidenAwsLayer),
            MutationDimension::ValidatorReplaceability,
        ),
        ("validator_replaceability", "ignore_custom") => (
            ContractValue::ValidatorReplaceability(ValidatorReplaceabilityValue::IgnoreCustom),
            MutationDimension::ValidatorReplaceability,
        ),
        ("validator_authority", "narrow_only_after_floor") => (
            ContractValue::ValidatorAuthority(ValidatorAuthorityValue::NarrowOnlyAfterFloor),
            MutationDimension::ValidatorAuthority,
        ),
        ("validator_authority", "custom_may_bypass_floor") => (
            ContractValue::ValidatorAuthority(ValidatorAuthorityValue::CustomMayBypassFloor),
            MutationDimension::ValidatorAuthority,
        ),
        ("client_ingress_forbidden_codepoints", "nul_c0_del") => (
            ContractValue::ClientIngressForbiddenCodepoints(ClientIngressForbiddenCodepointsValue::NulC0AndDel),
            MutationDimension::ClientIngressForbiddenCodepoints,
        ),
        ("client_ingress_forbidden_codepoints", "nul_only") => (
            ContractValue::ClientIngressForbiddenCodepoints(ClientIngressForbiddenCodepointsValue::NulOnly),
            MutationDimension::ClientIngressForbiddenCodepoints,
        ),
        ("stored_legacy_control_policy", "allow_non_nul_and_escape_on_xml_list") => (
            ContractValue::StoredLegacyControlPolicy(StoredLegacyControlPolicyValue::AllowNonNulAndEscapeOnXmlList),
            MutationDimension::StoredLegacyControlPolicy,
        ),
        ("stored_legacy_control_policy", "reject_all_controls") => (
            ContractValue::StoredLegacyControlPolicy(StoredLegacyControlPolicyValue::RejectAllControls),
            MutationDimension::StoredLegacyControlPolicy,
        ),
        ("unicode_normalization", "none") => (
            ContractValue::UnicodeNormalization(UnicodeNormalizationValue::None),
            MutationDimension::UnicodeNormalization,
        ),
        ("unicode_normalization", "nfc") => (
            ContractValue::UnicodeNormalization(UnicodeNormalizationValue::Nfc),
            MutationDimension::UnicodeNormalization,
        ),
        ("case_folding", "none") => (ContractValue::CaseFolding(CaseFoldingValue::None), MutationDimension::CaseFolding),
        ("case_folding", "lowercase") => {
            (ContractValue::CaseFolding(CaseFoldingValue::Lowercase), MutationDimension::CaseFolding)
        }
        (dimension, _) if is_naming_dimension(dimension) => {
            return Err(Error::Overlay(format!("quirk `{id}`: unknown naming contract `{dimension}={value}`")));
        }
        _ => return Ok(None),
    };
    Ok(Some(ContractRule {
        current: parsed.0,
        mutation_dimension: parsed.1,
    }))
}

fn is_naming_dimension(dimension: &str) -> bool {
    matches!(
        dimension,
        "default_slash_policy"
            | "percent_decode_passes"
            | "decoded_utf8"
            | "residual_encoded_dangerous"
            | "traversal_segment_delimiters"
            | "absolute_or_unc_policy"
            | "max_utf8_bytes"
            | "default_bucket_validator"
            | "validator_replaceability"
            | "validator_authority"
            | "client_ingress_forbidden_codepoints"
            | "stored_legacy_control_policy"
            | "unicode_normalization"
            | "case_folding"
    )
}
