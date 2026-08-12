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

//! Generated inputs for the object and bucket naming pipeline.
//!
//! Responsible for: rendering the typed current value of every naming contract.
//! NOT responsible for: naming behavior or mutation selection. Upstream: typed overlay contract rules. Downstream:
//! `rustfs-gateway-types::scalar::naming`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rustfs_gateway_model::{
    AbsoluteOrUncPolicyValue, CaseFoldingValue, ClientIngressForbiddenCodepointsValue, ContractRule, ContractValue,
    DecodedUtf8Value, DefaultBucketValidatorValue, DefaultSlashPolicyValue, MutationDimension, PercentDecodePassesValue,
    ResidualEncodedDangerousValue, StoredLegacyControlPolicyValue, TraversalSegmentDelimitersValue, UnicodeNormalizationValue,
    ValidatorAuthorityValue, ValidatorReplaceabilityValue,
};

use super::dto::LICENSE;

/// Renders the naming contract module included by the types crate.
pub fn render(rules: &BTreeMap<String, ContractRule>) -> Result<String, String> {
    let mut out = String::from(LICENSE);
    out.push_str("\n// Generated naming protocol-contract inputs.\n\n");

    render_enum(
        &mut out,
        "DEFAULT_SLASH_POLICY",
        "Default slash policy.",
        match unique(rules, MutationDimension::DefaultSlashPolicy)? {
            ContractValue::DefaultSlashPolicy(DefaultSlashPolicyValue::AwsPreserve) => "ContractSlashPolicy::AwsPreserve",
            ContractValue::DefaultSlashPolicy(DefaultSlashPolicyValue::Collapse) => "ContractSlashPolicy::Collapse",
            _ => return Err(wrong_type(MutationDimension::DefaultSlashPolicy)),
        },
        "ContractSlashPolicy",
    );
    render_enum(
        &mut out,
        "PERCENT_DECODE_PASSES",
        "Percent-decoding pass policy.",
        match unique(rules, MutationDimension::PercentDecodePasses)? {
            ContractValue::PercentDecodePasses(PercentDecodePassesValue::Once) => "PercentDecodePassesPolicy::Once",
            ContractValue::PercentDecodePasses(PercentDecodePassesValue::UntilStable) => "PercentDecodePassesPolicy::UntilStable",
            _ => return Err(wrong_type(MutationDimension::PercentDecodePasses)),
        },
        "PercentDecodePassesPolicy",
    );
    render_enum(
        &mut out,
        "DECODED_UTF8_POLICY",
        "Decoded UTF-8 policy.",
        match unique(rules, MutationDimension::DecodedUtf8)? {
            ContractValue::DecodedUtf8(DecodedUtf8Value::Strict) => "DecodedUtf8Policy::Strict",
            ContractValue::DecodedUtf8(DecodedUtf8Value::Lossy) => "DecodedUtf8Policy::Lossy",
            _ => return Err(wrong_type(MutationDimension::DecodedUtf8)),
        },
        "DecodedUtf8Policy",
    );
    render_enum(
        &mut out,
        "RESIDUAL_ENCODED_DANGER_POLICY",
        "Residual encoded-danger policy.",
        match unique(rules, MutationDimension::ResidualEncodedDangerous)? {
            ContractValue::ResidualEncodedDangerous(ResidualEncodedDangerousValue::Reject) => {
                "ResidualEncodedDangerPolicy::Reject"
            }
            ContractValue::ResidualEncodedDangerous(ResidualEncodedDangerousValue::Allow) => "ResidualEncodedDangerPolicy::Allow",
            _ => return Err(wrong_type(MutationDimension::ResidualEncodedDangerous)),
        },
        "ResidualEncodedDangerPolicy",
    );
    render_enum(
        &mut out,
        "TRAVERSAL_DELIMITERS",
        "Traversal segment delimiters.",
        match unique(rules, MutationDimension::TraversalSegmentDelimiters)? {
            ContractValue::TraversalSegmentDelimiters(TraversalSegmentDelimitersValue::SlashAndBackslash) => {
                "TraversalDelimitersPolicy::SlashAndBackslash"
            }
            ContractValue::TraversalSegmentDelimiters(TraversalSegmentDelimitersValue::SlashOnly) => {
                "TraversalDelimitersPolicy::SlashOnly"
            }
            _ => return Err(wrong_type(MutationDimension::TraversalSegmentDelimiters)),
        },
        "TraversalDelimitersPolicy",
    );
    render_enum(
        &mut out,
        "ABSOLUTE_OR_UNC_POLICY",
        "Absolute and UNC key policy.",
        match unique(rules, MutationDimension::AbsoluteOrUncPolicy)? {
            ContractValue::AbsoluteOrUncPolicy(AbsoluteOrUncPolicyValue::Reject) => "AbsoluteOrUncPolicy::Reject",
            ContractValue::AbsoluteOrUncPolicy(AbsoluteOrUncPolicyValue::Allow) => "AbsoluteOrUncPolicy::Allow",
            _ => return Err(wrong_type(MutationDimension::AbsoluteOrUncPolicy)),
        },
        "AbsoluteOrUncPolicy",
    );
    let ContractValue::MaxUtf8Bytes(max) = unique(rules, MutationDimension::MaxUtf8Bytes)? else {
        return Err(wrong_type(MutationDimension::MaxUtf8Bytes));
    };
    writeln!(
        out,
        "/// Maximum object-key length in UTF-8 bytes.\npub(crate) const MAX_KEY_BYTES: usize = {max};"
    )
    .expect("writing to String cannot fail");
    render_enum(
        &mut out,
        "DEFAULT_BUCKET_VALIDATOR",
        "Default bucket validator.",
        match unique(rules, MutationDimension::DefaultBucketValidator)? {
            ContractValue::DefaultBucketValidator(DefaultBucketValidatorValue::Aws) => "DefaultValidatorPolicy::Aws",
            ContractValue::DefaultBucketValidator(DefaultBucketValidatorValue::Permissive) => {
                "DefaultValidatorPolicy::Permissive"
            }
            _ => return Err(wrong_type(MutationDimension::DefaultBucketValidator)),
        },
        "DefaultValidatorPolicy",
    );
    render_enum(
        &mut out,
        "VALIDATOR_REPLACEABILITY",
        "Custom validator replacement policy.",
        match unique(rules, MutationDimension::ValidatorReplaceability)? {
            ContractValue::ValidatorReplaceability(ValidatorReplaceabilityValue::CustomMayWidenAwsLayer) => {
                "ValidatorReplaceabilityPolicy::CustomMayWidenAwsLayer"
            }
            ContractValue::ValidatorReplaceability(ValidatorReplaceabilityValue::IgnoreCustom) => {
                "ValidatorReplaceabilityPolicy::IgnoreCustom"
            }
            _ => return Err(wrong_type(MutationDimension::ValidatorReplaceability)),
        },
        "ValidatorReplaceabilityPolicy",
    );
    render_enum(
        &mut out,
        "VALIDATOR_AUTHORITY",
        "Custom validator authority.",
        match unique(rules, MutationDimension::ValidatorAuthority)? {
            ContractValue::ValidatorAuthority(ValidatorAuthorityValue::NarrowOnlyAfterFloor) => {
                "ValidatorAuthorityPolicy::NarrowOnlyAfterFloor"
            }
            ContractValue::ValidatorAuthority(ValidatorAuthorityValue::CustomMayBypassFloor) => {
                "ValidatorAuthorityPolicy::CustomMayBypassFloor"
            }
            _ => return Err(wrong_type(MutationDimension::ValidatorAuthority)),
        },
        "ValidatorAuthorityPolicy",
    );
    render_enum(
        &mut out,
        "CLIENT_INGRESS_FORBIDDEN_CODEPOINTS",
        "Client-ingress forbidden codepoints.",
        match unique(rules, MutationDimension::ClientIngressForbiddenCodepoints)? {
            ContractValue::ClientIngressForbiddenCodepoints(ClientIngressForbiddenCodepointsValue::NulC0AndDel) => {
                "ClientIngressCodepointPolicy::NulC0AndDel"
            }
            ContractValue::ClientIngressForbiddenCodepoints(ClientIngressForbiddenCodepointsValue::NulOnly) => {
                "ClientIngressCodepointPolicy::NulOnly"
            }
            _ => return Err(wrong_type(MutationDimension::ClientIngressForbiddenCodepoints)),
        },
        "ClientIngressCodepointPolicy",
    );
    render_enum(
        &mut out,
        "STORED_LEGACY_CONTROL_POLICY",
        "Stored legacy-control policy.",
        match unique(rules, MutationDimension::StoredLegacyControlPolicy)? {
            ContractValue::StoredLegacyControlPolicy(StoredLegacyControlPolicyValue::AllowNonNulAndEscapeOnXmlList) => {
                "StoredLegacyControlPolicy::AllowNonNulAndEscapeOnXmlList"
            }
            ContractValue::StoredLegacyControlPolicy(StoredLegacyControlPolicyValue::RejectAllControls) => {
                "StoredLegacyControlPolicy::RejectAllControls"
            }
            _ => return Err(wrong_type(MutationDimension::StoredLegacyControlPolicy)),
        },
        "StoredLegacyControlPolicy",
    );
    render_enum(
        &mut out,
        "UNICODE_NORMALIZATION",
        "Unicode normalization policy.",
        match unique(rules, MutationDimension::UnicodeNormalization)? {
            ContractValue::UnicodeNormalization(UnicodeNormalizationValue::None) => "UnicodeNormalizationPolicy::None",
            ContractValue::UnicodeNormalization(UnicodeNormalizationValue::Nfc) => "UnicodeNormalizationPolicy::Nfc",
            _ => return Err(wrong_type(MutationDimension::UnicodeNormalization)),
        },
        "UnicodeNormalizationPolicy",
    );
    render_enum(
        &mut out,
        "CASE_FOLDING",
        "Object-key case-folding policy.",
        match unique(rules, MutationDimension::CaseFolding)? {
            ContractValue::CaseFolding(CaseFoldingValue::None) => "CaseFoldingPolicy::None",
            ContractValue::CaseFolding(CaseFoldingValue::Lowercase) => "CaseFoldingPolicy::Lowercase",
            _ => return Err(wrong_type(MutationDimension::CaseFolding)),
        },
        "CaseFoldingPolicy",
    );

    Ok(out)
}

fn render_enum(out: &mut String, name: &str, docs: &str, value: &str, ty: &str) {
    writeln!(out, "/// {docs}\nconst {name}: {ty} = {value};").expect("writing to String cannot fail");
}

fn unique(rules: &BTreeMap<String, ContractRule>, dimension: MutationDimension) -> Result<&ContractValue, String> {
    let mut matches = rules.values().filter(|rule| rule.mutation_dimension == dimension);
    let value = matches
        .next()
        .ok_or_else(|| format!("missing `{}` contract rule", dimension.as_str()))?;
    if matches.next().is_some() {
        return Err(format!("multiple `{}` contract rules", dimension.as_str()));
    }
    Ok(&value.current)
}

fn wrong_type(dimension: MutationDimension) -> String {
    format!("`{}` contract carries the wrong typed value", dimension.as_str())
}
