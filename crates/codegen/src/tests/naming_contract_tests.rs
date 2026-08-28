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

//! Mutation checks for typed naming contract inputs.
//!
//! Responsible for: proving every naming mutation changes the generated types-crate input.
//! NOT responsible for: executing the naming conformance cases. Upstream: overlay contract rules.
//! Downstream: the codegen test gate.

use std::collections::BTreeMap;

use rustfs_gateway_model::{
    AbsoluteOrUncPolicyValue, CaseFoldingValue, ClientIngressForbiddenCodepointsValue, ContractRule, ContractValue,
    DecodedUtf8Value, DefaultBucketValidatorValue, DefaultSlashPolicyValue, MutationDimension, PercentDecodePassesValue,
    ResidualEncodedDangerousValue, StoredLegacyControlPolicyValue, TraversalSegmentDelimitersValue, UnicodeNormalizationValue,
    ValidatorAuthorityValue, ValidatorReplaceabilityValue,
};

use super::codegen_tests::artifacts;

#[test]
fn every_naming_contract_changes_the_generated_consumer_input() {
    let rules = artifacts().contract_rules;
    let current = crate::emit::naming_contracts::render(&rules).expect("current naming contracts render");
    for constant in [
        "DEFAULT_SLASH_POLICY",
        "PERCENT_DECODE_PASSES",
        "DECODED_UTF8_POLICY",
        "RESIDUAL_ENCODED_DANGER_POLICY",
        "TRAVERSAL_DELIMITERS",
        "ABSOLUTE_OR_UNC_POLICY",
        "MAX_KEY_BYTES",
        "DEFAULT_BUCKET_VALIDATOR",
        "VALIDATOR_REPLACEABILITY",
        "VALIDATOR_AUTHORITY",
        "CLIENT_INGRESS_FORBIDDEN_CODEPOINTS",
        "STORED_LEGACY_CONTROL_POLICY",
        "UNICODE_NORMALIZATION",
        "CASE_FOLDING",
    ] {
        assert!(current.contains(constant), "missing generated naming input {constant}");
    }

    assert_mutation(
        &rules,
        MutationDimension::DefaultSlashPolicy,
        ContractValue::DefaultSlashPolicy(DefaultSlashPolicyValue::Collapse),
        "ContractSlashPolicy::Collapse",
    );
    assert_mutation(
        &rules,
        MutationDimension::PercentDecodePasses,
        ContractValue::PercentDecodePasses(PercentDecodePassesValue::UntilStable),
        "PercentDecodePassesPolicy::UntilStable",
    );
    assert_mutation(
        &rules,
        MutationDimension::DecodedUtf8,
        ContractValue::DecodedUtf8(DecodedUtf8Value::Lossy),
        "DecodedUtf8Policy::Lossy",
    );
    assert_mutation(
        &rules,
        MutationDimension::ResidualEncodedDangerous,
        ContractValue::ResidualEncodedDangerous(ResidualEncodedDangerousValue::Allow),
        "ResidualEncodedDangerPolicy::Allow",
    );
    assert_mutation(
        &rules,
        MutationDimension::TraversalSegmentDelimiters,
        ContractValue::TraversalSegmentDelimiters(TraversalSegmentDelimitersValue::SlashOnly),
        "TraversalDelimitersPolicy::SlashOnly",
    );
    assert_mutation(
        &rules,
        MutationDimension::AbsoluteOrUncPolicy,
        ContractValue::AbsoluteOrUncPolicy(AbsoluteOrUncPolicyValue::Allow),
        "AbsoluteOrUncPolicy::Allow",
    );
    assert_mutation(
        &rules,
        MutationDimension::MaxUtf8Bytes,
        ContractValue::MaxUtf8Bytes(1023),
        "MAX_KEY_BYTES: usize = 1023",
    );
    assert_mutation(
        &rules,
        MutationDimension::DefaultBucketValidator,
        ContractValue::DefaultBucketValidator(DefaultBucketValidatorValue::Permissive),
        "DefaultValidatorPolicy::Permissive",
    );
    assert_mutation(
        &rules,
        MutationDimension::ValidatorReplaceability,
        ContractValue::ValidatorReplaceability(ValidatorReplaceabilityValue::IgnoreCustom),
        "ValidatorReplaceabilityPolicy::IgnoreCustom",
    );
    assert_mutation(
        &rules,
        MutationDimension::ValidatorAuthority,
        ContractValue::ValidatorAuthority(ValidatorAuthorityValue::CustomMayBypassFloor),
        "ValidatorAuthorityPolicy::CustomMayBypassFloor",
    );
    assert_mutation(
        &rules,
        MutationDimension::ClientIngressForbiddenCodepoints,
        ContractValue::ClientIngressForbiddenCodepoints(ClientIngressForbiddenCodepointsValue::NulOnly),
        "ClientIngressCodepointPolicy::NulOnly",
    );
    assert_mutation(
        &rules,
        MutationDimension::StoredLegacyControlPolicy,
        ContractValue::StoredLegacyControlPolicy(StoredLegacyControlPolicyValue::RejectAllControls),
        "StoredLegacyControlPolicy::RejectAllControls",
    );
    assert_mutation(
        &rules,
        MutationDimension::UnicodeNormalization,
        ContractValue::UnicodeNormalization(UnicodeNormalizationValue::Nfc),
        "UnicodeNormalizationPolicy::Nfc",
    );
    assert_mutation(
        &rules,
        MutationDimension::CaseFolding,
        ContractValue::CaseFolding(CaseFoldingValue::Lowercase),
        "CaseFoldingPolicy::Lowercase",
    );
}

#[test]
fn every_generated_object_key_decoder_uses_the_request_name_policy() {
    let artifacts = artifacts();
    let mut call_sites = 0usize;
    for (path, generated) in &artifacts.files {
        if !path.to_string_lossy().contains("generated/codec/ops/") {
            continue;
        }
        let calls: Vec<&str> = generated.lines().filter(|line| line.contains("value::object_key(")).collect();
        if calls.is_empty() {
            continue;
        }
        assert!(
            generated.contains("request.names()"),
            "{} decodes an object key without receiving the request policy",
            path.display()
        );
        for call in calls {
            call_sites = call_sites.saturating_add(1);
            assert!(
                call.contains(", names)") || call.contains(", request.names())"),
                "{} has an object-key bypass: {call}",
                path.display()
            );
        }
        assert!(
            !generated.contains("NamePolicy::default()"),
            "{} replaces the deployment policy with the default",
            path.display()
        );
    }
    assert!(call_sites > 0, "the check found no generated object-key decoder to inspect");
}

fn assert_mutation(rules: &BTreeMap<String, ContractRule>, dimension: MutationDimension, value: ContractValue, expected: &str) {
    let mut mutant = rules.clone();
    mutant
        .values_mut()
        .find(|rule| rule.mutation_dimension == dimension)
        .expect("the naming dimension exists")
        .current = value;
    let rendered = crate::emit::naming_contracts::render(&mutant).expect("the naming mutant renders");
    assert!(rendered.contains(expected));
}
