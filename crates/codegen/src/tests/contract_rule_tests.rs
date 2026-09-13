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

//! Tests for requiredness and runtime contract rules the generator emits as mutable data.
//!
//! Responsible for: object-lock and required-body requiredness quirks, and the ACL runtime
//! contracts each changing the generated consumer input when mutated.
//! NOT responsible for: the parsers, which are tested in `rustfs-gateway-model`.
//! Upstream: the pinned model through `generate`. Downstream: the repository verification gate.
use super::codegen_tests::artifacts;

#[test]
fn object_lock_payload_requiredness_reads_all_three_operations() {
    let artifacts = artifacts();
    let (_, quirk) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-lock-0007.toml"))
        .expect("the required payload rule is generated as mutable data");

    assert_eq!(quirk.matches("current = true").count(), 3);
}

#[test]
fn acl_type_requiredness_is_separate_from_runtime_discrimination() {
    use rustfs_gateway_model::{ContractValue, MutationDimension};

    let artifacts = artifacts();
    let (_, requiredness) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-acl-0004.toml"))
        .expect("the ACL requiredness rule is mutable");
    assert_eq!(requiredness.matches("current = false").count(), 2);
    let (_, contract) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/contracts/q-acl-0014.toml"))
        .expect("the runtime discriminator has a generated contract record");
    assert!(contract.contains("contract_value = \"derive_from_identifying_member\""));
    assert_eq!(
        artifacts
            .contract_rules
            .values()
            .filter(|rule| { rule.mutation_dimension == MutationDimension::GranteeDiscriminatorPolicy })
            .count(),
        1
    );

    let current =
        crate::emit::runtime_contracts::render(&artifacts.contract_rules).expect("the current runtime contract renders");
    assert!(current.contains("GranteeDiscriminatorPolicy::IdentifyingMember"));

    let mut mutated = artifacts.contract_rules;
    mutated
        .values_mut()
        .find(|rule| rule.mutation_dimension == MutationDimension::GranteeDiscriminatorPolicy)
        .expect("the typed ACL contract exists")
        .current = ContractValue::GranteeTypeLeaveUnset;
    let mutant = crate::emit::runtime_contracts::render(&mutated).expect("the mutated runtime contract renders");
    assert!(mutant.contains("GranteeDiscriminatorPolicy::LeaveUnset"));
}

#[test]
fn acl_runtime_contracts_each_change_the_generated_consumer_input() {
    use rustfs_gateway_model::{
        AclChannelPolicyValue, AclOwnerPolicyValue, ContractValue, ErrorSecretFlowValue, MutationDimension,
    };

    let rules = artifacts().contract_rules;
    for dimension in [
        MutationDimension::GranteeDiscriminatorPolicy,
        MutationDimension::TargetValueSets,
        MutationDimension::AclChannelMatrix,
        MutationDimension::GrantHeaderGrammar,
        MutationDimension::PermissionValueSet,
        MutationDimension::OwnerPolicy,
    ] {
        assert_eq!(
            rules.values().filter(|rule| rule.mutation_dimension == dimension).count(),
            1,
            "{} must have exactly one typed source",
            dimension.as_str()
        );
    }
    assert_eq!(
        rules
            .values()
            .filter(|rule| matches!(rule.current, ContractValue::AclErrorSecretFlow(_)))
            .count(),
        1,
        "ACL error secret flow must have exactly one typed source"
    );
    let current = crate::emit::runtime_contracts::render(&rules).expect("the current ACL contracts render");

    let mut target_sets = rules.clone();
    let rule = target_sets
        .values_mut()
        .find(|rule| rule.mutation_dimension == MutationDimension::TargetValueSets)
        .expect("the target value-set rule exists");
    let ContractValue::AclTargetValueSets { bucket, .. } = &mut rule.current else {
        panic!("the target value-set dimension carries its typed value");
    };
    bucket.retain(|value| value != "log-delivery-write");
    let mutant = crate::emit::runtime_contracts::render(&target_sets).expect("the target-set mutant renders");
    assert!(current.contains("log-delivery-write"));
    assert!(!mutant.contains("log-delivery-write"));

    let mut channel = rules.clone();
    channel
        .values_mut()
        .find(|rule| rule.mutation_dimension == MutationDimension::AclChannelMatrix)
        .expect("the channel rule exists")
        .current = ContractValue::AclChannelPolicy(AclChannelPolicyValue::RejectMixedHeaders);
    assert!(
        crate::emit::runtime_contracts::render(&channel)
            .expect("the channel mutant renders")
            .contains("AclChannelPolicy::RejectMixedHeaders")
    );

    let mut secret = rules.clone();
    secret
        .values_mut()
        .find(|rule| matches!(rule.current, ContractValue::AclErrorSecretFlow(_)))
        .expect("the error secret-flow rule exists")
        .current = ContractValue::AclErrorSecretFlow(ErrorSecretFlowValue::EchoRejectedValue);
    assert!(
        crate::emit::runtime_contracts::render(&secret)
            .expect("the error secret-flow mutant renders")
            .contains("AclErrorSecretFlowPolicy::EchoRejectedValue")
    );

    let mut grammar = rules.clone();
    let rule = grammar
        .values_mut()
        .find(|rule| rule.mutation_dimension == MutationDimension::GrantHeaderGrammar)
        .expect("the grant grammar rule exists");
    let ContractValue::AclGrantHeaderGrammar { case_insensitive, .. } = &mut rule.current else {
        panic!("the grant grammar dimension carries its typed value");
    };
    *case_insensitive = false;
    assert!(
        crate::emit::runtime_contracts::render(&grammar)
            .expect("the grant grammar mutant renders")
            .contains("ACL_GRANT_KEYS_CASE_INSENSITIVE: bool = false")
    );

    let mut permissions = rules.clone();
    let rule = permissions
        .values_mut()
        .find(|rule| rule.mutation_dimension == MutationDimension::PermissionValueSet)
        .expect("the permission rule exists");
    let ContractValue::AclPermissionValueSet(values) = &mut rule.current else {
        panic!("the permission dimension carries its typed value");
    };
    values.retain(|value| value != "READ_ACP");
    let mutant = crate::emit::runtime_contracts::render(&permissions).expect("the permission mutant renders");
    assert!(current.contains("READ_ACP"));
    assert!(!mutant.contains("READ_ACP"));

    let mut owner = rules;
    owner
        .values_mut()
        .find(|rule| rule.mutation_dimension == MutationDimension::OwnerPolicy)
        .expect("the owner policy exists")
        .current = ContractValue::AclOwnerPolicy(AclOwnerPolicyValue::Drop);
    assert!(
        crate::emit::runtime_contracts::render(&owner)
            .expect("the owner mutant renders")
            .contains("AclOwnerPolicy::Drop")
    );
}

#[test]
fn required_body_rules_read_the_exact_field_that_enforces_them() {
    let artifacts = artifacts();
    for id in ["q-web-0004", "q-restore-0006"] {
        let (_, quirk) = artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("spec/quirks/{id}.toml")))
            .expect("the required-body rule is generated as mutable data");
        assert!(quirk.contains("current = true"), "{id}");
    }
}
