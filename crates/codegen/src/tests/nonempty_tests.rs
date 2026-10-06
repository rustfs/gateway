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

//! Required text binding and mutation controls for request XML.
//!
//! Responsible for: proving the typed rule reaches only its declared fields and mutates both ways.
//! NOT responsible for: executing HTTP or parsing persisted XML. Upstream: lowered model artifacts.
//! Downstream: the codegen test gate.

use rustfs_gateway_model::ir::Type;
use rustfs_gateway_model::{CodecRule, CodecValue, MutationDimension};

use super::codegen_tests::artifacts;
use crate::emit::codec::operation_for_test;
use crate::mutate::{apply_codec, plan_codec};

const RULE: &str = "q-xml-status-0001";

#[test]
fn required_text_rule_mutates_the_real_request_readers() {
    let artifacts = artifacts();
    let mut rules = artifacts.codec_rules.clone();
    let mutation = plan_codec(RULE, &rules[RULE]).expect("typed rule is mutable");
    apply_codec(&mut rules, &mutation).expect("the mutation writes");
    for (name, count) in [("PutBucketLifecycleConfiguration", 1), ("PutBucketReplication", 7)] {
        let op = artifacts
            .operations
            .iter()
            .find(|op| op.operation == name)
            .expect("operation");
        let current = operation_for_test(op, &artifacts.codec_rules, &artifacts.error_codes).expect("current renders");
        let mutant = operation_for_test(op, &rules, &artifacts.error_codes).expect("mutant renders");
        assert_eq!(current.matches("a required text member is empty").count(), count, "{name}");
        assert!(!mutant.contains("a required text member is empty"), "{name}");
    }
    let reverse = plan_codec(RULE, &rules[RULE]).expect("reverse mutation");
    apply_codec(&mut rules, &reverse).expect("restore through the same writer");
    assert_eq!(rules, artifacts.codec_rules);
}

#[test]
fn n_nonempty_rule_on_optional_member_is_refused() {
    let mut artifacts = artifacts();
    let op = artifacts
        .operations
        .iter_mut()
        .find(|op| op.operation == "PutBucketLifecycleConfiguration")
        .expect("operation");
    op.shapes
        .get_mut("LifecycleRule")
        .expect("shape")
        .fields
        .iter_mut()
        .find(|f| f.name == "Status")
        .expect("field")
        .required = false;
    let error = operation_for_test(op, &artifacts.codec_rules, &artifacts.error_codes).expect_err("optional binding must fail");
    assert!(error.contains("requires a required text member"), "{error}");
}

#[test]
fn n_nonempty_rule_on_integer_member_is_refused() {
    let mut artifacts = artifacts();
    let op = artifacts
        .operations
        .iter_mut()
        .find(|op| op.operation == "PutBucketLifecycleConfiguration")
        .expect("operation");
    op.shapes
        .get_mut("LifecycleRule")
        .expect("shape")
        .fields
        .iter_mut()
        .find(|f| f.name == "Status")
        .expect("field")
        .ty = Type::Integer;
    let error = operation_for_test(op, &artifacts.codec_rules, &artifacts.error_codes).expect_err("integer binding must fail");
    assert!(error.contains("requires a required text member"), "{error}");
}

#[test]
fn n_conflicting_nonempty_rules_are_refused() {
    let mut artifacts = artifacts();
    artifacts.codec_rules.insert(
        "opposite".to_owned(),
        CodecRule {
            current: CodecValue::NonEmptyText(false),
            mutation_dimension: MutationDimension::MemberConstraint,
        },
    );
    let op = artifacts
        .operations
        .iter_mut()
        .find(|op| op.operation == "PutBucketLifecycleConfiguration")
        .expect("operation");
    op.shapes
        .get_mut("LifecycleRule")
        .expect("shape")
        .fields
        .iter_mut()
        .find(|f| f.name == "Status")
        .expect("field")
        .quirk_refs
        .push("opposite".to_owned());
    let error =
        operation_for_test(op, &artifacts.codec_rules, &artifacts.error_codes).expect_err("conflicting bindings must fail");
    assert!(error.contains("nonempty text rules disagree"), "{error}");
}

#[test]
fn n_nonempty_rule_with_wrong_mutation_dimension_is_refused() {
    let rule = CodecRule {
        current: CodecValue::NonEmptyText(true),
        mutation_dimension: MutationDimension::IntegerRange,
    };
    assert!(plan_codec(RULE, &rule).is_err());
}

#[test]
fn n_stale_nonempty_mutation_is_refused() {
    let mut rules = artifacts().codec_rules;
    let mutation = plan_codec(RULE, &rules[RULE]).expect("mutation");
    apply_codec(&mut rules, &mutation).expect("first write");
    assert!(apply_codec(&mut rules, &mutation).is_err());
}
