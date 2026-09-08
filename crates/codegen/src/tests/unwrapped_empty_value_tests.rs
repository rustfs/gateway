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

//! Generated runtime-code controls for empty unwrapped response members.
//!
//! Responsible for: proving an unwrapped output's authored empty-value policy changes the code
//! that decides whether its document root is written.
//! NOT responsible for: executing the generated codec or measuring the bytes served by a target;
//! the location conformance cases own that wire observation.
//! Upstream: the lowered `GetBucketLocation` IR. Downstream: the response codec emitter.

use rustfs_gateway_model::ir::{EmptyValue, OperationIr};

use super::codegen_tests::artifacts;

const OPEN_ROOT: &str = "        writer.open(\"LocationConstraint\", Some(rustfs_gateway_xml::S3_XMLNS));\n";
const OPTIONAL_VALUE: &str = "        if let Some(v) = output.location_constraint.as_ref() {\n";

fn location_ir() -> OperationIr {
    artifacts()
        .operations
        .into_iter()
        .find(|operation| operation.operation == "GetBucketLocation")
        .expect("GetBucketLocation is in the pinned model")
}

fn render_with(policy: EmptyValue) -> String {
    let mut operation = location_ir();
    operation
        .xml
        .empty_value_policy
        .iter_mut()
        .find(|(member, _)| member == "LocationConstraint")
        .expect("LocationConstraint has an authored empty-value policy")
        .1 = policy;
    crate::emit::codec::encode::body(&operation, &Default::default()).expect("the location response codec renders")
}

fn root_and_value_positions(rendered: &str) -> (usize, usize) {
    let root = rendered.find(OPEN_ROOT).expect("the generated codec opens the location root");
    let value = rendered
        .find(OPTIONAL_VALUE)
        .expect("the generated codec tests the optional location value");
    (root, value)
}

#[test]
fn unwrapped_emit_policy_opens_the_root_before_testing_the_optional_value() {
    let rendered = render_with(EmptyValue::Emit);
    let (root, value) = root_and_value_positions(&rendered);

    assert!(
        root < value,
        "emit must write the root even when the optional value is absent: {rendered}"
    );
}

#[test]
fn n_unwrapped_omit_policy_does_not_open_the_root_before_testing_the_optional_value() {
    let rendered = render_with(EmptyValue::Omit);
    let (root, value) = root_and_value_positions(&rendered);

    assert!(
        root > value,
        "omit must not write the root until the optional value is present: {rendered}"
    );
}

#[test]
fn n_unwrapped_empty_policies_generate_different_runtime_code() {
    assert_ne!(
        render_with(EmptyValue::Emit),
        render_with(EmptyValue::Omit),
        "q-empty-0002 must mutate the generated codec, not only the source ledger"
    );
}
