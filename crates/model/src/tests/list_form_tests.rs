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

//! IR v3 lowering: the three wire forms of a list, and a request checksum algorithm the IR cannot name.
//!
//! Responsible for: `Type::List::member_name` — the repeated element of a wrapped XML list, `None`
//! for a flattened one and for a comma-delimited header list — and the refusal to drop a modelled
//! request checksum algorithm silently.
//! NOT responsible for: how a codec reads or writes those forms; that is `rustfs-gateway-codegen`.
//! Upstream: `crate::lower`. Downstream: nothing.

use super::lower_tests::overlay_from;
use crate::ir::{Binding, Type};
use crate::lower::lower;
use crate::smithy::Model;

fn model(algorithms: &str) -> String {
    r#"{
  "smithy": "2.0",
  "shapes": {
    "ns#Svc": { "type": "service", "version": "2006-03-01", "operations": [{"target": "ns#PutThing"}] },
    "ns#PutThing": {
      "type": "operation",
      "input": { "target": "ns#PutThingRequest" },
      "output": { "target": "ns#PutThingOutput" },
      "traits": {
        "aws.protocols#httpChecksum": { "requestAlgorithmMember": "ChecksumAlgorithm" },
        "smithy.api#http": { "method": "PUT", "uri": "/{Bucket}?thing", "code": 200 }
      }
    },
    "ns#PutThingRequest": {
      "type": "structure",
      "members": {
        "Bucket": { "target": "ns#Str", "traits": { "smithy.api#httpLabel": {}, "smithy.api#required": {} } },
        "Attributes": { "target": "ns#AttributeList", "traits": { "smithy.api#httpHeader": "x-amz-attributes" } },
        "Dates": { "target": "ns#DateList", "traits": { "smithy.api#httpHeader": "x-amz-dates" } },
        "ChecksumAlgorithm": { "target": "ns#Algorithm", "traits": { "smithy.api#httpHeader": "x-amz-sdk-checksum-algorithm" } }
      }
    },
    "ns#PutThingOutput": {
      "type": "structure",
      "traits": { "smithy.api#xmlName": "ThingResult" },
      "members": {
        "Named": { "target": "ns#NamedList" },
        "Defaulted": { "target": "ns#DefaultedList" },
        "Flat": { "target": "ns#DefaultedList", "traits": { "smithy.api#xmlFlattened": {} } }
      }
    },
    "ns#AttributeList": { "type": "list", "member": { "target": "ns#Attribute" } },
    "ns#Attribute": { "type": "enum", "members": {
      "A": { "target": "smithy.api#Unit", "traits": { "smithy.api#enumValue": "Alpha" } },
      "B": { "target": "smithy.api#Unit", "traits": { "smithy.api#enumValue": "Beta" } }
    } },
    "ns#DateList": { "type": "list", "member": { "target": "ns#Date" } },
    "ns#Date": { "type": "timestamp" },
    "ns#NamedList": { "type": "list", "member": { "target": "ns#Str", "traits": { "smithy.api#xmlName": "Entry" } } },
    "ns#DefaultedList": { "type": "list", "member": { "target": "ns#Str" } },
    "ns#Algorithm": { "type": "enum", "members": {ALGORITHMS} },
    "ns#Str": { "type": "string" }
  }
}"#
    .replace("{ALGORITHMS}", algorithms)
}

const OVERLAY: &str = r#"
include = ["PutThing"]

[op.PutThing]
precedence = 100
auth_action = "s3:PutThing"
input_drop = ["Dates"]
"#;

const KNOWN: &str = r#"{
  "C": { "target": "smithy.api#Unit", "traits": { "smithy.api#enumValue": "CRC32" } },
  "S": { "target": "smithy.api#Unit", "traits": { "smithy.api#enumValue": "SHA256" } }
}"#;

fn lower_with(algorithms: &str) -> crate::Result<crate::Lowered> {
    lower_overlay(algorithms, OVERLAY)
}

fn lower_overlay(algorithms: &str, overlay: &str) -> crate::Result<crate::Lowered> {
    let model = Model::from_json(&model(algorithms))?;
    lower(&model, &overlay_from(overlay)?)
}

fn list(side: &[crate::ir::Field], name: &str) -> (bool, Option<String>, Binding) {
    let field = side.iter().find(|field| field.name == name).expect("member is lowered");
    let Type::List {
        flattened, member_name, ..
    } = &field.ty
    else {
        panic!("{name} is a list, got {:?}", field.ty);
    };
    (*flattened, member_name.clone(), field.binding.clone())
}

#[test]
fn a_header_list_lowers_to_the_delimited_form() {
    let lowered = lower_with(KNOWN).expect("lowers");
    let ir = &lowered.operations[0];
    assert_eq!(list(&ir.input, "Attributes"), (false, None, Binding::Header));
}

#[test]
fn a_wrapped_body_list_records_its_member_s_xml_name() {
    let lowered = lower_with(KNOWN).expect("lowers");
    let ir = &lowered.operations[0];
    assert_eq!(list(&ir.output, "Named"), (false, Some("Entry".to_owned()), Binding::BodyXml));
}

#[test]
fn n_a_wrapped_body_list_with_no_xml_name_records_the_smithy_default() {
    let lowered = lower_with(KNOWN).expect("lowers");
    let ir = &lowered.operations[0];
    assert_eq!(list(&ir.output, "Defaulted"), (false, Some("member".to_owned()), Binding::BodyXml));
}

#[test]
fn n_a_flattened_body_list_records_no_member_name() {
    let lowered = lower_with(KNOWN).expect("lowers");
    let ir = &lowered.operations[0];
    assert_eq!(list(&ir.output, "Flat"), (true, None, Binding::BodyXml));
}

#[test]
fn request_algorithms_the_ir_names_are_lowered() {
    let lowered = lower_with(KNOWN).expect("lowers");
    let names: Vec<&str> = lowered.operations[0]
        .checksum
        .request_algorithms
        .iter()
        .map(|algo| algo.as_str())
        .collect();
    assert_eq!(names, ["CRC32", "SHA256"]);
}

#[test]
fn n_a_request_algorithm_the_ir_cannot_name_fails_lowering() {
    let algorithms = r#"{
  "C": { "target": "smithy.api#Unit", "traits": { "smithy.api#enumValue": "CRC32" } },
  "B": { "target": "smithy.api#Unit", "traits": { "smithy.api#enumValue": "BLAKE3" } }
}"#;
    let error = lower_with(algorithms).expect_err("an algorithm the IR cannot name must not be dropped");
    let text = format!("{error}");
    assert!(text.contains("BLAKE3"), "the refusal names the algorithm: {text}");
    assert!(text.contains("PutThing"), "the refusal names the operation: {text}");
}

#[test]
fn n_a_header_list_whose_members_may_hold_a_comma_fails_lowering() {
    // An HTTP date is `Sun, 06 Nov 1994 08:49:37 GMT`: splitting the header on commas would cut
    // every member in two. Only an enumeration's names are known to be comma-free.
    let overlay = OVERLAY.replace("input_drop = [\"Dates\"]\n", "");
    let error = lower_overlay(KNOWN, &overlay).expect_err("a delimited list of dates cannot be split on commas");
    let text = format!("{error}");
    assert!(text.contains("x-amz-dates") || text.contains("DateList"), "{text}");
}
