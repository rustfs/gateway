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

//! Compile-time or regression support for this module.
//!
//! Responsible for: exercising the contract named by this file.
//! NOT responsible for: implementing the production behavior under test.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

//! Tests for trait stripping and the lowering rules, against a miniature model.
//!
//! The pinned `model/s3.json` is deliberately not used here: these tests must stay readable and
//! must fail for one reason each. End-to-end generation against the real model is covered by
//! `rustfs-gateway-codegen`.

use crate::ir::{ArnForm, Binding, EmptyValue, HostClass, Method, Predicate, TargetKind, Type};
use crate::lower::lower;
use crate::overlay::Overlay;
use crate::smithy::Model;

const MINI_MODEL: &str = r#"{
  "smithy": "2.0",
  "shapes": {
    "ns#Svc": { "type": "service", "version": "2006-03-01", "operations": [{"target": "ns#GetThing"}] },
    "ns#GetThing": {
      "type": "operation",
      "input": { "target": "ns#GetThingRequest" },
      "output": { "target": "ns#GetThingOutput" },
      "traits": {
        "smithy.api#documentation": "<p>prose that must never reach the IR</p>",
        "smithy.api#http": { "method": "GET", "uri": "/{Bucket}?thing", "code": 200 }
      }
    },
    "ns#GetThingRequest": {
      "type": "structure",
      "members": {
        "Bucket": {
          "target": "ns#BucketName",
          "traits": { "smithy.api#httpLabel": {}, "smithy.api#required": {}, "smithy.api#documentation": "x" }
        },
        "Marker": { "target": "ns#Str", "traits": { "smithy.api#httpQuery": "marker" } },
        "Owner": { "target": "ns#Str", "traits": { "smithy.api#httpHeader": "X-Amz-Expected-Bucket-Owner" } }
      }
    },
    "ns#GetThingOutput": {
      "type": "structure",
      "traits": { "smithy.api#xmlName": "ThingResult" },
      "members": {
        "Name": { "target": "ns#Str" },
        "Items": { "target": "ns#ItemList", "traits": { "smithy.api#xmlFlattened": {} } }
      }
    },
    "ns#ItemList": { "type": "list", "member": { "target": "ns#Item" } },
    "ns#Item": { "type": "structure", "members": { "Key": { "target": "ns#Str" } } },
    "ns#BucketName": { "type": "string" },
    "ns#Str": { "type": "string" }
  }
}"#;

const MINI_OVERLAY: &str = r#"
include = ["GetThing"]

[op.GetThing]
precedence = 100
auth_action = "s3:GetThing"
output_required = ["Name"]
"#;

fn load(overlay_text: &str) -> crate::Result<crate::Lowered> {
    let model = Model::from_json(MINI_MODEL)?;
    let overlay = overlay_from(overlay_text)?;
    lower(&model, &overlay)
}

fn overlay_from(text: &str) -> crate::Result<Overlay> {
    // One directory per call: the test binary runs these in parallel threads, and a shared path
    // would make them read each other's overlay.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("s3gate-overlay-{}-{n}", std::process::id()));
    std::fs::create_dir_all(dir.join("ops")).expect("temp dir");
    std::fs::create_dir_all(dir.join("quirks")).expect("temp dir");
    std::fs::write(
        dir.join(crate::overlay::ROUTE_FILE),
        "# no reviewed cross-precedence overlap in this fixture\n",
    )
    .expect("temp dir");
    // The overlay is a directory of family files: one cross-family scalar vocabulary, one
    // `ops/<family>.toml`, one `quirks/<family>.toml`. These tests are about lowering, so they
    // use one family and the smallest scalar map the miniature model needs.
    std::fs::write(dir.join("scalars.toml"), "[scalar]\nBucketName = \"BucketName\"\n").expect("write scalars");
    std::fs::write(
        dir.join("error-status.toml"),
        "[[code]]\nname = \"NoSuchKey\"\nconstant = \"NO_SUCH_KEY\"\nstatus = 404\n",
    )
    .expect("write error status");
    std::fs::write(dir.join("ops").join("mini.toml"), text).expect("write overlay");
    std::fs::write(dir.join("quirks").join("mini.toml"), "").expect("write quirks");
    Overlay::load(&dir)
}

#[test]
fn strips_documentation_before_anything_else_sees_it() {
    let model = Model::from_json(MINI_MODEL).expect("loads");
    assert_eq!(model.stripped_trait_count(), 2);
    let op = model.shape_local("GetThing").expect("operation");
    assert!(crate::smithy::trait_of(op, "smithy.api#documentation").is_none());
}

#[test]
fn derives_route_bindings_and_shapes_from_the_model() {
    let lowered = load(MINI_OVERLAY).expect("lowers");
    let ir = &lowered.operations[0];

    assert_eq!(ir.http.method, Method::Get);
    assert_eq!(ir.http.target, TargetKind::Bucket);
    assert_eq!(ir.http.path_shape, "/{Bucket}");
    assert_eq!(ir.http.predicates[2], Predicate::QueryPresent("thing".into()));

    let owner = ir.input.iter().find(|f| f.name == "Owner").expect("Owner");
    assert_eq!(owner.wire_name.as_deref(), Some("x-amz-expected-bucket-owner"), "header names lowercase");
    assert_eq!(owner.binding, Binding::Header);

    let bucket = ir.input.iter().find(|f| f.name == "Bucket").expect("Bucket");
    assert_eq!(bucket.ty, Type::BucketName, "the scalar map wins over the model's `string`");
    assert!(bucket.hot, "uri labels are always hot");

    assert_eq!(ir.xml.response_root.as_deref(), Some("ThingResult"));
    assert!(ir.shapes.contains_key("Item"), "nested list element shapes are collected");
    assert_eq!(ir.xml.element_order, ["Name", "Items"]);
    assert_eq!(
        ir.xml.empty_value_policy[0],
        ("Name".into(), EmptyValue::Emit),
        "required members emit when empty"
    );
    assert_eq!(
        ir.xml.empty_value_policy[1],
        ("Items".into(), EmptyValue::Emit),
        "an optional member emits when empty too: absence is `Option::None`, so dropping an empty \
         value as well collapses two values the decoder tells apart (rustfs/gateway#221)"
    );
}

#[test]
fn lowers_upload_id_query_as_an_owned_capability() {
    let text = format!(
        "{MINI_OVERLAY}\n\n[[op.GetThing.field]]\nside = \"input\"\nname = \"Marker\"\ntype = \"Capability:upload_id\"\n"
    );
    let lowered = load(&text).expect("known capability exchange lowers");
    let marker = lowered.operations[0]
        .input
        .iter()
        .find(|field| field.name == "Marker")
        .expect("Marker");

    assert_eq!(
        marker.ty,
        Type::Capability {
            exchange: "upload_id".to_owned(),
        }
    );
}

#[test]
fn n_rejects_an_unknown_capability_exchange() {
    let text = format!(
        "{MINI_OVERLAY}\n\n[[op.GetThing.field]]\nside = \"input\"\nname = \"Marker\"\ntype = \"Capability:session_id\"\n"
    );
    let err = load(&text).expect_err("unknown exchanges fail closed");

    assert!(format!("{err}").contains("unknown capability exchange `session_id`"), "{err}");
}

#[test]
fn n_rejects_a_capability_outside_the_query() {
    let text =
        format!("{MINI_OVERLAY}\n\n[[op.GetThing.field]]\nside = \"input\"\nname = \"Owner\"\ntype = \"Capability:upload_id\"\n");
    let err = load(&text).expect_err("capabilities are query-only");

    assert!(format!("{err}").contains("Capability fields must use a query binding"), "{err}");
}

#[test]
fn n_fails_when_an_operation_is_neither_included_nor_deferred() {
    let err = load("include = []\n").expect_err("an undecided operation is a hard failure");
    assert!(format!("{err}").contains("neither included nor deferred"), "{err}");
}

#[test]
fn n_fails_without_a_route_precedence() {
    let err = load("include = [\"GetThing\"]\n[op.GetThing]\nauth_action = \"s3:GetThing\"\n")
        .expect_err("precedence is a decision, not a derivation");
    assert!(format!("{err}").contains("precedence"), "{err}");
}

#[test]
fn n_fails_without_an_iam_action() {
    let err = load("include = [\"GetThing\"]\n[op.GetThing]\nprecedence = 1\n").expect_err("no action mapping");
    assert!(format!("{err}").contains("IAM action"), "{err}");
}

#[test]
fn n_fails_on_an_unknown_quirk_reference() {
    let text = format!("{MINI_OVERLAY}\nquirk_refs = [\"q-nope-0001\"]\n");
    let err = load(&text).expect_err("dangling quirk reference");
    assert!(format!("{err}").contains("not declared in the overlay"), "{err}");
}

#[test]
fn n_fails_when_element_order_does_not_cover_the_body() {
    let text = format!("{MINI_OVERLAY}\nelement_order = [\"Name\"]\n");
    let err = load(&text).expect_err("element_order must be exhaustive");
    assert!(format!("{err}").contains("element_order"), "{err}");
}

#[test]
fn n_fails_when_an_included_operation_is_not_in_the_model() {
    let err = load("include = [\"GetThing\", \"Nope\"]\n").expect_err("unknown operation");
    assert!(format!("{err}").contains("not in the model"), "{err}");
}

#[test]
fn n_fails_when_a_privileged_operation_allows_presigning() {
    let text = format!("{MINI_OVERLAY}\nauth_requirement = \"Privileged\"\nauth_presigned = true\n");
    let err = load(&text).expect_err("privileged surfaces are never presignable");
    assert!(format!("{err}").contains("presigned"), "{err}");
}

#[test]
fn n_fails_when_a_field_overlay_targets_a_member_the_model_does_not_have() {
    let text = format!("{MINI_OVERLAY}\n\n[[op.GetThing.field]]\nside = \"input\"\nname = \"Nope\"\nquirks = []\n");
    let err = load(&text).expect_err("a typo in the overlay must not be silently ignored");
    assert!(format!("{err}").contains("not a member of the input shape"), "{err}");
}

#[test]
fn n_fails_when_a_hot_list_names_an_unknown_member() {
    let text = format!("{MINI_OVERLAY}\ninput_hot = [\"Nope\"]\n");
    let err = load(&text).expect_err("unknown member in input_hot");
    assert!(format!("{err}").contains("input_hot"), "{err}");
}

#[test]
fn n_fails_when_a_shape_overlay_targets_an_unknown_member() {
    let text = format!("{MINI_OVERLAY}\n\n[shape.Item]\nrequired = [\"Nope\"]\n");
    let err = load(&text).expect_err("unknown member in a shape overlay");
    assert!(format!("{err}").contains("not one of its members"), "{err}");
}

#[test]
fn lowers_host_class_as_a_route_predicate() {
    let text = format!("{MINI_OVERLAY}\nhost_class = \"ObjectLambda\"\n");
    let lowered = load(&text).expect("a known host class lowers");
    let ir = &lowered.operations[0];
    assert!(
        ir.http.predicates.contains(&Predicate::HostClass(HostClass::ObjectLambda)),
        "{:?}",
        ir.http.predicates
    );
}

#[test]
fn lowers_arn_form_as_a_route_predicate() {
    let text = format!("{MINI_OVERLAY}\narn_form = \"AccessPoint\"\n");
    let lowered = load(&text).expect("a known ARN form lowers");
    let ir = &lowered.operations[0];
    assert!(
        ir.http.predicates.contains(&Predicate::ArnForm(ArnForm::AccessPoint)),
        "{:?}",
        ir.http.predicates
    );
}

#[test]
fn n_rejects_an_unknown_host_class() {
    let text = format!("{MINI_OVERLAY}\nhost_class = \"Nope\"\n");
    let err = load(&text).expect_err("an unknown host class must fail closed");
    assert!(format!("{err}").contains("host_class"), "{err}");
}

#[test]
fn n_rejects_an_unknown_arn_form() {
    let text = format!("{MINI_OVERLAY}\narn_form = \"Nope\"\n");
    let err = load(&text).expect_err("an unknown ARN form must fail closed");
    assert!(format!("{err}").contains("arn_form"), "{err}");
}
