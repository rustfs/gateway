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

//! c-param-1003: a query parameter that is both a route discriminator and a required parameter.
//!
//! Responsible for: proving lowering refuses an operation that records only one of the two roles —
//! a selector whose member is not required, or a required member that tells two operations on the
//! same route apart without a selector saying so.
//! NOT responsible for: the runtime answers those roles produce; `rustfs-gateway-core`'s
//! `selector_required_params` exercises them on the real `GetBucketAnalyticsConfiguration`.
//! Upstream: `crate::lower`. Downstream: nothing.

use super::lower_tests::overlay_from;
use crate::ir::Predicate;
use crate::lower::lower;
use crate::smithy::Model;

/// Two operations on one method, path and subresource that only a required `id` tells apart —
/// the shape `GetBucketAnalyticsConfiguration` and `ListBucketAnalyticsConfigurations` have.
const MODEL: &str = r#"{
  "smithy": "2.0",
  "shapes": {
    "ns#Svc": { "type": "service", "version": "2006-03-01", "operations": [{"target": "ns#GetThing"}, {"target": "ns#ListThings"}] },
    "ns#GetThing": {
      "type": "operation",
      "input": { "target": "ns#GetThingRequest" },
      "traits": { "smithy.api#http": { "method": "GET", "uri": "/{Bucket}?thing", "code": 200 } }
    },
    "ns#ListThings": {
      "type": "operation",
      "input": { "target": "ns#ListThingsRequest" },
      "traits": { "smithy.api#http": { "method": "GET", "uri": "/{Bucket}?thing", "code": 200 } }
    },
    "ns#GetThingRequest": {
      "type": "structure",
      "members": {
        "Bucket": { "target": "ns#Str", "traits": { "smithy.api#httpLabel": {}, "smithy.api#required": {} } },
        "Id": { "target": "ns#Str", "traits": { "smithy.api#httpQuery": "id", "smithy.api#required": {} } }
      }
    },
    "ns#ListThingsRequest": {
      "type": "structure",
      "members": {
        "Bucket": { "target": "ns#Str", "traits": { "smithy.api#httpLabel": {}, "smithy.api#required": {} } },
        "Token": { "target": "ns#Str", "traits": { "smithy.api#httpQuery": "continuation-token" } }
      }
    },
    "ns#Str": { "type": "string" }
  }
}"#;

const BOTH_ROLES: &str = r#"
include = ["GetThing", "ListThings"]

[op.GetThing]
precedence = 100
query_present = ["id"]
auth_action = "s3:GetThing"

[op.ListThings]
precedence = 101
auth_action = "s3:ListThings"
"#;

fn lower_with(overlay: &str) -> crate::Result<crate::Lowered> {
    let model = Model::from_json(MODEL)?;
    lower(&model, &overlay_from(overlay)?)
}

#[test]
fn c_param_1003_both_roles_recorded_lowers() {
    let lowered = lower_with(BOTH_ROLES).expect("both roles are recorded");
    let get = lowered
        .operations
        .iter()
        .find(|ir| ir.operation == "GetThing")
        .expect("GetThing is lowered");
    assert!(get.http.predicates.contains(&Predicate::QueryPresent("id".into())), "selector role");
    let id = get.input.iter().find(|field| field.name == "Id").expect("Id is lowered");
    assert!(id.required, "required-parameter role");
}

#[test]
fn n_c_param_1003_a_required_discriminator_without_a_selector_is_refused() {
    let overlay = BOTH_ROLES.replace("query_present = [\"id\"]\n", "");
    let error = lower_with(&overlay).expect_err("only the required-parameter role is recorded");
    let text = format!("{error}");
    assert!(text.contains("GetThing"), "{text}");
    assert!(text.contains("`id`"), "{text}");
    assert!(
        text.contains("ListThings"),
        "the refusal names the operation it cannot be told from: {text}"
    );
}

#[test]
fn n_c_param_1003_a_selector_whose_member_is_not_required_is_refused() {
    let overlay = format!("{BOTH_ROLES}\n[[op.GetThing.field]]\nside = \"input\"\nname = \"Id\"\nrequired = false\n");
    let error = lower_with(&overlay).expect_err("only the selector role is recorded");
    let text = format!("{error}");
    assert!(text.contains("GetThing"), "{text}");
    assert!(text.contains("`id`"), "{text}");
    assert!(text.contains("required"), "{text}");
}

#[test]
fn n_c_param_1003_an_optional_member_on_the_sibling_is_no_discriminator() {
    // `continuation-token` is ListThings' own optional member, so it tells nothing apart and needs
    // no selector: the guard is about required members only.
    let lowered = lower_with(BOTH_ROLES).expect("lowers");
    let list = lowered
        .operations
        .iter()
        .find(|ir| ir.operation == "ListThings")
        .expect("ListThings is lowered");
    assert!(
        !list
            .http
            .predicates
            .contains(&Predicate::QueryPresent("continuation-token".into()))
    );
}
