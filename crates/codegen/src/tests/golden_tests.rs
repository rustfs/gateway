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

//! Tests for the golden comparison.
//!
//! The comparison is the most valuable output of this task, so its failure modes matter more than
//! its success mode: a diff that reports thirty-eight shifted array elements for one inserted enum
//! value hides the finding instead of reporting it.

use rustfs_gateway_model::json::parse;

use crate::golden::compare;

fn diff(a: &str, b: &str) -> Vec<String> {
    compare(&parse(a).expect("golden parses"), &parse(b).expect("generated parses"))
        .into_iter()
        .map(|d| d.to_string())
        .collect()
}

#[test]
fn identical_documents_have_no_differences() {
    assert!(diff(r#"{"a": [1, 2], "b": {"c": true}}"#, r#"{"a": [1, 2], "b": {"c": true}}"#).is_empty());
}

#[test]
fn object_key_order_is_not_a_difference() {
    assert!(
        diff(r#"{"a": 1, "b": 2}"#, r#"{"b": 2, "a": 1}"#).is_empty(),
        "objects are maps, not sequences"
    );
}

#[test]
fn n_a_missing_key_is_reported_with_its_path() {
    let out = diff(r#"{"xml": {"response_root": "X"}}"#, r#"{"xml": {}}"#);
    assert_eq!(out.len(), 1);
    assert!(out[0].starts_with("xml.response_root: golden \"X\" / generated absent"), "{:?}", out);
}

#[test]
fn n_one_inserted_enum_value_is_one_difference_not_thirty_eight() {
    let out = diff(r#"["a", "b", "c"]"#, r#"["a", "a2", "b", "c"]"#);
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(out[0].contains("[+]") && out[0].contains("a2"), "{:?}", out);
}

#[test]
fn n_a_reordered_string_list_is_reported_as_an_order_difference() {
    let out = diff(r#"["a", "b"]"#, r#"["b", "a"]"#);
    assert_eq!(out.len(), 1);
    assert!(out[0].contains("[order]"), "{:?}", out);
}

#[test]
fn n_fields_are_matched_by_name_not_by_index() {
    let golden = r#"[{"name": "A", "required": true}, {"name": "B", "required": false}]"#;
    let generated = r#"[{"name": "B", "required": false}, {"name": "A", "required": false}]"#;
    let out = diff(golden, generated);
    assert!(out.iter().any(|d| d.contains("[A].required")), "the optionality change is found: {out:?}");
    assert!(out.iter().any(|d| d.contains("[order]")), "the reorder is reported separately: {out:?}");
    assert_eq!(out.len(), 2);
}

#[test]
fn n_quirk_records_are_matched_by_id() {
    let golden = r#"[{"id": "q-a-0001", "kind": "x"}, {"id": "q-b-0002", "kind": "y"}]"#;
    let generated = r#"[{"id": "q-b-0002", "kind": "y"}, {"id": "q-a-0001", "kind": "z"}]"#;
    let out = diff(golden, generated);
    assert!(out.iter().any(|d| d.contains("[q-a-0001].kind")), "{out:?}");
}

#[test]
fn n_a_type_change_is_reported_once() {
    let golden = r#"{"type": {"kind": "String"}}"#;
    let generated = r#"{"type": {"kind": "OpaqueString"}}"#;
    let out = diff(golden, generated);
    assert_eq!(out.len(), 1);
    assert!(out[0].contains("type.kind"), "{:?}", out);
}

#[test]
fn n_a_long_value_is_truncated_so_the_report_stays_readable() {
    let long: String = std::iter::repeat_n("value", 60).collect();
    let out = diff(&format!("{{\"a\": \"{long}\"}}"), r#"{"a": "short"}"#);
    assert_eq!(out.len(), 1);
    assert!(out[0].contains("..."), "{:?}", out);
    assert!(out[0].len() < 200, "{:?}", out);
}
