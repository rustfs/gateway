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

//! Semantic IR validation beyond JSON Schema.
//!
//! Responsible for: cross-field, shape-reference, unwrapped-output, and overlay-quirk invariants.
//! NOT responsible for: schema validation or golden-specific assertions. Upstream: parsed IR and
//! the loaded overlay. Downstream: positive and expected-failure validation.

use std::collections::{BTreeMap, BTreeSet};

use rustfs_gateway_model::Overlay;
use rustfs_gateway_model::ir::Quirk;
use serde_json::{Value, json};

use super::{Diagnostic, escape_pointer};

pub(super) fn diagnostics(doc: &Value, operations: &BTreeSet<String>, overlay: &Overlay) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    check_query_predicates(doc, &mut diagnostics);
    check_payload_count(doc, &mut diagnostics);
    check_element_order(doc, &mut diagnostics);
    check_unwrapped_output(doc, &mut diagnostics);
    check_shape_references(doc, &mut diagnostics);
    check_delimited_lists(doc, &mut diagnostics);
    check_quirks(doc, overlay, &mut diagnostics);
    if let Some(target) = doc.get("head_mirrors").and_then(Value::as_str)
        && !operations.contains(target)
    {
        diagnostics.push(Diagnostic::new(
            format!("head_mirrors names unknown operation `{target}`"),
            "/head_mirrors",
            "semantic/head-mirrors",
        ));
    }
    diagnostics
}

fn check_query_predicates(doc: &Value, diagnostics: &mut Vec<Diagnostic>) {
    let Some(predicates) = doc.pointer("/http/predicates").and_then(Value::as_array) else {
        return;
    };
    let mut present = BTreeSet::new();
    let mut absent = BTreeSet::new();
    for predicate in predicates {
        match predicate.get("kind").and_then(Value::as_str) {
            Some("QueryPresent") => {
                if let Some(key) = predicate.get("key").and_then(Value::as_str) {
                    present.insert(key);
                }
            }
            Some("QueryAbsent") => {
                if let Some(key) = predicate.get("key").and_then(Value::as_str) {
                    absent.insert(key);
                }
            }
            _ => {}
        }
    }
    for key in present.intersection(&absent) {
        diagnostics.push(Diagnostic::new(
            format!("query key `{key}` is both required and absent"),
            "/http/predicates",
            "semantic/query-predicate-conflict",
        ));
    }
}

fn check_payload_count(doc: &Value, diagnostics: &mut Vec<Diagnostic>) {
    let count = ["input", "output"]
        .into_iter()
        .filter_map(|side| doc.pointer(&format!("/{side}/fields")).and_then(Value::as_array))
        .flatten()
        .filter(|field| field.pointer("/binding/kind").and_then(Value::as_str) == Some("Payload"))
        .count();
    if count > 1 {
        diagnostics.push(Diagnostic::new(
            format!("operation has {count} Payload bindings; at most one is allowed"),
            "/input/fields",
            "semantic/single-payload",
        ));
    }
}

fn check_element_order(doc: &Value, diagnostics: &mut Vec<Diagnostic>) {
    if doc.pointer("/xml/unwrapped_output").and_then(Value::as_bool) != Some(true) {
        compare_element_order(
            doc.pointer("/output/fields"),
            doc.pointer("/xml/element_order"),
            doc.pointer("/xml/attributes"),
            "/xml/element_order",
            diagnostics,
        );
    }
    let Some(shapes) = doc.get("shapes").and_then(Value::as_object) else {
        return;
    };
    for (name, shape) in shapes {
        compare_element_order(
            shape.get("fields"),
            shape.pointer("/xml/element_order"),
            shape.pointer("/xml/attributes"),
            &format!("/shapes/{}/xml/element_order", escape_pointer(name)),
            diagnostics,
        );
    }
}

/// A `BodyXml` member written as an attribute (`Grantee`'s `xsi:type`, sourced from its `Type`
/// field) has no element, so it has no place in the element order.
fn compare_element_order(
    fields: Option<&Value>,
    order: Option<&Value>,
    attributes: Option<&Value>,
    at: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let as_attributes: BTreeSet<&str> = attributes
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|attribute| attribute.pointer("/source/kind").and_then(Value::as_str) == Some("Field"))
        .filter_map(|attribute| attribute.pointer("/source/field").and_then(Value::as_str))
        .collect();
    let body: BTreeSet<&str> = fields
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|field| field.pointer("/binding/kind").and_then(Value::as_str) == Some("BodyXml"))
        .filter_map(|field| field.get("name").and_then(Value::as_str))
        .filter(|name| !as_attributes.contains(name))
        .collect();
    let ordered_values: Vec<&str> = order
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let ordered: BTreeSet<&str> = ordered_values.iter().copied().collect();
    if body != ordered || ordered.len() != ordered_values.len() {
        diagnostics.push(Diagnostic::new(
            format!("element_order must cover each BodyXml field exactly once; fields={body:?}, order={ordered_values:?}"),
            at,
            "semantic/element-order",
        ));
    }
}

fn check_unwrapped_output(doc: &Value, diagnostics: &mut Vec<Diagnostic>) {
    if doc.pointer("/xml/unwrapped_output").and_then(Value::as_bool) != Some(true) {
        return;
    }
    let fields: Vec<&Value> = doc
        .pointer("/output/fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|field| field.pointer("/binding/kind").and_then(Value::as_str) == Some("BodyXml"))
        .collect();
    if fields.len() != 1 {
        diagnostics.push(Diagnostic::new(
            format!("unwrapped output must have exactly one BodyXml field; found {}", fields.len()),
            "/output/fields",
            "semantic/unwrapped-output-cardinality",
        ));
        return;
    }
    let response_root = doc.pointer("/xml/response_root").and_then(Value::as_str);
    let wire_name = fields[0].get("wire_name").and_then(Value::as_str);
    if response_root.is_none() || response_root != wire_name {
        diagnostics.push(Diagnostic::new(
            format!("unwrapped response_root {response_root:?} must equal BodyXml wire_name {wire_name:?}"),
            "/xml/response_root",
            "semantic/unwrapped-output-root",
        ));
    }
}

fn check_shape_references(doc: &Value, diagnostics: &mut Vec<Diagnostic>) {
    let known: BTreeMap<&str, &str> = doc
        .get("shapes")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|shapes| {
            shapes
                .iter()
                .filter_map(|(name, shape)| shape.get("kind").and_then(Value::as_str).map(|kind| (name.as_str(), kind)))
        })
        .collect();
    walk(doc, "", &mut |value, at| {
        let Some(reference_kind @ ("Structure" | "Union")) = value.get("kind").and_then(Value::as_str) else {
            return;
        };
        let Some(shape) = value.get("shape").and_then(Value::as_str) else {
            return;
        };
        match known.get(shape) {
            None => diagnostics.push(Diagnostic::new(
                format!("type names unknown shape `{shape}`"),
                format!("{at}/shape"),
                "semantic/shape-reference",
            )),
            Some(definition_kind) if *definition_kind != reference_kind => diagnostics.push(Diagnostic::new(
                format!("type declares `{reference_kind}` but shape `{shape}` is `{definition_kind}`"),
                format!("{at}/shape"),
                "semantic/shape-kind",
            )),
            Some(_) => {}
        }
    });
}

/// A list with neither `flattened` nor a `member_name` is the comma-delimited header form, which
/// has no XML elements. JSON Schema cannot see the binding beside a type, so this is where the form
/// is confined to the direct type of a `Header`-bound field — anywhere else it is a list no codec
/// can read or write.
fn check_delimited_lists(doc: &Value, diagnostics: &mut Vec<Diagnostic>) {
    let mut allowed = BTreeSet::new();
    for side in ["input", "output"] {
        let fields = doc.pointer(&format!("/{side}/fields")).and_then(Value::as_array);
        for (index, field) in fields.into_iter().flatten().enumerate() {
            if field.pointer("/binding/kind").and_then(Value::as_str) == Some("Header") {
                allowed.insert(format!("/{side}/fields/{index}/type"));
            }
        }
    }
    walk(doc, "", &mut |value, at| {
        let delimited = value.get("kind").and_then(Value::as_str) == Some("List")
            && value.get("flattened").and_then(Value::as_bool) == Some(false)
            && value.get("member_name").is_some_and(Value::is_null);
        if delimited && !allowed.contains(at) {
            diagnostics.push(Diagnostic::new(
                "a comma-delimited list is valid only as the type of a Header-bound field",
                at,
                "semantic/delimited-list-binding",
            ));
        }
    });
}

fn check_quirks(doc: &Value, overlay: &Overlay, diagnostics: &mut Vec<Diagnostic>) {
    let references = referenced_quirks(doc);
    let reference_ids: BTreeSet<String> = references.iter().map(|(_, id)| id.clone()).collect();
    let mut embedded_ids = BTreeSet::new();
    if let Some(quirks) = doc.get("quirks").and_then(Value::as_array) {
        for (index, embedded) in quirks.iter().enumerate() {
            let Some(id) = embedded.get("id").and_then(Value::as_str) else {
                continue;
            };
            if !embedded_ids.insert(id.to_owned()) {
                diagnostics.push(Diagnostic::new(
                    format!("embedded quirk id `{id}` is duplicated"),
                    format!("/quirks/{index}/id"),
                    "semantic/duplicate-quirk-id",
                ));
            }
            match overlay.quirks.get(id) {
                None => diagnostics.push(Diagnostic::new(
                    format!("embedded quirk `{id}` has no overlay source"),
                    format!("/quirks/{index}"),
                    "semantic/quirk-source",
                )),
                Some(source) if protocol_quirk_record(embedded) != canonical_quirk_protocol(source) => {
                    diagnostics.push(Diagnostic::new(
                        format!("embedded quirk `{id}` differs from its overlay source"),
                        format!("/quirks/{index}"),
                        "semantic/quirk-source",
                    ))
                }
                Some(_) => {}
            }
        }
    }
    if reference_ids != embedded_ids {
        diagnostics.push(Diagnostic::new(
            "embedded quirks do not equal the referenced quirk ids",
            "/quirks",
            "semantic/quirk-set",
        ));
    }
    for (at, id) in references {
        if !overlay.quirks.contains_key(&id) {
            diagnostics.push(Diagnostic::new(format!("unknown quirk id `{id}`"), at, id));
        }
    }
}

fn protocol_quirk_record(quirk: &Value) -> Value {
    // `cases` are mutable downstream backlinks, not protocol provenance. The protocol record is
    // the exact id/kind/target/summary/evidence tuple sourced from the overlay.
    json!({
        "id": quirk.get("id"),
        "kind": quirk.get("kind"),
        "target": quirk.get("target"),
        "summary": quirk.get("summary"),
        "evidence": quirk.get("evidence"),
    })
}

fn canonical_quirk_protocol(quirk: &Quirk) -> Value {
    let evidence: Vec<Value> = quirk
        .evidence
        .iter()
        .map(|entry| {
            json!({
                "kind": entry.kind,
                "ref": entry.reference,
                "summary": entry.summary,
            })
        })
        .collect();
    json!({
        "id": quirk.id,
        "kind": quirk.kind,
        "target": quirk.target,
        "summary": quirk.summary,
        "evidence": Value::Array(evidence),
    })
}

pub(super) fn referenced_quirks(doc: &Value) -> Vec<(String, String)> {
    let mut references = Vec::new();
    walk(doc, "", &mut |value, at| {
        let Some(ids) = value.get("quirk_refs").and_then(Value::as_array) else {
            return;
        };
        for (index, id) in ids.iter().enumerate() {
            if let Some(id) = id.as_str() {
                references.push((format!("{at}/quirk_refs/{index}"), id.to_owned()));
            }
        }
    });
    references
}

fn walk(value: &Value, at: &str, visit: &mut impl FnMut(&Value, &str)) {
    visit(value, at);
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                walk(child, &format!("{at}/{}", escape_pointer(key)), visit);
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                walk(child, &format!("{at}/{index}"), visit);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::ir::read_json;

    fn root() -> PathBuf {
        crate::repo_root::repo_root()
    }

    fn overlay() -> Overlay {
        Overlay::load(&root().join("model/overlays")).expect("overlay must load")
    }

    fn sample(name: &str) -> Value {
        read_json(&root().join(format!("spec/ir/samples/{name}.json"))).expect("sample must parse")
    }

    fn has_rule(diagnostics: &[Diagnostic], rule: &str) -> bool {
        diagnostics.iter().any(|diagnostic| diagnostic.rule == rule)
    }

    #[test]
    fn rejects_structure_union_kind_mismatch() {
        let mut doc = sample("ListObjectsV2");
        doc["output"]["fields"][6]["type"]["member"]["kind"] = json!("Union");
        let mut found = Vec::new();
        check_shape_references(&doc, &mut found);
        assert!(has_rule(&found, "semantic/shape-kind"));
    }

    #[test]
    fn rejects_unwrapped_output_with_multiple_body_fields() {
        let mut doc = sample("GetBucketLocation");
        let duplicate = doc["output"]["fields"][0].clone();
        doc["output"]["fields"]
            .as_array_mut()
            .expect("fields are an array")
            .push(duplicate);
        let mut found = Vec::new();
        check_unwrapped_output(&doc, &mut found);
        assert!(has_rule(&found, "semantic/unwrapped-output-cardinality"));
    }

    #[test]
    fn rejects_unwrapped_output_root_wire_name_mismatch() {
        let mut doc = sample("GetBucketLocation");
        doc["xml"]["response_root"] = json!("WrongRoot");
        let mut found = Vec::new();
        check_unwrapped_output(&doc, &mut found);
        assert!(has_rule(&found, "semantic/unwrapped-output-root"));
    }

    #[test]
    fn rejects_duplicate_embedded_quirk_ids() {
        let mut doc = sample("GetBucketLocation");
        let duplicate = doc["quirks"][0].clone();
        doc["quirks"].as_array_mut().expect("quirks are an array").push(duplicate);
        let mut found = Vec::new();
        check_quirks(&doc, &overlay(), &mut found);
        assert!(has_rule(&found, "semantic/duplicate-quirk-id"));
    }

    #[test]
    fn rejects_embedded_quirk_record_drift() {
        let mut doc = sample("GetBucketLocation");
        doc["quirks"][0]["summary"] = json!("drifted");
        let mut found = Vec::new();
        check_quirks(&doc, &overlay(), &mut found);
        assert!(has_rule(&found, "semantic/quirk-source"));
    }

    #[test]
    fn permits_cases_backlink_drift() {
        let mut doc = sample("GetBucketLocation");
        doc["quirks"][0]["cases"] = json!(["c-renamed-9999"]);
        let mut found = Vec::new();
        check_quirks(&doc, &overlay(), &mut found);
        assert!(!has_rule(&found, "semantic/quirk-source"));
    }

    #[test]
    fn rejects_missing_embedded_quirk_record() {
        let mut doc = sample("GetBucketLocation");
        doc["quirks"].as_array_mut().expect("quirks are an array").remove(0);
        let mut found = Vec::new();
        check_quirks(&doc, &overlay(), &mut found);
        assert!(has_rule(&found, "semantic/quirk-set"));
    }

    fn grantee_doc() -> Value {
        read_json(&root().join("generated/ir/PutObjectAcl.json")).expect("generated document parses")
    }

    #[test]
    fn a_member_carried_as_an_attribute_is_not_an_element() {
        let mut found = Vec::new();
        check_element_order(&grantee_doc(), &mut found);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn n_a_member_without_an_attribute_still_needs_an_element() {
        let mut doc = grantee_doc();
        let attributes = doc["shapes"]["Grantee"]["xml"]["attributes"]
            .as_array_mut()
            .expect("attributes");
        attributes.retain(|attribute| attribute.pointer("/source/kind").and_then(Value::as_str) != Some("Field"));
        let mut found = Vec::new();
        check_element_order(&doc, &mut found);
        assert!(has_rule(&found, "semantic/element-order"), "{found:?}");
    }

    fn delimited_header_list() -> Value {
        crate::ir::tests::delimited_header_list("Header")
    }

    #[test]
    fn accepts_a_delimited_list_bound_to_a_header() {
        let mut doc = sample("ListObjectsV2");
        doc["input"]["fields"]
            .as_array_mut()
            .expect("fields are an array")
            .push(delimited_header_list());
        let mut found = Vec::new();
        check_delimited_lists(&doc, &mut found);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rejects_a_delimited_list_in_a_body_position() {
        let mut doc = sample("ListObjectsV2");
        doc["output"]["fields"][6]["type"]["flattened"] = json!(false);
        doc["output"]["fields"][6]["type"]["member_name"] = Value::Null;
        let mut found = Vec::new();
        check_delimited_lists(&doc, &mut found);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].rule, "semantic/delimited-list-binding");
        assert_eq!(found[0].at, "/output/fields/6/type");
    }

    #[test]
    fn rejects_a_delimited_list_in_a_query_position() {
        let mut doc = sample("ListObjectsV2");
        let mut field = delimited_header_list();
        field["binding"] = json!({ "kind": "Query" });
        doc["input"]["fields"]
            .as_array_mut()
            .expect("fields are an array")
            .push(field);
        let mut found = Vec::new();
        check_delimited_lists(&doc, &mut found);
        assert!(has_rule(&found, "semantic/delimited-list-binding"), "{found:?}");
    }

    #[test]
    fn rejects_a_delimited_list_nested_inside_a_header_list() {
        let mut doc = sample("ListObjectsV2");
        let mut field = delimited_header_list();
        let inner = field["type"].clone();
        field["type"]["member"] = inner;
        let fields = doc["input"]["fields"].as_array_mut().expect("fields are an array");
        fields.push(field);
        let index = fields.len() - 1;
        let mut found = Vec::new();
        check_delimited_lists(&doc, &mut found);
        assert_eq!(found.len(), 1, "only the nested list is out of place: {found:?}");
        assert_eq!(found[0].at, format!("/input/fields/{index}/type/member"));
    }

    #[test]
    fn rejects_a_delimited_list_as_a_shape_member() {
        let mut doc = sample("ListObjectsV2");
        let shape = doc["shapes"]
            .as_object_mut()
            .expect("shapes are an object")
            .values_mut()
            .find(|shape| shape.get("fields").and_then(Value::as_array).is_some_and(|m| !m.is_empty()))
            .expect("one shape has members");
        let mut field = delimited_header_list();
        field["binding"] = json!({ "kind": "BodyXml" });
        shape["fields"].as_array_mut().expect("fields are an array").push(field);
        let mut found = Vec::new();
        check_delimited_lists(&doc, &mut found);
        assert!(has_rule(&found, "semantic/delimited-list-binding"), "{found:?}");
    }
}
