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

//! That `generated/OPERATIONS.json` carries seven wire fields per operation and that every one of
//! them is invertible.
//!
//! Responsible for: the field set, the derivation of each field from the IR, and the reverse
//! indexes in both directions — an index that names an operation the forward table does not back
//! is as wrong as a forward fact no index carries.
//! NOT responsible for: whether the file on disk matches a fresh run, which is the zero-diff gate
//! in `codegen_tests`, or the human rendering, which is `OPERATIONS.md`.
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use rustfs_gateway_model::ir::{ArnForm, HostClass, Predicate};
use rustfs_gateway_model::json::{self, Value};

use super::codegen_tests::artifacts;
use crate::emit::operations_json::{self, Entry, FIELDS, INDEXES};

fn document() -> Value {
    let rendered = operations_json::render(&artifacts().operations);
    json::parse(&rendered).expect("the emitter writes parseable JSON")
}

fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    let Value::Object(members) = value else {
        panic!("expected an object, got {value:?}");
    };
    members
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, member)| member)
        .unwrap_or_else(|| panic!("no member {key:?}"))
}

fn keys(value: &Value) -> Vec<String> {
    let Value::Object(members) = value else {
        panic!("expected an object, got {value:?}");
    };
    members.iter().map(|(name, _)| name.clone()).collect()
}

fn strings(value: &Value) -> Vec<String> {
    let Value::Array(items) = value else {
        panic!("expected an array, got {value:?}");
    };
    items
        .iter()
        .map(|item| match item {
            Value::Str(text) => text.clone(),
            other => panic!("expected a string, got {other:?}"),
        })
        .collect()
}

/// The acceptance line: seven fields, never six.
#[test]
fn every_operation_entry_carries_all_seven_wire_fields() {
    let document = document();
    let operations = get(&document, "operations");
    let names = keys(operations);
    assert!(names.len() >= 70, "the pinned model generates 70+ operations, saw {}", names.len());
    for name in names {
        let entry = get(operations, &name);
        assert_eq!(
            keys(entry),
            FIELDS.iter().map(|field| (*field).to_owned()).collect::<Vec<_>>(),
            "{name} does not carry exactly the seven wire fields"
        );
    }
}

/// Every field is derived from the IR, not from a second record.
#[test]
fn the_fields_are_the_ir_they_claim_to_be() {
    let document = document();
    let operations = get(&document, "operations");
    for ir in &artifacts().operations {
        let entry = get(operations, &ir.operation);
        assert_eq!(get(entry, "method"), &Value::Str(ir.http.method.as_str().to_owned()));
        assert_eq!(get(entry, "path_shape"), &Value::Str(ir.http.path_shape.clone()));
        assert_eq!(strings(get(entry, "query_keys")), ir.query_keys());
        assert_eq!(strings(get(entry, "error_codes")), ir.errors.codes);
        assert_eq!(get(entry, "precedence"), &Value::Int(i64::from(ir.http.precedence)));
    }
}

/// `host_classes` reports the one endpoint constraint in the pinned operation set and no others.
#[test]
fn host_classes_is_the_selector_constraint_for_the_pinned_model() {
    let document = document();
    let operations = get(&document, "operations");
    for name in keys(operations) {
        let expected = if name == "ListDirectoryBuckets" {
            vec!["S3Express"]
        } else {
            vec![]
        };
        assert_eq!(strings(get(get(operations, &name), "host_classes")), expected, "{name}");
    }
    let by_host_class = get(&document, "by_host_class");
    assert_eq!(keys(by_host_class), ["S3Express"]);
    assert_eq!(strings(get(by_host_class, "S3Express")), ["ListDirectoryBuckets"]);
}

/// `host_classes` reports exactly the [`Predicate::HostClass`] a selector carries, and an
/// [`Predicate::ArnForm`] on the same selector contributes nothing to it — the two are distinct
/// dimensions of the same route.
///
/// This mutates a clone of a real IR to prove `ArnForm` remains distinct from `HostClass`.
#[test]
fn emits_the_host_class_a_synthetic_operation_declares() {
    let mut ir = artifacts()
        .operations
        .into_iter()
        .next()
        .expect("the pinned model generates operations");
    ir.http.predicates.push(Predicate::HostClass(HostClass::ObjectLambda));
    ir.http.predicates.push(Predicate::ArnForm(ArnForm::AccessPoint));

    let entry = operations_json::entry(&ir);
    assert_eq!(
        entry.host_classes,
        vec!["ObjectLambda".to_owned()],
        "ArnForm must not leak into host_classes"
    );
}

/// Every one of the seven fields has an index that inverts it, and the constants say so truly.
///
/// `FIELDS` and `INDEXES` are read by `scripts/check_operations_json_fields.sh`, so a constant that
/// drifted from what the renderer emits would move the guard off the document rather than break it.
/// Comparing the two arrays to each other would be `7 == 7`; both are compared to the renderer.
#[test]
fn the_field_constants_are_what_the_renderer_emits() {
    let sample = Entry {
        operation: "Sample".to_owned(),
        method: "GET".to_owned(),
        path_shape: "/{Bucket}".to_owned(),
        query_keys: vec!["acl".to_owned()],
        key_headers: vec!["x-amz-acl".to_owned()],
        host_classes: vec!["Standard".to_owned()],
        error_codes: vec!["NoSuchBucket".to_owned()],
        precedence: 250,
    };
    assert_eq!(operations_json::rendered_field_names(&sample), FIELDS.to_vec());
    let document = json::parse(&operations_json::render_entries(&[sample])).expect("parseable");
    assert_eq!(
        keys(get(get(&document, "operations"), "Sample")),
        FIELDS.iter().map(|field| (*field).to_owned()).collect::<Vec<_>>()
    );
    let emitted: Vec<String> = keys(&document).into_iter().filter(|key| key.starts_with("by_")).collect();
    assert_eq!(emitted, INDEXES.iter().map(|index| (*index).to_owned()).collect::<Vec<_>>());
    for index in INDEXES {
        assert_eq!(
            keys(get(&document, index)).len(),
            1,
            "{index} must invert the one fact the sample carries"
        );
    }
}

/// Forward to reverse: every fact in an entry appears under the matching index.
#[test]
fn every_forward_fact_appears_in_its_index() {
    let document = document();
    let operations = get(&document, "operations");
    for name in keys(operations) {
        let entry = get(operations, &name);
        let single = [("method", "by_method"), ("path_shape", "by_path_shape")];
        for (field, index) in single {
            let Value::Str(key) = get(entry, field) else {
                panic!("{field} is not a string");
            };
            assert!(
                strings(get(get(&document, index), key)).contains(&name),
                "{name} has {field}={key} but {index} does not list it"
            );
        }
        let many = [
            ("query_keys", "by_query_key"),
            ("key_headers", "by_key_header"),
            ("host_classes", "by_host_class"),
            ("error_codes", "by_error_code"),
        ];
        for (field, index) in many {
            for key in strings(get(entry, field)) {
                assert!(
                    strings(get(get(&document, index), &key)).contains(&name),
                    "{name} carries {field} {key} but {index} does not list it"
                );
            }
        }
        let Value::Int(precedence) = get(entry, "precedence") else {
            panic!("precedence is not an integer");
        };
        assert!(
            strings(get(get(&document, "by_precedence"), &precedence.to_string())).contains(&name),
            "{name} sits at precedence {precedence} but by_precedence does not list it"
        );
    }
}

/// Reverse to forward: an index never names an operation the entry does not back.
///
/// This is the direction that catches a stale index. Without it an index could keep an operation
/// after the fact that put it there was removed, and the "every forward fact appears" assertion
/// above would still be green.
#[test]
fn n_no_index_names_an_operation_its_entry_does_not_back() {
    let document = document();
    let operations = get(&document, "operations");
    let plural = [
        ("by_query_key", "query_keys"),
        ("by_key_header", "key_headers"),
        ("by_host_class", "host_classes"),
        ("by_error_code", "error_codes"),
    ];
    for (index, field) in plural {
        for key in keys(get(&document, index)) {
            for name in strings(get(get(&document, index), &key)) {
                assert!(
                    strings(get(get(operations, &name), field)).contains(&key),
                    "{index} lists {name} under {key}, but its {field} does not contain it"
                );
            }
        }
    }
}

/// The index builder narrows with its input rather than reproducing a constant.
///
/// Fed one entry per host class, `by_host_class` must contain exactly one operation per class —
/// not every operation under every class. The pinned model constrains no operation's host class
/// (`rustfs/gateway#3`), so a synthetic entry set is the only way to prove the inversion is a
/// function of what it is given rather than of the shape of the document.
#[test]
fn the_reverse_index_follows_narrowed_input() {
    let classes = ["Standard", "ObjectLambda", "S3Express", "Website"];
    let entries: Vec<Entry> = classes
        .iter()
        .map(|class| Entry {
            operation: format!("Op{class}"),
            method: "GET".to_owned(),
            path_shape: "/{Bucket}".to_owned(),
            query_keys: vec![class.to_lowercase()],
            key_headers: Vec::new(),
            host_classes: vec![(*class).to_owned()],
            error_codes: Vec::new(),
            precedence: 300,
        })
        .collect();
    let document = json::parse(&operations_json::render_entries(&entries)).expect("parseable");
    let by_host_class = get(&document, "by_host_class");
    assert_eq!(keys(by_host_class).len(), classes.len());
    for class in classes {
        assert_eq!(
            strings(get(by_host_class, class)),
            vec![format!("Op{class}")],
            "{class} must index exactly the entry that named it"
        );
    }
    assert_eq!(strings(get(get(&document, "by_precedence"), "300")).len(), classes.len());
}

/// An entry naming no fact at all still appears in the forward table and in no index.
#[test]
fn n_an_entry_with_no_wire_facts_indexes_nothing() {
    let entries = vec![Entry {
        operation: "Bare".to_owned(),
        method: "GET".to_owned(),
        path_shape: "/".to_owned(),
        query_keys: Vec::new(),
        key_headers: Vec::new(),
        host_classes: Vec::new(),
        error_codes: Vec::new(),
        precedence: 900,
    }];
    let document = json::parse(&operations_json::render_entries(&entries)).expect("parseable");
    assert_eq!(keys(get(&document, "operations")), vec!["Bare".to_owned()]);
    for index in ["by_query_key", "by_key_header", "by_host_class", "by_error_code"] {
        assert!(keys(get(&document, index)).is_empty(), "{index} must be empty");
    }
    assert_eq!(strings(get(get(&document, "by_method"), "GET")), vec!["Bare".to_owned()]);
}

/// The document is a pure function of the IR: two runs are byte-identical.
#[test]
fn the_document_is_deterministic() {
    let operations = artifacts().operations;
    assert_eq!(operations_json::render(&operations), operations_json::render(&operations));
}
