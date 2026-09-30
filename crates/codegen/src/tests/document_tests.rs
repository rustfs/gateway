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

//! The request-document shapes the RustFS profile reads (rustfs/gateway#1078): each legacy fact
//! `emit::codec::document` carries, held against the pinned model and against what it renders.
//!
//! Responsible for: every table of legacy facts still describing the model — a member it leaves
//! out is in the model, a member it relaxes is one the model requires, an attribute it requires is
//! one the model leaves optional, a member it adds is one the model lacks — so a model change that
//! makes a fact stale fails here; each fact reaching the rendered document; the skip-or-refuse rule
//! for unknown elements holding for every structure of every document; and the emitter refusing
//! what it has no form for.
//! NOT responsible for: reading a document (`rustfs-gateway-xml`'s bound tests) or proving each fact
//! against legacy RustFS (the `request_documents` differential in `rustfs-gateway-goldens`).
//! Upstream: `emit::codec::document`, the pinned model. Downstream: nothing.

use std::collections::BTreeSet;

use rustfs_gateway_model::ir::{Binding, Field, OperationIr, Shape, Type};

use super::codegen_tests::artifacts;
use crate::emit::codec::document::{
    EMPTY_BODIES, LEGACY_ONLY, LEGACY_ONLY_SHAPES, OPTIONAL, REQUIRED_ATTRIBUTES, module, payload_roots,
};

/// Every operation whose request carries an XML document.
const DOCUMENT_OPERATIONS: [&str; 24] = [
    "CompleteMultipartUpload",
    "CreateBucket",
    "DeleteObjects",
    "PutBucketAccelerateConfiguration",
    "PutBucketAcl",
    "PutBucketCors",
    "PutBucketEncryption",
    "PutBucketLifecycleConfiguration",
    "PutBucketLogging",
    "PutBucketNotificationConfiguration",
    "PutBucketReplication",
    "PutBucketRequestPayment",
    "PutBucketTagging",
    "PutBucketVersioning",
    "PutBucketWebsite",
    "PutObjectAcl",
    "PutObjectLegalHold",
    "PutObjectLockConfiguration",
    "PutObjectRetention",
    "PutObjectTagging",
    "PutPublicAccessBlock",
    "RestoreObject",
    "SelectObjectContent",
    "UpdateObjectEncryption",
];

fn roots(operations: &[OperationIr]) -> BTreeSet<String> {
    payload_roots(&operations.iter().collect::<Vec<_>>())
}

/// Every rendered `document` module, by operation.
fn modules(operations: &[OperationIr]) -> Vec<(String, String)> {
    let roots = roots(operations);
    operations
        .iter()
        .filter_map(|ir| {
            let rendered = module(ir, &roots).unwrap_or_else(|error| panic!("{}: {error}", ir.operation));
            rendered.map(|text| (ir.operation.clone(), text))
        })
        .collect()
}

fn module_of<'a>(modules: &'a [(String, String)], operation: &str) -> &'a str {
    modules
        .iter()
        .find(|(name, _)| name == operation)
        .map(|(_, text)| text.as_str())
        .unwrap_or_else(|| panic!("{operation} renders no document"))
}

/// Every rendered structure of a module, as `(name, its block)`.
fn blocks(module: &str) -> Vec<(&str, &str)> {
    const OPEN: &str = "Shape { name: \"";
    let starts: Vec<usize> = module.match_indices(OPEN).map(|(index, _)| index).collect();
    starts
        .iter()
        .enumerate()
        .map(|(position, start)| {
            let end = starts.get(position + 1).copied().unwrap_or(module.len());
            let block = &module[*start..end];
            let name = &block[OPEN.len()..];
            (&name[..name.find('"').expect("a closing quote")], block)
        })
        .collect()
}

fn block<'a>(module: &'a str, shape: &str) -> &'a str {
    blocks(module)
        .into_iter()
        .find(|(name, _)| *name == shape)
        .map(|(_, block)| block)
        .unwrap_or_else(|| panic!("no structure {shape} rendered in\n{module}"))
}

/// The rendered `Member { .. }` literal for `element` in a structure's block.
fn member_line<'a>(block: &'a str, element: &str) -> Option<&'a str> {
    block
        .lines()
        .find(|line| line.contains(&format!("Member {{ element: {element:?},")))
}

fn model_shape<'a>(operations: &'a [OperationIr], name: &str) -> &'a Shape {
    operations
        .iter()
        .find_map(|ir| ir.shapes.get(name))
        .unwrap_or_else(|| panic!("the model has no structure {name}"))
}

fn model_field<'a>(operations: &'a [OperationIr], shape: &str, member: &str) -> &'a Field {
    model_shape(operations, shape)
        .fields
        .iter()
        .find(|field| field.name == member)
        .unwrap_or_else(|| panic!("the model's {shape} has no member {member}: the fact is stale"))
}

fn element(field: &Field) -> String {
    field.wire_name.clone().unwrap_or_else(|| field.name.clone())
}

/// Every operation that reaches `shape`, with its module.
fn reaching<'a>(modules: &'a [(String, String)], shape: &str) -> Vec<(&'a str, &'a str)> {
    modules
        .iter()
        .filter(|(_, text)| blocks(text).iter().any(|(name, _)| *name == shape))
        .map(|(operation, text)| (operation.as_str(), text.as_str()))
        .collect()
}

fn operation<'a>(operations: &'a [OperationIr], name: &str) -> &'a OperationIr {
    operations
        .iter()
        .find(|ir| ir.operation == name)
        .unwrap_or_else(|| panic!("no operation {name}"))
}

/// Positive — every operation whose request carries an XML document renders its shape, and no
/// other operation renders one.
#[test]
fn every_operation_with_a_request_document_renders_one_and_no_other_does() {
    let artifacts = artifacts();
    let rendered: BTreeSet<String> = modules(&artifacts.operations).into_iter().map(|(name, _)| name).collect();
    let expected: BTreeSet<String> = DOCUMENT_OPERATIONS.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(rendered, expected);
}

/// Negative — an element a structure does not know is skipped only inside a structure that is some
/// operation's whole document, wherever that structure appears, and refused inside every other.
#[test]
fn n_only_a_payload_root_skips_an_unknown_element() {
    let artifacts = artifacts();
    let roots = roots(&artifacts.operations);
    let modules = modules(&artifacts.operations);
    let mut refusing = 0;
    for (operation, text) in &modules {
        for (name, block) in blocks(text) {
            if block.contains("Content::Choice(") {
                continue;
            }
            let skips = block.contains("unknown: Unknown::Skip");
            let expected = roots.contains(name) || name == operation;
            assert_eq!(skips, expected, "{operation}: {name}");
            assert!(skips || block.contains("unknown: Unknown::Refuse"), "{operation}: {name}");
            refusing += usize::from(!skips);
        }
    }
    assert!(refusing >= 50, "only {refusing} refusing structures: the walk stopped reaching them");
    let lifecycle = module_of(&modules, "PutBucketLifecycleConfiguration");
    assert!(block(lifecycle, "BucketLifecycleConfiguration").contains("unknown: Unknown::Skip"));
    assert!(block(lifecycle, "LifecycleRule").contains("unknown: Unknown::Refuse"));
    assert!(roots.contains("Tagging") && !roots.contains("Tag"), "{roots:?}");
}

/// Negative — the Object Lock event hold, which legacy RustFS does not know, is read all the same
/// wherever the model places it, so a request naming it reaches the seam and is refused there
/// (rd-put-0009) instead of being handed over without the hold its client asked for.
#[test]
fn n_the_event_hold_legacy_rustfs_does_not_know_is_read_so_the_seam_refuses_it() {
    let artifacts = artifacts();
    let modules = modules(&artifacts.operations);
    for (shape, member) in [
        ("DefaultRetention", "DefaultEventHold"),
        ("ObjectLockRetention", "EventHold"),
        ("ObjectLockRetention", "EventHoldDuration"),
    ] {
        let element = element(model_field(&artifacts.operations, shape, member));
        let reached = reaching(&modules, shape);
        assert!(!reached.is_empty(), "no document reaches {shape}");
        for (operation, text) in reached {
            let line = member_line(block(text, shape), &element).unwrap_or_else(|| panic!("{operation}: {shape}.{member}"));
            assert!(line.contains("kept: true"), "{operation}: {line}");
        }
    }
}

/// Negative — a member legacy RustFS reads as optional is one the model requires, and is rendered
/// optional; a required member outside the table stays required.
#[test]
fn n_a_member_legacy_rustfs_reads_as_optional_is_one_the_model_requires() {
    let artifacts = artifacts();
    let modules = modules(&artifacts.operations);
    for (shape, member) in OPTIONAL {
        let field = model_field(&artifacts.operations, shape, member);
        assert!(field.required, "the model no longer requires {shape}.{member}: the fact is stale");
        let element = element(field);
        for (operation, text) in reaching(&modules, shape) {
            let line = member_line(block(text, shape), &element).unwrap_or_else(|| panic!("{operation}: {shape}.{member}"));
            assert!(line.contains("required: false"), "{operation}: {line}");
        }
    }
    let lifecycle = module_of(&modules, "PutBucketLifecycleConfiguration");
    let status = member_line(block(lifecycle, "LifecycleRule"), "Status").expect("the rule's Status");
    assert!(status.contains("required: true"), "{status}");
}

/// Negative — the grantee's type attribute is required by legacy RustFS and not by the model, and
/// is rendered required, matched by its literal spelling.
#[test]
fn n_the_grantee_type_attribute_is_rendered_required() {
    let artifacts = artifacts();
    let modules = modules(&artifacts.operations);
    for (shape, member) in REQUIRED_ATTRIBUTES {
        let field = model_field(&artifacts.operations, shape, member);
        assert!(!field.required, "the model requires {shape}.{member} itself: the fact is stale");
        let reached = reaching(&modules, shape);
        assert!(!reached.is_empty(), "no document reaches {shape}");
        for (operation, text) in reached {
            assert!(
                block(text, shape).contains(
                    "attribute: Some(Attribute { key: \"xsi:type\", name: \"type\", namespace: \
                     \"http://www.w3.org/2001/XMLSchema-instance\", required: true })"
                ),
                "{operation}: {}",
                block(text, shape)
            );
        }
    }
}

/// Negative — each member only legacy RustFS reads is absent from the model, and is rendered read
/// and then left out of the tree (`kept: false`), its structure refusing an unknown element.
#[test]
fn n_a_member_only_legacy_rustfs_reads_is_absent_from_the_model_and_not_kept() {
    let artifacts = artifacts();
    let modules = modules(&artifacts.operations);
    for extra in LEGACY_ONLY {
        let shape = model_shape(&artifacts.operations, extra.shape);
        assert!(
            shape.fields.iter().all(|field| element(field) != extra.element),
            "the model carries {}.{}: the fact is stale",
            extra.shape,
            extra.element
        );
        assert!(
            LEGACY_ONLY_SHAPES.iter().any(|(name, _)| *name == extra.value),
            "{} names an unrecorded structure",
            extra.value
        );
        for (operation, text) in reaching(&modules, extra.shape) {
            let line = member_line(block(text, extra.shape), extra.element)
                .unwrap_or_else(|| panic!("{operation}: {}.{}", extra.shape, extra.element));
            assert!(line.contains("kept: false") && line.contains("required: false"), "{operation}: {line}");
        }
    }
    let create = module_of(&modules, "CreateBucket");
    for (name, members) in LEGACY_ONLY_SHAPES {
        assert!(LEGACY_ONLY.iter().any(|extra| extra.value == *name), "{name} is recorded and unused");
        let block = block(create, name);
        assert!(block.contains("unknown: Unknown::Refuse"), "{block}");
        for member in *members {
            assert!(
                member_line(block, member).is_some_and(|line| line.contains("kept: true")),
                "{name}.{member}"
            );
        }
    }
}

/// Negative — an empty body is what the table names for exactly its operations (a malformed
/// document, or no document), and a missing body for every other document.
#[test]
fn n_an_empty_body_is_what_the_table_names_for_exactly_its_operations() {
    let artifacts = artifacts();
    let modules = modules(&artifacts.operations);
    for (operation, empty) in EMPTY_BODIES {
        assert!(DOCUMENT_OPERATIONS.contains(operation), "{operation} reads no document");
        assert!(["Refused", "Absent"].contains(empty), "{operation}: {empty}");
    }
    for (operation, text) in &modules {
        let empty = EMPTY_BODIES
            .iter()
            .find(|(name, _)| name == operation)
            .map_or("Missing", |(_, empty)| *empty);
        for variant in ["Missing", "Refused", "Absent"] {
            assert_eq!(
                text.contains(&format!("empty: EmptyBody::{variant}")),
                variant == empty,
                "{operation}: {variant}"
            );
        }
    }
    let lock = module_of(&modules, "PutObjectLockConfiguration");
    assert!(lock.contains("empty: EmptyBody::Absent"), "{lock}");
}

/// Negative — a member whose type the reading has no form for fails generation rather than being
/// left out of the document.
#[test]
fn n_a_member_the_reading_has_no_form_for_fails_generation() {
    let artifacts = artifacts();
    let roots = roots(&artifacts.operations);
    let mut ir = operation(&artifacts.operations, "PutBucketTagging").clone();
    let tag = ir.shapes.get_mut("Tag").expect("the tag structure");
    tag.fields[0].ty = Type::Map {
        key: Box::new(Type::String),
        value: Box::new(Type::String),
    };
    let error = module(&ir, &roots).expect_err("a map member");
    assert!(error.contains("has a type legacy RustFS's reading has no form for"), "{error}");
}

/// Negative — a structure the IR does not hold, an attribute whose prefix no declaration binds, and
/// operation-level members without a root each fail generation.
#[test]
fn n_an_incomplete_shape_fails_generation() {
    let artifacts = artifacts();
    let roots = roots(&artifacts.operations);

    let mut missing = operation(&artifacts.operations, "PutBucketTagging").clone();
    missing.shapes.remove("Tag");
    let error = module(&missing, &roots).expect_err("a missing structure");
    assert!(error.contains("is not in the IR"), "{error}");

    let mut undeclared = operation(&artifacts.operations, "PutBucketAcl").clone();
    undeclared
        .shapes
        .get_mut("Grantee")
        .expect("the grantee structure")
        .xml
        .attributes
        .retain(|attribute| !attribute.name.starts_with("xmlns:"));
    let error = module(&undeclared, &roots).expect_err("an undeclared prefix");
    assert!(error.contains("declares no `xmlns:"), "{error}");

    let mut rootless = operation(&artifacts.operations, "PutBucketTagging").clone();
    for field in &mut rootless.input {
        if field.binding == Binding::Payload {
            field.binding = Binding::BodyXml;
        }
    }
    rootless.xml.request_root = None;
    let error = module(&rootless, &roots).expect_err("operation-level members without a root");
    assert!(error.contains("operation-level members and no request root"), "{error}");
}
