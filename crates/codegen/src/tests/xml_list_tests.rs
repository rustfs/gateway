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

//! Which of a list's two element names encloses the other, on both sides of the codec.
//!
//! Responsible for: the wrapper-versus-entry resolution every list-typed member goes through, the
//! one pinned wrapped list the model contains (`ListBuckets`), and a second, synthetic one — the
//! defect was a property of the emitter, so a suite that only pins the single operation that
//! happened to expose it re-opens the moment AWS adds another.
//! NOT responsible for: what the bytes mean to a client, which is `conformance/cases/list`.
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.
//!
//! # Why a synthetic operation
//!
//! `ListBuckets` is today the only wrapped list in the pinned model, so it is the only wire
//! evidence available and it cannot demonstrate that the rule is general. The synthetic cases
//! below take a real lowered IR and give one member a wrapped list whose two names are spelled
//! nothing like each other, which is what makes a swap visible rather than plausible.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use rustfs_gateway_model::ir::{Binding, Field, OperationIr, Type};

use super::codegen_tests::artifacts;
use crate::emit::codec::{decode, encode, list_elements};

fn ir(operation: &str) -> OperationIr {
    artifacts()
        .operations
        .into_iter()
        .find(|ir| ir.operation == operation)
        .unwrap_or_else(|| panic!("{operation} is generated from the pinned model"))
}

/// Replaces one output member's wire name and type, leaving every other fact about the operation
/// alone — `element_order` keys on the member name, so the member keeps its position.
fn retype_output(ir: &mut OperationIr, member: &str, wire: &str, ty: Type) {
    let field: &mut Field = ir
        .output
        .iter_mut()
        .find(|f| f.name == member)
        .unwrap_or_else(|| panic!("{member} is an output member"));
    assert_eq!(field.binding, Binding::BodyXml, "{member} must already be a body member");
    field.wire_name = Some(wire.to_owned());
    field.ty = ty;
}

/// The byte offset of a generated line, so two lines can be asserted in order rather than merely
/// both present — the shipped defect emitted both names and only their nesting was wrong.
fn at(text: &str, needle: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("the generated body does not contain `{needle}`:\n{text}"))
}

#[test]
fn a_flattened_list_repeats_the_field_s_own_wire_name_and_has_no_wrapper() {
    let names = list_elements(true, None, "Contents");
    assert_eq!(names.wrapper, None, "a flattened list has no enclosing element");
    assert_eq!(names.entry, "Contents");
}

#[test]
fn a_wrapped_list_encloses_the_member_name_in_the_field_s_wire_name() {
    let names = list_elements(false, Some("Bucket"), "Buckets");
    assert_eq!(
        names.wrapper.as_deref(),
        Some("Buckets"),
        "the enclosing element is the field's own wire name, never the IR's misnamed `wrapper_name`"
    );
    assert_eq!(names.entry, "Bucket", "the repeated element is the list member's xmlName");
}

#[test]
fn a_wrapped_list_whose_model_names_no_member_falls_back_to_the_smithy_default() {
    let names = list_elements(false, None, "Values");
    assert_eq!(names.wrapper.as_deref(), Some("Values"));
    assert_eq!(names.entry, "member", "Smithy's default member spelling, not a repeat of the wrapper");
}

#[test]
fn the_pinned_wrapped_list_writes_the_wrapper_outside_the_entries() {
    let body = encode::body(&ir("ListBuckets"), &Default::default()).expect("ListBuckets encodes");
    let wrapper = at(&body, "writer.open(\"Buckets\", None);");
    let entry = at(&body, "writer.open(\"Bucket\", None);");
    assert!(
        wrapper < entry,
        "AWS writes <Buckets><Bucket>…</Bucket></Buckets>; the inverted nesting is what no SDK could parse:\n{body}"
    );
}

#[test]
fn a_second_wrapped_list_of_structures_nests_the_same_way() {
    let mut ir = ir("ListObjectsV2");
    let entries = Type::List {
        member: Box::new(Type::Structure("Object".to_owned())),
        flattened: false,
        wrapper_name: Some("Entry".to_owned()),
    };
    retype_output(&mut ir, "Contents", "Entries", entries);
    let body = encode::body(&ir, &Default::default()).expect("the retyped operation encodes");
    let wrapper = at(&body, "writer.open(\"Entries\", None);");
    let entry = at(&body, "writer.open(\"Entry\", None);");
    assert!(wrapper < entry, "the wrapper encloses the entries here too:\n{body}");
}

#[test]
fn a_second_wrapped_list_of_scalars_nests_the_same_way() {
    // `ListBuckets` rather than a listing: retyping a member of an operation that declares
    // `url_encoded_fields` would move a path out from under the member it names, and `super::url`
    // refuses that — correctly, but it is a different test than this one.
    let mut ir = ir("ListBuckets");
    let values = Type::List {
        member: Box::new(Type::String),
        flattened: false,
        wrapper_name: Some("Value".to_owned()),
    };
    retype_output(&mut ir, "Prefix", "Values", values);
    let body = encode::body(&ir, &Default::default()).expect("the retyped operation encodes");
    let wrapper = at(&body, "writer.open(\"Values\", None);");
    let entry = at(&body, "writer.element(\"Value\", v.as_str());");
    assert!(wrapper < entry, "a scalar list is wrapped by the same rule:\n{body}");
}

#[test]
fn n_a_flattened_list_gains_no_wrapper_when_the_inversion_is_fixed() {
    // The over-correction this guards: swapping the two names at the call site instead of
    // resolving them would give every flattened list an enclosing element it must not have.
    let body = encode::body(&ir("ListObjectsV2"), &Default::default()).expect("ListObjectsV2 encodes");
    assert!(
        body.contains("writer.open(\"Contents\", None);"),
        "a flattened list repeats the field's own wire name:\n{body}"
    );
    assert!(
        !body.contains("writer.open(\"member\", None);"),
        "no flattened list may fall back to the Smithy member spelling:\n{body}"
    );
}

#[test]
fn the_reader_of_a_wrapped_list_descends_through_the_same_two_names() {
    let mut ir = ir("DeleteObjects");
    let objects = Type::List {
        member: Box::new(Type::Structure("ObjectIdentifier".to_owned())),
        flattened: false,
        wrapper_name: Some("Entry".to_owned()),
    };
    let shape = ir.shapes.get_mut("Delete").expect("DeleteObjects carries a Delete shape");
    let field = shape
        .fields
        .iter_mut()
        .find(|f| f.name == "Objects")
        .expect("Delete carries an Objects member");
    field.wire_name = Some("Entries".to_owned());
    field.ty = objects;
    let shape = ir.shapes.get("Delete").expect("still there").clone();
    let reader = decode::shape_reader(
        &ir,
        "Delete",
        &shape,
        &Default::default(),
        rustfs_gateway_model::UnknownElementPolicyValue::Skip,
    )
    .expect("the shape reads");
    assert!(
        reader.contains("node.child(\"Entries\").into_iter().flat_map(|w| w.children_named(\"Entry\"))"),
        "the reader descends wrapper first, entry second — the same order the writer emits:\n{reader}"
    );
}

/// One generated file's bytes, by the suffix of its path.
fn body(suffix: &str) -> String {
    artifacts()
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with(suffix))
        .map(|(_, body)| body.clone())
        .unwrap_or_else(|| panic!("no generated file ends with {suffix}"))
}

/// Negative — a **wrapped** required list is refused for a missing wrapper, never for an empty one.
///
/// `<TagSet></TagSet>` is present and empty at the same time, so the two observations a flattened
/// list cannot tell apart are two different documents here, and only the absent wrapper is a
/// missing member. Reading the entry count refused a document the encoder on the other side of
/// this same shape writes for every untagged object (rustfs/backlog#1717).
///
/// Both directions, on the generated bytes, because the failure this guards is somebody restoring
/// the entry-count reading at one of the three wrapped readers and leaving the other two alone —
/// and because the flattened half has to be pinned in the same test or the fix would look like a
/// licence to drop the refusal everywhere.
#[test]
fn n_a_wrapped_required_list_refuses_an_absent_wrapper_and_not_an_empty_one() {
    let wrapped = [
        "codec/ops/put_bucket_tagging.rs",
        "codec/ops/put_object_tagging.rs",
        "codec/ops/restore_object.rs",
    ];
    for path in wrapped {
        let text = body(path);
        assert!(
            text.contains("if node.child(\"TagSet\").is_none() {"),
            "{path}: a wrapped required list is missing only when its wrapper is"
        );
        assert!(
            !text.contains("if shape.tag_set.is_empty() {"),
            "{path}: an empty <TagSet/> is a document AWS accepts and this encoder writes"
        );
    }
    assert!(
        body("codec/ops/delete_objects.rs").contains("if shape.objects.is_empty() {"),
        "a flattened required list has no wrapper to look for, so no entries is the member's absence"
    );
}
