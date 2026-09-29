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

//! Synthesized members of nested shapes, and synthesized shapes, against the miniature model.
//!
//! Responsible for: the `[[shape.<Shape>.field]] synthesize = true` and `[shape.<Shape>]
//! synthesize = true` rules of `lower::shape_members` — position, wire name, the three composite
//! spellings, and every refusal.
//! NOT responsible for: model-member lowering (`lower_tests`).
//! Upstream: `lower_tests`' miniature model and loader. Downstream: the repository verification gate.

use super::lower_tests::{MINI_OVERLAY, load};
use crate::ir::{Binding, Type};

fn with(extra: &str) -> crate::Result<crate::Lowered> {
    load(&format!("{MINI_OVERLAY}\n{extra}"))
}

const FLAG: &str = r#"
[[shape.Item.field]]
name = "Flag"
synthesize = true
type = "Boolean"
"#;

const MARKER: &str = r#"
[[shape.Item.field]]
name = "Marker"
synthesize = true
type = "Structure:Marker"

[[shape.Item.field]]
name = "Excluded"
synthesize = true
wire_name = "ExcludedPrefixes"
type = "FlattenedList:Prefix"

[shape.Marker]
synthesize = true

[[shape.Marker.field]]
name = "Status"
synthesize = true
type = "StringEnum:Enabled|Disabled"

[shape.Prefix]
synthesize = true

[[shape.Prefix.field]]
name = "Prefix"
synthesize = true
type = "String"
"#;

#[test]
fn a_synthesized_field_joins_a_model_shape_after_its_members() {
    let lowered = with(FLAG).expect("lowers");
    let item = &lowered.operations[0].shapes["Item"];
    let names: Vec<_> = item.fields.iter().map(|field| field.name.as_str()).collect();
    assert_eq!(names, ["Key", "Flag"]);
    let flag = &item.fields[1];
    assert_eq!(
        (flag.ty.clone(), flag.binding.clone(), flag.wire_name.as_deref()),
        (Type::Boolean, Binding::BodyXml, Some("Flag"))
    );
    assert!(!flag.required);
    assert_eq!(item.xml.element_order, ["Key", "Flag"]);
}

#[test]
fn a_synthesized_field_can_be_placed_after_a_named_member() {
    let lowered = with(&format!(
        "{FLAG}\n[[shape.Item.field]]\nname = \"First\"\nsynthesize = true\nafter = \"Key\"\ntype = \"Integer\"\n"
    ))
    .expect("lowers");
    let names: Vec<_> = lowered.operations[0].shapes["Item"]
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect();
    assert_eq!(names, ["Key", "First", "Flag"]);
}

#[test]
fn synthesized_shapes_are_collected_through_structure_and_flattened_list_members() {
    let lowered = with(MARKER).expect("lowers");
    let shapes = &lowered.operations[0].shapes;
    let item = &shapes["Item"];
    let marker = item.fields.iter().find(|field| field.name == "Marker").expect("Marker");
    assert_eq!(marker.ty, Type::Structure("Marker".to_owned()));
    let excluded = item.fields.iter().find(|field| field.name == "Excluded").expect("Excluded");
    assert_eq!(excluded.wire_name.as_deref(), Some("ExcludedPrefixes"));
    assert_eq!(
        excluded.ty,
        Type::List {
            member: Box::new(Type::Structure("Prefix".to_owned())),
            flattened: true,
            member_name: None,
        }
    );
    assert_eq!(
        shapes["Marker"].fields[0].ty,
        Type::StringEnum(vec!["Enabled".to_owned(), "Disabled".to_owned()])
    );
    assert_eq!(shapes["Marker"].xml.element_order, ["Status"]);
    assert_eq!(shapes["Prefix"].fields[0].ty, Type::String);
}

#[test]
fn n_a_shape_neither_in_the_model_nor_synthesized_is_refused() {
    let error = with("[[shape.Item.field]]\nname = \"Marker\"\nsynthesize = true\ntype = \"Structure:Missing\"\n")
        .map(|_| ())
        .expect_err("an unknown nested shape");
    assert!(error.to_string().contains("unknown nested shape `Missing`"), "{error}");
}

#[test]
fn n_a_synthesized_shape_with_a_model_style_field_is_refused() {
    let error = with("[[shape.Item.field]]\nname = \"Marker\"\nsynthesize = true\ntype = \"Structure:Marker\"\n\n[shape.Marker]\nsynthesize = true\n\n[[shape.Marker.field]]\nname = \"Status\"\ntype = \"String\"\n")
        .map(|_| ())
        .expect_err("a non-synthesized field on a synthesized shape");
    assert!(error.to_string().contains("must be too"), "{error}");
}

#[test]
fn n_a_synthesized_shape_without_fields_is_refused() {
    let error = with("[[shape.Item.field]]\nname = \"Marker\"\nsynthesize = true\ntype = \"Structure:Marker\"\n\n[shape.Marker]\nsynthesize = true\n")
        .map(|_| ())
        .expect_err("an empty synthesized shape");
    assert!(error.to_string().contains("has no fields"), "{error}");
}

#[test]
fn n_a_synthesized_field_without_a_type_or_with_an_empty_composite_is_refused() {
    for (spelling, needle) in [
        ("", "needs a type"),
        ("type = \"Structure:\"", "names nothing"),
        ("type = \"FlattenedList:\"", "names nothing"),
        ("type = \"StringEnum:A||B\"", "names nothing"),
        ("type = \"Nonsense\"", "unknown scalar spelling"),
    ] {
        let error = with(&format!("[[shape.Item.field]]\nname = \"Odd\"\nsynthesize = true\n{spelling}\n"))
            .map(|_| ())
            .expect_err(spelling);
        assert!(error.to_string().contains(needle), "{spelling}: {error}");
    }
}

#[test]
fn n_a_synthesized_field_placed_after_a_missing_member_is_refused() {
    let error = with("[[shape.Item.field]]\nname = \"Odd\"\nsynthesize = true\nafter = \"Nope\"\ntype = \"String\"\n")
        .map(|_| ())
        .expect_err("a missing anchor");
    assert!(error.to_string().contains("names no field"), "{error}");
}

#[test]
fn n_an_unsynthesized_field_naming_no_member_is_still_refused() {
    let error = with("[[shape.Item.field]]\nname = \"Odd\"\ntype = \"String\"\n")
        .map(|_| ())
        .expect_err("a typo");
    assert!(error.to_string().contains("not one of its members"), "{error}");
}
