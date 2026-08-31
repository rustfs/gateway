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

//! Response XML generation for structural unions.
//!
//! Responsible for: proving that a union field preserves its wrapper, writes exactly the selected
//! modeled child, delegates nested structures, and fails closed on a future variant.
//! NOT responsible for: request-side union parsing or the Analytics route table.
//! Upstream: lowered union shapes. Downstream: generated response codecs.

#![allow(clippy::expect_used, clippy::panic)]

use rustfs_gateway_model::ir::{Binding, Field, OperationIr, Shape, ShapeKind, ShapeXml, Type};

use super::codegen_tests::artifacts;
use crate::emit::codec::encode;

fn operation(name: &str) -> OperationIr {
    artifacts()
        .operations
        .into_iter()
        .find(|ir| ir.operation == name)
        .unwrap_or_else(|| panic!("{name} is generated from the pinned model"))
}

fn variant(name: &str, ty: Type) -> Field {
    Field {
        name: name.to_owned(),
        wire_name: Some(name.to_owned()),
        required: false,
        binding: Binding::BodyXml,
        ty,
        hot: false,
        default: None,
        omit_when: None,
        missing_error: None,
        quirk_refs: Vec::new(),
    }
}

fn synthetic_filter_ir() -> OperationIr {
    let mut ir = operation("GetBucketVersioning");
    let tag = operation("GetBucketTagging")
        .shapes
        .get("Tag")
        .cloned()
        .expect("GetBucketTagging carries the Tag shape");
    let field = ir
        .output
        .iter_mut()
        .find(|field| field.name == "Status")
        .expect("GetBucketVersioning carries Status");
    field.wire_name = Some("Filter".to_owned());
    field.ty = Type::Union("SyntheticFilter".to_owned());
    ir.shapes.insert("Tag".to_owned(), tag);
    ir.shapes.insert(
        "SyntheticFilter".to_owned(),
        Shape {
            kind: ShapeKind::Union,
            fields: vec![
                variant("Prefix", Type::String),
                variant("Tag", Type::Structure("Tag".to_owned())),
            ],
            xml: ShapeXml {
                element_order: vec!["Prefix".to_owned(), "Tag".to_owned()],
                empty_value_policy: Vec::new(),
                attributes: Vec::new(),
            },
        },
    );
    ir
}

#[test]
fn a_union_body_member_keeps_its_wrapper_and_delegates_to_the_union_writer() {
    let body = encode::body(&synthetic_filter_ir(), &Default::default()).expect("a response union has an XML form");
    assert!(body.contains("writer.open(\"Filter\", None);"), "{body}");
    assert!(body.contains("write_synthetic_filter(&mut writer, v)?;"), "{body}");
    assert!(body.contains("writer.close();"), "{body}");
}

#[test]
fn a_union_writer_maps_each_variant_and_refuses_an_unknown_future_variant() {
    let ir = synthetic_filter_ir();
    let shape = ir.shapes.get("SyntheticFilter").expect("the synthetic union exists");
    let writer = encode::shape_writer(&ir, "SyntheticFilter", shape).expect("the response union writer is generated");

    assert!(
        writer.contains("dto::SyntheticFilter::Prefix(v) => writer.element(\"Prefix\", v.as_str()),"),
        "{writer}"
    );
    assert!(writer.contains("dto::SyntheticFilter::Tag(v) => {"), "{writer}");
    assert!(writer.contains("writer.open(\"Tag\", None);"), "{writer}");
    assert!(writer.contains("write_tag(writer, v)?;"), "{writer}");
    assert!(writer.contains("_ => {"), "{writer}");
    assert!(
        writer.contains("an output structural union holds a variant this codec does not know"),
        "{writer}"
    );
    assert!(
        !writer.contains("value.prefix"),
        "a union is matched, never projected as a struct: {writer}"
    );
    assert!(!writer.contains("value.tag"), "a union is matched, never projected as a struct: {writer}");
}

#[test]
fn analytics_filter_emits_every_modeled_variant_without_a_default_payload() {
    let ir = operation("GetBucketAnalyticsConfiguration");
    let shape = ir
        .shapes
        .get("AnalyticsFilter")
        .expect("the pinned Analytics operation carries its filter union");
    let writer = encode::shape_writer(&ir, "AnalyticsFilter", shape).expect("the real response union writer is generated");

    assert!(writer.contains("dto::AnalyticsFilter::Prefix(v)"), "{writer}");
    assert!(writer.contains("dto::AnalyticsFilter::Tag(v)"), "{writer}");
    assert!(writer.contains("dto::AnalyticsFilter::And(v)"), "{writer}");
    assert!(writer.contains("write_tag(writer, v)?;"), "{writer}");
    assert!(writer.contains("write_analytics_and_operator(writer, v)?;"), "{writer}");
    assert!(!writer.contains("Default::default"), "a required payload is never fabricated: {writer}");
}
