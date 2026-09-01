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

//! Request and response XML generation for structural unions.
//!
//! Responsible for: proving that a union field preserves its wrapper, selects exactly one modeled
//! child, delegates nested structures, and fails closed on absent, ambiguous or future variants.
//! NOT responsible for: operation routing or encryption semantics after decoding.
//! Upstream: lowered union shapes. Downstream: generated request and response codecs.

#![allow(clippy::expect_used, clippy::panic)]

use rustfs_gateway_model::ir::{Binding, Field, OperationIr, Shape, ShapeKind, ShapeXml, Type};

use super::codegen_tests::artifacts;
use crate::emit::codec::{decode, encode};
use crate::emit::dto::{DtoReport, registry::Registry, render};

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

fn synthetic_request_union_ir() -> OperationIr {
    let mut ir = operation("PutBucketTagging");
    let tag = operation("GetBucketTagging")
        .shapes
        .get("Tag")
        .cloned()
        .expect("GetBucketTagging carries the Tag shape");
    let payload = ir
        .input
        .iter_mut()
        .find(|field| field.binding == Binding::Payload)
        .expect("PutBucketTagging carries an XML payload");
    payload.ty = Type::Union("ObjectEncryption".to_owned());
    payload.required = true;
    ir.xml.request_root = Some("ObjectEncryption".to_owned());
    ir.shapes.insert("Tag".to_owned(), tag);
    ir.shapes.insert(
        "ObjectEncryption".to_owned(),
        Shape {
            kind: ShapeKind::Union,
            fields: vec![
                variant("SSEKMS", Type::Structure("Tag".to_owned())),
                variant("BucketKeyOnly", Type::Boolean),
            ],
            xml: ShapeXml {
                element_order: vec!["SSEKMS".to_owned(), "BucketKeyOnly".to_owned()],
                empty_value_policy: Vec::new(),
                attributes: Vec::new(),
            },
        },
    );
    ir
}

#[test]
fn a_required_union_payload_delegates_to_its_union_reader_without_fabricating_a_default() {
    let ir = synthetic_request_union_ir();
    let artifacts = artifacts();
    let body =
        decode::body(&ir, &artifacts.codec_rules, &artifacts.error_codes).expect("a required request union has an XML form");

    assert!(body.contains("read_object_encryption(&root"), "{body}");
    assert!(
        !body.contains("ObjectEncryption::default"),
        "a required union payload is never fabricated: {body}"
    );
}

#[test]
fn a_request_union_reader_requires_exactly_one_known_variant() {
    let ir = synthetic_request_union_ir();
    let shape = ir.shapes.get("ObjectEncryption").expect("the synthetic request union exists");
    let artifacts = artifacts();
    let reader = decode::shape_reader(
        &ir,
        "ObjectEncryption",
        shape,
        &artifacts.codec_rules,
        rustfs_gateway_model::UnknownElementPolicyValue::Reject,
    )
    .expect("the request union reader is generated");

    assert!(reader.contains("dto::ObjectEncryption::"), "{reader}");
    assert!(reader.contains("read_tag("), "{reader}");
    assert!(reader.contains("the structural union selects more than one variant"), "{reader}");
    assert!(reader.contains("the structural union selects no modeled variant"), "{reader}");
    assert!(reader.contains("the structural union contains an unknown variant"), "{reader}");
    assert!(
        !reader.contains("Default::default"),
        "a request union is selected, never defaulted: {reader}"
    );
}

#[test]
fn update_object_encryption_keeps_its_required_union_payload_and_exact_variant_set() {
    let ir = operation("UpdateObjectEncryption");
    let payload = ir
        .input
        .iter()
        .find(|field| field.binding == Binding::Payload)
        .expect("UpdateObjectEncryption carries its XML payload");
    assert!(payload.required, "the operation cannot run without an encryption selection");
    assert_eq!(payload.ty, Type::Union("ObjectEncryption".to_owned()));
    assert_eq!(ir.xml.request_root.as_deref(), Some("ObjectEncryption"));
    assert_eq!(ir.auth.action, "s3:UpdateObjectEncryption");

    let union = ir.shapes.get("ObjectEncryption").expect("the payload union is retained");
    assert_eq!(union.kind, ShapeKind::Union);
    assert_eq!(union.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["SSEKMS"]);
}

#[test]
fn a_required_union_input_requires_the_real_variant_at_builder_construction() {
    let ir = operation("UpdateObjectEncryption");
    let registry = Registry::collect(&[&ir]).expect("the operation has one coherent vocabulary");
    let mut report = DtoReport::default();
    let source = render::operation(&ir, &registry, &mut report);

    assert!(
        source.contains("pub fn builder(object_encryption: crate::ops::shapes::ObjectEncryption) -> InputBuilder"),
        "{source}"
    );
    assert!(
        !source.contains("impl Default for Input"),
        "the Input cannot fabricate a union variant: {source}"
    );
    assert!(
        !source.contains("InputBuilder::default()"),
        "the builder cannot omit the required union: {source}"
    );
    assert!(source.contains("pub object_encryption: crate::ops::shapes::ObjectEncryption"), "{source}");
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

#[test]
fn metrics_filter_emits_every_modeled_variant_without_a_default_payload() {
    let ir = operation("GetBucketMetricsConfiguration");
    let shape = ir
        .shapes
        .get("MetricsFilter")
        .expect("the pinned Metrics operation carries its filter union");
    let writer = encode::shape_writer(&ir, "MetricsFilter", shape).expect("the real response union writer is generated");

    assert!(writer.contains("dto::MetricsFilter::Prefix(v)"), "{writer}");
    assert!(writer.contains("dto::MetricsFilter::Tag(v)"), "{writer}");
    assert!(writer.contains("dto::MetricsFilter::AccessPointArn(v)"), "{writer}");
    assert!(writer.contains("dto::MetricsFilter::And(v)"), "{writer}");
    assert!(writer.contains("write_tag(writer, v)?;"), "{writer}");
    assert!(writer.contains("write_metrics_and_operator(writer, v)?;"), "{writer}");
    assert!(!writer.contains("Default::default"), "a required payload is never fabricated: {writer}");
}
