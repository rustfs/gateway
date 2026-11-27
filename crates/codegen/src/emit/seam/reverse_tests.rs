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

//! Tests for the seam generator's reverse direction: the s3s input as the gateway input and the
//! gateway output as the s3s output (rustfs/backlog#2759).
//!
//! Responsible for: proving the rules that are role-specific in the first direction — supplied,
//! legacy-only, nested and absent-as-empty members, the SSE-C secret — render the right text the
//! other way round, that the leaf pairs the reverse needs exist, that the rendered files name
//! `s3s` and `leaf` relative to their mount rather than to one seam revision, and that the error
//! code census lists every code with its status.
//! NOT responsible for: whether the text compiles, which the types crate proves against the real
//! s3s. Upstream: [`super::render`], [`super::census`]. Downstream: none; test-only.

use rustfs_gateway_model::ir::{ETagRender, Shape, ShapeKind, ShapeXml, TimestampFormat, Type};

use super::backward::{self, LegacyMembers};
use super::expr::{ShapeDirection, Side};
use super::facts::S3sFacts;
use super::render::Forward;
use super::tests::{ctx, facts, field};
use super::{census, files, render};

#[test]
fn a_supplied_member_converts_back_into_the_gateway_member() {
    // Forward, `CopyObjectInput.copy_source` is a parameter the adapter builds from the authorized
    // resource; backward, the s3s value has exactly one text spelling and the gateway member holds it.
    let facts = facts("struct CopyObjectInput\n  bucket: String\n  copy_source: CopySource\n");
    let fields = [
        field("Bucket", Type::BucketName, true),
        field("CopySource", Type::String, true),
    ];
    let text = backward::backward_struct(&ctx(&facts), "CopyObjectInput", &fields, "G", "input", Side::Input).expect("renders");
    assert!(
        text.contains("copy_source: { let x = copy_source; leaf::copy_source_from_s3s(&x) },"),
        "{text}"
    );
}

#[test]
fn required_copy_header_converts_decoded_fields_without_a_wire_round_trip() {
    use rustfs_gateway_model::ir::Binding;
    for operation in ["CopyObject", "UploadPartCopy"] {
        let owner = format!("{operation}Input");
        let facts = facts(&format!("struct {owner}\n  copy_source: CopySource\n"));
        let mut source = field("CopySource", Type::String, true);
        source.wire_name = Some("x-amz-copy-source".to_owned());
        for (binding, required, wire, typed) in [
            (Binding::Header, true, "x-amz-copy-source", true),
            (Binding::Header, true, "X-Amz-Copy-Source", true),
            (Binding::Header, false, "x-amz-copy-source", false),
            (Binding::BodyXml, true, "x-amz-copy-source", false),
            (Binding::Query, true, "x-amz-copy-source", false),
            (Binding::Header, true, "different-header", false),
        ] {
            source.binding = binding.clone();
            source.required = required;
            source.wire_name = Some(wire.to_owned());
            let text =
                backward::backward_struct(&ctx(&facts), &owner, &[source.clone()], "G", "input", Side::Input).expect("renders");
            assert_eq!(
                text.contains("super::super::copy_source::from_s3s(x)"),
                typed,
                "{owner}: {binding:?}/{required}/{wire}"
            );
        }
    }
}

#[test]
fn n_a_supplied_member_without_a_backward_pair_fails_generation() {
    let facts = facts("struct CopyObjectInput\n  copy_source: Timestamp\n");
    let errors = backward::backward_struct(
        &ctx(&facts),
        "CopyObjectInput",
        &[field("CopySource", Type::String, true)],
        "G",
        "input",
        Side::Input,
    )
    .expect_err("no pair");
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].starts_with("CopyObjectInput.copy_source: no s3s → gateway conversion"),
        "{errors:?}"
    );
}

#[test]
fn n_a_legacy_query_member_set_is_refused_by_name_where_nothing_can_hand_it_back() {
    let facts = facts("struct CopyObjectInput\n  bucket: String\n  version_id: Option<String>\n");
    let text = backward::backward_struct(
        &ctx(&facts),
        "CopyObjectInput",
        &[field("Bucket", Type::BucketName, true)],
        "G",
        "input",
        Side::Input,
    )
    .expect("renders");
    assert!(text.contains("        version_id,\n"), "the member is bound, never `_`: {text}");
    assert!(
        text.contains("    if version_id.is_some() {\n        return Err(ConversionError { field: \"version_id\", reason: \"a member only the legacy decoder reads and no gateway member holds, refused rather than dropped\" });\n    }"),
        "{text}"
    );
}

#[test]
fn a_legacy_query_member_is_handed_back_beside_the_gateway_input() {
    let facts = facts("struct CopyObjectInput\n  bucket: String\n  version_id: Option<String>\n");
    let fields = [field("Bucket", Type::BucketName, true)];
    let text = backward::backward_struct_with(
        &ctx(&facts),
        "CopyObjectInput",
        &fields,
        "G",
        "input",
        LegacyMembers::HandBack,
        Side::Input,
    )
    .expect("renders");
    assert!(text.contains("        version_id,\n"), "{text}");
    assert!(
        text.ends_with("    Ok((G {\n        bucket: { let x = bucket; leaf::bucket_name(\"bucket\", x)? },\n    }, LegacyInput { version_id }))\n"),
        "{text}"
    );
    assert!(!text.contains("return Err"), "nothing is refused: {text}");
}

#[test]
fn a_legacy_bool_header_is_handed_back_and_refused_where_it_cannot_be() {
    let facts = facts("struct DeleteBucketInput\n  bucket: String\n  force_delete: Option<bool>\n");
    let fields = [field("Bucket", Type::BucketName, true)];
    let handed = backward::backward_struct_with(
        &ctx(&facts),
        "DeleteBucketInput",
        &fields,
        "G",
        "input",
        LegacyMembers::HandBack,
        Side::Input,
    )
    .expect("renders");
    assert!(handed.contains("LegacyInput { force_delete }"), "{handed}");
    let refused =
        backward::backward_struct(&ctx(&facts), "DeleteBucketInput", &fields, "G", "input", Side::Input).expect("renders");
    assert!(refused.contains("if force_delete.is_some() {"), "{refused}");
    assert!(refused.contains("field: \"force_delete\""), "{refused}");
    assert_eq!(
        render::legacy_members("DeleteBucketInput", &facts.structs["DeleteBucketInput"])
            .iter()
            .map(|(member, ty)| (member.to_string(), render::type_text(ty).expect("spelled")))
            .collect::<Vec<_>>(),
        [("force_delete".to_owned(), "Option<bool>".to_owned())]
    );
}

#[test]
fn n_a_legacy_member_of_a_type_the_hand_back_cannot_spell_fails_generation() {
    let facts = facts("struct T\n  rules: Option<Vec<String>>\n");
    assert!(render::type_text(&facts.structs["T"][0].1).is_err());
}

#[test]
fn a_nested_member_nests_forward() {
    let facts = facts(
        "struct CopyObjectOutput\n  copy_object_result: Option<struct CopyObjectResult>\n  version_id: Option<String>\nstruct CopyObjectResult\n  e_tag: Option<ETag>\n  last_modified: Option<Timestamp>\n",
    );
    let fields = [
        field("ETag", Type::ETag(ETagRender::XmlQuoted), false),
        field("LastModified", Type::Timestamp(TimestampFormat::Iso8601), false),
        field("VersionId", Type::String, false),
    ];
    let text = render::forward_struct(&ctx(&facts), "CopyObjectOutput", &fields, "output").expect("renders");
    assert!(text.contains("copy_object_result: Some(s3s::dto::CopyObjectResult {"), "{text}");
    assert!(
        text.contains("e_tag: output.e_tag.map(|x| -> Result<_, ConversionError> { Ok(leaf::etag_to_s3s(&x)) }).transpose()?,"),
        "{text}"
    );
    assert!(text.contains("last_modified: output.last_modified.map("), "{text}");
    assert!(text.contains("leaf::timestamp_to_s3s(\"last_modified\", x)?"), "{text}");
}

#[test]
fn n_a_nested_member_nobody_fills_fails_generation() {
    let facts = facts(
        "struct CopyObjectOutput\n  copy_object_result: Option<struct CopyObjectResult>\nstruct CopyObjectResult\n  e_tag: Option<ETag>\n  size: Option<i64>\n",
    );
    let errors = render::forward_struct(
        &ctx(&facts),
        "CopyObjectOutput",
        &[field("ETag", Type::ETag(ETagRender::XmlQuoted), false)],
        "output",
    )
    .expect_err("an unfilled nested member");
    assert_eq!(errors, ["CopyObjectResult.size: a nested s3s member no gateway member fills"]);
}

#[test]
fn an_absent_as_empty_member_crosses_forward_as_none_when_empty() {
    let facts = facts("struct HeadBucketOutput\n  bucket_region: Option<String>\n");
    let text = render::forward_struct(&ctx(&facts), "HeadBucketOutput", &[field("BucketRegion", Type::String, true)], "output")
        .expect("renders");
    assert!(
        text.contains("bucket_region: { let x = output.bucket_region; if x.is_empty() { None } else { Some(x) } },"),
        "{text}"
    );
}

#[test]
fn a_secret_member_is_rewrapped_backward() {
    let facts = facts("struct T\n  sse_customer_key: Option<String>\n");
    let text = backward::backward_struct(
        &ctx(&facts),
        "T",
        &[field("SSECustomerKey", Type::String, false)],
        "G",
        "input",
        Side::Input,
    )
    .expect("renders");
    assert!(
        text.contains("sse_customer_key: sse_customer_key.map(|x| -> Result<_, ConversionError> { Ok(crate::SseCustomerKey::new(x)) }).transpose()?,"),
        "{text}"
    );
}

#[test]
fn ranges_and_conditions_have_a_backward_spelling() {
    let facts = facts("struct T\n  range: Option<Range>\n  if_match: Option<ETagCondition>\n");
    let fields = [field("Range", Type::Range, false), field("IfMatch", Type::String, false)];
    let text = backward::backward_struct(&ctx(&facts), "T", &fields, "G", "input", Side::Input).expect("renders");
    assert!(text.contains("leaf::range_from_s3s(&x)"), "{text}");
    assert!(text.contains("leaf::etag_condition_to_text(\"if_match\", &x)?"), "{text}");
}

#[test]
fn the_rendered_files_name_s3s_relative_to_their_mount() {
    let root = files::root();
    assert!(root.contains("use super::{copy_source, leaf, s3s};"), "{root}");
    let shape = files::shape_file("T", &[]);
    assert!(shape.contains("use super::super::{leaf, s3s};"), "{shape}");
    for text in [&root, &shape, &census::root(&[])] {
        assert!(!text.contains("s3s_0_17_0"), "a seam revision is named only by its mount: {text}");
    }
}

#[test]
fn the_error_code_census_lists_every_code_with_its_status() {
    let facts = S3sFacts::parse("error NoSuchKey 404\nerror MissingAttachment -\nerror NotModified 304\n").expect("parses");
    let text = census::error_codes(&facts);
    assert!(text.contains("use super::super::s3s;"), "{text}");
    assert!(text.contains("    (\"NoSuchKey\", Some(404)),\n"), "{text}");
    assert!(text.contains("    (\"MissingAttachment\", None),\n"), "{text}");
    assert!(text.contains("    (\"NotModified\", Some(304)),\n"), "{text}");
    assert!(text.contains("pub const CODES: &[(&str, Option<u16>)] = &["), "{text}");
}

#[test]
fn the_checked_in_facts_list_the_pinned_error_codes() {
    let facts = S3sFacts::parse(super::FACTS).expect("facts");
    assert_eq!(facts.errors.len(), 239, "every S3ErrorCode variant but Custom");
    assert!(facts.errors.contains(&("NoSuchKey".to_owned(), Some(404))));
    assert!(facts.errors.contains(&("MissingAttachment".to_owned(), None)));
    let mut names: Vec<&str> = facts.errors.iter().map(|(name, _)| name.as_str()).collect();
    names.dedup();
    assert_eq!(names.len(), facts.errors.len(), "no code is listed twice");
}

#[test]
fn an_empty_optional_header_crosses_an_output_unchanged() {
    // The legacy decoder read an empty optional header as absent, so an input member is filtered;
    // the legacy writer writes what it is given, so an output member crosses whole.
    let facts = facts("struct TOutput\n  content_range: Option<String>\n");
    let fields = [field("ContentRange", Type::String, false)];
    let output = render::forward_struct_as(&ctx(&facts), "TOutput", &fields, "output", Forward::Output).expect("renders");
    assert!(output.contains("content_range: output.content_range,"), "{output}");
    let input = render::forward_struct(&ctx(&facts), "TOutput", &fields, "input").expect("renders");
    assert!(
        input.contains("content_range: input.content_range.filter(|x| !x.as_str().is_empty()),"),
        "{input}"
    );
}

/// `UploadPartInput.content_length` (`Rule::UndeclaredHandedBack`, rustfs/gateway#1616): an unset
/// legacy length crosses as `0` with the legacy member handed back, and a negative one is refused.
#[test]
fn an_undeclared_length_is_handed_back_and_a_negative_one_is_refused() {
    let facts = facts("struct UploadPartInput\n  content_length: Option<i64>\n");
    let fields = [field("ContentLength", Type::Long, true)];
    let text = backward::backward_struct_with(
        &ctx(&facts),
        "UploadPartInput",
        &fields,
        "G",
        "input",
        LegacyMembers::HandBack,
        Side::Input,
    )
    .expect("renders");
    assert!(
        text.contains("content_length: match content_length { Some(x) if x < 0 => return Err(ConversionError { field: \"content_length\", reason: \"a negative length\" }), Some(x) => x, None => 0 },"),
        "{text}"
    );
    assert!(text.contains("LegacyInput { content_length }"), "{text}");
    assert!(!text.contains("the gateway shape requires this member"), "{text}");
    let members = render::legacy_members("UploadPartInput", &facts.structs["UploadPartInput"]);
    assert_eq!(members.len(), 1, "{members:?}");
}

/// Negative — without a side channel to hand it back, an undeclared length fails generation
/// instead of crossing as a declared zero.
#[test]
fn n_an_undeclared_length_with_nowhere_to_hand_it_back_fails_generation() {
    let facts = facts("struct UploadPartInput\n  content_length: Option<i64>\n");
    let fields = [field("ContentLength", Type::Long, true)];
    let error =
        backward::backward_struct(&ctx(&facts), "UploadPartInput", &fields, "G", "input", Side::Input).expect_err("no hand-back");
    assert!(
        error
            .iter()
            .any(|error| error.contains("UploadPartInput.content_length: UndeclaredHandedBack")),
        "{error:?}"
    );
}

/// Negative — the rule converts only an optional legacy length into a required gateway length.
#[test]
fn n_an_undeclared_length_on_another_pairing_fails_generation() {
    for (s3s, ty, required) in [
        ("content_length: i64", Type::Long, true),
        ("content_length: Option<i64>", Type::Long, false),
        ("content_length: Option<String>", Type::String, true),
    ] {
        let facts = facts(&format!("struct UploadPartInput\n  {s3s}\n"));
        let fields = [field("ContentLength", ty, required)];
        let error = backward::backward_struct_with(
            &ctx(&facts),
            "UploadPartInput",
            &fields,
            "G",
            "input",
            LegacyMembers::HandBack,
            Side::Input,
        )
        .expect_err(s3s);
        assert!(
            error
                .iter()
                .any(|error| error.contains("UploadPartInput.content_length: UndeclaredHandedBack")),
            "{s3s}: {error:?}"
        );
    }
}

/// Response-side entity tags (direct and nested via `Rule::Nested`) use the stored leaf, while
/// request-side entity tags keep the strict leaf (rustfs/gateway#1618).
#[test]
fn an_output_etag_uses_the_stored_leaf_and_an_input_etag_keeps_the_strict_leaf() {
    let facts = facts(
        "struct TInput\n  e_tag: Option<ETag>\n\
         struct TOutput\n  e_tag: Option<ETag>\n\
         struct CopyObjectOutput\n  copy_object_result: Option<struct CopyObjectResult>\n\
         struct CopyObjectResult\n  e_tag: Option<ETag>\n",
    );
    let etag_field = [field("ETag", Type::ETag(ETagRender::HeaderQuoted), false)];
    let input = backward::backward_struct(&ctx(&facts), "TInput", &etag_field, "G", "input", Side::Input).expect("renders");
    assert!(input.contains("leaf::etag_from_s3s(\"e_tag\", x)?"), "{input}");
    assert!(!input.contains("stored_etag_from_s3s"), "{input}");

    let output = backward::backward_struct(&ctx(&facts), "TOutput", &etag_field, "G", "output", Side::Output).expect("renders");
    assert!(output.contains("leaf::stored_etag_from_s3s(\"e_tag\", x)?"), "{output}");
    assert!(!output.contains("leaf::etag_from_s3s("), "{output}");

    let nested_output = backward::backward_struct(
        &ctx(&facts),
        "CopyObjectOutput",
        &[field("ETag", Type::ETag(ETagRender::XmlQuoted), false)],
        "G",
        "output",
        Side::Output,
    )
    .expect("renders");
    assert!(nested_output.contains("leaf::stored_etag_from_s3s(\"e_tag\", x)?"), "{nested_output}");
    assert!(!nested_output.contains("leaf::etag_from_s3s("), "{nested_output}");
}

/// Negative — a nested shape reached from both an input and an output emits two separate backward
/// conversions so the output's stored leaf never leaks onto the input path (rustfs/gateway#1618).
#[test]
fn n_a_shared_shape_reached_from_both_sides_never_uses_the_stored_leaf_on_input() {
    let facts = facts(
        "struct DualInput\n  entry: Option<struct SharedEntry>\n  choice: Option<union SharedChoice>\n\
         struct DualOutput\n  entry: Option<struct SharedEntry>\n  choice: Option<union SharedChoice>\n\
         struct SharedEntry\n  e_tag: Option<ETag>\n\
         union SharedChoice { Entry: struct SharedEntry }\n",
    );
    let ctx = ctx(&facts);
    let dual_fields = [
        field("Entry", Type::Structure("SharedEntry".to_owned()), false),
        field("Choice", Type::Union("SharedChoice".to_owned()), false),
    ];
    let input = backward::backward_struct(&ctx, "DualInput", &dual_fields, "G", "input", Side::Input).expect("renders");
    let output = backward::backward_struct(&ctx, "DualOutput", &dual_fields, "G", "output", Side::Output).expect("renders");
    assert!(
        input.contains("super::super::shapes::shared_entry::shared_entry_input_from_s3s(x)?"),
        "{input}"
    );
    assert!(
        input.contains("super::super::shapes::shared_choice::shared_choice_input_from_s3s(x)?"),
        "{input}"
    );
    assert!(
        output.contains("super::super::shapes::shared_entry::shared_entry_output_from_s3s(x)?"),
        "{output}"
    );
    assert!(
        output.contains("super::super::shapes::shared_choice::shared_choice_output_from_s3s(x)?"),
        "{output}"
    );
    assert!(ctx.reached.borrow().backward_input.contains("SharedEntry"));
    assert!(ctx.reached.borrow().backward_output.contains("SharedEntry"));

    let entry_shape = Shape {
        kind: ShapeKind::Structure,
        fields: vec![field("ETag", Type::ETag(ETagRender::XmlQuoted), false)],
        xml: ShapeXml {
            element_order: Vec::new(),
            empty_value_policy: Vec::new(),
            attributes: Vec::new(),
        },
    };
    let input_fn = files::shape_fn(&ctx, "SharedEntry", &entry_shape, ShapeDirection::Backward(Side::Input)).expect("input");
    assert!(input_fn.contains("pub fn shared_entry_input_from_s3s("), "{input_fn}");
    assert!(input_fn.contains("leaf::etag_from_s3s(\"e_tag\", x)?"), "{input_fn}");
    assert!(!input_fn.contains("stored_etag_from_s3s"), "{input_fn}");

    let output_fn = files::shape_fn(&ctx, "SharedEntry", &entry_shape, ShapeDirection::Backward(Side::Output)).expect("output");
    assert!(output_fn.contains("pub fn shared_entry_output_from_s3s("), "{output_fn}");
    assert!(output_fn.contains("leaf::stored_etag_from_s3s(\"e_tag\", x)?"), "{output_fn}");
    assert!(!output_fn.contains("leaf::etag_from_s3s("), "{output_fn}");

    let choice_shape = Shape {
        kind: ShapeKind::Union,
        fields: vec![field("Entry", Type::Structure("SharedEntry".to_owned()), false)],
        xml: ShapeXml {
            element_order: Vec::new(),
            empty_value_policy: Vec::new(),
            attributes: Vec::new(),
        },
    };
    let union_in = files::shape_fn(&ctx, "SharedChoice", &choice_shape, ShapeDirection::Backward(Side::Input)).expect("union in");
    assert!(union_in.contains("shared_entry_input_from_s3s(x)?"), "{union_in}");
    assert!(!union_in.contains("shared_entry_output_from_s3s"), "{union_in}");

    let union_out =
        files::shape_fn(&ctx, "SharedChoice", &choice_shape, ShapeDirection::Backward(Side::Output)).expect("union out");
    assert!(union_out.contains("shared_entry_output_from_s3s(x)?"), "{union_out}");
    assert!(!union_out.contains("shared_entry_input_from_s3s"), "{union_out}");
}

/// Negative — string-typed entity tag members stay strict on inputs and use `ETag::from_stored`
/// only on outputs (rustfs/gateway#1618).
#[test]
fn n_a_string_etag_pair_keeps_strict_text_parsing_on_input() {
    let facts = facts("struct T\n  e_tag: Option<String>\n");
    let ctx = ctx(&facts);
    let ty = Type::ETag(ETagRender::XmlQuoted);
    let s3s = super::facts::S3sType::Leaf("String".to_owned());
    let input = ctx.backward(&s3s, &ty, "ETag", "x", "e_tag", Side::Input).expect("input");
    assert_eq!(input, "leaf::etag_from_text(\"e_tag\", &x)?");
    let output = ctx.backward(&s3s, &ty, "ETag", "x", "e_tag", Side::Output).expect("output");
    assert_eq!(output, "crate::ETag::from_stored(x)");
}
