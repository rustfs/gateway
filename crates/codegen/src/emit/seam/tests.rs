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

//! Tests for the seam generator's matching and wrapping rules.
//!
//! Responsible for: proving that an undecided member fails generation in both directions, and
//! that the rules the generator applies without an override — same name, keyword escaping, the
//! checksum fan-out, runtime members, `Option` and container wrapping — render the expected text.
//! NOT responsible for: whether the rendered text compiles, which the types crate's compat tests
//! prove against the real s3s. Upstream: [`super`]. Downstream: none; test-only.

use rustfs_gateway_model::ir::{Binding, Field, Type};

use super::expr::Ctx;
use super::facts::S3sFacts;
use super::render;

fn field(name: &str, ty: Type, required: bool) -> Field {
    Field {
        name: name.to_owned(),
        wire_name: Some(name.to_owned()),
        required,
        binding: Binding::Header,
        ty,
        hot: false,
        default: None,
        omit_when: None,
        missing_error: None,
        quirk_refs: Vec::new(),
    }
}

fn facts(text: &str) -> S3sFacts {
    S3sFacts::parse(text).expect("facts")
}

fn ctx(facts: &S3sFacts) -> Ctx<'_> {
    Ctx {
        facts,
        reached: Default::default(),
        supplied: Default::default(),
    }
}

#[test]
fn same_names_convert_and_options_are_threaded() {
    let facts = facts("struct T\n  bucket: String\n  prefix: Option<String>\n  max_keys: Option<i32>\n");
    let fields = [
        field("Bucket", Type::BucketName, true),
        field("Prefix", Type::String, false),
        field("MaxKeys", Type::Integer, true),
    ];
    let text = render::forward_struct(&ctx(&facts), "T", &fields, "input").expect("renders");
    assert!(text.contains("bucket: { let x = input.bucket; x.as_str().to_owned() },"), "{text}");
    assert!(text.contains("prefix: input.prefix,"), "{text}");
    assert!(text.contains("max_keys: Some(input.max_keys),"), "{text}");
}

#[test]
fn n_an_s3s_member_nobody_fills_fails_generation() {
    let facts = facts("struct T\n  bucket: String\n  force: Option<bool>\n");
    let errors = render::forward_struct(&ctx(&facts), "T", &[field("Bucket", Type::BucketName, true)], "input")
        .expect_err("undecided s3s member");
    assert_eq!(errors, ["T.force: an s3s member no gateway member fills"]);
}

#[test]
fn n_an_s3s_member_nobody_takes_fails_generation() {
    let facts = facts("struct T\n  bucket: Option<String>\n  arn: Option<String>\n");
    let errors = render::backward_struct(&ctx(&facts), "T", &[field("Bucket", Type::BucketName, true)], "G", "output")
        .expect_err("undecided s3s member");
    assert_eq!(errors, ["T.arn: an s3s member no gateway member takes"]);
}

#[test]
fn n_a_gateway_member_s3s_lacks_fails_generation() {
    let facts = facts("struct T\n  bucket: String\n");
    let fields = [
        field("Bucket", Type::BucketName, true),
        field("EventHold", Type::String, false),
    ];
    let errors = render::forward_struct(&ctx(&facts), "T", &fields, "input").expect_err("undecided gateway member");
    assert_eq!(errors, ["T.event_hold: the s3s struct has no member `event_hold`"]);
}

#[test]
fn n_a_pair_the_table_does_not_know_fails_generation() {
    let facts = facts("struct T\n  size: Option<Timestamp>\n");
    let errors =
        render::forward_struct(&ctx(&facts), "T", &[field("Size", Type::Long, false)], "input").expect_err("long into timestamp");
    assert_eq!(errors.len(), 1);
    assert!(errors[0].starts_with("T.size: no gateway → s3s conversion"), "{errors:?}");
}

#[test]
fn n_a_required_gateway_member_absent_from_s3s_output_is_refused_at_run_time() {
    let facts = facts("struct T\n  size: Option<i64>\n");
    let text = render::backward_struct(&ctx(&facts), "T", &[field("Size", Type::Long, true)], "G", "output").expect("renders");
    assert!(
        text.contains("size: match size { Some(x) => x, None => return Err(ConversionError { field: \"size\""),
        "{text}"
    );
}

#[test]
fn a_keyword_member_meets_its_underscored_s3s_twin() {
    let facts = facts("struct T\n  type_: Option<String>\n");
    let text = render::forward_struct(&ctx(&facts), "T", &[field("Type", Type::String, false)], "input").expect("renders");
    assert!(text.contains("type_: input.r#type,"), "{text}");
}

#[test]
fn a_checksum_spec_fans_out_to_every_algorithm_member_present() {
    let facts =
        facts("struct T\n  checksum_crc32: Option<String>\n  checksum_sha256: Option<String>\n  future: Option<opaque>\n");
    let text =
        render::forward_struct(&ctx(&facts), "T", &[field("ChecksumSpec", Type::ChecksumSpec, false)], "input").expect("renders");
    assert!(text.contains("let checksum_spec = input.checksum_spec;"), "{text}");
    assert!(
        text.contains("checksum_crc32: leaf::checksum_value(checksum_spec.as_ref(), crate::ChecksumAlgorithm::Crc32),"),
        "{text}"
    );
    assert!(
        text.contains("checksum_sha256: leaf::checksum_value(checksum_spec.as_ref(), crate::ChecksumAlgorithm::Sha256),"),
        "{text}"
    );
    assert!(text.contains("future: Default::default(),"), "{text}");
}

#[test]
fn an_empty_gateway_list_is_an_absent_s3s_list() {
    let facts = facts("struct T\n  tags: Option<Vec<String>>\n");
    let list = Type::List {
        member: Box::new(Type::String),
        flattened: false,
        member_name: None,
    };
    let text = render::forward_struct(&ctx(&facts), "T", &[field("Tags", list, false)], "input").expect("renders");
    assert!(
        text.contains("tags: if input.tags.is_empty() { None } else { Some(input.tags) },"),
        "{text}"
    );
}

#[test]
fn the_checked_in_facts_cover_every_generated_operation() {
    let facts = S3sFacts::parse(super::FACTS).expect("facts");
    for operation in super::overrides::OPERATIONS {
        assert!(facts.structs.contains_key(&format!("{operation}Input")), "{operation}");
        assert!(facts.structs.contains_key(&format!("{operation}Output")), "{operation}");
    }
}

#[test]
fn n_an_override_a_gateway_member_now_satisfies_is_reported_stale() {
    // `DeleteBucketInput.force_delete` is S3sOnly today; a model that grows the member must fail
    // generation until the override is deleted, never keep defaulting it.
    let facts = facts("struct DeleteBucketInput\n  bucket: String\n  force_delete: Option<bool>\n");
    let fields = [
        field("Bucket", Type::BucketName, true),
        field("ForceDelete", Type::Boolean, false),
    ];
    let errors = render::forward_struct(&ctx(&facts), "DeleteBucketInput", &fields, "input").expect_err("stale override");
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("stale override"), "{errors:?}");
}

#[test]
fn a_supplied_member_becomes_a_parameter_and_is_never_converted() {
    // `CopyObjectInput.copy_source` is supplied: the gateway seals it into the derived resources.
    let facts = facts("struct CopyObjectInput\n  bucket: String\n  copy_source: CopySource\n");
    let fields = [
        field("Bucket", Type::BucketName, true),
        field("CopySource", Type::String, true),
    ];
    let ctx = ctx(&facts);
    let text = render::forward_struct(&ctx, "CopyObjectInput", &fields, "input").expect("renders");
    assert!(text.contains("        copy_source,\n"), "{text}");
    assert!(!text.contains("input.copy_source"), "the sealed input member is never read: {text}");
    assert_eq!(*ctx.supplied.borrow(), [("copy_source".to_owned(), "s3s::dto::CopySource".to_owned())]);
}

#[test]
fn n_a_supplied_member_has_no_backward_conversion() {
    let facts = facts("struct CopyObjectInput\n  copy_source: Option<String>\n");
    let errors = render::backward_struct(&ctx(&facts), "CopyObjectInput", &[field("CopySource", Type::String, false)], "G", "v")
        .expect_err("forward only");
    assert!(errors[0].contains("forward only"), "{errors:?}");
}
