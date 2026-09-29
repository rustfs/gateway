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
    // `Prefix` is header-bound here, and the legacy decoder reads an empty header as absent.
    assert!(text.contains("prefix: input.prefix.filter(|x| !x.as_str().is_empty()),"), "{text}");
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
    // Header-bound, so an empty value crosses as absent, as the legacy decoder reads it.
    assert!(text.contains("type_: input.r#type.filter(|x| !x.as_str().is_empty()),"), "{text}");
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

// ── legacy header and query semantics ────────────────────────────────────────────────────────

mod legacy_semantics {
    use rustfs_gateway_model::ir::{Binding, Type};

    use super::{ctx, facts, field};
    use crate::emit::seam::render;

    fn header(name: &str, ty: Type) -> rustfs_gateway_model::ir::Field {
        field(name, ty, false)
    }

    #[test]
    fn an_empty_optional_textual_header_crosses_as_absent() {
        let facts =
            facts("struct T\n  cache_control: Option<String>\n  acl: Option<enum ObjectCannedACL>\n  range: Option<Range>\n");
        let fields = [
            header("CacheControl", Type::String),
            header("ACL", Type::StringEnum(vec!["private".to_owned()])),
            header("Range", Type::Range),
        ];
        let text = render::forward_struct(&ctx(&facts), "T", &fields, "input").expect("renders");
        assert!(
            text.contains("cache_control: input.cache_control.filter(|x| !x.as_str().is_empty()),"),
            "{text}"
        );
        assert!(text.contains("acl: input.acl.filter(|x| !x.as_str().is_empty()).map("), "{text}");
        assert!(text.contains("range: input.range.filter(|x| !x.as_str().is_empty()).map("), "{text}");
    }

    #[test]
    fn n_a_query_payload_required_or_numeric_member_keeps_its_empty_value() {
        let facts =
            facts("struct T\n  prefix: Option<String>\n  marker: Option<String>\n  bucket: String\n  size: Option<i64>\n");
        let mut query = field("Prefix", Type::String, false);
        query.binding = Binding::Query;
        let mut payload = field("Marker", Type::String, false);
        payload.binding = Binding::BodyXml;
        let fields = [
            query,
            payload,
            field("Bucket", Type::BucketName, true),
            header("Size", Type::Long),
        ];
        let text = render::forward_struct(&ctx(&facts), "T", &fields, "input").expect("renders");
        assert!(!text.contains(".filter("), "{text}");
    }

    #[test]
    fn a_member_only_the_legacy_decoder_reads_is_decoded_from_the_raw_request() {
        let facts = facts("struct CopyObjectInput\n  bucket: String\n  version_id: Option<String>\n");
        let ctx = ctx(&facts);
        let text = render::forward_struct(&ctx, "CopyObjectInput", &[field("Bucket", Type::BucketName, true)], "input")
            .expect("renders");
        assert!(text.contains("version_id: leaf::legacy_query(wire, \"versionId\")?,"), "{text}");
        assert_eq!(*ctx.supplied.borrow(), [("wire".to_owned(), "&leaf::RequestWire<'_>".to_owned())]);
        let facts = super::facts("struct DeleteBucketInput\n  bucket: String\n  force_delete: Option<bool>\n");
        let text = render::forward_struct(
            &super::ctx(&facts),
            "DeleteBucketInput",
            &[field("Bucket", Type::BucketName, true)],
            "input",
        )
        .expect("renders");
        assert!(
            text.contains("force_delete: leaf::legacy_bool_header(wire, \"x-minio-force-delete\")?,"),
            "{text}"
        );
    }

    #[test]
    fn n_a_legacy_query_member_of_another_type_fails_generation() {
        let facts = facts("struct CopyObjectInput\n  bucket: String\n  version_id: Option<i32>\n");
        let errors = render::forward_struct(&ctx(&facts), "CopyObjectInput", &[field("Bucket", Type::BucketName, true)], "input")
            .expect_err("no decoding for an integer");
        assert!(errors[0].contains("no legacy wire decoding"), "{errors:?}");
    }

    #[test]
    fn n_a_legacy_query_override_a_gateway_member_now_fills_is_reported_stale() {
        let facts = facts("struct CopyObjectInput\n  bucket: String\n  version_id: Option<String>\n");
        let fields = [
            field("Bucket", Type::BucketName, true),
            field("VersionId", Type::String, false),
        ];
        let errors = render::forward_struct(&ctx(&facts), "CopyObjectInput", &fields, "input").expect_err("stale");
        assert!(errors[0].contains("stale override"), "{errors:?}");
    }

    #[test]
    fn n_a_member_decoded_from_the_raw_request_has_no_backward_conversion() {
        let facts = facts("struct CopyObjectInput\n  version_id: Option<String>\n");
        let errors = render::backward_struct(&ctx(&facts), "CopyObjectInput", &[], "G", "v").expect_err("forward only");
        assert!(errors[0].contains("forward only"), "{errors:?}");
    }
}

// ── answer headers ───────────────────────────────────────────────────────────────────────────

mod answer_headers {
    use rustfs_gateway_model::ir::{Binding, Type};

    use super::{ctx, facts, field};
    use crate::emit::seam::render;

    fn output_field(name: &str, wire: &str, binding: Binding, ty: Type, required: bool) -> rustfs_gateway_model::ir::Field {
        let mut field = field(name, ty, required);
        field.wire_name = Some(wire.to_owned());
        field.binding = binding;
        field
    }

    #[test]
    fn a_header_the_body_sets_clears_the_member_that_writes_it() {
        let facts = facts(
            "struct T\n  accept_ranges: Option<String>\n  metadata: Option<Map<String, String>>\n  checksum_crc32: Option<String>\n  checksum_sha256: Option<String>\n",
        );
        let fields = [
            output_field("AcceptRanges", "accept-ranges", Binding::Header, Type::String, false),
            output_field(
                "Metadata",
                "x-amz-meta-",
                Binding::PrefixHeaders,
                Type::Map {
                    key: Box::new(Type::String),
                    value: Box::new(Type::String),
                },
                false,
            ),
            output_field("ChecksumSpec", "x-amz-checksum-", Binding::PrefixHeaders, Type::ChecksumSpec, false),
        ];
        let text = render::headers_body(&ctx(&facts), "T", &fields).expect("renders");
        assert!(
            text.contains("if headers.contains_key(\"accept-ranges\") { output.accept_ranges = None; }"),
            "{text}"
        );
        assert!(
            text.contains("map.retain(|key, _| !headers.contains_key(format!(\"x-amz-meta-{key}\").as_str()));"),
            "{text}"
        );
        assert!(
            text.contains("if headers.contains_key(\"x-amz-checksum-crc32\") { output.checksum_crc32 = None; }"),
            "{text}"
        );
        assert!(
            text.contains("if headers.contains_key(\"x-amz-checksum-sha256\") { output.checksum_sha256 = None; }"),
            "{text}"
        );
    }

    #[test]
    fn n_a_required_member_a_header_would_replace_is_refused_not_cleared() {
        let facts = facts("struct T\n  request_charged: String\n");
        let fields = [output_field(
            "RequestCharged",
            "x-amz-request-charged",
            Binding::Header,
            Type::String,
            true,
        )];
        let text = render::headers_body(&ctx(&facts), "T", &fields).expect("renders");
        assert!(text.contains("return Err(ConversionError { field: \"request_charged\""), "{text}");
        assert!(!text.contains("= None"), "{text}");
    }

    #[test]
    fn n_a_body_or_query_member_is_never_cleared_by_a_header() {
        let facts = facts("struct T\n  name: Option<String>\n  marker: Option<String>\n");
        let fields = [
            output_field("Name", "Name", Binding::BodyXml, Type::String, false),
            output_field("Marker", "marker", Binding::Query, Type::String, false),
        ];
        let text = render::headers_body(&ctx(&facts), "T", &fields).expect("renders");
        assert!(text.is_empty(), "{text}");
    }

    #[test]
    fn n_a_prefixed_header_member_that_is_not_a_map_fails_generation() {
        let facts = facts("struct T\n  metadata: Option<String>\n");
        let fields = [output_field(
            "Metadata",
            "x-amz-meta-",
            Binding::PrefixHeaders,
            Type::String,
            false,
        )];
        let errors = render::headers_body(&ctx(&facts), "T", &fields).expect_err("not a map");
        assert!(errors[0].contains("not an optional map"), "{errors:?}");
    }
}

// ── legacy-only output members ───────────────────────────────────────────────────────────────

mod legacy_only_outputs {
    use rustfs_gateway_model::ir::Type;

    use super::{ctx, facts, field};
    use crate::emit::seam::render;

    #[test]
    fn a_set_legacy_only_output_member_is_refused_rather_than_dropped() {
        // `HeadBucketOutput.bucket_arn` is a reviewed legacy-only member.
        let facts = facts("struct HeadBucketOutput\n  bucket_region: Option<String>\n  bucket_arn: Option<String>\n");
        let text = render::backward_struct(
            &ctx(&facts),
            "HeadBucketOutput",
            &[field("BucketRegion", Type::String, false)],
            "G",
            "output",
        )
        .expect("renders");
        assert!(text.contains("        bucket_arn,\n"), "{text}");
        assert!(
            text.contains("    if bucket_arn.is_some() {\n        return Err(ConversionError { field: \"bucket_arn\""),
            "{text}"
        );
    }

    #[test]
    fn n_a_runtime_member_is_still_ignored_whatever_it_holds() {
        let facts = facts("struct T\n  bucket: Option<String>\n  future: Option<opaque>\n");
        let text =
            render::backward_struct(&ctx(&facts), "T", &[field("Bucket", Type::String, false)], "G", "output").expect("renders");
        assert!(text.contains("        future: _,\n"), "{text}");
        assert!(!text.contains("future.is_some()"), "{text}");
    }
}

// ── the member census ─────────────────────────────────────────────────────────────────────────

mod census {
    use super::super::census;
    use super::facts;

    const NESTED: &str = "struct Op\n  bucket: String\n  body: Option<StreamingBlob>\n  cache: opaque\n  config: Option<struct Config>\n  tags: Option<Vec<struct Tag>>\n  ids: Vec<String>\n  meta: Option<Map<String, String>>\nstruct Config\n  rule: struct Rule\nstruct Rule\n  id: Option<String>\nstruct Tag\n  key: String\n  value: String\n";

    #[test]
    fn paths_expand_nested_structures_and_list_elements() {
        let facts = facts(NESTED);
        let mut out = Vec::new();
        census::paths(&facts, "Op", "", 0, &mut out).expect("paths");
        assert_eq!(out, ["bucket", "config.rule.id", "tags[].key", "tags[].value", "ids[]", "meta"]);
    }

    #[test]
    fn n_a_stream_and_a_runtime_member_are_never_compared_or_counted() {
        let facts = facts(NESTED);
        let text = census::module(&facts, "Op").expect("module");
        assert!(!text.contains("body"), "{text}");
        assert!(!text.contains("cache"), "{text}");
    }

    #[test]
    fn differences_recurse_into_structures_and_compare_lists_element_by_element() {
        let facts = facts(NESTED);
        let text = census::module(&facts, "Op").expect("module");
        assert!(text.contains("if left.bucket != right.bucket {"), "{text}");
        assert!(
            text.contains("(Some(l), Some(r)) => super::config::differences(&format!(\"{prefix}config.\"), l, r, out),"),
            "{text}"
        );
        assert!(
            text.contains("(Some(l), Some(r)) => super::list(prefix, \"tags\", l, r, out, super::tag::differences),"),
            "{text}"
        );
        assert!(text.contains("if left.ids != right.ids {"), "{text}");
        let config = census::module(&facts, "Config").expect("module");
        assert!(
            config.contains("super::rule::differences(&format!(\"{prefix}rule.\"), &left.rule, &right.rule, out);"),
            "{config}"
        );
    }

    #[test]
    fn present_counts_a_required_member_always_and_an_optional_one_when_set() {
        let facts = facts(NESTED);
        let text = census::module(&facts, "Op").expect("module");
        assert!(text.contains("    out.push(format!(\"{prefix}bucket\"));"), "{text}");
        assert!(
            text.contains("if !value.ids.is_empty() { out.push(format!(\"{prefix}ids[]\")); }"),
            "{text}"
        );
        assert!(
            text.contains("if value.meta.as_ref().is_some_and(|held| !held.is_empty()) { out.push(format!(\"{prefix}meta\")); }"),
            "{text}"
        );
        let rule = census::module(&facts, "Rule").expect("module");
        assert!(rule.contains("if value.id.is_some() { out.push(format!(\"{prefix}id\")); }"), "{rule}");
    }

    #[test]
    fn n_a_member_naming_an_undeclared_structure_is_refused_by_name() {
        let facts = facts("struct Op\n  config: Option<struct Missing>\n");
        let error = census::reachable(&facts, &["Op".to_owned()]).expect_err("undeclared");
        assert!(error.contains("`Missing`"), "{error}");
        let mut out = Vec::new();
        let error = census::paths(&facts, "Op", "", 0, &mut out).expect_err("undeclared");
        assert!(error.contains("`Missing`"), "{error}");
    }

    #[test]
    fn n_a_root_the_fact_table_lacks_is_refused() {
        let facts = facts(NESTED);
        let error = census::reachable(&facts, &["Nope".to_owned()]).expect_err("no root");
        assert!(error.contains("`Nope`"), "{error}");
    }

    #[test]
    fn n_a_cyclic_structure_is_refused_rather_than_expanded_forever() {
        let facts = facts("struct A\n  b: Option<struct B>\nstruct B\n  a: Option<struct A>\n");
        let mut out = Vec::new();
        let error = census::paths(&facts, "A", "", 0, &mut out).expect_err("cycle");
        assert!(error.contains("nests deeper"), "{error}");
    }

    #[test]
    fn n_reachability_takes_exactly_the_nested_structures_and_no_unrelated_one() {
        let facts = facts(&format!("{NESTED}struct Unrelated\n  id: String\n"));
        let reached = census::reachable(&facts, &["Op".to_owned()]).expect("reachable");
        assert_eq!(reached.into_iter().collect::<Vec<_>>(), ["Config", "Op", "Rule", "Tag"]);
    }

    #[test]
    fn the_checked_in_facts_census_every_covered_operation() {
        let facts = crate::emit::seam::facts::S3sFacts::parse(crate::emit::seam::FACTS).expect("facts");
        let files =
            census::emit(&facts, crate::emit::seam::overrides::OPERATIONS, std::path::Path::new("census")).expect("census");
        for operation in crate::emit::seam::overrides::OPERATIONS {
            for side in ["Input", "Output"] {
                let module = format!("census/{}.rs", crate::emit::dto::naming::module_name(&format!("{operation}{side}")));
                assert!(files.iter().any(|(path, _)| path.to_string_lossy() == module), "{module}");
            }
        }
        let delete = files
            .iter()
            .find(|(path, _)| path.to_string_lossy() == "census/delete_objects_input.rs")
            .expect("DeleteObjectsInput");
        assert!(delete.1.contains("\"delete.objects[].key\","), "{}", delete.1);
    }
}
