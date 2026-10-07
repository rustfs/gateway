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

//! Tests for the generated s3s fixtures the seam round trips start from (rustfs/backlog#2759).
//!
//! Responsible for: proving a fixture sets every member both sides hold, justifies every member it
//! leaves unset (a legacy-only member, a runtime member, the other algorithms of a checksum
//! fan-out), claims exactly the member paths it sets, reaches nested shapes and lists through
//! their own fixtures, takes a union's first variant, and fails generation on a pair the table
//! does not know rather than guessing a value.
//! NOT responsible for: whether the fixture converts, which the generated round-trip tests in the
//! types crate prove. Upstream: [`super::fixture`]. Downstream: none; test-only.

use std::collections::BTreeMap;

use rustfs_gateway_model::ir::{Shape, ShapeKind, ShapeXml, TimestampFormat, Type};

use super::fixture;
use super::tests::{ctx, facts, field};

fn shape(kind: ShapeKind, fields: Vec<rustfs_gateway_model::ir::Field>) -> Shape {
    Shape {
        kind,
        fields,
        xml: ShapeXml {
            element_order: Vec::new(),
            empty_value_policy: Vec::new(),
            attributes: Vec::new(),
        },
    }
}

const NO_SHAPES: BTreeMap<&str, &Shape> = BTreeMap::new();

#[test]
fn a_fixture_sets_every_paired_member_and_justifies_every_unset_one() {
    // `CreateBucketOutput.bucket_arn` is legacy-only in the override table.
    let facts =
        facts("struct CreateBucketOutput\n  location: Option<String>\n  bucket_arn: Option<String>\n  future: Option<opaque>\n");
    let fields = [field("Location", Type::String, false)];
    let fixture = fixture::struct_literal(&ctx(&facts), &NO_SHAPES, "CreateBucketOutput", &fields, "super").expect("renders");
    assert!(
        fixture.literal.contains("location: Some(\"location\".to_owned()),"),
        "{}",
        fixture.literal
    );
    assert!(fixture.literal.contains("bucket_arn: Default::default(),"), "{}", fixture.literal);
    assert!(fixture.literal.contains("future: Default::default(),"), "{}", fixture.literal);
    assert_eq!(fixture.held, ["location"]);
}

#[test]
fn n_a_member_left_unset_without_a_reason_fails_generation() {
    let facts = facts("struct T\n  bucket: String\n  extra: Option<String>\n");
    let errors = fixture::struct_literal(&ctx(&facts), &NO_SHAPES, "T", &[field("Bucket", Type::BucketName, true)], "super")
        .expect_err("an unjustified unset member");
    assert_eq!(errors, ["T.extra: an s3s member no gateway member fills"]);
}

#[test]
fn a_fixture_fans_out_one_checksum_and_claims_only_it() {
    let facts = facts("struct T\n  checksum_crc32: Option<String>\n  checksum_sha256: Option<String>\n");
    let fixture = fixture::struct_literal(
        &ctx(&facts),
        &NO_SHAPES,
        "T",
        &[field("ChecksumSpec", Type::ChecksumSpec, false)],
        "super",
    )
    .expect("renders");
    assert!(
        fixture.literal.contains("checksum_crc32: Some(\"AAAAAA==\".to_owned()),"),
        "{}",
        fixture.literal
    );
    assert!(fixture.literal.contains("checksum_sha256: None,"), "{}", fixture.literal);
    assert_eq!(fixture.held, ["checksum_crc32"]);
}

#[test]
fn optionality_is_bridged_in_both_directions() {
    let facts = facts("struct T\n  bucket: Option<String>\n  max_keys: i32\n");
    let fields = [
        field("Bucket", Type::BucketName, true),
        field("MaxKeys", Type::Integer, false),
    ];
    let fixture = fixture::struct_literal(&ctx(&facts), &NO_SHAPES, "T", &fields, "super").expect("renders");
    assert!(
        fixture.literal.contains("bucket: Some(\"fixture-bucket\".to_owned()),"),
        "{}",
        fixture.literal
    );
    assert!(fixture.literal.contains("max_keys: 7,"), "{}", fixture.literal);
    assert_eq!(fixture.held, ["bucket", "max_keys"]);
}

#[test]
fn a_fixture_reaches_nested_shapes_and_lists_through_their_fixtures() {
    let facts = facts(
        "struct T\n  items: Option<Vec<struct Item>>\n  owner: Option<struct Owner>\nstruct Item\n  key: String\nstruct Owner\n  id: Option<String>\n",
    );
    let item = shape(ShapeKind::Structure, vec![field("Key", Type::ObjectKey, true)]);
    let owner = shape(ShapeKind::Structure, vec![field("ID", Type::String, false)]);
    let shapes = BTreeMap::from([("Item", &item), ("Owner", &owner)]);
    let list = Type::List {
        member: Box::new(Type::Structure("Item".to_owned())),
        flattened: false,
        member_name: None,
    };
    let fields = [
        field("Items", list, false),
        field("Owner", Type::Structure("Owner".to_owned()), false),
    ];
    let fixture = fixture::struct_literal(&ctx(&facts), &shapes, "T", &fields, "super::super::shapes").expect("renders");
    assert!(
        fixture
            .literal
            .contains("items: Some(vec![super::super::shapes::item::value()]),"),
        "{}",
        fixture.literal
    );
    assert!(
        fixture.literal.contains("owner: Some(super::super::shapes::owner::value()),"),
        "{}",
        fixture.literal
    );
    assert_eq!(fixture.held, ["items[].key", "owner.id"]);
}

#[test]
fn a_union_fixture_takes_its_first_variant() {
    let facts = facts("union F { And: struct A, Prefix: String }\nstruct A\n  x: String\n");
    let a = shape(ShapeKind::Structure, vec![field("X", Type::String, true)]);
    let shapes = BTreeMap::from([("A", &a)]);
    let fields = [
        field("And", Type::Structure("A".to_owned()), false),
        field("Prefix", Type::String, false),
    ];
    let fixture = fixture::union_literal(&ctx(&facts), &shapes, "F", &fields, "super").expect("renders");
    assert_eq!(fixture.literal, "s3s::dto::F::And(super::a::value())");
    assert!(fixture.held.is_empty(), "a union member is one census path, named by its holder");
}

#[test]
fn an_instant_fixture_is_spelled_to_the_millisecond_s3s_writes() {
    let facts = facts("struct T\n  last_modified: Option<Timestamp>\n");
    let fields = [field("LastModified", Type::Timestamp(TimestampFormat::Iso8601), false)];
    let fixture = fixture::struct_literal(&ctx(&facts), &NO_SHAPES, "T", &fields, "super").expect("renders");
    assert!(
        fixture.literal.contains("last_modified: Some(s3s::dto::Timestamp::parse(s3s::dto::TimestampFormat::EpochSeconds, \"1700000000.123\").expect(\"a fixture instant\")),"),
        "{}",
        fixture.literal
    );
}

#[test]
fn n_a_pair_the_table_does_not_know_has_no_fixture() {
    let facts = facts("struct T\n  size: Option<Timestamp>\n");
    let errors = fixture::struct_literal(&ctx(&facts), &NO_SHAPES, "T", &[field("Size", Type::Long, false)], "super")
        .expect_err("long into timestamp");
    assert_eq!(errors.len(), 1);
    assert!(errors[0].starts_with("T.size: no fixture for"), "{errors:?}");
}

#[test]
fn n_a_nested_shape_the_ir_lacks_fails_generation() {
    let facts = facts("struct T\n  owner: Option<struct Owner>\nstruct Owner\n  id: Option<String>\n");
    let fields = [field("Owner", Type::Structure("Owner".to_owned()), false)];
    let errors = fixture::struct_literal(&ctx(&facts), &NO_SHAPES, "T", &fields, "super").expect_err("no IR shape");
    assert_eq!(errors, ["T.owner: shape Owner is not in the IR"]);
}
