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

//! What the two protocol refusals the model does not state actually generate.
//!
//! Responsible for: the bounded-integer resolution rules, and the two IR facts that must reach the
//! generated decoders — an inclusive range on a bounded member, and the integrity guard on an
//! `httpChecksumRequired` operation.
//! NOT responsible for: what the refusals do to a request, which is `rustfs-gateway-core`'s codec
//! suite.
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use rustfs_gateway_model::ir::{Binding, Field, Type};
use rustfs_gateway_model::{CodecRule, CodecValue, MutationDimension};

use crate::emit::codec::bounds::{self, Bound};

fn field(name: &str, ty: Type, quirks: &[&str]) -> Field {
    Field {
        name: name.to_owned(),
        wire_name: Some(name.to_lowercase()),
        required: false,
        binding: Binding::Query,
        ty,
        hot: false,
        default: None,
        omit_when: None,
        missing_error: None,
        quirk_refs: quirks.iter().map(|q| (*q).to_owned()).collect(),
    }
}

fn range(min: i32, max: i32) -> CodecRule {
    CodecRule {
        current: CodecValue::IntegerRange { min, max },
        mutation_dimension: MutationDimension::IntegerRange,
    }
}

#[test]
fn a_field_with_no_quirk_at_all_is_unbounded() {
    let resolved = bounds::of(&field("MaxKeys", Type::Integer, &[]), &BTreeMap::new(), "Fixture").expect("resolves");
    assert_eq!(resolved, None, "an ordinary integer keeps the unbounded parser");
}

#[test]
fn metadata_without_a_typed_rule_does_not_bound_anything() {
    let resolved =
        bounds::of(&field("MaxKeys", Type::Integer, &["q-maxkeys-0068"]), &BTreeMap::new(), "Fixture").expect("resolves");
    assert_eq!(resolved, None, "only the typed rule map declares a range");
}

#[test]
fn the_declared_ranges_reach_the_two_members_that_carry_them() {
    let values = BTreeMap::from([
        ("q-part-number-0072".to_owned(), range(1, 10_000)),
        ("q-max-keys-0073".to_owned(), range(0, 1_000)),
    ]);
    let part = bounds::of(&field("PartNumber", Type::Integer, &["q-part-number-0072"]), &values, "UploadPart").expect("resolves");
    assert_eq!(part, Some(Bound { min: 1, max: 10_000 }));
    let keys = bounds::of(&field("MaxKeys", Type::Integer, &["q-max-keys-0073"]), &values, "ListObjectsV2").expect("resolves");
    assert_eq!(keys, Some(Bound { min: 0, max: 1_000 }));
}

#[test]
fn a_list_of_bounded_integers_is_bounded_element_by_element() {
    let values = BTreeMap::from([("q-part-number-0072".to_owned(), range(1, 10_000))]);
    let list = Type::List {
        member: Box::new(Type::Integer),
        flattened: true,
        member_name: None,
    };
    let resolved = bounds::of(&field("PartNumbers", list, &["q-part-number-0072"]), &values, "Fixture").expect("resolves");
    assert_eq!(
        resolved,
        Some(Bound { min: 1, max: 10_000 }),
        "the range belongs to the value, not the container"
    );
}

#[test]
fn free_text_kind_is_not_a_codec_gate() {
    let resolved = bounds::of(&field("MaxKeys", Type::Integer, &["q-invented-9999"]), &BTreeMap::new(), "Fixture")
        .expect("metadata cannot control codec generation");
    assert_eq!(resolved, None);
}

#[test]
fn n_a_bounded_quirk_on_a_member_that_is_not_an_integer_fails_the_run() {
    let values = BTreeMap::from([("q-max-keys-0073".to_owned(), range(0, 1_000))]);
    let error = bounds::of(&field("Prefix", Type::String, &["q-max-keys-0073"]), &values, "Fixture")
        .expect_err("a range on a string is a mistake, not a range");
    assert!(error.contains("Prefix"), "{error}");
}

#[test]
fn n_two_bounded_quirks_disagreeing_on_one_member_fail_the_run() {
    let values = BTreeMap::from([
        ("q-part-number-0072".to_owned(), range(1, 10_000)),
        ("q-max-keys-0073".to_owned(), range(0, 1_000)),
    ]);
    let member = field("Confused", Type::Integer, &["q-part-number-0072", "q-max-keys-0073"]);
    let error = bounds::of(&member, &values, "Fixture").expect_err("one member has one range");
    assert!(error.contains("Confused"), "{error}");
}

#[test]
fn n_the_integrity_guard_is_generated_only_where_the_ir_asks_for_it() {
    let artifacts = super::codegen_tests::artifacts();
    for ir in &artifacts.operations {
        let generated = crate::emit::codec::decode::body(ir, &artifacts.codec_rules, &artifacts.error_codes)
            .expect("every included operation has a decoder");
        assert_eq!(
            generated.contains("value::require_integrity(request)?"),
            ir.checksum.http_checksum_required,
            "{}: the guard follows `checksum.http_checksum_required` and nothing else",
            ir.operation
        );
        if ir.checksum.http_checksum_required {
            let guard = generated.find("value::require_integrity").expect("present");
            let read = generated.find("body.into_buffered").unwrap_or(usize::MAX);
            assert!(guard < read, "{}: the guard must precede the first body read", ir.operation);
        }
    }
}

/// Structural control over the emitter's own claim that the two lines go together.
///
/// `BUFFER_BODY` writes the buffering and the digest verification as one constant precisely so a
/// site cannot acquire one without the other, and this is what makes that claim falsifiable: an
/// emitter that buffered a body somewhere without settling the `Content-MD5` declared over it would
/// produce a decoder that reads unverified bytes at exactly one operation, and every conformance
/// case for every other operation would stay green. Both directions are asserted — one verification
/// per buffered body, and none without one — because a decoder that verified a body it never read
/// would not compile but a count that only checked "at least one" would not notice two reads and
/// one check.
#[test]
fn every_buffered_body_is_settled_against_the_digest_declared_over_it() {
    const READ: &str = "let raw_body = body.into_buffered()?;\n";
    const SETTLE: &str = "        value::verify_body_digest(request, raw_body.as_ref())?;\n";
    let artifacts = super::codegen_tests::artifacts();
    let mut buffered = 0usize;
    for ir in &artifacts.operations {
        let generated = crate::emit::codec::decode::body(ir, &artifacts.codec_rules, &artifacts.error_codes)
            .expect("every included operation has a decoder");
        let reads: Vec<usize> = generated.match_indices(READ).map(|(index, _)| index).collect();
        assert_eq!(
            generated.matches(SETTLE.trim_start()).count(),
            reads.len(),
            "{}: one verification per buffered body, and none without one",
            ir.operation
        );
        for index in &reads {
            assert!(
                generated[index.saturating_add(READ.len())..].starts_with(SETTLE),
                "{}: the verification is the statement immediately after the body is buffered",
                ir.operation
            );
        }
        buffered = buffered.saturating_add(reads.len());
    }
    assert!(
        buffered >= 20,
        "only {buffered} operations buffer a body; the control has nothing to look at"
    );
}

/// MinIO's body literal is read by exactly the decoders whose IR says `xml.body_literal`, once
/// each, after the digest has been checked over the bytes that arrived and before the document is
/// parsed; no other decoder names it (rustfs/backlog#1677, R6).
#[test]
fn only_a_body_literal_decoder_reads_the_literal_and_only_after_the_digest() {
    const SETTLE: &str = "value::verify_body_digest(request, raw_body.as_ref())?;";
    const PARSE: &str = "rustfs_gateway_xml::parse(raw_body.as_ref())";
    let artifacts = super::codegen_tests::artifacts();
    let mut literal_decoders = Vec::new();
    for ir in &artifacts.operations {
        let generated = crate::emit::codec::decode::body(ir, &artifacts.codec_rules, &artifacts.error_codes)
            .expect("every included operation has a decoder");
        let calls: Vec<usize> = generated
            .match_indices("value::body_literal(request, ")
            .map(|(index, _)| index)
            .collect();
        if !ir.xml.body_literal {
            assert!(calls.is_empty(), "{}: reads a literal its IR does not accept", ir.operation);
            continue;
        }
        assert_eq!(calls.len(), 1, "{}: one literal read", ir.operation);
        let settle = generated.find(SETTLE).expect("the digest is checked");
        let parse = generated.find(PARSE).expect("the document is parsed");
        assert!(settle < calls[0] && calls[0] < parse, "{}: digest, literal, parse", ir.operation);
        literal_decoders.push(ir.operation.clone());
    }
    literal_decoders.sort_unstable();
    assert_eq!(literal_decoders, ["PutBucketVersioning", "PutObjectLockConfiguration"]);
}

#[test]
fn the_two_bounded_members_reach_the_generated_decoders() {
    let artifacts = super::codegen_tests::artifacts();
    let decoder = |name: &str| {
        let ir = artifacts
            .operations
            .iter()
            .find(|ir| ir.operation == name)
            .unwrap_or_else(|| panic!("{name} is generated"));
        crate::emit::codec::decode::body(ir, &artifacts.codec_rules, &artifacts.error_codes).expect("decodes")
    };
    assert!(decoder("UploadPart").contains("value::integer_in_range(raw, \"PartNumber\", 1, 10000)?"));
    assert!(decoder("ListObjectsV2").contains("value::integer_in_range(raw, \"MaxKeys\", 0, 1000)?"));
    // An integer nobody bounded still takes the plain parser, so the change is not a blanket one.
    assert!(decoder("ListParts").contains("value::integer(raw, \"MaxParts\")?"));
}
