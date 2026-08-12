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

//! What the wire-form refusals the model does not state actually generate.
//!
//! Responsible for: the form resolution rules, and that the declared forms reach the decoders of
//! the members that carry them and no others.
//! NOT responsible for: what the refusals do to a request, which is `rustfs-gateway-core`'s codec
//! suite.
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use rustfs_gateway_model::ir::{Binding, Field, Type};
use rustfs_gateway_model::{CodecRule, CodecValue, MutationDimension, WireFormValue};

use crate::emit::codec::forms::{self, Form};

fn field(name: &str, ty: Type, quirks: &[&str]) -> Field {
    Field {
        name: name.to_owned(),
        wire_name: Some(name.to_lowercase()),
        required: false,
        binding: Binding::Header,
        ty,
        hot: false,
        default: None,
        omit_when: None,
        missing_error: None,
        quirk_refs: quirks.iter().map(|q| (*q).to_owned()).collect(),
    }
}

fn wire_form(current: WireFormValue) -> CodecRule {
    CodecRule {
        current: CodecValue::WireForm(current),
        mutation_dimension: MutationDimension::WireForm,
    }
}

#[test]
fn a_field_with_no_quirk_at_all_has_no_wire_form() {
    let resolved = forms::of(&field("IfMatch", Type::String, &[]), &BTreeMap::new(), "Fixture").expect("resolves");
    assert_eq!(resolved, None, "an ordinary string keeps the plain conversion");
}

#[test]
fn metadata_without_a_typed_rule_does_not_declare_a_form() {
    let resolved = forms::of(&field("IfMatch", Type::String, &["q-cond-0046"]), &BTreeMap::new(), "Fixture").expect("resolves");
    assert_eq!(resolved, None, "only the typed rule map declares a grammar");
}

#[test]
fn the_declared_forms_reach_the_members_that_carry_them() {
    let values = BTreeMap::from([
        ("q-etag-form-0074".to_owned(), wire_form(WireFormValue::EntityTag)),
        ("q-token-form-0075".to_owned(), wire_form(WireFormValue::OpaqueToken)),
        ("q-marker-form-0076".to_owned(), wire_form(WireFormValue::OpaqueToken)),
    ]);
    let tag = forms::of(&field("IfMatch", Type::String, &["q-etag-form-0074"]), &values, "GetObject").expect("resolves");
    assert_eq!(tag, Some(Form::EntityTag));
    let cursor = forms::of(
        &field("ContinuationToken", Type::OpaqueString, &["q-token-form-0075"]),
        &values,
        "ListObjectsV2",
    )
    .expect("resolves");
    assert_eq!(cursor, Some(Form::OpaqueToken));
    // The same cursor grammar, reached through a member the model left as a plain string.
    let marker = forms::of(
        &field("UploadIdMarker", Type::String, &["q-marker-form-0076"]),
        &values,
        "ListMultipartUploads",
    )
    .expect("resolves");
    assert_eq!(marker, Some(Form::OpaqueToken));
}

#[test]
fn a_wire_form_comes_from_the_quirk_value_not_its_id() {
    let values = BTreeMap::from([("q-invented-9999".to_owned(), wire_form(WireFormValue::EntityTag))]);

    let resolved = forms::of(&field("IfMatch", Type::String, &["q-invented-9999"]), &values, "Fixture")
        .expect("the overlay value, not a Rust id table, selects the grammar");

    assert_eq!(resolved, Some(Form::EntityTag));
}

#[test]
fn the_storage_is_composed_around_one_checker_per_grammar() {
    assert_eq!(
        Form::OpaqueToken.call("ContinuationToken", &Type::OpaqueString),
        "value::opaque(value::token_form(raw, \"ContinuationToken\")?)"
    );
    assert_eq!(
        Form::OpaqueToken.call("UploadIdMarker", &Type::String),
        "value::token_form(raw, \"UploadIdMarker\")?.to_owned()"
    );
}

#[test]
fn free_text_kind_is_not_a_codec_gate() {
    let resolved = forms::of(&field("IfMatch", Type::String, &["q-invented-9999"]), &BTreeMap::new(), "Fixture")
        .expect("metadata cannot control codec generation");
    assert_eq!(resolved, None);
}

#[test]
fn n_a_form_on_a_member_whose_type_it_cannot_read_fails_the_run() {
    let values = BTreeMap::from([("q-etag-form-0074".to_owned(), wire_form(WireFormValue::EntityTag))]);
    let error = forms::of(&field("MaxKeys", Type::Integer, &["q-etag-form-0074"]), &values, "Fixture")
        .expect_err("an entity-tag grammar on an integer is a mistake, not a grammar");
    assert!(error.contains("MaxKeys"), "{error}");
}

#[test]
fn n_two_form_quirks_disagreeing_on_one_member_fail_the_run() {
    let values = BTreeMap::from([
        ("q-etag-form-0074".to_owned(), wire_form(WireFormValue::EntityTag)),
        ("q-token-form-0075".to_owned(), wire_form(WireFormValue::OpaqueToken)),
    ]);
    let member = field("Confused", Type::String, &["q-etag-form-0074", "q-token-form-0075"]);
    let error = forms::of(&member, &values, "Fixture").expect_err("one member has one wire form");
    assert!(error.contains("Confused"), "{error}");
}

#[test]
fn the_declared_forms_reach_the_generated_decoders() {
    let artifacts = super::codegen_tests::artifacts();
    let decoder = |name: &str| {
        let ir = artifacts
            .operations
            .iter()
            .find(|ir| ir.operation == name)
            .unwrap_or_else(|| panic!("{name} is generated"));
        crate::emit::codec::decode::body(ir, &artifacts.codec_rules).expect("decodes")
    };
    assert!(decoder("GetObject").contains("value::etag_form(raw, \"IfMatch\")?.to_owned()"));
    assert!(decoder("HeadObject").contains("value::etag_form(raw, \"IfNoneMatch\")?.to_owned()"));
    assert!(decoder("ListObjectsV2").contains("value::opaque(value::token_form(raw, \"ContinuationToken\")?)"));
    assert!(decoder("ListMultipartUploads").contains("value::token_form(raw, \"UploadIdMarker\")?.to_owned()"));
    // A string nobody gave a grammar to still takes the plain conversion, so the change is not a
    // blanket one: the key marker beside the upload-id marker is a key, and a key is not a token.
    assert!(decoder("ListMultipartUploads").contains("input.key_marker = Some(raw.to_owned());"));
}
