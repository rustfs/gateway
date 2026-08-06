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

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use rustfs_gateway_model::ir::{Binding, Evidence, Field, Quirk, Type};

use crate::emit::codec::forms::{self, FORM_KIND, Form};

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

fn quirk(id: &str, kind: &str) -> Quirk {
    Quirk {
        id: id.to_owned(),
        kind: kind.to_owned(),
        target: "Fixture.Member".to_owned(),
        summary: "a fixture quirk, long enough to satisfy the schema".to_owned(),
        evidence: vec![Evidence {
            kind: "observed".to_owned(),
            reference: "fixture".to_owned(),
            summary: "a fixture evidence entry, long enough".to_owned(),
        }],
        cases: vec!["c-fixture-0001".to_owned()],
    }
}

#[test]
fn a_field_with_no_quirk_at_all_has_no_wire_form() {
    let resolved = forms::of(&field("IfMatch", Type::String, &[]), &[], "Fixture").expect("resolves");
    assert_eq!(resolved, None, "an ordinary string keeps the plain conversion");
}

#[test]
fn a_quirk_of_another_kind_does_not_declare_a_form() {
    let quirks = vec![quirk("q-cond-0046", "etag_compare")];
    let resolved = forms::of(&field("IfMatch", Type::String, &["q-cond-0046"]), &quirks, "Fixture").expect("resolves");
    assert_eq!(resolved, None, "only `{FORM_KIND}` declares a grammar");
}

#[test]
fn the_declared_forms_reach_the_members_that_carry_them() {
    let quirks = vec![
        quirk("q-etag-form-0074", FORM_KIND),
        quirk("q-token-form-0075", FORM_KIND),
        quirk("q-marker-form-0076", FORM_KIND),
    ];
    let tag = forms::of(&field("IfMatch", Type::String, &["q-etag-form-0074"]), &quirks, "GetObject").expect("resolves");
    assert_eq!(tag, Some(Form::EntityTag));
    let cursor = forms::of(
        &field("ContinuationToken", Type::OpaqueString, &["q-token-form-0075"]),
        &quirks,
        "ListObjectsV2",
    )
    .expect("resolves");
    assert_eq!(cursor, Some(Form::OpaqueToken));
    // The same cursor grammar, reached through a member the model left as a plain string.
    let marker = forms::of(
        &field("UploadIdMarker", Type::String, &["q-marker-form-0076"]),
        &quirks,
        "ListMultipartUploads",
    )
    .expect("resolves");
    assert_eq!(marker, Some(Form::OpaqueToken));
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
fn n_a_form_quirk_with_no_declared_grammar_fails_the_run() {
    // The failure mode this prevents: an overlay claims a member has a wire form, nothing checks
    // it, and the refusal quietly stops existing while its evidence keeps saying it does.
    let quirks = vec![quirk("q-invented-9999", FORM_KIND)];
    let error = forms::of(&field("IfMatch", Type::String, &["q-invented-9999"]), &quirks, "Fixture")
        .expect_err("a form quirk with no grammar is an overlay mistake, not a no-op");
    assert!(error.contains("q-invented-9999"), "{error}");
    assert!(error.contains("forms.rs"), "the failure names where the row belongs: {error}");
}

#[test]
fn n_a_form_on_a_member_whose_type_it_cannot_read_fails_the_run() {
    let quirks = vec![quirk("q-etag-form-0074", FORM_KIND)];
    let error = forms::of(&field("MaxKeys", Type::Integer, &["q-etag-form-0074"]), &quirks, "Fixture")
        .expect_err("an entity-tag grammar on an integer is a mistake, not a grammar");
    assert!(error.contains("MaxKeys"), "{error}");
}

#[test]
fn n_two_form_quirks_disagreeing_on_one_member_fail_the_run() {
    let quirks = vec![quirk("q-etag-form-0074", FORM_KIND), quirk("q-token-form-0075", FORM_KIND)];
    let member = field("Confused", Type::String, &["q-etag-form-0074", "q-token-form-0075"]);
    let error = forms::of(&member, &quirks, "Fixture").expect_err("one member has one wire form");
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
        crate::emit::codec::decode::body(ir).expect("decodes")
    };
    assert!(decoder("GetObject").contains("value::etag_form(raw, \"IfMatch\")?.to_owned()"));
    assert!(decoder("HeadObject").contains("value::etag_form(raw, \"IfNoneMatch\")?.to_owned()"));
    assert!(decoder("ListObjectsV2").contains("value::opaque(value::token_form(raw, \"ContinuationToken\")?)"));
    assert!(decoder("ListMultipartUploads").contains("value::token_form(raw, \"UploadIdMarker\")?.to_owned()"));
    // A string nobody gave a grammar to still takes the plain conversion, so the change is not a
    // blanket one: the key marker beside the upload-id marker is a key, and a key is not a token.
    assert!(decoder("ListMultipartUploads").contains("input.key_marker = Some(raw.to_owned());"));
}
