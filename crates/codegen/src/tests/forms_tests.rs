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

//! The ownership boundary for values whose final grammar belongs to an operation parser.
//!
//! Responsible for: proving that generated codecs preserve conditional tags and listing cursors
//! unchanged, and that free-text `wire_form` records do not become mutable codec inputs.
//! NOT responsible for: the final rejection, which the linked conformance cases exercise through
//! the operation parser. Upstream: the overlay and codec emitter. Downstream: generated decoders.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::OnceLock;

use rustfs_gateway_model::ir::Type;
use rustfs_gateway_model::overlay::RuleClassification;

fn artifacts() -> &'static crate::Artifacts {
    static ARTIFACTS: OnceLock<crate::Artifacts> = OnceLock::new();
    ARTIFACTS.get_or_init(super::codegen_tests::artifacts)
}

fn decoder(name: &str) -> String {
    let artifacts = artifacts();
    let ir = artifacts
        .operations
        .iter()
        .find(|ir| ir.operation == name)
        .unwrap_or_else(|| panic!("{name} is generated"));
    crate::emit::codec::decode::body(ir, &artifacts.codec_rules, &artifacts.error_codes).expect("decodes")
}

#[test]
fn a_field_with_no_quirk_at_all_has_no_wire_form() {
    let conversion = crate::emit::codec::expr::from_wire(&Type::String, "Value", "Fixture", false, None, None, "names")
        .expect("a string has a plain decoder");
    assert_eq!(conversion, "raw.to_owned()");
}

#[test]
fn metadata_without_a_typed_rule_does_not_declare_a_form() {
    let artifacts = artifacts();
    for id in ["q-etag-form-0074", "q-token-form-0075", "q-marker-form-0076"] {
        assert!(!artifacts.codec_rules.contains_key(id), "{id} must not select codec validation");
    }
}

#[test]
fn the_contract_forms_reach_the_members_that_carry_them_unchanged() {
    assert!(decoder("GetObject").contains("input.if_match = Some(raw.to_owned());"));
    assert!(decoder("ListObjectsV2").contains("input.continuation_token = Some(value::opaque(raw));"));
    assert!(decoder("ListMultipartUploads").contains("input.upload_id_marker = Some(raw.to_owned());"));
}

#[test]
fn a_wire_form_comes_from_the_contract_record_not_a_codec_rule() {
    let root = super::codegen_tests::root();
    let overlay = rustfs_gateway_model::Overlay::load(&root.join("model/overlays")).expect("the canonical overlay loads");
    assert_eq!(overlay.classifications.get("q-etag-form-0074"), Some(&RuleClassification::Contract));
    assert!(!overlay.codec_rules.contains_key("q-etag-form-0074"));
}

#[test]
fn the_storage_is_composed_without_a_codec_owned_checker() {
    assert_eq!(
        crate::emit::codec::expr::from_wire(&Type::OpaqueString, "ContinuationToken", "Fixture", false, None, None, "names",)
            .expect("an opaque string is preserved"),
        "value::opaque(raw)"
    );
    assert_eq!(
        crate::emit::codec::expr::from_wire(&Type::String, "UploadIdMarker", "Fixture", false, None, None, "names")
            .expect("a string is preserved"),
        "raw.to_owned()"
    );
}

#[test]
fn free_text_kind_is_not_a_codec_gate() {
    let root = super::codegen_tests::root();
    let overlay = rustfs_gateway_model::Overlay::load(&root.join("model/overlays")).expect("the canonical overlay loads");
    for id in ["q-tag-wrapped-0088", "q-tag-header-form-0093"] {
        assert!(!overlay.codec_rules.contains_key(id), "{id} free-text metadata cannot select a codec");
    }
}

#[test]
fn n_contract_wire_forms_emit_no_mutable_spec_record() {
    let artifacts = artifacts();
    for id in ["q-etag-form-0074", "q-token-form-0075", "q-marker-form-0076"] {
        let suffix = format!("spec/quirks/{id}.toml");
        assert!(
            artifacts
                .files
                .iter()
                .all(|(path, _)| !path.to_string_lossy().ends_with(&suffix)),
            "{id} has no mechanically distinct mutation"
        );
    }
}

#[test]
fn n_generated_decoders_do_not_call_removed_wire_form_validators() {
    for operation in ["GetObject", "HeadObject", "ListObjectsV2", "ListMultipartUploads"] {
        let text = decoder(operation);
        assert!(!text.contains("etag_form("), "{operation} still calls the removed tag validator");
        assert!(!text.contains("token_form("), "{operation} still calls the removed token validator");
    }
}

#[test]
fn contract_wire_forms_are_not_emitted_as_mutable_spec_data() {
    let artifacts = artifacts();
    let root = super::codegen_tests::root();
    let overlay = rustfs_gateway_model::Overlay::load(&root.join("model/overlays")).expect("the canonical overlay loads");
    for id in ["q-etag-form-0074", "q-token-form-0075", "q-marker-form-0076"] {
        let path = format!("spec/quirks/{id}.toml");
        assert!(
            artifacts
                .files
                .iter()
                .all(|(candidate, _)| !candidate.to_string_lossy().ends_with(&path)),
            "{id} must not claim a mechanically distinct mutation"
        );
        assert_eq!(
            overlay.classifications.get(id),
            Some(&RuleClassification::Contract),
            "{id} keeps its evidence without duplicating the operation-owned validator"
        );
    }
}

#[test]
fn contract_wire_forms_leave_validation_to_the_operation_parser() {
    let get = decoder("GetObject");
    assert!(get.contains("input.if_match = Some(raw.to_owned());"));
    assert!(!get.contains("value::etag_form(raw, \"IfMatch\")?"));

    let head = decoder("HeadObject");
    assert!(head.contains("input.if_none_match = Some(raw.to_owned());"));
    assert!(!head.contains("value::etag_form(raw, \"IfNoneMatch\")?"));

    let list = decoder("ListObjectsV2");
    assert!(list.contains("input.continuation_token = Some(value::opaque(raw));"));
    assert!(!list.contains("value::token_form(raw, \"ContinuationToken\")?"));

    let multipart = decoder("ListMultipartUploads");
    assert!(multipart.contains("input.upload_id_marker = Some(raw.to_owned());"));
    assert!(!multipart.contains("value::token_form(raw, \"UploadIdMarker\")?"));
}
