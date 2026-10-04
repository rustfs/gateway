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

//! That `encoding-type=url` reaches the members the overlays declare, and that a path which
//! reaches none fails the run.
//!
//! Responsible for: the resolution of `xml.url_encoded_fields` into per-member decisions, and the
//! calls that resolution produces in the generated response half, including the forced echo.
//! NOT responsible for: what percent-encoding does to bytes, which is
//! `rustfs-gateway-core`'s codec suite.
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use rustfs_gateway_model::ir::OperationIr;

use super::codegen_tests::artifacts;
use crate::emit::codec::{encode, url};

fn ir(operation: &str) -> OperationIr {
    artifacts()
        .operations
        .into_iter()
        .find(|ir| ir.operation == operation)
        .unwrap_or_else(|| panic!("{operation} is generated from the pinned model"))
}

#[test]
fn every_declared_path_in_the_pinned_model_resolves_to_a_member() {
    // The whole defect was a declaration nothing read. A path that resolves to nothing is the same
    // failure one member at a time, so it is refused rather than skipped — and this asserts the
    // refusal never fires for what the overlays actually declare today.
    for operation in artifacts().operations {
        let declared = operation.xml.url_encoded_fields.len();
        let plan = url::plan(&operation)
            .unwrap_or_else(|error| panic!("{} declares a path that resolves to nothing: {error}", operation.operation));
        assert_eq!(
            plan.is_empty(),
            declared == 0,
            "{} declares {declared} path(s) and the plan disagrees",
            operation.operation
        );
    }
}

#[test]
fn the_listing_families_encode_their_root_members_and_their_entry_keys() {
    for operation in ["ListObjects", "ListObjectsV2", "ListObjectVersions", "ListMultipartUploads"] {
        let plan = url::plan(&ir(operation)).expect("resolves");
        assert!(plan.encodes_root("Prefix"), "{operation} must encode Prefix");
        assert!(plan.encodes_root("Delimiter"), "{operation} must encode Delimiter");
        assert!(
            plan.encodes_shape("CommonPrefix") && plan.encodes_shape_member("CommonPrefix", "Prefix"),
            "{operation} must encode the rolled-up prefixes as well as the keys"
        );
    }
}

#[test]
fn the_generated_encoder_reads_the_decision_once_and_passes_it_down() {
    let body = encode::body(&ir("ListObjectsV2"), &Default::default()).expect("encodes");
    assert_eq!(
        body.matches("value::url_encoding_for_response(request,").count(),
        1,
        "one decision per response, not one per member:\n{body}"
    );
    assert!(
        body.contains(
            "output.encoding_type = if url_encoding == value::UrlEncoding::Requested {\n\
             \x20           Some(dto::EncodingType::URL)\n\
             \x20       } else {\n\
             \x20           None\n\
             \x20       };"
        ),
        "the response-wide decision must set and clear the URL echo authoritatively:\n{body}"
    );
    assert!(
        body.contains("write_object(&mut writer, item, url_encoding)?"),
        "the entry writer receives the same decision the root used:\n{body}"
    );
    assert!(
        body.contains("&value::url_encoded(v.as_str(), url_encoding)"),
        "a declared root member is written through the encoder:\n{body}"
    );
}

#[test]
fn n_forced_encoding_cannot_ignore_the_requests_listing_profile() {
    for operation in ["ListObjects", "ListObjectsV2", "ListObjectVersions", "ListMultipartUploads"] {
        let body = encode::body(&ir(operation), &Default::default()).expect("encodes");
        assert!(
            body.contains("value::requires_url_encoding(request, &output.prefix)"),
            "{operation}: {body}"
        );
        assert!(
            body.contains("value::any_requires_url_encoding(request, &output.common_prefixes,"),
            "{operation}: {body}"
        );
    }
}

#[test]
fn n_an_operation_that_declares_nothing_reads_no_decision_at_all() {
    let body = encode::body(&ir("ListBuckets"), &Default::default()).expect("encodes");
    assert!(
        !body.contains("url_encoding"),
        "a decision nothing consumes would not compile under -D warnings:\n{body}"
    );
}

#[test]
fn n_a_path_naming_a_member_that_does_not_exist_fails_the_run() {
    let mut ir = ir("ListObjectsV2");
    ir.xml.url_encoded_fields = vec!["Prefixx".to_owned()];
    let error = url::plan(&ir).expect_err("a misspelled member must not be skipped");
    assert!(error.contains("Prefixx"), "{error}");
}

#[test]
fn n_a_path_naming_a_shape_member_that_does_not_exist_fails_the_run() {
    let mut ir = ir("ListObjectsV2");
    // The realistic spelling mistake: the member is `ETag`, and the model's own casing is easy to
    // get wrong from memory.
    ir.xml.url_encoded_fields = vec!["Contents.Etag".to_owned()];
    let error = url::plan(&ir).expect_err("a member of the wrong casing is not the member");
    assert!(error.contains("Contents.Etag"), "{error}");
}

#[test]
fn n_a_path_deeper_than_two_segments_fails_the_run() {
    let mut ir = ir("ListObjectsV2");
    ir.xml.url_encoded_fields = vec!["Contents.Owner.DisplayName".to_owned()];
    let error = url::plan(&ir).expect_err("the emitter has no way to thread the decision that deep");
    assert!(error.contains("two segments"), "{error}");
}

#[test]
fn n_a_path_naming_a_scalar_as_a_container_fails_the_run() {
    let mut ir = ir("ListObjectsV2");
    ir.xml.url_encoded_fields = vec!["Prefix.Key".to_owned()];
    let error = url::plan(&ir).expect_err("a string has no members");
    assert!(error.contains("no nested shape"), "{error}");
}

#[test]
fn n_a_member_whose_type_has_no_encoded_form_fails_the_run() {
    let mut ir = ir("ListObjectsV2");
    ir.xml.url_encoded_fields = vec!["MaxKeys".to_owned()];
    let error = encode::body(&ir, &Default::default()).expect_err("percent-encoding an integer is a path with no wire form");
    assert!(error.contains("MaxKeys"), "{error}");
}

/// Every encodable member is written through a decision narrowed to its own path, so a profile can
/// encode some declared members and not others (rustfs/gateway#1059): a root member by name, a
/// nested one as `Shape.Member`.
#[test]
fn every_encoded_member_narrows_the_decision_to_its_own_path() {
    let body = encode::body(&ir("ListObjectsV2"), &Default::default()).expect("encodes");
    let artifacts = artifacts();
    let shapes = crate::emit::codec::operation_for_test(&ir("ListObjectsV2"), &artifacts.codec_rules, &artifacts.error_codes)
        .expect("the whole codec renders");
    for path in ["Prefix", "Delimiter", "StartAfter"] {
        assert!(
            body.contains(&format!("let url_encoding = url_encoding.member(\"{path}\");")),
            "{path} is not narrowed:\n{body}"
        );
    }
    for path in ["Object.Key", "CommonPrefix.Prefix"] {
        assert!(
            shapes.contains(&format!("let url_encoding = url_encoding.member(\"{path}\");")),
            "{path} is not narrowed:\n{shapes}"
        );
    }
    assert!(
        body.contains("value::rustfs_listing_echo(request, url_encoding, &mut output.encoding_type);"),
        "the RustFS profile's echo follows the model echo:\n{body}"
    );
}

/// Negative — an opaque paging token has no URL-encoding decision, even on an encoded listing.
#[test]
fn n_continuation_tokens_are_not_url_encoded_fields() {
    let operation = ir("ListObjectsV2");
    let body = encode::body(&operation, &Default::default()).expect("encodes");
    for field in ["ContinuationToken", "NextContinuationToken"] {
        assert!(!operation.xml.url_encoded_fields.iter().any(|path| path == field), "{field}");
        assert!(!body.contains(&format!("url_encoding.member(\"{field}\")")), "{field}: {body}");
    }
}

/// Negative — a member the IR does not declare encodable is never narrowed, and an operation with
/// no echo member emits no echo call.
#[test]
fn n_an_undeclared_member_is_never_narrowed_and_no_echo_member_means_no_echo_call() {
    let body = encode::body(&ir("ListObjectsV2"), &Default::default()).expect("encodes");
    for path in ["Name", "MaxKeys", "KeyCount", "EncodingType"] {
        assert!(
            !body.contains(&format!("url_encoding.member(\"{path}\")")),
            "{path} is narrowed although nothing declares it:\n{body}"
        );
    }
    let parts = encode::body(&ir("ListParts"), &Default::default()).expect("encodes");
    assert!(parts.contains("let url_encoding = url_encoding.member(\"Key\");"), "{parts}");
    assert!(!parts.contains("rustfs_listing_echo"), "ListParts has no echo member:\n{parts}");
}
