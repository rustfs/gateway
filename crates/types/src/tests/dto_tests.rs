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

//! What ADR-0004 promises a consumer of the generated dto.
//!
//! Responsible for: functional update syntax, `Default` on every Output, the identity of the two
//! facades, open string enumerations, and the redaction of key material in `Debug`.
//! NOT responsible for: the shape of the generator's output text — that is `rustfs-gateway-codegen`.
//!
//! Every test here compiles the property it asserts. A test that only inspects a string could not
//! tell whether `..Default::default()` still works, and that is the single fact this whole layout
//! exists to preserve.

use crate::dto;
use crate::ops::enums::{ChecksumAlgorithm, EncodingType, StorageClass};
use crate::ops::{get_bucket_location, list_objects_v2, put_object};

// ── positive ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_dto_0002_every_output_can_be_defaulted() {
    let _ = get_bucket_location::Output::default();
    let _ = list_objects_v2::Output::default();
    let put = put_object::Output::default();
    assert!(put.e_tag.is_none(), "a defaulted Output invents no wire value");
}

#[test]
fn c_dto_0003_functional_update_syntax_constructs_an_input() {
    let bucket = crate::BucketName::new("example-bucket").expect("a valid bucket name");
    let input = list_objects_v2::Input {
        bucket: Some(bucket),
        max_keys: Some(100),
        ..Default::default()
    };
    assert_eq!(input.max_keys, Some(100));
    assert!(input.prefix.is_none(), "the remaining members stay absent");
}

#[test]
fn c_dto_0004_a_new_optional_member_leaves_functional_update_syntax_compiling() {
    // The control group from ADR-0004, expressed as a compiled fact rather than a claim: every
    // member below the two named ones arrived from the model without this call site changing.
    let input = put_object::Input {
        content_type: Some("text/plain".to_owned()),
        ..Default::default()
    };
    assert!(input.storage_class.is_none());
    assert!(input.metadata.is_empty(), "a map member defaults to empty, never to absent");
}

#[test]
fn c_dto_0006_the_two_facades_name_the_same_types() {
    let flat: dto::ListObjectsV2Output = list_objects_v2::Output::default();
    let nested: list_objects_v2::Output = flat;
    assert!(nested.contents.is_empty());

    let marker: dto::PutObject = put_object::PutObject;
    assert_eq!(marker, put_object::PutObject);
    assert_eq!(put_object::PutObject::NAME, "PutObject");
}

#[test]
fn c_dto_0005_a_string_enumeration_exposes_its_model_values() {
    assert_eq!(StorageClass::STANDARD.as_str(), "STANDARD");
    assert_eq!(StorageClass::GLACIER.as_str(), "GLACIER");
    assert!(StorageClass::STANDARD.is_known());
    assert_eq!(EncodingType::URL.as_str(), "url");
}

#[test]
fn c_dto_0007_the_builder_and_the_struct_literal_agree() {
    let bucket = crate::BucketName::new("example-bucket").expect("a valid bucket name");
    let built = get_bucket_location::Input::builder().bucket(bucket.clone()).build();
    let literal = get_bucket_location::Input {
        bucket: Some(bucket),
        ..Default::default()
    };
    assert_eq!(built.bucket.map(|b| b.as_str().to_owned()), literal.bucket.map(|b| b.as_str().to_owned()));
}

// ── negative ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_dto_n005_a_defaulted_input_carries_no_required_value() {
    // A required member is required *on the wire*. Giving it a bare type would need a `Default`
    // for a validated newtype, i.e. an invalid bucket name reachable from safe code.
    let input = put_object::Input::default();
    assert!(input.bucket.is_none());
    assert!(input.key.is_none());
    assert!(input.content_length.is_none());
    assert_eq!(
        put_object::PutObject::REQUIRED_INPUT,
        ["Bucket", "ContentLength", "Key"],
        "the requirement survives as data even though the type does not encode it"
    );
}

#[test]
fn c_dto_n016_an_unknown_enumeration_value_is_representable_and_not_known() {
    let invented = StorageClass::custom("MOONBASE");
    assert_eq!(invented.as_str(), "MOONBASE");
    assert!(!invented.is_known(), "an invented value must not claim to be a model value");
    assert_ne!(invented, StorageClass::STANDARD);
}

#[test]
fn c_dto_n006_a_string_enumeration_accepts_a_value_the_model_never_declared() {
    // The property a real `enum` would destroy: AWS adds values every quarter, and a consumer
    // must not need a new release to name one.
    assert!(!ChecksumAlgorithm::VALUES.contains(&"BLAKE3"));
    let future = ChecksumAlgorithm::custom("BLAKE3");
    assert_eq!(future.as_str(), "BLAKE3");
}

#[test]
fn c_dto_n018_debug_never_prints_an_sse_c_key() {
    let input = put_object::Input {
        sse_customer_key: Some("this-must-never-be-logged".to_owned()),
        ssekms_encryption_context: Some("this-must-never-be-logged-either".to_owned()),
        ..Default::default()
    };
    let rendered = format!("{input:?}");
    assert!(!rendered.contains("must-never-be-logged"), "key material reached Debug: {rendered}");
    assert!(rendered.contains("<redacted>"), "the field is still listed, with a placeholder");
}

#[test]
fn c_dto_n022_debug_still_prints_the_fields_that_are_not_secret() {
    // The redaction must not degrade into "print nothing", which would make the type useless for
    // diagnostics and would tempt somebody to remove it.
    let input = put_object::Input {
        content_type: Some("text/plain".to_owned()),
        ..Default::default()
    };
    let rendered = format!("{input:?}");
    assert!(rendered.contains("text/plain"), "an ordinary member is still visible: {rendered}");
}

#[test]
fn c_dto_n023_an_absent_secret_renders_as_absent_not_as_a_placeholder() {
    let rendered = format!("{:?}", put_object::Input::default());
    assert!(
        rendered.contains("sse_customer_key: None"),
        "an absent secret must not look like a present one: {rendered}"
    );
}

#[test]
fn c_dto_n024_a_container_member_is_never_wrapped_in_an_option() {
    // `Option<Vec<_>>` has two spellings of "nothing", and the wire has one.
    let output = list_objects_v2::Output::default();
    assert!(output.contents.is_empty());
    assert!(output.common_prefixes.is_empty());
}

#[test]
fn c_dto_n025_absence_is_never_spelled_as_an_enumeration_value() {
    // A `Default` on `StorageClass` would have to pick a value, and "the client said nothing" is
    // not "the client said STANDARD" — the two produce different objects. `Option` says absent.
    let input = put_object::Input::default();
    assert!(input.storage_class.is_none());
    assert!(input.server_side_encryption.is_none());
    assert!(input.acl.is_none());
}

#[test]
fn c_dto_n026_the_wire_algorithm_set_is_wider_than_the_computable_one() {
    // `crate::ChecksumAlgorithm` is the closed set this implementation can compute;
    // `ops::enums::ChecksumAlgorithm` is whatever the wire may carry. Collapsing them would make
    // an unknown request algorithm a parse failure instead of a rejection we choose.
    assert!(ChecksumAlgorithm::VALUES.len() > 5, "the model declares more than the five we compute");
    assert!(ChecksumAlgorithm::VALUES.contains(&"CRC32"));
}
