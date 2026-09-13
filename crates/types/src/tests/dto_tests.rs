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
//! Responsible for: functional update syntax, `Default` on every Output, the bare-required /
//! `Option`-optional member shape, the placeholder contract that pays for it, the identity of the
//! two facades, open string enumerations, and the redaction of key material in `Debug`.
//! NOT responsible for: the shape of the generator's output text — that is `rustfs-gateway-codegen`.
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.
//!
//! Every test here compiles the property it asserts. A test that only inspects a string could not
//! tell whether `..Default::default()` still works, and that is the single fact this whole layout
//! exists to preserve.

use crate::dto;
use crate::ops::enums::{ChecksumAlgorithm, EncodingType, StorageClass};
use crate::ops::shapes::Object;
use crate::ops::{get_bucket_location, list_objects_v2, put_object};
use crate::{BucketName, ETag, ObjectKey, SseCustomerKey, Timestamp, WirePlaceholder};

// ── positive ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_dto_0002_every_output_can_be_defaulted() {
    let _ = get_bucket_location::Output::default();
    let _ = list_objects_v2::Output::default();
    let put = put_object::Output::default();
    assert!(
        put.e_tag.is_wire_placeholder(),
        "a defaulted Output invents no wire value: the required ETag is the placeholder, not a tag"
    );
    assert!(put.check_required().is_err(), "and the decode-path guard says so");
}

#[test]
fn c_dto_0003_functional_update_syntax_constructs_an_input() {
    let bucket = BucketName::new("example-bucket").expect("a valid bucket name");
    let input = list_objects_v2::Input {
        bucket,
        max_keys: Some(100),
        ..Default::default()
    };
    assert_eq!(input.max_keys, Some(100));
    assert!(input.prefix.is_none(), "the remaining members stay absent");
    input.check_required().expect("every required member is filled in");
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
    let bucket = BucketName::new("example-bucket").expect("a valid bucket name");
    let built = get_bucket_location::Input::builder().bucket(bucket.clone()).build();
    let literal = get_bucket_location::Input {
        bucket,
        ..Default::default()
    };
    assert_eq!(built.bucket.as_str(), literal.bucket.as_str());
}

#[test]
fn c_dto_0008_a_required_member_is_a_bare_type_and_needs_no_unwrapping() {
    // The migration property the arbitration on issue 1722 was about: `req.input.bucket` is the
    // bucket, not an `Option` a handler has to unwrap at every call site. This test is the
    // compiled form of that claim — it would not build if the member went back to `Option`.
    let input = put_object::Input {
        bucket: BucketName::new("example-bucket").expect("a valid bucket name"),
        key: ObjectKey::new("a/b.txt").expect("a valid key"),
        content_length: 7,
        ..Default::default()
    };
    let bucket: &str = input.bucket.as_str();
    let key: &str = input.key.as_str();
    assert_eq!((bucket, key, input.content_length), ("example-bucket", "a/b.txt", 7));
    input.check_required().expect("every required member is filled in");
}

// ── negative ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_dto_n005_a_defaulted_input_carries_no_usable_required_value() {
    // A defaulted Input is constructible — P1 needs that — but it is not a request. Every required
    // member holds the wire-invalid placeholder P10 prescribes, so nothing here could be mistaken
    // for something a client sent.
    let input = put_object::Input::default();
    assert!(input.bucket.is_wire_placeholder(), "the bucket is a placeholder, not a name");
    assert!(input.key.is_wire_placeholder(), "the key is a placeholder, not a key");
    assert!(
        crate::validate_bucket_name(input.bucket.as_str()).is_err(),
        "and it is invalid on the wire"
    );
    assert!(crate::validate_object_key(input.key.as_str()).is_err());
    assert_eq!(
        put_object::PutObject::REQUIRED_INPUT,
        ["Bucket", "ContentLength", "Key"],
        "the requirement is data as well as type"
    );
}

#[test]
fn c_dto_n028_the_decode_guard_rejects_a_placeholder_and_names_the_member() {
    // The decode-path exit check (ADR-0004 P10). It returns an error rather than asserting,
    // because a `debug_assert!` is compiled out of exactly the build that faces hostile input.
    let err = put_object::Input::default()
        .check_required()
        .expect_err("a defaulted Input has not been decoded from anything");
    assert_eq!(err.type_name(), "PutObjectInput");
    assert_eq!(err.member(), "Bucket", "the first offending member is named");
    assert!(err.to_string().contains("placeholder default"), "{err}");
}

#[test]
fn c_dto_n029_a_zero_content_length_is_not_a_placeholder() {
    // `Content-Length: 0` is a legitimate PutObject, and an empty `Prefix` is a legitimate
    // listing. Numbers and plain strings have no bit pattern meaning "not filled in", so the guard
    // must not invent one — treating zero as absent would reject valid requests.
    let input = put_object::Input {
        bucket: BucketName::new("example-bucket").expect("a valid bucket name"),
        key: ObjectKey::new("empty").expect("a valid key"),
        content_length: 0,
        ..Default::default()
    };
    input.check_required().expect("zero is a length, not a placeholder");

    let output = list_objects_v2::Output {
        name: BucketName::new("example-bucket").expect("a valid bucket name"),
        prefix: String::new(),
        is_truncated: false,
        ..Default::default()
    };
    output.check_required().expect("an empty prefix is a prefix");
}

#[test]
fn c_dto_n030_a_placeholder_scalar_is_never_a_value_its_own_parser_would_accept() {
    // P10's substance: every placeholder is rejected by the constructor of its own type, so no
    // decoding path can produce one and a hand-built one cannot be mistaken for wire data.
    assert!(BucketName::new(BucketName::default().as_str()).is_err());
    assert!(ObjectKey::new(ObjectKey::default().as_str()).is_err());
    assert!(ETag::default().is_wire_placeholder());
    assert!(!ETag::default().is_any(), "the placeholder is not the `*` wildcard either");
    for format in [
        crate::TimestampFormat::HttpDate,
        crate::TimestampFormat::Iso8601,
        crate::TimestampFormat::Iso8601Basic,
    ] {
        assert!(Timestamp::default().render(format).is_err(), "no wire format can express {format:?}");
    }
    assert_ne!(Timestamp::default(), Timestamp::UNIX_EPOCH, "1970 is a real instant a client may mean");
}

#[test]
fn c_dto_n031_a_nested_shape_is_checked_as_deeply_as_it_is_required() {
    // `Object` is reached through a container, so a listing entry that was never filled in must
    // still be catchable — the guard is a method on the shape itself, not only on the Output.
    let entry = Object::default();
    let err = entry.check_required().expect_err("a defaulted listing entry names no object");
    assert_eq!((err.type_name(), err.member()), ("Object", "Key"));

    let filled = Object {
        key: ObjectKey::new("a/b.txt").expect("a valid key"),
        last_modified: Timestamp::from_secs(1_700_000_000),
        e_tag: ETag::new("d41d8cd98f00b204e9800998ecf8427e").expect("a valid tag"),
        size: 0,
        storage_class: StorageClass::STANDARD,
        ..Default::default()
    };
    filled.check_required().expect("a fully decoded entry passes");
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
        sse_customer_key: Some(SseCustomerKey::new("this-must-never-be-logged".to_owned())),
        ssekms_key_id: Some("kms-key-id-must-never-be-logged".to_owned()),
        ssekms_encryption_context: Some("this-must-never-be-logged-either".to_owned()),
        ..Default::default()
    };
    let rendered = format!("{input:?}");
    assert!(!rendered.contains("must-never-be-logged"), "key material reached Debug: {rendered}");
    assert!(!rendered.contains("kms-key-id"), "KMS key id reached Debug: {rendered}");
    assert!(rendered.contains("<redacted>"), "the field is still listed, with a placeholder");
}

#[test]
fn c_dto_n023_debug_never_prints_a_key_digest_or_a_bucket_kms_key_id() {
    let input = put_object::Input {
        sse_customer_key_md5: Some("digest-must-never-be-logged".to_owned()),
        ..Default::default()
    };
    let rendered = format!("{input:?}");
    assert!(
        !rendered.contains("digest-must-never-be-logged"),
        "a key digest reached Debug: {rendered}"
    );
    assert!(rendered.contains("sse_customer_key_md5: Some(\"<redacted>\")"), "{rendered}");

    let default = dto::ServerSideEncryptionByDefault {
        kms_master_key_id: Some("bucket-kms-key-must-never-be-logged".to_owned()),
        ..Default::default()
    };
    let rendered = format!("{default:?}");
    assert!(
        !rendered.contains("must-never-be-logged"),
        "a bucket KMS key id reached Debug: {rendered}"
    );
    assert!(rendered.contains("kms_master_key_id: Some(\"<redacted>\")"), "{rendered}");
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
