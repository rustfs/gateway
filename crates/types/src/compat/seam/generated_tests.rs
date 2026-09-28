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

//! Tests for the leaf conversions and the generated seam against s3s 0.17.0.
//!
//! Responsible for: proving each leaf keeps its value both ways and refuses what the other side
//! cannot hold, and that generated operation conversions carry members, nested shapes, the
//! checksum fan-out and bodies. NOT responsible for: wire decode/encode parity, which the goldens
//! diff owns. Upstream: `super::leaf`, `super::generated`. Downstream: none; test-only.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use bytes::Bytes;
use rustfs_gateway_stream::{PayloadRead, PayloadStream};

use super::generated::ops;
use super::leaf;
use super::s3s::dto as oracle;
use crate::{BucketName, ChecksumAlgorithm, ChecksumSpec, ETag, ObjectKey, RangeSpec, Timestamp};

#[test]
fn a_timestamp_keeps_every_digit_s3s_can_spell() {
    let at = Timestamp::from_secs_nanos(1_700_000_000, 123_456_789).expect("instant");
    let s3s = leaf::timestamp_to_s3s("t", at).expect("to s3s");
    let mut spelled = Vec::new();
    s3s.format(oracle::TimestampFormat::DateTime, &mut spelled).expect("spells");
    assert_eq!(spelled, b"2023-11-14T22:13:20.123Z", "s3s writes milliseconds and no finer");
    let back = leaf::timestamp_from_s3s("t", &s3s).expect("from s3s");
    assert_eq!((back.secs(), back.subsec_nanos()), (1_700_000_000, 123_000_000));
}

#[test]
fn n_a_timestamp_s3s_cannot_hold_is_refused_by_member() {
    let at = Timestamp::from_secs(i64::MAX / 2);
    let error = leaf::timestamp_to_s3s("last_modified", at).expect_err("far outside the s3s range");
    assert_eq!(error.field, "last_modified");
}

#[test]
fn an_entity_tag_keeps_its_strength_both_ways() {
    for etag in [ETag::new("abc").expect("strong"), ETag::new_weak("abc").expect("weak")] {
        let back = leaf::etag_from_s3s("e_tag", leaf::etag_to_s3s(&etag)).expect("round trip");
        assert_eq!(back.is_weak(), etag.is_weak());
        assert_eq!(back.opaque_tag(), "abc");
    }
}

#[test]
fn n_an_entity_tag_the_gateway_cannot_write_is_refused() {
    let error = leaf::etag_from_s3s("e_tag", oracle::ETag::Strong("a\u{1}b".to_owned())).expect_err("control character");
    assert_eq!(error.field, "e_tag");
}

#[test]
fn n_conditions_ranges_copy_sources_and_numbers_the_s3s_grammar_rejects_are_refused() {
    assert_eq!(
        leaf::etag_condition_from_text("if_match", "not quoted")
            .expect_err("condition")
            .field,
        "if_match"
    );
    assert_eq!(
        leaf::range_to_s3s("range", &RangeSpec::new("pages=1-2"))
            .expect_err("range")
            .field,
        "range"
    );
    assert_eq!(leaf::copy_source_to_s3s("copy_source", "").expect_err("copy source").field, "copy_source");
    assert_eq!(
        leaf::parse_i32("part_number_marker", "x1").expect_err("number").field,
        "part_number_marker"
    );
    assert_eq!(
        leaf::parse_i32("part_number_marker", "99999999999").expect_err("wide").field,
        "part_number_marker"
    );
    assert_eq!(
        leaf::bucket_name("name", "Not_A_Bucket".to_owned())
            .expect_err("bucket")
            .field,
        "name"
    );
}

fn crc32() -> ChecksumSpec {
    ChecksumSpec::parse_header(ChecksumAlgorithm::Crc32.header_name(), "AAAAAA==").expect("crc32")
}

#[test]
fn the_checksum_fan_out_sets_only_the_spec_algorithm() {
    let spec = crc32();
    assert_eq!(leaf::checksum_value(Some(&spec), ChecksumAlgorithm::Crc32).as_deref(), Some("AAAAAA=="));
    assert_eq!(leaf::checksum_value(Some(&spec), ChecksumAlgorithm::Sha256), None);
    assert_eq!(leaf::checksum_value(None, ChecksumAlgorithm::Crc32), None);
    let back = leaf::checksum_spec_from_s3s([
        ("checksum_crc32", ChecksumAlgorithm::Crc32, Some("AAAAAA==".to_owned())),
        ("checksum_sha1", ChecksumAlgorithm::Sha1, None),
    ])
    .expect("one member")
    .expect("present");
    assert_eq!(back.algorithm(), ChecksumAlgorithm::Crc32);
}

#[test]
fn n_two_checksums_or_a_wrong_width_are_refused() {
    let two = leaf::checksum_spec_from_s3s([
        ("checksum_crc32", ChecksumAlgorithm::Crc32, Some("AAAAAA==".to_owned())),
        ("checksum_crc32c", ChecksumAlgorithm::Crc32c, Some("AAAAAA==".to_owned())),
    ]);
    assert_eq!(two.expect_err("two members").field, "checksum_spec");
    let wide = leaf::checksum_spec_from_s3s([("checksum_crc32", ChecksumAlgorithm::Crc32, Some("AAAAAAAA".to_owned()))]);
    assert_eq!(wide.expect_err("width").field, "checksum_crc32");
}

fn drain(stream: &mut rustfs_gateway_stream::ByteStream) -> (Vec<u8>, bool) {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let mut bytes = Vec::new();
    loop {
        match std::pin::Pin::new(&mut *stream).poll_read(&mut cx) {
            std::task::Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => bytes.extend_from_slice(&chunk),
            std::task::Poll::Ready(Ok(PayloadRead::Eof { .. })) => return (bytes, true),
            std::task::Poll::Ready(Err(_)) => return (bytes, false),
            std::task::Poll::Pending => panic!("an in-memory body is never pending"),
        }
    }
}

#[test]
fn an_s3s_body_arrives_whole_with_its_length() {
    let mut stream = leaf::byte_stream(oracle::StreamingBlob::from_bytes(Bytes::from_static(b"hello")));
    assert_eq!(stream.len_hint(), Some(5));
    assert_eq!(drain(&mut stream), (b"hello".to_vec(), true));
}

#[test]
fn n_an_s3s_body_error_fails_the_gateway_body_instead_of_ending_it() {
    let failing = futures_util_like::once_then_error();
    let mut stream = leaf::byte_stream(oracle::StreamingBlob::wrap(failing));
    assert_eq!(drain(&mut stream), (b"part".to_vec(), false));
}

mod futures_util_like {
    use core::pin::Pin;
    use core::task::{Context, Poll};

    use bytes::Bytes;

    pub(super) struct OnceThenError(u8);

    pub(super) fn once_then_error() -> OnceThenError {
        OnceThenError(0)
    }

    impl futures_core::Stream for OnceThenError {
        type Item = Result<Bytes, std::io::Error>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            this.0 += 1;
            Poll::Ready(match this.0 {
                1 => Some(Ok(Bytes::from_static(b"part"))),
                2 => Some(Err(std::io::Error::other("disk gone"))),
                _ => None,
            })
        }
    }
}

#[test]
fn a_generated_input_carries_names_options_and_enumerations() {
    let input = crate::ops::list_objects_v2::Input {
        bucket: BucketName::new("bucket").expect("bucket"),
        prefix: Some("a/".to_owned()),
        max_keys: Some(7),
        encoding_type: Some(crate::ops::enums::EncodingType::custom("url")),
        ..Default::default()
    };
    let s3s = ops::list_objects_v2::input_to_s3s(input).expect("converts");
    assert_eq!(s3s.bucket, "bucket");
    assert_eq!(s3s.prefix.as_deref(), Some("a/"));
    assert_eq!(s3s.max_keys, Some(7));
    assert_eq!(s3s.encoding_type.as_ref().map(oracle::EncodingType::as_str), Some("url"));
    assert_eq!(s3s.continuation_token, None);
}

fn listed_object(key: &str) -> oracle::Object {
    oracle::Object {
        key: Some(key.to_owned()),
        e_tag: Some(oracle::ETag::Strong("abc".to_owned())),
        last_modified: Some(leaf::timestamp_to_s3s("t", Timestamp::from_secs(1_700_000_000)).expect("instant")),
        size: Some(5),
        storage_class: Some(oracle::ObjectStorageClass::from("STANDARD".to_owned())),
        ..Default::default()
    }
}

fn listing(contents: Vec<oracle::Object>) -> oracle::ListObjectsV2Output {
    oracle::ListObjectsV2Output {
        name: Some("bucket".to_owned()),
        prefix: Some(String::new()),
        max_keys: Some(1000),
        key_count: Some(i32::try_from(contents.len()).expect("small")),
        is_truncated: Some(false),
        contents: Some(contents),
        ..Default::default()
    }
}

#[test]
fn a_generated_output_carries_nested_shapes() {
    let output = ops::list_objects_v2::output_from_s3s(listing(vec![listed_object("k")])).expect("converts");
    assert_eq!(output.name.as_str(), "bucket");
    assert_eq!(output.contents.len(), 1);
    let object = &output.contents[0];
    assert_eq!(object.key, ObjectKey::new("k").expect("key"));
    assert_eq!(object.e_tag.opaque_tag(), "abc");
    assert_eq!(object.size, 5);
    assert_eq!(object.storage_class.as_str(), "STANDARD");
}

#[test]
fn n_a_nested_member_the_gateway_cannot_hold_is_refused_by_name() {
    let mut object = listed_object("k");
    object.e_tag = Some(oracle::ETag::Strong("a\u{1}b".to_owned()));
    let error = ops::list_objects_v2::output_from_s3s(listing(vec![object])).expect_err("bad tag");
    assert_eq!(error.field, "e_tag");
}

#[test]
fn n_a_member_the_gateway_output_requires_is_refused_when_absent() {
    let mut output = listing(Vec::new());
    output.is_truncated = None;
    let error = ops::list_objects_v2::output_from_s3s(output).expect_err("required");
    assert_eq!(error.field, "is_truncated");
}

#[test]
fn n_an_object_lock_event_hold_is_refused_not_dropped() {
    let input = crate::ops::create_multipart_upload::Input {
        bucket: BucketName::new("bucket").expect("bucket"),
        key: ObjectKey::new("k").expect("key"),
        object_lock_event_hold: Some(crate::ops::enums::ObjectLockEventHold::custom("ON")),
        ..Default::default()
    };
    let error = ops::create_multipart_upload::input_to_s3s(input).expect_err("event hold");
    assert_eq!(error.field, "object_lock_event_hold");
}

#[test]
fn n_a_part_number_marker_that_is_not_a_number_is_refused() {
    let input = crate::ops::list_parts::Input {
        bucket: BucketName::new("bucket").expect("bucket"),
        key: ObjectKey::new("k").expect("key"),
        upload_id: crate::UploadIdClaim::from_wire("id"),
        part_number_marker: Some("x".to_owned()),
        ..Default::default()
    };
    let error = ops::list_parts::input_to_s3s(input).expect_err("marker");
    assert_eq!(error.field, "part_number_marker");
}

#[test]
fn an_upload_id_reaches_the_s3s_input_as_claimed() {
    let input = crate::ops::list_parts::Input {
        bucket: BucketName::new("bucket").expect("bucket"),
        key: ObjectKey::new("k").expect("key"),
        upload_id: crate::UploadIdClaim::from_wire("id-1"),
        part_number_marker: Some("3".to_owned()),
        ..Default::default()
    };
    let s3s = ops::list_parts::input_to_s3s(input).expect("converts");
    assert_eq!((s3s.upload_id.as_str(), s3s.part_number_marker), ("id-1", Some(3)));
}

#[test]
fn a_copy_takes_the_authorized_source_not_the_sealed_input_member() {
    let input = crate::ops::copy_object::Input {
        bucket: BucketName::new("target").expect("bucket"),
        key: ObjectKey::new("k").expect("key"),
        // The gateway clears this once it has authorized the source as a derived resource.
        copy_source: String::new(),
        ..Default::default()
    };
    let source = oracle::CopySource::Bucket {
        bucket: "source".into(),
        key: "a/b".into(),
        version_id: None,
    };
    let s3s = ops::copy_object::input_to_s3s(input, source.clone()).expect("converts");
    assert_eq!(s3s.copy_source, source);
    assert_eq!(s3s.bucket, "target");
}
