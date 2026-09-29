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
    let headers = http::HeaderMap::new();
    let error = ops::create_multipart_upload::input_to_s3s(input, &wire_of("", &headers)).expect_err("event hold");
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
    let headers = http::HeaderMap::new();
    let s3s = ops::copy_object::input_to_s3s(input, source.clone(), &wire_of("", &headers)).expect("converts");
    assert_eq!(s3s.copy_source, source);
    assert_eq!(s3s.bucket, "target");
}

// ── members only the legacy decoder reads ─────────────────────────────────────────────────────

fn wire_of<'a>(raw_query: &'a str, headers: &'a http::HeaderMap) -> leaf::RequestWire<'a> {
    leaf::RequestWire { raw_query, headers }
}

#[test]
fn a_legacy_query_member_is_decoded_as_the_legacy_decoder_splits_the_query() {
    let headers = http::HeaderMap::new();
    for (query, expected) in [
        ("versionId=v1", Some("v1")),
        ("uploads&versionId=v1", Some("v1")),
        ("versionId=a%2Bb+c", Some("a+b c")),
        ("versionId=%zz", Some("%zz")),
        ("versionId=", Some("")),
        ("versionId", Some("")),
        ("versionid=v1", None),
        ("", None),
    ] {
        let value = leaf::legacy_query(&wire_of(query, &headers), "versionId").expect(query);
        assert_eq!(value.as_deref(), expected, "{query}");
    }
}

#[test]
fn n_a_legacy_query_member_seen_twice_is_refused_by_its_parameter() {
    let headers = http::HeaderMap::new();
    let error = leaf::legacy_query(&wire_of("versionId=a&versionId=b", &headers), "versionId").expect_err("twice");
    assert_eq!((error.field, error.reason), ("versionId", super::error::LEGACY_DUPLICATE_QUERY));
}

fn one_line(value: &'static str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.append("x-minio-force-delete", http::HeaderValue::from_static(value));
    headers
}

#[test]
fn a_legacy_boolean_header_takes_exactly_the_legacy_grammar() {
    for (value, expected) in [
        ("true", Some(true)),
        ("True", Some(true)),
        ("false", Some(false)),
        ("False", Some(false)),
        ("", None),
    ] {
        let headers = one_line(value);
        let decoded = leaf::legacy_bool_header(&wire_of("", &headers), "x-minio-force-delete").expect(value);
        assert_eq!(decoded, expected, "{value:?}");
    }
    let absent = http::HeaderMap::new();
    assert_eq!(
        leaf::legacy_bool_header(&wire_of("", &absent), "x-minio-force-delete").expect("absent"),
        None
    );
}

#[test]
fn n_a_legacy_boolean_header_outside_the_legacy_grammar_is_refused() {
    for value in ["1", "0", "TRUE", "t", "on", "yes", " true", "true "] {
        let headers = one_line(value);
        let error = leaf::legacy_bool_header(&wire_of("", &headers), "x-minio-force-delete").expect_err(value);
        assert_eq!(
            (error.field, error.reason),
            ("x-minio-force-delete", super::error::LEGACY_INVALID_BOOLEAN),
            "{value:?}"
        );
    }
}

#[test]
fn n_a_legacy_boolean_header_seen_twice_is_refused_even_when_both_lines_agree() {
    let mut headers = one_line("true");
    headers.append("x-minio-force-delete", http::HeaderValue::from_static("true"));
    let error = leaf::legacy_bool_header(&wire_of("", &headers), "x-minio-force-delete").expect_err("twice");
    assert_eq!(
        (error.field, error.reason),
        ("x-minio-force-delete", super::error::LEGACY_DUPLICATE_HEADER)
    );
}

#[test]
fn a_legacy_decoder_refusal_is_answered_with_its_code_and_status() {
    use super::error::{
        LEGACY_DUPLICATE_HEADER, LEGACY_DUPLICATE_QUERY, LEGACY_INVALID_BOOLEAN, Refusal, refusal_from_conversion,
    };
    use crate::compat::ConversionError;
    for (reason, field, code, message) in [
        (LEGACY_DUPLICATE_QUERY, "versionId", "InvalidRequest", "duplicate query: versionId"),
        (
            LEGACY_DUPLICATE_HEADER,
            "x-minio-force-delete",
            "InvalidRequest",
            "duplicate header: x-minio-force-delete",
        ),
        (
            LEGACY_INVALID_BOOLEAN,
            "x-minio-force-delete",
            "InvalidArgument",
            "invalid header: x-minio-force-delete",
        ),
    ] {
        match refusal_from_conversion(&ConversionError { field, reason }) {
            Some(Refusal::Ordinary {
                code: answered,
                message: text,
            }) => {
                assert_eq!(
                    (answered.as_str(), answered.default_status().as_u16(), text.as_str()),
                    (code, 400, message)
                );
            }
            other => panic!("{reason}: {other:?}"),
        }
    }
}

#[test]
fn n_any_other_conversion_error_is_not_a_legacy_decoder_refusal() {
    let error = crate::compat::ConversionError {
        field: "range",
        reason: "not a byte range the s3s input can hold",
    };
    assert_eq!(super::error::refusal_from_conversion(&error), None);
}

// ── a RustFS answer's own headers ─────────────────────────────────────────────────────────────

fn body_headers(lines: &[(&'static str, &'static str)]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in lines {
        headers.append(*name, http::HeaderValue::from_static(value));
    }
    headers
}

fn got_output() -> oracle::GetObjectOutput {
    oracle::GetObjectOutput {
        accept_ranges: Some("bytes".to_owned()),
        restore: Some("ongoing-request=\"true\"".to_owned()),
        metadata: Some(
            [("color".to_owned(), "blue".to_owned()), ("size".to_owned(), "big".to_owned())]
                .into_iter()
                .collect(),
        ),
        ..Default::default()
    }
}

#[test]
fn a_header_the_body_set_leaves_the_member_it_replaces_to_that_header() {
    let headers = body_headers(&[("accept-ranges", "bytes"), ("x-amz-meta-color", "red"), ("vary", "Origin")]);
    let (output, extra) = ops::get_object::answer_from_legacy(got_output(), headers.clone()).expect("converts");
    assert_eq!(output.accept_ranges, None);
    assert_eq!(output.metadata.keys().collect::<Vec<_>>(), ["size"]);
    assert_eq!(
        output.restore.as_deref(),
        Some("ongoing-request=\"true\""),
        "a member no header replaces stays"
    );
    assert_eq!(extra, headers, "every header the body set is handed on unchanged");
}

#[test]
fn n_an_answer_without_its_own_headers_converts_as_the_output_alone() {
    let (output, extra) = ops::get_object::answer_from_legacy(got_output(), http::HeaderMap::new()).expect("converts");
    let alone = ops::get_object::output_from_s3s(got_output()).expect("converts");
    assert!(extra.is_empty());
    assert_eq!(
        (output.accept_ranges, output.restore, output.metadata),
        (alone.accept_ranges, alone.restore, alone.metadata)
    );
}

#[test]
fn n_a_put_checksum_header_the_body_set_clears_only_its_own_algorithm() {
    let output = oracle::PutObjectOutput {
        checksum_sha512: Some("AAAA".to_owned()),
        e_tag: Some(oracle::ETag::Strong("abc".to_owned())),
        ..Default::default()
    };
    let headers = body_headers(&[("x-amz-checksum-sha512", "AAAA")]);
    let (converted, extra) = super::put_object::answer_from_legacy(output, headers).expect("converts");
    assert!(converted.checksum_spec.is_none(), "the body's header carries the checksum");
    assert_eq!(converted.e_tag.opaque_tag(), "abc");
    assert_eq!(extra.len(), 1);
}

#[test]
fn n_a_metadata_header_for_another_key_leaves_the_metadata_whole() {
    let headers = body_headers(&[("x-amz-meta-weight", "1kg")]);
    let (output, _) = ops::get_object::answer_from_legacy(got_output(), headers).expect("converts");
    assert_eq!(output.metadata.len(), 2);
}

#[test]
fn n_a_header_naming_a_member_written_elsewhere_clears_nothing() {
    // `ListObjectsV2Output.Name` is a document element, so a body header of the same spelling
    // replaces nothing on the legacy wire.
    let output = oracle::ListObjectsV2Output {
        name: Some("bucket".to_owned()),
        prefix: Some(String::new()),
        max_keys: Some(1000),
        key_count: Some(0),
        is_truncated: Some(false),
        ..Default::default()
    };
    let headers = body_headers(&[("name", "other"), ("x-rustfs-on-demand-migration-list", "local_only")]);
    let (converted, extra) = ops::list_objects_v2::answer_from_legacy(output, headers).expect("converts");
    assert_eq!(converted.name.as_str(), "bucket");
    assert_eq!(extra.len(), 2);
}

// ── legacy-only output members ────────────────────────────────────────────────────────────────

#[test]
fn a_head_bucket_answer_without_the_legacy_only_members_converts() {
    let output = oracle::HeadBucketOutput {
        bucket_region: Some("us-east-1".to_owned()),
        ..Default::default()
    };
    let converted = ops::head_bucket::output_from_s3s(output).expect("converts");
    assert_eq!(converted.bucket_region.as_str(), "us-east-1");
}

#[test]
fn n_every_legacy_only_output_member_set_is_refused_by_name() {
    let base = || oracle::HeadBucketOutput {
        bucket_region: Some("us-east-1".to_owned()),
        ..Default::default()
    };
    let rows: [(&str, oracle::HeadBucketOutput); 4] = [
        (
            "access_point_alias",
            oracle::HeadBucketOutput {
                access_point_alias: Some(true),
                ..base()
            },
        ),
        (
            "bucket_arn",
            oracle::HeadBucketOutput {
                bucket_arn: Some("arn:aws:s3:::b".to_owned()),
                ..base()
            },
        ),
        (
            "bucket_location_name",
            oracle::HeadBucketOutput {
                bucket_location_name: Some("usw2-az1".to_owned()),
                ..base()
            },
        ),
        (
            "bucket_location_type",
            oracle::HeadBucketOutput {
                bucket_location_type: Some(oracle::LocationType::from("AvailabilityZone".to_owned())),
                ..base()
            },
        ),
    ];
    for (member, output) in rows {
        let error = ops::head_bucket::output_from_s3s(output).expect_err(member);
        assert_eq!(error.field, member);
    }
    let created = oracle::CreateBucketOutput {
        bucket_arn: Some("arn:aws:s3:::b".to_owned()),
        ..Default::default()
    };
    assert_eq!(ops::create_bucket::output_from_s3s(created).expect_err("bucket_arn").field, "bucket_arn");
}

/// A legacy body may hand the legacy writer a deferred completion to stream behind keep-alive
/// whitespace; the gateway writes an output once, so a set one is refused rather than the output
/// written without the result it defers. An unset one converts as before.
#[test]
fn n_a_deferred_completion_is_refused_not_dropped() {
    fn complete() -> oracle::CompleteMultipartUploadOutput {
        oracle::CompleteMultipartUploadOutput {
            bucket: Some("bucket".to_owned()),
            key: Some("k".to_owned()),
            e_tag: Some(oracle::ETag::Strong("abc-2".to_owned())),
            ..Default::default()
        }
    }
    let deferred = oracle::CompleteMultipartUploadOutput {
        future: Some(Box::pin(async { Ok(complete()) })),
        ..complete()
    };
    let error = ops::complete_multipart_upload::output_from_s3s(deferred).expect_err("a deferred completion");
    assert_eq!(error.field, "future");
    let converted = ops::complete_multipart_upload::output_from_s3s(complete()).expect("an immediate completion converts");
    assert_eq!(converted.e_tag.map(|etag| etag.opaque_tag().to_owned()).as_deref(), Some("abc-2"));
}
