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

//! Tests for the reverse seam direction and the error-code census (rustfs/backlog#2759), compiled
//! once per seam revision.
//!
//! Responsible for: proving a 1 MiB body crosses whole in both directions and that a body failing
//! mid-stream fails the other side rather than ending it; that every pinned `S3ErrorCode` keeps
//! its status through both error seams and every code the gateway cannot answer bare is refused
//! by name; that the hand-written operations convert both ways, refuse what the gateway cannot
//! hold, and hand a legacy-only member back rather than dropping it.
//! NOT responsible for: the generated round trips, which live beside the fixtures
//! (`super::generated::fixtures`). Upstream: `super::leaf`, `super::error`, `super::put_object`,
//! `super::get_bucket_location`, `super::generated::census`. Downstream: none; test-only.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::pin::Pin;
use core::task::{Context, Poll};

use bytes::Bytes;
use http::StatusCode;
use rustfs_gateway_stream::{ByteStream, PayloadCaps, PayloadRead, PayloadStream, StreamError, StreamErrorKind};

use super::error::{CONTEXTUAL_CODES, NEEDS_FACTS_CODES, Refusal, refusal_from_legacy, refusal_from_s3s};
use super::generated::census::{self, error_codes::CODES};
use super::s3s::dto as oracle;
use super::s3s::{S3Error, S3ErrorCode};
use super::{get_bucket_location, leaf, put_object};
use crate::{BucketName, ChecksumSpec, ETag, ObjectKey, OpaqueString, dto};

const MIB: usize = 1024 * 1024;

/// A 1 MiB body whose bytes are not all alike, so a chunk delivered twice or out of order shows.
fn one_mib() -> Vec<u8> {
    (0..MIB).map(|index| (index % 251) as u8).collect()
}

fn drain(stream: &mut ByteStream) -> (Vec<u8>, bool) {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut bytes = Vec::new();
    loop {
        match Pin::new(&mut *stream).poll_read(&mut cx) {
            Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => bytes.extend_from_slice(&chunk),
            Poll::Ready(Ok(PayloadRead::Eof { .. })) => return (bytes, true),
            Poll::Ready(Err(_)) => return (bytes, false),
            Poll::Pending => panic!("an in-memory body is never pending"),
        }
    }
}

fn collect(mut blob: oracle::StreamingBlob) -> (Vec<u8>, bool) {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut bytes = Vec::new();
    loop {
        match futures_core::Stream::poll_next(Pin::new(&mut blob), &mut cx) {
            Poll::Ready(Some(Ok(chunk))) => bytes.extend_from_slice(&chunk),
            Poll::Ready(None) => return (bytes, true),
            Poll::Ready(Some(Err(_))) => return (bytes, false),
            Poll::Pending => panic!("an in-memory body is never pending"),
        }
    }
}

// ── bodies ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_one_mib_gateway_body_crosses_into_an_s3s_body_whole() {
    let bytes = one_mib();
    let blob = leaf::streaming_blob(ByteStream::from_bytes(Bytes::from(bytes.clone())));
    assert_eq!(s3s_remaining(&blob), Some(MIB), "the length crosses with the body");
    assert_eq!(collect(blob), (bytes, true));
}

#[test]
fn a_one_mib_s3s_body_crosses_into_a_gateway_body_whole_with_its_length() {
    let bytes = one_mib();
    let mut stream = leaf::byte_stream(oracle::StreamingBlob::from_bytes(Bytes::from(bytes.clone())));
    assert_eq!(stream.len_hint(), Some(MIB as u64));
    assert_eq!(drain(&mut stream), (bytes, true));
}

#[test]
fn a_one_mib_body_round_trips_through_both_adapters_byte_for_byte() {
    let bytes = one_mib();
    let blob = leaf::streaming_blob(ByteStream::from_bytes(Bytes::from(bytes.clone())));
    let mut back = leaf::byte_stream(blob);
    assert_eq!(back.len_hint(), Some(MIB as u64), "the length survives both adapters");
    assert_eq!(drain(&mut back), (bytes, true));
}

fn s3s_remaining(blob: &oracle::StreamingBlob) -> Option<usize> {
    super::s3s::stream::ByteStream::remaining_length(blob).exact()
}

/// A gateway body that yields one chunk and then fails.
struct FailsAfterOne(u8);

impl PayloadStream for FailsAfterOne {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        this.0 += 1;
        Poll::Ready(match this.0 {
            1 => Ok(PayloadRead::Chunk(Bytes::from_static(b"part"))),
            _ => Err(StreamError::new(StreamErrorKind::PolledAfterEof)),
        })
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH
    }

    fn len_hint(&self) -> Option<u64> {
        None
    }
}

#[test]
fn n_a_gateway_body_failing_mid_stream_fails_the_s3s_body_after_the_bytes_before_it() {
    let stream = ByteStream::new(Box::pin(FailsAfterOne(0))).expect("a push body with no length");
    let blob = leaf::streaming_blob(stream);
    assert_eq!(s3s_remaining(&blob), None, "no length is claimed for a body that has none");
    assert_eq!(collect(blob), (b"part".to_vec(), false));
}

// ── error codes ──────────────────────────────────────────────────────────────────────────────

#[test]
fn every_pinned_error_code_keeps_its_status_through_both_error_seams() {
    assert_eq!(CODES.len(), 239, "every S3ErrorCode variant but Custom");
    let mut refused_bare = Vec::new();
    for (name, status) in CODES {
        let code =
            S3ErrorCode::from_bytes(name.as_bytes()).unwrap_or_else(|| panic!("{name}: a variant of the pinned S3ErrorCode"));
        assert_eq!(
            code.status_code().map(|status| status.as_u16()),
            *status,
            "{name}: the census status is the crate's"
        );
        let expected = status.map_or(StatusCode::INTERNAL_SERVER_ERROR, |status| {
            StatusCode::from_u16(status).expect("a status")
        });
        let error = S3Error::new(code);
        match refusal_from_s3s(&error) {
            Ok(Refusal::Ordinary { code, .. }) => {
                assert_eq!(code.default_status(), expected, "{name}: the status crosses");
                assert_eq!(code.as_str(), *name, "{name}: the code crosses");
            }
            Ok(Refusal::MissingBucket) => assert_eq!(*name, "NoSuchBucket"),
            Ok(Refusal::MissingKey) => assert_eq!(*name, "NoSuchKey"),
            Ok(Refusal::MissingVersion) => assert_eq!(*name, "NoSuchVersion"),
            Ok(other) => panic!("{name}: a bare error states no fact for {other:?}"),
            Err(refused) => {
                refused_bare.push(*name);
                let contextual = CONTEXTUAL_CODES.contains(name) || NEEDS_FACTS_CODES.contains(name);
                let answerable = expected.is_client_error() || expected.is_server_error();
                assert!(
                    contextual || !answerable,
                    "{name}: refused as `{refused}` though the gateway answers it bare"
                );
                // A code answered from the error's own fact header names the header it lacks; the
                // rest of the contextual codes name the code; a 3xx outside them names the status.
                let field = match *name {
                    "NotModified" => "etag",
                    "InvalidRange" => "content-range",
                    _ if contextual => "code",
                    _ => "status_code",
                };
                assert_eq!(refused.field, field, "{name}");
            }
        }
        match refusal_from_legacy(&error) {
            Ok(legacy) => assert_eq!(legacy.code.default_status(), expected, "{name}: the legacy status crosses"),
            Err(refused) => {
                let legacy_writes =
                    expected.is_client_error() || expected.is_server_error() || expected == StatusCode::NOT_MODIFIED;
                assert!(!legacy_writes, "{name}: refused as `{refused}` though the legacy stack writes it");
                assert_eq!(refused.field, "status_code", "{name}");
            }
        }
    }
    // Every contextual code the pinned crate can spell is refused bare, never guessed; a gateway
    // contextual code s3s has no variant for (`AccessForbidden`) cannot arrive through this seam.
    let mut pinned_contextual = 0;
    for name in CONTEXTUAL_CODES.iter().chain(NEEDS_FACTS_CODES.iter()) {
        let pinned = CODES.iter().any(|(pinned, _)| pinned == name);
        if pinned && !["NoSuchBucket", "NoSuchKey", "NoSuchVersion"].contains(name) {
            pinned_contextual += 1;
            assert!(refused_bare.contains(name), "{name}: a contextual code is refused bare, never guessed");
        }
    }
    assert_eq!(pinned_contextual, 7, "the pinned crate spells every contextual code but AccessForbidden");
}

#[test]
fn n_a_code_with_no_status_of_its_own_answers_500_rather_than_guessing() {
    for name in ["InvalidAddressingHeader", "MissingAttachment"] {
        let code = S3ErrorCode::from_bytes(name.as_bytes()).expect("a pinned code");
        assert_eq!(code.status_code(), None, "{name}: the crate names no status");
        match refusal_from_s3s(&S3Error::new(code)).expect("answered bare") {
            Refusal::Ordinary { code, .. } => assert_eq!(code.default_status(), StatusCode::INTERNAL_SERVER_ERROR, "{name}"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[test]
fn a_custom_code_keeps_the_status_the_body_declared() {
    let mut error = S3Error::new(S3ErrorCode::Custom("Teapot".into()));
    error.set_status_code(StatusCode::IM_A_TEAPOT);
    match refusal_from_s3s(&error).expect("answered bare") {
        Refusal::Ordinary { code, .. } => {
            assert_eq!(code.as_str(), "Teapot");
            assert_eq!(code.default_status(), StatusCode::IM_A_TEAPOT);
            assert!(!code.is_known());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn n_a_status_outside_the_refusal_bands_is_refused_by_both_seams() {
    let mut error = S3Error::new(S3ErrorCode::AccessDenied);
    error.set_status_code(StatusCode::FOUND);
    assert_eq!(refusal_from_s3s(&error).expect_err("a 302 is no refusal").field, "status_code");
    assert_eq!(refusal_from_legacy(&error).expect_err("a 302 is no refusal").field, "status_code");
}

#[test]
fn n_a_pinned_code_whose_default_status_the_body_overrides_crosses_as_a_custom_code_at_that_status() {
    let mut error = S3Error::new(S3ErrorCode::NoSuchUpload);
    error.set_status_code(StatusCode::GONE);
    match refusal_from_s3s(&error).expect("answered bare") {
        Refusal::Ordinary { code, .. } => {
            assert_eq!(code.as_str(), "NoSuchUpload");
            assert_eq!(code.default_status(), StatusCode::GONE, "the status the body wrote, not the code's own");
            assert_ne!(code.default_status(), StatusCode::NOT_FOUND, "the code's own status is not what crosses");
        }
        other => panic!("{other:?}"),
    }
}

// ── the hand-written operations, the other way round ─────────────────────────────────────────

#[test]
fn a_bucket_location_input_and_output_convert_both_ways() {
    let input = get_bucket_location::input_from_s3s(oracle::GetBucketLocationInput {
        bucket: "fixture-bucket".to_owned(),
        expected_bucket_owner: Some("owner".to_owned()),
    })
    .expect("a name the gateway writes");
    assert_eq!(input.bucket.as_str(), "fixture-bucket");
    assert_eq!(input.expected_bucket_owner.as_deref(), Some("owner"));
    let back = get_bucket_location::input_to_s3s(input);
    assert_eq!(back.bucket, "fixture-bucket");
    assert_eq!(back.expected_bucket_owner.as_deref(), Some("owner"));
    for spelling in ["EU", "us-west-2", "a-region-aws-never-named"] {
        let output = get_bucket_location::output_to_s3s(dto::GetBucketLocationOutput {
            location_constraint: Some(dto::LocationConstraint::custom(spelling.to_owned())),
        });
        assert_eq!(output.location_constraint.as_ref().map(|value| value.as_str()), Some(spelling));
        let gateway = get_bucket_location::output_from_s3s(output);
        assert_eq!(
            gateway.location_constraint.as_ref().map(|value| value.as_str()),
            Some(spelling),
            "exact spelling both ways"
        );
    }
    assert_eq!(
        get_bucket_location::output_to_s3s(dto::GetBucketLocationOutput {
            location_constraint: None
        })
        .location_constraint,
        None
    );
}

#[test]
fn n_a_bucket_location_input_naming_no_bucket_the_gateway_writes_is_refused_by_member() {
    let error = get_bucket_location::input_from_s3s(oracle::GetBucketLocationInput {
        bucket: "Bad Bucket!".to_owned(),
        expected_bucket_owner: None,
    })
    .expect_err("not a bucket name");
    assert_eq!(error.field, "bucket");
}

/// An s3s `PutObjectInput` with every member a gateway member holds set, and the legacy-only one.
fn put_input() -> oracle::PutObjectInput {
    oracle::PutObjectInput {
        acl: Some("private".to_owned().into()),
        body: Some(oracle::StreamingBlob::from_bytes(Bytes::from_static(b"body"))),
        bucket: "fixture-bucket".to_owned(),
        bucket_key_enabled: Some(true),
        cache_control: Some("cache_control".to_owned()),
        checksum_algorithm: Some("CRC32".to_owned().into()),
        checksum_crc32: Some("AAAAAA==".to_owned()),
        checksum_crc32c: None,
        checksum_crc64nvme: None,
        checksum_md5: None,
        checksum_sha1: None,
        checksum_sha256: None,
        checksum_sha512: None,
        checksum_xxhash128: None,
        checksum_xxhash3: None,
        checksum_xxhash64: None,
        content_disposition: Some("content_disposition".to_owned()),
        content_encoding: Some("content_encoding".to_owned()),
        content_language: Some("content_language".to_owned()),
        content_length: Some(4),
        content_md5: Some("content_md5".to_owned()),
        content_type: Some("content_type".to_owned()),
        expected_bucket_owner: Some("expected_bucket_owner".to_owned()),
        expires: Some(super::expires("Sun, 06 Nov 1994 08:49:37 GMT").expect("an HTTP-date every revision holds")),
        grant_full_control: Some("grant_full_control".to_owned()),
        grant_read: Some("grant_read".to_owned()),
        grant_read_acp: Some("grant_read_acp".to_owned()),
        grant_write_acp: Some("grant_write_acp".to_owned()),
        if_match: Some(oracle::ETagCondition::ETag(oracle::ETag::Strong("if_match".to_owned()))),
        if_none_match: Some(oracle::ETagCondition::parse_http_header(b"*").expect("the wildcard condition")),
        key: "key".to_owned(),
        metadata: Some(std::collections::HashMap::from([("meta".to_owned(), "data".to_owned())])),
        object_lock_legal_hold_status: Some("ON".to_owned().into()),
        object_lock_mode: Some("GOVERNANCE".to_owned().into()),
        object_lock_retain_until_date: Some(
            oracle::Timestamp::parse(oracle::TimestampFormat::EpochSeconds, "1700000000.123").expect("an instant"),
        ),
        request_payer: Some("requester".to_owned().into()),
        sse_customer_algorithm: Some("AES256".to_owned()),
        sse_customer_key: Some("sse_customer_key".to_owned()),
        sse_customer_key_md5: Some("sse_customer_key_md5".to_owned()),
        ssekms_encryption_context: Some("ssekms_encryption_context".to_owned()),
        ssekms_key_id: Some("ssekms_key_id".to_owned()),
        server_side_encryption: Some("AES256".to_owned().into()),
        storage_class: Some("STANDARD".to_owned().into()),
        tagging: Some("tagging".to_owned()),
        version_id: Some("replica-version".to_owned()),
        website_redirect_location: Some("website_redirect_location".to_owned()),
        write_offset_bytes: Some(7),
    }
}

#[test]
fn a_put_input_round_trips_and_hands_its_legacy_member_back() {
    let (gateway, legacy) = put_object::input_from_s3s(put_input()).expect("the fixture converts");
    assert_eq!(
        legacy,
        put_object::LegacyInput {
            version_id: Some("replica-version".to_owned())
        }
    );
    assert_eq!(gateway.sse_customer_key.as_ref().map(|key| key.expose_secret()), Some("sse_customer_key"));
    assert_eq!(gateway.content_length, 4);
    assert_eq!(gateway.if_match.as_deref(), Some("\"if_match\""));
    assert_eq!(gateway.if_none_match.as_deref(), Some("*"));
    let back = put_object::replica_input_to_s3s(gateway, "replica-version".to_owned()).expect("and back");
    let mut differences = Vec::new();
    census::put_object_input::differences("", &put_input(), &back, &mut differences);
    assert!(differences.is_empty(), "members the round trip changed: {differences:?}");
    let mut present = Vec::new();
    census::put_object_input::present("", &put_input(), &mut present);
    let other_algorithms: Vec<&String> = present
        .iter()
        .filter(|path| path.starts_with("checksum_") && !["checksum_crc32", "checksum_algorithm"].contains(&path.as_str()))
        .collect();
    assert!(
        other_algorithms.is_empty(),
        "the fixture sets one checksum algorithm: {other_algorithms:?}"
    );
    // Every s3s member but the nine unset algorithms and the body the census never compares.
    assert_eq!(present.len(), 47 - 9 - 1);
}

#[test]
fn n_a_put_input_without_a_content_length_is_refused_by_member() {
    let mut input = put_input();
    input.content_length = None;
    assert_eq!(
        put_object::input_from_s3s(input)
            .expect_err("the gateway requires a length")
            .field,
        "content_length"
    );
}

#[test]
fn n_a_put_input_with_two_checksums_or_a_bad_name_is_refused_by_member() {
    let mut input = put_input();
    input.checksum_sha1 = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned());
    assert_eq!(put_object::input_from_s3s(input).expect_err("two checksums").field, "checksum_spec");
    let mut input = put_input();
    input.checksum_crc32 = Some("AAA=".to_owned());
    assert_eq!(
        put_object::input_from_s3s(input)
            .expect_err("a digest of another width")
            .field,
        "checksum_crc32"
    );
    let mut input = put_input();
    input.bucket = "Bad Bucket!".to_owned();
    assert_eq!(put_object::input_from_s3s(input).expect_err("not a bucket name").field, "bucket");
    let mut input = put_input();
    input.key = String::new();
    assert_eq!(put_object::input_from_s3s(input).expect_err("not an object key").field, "key");
}

#[test]
fn n_a_put_input_instant_the_gateway_cannot_spell_is_refused_by_member() {
    let mut input = put_input();
    input.object_lock_retain_until_date = Some(
        oracle::Timestamp::parse(oracle::TimestampFormat::EpochSeconds, "-70000000000").expect("an instant before the year 0"),
    );
    assert_eq!(
        put_object::input_from_s3s(input)
            .expect_err("neither side spells it with four digits")
            .field,
        "object_lock_retain_until_date"
    );
}

#[test]
fn a_put_input_never_crosses_an_event_hold() {
    let (gateway, _) = put_object::input_from_s3s(put_input()).expect("converts");
    assert!(gateway.object_lock_event_hold.is_none());
    assert!(gateway.object_lock_event_hold_duration_days.is_none());
    assert!(gateway.object_lock_event_hold_duration_years.is_none());
}

fn put_output() -> dto::PutObjectOutput {
    dto::PutObjectOutput {
        expiration: Some(OpaqueString::from(
            "expiry-date=\"Fri, 23 Dec 2012 00:00:00 GMT\", rule-id=\"rule\"".to_owned(),
        )),
        e_tag: ETag::new_weak("tag").expect("a weak tag"),
        checksum_spec: Some(
            ChecksumSpec::parse_header("x-amz-checksum-sha256", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
                .expect("a digest"),
        ),
        checksum_type: Some(dto::ChecksumType::custom("FULL_OBJECT".to_owned())),
        server_side_encryption: Some(dto::ServerSideEncryption::custom("aws:kms".to_owned())),
        version_id: Some("version".to_owned()),
        sse_customer_algorithm: Some("AES256".to_owned()),
        sse_customer_key_md5: Some("md5".to_owned()),
        ssekms_key_id: Some("kms".to_owned()),
        ssekms_encryption_context: Some("context".to_owned()),
        bucket_key_enabled: Some(false),
        size: Some(4),
        request_charged: Some(dto::RequestCharged::custom("requester".to_owned())),
    }
}

#[test]
fn a_put_output_round_trips_with_every_member_and_the_tag_strength() {
    let s3s = put_object::output_to_s3s(put_output());
    assert_eq!(s3s.e_tag, Some(oracle::ETag::Weak("tag".to_owned())));
    assert_eq!(s3s.checksum_sha256.as_deref(), Some("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="));
    assert_eq!(s3s.checksum_crc32, None, "only the spec's algorithm is set");
    let mut present = Vec::new();
    census::put_object_output::present("", &s3s, &mut present);
    assert_eq!(
        present.len(),
        put_object::GATEWAY_OUTPUT_MEMBERS.len(),
        "every gateway output member reaches an s3s member"
    );
    let back = put_object::output_from_s3s(put_object::output_to_s3s(put_output())).expect("and back");
    let again = put_object::output_to_s3s(back);
    let mut differences = Vec::new();
    census::put_object_output::differences("", &s3s, &again, &mut differences);
    assert!(differences.is_empty(), "members the round trip changed: {differences:?}");
}

#[test]
fn an_unnamed_head_bucket_region_crosses_back_as_no_region() {
    // Backward, the legacy stack's unset region is the gateway's empty string; forward, the empty
    // string is the unset region again, never an empty header the legacy writer would spell.
    let fixture = super::generated::fixtures::ops::head_bucket::output();
    let mut gateway = super::generated::ops::head_bucket::output_from_s3s(fixture).expect("the fixture converts");
    gateway.bucket_region = String::new();
    let back = super::generated::ops::head_bucket::output_to_s3s(gateway).expect("an empty region is the unset one");
    assert_eq!(back.bucket_region, None);
}

#[test]
fn n_a_bucket_name_and_key_the_gateway_grammar_refuses_never_become_gateway_names() {
    assert!(BucketName::new("Bad Bucket!").is_err());
    assert!(ObjectKey::new("").is_err());
}
