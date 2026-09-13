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

//! PutObject: the first single-operation decode/encode diff against the pinned s3s oracle.
//!
//! Responsible for: proving, for one operation, that a request the gateway routes and decodes
//! becomes — through `compat::put_object` — the same s3s input the s3s service decodes from the
//! same bytes, member by member; that the body crosses as the one live stream, unread until the
//! handler reads it; and that one s3s output encodes to the same status, header lines and body on
//! both stacks. Every divergence between the stacks this file knows of is a named test that says
//! what each side does, so none of them hides inside a generator that was narrowed around it.
//! NOT responsible for: request context, authentication, error-document parity, or any other
//! operation. Upstream: the harness in `super`. Downstream: nothing.
//!
//! # Why PutObject
//!
//! It is the one operation whose request payload is a live stream on both stacks, so it is the
//! only choice where "the body was consumed once and never buffered on the way" is an observable
//! question rather than a formality, and it carries more request headers than any other operation.

use std::collections::BTreeSet;
use std::sync::Arc;

use proptest::prelude::*;
use rustfs_gateway_types::compat::put_object::{GATEWAY_INPUT_MEMBERS, GATEWAY_OUTPUT_MEMBERS, input_to_s3s};
use rustfs_gateway_types::{ChecksumAlgorithm, ChecksumSpec, ContentMd5, Timestamp, TimestampFormat, dto};

use super::{BodyProbe, BodyReads, RawRequest, announced_length, block_on, drain, gateway_decode, oracle, s3s_exchange};

mod encode;

// ── the member diff ───────────────────────────────────────────────────────────────────────────

/// Declares the member list once and derives both the comparison and the census from it.
///
/// The pattern names every member of the pinned oracle input with no `..`, so an oracle re-pin that
/// adds a member is a compile error here — not a member the diff silently stops comparing.
macro_rules! oracle_members {
    ($($member:ident),+ $(,)?) => {
        /// Every non-body member of the pinned oracle `PutObjectInput`, in declaration order.
        const ORACLE_MEMBERS: &[&str] = &[$(stringify!($member)),+];

        /// The members on which two oracle inputs disagree. Values are never printed: one of them
        /// is an SSE-C key.
        fn differing_members(left: &oracle::PutObjectInput, right: &oracle::PutObjectInput) -> Vec<&'static str> {
            let oracle::PutObjectInput { body: _, $($member: _),+ } = left;
            let mut differing = Vec::new();
            $( if left.$member != right.$member { differing.push(stringify!($member)); } )+
            differing
        }
    };
}

oracle_members!(
    acl,
    bucket,
    bucket_key_enabled,
    cache_control,
    checksum_algorithm,
    checksum_crc32,
    checksum_crc32c,
    checksum_crc64nvme,
    checksum_md5,
    checksum_sha1,
    checksum_sha256,
    checksum_sha512,
    checksum_xxhash128,
    checksum_xxhash3,
    checksum_xxhash64,
    content_disposition,
    content_encoding,
    content_language,
    content_length,
    content_md5,
    content_type,
    expected_bucket_owner,
    expires,
    grant_full_control,
    grant_read,
    grant_read_acp,
    grant_write_acp,
    if_match,
    if_none_match,
    key,
    metadata,
    object_lock_legal_hold_status,
    object_lock_mode,
    object_lock_retain_until_date,
    request_payer,
    sse_customer_algorithm,
    sse_customer_key,
    sse_customer_key_md5,
    ssekms_encryption_context,
    ssekms_key_id,
    server_side_encryption,
    storage_class,
    tagging,
    version_id,
    website_redirect_location,
    write_offset_bytes,
);

type Convert = fn(dto::PutObjectInput) -> Result<oracle::PutObjectInput, String>;

fn convert(input: dto::PutObjectInput) -> Result<oracle::PutObjectInput, String> {
    input_to_s3s(input).map_err(|error| error.to_string())
}

/// Everything one request produced when both stacks decoded it.
#[derive(Debug)]
struct DecodeDiff {
    differing: Vec<&'static str>,
    /// Source reads (gateway, oracle) once each handler held its input and before anything drained.
    reads_before_handler: (BodyReads, BodyReads),
    /// The exact length each handler's body announces.
    announced: (Option<usize>, Option<usize>),
    /// What each handler's body yields when drained.
    bodies: (Result<Vec<u8>, String>, Result<Vec<u8>, String>),
    /// Source reads after both bodies were drained.
    reads_after_drain: (BodyReads, BodyReads),
}

/// The verdict of each side when at least one did not reach its handler.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    gateway: Result<(), String>,
    conversion: Result<(), String>,
    /// The s3s status and error code, when it refused.
    oracle: Result<(), (u16, Option<String>)>,
}

#[derive(Debug)]
enum Decoded {
    Compared(Box<DecodeDiff>),
    Refused(Refusal),
}

impl Decoded {
    fn compared(self) -> DecodeDiff {
        match self {
            Self::Compared(diff) => *diff,
            Self::Refused(refusal) => panic!("expected both stacks to reach their handler: {refusal:?}"),
        }
    }

    fn refused(self) -> Refusal {
        match self {
            Self::Refused(refusal) => refusal,
            Self::Compared(diff) => panic!("expected a refusal, both stacks decoded: {:?}", diff.differing),
        }
    }
}

/// Decodes `gateway_side` on the gateway and `oracle_side` on s3s, converts the gateway input with
/// `conversion`, and diffs the two oracle inputs. The two requests are the same one except where a
/// mutation below edits one of them on purpose.
fn run_decode(gateway_side: &RawRequest, oracle_side: &RawRequest, conversion: Convert) -> Decoded {
    let gateway_probe = Arc::new(BodyProbe::default());
    let oracle_probe = Arc::new(BodyProbe::default());
    let gateway = gateway_decode(gateway_side, &gateway_probe);
    let exchange = s3s_exchange(oracle_side, &oracle_probe, accepted_output()).expect("the s3s harness itself runs");
    let oracle_verdict = match &exchange.input {
        Some(_) => Ok(()),
        None => Err((exchange.answer.status, exchange.answer.error_code())),
    };
    let gateway_verdict = gateway.as_ref().map(|_| ()).map_err(Clone::clone);
    let (Ok(input), Some(mut decoded)) = (gateway, exchange.input) else {
        return Decoded::Refused(Refusal {
            gateway: gateway_verdict,
            conversion: Ok(()),
            oracle: oracle_verdict,
        });
    };
    let mut converted = match conversion(input) {
        Ok(converted) => converted,
        Err(error) => {
            return Decoded::Refused(Refusal {
                gateway: Ok(()),
                conversion: Err(error),
                oracle: oracle_verdict,
            });
        }
    };
    let reads_before_handler = (gateway_probe.reads(), oracle_probe.reads());
    let differing = differing_members(&converted, &decoded);
    let announced = (
        converted.body.as_ref().and_then(announced_length),
        decoded.body.as_ref().and_then(announced_length),
    );
    let bodies = (
        converted.body.take().map_or_else(|| Err("no body".to_owned()), drain),
        decoded.body.take().map_or_else(|| Err("no body".to_owned()), drain),
    );
    Decoded::Compared(Box::new(DecodeDiff {
        differing,
        reads_before_handler,
        announced,
        bodies,
        reads_after_drain: (gateway_probe.reads(), oracle_probe.reads()),
    }))
}

/// The body crossed as one live stream: unread by either stack before its handler held it, the
/// same announced length and bytes on both, every byte and the end handed out once, and nothing
/// read past the end. On the gateway side it is also read chunk by chunk — one poll per chunk plus
/// the end — so a conversion that collected the body and replayed it cannot pass for streaming.
fn body_streamed_once(diff: &DecodeDiff, request: &RawRequest) -> Result<(), String> {
    let expected = request.body();
    let length = expected.len();
    if diff.reads_before_handler != (BodyReads::default(), BodyReads::default()) {
        return Err(format!("the body was read before the handler held it: {:?}", diff.reads_before_handler));
    }
    if diff.announced != (Some(length), Some(length)) {
        return Err(format!("announced lengths {:?}, body is {length}", diff.announced));
    }
    match &diff.bodies {
        (Ok(converted), Ok(decoded)) if converted == &expected && decoded == &expected => {}
        other => return Err(format!("drained bodies differ from the request body: {other:?}")),
    }
    for (side, reads) in [("gateway", diff.reads_after_drain.0), ("oracle", diff.reads_after_drain.1)] {
        if reads.delivered != length as u64 || reads.eof != 1 || reads.polled_after_eof != 0 {
            return Err(format!("{side} source was not read exactly once to its end: {reads:?}"));
        }
    }
    let chunks = request.chunks.iter().filter(|chunk| !chunk.is_empty()).count();
    if diff.reads_after_drain.0.polls != chunks + 1 {
        return Err(format!(
            "gateway source polled {} times for {chunks} chunks",
            diff.reads_after_drain.0.polls
        ));
    }
    Ok(())
}

fn assert_zero_diff(request: &RawRequest) {
    let diff = run_decode(request, request, convert).compared();
    assert!(diff.differing.is_empty(), "members differ: {:?}", diff.differing);
    body_streamed_once(&diff, request).unwrap();
}

// ── fixtures ──────────────────────────────────────────────────────────────────────────────────

const BODY: &[u8] = b"hello";
const TARGET: &str = "/photos/2026/kitten%20one.jpg";

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let padded = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let triple = (u32::from(padded[0]) << 16) | (u32::from(padded[1]) << 8) | u32::from(padded[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[(triple >> (18 - 6 * index)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn md5_base64(bytes: &[u8]) -> String {
    let mut digest = ContentMd5::digester();
    digest.update(bytes);
    base64(&digest.finish())
}

/// A fixture PUT that states its media type.
///
/// Every zero-diff fixture and generated request sends `Content-Type` and none sends
/// `x-amz-sdk-checksum-algorithm`: those are the two known decode divergences, each pinned by its
/// own named test below, and a fixture that tripped one would only restate it.
fn put(target: &str, body: &[u8], chunk: usize) -> RawRequest {
    RawRequest::put(target, body, chunk).with("content-type", "application/octet-stream")
}

/// Every request header the pinned oracle binds for PutObject that can coexist with SSE-KMS.
fn full_request() -> RawRequest {
    RawRequest::put(TARGET, BODY, 2)
        .with("x-amz-acl", "bucket-owner-full-control")
        .with("cache-control", "max-age=60")
        .with("content-disposition", "attachment; filename=\"k.jpg\"")
        .with("content-encoding", "identity")
        .with("content-language", "en-GB")
        .with("content-md5", &md5_base64(BODY))
        .with("content-type", "image/jpeg")
        .with("x-amz-checksum-crc32", "NhCmhg==")
        .with("expires", "Wed, 21 Oct 2037 07:28:00 GMT")
        .with("if-none-match", "*")
        .with("x-amz-grant-full-control", "id=\"owner-full\"")
        .with("x-amz-grant-read", "id=\"reader\"")
        .with("x-amz-grant-read-acp", "id=\"acp-reader\"")
        .with("x-amz-grant-write-acp", "id=\"acp-writer\"")
        .with("x-amz-write-offset-bytes", "0")
        .with("x-amz-meta-camera", "x100")
        .with("x-amz-meta-album", "cats")
        .with("x-amz-server-side-encryption", "aws:kms")
        .with("x-amz-server-side-encryption-aws-kms-key-id", "arn:aws:kms:us-east-1:123456789012:key/k1")
        .with("x-amz-server-side-encryption-context", "eyJhIjoiYiJ9")
        .with("x-amz-server-side-encryption-bucket-key-enabled", "true")
        .with("x-amz-storage-class", "STANDARD_IA")
        .with("x-amz-website-redirect-location", "/elsewhere")
        .with("x-amz-request-payer", "requester")
        .with("x-amz-tagging", "a=b&c=d")
        .with("x-amz-object-lock-mode", "GOVERNANCE")
        .with("x-amz-object-lock-retain-until-date", "2037-10-21T07:28:00.123Z")
        .with("x-amz-object-lock-legal-hold", "ON")
        .with("x-amz-expected-bucket-owner", "123456789012")
}

/// The SSE-C and `If-Match` members, which the full request cannot also carry.
fn sse_c_request() -> RawRequest {
    let key = [7u8; 32];
    put(TARGET, BODY, 1)
        .with("x-amz-server-side-encryption-customer-algorithm", "AES256")
        .with("x-amz-server-side-encryption-customer-key", &base64(&key))
        .with("x-amz-server-side-encryption-customer-key-md5", &md5_base64(&key))
        .with("if-match", "\"5d41402abc4b2a76b9719d911017c592\"")
}

/// The output the recording handler answers every decode case with.
fn accepted_output() -> oracle::PutObjectOutput {
    oracle::PutObjectOutput {
        e_tag: Some(s3s_etag("5d41402abc4b2a76b9719d911017c592")),
        ..Default::default()
    }
}

fn s3s_etag(value: &str) -> rustfs_gateway_types::compat::s3s::dto::ETag {
    rustfs_gateway_types::compat::s3s::dto::ETag::Strong(value.to_owned())
}

// ── decode: the zero-diff claims ──────────────────────────────────────────────────────────────

#[test]
fn every_member_of_the_full_request_decodes_to_the_same_oracle_input() {
    assert_zero_diff(&full_request());
}

#[test]
fn the_sse_c_and_if_match_members_decode_to_the_same_oracle_input() {
    assert_zero_diff(&sse_c_request());
}

/// Every generated date stops at milliseconds, so this is the case that proves the retention
/// instant crosses at full precision rather than through the millisecond ISO 8601 rendering.
#[test]
fn a_retention_date_with_sub_millisecond_digits_keeps_them() {
    assert_zero_diff(&full_request().replace("x-amz-object-lock-retain-until-date", "2037-10-21T07:28:00.123456789Z"));
}

#[test]
fn an_empty_body_crosses_as_an_empty_stream() {
    assert_zero_diff(&put("/photos/empty", b"", 1));
}

// ── decode: every member is compared ──────────────────────────────────────────────────────────

/// One edit applied to the s3s-side copy of a request only.
#[derive(Clone, Copy, Debug)]
enum Edit {
    Drop(&'static str),
    Set(&'static str, &'static str),
    Target(&'static str),
}

/// For every oracle member, an edit that changes that member and nothing else.
///
/// This is the mutation the member diff owes: the two stacks are handed requests that differ in
/// exactly one member, and the diff must name that member and only that member. A member the diff
/// ignored, or compared through the wrong field, fails its row.
const ONE_MEMBER_EDITS: &[(&str, bool, Edit)] = &[
    ("acl", false, Edit::Drop("x-amz-acl")),
    ("bucket", false, Edit::Target("/other-photos/2026/kitten%20one.jpg")),
    (
        "bucket_key_enabled",
        false,
        Edit::Set("x-amz-server-side-encryption-bucket-key-enabled", "false"),
    ),
    ("cache_control", false, Edit::Drop("cache-control")),
    // The pinned s3s reads the algorithm from `x-amz-checksum-algorithm`, a name the gateway does
    // not bind; see the named divergence test for the SDK header the gateway does read.
    ("checksum_algorithm", false, Edit::Set("x-amz-checksum-algorithm", "CRC32")),
    ("checksum_crc32", false, Edit::Set("x-amz-checksum-crc32", "AAAAAA==")),
    ("checksum_crc32c", false, Edit::Set("x-amz-checksum-crc32c", "AAAAAA==")),
    ("checksum_crc64nvme", false, Edit::Set("x-amz-checksum-crc64nvme", "AAAAAAAAAAA=")),
    ("checksum_md5", false, Edit::Set("x-amz-checksum-md5", "XUFAKrxLKna5cZ2REBfFkg==")),
    ("checksum_sha1", false, Edit::Set("x-amz-checksum-sha1", "qvTGHdzF6KLavt4PO0gs2a6pQ00=")),
    (
        "checksum_sha256",
        false,
        Edit::Set("x-amz-checksum-sha256", "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="),
    ),
    ("checksum_sha512", false, Edit::Set("x-amz-checksum-sha512", "AAAA")),
    ("checksum_xxhash128", false, Edit::Set("x-amz-checksum-xxhash128", "AAAA")),
    ("checksum_xxhash3", false, Edit::Set("x-amz-checksum-xxhash3", "AAAA")),
    ("checksum_xxhash64", false, Edit::Set("x-amz-checksum-xxhash64", "AAAA")),
    ("content_disposition", false, Edit::Drop("content-disposition")),
    ("content_encoding", false, Edit::Drop("content-encoding")),
    ("content_language", false, Edit::Drop("content-language")),
    ("content_length", false, Edit::Set("content-length", "6")),
    ("content_md5", false, Edit::Drop("content-md5")),
    ("content_type", false, Edit::Set("content-type", "text/plain")),
    ("expected_bucket_owner", false, Edit::Drop("x-amz-expected-bucket-owner")),
    ("expires", false, Edit::Set("expires", "Thu, 22 Oct 2037 07:28:00 GMT")),
    ("grant_full_control", false, Edit::Drop("x-amz-grant-full-control")),
    ("grant_read", false, Edit::Drop("x-amz-grant-read")),
    ("grant_read_acp", false, Edit::Drop("x-amz-grant-read-acp")),
    ("grant_write_acp", false, Edit::Drop("x-amz-grant-write-acp")),
    ("if_match", true, Edit::Drop("if-match")),
    ("if_none_match", false, Edit::Drop("if-none-match")),
    ("key", false, Edit::Target("/photos/2026/kitten%20two.jpg")),
    ("metadata", false, Edit::Set("x-amz-meta-camera", "x200")),
    ("object_lock_legal_hold_status", false, Edit::Set("x-amz-object-lock-legal-hold", "OFF")),
    ("object_lock_mode", false, Edit::Set("x-amz-object-lock-mode", "COMPLIANCE")),
    (
        "object_lock_retain_until_date",
        false,
        Edit::Set("x-amz-object-lock-retain-until-date", "2037-10-21T07:28:00.124Z"),
    ),
    ("request_payer", false, Edit::Drop("x-amz-request-payer")),
    (
        "sse_customer_algorithm",
        true,
        Edit::Drop("x-amz-server-side-encryption-customer-algorithm"),
    ),
    ("sse_customer_key", true, Edit::Drop("x-amz-server-side-encryption-customer-key")),
    ("sse_customer_key_md5", true, Edit::Drop("x-amz-server-side-encryption-customer-key-md5")),
    ("ssekms_encryption_context", false, Edit::Drop("x-amz-server-side-encryption-context")),
    ("ssekms_key_id", false, Edit::Drop("x-amz-server-side-encryption-aws-kms-key-id")),
    ("server_side_encryption", false, Edit::Set("x-amz-server-side-encryption", "AES256")),
    ("storage_class", false, Edit::Set("x-amz-storage-class", "GLACIER")),
    ("tagging", false, Edit::Set("x-amz-tagging", "a=z")),
    ("version_id", false, Edit::Target("/photos/2026/kitten%20one.jpg?versionId=v1")),
    ("website_redirect_location", false, Edit::Drop("x-amz-website-redirect-location")),
    ("write_offset_bytes", false, Edit::Drop("x-amz-write-offset-bytes")),
];

fn edited(request: &RawRequest, edit: Edit) -> RawRequest {
    match edit {
        Edit::Drop(name) => request.clone().without(name),
        Edit::Set(name, value) => request.clone().replace(name, value),
        Edit::Target(target) => RawRequest {
            target: target.to_owned(),
            ..request.clone()
        },
    }
}

#[test]
fn the_edit_table_covers_every_oracle_member_once() {
    let edited_members: Vec<&str> = ONE_MEMBER_EDITS.iter().map(|(member, _, _)| *member).collect();
    assert_eq!(edited_members, ORACLE_MEMBERS, "one edit per member, in declaration order");
}

#[test]
fn a_request_that_differs_in_one_member_is_named_by_exactly_that_member() {
    for (member, sse_c, edit) in ONE_MEMBER_EDITS {
        let base = if *sse_c { sse_c_request() } else { full_request() };
        let diff = run_decode(&base, &edited(&base, *edit), convert);
        let Decoded::Compared(diff) = diff else {
            panic!("{member}: the edited request must still reach both handlers: {diff:?}");
        };
        assert_eq!(diff.differing, [*member], "{member}: {edit:?}");
    }
}

/// A conversion that reads one member from the wrong source field: the defect a hand-written
/// mapping of 37 members is most likely to have, and the one the diff exists to catch.
fn crossed_grant_conversion(input: dto::PutObjectInput) -> Result<oracle::PutObjectInput, String> {
    let mut converted = convert(input)?;
    converted.grant_read = converted.grant_read_acp.clone();
    Ok(converted)
}

#[test]
fn a_conversion_that_maps_a_member_from_the_wrong_field_is_caught() {
    let request = full_request();
    let diff = run_decode(&request, &request, crossed_grant_conversion).compared();
    assert_eq!(diff.differing, ["grant_read"]);
}

// ── decode: body consumption ──────────────────────────────────────────────────────────────────

/// A conversion that drains the gateway body into memory and hands s3s the copy: byte-for-byte
/// the same body, and exactly the implicit buffering the streaming claim rules out.
fn buffering_conversion(mut input: dto::PutObjectInput) -> Result<oracle::PutObjectInput, String> {
    use rustfs_gateway_stream::{PayloadRead, PayloadStream};
    let mut bytes = Vec::new();
    if let Some(mut stream) = input.body.take() {
        block_on(std::future::poll_fn(|cx| {
            loop {
                match std::pin::Pin::new(&mut stream).poll_read(cx) {
                    std::task::Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => bytes.extend_from_slice(&chunk),
                    std::task::Poll::Ready(Ok(PayloadRead::Eof { .. })) => return std::task::Poll::Ready(Ok(())),
                    std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error.to_string())),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
        }))?;
    }
    let mut converted = convert(input)?;
    converted.body = Some(bytes::Bytes::from(bytes).into());
    Ok(converted)
}

#[test]
fn a_conversion_that_buffers_the_body_is_caught() {
    let request = full_request();
    let diff = run_decode(&request, &request, buffering_conversion).compared();
    assert!(diff.differing.is_empty(), "the members are unchanged: {:?}", diff.differing);
    let refusal = body_streamed_once(&diff, &request).expect_err("buffering must not pass for streaming");
    assert!(refusal.contains("before the handler"), "{refusal}");
}

#[test]
fn a_body_that_fails_mid_stream_fails_the_handler_instead_of_ending_early() {
    let mut request = RawRequest::put(TARGET, BODY, 2);
    request.fail_after_first_chunk = true;
    let probe = Arc::new(BodyProbe::default());
    let input = gateway_decode(&request, &probe).expect("the head is valid; the failure is in the body");
    let converted = input_to_s3s(input).expect("the members convert");
    let drained = drain(converted.body.expect("PutObject always carries its body"));
    assert!(drained.is_err(), "a truncated body must not drain as a complete one: {drained:?}");
}

#[test]
fn trailers_the_s3s_body_cannot_carry_fail_the_handler_instead_of_vanishing() {
    let mut request = RawRequest::put(TARGET, BODY, 5);
    request.trailers = vec![("x-amz-checksum-crc32".to_owned(), "NhCmhg==".to_owned())];
    let probe = Arc::new(BodyProbe::default());
    let input = gateway_decode(&request, &probe).expect("the head is valid");
    let converted = input_to_s3s(input).expect("the members convert");
    let error = drain(converted.body.expect("PutObject always carries its body")).expect_err("a dropped trailer is lost data");
    assert!(error.contains("trailer"), "{error}");
}

// ── decode: the known divergences, named ──────────────────────────────────────────────────────

/// The gateway answers a PUT without `Content-Length` with the dedicated 411 code
/// (`q-length-0007`); the pinned s3s back-fills the length from the body it can measure and hands
/// the request to its handler. This is a behavioral difference a migration must decide, not a
/// conversion gap: no gateway input exists for the conversion to run on.
#[test]
fn a_put_without_content_length_is_refused_by_the_gateway_and_backfilled_by_s3s() {
    let request = RawRequest::put(TARGET, BODY, 5).without("content-length");
    let refusal = run_decode(&request, &request, convert).refused();
    assert_eq!(
        refusal,
        Refusal {
            gateway: Err("MissingContentLength".to_owned()),
            conversion: Ok(()),
            oracle: Ok(()),
        }
    );
}

#[test]
fn an_expires_that_is_not_a_date_is_kept_by_the_gateway_and_refused_by_s3s() {
    let request = full_request().replace("expires", "never");
    let refusal = run_decode(&request, &request, convert).refused();
    assert_eq!(refusal.gateway, Ok(()), "the gateway keeps Expires opaque (q-timestamp-0005)");
    assert!(matches!(refusal.oracle, Err((400, _))), "{refusal:?}");
    let probe = Arc::new(BodyProbe::default());
    let error = input_to_s3s(gateway_decode(&request, &probe).expect("accepted"))
        .expect_err("an s3s input cannot hold a non-date Expires");
    assert_eq!(error.field, "expires");
}

#[test]
fn two_checksum_headers_are_refused_by_the_gateway_and_kept_by_s3s() {
    let request = full_request().with("x-amz-checksum-sha256", "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
    let refusal = run_decode(&request, &request, convert).refused();
    assert!(refusal.gateway.is_err(), "q-checksum-0006: more than one checksum header is a hard error");
    assert_eq!(refusal.oracle, Ok(()));
}

#[test]
fn a_checksum_algorithm_the_gateway_does_not_know_is_a_member_diff() {
    let request = RawRequest::put(TARGET, BODY, 5).with("x-amz-checksum-sha512", "AAAA");
    let observed = run_decode(&request, &request, convert);
    match observed {
        Decoded::Compared(diff) => assert_eq!(diff.differing, ["checksum_sha512"]),
        Decoded::Refused(refusal) => assert!(refusal.gateway.is_err() && refusal.oracle.is_ok(), "{refusal:?}"),
    }
}

/// `q-content-0008`: the gateway decoder fills an absent `Content-Type` with the S3 default, so the
/// converted input says `binary/octet-stream` where s3s says nothing. The conversion cannot undo
/// it — the gateway input no longer records whether the client sent the header — so the migration
/// has to decide which answer the RustFS app body gets.
#[test]
fn an_absent_content_type_is_defaulted_by_the_gateway_and_left_absent_by_s3s() {
    let request = RawRequest::put(TARGET, BODY, 5);
    let diff = run_decode(&request, &request, convert).compared();
    assert_eq!(diff.differing, ["content_type"]);
    let probe = Arc::new(BodyProbe::default());
    let converted = input_to_s3s(gateway_decode(&request, &probe).expect("accepted")).expect("converts");
    assert_eq!(converted.content_type.as_deref(), Some("binary/octet-stream"));
}

/// The gateway binds the algorithm to `x-amz-sdk-checksum-algorithm`, the header the SDKs send;
/// the pinned s3s reads `x-amz-checksum-algorithm` (or infers it from `x-amz-trailer`) and so hands
/// its handler no algorithm for the same request.
#[test]
fn the_sdk_checksum_algorithm_header_is_read_by_the_gateway_and_not_by_s3s() {
    let request = put(TARGET, BODY, 5)
        .with("x-amz-sdk-checksum-algorithm", "CRC32")
        .with("x-amz-checksum-crc32", "NhCmhg==");
    let diff = run_decode(&request, &request, convert).compared();
    assert_eq!(diff.differing, ["checksum_algorithm"]);
}

#[test]
fn the_minio_version_id_query_on_a_put_is_seen_by_s3s_only() {
    let request = RawRequest {
        target: format!("{TARGET}?versionId=v1"),
        ..put(TARGET, BODY, 5)
    };
    let diff = run_decode(&request, &request, convert).compared();
    assert_eq!(diff.differing, ["version_id"], "the gateway model has no PutObject versionId member");
}

/// The gateway's object-key floor refuses a `..` path segment before anything is stored; the
/// pinned s3s hands its handler the key `..` unchanged. Found by the decode property, which
/// therefore never draws a dot-only segment.
#[test]
fn a_dot_dot_key_segment_is_refused_by_the_gateway_and_kept_by_s3s() {
    let request = put("/photos/..", BODY, 5);
    let refusal = run_decode(&request, &request, convert).refused();
    assert_eq!(
        refusal,
        Refusal {
            gateway: Err("InvalidArgument".to_owned()),
            conversion: Ok(()),
            oracle: Ok(()),
        }
    );
}

// ── decode: the property ──────────────────────────────────────────────────────────────────────

fn optional(name: &'static str, value: impl Strategy<Value = String> + 'static) -> BoxedStrategy<Option<(&'static str, String)>> {
    proptest::option::of(value.prop_map(move |value| (name, value))).boxed()
}

fn pick(values: &'static [&'static str]) -> impl Strategy<Value = String> {
    proptest::sample::select(values).prop_map(str::to_owned)
}

fn instant(format: TimestampFormat, millis: bool) -> impl Strategy<Value = String> {
    (0i64..4_102_444_800, 0u32..1000).prop_map(move |(secs, ms)| {
        let nanos = if millis { ms * 1_000_000 } else { 0 };
        Timestamp::from_secs_nanos(secs, nanos)
            .and_then(|at| at.render(format))
            .expect("the range is inside the renderable years")
    })
}

fn checksum() -> impl Strategy<Value = (ChecksumAlgorithm, String)> {
    (proptest::sample::select(ChecksumAlgorithm::ALL), any::<[u8; 32]>()).prop_map(|(algo, bytes)| {
        let spec = ChecksumSpec::from_digest(algo, &bytes[..algo.digest_len()]).expect("the width is the algorithm's");
        (algo, spec.render_base64().to_owned())
    })
}

prop_compose! {
    fn requests()(
        bucket in "[a-z]{3,12}",
        // A segment never starts with a dot, so none is dot-only: `..` is a pinned divergence
        // (`a_dot_dot_key_segment_is_refused_by_the_gateway_and_kept_by_s3s`), not a draw.
        key in proptest::collection::vec("[A-Za-z0-9_-][A-Za-z0-9._-]{0,7}|%20", 1..4),
        body in proptest::collection::vec(any::<u8>(), 0..64),
        chunk in 1usize..16,
        checksum in proptest::option::of(checksum()),
        content_type in pick(&["text/plain", "image/png", "application/octet-stream"]),
        declare_md5 in any::<bool>(),
        metadata in proptest::collection::btree_map("[a-z][a-z0-9]{0,8}", "[A-Za-z0-9._~+-]{1,16}", 0..3),
        headers in vec![
            optional("x-amz-acl", pick(&["private", "public-read", "public-read-write", "authenticated-read", "aws-exec-read", "bucket-owner-read", "bucket-owner-full-control"])),
            optional("cache-control", pick(&["no-cache", "max-age=60", "private, max-age=0"])),
            optional("content-disposition", pick(&["inline", "attachment; filename=\"a.bin\""])),
            optional("content-encoding", pick(&["gzip", "identity", "br"])),
            optional("content-language", pick(&["en", "zh-CN", "en-GB"])),
            optional("expires", instant(TimestampFormat::HttpDate, false)),
            optional("if-match", pick(&["*", "\"5d41402abc4b2a76b9719d911017c592\""])),
            optional("if-none-match", pick(&["*", "\"0000000000000000000000000000dead\""])),
            optional("x-amz-grant-full-control", "id=\"[a-z0-9]{1,12}\""),
            optional("x-amz-grant-read", "id=\"[a-z0-9]{1,12}\""),
            optional("x-amz-grant-read-acp", "id=\"[a-z0-9]{1,12}\""),
            optional("x-amz-grant-write-acp", "id=\"[a-z0-9]{1,12}\""),
            optional("x-amz-write-offset-bytes", (0u64..1 << 40).prop_map(|n| n.to_string())),
            optional("x-amz-server-side-encryption", pick(&["AES256", "aws:kms"])),
            optional("x-amz-server-side-encryption-aws-kms-key-id", "[a-z0-9:/-]{1,24}"),
            optional("x-amz-server-side-encryption-context", pick(&["e30=", "eyJhIjoiYiJ9"])),
            optional("x-amz-server-side-encryption-bucket-key-enabled", pick(&["true", "false"])),
            optional("x-amz-storage-class", pick(&["STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER", "DEEP_ARCHIVE", "GLACIER_IR"])),
            optional("x-amz-website-redirect-location", "/[a-z0-9]{0,12}"),
            optional("x-amz-request-payer", pick(&["requester"])),
            optional("x-amz-tagging", "[a-z]{1,4}=[a-z]{0,4}"),
            optional("x-amz-object-lock-mode", pick(&["GOVERNANCE", "COMPLIANCE"])),
            optional("x-amz-object-lock-retain-until-date", instant(TimestampFormat::Iso8601, true)),
            optional("x-amz-object-lock-legal-hold", pick(&["ON", "OFF"])),
            optional("x-amz-expected-bucket-owner", "[0-9]{12}"),
        ],
    ) -> RawRequest {
        let mut request = RawRequest::put(&format!("/{bucket}/{}", key.join("/")), &body, chunk).with("content-type", &content_type);
        if declare_md5 {
            request = request.with("content-md5", &md5_base64(&body));
        }
        if let Some((algo, value)) = checksum {
            request = request.with(algo.header_name(), &value);
        }
        for (name, value) in metadata {
            request = request.with(&format!("x-amz-meta-{name}"), &value);
        }
        for (name, value) in headers.into_iter().flatten() {
            request = request.with(name, &value);
        }
        request
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Any request both stacks accept decodes, through the conversion, to the oracle's own input
    /// in every member, and its body crosses unread and is read exactly once.
    #[test]
    fn a_generated_request_decodes_to_the_same_oracle_input(request in requests()) {
        match run_decode(&request, &request, convert) {
            Decoded::Compared(diff) => {
                prop_assert!(diff.differing.is_empty(), "members differ: {:?}", diff.differing);
                if let Err(error) = body_streamed_once(&diff, &request) {
                    return Err(TestCaseError::fail(error));
                }
            }
            Decoded::Refused(refusal) => {
                return Err(TestCaseError::fail(format!("the generator only draws requests both stacks accept: {refusal:?}")));
            }
        }
    }
}

// ── the gateway half of the census ────────────────────────────────────────────────────────────

/// The field-count ratchet for one generated DTO, read from the protected file.
fn generated_field_count(type_name: &str) -> usize {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/dto/field_counts.txt");
    let counts = std::fs::read_to_string(path).expect("the field-count ratchet is committed");
    counts
        .lines()
        .find_map(|line| {
            let (name, count) = line.split_once(' ')?;
            (name == type_name).then(|| count.trim().parse().expect("a count is a number"))
        })
        .unwrap_or_else(|| panic!("{type_name} is missing from the field-count ratchet"))
}

/// The gateway structs may not be destructured exhaustively (ADR-0004 P3), so the conversion
/// declares the members it maps and this pins that declaration to the generated struct: a member
/// added to the model fails here until the conversion maps it.
#[test]
fn the_conversion_declares_every_gateway_member() {
    for (type_name, members) in [
        ("PutObjectInput", GATEWAY_INPUT_MEMBERS),
        ("PutObjectOutput", GATEWAY_OUTPUT_MEMBERS),
    ] {
        let distinct: BTreeSet<&str> = members.iter().copied().collect();
        assert_eq!(distinct.len(), members.len(), "{type_name}: a member is declared twice");
        assert_eq!(
            members.len(),
            generated_field_count(type_name),
            "{type_name}: the conversion is behind the model"
        );
    }
}
