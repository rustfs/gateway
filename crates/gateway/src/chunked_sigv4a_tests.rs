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

//! End-to-end SigV4a (`AWS4-ECDSA-P256-SHA256`) authentication and streaming chunked-body tests
//! inside `rustfs-gateway`.
//!
//! Responsible for: verifying `SecurityFloor::admit` -> `SigV4Authenticator::authenticate` ->
//! `ChunkSink` -> `ChunkIngest::prepare`/`run` -> `BodyDigests::verify` across SigV4a header,
//! presigned, streaming unpadded, streaming CRT-padded, streaming trailer, cross-algorithm
//! refusals, unknown keys, missing/mismatched `x-amz-region-set`, POST form refusal, and
//! anonymous streaming refusal.
//! NOT responsible for: upstream smithy-rs suite replay (`rustfs-gateway-sig`).
//! Upstream: `super` (`crate::chunked`), `crate::ext`, `crate::payload_header`.
//! Downstream: none (unit test submodule).

use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use rustfs_gateway_http::{BodyIntegrity, ChecksumSubject, ChunkLimits, Framing, HeaderView, Limits};
use rustfs_gateway_sig::{
    Admission, AmzDate, AuthError, DeclaredTrailers, OperationFloor, PayloadMode, RawHost, RawQuery, RegionSet, RequestNow,
    STREAMING_ECDSA, STREAMING_ECDSA_TRAILER, ScopeDate, SecurityFloor, SigFamily, SigLocation, SigService, SigV4Signer,
    SigV4aSigner, SigningCredentials, SigningRequest, SigningScope, TrailerName, TrailerSet, Unimplemented, WireView,
    X_AMZ_REGION_SET_HEADER,
};
use rustfs_gateway_stream::{MemoryReader, TrailingHeaders};

use super::ChunkIngest;
use crate::ext::{AuthSchemeRef, Authentication, Authenticator, ChunkSink, Credentials, SigV4Authenticator, StaticCredentials};

const AKID: &str = "AKIDEXAMPLE";
const SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const STAMP: &str = "20150830T123600Z";
const NOW_UNIX: i64 = 1_440_938_160;

fn auth() -> SigV4Authenticator {
    SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(Credentials::new(AKID, SECRET).expect("valid"))),
        RegionSet::new(["us-east-1"]).expect("valid"),
    )
}

fn s3_op() -> OperationFloor {
    OperationFloor::builtin_presigned("PutObject", SigService::S3).allow_post_policy()
}

fn raw_host() -> RawHost {
    RawHost::from_host_header(b"example.amazonaws.com").expect("valid")
}

fn stamp() -> AmzDate {
    AmzDate::parse(STAMP).expect("valid")
}

fn day() -> ScopeDate {
    ScopeDate::parse("20150830").expect("valid")
}

fn v4a_signer(region_set: &str) -> SigV4aSigner {
    SigV4aSigner::new(SigningCredentials::new(AKID, SECRET).expect("valid"), day(), SigService::S3, region_set).expect("valid")
}

fn wire_framing(len: u64) -> Framing {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_str(&len.to_string()).expect("digits"));
    Framing::classify(http::Version::HTTP_11, &headers, &Limits::default()).expect("framed")
}

// ---------------------------------------------------------------------------
// Positive cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sigv4a_header_authenticates_through_sigv4_authenticator() {
    let signer = v4a_signer("eu-west-1,us-east-1");
    let headers = HeaderMap::new();
    let host = raw_host();
    let req = SigningRequest::new(&Method::GET, "/bucket/obj", "", &headers, &host, PayloadMode::Empty, stamp());
    let signed = signer.sign_headers(&req).expect("signs");

    let floor = SecurityFloor::new();
    let view = WireView::new(signed.headers(), RawQuery::new(""));
    let Admission::Sealed(sealed) = floor
        .admit(view, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    let question = Authentication::new(&sealed, &Method::GET, "/bucket/obj", &host, &PayloadMode::Empty, None);
    let outcome = auth().authenticate(&question).await.expect("store ok");
    assert!(outcome.verdict().is_authenticated());
    assert_eq!(AuthSchemeRef::of_verdict(outcome.verdict()), Some(AuthSchemeRef::OtherSigned));
    assert_eq!(outcome.verdict().verified_scope().map(|s| s.region()), Some("eu-west-1,us-east-1"));
}

#[tokio::test]
async fn sigv4a_presigned_authenticates_through_sigv4_authenticator() {
    let signer = v4a_signer("*");
    let headers = HeaderMap::new();
    let host = raw_host();
    let req = SigningRequest::new(&Method::GET, "/bucket/obj", "", &headers, &host, PayloadMode::Unsigned, stamp());
    let signed = signer.presign(&req, 3600).expect("presigns");

    let floor = SecurityFloor::new();
    let view = WireView::new(signed.headers(), RawQuery::new(signed.query()));
    let Admission::Sealed(sealed) = floor
        .admit(view, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX + 60))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    let question = Authentication::new(&sealed, &Method::GET, "/bucket/obj", &host, &PayloadMode::Unsigned, None);
    let outcome = auth().authenticate(&question).await.expect("store ok");
    assert!(outcome.verdict().is_authenticated());
    assert_eq!(outcome.verdict().verified_scope().map(|s| s.region()), Some("*"));
}

#[tokio::test]
async fn sigv4a_streaming_upload_unpadded_and_crt_padded_verify_end_to_end() {
    for padded in [false, true] {
        let signer = v4a_signer("*");
        let headers = HeaderMap::new();
        let host = raw_host();
        let payload = PayloadMode::parse(STREAMING_ECDSA, TrailerSet::None).expect("valid");
        let req = SigningRequest::new(&Method::PUT, "/bucket/obj", "", &headers, &host, payload.clone(), stamp())
            .with_decoded_content_length(11);
        let signed = signer.sign_headers(&req).expect("signs");

        let floor = SecurityFloor::new();
        let view = WireView::new(signed.headers(), RawQuery::new(""));
        let Admission::Sealed(sealed) = floor
            .admit(view, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
            .expect("ok")
        else {
            panic!("expected Sealed");
        };
        let sink = ChunkSink::new();
        let question = Authentication::new(&sealed, &Method::PUT, "/bucket/obj", &host, &payload, None).with_chunk_sink(&sink);
        let outcome = auth().authenticate(&question).await.expect("store ok");
        assert!(outcome.verdict().is_authenticated(), "padded={padded}");
        assert!(question.signs_its_body());

        let mut chunker = signer.chunk_signer(signed.signature_hex(), stamp());
        let mut wire = Vec::new();
        if padded {
            wire.extend_from_slice(&chunker.encode_chunk_padded(b"hello "));
            wire.extend_from_slice(&chunker.encode_chunk_padded(b"world"));
            wire.extend_from_slice(&chunker.encode_chunk_padded(b""));
        } else {
            wire.extend_from_slice(&chunker.encode_chunk(b"hello "));
            wire.extend_from_slice(&chunker.encode_chunk(b"world"));
            wire.extend_from_slice(&chunker.encode_chunk(b""));
        }

        let ingest = ChunkIngest::prepare(
            &payload,
            signed.headers(),
            &wire_framing(wire.len() as u64),
            &sink,
            ChunkLimits::default(),
        )
        .expect("prepare ok")
        .expect("framed");

        let mut digests = BodyIntegrity::NONE.begin();
        let out = ingest
            .run(MemoryReader::new([Bytes::from(wire)], TrailingHeaders::empty()), &mut digests)
            .await
            .expect("chunk stream verifies");
        assert_eq!(out.into_body().as_ref(), b"hello world");
    }
}

#[tokio::test]
async fn sigv4a_streaming_trailer_upload_verifies_end_to_end() {
    let signer = v4a_signer("us-east-1");
    let headers = HeaderMap::new();
    let host = raw_host();
    let payload = PayloadMode::parse(
        STREAMING_ECDSA_TRAILER,
        TrailerSet::Declared(DeclaredTrailers::new([TrailerName::new("x-amz-checksum-crc32").expect("ok")], true).expect("ok")),
    )
    .expect("valid");
    let req = SigningRequest::new(&Method::PUT, "/bucket/obj", "", &headers, &host, payload.clone(), stamp())
        .with_decoded_content_length(11);
    let signed = signer.sign_headers(&req).expect("signs");

    let floor = SecurityFloor::new();
    let view = WireView::new(signed.headers(), RawQuery::new(""));
    let Admission::Sealed(sealed) = floor
        .admit(view, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    let sink = ChunkSink::new();
    let question = Authentication::new(&sealed, &Method::PUT, "/bucket/obj", &host, &payload, None).with_chunk_sink(&sink);
    let outcome = auth().authenticate(&question).await.expect("store ok");
    assert!(outcome.verdict().is_authenticated());

    let mut chunker = signer.chunk_signer(signed.signature_hex(), stamp());
    let mut wire = chunker.encode_chunk_padded(b"hello world");
    let term_sig = chunker.sign_chunk_padded(b"");
    wire.extend_from_slice(format!("0;chunk-signature={term_sig}\r\n").as_bytes());
    let trailer_sig = chunker.sign_trailer_padded("x-amz-checksum-crc32:DUoRhQ==\n");
    wire.extend_from_slice(b"x-amz-checksum-crc32:DUoRhQ==\r\n");
    wire.extend_from_slice(format!("x-amz-trailer-signature:{trailer_sig}\r\n\r\n").as_bytes());

    let ingest = ChunkIngest::prepare(
        &payload,
        signed.headers(),
        &wire_framing(wire.len() as u64),
        &sink,
        ChunkLimits::default(),
    )
    .expect("prepare ok")
    .expect("framed");

    let mut integrity_headers = HeaderMap::new();
    integrity_headers.insert(HeaderName::from_static("x-amz-trailer"), HeaderValue::from_static("x-amz-checksum-crc32"));
    let mut digests = BodyIntegrity::resolve(&HeaderView::new(&integrity_headers), ChecksumSubject::RequestBody)
        .expect("ok")
        .begin();
    let out = ingest
        .run(MemoryReader::new([Bytes::from(wire)], TrailingHeaders::empty()), &mut digests)
        .await
        .expect("trailer stream verifies");
    let verified = digests.verify_with_trailers(out.trailers()).expect("crc32 matches");
    assert!(out.commit_allowed(&verified));
    assert_eq!(out.into_body().as_ref(), b"hello world");
}

// ---------------------------------------------------------------------------
// Negative cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn n_sigv4a_unknown_access_key_returns_uniform_invalid_access_key_id() {
    let unknown_signer =
        SigV4aSigner::new(SigningCredentials::new("AKIDUNKNOWN", SECRET).expect("valid"), day(), SigService::S3, "*")
            .expect("valid");
    let headers = HeaderMap::new();
    let host = raw_host();
    let req = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Empty, stamp());
    let signed = unknown_signer.sign_headers(&req).expect("signs");

    let floor = SecurityFloor::new();
    let view = WireView::new(signed.headers(), RawQuery::new(""));
    let Admission::Sealed(sealed) = floor
        .admit(view, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    let question = Authentication::new(&sealed, &Method::GET, "/b/k", &host, &PayloadMode::Empty, None);
    let outcome = auth().authenticate(&question).await.expect("store ok");
    assert_eq!(outcome.verdict().rejection(), Some(AuthError::InvalidAccessKeyId));
}

#[tokio::test]
async fn n_sigv4a_wrong_secret_never_publishes_chunk_material() {
    let wrong_signer = SigV4aSigner::new(
        SigningCredentials::new(AKID, b"wrong-secret-key").expect("valid"),
        day(),
        SigService::S3,
        "*",
    )
    .expect("valid");
    let headers = HeaderMap::new();
    let host = raw_host();
    let payload = PayloadMode::parse(STREAMING_ECDSA, TrailerSet::None).expect("valid");
    let req =
        SigningRequest::new(&Method::PUT, "/b/k", "", &headers, &host, payload.clone(), stamp()).with_decoded_content_length(5);
    let signed = wrong_signer.sign_headers(&req).expect("signs");

    let floor = SecurityFloor::new();
    let view = WireView::new(signed.headers(), RawQuery::new(""));
    let Admission::Sealed(sealed) = floor
        .admit(view, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    let sink = ChunkSink::new();
    let question = Authentication::new(&sealed, &Method::PUT, "/b/k", &host, &payload, None).with_chunk_sink(&sink);
    let outcome = auth().authenticate(&question).await.expect("store ok");
    assert_eq!(outcome.verdict().rejection(), Some(AuthError::SignatureDoesNotMatch));
    assert!(sink.get().is_none(), "failed auth must never publish chunk material");
}

#[tokio::test]
async fn n_sigv4a_missing_region_set_header_is_rejected() {
    let signer = v4a_signer("us-east-1");
    let headers = HeaderMap::new();
    let host = raw_host();
    let req = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Empty, stamp());
    let signed = signer.sign_headers(&req).expect("signs");
    let mut stripped = signed.headers().clone();
    stripped.remove(X_AMZ_REGION_SET_HEADER);

    let floor = SecurityFloor::new();
    let view = WireView::new(&stripped, RawQuery::new(""));
    let Admission::Sealed(sealed) = floor
        .admit(view, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    let question = Authentication::new(&sealed, &Method::GET, "/b/k", &host, &PayloadMode::Empty, None);
    let outcome = auth().authenticate(&question).await.expect("store ok");
    assert_eq!(outcome.verdict().rejection(), Some(AuthError::AuthorizationHeaderMalformed));
}

#[tokio::test]
async fn n_sigv4a_mismatched_region_set_yields_scope_rejection_with_remediation() {
    let signer = v4a_signer("ap-southeast-1");
    let headers = HeaderMap::new();
    let host = raw_host();
    let req = SigningRequest::new(&Method::GET, "/b/k", "", &headers, &host, PayloadMode::Empty, stamp());
    let signed = signer.sign_headers(&req).expect("signs");

    let floor = SecurityFloor::new();
    let view = WireView::new(signed.headers(), RawQuery::new(""));
    let Admission::Sealed(sealed) = floor
        .admit(view, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    let question = Authentication::new(&sealed, &Method::GET, "/b/k", &host, &PayloadMode::Empty, None);
    let outcome = auth().authenticate(&question).await.expect("store ok");
    let (verdict, scope_rej, _) = outcome.into_parts();
    assert_eq!(verdict.rejection(), Some(AuthError::AuthorizationHeaderMalformed));
    assert_eq!(
        scope_rej.and_then(|r| r.expected_region().map(|reg| reg.as_str().to_owned())),
        Some("us-east-1".to_owned())
    );
}

#[tokio::test]
async fn n_cross_algorithm_streaming_pairings_are_refused() {
    let host = raw_host();
    let headers = HeaderMap::new();
    let floor = SecurityFloor::new();

    // 1. SigV4a request declaring HMAC streaming payload -> refused.
    let v4a = v4a_signer("*");
    let hmac_payload = PayloadMode::StreamingSigned {
        trailer: TrailerSet::None,
    };
    let req1 = SigningRequest::new(&Method::PUT, "/b/k", "", &headers, &host, hmac_payload.clone(), stamp())
        .with_decoded_content_length(5);
    let signed1 = v4a.sign_headers(&req1).expect("signs");
    let view1 = WireView::new(signed1.headers(), RawQuery::new(""));
    let Admission::Sealed(sealed1) = floor
        .admit(view1, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    let q1 = Authentication::new(&sealed1, &Method::PUT, "/b/k", &host, &hmac_payload, None);
    assert_eq!(
        auth().authenticate(&q1).await.expect("ok").verdict().rejection(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );

    // 2. SigV4 HMAC request declaring ECDSA streaming payload -> refused.
    let mut v4 = SigV4Signer::new(
        SigningCredentials::new(AKID, SECRET).expect("valid"),
        SigningScope::new(day(), "us-east-1", SigService::S3).expect("valid"),
    );
    let ecdsa_payload = PayloadMode::parse(STREAMING_ECDSA, TrailerSet::None).expect("valid");
    let req2 = SigningRequest::new(&Method::PUT, "/b/k", "", &headers, &host, ecdsa_payload.clone(), stamp())
        .with_decoded_content_length(5);
    let signed2 = v4.sign_headers(&req2).expect("signs");
    let view2 = WireView::new(signed2.headers(), RawQuery::new(""));
    let Admission::Sealed(sealed2) = floor
        .admit(view2, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    let q2 = Authentication::new(&sealed2, &Method::PUT, "/b/k", &host, &ecdsa_payload, None);
    assert_eq!(
        auth().authenticate(&q2).await.expect("ok").verdict().rejection(),
        Some(AuthError::AuthorizationHeaderMalformed)
    );
}

#[tokio::test]
async fn n_sigv4a_post_form_is_refused_not_implemented() {
    let headers = HeaderMap::new();
    let fields = [
        ("x-amz-algorithm", "AWS4-ECDSA-P256-SHA256"),
        ("x-amz-credential", "AKIDEXAMPLE/20150830/s3/aws4_request"),
        ("x-amz-date", STAMP),
        ("x-amz-signature", "3006020101020101"),
        ("policy", "e30="),
    ];
    let floor = SecurityFloor::new();
    let view = WireView::new(&headers, RawQuery::new("")).with_form_fields(&fields);
    let Admission::Sealed(sealed) = floor
        .admit(view, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    assert_eq!(sealed.marker().family(), SigFamily::V4a);
    assert_eq!(sealed.marker().location(), SigLocation::FormField);
    let host = raw_host();
    let question = Authentication::new(&sealed, &Method::POST, "/bucket", &host, &PayloadMode::Unsigned, None);
    let outcome = auth().authenticate(&question).await.expect("store ok");
    assert_eq!(outcome.verdict().rejection(), Some(AuthError::NotImplemented(Unimplemented::SigV4a)));
}

#[tokio::test]
async fn n_sigv4a_tampered_chunk_and_trailer_return_403_and_close_connection() {
    let signer = v4a_signer("*");
    let headers = HeaderMap::new();
    let host = raw_host();
    let payload = PayloadMode::parse(STREAMING_ECDSA, TrailerSet::None).expect("valid");
    let req =
        SigningRequest::new(&Method::PUT, "/b/k", "", &headers, &host, payload.clone(), stamp()).with_decoded_content_length(5);
    let signed = signer.sign_headers(&req).expect("signs");

    let floor = SecurityFloor::new();
    let view = WireView::new(signed.headers(), RawQuery::new(""));
    let Admission::Sealed(sealed) = floor
        .admit(view, &s3_op(), RequestNow::from_unix_seconds(NOW_UNIX))
        .expect("ok")
    else {
        panic!("expected Sealed");
    };
    let sink = ChunkSink::new();
    let question = Authentication::new(&sealed, &Method::PUT, "/b/k", &host, &payload, None).with_chunk_sink(&sink);
    assert!(auth().authenticate(&question).await.expect("ok").verdict().is_authenticated());

    let mut chunker = signer.chunk_signer(signed.signature_hex(), stamp());
    let mut wire = chunker.encode_chunk(b"hello");
    wire.extend_from_slice(&chunker.encode_chunk(b""));
    let pos = wire.windows(5).position(|w| w == b"hello").expect("payload");
    *wire.get_mut(pos).expect("payload byte") = b'j';

    let ingest = ChunkIngest::prepare(
        &payload,
        signed.headers(),
        &wire_framing(wire.len() as u64),
        &sink,
        ChunkLimits::default(),
    )
    .expect("prepare ok")
    .expect("framed");

    let err = ingest
        .run(
            MemoryReader::new([Bytes::from(wire)], TrailingHeaders::empty()),
            &mut BodyIntegrity::NONE.begin(),
        )
        .await
        .expect_err("tampered chunk must fail");
    assert_eq!(err.status(), StatusCode::FORBIDDEN);
    assert!(err.must_close_connection());
}

#[test]
fn n_anonymous_ecdsa_streaming_request_is_refused() {
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static("x-amz-content-sha256"), HeaderValue::from_static(STREAMING_ECDSA));
    let err = crate::payload_header::anonymous_framing(&headers, true).expect_err("must refuse");
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

struct RecordingPut(Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

impl crate::Handler<crate::dto::PutObject> for RecordingPut {
    async fn call(&self, request: crate::Req<crate::dto::PutObject>) -> crate::HandlerResult<crate::dto::PutObject> {
        use http_body_util::BodyExt as _;
        let mut collected = Vec::new();
        if let Some(body) = request.into_input().body {
            collected = body
                .into_body()
                .collect()
                .await
                .map_err(|_| crate::HandlerError::internal_error("body stream failed"))?
                .to_bytes()
                .to_vec();
        }
        self.0.lock().expect("lock").push(collected);
        Ok(crate::Resp::new(crate::dto::PutObjectOutput::default()))
    }
}

struct StubGet;

impl crate::Handler<crate::dto::GetObject> for StubGet {
    async fn call(&self, _request: crate::Req<crate::dto::GetObject>) -> crate::HandlerResult<crate::dto::GetObject> {
        Ok(crate::Resp::new(crate::dto::GetObjectOutput::default()))
    }
}

fn sigv4a_service(rustfs_profile: bool) -> (crate::S3Service, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let creds = Arc::new(
        StaticCredentials::new()
            .with(Credentials::new(AKID, SECRET).expect("valid"))
            .with(Credentials::new("AKIDSignature=deadbeef", SECRET).expect("valid")),
    );
    let regions = RegionSet::new(["us-east-1"]).expect("valid");
    let (builder, authenticator) = if rustfs_profile {
        (
            crate::ServiceBuilder::new().rustfs_profile(),
            SigV4Authenticator::new(creds, regions).rustfs_profile(),
        )
    } else {
        (crate::ServiceBuilder::new(), SigV4Authenticator::new(creds, regions))
    };
    let service = builder
        .authenticator(authenticator)
        .authorizer(crate::allow_when(|_| true))
        .clock_with_skew_ack(
            crate::FixedClock::at_unix_seconds(NOW_UNIX),
            crate::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<crate::dto::PutObject, _>(Arc::new(RecordingPut(Arc::clone(&recorded))))
        .register::<crate::dto::GetObject, _>(Arc::new(StubGet))
        .build()
        .expect("complete S3Service");
    (service, recorded)
}

async fn call_service(
    service: &crate::S3Service,
    method: Method,
    uri: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
) -> crate::WireResponse {
    let mut builder = http::Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    if !headers.contains_key(http::header::HOST) {
        builder = builder.header(http::header::HOST, "example.amazonaws.com");
    }
    let req = builder
        .body(http_body_util::Full::new(Bytes::from(body)))
        .expect("valid request");
    let resp = service.call(req).await;
    crate::wire::collect(resp).await.expect("collect response")
}

#[tokio::test]
async fn s3_service_sigv4a_header_presigned_streaming_and_trailer_end_to_end() {
    for rustfs_profile in [false, true] {
        let (service, recorded) = sigv4a_service(rustfs_profile);
        let signer = v4a_signer("us-east-1,eu-west-1");
        let host = raw_host();

        // 1. Header-signed PutObject (exact SHA-256 of "hello world").
        let body = b"hello world";
        let payload = PayloadMode::parse("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", TrailerSet::None)
            .expect("sha256");
        let mut h = HeaderMap::new();
        h.insert(http::header::CONTENT_LENGTH, HeaderValue::from_str(&body.len().to_string()).expect("len"));
        let req = SigningRequest::new(&Method::PUT, "/bucket/header.txt", "", &h, &host, payload, stamp())
            .with_wire_content_length(body.len() as u64);
        let signed = signer.sign_headers(&req).expect("signs");
        let resp = call_service(&service, Method::PUT, "/bucket/header.txt", signed.headers(), body.to_vec()).await;
        assert_eq!(resp.status(), StatusCode::OK, "profile={rustfs_profile} body={:?}", resp.body());

        // 2. Presigned GetObject.
        let empty = HeaderMap::new();
        let pre_req = SigningRequest::new(&Method::GET, "/bucket/header.txt", "", &empty, &host, PayloadMode::Unsigned, stamp());
        let presigned = signer.presign(&pre_req, 300).expect("presigns");
        let uri = format!("/bucket/header.txt?{}", presigned.query());
        let resp = call_service(&service, Method::GET, &uri, presigned.headers(), Vec::new()).await;
        assert_eq!(resp.status(), StatusCode::OK, "profile={rustfs_profile} body={:?}", resp.body());

        // 3. Streaming SigV4a CRT-padded PutObject.
        let s_body = b"stream-ecdsa-payload";
        let s_payload = PayloadMode::parse(STREAMING_ECDSA, TrailerSet::None).expect("valid");
        let mut sh = HeaderMap::new();
        sh.insert(http::header::CONTENT_ENCODING, HeaderValue::from_static("aws-chunked"));
        let s_req = SigningRequest::new(&Method::PUT, "/bucket/stream.bin", "", &sh, &host, s_payload, stamp())
            .with_decoded_content_length(s_body.len() as u64);
        let s_signed = signer.sign_headers(&s_req).expect("signs");
        let mut chunker = signer.chunk_signer(s_signed.signature_hex(), stamp());
        let mut wire = chunker.encode_chunk_padded(s_body);
        wire.extend_from_slice(&chunker.encode_chunk_padded(b""));
        let mut send_headers = s_signed.headers().clone();
        send_headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_str(&wire.len().to_string()).expect("len"));
        let resp = call_service(&service, Method::PUT, "/bucket/stream.bin", &send_headers, wire).await;
        assert_eq!(resp.status(), StatusCode::OK, "profile={rustfs_profile} body={:?}", resp.body());

        // 4. Streaming SigV4a with signed CRC32 trailer ("hello world" -> CRC32 "DUoRhQ==").
        let t_body = b"hello world";
        let declared = DeclaredTrailers::new([TrailerName::new("x-amz-checksum-crc32").expect("ok")], true).expect("valid");
        let t_payload = PayloadMode::parse(STREAMING_ECDSA_TRAILER, TrailerSet::Declared(declared)).expect("valid");
        let t_req = SigningRequest::new(&Method::PUT, "/bucket/trailer.bin", "", &sh, &host, t_payload, stamp())
            .with_decoded_content_length(t_body.len() as u64);
        let t_signed = signer.sign_headers(&t_req).expect("signs");
        let mut t_chunker = signer.chunk_signer(t_signed.signature_hex(), stamp());
        let mut t_wire = t_chunker.encode_chunk_padded(t_body);
        let term_sig = t_chunker.sign_chunk_padded(b"");
        t_wire.extend_from_slice(format!("0;chunk-signature={term_sig}\r\n").as_bytes());
        let trailer_sig = t_chunker.sign_trailer_padded("x-amz-checksum-crc32:DUoRhQ==\n");
        t_wire.extend_from_slice(b"x-amz-checksum-crc32:DUoRhQ==\r\n");
        t_wire.extend_from_slice(format!("x-amz-trailer-signature:{trailer_sig}\r\n\r\n").as_bytes());
        let mut t_headers = t_signed.headers().clone();
        t_headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&t_wire.len().to_string()).expect("len"),
        );
        let resp = call_service(&service, Method::PUT, "/bucket/trailer.bin", &t_headers, t_wire).await;
        assert_eq!(resp.status(), StatusCode::OK, "profile={rustfs_profile} body={:?}", resp.body());

        let stored = recorded.lock().expect("lock").clone();
        assert_eq!(stored, vec![body.to_vec(), s_body.to_vec(), t_body.to_vec()]);
    }
}

/// Regression: an AccessKeyId containing `Signature=` must not hijack or break streaming SigV4a
/// chunk seeding because the verified head DER bytes are published directly into `ChunkSink`.
#[tokio::test]
async fn s3_service_sigv4a_streaming_with_signature_equals_in_access_key_id() {
    let (service, recorded) = sigv4a_service(false);
    let akid = "AKIDSignature=deadbeef";
    let signer =
        SigV4aSigner::new(SigningCredentials::new(akid, SECRET).expect("valid"), day(), SigService::S3, "*").expect("ok");
    let host = raw_host();
    let body = b"seed-isolated";
    let payload = PayloadMode::parse(STREAMING_ECDSA, TrailerSet::None).expect("valid");
    let mut h = HeaderMap::new();
    h.insert(http::header::CONTENT_ENCODING, HeaderValue::from_static("aws-chunked"));
    let req = SigningRequest::new(&Method::PUT, "/bucket/seed.bin", "", &h, &host, payload, stamp())
        .with_decoded_content_length(body.len() as u64);
    let signed = signer.sign_headers(&req).expect("signs");
    let mut chunker = signer.chunk_signer(signed.signature_hex(), stamp());
    let mut wire = chunker.encode_chunk(body);
    wire.extend_from_slice(&chunker.encode_chunk(b""));
    let mut send_headers = signed.headers().clone();
    send_headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_str(&wire.len().to_string()).expect("len"));
    let resp = call_service(&service, Method::PUT, "/bucket/seed.bin", &send_headers, wire).await;
    assert_eq!(resp.status(), StatusCode::OK, "body={:?}", resp.body());
    assert_eq!(recorded.lock().expect("lock").as_slice(), &[body.to_vec()]);
}

/// Negative: tampered SigV4a streaming chunk returns 403 and invokes the handler zero times; under
/// `rustfs_profile()`, an unsigned `x-amz-*` header on a 4-field SigV4a request is refused by the
/// pre-routing header guard.
#[tokio::test]
async fn n_s3_service_sigv4a_tampered_chunk_and_rustfs_profile_unsigned_header_refused() {
    let (service, recorded) = sigv4a_service(false);
    let signer = v4a_signer("*");
    let host = raw_host();
    let payload = PayloadMode::parse(STREAMING_ECDSA, TrailerSet::None).expect("valid");
    let mut h = HeaderMap::new();
    h.insert(http::header::CONTENT_ENCODING, HeaderValue::from_static("aws-chunked"));
    let req =
        SigningRequest::new(&Method::PUT, "/bucket/bad.bin", "", &h, &host, payload, stamp()).with_decoded_content_length(5);
    let signed = signer.sign_headers(&req).expect("signs");
    let mut chunker = signer.chunk_signer(signed.signature_hex(), stamp());
    let mut wire = chunker.encode_chunk(b"hello");
    wire.extend_from_slice(&chunker.encode_chunk(b""));
    let pos = wire.windows(5).position(|w| w == b"hello").expect("payload");
    *wire.get_mut(pos).expect("byte") = b'X';
    let mut send_headers = signed.headers().clone();
    send_headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_str(&wire.len().to_string()).expect("len"));
    let resp = call_service(&service, Method::PUT, "/bucket/bad.bin", &send_headers, wire).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(recorded.lock().expect("lock").is_empty(), "tampered chunk must deliver zero bytes");

    let (profile_service, _) = sigv4a_service(true);
    let empty = HeaderMap::new();
    let get_req = SigningRequest::new(&Method::GET, "/bucket/obj", "", &empty, &host, PayloadMode::Empty, stamp());
    let get_signed = signer.sign_headers(&get_req).expect("signs");
    let mut forged = get_signed.headers().clone();
    forged.insert(HeaderName::from_static("x-amz-copy-source"), HeaderValue::from_static("/secret/key"));
    let resp = call_service(&profile_service, Method::GET, "/bucket/obj", &forged, Vec::new()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let text = std::str::from_utf8(resp.body()).expect("xml");
    assert!(text.contains("There were headers present in the request which were not signed"), "{text}");
}
