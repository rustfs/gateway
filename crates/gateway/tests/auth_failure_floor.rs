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

//! T6 `FailureFloor` enforcement across every `Refused::Authentication` exit path (rustfs/gateway#1628).
//!
//! Responsible for: proving that every authentication failure path — floor admission rejections,
//! early authenticator scope/parse exits, signature mismatches, unknown keys, unavailable store
//! faults, RustFS-profile pre-lookup header/presigned/header-guard refusals, unrouted POST form
//! authentication refusals, and streaming chunk signature mismatches — holds the framework
//! `FailureFloor` before answering.
//! NOT responsible for: authorization denial floor (`authz_contract.rs`) or CORS preflight floor
//! (`cors_runtime.rs`).
//! Upstream: `rustfs_gateway::S3Service`. Downstream: Cargo integration test harness.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, RegionSet, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
};
use rustfs_gateway::{
    ClockSkewAck, CredentialLookup, CredentialProvider, Credentials, Handler, HandlerResult, ProviderError, Req, Resp, S3Service,
    ServiceBuilder, SigV4Authenticator, StaticCredentials, dto,
};

use crate::support::{Backend, Ping, SIGNED_AT_STAMP, fixed_clock, ping_dialect};

const FLOOR_MIN: Duration = Duration::from_millis(25);

struct FailingProvider;

impl CredentialProvider for FailingProvider {
    fn lookup<'a>(&'a self, _access_key_id: &'a str) -> rustfs_gateway::BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        Box::pin(async { Err(ProviderError::Unavailable) })
    }
}

struct NoopGetObject;

impl Handler<dto::GetObject> for NoopGetObject {
    async fn call(&self, _request: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        Ok(Resp::new(dto::GetObjectOutput::default()))
    }
}

struct DrainPutObject;

impl Handler<dto::PutObject> for DrainPutObject {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        let mut body = request.into_input().body.expect("PutObject body").into_body();
        while http_body_util::BodyExt::frame(&mut body)
            .await
            .transpose()
            .is_ok_and(|f| f.is_some())
        {}
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

fn default_service() -> S3Service {
    crate::support::wired_at_signed_time()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&ping_dialect())
        .register::<dto::PutObject, _>(Arc::new(DrainPutObject))
        .build()
        .expect("default test service")
}

fn unavailable_service() -> S3Service {
    let authenticator = Arc::new(
        SigV4Authenticator::new(Arc::new(FailingProvider), RegionSet::new(["us-east-1"]).expect("region"))
            .answer_credential_store_faults_as_unavailable(),
    );
    ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(rustfs_gateway::allow_when(|_| true))
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&ping_dialect())
        .build()
        .expect("unavailable test service")
}

fn rustfs_profile_service() -> S3Service {
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials")));
    let authenticator =
        Arc::new(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("region")).rustfs_profile());
    ServiceBuilder::new()
        .rustfs_profile()
        .authenticator(authenticator)
        .authorizer(rustfs_gateway::allow_when(|_| true))
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .register::<dto::PutObject, _>(Arc::new(DrainPutObject))
        .register::<dto::GetObject, _>(Arc::new(NoopGetObject))
        .build()
        .expect("rustfs-profile test service")
}

async fn assert_obeys_floor(label: &str, service: &S3Service, request: Request<Bytes>, expected_status: StatusCode) {
    let started = Instant::now();
    let response = service.call_bytes(request).await;
    let elapsed = started.elapsed();
    assert_eq!(response.status(), expected_status, "{label}: unexpected status (elapsed={elapsed:?})");
    assert!(
        elapsed >= FLOOR_MIN,
        "{label}: auth failure returned in {elapsed:?}, bypassing the 25ms FailureFloor"
    );
}

/// Negative — every standard authentication failure exit path holds the 25ms `FailureFloor`.
#[tokio::test]
async fn n_all_standard_auth_failure_exit_paths_obey_failure_floor() {
    let service = default_service();
    let date = &SIGNED_AT_STAMP[..8];

    // 1. Floor admission rejection (malformed Authorization scheme / conflicting headers).
    let floor_reject = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(header::HOST, "s3.example.com")
        .header(header::AUTHORIZATION, "AWS4-HMAC-SHA256")
        .header("x-amz-date", SIGNED_AT_STAMP)
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .body(Bytes::new())
        .expect("floor reject fixture");
    assert_obeys_floor("floor.admit reject", &service, floor_reject, StatusCode::FORBIDDEN).await;

    // 2. Early authenticator scope rejection (wrong region -> 400 AuthorizationHeaderMalformed).
    let wrong_region = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(header::HOST, "s3.example.com")
        .header(
            header::AUTHORIZATION,
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{date}/eu-west-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
                 Signature=0000000000000000000000000000000000000000000000000000000000000000"
            ),
        )
        .header("x-amz-date", SIGNED_AT_STAMP)
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .body(Bytes::new())
        .expect("wrong region fixture");
    assert_obeys_floor("authenticator wrong region", &service, wrong_region, StatusCode::BAD_REQUEST).await;

    // 3. Wrong signature (SignatureDoesNotMatch).
    let wrong_sig = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(header::HOST, "s3.example.com")
        .header(
            header::AUTHORIZATION,
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{date}/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
                 Signature=0000000000000000000000000000000000000000000000000000000000000000"
            ),
        )
        .header("x-amz-date", SIGNED_AT_STAMP)
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .body(Bytes::new())
        .expect("wrong sig fixture");
    assert_obeys_floor("wrong signature", &service, wrong_sig, StatusCode::FORBIDDEN).await;

    // 4. Unknown access key (InvalidAccessKeyId).
    let unknown_key = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(header::HOST, "s3.example.com")
        .header(
            header::AUTHORIZATION,
            format!(
                "AWS4-HMAC-SHA256 Credential=NO_SUCH_KEY/{date}/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
                 Signature=0000000000000000000000000000000000000000000000000000000000000000"
            ),
        )
        .header("x-amz-date", SIGNED_AT_STAMP)
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .body(Bytes::new())
        .expect("unknown key fixture");
    assert_obeys_floor("unknown key", &service, unknown_key, StatusCode::FORBIDDEN).await;

    // 5. Credential-store unavailable fault (500 under opt-in switch).
    let unavailable = unavailable_service();
    let store_fault = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(header::HOST, "s3.example.com")
        .header(
            header::AUTHORIZATION,
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{date}/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
                 Signature=0000000000000000000000000000000000000000000000000000000000000000"
            ),
        )
        .header("x-amz-date", SIGNED_AT_STAMP)
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .body(Bytes::new())
        .expect("store fault fixture");
    assert_obeys_floor("authenticator unavailable", &unavailable, store_fault, StatusCode::INTERNAL_SERVER_ERROR).await;

    // 6. Streaming chunk signature mismatch (Refused::Authentication on body stage).
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(SIGNED_AT_STAMP).expect("valid stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("valid scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let probe = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header(header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("probe");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("accepted");
    let payload = b"hello";
    let wire_len = payload.len() + (format!("{:x}", payload.len()).len() + 17 + 64 + 4) + 1 + 17 + 64 + 4;
    let mut map = HeaderMap::new();
    map.insert(header::HOST, HeaderValue::from_static("s3.example.com"));
    map.insert(header::CONTENT_LENGTH, HeaderValue::from_str(&wire_len.to_string()).expect("len"));
    let signing = SigningRequest::new(
        &Method::PUT,
        "/bucket/key",
        "",
        &map,
        accepted.host().raw_for_signing(),
        PayloadMode::StreamingSigned {
            trailer: TrailerSet::None,
        },
        stamp,
    )
    .with_wire_content_length(wire_len as u64)
    .with_decoded_content_length(payload.len() as u64);
    let signed = signer.sign_headers(&signing).expect("signed");
    let mut chain = signer.chunk_signer(&signed).expect("chain");
    let mut wire = chain.encode_chunk(payload);
    wire.extend_from_slice(&chain.encode_chunk(b""));
    if let Some(pos) = wire.windows(16).position(|w| w == b"chunk-signature=") {
        let idx = pos + 16;
        wire[idx] = if wire[idx] == b'0' { b'1' } else { b'0' };
    }
    let mut req_builder = Request::builder().method(Method::PUT).uri("/bucket/key");
    for (name, value) in signed.headers() {
        req_builder = req_builder.header(name, value);
    }
    let bad_chunk_req = req_builder.body(Bytes::from(wire)).expect("bad chunk req");
    assert_obeys_floor("streaming chunk signature mismatch", &service, bad_chunk_req, StatusCode::FORBIDDEN).await;
}

/// Negative — RustFS-profile pre-lookup authentication exit paths (`sigv4_header_guard`,
/// `header_signatures`/`presigned_urls`, and `refused_post`) also hold the 25ms `FailureFloor`.
#[tokio::test]
async fn n_rustfs_profile_pre_lookup_and_refused_post_auth_failures_obey_failure_floor() {
    let service = rustfs_profile_service();
    let date = &SIGNED_AT_STAMP[..8];

    // 1. sigv4_header_guard refusal before routing (unsigned x-amz-* header).
    let header_guard = Request::builder()
        .method(Method::GET)
        .uri("/bucket/key")
        .header(header::HOST, "s3.example.com")
        .header(
            header::AUTHORIZATION,
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{date}/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-date, \
                 Signature=0000000000000000000000000000000000000000000000000000000000000000"
            ),
        )
        .header("x-amz-date", SIGNED_AT_STAMP)
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .body(Bytes::new())
        .expect("header guard fixture");
    assert_obeys_floor("sigv4_header_guard", &service, header_guard, StatusCode::FORBIDDEN).await;

    // 2. header_signatures pre-lookup refusal (malformed x-amz-date on signed request).
    let pre_lookup = Request::builder()
        .method(Method::GET)
        .uri("/bucket/key")
        .header(header::HOST, "s3.example.com")
        .header(
            header::AUTHORIZATION,
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{date}/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
                 Signature=0000000000000000000000000000000000000000000000000000000000000000"
            ),
        )
        .header("x-amz-date", "not-a-date")
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .body(Bytes::new())
        .expect("pre-lookup header signature fixture");
    assert_obeys_floor("header_signatures pre-lookup", &service, pre_lookup, StatusCode::BAD_REQUEST).await;

    // 3. refused_post unrouted object POST form with invalid SigV4 policy metadata.
    let multipart_bad_policy = concat!(
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"x-amz-algorithm\"\r\n\r\n",
        "AWS4-HMAC-SHA256\r\n",
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"x-amz-signature\"\r\n\r\n",
        "0000000000000000000000000000000000000000000000000000000000000000\r\n",
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"policy\"\r\n\r\n",
        "not-base64!!!\r\n",
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\n",
        "hi\r\n",
        "--boundary--\r\n"
    );
    let refused_post_meta = Request::builder()
        .method(Method::POST)
        .uri("/bucket/key")
        .header(header::HOST, "s3.example.com")
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=boundary")
        .header(header::CONTENT_LENGTH, multipart_bad_policy.len().to_string())
        .body(Bytes::from_static(multipart_bad_policy.as_bytes()))
        .expect("refused_post metadata fixture");
    assert_obeys_floor(
        "refused_post invalid policy metadata",
        &service,
        refused_post_meta,
        StatusCode::BAD_REQUEST,
    )
    .await;

    // 4. refused_post unrouted object POST form with SigV2 wrong signature.
    let multipart_bad_sigv2 = concat!(
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"AWSAccessKeyId\"\r\n\r\n",
        "AKIDEXAMPLE\r\n",
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"policy\"\r\n\r\n",
        "e30=\r\n",
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"signature\"\r\n\r\n",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n",
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\n",
        "hi\r\n",
        "--boundary--\r\n"
    );
    let refused_post_sigv2 = Request::builder()
        .method(Method::POST)
        .uri("/bucket/key")
        .header(header::HOST, "s3.example.com")
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=boundary")
        .header(header::CONTENT_LENGTH, multipart_bad_sigv2.len().to_string())
        .body(Bytes::from_static(multipart_bad_sigv2.as_bytes()))
        .expect("refused_post sigv2 fixture");
    assert_obeys_floor("refused_post bad sigv2 signature", &service, refused_post_sigv2, StatusCode::FORBIDDEN).await;
}
