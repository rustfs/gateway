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

//! `SigV4Authenticator::read_signed_headers_as_legacy_rustfs`, through an assembled service:
//! `SignedHeaders` read, and its refusals answered, as legacy RustFS reads and answers them
//! (rustfs/gateway#1130).
//!
//! Responsible for: both signed-header readings, header-auth payload coverage, stored bytes and
//! independent signature controls for the Host, semantic-header and presigned-query boundaries.
//! NOT responsible for: the complete RustFS assembly or live AWS capture.
//! Upstream: `support` and the authenticator. Downstream: the integration verification gate.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    ClockSkewAck, Credentials, Handler, HandlerError, HandlerResult, RegionSet, Req, Resp, S3Service, ServiceBuilder,
    SigV4Authenticator, StaticCredentials, allow_when, dto,
};
use sha2::{Digest as _, Sha256};

use crate::support;

#[derive(Default)]
struct Backend {
    calls: Mutex<u32>,
    stored: Mutex<Vec<Bytes>>,
}

impl Handler<dto::GetObject> for Backend {
    async fn call(&self, _request: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        *self.calls.lock().expect("the record is never poisoned") += 1;
        Ok(Resp::new(dto::GetObjectOutput::default()))
    }
}

impl Handler<dto::PutObject> for Backend {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        *self.calls.lock().expect("the record is never poisoned") += 1;
        let body = request
            .into_input()
            .body
            .ok_or_else(|| HandlerError::internal_error("missing body"))?;
        let bytes = body
            .into_body()
            .collect()
            .await
            .map_err(|_| HandlerError::internal_error("body failed"))?
            .to_bytes();
        self.stored.lock().expect("the record is never poisoned").push(bytes);
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

fn service(legacy: bool) -> (S3Service, Arc<Backend>) {
    let backend = Arc::new(Backend::default());
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
    let mut authenticator = SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty"));
    if legacy {
        authenticator = authenticator.read_signed_headers_as_legacy_rustfs();
    }
    let service = ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(allow_when(|_| true))
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::GetObject, _>(Arc::clone(&backend))
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .build()
        .expect("a complete assembly");
    (service, backend)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(data);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// A `GET /bucket/key` presenting `list` as its `SignedHeaders` and signing `canonical_headers`
/// and `signed_line` in its string to sign, with `extra` headers sent beside the three it always
/// sends.
fn get(list: &str, canonical_headers: &str, signed_line: &str, extra: &[(&str, &str)]) -> http::Request<Bytes> {
    request("GET", list, canonical_headers, signed_line, PAYLOAD, Bytes::new(), extra)
}

fn request(
    method: &str,
    list: &str,
    canonical_headers: &str,
    signed_line: &str,
    payload: &str,
    body: Bytes,
    extra: &[(&str, &str)],
) -> http::Request<Bytes> {
    let stamp = support::SIGNED_AT_STAMP;
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let canonical = format!("{method}\n/bucket/key\n\n{canonical_headers}\n{signed_line}\n{payload}");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac_sha256(b"AWS4secret", day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    let mut request = http::Request::builder()
        .method(method)
        .uri("/bucket/key")
        .header(http::header::HOST, "s3.example.com")
        .header("x-amz-content-sha256", payload)
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .header("x-amz-date", stamp);
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    request
        .header(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope}, SignedHeaders={list}, Signature={signature}"),
        )
        .body(body)
        .expect("a valid request")
}

/// The canonical headers of the three headers every request here sends, in `names`' spelling.
fn three(names: [&str; 3]) -> String {
    let stamp = support::SIGNED_AT_STAMP;
    format!("{}:s3.example.com\n{}:{PAYLOAD}\n{}:{stamp}\n", names[0], names[1], names[2])
}

const AWS: [&str; 3] = ["host", "x-amz-content-sha256", "x-amz-date"];
const UPPER: [&str; 3] = ["HOST", "X-AMZ-CONTENT-SHA256", "X-AMZ-DATE"];

async fn answer(legacy: bool, request: http::Request<Bytes>) -> (http::StatusCode, String, u32) {
    let (service, calls) = service(legacy);
    let (status, body) = support::exchange(&service, request).await;
    let reached = *calls.calls.lock().expect("the record is never poisoned");
    (status, body, reached)
}

/// AWS permits the payload declaration outside SignedHeaders: HashedPayload covers it already.
#[tokio::test]
async fn a_payload_declaration_is_covered_by_the_payload_line_under_both_readings() {
    let empty = hex(&Sha256::digest([]));
    for legacy in [false, true] {
        for payload in [PAYLOAD, empty.as_str()] {
            let list = "host;x-amz-date";
            let headers = format!("host:s3.example.com\nx-amz-date:{}\n", support::SIGNED_AT_STAMP);
            let request = request("GET", list, &headers, list, payload, Bytes::new(), &[]);
            let (status, body, reached) = answer(legacy, request).await;
            assert_eq!((status, reached), (http::StatusCode::OK, 1), "{legacy}: {body}");
        }
    }
    let list = "HOST;X-AMZ-DATE";
    let headers = format!("HOST:s3.example.com\nX-AMZ-DATE:{}\n", support::SIGNED_AT_STAMP);
    let (status, body, reached) = answer(true, get(list, &headers, list, &[])).await;
    assert_eq!((status, reached), (http::StatusCode::OK, 1), "{body}");
}

/// Negative — changing the unlisted digest or mode changes HashedPayload and must invalidate HMAC.
#[tokio::test]
async fn n_changing_an_unlisted_payload_declaration_breaks_the_signature() {
    let empty = hex(&Sha256::digest([]));
    let headers = format!("host:s3.example.com\nx-amz-date:{}\n", support::SIGNED_AT_STAMP);
    for legacy in [false, true] {
        for (signed, sent) in [(PAYLOAD, empty.as_str()), (empty.as_str(), PAYLOAD)] {
            let list = "host;x-amz-date";
            let mut request = request("GET", list, &headers, list, signed, Bytes::new(), &[]);
            request
                .headers_mut()
                .insert("x-amz-content-sha256", sent.parse().expect("a declaration"));
            let (status, body, reached) = answer(legacy, request).await;
            assert_eq!((status, reached), (http::StatusCode::FORBIDDEN, 0), "{body}");
            assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
        }
    }
}

/// Negative — the payload line covers no metadata, copy instruction or object-lock header.
#[tokio::test]
async fn n_payload_line_coverage_does_not_cover_other_amz_headers() {
    let list = "host;x-amz-date";
    let headers = format!("host:s3.example.com\nx-amz-date:{}\n", support::SIGNED_AT_STAMP);
    for legacy in [false, true] {
        for (name, value) in [
            ("x-amz-meta-note", "unsigned"),
            ("x-amz-copy-source", "/other/key"),
            ("x-amz-object-lock-mode", "GOVERNANCE"),
        ] {
            let (status, body, reached) = answer(legacy, get(list, &headers, list, &[(name, value)])).await;
            assert_eq!((status, reached), (http::StatusCode::FORBIDDEN, 0), "{name}: {body}");
        }
    }
}

/// Negative — the HashedPayload exception cannot exempt the request's destination.
#[tokio::test]
async fn n_payload_line_coverage_still_requires_host() {
    let list = "x-amz-date";
    let headers = format!("x-amz-date:{}\n", support::SIGNED_AT_STAMP);
    for legacy in [false, true] {
        let (status, body, reached) = answer(legacy, get(list, &headers, list, &[])).await;
        assert_eq!((status, reached), (http::StatusCode::FORBIDDEN, 0), "{body}");
    }
}

/// A valid header signature over the body digest stores the exact bytes without signing it twice.
#[tokio::test]
async fn a_put_with_its_digest_outside_signed_headers_stores_the_body() {
    let list = "host;x-amz-date";
    let headers = format!("host:s3.example.com\nx-amz-date:{}\n", support::SIGNED_AT_STAMP);
    let bytes = Bytes::from_static(b"body covered once");
    let digest = hex(&Sha256::digest(&bytes));
    for legacy in [false, true] {
        let (service, backend) = service(legacy);
        let request = request("PUT", list, &headers, list, &digest, bytes.clone(), &[]);
        let (status, body) = support::exchange(&service, request).await;
        assert_eq!(status, http::StatusCode::OK, "{body}");
        assert_eq!(*backend.calls.lock().expect("record"), 1);
        assert_eq!(*backend.stored.lock().expect("record"), vec![bytes.clone()]);
    }
}

/// Negative — the body verifier must refuse different bytes before the backend commits them.
#[tokio::test]
async fn n_a_put_with_different_bytes_does_not_commit() {
    let list = "host;x-amz-date";
    let headers = format!("host:s3.example.com\nx-amz-date:{}\n", support::SIGNED_AT_STAMP);
    let digest = hex(&Sha256::digest(b"signed body"));
    for legacy in [false, true] {
        let (service, backend) = service(legacy);
        let request = request("PUT", list, &headers, list, &digest, Bytes::from_static(b"wrong body"), &[]);
        let (status, body) = support::exchange(&service, request).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(*backend.calls.lock().expect("record"), 1, "payload verification was not exercised");
        assert!(backend.stored.lock().expect("record").is_empty());
    }
}

/// Negative — query authentication has no header-auth payload exception. A real valid query is
/// the control, so this cannot pass merely because the test built an invalid presigned URL.
#[tokio::test]
async fn n_a_presigned_request_still_cannot_add_an_unlisted_payload_header() {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, "s3.example.com".parse().expect("host"));
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("host");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("timestamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("scope");
    let signing = SigningRequest::new(&http::Method::GET, "/bucket/key", "", &headers, &host, PayloadMode::Unsigned, stamp);
    let mut signer = SigV4Signer::new(SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("credentials"), scope);
    let signed = signer.presign(&signing, 900).expect("signable request");
    for legacy in [false, true] {
        for add_payload in [false, true] {
            let mut request = http::Request::builder()
                .method("GET")
                .uri(format!("/bucket/key?{}", signed.query()));
            for (name, value) in signed.headers() {
                request = request.header(name, value);
            }
            if add_payload {
                request = request.header("x-amz-content-sha256", PAYLOAD);
            }
            let (status, body, reached) = answer(legacy, request.body(Bytes::new()).expect("request")).await;
            let expected = if add_payload {
                (http::StatusCode::FORBIDDEN, 0)
            } else {
                (http::StatusCode::OK, 1)
            };
            assert_eq!((status, reached), expected, "{legacy}, {add_payload}: {body}");
        }
    }
}

/// Positive — under the switch a list in uppercase is verified when the string to sign spells it
/// so, and a list AWS emits is verified as always.
#[tokio::test]
async fn a_list_signed_as_legacy_rustfs_spells_it_reaches_the_handler() {
    let upper = UPPER.join(";");
    let aws = AWS.join(";");
    for request in [get(&upper, &three(UPPER), &upper, &[]), get(&aws, &three(AWS), &aws, &[])] {
        let (status, body, reached) = answer(true, request).await;
        assert_eq!((status, reached), (http::StatusCode::OK, 1), "{body}");
    }
}

/// Negative — under the switch a list in uppercase signed in AWS's spelling is
/// `SignatureDoesNotMatch`; a name the request did not send is named; an unsigned `x-amz-*`
/// header is `AccessDenied` with legacy RustFS's sentence.
#[tokio::test]
async fn n_the_switch_answers_as_legacy_rustfs_answers() {
    let upper = UPPER.join(";");
    let aws = AWS.join(";");
    let cases = [
        (
            get(&upper, &three(AWS), &aws, &[]),
            http::StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            None,
        ),
        (
            get(&format!("{aws};x-amz-meta-gone"), &three(AWS), &aws, &[]),
            http::StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            Some("missing signed header: x-amz-meta-gone"),
        ),
        (
            get(&aws, &three(AWS), &aws, &[("x-amz-meta-note", "unsigned")]),
            http::StatusCode::FORBIDDEN,
            "AccessDenied",
            Some("There were headers present in the request which were not signed"),
        ),
    ];
    for (request, expected, code, sentence) in cases {
        let (status, body, reached) = answer(true, request).await;
        assert_eq!((status, reached), (expected, 0), "{body}");
        assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
        if let Some(sentence) = sentence {
            assert!(body.contains(&format!("<Message>{sentence}</Message>")), "{body}");
        }
    }
}

/// Negative — without the switch the gateway's answers stand: a list in uppercase is `400
/// AuthorizationHeaderMalformed` however it was signed, and a missing or unsigned header is `403
/// SignatureDoesNotMatch` naming nothing.
#[tokio::test]
async fn n_the_default_keeps_the_gateway_answers() {
    let upper = UPPER.join(";");
    let aws = AWS.join(";");
    let cases = [
        (
            get(&upper, &three(UPPER), &upper, &[]),
            http::StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
        ),
        (
            get(&format!("{aws};x-amz-meta-gone"), &three(AWS), &aws, &[]),
            http::StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
        ),
        (
            get(&aws, &three(AWS), &aws, &[("x-amz-meta-note", "unsigned")]),
            http::StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
        ),
    ];
    for (request, expected, code) in cases {
        let (status, body, reached) = answer(false, request).await;
        assert_eq!((status, reached), (expected, 0), "{body}");
        assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
        assert!(!body.contains("missing signed header"), "{body}");
        assert!(!body.contains("were not signed"), "{body}");
    }
}
