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
//! Responsible for: both directions of the switch on a header-signed `GetObject` — with it, a list
//! in uppercase verified when the string to sign spells it so, a name the request did not send
//! named, and an unsigned `x-amz-*` header `AccessDenied`; without it, the gateway's own answers.
//! NOT responsible for: presigned URLs and the storage outcome, which `compat/sut`'s
//! `signed_header_reading_tests.rs` drives through the RustFS-profile assembly.
//! Upstream: `support`. Downstream: nothing.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::{
    ClockSkewAck, Credentials, Handler, HandlerResult, RegionSet, Req, Resp, S3Service, ServiceBuilder, SigV4Authenticator,
    StaticCredentials, allow_when, dto,
};
use sha2::{Digest as _, Sha256};

use crate::support;

struct Backend(Arc<Mutex<u32>>);

impl Handler<dto::GetObject> for Backend {
    fn call(&self, _request: Req<dto::GetObject>) -> impl core::future::Future<Output = HandlerResult<dto::GetObject>> + Send {
        let calls = Arc::clone(&self.0);
        async move {
            *calls.lock().expect("the record is never poisoned") += 1;
            Ok(Resp::new(dto::GetObjectOutput::default()))
        }
    }
}

fn service(legacy: bool) -> (S3Service, Arc<Mutex<u32>>) {
    let calls = Arc::new(Mutex::new(0));
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
        .register::<dto::GetObject, _>(Arc::new(Backend(Arc::clone(&calls))))
        .build()
        .expect("a complete GetObject assembly");
    (service, calls)
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
    let stamp = support::SIGNED_AT_STAMP;
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let canonical = format!("GET\n/bucket/key\n\n{canonical_headers}\n{signed_line}\n{PAYLOAD}");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac_sha256(b"AWS4secret", day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    let mut request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/bucket/key")
        .header(http::header::HOST, "s3.example.com")
        .header("x-amz-content-sha256", PAYLOAD)
        .header("x-amz-date", stamp);
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    request
        .header(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope}, SignedHeaders={list}, Signature={signature}"),
        )
        .body(Bytes::new())
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
    let reached = *calls.lock().expect("the record is never poisoned");
    (status, body, reached)
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
