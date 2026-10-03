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

//! `SigV4Authenticator::answer_credential_scope_refusals_as_legacy_rustfs`, through an assembled
//! service: legacy RustFS's answers to a scope date other than the signed day and to a region
//! outside its grammar (rustfs/gateway#1130).
//!
//! Responsible for: both directions of the switch on a header-signed and a presigned `GetObject` —
//! with it, legacy RustFS's code and sentence, the refusal still made where it was made (a region
//! the parsers cannot read before any key is derived, one they read after the signature); without
//! it, the gateway's own answers, as before.
//! NOT responsible for: the browser `POST` surface and the storage outcome, which `compat/sut`'s
//! `scope_refusal_tests.rs` drives through the RustFS-profile assembly.
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

/// The region switches `compat/sut` turns on, with the legacy scope refusals when `legacy`.
fn service(legacy: bool) -> (S3Service, Arc<Mutex<u32>>) {
    let calls = Arc::new(Mutex::new(0));
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
    let mut authenticator = SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty"))
        .accept_any_signing_region()
        .accept_empty_signing_region()
        .refuse_unreadable_signing_regions_after_verification()
        .accept_signing_regions_of_any_length();
    if legacy {
        authenticator = authenticator.answer_credential_scope_refusals_as_legacy_rustfs();
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

/// RFC 3986 percent-encoding of everything but the unreserved characters.
fn encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => char::from(byte).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// The signature over `string_to_sign` with `secret`, for a scope of `day` and `region`.
fn sign(secret: &str, day: &str, region: &str, string_to_sign: &str) -> String {
    let mut key = hmac_sha256(format!("AWS4{secret}").as_bytes(), day.as_bytes());
    for part in [region, "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    hex(&hmac_sha256(&key, string_to_sign.as_bytes()))
}

/// How a case bends the scope: the day it names and the region, and the secret it signs with.
struct Scope {
    day: &'static str,
    region: &'static str,
    secret: &'static str,
}

impl Scope {
    fn region(region: &'static str) -> Self {
        Self {
            day: &support::SIGNED_AT_STAMP[..8],
            region,
            secret: "secret",
        }
    }

    fn dated(day: &'static str) -> Self {
        Self {
            day,
            ..Self::region("us-east-1")
        }
    }

    fn forged(self) -> Self {
        Self {
            secret: "not-the-secret",
            ..self
        }
    }

    /// A header-signed `GET /bucket/key`, by an independent signer.
    fn header(&self) -> http::Request<Bytes> {
        let stamp = support::SIGNED_AT_STAMP;
        let scope = format!("{}/{}/s3/aws4_request", self.day, self.region);
        let payload = "UNSIGNED-PAYLOAD";
        let canonical = format!(
            "GET\n/bucket/key\n\nhost:s3.example.com\nx-amz-content-sha256:{payload}\nx-amz-date:{stamp}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload}"
        );
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
        let signature = sign(self.secret, self.day, self.region, &string_to_sign);
        http::Request::builder()
            .method(http::Method::GET)
            .uri("/bucket/key")
            .header(http::header::HOST, "s3.example.com")
            .header("x-amz-content-sha256", payload)
            .header("x-amz-date", stamp)
            .header(
                http::header::AUTHORIZATION,
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"
                ),
            )
            .body(Bytes::new())
            .expect("a valid request")
    }

    /// The same `GET` presigned over `host` for five minutes, by an independent signer.
    fn presigned(&self) -> http::Request<Bytes> {
        let stamp = support::SIGNED_AT_STAMP;
        let credential = format!("AKIDEXAMPLE/{}/{}/s3/aws4_request", self.day, self.region);
        let query = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", credential.as_str()),
            ("X-Amz-Date", stamp),
            ("X-Amz-Expires", "300"),
            ("X-Amz-SignedHeaders", "host"),
        ]
        .iter()
        .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
        .collect::<Vec<_>>()
        .join("&");
        let canonical = format!("GET\n/bucket/key\n{query}\nhost:s3.example.com\n\nhost\nUNSIGNED-PAYLOAD");
        let scope = format!("{}/{}/s3/aws4_request", self.day, self.region);
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
        let signature = sign(self.secret, self.day, self.region, &string_to_sign);
        http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("/bucket/key?{query}&X-Amz-Signature={signature}"))
            .header(http::header::HOST, "s3.example.com")
            .body(Bytes::new())
            .expect("a valid request")
    }
}

/// Legacy RustFS's sentence for `region`, as the error document carries it.
fn region_sentence(region: &str) -> String {
    format!("<Message>invalid credential region: invalid region: {region:?}</Message>").replace('"', "&quot;")
}

async fn answer(legacy: bool, request: http::Request<Bytes>) -> (http::StatusCode, String, u32) {
    let (service, calls) = service(legacy);
    let (status, body) = support::exchange(&service, request).await;
    let reached = *calls.lock().expect("the record is never poisoned");
    (status, body, reached)
}

/// Positive — the controls: a scope dated the signed day, in the configured region or another of
/// the grammar, reaches the handler with the switch on, header-signed and presigned.
#[tokio::test]
async fn a_scope_legacy_rustfs_reads_reaches_the_handler() {
    for region in ["us-east-1", "rustfs-local-2"] {
        for request in [Scope::region(region).header(), Scope::region(region).presigned()] {
            let (status, body, reached) = answer(true, request).await;
            assert_eq!((status, reached), (http::StatusCode::OK, 1), "{region}: {body}");
        }
    }
}

/// Negative — under the switch a scope dated other than the signed day is `403
/// SignatureDoesNotMatch` with legacy RustFS's sentence, header-signed and presigned.
#[tokio::test]
async fn n_a_scope_date_other_than_the_signed_day_is_answered_with_the_legacy_sentence() {
    for request in [Scope::dated("20200101").header(), Scope::dated("20200101").presigned()] {
        let (status, body, reached) = answer(true, request).await;
        assert_eq!((status, reached), (http::StatusCode::FORBIDDEN, 0), "{body}");
        assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
        assert!(
            body.contains("<Message>credential scope date does not match x-amz-date</Message>"),
            "{body}"
        );
    }
}

/// Negative — under the switch a region outside legacy RustFS's grammar is `400 InvalidRequest`
/// naming it: one the parsers cannot read (a space, a tab, a non-ASCII letter, a comma in the
/// header) before any key is derived, so a wrong secret gets the same answer; one they read (an
/// uppercase letter, a comma in a query) after the signature, so a wrong secret is `403
/// SignatureDoesNotMatch` first.
#[tokio::test]
async fn n_a_region_outside_the_legacy_grammar_is_answered_with_the_legacy_sentence() {
    for region in ["us east", "us\teast", "us-\u{e9}ast", "us,east", "US-EAST-1"] {
        let mut requests = vec![Scope::region(region).header(), Scope::region(region).presigned()];
        if region != "US-EAST-1" {
            requests.push(Scope::region(region).forged().header());
        }
        for request in requests {
            let (status, body, reached) = answer(true, request).await;
            assert_eq!((status, reached), (http::StatusCode::BAD_REQUEST, 0), "{region}: {body}");
            assert!(body.contains("<Code>InvalidRequest</Code>"), "{region}: {body}");
            assert!(body.contains(&region_sentence(region)), "{region}: {body}");
        }
    }
    for request in [
        Scope::region("US-EAST-1").forged().header(),
        Scope::region("US-EAST-1").forged().presigned(),
        Scope::region("us,east").forged().presigned(),
    ] {
        let (status, body, reached) = answer(true, request).await;
        assert_eq!((status, reached), (http::StatusCode::FORBIDDEN, 0), "{body}");
        assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    }
}

/// Negative — without the switch the gateway's own answers stand: a scope date the scope check
/// refuses is `400 AuthorizationHeaderMalformed`, a region the parsers cannot read `403
/// InvalidAccessKeyId`, and one refused after the signature `400 InvalidRequest` with the gateway's
/// sentence.
#[tokio::test]
async fn n_the_default_keeps_the_gateway_answers() {
    for (request, expected, code) in [
        (
            Scope::dated("20200101").presigned(),
            http::StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
        ),
        (Scope::region("us east").header(), http::StatusCode::FORBIDDEN, "InvalidAccessKeyId"),
        (Scope::region("us\teast").presigned(), http::StatusCode::FORBIDDEN, "InvalidAccessKeyId"),
        (Scope::region("US-EAST-1").header(), http::StatusCode::BAD_REQUEST, "InvalidRequest"),
    ] {
        let (status, body, reached) = answer(false, request).await;
        assert_eq!((status, reached), (expected, 0), "{body}");
        assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
        assert!(!body.contains("invalid credential region"), "{body}");
        assert!(!body.contains("credential scope date does not match"), "{body}");
    }
}
