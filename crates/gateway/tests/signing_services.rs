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

//! `SigV4Authenticator::accept_legacy_rustfs_signing_services`, through an assembled service: the
//! credential-scope services legacy RustFS verifies on every operation (rustfs/gateway#1130).
//!
//! Responsible for: both directions of the switch on a header-signed `GetObject` — with it, `s3`,
//! `sts` and `s3tables` are verified and every other service is `501 NotImplemented` with legacy
//! RustFS's sentence; without it, only the routed operation's own service is verified, as before.
//! NOT responsible for: the presigned and POST-form surfaces, which `compat/sut`'s
//! `signing_service_tests.rs` drives through the RustFS-profile assembly.
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

fn service(legacy_services: bool) -> (S3Service, Arc<Mutex<u32>>) {
    let calls = Arc::new(Mutex::new(0));
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
    let mut authenticator = SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty"));
    if legacy_services {
        authenticator = authenticator.accept_legacy_rustfs_signing_services();
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

/// A header-signed `GET /bucket/key` whose credential scope names `service`, signed with `secret`
/// by an independent signer: no SDK signer names a service outside the S3 family.
fn get(service: &str, secret: &str) -> http::Request<Bytes> {
    let stamp = support::SIGNED_AT_STAMP;
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/{service}/aws4_request");
    let payload = "UNSIGNED-PAYLOAD";
    let canonical = format!(
        "GET\n/bucket/key\n\nhost:s3.example.com\nx-amz-content-sha256:{payload}\nx-amz-date:{stamp}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload}"
    );
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac_sha256(format!("AWS4{secret}").as_bytes(), day.as_bytes());
    for part in ["us-east-1", service, "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
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

/// Positive — under the switch a scope naming `s3`, `sts` or `s3tables` is verified on an S3
/// operation and reaches its handler, as legacy RustFS serves it.
#[tokio::test]
async fn the_legacy_services_are_verified_on_an_s3_operation() {
    for scoped in ["s3", "sts", "s3tables"] {
        let (service, calls) = service(true);
        let (status, body) = support::exchange(&service, get(scoped, "secret")).await;
        assert_eq!(status, http::StatusCode::OK, "{scoped}: {body}");
        assert_eq!(*calls.lock().expect("the record is never poisoned"), 1, "{scoped}");
    }
}

/// Negative — under the switch any other service is `501 NotImplemented` with legacy RustFS's
/// sentence, before a handler: an unknown name, an S3-family service, and a known name in another
/// case.
#[tokio::test]
async fn n_another_service_is_refused_with_the_legacy_sentence() {
    for scoped in ["foo", "s3express", "s3-outposts", "S3", "STS"] {
        let (service, calls) = service(true);
        let (status, body) = support::exchange(&service, get(scoped, "secret")).await;
        assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED, "{scoped}: {body}");
        assert!(body.contains("<Code>NotImplemented</Code>"), "{scoped}: {body}");
        let sentence = format!(
            "<Message>unknown service &apos;{scoped}&apos; in credential scope; expected one of: s3, sts, s3tables</Message>"
        );
        assert!(body.contains(&sentence), "{scoped}: {body}");
        assert_eq!(*calls.lock().expect("the record is never poisoned"), 0, "{scoped}");
    }
}

/// Negative — under the switch the key is still derived from the service the client named: a
/// wrong secret, or a signature derived for `s3` presented under `sts`, is `403
/// SignatureDoesNotMatch`.
#[tokio::test]
async fn n_the_legacy_services_still_bind_the_signature_to_the_service() {
    for scoped in ["sts", "s3tables"] {
        let (service, calls) = service(true);
        let (status, body) = support::exchange(&service, get(scoped, "not-the-secret")).await;
        assert_eq!(status, http::StatusCode::FORBIDDEN, "{scoped}: {body}");
        assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{scoped}: {body}");
        assert_eq!(*calls.lock().expect("the record is never poisoned"), 0, "{scoped}");
    }
    let signed_for_s3 = get("s3", "secret");
    let (parts, body) = signed_for_s3.into_parts();
    let mut swapped = http::Request::from_parts(parts, body);
    let authorization = swapped
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .expect("a signed request")
        .replace("/us-east-1/s3/aws4_request", "/us-east-1/sts/aws4_request");
    swapped.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&authorization).expect("a valid header"),
    );
    let (service, _calls) = service(true);
    let (status, body) = support::exchange(&service, swapped).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
}

/// Negative — without the switch the default is unchanged: another S3-family service is `400
/// AuthorizationHeaderMalformed` and a name outside the family a credential it cannot read, `403
/// InvalidAccessKeyId`; only `s3` reaches the handler.
#[tokio::test]
async fn n_the_default_verifies_only_the_routed_service() {
    for (scoped, expected, code) in [
        ("sts", http::StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed"),
        ("s3express", http::StatusCode::BAD_REQUEST, "AuthorizationHeaderMalformed"),
        ("s3tables", http::StatusCode::FORBIDDEN, "InvalidAccessKeyId"),
        ("foo", http::StatusCode::FORBIDDEN, "InvalidAccessKeyId"),
    ] {
        let (service, calls) = service(false);
        let (status, body) = support::exchange(&service, get(scoped, "secret")).await;
        assert_eq!(status, expected, "{scoped}: {body}");
        assert!(body.contains(&format!("<Code>{code}</Code>")), "{scoped}: {body}");
        assert_eq!(*calls.lock().expect("the record is never poisoned"), 0, "{scoped}");
    }
    let (service, calls) = service(false);
    let (status, body) = support::exchange(&service, get("s3", "secret")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(*calls.lock().expect("the record is never poisoned"), 1);
}
