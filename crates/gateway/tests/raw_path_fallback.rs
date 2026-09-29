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

//! Which spelling of a request path a SigV4 signature is verified over, through the whole service
//! (rustfs/rustfs#2593, rustfs/gateway#1099).
//!
//! Responsible for: proving that `SigV4Authenticator::verify_raw_paths_only_with_unencoded_bytes`
//! still verifies a signature over the wire spelling of a path that carries an unencoded byte (a
//! raw `=`, `+`, or a raw `=` beside an escape) and over the decoded spelling of any path, and
//! refuses one over a wire spelling that differs from the decoded one only in how its escapes are
//! spelled — which the default authenticator verifies — without reaching the handler.
//! NOT responsible for: the candidate rule itself (`rustfs-gateway-sig`'s `canonical` unit tests)
//! or the launcher that turns the switch on (`compat/sut`).
//! Upstream: `S3Service` with a recording `GetObject` backend. Downstream: none.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::{
    ClockSkewAck, Credentials, Handler, HandlerResult, RegionSet, Req, Resp, S3Service, ServiceBuilder, SigV4Authenticator,
    StaticCredentials, allow_when, dto,
};
use sha2::{Digest as _, Sha256};

use crate::support;

struct Backend(Arc<Mutex<Vec<String>>>);

impl Handler<dto::GetObject> for Backend {
    fn call(&self, request: Req<dto::GetObject>) -> impl core::future::Future<Output = HandlerResult<dto::GetObject>> + Send {
        let keys = Arc::clone(&self.0);
        let key = request.into_input().key;
        async move {
            keys.lock()
                .expect("the record is never poisoned")
                .push(key.as_str().to_owned());
            Ok(Resp::new(dto::GetObjectOutput::default()))
        }
    }
}

fn service(legacy_fallback: bool) -> (S3Service, Arc<Mutex<Vec<String>>>) {
    let keys = Arc::new(Mutex::new(Vec::new()));
    let credentials =
        Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("a valid access key id")));
    let mut authenticator = SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty"));
    if legacy_fallback {
        authenticator = authenticator.verify_raw_paths_only_with_unencoded_bytes();
    }
    let service = ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(allow_when(|_| true))
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::GetObject, _>(Arc::new(Backend(Arc::clone(&keys))))
        .build()
        .expect("a complete GetObject assembly");
    (service, keys)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
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

/// A header-signed `GET` sent to `wire_path` whose signature covers `signed_path` as its canonical
/// URI: an independent signer, so the path spelling it signs is the case's choice, not a
/// signer's canonicalisation.
fn get(wire_path: &str, signed_path: &str) -> http::Request<Bytes> {
    let stamp = support::SIGNED_AT_STAMP;
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let payload = "UNSIGNED-PAYLOAD";
    let canonical = format!(
        "GET\n{signed_path}\n\nhost:s3.example.com\nx-amz-content-sha256:{payload}\nx-amz-date:{stamp}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload}"
    );
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac_sha256(b"AWS4secret", day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    http::Request::builder()
        .method(http::Method::GET)
        .uri(wire_path)
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

/// (wire path, signed path, the key the handler reads) for requests both authenticators verify.
const VERIFIED_EITHER_WAY: [(&str, &str, &str); 6] = [
    // RustFS's `special_chars_test` shape: a raw `=` signed as sent, and signed encoded.
    ("/bucket/sitemap.xmlage=", "/bucket/sitemap.xmlage=", "sitemap.xmlage="),
    ("/bucket/sitemap.xmlage=", "/bucket/sitemap.xmlage%3D", "sitemap.xmlage="),
    ("/bucket/a+b", "/bucket/a+b", "a+b"),
    ("/bucket/a%20b=", "/bucket/a%20b=", "a b="),
    // A re-spelled escape signed in its decoded spelling.
    ("/bucket/a%7Eb", "/bucket/a~b", "a~b"),
    ("/bucket/a%3d", "/bucket/a%3D", "a="),
];

/// (wire path, signed path) for requests signed over a wire spelling that differs from the decoded
/// one only in how its escapes are spelled.
const RESPELLED_ESCAPES: [(&str, &str); 3] = [
    ("/bucket/a%7Eb", "/bucket/a%7Eb"),
    ("/bucket/a%3d", "/bucket/a%3d"),
    ("/bucket/%41", "/bucket/%41"),
];

/// Positive — under the switch a signature over the wire spelling of a path with an unencoded byte,
/// or over the decoded spelling of any path, is verified and reaches the handler with the key.
#[tokio::test]
async fn the_legacy_fallback_verifies_raw_bytes_and_decoded_spellings() {
    for (wire, signed, key) in VERIFIED_EITHER_WAY {
        let (service, keys) = service(true);
        let (status, body) = support::exchange(&service, get(wire, signed)).await;
        assert_eq!(status, http::StatusCode::OK, "{wire} signed as {signed}: {body}");
        assert_eq!(*keys.lock().expect("the record is never poisoned"), [key.to_owned()], "{wire}");
    }
}

/// Negative — under the switch a signature over re-spelled escapes is `403
/// SignatureDoesNotMatch`, as legacy RustFS answers it, and no handler is reached.
#[tokio::test]
async fn n_the_legacy_fallback_refuses_a_signature_over_respelled_escapes() {
    for (wire, signed) in RESPELLED_ESCAPES {
        let (service, keys) = service(true);
        let (status, body) = support::exchange(&service, get(wire, signed)).await;
        assert_eq!(status, http::StatusCode::FORBIDDEN, "{wire}: {body}");
        assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{wire}: {body}");
        assert!(keys.lock().expect("the record is never poisoned").is_empty(), "{wire}");
    }
}

/// Negative — the default authenticator keeps verifying both: the switch is what narrows it.
#[tokio::test]
async fn n_the_default_verifies_every_spelling_the_switch_narrows() {
    for (wire, signed) in RESPELLED_ESCAPES {
        let (service, _keys) = service(false);
        let (status, body) = support::exchange(&service, get(wire, signed)).await;
        assert_eq!(status, http::StatusCode::OK, "{wire}: {body}");
    }
    for (wire, signed, key) in VERIFIED_EITHER_WAY {
        let (service, keys) = service(false);
        let (status, body) = support::exchange(&service, get(wire, signed)).await;
        assert_eq!(status, http::StatusCode::OK, "{wire} signed as {signed}: {body}");
        assert_eq!(*keys.lock().expect("the record is never poisoned"), [key.to_owned()], "{wire}");
    }
}
