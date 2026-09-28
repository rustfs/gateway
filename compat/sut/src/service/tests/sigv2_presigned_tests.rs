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

//! SigV2 presigned URLs as the RustFS-profile launcher serves them (rustfs/gateway#913).
//!
//! Responsible for: an `s3cmd signurl`-shaped link — `AWSAccessKeyId`, `Expires`, `Signature` in
//! the query — reading the object it was signed for, and every variation of that link that is not
//! the one the key holder signed (a changed signature, path or expiry, another secret, a lapsed
//! expiry) being refused without the object.
//! NOT responsible for: the core default (`SigV2Policy::HeaderOnly`), which
//! `rustfs-gateway-sig`'s admission tests pin, or SigV2 verification itself.
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

use rustfs_gateway::sig::{RawQuery, SigV2Mode, SigV2Signer, SigV2StringToSignSpec};

const CONTENT: &[u8] = b"signed-url content";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs()
}

/// Escapes the three base64 characters a query value cannot carry literally.
fn escape(signature: &str) -> String {
    signature.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
}

/// The `Signature` a SigV2 client computes for `GET path` expiring at `expires`.
fn signature(secret: &str, path: &str, expires: u64) -> String {
    let raw = format!("AWSAccessKeyId={MAIN_KEY}&Expires={expires}");
    let query = RawQuery::new(&raw);
    let headers = http::HeaderMap::new();
    let spec = SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &http::Method::GET, path, &query, &headers, None);
    SigV2Signer::new(MAIN_KEY, secret.as_bytes())
        .expect("a valid access key id")
        .presigned_signature(&spec)
        .expect("a signable request")
}

/// Redeems a presigned link the way curl does: no `Authorization`, only the query.
async fn redeem(service: &S3Service, path: &str, expires: u64, signature: &str) -> WireResponse {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!(
            "{path}?AWSAccessKeyId={MAIN_KEY}&Expires={expires}&Signature={}",
            escape(signature)
        ))
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    exchange(service, request).await
}

async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    assert_eq!(
        exchange(&service, as_main(http::Method::PUT, "/signurl", Bytes::new()))
            .await
            .status(),
        200
    );
    let put = exchange(&service, as_main(http::Method::PUT, "/signurl/k", Bytes::from_static(CONTENT))).await;
    assert_eq!(put.status(), 200, "{}", body_of(&put));
    service
}

/// Positive — the link the key holder signed reads the object.
#[tokio::test]
async fn a_correctly_signed_sigv2_presigned_get_reads_the_object() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let expires = now() + 300;

    let response = redeem(&service, "/signurl/k", expires, &signature(MAIN_SECRET, "/signurl/k", expires)).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    assert_eq!(response.body().as_ref(), CONTENT);
}

/// Negative — a link whose expiry has passed is refused, even though its signature is valid.
#[tokio::test]
async fn n_an_expired_sigv2_presigned_get_is_refused() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let expires = now() - 60;

    let response = redeem(&service, "/signurl/k", expires, &signature(MAIN_SECRET, "/signurl/k", expires)).await;
    assert_eq!(response.status(), 403, "{}", body_of(&response));
    assert_ne!(response.body().as_ref(), CONTENT);
}

/// Negative — every tampering with a live link is refused: a changed signature, a signature for
/// another object, an `Expires` moved after signing, and a signature made with another secret.
#[tokio::test]
async fn n_a_tampered_sigv2_presigned_get_is_refused() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let expires = now() + 300;
    let genuine = signature(MAIN_SECRET, "/signurl/k", expires);
    let mut flipped = genuine.clone().into_bytes();
    flipped[0] = if flipped[0] == b'A' { b'B' } else { b'A' };
    let flipped = String::from_utf8(flipped).expect("base64 stays ASCII");

    let cases = [
        ("a flipped signature byte", expires, flipped),
        ("a signature for another key", expires, signature(MAIN_SECRET, "/signurl/other", expires)),
        ("an extended expiry", expires + 3600, genuine),
        ("another secret", expires, signature(ALT_SECRET, "/signurl/k", expires)),
    ];
    for (label, presented_expires, presented_signature) in cases {
        let response = redeem(&service, "/signurl/k", presented_expires, &presented_signature).await;
        assert_eq!(response.status(), 403, "{label}: {}", body_of(&response));
        assert_ne!(response.body().as_ref(), CONTENT, "{label}");
    }
}
