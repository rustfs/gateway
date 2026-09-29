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

//! The spelling of a request path the RustFS-profile launcher verifies a SigV4 signature over
//! (rustfs/rustfs#2593, rustfs/gateway#1099).
//!
//! Responsible for: legacy RustFS's reading — a signature over the wire spelling of a key with an
//! unencoded byte (RustFS's `special_chars_test` trailing `=`, a raw `+`, `!*()'`, `,;:@&$`) is
//! verified and the object is stored and read back under the decoded key; a signature over a
//! wire spelling that only re-spells an escape (`%7E`, a lowercase `%3d`) is `403
//! SignatureDoesNotMatch` and stores nothing, while the decoded spelling of the same path is
//! verified.
//! NOT responsible for: the candidate rule (`rustfs-gateway-sig`) or the switch's service-level
//! behaviour (`rustfs-gateway`'s `tests/raw_path_fallback.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

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

/// A request to `wire_path` signed as the main identity by an independent signer whose canonical
/// URI is `signed_path`, the spelling the case chooses.
fn signed_over(method: http::Method, wire_path: &str, signed_path: &str, body: &'static [u8]) -> http::Request<Bytes> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let stamp = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let payload = hex(&Sha256::digest(body));
    let length = body.len().to_string();
    let canonical = format!(
        "{method}\n{signed_path}\n\ncontent-length:{length}\nhost:s3.example.com\nx-amz-content-sha256:{payload}\nx-amz-date:{stamp}\n\ncontent-length;host;x-amz-content-sha256;x-amz-date\n{payload}"
    );
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac_sha256(format!("AWS4{MAIN_SECRET}").as_bytes(), day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    http::Request::builder()
        .method(method)
        .uri(wire_path)
        .header(http::header::CONTENT_LENGTH, length)
        .header(http::header::HOST, "s3.example.com")
        .header("x-amz-content-sha256", payload)
        .header("x-amz-date", stamp)
        .header(
            http::header::AUTHORIZATION,
            format!(
                "AWS4-HMAC-SHA256 Credential={MAIN_KEY}/{scope}, SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date, Signature={signature}"
            ),
        )
        .body(Bytes::from_static(body))
        .expect("a valid request")
}

async fn with_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/paths", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

async fn listed_keys(service: &S3Service) -> String {
    let listing = exchange(service, as_main(http::Method::GET, "/paths?list-type=2", Bytes::new())).await;
    assert_eq!(listing.status(), 200, "{}", body_of(&listing));
    body_of(&listing)
}

/// Positive — a key with an unencoded byte, signed over the wire spelling, is stored under the
/// decoded key and read back byte for byte, as legacy RustFS stores and serves it; the same key
/// signed over its encoded spelling reads the same object.
#[tokio::test]
async fn a_raw_byte_in_a_key_is_verified_over_the_wire_spelling() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    // The listed key is checked where it needs no XML escaping; the other two are identified by
    // reading them back through both spellings.
    for (wire, encoded, key) in [
        (
            "/paths/path/sitemap.xmlage=",
            "/paths/path/sitemap.xmlage%3D",
            Some("path/sitemap.xmlage="),
        ),
        ("/paths/a+b", "/paths/a%2Bb", Some("a+b")),
        ("/paths/a!*()'", "/paths/a%21%2A%28%29%27", None),
        ("/paths/a,;:@&$", "/paths/a%2C%3B%3A%40%26%24", None),
    ] {
        let stored = exchange(&service, signed_over(http::Method::PUT, wire, wire, b"raw-signed body")).await;
        assert_eq!(stored.status(), 200, "{wire}: {}", body_of(&stored));
        for signed in [wire, encoded] {
            let read = exchange(&service, signed_over(http::Method::GET, wire, signed, b"")).await;
            assert_eq!(read.status(), 200, "{wire} signed as {signed}: {}", body_of(&read));
            assert_eq!(body_of(&read), "raw-signed body", "{wire}");
        }
        if let Some(key) = key {
            let keys = listed_keys(&service).await;
            assert!(keys.contains(&format!("<Key>{key}</Key>")), "{wire}: {keys}");
        }
    }
}

/// Negative — a signature over a wire spelling that differs from the decoded one only in how its
/// escapes are spelled is `403 SignatureDoesNotMatch`, as legacy RustFS answers it, and stores
/// nothing; the decoded spelling of the same path is verified and stores the object.
#[tokio::test]
async fn n_a_signature_over_respelled_escapes_is_refused_and_stores_nothing() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for (wire, decoded, key) in [("/paths/a%7Eb", "/paths/a~b", "a~b"), ("/paths/b%3d", "/paths/b%3D", "b=")] {
        let refused = exchange(&service, signed_over(http::Method::PUT, wire, wire, b"respelled")).await;
        assert_eq!(refused.status(), 403, "{wire}: {}", body_of(&refused));
        assert!(body_of(&refused).contains("<Code>SignatureDoesNotMatch</Code>"), "{wire}");
        assert!(!listed_keys(&service).await.contains(&format!("<Key>{key}</Key>")), "{wire} was stored");
        let stored = exchange(&service, signed_over(http::Method::PUT, wire, decoded, b"decoded")).await;
        assert_eq!(stored.status(), 200, "{wire} signed as {decoded}: {}", body_of(&stored));
        assert!(listed_keys(&service).await.contains(&format!("<Key>{key}</Key>")), "{wire}");
    }
}
