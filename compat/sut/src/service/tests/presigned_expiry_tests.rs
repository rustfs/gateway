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

//! A presigned URL's lifetime as the RustFS-profile launcher reads it (rustfs/rustfs#5368).
//!
//! Responsible for: the lifetimes legacy RustFS honours — an escaped `+` or leading zeros in
//! `X-Amz-Expires`, a zero lifetime on a URL dated ahead, a SigV2 `Expires` months away — reading
//! the object, and the ones it refuses being refused without it: a lifetime past 604800, a literal
//! `+` (a space to legacy RustFS's form decoding), a zero lifetime dated now, an elapsed SigV2
//! instant.
//! NOT responsible for: the AWS default (`rustfs-gateway-sig`'s floor tests) or the rule itself
//! (`rustfs-gateway-sig`'s `presigned_expiry` tests).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

use hmac::{Hmac, KeyInit, Mac};
use rustfs_gateway::PresignedExpiryRule;
use rustfs_gateway::sig::{RawQuery, SigV2Mode, SigV2Signer, SigV2StringToSignSpec};

const CONTENT: &[u8] = b"presigned lifetime content";
const OBJECT: &str = "/lifetimes/k";

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_secs(),
    )
    .expect("a representable clock")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A SigV4 presigned `GET` of [`OBJECT`] dated `signed_at`, whose `X-Amz-Expires` is `expires`
/// exactly as written on the wire, signed independently of the gateway's own signer (which will
/// not mint `0` or a `+`). A client signs the value it put in the URL, decoded.
fn sigv4_presigned(signed_at: i64, expires: &str) -> http::Request<Bytes> {
    let stamp = Timestamp::from_secs(signed_at)
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let decoded_expires = expires.replace("%2B", "+");
    let credential = format!("{MAIN_KEY}/{scope}").replace('/', "%2F");
    let mut canonical_query = [
        ("X-Amz-Algorithm".to_owned(), "AWS4-HMAC-SHA256".to_owned()),
        ("X-Amz-Credential".to_owned(), credential),
        ("X-Amz-Date".to_owned(), stamp.clone()),
        ("X-Amz-Expires".to_owned(), decoded_expires.replace('+', "%2B")),
        ("X-Amz-SignedHeaders".to_owned(), "host".to_owned()),
    ];
    canonical_query.sort();
    let canonical_query = canonical_query
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let canonical = format!("GET\n{OBJECT}\n{canonical_query}\nhost:s3.example.com\n\nhost\nUNSIGNED-PAYLOAD");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac_sha256(format!("AWS4{MAIN_SECRET}").as_bytes(), day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    let wire_query = canonical_query.replace(
        &format!("X-Amz-Expires={}", decoded_expires.replace('+', "%2B")),
        &format!("X-Amz-Expires={expires}"),
    );
    http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("{OBJECT}?{wire_query}&X-Amz-Signature={signature}"))
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid presigned request")
}

/// A SigV2 presigned `GET` of [`OBJECT`] whose `Expires` is `expires` as written on the wire,
/// signed over its decoded value as a SigV2 client signs it.
fn sigv2_presigned(expires: &str) -> http::Request<Bytes> {
    let decoded = expires.replace("%2B", "+");
    let raw = format!("AWSAccessKeyId={MAIN_KEY}&Expires={expires}");
    let query = RawQuery::new(&raw);
    let headers = http::HeaderMap::new();
    let spec = SigV2StringToSignSpec::new(SigV2Mode::PresignedUrl, &http::Method::GET, OBJECT, &query, &headers, None)
        .with_presigned_expiry_rule(PresignedExpiryRule::LegacyRustfs);
    // A value no rule reads cannot be signed; any well-formed signature then stands in for it,
    // because the refusal it is sent for happens before the signature is compared.
    let signature = SigV2Signer::new(MAIN_KEY, MAIN_SECRET.as_bytes())
        .expect("a valid access key id")
        .presigned_signature(&spec)
        .unwrap_or_else(|_| "AAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned());
    assert!(!decoded.is_empty());
    let escaped = signature.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
    http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("{OBJECT}?AWSAccessKeyId={MAIN_KEY}&Expires={expires}&Signature={escaped}"))
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid presigned request")
}

async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/lifetimes", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let put = exchange(&service, as_main(http::Method::PUT, OBJECT, Bytes::from_static(CONTENT))).await;
    assert_eq!(put.status(), 200, "{}", body_of(&put));
    service
}

fn code_of(response: &WireResponse) -> String {
    let body = body_of(response);
    body.split("<Code>")
        .nth(1)
        .and_then(|rest| rest.split("</Code>").next())
        .unwrap_or_default()
        .to_owned()
}

/// Positive — the SigV4 lifetimes legacy RustFS honours read the object: an escaped `+`, leading
/// zeros, the 604800 ceiling itself, and a zero lifetime on a URL dated a minute ahead of the
/// clock (within the skew window).
#[tokio::test]
async fn the_sigv4_lifetimes_legacy_rustfs_honours_read_the_object() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let at = now();
    for (label, signed_at, expires) in [
        ("an escaped plus", at, "%2B300"),
        ("leading zeros", at, "0300"),
        ("the ceiling", at, "604800"),
        ("zero, dated ahead", at + 60, "0"),
    ] {
        let response = exchange(&service, sigv4_presigned(signed_at, expires)).await;
        assert_eq!(response.status(), 200, "{label}: {}", body_of(&response));
        assert_eq!(response.body().as_ref(), CONTENT, "{label}");
    }
}

/// Negative — the SigV4 lifetimes legacy RustFS refuses are refused without the object: past the
/// ceiling and a literal `+` are `400 AuthorizationQueryParametersError`; a zero lifetime dated
/// now, and a lifetime that ended, are `403 AccessDenied`.
#[tokio::test]
async fn n_the_sigv4_lifetimes_legacy_rustfs_refuses_are_refused() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let at = now();
    for (label, signed_at, expires, status, code) in [
        ("past the ceiling", at, "604801", 400, "AuthorizationQueryParametersError"),
        ("a literal plus", at, "+300", 400, "AuthorizationQueryParametersError"),
        ("a sign", at, "-300", 400, "AuthorizationQueryParametersError"),
        ("zero, dated now", at, "0", 403, "AccessDenied"),
        ("an ended lifetime", at - 120, "60", 403, "AccessDenied"),
    ] {
        let response = exchange(&service, sigv4_presigned(signed_at, expires)).await;
        assert_eq!(response.status(), status, "{label}: {}", body_of(&response));
        assert_eq!(code_of(&response), code, "{label}");
        assert_ne!(response.body().as_ref(), CONTENT, "{label}");
    }
}

/// Positive — a SigV2 link honoured by legacy RustFS reads the object however far ahead it
/// expires, and with an escaped `+` before its instant.
#[tokio::test]
async fn the_sigv2_links_legacy_rustfs_honours_read_the_object() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let at = now();
    for (label, expires) in [
        ("thirty days", (at + 30 * 86_400).to_string()),
        ("four hundred days", (at + 400 * 86_400).to_string()),
        ("an escaped plus", format!("%2B{}", at + 300)),
    ] {
        let response = exchange(&service, sigv2_presigned(&expires)).await;
        assert_eq!(response.status(), 200, "{label}: {}", body_of(&response));
        assert_eq!(response.body().as_ref(), CONTENT, "{label}");
    }
}

/// Negative — a SigV2 link legacy RustFS refuses is refused without the object: an elapsed
/// instant is `403 AccessDenied`, a literal `+` and a negative instant are `400`.
#[tokio::test]
async fn n_the_sigv2_links_legacy_rustfs_refuses_are_refused() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let at = now();
    for (label, expires, status) in [
        ("an elapsed instant", (at - 1).to_string(), 403),
        ("a literal plus", format!("+{}", at + 300), 400),
        ("a negative instant", "-5".to_owned(), 400),
    ] {
        let response = exchange(&service, sigv2_presigned(&expires)).await;
        assert_eq!(response.status(), status, "{label}: {}", body_of(&response));
        assert_ne!(response.body().as_ref(), CONTENT, "{label}");
    }
}
