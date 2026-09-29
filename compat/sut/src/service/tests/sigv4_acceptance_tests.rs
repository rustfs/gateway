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

//! Which header-signed SigV4 requests the RustFS-profile launcher accepts and refuses, where it
//! already agrees with legacy RustFS (rustfs/gateway#1099).
//!
//! Responsible for: pinning both directions of the agreement observed against a legacy RustFS
//! build — the spellings legacy verifies (commas without spaces, extra spaces, an unsigned
//! `Content-Type`, `UNSIGNED-PAYLOAD`, a clock fourteen minutes behind) are verified, and the ones
//! it refuses with `403` (an unsigned `x-amz-*` header, `x-amz-date` left out of `SignedHeaders`,
//! a clock sixteen minutes behind or ahead, an algorithm token that is not `AWS4-HMAC-SHA256`, an
//! uppercase signature) are refused with `403`.
//! NOT responsible for: the refusals where the two disagree, which #1099 lists; the signing-region
//! readings (`signing_region_tests.rs`); the presigned forms (`presigned_*_tests.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

use hmac::{Hmac, KeyInit, Mac};

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// How a case bends an otherwise correct header-signed `GET`.
#[derive(Clone, Copy, Debug)]
struct Shape {
    /// Seconds the signing clock is behind the server's (negative: ahead).
    behind: i64,
    /// Sign `UNSIGNED-PAYLOAD` instead of the empty body's digest.
    unsigned_payload: bool,
    /// Send an unsigned header with this name and value.
    unsigned_header: Option<(&'static str, &'static str)>,
    /// Leave `x-amz-date` out of `SignedHeaders` (and the canonical request).
    unsigned_date: bool,
    /// The separator between the `Authorization` components.
    separator: &'static str,
    /// The algorithm token to present.
    algorithm: &'static str,
    /// Present the signature in uppercase hex.
    uppercase_signature: bool,
}

impl Shape {
    const fn new() -> Self {
        Self {
            behind: 0,
            unsigned_payload: false,
            unsigned_header: None,
            unsigned_date: false,
            separator: ", ",
            algorithm: "AWS4-HMAC-SHA256",
            uppercase_signature: false,
        }
    }
}

/// A header-signed `GET /sigv4/k`, signed as the main identity by an independent signer, bent as
/// `shape` says.
fn get(shape: Shape) -> http::Request<Bytes> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let at = i64::try_from(now).expect("a representable clock") - shape.behind;
    let stamp = Timestamp::from_secs(at)
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let payload = if shape.unsigned_payload {
        "UNSIGNED-PAYLOAD".to_owned()
    } else {
        hex(&Sha256::digest(b""))
    };
    let mut signed = vec![
        ("host", "s3.example.com".to_owned()),
        ("x-amz-content-sha256", payload.clone()),
    ];
    if !shape.unsigned_date {
        signed.push(("x-amz-date", stamp.clone()));
    }
    let canonical_headers: String = signed.iter().map(|(name, value)| format!("{name}:{value}\n")).collect();
    let signed_names = signed.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(";");
    let canonical = format!("GET\n/sigv4/k\n\n{canonical_headers}\n{signed_names}\n{payload}");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac_sha256(format!("AWS4{MAIN_SECRET}").as_bytes(), day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let mut signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    if shape.uppercase_signature {
        signature = signature.to_uppercase();
    }
    let separator = shape.separator;
    let mut request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/sigv4/k")
        .header(http::header::HOST, "s3.example.com")
        .header("x-amz-content-sha256", payload)
        .header("x-amz-date", stamp)
        .header(
            http::header::AUTHORIZATION,
            format!(
                "{} Credential={MAIN_KEY}/{scope}{separator}SignedHeaders={signed_names}{separator}Signature={signature}",
                shape.algorithm
            ),
        );
    if let Some((name, value)) = shape.unsigned_header {
        request = request.header(name, value);
    }
    request.body(Bytes::new()).expect("a valid request")
}

async fn with_object(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/sigv4", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(&service, as_main(http::Method::PUT, "/sigv4/k", Bytes::from_static(b"signed"))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

/// Positive — every spelling legacy RustFS verifies is verified and serves the object.
#[tokio::test]
async fn a_request_legacy_verifies_is_verified() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for (label, shape) in [
        ("canonical", Shape::new()),
        (
            "no space after the commas",
            Shape {
                separator: ",",
                ..Shape::new()
            },
        ),
        (
            "extra spaces after the commas",
            Shape {
                separator: ",   ",
                ..Shape::new()
            },
        ),
        (
            "an unsigned Content-Type",
            Shape {
                unsigned_header: Some(("content-type", "text/plain")),
                ..Shape::new()
            },
        ),
        (
            "UNSIGNED-PAYLOAD",
            Shape {
                unsigned_payload: true,
                ..Shape::new()
            },
        ),
        (
            "a clock fourteen minutes behind",
            Shape {
                behind: 14 * 60,
                ..Shape::new()
            },
        ),
    ] {
        let answer = exchange(&service, get(shape)).await;
        assert_eq!(answer.status(), 200, "{label}: {}", body_of(&answer));
        assert_eq!(body_of(&answer), "signed", "{label}");
    }
}

/// Negative — every spelling legacy RustFS refuses with `403` is refused with `403`.
#[tokio::test]
async fn n_a_request_legacy_refuses_with_403_is_refused_with_403() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for (label, shape) in [
        (
            "an unsigned x-amz-meta header",
            Shape {
                unsigned_header: Some(("x-amz-meta-extra", "1")),
                ..Shape::new()
            },
        ),
        (
            "an unsigned x-amz-request-payer",
            Shape {
                unsigned_header: Some(("x-amz-request-payer", "requester")),
                ..Shape::new()
            },
        ),
        (
            "x-amz-date outside SignedHeaders",
            Shape {
                unsigned_date: true,
                ..Shape::new()
            },
        ),
        (
            "a clock sixteen minutes behind",
            Shape {
                behind: 16 * 60,
                ..Shape::new()
            },
        ),
        (
            "a clock sixteen minutes ahead",
            Shape {
                behind: -16 * 60,
                ..Shape::new()
            },
        ),
        (
            "a lowercase algorithm token",
            Shape {
                algorithm: "aws4-hmac-sha256",
                ..Shape::new()
            },
        ),
        (
            "the SigV4a algorithm token",
            Shape {
                algorithm: "AWS4-ECDSA-P256-SHA256",
                ..Shape::new()
            },
        ),
        (
            "an uppercase signature",
            Shape {
                uppercase_signature: true,
                ..Shape::new()
            },
        ),
    ] {
        let answer = exchange(&service, get(shape)).await;
        assert_eq!(answer.status(), 403, "{label}: {}", body_of(&answer));
    }
}

/// Negative — a clock sixteen minutes off is refused as legacy refuses it, with
/// `RequestTimeTooSkewed`, in both directions.
#[tokio::test]
async fn n_a_skewed_clock_is_request_time_too_skewed() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    for behind in [16 * 60, -16 * 60] {
        let answer = exchange(&service, get(Shape { behind, ..Shape::new() })).await;
        let body = body_of(&answer);
        assert_eq!(answer.status(), 403, "{behind}: {body}");
        assert!(body.contains("<Code>RequestTimeTooSkewed</Code>"), "{behind}: {body}");
    }
}
