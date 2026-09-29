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

//! A presigned upload's `x-amz-content-sha256` as the RustFS-profile launcher reads it
//! (rustfs/rustfs#2379).
//!
//! Responsible for: a presigned `PutObject` signed over `UNSIGNED-PAYLOAD` whose signed
//! `x-amz-content-sha256` names the body's digest (hex or base64) being stored byte for byte, as
//! legacy RustFS stores it, and every other declaration being refused without touching storage: a
//! digest the body does not match, a signature made over the digest instead of `UNSIGNED-PAYLOAD`,
//! a value that is not a digest, and a streaming declaration.
//! NOT responsible for: the core default, which signs the declared digest (`c-sig-0430`), or the
//! refusal codes of a mismatched body (#1085).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

use rustfs_gateway::sig::RawQuery;

const BODY: &[u8] = b"a presigned upload body";
const OTHER: &[u8] = b"other bytes than the body";

/// A presigned `PUT` of `target` carrying `declared` in a signed `x-amz-content-sha256` (or no such
/// header), whose canonical payload line is `signed_payload`.
fn presigned_put(target: &str, declared: Option<&str>, signed_payload: PayloadMode, body: &'static [u8]) -> http::Request<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    if let Some(declared) = declared {
        headers.insert(
            http::HeaderName::from_static("x-amz-content-sha256"),
            http::HeaderValue::from_str(declared).expect("a header value"),
        );
    }
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid host probe");
    let accepted = WireRequest::accept(probe, &Limits::default()).expect("an acceptable host");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let rendered = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let stamp = AmzDate::parse(&rendered).expect("a valid signing stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a valid signing scope");
    let credentials = SigningCredentials::new(MAIN_KEY, MAIN_SECRET.as_bytes()).expect("valid signing credentials");
    let method = http::Method::PUT;
    let signing = SigningRequest::new(&method, target, "", &headers, accepted.host().raw_for_signing(), signed_payload, stamp);
    let signed = SigV4Signer::new(credentials, scope)
        .presign(&signing, 900)
        .expect("a signable request");
    assert!(RawQuery::new(signed.query()).decoded_value("X-Amz-Signature").is_ok());
    let mut request = http::Request::builder()
        .method(http::Method::PUT)
        .uri(format!("{target}?{}", signed.query()))
        .header(http::header::CONTENT_LENGTH, body.len().to_string());
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(Bytes::from_static(body)).expect("a valid presigned request")
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn base64_digest(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let digest = Sha256::digest(bytes);
    let mut out = String::new();
    for chunk in digest.chunks(3) {
        let triple = chunk.iter().fold(0u32, |acc, byte| (acc << 8) | u32::from(*byte)) << (8 * (3 - chunk.len()));
        for index in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((triple >> (18 - 6 * index)) & 0x3f) as usize]));
        }
    }
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

async fn served(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/presigned-uploads", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let kept = exchange(
        &service,
        as_main(http::Method::PUT, "/presigned-uploads/kept", Bytes::from_static(b"kept bytes")),
    )
    .await;
    assert_eq!(kept.status(), 200, "{}", body_of(&kept));
    service
}

async fn stored(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

fn code_of(response: &WireResponse) -> String {
    let body = body_of(response);
    body.split("<Code>")
        .nth(1)
        .and_then(|rest| rest.split("</Code>").next())
        .unwrap_or_default()
        .to_owned()
}

/// Positive — a presigned upload signed over `UNSIGNED-PAYLOAD` whose signed
/// `x-amz-content-sha256` is the body's digest, in hex or in base64, stores the body byte for byte;
/// so does one declaring `UNSIGNED-PAYLOAD` itself.
#[tokio::test]
async fn a_presigned_upload_declaring_its_digest_outside_the_signature_is_stored() {
    let root = TestRoot::new();
    let service = served(&root).await;
    for (key, declared) in [
        ("hex", hex_digest(BODY)),
        ("base64", base64_digest(BODY)),
        ("unsigned", "UNSIGNED-PAYLOAD".to_owned()),
    ] {
        let target = format!("/presigned-uploads/{key}");
        let put = exchange(&service, presigned_put(&target, Some(&declared), PayloadMode::Unsigned, BODY)).await;
        assert_eq!(put.status(), 200, "{key}: {}", body_of(&put));
        let read = stored(&service, &target).await;
        assert_eq!(read.status(), 200, "{key}");
        assert_eq!(read.body().as_ref(), BODY, "{key}");
    }
}

/// Negative — a digest the body does not match is refused and stores nothing; over an existing
/// object it leaves the stored bytes exactly as they were.
#[tokio::test]
async fn n_a_presigned_body_that_does_not_match_its_declared_digest_changes_nothing() {
    let root = TestRoot::new();
    let service = served(&root).await;
    for (key, declared) in [("kept", hex_digest(OTHER)), ("fresh", base64_digest(OTHER))] {
        let target = format!("/presigned-uploads/{key}");
        let refused = exchange(&service, presigned_put(&target, Some(&declared), PayloadMode::Unsigned, BODY)).await;
        assert_eq!(refused.status(), 400, "{key}: {}", body_of(&refused));
    }
    assert_eq!(stored(&service, "/presigned-uploads/kept").await.body().as_ref(), b"kept bytes");
    assert_eq!(stored(&service, "/presigned-uploads/fresh").await.status(), 404);
}

/// Negative — a presigned signature made over the declared digest instead of `UNSIGNED-PAYLOAD` is
/// not the signature legacy RustFS verifies: `403 SignatureDoesNotMatch`, nothing stored.
#[tokio::test]
async fn n_a_presigned_signature_over_the_digest_is_signature_does_not_match() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let digest: [u8; 32] = Sha256::digest(BODY).into();
    let request = presigned_put(
        "/presigned-uploads/over-digest",
        Some(&hex_digest(BODY)),
        PayloadMode::ExactSha256(digest),
        BODY,
    );
    let refused = exchange(&service, request).await;
    assert_eq!(refused.status(), 403, "{}", body_of(&refused));
    assert_eq!(code_of(&refused), "SignatureDoesNotMatch");
    assert_eq!(stored(&service, "/presigned-uploads/over-digest").await.status(), 404);
}

/// Negative — a declaration that is not a digest, `UNSIGNED-PAYLOAD` or a streaming mode is
/// `403 SignatureDoesNotMatch` on a presigned request, as legacy RustFS answers it, and a
/// streaming declaration is `501 NotImplemented`; neither stores anything.
#[tokio::test]
async fn n_a_presigned_upload_with_an_unreadable_or_streaming_declaration_is_refused() {
    let root = TestRoot::new();
    let service = served(&root).await;
    let upper = hex_digest(BODY).to_ascii_uppercase();
    for (key, declared, status, code) in [
        ("not-a-digest", "invalid-sha256", 403, "SignatureDoesNotMatch"),
        ("upper-hex", upper.as_str(), 403, "SignatureDoesNotMatch"),
        ("lowercase-keyword", "unsigned-payload", 403, "SignatureDoesNotMatch"),
        ("streaming-unsigned", "STREAMING-UNSIGNED-PAYLOAD-TRAILER", 501, "NotImplemented"),
        ("streaming-signed", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", 501, "NotImplemented"),
    ] {
        let target = format!("/presigned-uploads/{key}");
        let refused = exchange(&service, presigned_put(&target, Some(declared), PayloadMode::Unsigned, BODY)).await;
        assert_eq!(refused.status(), status, "{key}: {}", body_of(&refused));
        assert_eq!(code_of(&refused), code, "{key}");
        assert_eq!(stored(&service, &target).await.status(), 404, "{key}");
    }
}
