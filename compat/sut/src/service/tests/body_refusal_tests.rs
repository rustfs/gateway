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

//! Request-body refusals as the RustFS-profile launcher answers them (rustfs/gateway#1099).
//!
//! Responsible for: the status, code and `<Message>` legacy RustFS answers a body that failed
//! verification or arrived short with — a tampered signed payload, a mismatched or unreadable
//! checksum, a mismatched `Content-MD5`, a trailer section that is not the declared one, a
//! decoded-length mismatch, a body cut short, a declared length above 5 GiB — and each of them
//! storing nothing, as legacy stores nothing.
//! NOT responsible for: the codes of the checksum refusals (`bad_digest_tests.rs`) or the refusal
//! points themselves (`rustfs-gateway`'s gate and body producer).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

use hmac::{Hmac, KeyInit, Mac};

/// Legacy RustFS's sentence for `BadDigest` (`rustfs/src/error.rs:307`).
const BAD_DIGEST: &str = "The Content-Md5 you specified did not match what we received.";
/// Legacy RustFS's sentence for `IncompleteBody` (`rustfs/src/error.rs:339`).
const INCOMPLETE_BODY: &str = "You did not provide the number of bytes specified by the Content-Length HTTP header.";
/// Legacy RustFS's sentence for an upload declared larger than 5 GiB.
const UPLOAD_TOO_LARGE: &str = "Request body exceeds the configured maximum object size.";

/// 5 GiB, RustFS's single-request upload ceiling.
const FIVE_GIB: u64 = 5 * 1024 * 1024 * 1024;

async fn with_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/refusals", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

fn element<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find('<')? + start;
    Some(&body[start..end])
}

/// Holds `response` to legacy RustFS's answer: `status`, `code`, and exactly `message`.
fn assert_answer(response: &WireResponse, status: u16, code: &str, message: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), status, "{body}");
    assert_eq!(element(&body, "Code"), Some(code), "{body}");
    assert_eq!(element(&body, "Message"), Some(message), "{body}");
}

async fn assert_absent(service: &S3Service, target: &str) {
    let read = exchange(service, as_main(http::Method::GET, target, Bytes::new())).await;
    assert_eq!(read.status(), 404, "{target} was stored: {}", body_of(&read));
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A header-signed `STREAMING-UNSIGNED-PAYLOAD-TRAILER` `PUT` of `target` declaring
/// `decoded_length` bytes and the trailer `trailer`, whose body is `framed` exactly as written.
///
/// Signed by hand: the gateway's own signer refuses to mint a trailer section that disagrees with
/// its head, which is exactly what these cases send.
pub(super) fn streaming_put(target: &str, decoded_length: usize, trailer: &str, framed: Vec<u8>) -> http::Request<Bytes> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs();
    let stamp = Timestamp::from_secs(i64::try_from(now).expect("a representable clock"))
        .render(TimestampFormat::Iso8601Basic)
        .expect("a representable signing stamp");
    let day = &stamp[..8];
    let scope = format!("{day}/us-east-1/s3/aws4_request");
    let token = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
    let headers = [
        ("content-encoding", "aws-chunked".to_owned()),
        ("host", "s3.example.com".to_owned()),
        ("x-amz-content-sha256", token.to_owned()),
        ("x-amz-date", stamp.clone()),
        ("x-amz-decoded-content-length", decoded_length.to_string()),
        ("x-amz-trailer", trailer.to_owned()),
    ];
    let canonical_headers: String = headers.iter().map(|(name, value)| format!("{name}:{value}\n")).collect();
    let signed_names = headers.iter().map(|(name, _)| *name).collect::<Vec<_>>().join(";");
    let canonical = format!("PUT\n{target}\n\n{canonical_headers}\n{signed_names}\n{token}");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = hmac_sha256(format!("AWS4{MAIN_SECRET}").as_bytes(), day.as_bytes());
    for part in ["us-east-1", "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    let mut request = http::Request::builder()
        .method(http::Method::PUT)
        .uri(target)
        .header(http::header::CONTENT_LENGTH, framed.len().to_string())
        .header(
            http::header::AUTHORIZATION,
            format!("AWS4-HMAC-SHA256 Credential={MAIN_KEY}/{scope}, SignedHeaders={signed_names}, Signature={signature}"),
        );
    for (name, value) in &headers {
        request = request.header(*name, value.as_str());
    }
    request.body(Bytes::from(framed)).expect("a valid streaming request")
}

/// `data` in one unsigned aws-chunked chunk, then the terminal chunk and `trailer_lines`.
pub(super) fn framed(data: &[u8], trailer_lines: &str) -> Vec<u8> {
    let mut body = format!("{:x}\r\n", data.len()).into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(b"\r\n0\r\n");
    body.extend_from_slice(trailer_lines.as_bytes());
    body.extend_from_slice(b"\r\n");
    body
}

/// The base64 SHA-256 of `data`.
fn sha256_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let digest = Sha256::digest(data);
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

/// Positive control — a well-formed streaming upload with its declared trailer is stored whole, so
/// every refusal below is about the body and not the fixture.
#[tokio::test]
async fn a_streaming_upload_with_its_declared_trailer_is_stored() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let data = b"streamed body";
    let trailer = format!("x-amz-checksum-sha256:{}\r\n", sha256_base64(data));
    let stored = exchange(
        &service,
        streaming_put("/refusals/streamed", data.len(), "x-amz-checksum-sha256", framed(data, &trailer)),
    )
    .await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    let read = exchange(&service, as_main(http::Method::GET, "/refusals/streamed", Bytes::new())).await;
    assert_eq!(read.body().as_ref(), data);
}

/// Negative — every body that does not match its claim is `400 BadDigest` with legacy RustFS's
/// sentence, and stores nothing: a signed payload swapped after signing, a mismatched and an
/// unreadable `x-amz-checksum-crc32`, a mismatched `Content-MD5`.
#[tokio::test]
async fn n_a_body_that_does_not_match_its_claim_is_legacy_bad_digest_and_stores_nothing() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let swapped = signed(
        MAIN_KEY,
        MAIN_SECRET,
        http::Method::PUT,
        "/refusals/swapped",
        Bytes::from_static(b"hello"),
        &[],
    )
    .map(|_| Bytes::from_static(b"HELLO"));
    assert_answer(&exchange(&service, swapped).await, 400, "BadDigest", BAD_DIGEST);
    assert_absent(&service, "/refusals/swapped").await;

    for (key, header, value) in [
        ("crc-mismatch", "x-amz-checksum-crc32", "AAAAAA=="),
        ("crc-unreadable", "x-amz-checksum-crc32", "nope"),
        ("md5-mismatch", "content-md5", "K9opmNmw7hl9oUKgRH9nJQ=="),
    ] {
        let target = format!("/refusals/{key}");
        let request = signed(
            MAIN_KEY,
            MAIN_SECRET,
            http::Method::PUT,
            &target,
            Bytes::from_static(b"hello"),
            &[(header, value)],
        );
        assert_answer(&exchange(&service, request).await, 400, "BadDigest", BAD_DIGEST);
        assert_absent(&service, &target).await;
    }
}

/// Negative — a trailer section that is not the one the head declared — no trailer, another
/// checksum — is `400 BadDigest` with legacy RustFS's sentence, and stores nothing, as a legacy
/// RustFS build answers it. (A trailer field outside the checksum set is refused by the decoder
/// before any checksum is compared; legacy answers `BadDigest` there too, and that difference in
/// code is recorded in rustfs/gateway#1099.)
#[tokio::test]
async fn n_a_trailer_section_that_is_not_the_declared_one_is_legacy_bad_digest() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let data = b"decoded!";
    for (key, trailer) in [
        ("no-trailer", String::new()),
        ("other-checksum", "x-amz-checksum-crc32:WArTKw==\r\n".to_owned()),
    ] {
        let target = format!("/refusals/{key}");
        let request = streaming_put(&target, data.len(), "x-amz-checksum-sha256", framed(data, &trailer));
        assert_answer(&exchange(&service, request).await, 400, "BadDigest", BAD_DIGEST);
        assert_absent(&service, &target).await;
    }
}

/// Negative — an aws-chunked body that is not the length it was declared as is `400
/// IncompleteBody` with legacy RustFS's sentence, and stores nothing: a decoded length above and
/// below what the chunks carry. (A plain body cut short is a transport error only a real socket
/// produces; `crates/gateway/tests/body_refusal_sentences.rs` holds it on one.)
#[tokio::test]
async fn n_a_body_of_the_wrong_length_is_legacy_incomplete_body_and_stores_nothing() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let data = b"decoded";
    let trailer = format!("x-amz-checksum-sha256:{}\r\n", sha256_base64(data));
    for (key, declared) in [("overrun", 3), ("shortfall", 9)] {
        let target = format!("/refusals/{key}");
        let request = streaming_put(&target, declared, "x-amz-checksum-sha256", framed(data, &trailer));
        assert_answer(&exchange(&service, request).await, 400, "IncompleteBody", INCOMPLETE_BODY);
        assert_absent(&service, &target).await;
    }
}

/// A header-signed `UNSIGNED-PAYLOAD` `PUT` of `target` that declares, and signs, a
/// `Content-Length` of `content_length` but carries only `body`: the head of a large upload, whose
/// answer is decided before its body is read.
fn declared_put(target: &str, content_length: u64, body: &'static [u8]) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(content_length));
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
    let signing = SigningRequest::new(
        &http::Method::PUT,
        path,
        query,
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    )
    .with_wire_content_length(content_length);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(http::Method::PUT).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(Bytes::from_static(body)).expect("a valid request")
}

/// Negative — an upload that declares, and signs, one byte past 5 GiB is `400 EntityTooLarge`
/// with legacy RustFS's sentence before any body byte is read, for `PutObject` and `UploadPart`
/// alike.
#[tokio::test]
async fn n_an_upload_declared_past_five_gibibytes_is_legacy_entity_too_large() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let created = exchange(&service, as_main(http::Method::POST, "/refusals/parts?uploads", Bytes::new())).await;
    let listing = body_of(&created);
    let upload_id = element(&listing, "UploadId").expect("an upload id").to_owned();
    for target in [
        "/refusals/huge".to_owned(),
        format!("/refusals/parts?partNumber=1&uploadId={upload_id}"),
    ] {
        let request = declared_put(&target, FIVE_GIB + 1, b"only a few bytes of it");
        assert_eq!(
            request
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some((FIVE_GIB + 1).to_string().as_str()),
            "the declared length is the signed one"
        );
        assert_answer(&exchange(&service, request).await, 400, "EntityTooLarge", UPLOAD_TOO_LARGE);
    }
    assert_absent(&service, "/refusals/huge").await;
}

/// Negative — a refusal of any other code keeps the gateway's own sentence: an unauthenticated
/// signature is still `403 SignatureDoesNotMatch`, and its message is not one of legacy RustFS's
/// body sentences.
#[tokio::test]
async fn n_a_refusal_of_another_code_keeps_its_sentence() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    let forged = signed(ALT_KEY, MAIN_SECRET, http::Method::PUT, "/refusals/forged", Bytes::from_static(b"x"), &[]);
    let refused = exchange(&service, forged).await;
    let body = body_of(&refused);
    assert_eq!(refused.status(), 403, "{body}");
    for sentence in [BAD_DIGEST, INCOMPLETE_BODY, UPLOAD_TOO_LARGE] {
        assert_ne!(element(&body, "Message"), Some(sentence), "{body}");
    }
}
