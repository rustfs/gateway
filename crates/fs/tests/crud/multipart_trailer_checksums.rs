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

//! Multipart part checksums that arrive in an `aws-chunked` trailer (rustfs/gateway#929).
//!
//! Responsible for: proving that a part whose checksum is carried by a verified
//! `STREAMING-UNSIGNED-PAYLOAD-TRAILER` trailer is accepted, reported and combined into the
//! composite object checksum exactly like one whose checksum is a header, and that every way the
//! trailer can disagree with the body or the negotiated upload is still refused with no part stored.
//! NOT responsible for: header-carried part checksums (`multipart_checksums.rs`), chunk grammar
//! (`rustfs-gateway-http`'s ingest suites), or signed chunk chains.
//! Upstream: the filesystem multipart authority, reached through the signed production service.
//! Downstream: the crate verification gate.

use rustfs_gateway::sig::TrailerSet;
use rustfs_gateway::{ChecksumAlgorithm, ChecksumSpec};

use super::multipart_checksums::{
    checksum, complete_checksum, completion_with_checksum, error_code, initiate_checksum, put_checksum_part,
};
use super::*;

/// What the `aws-chunked` body carries after its zero-length chunk.
enum Trailer<'a> {
    /// One `name:value` trailer field — what aws-sdk-java-v2 sends for every part.
    Field(&'a str, &'a str),
    /// The terminating empty line and nothing before it: the declared trailer never arrives.
    Absent,
}

/// An unsigned-payload trailer `UploadPart`, shaped as aws-sdk-java-v2's multipart client sends it.
///
/// `declared` is the `x-amz-trailer` value; `extra` adds head fields such as a checksum header.
fn trailer_part_request(
    target: &str,
    body: &[u8],
    declared: &str,
    trailer: &Trailer<'_>,
    extra: &[(&'static str, &str)],
) -> http::Request<Bytes> {
    let mut wire = format!("{:x}\r\n", body.len()).into_bytes();
    wire.extend_from_slice(body);
    wire.extend_from_slice(b"\r\n0\r\n");
    if let Trailer::Field(name, value) = trailer {
        wire.extend_from_slice(format!("{name}:{value}\r\n").as_bytes());
    }
    wire.extend_from_slice(b"\r\n");
    let wire = Bytes::from(wire);

    let method = http::Method::PUT;
    let (path, query) = target.split_once('?').expect("an UploadPart target carries a query");
    let payload = PayloadMode::StreamingUnsigned {
        trailer: TrailerSet::None,
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::CONTENT_ENCODING, http::HeaderValue::from_static("aws-chunked"));
    headers.insert(
        http::HeaderName::from_static("x-amz-content-sha256"),
        http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("a payload token"),
    );
    headers.insert(
        http::HeaderName::from_static("x-amz-decoded-content-length"),
        http::HeaderValue::from_str(&body.len().to_string()).expect("a decoded length"),
    );
    headers.insert(
        http::HeaderName::from_static("x-amz-trailer"),
        http::HeaderValue::from_str(declared).expect("a trailer declaration"),
    );
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&wire.len().to_string()).expect("a wire length"),
    );
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_str(value).expect("a fixture header"),
        );
    }
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid host probe");
    let accepted = WireRequest::accept(probe, &Limits::default()).expect("an acceptable host");
    let stamp = AmzDate::parse(SIGNED_AT).expect("a valid signing stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a valid signing scope");
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid signing credentials");
    let signing = SigningRequest::new(&method, path, query, &headers, accepted.host().raw_for_signing(), payload, stamp)
        .with_wire_content_length(wire.len() as u64)
        .with_decoded_content_length(body.len() as u64);
    let mut signer = SigV4Signer::new(credentials, scope);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(wire).expect("a valid signed request")
}

async fn put_trailer_part(
    service: &S3Service,
    target: &str,
    body: &[u8],
    declared: &str,
    trailer: &Trailer<'_>,
    extra: &[(&'static str, &str)],
) -> rustfs_gateway::WireResponse {
    exchange(service, trailer_part_request(target, body, declared, trailer, extra)).await
}

async fn composite_upload(service: &S3Service, bucket: &str, algorithm: &str) -> String {
    create_bucket(service, bucket).await;
    let initiated = initiate_checksum(service, bucket, "object", algorithm, "COMPOSITE").await;
    assert_eq!(initiated.status(), 200, "{}", String::from_utf8_lossy(initiated.body()));
    element(initiated.body(), "UploadId").expect("an upload id")
}

fn part_target(bucket: &str, upload_id: &str) -> String {
    format!("/{bucket}/object?partNumber=1&uploadId={upload_id}")
}

/// `ListParts` answers with no `<Part>` when nothing was stored.
async fn assert_no_part_stored(service: &S3Service, bucket: &str, upload_id: &str) {
    let listed = exchange(
        service,
        signed(http::Method::GET, &format!("/{bucket}/object?uploadId={upload_id}"), Bytes::new()),
    )
    .await;
    assert_eq!(listed.status(), 200, "{}", String::from_utf8_lossy(listed.body()));
    assert_eq!(element(listed.body(), "PartNumber"), None, "{}", String::from_utf8_lossy(listed.body()));
}

fn message(response: &rustfs_gateway::WireResponse) -> Option<String> {
    element(response.body(), "Message")
}

fn crc32(bytes: &[u8]) -> ChecksumSpec {
    checksum(ChecksumAlgorithm::Crc32, bytes)
}

/// Positive — the aws-sdk-java-v2 shape: a trailer CRC32 satisfies a composite CRC32 upload, is
/// reported on the part, and is combined into the composite checksum at completion.
#[tokio::test]
async fn a_verified_trailer_checksum_is_a_part_checksum_of_a_composite_upload() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let upload_id = composite_upload(&service, "trailer-composite", "CRC32").await;
    let part = crc32(b"trailer-part");
    let uploaded = put_trailer_part(
        &service,
        &part_target("trailer-composite", &upload_id),
        b"trailer-part",
        "x-amz-checksum-crc32",
        &Trailer::Field("x-amz-checksum-crc32", part.render_base64()),
        &[("x-amz-sdk-checksum-algorithm", "CRC32")],
    )
    .await;
    assert_eq!(uploaded.status(), 200, "{}", String::from_utf8_lossy(uploaded.body()));
    assert_eq!(
        header(&uploaded, "x-amz-checksum-crc32"),
        Some(&http::HeaderValue::from_str(part.render_base64()).expect("a checksum header"))
    );
    let etag = header(&uploaded, "etag")
        .expect("an entity tag")
        .to_str()
        .expect("an ASCII tag");
    let completed = complete_checksum(
        &service,
        "trailer-composite",
        "object",
        &upload_id,
        completion_with_checksum(1, etag, ChecksumAlgorithm::Crc32, part.render_base64()),
    )
    .await;
    assert_eq!(completed.status(), 200, "{}", String::from_utf8_lossy(completed.body()));
    let composite = ChecksumSpec::composite_of(&[part]).expect("one part has a composite checksum");
    assert_eq!(element(completed.body(), "ChecksumCRC32").as_deref(), Some(composite.render_base64()));
    assert_eq!(element(completed.body(), "ChecksumType").as_deref(), Some("COMPOSITE"));
    let object = exchange(&service, signed(http::Method::GET, "/trailer-composite/object", Bytes::new())).await;
    assert_eq!(object.status(), 200);
    assert_eq!(object.body().as_ref(), b"trailer-part");
}

/// Negative — a trailer value that disagrees with the body is refused, stores nothing, and the
/// upload stays usable for the retry with the right value.
#[tokio::test]
async fn a_wrong_trailer_checksum_is_refused_and_stores_no_part() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let upload_id = composite_upload(&service, "trailer-wrong", "CRC32").await;
    let target = part_target("trailer-wrong", &upload_id);
    let wrong = crc32(b"other-bytes");
    let refused = put_trailer_part(
        &service,
        &target,
        b"trailer-part",
        "x-amz-checksum-crc32",
        &Trailer::Field("x-amz-checksum-crc32", wrong.render_base64()),
        &[],
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("XAmzContentChecksumMismatch"));
    assert_no_part_stored(&service, "trailer-wrong", &upload_id).await;

    let right = crc32(b"trailer-part");
    let retried = put_trailer_part(
        &service,
        &target,
        b"trailer-part",
        "x-amz-checksum-crc32",
        &Trailer::Field("x-amz-checksum-crc32", right.render_base64()),
        &[],
    )
    .await;
    assert_eq!(retried.status(), 200, "{}", String::from_utf8_lossy(retried.body()));
}

/// Negative — a correct trailer under another algorithm cannot satisfy the negotiated upload,
/// exactly as the same value in a header cannot.
#[tokio::test]
async fn a_trailer_checksum_under_another_algorithm_is_refused_like_a_header() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let upload_id = composite_upload(&service, "trailer-algorithm", "CRC32").await;
    let target = part_target("trailer-algorithm", &upload_id);
    let crc32c = checksum(ChecksumAlgorithm::Crc32c, b"trailer-part");
    let refused = put_trailer_part(
        &service,
        &target,
        b"trailer-part",
        "x-amz-checksum-crc32c",
        &Trailer::Field("x-amz-checksum-crc32c", crc32c.render_base64()),
        &[],
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidRequest"));
    assert_eq!(
        message(&refused).as_deref(),
        Some("the part checksum algorithm differs from the initiated upload")
    );
    assert_no_part_stored(&service, "trailer-algorithm", &upload_id).await;

    let header = put_checksum_part(&service, "trailer-algorithm", "object", &upload_id, 1, crc32c, b"trailer-part").await;
    assert_eq!(header.status(), 400, "{}", String::from_utf8_lossy(header.body()));
    assert_eq!(error_code(&header).as_deref(), Some("InvalidRequest"));
    assert_eq!(message(&header), message(&refused));
}

/// Negative — a declared trailer that never arrives is refused, so no part reaches a composite
/// upload without its checksum.
#[tokio::test]
async fn a_declared_trailer_that_never_arrives_is_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let upload_id = composite_upload(&service, "trailer-absent", "CRC32").await;
    let refused = put_trailer_part(
        &service,
        &part_target("trailer-absent", &upload_id),
        b"trailer-part",
        "x-amz-checksum-crc32",
        &Trailer::Absent,
        &[],
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidRequest"));
    // The chunk parser holds the trailer section to the declared set, so the refusal is the
    // framing's own, before any checksum rule is consulted.
    assert_eq!(
        message(&refused).as_deref(),
        Some("The chunked encoding of the request body is not one this service can read.")
    );
    assert_no_part_stored(&service, "trailer-absent", &upload_id).await;
}

/// Negative — a checksum header beside a checksum trailer is one claim too many, whichever agrees.
#[tokio::test]
async fn a_checksum_header_beside_a_checksum_trailer_is_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let upload_id = composite_upload(&service, "trailer-both", "CRC32").await;
    let part = crc32(b"trailer-part");
    let refused = put_trailer_part(
        &service,
        &part_target("trailer-both", &upload_id),
        b"trailer-part",
        "x-amz-checksum-crc32",
        &Trailer::Field("x-amz-checksum-crc32", part.render_base64()),
        &[("x-amz-checksum-crc32", part.render_base64())],
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidRequest"));
    assert_eq!(
        message(&refused).as_deref(),
        Some("A checksum cannot be supplied in both the request headers and trailer")
    );
    assert_no_part_stored(&service, "trailer-both", &upload_id).await;
}

/// Negative — a malformed trailer value is refused rather than read as "no checksum".
#[tokio::test]
async fn a_malformed_trailer_checksum_is_refused() {
    let root = TestRoot::new();
    let (_, service) = service(&root);
    let upload_id = composite_upload(&service, "trailer-malformed", "CRC32").await;
    let refused = put_trailer_part(
        &service,
        &part_target("trailer-malformed", &upload_id),
        b"trailer-part",
        "x-amz-checksum-crc32",
        &Trailer::Field("x-amz-checksum-crc32", "not-base64!"),
        &[],
    )
    .await;
    assert_eq!(refused.status(), 400, "{}", String::from_utf8_lossy(refused.body()));
    assert_eq!(error_code(&refused).as_deref(), Some("InvalidRequest"));
    assert_eq!(
        message(&refused).as_deref(),
        Some("The checksum value is not valid for the named algorithm")
    );
    assert_no_part_stored(&service, "trailer-malformed", &upload_id).await;
}
