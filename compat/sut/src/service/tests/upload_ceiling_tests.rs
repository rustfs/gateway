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

//! RustFS's single-request ceiling on an upload's object, as the RustFS-profile launcher applies
//! it (rustfs/rustfs#7635, rustfs/gateway#1099).
//!
//! Responsible for: `build_service`'s `rustfs_limits` and upload ceiling — a `PutObject` or
//! `UploadPart` whose object is larger than 5 GiB is `400 EntityTooLarge` before its body is read
//! and stores nothing, and an aws-chunked upload is measured by its decoded length, so one whose
//! framing takes it past 5 GiB on the wire is admitted, as legacy RustFS admits it.
//! NOT responsible for: the ceiling's mechanics or storing an upload at the ceiling byte for byte
//! (`rustfs-gateway`'s `tests/upload_object_ceiling.rs`, with a small ceiling), or the sentence of
//! the refusal (`body_refusal_tests.rs`).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

use rustfs_gateway::sig::TrailerSet;

/// RustFS's single-request ceiling.
const FIVE_GIB: u64 = 5 * 1024 * 1024 * 1024;

/// The chunk size the streaming cases frame their objects in, as the AWS SDKs frame theirs.
const CHUNK: u64 = 64 * 1024;

async fn with_bucket(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/ceiling", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    service
}

/// A `PutObject` target and an `UploadPart` target of a fresh multipart upload.
async fn upload_targets(service: &S3Service, key: &str) -> [String; 2] {
    let created = exchange(
        service,
        as_main(http::Method::POST, &format!("/ceiling/{key}-parts?uploads"), Bytes::new()),
    )
    .await;
    let listing = body_of(&created);
    assert_eq!(created.status(), 200, "{listing}");
    let upload_id = element(&listing, "UploadId").expect("an upload id").to_owned();
    [
        format!("/ceiling/{key}"),
        format!("/ceiling/{key}-parts?partNumber=1&uploadId={upload_id}"),
    ]
}

fn element<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find('<')? + start;
    Some(&body[start..end])
}

/// Legacy RustFS's sentence for an upload past its ceiling (the launcher answers body refusals
/// with legacy's sentences, `answer_body_refusals_with_legacy_rustfs_sentences`).
const UPLOAD_TOO_LARGE: &str = "Request body exceeds the configured maximum object size.";
/// Legacy RustFS's sentence for a body that arrived short.
const INCOMPLETE_BODY: &str = "You did not provide the number of bytes specified by the Content-Length HTTP header.";

/// Holds `response` to `status` and `code`.
fn assert_code(response: &WireResponse, status: u16, code: &str, context: &str) {
    let body = body_of(response);
    assert_eq!(response.status(), status, "{context}: {body}");
    assert_eq!(element(&body, "Code"), Some(code), "{context}: {body}");
}

/// Holds `response` to `status`, `code`, and legacy RustFS's sentence for that code.
fn assert_answer(response: &WireResponse, status: u16, code: &str, sentence: &str, context: &str) {
    assert_code(response, status, code, context);
    let body = body_of(response);
    assert_eq!(element(&body, "Message"), Some(sentence), "{context}: {body}");
}

/// Nothing is stored under `target`: no object for a `PutObject`, no part for an `UploadPart`.
async fn assert_nothing_stored(service: &S3Service, target: &str) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if query.is_empty() {
        let read = exchange(service, as_main(http::Method::GET, path, Bytes::new())).await;
        assert_eq!(read.status(), 404, "{target} was stored: {}", body_of(&read));
    } else {
        let upload_id = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("uploadId="))
            .expect("an upload id");
        let parts = exchange(service, as_main(http::Method::GET, &format!("{path}?uploadId={upload_id}"), Bytes::new())).await;
        let listing = body_of(&parts);
        assert_eq!(parts.status(), 200, "{listing}");
        assert!(!listing.contains("<Part>"), "{target} stored a part: {listing}");
    }
}

/// The signing stamp and scope of a request signed now as the main identity.
fn signer_now() -> (SigV4Signer, AmzDate) {
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
    (SigV4Signer::new(credentials, scope), stamp)
}

fn host() -> WireRequest<Bytes> {
    let probe = http::Request::builder()
        .uri("/")
        .header(http::header::HOST, "s3.example.com")
        .body(Bytes::new())
        .expect("a valid host probe");
    WireRequest::accept(probe, &Limits::default()).expect("an acceptable host")
}

/// A header-signed `UNSIGNED-PAYLOAD` `PUT` of `target` that declares, and signs, a
/// `Content-Length` of `content_length` but carries only its first bytes: the head of a large
/// upload, whose answer is decided before the body is read.
fn declared_put(target: &str, content_length: u64) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(content_length));
    let accepted = host();
    let (mut signer, stamp) = signer_now();
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
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut request = http::Request::builder().method(http::Method::PUT).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request
        .body(Bytes::from_static(b"the first bytes of it"))
        .expect("a valid request")
}

/// The wire length of a `decoded`-byte object in signed aws-chunked framing of [`CHUNK`]-byte
/// chunks: per chunk the hex size, `;chunk-signature=`, 64 hex digits and two CRLFs around the
/// data, then the same for the terminal chunk.
fn signed_framed_length(decoded: u64) -> u64 {
    let frame = |size: u64| format!("{size:x}").len() as u64 + 17 + 64 + 4 + size;
    let full = decoded / CHUNK;
    let rest = decoded % CHUNK;
    full * frame(CHUNK) + if rest > 0 { frame(rest) } else { 0 } + frame(0)
}

/// How HTTP frames the aws-chunked body.
#[derive(Clone, Copy, Debug)]
enum Wire {
    /// `Content-Length` counting every framing byte.
    ContentLength,
    /// `Transfer-Encoding: chunked` with no `Content-Length`, as botocore sends over TLS.
    TransferChunked,
}

/// A correctly signed `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` `PUT` of `target` declaring a `decoded`
/// byte object, framed on the wire as `wire` says, that carries only its first signed chunk.
fn streaming_put(target: &str, decoded: u64, wire: Wire) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let framed = signed_framed_length(decoded);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    if matches!(wire, Wire::ContentLength) {
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(framed));
    }
    let accepted = host();
    let (mut signer, stamp) = signer_now();
    let mut signing = SigningRequest::new(
        &http::Method::PUT,
        path,
        query,
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::StreamingSigned {
            trailer: TrailerSet::None,
        },
        stamp,
    )
    .with_decoded_content_length(decoded);
    if matches!(wire, Wire::ContentLength) {
        signing = signing.with_wire_content_length(framed);
    }
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let first = chain.encode_chunk(&vec![b'x'; usize::try_from(CHUNK).expect("a chunk fits in memory")]);
    let mut request = http::Request::builder().method(http::Method::PUT).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    if matches!(wire, Wire::TransferChunked) {
        request = request.header(http::header::TRANSFER_ENCODING, "chunked");
    }
    request.body(Bytes::from(first)).expect("a valid request")
}

/// Positive — an aws-chunked upload of exactly 5 GiB is admitted although its framing takes it
/// past 5 GiB on the wire: legacy RustFS measures it by its decoded length and stores it. The body
/// here is cut after its first chunk, so the answer is the short body's `IncompleteBody`, not the
/// ceiling's `EntityTooLarge`; nothing is stored.
#[tokio::test]
async fn a_streaming_upload_of_five_gibibytes_is_admitted_although_its_framing_is_longer() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    assert!(signed_framed_length(FIVE_GIB) > FIVE_GIB, "the framing alone takes it past the ceiling");
    for target in upload_targets(&service, "exact").await {
        let answer = exchange(&service, streaming_put(&target, FIVE_GIB, Wire::ContentLength)).await;
        assert_answer(&answer, 400, "IncompleteBody", INCOMPLETE_BODY, &target);
        assert_nothing_stored(&service, &target).await;
    }
}

/// Negative — an aws-chunked upload whose decoded length is one byte past 5 GiB is `400
/// EntityTooLarge` before its body is read, whether HTTP frames it with `Content-Length` or with
/// `Transfer-Encoding: chunked`, for `PutObject` and `UploadPart` alike; nothing is stored.
#[tokio::test]
async fn n_a_streaming_upload_decoded_past_five_gibibytes_is_entity_too_large() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for wire in [Wire::ContentLength, Wire::TransferChunked] {
        for target in upload_targets(&service, &format!("{wire:?}").to_lowercase()).await {
            let answer = exchange(&service, streaming_put(&target, FIVE_GIB + 1, wire)).await;
            assert_answer(&answer, 400, "EntityTooLarge", UPLOAD_TOO_LARGE, &format!("{wire:?} {target}"));
            assert_nothing_stored(&service, &target).await;
        }
    }
}

/// Negative — a plain upload that declares, and signs, a `Content-Length` past 5 GiB is `400
/// EntityTooLarge` before its body is read: one byte past, inside the framing allowance the wire
/// ceiling was widened by, and past that allowance too; nothing is stored.
#[tokio::test]
async fn n_a_plain_upload_declared_past_five_gibibytes_is_entity_too_large() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for (key, declared) in [
        ("one-byte-past", FIVE_GIB + 1),
        ("inside-the-framing-allowance", FIVE_GIB + 100 * 1024 * 1024),
        ("past-the-framing-allowance", 6 * 1024 * 1024 * 1024),
    ] {
        for target in upload_targets(&service, key).await {
            let answer = exchange(&service, declared_put(&target, declared)).await;
            assert_answer(&answer, 400, "EntityTooLarge", UPLOAD_TOO_LARGE, &target);
            assert_nothing_stored(&service, &target).await;
        }
    }
}

/// Positive — a plain upload that declares exactly 5 GiB is admitted, as legacy RustFS admits it:
/// the body here is cut short, so the answer is the short body's `IncompleteBody`, not the
/// ceiling's `EntityTooLarge`; nothing is stored. Only the code is held: an in-process body that
/// ends early is answered by the reference backend's read of it, and the sentence a body cut short
/// on a real socket gets is `rustfs-gateway`'s `tests/body_refusal_sentences.rs`.
#[tokio::test]
async fn a_plain_upload_of_exactly_five_gibibytes_is_admitted() {
    let root = TestRoot::new();
    let service = with_bucket(&root).await;
    for target in upload_targets(&service, "plain-exact").await {
        let answer = exchange(&service, declared_put(&target, FIVE_GIB)).await;
        assert_code(&answer, 400, "IncompleteBody", &target);
        assert_nothing_stored(&service, &target).await;
    }
}
