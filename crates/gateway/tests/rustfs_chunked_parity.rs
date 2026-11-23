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

//! The request-body framing answers of the RustFS profile, byte for byte as RustFS's own
//! negative SigV4 suite sends them, through the whole service.
//!
//! Responsible for: proving that `ServiceBuilder::rustfs_profile` stores the signed and trailer
//! uploads legacy RustFS stores, and answers the malformed ones with legacy RustFS's code — on
//! `PutObject` and `UploadPart` alike — with nothing reaching the backend as complete; and that
//! the default assembly answers each as it did before.
//! NOT responsible for: the decoder's rules (`rustfs-gateway-http`), each switch's unit behaviour
//! (`src/builder/legacy_chunks.rs`), or the RustFS host that assembles the profile.
//! Upstream: `S3Service` with recording `PutObject` and `UploadPart` backends. Downstream: none.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
};
use rustfs_gateway::{ByteStream, Handler, HandlerError, HandlerResult, Req, Resp, S3Service, dto};
use rustfs_gateway_sig::{DeclaredTrailers, TrailerName};
use sha2::{Digest as _, Sha256};

use crate::support;

const OBJECT: &[u8] = b"valid-chunked-control";
const PUT: &str = "/bucket/object";
const PART: &str = "/bucket/object?partNumber=1&uploadId=upload";
const CHECKSUM: &str = "x-amz-checksum-sha256";

/// The bodies a handler read, and the `Content-Length` each `PutObject` handler was shown.
#[derive(Default)]
struct Stored(Mutex<Vec<Vec<u8>>>, Mutex<Vec<i64>>);

struct Backend(Arc<Stored>);

async fn store(stored: &Stored, body: Option<ByteStream>) -> Result<(), HandlerError> {
    let mut body = body
        .ok_or_else(|| HandlerError::internal_error("the upload reached its handler without a body stream"))?
        .into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
        if let Ok(data) = frame.into_data() {
            bytes.extend_from_slice(&data);
        }
    }
    stored.0.lock().expect("the record is never poisoned").push(bytes);
    Ok(())
}

impl Handler<dto::PutObject> for Backend {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let stored = Arc::clone(&self.0);
        let input = request.into_input();
        stored
            .1
            .lock()
            .expect("the record is never poisoned")
            .push(input.content_length);
        let body = input.body;
        async move {
            store(&stored, body).await?;
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

impl Handler<dto::UploadPart> for Backend {
    fn call(&self, request: Req<dto::UploadPart>) -> impl core::future::Future<Output = HandlerResult<dto::UploadPart>> + Send {
        let stored = Arc::clone(&self.0);
        let body = request.into_input().body;
        async move {
            store(&stored, body).await?;
            Ok(Resp::new(dto::UploadPartOutput::default()))
        }
    }
}

fn assembled(profile: bool) -> (S3Service, Arc<Stored>) {
    let stored = Arc::new(Stored::default());
    let backend = Arc::new(Backend(Arc::clone(&stored)));
    let mut builder = support::wired_at_signed_time();
    if profile {
        builder = builder.rustfs_profile();
    }
    let service = builder
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::UploadPart, _>(backend)
        .build()
        .expect("a complete upload assembly");
    (service, stored)
}

/// Standard padded base64.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for group in bytes.chunks(3) {
        let word = group
            .iter()
            .enumerate()
            .fold(0_u32, |acc, (at, byte)| acc | u32::from(*byte) << (16 - 8 * at));
        for index in 0..4 {
            if index <= group.len() {
                out.push(char::from(
                    ALPHABET[usize::try_from((word >> (18 - 6 * index)) & 0x3F).expect("six bits")],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn sha256_base64(data: &[u8]) -> String {
    base64(&Sha256::digest(data))
}

/// The payload mode, and whether it declares `x-amz-checksum-sha256` as its trailer.
#[derive(Clone, Copy)]
enum Mode {
    Signed,
    SignedTrailer,
    UnsignedTrailer,
}

impl Mode {
    fn payload(self) -> PayloadMode {
        let trailer = || {
            TrailerSet::Declared(
                DeclaredTrailers::new([TrailerName::new(CHECKSUM).expect("a trailer name")], false).expect("a declaration"),
            )
        };
        match self {
            Self::Signed => PayloadMode::StreamingSigned {
                trailer: TrailerSet::None,
            },
            Self::SignedTrailer => PayloadMode::StreamingSigned { trailer: trailer() },
            Self::UnsignedTrailer => PayloadMode::StreamingUnsigned { trailer: trailer() },
        }
    }
}

/// A header-signed aws-chunked upload to `target` declaring `decoded` bytes, whose body `frame`
/// writes from the request's chunk-signature chain.
fn upload(
    target: &str,
    mode: Mode,
    decoded: usize,
    frame: impl FnOnce(&mut rustfs_gateway::sig::ChunkSigner) -> Vec<u8>,
) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(http::header::CONTENT_ENCODING, http::HeaderValue::from_static("aws-chunked"));
    if !matches!(mode, Mode::Signed) {
        headers.insert("x-amz-trailer", http::HeaderValue::from_static(CHECKSUM));
    }
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let signing = SigningRequest::new(&http::Method::PUT, path, query, &headers, &host, mode.payload(), stamp)
        .with_decoded_content_length(decoded as u64);
    let mut signer = SigV4Signer::new(credentials, scope);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let body = frame(&mut signer.chunk_signer(&signed).expect("a chunk chain"));
    let mut request = http::Request::builder().method(http::Method::PUT).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(Bytes::from(body))
        .expect("a valid request")
}

/// RustFS's signed framing: the object as one chunk, then `0;chunk-signature=…\r\n\r\n` and, for a
/// trailer mode, the checksum and the trailer signature after that empty line.
fn signed_body(chain: &mut rustfs_gateway::sig::ChunkSigner, trailer: bool) -> Vec<u8> {
    let mut body = chain.encode_chunk(OBJECT);
    body.extend_from_slice(&chain.encode_chunk(b""));
    if trailer {
        let checksum = sha256_base64(OBJECT);
        let signature = chain.sign_trailer(&format!("{CHECKSUM}:{checksum}\n")).to_owned();
        body.extend_from_slice(format!("{CHECKSUM}:{checksum}\r\nx-amz-trailer-signature:{signature}\r\n\r\n").as_bytes());
    }
    body
}

fn code(body: &str) -> Option<&str> {
    support::element_text(body, "Code")
}

/// Sends `request` with its body cut into 64 KiB transport frames, as a socket delivers it.
async fn answer(service: &S3Service, request: http::Request<Bytes>) -> (u16, String) {
    let (parts, body) = request.into_parts();
    let frames: Vec<Result<http_body::Frame<Bytes>, std::convert::Infallible>> = body
        .chunks(64 * 1024)
        .map(|piece| Ok(http_body::Frame::data(Bytes::copy_from_slice(piece))))
        .collect();
    let body = http_body_util::StreamBody::new(futures_util::stream::iter(frames));
    let response = service.call(http::Request::from_parts(parts, body)).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    (collected.status().as_u16(), String::from_utf8_lossy(collected.body()).into_owned())
}

/// Only a timeout marked by the host's client-body timer has the S3 request-timeout contract.
#[tokio::test]
async fn host_body_read_timeout_is_distinct_from_transport_failures() {
    use std::io;

    for target in [PUT, PART] {
        type BodyError = Box<dyn std::error::Error + Send + Sync>;
        let cases: [(BodyError, &str); 4] = [
            (rustfs_gateway::HostBodyReadTimeout.into(), "RequestTimeout"),
            (io::Error::other(rustfs_gateway::HostBodyReadTimeout).into(), "RequestTimeout"),
            (
                io::Error::new(io::ErrorKind::TimedOut, "client body read timed out").into(),
                "IncompleteBody",
            ),
            (io::Error::new(io::ErrorKind::UnexpectedEof, "RequestTimeout").into(), "IncompleteBody"),
        ];
        for (error, expected) in cases {
            let (service, stored) = assembled(true);
            let request = upload(target, Mode::Signed, OBJECT.len(), |chain| signed_body(chain, false));
            let (parts, bytes) = request.into_parts();
            let frames = [Ok(http_body::Frame::data(bytes.slice(..1))), Err(error)];
            let body = http_body_util::StreamBody::new(futures_util::stream::iter(frames));
            let response = service.call(http::Request::from_parts(parts, body)).await;
            let collected = rustfs_gateway::collect(response).await.expect("a gateway error response");
            assert_eq!(collected.status(), http::StatusCode::BAD_REQUEST);
            assert_eq!(code(std::str::from_utf8(collected.body()).unwrap()), Some(expected));
            assert!(stored.0.lock().unwrap().is_empty());
        }
    }
}

// ── signed trailers after an empty line ────────────────────────────────────────────────────

/// Positive — the signed-trailer upload RustFS's suite sends, with an empty line between the
/// terminal chunk and the trailer, is stored on both upload operations.
#[tokio::test]
async fn a_signed_trailer_after_an_empty_line_is_stored_under_the_profile() {
    for target in [PUT, PART] {
        let (service, stored) = assembled(true);
        let request = upload(target, Mode::SignedTrailer, OBJECT.len(), |chain| signed_body(chain, true));
        let (status, body) = answer(&service, request).await;
        assert_eq!(status, 200, "{target}: {body}");
        assert_eq!(*stored.0.lock().expect("not poisoned"), [OBJECT.to_vec()], "{target}");
    }
}

/// Positive — the plain signed upload is stored under the profile and without it.
#[tokio::test]
async fn a_signed_upload_is_stored_with_and_without_the_profile() {
    for profile in [true, false] {
        let (service, stored) = assembled(profile);
        let request = upload(PUT, Mode::Signed, OBJECT.len(), |chain| signed_body(chain, false));
        let (status, body) = answer(&service, request).await;
        assert_eq!(status, 200, "{profile}: {body}");
        assert_eq!(*stored.0.lock().expect("not poisoned"), [OBJECT.to_vec()]);
    }
}

/// Negative — the default assembly reads the empty line as an empty trailer section, which lacks
/// its signature: `403`, nothing stored.
#[tokio::test]
async fn n_the_default_assembly_refuses_a_signed_trailer_after_an_empty_line() {
    let (service, stored) = assembled(false);
    let request = upload(PUT, Mode::SignedTrailer, OBJECT.len(), |chain| signed_body(chain, true));
    let (status, body) = answer(&service, request).await;
    assert_eq!((status, code(&body)), (403, Some("SignatureDoesNotMatch")), "{body}");
    assert!(stored.0.lock().expect("not poisoned").iter().all(|bytes| bytes != OBJECT));
}

/// Negative — under the profile a second empty line is still refused, and nothing is stored.
#[tokio::test]
async fn n_two_empty_lines_before_signed_trailers_are_refused_under_the_profile() {
    let (service, stored) = assembled(true);
    let request = upload(PUT, Mode::SignedTrailer, OBJECT.len(), |chain| {
        let mut body = chain.encode_chunk(OBJECT);
        body.extend_from_slice(&chain.encode_chunk(b""));
        body.extend_from_slice(b"\r\n");
        let checksum = sha256_base64(OBJECT);
        let signature = chain.sign_trailer(&format!("{CHECKSUM}:{checksum}\n")).to_owned();
        body.extend_from_slice(format!("{CHECKSUM}:{checksum}\r\nx-amz-trailer-signature:{signature}\r\n\r\n").as_bytes());
        body
    });
    let (status, body) = answer(&service, request).await;
    assert_eq!((status, code(&body)), (403, Some("SignatureDoesNotMatch")), "{body}");
    assert!(stored.0.lock().expect("not poisoned").iter().all(|bytes| bytes != OBJECT));
}

/// RustFS's unsigned trailer framing: the object as one chunk, the terminal chunk, `fields` and
/// the empty line that ends them.
fn unsigned_body(empty_line: bool, fields: &str) -> Vec<u8> {
    let mut body = format!("{:x}\r\n", OBJECT.len()).into_bytes();
    body.extend_from_slice(OBJECT);
    body.extend_from_slice(b"\r\n0\r\n");
    if empty_line {
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(fields.as_bytes());
    body.extend_from_slice(b"\r\n");
    body
}

fn checksum_line() -> String {
    format!("{CHECKSUM}:{}\r\n", sha256_base64(OBJECT))
}

/// Positive — legacy RustFS skips the empty line in the unsigned trailer mode too.
#[tokio::test]
async fn an_unsigned_trailer_after_an_empty_line_is_stored_under_the_profile() {
    let (service, stored) = assembled(true);
    let request = upload(PUT, Mode::UnsignedTrailer, OBJECT.len(), |_| unsigned_body(true, &checksum_line()));
    let (status, body) = answer(&service, request).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(*stored.0.lock().expect("not poisoned"), [OBJECT.to_vec()]);
}

// ── legacy RustFS's trailer bounds ─────────────────────────────────────────────────────────

/// RustFS's `trailer-size-limit` section: the checksum and one padding field, 16 KiB with the
/// final CRLF.
fn size_limit_fields(section: usize) -> String {
    let checksum = checksum_line();
    format!("{checksum}x-padding:{}\r\n", "v".repeat(section - checksum.len() - 14))
}

/// RustFS's `trailer-count-limit` section: ninety-nine padding fields and the checksum.
fn count_limit_fields(padding: usize) -> String {
    format!("{}{}", "x-padding:v\r\n".repeat(padding), checksum_line())
}

/// Positive — both of RustFS's trailer-bound uploads are stored on both upload operations.
#[tokio::test]
async fn trailer_sections_at_legacy_rustfs_bounds_are_stored_under_the_profile() {
    for fields in [size_limit_fields(16 * 1024), count_limit_fields(99)] {
        for target in [PUT, PART] {
            let (service, stored) = assembled(true);
            let request = upload(target, Mode::UnsignedTrailer, OBJECT.len(), |_| unsigned_body(false, &fields));
            let (status, body) = answer(&service, request).await;
            assert_eq!(status, 200, "{target}: {body}");
            assert_eq!(*stored.0.lock().expect("not poisoned"), [OBJECT.to_vec()], "{target}");
        }
    }
}

/// Negative — the default assembly refuses both, and stores nothing.
#[tokio::test]
async fn n_the_default_assembly_keeps_its_trailer_bounds() {
    for fields in [size_limit_fields(16 * 1024), count_limit_fields(99)] {
        let (service, stored) = assembled(false);
        let request = upload(PUT, Mode::UnsignedTrailer, OBJECT.len(), |_| unsigned_body(false, &fields));
        let (status, body) = answer(&service, request).await;
        assert_eq!(status, 400, "{body}");
        assert!(stored.0.lock().expect("not poisoned").iter().all(|bytes| bytes != OBJECT));
    }
}

/// Negative — one byte or one field past legacy RustFS's bounds is refused under the profile.
#[tokio::test]
async fn n_trailer_sections_past_legacy_rustfs_bounds_are_refused_under_the_profile() {
    for fields in [size_limit_fields(16 * 1024 + 1), count_limit_fields(100)] {
        let (service, stored) = assembled(true);
        let request = upload(PUT, Mode::UnsignedTrailer, OBJECT.len(), |_| unsigned_body(false, &fields));
        let (status, body) = answer(&service, request).await;
        assert_eq!(status, 400, "{body}");
        assert!(stored.0.lock().expect("not poisoned").iter().all(|bytes| bytes != OBJECT));
    }
}

// ── a body that does not match its signed x-amz-content-sha256 ─────────────────────────────

/// Legacy RustFS's sentence for `XAmzContentSHA256Mismatch` (rustfs/rustfs `rustfs/src/error.rs:24`).
const SHA256_MISMATCH_SENTENCE: &str = "The provided 'x-amz-content-sha256' header does not match what was computed.";

/// A header-signed upload of `body` whose `x-amz-content-sha256` is the digest of something else.
fn tampered(target: &str, body: Vec<u8>, extra: &[(&str, &str)]) -> http::Request<Bytes> {
    signed_put(target, body, extra, Sha256::digest(b"a different payload").into())
}

/// A header-signed upload of `body` declaring `claimed` as its `x-amz-content-sha256`.
fn signed_put(target: &str, body: Vec<u8>, extra: &[(&str, &str)], claimed: [u8; 32]) -> http::Request<Bytes> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            http::HeaderValue::from_str(value).expect("a header value"),
        );
    }
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let signing = SigningRequest::new(&http::Method::PUT, path, query, &headers, &host, PayloadMode::ExactSha256(claimed), stamp)
        .with_wire_content_length(body.len() as u64);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(http::Method::PUT).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(Bytes::from(body))
        .expect("a valid request")
}

fn message(body: &str) -> Option<String> {
    support::element_text(body, "Message").map(|text| text.replace("&apos;", "'"))
}

/// Positive — every size RustFS's suite sends, with and without a matching `Content-MD5`, on both
/// upload operations: `400 XAmzContentSHA256Mismatch` in RustFS's words, nothing stored.
#[tokio::test]
async fn a_body_that_misses_its_signed_digest_is_answered_as_legacy_rustfs() {
    for size in [0, 24, 2 * 1024 * 1024, 17 * 1024 * 1024] {
        let object = vec![b'a'; size];
        let md5 = base64(&md5_digest(&object));
        for extra in [vec![], vec![("content-md5", md5.as_str())]] {
            for target in [PUT, PART] {
                let (service, stored) = assembled(true);
                let (status, body) = answer(&service, tampered(target, object.clone(), &extra)).await;
                assert_eq!(
                    (status, code(&body), message(&body).as_deref()),
                    (400, Some("XAmzContentSHA256Mismatch"), Some(SHA256_MISMATCH_SENTENCE)),
                    "{size} {target} {extra:?}: {body}"
                );
                assert!(stored.0.lock().expect("not poisoned").is_empty(), "{size} {target}");
            }
        }
    }
}

/// Negative — the default assembly keeps its own code and sentence.
#[tokio::test]
async fn n_the_default_assembly_answers_a_missed_digest_in_its_own_words() {
    for size in [0, 24] {
        let (service, stored) = assembled(false);
        let (status, body) = answer(&service, tampered(PUT, vec![b'a'; size], &[])).await;
        assert_eq!((status, code(&body)), (400, Some("XAmzContentSHA256Mismatch")), "{body}");
        assert_ne!(message(&body).as_deref(), Some(SHA256_MISMATCH_SENTENCE), "{body}");
        assert!(stored.0.lock().expect("not poisoned").is_empty());
    }
}

/// Negative — under the profile a mismatched `x-amz-checksum-*` or `Content-MD5` is still
/// `BadDigest`: only the signed payload digest changed its code.
#[tokio::test]
async fn n_checksum_and_md5_mismatches_stay_bad_digest_under_the_profile() {
    let object = vec![b'a'; 24];
    let wrong_md5 = base64(&md5_digest(b"something else"));
    let wrong_crc = base64(&[0, 0, 0, 0]);
    for (name, value) in [
        ("content-md5", wrong_md5.as_str()),
        ("x-amz-checksum-crc32", wrong_crc.as_str()),
    ] {
        let (service, stored) = assembled(true);
        let request = signed_put(PUT, object.clone(), &[(name, value)], Sha256::digest(&object).into());
        let (status, body) = answer(&service, request).await;
        assert_eq!((status, code(&body)), (400, Some("BadDigest")), "{name}: {body}");
        assert!(stored.0.lock().expect("not poisoned").is_empty(), "{name}");
    }
}

fn md5_digest(data: &[u8]) -> Vec<u8> {
    md5::Md5::digest(data).to_vec()
}

// ── malformed aws-chunked bodies ───────────────────────────────────────────────────────────

const NAMED: &[u8] = b"private-chunked-fixture-body";

/// One of RustFS's `aws_chunked_named_errors_reject_put_and_upload_part` requests, byte for byte:
/// the case, the mode it is signed in, and the body.
fn named_error(target: &str, case: &str) -> http::Request<Bytes> {
    let unsigned = matches!(case, "trailers-over-limit" | "too-many-trailers");
    let mode = if unsigned { Mode::UnsignedTrailer } else { Mode::Signed };
    upload(target, mode, NAMED.len(), |chain| match case {
        "signature" | "final-signature" => {
            let mut body = chain.encode_chunk(NAMED);
            body.extend_from_slice(&chain.encode_chunk(b""));
            let at = if case == "signature" {
                body.windows(2).position(|window| window == b"\r\n").expect("a chunk header") + 2
            } else {
                body.len() - 5
            };
            body[at] = if body[at] == b'a' { b'b' } else { b'a' };
            body
        }
        "format" => b"invalid-chunk-size\r\n".to_vec(),
        "metadata-at-limit" | "metadata-over-limit" => {
            let size = if case == "metadata-at-limit" { 1024 } else { 1025 };
            let mut body = vec![b'z'; size - 2];
            body.extend_from_slice(b"\r\n");
            body
        }
        "chunk-over-limit" => format!("10000001;chunk-signature={}\r\n", "0".repeat(64)).into_bytes(),
        _ => {
            let mut body = format!("{:x}\r\n", NAMED.len()).into_bytes();
            body.extend_from_slice(NAMED);
            body.extend_from_slice(b"\r\n0\r\n");
            if case == "trailers-over-limit" {
                body.extend_from_slice(format!("x-private:{}\r\n\r\n", "v".repeat(16385 - 14)).as_bytes());
            } else {
                body.extend_from_slice("x-private:v\r\n".repeat(101).as_bytes());
                body.extend_from_slice(b"\r\n");
            }
            body
        }
    })
}

const NAMED_ERRORS: [(&str, u16, &str); 8] = [
    ("signature", 403, "SignatureDoesNotMatch"),
    ("final-signature", 403, "SignatureDoesNotMatch"),
    ("format", 400, "IncompleteBody"),
    ("metadata-at-limit", 400, "IncompleteBody"),
    ("metadata-over-limit", 400, "EntityTooLarge"),
    ("chunk-over-limit", 400, "EntityTooLarge"),
    ("trailers-over-limit", 400, "IncompleteBody"),
    ("too-many-trailers", 400, "IncompleteBody"),
];

/// Negative — every malformed body RustFS's suite sends is answered with legacy RustFS's status
/// and code on both upload operations, names nothing private, and stores nothing.
#[tokio::test]
async fn n_malformed_chunked_bodies_are_answered_as_legacy_rustfs_under_the_profile() {
    for (case, expected_status, expected_code) in NAMED_ERRORS {
        for target in [PUT, PART] {
            let (service, stored) = assembled(true);
            let (status, body) = answer(&service, named_error(target, case)).await;
            assert_eq!((status, code(&body)), (expected_status, Some(expected_code)), "{case} {target}: {body}");
            for private in ["private-chunked-fixture-body", "chunk-signature=", "x-private", "ChunkReject"] {
                assert!(!body.contains(private), "{case} {target} exposed {private}: {body}");
            }
            assert!(
                stored.0.lock().expect("not poisoned").iter().all(|bytes| bytes != NAMED),
                "{case} {target}"
            );
        }
    }
}

/// Negative — the default assembly keeps the core's answers: framing refusals `InvalidRequest`, a
/// chunk past its ceiling `InvalidChunkSizeError`, decided from the head where the head decides it.
#[tokio::test]
async fn n_the_default_assembly_keeps_the_cores_chunk_refusals() {
    for (case, expected) in [
        ("format", "InvalidRequest"),
        ("metadata-at-limit", "InvalidRequest"),
        ("metadata-over-limit", "InvalidRequest"),
        ("chunk-over-limit", "InvalidRequest"),
        ("too-many-trailers", "InvalidRequest"),
        ("signature", "SignatureDoesNotMatch"),
    ] {
        let (service, stored) = assembled(false);
        let (_, body) = answer(&service, named_error(PUT, case)).await;
        assert_eq!(code(&body), Some(expected), "{case}: {body}");
        assert!(stored.0.lock().expect("not poisoned").iter().all(|bytes| bytes != NAMED), "{case}");
    }
}

/// Negative — a decoded length the wire cannot carry, read under the profile, is never stored
/// however well-formed the bytes it does carry are.
#[tokio::test]
async fn n_a_body_shorter_than_its_decoded_length_is_never_stored_under_the_profile() {
    let (service, stored) = assembled(true);
    let request = upload(PUT, Mode::Signed, NAMED.len() + 1000, |chain| {
        let mut body = chain.encode_chunk(NAMED);
        body.extend_from_slice(&chain.encode_chunk(b""));
        body
    });
    let (status, body) = answer(&service, request).await;
    assert_eq!((status, code(&body)), (400, Some("IncompleteBody")), "{body}");
    assert!(stored.0.lock().expect("not poisoned").iter().all(|bytes| bytes != NAMED));
    // The wire carries far fewer than 1000 bytes. The head is accepted under the profile, so the
    // handler is shown the declared decoded length, the same verdict the pipeline reached.
    assert_eq!(*stored.1.lock().expect("not poisoned"), [(NAMED.len() + 1000) as i64]);
}
