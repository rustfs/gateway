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

//! A body sent to an operation that takes none, as the RustFS-profile launcher answers it
//! (rustfs/gateway#1173).
//!
//! Responsible for: legacy RustFS's answers to a read, a delete, a copy and a multipart creation
//! carrying a body — each answered as without one, the body never polled, whatever it declares —
//! and what each leaves in storage; and the controls that an upload and a buffered write are still
//! read and refused as before, and a bad signature still refused.
//! NOT responsible for: the switch's mechanics (`rustfs-gateway`'s `tests/bodyless_bodies.rs`) or
//! draining the body behind the answer (the embedding host).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.
//!
//! Legacy behaviour, observed against a legacy RustFS build (rustfs/rustfs `3268c42e00`): a
//! `GetObject`, `DeleteObject`, `CopyObject` or `CreateMultipartUpload` carrying a body answers
//! `200`/`204` as without one; a `GetObject` declaring 100 MiB answers `200` after 64 KiB arrived;
//! a `Content-MD5` that is not base64 on a `GetObject`, and one contradicting the body of a
//! `CopyObject`, are both served, and the copy stores the source's bytes.

use super::*;

/// A body that counts how many of its bytes were ever polled, and whose length the transport does
/// not know.
pub(super) struct Counted {
    bytes: Option<Bytes>,
    polled: Arc<AtomicU64>,
}

impl Counted {
    /// `bytes` as one frame, and the counter of what was polled.
    pub(super) fn new(bytes: Bytes) -> (Self, Arc<AtomicU64>) {
        let polled = Arc::new(AtomicU64::new(0));
        let body = Self {
            bytes: Some(bytes),
            polled: Arc::clone(&polled),
        };
        (body, polled)
    }
}

impl http_body::Body for Counted {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        _context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        core::task::Poll::Ready(this.bytes.take().map(|bytes| {
            this.polled.fetch_add(bytes.len() as u64, Ordering::SeqCst);
            Ok(http_body::Frame::data(bytes))
        }))
    }
}

/// A request as the main identity, header-signed over `UNSIGNED-PAYLOAD` with `extra` headers
/// signed too, declaring `length` and carrying `body` as a [`Counted`] body; the counter is
/// returned beside it. `secret` signs it, so a wrong one makes a request whose signature fails.
fn unsigned_as(
    secret: &str,
    method: http::Method,
    target: &str,
    extra: &[(&str, &str)],
    length: u64,
    body: Bytes,
) -> (http::Request<Counted>, Arc<AtomicU64>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).expect("a valid header name"),
            http::HeaderValue::from_str(value).expect("a valid header value"),
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
    let credentials = SigningCredentials::new(MAIN_KEY, secret.as_bytes()).expect("valid signing credentials");
    let signing = SigningRequest::new(
        &method,
        path,
        query,
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    )
    .with_wire_content_length(length);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(method).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    let (body, polled) = Counted::new(body);
    let request = request
        .header(http::header::CONTENT_LENGTH, length)
        .body(body)
        .expect("a valid request");
    (request, polled)
}

fn unsigned(
    method: http::Method,
    target: &str,
    extra: &[(&str, &str)],
    length: u64,
    body: Bytes,
) -> (http::Request<Counted>, Arc<AtomicU64>) {
    unsigned_as(MAIN_SECRET, method, target, extra, length, body)
}

pub(super) async fn answer(service: &S3Service, request: http::Request<Counted>) -> WireResponse {
    collect(service.call(request).await).await.expect("a finite response")
}

/// A well-formed `Content-MD5` (sixteen zero bytes) that no body below hashes to.
const WRONG_MD5: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

const STORED: &[u8] = b"the stored object";

/// A service with bucket `bodies` holding `k` = [`STORED`].
async fn with_object(root: &TestRoot) -> S3Service {
    let (_backend, service) = assembled(&two_identity_options(root, &[]));
    let created = exchange(&service, as_main(http::Method::PUT, "/bodies", Bytes::new())).await;
    assert_eq!(created.status(), 200, "{}", body_of(&created));
    let stored = exchange(&service, as_main(http::Method::PUT, "/bodies/k", Bytes::from_static(STORED))).await;
    assert_eq!(stored.status(), 200, "{}", body_of(&stored));
    service
}

async fn read(service: &S3Service, target: &str) -> WireResponse {
    exchange(service, as_main(http::Method::GET, target, Bytes::new())).await
}

/// Positive — a read carrying a body is answered with the object, and no byte of the body is
/// polled.
#[tokio::test]
async fn a_read_carrying_a_body_is_answered_without_reading_it() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (request, polled) = unsigned(http::Method::GET, "/bodies/k", &[], 4096, Bytes::from(vec![b'x'; 4096]));
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    assert_eq!(response.body().as_ref(), STORED);
    assert_eq!(polled.load(Ordering::SeqCst), 0, "the body of a read was polled");
}

/// Positive — a read declaring a body far past the buffered ceiling is answered with the object,
/// as legacy RustFS answers it after the first 64 KiB, instead of `413`.
#[tokio::test]
async fn a_read_declaring_a_body_past_the_buffered_ceiling_is_answered() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (request, polled) = unsigned(http::Method::GET, "/bodies/k", &[], 100 * 1024 * 1024, Bytes::from(vec![b'x'; 64 * 1024]));
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    assert_eq!(response.body().as_ref(), STORED);
    assert_eq!(polled.load(Ordering::SeqCst), 0);
}

/// Positive — a read whose `Content-MD5` is not base64 at all is answered, as legacy RustFS
/// answers it.
#[tokio::test]
async fn a_read_with_a_malformed_content_md5_is_answered() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (request, _polled) = unsigned(http::Method::GET, "/bodies/k", &[("content-md5", "not base64!")], 0, Bytes::new());
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    assert_eq!(response.body().as_ref(), STORED);
}

/// Positive — a delete carrying a body deletes the object, as legacy RustFS's does.
#[tokio::test]
async fn a_delete_carrying_a_body_deletes() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (request, polled) = unsigned(http::Method::DELETE, "/bodies/k", &[], 5, Bytes::from_static(b"hello"));
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 204, "{}", body_of(&response));
    assert_eq!(polled.load(Ordering::SeqCst), 0);
    assert_eq!(read(&service, "/bodies/k").await.status(), 404, "the delete left the object");
}

/// Positive — a copy carrying a body that contradicts its `Content-MD5` is copied: the target
/// holds exactly the source's bytes, as legacy RustFS stores it.
#[tokio::test]
async fn a_copy_whose_body_contradicts_its_content_md5_is_copied() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (request, polled) = unsigned(
        http::Method::PUT,
        "/bodies/copy",
        &[("x-amz-copy-source", "/bodies/k"), ("content-md5", WRONG_MD5)],
        5,
        Bytes::from_static(b"hello"),
    );
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    assert_eq!(polled.load(Ordering::SeqCst), 0);
    let copied = read(&service, "/bodies/copy").await;
    assert_eq!(copied.status(), 200, "{}", body_of(&copied));
    assert_eq!(copied.body().as_ref(), STORED, "the copy stored other bytes than the source's");
}

/// Positive — a multipart upload created by a request carrying a body is created and listed.
#[tokio::test]
async fn a_multipart_upload_created_with_a_body_is_listed() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (request, polled) = unsigned(http::Method::POST, "/bodies/upload?uploads", &[], 5, Bytes::from_static(b"hello"));
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 200, "{}", body_of(&response));
    assert_eq!(polled.load(Ordering::SeqCst), 0);
    let uploads = read(&service, "/bodies?uploads").await;
    assert_eq!(uploads.status(), 200, "{}", body_of(&uploads));
    assert!(body_of(&uploads).contains("<Key>upload</Key>"), "{}", body_of(&uploads));
}

/// Negative — an upload whose body contradicts its `Content-MD5` is still read and refused
/// `400 BadDigest`, and nothing is stored.
#[tokio::test]
async fn n_an_upload_contradicting_its_content_md5_is_still_refused() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (request, polled) = unsigned(
        http::Method::PUT,
        "/bodies/fresh",
        &[("content-md5", WRONG_MD5)],
        5,
        Bytes::from_static(b"hello"),
    );
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 400, "{}", body_of(&response));
    assert!(body_of(&response).contains("<Code>BadDigest</Code>"), "{}", body_of(&response));
    assert_eq!(polled.load(Ordering::SeqCst), 5, "the upload was not read");
    assert_eq!(read(&service, "/bodies/fresh").await.status(), 404, "the refused upload was stored");
}

/// Negative — a tag set contradicting its `Content-MD5` is still read and refused, and the
/// object's tag set stays empty.
#[tokio::test]
async fn n_a_tag_set_contradicting_its_content_md5_is_still_refused() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let tagging = Bytes::from_static(b"<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>");
    let length = tagging.len() as u64;
    let (request, polled) = unsigned(http::Method::PUT, "/bodies/k?tagging", &[("content-md5", WRONG_MD5)], length, tagging);
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 400, "{}", body_of(&response));
    assert_eq!(polled.load(Ordering::SeqCst), length, "the tag set was not read");
    let tags = read(&service, "/bodies/k?tagging").await;
    assert_eq!(tags.status(), 200, "{}", body_of(&tags));
    assert!(
        !body_of(&tags).contains("<Key>a</Key>"),
        "the refused tag set was stored: {}",
        body_of(&tags)
    );
}

/// Negative — a delete whose signature does not verify is refused `403` and deletes nothing,
/// its body unread.
#[tokio::test]
async fn n_a_delete_with_a_bad_signature_deletes_nothing() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (request, polled) = unsigned_as(
        "not-the-main-secret",
        http::Method::DELETE,
        "/bodies/k",
        &[],
        5,
        Bytes::from_static(b"hello"),
    );
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 403, "{}", body_of(&response));
    assert_eq!(polled.load(Ordering::SeqCst), 0);
    let kept = read(&service, "/bodies/k").await;
    assert_eq!(kept.status(), 200, "a refused delete removed the object");
    assert_eq!(kept.body().as_ref(), STORED);
}

/// Negative — a read whose signature does not verify is refused `403`, its body unread.
#[tokio::test]
async fn n_a_read_with_a_bad_signature_is_refused_unread() {
    let root = TestRoot::new();
    let service = with_object(&root).await;
    let (request, polled) = unsigned_as(
        "not-the-main-secret",
        http::Method::GET,
        "/bodies/k",
        &[],
        4096,
        Bytes::from(vec![b'x'; 4096]),
    );
    let response = answer(&service, request).await;
    assert_eq!(response.status(), 403, "{}", body_of(&response));
    assert_eq!(polled.load(Ordering::SeqCst), 0);
}
