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

//! An upload with no `Content-Length` whose transport ended it empty, through the whole service
//! (rustfs/rustfs#6849).
//!
//! Responsible for: proving that `ServiceBuilder::accept_empty_uploads_without_content_length`
//! hands such a `PutObject` or `UploadPart` to its handler as a zero-length upload, and that
//! everything else keeps its answer: the default assembly's `411`, a chunked transfer, a body the
//! transport does not know the length of, a length the request carries, and a signed digest the
//! empty body does not match.
//! NOT responsible for: the view reading itself (`rustfs-gateway-core`'s codec tests) or the
//! launcher that turns the switch on (`compat/sut`).
//! Upstream: `S3Service` with recording `PutObject` and `UploadPart` backends. Downstream: none.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::sig::PayloadMode;
use rustfs_gateway::{ByteStream, Handler, HandlerError, HandlerResult, Req, Resp, S3Service, dto};

use crate::support;

#[derive(Default)]
struct Recorded {
    reached: AtomicUsize,
    bodies: Mutex<Vec<(&'static str, i64, Vec<u8>)>>,
}

struct Backend(Arc<Recorded>);

async fn drain(
    recorded: &Recorded,
    operation: &'static str,
    content_length: i64,
    body: Option<ByteStream>,
) -> Result<(), HandlerError> {
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
    recorded
        .bodies
        .lock()
        .expect("the record is never poisoned")
        .push((operation, content_length, bytes));
    Ok(())
}

impl Handler<dto::PutObject> for Backend {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let recorded = Arc::clone(&self.0);
        recorded.reached.fetch_add(1, Ordering::SeqCst);
        let input = request.into_input();
        async move {
            drain(&recorded, "PutObject", input.content_length, input.body).await?;
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

impl Handler<dto::UploadPart> for Backend {
    fn call(&self, request: Req<dto::UploadPart>) -> impl core::future::Future<Output = HandlerResult<dto::UploadPart>> + Send {
        let recorded = Arc::clone(&self.0);
        recorded.reached.fetch_add(1, Ordering::SeqCst);
        let input = request.into_input();
        async move {
            drain(&recorded, "UploadPart", input.content_length, input.body).await?;
            Ok(Resp::new(dto::UploadPartOutput::default()))
        }
    }
}

fn assembled(rustfs_profile: bool) -> (S3Service, Arc<Recorded>) {
    let recorded = Arc::new(Recorded::default());
    let backend = Arc::new(Backend(Arc::clone(&recorded)));
    let mut builder = support::wired_at_signed_time();
    if rustfs_profile {
        builder = builder.accept_empty_uploads_without_content_length();
    }
    let service = builder
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::UploadPart, _>(backend)
        .build()
        .expect("a complete upload assembly");
    (service, recorded)
}

const EMPTY_PUT: &str = "/bucket/object";
const EMPTY_PART: &str = "/bucket/object?partNumber=1&uploadId=upload";

/// A request to `target` signed for `payload`, with no body and neither `Content-Length` nor
/// `Transfer-Encoding` in its head.
fn signed_for(target: &str, payload: PayloadMode) -> http::Request<Bytes> {
    use rustfs_gateway::sig::{AmzDate, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};

    let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    headers.insert(
        http::HeaderName::from_static("x-amz-content-sha256"),
        http::HeaderValue::from_str(payload.canonical_payload_token().as_str()).expect("a payload token"),
    );
    let host = rustfs_gateway_http::RawHost::from_host_header(b"s3.example.com").expect("an acceptable host");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let signing = SigningRequest::new(&http::Method::PUT, path, query, &headers, &host, payload, stamp);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(http::Method::PUT).uri(target);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    let request = request.body(Bytes::new()).expect("a valid request");
    assert!(
        request.headers().get(http::header::CONTENT_LENGTH).is_none(),
        "the fixture carries no length"
    );
    assert!(
        request.headers().get(http::header::TRANSFER_ENCODING).is_none(),
        "the fixture carries no transfer coding"
    );
    request
}

/// A signed upload of nothing: the empty body's digest, or `UNSIGNED-PAYLOAD`.
fn lengthless(target: &str, payload: PayloadMode) -> http::Request<Bytes> {
    use sha2::{Digest as _, Sha256};

    let payload = match payload {
        PayloadMode::Unsigned => PayloadMode::Unsigned,
        _ => PayloadMode::ExactSha256(Sha256::digest(b"").into()),
    };
    let request = signed_for(target, payload.clone());
    let token = request
        .headers()
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    assert_eq!(
        token.as_deref(),
        Some(payload.canonical_payload_token().as_str()),
        "the declared payload is sent"
    );
    request
}

/// Positive — under the switch an empty `PutObject` and `UploadPart` with no `Content-Length`
/// reach their handlers as zero-length uploads, whether the empty body is signed by its digest or
/// declared unsigned.
#[tokio::test]
async fn an_empty_upload_without_content_length_reaches_the_handler_as_zero_length() {
    for payload in [PayloadMode::Empty, PayloadMode::Unsigned] {
        for (target, operation) in [(EMPTY_PUT, "PutObject"), (EMPTY_PART, "UploadPart")] {
            let (service, recorded) = assembled(true);
            let (status, body) = support::exchange(&service, lengthless(target, payload.clone())).await;
            assert_eq!(status, http::StatusCode::OK, "{operation} {payload:?}: {body}");
            let bodies = recorded.bodies.lock().expect("the record is never poisoned");
            assert_eq!(*bodies, [(operation, 0, Vec::new())], "{operation} {payload:?}");
        }
    }
}

/// Negative — the default assembly keeps the AWS answer: `411` naming the member, and no handler.
#[tokio::test]
async fn n_the_default_assembly_still_answers_411_and_reaches_no_handler() {
    for target in [EMPTY_PUT, EMPTY_PART] {
        let (service, recorded) = assembled(false);
        let (status, body) = support::exchange(&service, lengthless(target, PayloadMode::Empty)).await;
        assert_eq!(status, http::StatusCode::LENGTH_REQUIRED, "{target}: {body}");
        assert!(body.contains("<Code>MissingContentLength</Code>"), "{body}");
        assert_eq!(recorded.reached.load(Ordering::SeqCst), 0, "{target}");
    }
}

/// Negative — a chunked transfer is a body whose length is unknown until it ends, so even an empty
/// one is still refused with `411`, as RustFS refuses it.
#[tokio::test]
async fn n_a_chunked_transfer_without_content_length_is_still_411() {
    let (service, recorded) = assembled(true);
    let mut request = lengthless(EMPTY_PUT, PayloadMode::Empty);
    request
        .headers_mut()
        .insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::LENGTH_REQUIRED, "{body}");
    assert_eq!(recorded.reached.load(Ordering::SeqCst), 0);
}

/// A body that reports no exact length, as an HTTP/2 stream still carrying data does.
struct UnknownLength(Option<Bytes>);

impl http_body::Body for UnknownLength {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.0.take().map(|data| Ok(http_body::Frame::data(data))))
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::default()
    }
}

/// Negative — without `Content-Length` a body whose transport has not ended it empty is still
/// refused with `411`: the switch reads nothing into a body that may carry data.
#[tokio::test]
async fn n_a_body_the_transport_has_not_ended_is_still_411() {
    let (service, recorded) = assembled(true);
    let (parts, _) = lengthless(EMPTY_PUT, PayloadMode::Unsigned).into_parts();
    let request = http::Request::from_parts(parts, UnknownLength(Some(Bytes::from_static(b"abc"))));
    let response = service.call(request).await;
    assert_eq!(response.status(), http::StatusCode::LENGTH_REQUIRED);
    assert_eq!(recorded.reached.load(Ordering::SeqCst), 0);
}

/// Negative — a length the request carries is read exactly as sent, and its body stored whole.
#[tokio::test]
async fn n_a_content_length_the_request_carries_is_never_replaced() {
    let (service, recorded) = assembled(true);
    let mut request = support::signed_target_with_body(http::Method::PUT, EMPTY_PUT, Bytes::from_static(b"abc"));
    request
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("3"));
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let bodies = recorded.bodies.lock().expect("the record is never poisoned");
    assert_eq!(*bodies, [("PutObject", 3, b"abc".to_vec())]);
}

/// Negative — an empty body signed for a digest it does not have is refused, and no handler reads
/// it to a clean end: the zero length changes where the body ends, never whether it is verified.
#[tokio::test]
async fn n_an_empty_body_signed_for_other_bytes_is_refused_and_never_completed() {
    use sha2::{Digest as _, Sha256};

    let (service, recorded) = assembled(true);
    let request = signed_for(EMPTY_PUT, PayloadMode::ExactSha256(Sha256::digest(b"abc").into()));
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
    assert!(recorded.bodies.lock().expect("the record is never poisoned").is_empty());
}
