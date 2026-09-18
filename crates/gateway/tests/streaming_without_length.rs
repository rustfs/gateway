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

//! A `PutObject` whose `aws-chunked` body the transport ends, through the whole service.
//!
//! Responsible for: the service-level answers of rustfs/gateway#750 — a streaming upload under
//! `Transfer-Encoding: chunked` or HTTP/2 without `Content-Length` (botocore's trailer upload over
//! TLS) is accepted and handed to the handler with `ContentLength` equal to its decoded length; a
//! decoded count that differs from the declaration is refused; and a plain body with no length is
//! still `411`. Also that a framed body carrying `Content-Length` hands the handler the decoded
//! length rather than the wire length, which counts the chunk framing too. And rustfs/gateway#813:
//! the `aws-chunked` token in a framed upload's `Content-Encoding` names the framing, not the
//! object, so the handler reads the header without it.
//! NOT responsible for: the head rules (`crates/http/tests/ingest_framing.rs`), the chunk grammar
//! (`ingest_chunk_rules`), or a framed head without a decoded length, which no signer produces
//! and `crates/gateway/src/chunked.rs` refuses at `ChunkIngest::prepare`.
//! Upstream: `S3Service` with a recording `PutObject` backend. Downstream: none.

use crate::support;

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::sig::{
    AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, TrailerSet,
};
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp, S3Service, dto};

const TARGET: &str = "/bucket/object";

/// Small enough that every object below spans several chunks.
const CHUNK: usize = 8;

/// What the handler saw, one entry per call that read its body to the end.
#[derive(Default)]
struct Recorded {
    content_lengths: Vec<i64>,
    content_encodings: Vec<Option<String>>,
    bodies: Vec<Vec<u8>>,
}

struct Backend(Arc<Mutex<Recorded>>);

impl Handler<dto::PutObject> for Backend {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let recorded = Arc::clone(&self.0);
        let input = request.into_input();
        let content_length = input.content_length;
        let content_encoding = input.content_encoding.clone();
        let body = input.body;
        async move {
            let mut body = body
                .ok_or_else(|| HandlerError::internal_error("PutObject reached its handler without a body stream"))?
                .into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
                if let Ok(data) = frame.into_data() {
                    bytes.extend_from_slice(&data);
                }
            }
            let mut recorded = recorded.lock().expect("the record is never poisoned");
            recorded.content_lengths.push(content_length);
            recorded.content_encodings.push(content_encoding);
            recorded.bodies.push(bytes);
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
}

fn service() -> (S3Service, Arc<Mutex<Recorded>>) {
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let service = support::wired_at_signed_time()
        .register::<dto::PutObject, _>(Arc::new(Backend(Arc::clone(&recorded))))
        .build()
        .expect("a complete PutObject assembly");
    (service, recorded)
}

/// How HTTP frames the wire body around the `aws-chunked` one.
#[derive(Clone, Copy)]
enum Wire {
    /// `Transfer-Encoding: chunked`, no `Content-Length`: what botocore sends over TLS.
    TransferChunked,
    /// HTTP/2 with no `Content-Length`: the stream ends the body.
    Http2,
    /// `Content-Length` counting every framing byte, as the other SDKs send.
    ContentLength,
}

/// The wire length of `object` in signed framing: per chunk the hex size, the 17-byte
/// `;chunk-signature=` extension, 64 hex digits and two CRLFs; then the same for the terminal chunk.
fn signed_wire_length(object: &[u8]) -> usize {
    let data: usize = object
        .chunks(CHUNK)
        .map(|chunk| format!("{:x}", chunk.len()).len() + 17 + 64 + 4 + chunk.len())
        .sum();
    data + 1 + 17 + 64 + 4
}

/// A correctly signed `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` upload of `object` that declares
/// `declared` decoded bytes, framed on the wire as `wire` says.
fn streaming_put(object: &[u8], declared: u64, wire: Wire) -> http::Request<Bytes> {
    streaming_put_encoded(object, declared, wire, None)
}

/// [`streaming_put`] with a signed `Content-Encoding` header, as an SDK that also declares the
/// framing there sends it.
fn streaming_put_encoded(object: &[u8], declared: u64, wire: Wire, content_encoding: Option<&str>) -> http::Request<Bytes> {
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);

    let probe = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("an acceptable host");

    let wire_length = signed_wire_length(object);
    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    if matches!(wire, Wire::ContentLength) {
        map.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(wire_length));
    }
    if let Some(encoding) = content_encoding {
        map.insert(
            http::header::CONTENT_ENCODING,
            http::HeaderValue::from_str(encoding).expect("a valid header value"),
        );
    }
    let method = http::Method::PUT;
    let mut signing = SigningRequest::new(
        &method,
        TARGET,
        "",
        &map,
        accepted.host().raw_for_signing(),
        PayloadMode::StreamingSigned {
            trailer: TrailerSet::None,
        },
        stamp,
    )
    .with_decoded_content_length(declared);
    if matches!(wire, Wire::ContentLength) {
        signing = signing.with_wire_content_length(wire_length as u64);
    }
    let signed = signer.sign_headers(&signing).expect("a signable request");

    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let mut body = Vec::with_capacity(wire_length);
    for chunk in object.chunks(CHUNK) {
        body.extend_from_slice(&chain.encode_chunk(chunk));
    }
    body.extend_from_slice(&chain.encode_chunk(b""));
    assert_eq!(body.len(), wire_length, "the framing arithmetic above is the one the signer used");

    let mut builder = http::Request::builder().method(http::Method::PUT).uri(TARGET);
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder = match wire {
        Wire::TransferChunked => builder.header(http::header::TRANSFER_ENCODING, "chunked"),
        Wire::Http2 => builder.version(http::Version::HTTP_2),
        Wire::ContentLength => builder,
    };
    builder.body(Bytes::from(body)).expect("a valid request")
}

fn object() -> Vec<u8> {
    (0..45_u8).collect()
}

/// Positive — botocore's shape: `Transfer-Encoding: chunked`, `aws-chunked`, a decoded length, no
/// `Content-Length`. Accepted, and the handler reads the object's own length and bytes.
#[tokio::test]
async fn a_streaming_upload_under_transfer_encoding_chunked_is_accepted_with_its_decoded_length() {
    let (service, recorded) = service();
    let object = object();
    let (status, body) = support::exchange(&service, streaming_put(&object, object.len() as u64, Wire::TransferChunked)).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let recorded = recorded.lock().expect("the record is never poisoned");
    assert_eq!(recorded.content_lengths, [object.len() as i64]);
    assert_eq!(recorded.bodies, [object]);
}

/// Positive — the same body on HTTP/2 without `Content-Length`.
#[tokio::test]
async fn a_streaming_upload_on_http2_without_content_length_is_accepted_with_its_decoded_length() {
    let (service, recorded) = service();
    let object = object();
    let (status, body) = support::exchange(&service, streaming_put(&object, object.len() as u64, Wire::Http2)).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let recorded = recorded.lock().expect("the record is never poisoned");
    assert_eq!(recorded.content_lengths, [object.len() as i64]);
    assert_eq!(recorded.bodies, [object]);
}

/// Negative — `Content-Encoding: gzip, aws-chunked` reaches the handler as `gzip`: the framing
/// token is the ingest layer's and would otherwise be stored and served back, telling a reader to
/// un-chunk a body that is not chunked (rustfs/gateway#813). The body is still decoded whole.
#[tokio::test]
async fn n_the_aws_chunked_token_is_removed_from_a_framed_uploads_content_encoding() {
    let (service, recorded) = service();
    let object = object();
    let request = streaming_put_encoded(&object, object.len() as u64, Wire::ContentLength, Some("gzip, aws-chunked"));
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let recorded = recorded.lock().expect("the record is never poisoned");
    assert_eq!(recorded.content_encodings, [Some("gzip".to_owned())]);
    assert_eq!(recorded.bodies, [object]);
}

/// Negative — `Content-Encoding: aws-chunked` alone names no encoding of the object at all, so the
/// handler reads no `Content-Encoding`; and a real encoding without the token is kept as sent.
#[tokio::test]
async fn n_an_aws_chunked_only_content_encoding_reaches_the_handler_as_absent() {
    let (service, recorded) = service();
    let object = object();
    let framed_only = streaming_put_encoded(&object, object.len() as u64, Wire::TransferChunked, Some("aws-chunked"));
    let (status, body) = support::exchange(&service, framed_only).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let plain = streaming_put_encoded(&object, object.len() as u64, Wire::TransferChunked, Some("gzip"));
    let (status, body) = support::exchange(&service, plain).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let recorded = recorded.lock().expect("the record is never poisoned");
    assert_eq!(recorded.content_encodings, [None, Some("gzip".to_owned())]);
}

/// Positive — with `Content-Length` present the handler still reads the decoded length. The wire
/// length counts every chunk header and signature; the object is the 45 bytes inside them.
#[tokio::test]
async fn a_streaming_upload_with_content_length_hands_the_handler_the_decoded_length() {
    let (service, recorded) = service();
    let object = object();
    let (status, body) = support::exchange(&service, streaming_put(&object, object.len() as u64, Wire::ContentLength)).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let recorded = recorded.lock().expect("the record is never poisoned");
    assert_ne!(
        signed_wire_length(&object),
        object.len(),
        "the two lengths differ, so the assertion can tell them apart"
    );
    assert_eq!(recorded.content_lengths, [object.len() as i64]);
}

/// Negative — without a wire length the decoded length is the only ceiling: one byte more than it
/// declares is refused, and the handler never sees a complete body.
#[tokio::test]
async fn a_transport_delimited_upload_longer_than_its_decoded_length_is_refused() {
    for wire in [Wire::TransferChunked, Wire::Http2] {
        let (service, recorded) = service();
        let object = object();
        let (status, body) = support::exchange(&service, streaming_put(&object, object.len() as u64 - 1, wire)).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("<Code>IncompleteBody</Code>"), "{body}");
        assert!(recorded.lock().expect("the record is never poisoned").bodies.is_empty());
    }
}

/// Negative — and one byte fewer than it declares is refused rather than stored short.
#[tokio::test]
async fn a_transport_delimited_upload_shorter_than_its_decoded_length_is_refused() {
    for wire in [Wire::TransferChunked, Wire::Http2] {
        let (service, recorded) = service();
        let object = object();
        let (status, body) = support::exchange(&service, streaming_put(&object, object.len() as u64 + 1, wire)).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("<Code>IncompleteBody</Code>"), "{body}");
        assert!(recorded.lock().expect("the record is never poisoned").bodies.is_empty());
    }
}

/// Negative — a plain, non-streaming body with no `Content-Length` is still `411
/// MissingContentLength`, whether HTTP chunks it or not. Chunked transfer is not a length, and only
/// an `aws-chunked` body states one another way.
#[tokio::test]
async fn a_plain_upload_without_content_length_is_still_411() {
    for chunked in [true, false] {
        let (service, recorded) = service();
        let mut request = support::signed_target_with_body(http::Method::PUT, TARGET, Bytes::from_static(b"hello"));
        assert!(request.headers().get(http::header::CONTENT_LENGTH).is_none());
        if chunked {
            request
                .headers_mut()
                .insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
        }
        let (status, body) = support::exchange(&service, request).await;
        assert_eq!(status, http::StatusCode::LENGTH_REQUIRED, "chunked={chunked}: {body}");
        assert!(body.contains("<Code>MissingContentLength</Code>"), "{body}");
        assert!(recorded.lock().expect("the record is never poisoned").bodies.is_empty());
    }
}
