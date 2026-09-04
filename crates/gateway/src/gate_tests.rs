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

//! What the bounded body read does, asserted where the ceilings and the deadlines are enforced.
//!
//! Responsible for: [`super::SealedBody::read`]'s two ceilings, its two idle deadlines, the
//! per-operation body cap table, the bound on frames that carry no payload, and the framed path's
//! refusal codes.
//! NOT responsible for: the framing rules themselves (`rustfs_gateway_http::ingest` owns them), or
//! what a request does to the assembled pipeline (`crates/gateway/tests/`).
//! Upstream: `super`, plus `rustfs-gateway-server` for the cases that need a real socket.
//! Downstream: Cargo's test harness.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use core::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustfs_gateway_server::{RunningServer, Server, ServerConfig, ShutdownReport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::*;

fn body_timeout_server(timeouts: BodyTimeouts) -> (RunningServer, Arc<AtomicUsize>) {
    let reached = Arc::new(AtomicUsize::new(0));
    let service_reached = Arc::clone(&reached);
    let service = tower::service_fn(move |request: http::Request<hyper::body::Incoming>| {
        let service_reached = Arc::clone(&service_reached);
        async move {
            let declared_length = request
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok());
            let body = SealedBody::seal(Some(request.into_body()), declared_length);
            let proof = MetadataAdmission::granted_for_test();
            let mut response = match body
                .read(&proof, roomy(), timeouts, None, BodyDigestObligation::None, BodyIntegrity::NONE)
                .await
            {
                Ok(_) => {
                    service_reached.fetch_add(1, Ordering::SeqCst);
                    http::Response::new(rustfs_gateway_stream::Body::from_bytes(Bytes::from_static(b"ok")))
                }
                Err(error) => crate::render::render(&error, &crate::trace::RequestTrace::from_bits(1, 2)),
            };
            crate::adapt::announce_connection_verdict(&mut response);
            let wire = crate::wire::collect(response).await.expect("the fixture response is finite");
            let (status, headers, body, trailers) = wire.into_parts();
            assert!(trailers.is_empty(), "the fixture response has no trailers");
            let mut response = http::Response::builder().status(status);
            for (name, value) in headers {
                response = response.header(name, value);
            }
            Ok::<_, Infallible>(response.body(http_body_util::Full::new(body)).expect("a valid response"))
        }
    });
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout: Duration::from_secs(1),
        ..ServerConfig::default()
    };
    (Server::new(config, service).serve().expect("server starts"), reached)
}

fn raw_head(close: bool) -> Vec<u8> {
    let mut head = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n".to_vec();
    if close {
        head.extend_from_slice(b"Connection: close\r\n");
    }
    head.extend_from_slice(b"\r\n");
    head
}

async fn stop_server(running: RunningServer) {
    assert_eq!(
        running.shutdown.trigger(Duration::from_secs(1)).await,
        ShutdownReport { drained: 0, aborted: 0 }
    );
    assert!(running.task.await.expect("server task joins").is_ok());
}

async fn timeout_response(prefix: &[u8], timeouts: BodyTimeouts) -> (Vec<u8>, Arc<AtomicUsize>) {
    let (running, reached) = body_timeout_server(timeouts);
    let mut stream = TcpStream::connect(running.local_addr).await.expect("connection succeeds");
    stream.write_all(&raw_head(false)).await.expect("head writes");
    stream.write_all(prefix).await.expect("body prefix writes");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_millis(250), stream.read_to_end(&mut response))
        .await
        .expect("the idle deadline closes the socket")
        .expect("response reads to EOF");
    stop_server(running).await;
    (response, reached)
}

/// Positive — the only operation with a declared cap has one, and it is the documented number.
#[test]
fn the_multi_object_delete_body_is_the_one_bounded_body() {
    assert_eq!(declared_body_cap("DeleteObjects"), Some(2 * 1024 * 1024));
    assert_eq!(declared_body_cap("PutObject"), None);
}

/// Negative — an operation name that only looks like the bounded one gets no cap. A prefix or
/// case match here would silently bound `DeleteObject`, which has no body at all.
#[test]
fn a_neighbouring_operation_name_does_not_inherit_the_cap() {
    assert_eq!(declared_body_cap("DeleteObject"), None);
    assert_eq!(declared_body_cap("deleteobjects"), None);
    assert_eq!(declared_body_cap("DeleteObjectsExtra"), None);
}

/// The ceilings a test that is not about ceilings wants.
const fn roomy() -> BodyCeilings {
    BodyCeilings {
        buffered: 1 << 20,
        whole_body: true,
        declared: None,
    }
}

/// Negative — every rejecting verdict yields no proof, so nothing built from one can reach a
/// body. This is the run-time half of what the type does at compile time.
#[test]
fn a_rejected_verdict_mints_no_proof() {
    for error in [
        rustfs_gateway_sig::AuthError::SignatureDoesNotMatch,
        rustfs_gateway_sig::AuthError::InvalidAccessKeyId,
        rustfs_gateway_sig::AuthError::RequestTimeTooSkewed,
        rustfs_gateway_sig::AuthError::AccessDenied,
    ] {
        assert!(MetadataAdmission::of(&Verdict::reject(error)).is_none(), "{error:?}");
    }
}

/// Negative — an absent body is a zero-length body, and a claim about a longer one fails.
///
/// The state this refuses is "there was nothing to compare, so nothing disagreed". The absent
/// body takes its own early return out of `read`, so without a comparison on that path a
/// request declaring the digest of eleven bytes and sending none is answered `200`.
#[tokio::test]
async fn an_absent_body_still_discharges_the_claim_it_carried() {
    let mut map = http::HeaderMap::new();
    // The CRC32 of "hello world", against a body of no bytes at all.
    let (name, value) = ("x-amz-checksum-crc32", "DUoRhQ==");
    map.insert(http::HeaderName::from_static(name), http::HeaderValue::from_static(value));
    let view = rustfs_gateway_http::HeaderView::new(&map);
    let integrity = crate::integrity::resolve(&view, &http::Method::PUT, "PutObject").expect("one well-formed claim");
    let error = SealedBody::<crate::probe::ObservedBody>::seal(None, None)
        .read(
            &MetadataAdmission::granted_for_test(),
            roomy(),
            BodyTimeouts::S3,
            None,
            BodyDigestObligation::None,
            integrity,
        )
        .await
        .expect_err("a claim about eleven bytes is not satisfied by none");
    assert_eq!(error.code(), Some(&ErrorCode::X_AMZ_CONTENT_CHECKSUM_MISMATCH));
}

/// Negative — a body that announces more than the assembly's ceiling is refused before a single
/// frame is polled, so the refusal costs nothing.
#[tokio::test]
async fn an_oversized_declared_body_is_refused_without_being_read() {
    let proof = MetadataAdmission::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"x")]);
    let ceilings = BodyCeilings {
        buffered: 1024,
        whole_body: true,
        declared: None,
    };
    let error = SealedBody::seal(Some(body), Some(1 << 30))
        .read(&proof, ceilings, BodyTimeouts::S3, None, BodyDigestObligation::None, BodyIntegrity::NONE)
        .await
        .expect_err("over the ceiling");
    assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error.code(), Some(&ErrorCode::ENTITY_TOO_LARGE));
    assert_eq!(read.bytes_read(), 0, "not one frame was polled");
}

/// Negative — a body that announces nothing and then exceeds the ceiling is still refused; a
/// limit that only fires on a declared length is one a client removes by not declaring it.
#[tokio::test]
async fn an_undeclared_oversized_body_is_still_refused() {
    let proof = MetadataAdmission::granted_for_test();
    let (body, _) = crate::probe::ObservedBody::new([Bytes::from(vec![0_u8; 4096])]);
    let ceilings = BodyCeilings {
        buffered: 1024,
        whole_body: true,
        declared: None,
    };
    let error = SealedBody::seal(Some(body), None)
        .read(&proof, ceilings, BodyTimeouts::S3, None, BodyDigestObligation::None, BodyIntegrity::NONE)
        .await
        .expect_err("over the ceiling");
    assert_eq!(error.code(), Some(&ErrorCode::ENTITY_TOO_LARGE));
}

/// c-lim-0027 / c-ing-0044. Negative — gzip metadata never enables decompression, and both sides
/// of the body ceiling are decided from the compressed wire size. This complete 96-byte gzip
/// stream expands to 64 KiB; accepting it at 96 and refusing it at 95 distinguishes raw-byte
/// accounting from both expanded-byte accounting and no accounting.
#[tokio::test]
async fn c_ing_0044_c_lim_0027_gzip_wire_bytes_set_the_body_ceiling() {
    const GZIP_STREAM: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xed, 0xc1, 0x01, 0x01, 0x00, 0x00, 0x00, 0x80, 0x90, 0xfe,
        0xaf, 0xee, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0xeb, 0x8e, 0x97, 0xd7, 0x00, 0x00, 0x01, 0x00,
    ];
    const RAW_BYTES: u64 = GZIP_STREAM.len() as u64;

    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::CONTENT_ENCODING, http::HeaderValue::from_static("gzip"));
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&RAW_BYTES.to_string()).expect("a digit run"),
    );
    let framing =
        rustfs_gateway_http::Framing::classify(http::Version::HTTP_11, &headers, &rustfs_gateway_http::Limits::default())
            .expect("a framed request");
    let ingest = crate::chunked::ChunkIngest::prepare(
        &rustfs_gateway_sig::PayloadMode::Unsigned,
        &headers,
        &framing,
        &crate::ext::ChunkSink::new(),
        None,
        rustfs_gateway_http::ChunkLimits::default(),
    )
    .expect("gzip metadata is not a framing error");
    assert!(ingest.is_none(), "gzip never selects a decoder");

    let proof = MetadataAdmission::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(GZIP_STREAM)]);
    let opaque = SealedBody::seal(Some(body), Some(RAW_BYTES))
        .read(
            &proof,
            BodyCeilings {
                buffered: RAW_BYTES,
                whole_body: true,
                declared: None,
            },
            BodyTimeouts::S3,
            ingest,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .await
        .expect("the raw stream fits exactly");
    assert_eq!(opaque, Bytes::from_static(GZIP_STREAM));
    assert_eq!(read.bytes_read(), RAW_BYTES);

    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(GZIP_STREAM)]);
    let error = SealedBody::seal(Some(body), Some(RAW_BYTES))
        .read(
            &proof,
            BodyCeilings {
                buffered: RAW_BYTES - 1,
                whole_body: true,
                declared: None,
            },
            BodyTimeouts::S3,
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .await
        .expect_err("one raw byte past the ceiling is refused");
    assert_eq!(error.code(), Some(&ErrorCode::ENTITY_TOO_LARGE));
    assert_eq!(read.bytes_read(), 0, "the raw Content-Length is refused before a frame is polled");
}

/// Negative — the operation's own cap is refused **while the body is still arriving**: the
/// frames behind the one that crossed the line are never polled, which is the difference
/// between a cap and a report. Without this assertion "refused at 2 MiB" and "collected 40 MiB
/// and then complained" are the same test.
#[tokio::test]
async fn the_declared_cap_is_refused_at_the_frame_that_crosses_it() {
    let proof = MetadataAdmission::granted_for_test();
    let frames = core::iter::repeat_n(Bytes::from(vec![b'k'; 64]), 100);
    let (body, read) = crate::probe::ObservedBody::new(frames);
    let ceilings = BodyCeilings {
        buffered: 1 << 20,
        whole_body: true,
        declared: Some(128),
    };
    let error = SealedBody::seal(Some(body), None)
        .read(&proof, ceilings, BodyTimeouts::S3, None, BodyDigestObligation::None, BodyIntegrity::NONE)
        .await
        .expect_err("past the operation's cap");
    assert_eq!(error.code(), Some(&ErrorCode::INVALID_REQUEST));
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    // Three frames of 64 bytes is the first total past 128, and nothing after it was asked for.
    assert_eq!(read.bytes_read(), 192);
    assert!(!read.is_exhausted(), "the rest of the body was never pulled");
}

/// Negative — the operation's cap is decided on the announced length too, so a body that
/// declares more than the cap never has a frame polled at all.
#[tokio::test]
async fn a_declared_length_past_the_operation_cap_is_refused_unread() {
    let proof = MetadataAdmission::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"x")]);
    let ceilings = BodyCeilings {
        buffered: 1 << 20,
        whole_body: true,
        declared: Some(128),
    };
    let error = SealedBody::seal(Some(body), Some(4096))
        .read(&proof, ceilings, BodyTimeouts::S3, None, BodyDigestObligation::None, BodyIntegrity::NONE)
        .await
        .expect_err("past the operation's cap");
    assert_eq!(error.code(), Some(&ErrorCode::INVALID_REQUEST));
    assert_eq!(read.bytes_read(), 0);
}

/// Positive — an absent body reads as empty rather than as an error.
#[tokio::test]
async fn an_absent_body_reads_as_empty() {
    let proof = MetadataAdmission::granted_for_test();
    let sealed: SealedBody<crate::probe::ObservedBody> = SealedBody::seal(None, None);
    assert!(
        sealed
            .read(&proof, roomy(), BodyTimeouts::S3, None, BodyDigestObligation::None, BodyIntegrity::NONE,)
            .await
            .expect("no body")
            .is_empty()
    );
}

/// Positive — a body inside both ceilings arrives whole, in frame order.
#[tokio::test]
async fn a_body_inside_every_ceiling_arrives_whole() {
    let proof = MetadataAdmission::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"first-"), Bytes::from_static(b"second")]);
    let bytes = SealedBody::seal(Some(body), Some(12))
        .read(&proof, roomy(), BodyTimeouts::S3, None, BodyDigestObligation::None, BodyIntegrity::NONE)
        .await
        .expect("inside every ceiling");
    assert_eq!(bytes, Bytes::from_static(b"first-second"));
    assert_eq!(read.bytes_read(), 12);
    assert!(read.is_exhausted());
}

/// An unsigned `aws-chunked` ingest for a body declaring `decoded` bytes on a `wire` of that
/// many. The only framed shape this assembly decodes without published signing material.
fn unsigned_ingest(decoded: u64, wire: u64) -> crate::chunked::ChunkIngest {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::HeaderName::from_static("x-amz-decoded-content-length"),
        http::HeaderValue::from_str(&decoded.to_string()).expect("a digit run"),
    );
    let mut framing_headers = http::HeaderMap::new();
    framing_headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&wire.to_string()).expect("a digit run"),
    );
    let framing =
        rustfs_gateway_http::Framing::classify(http::Version::HTTP_11, &framing_headers, &rustfs_gateway_http::Limits::default())
            .expect("a framed request");
    crate::chunked::ChunkIngest::prepare(
        &rustfs_gateway_sig::PayloadMode::StreamingUnsigned {
            trailer: rustfs_gateway_sig::TrailerSet::None,
        },
        &headers,
        &framing,
        &crate::ext::ChunkSink::new(),
        None,
        rustfs_gateway_http::ChunkLimits::default(),
    )
    .expect("head-level checks pass")
    .expect("a framed mode")
}

/// `count` well-formed unsigned `aws-chunked` frames, one whole chunk each.
///
/// Well-formed on purpose: a body of arbitrary bytes would be refused by the decoder's own
/// grammar long before a ceiling could fire, and the case would then be asserting on the
/// wrong refusal.
fn framed_chunks(count: usize) -> Vec<Bytes> {
    let mut chunk = b"40\r\n".to_vec();
    chunk.extend_from_slice(&[b'k'; 64]);
    chunk.extend_from_slice(b"\r\n");
    assert_eq!(chunk.len() as u64, CHUNK_FRAME_BYTES);
    core::iter::repeat_n(Bytes::from(chunk), count).collect()
}

/// The wire size of one frame from [`framed_chunks`]: a size line, 64 data bytes, two CRLFs.
const CHUNK_FRAME_BYTES: u64 = 70;

/// Positive — a framed body is pulled to its end, so the transport is left with nothing
/// undrained and the connection stays reusable.
///
/// The `is_exhausted` half is the one that matters. Now that the decoder pulls frames instead
/// of being handed a collected body, a pipeline that stopped at the terminal chunk without
/// asking the transport for the next frame would produce this same decoded body over a socket
/// that still had bytes queued on it.
#[tokio::test]
async fn a_framed_body_is_pulled_to_the_end_of_the_transport() {
    let proof = MetadataAdmission::granted_for_test();
    let wire: &[u8] = b"b\r\nhello world\r\n0\r\n\r\n";
    let frames = wire.chunks(4).map(Bytes::copy_from_slice).collect::<Vec<_>>();
    let (body, read) = crate::probe::ObservedBody::new(frames);
    let ingest = unsigned_ingest(11, wire.len() as u64);
    let decoded = SealedBody::seal(Some(body), Some(wire.len() as u64))
        .read(
            &proof,
            roomy(),
            BodyTimeouts::S3,
            Some(ingest),
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .await
        .expect("well-formed unsigned framing");
    assert_eq!(decoded, Bytes::from_static(b"hello world"));
    assert_eq!(read.bytes_read(), wire.len() as u64, "the wire body was not read to its end");
    assert!(read.is_exhausted(), "the transport was left with frames nobody asked for");
}

/// Negative — a framed body past the assembly's ceiling is a `413 EntityTooLarge`, refused at
/// the frame that crossed the line and with the frames behind it never polled.
///
/// The status is the assertion. The decoder pulls its wire bytes through a contract that
/// carries a `StreamError` — which has no status and no S3 error code — so a ceiling flattened
/// into that contract comes back as `400 IncompleteBody`: the wrong code, the wrong band for
/// an SDK's retry logic, and a statement about the request where the truth is a statement
/// about the server. `crate::wire_read` keeps the refusal whole beside the stream for exactly
/// this, and without this case that arrangement is untested.
#[tokio::test]
async fn a_framed_body_past_the_ceiling_is_a_413_and_not_an_incomplete_body() {
    let proof = MetadataAdmission::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new(framed_chunks(100));
    let ceilings = BodyCeilings {
        buffered: 1024,
        whole_body: true,
        declared: None,
    };
    let ingest = unsigned_ingest(6400, 7000);
    let error = SealedBody::seal(Some(body), None)
        .read(
            &proof,
            ceilings,
            BodyTimeouts::S3,
            Some(ingest),
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .await
        .expect_err("over the ceiling");
    assert_eq!(error.code(), Some(&ErrorCode::ENTITY_TOO_LARGE));
    assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        read.bytes_read() <= 1024 + CHUNK_FRAME_BYTES,
        "{} wire bytes were pulled past a 1024-byte ceiling",
        read.bytes_read()
    );
    assert!(!read.is_exhausted(), "the rest of the body was never pulled");
}

/// Negative — the operation's own cap keeps its `400 InvalidRequest` on the framed path too.
///
/// The pair with the case above: two ceilings that answer with two different codes, and a
/// refusal channel that collapsed them into one would satisfy whichever of the two it happened
/// to collapse onto.
#[tokio::test]
async fn a_framed_body_past_the_operation_cap_is_a_400_invalid_request() {
    let proof = MetadataAdmission::granted_for_test();
    let (body, _) = crate::probe::ObservedBody::new(framed_chunks(100));
    let ceilings = BodyCeilings {
        buffered: 1 << 20,
        whole_body: true,
        declared: Some(128),
    };
    let ingest = unsigned_ingest(6400, 7000);
    let error = SealedBody::seal(Some(body), None)
        .read(
            &proof,
            ceilings,
            BodyTimeouts::S3,
            Some(ingest),
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .await
        .expect_err("past the operation's cap");
    assert_eq!(error.code(), Some(&ErrorCode::INVALID_REQUEST));
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
}

/// c-lim-0033. Negative — a real h1 connection closes after the first-body-byte deadline.
#[tokio::test]
async fn c_wire_0062_c_lim_0033_closes_a_socket_when_the_first_body_byte_never_arrives() {
    let timeouts = BodyTimeouts::new(Duration::from_millis(20), Duration::from_millis(500)).expect("non-zero timeouts");
    let (response, reached) = timeout_response(b"", timeouts).await;
    let text = String::from_utf8(response).expect("HTTP response is text");
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
    assert!(text.contains("<Code>RequestTimeout</Code>"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert_eq!(reached.fetch_add(0, Ordering::SeqCst), 0, "the timed-out request reached the handler");
}

/// c-lim-0034. Negative — progress once does not exempt the next body gap from its deadline.
#[tokio::test]
async fn c_lim_0034_closes_a_socket_when_the_body_stalls_between_bytes() {
    let timeouts = BodyTimeouts::new(Duration::from_millis(500), Duration::from_millis(20)).expect("non-zero timeouts");
    let (response, reached) = timeout_response(b"x", timeouts).await;
    let text = String::from_utf8(response).expect("HTTP response is text");
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert_eq!(reached.fetch_add(0, Ordering::SeqCst), 0, "the stalled request reached the handler");
}

/// c-lim-0001. Positive — total transfer time may exceed one idle interval while progress continues.
#[tokio::test]
async fn c_lim_0001_allows_a_long_socket_body_that_keeps_making_progress() {
    let timeouts = BodyTimeouts::new(Duration::from_millis(100), Duration::from_millis(100)).expect("non-zero timeouts");
    let (running, reached) = body_timeout_server(timeouts);
    let mut stream = TcpStream::connect(running.local_addr).await.expect("connection succeeds");
    stream.write_all(&raw_head(true)).await.expect("head writes");
    for byte in b"body" {
        tokio::time::sleep(Duration::from_millis(30)).await;
        stream.write_all(&[*byte]).await.expect("one progress byte writes");
    }
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
        .await
        .expect("the response completes")
        .expect("response reads to EOF");
    let text = String::from_utf8(response).expect("HTTP response is text");
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert_eq!(reached.fetch_add(0, Ordering::SeqCst), 1, "the progressing request missed the handler");
    stop_server(running).await;
}

/// The two frame shapes that carry no payload, and which `WireFrames::poll_next` skips.
#[derive(Clone, Copy, Debug)]
enum PayloadFree {
    /// A data frame of zero bytes.
    EmptyData,
    /// A trailer section, which `http_body::Frame::into_data` refuses.
    Trailers,
}

/// A body that answers every poll with a frame carrying no payload, for ever.
///
/// The instrument rustfs/gateway#263 needs and `crate::probe::ObservedBody` cannot be: the
/// defect is a body that never *ends*, and a body assembled from a finite list of frames always
/// does. It counts its polls, so the bound can be read as a number rather than as "it returned".
struct EndlessPayloadFreeBody {
    shape: PayloadFree,
    polls: Arc<AtomicUsize>,
}

impl http_body::Body for EndlessPayloadFreeBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        _context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        let frame = match self.shape {
            PayloadFree::EmptyData => http_body::Frame::data(Bytes::new()),
            PayloadFree::Trailers => http_body::Frame::trailers(http::HeaderMap::new()),
        };
        core::task::Poll::Ready(Some(Ok(frame)))
    }
}

/// Reads `body` on a thread of its own and gives up after `PATIENCE`.
///
/// The deadline has to be outside the future. A body that answers `Ready` for ever never returns
/// `Poll::Pending`, so nothing on the same thread — not `tokio::time::timeout`, not the reader's
/// own between-frame `Delay` — ever gets to run: the spin is synchronous. Without this, a
/// regression here does not fail the suite, it hangs it, and a hung job reads as infrastructure.
fn read_off_thread<B>(body: B, ingest: Option<crate::chunked::ChunkIngest>) -> Result<Bytes, S3Error>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    /// Long enough that a slow shared runner is never the reason, short enough to fail a job
    /// rather than time it out. It is a hang detector and never the assertion.
    const PATIENCE: Duration = Duration::from_secs(30);

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        let outcome = runtime.block_on(async move {
            let proof = MetadataAdmission::granted_for_test();
            SealedBody::seal(Some(body), None)
                .read(&proof, roomy(), BodyTimeouts::S3, ingest, BodyDigestObligation::None, BodyIntegrity::NONE)
                .await
        });
        let _ = sender.send(outcome);
    });
    receiver
        .recv_timeout(PATIENCE)
        .expect("the reader spun on a body that carries no payload instead of refusing it")
}

/// Negative — a body that yields nothing but payload-free frames is refused, on both shapes.
///
/// Neither shape advances `WireProgress::seen`, so neither is charged against a ceiling, and each
/// one is a frame *arriving*, so each one resets the between-frame deadline rather than expiring
/// it. Before the run bound this loop had no exit: unbounded work for a peer that transfers no
/// bytes, which is a resource-exhaustion path open to anyone who can open a connection.
/// rustfs/gateway#263.
///
/// The poll count is the sharp end. "It returned an error" would also be satisfied by a reader
/// that spun ten million times first.
#[test]
fn a_body_of_payload_free_frames_is_refused_rather_than_spun_on() {
    for shape in [PayloadFree::EmptyData, PayloadFree::Trailers] {
        let polls = Arc::new(AtomicUsize::new(0));
        let body = EndlessPayloadFreeBody {
            shape,
            polls: Arc::clone(&polls),
        };
        let error = read_off_thread(body, None).expect_err("a body that never carries payload is not a body");
        assert_eq!(error.code(), Some(&ErrorCode::REQUEST_TIMEOUT), "{shape:?}");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{shape:?}");
        assert_eq!(
            polls.fetch_add(0, Ordering::SeqCst),
            crate::wire_read::MAX_PAYLOAD_FREE_FRAME_RUN as usize + 1,
            "{shape:?}: the refusal fires on the frame that crosses the run, and not one later"
        );
        // A body abandoned mid-stream leaves no synchronisation point on the connection, so the
        // refusal has to end it — RFC 9112 §9.3.
        assert!(error.must_close_connection(), "{shape:?}");
    }
    // The control for the line above: the accessor is not stuck on `true`. A refusal that does
    // not force the close reads `false` through the same call.
    assert!(!content_sha256_mismatch().must_close_connection());
}

/// Negative — the framed path is bounded by the same rule, and by the same reader.
///
/// `ChunkIngest::run` pulls its wire octets through `WireReader`, so a payload-free spin reaches
/// it as a stalled `poll_fill` rather than as a decode error. If the bound lived in the unframed
/// collector instead of in `WireFrames`, this case would hang while its sibling passed.
#[test]
fn a_framed_body_of_payload_free_frames_is_refused_by_the_same_bound() {
    let polls = Arc::new(AtomicUsize::new(0));
    let body = EndlessPayloadFreeBody {
        shape: PayloadFree::EmptyData,
        polls: Arc::clone(&polls),
    };
    let error = read_off_thread(body, Some(unsigned_ingest(11, 21))).expect_err("no chunk header ever arrives");
    assert_eq!(error.code(), Some(&ErrorCode::REQUEST_TIMEOUT));
    assert_eq!(
        polls.fetch_add(0, Ordering::SeqCst),
        crate::wire_read::MAX_PAYLOAD_FREE_FRAME_RUN as usize + 1
    );
}

/// Negative — a peer that pays for its payload-free frames one byte at a time is bounded by the
/// ceiling it is now spending, and is refused there.
///
/// This is what the run bound buys, and why it is a run rather than a per-body total: every
/// `MAX_PAYLOAD_FREE_FRAME_RUN + 1` frames at least one carried a byte, so the reader's work is a
/// function of `BodyCeilings` — which is bounded — instead of a function of what the peer feels
/// like sending. The refusal here is `413`, from the ceiling, and never the run bound.
#[test]
fn payload_free_frames_paid_for_a_byte_at_a_time_are_bounded_by_the_ceiling() {
    /// A body that pads every payload byte with a full legal run of empty frames.
    struct PaddedBody {
        emitted: usize,
        budget: usize,
    }

    impl http_body::Body for PaddedBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: core::pin::Pin<&mut Self>,
            _context: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            this.emitted = this.emitted.saturating_add(1);
            assert!(this.emitted <= this.budget, "the ceiling did not stop a padded body");
            let period = crate::wire_read::MAX_PAYLOAD_FREE_FRAME_RUN as usize + 1;
            let frame = if this.emitted.is_multiple_of(period) {
                http_body::Frame::data(Bytes::from_static(b"x"))
            } else {
                http_body::Frame::data(Bytes::new())
            };
            core::task::Poll::Ready(Some(Ok(frame)))
        }
    }

    // `roomy()` is a 1 MiB ceiling, so a byte per period bounds the whole read at
    // (1 MiB + 1) periods of frames — reached, and refused, well inside the patience above.
    let budget = ((1_usize << 20) + 2) * (crate::wire_read::MAX_PAYLOAD_FREE_FRAME_RUN as usize + 1);
    let error = read_off_thread(PaddedBody { emitted: 0, budget }, None).expect_err("over the ceiling");
    assert_eq!(error.code(), Some(&ErrorCode::ENTITY_TOO_LARGE));
    assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// Positive — a legal run of payload-free frames is not a refusal, and the run resets.
///
/// The green half of the boundary, and the one that says the counter is a *run*: three full legal
/// runs separated by one payload byte each is `3 * MAX + 2` payload-free frames in one body, and
/// a per-body total of any size below that would refuse a body every transport in this workspace
/// can legitimately produce.
#[tokio::test]
async fn a_legal_run_of_payload_free_frames_still_delivers_the_body() {
    let proof = MetadataAdmission::granted_for_test();
    let run = crate::wire_read::MAX_PAYLOAD_FREE_FRAME_RUN as usize;
    let mut frames = Vec::new();
    for payload in [Bytes::from_static(b"a"), Bytes::from_static(b"b"), Bytes::new()] {
        frames.extend(core::iter::repeat_n(Bytes::new(), run));
        if !payload.is_empty() {
            frames.push(payload);
        }
    }
    let payload_free = frames.iter().filter(|frame| frame.is_empty()).count();
    assert_eq!(payload_free, 3 * run, "the fixture must carry more empties than any per-body total");

    let (body, read) = crate::probe::ObservedBody::new(frames);
    let bytes = SealedBody::seal(Some(body), None)
        .read(&proof, roomy(), BodyTimeouts::S3, None, BodyDigestObligation::None, BodyIntegrity::NONE)
        .await
        .expect("a legal run of empty frames is not a refusal");
    assert_eq!(bytes, Bytes::from_static(b"ab"));
    assert!(read.is_exhausted(), "the body was refused instead of being read to its end");
}

/// Positive — a real hyper connection whose chunked body ends in a trailer section is still read
/// whole, over a socket.
///
/// The bound above is a rule about what the *transport* is allowed to hand over, so the case that
/// says it does not refuse conforming traffic has to be one where hyper does the framing rather
/// than a fixture that decides for itself what a frame is. A trailer section is the one
/// payload-free frame an ordinary HTTP/1.1 request produces, and RFC 9112 §7.1.2 allows a chunked
/// body exactly one — which is the floor `MAX_PAYLOAD_FREE_FRAME_RUN` is derived from, measured
/// here rather than assumed.
#[tokio::test]
async fn a_real_chunked_body_with_a_trailer_section_is_still_read_whole() {
    let timeouts = BodyTimeouts::new(Duration::from_secs(5), Duration::from_secs(5)).expect("non-zero timeouts");
    let (running, reached) = body_timeout_server(timeouts);
    let mut stream = TcpStream::connect(running.local_addr).await.expect("connection succeeds");
    stream
        .write_all(
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: x-probe\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("head writes");
    stream
        .write_all(b"4\r\nbody\r\n0\r\nx-probe: 1\r\n\r\n")
        .await
        .expect("a chunked body with a trailer section writes");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("the response completes")
        .expect("response reads to EOF");
    let text = String::from_utf8(response).expect("HTTP response is text");
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert_eq!(reached.fetch_add(0, Ordering::SeqCst), 1, "the trailered body never reached the handler");
    stop_server(running).await;
}

/// Negative — zero is never an implicit unlimited body deadline.
#[test]
fn zero_body_deadlines_are_refused() {
    assert!(BodyTimeouts::new(Duration::ZERO, Duration::from_secs(1)).is_none());
    assert!(BodyTimeouts::new(Duration::from_secs(1), Duration::ZERO).is_none());
}

/// Positive — the assembly defaults are the two independent limits contract values.
#[test]
fn body_deadline_defaults_match_the_limits_contract() {
    assert_eq!(BodyTimeouts::S3.first_byte(), Duration::from_secs(20));
    assert_eq!(BodyTimeouts::S3.read_idle(), Duration::from_secs(30));
}

/// Negative — both ways a live body can time out share the error-status authority and teardown.
///
/// A split here would let a client receive 400 or 408 for the same S3 `RequestTimeout` code based
/// only on which progress clock happened to expire first.
#[test]
fn request_timeout_status_and_close_are_identical_for_idle_and_throughput() {
    for error in [body_idle_timeout(None), body_throughput_timeout(None)] {
        assert_eq!(error.code(), Some(&ErrorCode::REQUEST_TIMEOUT));
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        assert!(error.must_close_connection());
    }
}
