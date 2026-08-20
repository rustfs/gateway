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
//! per-operation body cap table, and the framed path's refusal codes.
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
            let proof = Authenticated::granted_for_test();
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
        assert!(Authenticated::of(&Verdict::reject(error)).is_none(), "{error:?}");
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
            &Authenticated::granted_for_test(),
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
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"x")]);
    let ceilings = BodyCeilings {
        buffered: 1024,
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
    let proof = Authenticated::granted_for_test();
    let (body, _) = crate::probe::ObservedBody::new([Bytes::from(vec![0_u8; 4096])]);
    let ceilings = BodyCeilings {
        buffered: 1024,
        declared: None,
    };
    let error = SealedBody::seal(Some(body), None)
        .read(&proof, ceilings, BodyTimeouts::S3, None, BodyDigestObligation::None, BodyIntegrity::NONE)
        .await
        .expect_err("over the ceiling");
    assert_eq!(error.code(), Some(&ErrorCode::ENTITY_TOO_LARGE));
}

/// Negative — the operation's own cap is refused **while the body is still arriving**: the
/// frames behind the one that crossed the line are never polled, which is the difference
/// between a cap and a report. Without this assertion "refused at 2 MiB" and "collected 40 MiB
/// and then complained" are the same test.
#[tokio::test]
async fn the_declared_cap_is_refused_at_the_frame_that_crosses_it() {
    let proof = Authenticated::granted_for_test();
    let frames = core::iter::repeat_n(Bytes::from(vec![b'k'; 64]), 100);
    let (body, read) = crate::probe::ObservedBody::new(frames);
    let ceilings = BodyCeilings {
        buffered: 1 << 20,
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
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"x")]);
    let ceilings = BodyCeilings {
        buffered: 1 << 20,
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
    let proof = Authenticated::granted_for_test();
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
    let proof = Authenticated::granted_for_test();
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
    let proof = Authenticated::granted_for_test();
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
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new(framed_chunks(100));
    let ceilings = BodyCeilings {
        buffered: 1024,
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
    let proof = Authenticated::granted_for_test();
    let (body, _) = crate::probe::ObservedBody::new(framed_chunks(100));
    let ceilings = BodyCeilings {
        buffered: 1 << 20,
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
async fn c_lim_0033_closes_a_socket_when_the_first_body_byte_never_arrives() {
    let timeouts = BodyTimeouts::new(Duration::from_millis(20), Duration::from_millis(500)).expect("non-zero timeouts");
    let (response, reached) = timeout_response(b"", timeouts).await;
    let text = String::from_utf8(response).expect("HTTP response is text");
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
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
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
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
