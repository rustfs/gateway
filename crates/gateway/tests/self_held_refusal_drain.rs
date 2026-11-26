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

//! How long the self-held driver waits for a refused request's body before it answers
//! (rustfs/gateway#1207).
//!
//! Responsible for: a refusal that may keep the connection, over a body its peer stops sending,
//! on a real socket — the answer still arrives, the connection closes, and the request permit
//! returns; and the control whose body arrives inside the bound and keeps the connection.
//! NOT responsible for: which refusals may keep a connection (`crate::close`), or the Hyper driver,
//! which never waits for such a body.
//! Upstream: `rustfs-gateway`'s self-held driver over the streaming fixture in
//! `support/streaming.rs`. Downstream: none.

#![allow(clippy::expect_used, clippy::panic)]

use crate::support::streaming::{StreamingPut, service_with_deadlines};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustfs_gateway::{
    Handler, HandlerErrorContext, HandlerResult, Req, RequestBodyDeadlineConfig, RunningServer, SelfHeldHttp1Driver,
    UnreadBodyDrain,
};
use rustfs_gateway_server::{Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const HEAD: &[u8] = b"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 30\r\n\r\n";
const EMPTY_KEEP_ALIVE_HEAD: &[u8] = b"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n";
const EMPTY_CLOSE_HEAD: &[u8] = b"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const EXPECT_HEAD: &[u8] = b"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 30\r\nExpect: 100-continue\r\n\r\n";
const BODY: &[u8; 30] = b"a part the backend never reads";

/// Refuses without reading a byte of the body: `404 NoSuchBucket`, which may keep the connection.
struct RefusesUnread;

impl Handler<StreamingPut> for RefusesUnread {
    async fn call(&self, request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        drop(request.into_input());
        Err(HandlerErrorContext::missing_bucket().into())
    }
}

/// One request permit, so a permit the stalled exchange never returns refuses every later request.
fn serve(lingering_close_time: Duration) -> RunningServer {
    let deadlines = RequestBodyDeadlineConfig::new(Duration::from_secs(1), Duration::from_secs(1)).expect("non-zero deadlines");
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        max_global_inflight_requests: 1,
        lingering_close_time,
        ..ServerConfig::default()
    };
    Server::new(config, service_with_deadlines(Arc::new(RefusesUnread), deadlines))
        .serve_with(SelfHeldHttp1Driver)
        .expect("the loopback server starts")
}

/// Reads until the server closes the connection, or until `patience` passes with nothing read.
async fn read_until_closed(stream: &mut TcpStream, patience: Duration) -> (String, bool) {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    let closed = loop {
        match tokio::time::timeout(patience, stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break true,
            Ok(Ok(read)) => response.extend_from_slice(&buffer[..read]),
            Err(_) => break false,
        }
    };
    (String::from_utf8_lossy(&response).into_owned(), closed)
}

/// Reads exactly one refusal off a connection that stays open.
async fn read_one_refusal(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !response.ends_with(b"</Error>") {
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer))
            .await
            .expect("the refusal arrives")
            .expect("the refusal reads");
        assert_ne!(read, 0, "the connection closed before its refusal ended");
        response.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8_lossy(&response).into_owned()
}

/// Negative — the peer declares 30 octets, sends 10 and stops. Before #1207 the driver waited for
/// the other 20 before it wrote anything: the refusal never arrived and its response held the
/// listener's only request permit, so the next client was never served either.
#[tokio::test]
async fn a_body_its_peer_stops_sending_is_given_up_on_and_the_refusal_still_arrives() {
    let running = serve(Duration::from_millis(200));
    let mut stalled = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stalled.write_all(HEAD).await.expect("the head writes");
    stalled.write_all(&BODY[..10]).await.expect("the first octets write");
    let (text, closed) = read_until_closed(&mut stalled, Duration::from_secs(10)).await;
    assert!(text.starts_with("HTTP/1.1 404"), "the refusal was never answered: {text:?}");
    assert!(text.contains("<Code>NoSuchBucket</Code>"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert!(closed, "a connection whose body was given up on stayed open");

    let mut next = TcpStream::connect(running.local_addr)
        .await
        .expect("the next client connects");
    next.write_all(HEAD).await.expect("the head writes");
    next.write_all(BODY).await.expect("the whole body writes");
    let text = read_one_refusal(&mut next).await;
    assert!(text.starts_with("HTTP/1.1 404"), "the request permit never came back: {text}");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}

/// Negative — a peer that keeps sending, one octet every 50 ms, would finish its 30 octets well
/// after the 300 ms bound: the bound is on the whole drain, not on each read, so the driver gives up
/// and closes (a drain that completed would have kept the connection, without `Connection: close`).
#[tokio::test]
async fn a_body_dripped_past_the_bound_is_given_up_on() {
    let running = serve(Duration::from_millis(300));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(HEAD).await.expect("the head writes");
    let (mut reader, mut writer) = stream.into_split();
    let drip = tokio::spawn(async move {
        for octet in BODY {
            if writer.write_all(std::slice::from_ref(octet)).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !response.ends_with(b"</Error>") {
        let read = tokio::time::timeout(Duration::from_secs(10), reader.read(&mut buffer))
            .await
            .expect("the refusal arrives")
            .expect("the refusal reads");
        assert_ne!(read, 0, "the connection closed before its refusal ended");
        response.extend_from_slice(&buffer[..read]);
    }
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 404"), "{text}");
    assert!(
        text.to_ascii_lowercase().contains("connection: close"),
        "the drain outlasted its bound and kept the connection: {text}"
    );
    drip.abort();
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}

/// Positive control — the rest of the body arrives well inside the bound, so it is drained and the
/// connection is kept: a second request on the same socket is answered.
#[tokio::test]
async fn a_body_that_arrives_inside_the_bound_keeps_the_connection() {
    let running = serve(Duration::from_secs(5));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(HEAD).await.expect("the head writes");
    stream.write_all(&BODY[..10]).await.expect("the first octets write");
    tokio::time::sleep(Duration::from_millis(50)).await;
    stream.write_all(&BODY[10..]).await.expect("the rest writes");
    let first = read_one_refusal(&mut stream).await;
    assert!(first.starts_with("HTTP/1.1 404"), "{first}");
    assert!(!first.to_ascii_lowercase().contains("connection: close"), "{first}");
    stream.write_all(HEAD).await.expect("the second head writes");
    stream.write_all(BODY).await.expect("the second body writes");
    let second = read_one_refusal(&mut stream).await;
    assert!(
        second.starts_with("HTTP/1.1 404"),
        "the kept connection served a second request: {second}"
    );
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}

fn serve_with_drain(lingering_close_time: Duration, drain: UnreadBodyDrain) -> RunningServer {
    let deadlines = RequestBodyDeadlineConfig::new(Duration::from_secs(1), Duration::from_secs(1)).expect("non-zero deadlines");
    let (builder, _handle) = crate::support::wired()
        .clock_with_skew_ack(
            crate::support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<StreamingPut, _>(Arc::new(RefusesUnread))
        .dialect(&crate::support::streaming::streaming_dialect())
        .drain_unread_request_bodies(drain)
        .config(rustfs_gateway::ServiceConfig::new(1024 * 1024).with_request_body_deadlines(deadlines));
    let service = builder.build().expect("a complete streaming assembly with unread-body drain");
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        lingering_close_time,
        ..ServerConfig::default()
    };
    Server::new(config, service)
        .serve_with(SelfHeldHttp1Driver)
        .expect("the loopback server starts")
}

fn serve_with_timeouts(header_read_timeout: Duration, keep_alive_idle: Duration) -> RunningServer {
    let deadlines = RequestBodyDeadlineConfig::new(Duration::from_secs(1), Duration::from_secs(1)).expect("non-zero deadlines");
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        header_read_timeout,
        keep_alive_idle,
        ..ServerConfig::default()
    };
    Server::new(config, service_with_deadlines(Arc::new(RefusesUnread), deadlines))
        .serve_with(SelfHeldHttp1Driver)
        .expect("the loopback server starts")
}

/// Negative — enabling `drain_unread_request_bodies` on `SelfHeldHttp1Driver` must not spawn a
/// background drain task that locks `ConnectionIo` and deadlocks the driver's own refusal response.
#[tokio::test]
async fn n_unread_body_drain_on_self_held_driver_answers_refusal_without_deadlock() {
    let running = serve_with_drain(Duration::from_millis(200), UnreadBodyDrain::with_idle_timeout(Duration::from_secs(300)));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(HEAD).await.expect("the head writes");
    stream.write_all(&BODY[..10]).await.expect("the partial body writes");
    let (text, closed) = read_until_closed(&mut stream, Duration::from_secs(2)).await;
    assert!(
        text.starts_with("HTTP/1.1 404"),
        "refusal hung or failed under unread_body_drain: {text:?}"
    );
    assert!(text.contains("<Code>NoSuchBucket</Code>"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert!(closed, "the connection closed cleanly after refusal");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}

/// Negative — enabling `drain_unread_request_bodies` on `SelfHeldHttp1Driver` with
/// `Expect: 100-continue` must neither emit a spurious `100 Continue` nor deadlock waiting for a
/// body the service refused.
#[tokio::test]
async fn n_unread_body_drain_on_self_held_driver_does_not_emit_100_continue_on_refusal() {
    let running = serve_with_drain(Duration::from_secs(30), UnreadBodyDrain::with_idle_timeout(Duration::from_secs(300)));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(EXPECT_HEAD).await.expect("the expect head writes");
    let (text, closed) = read_until_closed(&mut stream, Duration::from_secs(2)).await;
    assert!(
        text.starts_with("HTTP/1.1 404"),
        "expected immediate 404 without 100 Continue or hang, got: {text:?}"
    );
    assert!(!text.contains("100 Continue"), "spurious 100 Continue emitted: {text:?}");
    assert!(text.contains("<Code>NoSuchBucket</Code>"), "{text}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert!(closed, "the connection closed cleanly");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}

/// Negative — an unauthenticated `Expect: 100-continue` request under unbounded
/// `drain_unread_request_bodies` on `SelfHeldHttp1Driver` still refuses immediately without
/// inviting the body.
#[tokio::test]
async fn n_unauthenticated_expect_continue_with_unbounded_drain_answers_promptly() {
    let running = serve_with_drain(Duration::from_secs(30), UnreadBodyDrain::unbounded());
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream
        .write_all(
            b"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 30\r\nExpect: 100-continue\r\n\
              x-amz-date: 20260102T030405Z\r\n\
              x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n\
              Authorization: AWS4-HMAC-SHA256 Credential=AKIDUNKNOWN/20260102/us-east-1/s3/aws4_request, \
              SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
              Signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\r\n",
        )
        .await
        .expect("the signed expect head writes");
    let (text, closed) = read_until_closed(&mut stream, Duration::from_secs(2)).await;
    assert!(text.starts_with("HTTP/1.1 403"), "expected immediate 403, got: {text:?}");
    assert!(!text.contains("100 Continue"), "spurious 100 Continue emitted: {text:?}");
    assert!(text.to_ascii_lowercase().contains("connection: close"), "{text}");
    assert!(closed, "the connection closed cleanly");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}

/// Negative — an idle keep-alive socket that sends zero bytes past `keep_alive_idle` must close
/// cleanly with zero bytes written, never `400 Bad Request`.
#[tokio::test]
async fn n_idle_keep_alive_closes_cleanly_with_zero_bytes_after_keep_alive_idle() {
    let running = serve_with_timeouts(Duration::from_millis(80), Duration::from_millis(200));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream
        .write_all(EMPTY_KEEP_ALIVE_HEAD)
        .await
        .expect("the first request writes");
    let first = read_one_refusal(&mut stream).await;
    assert!(first.starts_with("HTTP/1.1 404"), "{first}");
    assert!(!first.to_ascii_lowercase().contains("connection: close"), "{first}");

    let (tail, closed) = read_until_closed(&mut stream, Duration::from_secs(3)).await;
    assert!(closed, "idle keep-alive connection did not close");
    assert!(tail.is_empty(), "idle keep-alive timeout must write zero bytes, got: {tail:?}");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}

/// Positive — an idle keep-alive socket sitting idle longer than `header_read_timeout` but shorter
/// than `keep_alive_idle` stays open and serves the next request.
#[tokio::test]
async fn keep_alive_connection_survives_idle_longer_than_header_read_timeout() {
    let running = serve_with_timeouts(Duration::from_millis(120), Duration::from_millis(1500));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream
        .write_all(EMPTY_KEEP_ALIVE_HEAD)
        .await
        .expect("the first request writes");
    let first = read_one_refusal(&mut stream).await;
    assert!(first.starts_with("HTTP/1.1 404"), "{first}");

    tokio::time::sleep(Duration::from_millis(300)).await;

    stream
        .write_all(EMPTY_CLOSE_HEAD)
        .await
        .expect("the second request writes on the kept socket");
    let (second, closed) = read_until_closed(&mut stream, Duration::from_secs(3)).await;
    assert!(
        second.starts_with("HTTP/1.1 404"),
        "keep-alive connection closed before keep_alive_idle: {second:?}"
    );
    assert!(closed, "connection closed after Connection: close");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}

/// Negative — once the first byte of a subsequent keep-alive request arrives, stalling mid-header
/// is still cut by `header_read_timeout`, well before `keep_alive_idle`.
#[tokio::test]
async fn n_mid_header_stall_after_keep_alive_still_enforces_header_read_timeout() {
    let running = serve_with_timeouts(Duration::from_millis(150), Duration::from_secs(5));
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream
        .write_all(EMPTY_KEEP_ALIVE_HEAD)
        .await
        .expect("the first request writes");
    let first = read_one_refusal(&mut stream).await;
    assert!(first.starts_with("HTTP/1.1 404"), "{first}");

    stream
        .write_all(b"PUT / HTTP/1.1\r\n")
        .await
        .expect("partial second head writes");
    let (tail, closed) = read_until_closed(&mut stream, Duration::from_secs(2)).await;
    assert!(closed, "mid-header stall did not close at header_read_timeout");
    assert!(
        tail.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "mid-header stall should answer 400 Bad Request, got: {tail:?}"
    );
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
}
