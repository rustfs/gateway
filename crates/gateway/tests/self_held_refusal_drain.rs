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
//! `streaming_request.rs`. Downstream: none.

#![allow(clippy::expect_used, clippy::panic)]

use super::streaming_request::{StreamingPut, service_with_deadlines};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustfs_gateway::{
    Handler, HandlerErrorContext, HandlerResult, Req, RequestBodyDeadlineConfig, RunningServer, SelfHeldHttp1Driver,
};
use rustfs_gateway_server::{Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const HEAD: &[u8] = b"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 30\r\n\r\n";
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
