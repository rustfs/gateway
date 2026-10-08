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

//! When the self-held driver invites a body with `100 Continue` (rustfs/gateway#1222).
//!
//! Responsible for: a request carrying `Expect: 100-continue` that is refused before its body is
//! read — by authentication, or by its handler — being answered with the refusal alone, and the
//! connection then closing; the invitation for a body the service does read is
//! `self_held_http1.rs`'s `production_driver_answers_expect_continue_before_reading_the_body`.
//! NOT responsible for: the Hyper driver, which already invites only on the first body read, or
//! unsupported expectations (`417`, `self_held_http1.rs`).
//! Upstream: `rustfs-gateway`'s self-held driver over the streaming fixture in
//! `support/streaming.rs`. Downstream: none.

#![allow(clippy::expect_used, clippy::panic)]

use crate::support::streaming::{StreamingPut, service_with_deadlines};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustfs_gateway::{
    Handler, HandlerErrorContext, HandlerResult, Req, RequestBodyDeadlineConfig, RunningServer, SelfHeldHttp1Driver,
};
use rustfs_gateway_server::{Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Refuses without reading a byte of the body: `404 NoSuchBucket`, which may keep the connection.
struct RefusesUnread;

impl Handler<StreamingPut> for RefusesUnread {
    async fn call(&self, request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        drop(request.into_input());
        Err(HandlerErrorContext::missing_bucket().into())
    }
}

fn serve() -> RunningServer {
    let deadlines = RequestBodyDeadlineConfig::new(Duration::from_secs(1), Duration::from_secs(1)).expect("non-zero deadlines");
    let config = ServerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plaintext: true,
        // Longer than every wait below: a driver that drained the uninvited body before answering
        // would miss them, while the lingering close after an answer ends on its short quiet grace.
        lingering_close_time: Duration::from_secs(30),
        ..ServerConfig::default()
    };
    Server::new(config, service_with_deadlines(Arc::new(RefusesUnread), deadlines))
        .serve_with(SelfHeldHttp1Driver)
        .expect("the loopback server starts")
}

/// Sends `head`, and no body, then reads everything the server writes until it closes.
async fn answer_to(head: &[u8]) -> String {
    let running = serve();
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(head).await.expect("the head writes");
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer))
        .await
        .expect("the server answers and closes without waiting for a body it never invited")
        .expect("the answer reads");
    let _ = running.shutdown.trigger(Duration::from_secs(1)).await;
    let _ = running.task.await;
    String::from_utf8_lossy(&answer).into_owned()
}

/// Negative — the handler refuses without reading the body. Before #1222 the driver wrote
/// `100 Continue` as soon as it parsed the head, inviting thirty octets that would never be read.
#[tokio::test]
async fn a_request_its_handler_refuses_unread_is_never_invited_to_send_its_body() {
    let answer = answer_to(b"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 30\r\nExpect: 100-continue\r\n\r\n").await;
    assert!(
        answer.starts_with("HTTP/1.1 404"),
        "the first thing written was not the refusal: {answer}"
    );
    assert!(!answer.contains("100 Continue"), "{answer}");
    assert!(answer.contains("<Code>NoSuchBucket</Code>"), "{answer}");
    assert!(answer.to_ascii_lowercase().contains("connection: close"), "{answer}");
}

/// Negative — a request whose credential is unknown is refused before any body is read; the
/// driver used to invite that body before authentication had even run.
#[tokio::test]
async fn an_unauthenticated_request_is_never_invited_to_send_its_body() {
    let answer = answer_to(
        b"PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 30\r\nExpect: 100-continue\r\n\
          x-amz-date: 20260102T030405Z\r\n\
          x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n\
          Authorization: AWS4-HMAC-SHA256 Credential=AKIDUNKNOWN/20260102/us-east-1/s3/aws4_request, \
          SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
          Signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\r\n",
    )
    .await;
    assert!(
        answer.starts_with("HTTP/1.1 403"),
        "the first thing written was not the refusal: {answer}"
    );
    assert!(!answer.contains("100 Continue"), "{answer}");
    assert!(answer.to_ascii_lowercase().contains("connection: close"), "{answer}");
}
