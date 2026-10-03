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

//! An early answer over an upload still arriving, with the service hosted by a plain Hyper HTTP/1
//! server the way RustFS hosts it (rustfs/gateway#1120).
//!
//! Responsible for: the wire scenarios of RustFS's `EarlyResponseBodyService` tests
//! (`rustfs/src/server/http.rs:3198-3291`, rustfs/rustfs#7019) against
//! `ServiceBuilder::drain_unread_request_bodies`: a `PutObject` its handler refuses without
//! reading, over a 2 MiB body the peer is still writing through a small send buffer, with and
//! without `Expect: 100-continue` — the answer arrives before the upload is finished, closes the
//! connection, invites no further upload, and the upload itself completes without a reset; and the
//! same assembly without the setting, whose answer announces no close.
//! NOT responsible for: this crate's own server, which lingers on the socket it owns
//! (`crates/server/tests/lingering_close.rs`), or the drain's rules one by one
//! (`src/unread_body_tests.rs`).
//! Upstream: `tests/support`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic)]

use crate::support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hyper_util::rt::TokioIo;
use rustfs_gateway::{Handler, HandlerError, HandlerErrorContext, HandlerResult, Req, S3Service, UnreadBodyDrain, dto};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

const FIRST_CHUNK: usize = 4096;
const BODY_LENGTH: usize = 2 * 1024 * 1024;

/// Refuses every upload without reading a byte of it.
struct RefusesUnread;

impl Handler<dto::PutObject> for RefusesUnread {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        drop(request.into_input());
        Err(HandlerError::from(HandlerErrorContext::missing_bucket()))
    }
}

fn assembly(drain: Option<UnreadBodyDrain>) -> S3Service {
    let builder = support::wired_at_signed_time().register::<dto::PutObject, _>(Arc::new(RefusesUnread));
    match drain {
        Some(drain) => builder.drain_unread_request_bodies(drain),
        None => builder,
    }
    .build()
    .expect("a PutObject assembly")
}

fn body() -> Vec<u8> {
    let mut body = vec![b'a'; FIRST_CHUNK];
    body.resize(BODY_LENGTH, b'b');
    body
}

/// The signed request's head, as the bytes a client writes.
fn head(expect_continue: bool) -> Vec<u8> {
    let request = support::signed_target_with_body(http::Method::PUT, "/bucket/object", Bytes::from(body()));
    let mut head = format!("PUT {} HTTP/1.1\r\n", request.uri());
    for (name, value) in request.headers() {
        if name == http::header::CONTENT_LENGTH {
            continue;
        }
        head.push_str(&format!("{name}: {}\r\n", value.to_str().expect("a printable header")));
    }
    head.push_str(&format!("content-length: {BODY_LENGTH}\r\n"));
    if expect_continue {
        head.push_str("expect: 100-continue\r\n");
    }
    head.push_str("\r\n");
    head.into_bytes()
}

/// Hosts `service` on one plain Hyper HTTP/1 connection, as an embedding host does.
async fn host(service: S3Service) -> (SocketAddr, tokio::task::JoinHandle<Result<(), hyper::Error>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a loopback listener");
    let address = listener.local_addr().expect("a bound address");
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("one connection");
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(socket), service)
            .await
    });
    (address, server)
}

struct Exchange {
    response: String,
    upload: std::io::Result<()>,
    server: Result<Result<(), hyper::Error>, tokio::time::error::Elapsed>,
}

/// Writes the head and the first 4 KiB, reads the answer, then writes the rest and shuts down.
async fn upload_refused_early(service: S3Service, expect_continue: bool) -> Exchange {
    let (address, server) = host(service).await;
    let stream = TcpStream::connect(address).await.expect("the client connects");
    socket2::SockRef::from(&stream)
        .set_send_buffer_size(4096)
        .expect("a small send buffer");
    let (mut reader, mut writer) = stream.into_split();
    writer.write_all(&head(expect_continue)).await.expect("the head writes");
    if expect_continue {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let body = body();
    writer.write_all(&body[..FIRST_CHUNK]).await.expect("the first chunk writes");
    let go = Arc::new(Notify::new());
    let writer_go = Arc::clone(&go);
    let writer_task = tokio::spawn(async move {
        writer_go.notified().await;
        writer.write_all(&body[FIRST_CHUNK..]).await?;
        writer.shutdown().await
    });
    let mut received = Vec::new();
    let answer = tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0_u8; 1024];
        loop {
            let read = reader.read(&mut chunk).await?;
            if read == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed before the answer"));
            }
            received.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&received).to_ascii_lowercase();
            if let Some(start) = text.find("http/1.1 404")
                && text[start..].contains("\r\n\r\n")
            {
                return Ok::<(), std::io::Error>(());
            }
        }
    })
    .await;
    go.notify_one();
    answer
        .expect("the answer arrives before the upload is finished")
        .expect("the answer is readable");
    let upload = writer_task.await.expect("the writer task");
    let server = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .map(|joined| joined.expect("the server task"));
    Exchange {
        response: String::from_utf8_lossy(&received).to_ascii_lowercase(),
        upload,
        server,
    }
}

/// Positive — with the setting, the refusal of an upload still arriving is answered at once and
/// announces the close; the peer then finishes its upload without a reset, and the connection ends
/// cleanly once the body is read out.
#[tokio::test]
async fn an_early_refusal_is_answered_and_the_upload_drained_on_a_hyper_host() {
    let exchange = upload_refused_early(assembly(Some(UnreadBodyDrain::with_idle_timeout(Duration::from_secs(5)))), false).await;
    assert!(exchange.response.contains("http/1.1 404"), "{}", exchange.response);
    assert!(exchange.response.contains("<code>nosuchbucket</code>"), "{}", exchange.response);
    assert!(exchange.response.contains("connection: close"), "{}", exchange.response);
    exchange.upload.expect("the peer's upload met a reset instead of a drain");
    exchange
        .server
        .expect("the connection outlived the drained upload")
        .expect("the connection ended cleanly");
}

/// Negative — `Expect: 100-continue` is not answered with an invitation to keep uploading before
/// the refusal; the rest is as without the header.
#[tokio::test]
async fn an_early_refusal_invites_no_further_upload_under_expect_continue() {
    let exchange = upload_refused_early(assembly(Some(UnreadBodyDrain::with_idle_timeout(Duration::from_secs(5)))), true).await;
    assert!(exchange.response.contains("http/1.1 404"), "{}", exchange.response);
    assert!(!exchange.response.contains("100 continue"), "{}", exchange.response);
    assert!(exchange.response.contains("connection: close"), "{}", exchange.response);
    exchange.upload.expect("the peer's upload met a reset instead of a drain");
    exchange
        .server
        .expect("the connection outlived the drained upload")
        .expect("the connection ended cleanly");
}

/// Negative control — the same refusal without the setting announces no close: the handler's
/// refusal leaves the connection to the transport, which is the case the setting exists for.
#[tokio::test]
async fn n_without_the_setting_the_answer_announces_no_close() {
    let (address, server) = host(assembly(None)).await;
    let mut stream = TcpStream::connect(address).await.expect("the client connects");
    stream.write_all(&head(false)).await.expect("the head writes");
    stream
        .write_all(&body()[..FIRST_CHUNK])
        .await
        .expect("the first chunk writes");
    let mut received = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0_u8; 1024];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => received.extend_from_slice(&chunk[..read]),
            }
            if String::from_utf8_lossy(&received).contains("</Error>") {
                return;
            }
        }
    })
    .await;
    let response = String::from_utf8_lossy(&received).to_ascii_lowercase();
    assert!(response.contains("http/1.1 404"), "{response}");
    assert!(!response.contains("connection: close"), "{response}");
    server.abort();
}
