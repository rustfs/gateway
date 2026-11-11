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

//! The claimed header as bytes on a socket (ADR-0051, rustfs/gateway#1586).
//!
//! Responsible for: what the service decides when the claimed header arrives through a real
//! Hyper HTTP/1 connection in the spellings a head can carry it — once, in another case, padded,
//! repeated, empty, folded over two lines, and nominated by `Connection` — measured on the wire
//! rather than inferred from the parser's documentation.
//! NOT responsible for: the floor's rules over a parsed head (`rustfs-gateway-sig`'s
//! `tests/header_token.rs`), HTTP/2, or anything a proxy in front of the host does to a head.
//! Upstream: `hyper`, `rustfs_gateway::S3Service`. Downstream: nothing.

use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::header_token::fixtures::{Answer, Established, Fixture, Handed, PRINCIPAL, assemble};

/// Sends `head_lines` as one `POST /` on a fresh connection to `fixture`, behind a layer that
/// leaves [`PRINCIPAL`] established in every request as a host's outer layer does, and returns
/// the status code and what the handler was handed, if one ran.
async fn send(fixture: &Fixture, head_lines: &[&str]) -> (u16, Vec<Handed>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a loopback listener");
    let address = listener.local_addr().expect("a bound address");
    let service = fixture.service.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("one connection");
        let outer = hyper::service::service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
            request.extensions_mut().insert(Established(PRINCIPAL));
            hyper::service::Service::call(&service, request)
        });
        // A malformed head ends the connection with an error; that is an answer, not a failure.
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(socket), outer)
            .await;
    });
    let mut stream = TcpStream::connect(address).await.expect("the client connects");
    let mut head = String::from("POST / HTTP/1.1\r\nhost: s3.example.com\r\ncontent-length: 0\r\nconnection: close\r\n");
    for line in head_lines {
        head.push_str(line);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.expect("the head writes");
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer))
        .await
        .expect("the server answers and closes")
        .expect("the answer reads");
    server.await.expect("the server task did not panic");
    let text = String::from_utf8_lossy(&answer);
    let status = text
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {text:?}"));
    let _ = fixture.stages.take();
    (status, fixture.backend.take())
}

/// Positive — one line of the claimed header reaches the floor as one token whatever the case of
/// its name and whatever optional whitespace surrounds its value, and the request is served as
/// the principal the host established. The request without the header, on the same connection
/// shape, is served as nobody: the control that the header decides anything here.
#[tokio::test]
async fn one_line_of_the_claimed_header_is_a_token_in_any_case_and_padding() {
    let fixture = assemble(Some(Answer::Accepts));
    for line in [
        "x-auth-token: gAAAAABtoken",
        "X-Auth-Token: gAAAAABtoken",
        "X-AUTH-TOKEN:gAAAAABtoken",
        "x-auth-token: \t gAAAAABtoken \t ",
    ] {
        let (status, handed) = send(&fixture, &[line]).await;
        assert_eq!(status, 200, "{line:?}");
        assert_eq!(handed.len(), 1, "{line:?}");
        assert_eq!(handed[0].header_token.as_deref(), Some(PRINCIPAL), "{line:?}");
        assert!(!handed[0].anonymous, "{line:?}");
    }
    let (status, handed) = send(&fixture, &[]).await;
    assert_eq!(status, 200);
    assert!(handed[0].anonymous && handed[0].header_token.is_none(), "{:?}", handed[0]);
}

/// Negative — a head that carries the claimed header twice, in one case or two, with equal or
/// different values, or with no value, is refused `403` and no handler runs: on an operation that
/// would serve the same request without the header, so it is never served as nobody either.
#[tokio::test]
async fn n_a_repeated_or_empty_line_on_the_wire_is_refused_and_never_served_as_nobody() {
    let fixture = assemble(Some(Answer::Accepts));
    let cases: [&[&str]; 6] = [
        &["x-auth-token: first", "x-auth-token: second"],
        &["x-auth-token: same", "x-auth-token: same"],
        &["x-auth-token: first", "X-Auth-Token: second"],
        &["x-auth-token: first", "x-other: between", "x-auth-token: second"],
        &["x-auth-token:"],
        &["x-auth-token:   "],
    ];
    for lines in cases {
        let (status, handed) = send(&fixture, lines).await;
        assert_eq!(status, 403, "{lines:?}");
        assert!(handed.is_empty(), "{lines:?}: {handed:?}");
    }
    assert_eq!(
        fixture.verifier_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the verifier was asked about a head the floor refuses"
    );
}

/// Negative — a claimed header folded over two lines never becomes a token that is served, and
/// never leaves the request to be served as nobody: the connection's parser refuses the head, or
/// the floor refuses the value. Measured, so a parser that started joining the fold would show.
#[tokio::test]
async fn n_a_folded_line_on_the_wire_is_never_a_token_and_never_nobody() {
    let fixture = assemble(Some(Answer::Accepts));
    for lines in [
        &["x-auth-token: first", " second"][..],
        &["x-auth-token:", " folded"][..],
        &["x-auth-token: first", "\tsecond"][..],
    ] {
        let (status, handed) = send(&fixture, lines).await;
        assert!(status == 400 || status == 403, "{lines:?}: {status}");
        assert!(handed.is_empty(), "{lines:?}: {handed:?}");
    }
}

/// Positive and negative — a `Connection` field that nominates the claimed header does not make
/// the service read the request as nobody: this hop received the header, the floor decides by
/// it, and the request is served as the established principal. Removing a nominated field is a
/// proxy's duty before this hop, which the record of the decision states as the host's.
#[tokio::test]
async fn a_claimed_header_nominated_by_connection_is_still_decided_by_the_claim() {
    let fixture = assemble(Some(Answer::Accepts));
    let (status, handed) = send(&fixture, &["x-auth-token: gAAAAABtoken", "connection: x-auth-token"]).await;
    assert_eq!(status, 200);
    assert_eq!(handed[0].header_token.as_deref(), Some(PRINCIPAL));
    let (status, handed) = send(&fixture, &["x-auth-token: a", "x-auth-token: b", "connection: x-auth-token"]).await;
    assert_eq!(status, 403);
    assert!(handed.is_empty());
}
