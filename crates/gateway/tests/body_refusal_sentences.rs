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

//! The RustFS-profile switch that answers a request-body refusal with legacy RustFS's sentence,
//! over a real socket (rustfs/gateway#1099).
//!
//! Responsible for: a body cut short on the wire — a transport error only a real socket produces —
//! answered `400 IncompleteBody` with legacy RustFS's sentence under
//! `ServiceBuilder::answer_body_refusals_with_legacy_rustfs_sentences`, and with the gateway's own
//! sentence without it; and a declared length past the wire ceiling answered with legacy RustFS's
//! `EntityTooLarge` sentence under the switch only. The code, the status and the handler never
//! seeing a complete body are the same either way.
//! NOT responsible for: the sentence table (`builder/legacy_sentences.rs`) or the launcher that
//! turns the switch on (`compat/sut`).
//! Upstream: the streaming fixture in `streaming_request.rs`. Downstream: none.

#![allow(clippy::expect_used, clippy::panic)]

use super::streaming_request::{StreamingPut, SwallowingBackend, live_server, stop, streaming_dialect};
use crate::support;

use std::sync::Arc;
use std::time::Duration;

use rustfs_gateway::{RequestBodyDeadlineConfig, S3Service, ServiceConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const LEGACY_INCOMPLETE_BODY: &str = "You did not provide the number of bytes specified by the Content-Length HTTP header.";
const LEGACY_UPLOAD_TOO_LARGE: &str = "Request body exceeds the configured maximum object size.";

fn service(legacy_sentences: bool) -> S3Service {
    let deadlines = RequestBodyDeadlineConfig::new(Duration::from_secs(1), Duration::from_secs(1)).expect("non-zero deadlines");
    let mut builder = support::wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<StreamingPut, _>(Arc::new(SwallowingBackend))
        .dialect(&streaming_dialect());
    if legacy_sentences {
        builder = builder.answer_body_refusals_with_legacy_rustfs_sentences();
    }
    let (builder, _handle) = builder.config(ServiceConfig::new(1024 * 1024).with_request_body_deadlines(deadlines));
    builder.build().expect("a complete streaming assembly")
}

/// Sends `head` and `body`, publishes EOF, and reads the whole answer.
async fn send(service: S3Service, head: String, body: &[u8]) -> String {
    let running = live_server(service);
    let mut stream = TcpStream::connect(running.local_addr).await.expect("the client connects");
    stream.write_all(head.as_bytes()).await.expect("the head writes");
    stream.write_all(body).await.expect("the body writes");
    stream.shutdown().await.expect("the client publishes EOF");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("the refusal completes")
        .expect("the response reads");
    stop(running).await;
    String::from_utf8(response).expect("an HTTP/1.1 response")
}

fn message_of(text: &str) -> Option<&str> {
    let start = text.find("<Message>")? + "<Message>".len();
    let end = text[start..].find("</Message>")? + start;
    Some(&text[start..end])
}

fn put(content_length: u64) -> String {
    format!("PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n")
}

/// Positive — under the switch a body cut short on the wire is `IncompleteBody` with legacy
/// RustFS's sentence.
#[tokio::test]
async fn a_body_cut_short_answers_legacy_rustfs_s_incomplete_body_sentence() {
    let text = send(service(true), put(30), b"only ten b").await;
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
    assert!(text.contains("<Code>IncompleteBody</Code>"), "{text}");
    assert_eq!(message_of(&text), Some(LEGACY_INCOMPLETE_BODY), "{text}");
}

/// Negative — without the switch the same refusal keeps the gateway's own sentence and code.
#[tokio::test]
async fn n_without_the_switch_a_body_cut_short_keeps_the_gateway_s_sentence() {
    let text = send(service(false), put(30), b"only ten b").await;
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
    assert!(text.contains("<Code>IncompleteBody</Code>"), "{text}");
    assert_ne!(message_of(&text), Some(LEGACY_INCOMPLETE_BODY), "{text}");
    assert!(message_of(&text).is_some_and(|message| !message.is_empty()), "{text}");
}

/// Positive and negative — a declared length past the wire ceiling is `400 EntityTooLarge` either
/// way, with legacy RustFS's sentence only under the switch.
#[tokio::test]
async fn a_declared_length_past_the_ceiling_answers_legacy_rustfs_s_sentence_only_under_the_switch() {
    let past = 5 * 1024 * 1024 * 1024 + 1;
    let legacy = send(service(true), put(past), b"").await;
    assert!(legacy.starts_with("HTTP/1.1 400"), "{legacy}");
    assert!(legacy.contains("<Code>EntityTooLarge</Code>"), "{legacy}");
    assert_eq!(message_of(&legacy), Some(LEGACY_UPLOAD_TOO_LARGE), "{legacy}");

    let gateway = send(service(false), put(past), b"").await;
    assert!(gateway.contains("<Code>EntityTooLarge</Code>"), "{gateway}");
    assert_ne!(message_of(&gateway), Some(LEGACY_UPLOAD_TOO_LARGE), "{gateway}");
}
