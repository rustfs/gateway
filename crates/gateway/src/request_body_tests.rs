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

//! Unit contracts for the live request-body producer.
//!
//! Responsible for: read-ahead, logical-size, resident-frame, and early-drop behavior.
//! NOT responsible for: live sockets or process RSS.
//! Upstream: `request_body`. Downstream: c-ing-0061 and c-ing-0063 acceptance evidence.

use bytes::Bytes;
use rustfs_gateway_http::BodyIntegrity;
use rustfs_gateway_types::ErrorCode;

use crate::gate::{Authenticated, BodyCeilings, BodyDigestObligation, BodyTimeouts, SealedBody};

const fn roomy() -> BodyCeilings {
    BodyCeilings {
        buffered: 1024 * 1024,
        whole_body: true,
        declared: None,
    }
}

/// `c-ing-0061`. Negative — opening a stream does not poll its transport.
#[tokio::test]
async fn opening_a_streaming_body_does_not_read_ahead() {
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"first-"), Bytes::from_static(b"second")]);
    let opened = SealedBody::seal(Some(body), Some(12))
        .stream(
            &proof,
            (roomy(), BodyTimeouts::S3, None),
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .ok();
    assert!(opened.is_some(), "the streaming body did not open");
    let Some(opened) = opened else {
        return;
    };
    assert_eq!(read.bytes_read(), 0, "opening the handler stream polled the transport");
    let (stream, terminal) = opened.into_parts();
    let collected = crate::wire::collect(http::Response::new(stream.into_body())).await.ok();
    assert!(collected.is_some(), "the handler did not drain the stream");
    let Some(collected) = collected else {
        return;
    };
    assert_eq!(collected.body(), &Bytes::from_static(b"first-second"));
    assert!(terminal.wait().await.is_ok());
    assert!(read.is_exhausted());
}

/// `c-ing-0063`. Positive — logical size may exceed the resident window.
#[tokio::test]
async fn a_streaming_body_may_exceed_its_resident_window() {
    const FRAME_BYTES: usize = 768 * 1024;
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([
        Bytes::from(vec![b'a'; FRAME_BYTES]),
        Bytes::from(vec![b'b'; FRAME_BYTES]),
        Bytes::from(vec![b'c'; FRAME_BYTES]),
    ]);
    let opened = SealedBody::seal(Some(body), Some((3 * FRAME_BYTES) as u64))
        .stream(
            &proof,
            (BodyCeilings::streaming(None), BodyTimeouts::S3, None),
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .ok();
    assert!(opened.is_some(), "the large logical stream did not open");
    let Some(opened) = opened else {
        return;
    };
    let (stream, terminal) = opened.into_parts();
    let collected = crate::wire::collect(http::Response::new(stream.into_body())).await.ok();
    assert!(collected.is_some(), "the handler did not drain the stream");
    let Some(collected) = collected else {
        return;
    };
    assert_eq!(collected.body().len(), 3 * FRAME_BYTES);
    assert!(terminal.wait().await.is_ok());
    assert_eq!(read.bytes_read(), (3 * FRAME_BYTES) as u64);
}

/// `c-ing-0063`. Negative — one transport frame cannot widen the resident window.
#[tokio::test]
async fn a_streaming_frame_wider_than_the_resident_window_is_refused() {
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from(vec![0_u8; 1024 * 1024 + 1])]);
    let opened = SealedBody::seal(Some(body), None)
        .stream(
            &proof,
            (BodyCeilings::streaming(None), BodyTimeouts::S3, None),
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .ok();
    assert!(opened.is_some(), "the head-level stream did not open");
    let Some(opened) = opened else {
        return;
    };
    let (stream, terminal) = opened.into_parts();
    assert!(crate::wire::collect(http::Response::new(stream.into_body())).await.is_err());
    let error = terminal.wait().await.err();
    assert_eq!(error.as_ref().and_then(crate::render::S3Error::code), Some(&ErrorCode::ENTITY_TOO_LARGE));
    assert_eq!(read.bytes_read(), (1024 * 1024 + 1) as u64);
}

/// Negative — dropping before EOF cannot manufacture a successful terminal verdict.
#[tokio::test]
async fn dropping_an_unread_streaming_body_refuses_commit() {
    let proof = Authenticated::granted_for_test();
    let (body, read) = crate::probe::ObservedBody::new([Bytes::from_static(b"body")]);
    let opened = SealedBody::seal(Some(body), Some(4))
        .stream(
            &proof,
            (roomy(), BodyTimeouts::S3, None),
            None,
            BodyDigestObligation::None,
            BodyIntegrity::NONE,
        )
        .ok();
    assert!(opened.is_some(), "the streaming body did not open");
    let Some(opened) = opened else {
        return;
    };
    let (stream, terminal) = opened.into_parts();
    drop(stream);
    let error = terminal.wait().await.err();
    assert_eq!(error.as_ref().and_then(crate::render::S3Error::code), Some(&ErrorCode::INCOMPLETE_BODY));
    assert_eq!(read.bytes_read(), 0, "dropping the stream drained the peer");
}
