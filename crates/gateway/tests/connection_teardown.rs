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

//! Compile-time or regression support for this module.
//!
//! Responsible for: exercising the contract named by this file.
//! NOT responsible for: implementing the production behavior under test.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

//! What a refusal does to the connection it arrived on, checked where the decision is carried.
//!
//! Two flags — `WireReject::must_close_connection` and `ChunkReject::must_close_connection` — were
//! declared, returned a constant, and were dropped by the renderer, so no response ever carried
//! `Connection: close` and no assertion that read either one could fail. That is
//! <https://github.com/rustfs/gateway/issues/20>. The suite below pins the three halves of the
//! repair separately, because they fail independently:
//!
//! 1. the flag branches (`crates/http`'s own suites, and `rustfs_gateway::close`'s unit tests);
//! 2. the renderer carries it onto the response, in the extensions — this file;
//! 3. a transport reads it and turns it into `Connection: close` on a socket it then closes.
//!    `crate::adapt` does the header half for the hyper and tower paths; nothing in this crate does
//!    the socket half, because nothing in this crate owns a socket.
//!
//! # Why the verdict is not a header until a transport says so
//!
//! `Connection` is hop-by-hop. `render` used to write it, which made this crate a second writer
//! behind whatever transport was already writing its own — and a response reached the wire carrying
//! `Connection: close` *and* `Connection: keep-alive`. The verdict now travels in the response's
//! extensions, which never reach the wire, and exactly one place turns it into a header.
//!
//! # What this file deliberately does not claim
//!
//! Nothing below asserts that a connection closed. A test in this crate that said so would be
//! reporting the service's intention as an observation, which is the defect class the issue was
//! opened about and which this suite has now produced six times. Every assertion here is about a
//! value or a header, and is worded as one.

use crate::support;

use bytes::Bytes;
use rustfs_gateway::{ConnectionIntent, Limits, S3Service, connection_intent_of};
use support::{Backend, Failing, Ping, ping_route, plain, service, wired, wired_denying};

async fn refusal(service: &S3Service, request: http::Request<Bytes>) -> http::Response<rustfs_gateway::Body> {
    service.call_bytes(request).await
}

#[tokio::test]
async fn a_framing_conflict_reaches_the_response_as_a_close() {
    let mut request = plain(http::Method::POST, "/");
    request
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
    request
        .headers_mut()
        .insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
    let response = refusal(&service(), request).await;
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::Close));
}

#[tokio::test]
async fn a_head_verdict_reaches_the_response_without_one() {
    let mut request = plain(http::Method::POST, "/");
    request
        .headers_mut()
        .append(http::header::HOST, http::HeaderValue::from_static("other.example"));
    let response = refusal(&service(), request).await;
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::MayKeepAlive));
}

#[tokio::test]
async fn the_body_ceiling_closes_and_a_head_ceiling_does_not() {
    let body_limits = Limits {
        max_body_bytes: 0,
        ..Limits::default()
    };
    let body_service = wired()
        .register::<Ping, _>(std::sync::Arc::new(Backend))
        .route(ping_route())
        .limits(body_limits)
        .build()
        .expect("a complete assembly");
    let mut request = plain(http::Method::POST, "/");
    request
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("1"));
    let response = refusal(&body_service, request).await;
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::Close));

    let head_limits = Limits {
        max_header_count: 0,
        ..Limits::default()
    };
    let head_service = wired()
        .register::<Ping, _>(std::sync::Arc::new(Backend))
        .route(ping_route())
        .limits(head_limits)
        .build()
        .expect("a complete assembly");
    let response = refusal(&head_service, plain(http::Method::POST, "/")).await;
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::MayKeepAlive));
}

#[tokio::test]
async fn an_authorisation_denial_keeps_the_connection() {
    let service = wired_denying()
        .register::<Ping, _>(std::sync::Arc::new(Backend))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    let response = refusal(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::MayKeepAlive));
}

#[tokio::test]
async fn an_ordinary_refusal_keeps_the_connection_and_no_refusal_writes_the_header() {
    let service = wired()
        .register::<Ping, _>(std::sync::Arc::new(Failing))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    let response = refusal(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(connection_intent_of(&response), Some(ConnectionIntent::MayKeepAlive));
    assert!(response.headers().get(http::header::CONNECTION).is_none());
}

#[tokio::test]
async fn a_response_no_refusal_produced_carries_no_verdict() {
    let response = refusal(&service(), plain(http::Method::POST, "/")).await;
    assert_eq!(connection_intent_of(&response), None);
}
