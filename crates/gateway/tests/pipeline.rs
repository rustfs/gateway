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

//! What an assembled service does with a request, asserted through the public facade only.
//!
//! Responsible for: the ordered pipeline's observable consequences — the two `501`s, the floor's
//! refusal of an unsigned request, the governor's position relative to the body, the handler
//! failure path, the observer's coverage, and the `Infallible` error type.
//! NOT responsible for: assembly refusals, which are `tests/assembly.rs`.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! Negative cases outnumber positive ones. The positive path is one exchange; every other
//! assertion here is about a request that must not reach the handler.

mod support;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use rustfs_gateway::{S3Service, ServiceBuilder};
use support::{Backend, CountingBody, Failing, Ping, Recorder, RefuseEverything, exchange, ping_route, plain, wired};

/// Negative — a request that names no operation is answered with the `501` that tells an operator
/// to check the configured domain, not with a bare "not implemented".
#[tokio::test]
async fn a_request_naming_no_operation_is_answered_with_the_configuration_hint() {
    let (status, body) = exchange(&support::service(), plain(http::Method::PATCH, "/anything")).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("virtual hosts"), "{body}");
    assert!(body.contains("<Code>NotImplemented</Code>"), "{body}");
}

/// Negative — an operation this backend does not handle reads differently from one that names no
/// operation at all. One string for both hides which of the two happened.
#[tokio::test]
async fn an_unhandled_operation_reads_differently_from_an_unrouted_one() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, plain(http::Method::GET, "/")).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("not handled by this backend"), "{body}");
    assert!(!body.contains("virtual hosts"), "{body}");
}

/// Negative — an AWS operation reached without a signature is refused by the security floor. Every
/// standard operation ships header-signatures-only, so anonymous access is opt-in and this is what
/// opting out looks like.
#[tokio::test]
async fn an_unsigned_request_to_an_aws_operation_is_refused() {
    let (status, body) = exchange(&support::service(), plain(http::Method::GET, "/")).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
}

/// Negative — a refusal body carries the code and a message and nothing the caller sent. The
/// rejection body is the only thing an unauthenticated caller can make this service produce.
#[tokio::test]
async fn a_refusal_echoes_nothing_from_the_request() {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/?marker=SECRET-VALUE")
        .header("host", "s3.example.com")
        .header("x-vendor-token", "SECRET-HEADER")
        .body(Bytes::new())
        .expect("a valid request");
    let (status, body) = exchange(&support::service(), request).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(!body.contains("SECRET-VALUE"), "{body}");
    assert!(!body.contains("SECRET-HEADER"), "{body}");
}

/// Negative — two disagreeing `Content-Length` headers are refused at acceptance. A first-wins or
/// last-wins choice here is how request smuggling is built.
#[tokio::test]
async fn a_framing_ambiguity_is_refused_at_acceptance() {
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    request
        .headers_mut()
        .append(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
    request
        .headers_mut()
        .append(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("7"));
    let (status, _body) = exchange(&support::service(), request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST);
}

/// Negative — a refusing governor answers `503 SlowDown`, and the body is never read. The byte
/// counter is what makes "before the body" a measurement rather than a claim: a governor placed
/// after the read would have paid for the upload it refused.
#[tokio::test]
async fn a_refusing_governor_answers_before_the_body_is_read() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .governor(RefuseEverything)
        .build()
        .expect("a complete assembly");

    let (body, read) = CountingBody::new(Bytes::from(vec![0_u8; 4096]));
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .header("content-length", "4096")
        .body(body)
        .expect("a valid request");

    let response = service.call(request).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(read.load(Ordering::SeqCst), 0, "the body must not have been read");
}

/// Negative — a body larger than the assembly will hold is refused with `413`, and the declared
/// length is what refuses it, so nothing is read first.
#[tokio::test]
async fn an_oversized_body_is_refused() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .max_buffered_body_bytes(16)
        .build()
        .expect("a complete assembly");

    let (body, read) = CountingBody::new(Bytes::from(vec![0_u8; 4096]));
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .header("content-length", "4096")
        .body(body)
        .expect("a valid request");

    let response = service.call(request).await;
    assert_eq!(response.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(read.load(Ordering::SeqCst), 0);
}

/// Negative — a denying authorizer stops a request that the floor admitted, so authorisation is
/// reached and is not skippable by an operation that authenticates anonymously.
#[tokio::test]
async fn a_denying_authorizer_stops_an_admitted_request() {
    let credentials = Arc::new(
        rustfs_gateway::StaticCredentials::new().with(rustfs_gateway::Credentials::new("AKIDEXAMPLE", b"secret").expect("valid")),
    );
    let service = ServiceBuilder::new()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .authenticator(rustfs_gateway::SigV4Authenticator::new(
            credentials,
            rustfs_gateway::RegionSet::new(["us-east-1"]).expect("non-empty"),
        ))
        .authorizer(rustfs_gateway::allow_when(|_| false))
        .build()
        .expect("a complete assembly");

    let (status, body) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
}

/// Negative — a handler failure becomes its own code and status, and does not escape as a
/// transport error.
#[tokio::test]
async fn a_failing_handler_becomes_a_response() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Failing))
        .route(ping_route())
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("<Code>InternalError</Code>"), "{body}");
}

/// Negative — the tower adapter never returns `Err`, whatever the request was. A `tower` layer
/// that saw an `Err` would drop the connection instead of relaying the status.
#[tokio::test]
async fn the_tower_adapter_never_returns_an_error() {
    let mut service = support::service();
    for (method, uri) in [
        (http::Method::PATCH, "/nowhere"),
        (http::Method::GET, "/"),
        (http::Method::POST, "/"),
    ] {
        // `tower_exchange` unwraps the adapter's `Result`. It compiles only because the error type
        // is `Infallible`, so this assertion is as much a compile-time one as a run-time one.
        let (status, _body) = support::tower_exchange(&mut service, plain(method, uri)).await;
        assert!(status.as_u16() >= 200);
    }
}

/// Negative — the observer is told about a request that was refused at acceptance, not only about
/// the ones that reached a handler. An audit trail with the interesting half missing is not one.
#[tokio::test]
async fn the_observer_sees_refusals_as_well_as_answers() {
    let recorder = Arc::new(Recorder::default());
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .observer(Arc::clone(&recorder))
        .build()
        .expect("a complete assembly");

    let _ = exchange(&service, plain(http::Method::POST, "/")).await;
    let _ = exchange(&service, plain(http::Method::PATCH, "/nowhere")).await;

    let seen = recorder.seen.lock().expect("not poisoned").clone();
    assert_eq!(seen, [(Some("example:Ping".to_owned()), 200), (None, 501)]);
}

/// Positive — the whole pipeline carries one request from raw bytes to an encoded answer, and the
/// answer is the handler's.
#[tokio::test]
async fn a_request_reaches_the_handler_and_comes_back_encoded() {
    let (status, body) = exchange(&support::service(), plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(body, "<Ping>pong</Ping>");
}

/// Positive — the response head is readable in emission order, which is what a conformance case
/// compares.
#[tokio::test]
async fn the_response_head_is_readable_in_wire_order() {
    let response = support::service().call_bytes(plain(http::Method::POST, "/")).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    assert_eq!(collected.header("content-type"), Some("application/xml"));
    assert!(collected.trailers().is_empty());
}

/// Positive — one service instance answers over the direct path and over the tower adapter
/// identically. Both assembly paths must agree, which is the whole reason `Transport` exists.
#[tokio::test]
async fn both_entry_points_agree() {
    let mut service: S3Service = support::service();
    let direct = exchange(&service, plain(http::Method::POST, "/")).await;
    let towered = support::tower_exchange(&mut service, plain(http::Method::POST, "/")).await;
    assert_eq!(direct, towered);
}

// ── the request identifier ──────────────────────────────────────────────────────────────────────

/// Negative — the header and the error document carry the *same* identifier. Two formatting sites
/// that agree today are two that can drift; this is the assertion that notices.
#[tokio::test]
async fn a_refusal_carries_one_identifier_in_both_places() {
    let response = support::exchange_wire(&support::service(), plain(http::Method::PATCH, "/nowhere")).await;
    let body = String::from_utf8(response.body().to_vec()).expect("utf-8");
    let header = response.header("x-amz-request-id").expect("a request id header");
    assert_eq!(support::element_text(&body, "RequestId"), Some(header), "{body}");
    let host_header = response.header("x-amz-id-2").expect("a host id header");
    assert_eq!(support::element_text(&body, "HostId"), Some(host_header), "{body}");
}

/// Negative — an identifier the caller supplied is never the one that comes back. Echoing one
/// would let a caller choose what every log line about its own request says.
#[tokio::test]
async fn a_caller_supplied_identifier_is_not_echoed() {
    let request = http::Request::builder()
        .method(http::Method::PATCH)
        .uri("/nowhere")
        .header("host", "s3.example.com")
        .header("x-amz-request-id", "CALLER-CHOSEN-0001")
        .header("x-amz-id-2", "CALLER-CHOSEN-0002")
        .body(Bytes::new())
        .expect("a valid request");
    let response = support::exchange_wire(&support::service(), request).await;
    let body = String::from_utf8(response.body().to_vec()).expect("utf-8");
    assert_ne!(response.header("x-amz-request-id"), Some("CALLER-CHOSEN-0001"));
    assert_ne!(response.header("x-amz-id-2"), Some("CALLER-CHOSEN-0002"));
    assert!(!body.contains("CALLER-CHOSEN"), "{body}");
}

/// Negative — an identifier a handler's encoder wrote does not survive either. The service mints
/// the value it will also put in a log line, so a backend cannot make the two disagree.
#[tokio::test]
async fn a_handler_supplied_identifier_does_not_win() {
    let response = support::exchange_wire(&support::service(), plain(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_ne!(response.header("x-amz-request-id"), Some(support::HANDLER_CHOSEN_ID));
    assert_eq!(response.header_values("x-amz-request-id").count(), 1);
}

/// Negative — two requests are told apart. An identifier that repeats correlates the wrong two
/// support conversations.
#[tokio::test]
async fn two_requests_are_given_different_identifiers() {
    let service = support::service();
    let first = support::exchange_wire(&service, plain(http::Method::PATCH, "/nowhere")).await;
    let second = support::exchange_wire(&service, plain(http::Method::PATCH, "/nowhere")).await;
    assert_ne!(first.header("x-amz-request-id"), second.header("x-amz-request-id"));
    assert_ne!(first.header("x-amz-id-2"), second.header("x-amz-id-2"));
}

/// Negative — the rendered alphabet is closed. Even a value that somehow came from a request could
/// not carry a quote, an angle bracket or a newline into a log line or a document.
#[tokio::test]
async fn an_identifier_is_uppercase_hexadecimal_and_nothing_else() {
    let response = support::exchange_wire(&support::service(), plain(http::Method::PATCH, "/nowhere")).await;
    let request_id = response.header("x-amz-request-id").expect("a request id header");
    let host_id = response.header("x-amz-id-2").expect("a host id header");
    assert_eq!(request_id.len(), 16, "{request_id}");
    assert_eq!(host_id.len(), 32, "{host_id}");
    for text in [request_id, host_id] {
        assert!(
            text.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)),
            "{text}"
        );
    }
}

/// Positive — a success carries the identifiers too. AWS sends them on every response, and an
/// operator correlating a slow `PutObject` has nothing to paste otherwise.
#[tokio::test]
async fn a_success_carries_the_identifiers_as_well() {
    let response = support::exchange_wire(&support::service(), plain(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(response.header("x-amz-request-id").is_some());
    assert!(response.header("x-amz-id-2").is_some());
}

/// Positive — a fixed source makes the whole response comparable byte for byte, which is what a
/// conformance case that pins an error document needs.
#[tokio::test]
async fn a_fixed_source_makes_a_response_byte_comparable() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .trace_source(rustfs_gateway::FixedTrace::at(0x0123_4567_89AB_CDEF, 0))
        .build()
        .expect("a complete assembly");
    let first = support::exchange_wire(&service, plain(http::Method::PATCH, "/nowhere")).await;
    let second = support::exchange_wire(&service, plain(http::Method::PATCH, "/nowhere")).await;
    assert_eq!(first.header("x-amz-request-id"), Some("0123456789ABCDEF"));
    assert_eq!(first.body(), second.body());
}
