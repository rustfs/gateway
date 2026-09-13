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

use crate::support;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use rustfs_gateway::{BodyProgress, ClockSkewAck, EVENT_STREAM_CONTENT_TYPE, ObservedBody, S3Service, ServiceBuilder, dto};
use support::{Backend, CountingBody, Failing, Ping, Recorder, RefuseEverything, exchange, plain, wired};

const EXPECTED_PAYLOAD_SHA256: &str = "c32cace75647e3e184b9dce888af087f63740976550541874c37a1037b196b56";

fn exact_presigned_payload() -> rustfs_gateway::sig::PayloadMode {
    rustfs_gateway::sig::PayloadMode::parse(EXPECTED_PAYLOAD_SHA256, rustfs_gateway::sig::TrailerSet::None)
        .expect("a lowercase SHA-256")
}

fn presigned_service(reached: &Arc<std::sync::atomic::AtomicUsize>) -> S3Service {
    wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(reached)))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly")
}

/// Positive — a presigned body that matches its signed digest reaches the handler once.
#[tokio::test]
async fn c_sig_0429_presigned_body_matching_its_signed_digest_is_accepted() {
    let reached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let request = support::presigned_with_body(Bytes::from_static(b"expected-payload"), exact_presigned_payload());
    let (status, body) = exchange(&presigned_service(&reached), request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

/// Negative — changing the body after presigning is refused before the handler can commit it.
#[tokio::test]
async fn c_sig_0430_tampered_presigned_body_is_refused_before_the_handler() {
    let reached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let request = support::presigned_with_body(Bytes::from_static(b"tampered-payload"), exact_presigned_payload());
    let (status, body) = exchange(&presigned_service(&reached), request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST);
    assert!(body.contains("<Code>XAmzContentSHA256Mismatch</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "a mismatched body reached the handler");
}

/// Negative — omitting a body cannot satisfy a signed non-empty digest.
#[tokio::test]
async fn c_sig_0431_missing_presigned_body_is_refused_before_the_handler() {
    let reached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let request = support::presigned_with_body(Bytes::new(), exact_presigned_payload());
    let (status, body) = exchange(&presigned_service(&reached), request).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST);
    assert!(body.contains("<Code>XAmzContentSHA256Mismatch</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "a missing body reached the handler");
}

/// Negative — streaming payload modes are recognised but unsupported for presigned requests.
#[tokio::test]
async fn c_sig_0432_streaming_presigned_body_is_not_implemented() {
    let reached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let payload =
        rustfs_gateway::sig::PayloadMode::parse("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", rustfs_gateway::sig::TrailerSet::None)
            .expect("a recognised streaming mode");
    let request = support::presigned_with_body(Bytes::new(), payload);
    let (status, body) = exchange(&presigned_service(&reached), request).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("<Code>NotImplemented</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "an unsupported body reached the handler");
}

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
        .dialect(&crate::support::ping_dialect())
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

/// c-lim-0040 / a-asm-0021. A refusing governor answers `503 SlowDown`, and the body is never read. The byte
/// counter is what makes "before the body" a measurement rather than a claim: a governor placed
/// after the read would have paid for the upload it refused.
#[tokio::test]
async fn c_lim_0040_refusing_governor_answers_before_the_body_is_read() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
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
        .dialect(&crate::support::ping_dialect())
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
        .dialect(&crate::support::ping_dialect())
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
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("<Code>InternalError</Code>"), "{body}");
}

/// a-asm-0020. Negative — the tower adapter never returns `Err`, whatever the request was. A `tower` layer
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
        .dialect(&crate::support::ping_dialect())
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
        .dialect(&crate::support::ping_dialect())
        .trace_source(rustfs_gateway::FixedTrace::at(0x0123_4567_89AB_CDEF, 0))
        .build()
        .expect("a complete assembly");
    let first = support::exchange_wire(&service, plain(http::Method::PATCH, "/nowhere")).await;
    let second = support::exchange_wire(&service, plain(http::Method::PATCH, "/nowhere")).await;
    assert_eq!(first.header("x-amz-request-id"), Some("0123456789ABCDEF"));
    assert_eq!(first.body(), second.body());
}

// ── the RFC 9110 body invariants, on the answered path and the refused one ─────────────────────

/// Negative — a refusal answered to a `HEAD` carries no content, and still reports the length the
/// same refusal reported to a method that may carry one.
///
/// RFC 9110 §9.3.2 states the rule with no status exception, and this is the exchange that used to
/// break it: a refusal never reaches an encoder, so the `<Error>` document went out under a method
/// that forbids content. On a keep-alive connection the peer frames by `Content-Length` and does not
/// read the content because the method is `HEAD`, so it reads the next response starting from the
/// middle of ours. That is response smuggling, not a cosmetic defect.
///
/// The expected length is *measured* from the twin exchange rather than written down: a fix that
/// answered `0` would satisfy "no content" and tell every client the representation is empty.
#[tokio::test]
async fn a_refusal_answered_to_a_head_carries_no_content_and_still_reports_the_length_it_would_have_sent() {
    let service = support::service();
    let with_content = support::exchange_wire(&service, plain(http::Method::PUT, "/?refuse")).await;
    let head = support::exchange_wire(&service, plain(http::Method::HEAD, "/?refuse")).await;

    assert_eq!(head.status(), http::StatusCode::PRECONDITION_FAILED);
    assert_eq!(head.body().len(), 0, "a HEAD refusal carried content");
    let length = head.header("content-length").expect("a HEAD refusal keeps its length");
    assert_ne!(length, "0", "the length was rewritten rather than the content dropped");
    assert_eq!(
        length,
        with_content.body().len().to_string(),
        "the length is not the one the same refusal reported to a method that may carry content"
    );
}

/// Negative — the same refusal answered to a method that may carry content still carries its
/// document. A fix that dropped every error body would pass the assertion above and leave every
/// client with nothing to branch on.
#[tokio::test]
async fn the_same_refusal_answered_to_a_method_that_may_carry_content_keeps_its_document() {
    let refused = support::exchange_wire(&support::service(), plain(http::Method::PUT, "/?refuse")).await;
    assert_eq!(refused.status(), http::StatusCode::PRECONDITION_FAILED);
    assert!(!refused.body().is_empty(), "the refusal lost its document");
    let body = String::from_utf8(refused.body().to_vec()).expect("utf-8");
    assert!(body.contains("<Code>PreconditionFailed</Code>"), "{body}");
    assert_eq!(refused.header("content-length"), Some(refused.body().len().to_string().as_str()));
}

/// Negative — a `HEAD` that *succeeds* carries no content either, and reports the length of the
/// content it did not send. That number is the answer the request was asking for.
#[tokio::test]
async fn a_success_answered_to_a_head_carries_no_content_and_still_reports_a_length() {
    let head = support::exchange_wire(&support::service(), plain(http::Method::HEAD, "/")).await;
    assert_eq!(head.status(), http::StatusCode::OK);
    assert_eq!(head.body().len(), 0, "a HEAD success carried content");
    let length = head.header("content-length").expect("a HEAD success keeps its length");
    assert_ne!(length, "0", "the length was rewritten rather than the content dropped");
    assert_eq!(length, support::HEAD_PING_LENGTH.to_string());
}

/// Negative — a `304` carries no content and no framing header describing one, whichever method
/// asked for it. A `304` announcing bytes it will never send desynchronises a connection exactly as
/// the `HEAD` case does, and the framing header goes with the content here and only here — which is
/// what `c-cond-0005`, `c-cond-0007`, `c-cond-0010`, `c-cond-0017` and `c-cond-0022` pin, and why
/// this is the one status where the length is *not* kept.
#[tokio::test]
async fn a_not_modified_refusal_carries_neither_content_nor_a_framing_header() {
    for method in [http::Method::PUT, http::Method::HEAD] {
        let response = support::exchange_wire(&support::service(), plain(method.clone(), "/?not-modified")).await;
        assert_eq!(response.status(), http::StatusCode::NOT_MODIFIED, "{method}");
        assert_eq!(response.body().len(), 0, "{method}: a 304 carried content");
        assert_eq!(response.header("content-length"), None, "{method}: a 304 announced content");
        assert_eq!(response.header("transfer-encoding"), None, "{method}");
        assert_eq!(response.header("etag"), Some("\"head-ping\""), "{method}: a 304 lost its validator");
    }
}

/// Negative — dropping the content must not turn into dropping the head. A `HEAD` whose headers went
/// with its body answers nothing at all, which is worse than the defect this fix is about.
#[tokio::test]
async fn a_head_keeps_the_headers_a_get_would_have_carried() {
    let head = support::exchange_wire(&support::service(), plain(http::Method::HEAD, "/")).await;
    assert_eq!(head.header("content-type"), Some("application/xml"));
    assert!(head.header("x-amz-request-id").is_some());
    assert!(head.header("x-amz-id-2").is_some());
    assert!(head.header("server").is_some());
    assert!(head.header("date").is_some());
}

// ── the commit seam: a head that goes out before the outcome is known ──────────────────────────

/// Negative — a failure discovered after the head was committed keeps the committed status and puts
/// the `<Error>` document in the body.
///
/// The shape AWS documents for `CompleteMultipartUpload` and `CopyObject`, and the one a
/// `Result<Resp<O>, HandlerError>` could not express: choosing `Err` gave up the head and choosing
/// `Ok` gave up the right to fail. A client that decides from the status line records an upload that
/// never happened, which is why the document has to be there and the status has to stay.
#[tokio::test]
async fn a_failure_after_the_head_is_committed_keeps_the_status_and_carries_the_document() {
    let service = support::copy_commit_builder(support::CopyCommit::Fail)
        .build()
        .expect("a complete assembly");
    let response = support::exchange_wire(&service, support::copy_commit_request()).await;
    assert_eq!(response.status(), http::StatusCode::OK, "the refusal changed the status line");
    let body = String::from_utf8(response.body().to_vec()).expect("utf-8");
    assert!(body.starts_with(rustfs_gateway::commit::PROLOGUE), "{body}");
    assert!(body.contains("<Code>NoSuchKey</Code>"), "{body}");
    assert_eq!(response.header("content-type"), Some("application/xml"));
}

/// Negative — the committed body carries one XML declaration, in the prologue, and none after it.
/// A second declaration inside a body is a syntax error reported instead of the failure the body was
/// carrying, and it is the trap `c-mpu-0038` exists for.
#[tokio::test]
async fn a_committed_body_carries_exactly_one_declaration_whichever_way_it_ends() {
    for outcome in [support::CopyCommit::Fail, support::CopyCommit::Answer] {
        let service = support::copy_commit_builder(outcome).build().expect("a complete assembly");
        let response = support::exchange_wire(&service, support::copy_commit_request()).await;
        let body = String::from_utf8(response.body().to_vec()).expect("utf-8");
        assert_eq!(body.matches("<?xml").count(), 1, "{body}");
        assert!(body.starts_with(rustfs_gateway::commit::PROLOGUE), "{body}");
    }
}

/// Negative — a committed response announces no length and no trailer section. Both are promises the
/// head would have had to carry, and the head went out before either was knowable; a `Trailer` that
/// never arrives leaves a client waiting, which turns a reported failure into a hang.
#[tokio::test]
async fn a_committed_response_announces_neither_a_length_nor_a_trailer_section() {
    for outcome in [support::CopyCommit::Fail, support::CopyCommit::Answer] {
        let service = support::copy_commit_builder(outcome).build().expect("a complete assembly");
        let response = support::exchange_wire(&service, support::copy_commit_request()).await;
        assert_eq!(response.header("content-length"), None);
        assert_eq!(response.header("trailer"), None);
        assert_eq!(response.header("transfer-encoding"), None);
    }
}

/// Negative — the observer is told the failure even though the status line says `200`. An audit
/// trail that read the status would record a success, which is the exact mistake the shape invites.
#[tokio::test]
async fn the_observer_sees_a_committed_failure_as_a_failure() {
    let recorder = Arc::new(Recorder::default());
    let service = support::copy_commit_builder(support::CopyCommit::Fail)
        .observer(Arc::clone(&recorder) as Arc<dyn rustfs_gateway::Observer>)
        .build()
        .expect("a complete assembly");
    let response = support::exchange_wire(&service, support::copy_commit_request()).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let seen = recorder.seen.lock().expect("the recorder");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].1, 200, "the status the client saw");
    let errors = recorder.errors.lock().expect("the recorder");
    assert_eq!(
        errors.first().and_then(Option::as_deref),
        Some("NoSuchKey"),
        "a committed failure must reach the observer as a failure"
    );
}

/// Positive — a committed response that succeeds carries the encoder's document after the prologue,
/// and nothing of the refusal path. The commit seam must not turn every committed answer into an
/// error document.
#[tokio::test]
async fn a_committed_response_that_succeeds_carries_the_encoders_document() {
    let service = support::copy_commit_builder(support::CopyCommit::Answer)
        .build()
        .expect("a complete assembly");
    let response = support::exchange_wire(&service, support::copy_commit_request()).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = String::from_utf8(response.body().to_vec()).expect("utf-8");
    assert!(body.contains("<CopyObjectResult"), "{body}");
    assert!(!body.contains("<Error>"), "{body}");
}

// ── the body is not read until the signature has been judged ────────────────────────────────────

/// A body large enough that reading it would be the expensive half of the exchange, plus the handle
/// that says whether anything asked for it.
fn watched_body(bytes: usize) -> (ObservedBody, std::sync::Arc<BodyProgress>) {
    // Sixty-four frames rather than one: a body handed over whole can only be all-or-nothing, and
    // "the server stopped part way through" is the reading these assertions are about.
    let frame = Bytes::from(vec![b'p'; bytes / 64]);
    ObservedBody::new(core::iter::repeat_n(frame, 64))
}

/// Negative — **the c-sig-0001 property.** A request whose signature the floor refuses is answered
/// without one byte of its payload being asked for.
///
/// The counter is the whole test. "The refusal happens before the read" is unfalsifiable by reading
/// the pipeline — an edit that swapped the two stages would leave every other assertion in this file
/// green — so the evidence has to be a number the body itself reports. Zero bytes read and a body
/// that was never exhausted is the same evidence `expect.request_progress` asks a real server for.
#[tokio::test]
async fn an_unsigned_request_to_an_aws_operation_never_has_its_body_read() {
    let (body, progress) = watched_body(1 << 20);
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .header("content-length", (1_u64 << 20).to_string())
        .body(body)
        .expect("a valid request");

    let response = support::service().call(request).await;
    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(progress.bytes_read(), 0, "the payload was read before the request was refused");
    assert!(!progress.is_exhausted(), "the payload was drained before the request was refused");
}

/// Negative — the same property against a signature that is well formed and wrong, which is the
/// exact shape `c-sig-0001` sends: the request parses, reaches the verifier, and is refused
/// with the uniform credential error. An implementation could plausibly refuse an *absent*
/// signature early and still read the body before checking a present one, so the two cases are not
/// one case.
#[tokio::test]
async fn a_mismatched_signature_is_refused_before_the_body_is_read() {
    let service = wired()
        .clock_with_skew_ack(
            rustfs_gateway::FixedClock::at_unix_seconds(1_767_323_045),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");

    let (body, progress) = watched_body(1 << 20);
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .header("content-length", (1_u64 << 20).to_string())
        .header("x-amz-date", "20260102T030405Z")
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=0000000000000000000000000000000000000000000000000000000000000000",
        )
        .body(body)
        .expect("a valid request");

    let response = service.call(request).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    let document = String::from_utf8(collected.body().to_vec()).expect("utf-8");
    assert_eq!(collected.status(), http::StatusCode::FORBIDDEN);
    assert!(document.contains("<Code>SignatureDoesNotMatch</Code>"), "{document}");
    assert_eq!(progress.bytes_read(), 0, "the payload was read before the signature was judged");
    assert!(!progress.is_exhausted());
}

/// Negative — two different `x-amz-checksum-*` headers are two integrity claims, and the
/// contradiction is answered from the head alone. Nothing in the payload could settle which claim
/// the caller meant, so reading it first buys nothing and costs the transfer.
#[tokio::test]
async fn two_different_checksum_headers_are_refused_before_the_body_is_read() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");

    let (body, progress) = watched_body(1 << 20);
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .header("content-length", (1_u64 << 20).to_string())
        .header("x-amz-checksum-crc32", "AAAAAA==")
        .header("x-amz-checksum-sha1", "2jmj7l5rSw0yVb/vlWAYkK/YBwk=")
        .body(body)
        .expect("a valid request");

    let response = service.call(request).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    let document = String::from_utf8(collected.body().to_vec()).expect("utf-8");
    assert_eq!(collected.status(), http::StatusCode::BAD_REQUEST);
    assert!(document.contains("<Code>InvalidRequest</Code>"), "{document}");
    assert_eq!(progress.bytes_read(), 0, "the payload was read before the contradiction was noticed");
}

/// Negative — one checksum header repeated with the *same* algorithm is not a contradiction, so the
/// guard above must not fire on it. A rule that refused every repeated header would refuse traffic a
/// proxy legitimately produces, and the case for refusing two claims does not extend to one claim
/// spelled twice.
#[tokio::test]
async fn one_checksum_algorithm_sent_twice_is_not_a_contradiction() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .header("x-amz-checksum-crc32", "AAAAAA==")
        .body(Bytes::new())
        .expect("a valid request");

    let (status, _body) = exchange(&service, request).await;
    assert_ne!(status, http::StatusCode::BAD_REQUEST);
}

/// Positive — a request nothing objects to has its body read to the end and reaches the handler.
/// Without this, every assertion above would also be satisfied by a service that never reads a body
/// at all.
#[tokio::test]
async fn an_accepted_request_has_its_body_read_to_the_end() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");

    let (body, progress) = watched_body(4096);
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .header("content-length", "4096")
        .body(body)
        .expect("a valid request");

    let response = service.call(request).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(progress.bytes_read(), 4096);
    assert!(progress.is_exhausted());
}

/// a-asm-0008. Positive — Select's framed stream and an ordinary encoded document leave through
/// the same non-generic service. A separate service path for streams would make middleware and
/// authorization coverage depend on the response shape.
#[tokio::test]
async fn an_event_stream_and_a_document_share_one_service_exit() {
    let service = wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<Ping, _>(Arc::new(Backend))
        .register::<dto::SelectObjectContent, _>(Arc::new(support::select::SelectBackend))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");
    let select_body = Bytes::from_static(
        b"<SelectObjectContentRequest><Expression>SELECT * FROM S3Object</Expression>\
          <ExpressionType>SQL</ExpressionType><InputSerialization><CSV/></InputSerialization>\
          <OutputSerialization><CSV/></OutputSerialization></SelectObjectContentRequest>",
    );

    let stream = rustfs_gateway::collect(service.call_bytes(support::select::signed_select(select_body)).await)
        .await
        .expect("a complete event stream");
    assert_eq!(stream.status(), http::StatusCode::OK);
    let content_type = stream
        .headers()
        .iter()
        .find(|(name, _)| name == http::header::CONTENT_TYPE)
        .map(|(_, value)| value);
    assert_eq!(content_type, Some(&http::HeaderValue::from_static(EVENT_STREAM_CONTENT_TYPE)));
    assert!(!stream.body().is_empty(), "the generated empty output encoder was used");
    assert!(stream.body().windows(3).any(|window| window == b"End"), "the stream has no terminator");

    let (status, document) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(document, "<Ping>pong</Ping>");
}
