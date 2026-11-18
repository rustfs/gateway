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

//! The two RustFS refusal shapes a handler error could not state: a dotted custom code and the
//! `x-rustfs-error-cause` header.
//!
//! Responsible for: proving, on the wire, the status, code and header bytes those two produce and
//! that a misplaced cause is replaced by the generic `500`.
//! NOT responsible for: the admission rules themselves, which `rustfs-gateway-core` pins.
//! Upstream: `tests/support`. Downstream: nothing.

use crate::support;

use http::StatusCode;
use rustfs_gateway::{ErrorCode, ErrorHeader, HandlerError, RustfsErrorCause, WireHead, WireResponse, wire_filter};

use support::{Ping, exchange_wire, plain, wired};

async fn answer(error: HandlerError) -> WireResponse {
    let filter = wire_filter(move |_head: &mut WireHead<'_>| Err(error.clone()));
    let service = wired()
        .register::<Ping, _>(std::sync::Arc::new(support::Backend))
        .dialect(&support::ping_dialect())
        .stage_filter(filter)
        .build()
        .expect("a complete assembly");
    exchange_wire(&service, plain(http::Method::POST, "/")).await
}

fn header<'a>(response: &'a WireResponse, name: &str) -> Vec<&'a [u8]> {
    response
        .headers()
        .iter()
        .filter(|(line, _)| line.as_str() == name)
        .map(|(_, value)| value.as_bytes())
        .collect()
}

#[tokio::test]
async fn a_dotted_custom_code_is_written_with_its_status() {
    let code = ErrorCode::custom("KMS.NotFoundException", StatusCode::BAD_REQUEST);
    let response = answer(HandlerError::new(code, "no such key")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8_lossy(response.body());
    assert!(body.contains("<Code>KMS.NotFoundException</Code>"), "{body}");
}

#[tokio::test]
async fn a_malformed_dotted_code_is_replaced_by_the_generic_500() {
    for code in ["Foo.", ".Foo", "Foo..Bar", "Foo.Bar/Baz", "Foo.Bar<"] {
        let response = answer(HandlerError::new(ErrorCode::custom(code, StatusCode::BAD_REQUEST), "x")).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR, "{code}");
        let body = String::from_utf8_lossy(response.body());
        assert!(body.contains("<Code>InternalError</Code>"), "{code}: {body}");
    }
}

#[tokio::test]
async fn each_cause_is_written_as_the_bytes_rustfs_writes() {
    for (cause, wire) in [
        (RustfsErrorCause::NamespaceLockTimeout, &b"namespace_lock_timeout"[..]),
        (RustfsErrorCause::NamespaceLockUnavailable, &b"namespace_lock_unavailable"[..]),
        (RustfsErrorCause::StorageWriteQuorum, &b"storage_write_quorum"[..]),
    ] {
        let response = answer(
            HandlerError::new(ErrorCode::SERVICE_UNAVAILABLE, "busy").with_header(ErrorHeader::RustfsErrorCause { cause }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(header(&response, "x-rustfs-error-cause"), [wire]);
        assert!(header(&response, "retry-after").is_empty());
    }
}

#[tokio::test]
async fn a_cause_and_a_retry_after_are_both_written() {
    let response = answer(
        HandlerError::new(ErrorCode::SERVICE_UNAVAILABLE, "busy")
            .with_header(ErrorHeader::RetryAfter { seconds: 1 })
            .with_header(ErrorHeader::RustfsErrorCause {
                cause: RustfsErrorCause::NamespaceLockTimeout,
            }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(header(&response, "retry-after"), [&b"1"[..]]);
    assert_eq!(header(&response, "x-rustfs-error-cause"), [&b"namespace_lock_timeout"[..]]);
}

#[tokio::test]
async fn a_cause_on_any_other_error_is_refused_and_leaks_no_header() {
    for code in [ErrorCode::SLOW_DOWN, ErrorCode::INTERNAL_ERROR, ErrorCode::ACCESS_DENIED] {
        let response = answer(HandlerError::new(code.clone(), "x").with_header(ErrorHeader::RustfsErrorCause {
            cause: RustfsErrorCause::StorageWriteQuorum,
        }))
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR, "{code:?}");
        assert!(header(&response, "x-rustfs-error-cause").is_empty(), "{code:?}");
    }
}

#[tokio::test]
async fn a_plain_service_unavailable_carries_no_cause() {
    let response = answer(HandlerError::new(ErrorCode::SERVICE_UNAVAILABLE, "busy")).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(header(&response, "x-rustfs-error-cause").is_empty());
}
