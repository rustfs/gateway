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

//! The RustFS refusal shapes a handler error could not state.
//!
//! Responsible for: proving, on the wire, the status and code a dotted custom code produces.
//! NOT responsible for: the admission rules themselves, which `rustfs-gateway-core` pins.
//! Upstream: `tests/support`. Downstream: nothing.

use crate::support;

use http::StatusCode;
use rustfs_gateway::{ErrorCode, HandlerError, WireHead, WireResponse, wire_filter};

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
