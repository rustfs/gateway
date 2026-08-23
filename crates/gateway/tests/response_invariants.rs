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

//! Runtime response correction metrics and malformed response refusal.
//!
//! Responsible for: observing the final response-invariant seam after a deployment filter runs.
//! NOT responsible for: the filter contract itself, which is covered by `middleware.rs`.
//! Upstream: the shared gateway fixture. Downstream: the P3-06 response-encoding ledger.

use std::sync::Arc;

use bytes::Bytes;
use rustfs_gateway::{ResponseView, response_filter};

use crate::support::{Backend, ContentPing, Ping, content_ping_route, exchange_wire, ping_route, plain, wired};

/// Negative — repairing a forbidden runtime body is observable rather than a silent backend
/// correction. One response produces one increment.
#[tokio::test]
async fn c_enc_0021_a_body_on_204_is_removed_and_counted() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .route(ping_route())
        .stage_filter(response_filter(
            |_view: &ResponseView<'_>, response: &mut http::Response<rustfs_gateway::Body>| {
                *response.status_mut() = http::StatusCode::NO_CONTENT;
                *response.body_mut() = rustfs_gateway::Body::from_bytes(Bytes::from_static(b"<Nonsense/>"));
                response
                    .headers_mut()
                    .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("11"));
                Ok(())
            },
        ))
        .build()
        .expect("a complete assembly");
    assert_eq!(service.response_body_corrections_total(), 0);
    let response = exchange_wire(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
    assert!(response.body().is_empty(), "a 204 kept a filter's body");
    assert_eq!(response.header("content-length"), None);
    assert_eq!(service.response_body_corrections_total(), 1);
}

/// Negative — a response filter cannot create the request-smuggling shape on the response side.
/// The conflict is rejected before either framing header reaches the wire.
#[tokio::test]
async fn c_enc_0024_content_length_with_transfer_encoding_is_rejected() {
    let service = wired()
        .register::<ContentPing, _>(Arc::new(Backend))
        .route(content_ping_route())
        .stage_filter(response_filter(
            |_view: &ResponseView<'_>, response: &mut http::Response<rustfs_gateway::Body>| {
                response
                    .headers_mut()
                    .insert(http::header::TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
                Ok(())
            },
        ))
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&service, plain(http::Method::PUT, "/")).await;
    let body = std::str::from_utf8(response.body()).expect("the framework error document is UTF-8");
    assert_eq!(response.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("<Code>InternalError</Code>"), "{body}");
    assert_eq!(response.header("transfer-encoding"), None);
}
