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

//! Real gateway-path controls for contracts the conformance fixture cannot observe.
//!
//! Responsible for: proving conditional-race and completed-part decisions survive routing,
//! dispatch, and response encoding. NOT responsible for: storage race detection or multipart
//! layout. Upstream: typed shared precondition helpers. Downstream: the assembled gateway wire.

use crate::support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use rustfs_gateway::dto;
use rustfs_gateway::{
    ByteStream, ConditionalOutcome, Handler, HandlerError, HandlerResult, ObjectValidators, RangeDecision, RangeSelectors, Req,
    Resp, evaluate_range,
};

struct Backend {
    put_called: Arc<AtomicBool>,
}

impl Handler<dto::PutObject> for Backend {
    fn call(&self, _request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        self.put_called.store(true, Ordering::SeqCst);
        let outcome = ConditionalOutcome::lost_race();
        async move {
            let code = outcome
                .error_code()
                .ok_or_else(|| HandlerError::internal_error("a lost race must be a refusal"))?;
            Err(HandlerError::new(code, "A conflicting conditional operation is currently in progress."))
        }
    }

    fn call_with_context(
        &self,
        _request: Req<dto::PutObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        self.put_called.store(true, Ordering::SeqCst);
        let outcome = ConditionalOutcome::lost_race();
        async move {
            let code = outcome
                .error_code()
                .ok_or_else(|| HandlerError::internal_error("a lost race must be a refusal"))?;
            Err(HandlerError::new(code, "A conflicting conditional operation is currently in progress."))
        }
    }
}

impl Handler<dto::GetObject> for Backend {
    fn call(&self, request: Req<dto::GetObject>) -> impl core::future::Future<Output = HandlerResult<dto::GetObject>> + Send {
        let part_number = request.input().part_number;
        async move {
            let selectors = RangeSelectors {
                range: None,
                part_number: part_number.and_then(|value| u32::try_from(value).ok()),
                if_range: None,
            };
            let decision = evaluate_range(&selectors, &ObjectValidators::default(), 12)
                .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
            if !matches!(&decision, RangeDecision::Part { part_number: 2, .. }) {
                return Err(HandlerError::internal_error("the completed-part adapter received the wrong selector"));
            }
            let status = decision.status().as_u16();
            let parts_count = decision.part_count_header(3).map(|value| value as i32);
            Ok(Resp::with_status(
                dto::GetObjectOutput {
                    body: Some(ByteStream::from_bytes(Bytes::from_static(b"part"))),
                    content_length: Some(4),
                    parts_count,
                    ..dto::GetObjectOutput::default()
                },
                status,
            ))
        }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObject>> + Send {
        let part_number = request.input().part_number;
        async move {
            let selectors = RangeSelectors {
                range: None,
                part_number: part_number.and_then(|value| u32::try_from(value).ok()),
                if_range: None,
            };
            let decision = evaluate_range(&selectors, &ObjectValidators::default(), 12)
                .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
            if !matches!(&decision, RangeDecision::Part { part_number: 2, .. }) {
                return Err(HandlerError::internal_error("the completed-part adapter received the wrong selector"));
            }
            let status = decision.status().as_u16();
            let parts_count = decision.part_count_header(3).map(|value| value as i32);
            Ok(Resp::with_status(
                dto::GetObjectOutput {
                    body: Some(ByteStream::from_bytes(Bytes::from_static(b"part"))),
                    content_length: Some(4),
                    parts_count,
                    ..dto::GetObjectOutput::default()
                },
                status,
            ))
        }
    }
}

fn service() -> (rustfs_gateway::S3Service, Arc<AtomicBool>) {
    let put_called = Arc::new(AtomicBool::new(false));
    let backend = Arc::new(Backend {
        put_called: Arc::clone(&put_called),
    });
    let service = support::wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::GetObject, _>(backend)
        .build()
        .expect("a complete assembly");
    (service, put_called)
}

/// c-cond-0029 / q-cond-0049: the actual PutObject adapter renders the typed race outcome.
#[tokio::test]
async fn c_cond_0029_a_lost_conditional_race_is_a_retryable_conflict() {
    let quirk = "q-cond-0049";
    let (service, put_called) = service();
    let request = support::signed_with(http::Method::PUT, "/bucket/key", &[("content-length", "0")]);
    let response = support::exchange_wire(&service, request).await;
    let body = String::from_utf8(response.body().to_vec()).expect("an XML error body");

    assert!(put_called.load(Ordering::SeqCst), "the request must reach the race consumer");
    ::core::assert_eq!(response.status(), http::StatusCode::CONFLICT, "{}: {body}", quirk);
    assert!(body.contains("<Code>ConditionalRequestConflict</Code>"), "{body}");
}

/// c-range-0020 / q-range-0056: the actual GetObject adapter consumes the typed part outcome.
#[tokio::test]
async fn c_range_0020_a_completed_part_selection_is_partial_content() {
    let quirk = "q-range-0056";
    let (service, _) = service();
    let response = support::exchange_wire(&service, support::signed(http::Method::GET, "/bucket/key?partNumber=2")).await;

    ::core::assert_eq!(response.status(), http::StatusCode::PARTIAL_CONTENT, "{}", quirk);
    assert_eq!(response.body(), b"part".as_slice());
}

/// c-range-0021 / q-range-part-count-0105: the encoded GetObject head carries the typed count.
#[tokio::test]
async fn c_range_0021_a_completed_part_reports_the_total_part_count() {
    let quirk = "q-range-part-count-0105";
    let (service, _) = service();
    let response = support::exchange_wire(&service, support::signed(http::Method::GET, "/bucket/key?partNumber=2")).await;
    let parts_count = response
        .headers()
        .iter()
        .filter(|(name, _)| name.as_str() == "x-amz-mp-parts-count")
        .map(|(_, value)| value.to_str())
        .collect::<Result<Vec<_>, _>>()
        .expect("part-count header values are text");

    ::core::assert_eq!(parts_count, ["3"], "{}", quirk);
}
