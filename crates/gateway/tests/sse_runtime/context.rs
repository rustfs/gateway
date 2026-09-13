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

//! Responsible for: JSON context refusal before body reads and handler dispatch.
//! NOT responsible for: KMS semantics, encryption or customer key checks.
//! Upstream: the shared SSE runtime assembly and raw request body observer.
//! Downstream: the caller-visible response and backend dispatch count.

use super::*;
use crate::support::CountingBody;

async fn call_context(encoded: &str) -> (WireResponse, usize, u64) {
    let (service, backend) = build(SseConfig::default());
    let (body, read) = CountingBody::new(bytes::Bytes::from_static(b"payload"));
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://host.invalid{OBJECT}"))
        .header("host", "host.invalid")
        .header("content-length", "7")
        .header("x-amz-server-side-encryption", "aws:kms")
        .header("x-amz-server-side-encryption-context", encoded)
        .body(body)
        .expect("a context request");
    let response = collect(service.call(request).await).await.expect("a readable response");
    (response, backend.calls.load(Ordering::SeqCst), read.load(Ordering::SeqCst))
}

#[tokio::test]
async fn context_json_valid_pairs_reach_the_handler_and_body_reader() {
    let (response, calls, read) = call_context("eyJrZXkiOiJ2YWx1ZSJ9").await;
    assert_eq!(response.status(), 200);
    assert_eq!(calls, 1);
    assert_eq!(read, 7);
}

#[tokio::test]
async fn context_json_malformed_data_reaches_neither_body_nor_handler() {
    for encoded in [
        "eyJtYXJrZXIiOiJjb25maWRlbnRpYWwtY29udGV4dC1tYXJrZXIi", // {"marker":"confidential-context-marker"
        "W10=",                                                 // []
        "eyJrZXkiOnt9fQ==",                                     // {"key":{}}
        "eyJrZXkiOiJhIiwia2V5IjoiYiJ9",                         // {"key":"a","key":"b"}
        "e30gbnVsbA==",                                         // {} null
    ] {
        let (response, calls, read) = call_context(encoded).await;
        assert_eq!(calls, 0, "invalid context reached the handler");
        assert_eq!(read, 0, "invalid context consumed the body");
        // The leak checks run before the exact-sentence check: a refusal that appended the
        // context to the fixed sentence would otherwise fail on the sentence and never prove
        // these two can fail on their own.
        let seen = everything_the_caller_sees(&response);
        let visible = String::from_utf8_lossy(&seen);
        assert!(!visible.contains(encoded), "encoded context escaped into the response");
        assert!(
            !visible.contains("confidential-context-marker"),
            "decoded context escaped into the response"
        );
        assert_eq!(response.status(), 400);
        let body = String::from_utf8_lossy(response.body());
        assert!(body.contains("<Code>InvalidArgument</Code>"));
        assert!(body.contains("<Message>x-amz-server-side-encryption-context must be a JSON object with unique string keys and string values</Message>"));
    }
}

#[tokio::test]
async fn context_json_one_byte_over_the_limit_is_rejected_before_body_and_handler() {
    // Canonical base64 of {"k":"<2040 A bytes>"}: exactly 2048 decoded bytes.
    let at_limit = format!("eyJrIjoi{}In0=", "QUFB".repeat(680));
    let (response, calls, read) = call_context(&at_limit).await;
    assert_eq!(response.status(), 200);
    assert_eq!(calls, 1);
    assert_eq!(read, 7);
    let over_limit = format!("eyJrIjoi{}QSJ9", "QUFB".repeat(680));
    let (response, calls, read) = call_context(&over_limit).await;
    assert_eq!(response.status(), 400);
    assert_eq!(calls, 0);
    assert_eq!(read, 0);
}
