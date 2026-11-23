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

//! Signed, multi-event subscriptions on the two RustFS notification routes.
//!
//! Responsible for: exercising the RustFS dialect and real SigV4 verifier with MinIO Java requests.
//! NOT responsible for: delivering notifications. The host consumes every event filter.
//! Upstream: the Mint SDK and the two listen operations. Downstream: the recording handler.

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use rustfs_gateway::{Handler, HandlerResult, Operation, Req, Resp, S3Service};
use rustfs_gateway_dialect_rustfs_admin::ops::{
    check_replication::CheckReplication, listen_bucket_notification::ListenBucketNotification,
    listen_notification::ListenNotification,
};
use rustfs_gateway_dialect_rustfs_admin::{AdminResponse, rustfs_admin_dialect};

use crate::support;

// MinIO Java 8.6.0 Signer.signV4S3, the same signer used by Mint's listenBucketNotification test.
// A fixed clock and the suite's public example identity make the two signatures reproducible.
const FILTERS: &str = "prefix=prefix&suffix=suffix&events=s3%3AObjectCreated%3A%2A&events=s3%3AObjectAccessed%3A%2A";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SERVICE_SIGNATURE: &str = "201f52735de74ecd91a2f2635383c64bd44bf9b6ba815e24cd867ee72c18f715";
const BUCKET_SIGNATURE: &str = "312a7fc61bc83133a2c2a393e60ff1d94425892439fffea40e822ef23f0696d1";

struct Listener;

impl<O: Operation<Output = AdminResponse>> Handler<O> for Listener {
    async fn call(&self, request: Req<O>) -> HandlerResult<O> {
        Ok(Resp::new(AdminResponse::json(request.context().raw_query().to_owned())))
    }
}

fn service() -> S3Service {
    support::wired_at_signed_time()
        .dialect(&rustfs_admin_dialect().expect("the generated dialect"))
        .register::<ListenNotification, _>(Arc::new(Listener))
        .register::<ListenBucketNotification, _>(Arc::new(Listener))
        .register::<CheckReplication, _>(Arc::new(Listener))
        .build()
        .expect("the test service")
}

fn java_request(path: &str, query: &str, signature: &str) -> Request<Bytes> {
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request, SignedHeaders=content-md5;host;x-amz-content-sha256;x-amz-date, Signature={signature}"
    );
    Request::builder()
        .method(Method::GET)
        .uri(format!("{path}?{query}"))
        .header("host", "s3.example.com")
        .header("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg==")
        .header("x-amz-content-sha256", EMPTY_SHA256)
        .header("x-amz-date", support::SIGNED_AT_STAMP)
        .header("authorization", authorization)
        .body(Bytes::new())
        .expect("the SDK request")
}

#[tokio::test]
async fn minio_java_subscribes_to_both_events_on_both_listen_routes() {
    let service = service();
    for (path, signature) in [("/", SERVICE_SIGNATURE), ("/bucket", BUCKET_SIGNATURE)] {
        let (status, body) = support::exchange(&service, java_request(path, FILTERS, signature)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, FILTERS, "the handler receives every event in wire order");
    }
}

#[tokio::test]
async fn changing_either_signed_event_or_their_order_is_refused() {
    let service = service();
    for query in [
        FILTERS.replace("ObjectCreated", "ObjectRemoved"),
        FILTERS.replace("ObjectAccessed", "ObjectRemoved"),
        FILTERS
            .replace("ObjectCreated", "swap")
            .replace("ObjectAccessed", "ObjectCreated")
            .replace("swap", "ObjectAccessed"),
    ] {
        let (status, body) = support::exchange(&service, java_request("/bucket", &query, BUCKET_SIGNATURE)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"), "{body}");
    }
}

#[tokio::test]
async fn repeated_scalar_filters_and_repeated_events_on_another_operation_are_refused() {
    let service = service();
    for (path, query, code) in [
        ("/bucket", format!("{FILTERS}&prefix=extra"), "<Code>InvalidArgument</Code>"),
        ("/", format!("{FILTERS}&suffix=extra"), "<Code>AuthorizationHeaderMalformed</Code>"),
        (
            "/bucket",
            format!("replication-check&{FILTERS}"),
            "<Code>AuthorizationHeaderMalformed</Code>",
        ),
    ] {
        let (status, body) = support::exchange(&service, java_request(path, &query, BUCKET_SIGNATURE)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains(code), "{body}");
    }
}
