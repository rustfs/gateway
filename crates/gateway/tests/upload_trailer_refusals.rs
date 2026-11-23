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

//! Responsible for: checking authentication and refusal ordering for unframed uploads with declared trailers.
//! NOT responsible for: decoding aws-chunked payloads.
//! Upstream: the signed-request fixture. Downstream: the route policy and the wire response.

use crate::support;
use bytes::Bytes;
use http::{Method, StatusCode};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, ErrorCode, Handler, HandlerError, HandlerResult,
    InputAuthzRequest, InputDecisions, RegionSet, Req, RequestContext, SigV4Authenticator, StaticCredentials, dto,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Unreachable;
macro_rules! reject_handler {
    ($operation:ty) => {
        impl Handler<$operation> for Unreachable {
            async fn call(&self, _: Req<$operation>) -> HandlerResult<$operation> {
                panic!("a refused request reached the handler")
            }
        }
    };
}
reject_handler!(dto::PutObject);
reject_handler!(dto::UploadPart);
reject_handler!(dto::GetObject);

struct Policy {
    calls: Arc<AtomicUsize>,
    refuse: bool,
}
impl Authorizer for Policy {
    fn authorize_route<'a>(&'a self, _: &'a RequestContext<'a>, _: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Deny })
    }

    fn authorize_route_result<'a>(
        &'a self,
        _: &'a RequestContext<'a>,
        request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Result<Decision, HandlerError>> {
        assert_eq!(request.identity.expect("a verified caller").access_key_id(), "AKIDEXAMPLE");
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.refuse {
                Err(HandlerError::new(ErrorCode::INVALID_REQUEST, "this target refuses trailer uploads"))
            } else {
                Ok(Decision::Allow)
            }
        })
    }

    fn authorize_input<'a>(&'a self, _: &'a RequestContext<'a>, _: &'a InputAuthzRequest<'a>) -> BoxFuture<'a, InputDecisions> {
        panic!("a refused request reached input authorization")
    }
}

async fn check(
    method: Method,
    target: &str,
    enabled: bool,
    refuse: bool,
    valid_key: bool,
    trailer: &str,
) -> (StatusCode, String, usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    let builder = support::wired_at_signed_time();
    let builder = if enabled {
        builder.authenticate_before_rejecting_unframed_upload_trailers()
    } else {
        builder
    };
    let builder = if valid_key {
        builder
    } else {
        let other = StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"another-secret").unwrap());
        builder.authenticator(SigV4Authenticator::new(Arc::new(other), RegionSet::new(["us-east-1"]).unwrap()))
    };
    let backend = Arc::new(Unreachable);
    let service = builder
        .authorizer(Policy {
            calls: Arc::clone(&calls),
            refuse,
        })
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::UploadPart, _>(Arc::clone(&backend))
        .register::<dto::GetObject, _>(backend)
        .build()
        .unwrap();
    let req = support::signed_target_with_body_and_headers(
        method,
        target,
        &[("x-amz-trailer", trailer)],
        Bytes::from_static(b"payload"),
    );
    let (parts, bytes) = req.into_parts();
    let (body, read) = support::CountingBody::new(bytes);
    let response = service.call(http::Request::from_parts(parts, body)).await;
    let response = rustfs_gateway::collect(response).await.unwrap();
    assert_eq!(read.load(Ordering::SeqCst), 0);
    (
        response.status(),
        String::from_utf8(response.body().to_vec()).unwrap(),
        calls.load(Ordering::SeqCst),
    )
}

const TRAILER: &str = "x-amz-checksum-crc32";
const OBJECT: &str = "/bucket/key";
const PART: &str = "/bucket/key?partNumber=1&uploadId=upload";

#[tokio::test]
async fn only_verified_signed_uploads_can_get_the_deployments_own_refusal() {
    for target in [OBJECT, PART] {
        let (status, message, calls) = check(Method::PUT, target, true, true, true, TRAILER).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("this target refuses trailer uploads"), "{message}");
        assert_eq!(calls, 1);
    }
}

#[tokio::test]
async fn allowing_the_route_still_refuses_the_payload() {
    let (status, message, calls) = check(Method::PUT, OBJECT, true, false, true, TRAILER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(message.contains("<Code>InvalidRequest</Code>"), "{message}");
    assert_eq!(calls, 1);
}

#[tokio::test]
async fn wrong_credentials_never_reach_policy() {
    let (status, message, calls) = check(Method::PUT, OBJECT, true, true, false, TRAILER).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(message.contains("<Code>SignatureDoesNotMatch</Code>"), "{message}");
    assert_eq!(calls, 0);
}

#[tokio::test]
async fn defaults_other_operations_and_invalid_declarations_keep_their_early_refusal() {
    for (method, enabled, trailer) in [
        (Method::PUT, false, TRAILER),
        (Method::GET, true, TRAILER),
        (Method::PUT, true, "bad name"),
    ] {
        let (status, message, calls) = check(method, OBJECT, enabled, true, true, trailer).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("<Code>InvalidRequest</Code>"), "{message}");
        assert_eq!(calls, 0);
    }
}
