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

//! Legacy RustFS's operation selection through the facade (rustfs/gateway#1127): which handler a
//! request reaches under `select_operations_as_legacy_rustfs` when its query carries `x-id` or two
//! operation keys.
//!
//! Responsible for: an `x-id` named once selecting its operation over the query's keys, two
//! operation keys selecting the first in legacy RustFS's order, and an undeclared `x-id` refused
//! `400 InvalidRequest` before any handler; each against the default assembly, which routes as it
//! always has. Every expectation is legacy RustFS's answer on a legacy build.
//! NOT responsible for: the order itself (`rustfs-gateway-core`'s `legacy_rustfs` tests) or what
//! the handler stores (`compat/sut`'s selection cases).
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::dto::{
    AbortMultipartUpload, CreateMultipartUpload, DeleteObjectTagging, GetBucketAcl, GetBucketVersioning, GetObjectTagging,
    ListObjects, PutObject, PutObjectTagging,
};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, ClockSkewAck, Credentials, Decision, ErrorCode, HandlerError, HandlerResult,
    InputAuthzRequest, InputDecisions, RegionSet, Req, RequestContext, S3Service, SecurityFloor, ServiceBuilder,
    SigV4Authenticator, StaticCredentials,
};

use crate::support::{exchange, fixed_clock, signed, signed_target_with_body_and_headers};

/// The operations the handlers were reached as, in order.
#[derive(Default)]
struct Seen(Mutex<Vec<&'static str>>);

impl Seen {
    fn take(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.0.lock().expect("not poisoned"))
    }

    fn hand(&self, operation: &'static str) {
        self.0.lock().expect("not poisoned").push(operation);
    }
}

struct Allow;

impl Authorizer for Allow {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

struct Recorder(Arc<Seen>);

fn recorded<T>() -> Result<T, HandlerError> {
    Err(HandlerError::new(ErrorCode::NOT_IMPLEMENTED, "recorded"))
}

#[rustfs_gateway::handlers]
impl Recorder {
    async fn put_object(&self, _request: Req<PutObject>) -> HandlerResult<PutObject> {
        self.0.hand("PutObject");
        recorded()
    }

    async fn put_object_tagging(&self, _request: Req<PutObjectTagging>) -> HandlerResult<PutObjectTagging> {
        self.0.hand("PutObjectTagging");
        recorded()
    }

    async fn get_object_tagging(&self, _request: Req<GetObjectTagging>) -> HandlerResult<GetObjectTagging> {
        self.0.hand("GetObjectTagging");
        recorded()
    }

    async fn delete_object_tagging(&self, _request: Req<DeleteObjectTagging>) -> HandlerResult<DeleteObjectTagging> {
        self.0.hand("DeleteObjectTagging");
        recorded()
    }

    async fn abort_multipart_upload(&self, _request: Req<AbortMultipartUpload>) -> HandlerResult<AbortMultipartUpload> {
        self.0.hand("AbortMultipartUpload");
        recorded()
    }

    async fn create_multipart_upload(&self, _request: Req<CreateMultipartUpload>) -> HandlerResult<CreateMultipartUpload> {
        self.0.hand("CreateMultipartUpload");
        recorded()
    }

    async fn get_bucket_acl(&self, _request: Req<GetBucketAcl>) -> HandlerResult<GetBucketAcl> {
        self.0.hand("GetBucketAcl");
        recorded()
    }

    async fn get_bucket_versioning(&self, _request: Req<GetBucketVersioning>) -> HandlerResult<GetBucketVersioning> {
        self.0.hand("GetBucketVersioning");
        recorded()
    }

    async fn list_objects(&self, _request: Req<ListObjects>) -> HandlerResult<ListObjects> {
        self.0.hand("ListObjects");
        recorded()
    }
}

fn assembled(rustfs: bool) -> (S3Service, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid key")));
    let recorder = Arc::new(Recorder(Arc::clone(&seen)));
    let builder = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .clock_with_skew_ack(fixed_clock(), ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry())
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .authorizer(Allow)
        .register::<PutObject, _>(Arc::clone(&recorder))
        .register::<PutObjectTagging, _>(Arc::clone(&recorder))
        .register::<GetObjectTagging, _>(Arc::clone(&recorder))
        .register::<DeleteObjectTagging, _>(Arc::clone(&recorder))
        .register::<AbortMultipartUpload, _>(Arc::clone(&recorder))
        .register::<CreateMultipartUpload, _>(Arc::clone(&recorder))
        .register::<GetBucketAcl, _>(Arc::clone(&recorder))
        .register::<GetBucketVersioning, _>(Arc::clone(&recorder))
        .register::<ListObjects, _>(recorder);
    let builder = if rustfs {
        builder.select_operations_as_legacy_rustfs()
    } else {
        builder
    };
    (builder.build().expect("a complete assembly"), seen)
}

const TAGS: &[u8] = b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";

/// `TAGS`' Content-MD5, which the tagging operation requires of its body.
const TAGS_MD5: &str = "EbdZDxVT2OADmYhaGBi6mA==";

/// A signed `PUT` of the tagging document to `target`.
fn put_tags(target: &str) -> http::Request<Bytes> {
    let headers = [("content-md5", TAGS_MD5), ("content-length", "75")];
    signed_target_with_body_and_headers(http::Method::PUT, target, &headers, Bytes::from_static(TAGS))
}

/// The operation a signed request reached, and the answer it got.
async fn reached(service: &S3Service, seen: &Seen, request: http::Request<Bytes>) -> (Vec<&'static str>, http::StatusCode) {
    let (status, _) = exchange(service, request).await;
    (seen.take(), status)
}

/// Positive — an `x-id` named once is the operation, whatever the query's keys name: a tagging
/// document sent with `x-id=PutObjectTagging` reaches the tagging handler, not `PutObject`.
#[tokio::test]
async fn an_x_id_selects_the_operation_it_names() {
    let (service, seen) = assembled(true);
    assert_eq!(
        reached(&service, &seen, put_tags("/bkt/obj?x-id=PutObjectTagging")).await.0,
        ["PutObjectTagging"]
    );
    let acl = signed(http::Method::GET, "/bkt?x-id=GetBucketAcl");
    assert_eq!(reached(&service, &seen, acl).await.0, ["GetBucketAcl"]);
    let versioning = signed(http::Method::GET, "/bkt?acl&x-id=GetBucketVersioning");
    assert_eq!(reached(&service, &seen, versioning).await.0, ["GetBucketVersioning"]);
}

/// Positive — two operation keys: the first in legacy RustFS's order.
#[tokio::test]
async fn two_operation_keys_select_the_first_in_legacy_order() {
    let (service, seen) = assembled(true);
    for (method, target, expected) in [
        (http::Method::GET, "/bkt?acl&versioning", "GetBucketAcl"),
        (http::Method::GET, "/bkt/obj?uploadId=u&tagging", "GetObjectTagging"),
        (http::Method::DELETE, "/bkt/obj?tagging&uploadId=u", "DeleteObjectTagging"),
        (http::Method::POST, "/bkt/obj?uploadId=u&uploads", "CreateMultipartUpload"),
    ] {
        let (reached, _) = reached(&service, &seen, signed(method.clone(), target)).await;
        assert_eq!(reached, [expected], "{method} {target}");
    }
}

/// Negative — an `x-id` legacy RustFS does not accept is `400 InvalidRequest`, before any handler.
#[tokio::test]
async fn n_an_undeclared_x_id_is_refused_before_any_handler() {
    let (service, seen) = assembled(true);
    for target in ["/bkt?x-id=NoSuchOp", "/bkt?x-id=GetObject", "/bkt?x-id=a&x-id=b"] {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(target)
            .header("host", "s3.example.com")
            .body(Bytes::new())
            .expect("a valid request");
        let (status, body) = exchange(&service, request).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{target}: {body}");
        assert!(body.contains("<Code>InvalidRequest</Code>"), "{target}: {body}");
    }
    assert!(seen.take().is_empty());
}

/// Negative — the default assembly routes by its own precedences and ignores `x-id`.
#[tokio::test]
async fn n_the_default_assembly_is_unchanged() {
    let (service, seen) = assembled(false);
    assert_eq!(
        reached(&service, &seen, put_tags("/bkt/obj?x-id=PutObjectTagging")).await.0,
        ["PutObject"]
    );
    let pair = signed(http::Method::GET, "/bkt?acl&versioning");
    assert_eq!(reached(&service, &seen, pair).await.0, ["GetBucketVersioning"]);
    let unknown = signed(http::Method::GET, "/bkt?x-id=NoSuchOp");
    assert_eq!(reached(&service, &seen, unknown).await.0, ["ListObjects"]);
}
