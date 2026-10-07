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

//! Input-derived resources are authorized before a backend can receive a request.
//!
//! Responsible for: copy-source and version-list authorization, including measured backend calls.
//! NOT responsible for: policy evaluation or audit formatting.
//! Upstream: `rustfs_gateway_core::authz`. Downstream: the facade service pipeline.

use crate::support;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::{
    AuthzRequest, BoxFuture, Decision, Handler, HandlerResult, InputAuthzRequest, InputDecisions, PolicyError, PolicySnapshot,
    Req, RequestContext, Resp, dto, policy_from,
};

use support::{exchange, fixed_clock, signed_with, wired};

struct DestinationOnly;

impl rustfs_gateway::Authorizer for DestinationOnly {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = if request.action == "s3:PutObject" {
            Decision::Allow
        } else {
            Decision::Deny
        };
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |resource| {
            if resource.action == "s3:PutObject" {
                Decision::Allow
            } else {
                Decision::Deny
            }
        });
        Box::pin(async move { decisions })
    }
}

struct DestinationSourceConstraint;

impl rustfs_gateway::Authorizer for DestinationSourceConstraint {
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
        let decisions = request.decide_all(Decision::Allow, |resource| {
            let request = resource;
            let forbidden_pair = request.copy_source_identity.is_some()
                && request.route_bucket.is_some_and(|bucket| bucket.as_str() == "destination")
                && request.bucket.is_some_and(|bucket| bucket.as_str() == "source");
            if forbidden_pair { Decision::Deny } else { Decision::Allow }
        });
        Box::pin(async move { decisions })
    }
}

struct CopyBackend(Arc<AtomicUsize>);

struct RecordingAuthorizer(Arc<Mutex<Vec<(u64, i64, usize)>>>);

impl rustfs_gateway::Authorizer for RecordingAuthorizer {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, _request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        self.0.lock().expect("recording lock").push((
            context.policy().id().get(),
            context.now().unix_seconds(),
            std::ptr::from_ref(context.policy()) as usize,
        ));
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.0.lock().expect("recording lock").push((
            context.policy().id().get(),
            context.now().unix_seconds(),
            std::ptr::from_ref(context.policy()) as usize,
        ));
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

impl Handler<dto::CopyObject> for CopyBackend {
    async fn call(&self, request: Req<dto::CopyObject>) -> HandlerResult<dto::CopyObject> {
        self.0.fetch_add(1, Ordering::SeqCst);
        assert!(
            request.input().copy_source.is_empty(),
            "the raw source remained visible after authorization"
        );
        let source = request
            .resources()
            .source()
            .resolve(request.read_proof())
            .expect("the proof belongs to this source");
        assert_eq!(source.bucket().expect("source names a bucket").as_str(), "source");
        assert_eq!(source.key().as_str(), "secret");
        Ok(Resp::new(dto::CopyObjectOutput::default()))
    }

    async fn call_with_context(
        &self,
        request: Req<dto::CopyObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> HandlerResult<dto::CopyObject> {
        self.0.fetch_add(1, Ordering::SeqCst);
        assert!(
            request.input().copy_source.is_empty(),
            "the raw source remained visible after authorization"
        );
        let source = request
            .resources()
            .source()
            .resolve(request.read_proof())
            .expect("the proof belongs to this source");
        assert_eq!(source.bucket().expect("source names a bucket").as_str(), "source");
        assert_eq!(source.key().as_str(), "secret");
        Ok(Resp::new(dto::CopyObjectOutput::default()))
    }
}

/// c-azc-0026: every normalized copy source is decided before the backend can run.
#[tokio::test]
async fn n_copy_source_denial_never_reaches_the_backend() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .authorizer(DestinationOnly)
        .clock_with_skew_ack(
            fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::CopyObject, _>(Arc::new(CopyBackend(Arc::clone(&reached))))
        .build()
        .expect("a complete assembly");

    let request = signed_with(http::Method::PUT, "/destination/object", &[("x-amz-copy-source", "/source/secret")]);
    let (status, body) = exchange(&service, request).await;

    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "the backend ran after source denial");
}

#[tokio::test]
async fn a_destination_policy_can_refuse_an_otherwise_readable_copy_source() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .authorizer(DestinationSourceConstraint)
        .clock_with_skew_ack(
            fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::CopyObject, _>(Arc::new(CopyBackend(Arc::clone(&reached))))
        .build()
        .expect("a complete assembly");

    let request = signed_with(http::Method::PUT, "/destination/object", &[("x-amz-copy-source", "/source/secret")]);
    let (status, body) = exchange(&service, request).await;

    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(
        reached.load(Ordering::SeqCst),
        0,
        "the backend ran after the destination policy denied the source"
    );
}

/// c-azc-0001: only an authorized, normalized operation input reaches dispatch.
#[tokio::test]
async fn an_authorized_handler_sees_only_the_normalized_copy_source() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .clock_with_skew_ack(
            fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::CopyObject, _>(Arc::new(CopyBackend(Arc::clone(&reached))))
        .build()
        .expect("a complete assembly");

    let request = signed_with(http::Method::PUT, "/destination/object", &[("x-amz-copy-source", "/source/secret")]);
    let (status, _) = exchange(&service, request).await;

    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

/// c-azc-0002, c-azc-0029: both stages use one policy pointer, clock, and authorizer.
#[tokio::test]
async fn both_authorization_stages_share_one_policy_and_clock_snapshot() {
    let reads = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let reached = Arc::new(AtomicUsize::new(0));
    let source_reads = Arc::clone(&reads);
    let service = wired()
        .policy_source(policy_from(move |_| {
            source_reads.fetch_add(1, Ordering::SeqCst);
            Ok(PolicySnapshot::of(Arc::new("policy-v1")))
        }))
        .authorizer(RecordingAuthorizer(Arc::clone(&seen)))
        .clock_with_skew_ack(
            fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::CopyObject, _>(Arc::new(CopyBackend(reached)))
        .build()
        .expect("a complete assembly");

    let request = signed_with(http::Method::PUT, "/destination/object", &[("x-amz-copy-source", "/source/secret")]);
    let (status, _) = exchange(&service, request).await;

    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    let seen = seen.lock().expect("recording lock");
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], seen[1]);
    assert_eq!(seen[0].2, seen[1].2, "both stages must borrow the exact same snapshot allocation");
}

#[tokio::test]
async fn an_unreadable_policy_is_a_403_and_never_reaches_the_backend() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .policy_source(policy_from(|_| Err(PolicyError::unavailable())))
        .clock_with_skew_ack(
            fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<dto::CopyObject, _>(Arc::new(CopyBackend(Arc::clone(&reached))))
        .build()
        .expect("a complete assembly");

    let request = signed_with(http::Method::PUT, "/destination/object", &[("x-amz-copy-source", "/source/secret")]);
    let (status, body) = exchange(&service, request).await;

    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

struct ListBackend(Arc<AtomicUsize>);

impl<O: rustfs_gateway::Operation> Handler<O> for ListBackend
where
    O::Output: Default,
{
    async fn call(&self, _request: Req<O>) -> HandlerResult<O> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(O::Output::default()))
    }

    async fn call_with_context(&self, _request: Req<O>, _context: rustfs_gateway::HandlerContext) -> HandlerResult<O> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(O::Output::default()))
    }
}

async fn list_authorization(target: &str, allowed_action: &'static str, allowed_bucket: &'static str) -> (u16, usize) {
    let reached = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(ListBackend(Arc::clone(&reached)));
    let service = support::wired_at_signed_time()
        .authorizer(rustfs_gateway::allow_when(move |request| {
            request.action == allowed_action
                && request.resource == rustfs_gateway::ResourceShape::Bucket
                && request.bucket.is_some_and(|bucket| bucket.as_str() == allowed_bucket)
                && request.key.is_none()
        }))
        .register::<dto::ListObjectVersions, _>(Arc::clone(&backend))
        .register::<dto::ListObjects, _>(Arc::clone(&backend))
        .register::<dto::ListObjectsV2, _>(backend)
        .build()
        .expect("the list operations are registered");
    let (status, _) = exchange(&service, support::signed(http::Method::GET, target)).await;
    (status.as_u16(), reached.load(Ordering::SeqCst))
}

// AWS assigns version listing a distinct bucket permission:
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html
#[tokio::test]
async fn n_list_versions_refuses_ordinary_list_permission_before_the_handler() {
    assert_eq!(list_authorization("/bucket?versions", "s3:ListBucket", "bucket").await, (403, 0));
}

#[tokio::test]
async fn n_list_versions_refuses_an_unrelated_permission_before_the_handler() {
    assert_eq!(list_authorization("/bucket?versions", "s3:GetObject", "bucket").await, (403, 0));
}

#[tokio::test]
async fn n_list_versions_refuses_permission_for_another_bucket() {
    assert_eq!(
        list_authorization("/bucket?versions", "s3:ListBucketVersions", "another-bucket").await,
        (403, 0)
    );
}

#[tokio::test]
async fn n_list_versions_permission_does_not_grant_ordinary_listing() {
    for target in ["/bucket", "/bucket?list-type=2"] {
        assert_eq!(list_authorization(target, "s3:ListBucketVersions", "bucket").await, (403, 0), "{target}");
    }
}

#[tokio::test]
async fn list_versions_authorizes_its_bucket_permission_and_reaches_the_handler() {
    assert_eq!(list_authorization("/bucket?versions", "s3:ListBucketVersions", "bucket").await, (200, 1));
}

#[tokio::test]
async fn list_versions_fix_preserves_ordinary_list_authorization() {
    for target in ["/bucket", "/bucket?list-type=2"] {
        assert_eq!(list_authorization(target, "s3:ListBucket", "bucket").await, (200, 1), "{target}");
    }
}

#[derive(Debug)]
struct OutpostsSource {
    bucket: Option<String>,
    key: Option<String>,
    identity: rustfs_gateway::ResourceIdentity,
    version: Option<String>,
    route_bucket: Option<String>,
}

async fn bucketless_copy_authorization(
    source: &str,
    part: bool,
    allow_source: bool,
) -> (u16, String, Vec<OutpostsSource>, usize) {
    let reached = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(ListBackend(Arc::clone(&reached)));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let observations = Arc::clone(&seen);
    let service = support::wired_at_signed_time()
        .authorizer(rustfs_gateway::allow_when(move |request| {
            if let Some(identity) = request.copy_source_identity {
                observations.lock().expect("observations").push(OutpostsSource {
                    bucket: request.bucket.map(|value| value.as_str().to_owned()),
                    key: request.key.map(|value| value.as_str().to_owned()),
                    identity: identity.clone(),
                    version: request.version_id.map(str::to_owned),
                    route_bucket: request.route_bucket.map(|value| value.as_str().to_owned()),
                });
                allow_source
            } else {
                true
            }
        }))
        .register::<dto::CopyObject, _>(Arc::clone(&backend))
        .register::<dto::UploadPartCopy, _>(backend)
        .build()
        .expect("copy operations registered");
    let target = if part {
        "/destination/object?partNumber=1&uploadId=upload-one"
    } else {
        "/destination/object"
    };
    let (status, body) = exchange(&service, signed_with(http::Method::PUT, target, &[("x-amz-copy-source", source)])).await;
    let seen = std::mem::take(&mut *seen.lock().expect("observations"));
    (status.as_u16(), body, seen, reached.load(Ordering::SeqCst))
}

fn assert_bucketless_source(seen: &[OutpostsSource], version: Option<&str>) {
    assert_eq!(seen.len(), 1);
    let source = &seen[0];
    assert_eq!(source.bucket, None);
    assert_eq!(source.route_bucket.as_deref(), Some("destination"));
    assert_eq!(source.key.as_deref(), Some("literal%2Fkey"));
    assert_eq!(source.version.as_deref(), version);
    assert_eq!(
        source.identity,
        rustfs_gateway::ResourceIdentity::Outposts {
            partition: "aws".to_owned(),
            region: "us-east-1".to_owned(),
            account: "123456789012".to_owned(),
            outpost_id: "op-1".to_owned(),
        }
    );
}

const BUCKETLESS_OUTPOSTS: &str = "arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-1/object/literal%252Fkey";

#[tokio::test]
async fn bucketless_outposts_authorization_keeps_the_destination_separate() {
    for part in [false, true] {
        for source in [
            BUCKETLESS_OUTPOSTS.to_owned(),
            format!("/{BUCKETLESS_OUTPOSTS}"),
            BUCKETLESS_OUTPOSTS.replace(':', "%3A"),
        ] {
            for (suffix, version) in [("", None), ("?versionId=v1", Some("v1"))] {
                let (status, body, seen, reached) = bucketless_copy_authorization(&format!("{source}{suffix}"), part, true).await;
                assert_eq!(status, 200, "{body}");
                assert_bucketless_source(&seen, version);
                assert_eq!(reached, 1);
            }
        }
    }
}

#[tokio::test]
async fn n_bucketless_outposts_source_denial_never_reaches_either_handler() {
    for part in [false, true] {
        for (suffix, version) in [("", None), ("?versionId=v1", Some("v1"))] {
            let (status, body, seen, reached) =
                bucketless_copy_authorization(&format!("{BUCKETLESS_OUTPOSTS}{suffix}"), part, false).await;
            assert_eq!(status, 403, "{body}");
            assert!(body.contains("<Code>AccessDenied</Code>"));
            assert_bucketless_source(&seen, version);
            assert_eq!(reached, 0);
        }
    }
}

#[tokio::test]
async fn n_malformed_bucketless_outposts_reaches_no_source_authorizer_or_handler() {
    for part in [false, true] {
        for source in [
            BUCKETLESS_OUTPOSTS.replace("op-1", ""),
            BUCKETLESS_OUTPOSTS.replace("123456789012", "123"),
        ] {
            let (status, body, seen, reached) = bucketless_copy_authorization(&source, part, true).await;
            assert_eq!(status, 400, "{body}");
            assert!(body.contains("<Code>InvalidArgument</Code>"));
            assert!(seen.is_empty());
            assert_eq!(reached, 0);
        }
    }
}

#[tokio::test]
async fn derived_delete_keys_still_inherit_the_routed_bucket() {
    let reached = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let observations = Arc::clone(&seen);
    let service = support::wired_at_signed_time()
        .authorizer(rustfs_gateway::allow_when(move |request| {
            if let Some(key) = request.key {
                observations
                    .lock()
                    .expect("observations")
                    .push((request.bucket.map(|bucket| bucket.as_str().to_owned()), key.as_str().to_owned()));
            }
            true
        }))
        .register::<dto::DeleteObjects, _>(Arc::new(ListBackend(Arc::clone(&reached))))
        .build()
        .expect("delete registered");
    let request = support::signed_target_with_body_and_headers(
        http::Method::POST,
        "/destination?delete",
        &[("content-md5", "iQR1tr4J3iyw2ElG8CAWPA==")],
        bytes::Bytes::from_static(b"<Delete><Object><Key>one</Key></Object><Object><Key>two</Key></Object></Delete>"),
    );
    let (status, body) = exchange(&service, request).await;
    assert_eq!(status.as_u16(), 200, "{body}");
    assert_eq!(
        *seen.lock().expect("observations"),
        [
            (Some("destination".to_owned()), "one".to_owned()),
            (Some("destination".to_owned()), "two".to_owned()),
        ]
    );
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}
