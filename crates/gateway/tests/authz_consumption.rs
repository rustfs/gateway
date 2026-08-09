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
//! Responsible for: the copy-source denial exploit path and its backend call measurement.
//! NOT responsible for: policy evaluation or audit formatting.
//! Upstream: `rustfs_gateway_core::authz`. Downstream: the facade service pipeline.

mod support;

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
        assert_eq!(source.bucket().as_str(), "source");
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

/// c-azc-0002, c-azc-0028, c-azc-0029: both stages use one policy pointer, clock, and authorizer.
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
