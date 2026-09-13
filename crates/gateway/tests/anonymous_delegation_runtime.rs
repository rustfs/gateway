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

//! Anonymous admission delegated to the `Authorizer`, as an assembled service runs it (ADR-0021).
//!
//! Responsible for: proving that the default floor still refuses an anonymous request to an
//! operation that did not opt in, before any authorizer runs; that a floor delegating anonymous
//! admission sends that request to the authorizer, which alone decides; and that presented
//! credentials are never downgraded to anonymous under delegation.
//! NOT responsible for: the floor's allow-list arithmetic (`rustfs-gateway-sig`'s
//! `security_floor_schemes`) or the startup posture line (`src/posture.rs`).
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::dto::ListBuckets;
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, InputAuthzRequest, InputDecisions, RegionSet, RequestContext,
    S3Service, SecurityFloor, ServiceBuilder, SigV4Authenticator, StaticCredentials,
};

use crate::support::{self, Backend, exchange};

/// Answers one fixed decision and records, per stage, whether the request was anonymous.
struct Recording {
    decision: Decision,
    anonymous: Mutex<Vec<bool>>,
}

impl Recording {
    fn new(decision: Decision) -> Arc<Self> {
        Arc::new(Self {
            decision,
            anonymous: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<bool> {
        self.anonymous.lock().expect("not poisoned").clone()
    }
}

impl Authorizer for Recording {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        self.anonymous.lock().expect("not poisoned").push(request.is_anonymous());
        let decision = self.decision;
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.anonymous
            .lock()
            .expect("not poisoned")
            .push(request.route().is_anonymous());
        let decisions = request.decide_all(self.decision, |_| self.decision);
        Box::pin(async move { decisions })
    }
}

/// `ListBuckets` is a built-in, header-only operation: it never opted in to anonymous access.
fn service(floor: SecurityFloor, authorizer: &Arc<Recording>) -> S3Service {
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid key")));
    ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .security_floor(floor)
        .register::<ListBuckets, _>(Arc::new(Backend))
        .authorizer(Arc::clone(authorizer) as Arc<dyn Authorizer>)
        .build()
        .expect("a complete assembly")
}

fn delegating() -> SecurityFloor {
    SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
}

fn list_buckets(extra: &[(&str, &str)]) -> http::Request<Bytes> {
    let mut builder = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com");
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder.body(Bytes::new()).expect("a valid request")
}

/// Negative — the default is unchanged: an anonymous request to an operation that did not opt in
/// is refused by the floor, and the authorizer is never consulted.
#[tokio::test]
async fn by_default_an_anonymous_request_never_reaches_the_authorizer() {
    let authorizer = Recording::new(Decision::Allow);
    let (status, body) = exchange(&service(SecurityFloor::new(), &authorizer), list_buckets(&[])).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(authorizer.seen().is_empty(), "the floor refused before authorization");
}

/// Negative — delegation hands the decision to the authorizer, and the authorizer can refuse it.
/// A delegating floor is not an allow-all.
#[tokio::test]
async fn under_delegation_the_authorizer_can_refuse_an_anonymous_request() {
    let authorizer = Recording::new(Decision::Deny);
    let (status, body) = exchange(&service(delegating(), &authorizer), list_buckets(&[])).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(authorizer.seen(), [true], "the route stage decided, and saw an anonymous caller");
}

/// Positive — under delegation an anonymous request the authorizer allows is served, and both
/// mandatory stages ran with an anonymous caller.
#[tokio::test]
async fn under_delegation_the_authorizer_can_allow_an_anonymous_request() {
    let authorizer = Recording::new(Decision::Allow);
    let (status, body) = exchange(&service(delegating(), &authorizer), list_buckets(&[])).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(authorizer.seen(), [true, true]);
}

/// Negative — delegation admits only a request that presented nothing. A malformed signature, a
/// wrong one, or a lone security token is refused by authentication, never passed on as anonymous.
#[tokio::test]
async fn under_delegation_presented_credentials_are_never_downgraded() {
    for extra in [
        &[("authorization", "AWS4-HMAC-SHA256 Credential=garbage")][..],
        &[("x-amz-security-token", "a-token-with-no-signature")][..],
    ] {
        let authorizer = Recording::new(Decision::Allow);
        let (status, body) = exchange(&service(delegating(), &authorizer), list_buckets(extra)).await;
        assert!(status.is_client_error(), "{extra:?} answered {status}: {body}");
        assert!(
            authorizer.seen().is_empty(),
            "{extra:?} reached the authorizer as {:?}",
            authorizer.seen()
        );
    }
    let mut wrong = support::signed(http::Method::GET, "/");
    let authorization = wrong
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .expect("signed")
        .to_owned();
    let tampered = format!("{}0", &authorization[..authorization.len() - 1]);
    wrong
        .headers_mut()
        .insert("authorization", http::HeaderValue::from_str(&tampered).expect("valid"));
    let authorizer = Recording::new(Decision::Allow);
    let (status, body) = exchange(&service(delegating(), &authorizer), wrong).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(authorizer.seen().is_empty(), "a wrong signature is not an anonymous request");
}

/// Positive control — a correctly signed request under delegation is still authenticated.
#[tokio::test]
async fn under_delegation_a_signed_request_is_still_authenticated() {
    let authorizer = Recording::new(Decision::Allow);
    let (status, body) = exchange(&service(delegating(), &authorizer), support::signed(http::Method::GET, "/")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(authorizer.seen(), [false, false]);
}
