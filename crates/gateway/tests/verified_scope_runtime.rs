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

//! The verified credential scope, as an assembled service hands it to the `Authorizer`.
//!
//! Responsible for: proving that the scope the built-in verifier checked reaches both
//! authorization stages through `RequestContext::verified_scope`, unchanged, and that an anonymous
//! request reaches them with none (ADR-0020).
//! NOT responsible for: how the scope is checked (`rustfs-gateway-sig`'s `enforce_scope`) or which
//! verdict carries it (`src/ext/authenticator_tests.rs`).
//! Upstream: `rustfs-gateway`. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, InputAuthzRequest, InputDecisions, RegionSet, RequestContext,
    S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials,
};

use crate::support::{self, Backend, Ping, exchange};

/// `(date, region, service)` of one scope, or `None` for a stage that saw none.
type SeenScope = Option<(String, String, String)>;

/// Allows everything and records the scope each stage was shown.
#[derive(Default)]
struct ScopeRecorder {
    seen: Mutex<Vec<SeenScope>>,
}

impl ScopeRecorder {
    fn record(&self, context: &RequestContext<'_>) {
        let seen = context
            .verified_scope()
            .map(|scope| (scope.date().as_str().to_owned(), scope.region().to_owned(), scope.service().to_owned()));
        self.seen.lock().expect("not poisoned").push(seen);
    }

    fn seen(&self) -> Vec<SeenScope> {
        self.seen.lock().expect("not poisoned").clone()
    }
}

impl Authorizer for ScopeRecorder {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, _request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        self.record(context);
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.record(context);
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// Serves two regions whose sorted first is `eu-west-1`, while the fixture signs for `us-east-1`:
/// a context that reported the first configured region instead of the verified one is caught.
fn service(recorder: &Arc<ScopeRecorder>) -> S3Service {
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").expect("valid key")));
    ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(
            credentials,
            RegionSet::new(["us-east-1", "eu-west-1"]).expect("non-empty"),
        ))
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&support::ping_dialect())
        .authorizer(Arc::clone(recorder) as Arc<dyn Authorizer>)
        .build()
        .expect("a complete assembly")
}

fn anonymous_ping() -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request")
}

/// Positive — both stages see the scope the signature was verified under.
#[tokio::test]
async fn both_authorization_stages_see_the_verified_scope() {
    let recorder = Arc::new(ScopeRecorder::default());
    let (status, body) = exchange(&service(&recorder), support::signed(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let expected = Some(("20260102".to_owned(), "us-east-1".to_owned(), "s3".to_owned()));
    assert_eq!(recorder.seen(), [expected.clone(), expected]);
}

/// Negative — an anonymous request is authorised with no scope, never with a configured default.
#[tokio::test]
async fn an_anonymous_request_is_authorised_with_no_scope() {
    let recorder = Arc::new(ScopeRecorder::default());
    let (status, body) = exchange(&service(&recorder), anonymous_ping()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(recorder.seen(), [None, None]);
}

/// Negative — a context built outside the pipeline carries no scope: `RequestContext::new` is the
/// public constructor and it has no parameter through which a scope could be supplied.
#[test]
fn a_context_built_outside_the_pipeline_has_no_scope() {
    let policy = rustfs_gateway::PolicySnapshot::of(Arc::new(String::from("a policy document")));
    let context = RequestContext::new(rustfs_gateway::RequestNow::from_unix_seconds(0), &policy);
    assert!(context.verified_scope().is_none());
}
