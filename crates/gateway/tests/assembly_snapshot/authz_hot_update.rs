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

//! Proves a hot authorizer replacement decides each request with exactly one generation.
//!
//! Responsible for: holding a request before and after route authorization across a complete
//! assembly replacement, and probing a request sent while publication is in progress.
//! NOT responsible for: other middleware generations or authorization semantics.
//! Upstream: `S3Service::replace_assembly`. Downstream: c-azc-0028.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode};
use rustfs_gateway::{
    AssemblyUpdate, Authorizer, AuthzAuditEvent, AuthzAuditSink, AuthzRequest, AuthzStage, BoxFuture, Decision, Identity,
    InputAuthzRequest, InputDecisions, PolicyError, PolicySnapshot, PolicySource, PolicyTimeout, RequestContext, S3Service,
};
use tokio::sync::oneshot;

use crate::support::{self, Backend, ContentPing, wired};

/// `(generation that acted, what it did, policy generation it was handed)`.
type HotTrace = Arc<Mutex<Vec<(&'static str, &'static str, &'static str)>>>;

#[derive(Clone)]
struct HotRecord {
    generation: &'static str,
    trace: HotTrace,
}

impl HotRecord {
    fn mark(&self, stage: &'static str, policy: &'static str) {
        self.trace
            .lock()
            .expect("authorization trace is not poisoned")
            .push((self.generation, stage, policy));
    }

    /// The policy generation this request's one snapshot carries.
    fn seen(context: &RequestContext<'_>) -> &'static str {
        context.policy().get::<&'static str>().copied().unwrap_or("none")
    }

    /// Allows only when authorizer and policy come from the same generation, so any mixture is a
    /// visible refusal as well as a visible trace entry.
    fn decide(&self, policy: &'static str) -> Decision {
        if policy == self.generation {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

impl AuthzAuditSink for HotRecord {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        self.mark(
            match event.stage {
                AuthzStage::Route => "route-audit",
                AuthzStage::Input => "input-audit",
            },
            "",
        );
    }
}

/// Signals when the old authorizer leaves the live store, then holds the publisher there until the
/// test has sent a request through whatever the store holds at that instant.
struct ReleaseProbe {
    released: Option<oneshot::Sender<()>>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl Drop for ReleaseProbe {
    fn drop(&mut self) {
        if let Some(released) = self.released.take() {
            let _ = released.send(());
            let _ = self
                .resume
                .lock()
                .expect("release control is not poisoned")
                .recv_timeout(Duration::from_secs(3));
        }
    }
}

struct HotAuthorizer {
    record: HotRecord,
    _release: Option<ReleaseProbe>,
}

impl Authorizer for HotAuthorizer {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, _request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let policy = HotRecord::seen(context);
        self.record.mark("route", policy);
        let decision = self.record.decide(policy);
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let policy = HotRecord::seen(context);
        self.record.mark("input", policy);
        let decision = self.record.decide(policy);
        Box::pin(async move { request.decide_all(decision, |_| decision) })
    }
}

/// `(signal that the hold point was reached, release)`.
pub(super) type Hold = (oneshot::Sender<()>, oneshot::Receiver<()>);

/// A policy source that can hold its first reading open: the request has captured its generation
/// at entry, and neither authorization stage has run.
struct HotPolicy {
    record: HotRecord,
    hold: Mutex<Option<Hold>>,
}

impl PolicySource for HotPolicy {
    fn snapshot<'a>(&'a self, _identity: Option<&'a Identity>) -> BoxFuture<'a, Result<PolicySnapshot, PolicyError>> {
        self.record.mark("policy", self.record.generation);
        let hold = self.hold.lock().expect("policy hold is not poisoned").take();
        Box::pin(async move {
            if let Some((entered, release)) = hold {
                let _ = entered.send(());
                let _ = release.await;
            }
            Ok(PolicySnapshot::of(Arc::new(self.record.generation)))
        })
    }
}

/// A body whose first poll can be held. The pipeline polls a body only once route authorization
/// has allowed the request (c-azc-0009), and decodes and authorizes input only after reading it.
struct HeldBody {
    bytes: Option<Bytes>,
    entered: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}

impl http_body::Body for HeldBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<http_body::Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if let Some(entered) = this.entered.take() {
            let _ = entered.send(());
        }
        if let Some(release) = this.release.as_mut() {
            if Pin::new(release).poll(context).is_pending() {
                return Poll::Pending;
            }
            this.release = None;
        }
        Poll::Ready(this.bytes.take().map(|bytes| Ok(http_body::Frame::data(bytes))))
    }
}

async fn held_call(service: &S3Service, hold: Option<Hold>) -> StatusCode {
    let (entered, release) = hold.map_or((None, None), |(entered, release)| (Some(entered), Some(release)));
    let request = http::Request::builder()
        .method(Method::PUT)
        .uri("/")
        .header("host", "s3.example.com")
        .header("content-length", "4")
        .body(HeldBody {
            bytes: Some(Bytes::from_static(b"four")),
            entered,
            release,
        })
        .expect("valid request");
    tokio::time::timeout(Duration::from_secs(3), service.call(request))
        .await
        .expect("authorization request completed")
        .status()
}

fn hot_service(trace: &HotTrace, policy_hold: Option<Hold>, release: Option<ReleaseProbe>) -> S3Service {
    let record = HotRecord {
        generation: "old",
        trace: Arc::clone(trace),
    };
    wired()
        .dialect(&support::content_ping_dialect())
        .register::<ContentPing, _>(Arc::new(Backend))
        .authorizer(HotAuthorizer {
            record: record.clone(),
            _release: release,
        })
        .policy_source(HotPolicy {
            record: record.clone(),
            hold: Mutex::new(policy_hold),
        })
        // A held policy read must not become Indeterminate however slow the runner is.
        .policy_timeout(PolicyTimeout::new(Duration::from_secs(5)).expect("the maximum policy timeout is valid"))
        .authz_audit(record)
        .build()
        .expect("the old authorization generation is valid")
}

fn hot_update(trace: &HotTrace) -> AssemblyUpdate {
    let record = HotRecord {
        generation: "new",
        trace: Arc::clone(trace),
    };
    AssemblyUpdate::new()
        .dialect(&support::content_ping_dialect())
        .register::<ContentPing, _>(Arc::new(Backend))
        .authorizer(HotAuthorizer {
            record: record.clone(),
            _release: None,
        })
        .policy_source(HotPolicy {
            record: record.clone(),
            hold: Mutex::new(None),
        })
        .authz_audit(record)
}

fn hot_take(trace: &HotTrace) -> Vec<(&'static str, &'static str, &'static str)> {
    std::mem::take(&mut *trace.lock().expect("authorization trace is not poisoned"))
}

/// Everything one generation does for one allowed request, in pipeline order.
fn decided_by(generation: &'static str) -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (generation, "policy", generation),
        (generation, "route", generation),
        (generation, "route-audit", ""),
        (generation, "input", generation),
        (generation, "input-audit", ""),
    ]
}

#[derive(Clone, Copy, Debug)]
enum HoldPoint {
    /// Inside the request's one policy reading, before route authorization.
    BeforeRoute,
    /// On the first body poll, after route authorization and before input authorization.
    AfterRoute,
}

async fn replace_while_held(point: HoldPoint) {
    let trace = HotTrace::default();
    let (entered, reached) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (policy_hold, body_hold) = match point {
        HoldPoint::BeforeRoute => (Some((entered, released)), None),
        HoldPoint::AfterRoute => (None, Some((entered, released))),
    };
    let service = hot_service(&trace, policy_hold, None);
    let inflight = service.clone();
    let request = tokio::spawn(async move { held_call(&inflight, body_hold).await });
    tokio::time::timeout(Duration::from_secs(3), reached)
        .await
        .expect("the request reached its hold point")
        .expect("the hold point signalled");
    let before = hot_take(&trace);

    service
        .replace_assembly(hot_update(&trace))
        .expect("a valid authorization update");
    release.send(()).expect("the held request is waiting");
    let status = request.await.expect("the held request completed");
    let after = hot_take(&trace);

    let old = decided_by("old");
    let split = match point {
        HoldPoint::BeforeRoute => 1,
        HoldPoint::AfterRoute => 3,
    };
    assert_eq!(
        (status, before, after),
        (StatusCode::OK, old[..split].to_vec(), old[split..].to_vec()),
        "{point:?}: the in-flight request must be decided by the old authorizer and policy at both stages"
    );
    assert_eq!(held_call(&service, None).await, StatusCode::OK, "{point:?}");
    assert_eq!(
        hot_take(&trace),
        decided_by("new"),
        "{point:?}: the next request must be decided by the new generation alone"
    );
}

async fn no_request_enters_a_partial_publication() {
    let trace = HotTrace::default();
    let (released, left_store) = oneshot::channel();
    let (resume, resumed) = mpsc::sync_channel(1);
    let service = hot_service(
        &trace,
        None,
        Some(ReleaseProbe {
            released: Some(released),
            resume: Mutex::new(resumed),
        }),
    );
    let publisher_service = service.clone();
    let update = hot_update(&trace);
    let publisher = std::thread::spawn(move || publisher_service.replace_assembly(update));
    tokio::time::timeout(Duration::from_secs(3), left_store)
        .await
        .expect("publication released the old authorizer")
        .expect("the release probe signalled");

    // The publisher is parked at the instant the old authorizer left the store.
    let probe = held_call(&service, None).await;
    resume.send(()).expect("the publisher is parked in the release probe");
    publisher
        .join()
        .expect("the publisher completed")
        .expect("a valid authorization update");
    assert_eq!(
        (probe, hot_take(&trace)),
        (StatusCode::OK, decided_by("new")),
        "a request entering during publication must see the whole new authorization generation"
    );
}

/// c-azc-0028. Negative — a hot authorizer replacement cannot split one request's two stages.
///
/// The authorizer, policy source and audit sink are replaced together through
/// `S3Service::replace_assembly`. A request held before or after its route stage keeps the old
/// generation for both stages; the next request uses only the new one; and a request entering while
/// the publication is in progress sees no mixture of the two.
#[tokio::test]
async fn c_azc_0028_a_hot_authorizer_update_never_splits_one_request() {
    replace_while_held(HoldPoint::BeforeRoute).await;
    replace_while_held(HoldPoint::AfterRoute).await;
    no_request_enters_a_partial_publication().await;
}
