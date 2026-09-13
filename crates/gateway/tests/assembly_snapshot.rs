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

//! Proves one request retains one validated middleware and operation generation.
//!
//! Responsible for: publishing complete assemblies and preserving unrelated fields during partial
//! updates. NOT responsible for: individual middleware behavior or route-conflict validation.
//! Upstream: the public update API and real request pipeline. Downstream: c-mw-0026 and the
//! authorization hot-update case.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode};
use rustfs_gateway::{
    AssemblyError, AssemblyUpdate, Authorizer, AuthzAuditEvent, AuthzAuditSink, AuthzRequest, AuthzStage, Body, BoxFuture,
    ConfigHandle, Decision, HandlerError, HandlerResult, Identity, InputAuthzRequest, InputDecisions, Next, Observer, OpLayer,
    Operation, PolicyError, PolicySnapshot, PolicySource, PolicyTimeout, Req, RequestContext, RequestEvent, ResponseView,
    RoutedView, S3Service, ServiceBuilder, ServiceConfig, StageFilter, WireHead, op_layer, policy_from,
};
use tokio::sync::{Notify, oneshot};

use crate::support::{self, Backend, ContentPing, Ping, exchange, plain, wired};

type Events = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

#[derive(Clone)]
struct Record {
    generation: &'static str,
    events: Events,
}

impl Record {
    fn mark(&self, stage: &'static str) {
        self.events
            .lock()
            .expect("event log is not poisoned")
            .push((self.generation, stage));
    }

    fn policy(&self, context: &RequestContext<'_>) -> Decision {
        if context.policy().get::<&'static str>() == Some(&self.generation) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

impl StageFilter for Record {
    fn on_wire(&self, _head: &mut WireHead<'_>) -> Result<(), HandlerError> {
        self.mark("wire");
        Ok(())
    }

    fn on_routed(&self, _routed: &RoutedView<'_>) -> Result<(), HandlerError> {
        self.mark("routed");
        Ok(())
    }

    fn on_response(&self, _view: &ResponseView<'_>, _response: &mut http::Response<Body>) -> Result<(), HandlerError> {
        self.mark("response");
        Ok(())
    }
}

impl Observer for Record {
    fn on_response(&self, _event: &RequestEvent<'_>) {
        self.mark("observer");
    }
}

impl AuthzAuditSink for Record {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        self.mark(match event.stage {
            AuthzStage::Route => "route-audit",
            AuthzStage::Input => "input-audit",
        });
    }
}

#[derive(Default)]
struct Pause {
    entered: Notify,
    release: Notify,
}

struct GenerationAuthorizer {
    record: Record,
    pause: Option<Arc<Pause>>,
}

struct HoldsConfig {
    _handle: ConfigHandle,
    _lifetime: Arc<()>,
}

impl StageFilter for HoldsConfig {}

// Registry-only replacement discards filters after validating its route table. Rendezvous here
// puts both writers at publication, rather than racing a settings write against route validation.
struct PublishBarrier {
    entered: mpsc::SyncSender<()>,
    ready: Mutex<mpsc::Receiver<()>>,
}

impl StageFilter for PublishBarrier {}

impl Drop for PublishBarrier {
    fn drop(&mut self) {
        let _ = self.entered.send(());
        let _ = self
            .ready
            .lock()
            .expect("publication control is not poisoned")
            .recv_timeout(Duration::from_secs(3));
    }
}

impl Authorizer for GenerationAuthorizer {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, _request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        self.record.mark("route");
        let decision = self.record.policy(context);
        Box::pin(async move {
            if let Some(pause) = &self.pause {
                pause.entered.notify_one();
                pause.release.notified().await;
            }
            decision
        })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.record.mark("input");
        let decision = self.record.policy(context);
        Box::pin(async move { request.decide_all(decision, |_| decision) })
    }
}

fn layer<O: Operation>(record: Record) -> impl OpLayer<O> {
    op_layer(move |request: Req<O>, next: Next<'_, O>| {
        let record = record.clone();
        Box::pin(async move {
            record.mark("layer");
            next.run(request).await
        }) as BoxFuture<'_, HandlerResult<O>>
    })
}

fn live(events: &Events, pause: Option<Arc<Pause>>, ceiling: u64) -> (S3Service, ConfigHandle) {
    let record = Record {
        generation: "old",
        events: Arc::clone(events),
    };
    let policy = record.clone();
    let (builder, handle) = wired().config(ServiceConfig::new(ceiling));
    let service = builder
        .dialect(&support::ping_dialect())
        .dialect(&support::content_ping_dialect())
        .register::<Ping, _>(Arc::new(Backend))
        .register::<ContentPing, _>(Arc::new(Backend))
        .op_layer::<Ping, _>(layer(record.clone()))
        .op_layer::<ContentPing, _>(layer(record.clone()))
        .stage_filter(record.clone())
        .observer(record.clone())
        .authz_audit(record.clone())
        .authorizer(GenerationAuthorizer { record, pause })
        .policy_source(policy_from(move |_| {
            policy.mark("policy");
            Ok(PolicySnapshot::of(Arc::new(policy.generation)))
        }))
        .build()
        .expect("the initial generation is valid");
    (service, handle)
}

fn replacement(events: &Events, ceiling: u64) -> AssemblyUpdate {
    let record = Record {
        generation: "new",
        events: Arc::clone(events),
    };
    let policy = record.clone();
    AssemblyUpdate::new()
        .config(ServiceConfig::new(ceiling))
        .dialect(&support::ping_dialect())
        .dialect(&support::content_ping_dialect())
        .register::<Ping, _>(Arc::new(Backend))
        .register::<ContentPing, _>(Arc::new(Backend))
        .op_layer::<Ping, _>(layer(record.clone()))
        .op_layer::<ContentPing, _>(layer(record.clone()))
        .stage_filter(record.clone())
        .observer(record.clone())
        .authz_audit(record.clone())
        .authorizer(GenerationAuthorizer { record, pause: None })
        .policy_source(policy_from(move |_| {
            policy.mark("policy");
            Ok(PolicySnapshot::of(Arc::new(policy.generation)))
        }))
}

fn take(events: &Events) -> Vec<(&'static str, &'static str)> {
    std::mem::take(&mut *events.lock().expect("event log is not poisoned"))
}

fn expected(generation: &'static str) -> Vec<(&'static str, &'static str)> {
    [
        "wire",
        "routed",
        "policy",
        "route",
        "route-audit",
        "input",
        "input-audit",
        "layer",
        "response",
        "observer",
    ]
    .into_iter()
    .map(|stage| (generation, stage))
    .collect()
}

async fn body_request(service: &S3Service) -> StatusCode {
    tokio::time::timeout(
        Duration::from_secs(3),
        service.call(
            http::Request::builder()
                .method(Method::PUT)
                .uri("/")
                .header("host", "s3.example.com")
                .body(http_body_util::Full::new(Bytes::from_static(b"sixteen-byte-body")))
                .expect("valid request"),
        ),
    )
    .await
    .expect("body request completed")
    .status()
}

async fn ping(service: &S3Service) -> (StatusCode, String) {
    tokio::time::timeout(Duration::from_secs(3), exchange(service, plain(Method::POST, "/")))
        .await
        .expect("ping request completed")
}

/// Positive control: the next request sees every replaced seam, including the operation layer.
#[tokio::test]
async fn a_complete_update_reaches_every_service_clone() {
    let events = Events::default();
    let (service, _handle) = live(&events, None, 8);
    let clone = service.clone();
    service.replace_assembly(replacement(&events, 64)).expect("valid update");

    assert_eq!(ping(&clone).await, (StatusCode::OK, "<Ping>pong</Ping>".to_owned()));
    assert_eq!(take(&events), expected("new"));
    assert_eq!(body_request(&service).await, StatusCode::OK);
    assert_eq!(take(&events), expected("new"));
}

/// Negative: publishing during route authorization cannot replace input auth, layers, or sinks.
#[tokio::test]
async fn an_inflight_request_cannot_mix_middleware_generations() {
    let events = Events::default();
    let pause = Arc::new(Pause::default());
    let (service, _handle) = live(&events, Some(Arc::clone(&pause)), 64);
    let inflight = service.clone();
    let request = tokio::spawn(async move { ping(&inflight).await });
    tokio::time::timeout(Duration::from_secs(3), pause.entered.notified())
        .await
        .expect("route stage reached");

    service.replace_assembly(replacement(&events, 64)).expect("valid update");
    pause.release.notify_one();
    assert_eq!(
        request.await.expect("request completed"),
        (StatusCode::OK, "<Ping>pong</Ping>".to_owned())
    );
    assert_eq!(take(&events), expected("old"));
    assert_eq!(ping(&service).await.0, StatusCode::OK);
    assert_eq!(take(&events), expected("new"));
}

/// Negative: an update cannot widen a body ceiling after the request entered the old generation.
#[tokio::test]
async fn assembly_settings_cannot_tear_an_inflight_request() {
    let events = Events::default();
    let pause = Arc::new(Pause::default());
    let (service, _handle) = live(&events, Some(Arc::clone(&pause)), 8);
    let inflight = service.clone();
    let request = tokio::spawn(async move { body_request(&inflight).await });
    tokio::time::timeout(Duration::from_secs(3), pause.entered.notified())
        .await
        .expect("route stage reached");

    service.replace_assembly(replacement(&events, 64)).expect("valid update");
    pause.release.notify_one();
    assert_eq!(request.await.expect("request completed"), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        take(&events),
        ["wire", "routed", "policy", "route", "route-audit", "response", "observer"].map(|stage| ("old", stage))
    );
    assert_eq!(body_request(&service).await, StatusCode::OK);
    assert_eq!(take(&events), expected("new"));
}

/// Negative: rejected candidates cannot publish their settings or any part of their middleware.
#[tokio::test]
async fn invalid_candidates_preserve_the_last_good_generation() {
    let events = Events::default();
    let (service, _handle) = live(&events, None, 8);
    let missing_authorizer = AssemblyUpdate::new()
        .config(ServiceConfig::new(64))
        .dialect(&support::ping_dialect())
        .register::<Ping, _>(Arc::new(Backend));
    assert!(matches!(
        service.replace_assembly(missing_authorizer),
        Err(AssemblyError::MissingAuthorizer { .. })
    ));
    assert_eq!(ping(&service).await.0, StatusCode::OK);
    assert_eq!(take(&events), expected("old"));

    let orphan = replacement(&events, 64).op_layer::<support::HeadPing, _>(layer(Record {
        generation: "invalid",
        events: Arc::clone(&events),
    }));
    assert!(matches!(
        service.replace_assembly(orphan),
        Err(AssemblyError::UnattachedOpLayer {
            operation: "example:HeadPing",
            ..
        })
    ));
    assert_eq!(ping(&service).await.0, StatusCode::OK);
    assert_eq!(take(&events), expected("old"));
    assert_eq!(body_request(&service).await, StatusCode::PAYLOAD_TOO_LARGE);
}

/// Negative: complete replacement must not detach handles issued by the original builder.
#[tokio::test]
async fn an_earlier_config_handle_retains_the_replacement_middleware() {
    let events = Events::default();
    let (service, handle) = live(&events, None, 64);
    service.replace_assembly(replacement(&events, 8)).expect("valid update");
    assert_eq!(body_request(&service).await, StatusCode::PAYLOAD_TOO_LARGE);
    take(&events);
    handle.store(ServiceConfig::new(64));
    assert_eq!(body_request(&service).await, StatusCode::OK);
    assert_eq!(take(&events), expected("new"));
}

/// Negative: a filter may retain its settings handle without creating a store-to-filter cycle.
#[test]
fn a_config_handle_owned_by_a_filter_cannot_keep_the_service_alive() {
    let lifetime = Arc::new(());
    let observed = Arc::downgrade(&lifetime);
    let (builder, handle) = wired().config(ServiceConfig::new(8));
    let service = builder
        .dialect(&support::ping_dialect())
        .register::<Ping, _>(Arc::new(Backend))
        .stage_filter(HoldsConfig {
            _handle: handle,
            _lifetime: lifetime,
        })
        .build()
        .expect("the initial assembly is valid");
    let clone = service.clone();
    drop(service);
    let retained = observed.upgrade().is_some();
    drop(clone);
    assert_eq!((retained, observed.upgrade().is_some()), (true, false));
}

/// Negative: simultaneous independent updates must retain both values and the existing middleware.
#[tokio::test]
async fn concurrent_partial_updates_cannot_overwrite_each_other() {
    let events = Events::default();
    let (service, handle) = live(&events, None, 8);
    for iteration in 0..64 {
        handle.store(ServiceConfig::new(8));
        let (entered_send, entered_receive) = mpsc::sync_channel(1);
        let (ready_send, ready_receive) = mpsc::sync_channel(1);
        let settings = handle.clone();
        let settings_thread = std::thread::spawn(move || {
            entered_receive
                .recv_timeout(Duration::from_secs(3))
                .expect("registry validation completed");
            ready_send.send(()).expect("registry publication is waiting");
            settings.store(ServiceConfig::new(64));
        });
        let registry_service = service.clone();
        let generation = if iteration % 2 == 0 { "registry-a" } else { "registry-b" };
        let record = Record {
            generation,
            events: Arc::clone(&events),
        };
        let candidate = ServiceBuilder::new()
            .dialect(&support::content_ping_dialect())
            .register::<ContentPing, _>(Arc::new(Backend))
            .op_layer::<ContentPing, _>(layer(record))
            .stage_filter(PublishBarrier {
                entered: entered_send,
                ready: Mutex::new(ready_receive),
            });
        let registry_thread = std::thread::spawn(move || {
            registry_service.replace_registry(candidate).expect("valid registry");
        });
        settings_thread.join().expect("settings writer completed");
        registry_thread.join().expect("registry writer completed");
        assert_eq!(body_request(&service).await, StatusCode::OK);
        let mut expected = expected("old");
        expected[7] = (generation, "layer");
        assert_eq!(take(&events), expected);
    }
}

// ── authorization hot update ─────────────────────────────────────────────────────────────────────

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
type Hold = (oneshot::Sender<()>, oneshot::Receiver<()>);

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
