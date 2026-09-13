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
//! Upstream: the public update API and real request pipeline. Downstream: c-mw-0026; the
//! authorization hot-update case lives in `assembly_snapshot/authz_hot_update.rs`.

use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode};
use rustfs_gateway::{
    AssemblyError, AssemblyUpdate, Authorizer, AuthzAuditEvent, AuthzAuditSink, AuthzRequest, AuthzStage, Body, BoxFuture,
    ConfigHandle, Decision, HandlerError, HandlerResult, InputAuthzRequest, InputDecisions, Next, Observer, OpLayer, Operation,
    PolicySnapshot, Req, RequestContext, RequestEvent, ResponseView, RoutedView, S3Service, ServiceBuilder, ServiceConfig,
    StageFilter, WireHead, op_layer, policy_from,
};
use tokio::sync::{Notify, oneshot};

use self::authz_hot_update::Hold;
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

fn old_generation(events: &Events, pause: Option<Arc<Pause>>, ceiling: u64) -> (ServiceBuilder, ConfigHandle) {
    let record = Record {
        generation: "old",
        events: Arc::clone(events),
    };
    let policy = record.clone();
    let (builder, handle) = wired().config(ServiceConfig::new(ceiling));
    let builder = builder
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
        }));
    (builder, handle)
}

fn live(events: &Events, pause: Option<Arc<Pause>>, ceiling: u64) -> (S3Service, ConfigHandle) {
    let (builder, handle) = old_generation(events, pause, ceiling);
    (builder.build().expect("the initial generation is valid"), handle)
}

fn replacement(events: &Events, ceiling: u64) -> AssemblyUpdate {
    replacement_serving(events, ceiling, true)
}

/// The "new" generation; without `ping`, it has no route for `POST /` at all.
fn replacement_serving(events: &Events, ceiling: u64, ping: bool) -> AssemblyUpdate {
    let record = Record {
        generation: "new",
        events: Arc::clone(events),
    };
    let policy = record.clone();
    let mut update = AssemblyUpdate::new()
        .config(ServiceConfig::new(ceiling))
        .dialect(&support::content_ping_dialect())
        .register::<ContentPing, _>(Arc::new(Backend))
        .op_layer::<ContentPing, _>(layer(record.clone()));
    if ping {
        update = update
            .dialect(&support::ping_dialect())
            .register::<Ping, _>(Arc::new(Backend))
            .op_layer::<Ping, _>(layer(record.clone()));
    }
    update
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
///
/// The rendezvous puts both writers at publication together, but which one loads first is the
/// scheduler's choice, so a load-then-store defect loses an update only on some runs. The
/// deterministic proof is `scripts/check_config_load_once.sh`, which requires every partial write
/// to the store to be an `rcu`.
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

#[path = "assembly_snapshot/authz_hot_update.rs"]
mod authz_hot_update;

/// Allows both stages, holding the first route decision until released.
struct HeldAllow(Mutex<Option<Hold>>);

impl Authorizer for HeldAllow {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        let hold = self.0.lock().expect("route hold is not poisoned").take();
        Box::pin(async move {
            if let Some((entered, release)) = hold {
                let _ = entered.send(());
                let _ = release.await;
            }
            Decision::Allow
        })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        Box::pin(async move { request.decide_all(Decision::Allow, |_| Decision::Allow) })
    }
}

/// Negative: a committed response reports to the observer of the generation it entered with.
///
/// Committed work receives its observer when the response is built, after the handler ran. A
/// replacement published while the request is held in route authorization must not redirect it.
#[tokio::test]
async fn a_committed_response_reports_to_the_observer_it_entered_with() {
    let events = Events::default();
    let (entered, reached) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let service = support::copy_commit_builder(support::CopyCommit::Answer)
        .observer(Record {
            generation: "old",
            events: Arc::clone(&events),
        })
        .authorizer(HeldAllow(Mutex::new(Some((entered, released)))))
        .build()
        .expect("the committed-response generation is valid");
    let inflight = service.clone();
    let request = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(3), exchange(&inflight, support::copy_commit_request())).await
    });
    tokio::time::timeout(Duration::from_secs(3), reached)
        .await
        .expect("route authorization reached")
        .expect("the route hold signalled");

    service
        .replace_assembly(
            AssemblyUpdate::new()
                .register::<rustfs_gateway::dto::CopyObject, _>(support::copy_commit_backend(support::CopyCommit::Answer))
                .authorizer(rustfs_gateway::allow_when(|_| true))
                .observer(Record {
                    generation: "new",
                    events: Arc::clone(&events),
                }),
        )
        .expect("a valid committed-response update");
    release.send(()).expect("the held request is waiting");
    let (status, _) = request
        .await
        .expect("the committed request task completed")
        .expect("the committed request completed");
    assert_eq!((status, take(&events)), (StatusCode::OK, vec![("old", "observer")]));
}

type Deferred = Box<dyn FnOnce() + Send>;

/// Publishes a replacement from inside one seam of the generation serving the request.
///
/// The hook is the pipeline's own call rather than a timer: the replacement is validated and
/// installed before the seam returns, so every later stage runs with a newer generation already in
/// the store, and only a stage reading the request's entry snapshot still sees the old one. It is
/// one-shot, which also drops the service clone it holds and so leaves no ownership cycle.
struct PublishAt {
    seam: &'static str,
    update: Arc<Mutex<Option<Deferred>>>,
}

impl PublishAt {
    fn fire(&self, seam: &'static str) {
        if seam != self.seam {
            return;
        }
        let update = self.update.lock().expect("the publication slot is not poisoned").take();
        if let Some(update) = update {
            update();
        }
    }
}

impl StageFilter for PublishAt {
    fn on_wire(&self, _head: &mut WireHead<'_>) -> Result<(), HandlerError> {
        self.fire("wire");
        Ok(())
    }

    fn on_routed(&self, _routed: &RoutedView<'_>) -> Result<(), HandlerError> {
        self.fire("routed");
        Ok(())
    }
}

/// The old generation, with a filter that publishes `update()` at `seam` during the first request.
fn publishing_at(events: &Events, seam: &'static str, update: impl FnOnce() -> AssemblyUpdate + Send + 'static) -> S3Service {
    let slot: Arc<Mutex<Option<Deferred>>> = Arc::default();
    let (builder, _handle) = old_generation(events, None, 64);
    let service = builder
        .stage_filter(PublishAt {
            seam,
            update: Arc::clone(&slot),
        })
        .build()
        .expect("the initial generation is valid");
    let publisher = service.clone();
    let published = Arc::clone(events);
    *slot.lock().expect("the publication slot is not poisoned") = Some(Box::new(move || {
        publisher
            .replace_assembly(update())
            .expect("the mid-request replacement is valid");
        published.lock().expect("event log is not poisoned").push(("replaced", seam));
    }));
    service
}

/// The old generation's full trail, with the publication recorded right after `seam`'s own mark.
fn in_flight(seam: &'static str) -> Vec<(&'static str, &'static str)> {
    let mut events = expected("old");
    let at = events
        .iter()
        .position(|&(_, stage)| stage == seam)
        .expect("the seam is part of the trail");
    events.insert(at + 1, ("replaced", seam));
    events
}

/// Negative, with a runtime counterexample for routing. A replacement published inside `on_wire`,
/// before host resolution and routing, has no `POST /` route at all. The in-flight request is still
/// routed, filtered, authorized, layered and reported by the generation it entered with; a router,
/// policy source or seam read from the store after entry would answer it with the new
/// generation's `501` or record a `new` stage.
#[tokio::test]
async fn a_replacement_published_at_the_wire_seam_cannot_reach_the_routing_of_the_request() {
    let events = Events::default();
    let replacement_events = Arc::clone(&events);
    let service = publishing_at(&events, "wire", move || replacement_serving(&replacement_events, 64, false));

    assert_eq!(ping(&service).await, (StatusCode::OK, "<Ping>pong</Ping>".to_owned()));
    assert_eq!(take(&events), in_flight("wire"));
    // The control: the replacement really is installed, and it has no route for the same request.
    assert_eq!(ping(&service).await.0, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(take(&events), [("new", "wire"), ("new", "response"), ("new", "observer")]);
    assert_eq!(body_request(&service).await, StatusCode::OK);
    assert_eq!(take(&events), expected("new"));
}

/// Negative. A replacement published inside `on_routed` lands between the routed seam and the
/// policy fetch. The policy source, both authorization stages, the audit sink, the operation layer,
/// the response seam and the observer all still belong to the generation the request entered with.
#[tokio::test]
async fn a_replacement_published_at_the_routed_seam_cannot_reach_later_stages() {
    let events = Events::default();
    let replacement_events = Arc::clone(&events);
    let service = publishing_at(&events, "routed", move || replacement(&replacement_events, 64));

    assert_eq!(ping(&service).await, (StatusCode::OK, "<Ping>pong</Ping>".to_owned()));
    assert_eq!(take(&events), in_flight("routed"));
    assert_eq!(ping(&service).await, (StatusCode::OK, "<Ping>pong</Ping>".to_owned()));
    assert_eq!(take(&events), expected("new"));
}
