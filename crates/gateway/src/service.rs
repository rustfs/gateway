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

//! The assembled service, and the one ordered walk from a request to a response.
//!
//! Responsible for: assembling [`S3Service`] and running the ordered request pipeline.
//! NOT responsible for: wire acceptance, routing, decoding, security policy, or listening.
//! Those belong to `rustfs-gateway-http`, `rustfs-gateway-core`, `rustfs-gateway-sig`, and P7-02.
//! Upstream: `crate::builder`. Downstream: `crate::adapt`, and any consumer holding a service.
//! # The order, and what each position is load-bearing for
//!
//! ```text
//!   freeze        the signing material, copied out before anything may touch the head
//!   FILTER wire   the deployment's head rewrite — before acceptance, so acceptance judges it
//!   accept        every wire-level ambiguity refused; no body byte read
//!   resolve host  what the path addresses, and which endpoint family
//!   route         which operation — decided before anything is authenticated
//!   address       the one percent-decode, the one bucket and the one key
//!   FILTER routed the deployment's chance to refuse by operation, read-only, still pre-auth
//!   govern        the deployment's chance to refuse: routed, so it has a bucket; before the body
//!   admit         the seven unconditional rules, outside every replaceable verifier
//!   authenticate  who the caller is, from a request the floor has already cleared
//!   authorize     whether that caller may do this — identity known, operation known
//!   contradict    the head-decidable contradictions, refused while the body is still outside
//!                 — two checksum claims, and the server-side-encryption family's transport
//!                   gate, key/digest agreement and channel exclusivity
//!   read body     bounded by the assembly's ceiling and by the operation's own cap
//!   decode        the request head and body into the operation's input
//!   OP LAYERS     per-operation middleware, outer to inner, inside dispatch
//!   dispatch      the backend
//!   encode        the answer
//!   FILTER resp   the deployment's response rewrite — before the invariants, never after
//!   invariants    the RFC 9110 body rules
//!   stamp         the four headers the framework guarantees, last on every path
//! ```
//!
//! # The three middleware seams, and why they sit where they do
//!
//! `docs/middleware.md` argues the whole design; the three positions above are the part that is
//! this file's. **`FILTER wire` before acceptance** so that whatever a filter writes is judged by
//! the same acceptance rules a client's own bytes are — a seam after acceptance would need a second
//! acceptance pass over rewritten input, and "the front end and the back end parsed different
//! bytes" is request smuggling. **`freeze` before it** so that no rewrite can reach the verifier:
//! the header copy this function already took for `SecurityFloor` is now also the reason a filter
//! can neither forge a signature nor break one. **`FILTER routed` after `address`** because that is
//! the earliest point at which the operation, the bucket and the key are all decided, and it is
//! read-only because they are decided — the target has one producer and a seam is not a second one.
//! **`FILTER resp` before `invariants` and `stamp`** so that the two things the framework
//! guarantees about every response survive a deployment's rewrite: a `304` cannot be given content,
//! and a response cannot lose its request identifier.
//! Three positions would be defects if moved. **Govern before the body** is the difference between
//! refusing a gibibyte upload and paying for it first. **Authorize before dispatch** is what gives
//! the authorizer the bucket and key the path actually named, rather than a second parse of the
//! path. **Read the body last** is the one that used to be wrong: the body was collected between
//! `govern` and `admit`, so a request with a bad signature and a large payload had its payload read
//! in full before the signature was looked at, and an unauthenticated caller could make this
//! service buffer whatever it liked by sending a request it was always going to be refused.
//!
//! That order is no longer a property of this function. `crate::gate::SealedBody::read` takes an
//! `&crate::gate::MetadataAdmission`, and the only constructor of one is fallible on a
//! [`rustfs_gateway_sig::Verdict`] — so the read below cannot be moved above the verifier without
//! failing to compile, which is what axiom A3 asks of an ordering contract.
//!
//! # Where the connection's security comes from
//!
//! [`rustfs_gateway_core::TransportSecurity`] is read out of the `http::Request`'s extensions, at
//! the top of [`S3Service::call`] and before anything consumes the request. Extensions are a
//! server-side channel: nothing a client can put on the wire lands in one, so whatever is there
//! was put there by the code that accepted the socket. Absent, the answer is
//! `TransportSecurity::Plaintext` — fail closed, because a deployment that has not said is a
//! deployment nobody has checked.
//!
//! `X-Forwarded-Proto` and its family are **never** consulted. They are request headers, so a
//! caller sending a customer-provided encryption key over cleartext could switch off the gate that
//! exists to refuse exactly that request. A deployment terminating TLS in front of this service
//! declares it through its transport, or acknowledges the risk through
//! [`rustfs_gateway_core::SseConfig`]; there is no third way, and
//! `tests/sse_runtime.rs` asserts the header does not become one.
//! # Why the clock is read once
//!
//! At the top, before acceptance, and never again — the reading is taken in [`S3Service::call`] and
//! passed into the pipeline, which has no way to take another. Two readings inside one request let
//! the skew check and the expiry check straddle a second boundary, so a presigned URL can be inside
//! its window when it is admitted and outside it when its lifetime is computed. The same reading is
//! what `crate::stamp` writes into the `Date` header, so the instant a caller is told about is the
//! instant its signature was judged against.
//!
//! # Why `Service::Error` is `Infallible`
//!
//! Every refusal below becomes a response. Returning `Err` from a `tower::Service` hands the layer
//! above a failure with no status, and the only thing it can do with one is drop the connection —
//! so a client that sent a malformed request would see a reset instead of the `400` that tells it
//! what to fix.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http::{Method, Request, Response};
use rustfs_gateway_core::cors::CorsPolicy;
use rustfs_gateway_core::{
    Decision, ErrorContext, HandlerError, OwnedResource, RedirectTarget, RegionLabel, RequestBodyMode, ResponseKind,
    RouteRequestParts, SseConfig, TransportSecurity,
    dispatch::{NO_ROUTE_MESSAGE, NOT_REGISTERED_MESSAGE, SERVICE_NOT_REGISTERED_MESSAGE},
};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{
    Admission, AuthError, RawQuery, RequestNow, ScopeRejection, SecurityFloor, SigService, WireView, detect_credentials,
};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::{ErrorCode, NamePolicy};

use crate::clock::{Clock, ClockPosture, MonotonicClock};
use crate::close::ConnectionIntent;
use crate::config::{ConfigSnapshot, ConfigStore};
use crate::ext::{
    AuthSchemeRef, Authenticator, BucketOwnerSource, CachedCorsSource, ClassKind, ClientAddr, ClientFacts, Governor,
    GovernorRequest, HostResolver, InputAuthzRequest, PolicySnapshot, RequestContext, RequestEvent, ResponseView, RoutedView,
};
use crate::gate::{BodyDigestObligation, MetadataAdmission, SealedBody};
use crate::logging::{Extension, Refused};
use crate::monomorphic::sealed::Set as StaticSet;
use crate::operation_mode::{DynamicMode, MonomorphicMode, OperationMode};
use crate::panic_boundary::catch_boxed_future;
use crate::post_object::{PostObjectPrelude, ResolvedPostObject};
pub use crate::posture::SecurityPosture;
use crate::render::{from_auth_context, from_codec, from_denial, from_handler, from_pre_auth};
use crate::request_config::{Entered, Guarded, HandlerDeadlineReport, HandlerDeadlineReportSlot, RequestConfig, RouteAuthorized};
use crate::request_deadline::{PolicySnapshotOutcome, elapsed_since, hold_failure_floor, policy_snapshot_with_timeout};
use crate::routed_facts::RoutedFacts;
use crate::routing::RuntimeAssembly;
use crate::trace::TraceSource;

mod authenticate;
mod authz_support;
mod body_preparation;
mod body_stage;
mod bucket_owner;
mod cors;
pub(crate) mod extension_guards;
pub(crate) mod host_tokens;
mod ingress;
mod isolation;
mod outcome;
pub(crate) mod refused_post;
mod response;
mod state;
mod update;

pub(crate) use self::cors::preflight_bucket;
pub(crate) use self::isolation::is_non_s3_service;
use self::outcome::{LegacyCorsDisposition, Outcome};

/// The one sentence a request gets when the authenticator itself could not answer.
///
/// Both signing families share this constant so credential-store failures cannot reveal the signing algorithm.
const UNAUTHENTICATED: &str = "the request could not be authenticated";

/// Everything an assembled service holds, behind one `Arc` so a clone is one refcount bump.
pub(crate) struct Inner {
    pub(crate) floor: SecurityFloor,
    pub(crate) signing_service: Option<SigService>,
    pub(crate) selection: rustfs_gateway_core::route::Selection,
    pub(crate) monomorphic: bool,
    pub(crate) limits: Limits,
    pub(crate) names: NamePolicy,
    pub(crate) config: ConfigStore,
    pub(crate) authenticator: Arc<dyn Authenticator>,
    pub(crate) replay_nonce_store: Option<Arc<dyn rustfs_gateway_sig::ReplayNonceStore + Send + Sync>>,
    pub(crate) custom_signature_verifier: Option<Arc<dyn rustfs_gateway_sig::SignatureVerifier>>,
    /// The host's query bearer verifier (ADR-0042); `None` refuses every bearer admission.
    pub(crate) bearer_token_verifier: Option<Arc<dyn rustfs_gateway_sig::BearerTokenVerifier>>,
    /// The host's header token verifier (ADR-0054); `None` refuses every header-token admission.
    pub(crate) header_token_verifier: Option<host_tokens::HeaderTokenVerify>,
    #[cfg(feature = "dangerous-replace-signature-verifier")]
    pub(crate) dangerously_replaced_signature_verifier: Option<Arc<dyn rustfs_gateway_sig::AwsSignatureVerifier>>,
    pub(crate) authz_clock: Arc<dyn MonotonicClock>,
    pub(crate) bucket_owner_source: Arc<dyn BucketOwnerSource>,
    pub(crate) host_resolver: Arc<dyn HostResolver>,
    pub(crate) governor: Arc<dyn Governor>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) clock_posture: ClockPosture,
    pub(crate) security_posture: SecurityPosture,
    pub(crate) traces: Arc<dyn TraceSource>,
    pub(crate) cors: Arc<CachedCorsSource>,
    pub(crate) cors_policy: CorsPolicy,
    /// Legacy RustFS's CORS answers, in place of the gateway's own (`crate::cors_legacy`).
    pub(crate) legacy_cors: Option<crate::LegacyRustfsCors>,
    pub(crate) sse: SseConfig,
    pub(crate) response_body_corrections: AtomicU64,
    pub(crate) temporary_redirect_targets: Arc<[RedirectTarget]>,
    /// Whether a handed-over caller secret reaches every operation, not only opted-in ones (ADR-0024).
    pub(crate) caller_secret_every_operation: bool,
    pub(crate) view_policy: crate::builder::view_policy::ViewPolicy,
    /// The posture lines logged at assembly, kept for `S3Service::startup_posture`.
    pub(crate) startup_report: Box<str>,
    /// Off in the RustFS profile: an anonymous aws-chunked body stays undecoded, as legacy RustFS leaves it.
    pub(crate) decode_anonymous_framing: bool,
    pub(crate) detached_work: crate::DetachedWork,
    pub(crate) unread_body_drain_permits: Option<Arc<tokio::sync::Semaphore>>,
}

pub(crate) use self::state::connection_security;
use self::state::{AcceptedBody, AuthorizedRoute, ReadForDecode, RequestEntryContext, RoutedBody};

/// An assembled S3 service.
///
/// Non-generic on purpose: the backend was erased at registration, so one process can hold several
/// services over different backends, and no consumer's type signature grows a parameter per
/// extension point. `Clone` costs one `Arc::clone`, which is what makes "clone it per connection"
/// the right thing for a server to do.
#[derive(Clone)]
pub struct S3Service {
    pub(crate) inner: Arc<Inner>,
}

impl S3Service {
    /// The operations this service answers, sorted. Everything else is `501`.
    pub fn operations(&self) -> impl Iterator<Item = &'static str> {
        let snapshot = self.inner.config.load();
        snapshot.runtime().routing.dispatch.names().collect::<Vec<_>>().into_iter()
    }

    /// Answers one request.
    ///
    /// The entry point both assembly paths share. It never fails: every refusal is a response, for
    /// the reason in the module documentation.
    pub async fn call<B>(&self, request: Request<B>) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let snapshot = self.inner.config.load_full();
        let runtime = snapshot.runtime();
        let mode = DynamicMode {
            dispatch: &runtime.routing.dispatch,
        };
        self.call_with_mode(request, mode, Arc::clone(&snapshot.config), runtime)
            .await
    }

    pub(crate) async fn call_monomorphic<B, H, Operations>(&self, request: Request<B>, backend: Arc<H>) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        H: Send + Sync + 'static,
        Operations: StaticSet<H>,
    {
        let snapshot = self.inner.config.load_full();
        let runtime = snapshot.runtime();
        let mode: MonomorphicMode<H, Operations> = MonomorphicMode {
            backend,
            operations: core::marker::PhantomData,
        };
        self.call_with_mode(request, mode, Arc::clone(&snapshot.config), runtime)
            .await
    }

    async fn call_with_mode<B, M>(
        &self,
        request: Request<B>,
        mode: M,
        config: ConfigSnapshot,
        runtime: &Arc<RuntimeAssembly>,
    ) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        M: OperationMode,
    {
        // Select one trace and read the clock once; external completion retains the selected trace.
        // Settings and middleware came from the same entry snapshot. No stage reloads the store.
        let request_cancellation = request.extensions().get::<tokio::sync::watch::Receiver<bool>>().cloned();
        let config = RequestConfig::enter(config).with_request_cancellation(request_cancellation);
        let handler_deadline_report = config.handler_deadline_report();
        // The host's own identifier, when it handed one over, and the identifiers this assembly's answer
        // carries on this request's path: settled once, with the minting (rustfs/backlog#1677, R10).
        let trace = self
            .inner
            .view_policy
            .identification()
            .settle(self.inner.traces.mint(), &request, &runtime.routing.router);
        let now = self.inner.clock.now();
        // Read before the request is consumed, and the only thing kept out of it: the RFC 9110 body rules are
        // stated over the request method, and every stage below has either forgotten it or never had it.
        let method = request.method().clone();
        let signing_service = runtime.routing.router.signing_service();
        let non_s3 = is_non_s3_service(signing_service);
        let connection = connection_security(request.extensions());
        let legacy_cors = (!non_s3).then(|| self.legacy_cors_request(&request)).flatten();
        let client_addr = request.extensions().get::<ClientAddr>().copied();
        let file_body_path = crate::file_fallback::FileBodyPath::of(request.extensions(), request.version());
        #[cfg(feature = "external-payload")]
        let download = request.extensions().get::<crate::external_payload::DownloadEntry>().cloned();
        let error_format = crate::render::json::ErrorFormat::for_service(signing_service);
        let mut outcome = Outcome::new(&trace, &method, self.inner.view_policy.credential_sentences(), error_format);
        let response = self
            .run(
                request,
                &mut outcome,
                config,
                RequestEntryContext {
                    now,
                    connection,
                    client_addr,
                },
                &mode,
                runtime,
            )
            .await;
        let prepare_response = async |response: Response<Body>, outcome: &mut Outcome<'_>| {
            let response = self
                .decorate_and_filter_response(response, outcome, legacy_cors.as_ref(), runtime, &method, now, non_s3)
                .await;
            self.finish_response(response, outcome, &method, &handler_deadline_report, now)
        };
        let (response, handler_deadline) = prepare_response(response, &mut outcome).await;
        #[cfg(feature = "external-payload")]
        let (response, handler_deadline) = match download {
            Some(download) if matches!(response.status(), http::StatusCode::OK | http::StatusCode::PARTIAL_CONTENT) => {
                // The consumer binds the filtered representation before transferring any bytes.
                // A later transfer refusal is a separate response with the same request snapshot.
                match download.consume(response).await {
                    Ok(response) => (response, handler_deadline),
                    Err(error) => {
                        let refusal = outcome.refuse_handler(error);
                        prepare_response(refusal, &mut outcome).await
                    }
                }
            }
            _ => (response, handler_deadline),
        };
        let mut response = response;
        let event_status = response.status().as_u16();
        let started_committed_work =
            self.start_committed_observation(&mut response, &outcome, runtime, &method, handler_deadline);
        if let Some(refused) = outcome.refused {
            crate::logging::request_refused(refused, trace.request_id(), outcome.operation, event_status, outcome.error.as_ref());
        }
        if !started_committed_work {
            let event = RequestEvent {
                request_id: trace.request_id(),
                operation: outcome.operation,
                method: &method,
                status: response.status().as_u16(),
                handler_deadline,
                identity: outcome.identity.as_ref(),
                error: outcome.error.as_ref(),
            };
            crate::ext::observe_safely(runtime.observer.as_ref(), &event);
        }
        if outcome.identity.is_none() && (outcome.refused.is_some() || outcome.error.is_some() || !response.status().is_success())
        {
            response.extensions_mut().insert(crate::unread_body::SkipUnreadBodyDrain);
        }
        file_body_path.adapt(response)
    }

    fn finish_response(
        &self,
        mut response: Response<Body>,
        outcome: &mut Outcome<'_>,
        method: &Method,
        handler_deadline_report: &HandlerDeadlineReportSlot,
        now: RequestNow,
    ) -> (Response<Body>, Option<HandlerDeadlineReport>) {
        let handler_deadline = handler_deadline_report.outcome();
        if handler_deadline == Some(HandlerDeadlineReport::Unacknowledged) {
            response.extensions_mut().insert(ConnectionIntent::Close);
        }
        // The body invariants run here on both paths; this is the only position from which
        // "a `HEAD` response has no content" covers refusals that never reached an encoder.
        if let Err(error) = crate::invariants::validate(&response, &self.inner.temporary_redirect_targets) {
            response = outcome.refuse_handler(error.into());
        }
        let corrections = crate::invariants::enforce(&mut response, method);
        if *method == Method::HEAD && outcome.error.is_some() && self.inner.view_policy.head_refusals_without_length() {
            response.headers_mut().remove(http::header::CONTENT_LENGTH);
        }
        if corrections.removed_forbidden_body() {
            self.inner.response_body_corrections.fetch_add(1, Ordering::Relaxed);
        }
        // Stamp last on both paths. A refusal already has the same identifiers; success encoders
        // and filters cannot replace this final value.
        self.keep_out_of_shared_caches(response.headers_mut(), outcome.identity.as_ref());
        crate::stamp::stamp(response.headers_mut(), outcome.trace, now);
        (response, handler_deadline)
    }

    async fn run<B, M>(
        &self,
        request: Request<B>,
        outcome: &mut Outcome<'_>,
        config: RequestConfig<Entered>,
        context: RequestEntryContext,
        mode: &M,
        runtime: &Arc<RuntimeAssembly>,
    ) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        M: OperationMode,
    {
        let router = &runtime.routing.router;
        let signing_service = router.signing_service();
        let non_s3 = is_non_s3_service(signing_service);
        let RequestEntryContext {
            now,
            connection,
            client_addr,
        } = context;
        let response_kind = outcome.response_kind;
        let ingress::PreparedWire {
            request,
            headers,
            external_bound,
            reject_external,
        } = match self.prepare_wire_head(request, signing_service, outcome, runtime) {
            Ok(prepared) => prepared,
            Err(response) => return *response,
        };
        let wire = match WireRequest::accept(request, &self.inner.limits) {
            Ok(wire) => wire,
            Err(reject) => {
                return outcome.refuse_at(Refused::Wire, self.inner.view_policy.wire_refusal(reject));
            }
        };
        if reject_external {
            return outcome.refuse_at(Refused::Wire, crate::external_marker::refusal(response_kind));
        }
        let config = config.wire();
        // The RustFS profile's cleartext customer-key gate (S3-only).
        if !non_s3
            && let Some(refusal) =
                self.inner
                    .view_policy
                    .plaintext_customer_keys
                    .refusal(&self.inner.sse, connection, &headers, response_kind)
        {
            outcome.legacy_cors_disposition = LegacyCorsDisposition::PlaintextCustomerKeyRefusal;
            return outcome.refuse_at(Refused::Wire, refusal);
        }

        // The host's one reading, and the bucket label SigV2 signs from it (S3-only).
        let (resolved, vhost_bucket) =
            match isolation::resolve_host_for_service(&*self.inner.host_resolver, &wire, signing_service, Some(outcome.trace)) {
                Ok(resolved) => resolved,
                Err(error) => return outcome.refuse_handler(error),
            };
        let config = config.targeted();
        let target_origin = resolved.origin();

        // ── CORS preflight (S3-only) ─────────────────────────────────────────────────────
        if !non_s3
            && let Some(response) = self
                .maybe_serve_preflight(
                    wire.method(),
                    wire.raw_path().as_str(),
                    wire.headers(),
                    &headers,
                    &resolved,
                    outcome,
                    now,
                    client_addr,
                )
                .await
        {
            return response;
        }
        // The RustFS profile's SigV4 header guard, where legacy RustFS asks it: before routing.
        let guard_started = self.inner.authz_clock.monotonic();
        let guard = self.inner.view_policy.sigv4_header_guard();
        let by_header_token = self.header_token_presented(&headers); // ADR-0054: the floor alone answers such a request
        let guarded = guard.refusal(&headers, wire.query().as_str(), wire.method(), &resolved, response_kind);
        if let Some(refusal) = guarded.filter(|_| !by_header_token) {
            self.hold_auth_failure_floor(guard_started).await;
            return outcome.refuse(refusal);
        }

        let resolver = &*self.inner.host_resolver;
        let resolved = match extension_guards::classify_addressing_safely(
            &self.inner.names,
            resolver,
            router,
            &wire,
            resolved,
            Some(outcome.trace),
        ) {
            Ok(Ok(resolved)) => resolved,
            Ok(Err(refusal)) => return outcome.refuse_at(Refused::Wire, from_codec(refusal, response_kind)),
            Err(error) => return outcome.refuse_handler(error),
        };
        let dispatched = match router.dispatch(&RouteRequestParts {
            method: wire.method(),
            path: wire.raw_path().as_str(),
            target: resolved.target,
            host_class: resolved.host_class,
            arn_form: resolved.arn_form,
            query: wire.query(),
            headers: wire.headers(),
            host_named_bucket: resolved.bucket().is_some(),
        }) {
            Ok(dispatched) => dispatched,
            // The one place a `VhostHint` is rendered. It replaces the message of the generic
            // "this names no operation" `501` and nothing else — same code, same status, same
            // connection verdict — because a request that failed to route on a host the deployment
            // does not serve has almost always been addressed virtual-hosted at a gateway that was
            // never told the domain. The sentence is `VhostHint::message()`, a constant: this runs
            // before authentication, so nothing derived from the request may appear in it.
            Err(error) => {
                if !by_header_token && refused_post::applies_to(router, &wire, resolved.target, &error) {
                    return refused_post::refuse(self, wire, &resolved, config.config(), outcome, now, client_addr).await;
                }
                let refusal = match resolved.diagnostic {
                    Some(hint) if error.message() == NO_ROUTE_MESSAGE => from_handler(
                        HandlerError::new(error.code().clone(), hint.message()),
                        response_kind,
                        ConnectionIntent::MayKeepAlive,
                    ),
                    _ => from_pre_auth(error, response_kind),
                };
                return outcome.refuse_at(Refused::Wire, refusal);
            }
        };
        let operation = dispatched.spec.name;
        // Service-level addressing, the operation's own secret opt-in, and a claimed row's typed
        // values, decided once from the routed row and before anything is authenticated (ADR-0024).
        // A bound bucket and a named subject are decided here too, before authentication (ADR-0025).
        let facts = match RoutedFacts::of(&dispatched, wire.raw_path().as_str(), wire.query().as_str(), &self.inner.names) {
            Ok(facts) => facts,
            Err(refusal) => return outcome.refuse_at(Refused::Decode, from_codec(refusal, response_kind)),
        };
        let (service_level, target, secret_scope) = (facts.service_level, facts.target, facts.secret);
        let (path_params, subjects, claimed, bound_bucket) =
            (facts.path_params, facts.subjects, facts.claimed, facts.bound_bucket);
        // Claimed routes sign their declared path; only ordinary S3 requests retain the host-derived bucket.
        let vhost_bucket = if claimed { None } else { vhost_bucket };
        outcome.operation = Some(operation);

        let Some(op) = mode.entry(operation) else {
            let message = if non_s3 {
                SERVICE_NOT_REGISTERED_MESSAGE
            } else {
                NOT_REGISTERED_MESSAGE
            };
            return outcome.refuse_handler(HandlerError::new(ErrorCode::NOT_IMPLEMENTED, message));
        };
        let request_body_mode = M::request_body_mode(&op);
        #[cfg(feature = "external-payload")]
        if external_bound
            && crate::external_payload::upload_entry(wire.transport_extensions())
            && !M::supports_external_payload(&op)
        {
            return outcome
                .refuse_handler(HandlerError::not_implemented("the registered handler does not support external uploads"));
        }
        let declared_length = wire.framing().declared_length();

        // The body is taken out before anything borrows the head, so the head can be read across
        // every await below while the body is owned separately.
        let mut pending = None;
        let wire = wire.map_body(|body| pending = Some(body));
        // What the transport knows of the body's length, before anything reads it.
        let transport_length = pending.as_ref().and_then(|body| http_body::Body::size_hint(body).exact());

        let meta = match self.address_meta(
            &wire,
            ingress::AddressTarget {
                operation,
                target,
                bound_bucket: bound_bucket.as_ref(),
                service_level,
            },
            &resolved,
            pending.as_ref(),
            outcome,
        ) {
            Ok(meta) => meta,
            Err(response) => return *response,
        };
        let config = config.routed();

        if let Some(response) =
            S3Service::run_routed_filters(runtime, operation, dispatched.spec, &wire, target, &meta, declared_length, outcome)
        {
            return response;
        }

        let query = RawQuery::new(wire.query().as_str());
        let head_view = WireView::new(&headers, query);
        let head_presence = detect_credentials(&head_view);
        let is_post_object = request_body_mode == RequestBodyMode::PostObject;
        // ADR-0042: only an operation whose floor declares a query bearer claim reads its token, and
        // a presented token is credential-verification work like any other credential.
        let bearer_claim = M::floor(&op).query_bearer_claim();
        let bearer_presented = bearer_claim.is_some_and(|claim| claim.presented(&head_view));
        let token_presented = bearer_presented || by_header_token;
        // Once the host's verifier is installed the token is verified on this operation's signed
        // path too, and no authorization or handler context ever holds it.
        let bearer_verified_claim = bearer_claim.filter(|_| self.inner.bearer_token_verifier.is_some());
        let class = if is_post_object || head_presence.any() || token_presented {
            ClassKind::CredentialLookup
        } else {
            ClassKind::Unauthenticated
        };

        // Routed, so there is a bucket to expose to a deployment governor; before the body and
        // credential lookup, so either framework refusal prevents the work it limits.
        let lease = match self
            .inner
            .governor
            .try_acquire(&GovernorRequest::new(operation, meta.bucket(), declared_length, client_addr, class))
            .await
        {
            Ok(lease) => lease,
            Err(()) => return outcome.refuse_for_load(),
        };
        let config = config.governed(lease);
        // POST Object's credentials live in its bounded prelude. Ordinary bodies remain sealed,
        // including a body the RustFS authenticator may bound and hash for an STS-scoped signature.
        let sealed = SealedBody::seal(pending, declared_length);
        let form_started = self.inner.authz_clock.monotonic();
        let routed_body = if is_post_object {
            let content_type = headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let prelude = match sealed
                .post_object_prelude(
                    content_type,
                    self.inner.view_policy.post_forms.read(&headers),
                    config.config().request_body_deadlines(),
                )
                .await
            {
                Ok(prelude) => prelude,
                Err(error) => {
                    let refused = Refused::reading_a_form(&error);
                    if refused == Some(Refused::Authentication) {
                        self.hold_auth_failure_floor(form_started).await;
                    }
                    return outcome.refuse_as(refused, error);
                }
            };
            RoutedBody::PostObject(Box::new(prelude))
        } else {
            RoutedBody::Ordinary(sealed)
        };
        let auth_started = self.inner.authz_clock.monotonic();
        let (form_fields, post_policy_limits) = match &routed_body {
            RoutedBody::PostObject(prelude) => (Some(prelude.form_fields()), Some(prelude.policy_limits())),
            RoutedBody::Ordinary(_) => (None, None),
        };
        let view = match form_fields.as_deref() {
            Some(fields) => head_view.with_form_fields(fields),
            None => head_view,
        };
        let signed_head = crate::builder::view_policy::header_signatures::SignedHead {
            method: wire.method(),
            headers: &headers,
            query: wire.query().as_str(),
            now,
            window: self.inner.floor.skew_window(),
        };
        let body_owed = wire.framing().has_body();
        if let Some(response) = self
            .pre_lookup_auth_refusal(
                &signed_head,
                by_header_token,
                signing_service,
                response_kind,
                body_owed,
                auth_started,
                outcome,
            )
            .await
        {
            return response;
        }
        let presence = detect_credentials(&view);
        // Presenting nothing leaves no signature to verify first: legacy RustFS's claimed-route ceiling precedes the floor.
        let claimed_ceiling = self.inner.view_policy.claimed_bodies.ceiling(claimed, signing_service);
        let aws_credential_marker = self.inner.floor.credential_marker(&view);
        let presented = presence.any()
            || aws_credential_marker.is_some()
            || self.inner.floor.custom_schemes().any_matches(&view)
            || token_presented;
        if let (false, RoutedBody::Ordinary(sealed)) = (presented, &routed_body)
            && let Some(refusal) = sealed.past_claimed_ceiling(claimed_ceiling).await
        {
            return outcome.refuse(refusal);
        }
        let (admission, prepared_sealed, replacement_verdict) = match self.inner.floor.admit(view, M::floor(&op), now) {
            Ok(Admission::Sealed(sealed)) => {
                let prepared = match self
                    .prepare_sealed_payload(
                        &sealed,
                        &signed_head,
                        operation,
                        request_body_mode,
                        response_kind,
                        body_owed,
                        auth_started,
                        outcome,
                    )
                    .await
                {
                    Ok(prepared) => prepared,
                    Err(response) => return response,
                };
                #[cfg(feature = "dangerous-replace-signature-verifier")]
                let replacement_verdict = match self
                    .inner
                    .dangerously_replaced_signature_verifier
                    .as_ref()
                    .map(|verifier| crate::panic_boundary::contain_decision(|| verifier.verify_sealed(&sealed)))
                {
                    Some(Ok(verdict)) => Some(verdict),
                    Some(Err(())) => {
                        self.hold_auth_failure_floor(auth_started).await;
                        return outcome.refuse_handler(extension_guards::replaced_verifier_panicked(outcome.trace, operation));
                    }
                    None => None,
                };
                #[cfg(not(feature = "dangerous-replace-signature-verifier"))]
                let replacement_verdict: Option<rustfs_gateway_sig::Verdict> = None;
                (Ok(Admission::Sealed(sealed)), Some(prepared), replacement_verdict)
            }
            other => (other, None, None),
        };
        let auth_stage = match self
            .complete_auth_stage(
                admission,
                authenticate::AuthStageInput {
                    auth_started,
                    operation,
                    operation_floor: M::floor(&op),
                    request_body_mode,
                    declared_length,
                    external_bound,
                    claimed,
                    bearer_claim,
                    bearer_verified_claim,
                    secret_scope,
                    vhost_bucket: vhost_bucket.as_deref(),
                    now,
                    response_kind,
                    headers: &headers,
                    wire: &wire,
                    view,
                    presence,
                    prepared_sealed,
                    replacement_verdict,
                    post_policy_limits,
                    post_filename: routed_body.post_filename(),
                    sts_body_reader: routed_body.sts_body_reader(),
                    config: config.config(),
                },
                outcome,
            )
            .await
        {
            Ok(stage) => stage,
            Err(response) => return response,
        };
        let authenticate::AuthStageOutput {
            verdict,
            caller_secret,
            chunk_sink,
            framing_mode,
            trailer_refusal,
            signed_length,
            body_digest,
            signed_bearer,
        } = auth_stage;
        let context_query: std::borrow::Cow<'_, str> = match bearer_verified_claim {
            Some(claim) => std::borrow::Cow::Owned(claim.strip_from(wire.query().as_str())),
            None => std::borrow::Cow::Borrowed(wire.query().as_str()),
        };
        // Metadata admission and credential location follow the settled verdict; a missing proof
        // is refused, and codec-facing header rewrites cannot supply or erase the original AWS fact.
        let Some(metadata_admission) = MetadataAdmission::of(&verdict) else {
            self.hold_auth_failure_floor(auth_started).await;
            return outcome
                .refuse_handler(HandlerError::internal_error("the request could not be shown to have been authenticated"));
        };
        let meta = meta.with_authenticated_aws_marker(&verdict, aws_credential_marker);
        // A presented credential is verified before the claimed-route ceiling, which precedes authorization as in legacy RustFS.
        if let RoutedBody::Ordinary(sealed) = &routed_body
            && let Some(refusal) = sealed.past_claimed_ceiling(claimed_ceiling).await
        {
            return outcome.refuse(refusal);
        }
        let accepted_body = match self.resolve_routed_body(routed_body, &meta, now) {
            Ok(body) => body,
            Err(error) => {
                let refused = Refused::reading_a_form(&error);
                if refused == Some(Refused::Authentication) {
                    self.hold_auth_failure_floor(auth_started).await;
                }
                return outcome.refuse_as(refused, error);
            }
        };
        let post_key_constraints = accepted_body.post_key_constraints(&verdict);
        // Own the form's request facts so the route and input stages borrow no body.
        let (effective_key, post_response, post_fields, post_date_offset, post_expected_owner) = match &accepted_body {
            AcceptedBody::Ordinary(_) => (meta.key().cloned(), None, None, None, None),
            AcceptedBody::PostObject(post) => (
                Some(post.key().clone()),
                Some(post.response_plan()),
                Some(post.permission_fields()),
                post.retain_until_offset_seconds(),
                post.expected_bucket_owner().map(str::to_owned),
            ),
        };
        let defer_post_success_check = M::defers_post_object_success_check(&op);
        let post_success_check = post_response
            .as_ref()
            .and_then(|plan| defer_post_success_check.then(|| plan.success_check()));
        let config = config.meta_auth();
        outcome.identity = verdict.identity().cloned();
        let Some(requirement) = M::auth(&op) else {
            // Registration requires an action. Fail closed if that invariant breaks (rustfs/rustfs#4845).
            return outcome.refuse_handler(HandlerError::internal_error("this operation declares no authorisation action"));
        };
        // A named version selects the version action unless the RustFS profile keeps the legacy one (GHSA-3ppv).
        let (requirement, named_version) = match self.resolve_version_requirement(operation, requirement, &meta) {
            Ok(resolved) => resolved,
            Err(error) => return outcome.refuse_at(Refused::Decode, from_codec(error, response_kind)),
        };
        let asked_version = named_version.as_deref();
        let extra_permissions = M::extra_permissions(&op);
        let authz_started = self.inner.authz_clock.monotonic();
        // A rejected verdict was answered above; refused here rather than reported as anonymous.
        let Some(auth_scheme) = AuthSchemeRef::of_verdict(&verdict) else {
            return outcome.refuse_handler(HandlerError::internal_error("an unsettled verdict reached authorization"));
        };
        if auth_scheme.is_authenticated() {
            let governed = GovernorRequest::new(operation, meta.bucket(), declared_length, client_addr, class);
            self.inner.governor.verified(&governed);
        }
        let request_id = outcome.trace.request_id();

        let route_service = self;
        let route_runtime = runtime;
        let route_meta = &meta;
        let route_headers = &headers;
        let route_wire = &wire;
        let route_query: &str = &context_query;
        let route_verdict = &verdict;
        let route_effective_key = effective_key.as_ref();
        let route_post_fields = post_fields.as_deref();
        let route_post_expected_owner = post_expected_owner.as_deref();
        let route_subjects = subjects.as_ref();
        let cors_slot = Mutex::new(None);
        let route_cors = &cors_slot;
        let authorize_route = move || async move {
            // ADR-0025, ADR-0026: one question per action and per account, all of them asked so the
            // audit record carries each. The first is the request itself; one question allocates
            // nothing.
            let route_questions = authz_support::RouteQuestions::build(
                operation,
                requirement,
                route_meta,
                route_effective_key,
                asked_version,
                route_verdict.identity(),
                target_origin,
                route_subjects,
            );
            let asked = route_questions.as_slice();
            let mut deciding = 0_usize;
            let policy = match policy_snapshot_with_timeout(
                route_runtime.policy_source.as_ref(),
                route_verdict.identity(),
                route_runtime.policy_timeout.get(),
            )
            .await
            {
                PolicySnapshotOutcome::Ready(Ok(policy)) => policy,
                outcome => {
                    return Err(extension_guards::handle_policy_snapshot_failure(
                        matches!(outcome, PolicySnapshotOutcome::Panicked),
                        extension_guards::PolicyLoadContext {
                            service: route_service,
                            runtime: route_runtime.as_ref(),
                            request_id,
                            operation,
                            requirement,
                            bucket: route_meta.bucket(),
                            key: route_effective_key,
                            asked,
                            auth_scheme,
                            identity: route_verdict.identity(),
                            target_origin,
                            authz_started,
                            response_kind,
                        },
                    )
                    .await);
                }
            };
            let policy = Arc::new(policy);
            let authz_context = RequestContext::from_request(
                now,
                policy.as_ref(),
                auth_scheme,
                route_verdict.verified_scope(),
                route_wire,
                route_query,
            );
            let route_started = route_service.inner.authz_clock.monotonic();
            // A subject is an account, and an anonymous caller has none: refused without asking,
            // even when a deployment delegates anonymous admission to the authorizer (ADR-0025).
            let anonymous_about_a_subject = route_subjects.is_some() && route_verdict.identity().is_none();
            let (decisions, mut route_error) = extension_guards::evaluate_route_questions(
                route_runtime.authorizer.as_ref(),
                &authz_context,
                asked,
                anonymous_about_a_subject,
                request_id,
                operation,
                response_kind,
            )
            .await?;
            let mut route_decision = if route_error.is_some() {
                Decision::Indeterminate
            } else if anonymous_about_a_subject {
                Decision::Deny
            } else {
                let combined = requirement.decide(route_subjects, &decisions);
                deciding = combined.deciding;
                combined.decision
            };
            // Each triggered, profile-required extra is all-of on top of the base decision.
            // Evaluate every route-stage authorization rule before consulting `BucketOwnerSource`
            // so a caller denied on an extra action (e.g. `s3:PutObjectTagging`) still receives
            // `403 AccessDenied` rather than learning bucket absence (`404 NoSuchBucket`).
            let route_extras = if route_decision == Decision::Allow {
                let extras = authz_support::collect_route_extras(
                    extra_permissions,
                    route_service.inner.view_policy,
                    route_post_fields,
                    route_headers,
                    &route_questions.primary,
                );
                let (extra_decision, extra_error) = extension_guards::evaluate_route_extras(
                    route_runtime.authorizer.as_ref(),
                    &authz_context,
                    &extras,
                    request_id,
                    operation,
                    response_kind,
                )
                .await?;
                if extra_error.is_some() {
                    route_error = extra_error;
                }
                if extra_decision != Decision::Allow {
                    route_decision = extra_decision;
                }
                extras
            } else {
                Vec::new()
            };
            // The raw map is asked first: it answers without allocating, and an absent owner — the
            // common case — never reaches the view's reading of an empty line.
            if !non_s3
                && route_decision == Decision::Allow
                && route_headers.contains_key("x-amz-expected-bucket-owner")
                && route_meta.has_header("x-amz-expected-bucket-owner")
            {
                let outcome = bucket_owner::check_route_owner(
                    route_service.inner.bucket_owner_source.as_ref(),
                    route_meta.bucket(),
                    route_meta.header("x-amz-expected-bucket-owner").as_deref(),
                )
                .await;
                route_decision = outcome.decision;
                if outcome.error.is_some() {
                    route_error = outcome.error;
                }
            }
            if !non_s3
                && route_decision == Decision::Allow
                && let Some(expected_owner) = route_post_expected_owner
            {
                let outcome = bucket_owner::check_route_owner(
                    route_service.inner.bucket_owner_source.as_ref(),
                    route_meta.bucket(),
                    Some(expected_owner),
                )
                .await;
                route_decision = outcome.decision;
                if outcome.error.is_some() {
                    route_error = outcome.error;
                }
            }
            let settled = route_decision.settle();
            authz_support::emit_route_audit(
                route_runtime.authz_audit.as_ref(),
                request_id,
                operation,
                requirement,
                route_meta,
                route_effective_key,
                asked,
                &route_extras,
                auth_scheme,
                route_verdict.identity(),
                target_origin,
                Some(policy.id()),
                route_decision,
                elapsed_since(route_service.inner.authz_clock.as_ref(), route_started),
            );
            if let Err(denial) = settled {
                hold_failure_floor(
                    route_service.inner.floor.failure_floor(),
                    route_service.inner.authz_clock.as_ref(),
                    authz_started,
                )
                .await;
                return Err(match route_error {
                    Some(error) => from_handler(error, response_kind, ConnectionIntent::MayKeepAlive),
                    None => from_denial(denial, response_kind, route_service.inner.view_policy.denial_sentences()),
                });
            }

            if let Some(refusal) = trailer_refusal {
                return Err(refusal);
            }
            let cors_bucket = if claimed { None } else { route_meta.bucket() };
            let cors = if non_s3 {
                None
            } else {
                route_service
                    .actual_cors(route_headers, cors_bucket, route_wire.method(), now)
                    .await
            };
            let mut stored = route_cors.lock().map_err(|_| {
                from_handler(
                    HandlerError::internal_error("the request configuration state failed"),
                    response_kind,
                    ConnectionIntent::MayKeepAlive,
                )
            })?;
            *stored = cors;
            Ok(AuthorizedRoute {
                policy,
                config: config.route_authorized(),
                deciding,
            })
        };

        let framed_meta = crate::chunked::framed_meta(
            &meta,
            framing_mode.as_ref(),
            &headers,
            wire.framing(),
            &self.inner.view_policy.chunk_reading.limits(),
        );
        let dispatch_meta = framed_meta.as_ref().unwrap_or(&meta);
        let body_service = self;
        let body_meta = &meta;
        let body_headers = &headers;
        let body_wire = &wire;
        let view_policy = self.inner.view_policy;
        let read_body = move |state: AuthorizedRoute| async move {
            let (sse, ingest) = body_stage::enforce_body_preconditions(
                signing_service,
                body_meta,
                body_headers,
                body_wire,
                operation,
                connection,
                &body_service.inner.sse,
                view_policy,
                &accepted_body,
                framing_mode.as_ref(),
                &chunk_sink,
                response_kind,
            )?;
            let body_deadlines = state.config.config().request_body_deadlines();
            let framed = ingest.is_some();
            let is_ordinary = !accepted_body.is_post();
            let (body, body_monitor) = match accepted_body {
                // Released unpolled, where it would have been read: no claim about it is judged
                // and no byte of it is held (`builder/bodyless_bodies.rs`).
                AcceptedBody::Ordinary(sealed) if view_policy.bodyless_bodies.leaves_unread(request_body_mode) => {
                    drop(sealed);
                    (rustfs_gateway_core::RequestBody::None, None)
                }
                AcceptedBody::Ordinary(sealed) => {
                    let plan = body_stage::prepare_ordinary_handoff(
                        signing_service,
                        body_meta,
                        body_wire,
                        operation,
                        request_body_mode,
                        claimed,
                        state.config.config(),
                        view_policy,
                        framed,
                        signed_length,
                        declared_length,
                        transport_length,
                    )?;
                    let body_quota = state.config.body_quota();
                    let sealed = sealed.with_object_ceiling(plan.object_ceiling);
                    sealed
                        .handoff(
                            &metadata_admission,
                            (request_body_mode, plan.ceilings, body_deadlines, body_quota),
                            ingest,
                            body_digest,
                            plan.integrity,
                        )
                        .await
                        .map_err(|refusal| {
                            view_policy
                                .buffered_ceiling
                                .refusal(request_body_mode, claimed, signing_service, refusal)
                        })?
                }
                AcceptedBody::PostObject(post) => {
                    (*post).handoff(&metadata_admission, defer_post_success_check, state.config.body_quota())?
                }
            };
            let body = body_stage::finalize_body_after_handoff(
                body,
                body_wire,
                request_body_mode,
                view_policy,
                framed,
                declared_length,
                is_ordinary,
                response_kind,
            )?;
            Ok((
                ReadForDecode {
                    policy: state.policy,
                    config: state.config.guarded(sse).with_body_monitor(body_monitor),
                    deciding: state.deciding,
                },
                body,
            ))
        };

        let input_service = self;
        let input_runtime = runtime;
        let input_meta = &meta;
        let input_headers = &headers;
        let input_verdict = &verdict;
        let input_wire = &wire;
        let input_query: &str = &context_query;
        let input_bearer = signed_bearer.as_ref();
        let addressed = resolved.addressed(meta.bucket(), effective_key.as_ref());
        let input_effective_key = effective_key.as_ref();
        let input_subjects = subjects.as_ref();
        let authorize_input = move |state: ReadForDecode, resources: Vec<OwnedResource>| async move {
            let config = state.config.decoded();
            // The question that decided the route stage: the allowed action of an any-of rule, about
            // the account it was asked about (ADR-0025, ADR-0026).
            let Some(deciding) = requirement.question(input_subjects, state.deciding) else {
                return Err(from_handler(
                    HandlerError::internal_error("the route stage decided no question"),
                    response_kind,
                    ConnectionIntent::MayKeepAlive,
                ));
            };
            let (route_request, input_resources) = authz_support::build_input_authz_requests(
                operation,
                requirement,
                deciding.action,
                deciding.subject,
                input_meta,
                input_effective_key,
                asked_version,
                input_verdict.identity(),
                target_origin,
                &resources,
            );
            let input_request = InputAuthzRequest::new(&route_request, &input_resources);
            let authz_context = RequestContext::from_request(
                now,
                state.policy.as_ref(),
                auth_scheme,
                input_verdict.verified_scope(),
                input_wire,
                input_query,
            );
            let input_started = input_service.inner.authz_clock.monotonic();
            let input_decisions =
                match catch_boxed_future(|| input_runtime.authorizer.authorize_input(&authz_context, &input_request)).await {
                    Ok(decisions) => decisions,
                    Err(()) => {
                        crate::logging::extension_panicked(Extension::Authorizer, request_id, operation);
                        return Err(from_handler(
                            HandlerError::internal_error("the authorizer failed"),
                            response_kind,
                            ConnectionIntent::MayKeepAlive,
                        ));
                    }
                };
            let decisions = input_decisions.as_slice().to_vec();
            let visibility = input_decisions.visibility();
            let mut stage = input_decisions.stage();
            let input_allowed = stage == Decision::Allow && decisions.iter().all(|decision| *decision == Decision::Allow);
            let mut input_error = None;
            if !non_s3
                && input_allowed
                && (matches!(operation, "CopyObject" | "UploadPartCopy")
                    || resources.iter().any(|resource| resource.identity().is_some()))
                && input_headers.contains_key("x-amz-source-expected-bucket-owner")
                && input_meta.has_header("x-amz-source-expected-bucket-owner")
            {
                let outcome = bucket_owner::check_source_owner(
                    input_service.inner.bucket_owner_source.as_ref(),
                    &resources,
                    input_meta.header("x-amz-source-expected-bucket-owner").as_deref(),
                )
                .await;
                if outcome.decision != Decision::Allow {
                    stage = outcome.decision;
                    input_error = outcome.error;
                }
            }
            authz_support::emit_input_audit(
                input_runtime.authz_audit.as_ref(),
                request_id,
                operation,
                requirement,
                input_meta,
                input_effective_key,
                route_request,
                &input_resources,
                &input_request,
                auth_scheme,
                input_verdict.identity(),
                target_origin,
                state.policy.id(),
                stage,
                &decisions,
                visibility,
                elapsed_since(input_service.inner.authz_clock.as_ref(), input_started),
            );
            if let Err(denial) = stage.settle() {
                hold_failure_floor(
                    input_service.inner.floor.failure_floor(),
                    input_service.inner.authz_clock.as_ref(),
                    authz_started,
                )
                .await;
                return Err(match input_error {
                    Some(error) => from_handler(error, response_kind, ConnectionIntent::MayKeepAlive),
                    None => from_denial(denial, response_kind, input_service.inner.view_policy.denial_sentences()),
                });
            }
            let config = config.with_missing_object_visibility(visibility).authorized();
            let map = |error| from_handler(error, response_kind, ConnectionIntent::MayKeepAlive);
            let sse = config.sse().cloned().map_err(map)?;
            let context = authz_support::build_handler_context(
                operation,
                input_wire,
                addressed,
                input_verdict,
                caller_secret,
                post_success_check,
                post_key_constraints,
                post_date_offset,
                path_params,
                input_subjects.cloned(),
                response_kind,
            )?;
            let context = match input_bearer {
                Some(receipt) => rustfs_gateway_core::__facade_internal::attach_signed_bearer_receipt(
                    rustfs_gateway_core::__facade_internal::FacadeSeal::new(),
                    context,
                    receipt,
                ),
                None => context,
            };
            #[cfg(feature = "external-payload")]
            crate::external_payload::record_download_context(&context);
            Ok((decisions, config, sse, context))
        };
        let execution = match std::panic::catch_unwind(AssertUnwindSafe(|| {
            mode.dispatch(op, operation, dispatch_meta, authorize_route, read_body, authorize_input)
        })) {
            Ok(execution) => execution,
            Err(_) => {
                crate::logging::extension_panicked(Extension::Handler, outcome.trace.request_id(), operation);
                return outcome.refuse_handler(HandlerError::internal_error("the handler failed"));
            }
        };
        let dispatched = match catch_boxed_future(|| execution).await {
            Ok(result) => result,
            Err(()) => {
                crate::logging::extension_panicked(Extension::Handler, outcome.trace.request_id(), operation);
                return outcome.refuse_handler(HandlerError::internal_error("the handler failed"));
            }
        };
        outcome.cors = match cors_slot.lock() {
            Ok(mut stored) => stored.take(),
            Err(_) => {
                return outcome.refuse_handler(HandlerError::internal_error("the request configuration state failed"));
            }
        };
        let dispatched = match dispatched {
            Ok(dispatched) => dispatched,
            Err(error) => return self.render_dispatch_error(error, outcome, auth_started, authz_started).await,
        };
        drop(meta);
        self.render_dispatch_outcome(
            dispatched,
            operation,
            post_response,
            connection,
            target_origin,
            bound_bucket,
            service_level,
            &resolved,
            target,
            wire,
            outcome,
        )
    }

    fn refuse_scope_rejection(
        error: AuthError,
        scope_rejection: Option<ScopeRejection>,
        response_kind: ResponseKind,
        body_owed: bool,
        outcome: &mut Outcome<'_>,
    ) -> Response<Body> {
        let context = match scope_rejection.and_then(|rejection| rejection.expected_region().cloned()) {
            Some(region) => {
                let Ok(region) = RegionLabel::new(region.as_str()) else {
                    return outcome
                        .refuse_handler(HandlerError::internal_error("the configured signing region could not be rendered"));
                };
                ErrorContext::authorization_region_mismatch(region)
            }
            None => ErrorContext::authorization_scope_malformed(),
        };
        outcome.refuse_at(Refused::Authentication, from_auth_context(error, context, response_kind, body_owed))
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
