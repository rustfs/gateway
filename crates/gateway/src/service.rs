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
//! Responsible for: [`S3Service`] — non-generic, `Clone` for the price of one `Arc` — and the
//! pipeline that runs the stages in their fixed order.
//! NOT responsible for: implementing any stage. Acceptance is `rustfs-gateway-http`'s, routing and
//! decoding are `rustfs-gateway-core`'s, the security floor is `rustfs-gateway-sig`'s, and every
//! decision this file makes is delegated to one of them. It does not listen on a socket either:
//! that is P7-02's.
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
//! `&crate::gate::Authenticated`, and the only constructor of one is fallible on a
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

use std::future::poll_fn;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use rustfs_gateway_core::cors::{
    CorsHeaders, CorsPolicy, PreflightClass, PreflightOutcome, PreflightRefusalCause, PreflightRequest, VARY, VARY_ORIGIN,
    answer_actual, answer_preflight, classify, headers_apply_to_post_auth_errors, invalid_target_is_uniform_refusal,
    preflight_bypasses_pipeline, preflight_refusal_for, preflight_uses_resolved_target,
};
use rustfs_gateway_core::{
    BoxFuture, Decision, EncodedResponse, ErrorContext, HandlerError, MetaView, OwnedResource, RegionLabel, ResourceShape,
    ResponseBody, ResponseKind, RouteRequestParts, Router, SseConfig, StaticDispatchError, StaticDispatchOutcome, TargetKind,
    TransportSecurity,
    dispatch::{NO_ROUTE_MESSAGE, NOT_REGISTERED_MESSAGE},
    resolve,
};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{
    Admission, AuthError, PayloadMode, RawQuery, RequestNow, SecurityFloor, Verdict, WireView, detect_credentials,
};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::{ErrorCode, NamePolicy};

use crate::clock::{Clock, ClockPosture, MonotonicClock, MonotonicNow};
use crate::close::ConnectionIntent;
use crate::config::ConfigStore;
use crate::dispatch::{DispatchTable, target_of};
use crate::ext::{
    AuthSchemeRef, Authentication, AuthenticationOutcome, Authenticator, Authorizer, AuthzAuditEvent, AuthzAuditSink,
    AuthzRequest, AuthzStage, CORS_PREFLIGHT, CachedCorsSource, ClassKind, ClientAddr, Governor, GovernorRequest, HostQuery,
    HostResolver, InputAuthzRequest, Observer, PolicySnapshot, PolicySource, PolicyTimeout, RequestContext, RequestEvent,
    ResolvedHost, ResponseView, RoutedView, ServerExtensions, SigV2Authentication, StageFilter, WireHead, emit_safely,
};
use crate::gate::{Authenticated, BodyCeilings, BodyDigestObligation, SealedBody};
use crate::monomorphic::sealed::Set as StaticSet;
use crate::operation_mode::{DynamicMode, MonomorphicMode, OperationMode};
use crate::payload_header::{payload_mode, presigned_body_obligation};
pub use crate::posture::SecurityPosture;
use crate::render::{
    S3Error, from_auth, from_auth_context, from_auth_with_detail, from_codec, from_denial, from_handler, from_pre_auth, from_sse,
    from_wire_reject, render,
};
use crate::request_config::{BodyRead, Entered, HandlerDeadlineReport, RequestConfig, RouteAuthorized};
use crate::request_deadline::{elapsed_since, hold_failure_floor, policy_snapshot_with_timeout};
use crate::trace::{RequestTrace, TraceSource};

/// The one sentence a request gets when the authenticator itself could not answer.
///
/// A constant because both signing families reach it and they must be indistinguishable: which
/// algorithm the credential store fell over under is not a fact a caller needs.
const UNAUTHENTICATED: &str = "the request could not be authenticated";

/// Everything an assembled service holds. Behind one `Arc`, so cloning the service is one
/// refcount bump and a connection may hold its own clone.
pub(crate) struct Inner {
    pub(crate) router: Router,
    pub(crate) dispatch: DispatchTable,
    /// The deployment's stage filters, in order; emptiness is checked before any seam does work.
    pub(crate) filters: Arc<[Arc<dyn StageFilter>]>,
    pub(crate) floor: SecurityFloor,
    pub(crate) limits: Limits,
    pub(crate) names: NamePolicy,
    pub(crate) config: ConfigStore,
    pub(crate) authorizer: Arc<dyn Authorizer>,
    pub(crate) authenticator: Arc<dyn Authenticator>,
    pub(crate) custom_signature_verifier: Option<Arc<dyn rustfs_gateway_sig::SignatureVerifier>>,
    #[cfg(feature = "dangerous-replace-signature-verifier")]
    pub(crate) dangerously_replaced_signature_verifier: Option<Arc<dyn rustfs_gateway_sig::AwsSignatureVerifier>>,
    pub(crate) policy_source: Arc<dyn PolicySource>,
    pub(crate) policy_timeout: PolicyTimeout,
    pub(crate) authz_audit: Arc<dyn AuthzAuditSink>,
    pub(crate) authz_clock: Arc<dyn MonotonicClock>,
    pub(crate) host_resolver: Arc<dyn HostResolver>,
    pub(crate) governor: Arc<dyn Governor>,
    pub(crate) observer: Arc<dyn Observer>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) clock_posture: ClockPosture,
    pub(crate) security_posture: SecurityPosture,
    pub(crate) traces: Arc<dyn TraceSource>,
    pub(crate) cors: Arc<CachedCorsSource>,
    pub(crate) cors_policy: CorsPolicy,
    pub(crate) sse: SseConfig,
    pub(crate) response_body_corrections: AtomicU64,
}

struct AuthorizedRoute {
    policy: Arc<PolicySnapshot>,
    config: RequestConfig<RouteAuthorized>,
}

struct ReadForDecode {
    policy: Arc<PolicySnapshot>,
    config: RequestConfig<BodyRead>,
}

struct RequestEntryContext {
    now: RequestNow,
    connection: TransportSecurity,
    client_addr: Option<ClientAddr>,
}

/// An assembled S3 service.
///
/// Non-generic on purpose: the backend was erased at registration, so one process can hold several
/// services over different backends, and no consumer's type signature grows a parameter per
/// extension point. `Clone` costs one `Arc::clone`, which is what makes "clone it per connection"
/// the right thing for a server to do.
#[derive(Clone)]
pub struct S3Service {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for S3Service {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("S3Service")
            .field("operations", &self.inner.dispatch.names().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl S3Service {
    pub(crate) fn from_inner(inner: Inner) -> Self {
        Self { inner: Arc::new(inner) }
    }

    /// The operations this service answers, sorted. Everything else is `501`.
    pub fn operations(&self) -> impl Iterator<Item = &'static str> {
        self.inner.dispatch.names()
    }

    /// The acceptance ceilings in force.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.inner.limits
    }

    /// Whether the service uses the system clock, a checked custom source, or an acknowledged one.
    #[must_use]
    pub fn clock_posture(&self) -> ClockPosture {
        self.inner.clock_posture
    }

    /// The credential-cache and pre-authentication per-client posture selected at assembly.
    #[must_use]
    pub fn security_posture(&self) -> SecurityPosture {
        self.inner.security_posture
    }

    /// Number of forbidden response bodies removed by this service's final invariant pass.
    #[must_use]
    pub fn response_body_corrections_total(&self) -> u64 {
        self.inner.response_body_corrections.load(Ordering::Relaxed)
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
        let mode = DynamicMode {
            dispatch: &self.inner.dispatch,
        };
        self.call_with_mode(request, mode).await
    }

    pub(crate) async fn call_monomorphic<B, H, Operations>(&self, request: Request<B>, backend: Arc<H>) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        H: Send + Sync + 'static,
        Operations: StaticSet<H>,
    {
        let mode: MonomorphicMode<H, Operations> = MonomorphicMode {
            backend,
            operations: core::marker::PhantomData,
        };
        self.call_with_mode(request, mode).await
    }

    async fn call_with_mode<B, M>(&self, request: Request<B>, mode: M) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        M: OperationMode,
    {
        // One minting and one reading of the clock, at the top, side by side. Everything below is
        // handed both values; nothing below holds either source, so neither a second identifier nor
        // a second instant can be produced — which is what lets the `Date` header and the skew
        // window name the same moment.
        // Exactly one load per request. The snapshot is passed down rather than the store, so no
        // later stage can observe a replacement made while this request is in flight.
        let config = self.inner.config.load_full();
        let request_cancellation = request.extensions().get::<tokio::sync::watch::Receiver<bool>>().cloned();
        let config = RequestConfig::enter(config).with_request_cancellation(request_cancellation);
        let handler_deadline_report = config.handler_deadline_report();
        let trace = self.inner.traces.mint();
        let now = self.inner.clock.now();
        // Read before the request is consumed, and the only thing kept out of it: the RFC 9110 body
        // rules are stated over the request method, and every stage below has either forgotten it or
        // never had it.
        let method = request.method().clone();
        // Read here for the same reason as the method: this is the last place the whole request
        // exists, and `WireRequest::accept` publishes no way back to its extensions. Absent means
        // cleartext, which is what makes the customer-key gate fail closed for a transport that
        // has not been taught to declare anything.
        let connection = connection_security(request.extensions());
        let client_addr = request.extensions().get::<ClientAddr>().copied();
        let mut outcome = Outcome::new(&trace, &method);
        let mut response = self
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
            )
            .await;
        // The CORS decoration for an ordinary request, applied here because it belongs on
        // **every** answer the pipeline produced once authorisation was granted — the `404` and
        // the `500` included. A browser cannot read a response it was not granted access to, so
        // an error without these headers reaches the page as an opaque network failure and the
        // status the operator is looking at is invisible to the client. Nothing is applied when
        // `run` never got as far as authorising: see `Outcome::cors`.
        if let Some(cors) = outcome
            .cors
            .take()
            .filter(|_| headers_apply_to_post_auth_errors() || response.status().is_success())
        {
            let headers = response.headers_mut();
            if let Some(cors_headers) = cors.headers {
                for (name, value) in cors_headers.iter() {
                    headers.insert(name, value.clone());
                }
            }
            if cors.vary_origin {
                headers.insert(VARY, VARY_ORIGIN);
            }
        }
        // The response seam. After the CORS decoration, so a filter sees the response a browser
        // would; before the invariants and the stamp, so neither can be defeated by one. It runs
        // for every response this service produces, including one refused at acceptance — which is
        // most of what a compatibility rewrite is about.
        if !self.inner.filters.is_empty() {
            let view = ResponseView {
                request_id: trace.request_id(),
                operation: outcome.operation,
                method: &method,
            };
            for filter in self.inner.filters.iter() {
                if let Err(error) = filter.on_response(&view, &mut response) {
                    response = outcome.refuse_handler(error);
                    break;
                }
            }
        }
        let handler_deadline = handler_deadline_report.outcome();
        if handler_deadline == Some(HandlerDeadlineReport::Unacknowledged) {
            response.extensions_mut().insert(ConnectionIntent::Close);
        }
        // The body invariants run here on both paths; this is the only position from which
        // "a `HEAD` response has no content" covers refusals that never reached an encoder.
        if let Err(error) = crate::invariants::validate(&response) {
            response = outcome.refuse_handler(error.into());
        }
        let corrections = crate::invariants::enforce(&mut response, &method);
        if corrections.removed_forbidden_body() {
            self.inner.response_body_corrections.fetch_add(1, Ordering::Relaxed);
        }
        // Stamp last on both paths. A refusal already has the same identifiers; success encoders
        // and filters cannot replace this final value.
        crate::stamp::stamp(response.headers_mut(), &trace, now);
        let event_request_id = *trace.request_id();
        let event_operation = outcome.operation;
        let event_status = response.status().as_u16();
        let event_identity = outcome.identity.clone();
        let committed_observer = Arc::clone(&self.inner.observer);
        let started_committed_work = crate::commit::start_pending(
            &mut response,
            Box::new(move |error| {
                committed_observer.on_response(&RequestEvent {
                    request_id: &event_request_id,
                    operation: event_operation,
                    status: event_status,
                    handler_deadline,
                    identity: event_identity.as_ref(),
                    error: error.as_ref(),
                });
            }),
        );
        if !started_committed_work {
            self.inner.observer.on_response(&RequestEvent {
                request_id: trace.request_id(),
                operation: outcome.operation,
                status: response.status().as_u16(),
                handler_deadline,
                identity: outcome.identity.as_ref(),
                error: outcome.error.as_ref(),
            });
        }
        response
    }

    /// Answers one request whose body is already in memory.
    ///
    /// The shape an in-process caller has, and the one the conformance runner uses: it builds a
    /// request from raw bytes and wants the response without a socket in between.
    pub async fn call_bytes(&self, request: Request<Bytes>) -> Response<Body> {
        let (parts, body) = request.into_parts();
        self.call(Request::from_parts(parts, http_body_util::Full::new(body))).await
    }

    async fn run<B, M>(
        &self,
        request: Request<B>,
        outcome: &mut Outcome<'_>,
        config: RequestConfig<Entered>,
        context: RequestEntryContext,
        mode: &M,
    ) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        M: OperationMode,
    {
        let RequestEntryContext {
            now,
            connection,
            client_addr,
        } = context;
        let response_kind = outcome.response_kind;
        // `WireRequest` publishes no way back to the header map — that is the boundary it exists to
        // draw — while `SecurityFloor` and the canonical request are defined over the raw map. The
        // copy is taken before acceptance and used only after it has succeeded, so what is held is
        // an accepted map. Removing the copy needs a signing accessor on `WireRequest` itself.
        //
        // It is also the whole of "a stage filter cannot touch a signature". This line runs before
        // the wire seam below, so every verifier downstream reads the head as the *caller* sent it:
        // a filter that writes an `Authorization` header does not make an anonymous request
        // authenticated, and one that deletes it does not make a signed request fail.
        let (mut parts, body) = request.into_parts();
        let headers = parts.headers.clone();

        // The wire seam, before acceptance so that whatever it writes is subject to every
        // acceptance rule — the framing conflict, the duplicate headers, the limits — exactly as a
        // client's own bytes are.
        if !self.inner.filters.is_empty() {
            let mut head = WireHead::new(&mut parts);
            for filter in self.inner.filters.iter() {
                if let Err(error) = filter.on_wire(&mut head) {
                    return outcome.refuse_handler(error);
                }
            }
        }

        let wire = match WireRequest::accept(Request::from_parts(parts, body), &self.inner.limits) {
            Ok(wire) => wire,
            Err(reject) => return outcome.refuse(from_wire_reject(reject)),
        };
        let config = config.accepted();

        let resolved = self.inner.host_resolver.resolve(&HostQuery {
            host: wire.host(),
            path: wire.raw_path().as_str(),
            method: wire.method(),
        });
        let target_origin = resolved.origin();

        // ── CORS preflight ───────────────────────────────────────────────────────────────
        // After acceptance, after host resolution, and before routing. Every part of that is
        // load-bearing.
        //
        // *After acceptance* so that a preflight is subject to the same wire-level refusals as
        // everything else — a smuggled request must not become answerable by adding an `Origin`.
        // *After host resolution* because whether the path names a bucket is the resolver's
        // answer and not this file's. *Before routing* because the route table has no `OPTIONS`
        // row and never will: a preflight is answered **instead of** an operation, from the
        // bucket's stored document, and routing it would answer a CORS question with a `501`.
        // Removing this branch is therefore visible as an `OPTIONS` reaching the route table.
        //
        // Nothing below this point runs for a preflight: no signature admission, authenticator,
        // authorizer or handler. Refusal latency is held inside this branch; requiring a signature
        // here would switch CORS off because a browser sends no credentials on a preflight.
        match classify(wire.method(), &wire.headers()) {
            PreflightClass::NotPreflight => {}
            PreflightClass::Malformed => {
                let started = self.inner.authz_clock.monotonic();
                return self
                    .refuse_preflight(outcome, PreflightRefusalCause::Malformed, started)
                    .await;
            }
            PreflightClass::Preflight(preflight) => {
                let valid_target = preflight_bucket(wire.raw_path().as_str(), &resolved).is_some();
                if preflight_bypasses_pipeline() && (invalid_target_is_uniform_refusal() || valid_target) {
                    return self
                        .serve_preflight(wire.raw_path().as_str(), resolved, &preflight, outcome, now, client_addr)
                        .await;
                }
            }
        }

        let dispatched = match self.inner.router.dispatch(&RouteRequestParts {
            method: wire.method(),
            path: wire.raw_path().as_str(),
            target: resolved.target,
            host_class: resolved.host_class,
            arn_form: resolved.arn_form,
            query: wire.query(),
            headers: wire.headers(),
        }) {
            Ok(dispatched) => dispatched,
            // The one place a `VhostHint` is rendered. It replaces the message of the generic
            // "this names no operation" `501` and nothing else — same code, same status, same
            // connection verdict — because a request that failed to route on a host the deployment
            // does not serve has almost always been addressed virtual-hosted at a gateway that was
            // never told the domain. The sentence is `VhostHint::message()`, a constant: this runs
            // before authentication, so nothing derived from the request may appear in it.
            Err(error) => {
                let refusal = match resolved.diagnostic {
                    Some(hint) if error.message() == NO_ROUTE_MESSAGE => from_handler(
                        HandlerError::new(error.code().clone(), hint.message()),
                        response_kind,
                        ConnectionIntent::MayKeepAlive,
                    ),
                    _ => from_pre_auth(error, response_kind),
                };
                return outcome.refuse(refusal);
            }
        };
        let operation = dispatched.spec.name;
        let target = target_of(dispatched.entry);
        outcome.operation = Some(operation);

        let Some(op) = mode.entry(operation) else {
            // Unreachable through `build`, which refuses an operation the router knows and this
            // crate has no codec for. Answered rather than panicked.
            return outcome.refuse_handler(HandlerError::new(ErrorCode::NOT_IMPLEMENTED, NOT_REGISTERED_MESSAGE));
        };
        let request_body_mode = M::request_body_mode(&op);
        let declared_length = wire.framing().declared_length();

        // The body is taken out before anything borrows the head, so the head can be read across
        // every await below while the body is owned separately.
        let mut pending = None;
        let wire = wire.map_body(|body| pending = Some(body));

        // Two decisions, one call. The bucket has one source — the host's, when the resolver read
        // one out of the host, and the path's otherwise — and the name it produces goes through
        // the single normalisation under the deployment's policy. Routing above read the raw path
        // and the signature below reads the raw path; everything after this line reads `meta` and
        // is never handed the path to parse again.
        let vhost_bucket = crate::ext::vhost_signing_bucket(&resolved);
        let meta = match MetaView::addressed_with(&wire, target, resolved.bucket().cloned(), &self.inner.names) {
            Ok(meta) => meta,
            Err(error) => return outcome.refuse(from_codec(error, response_kind)),
        };
        let config = config.routed();

        // The routed seam. Read-only, and this is the position that makes it so: the operation, the
        // bucket and the key are all decided by the line above, and the whole point of the single
        // normalisation is that they have one producer. A seam able to write them would be a
        // second.
        if !self.inner.filters.is_empty() {
            let view = RoutedView {
                operation,
                spec: dispatched.spec,
                method: wire.method(),
                path: wire.raw_path().as_str(),
                target,
                bucket: meta.bucket(),
                key: meta.key(),
                declared_body_bytes: declared_length,
            };
            for filter in self.inner.filters.iter() {
                if let Err(error) = filter.on_routed(&view) {
                    return outcome.refuse_handler(error);
                }
            }
        }

        let query = RawQuery::new(wire.query().as_str());
        let view = WireView::new(&headers, query);
        let presence = detect_credentials(&view);
        let class = if presence.any() {
            ClassKind::CredentialLookup
        } else {
            ClassKind::Unauthenticated
        };

        // Routed, so there is a bucket to expose to a deployment governor; before the body and
        // credential lookup, so either framework refusal prevents the work it limits.
        let lease = match self
            .inner
            .governor
            .try_acquire(&GovernorRequest::new(operation, meta.bucket(), declared_length, None, client_addr, class))
            .await
        {
            Ok(lease) => lease,
            Err(()) => return outcome.refuse_for_load(),
        };
        let config = config.governed(lease);

        // Sealed here and read at the bottom. Between the two lies every stage that can refuse
        // this request for a reason decidable from its head, and none of them can reach the bytes:
        // `SealedBody::read` needs an `Authenticated`, which does not exist yet.
        let sealed = SealedBody::seal(pending, declared_length);

        let chunk_sink = crate::ext::ChunkSink::new();
        // Kept out of the `match` so the read at the bottom can consult it: for an anonymous or
        // custom admission there is no payload mode and therefore no framed body to decode.
        let mut framing_mode: Option<PayloadMode> = None;
        let mut body_digest = BodyDigestObligation::None;
        let (authentication, signature_mismatch) = match self.inner.floor.admit(view, M::floor(&op), now) {
            Ok(Admission::Anonymous(evidence)) => (AuthenticationOutcome::ordinary(Verdict::anonymous(evidence)), None),
            Ok(Admission::Sealed(sealed)) => {
                let payload = match payload_mode(&headers, sealed.marker().location()) {
                    Ok(payload) => payload,
                    Err(error) => return outcome.refuse(error),
                };
                body_digest = match presigned_body_obligation(&payload, sealed.marker().location()) {
                    Ok(obligation) => obligation,
                    Err(_) => {
                        return outcome.refuse_handler(HandlerError::new(
                            ErrorCode::NOT_IMPLEMENTED,
                            "streaming payloads are not implemented for presigned requests",
                        ));
                    }
                };
                framing_mode = Some(payload.clone());
                #[cfg(feature = "dangerous-replace-signature-verifier")]
                let replacement_verdict = self
                    .inner
                    .dangerously_replaced_signature_verifier
                    .as_ref()
                    .map(|verifier| verifier.verify_sealed(&sealed));
                #[cfg(not(feature = "dangerous-replace-signature-verifier"))]
                let replacement_verdict: Option<Verdict> = None;
                if let Some(verdict) = replacement_verdict {
                    (AuthenticationOutcome::ordinary(verdict), None)
                } else {
                    let question = Authentication::new(
                        &sealed,
                        wire.method(),
                        wire.raw_path().as_str(),
                        wire.host().raw_for_signing(),
                        &payload,
                        declared_length,
                    )
                    // Offered before the verdict and read long after it. An `aws-chunked` body's chunk
                    // chain is verified with the same key and seed the request signature was, and
                    // neither survives `Verdict` — see `crate::ext::ChunkVerification`.
                    .with_chunk_sink(&chunk_sink);
                    let result = self.inner.authenticator.authenticate(&question).await;
                    let signature_mismatch = question.into_signature_mismatch();
                    match result {
                        Ok(authentication) => (authentication, signature_mismatch),
                        Err(_) => return outcome.refuse_handler(HandlerError::internal_error(UNAUTHENTICATED)),
                    }
                }
            }
            // No payload mode and no framed body: SigV2 has neither, so `framing_mode` stays
            // `None` and the body read at the bottom is a plain one.
            Ok(Admission::SealedSigV2(sealed)) => {
                let question =
                    SigV2Authentication::new(&sealed, wire.method(), wire.raw_path().as_str(), vhost_bucket.as_deref());
                match self.inner.authenticator.authenticate_sigv2(&question).await {
                    Ok(authentication) => (authentication, None),
                    Err(_) => return outcome.refuse_handler(HandlerError::internal_error(UNAUTHENTICATED)),
                }
            }
            Ok(Admission::Custom(request)) => match &self.inner.custom_signature_verifier {
                Some(verifier) => {
                    let verdict = verifier.verify(&request);
                    let verdict = if verdict.is_anonymous() {
                        Verdict::reject(AuthError::AuthorizationHeaderMalformed)
                    } else {
                        verdict
                    };
                    (AuthenticationOutcome::ordinary(verdict), None)
                }
                None => {
                    return outcome.refuse_handler(HandlerError::new(
                        ErrorCode::NOT_IMPLEMENTED,
                        "this deployment registered a custom authentication scheme and installed no verifier for it",
                    ));
                }
            },
            // `Admission` is `#[non_exhaustive]`: a variant added later must not be answered by a
            // wildcard that falls through to "authenticated". Refused, loudly.
            Ok(_) => {
                return outcome.refuse_handler(HandlerError::new(
                    ErrorCode::NOT_IMPLEMENTED,
                    "the security floor admitted this request in a way this assembly does not handle",
                ));
            }
            // The floor rejects malformed credential surfaces before a verifier can recover a
            // scope. Keep that fail-closed response distinct from a verifier's well-formed but
            // unserved scope, which is `400 AuthorizationHeaderMalformed`.
            Err(error) => {
                return outcome.refuse(from_auth(error, response_kind));
            }
        };
        // H4's run-time half: a receipt minted for another request cannot be attached to this one.
        let (verdict, scope_rejection) = authentication.into_parts();
        let verdict = SecurityFloor::seal_verdict(verdict, presence);
        if let Some(error) = verdict.rejection() {
            if error == AuthError::AuthorizationHeaderMalformed {
                let context = match scope_rejection.and_then(|rejection| rejection.expected_region().cloned()) {
                    Some(region) => {
                        let Ok(region) = RegionLabel::new(region.as_str()) else {
                            return outcome.refuse_handler(HandlerError::internal_error(
                                "the configured signing region could not be rendered",
                            ));
                        };
                        ErrorContext::authorization_region_mismatch(region)
                    }
                    None => ErrorContext::authorization_scope_malformed(),
                };
                return outcome.refuse(from_auth_context(error, context, response_kind));
            }
            return outcome.refuse(from_auth_with_detail(
                error,
                signature_mismatch.as_ref(),
                config.config().verbose_signature_errors(),
                response_kind,
            ));
        }
        // The proof, minted from the verdict that has just been checked. The `else` arm is
        // unreachable — `rejection()` was `None` one line ago — and is refused rather than
        // unwrapped, because "the signature was fine, take my word for it" is exactly the sentence
        // this type exists to make unspellable.
        let Some(authenticated) = Authenticated::of(&verdict) else {
            return outcome
                .refuse_handler(HandlerError::internal_error("the request could not be shown to have been authenticated"));
        };
        let config = config.authenticated();
        outcome.identity = verdict.identity().cloned();

        let Some(requirement) = M::auth(&op) else {
            // Registration refuses an operation with no authorisation action, so this is a defect
            // rather than a configuration. Refused, never permitted: rustfs/rustfs#4845 is what a
            // permissive answer here looks like in production.
            return outcome.refuse_handler(HandlerError::internal_error("this operation declares no authorisation action"));
        };
        let authz_started = self.inner.authz_clock.monotonic();
        let auth_scheme = if verdict.is_authenticated() {
            AuthSchemeRef::Authenticated
        } else {
            AuthSchemeRef::Anonymous
        };
        let request_id = outcome.trace.request_id();
        let server_extensions = ServerExtensions::new();

        let route_service = self;
        let route_meta = &meta;
        let route_headers = &headers;
        let route_wire = &wire;
        let route_verdict = &verdict;
        let route_server_extensions = &server_extensions;
        let cors_slot = Mutex::new(None);
        let route_cors = &cors_slot;
        let authorize_route = move || async move {
            let route_request = AuthzRequest {
                operation,
                action: requirement.action,
                resource: requirement.resource,
                bucket: route_meta.bucket(),
                key: route_meta.key(),
                copy_source_identity: None,
                version_id: None,
                route_action: requirement.action,
                route_bucket: route_meta.bucket(),
                route_key: route_meta.key(),
                identity: route_verdict.identity(),
                target_origin,
            };
            let policy = match policy_snapshot_with_timeout(
                route_service.inner.policy_source.as_ref(),
                route_verdict.identity(),
                route_service.inner.policy_timeout.get(),
            )
            .await
            {
                Some(Ok(policy)) => policy,
                Some(Err(_)) | None => {
                    let decision = Decision::Indeterminate;
                    emit_safely(
                        route_service.inner.authz_audit.as_ref(),
                        &AuthzAuditEvent {
                            request_id,
                            stage: AuthzStage::Route,
                            operation,
                            action: requirement.action,
                            resource: requirement.resource,
                            bucket: route_meta.bucket(),
                            key: route_meta.key(),
                            resources: std::slice::from_ref(&route_request),
                            auth_scheme,
                            identity: route_verdict.identity(),
                            target_origin,
                            policy_snapshot: None,
                            decision,
                            elapsed: elapsed_since(route_service.inner.authz_clock.as_ref(), authz_started),
                        },
                    );
                    hold_failure_floor(
                        route_service.inner.floor.failure_floor(),
                        route_service.inner.authz_clock.as_ref(),
                        authz_started,
                    )
                    .await;
                    return Err(from_denial(rustfs_gateway_core::Denied::indeterminate(), response_kind));
                }
            };
            let policy = Arc::new(policy);
            let authz_context = RequestContext::from_request(now, policy.as_ref(), auth_scheme, route_server_extensions);
            let route_started = route_service.inner.authz_clock.monotonic();
            let route_decision =
                match catch_boxed_future(|| route_service.inner.authorizer.authorize_route(&authz_context, &route_request)).await
                {
                    Ok(decision) => decision,
                    Err(()) => {
                        return Err(from_handler(
                            HandlerError::internal_error("the authorizer failed"),
                            response_kind,
                            ConnectionIntent::MayKeepAlive,
                        ));
                    }
                };
            let settled = route_decision.settle();
            emit_safely(
                route_service.inner.authz_audit.as_ref(),
                &AuthzAuditEvent {
                    request_id,
                    stage: AuthzStage::Route,
                    operation,
                    action: requirement.action,
                    resource: requirement.resource,
                    bucket: route_meta.bucket(),
                    key: route_meta.key(),
                    resources: std::slice::from_ref(&route_request),
                    auth_scheme,
                    identity: route_verdict.identity(),
                    target_origin,
                    policy_snapshot: Some(policy.id()),
                    decision: route_decision,
                    elapsed: elapsed_since(route_service.inner.authz_clock.as_ref(), route_started),
                },
            );
            if let Err(denial) = settled {
                hold_failure_floor(
                    route_service.inner.floor.failure_floor(),
                    route_service.inner.authz_clock.as_ref(),
                    authz_started,
                )
                .await;
                return Err(from_denial(denial, response_kind));
            }

            let cors = route_service
                .actual_cors(route_headers, route_meta.bucket(), route_wire.method(), now)
                .await;
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
            })
        };

        let body_service = self;
        let body_meta = &meta;
        let body_headers = &headers;
        let body_wire = &wire;
        let read_body = move |state: AuthorizedRoute| async move {
            if let Err(rejection) = rustfs_gateway_core::sse::enforce(body_meta, connection, &body_service.inner.sse) {
                return Err(from_sse(rejection, response_kind));
            }

            let ingest = match framing_mode.as_ref() {
                Some(payload) => {
                    let seed = crate::chunked::presented_signature_hex(body_headers, body_wire.query().as_str());
                    match crate::chunked::ChunkIngest::prepare(
                        payload,
                        body_headers,
                        body_wire.framing(),
                        &chunk_sink,
                        seed.as_deref(),
                        rustfs_gateway_http::ChunkLimits::default(),
                    ) {
                        Ok(ingest) => ingest,
                        Err(error) => return Err(error),
                    }
                }
                None => None,
            };

            let ceilings = BodyCeilings::for_mode(request_body_mode, operation, state.config.config().max_buffered_body_bytes());
            let body_deadlines = state.config.config().request_body_deadlines();
            let body_quota = state.config.body_quota();
            // The accepted head, not the pre-filter copy: it is the map the codec binds from.
            let integrity = crate::integrity::resolve(&body_wire.headers(), body_wire.method(), operation)?;
            let (body, body_monitor) = sealed
                .handoff(
                    &authenticated,
                    (request_body_mode, ceilings, body_deadlines, body_quota),
                    ingest,
                    body_digest,
                    integrity,
                )
                .await?;
            Ok((
                ReadForDecode {
                    policy: state.policy,
                    config: state.config.body_read().with_body_monitor(body_monitor),
                },
                body,
            ))
        };

        let input_service = self;
        let input_meta = &meta;
        let input_verdict = &verdict;
        let input_server_extensions = &server_extensions;
        let authorize_input = move |state: ReadForDecode, resources: Vec<OwnedResource>| async move {
            let config = state.config.decoded();
            let route_request = AuthzRequest {
                operation,
                action: requirement.action,
                resource: requirement.resource,
                bucket: input_meta.bucket(),
                key: input_meta.key(),
                copy_source_identity: None,
                version_id: None,
                route_action: requirement.action,
                route_bucket: input_meta.bucket(),
                route_key: input_meta.key(),
                identity: input_verdict.identity(),
                target_origin,
            };
            let mut input_resources = Vec::with_capacity(resources.len());
            for resource in &resources {
                let shape = if resource.key().is_some() {
                    ResourceShape::Object
                } else if resource.bucket().is_some() {
                    ResourceShape::Bucket
                } else {
                    ResourceShape::Service
                };
                input_resources.push(AuthzRequest {
                    operation,
                    action: resource.action(),
                    resource: shape,
                    bucket: resource.bucket().or_else(|| input_meta.bucket()),
                    key: resource.key(),
                    copy_source_identity: resource.identity(),
                    version_id: resource.version_id(),
                    route_action: requirement.action,
                    route_bucket: input_meta.bucket(),
                    route_key: input_meta.key(),
                    identity: input_verdict.identity(),
                    target_origin,
                });
            }
            let input_request = InputAuthzRequest::new(&route_request, &input_resources);
            let authz_context = RequestContext::from_request(now, state.policy.as_ref(), auth_scheme, input_server_extensions);
            let input_started = input_service.inner.authz_clock.monotonic();
            let input_decisions =
                match catch_boxed_future(|| input_service.inner.authorizer.authorize_input(&authz_context, &input_request)).await
                {
                    Ok(decisions) => decisions,
                    Err(()) => {
                        return Err(from_handler(
                            HandlerError::internal_error("the authorizer failed"),
                            response_kind,
                            ConnectionIntent::MayKeepAlive,
                        ));
                    }
                };
            let decisions = input_decisions.as_slice().to_vec();
            let stage = input_decisions.stage();
            let input_decision = if stage != Decision::Allow {
                stage
            } else {
                decisions
                    .iter()
                    .copied()
                    .find(|decision| *decision != Decision::Allow)
                    .unwrap_or(Decision::Allow)
            };
            let mut audited_resources = Vec::with_capacity(input_resources.len().saturating_add(1));
            audited_resources.push(route_request);
            audited_resources.extend(input_resources.iter().copied());
            emit_safely(
                input_service.inner.authz_audit.as_ref(),
                &AuthzAuditEvent {
                    request_id,
                    stage: AuthzStage::Input,
                    operation,
                    action: requirement.action,
                    resource: requirement.resource,
                    bucket: input_meta.bucket(),
                    key: input_meta.key(),
                    resources: &audited_resources,
                    auth_scheme,
                    identity: input_verdict.identity(),
                    target_origin,
                    policy_snapshot: Some(state.policy.id()),
                    decision: input_decision,
                    elapsed: elapsed_since(input_service.inner.authz_clock.as_ref(), input_started),
                },
            );
            if let Err(denial) = stage.settle() {
                hold_failure_floor(
                    input_service.inner.floor.failure_floor(),
                    input_service.inner.authz_clock.as_ref(),
                    authz_started,
                )
                .await;
                return Err(from_denial(denial, response_kind));
            }
            Ok((decisions, config.input_authorized()))
        };

        let execution = match std::panic::catch_unwind(AssertUnwindSafe(|| {
            mode.dispatch(op, operation, &meta, authorize_route, read_body, authorize_input)
        })) {
            Ok(execution) => execution,
            Err(_) => {
                return outcome.refuse_handler(HandlerError::internal_error("the handler failed"));
            }
        };
        let dispatched = match catch_boxed_future(|| execution).await {
            Ok(result) => result,
            Err(()) => {
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
            Err(StaticDispatchError::OperationMismatch { .. }) => {
                return outcome.refuse_handler(HandlerError::internal_error(
                    "the static operation set did not match the routed operation",
                ));
            }
            Err(StaticDispatchError::Route(error))
            | Err(StaticDispatchError::Body(error))
            | Err(StaticDispatchError::Input(error)) => return outcome.refuse(error),
            Err(StaticDispatchError::Codec(error)) => {
                return outcome.refuse(from_codec(error, response_kind));
            }
            Err(StaticDispatchError::Denied(denial)) => {
                hold_failure_floor(self.inner.floor.failure_floor(), self.inner.authz_clock.as_ref(), authz_started).await;
                return outcome.refuse(from_denial(denial, response_kind));
            }
            Err(StaticDispatchError::Handler(error)) => {
                return outcome.refuse(from_handler(error, response_kind, ConnectionIntent::MayKeepAlive));
            }
        };

        match dispatched {
            StaticDispatchOutcome::Settled(encoded) => into_response(encoded),
            StaticDispatchOutcome::Committed { status, response } => {
                let host_bucket = resolved.bucket().cloned();
                let names = self.inner.names.clone();
                let trace = *outcome.trace;
                drop(meta);
                let context = crate::commit::CommitContext::new(wire, target, host_bucket, names, response_kind, trace);
                match crate::commit::prepare_response(response, status, context) {
                    Ok(response) => response,
                    Err(error) => outcome.refuse_handler(error),
                }
            }
            StaticDispatchOutcome::EventStream { status, stream } => {
                let mut encoded = EncodedResponse::of(status);
                encoded.set_header("content-type", crate::EVENT_STREAM_CONTENT_TYPE);
                encoded.body = ResponseBody::Stream(stream);
                encoded.enforce_http_invariants(meta.method());
                into_response(encoded)
            }
        }
    }

    /// Answers one preflight, and never anything else.
    ///
    /// The order below is the mitigation, in three steps that may not be reordered:
    ///
    /// 1. **The governor, first and unconditionally**, including for a bucket name that is not a
    ///    legal one. A limit applied after the read is a limit on nothing, and skipping it for
    ///    the illegal-name case would make that case cheaper than the others — a difference an
    ///    attacker can measure.
    /// 2. **The document, through the mandatory cache.** Every negative answer — no document, no
    ///    bucket, no legal name, source failure — is the same `None` by the time it gets here.
    /// 3. **One answer or one refusal.** The refusal has a single constructor with no arguments,
    ///    so the four ways to reach it produce identical bytes.
    async fn serve_preflight(
        &self,
        path: &str,
        resolved: ResolvedHost,
        preflight: &PreflightRequest<'_>,
        outcome: &mut Outcome<'_>,
        now: RequestNow,
        client_addr: Option<ClientAddr>,
    ) -> Response<Body> {
        let started = self.inner.authz_clock.monotonic();
        let bucket = preflight_bucket(path, &resolved);
        if self
            .inner
            .governor
            .try_acquire(&GovernorRequest::new(
                CORS_PREFLIGHT,
                bucket.as_ref(),
                None,
                None,
                client_addr,
                ClassKind::CorsPreflight,
            ))
            .await
            .is_err()
        {
            return outcome.refuse_for_load();
        }
        let document = match bucket.as_ref() {
            Some(name) => self.inner.cors.get(name, now).await,
            // An illegal bucket name, or a path that names no bucket at all. Answered exactly as
            // a bucket that does not exist is, and without a read.
            None => {
                return self
                    .refuse_preflight(outcome, PreflightRefusalCause::InvalidTarget, started)
                    .await;
            }
        };
        let Some(document) = document else {
            return self
                .refuse_preflight(outcome, PreflightRefusalCause::MissingDocument, started)
                .await;
        };
        match answer_preflight(&self.inner.cors_policy, Some(document.as_ref()), preflight) {
            PreflightOutcome::Allowed(headers) => preflight_response(&headers),
            PreflightOutcome::Refused => {
                self.refuse_preflight(outcome, PreflightRefusalCause::RuleMismatch, started)
                    .await
            }
        }
    }

    async fn refuse_preflight(
        &self,
        outcome: &mut Outcome<'_>,
        cause: PreflightRefusalCause,
        started: MonotonicNow,
    ) -> Response<Body> {
        hold_failure_floor(self.inner.floor.failure_floor(), self.inner.authz_clock.as_ref(), started).await;
        outcome.refuse_preflight(cause)
    }

    /// The CORS decoration an ordinary response should carry, if any.
    ///
    /// Called once, after authorisation. `None` for a request with no usable `Origin`, for a path
    /// that names no bucket, and for a bucket with no CORS document. An origin no rule admits gets
    /// only `Vary: Origin`: the request is served and the browser withholds the answer from the
    /// page, while shared caches still keep origin-dependent answers separate.
    async fn actual_cors(
        &self,
        headers: &http::HeaderMap,
        bucket: Option<&rustfs_gateway_types::BucketName>,
        method: &http::Method,
        now: RequestNow,
    ) -> Option<CorsDecoration> {
        let view = rustfs_gateway_http::HeaderView::new(headers);
        // Exactly one line, and one this runtime would be willing to echo. Two `Origin` lines are
        // refused here as they are on a preflight, and for the same cache-poisoning reason.
        let origin = (view.count(&rustfs_gateway_core::cors::ORIGIN) == 1)
            .then(|| view.get_str(&rustfs_gateway_core::cors::ORIGIN))
            .flatten()
            .filter(|origin| rustfs_gateway_core::cors::is_plausible_origin(origin))?;
        let document = self.inner.cors.get(bucket?, now).await?;
        Some(CorsDecoration {
            headers: answer_actual(&self.inner.cors_policy, Some(&document), origin, method.as_str()),
            vary_origin: true,
        })
    }
}

async fn catch_boxed_future<'a, T, F>(build: F) -> Result<T, ()>
where
    F: FnOnce() -> BoxFuture<'a, T>,
{
    let Ok(mut future) = std::panic::catch_unwind(AssertUnwindSafe(build)) else {
        return Err(());
    };
    poll_fn(
        move |context| match std::panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(())),
        },
    )
    .await
}

/// The bucket a preflight addresses, from the host when the host named one and from the path
/// otherwise.
///
/// **The host wins, and it has to.** On a virtual-hosted request the whole path is the object key,
/// so reading the first path segment would answer a preflight for a bucket called `key.txt` —
/// present, absent or somebody else's, at the caller's choice. `OPTIONS https://b.s3.example.com/`
/// would be worse: the path names nothing, the derivation returns `None`, and every browser
/// preflight against a virtual-hosted bucket is refused while the same request path-style is
/// served. Both are the same one-line mistake, and [`ResolvedHost::bucket`] is the answer to it —
/// the resolver already read the host, and this is not a second place that decides.
///
/// The path branch is reached only when the resolver reports [`Addressing::Path`], and it agrees
/// with `MetaView`'s split by construction: the first segment, and the resolver's own
/// [`TargetKind`] deciding whether there is a segment to take.
///
/// A name the bucket grammar refuses answers `None`, which the caller turns into the same refusal
/// a non-existent bucket gets. Telling a caller that a name is *illegal* rather than *absent* is
/// two probes away from an enumeration oracle.
///
/// [`Addressing::Path`]: crate::Addressing::Path
fn preflight_bucket(path: &str, resolved: &ResolvedHost) -> Option<rustfs_gateway_types::BucketName> {
    if preflight_uses_resolved_target() {
        if let Some(bucket) = resolved.bucket() {
            return Some(bucket.clone());
        }
        if !matches!(resolved.target, TargetKind::Bucket | TargetKind::Object) {
            return None;
        }
    }
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let first = trimmed.split('/').next().unwrap_or(trimmed);
    rustfs_gateway_types::BucketName::new(first).ok()
}

/// The response an allowed preflight goes out with: `200`, the headers, and no body.
fn preflight_response(headers: &CorsHeaders) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    let map = response.headers_mut();
    for (name, value) in headers.iter() {
        map.insert(name, value.clone());
    }
    map.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
    response
}

/// What the observer is told, accumulated as the pipeline learns it.
///
/// Borrows the request's [`RequestTrace`] rather than owning a source, which is what makes the one
/// identifier per request a property of the type: every refusal below renders through
/// [`Outcome::refuse`], and `refuse` has exactly one trace it can render with.
struct CorsDecoration {
    headers: Option<CorsHeaders>,
    vary_origin: bool,
}

struct Outcome<'a> {
    trace: &'a RequestTrace,
    operation: Option<&'static str>,
    identity: Option<rustfs_gateway_sig::Identity>,
    error: Option<ErrorCode>,
    /// The CORS decoration for an ordinary response, set once authorisation has been granted and
    /// applied by [`S3Service::call`] to whatever the pipeline produced afterwards. `None` for
    /// every request that never got that far, which is what keeps a pre-authentication refusal
    /// from costing a configuration read.
    cors: Option<CorsDecoration>,
    response_kind: ResponseKind,
}

impl<'a> Outcome<'a> {
    /// An outcome that knows nothing yet, except which request it is about.
    fn new(trace: &'a RequestTrace, method: &Method) -> Self {
        Self {
            trace,
            operation: None,
            identity: None,
            error: None,
            cors: None,
            response_kind: if *method == Method::HEAD {
                ResponseKind::Head
            } else {
                ResponseKind::Other
            },
        }
    }

    /// Renders a refusal and records its code, so every early return goes through one place.
    fn refuse(&mut self, error: S3Error) -> Response<Body> {
        self.error = error.code().cloned();
        render(&error, self.trace)
    }

    fn refuse_handler(&mut self, error: HandlerError) -> Response<Body> {
        self.refuse(from_handler(error, self.response_kind, ConnectionIntent::MayKeepAlive))
    }

    /// The one refusal a preflight can receive.
    ///
    /// `preflight_refusal_for` erases the typed cause before rendering. The closed contextual
    /// resolver remains the only authority for `AccessForbidden`; the non-contextual branch makes
    /// the refusal-profile mutation observable without opening another public construction seam.
    /// `Vary: Origin` rides along because the refusal is still
    /// an answer that depends on the `Origin` header: a shared cache that stored it under the URL
    /// alone would serve it to an origin that would have been allowed.
    fn refuse_preflight(&mut self, cause: PreflightRefusalCause) -> Response<Body> {
        let refusal = preflight_refusal_for(cause);
        let error = if refusal.code() == &ErrorCode::ACCESS_FORBIDDEN {
            S3Error::from(resolve(ErrorContext::cors_forbidden(), self.response_kind))
        } else {
            from_pre_auth(refusal, self.response_kind)
        };
        self.error = error.code().cloned();
        let mut response = render(&error, self.trace);
        response.headers_mut().insert(VARY, VARY_ORIGIN);
        response
    }

    /// The one refusal a governor can cause.
    ///
    /// Takes no argument, and there is deliberately nowhere to put one. Every reason a limiter
    /// can have — the aggregate ceiling, one client, one class, a deployment's own
    /// quota — renders the same bytes, because a refusal that named its reason would answer "which
    /// of my buckets is nearly full" for anybody willing to send traffic and read the difference.
    /// Nothing here is derived from the request, and no `Retry-After` is written: the exact time
    /// the limiter recovers is the recovery rate, told to whoever asked.
    fn refuse_for_load(&mut self) -> Response<Body> {
        self.refuse_handler(HandlerError::new(
            ErrorCode::SLOW_DOWN,
            "the service is not accepting this request right now",
        ))
    }
}

/// What the transport said about this connection, or [`TransportSecurity::Plaintext`].
///
/// The **only** source. A transport that terminates TLS, or that is handed a connection by one
/// that did, inserts a `TransportSecurity` into the request's extensions:
///
/// ```
/// # use rustfs_gateway::TransportSecurity;
/// let mut request = http::Request::new(());
/// request.extensions_mut().insert(TransportSecurity::Encrypted);
/// ```
///
/// Extensions cannot be written from the wire, which is the property that makes this trustworthy
/// and `X-Forwarded-Proto` not. A deployment behind a TLS-terminating proxy that cannot be taught
/// to set the extension has one other option, and it is an explicit one:
/// `ServiceBuilder::sse_config` with
/// `rustfs_gateway_core::SseConfig::allowing_customer_keys_over_plaintext`, whose witness has to be
/// named in full.
///
/// Absent is cleartext. The alternative — assuming encryption when nobody said — is the failure
/// mode where a development deployment that was never given a transport quietly serves customer
/// keys over HTTP.
fn connection_security(extensions: &http::Extensions) -> TransportSecurity {
    extensions
        .get::<TransportSecurity>()
        .copied()
        .unwrap_or(TransportSecurity::Plaintext)
}

/// Turns an encoder's output into the response that goes on the wire.
fn into_response(encoded: EncodedResponse) -> Response<Body> {
    let body = match encoded.body {
        ResponseBody::Empty => Body::empty(),
        ResponseBody::Complete(bytes) => Body::from(bytes),
        ResponseBody::Stream(stream) => stream.into_body(),
    };
    let mut response = Response::new(body);
    *response.status_mut() = encoded.status;
    *response.headers_mut() = encoded.headers;
    response
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
