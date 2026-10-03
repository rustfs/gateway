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
use rustfs_gateway_core::cors::{
    CorsPolicy, PreflightClass, PreflightRefusalCause, VARY, VARY_ORIGIN, classify, headers_apply_to_post_auth_errors,
    invalid_target_is_uniform_refusal, preflight_bypasses_pipeline, preflight_refusal_for,
};
use rustfs_gateway_core::{
    Decision, EncodedResponse, ErrorContext, HandlerError, MetaView, OwnedResource, RedirectTarget, RegionLabel, RequestBodyMode,
    RequestContextView, ResourceShape, ResponseBody, ResponseKind, RouteRequestParts, SseConfig, StaticDispatchError,
    StaticDispatchOutcome, TransportSecurity,
    dispatch::{NO_ROUTE_MESSAGE, NOT_REGISTERED_MESSAGE},
    resolve,
};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{
    Admission, AuthError, PayloadMode, RawQuery, RequestNow, SecurityFloor, Verdict, WireView, detect_credentials,
};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::{ErrorCode, NamePolicy};

use crate::builder::credential_sentences::CredentialSentences;
use crate::clock::{Clock, ClockPosture, MonotonicClock};
use crate::close::ConnectionIntent;
use crate::config::{ConfigSnapshot, ConfigStore};
use crate::ext::{
    AuthSchemeRef, Authentication, AuthenticationOutcome, Authenticator, AuthzAuditEvent, AuthzRequest, AuthzStage,
    BucketOwnerSource, CachedCorsSource, ClassKind, ClientAddr, Governor, GovernorRequest, HostQuery, HostResolver,
    InputAuthzRequest, PolicySnapshot, RequestContext, RequestEvent, ResponseView, RoutedView, ServerExtensions,
    SigV2Authentication, WireHead, emit_safely,
};
use crate::gate::{BodyCeilings, BodyDigestObligation, MetadataAdmission, SealedBody};
use crate::logging::{Extension, Refused};
use crate::monomorphic::sealed::Set as StaticSet;
use crate::operation_mode::{DynamicMode, MonomorphicMode, OperationMode};
use crate::panic_boundary::catch_boxed_future;
use crate::payload_header::signed_payload;
use crate::post_object::{PostObjectPrelude, ResolvedPostObject};
pub use crate::posture::SecurityPosture;
use crate::render::{
    S3Error, from_auth, from_auth_context, from_auth_with_detail, from_codec, from_denial, from_handler, from_pre_auth, from_sse,
    render,
};
use crate::request_config::{Entered, Guarded, HandlerDeadlineReport, RequestConfig, RouteAuthorized};
use crate::request_deadline::{elapsed_since, hold_failure_floor, policy_snapshot_with_timeout};
use crate::routed_facts::RoutedFacts;
use crate::trace::{RequestTrace, TraceSource};
use crate::{response::into_response, routing::RuntimeAssembly};

mod cors;
mod update;

use self::cors::CorsDecoration;
pub(crate) use self::cors::preflight_bucket;

/// The one sentence a request gets when the authenticator itself could not answer.
///
/// A constant because both signing families reach it and they must be indistinguishable: which
/// algorithm the credential store fell over under is not a fact a caller needs.
const UNAUTHENTICATED: &str = "the request could not be authenticated";

/// Everything an assembled service holds, behind one `Arc` so a clone is one refcount bump.
pub(crate) struct Inner {
    pub(crate) floor: SecurityFloor,
    pub(crate) limits: Limits,
    pub(crate) names: NamePolicy,
    pub(crate) config: ConfigStore,
    pub(crate) authenticator: Arc<dyn Authenticator>,
    pub(crate) custom_signature_verifier: Option<Arc<dyn rustfs_gateway_sig::SignatureVerifier>>,
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
    /// Off in the RustFS profile: an anonymous aws-chunked body stays undecoded, as legacy RustFS leaves it.
    pub(crate) decode_anonymous_framing: bool,
    pub(crate) detached_work: crate::DetachedWork,
}

struct AuthorizedRoute {
    policy: Arc<PolicySnapshot>,
    config: RequestConfig<RouteAuthorized>,
    /// The index of the question that decided the route stage, which the input stage re-asks
    /// (ADR-0025, ADR-0026).
    deciding: usize,
}

struct ReadForDecode {
    policy: Arc<PolicySnapshot>,
    config: RequestConfig<Guarded>,
    deciding: usize,
}

struct RequestEntryContext {
    now: RequestNow,
    connection: TransportSecurity,
    client_addr: Option<ClientAddr>,
}

enum RoutedBody<B> {
    Ordinary(SealedBody<B>),
    PostObject(Box<PostObjectPrelude<B>>),
}

enum AcceptedBody<B> {
    Ordinary(SealedBody<B>),
    PostObject(Box<ResolvedPostObject<B>>),
}

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

impl core::fmt::Debug for S3Service {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let snapshot = self.inner.config.load();
        f.debug_struct("S3Service")
            .field("operations", &snapshot.runtime().routing.dispatch.names().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl S3Service {
    /// The drain this assembly runs behind an answer that left an HTTP/1 request body unread.
    pub(crate) fn unread_body_drain(&self) -> Option<crate::UnreadBodyDrain> {
        self.inner.view_policy.unread_body_drain()
    }

    pub(crate) fn from_inner(inner: Inner) -> Self {
        Self { inner: Arc::new(inner) }
    }

    /// The operations this service answers, sorted. Everything else is `501`.
    pub fn operations(&self) -> impl Iterator<Item = &'static str> {
        let snapshot = self.inner.config.load();
        snapshot.runtime().routing.dispatch.names().collect::<Vec<_>>().into_iter()
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
        // One minting and one reading of the clock, at the top, side by side. Everything below is
        // handed both values; nothing below holds either source, so neither a second identifier nor
        // a second instant can be produced — which is what lets the `Date` header and the skew
        // window name the same moment.
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
        // Read here for the same reason as the method: this is the last place the whole request exists, and
        // `WireRequest::accept` publishes no way back to its extensions. Absent means cleartext, which is what
        // makes the customer-key gate fail closed for a transport that has not been taught to declare anything.
        // The file-body path is decided here too, and applied last (rustfs/gateway#949).
        let connection = connection_security(request.extensions());
        // Legacy RustFS's CORS decoration needs the request after the pipeline has consumed it.
        let legacy_cors = self.legacy_cors_request(&request);
        let client_addr = request.extensions().get::<ClientAddr>().copied();
        let file_body_path = crate::file_fallback::FileBodyPath::of(request.extensions(), request.version());
        let mut outcome = Outcome::new(&trace, &method, self.inner.view_policy.credential_sentences());
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
                runtime,
            )
            .await;
        // The RustFS profile's `304` carries legacy RustFS's object headers (`builder/not_modified_headers.rs`).
        let status = response.status();
        self.inner
            .view_policy
            .not_modified_headers
            .apply(outcome.operation, status, response.headers_mut());
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
        // Legacy RustFS's decoration instead, on every answer, refusals before authentication
        // included (`crate::cors_legacy`).
        if let Some(legacy_cors) = legacy_cors {
            self.decorate_legacy_cors(legacy_cors, &mut response, now).await;
        }
        // The response seam. After the CORS decoration, so a filter sees the response a browser
        // would; before the invariants and the stamp, so neither can be defeated by one. It runs
        // for every response this service produces, including one refused at acceptance — which is
        // most of what a compatibility rewrite is about.
        if !runtime.filters.is_empty() {
            let view = ResponseView {
                request_id: trace.request_id(),
                operation: outcome.operation,
                method: &method,
            };
            for filter in runtime.filters.iter() {
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
        if let Err(error) = crate::invariants::validate(&response, &self.inner.temporary_redirect_targets) {
            response = outcome.refuse_handler(error.into());
        }
        let corrections = crate::invariants::enforce(&mut response, &method);
        if method == Method::HEAD && outcome.error.is_some() && self.inner.view_policy.head_refusals_without_length() {
            response.headers_mut().remove(http::header::CONTENT_LENGTH);
        }
        if corrections.removed_forbidden_body() {
            self.inner.response_body_corrections.fetch_add(1, Ordering::Relaxed);
        }
        // Stamp last on both paths. A refusal already has the same identifiers; success encoders
        // and filters cannot replace this final value.
        crate::stamp::stamp(response.headers_mut(), &trace, now);
        let event_request_id = *trace.request_id();
        let event_operation = outcome.operation;
        let event_method = method.clone();
        let event_status = response.status().as_u16();
        let event_identity = outcome.identity.clone();
        // Both reports below go to the observer this request's entry snapshot holds, and both go
        // through one panic boundary. The committed one runs before the terminal document is sent,
        // so a panic there would otherwise replace that document with the stopped-work fallback.
        let committed_observer = Arc::clone(&runtime.observer);
        let started_committed_work = self.inner.detached_work.start(
            &mut response,
            Box::new(move |error| {
                let event = RequestEvent {
                    request_id: &event_request_id,
                    operation: event_operation,
                    method: &event_method,
                    status: event_status,
                    handler_deadline,
                    identity: event_identity.as_ref(),
                    error: error.as_ref(),
                };
                crate::ext::observe_safely(committed_observer.as_ref(), &event);
            }),
        );
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
        file_body_path.adapt(response)
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
        runtime: &Arc<RuntimeAssembly>,
    ) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        M: OperationMode,
    {
        let router = &runtime.routing.router;
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
        crate::legacy_addressing::rewrite_double_slash_root(&self.inner.names, &mut parts);
        let headers = parts.headers.clone();

        // The wire seam, before acceptance so that whatever it writes is subject to every
        // acceptance rule — the framing conflict, the duplicate headers, the limits — exactly as a
        // client's own bytes are.
        if !runtime.filters.is_empty() {
            let mut head = WireHead::new(&mut parts);
            for filter in runtime.filters.iter() {
                if let Err(error) = filter.on_wire(&mut head) {
                    return outcome.refuse_handler(error);
                }
            }
        }

        let wire = match WireRequest::accept(Request::from_parts(parts, body), &self.inner.limits) {
            Ok(wire) => wire,
            Err(reject) => return outcome.refuse_at(Refused::Wire, self.inner.view_policy.wire_refusal(reject)),
        };
        let config = config.wire();

        let resolved = self.inner.host_resolver.resolve(&HostQuery {
            host: wire.host(),
            path: wire.raw_path().as_str(),
            method: wire.method(),
        });
        let config = config.targeted();
        let target_origin = resolved.origin();

        // ── CORS preflight ───────────────────────────────────────────────────────────────
        // Acceptance runs first so that CORS cannot bypass framing or header refusals.
        // Host resolution determines the bucket before classification; routing has no OPTIONS operation.
        // Entirely headerless OPTIONS returns the observed S3 BadRequest; malformed
        // preflights retain their uniform refusal and valid ones use the stored document.
        // No signature admission, authenticator, authorizer or handler runs in these
        // branches. Refusal latency uses the same security floor as other failures.
        if let Some(legacy) = self.inner.legacy_cors.as_ref()
            && *wire.method() == Method::OPTIONS
        {
            let path = wire.raw_path().as_str();
            return self
                .serve_legacy_preflight(legacy, path, &headers, outcome, now, client_addr)
                .await;
        }
        match classify(wire.method(), &wire.headers()) {
            PreflightClass::NotPreflight => {}
            PreflightClass::HeaderlessOptions => {
                let started = self.inner.authz_clock.monotonic();
                hold_failure_floor(self.inner.floor.failure_floor(), self.inner.authz_clock.as_ref(), started).await;
                let refusal = rustfs_gateway_core::error::PreAuthError::bad_request(
                    "An Origin header is required for this OPTIONS request",
                );
                return outcome.refuse_at(Refused::Wire, from_pre_auth(refusal, response_kind));
            }
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
        // The RustFS profile's SigV4 header guard, where legacy RustFS asks it: before routing.
        let guard = self.inner.view_policy.sigv4_header_guard();
        if let Some(refusal) = guard.refusal(&headers, wire.query().as_str(), wire.method(), &resolved, response_kind) {
            return outcome.refuse(refusal);
        }

        let resolver = &*self.inner.host_resolver;
        let resolved = match crate::legacy_addressing::classify(&self.inner.names, resolver, router, &wire, resolved) {
            Ok(resolved) => resolved,
            Err(refusal) => return outcome.refuse_at(Refused::Wire, from_codec(refusal, response_kind)),
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
        let (service_level, target, hands_caller_secret) = (facts.service_level, facts.target, facts.hands_caller_secret);
        let (path_params, subjects, claimed, bound_bucket) =
            (facts.path_params, facts.subjects, facts.claimed, facts.bound_bucket);
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
        // What the transport knows of the body's length, before anything reads it.
        let transport_length = pending.as_ref().and_then(|body| http_body::Body::size_hint(body).exact());

        // Two decisions, one call. The bucket has one source — the host's, when the resolver read
        // one out of the host, and the path's otherwise — and the name it produces goes through
        // the single normalisation under the deployment's policy. Routing above read the raw path
        // and the signature below reads the raw path; everything after this line reads `meta` and
        // is never handed the path to parse again.
        let vhost_bucket = crate::ext::vhost_signing_bucket(&resolved);
        // A claimed row's bound bucket, already validated as a path-style bucket is (ADR-0025),
        // takes the host's place; `vhost_key` then reads no key for a bucket target.
        let host_bucket = match &bound_bucket {
            Some(bucket) => Some(bucket.clone()),
            None if service_level => None,
            None => resolved.bucket().cloned(),
        };
        let meta = match MetaView::addressed_with(&wire, target, host_bucket, &self.inner.names) {
            Ok(meta) => self.inner.view_policy.apply(operation, meta, pending.as_ref()),
            Err(error) => return outcome.refuse_at(Refused::Decode, from_codec(error, response_kind)),
        };
        let config = config.routed();

        // The routed seam. Read-only, and this is the position that makes it so: the operation, the
        // bucket and the key are all decided by the line above, and the whole point of the single
        // normalisation is that they have one producer. A seam able to write them would be a
        // second.
        if !runtime.filters.is_empty() {
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
            for filter in runtime.filters.iter() {
                if let Err(error) = filter.on_routed(&view) {
                    return outcome.refuse_handler(error);
                }
            }
        }

        let query = RawQuery::new(wire.query().as_str());
        let head_view = WireView::new(&headers, query);
        let head_presence = detect_credentials(&head_view);
        let is_post_object = request_body_mode == RequestBodyMode::PostObject;
        let class = if is_post_object || head_presence.any() {
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

        // POST Object is the one protocol surface whose credentials live before the file inside
        // the body. Its bounded text prelude is the only pre-auth body read; the returned type has
        // no file reader, so this exception cannot consume an object byte.
        let sealed = SealedBody::seal(pending, declared_length);
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
                Err(error) => return outcome.refuse_as(Refused::reading_a_form(&error), error),
            };
            RoutedBody::PostObject(Box::new(prelude))
        } else {
            RoutedBody::Ordinary(sealed)
        };
        let form_fields = match &routed_body {
            RoutedBody::PostObject(prelude) => Some(prelude.form_fields()),
            RoutedBody::Ordinary(_) => None,
        };
        let view = match form_fields.as_deref() {
            Some(fields) => head_view.with_form_fields(fields),
            None => head_view,
        };
        let presence = detect_credentials(&view);

        // Legacy RustFS's answers to a header signature or a presigned URL it refuses before its
        // credential lookup, in its order, when the assembly answers with them (rustfs/gateway#1130).
        let signed_head = crate::builder::view_policy::header_signatures::SignedHead {
            method: wire.method(),
            headers: &headers,
            query: wire.query().as_str(),
            now,
            window: self.inner.floor.skew_window(),
        };
        let policy = &self.inner.view_policy;
        let body_owed = wire.framing().has_body();
        let legacy_refusal = policy
            .header_signatures
            .refusal(&signed_head, response_kind, body_owed)
            .or_else(|| policy.presigned_urls.refusal(&signed_head, response_kind, body_owed));
        if let Some(refusal) = legacy_refusal {
            return outcome.refuse(refusal);
        }

        let chunk_sink = crate::ext::ChunkSink::new();
        // Kept out of the `match` so the read at the bottom can consult it. A custom admission has no
        // payload mode; an anonymous one has only the unsigned streaming mode its head declares.
        let mut framing_mode: Option<PayloadMode> = None;
        let mut signed_length = crate::builder::buffered_lengths::SignedLength::default();
        let mut body_digest = BodyDigestObligation::None;
        // Legacy RustFS's words for a RustFS-profile refusal, when the authenticator published them.
        let mut legacy = None;
        let (authentication, signature_mismatch) = match self.inner.floor.admit(view, M::floor(&op), now) {
            Ok(Admission::Anonymous(evidence)) => {
                framing_mode = match crate::payload_header::anonymous_framing(&headers, self.inner.decode_anonymous_framing) {
                    Ok(mode) => mode,
                    Err(error) => return outcome.refuse_at(Refused::Decode, error),
                };
                (AuthenticationOutcome::ordinary(Verdict::anonymous(evidence)), None)
            }
            Ok(Admission::Sealed(sealed)) => {
                let location = sealed.marker().location();
                let presigned_unsigned = self.inner.view_policy.presigned_payload_unsigned();
                let (payload, obligation) = match signed_payload(&headers, location, presigned_unsigned) {
                    Ok(declared) => declared,
                    Err(refusal) => {
                        return outcome
                            .refuse_at(Refused::Authentication, refusal.render(response_kind, wire.framing().has_body()));
                    }
                };
                signed_length = crate::builder::buffered_lengths::SignedLength::of(location, &payload, obligation);
                body_digest = self.inner.view_policy.bodyless_digest.apply(request_body_mode, obligation);
                let payload = self.inner.view_policy.signed_payload_mode(payload);
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
                    let (signature_mismatch, published_legacy) = question.into_published();
                    legacy = published_legacy;
                    match result {
                        Ok(authentication) => (authentication, signature_mismatch),
                        Err(_) => {
                            return outcome
                                .refuse_handler_at(Refused::Authentication, HandlerError::internal_error(UNAUTHENTICATED));
                        }
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
                    Err(_) => {
                        return outcome.refuse_handler_at(Refused::Authentication, HandlerError::internal_error(UNAUTHENTICATED));
                    }
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
                    return outcome.refuse_handler_at(
                        Refused::Authentication,
                        HandlerError::new(
                            ErrorCode::NOT_IMPLEMENTED,
                            "this deployment registered a custom authentication scheme and installed no verifier for it",
                        ),
                    );
                }
            },
            // `Admission` is `#[non_exhaustive]`: a variant added later must not be answered by a
            // wildcard that falls through to "authenticated". Refused, loudly.
            Ok(_) => {
                return outcome.refuse_handler_at(
                    Refused::Authentication,
                    HandlerError::new(
                        ErrorCode::NOT_IMPLEMENTED,
                        "the security floor admitted this request in a way this assembly does not handle",
                    ),
                );
            }
            // The floor rejects malformed credential surfaces before a verifier can recover a scope. Keep that fail-closed
            // response distinct from a verifier's well-formed but unserved scope, which is `400 AuthorizationHeaderMalformed`.
            Err(error) => {
                return outcome.refuse_at(Refused::Authentication, from_auth(error, response_kind, wire.framing().has_body()));
            }
        };
        // H4's run-time half: a receipt minted for another request cannot be attached to this one.
        let (verdict, scope_rejection, caller_secret) = authentication.into_parts();
        // Zeroized on drop: an operation outside the assembly's secret scope never holds the key past this line (ADR-0024).
        let caller_secret = caller_secret.filter(|_| hands_caller_secret || self.inner.caller_secret_every_operation);
        let verdict = SecurityFloor::seal_verdict(verdict, presence);
        if let Some(error) = verdict.rejection() {
            // A RustFS-profile reading's refusal, in legacy RustFS's words (rustfs/gateway#1130).
            if let Some(legacy) = legacy {
                return outcome.refuse(legacy.render(&error, response_kind, wire.framing().has_body()));
            }
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
                return outcome.refuse_at(
                    Refused::Authentication,
                    from_auth_context(error, context, response_kind, wire.framing().has_body()),
                );
            }
            return outcome.refuse_at(
                Refused::Authentication,
                from_auth_with_detail(
                    error,
                    signature_mismatch.as_ref(),
                    config.config().verbose_signature_errors(),
                    response_kind,
                    wire.framing().has_body(),
                ),
            );
        }
        // The proof, minted from the verdict that has just been checked. The `else` arm is
        // unreachable — `rejection()` was `None` one line ago — and is refused rather than
        // unwrapped, because "the signature was fine, take my word for it" is exactly the sentence
        // this type exists to make unspellable.
        let Some(metadata_admission) = MetadataAdmission::of(&verdict) else {
            return outcome
                .refuse_handler(HandlerError::internal_error("the request could not be shown to have been authenticated"));
        };
        let accepted_body = match routed_body {
            RoutedBody::Ordinary(sealed) => AcceptedBody::Ordinary(sealed),
            RoutedBody::PostObject(prelude) => {
                let Some(bucket) = meta.bucket().cloned() else {
                    return outcome.refuse_handler(HandlerError::internal_error("PostObject routed without a bucket"));
                };
                let resolved = match (*prelude).resolve(bucket, &self.inner.names, now) {
                    Ok(resolved) => resolved,
                    Err(error) => return outcome.refuse_as(Refused::reading_a_form(&error), error),
                };
                AcceptedBody::PostObject(Box::new(resolved))
            }
        };
        let effective_key = match &accepted_body {
            AcceptedBody::Ordinary(_) => meta.key().cloned(),
            AcceptedBody::PostObject(post) => Some(post.key().clone()),
        };
        let post_response = match &accepted_body {
            AcceptedBody::Ordinary(_) => None,
            AcceptedBody::PostObject(post) => Some(post.response_plan()),
        };
        let config = config.meta_auth();
        outcome.identity = verdict.identity().cloned();

        let Some(requirement) = M::auth(&op) else {
            // Registration refuses an operation with no authorisation action, so this is a defect rather than a configuration.
            // Refused, never permitted: rustfs/rustfs#4845 is what a permissive answer here looks like in production.
            return outcome.refuse_handler(HandlerError::internal_error("this operation declares no authorisation action"));
        };
        let authz_started = self.inner.authz_clock.monotonic();
        let auth_scheme = if verdict.is_authenticated() {
            let governed = GovernorRequest::new(operation, meta.bucket(), declared_length, client_addr, class);
            self.inner.governor.verified(&governed);
            AuthSchemeRef::Authenticated
        } else {
            AuthSchemeRef::Anonymous
        };
        let request_id = outcome.trace.request_id();
        let server_extensions = &ServerExtensions::new();

        let route_service = self;
        let route_runtime = runtime;
        let route_meta = &meta;
        let route_headers = &headers;
        let route_wire = &wire;
        let route_verdict = &verdict;
        let route_effective_key = effective_key.as_ref();
        let route_subjects = subjects.as_ref();
        let cors_slot = Mutex::new(None);
        let route_cors = &cors_slot;
        let authorize_route = move || async move {
            // ADR-0025, ADR-0026: one question per action and per account, all of them asked so the
            // audit record carries each. The first is the request itself; one question allocates
            // nothing.
            let first = requirement.question(route_subjects, 0);
            let first_action = first.map_or(requirement.action, |question| question.action);
            let route_request = AuthzRequest {
                operation,
                action: first_action,
                resource: requirement.resource,
                bucket: route_meta.bucket(),
                key: route_effective_key,
                copy_source_identity: None,
                version_id: None,
                route_action: first_action,
                route_bucket: route_meta.bucket(),
                route_key: route_effective_key,
                identity: route_verdict.identity(),
                target_origin,
                subject: first.and_then(|question| question.subject),
            };
            let question_count = requirement.question_count(route_subjects);
            let questions: Vec<AuthzRequest<'_>> = if question_count > 1 {
                (0..question_count)
                    .filter_map(|index| requirement.question(route_subjects, index))
                    .map(|question| AuthzRequest {
                        action: question.action,
                        route_action: question.action,
                        subject: question.subject,
                        ..route_request
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let asked = if questions.is_empty() {
                std::slice::from_ref(&route_request)
            } else {
                questions.as_slice()
            };
            let mut deciding = 0_usize;
            let policy = match policy_snapshot_with_timeout(
                route_runtime.policy_source.as_ref(),
                route_verdict.identity(),
                route_runtime.policy_timeout.get(),
            )
            .await
            {
                Some(Ok(policy)) => policy,
                Some(Err(_)) | None => {
                    let decision = Decision::Indeterminate;
                    emit_safely(
                        route_runtime.authz_audit.as_ref(),
                        &AuthzAuditEvent {
                            request_id,
                            stage: AuthzStage::Route,
                            operation,
                            action: requirement.action,
                            resource: requirement.resource,
                            bucket: route_meta.bucket(),
                            key: route_effective_key,
                            resources: asked,
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
            let authz_context = RequestContext::from_request(
                now,
                policy.as_ref(),
                auth_scheme,
                route_verdict.verified_scope(),
                server_extensions,
                route_wire.headers(),
            );
            let route_started = route_service.inner.authz_clock.monotonic();
            let mut decisions = Vec::with_capacity(if questions.is_empty() { 0 } else { asked.len() });
            // A subject is an account, and an anonymous caller has none: refused without asking,
            // even when a deployment delegates anonymous admission to the authorizer (ADR-0025).
            let anonymous_about_a_subject = route_subjects.is_some() && route_verdict.identity().is_none();
            for question in asked {
                if anonymous_about_a_subject {
                    break;
                }
                match catch_boxed_future(|| route_runtime.authorizer.authorize_route(&authz_context, question)).await {
                    Ok(decision) => decisions.push(decision),
                    Err(()) => {
                        crate::logging::extension_panicked(Extension::Authorizer, request_id, operation);
                        return Err(from_handler(
                            HandlerError::internal_error("the authorizer failed"),
                            response_kind,
                            ConnectionIntent::MayKeepAlive,
                        ));
                    }
                }
            }
            let mut route_decision = if anonymous_about_a_subject {
                Decision::Deny
            } else {
                let combined = requirement.decide(route_subjects, &decisions);
                deciding = combined.deciding;
                combined.decision
            };
            // The raw map is asked first: it answers without allocating, and an absent owner — the
            // common case — never reaches the view's reading of an empty line.
            if route_decision == Decision::Allow
                && route_headers.contains_key("x-amz-expected-bucket-owner")
                && route_meta.has_header("x-amz-expected-bucket-owner")
            {
                route_decision = match (route_meta.header("x-amz-expected-bucket-owner"), route_meta.bucket()) {
                    (Some(expected_owner), Some(bucket)) => {
                        match catch_boxed_future(|| route_service.inner.bucket_owner_source.owner(bucket)).await {
                            Ok(Ok(actual_owner)) if actual_owner.as_ref() == expected_owner.as_ref() => Decision::Allow,
                            Ok(Ok(_)) => Decision::Deny,
                            Ok(Err(_)) | Err(()) => Decision::Indeterminate,
                        }
                    }
                    (None, _) | (_, None) => Decision::Indeterminate,
                };
            }
            let settled = route_decision.settle();
            emit_safely(
                route_runtime.authz_audit.as_ref(),
                &AuthzAuditEvent {
                    request_id,
                    stage: AuthzStage::Route,
                    operation,
                    action: requirement.action,
                    resource: requirement.resource,
                    bucket: route_meta.bucket(),
                    key: route_effective_key,
                    resources: asked,
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

            // A claimed row's path is not a bucket surface: a bound bucket's CORS rules do not
            // answer an admin request (ADR-0025).
            let cors_bucket = if claimed { None } else { route_meta.bucket() };
            let cors = route_service
                .actual_cors(route_headers, cors_bucket, route_wire.method(), now)
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
                deciding,
            })
        };

        let framed_meta = crate::chunked::framed_meta(&meta, framing_mode.as_ref(), &headers, wire.framing());
        let dispatch_meta = framed_meta.as_ref().unwrap_or(&meta);
        let body_service = self;
        let body_meta = &meta;
        let body_headers = &headers;
        let body_wire = &wire;
        let view_policy = self.inner.view_policy;
        let read_body = move |state: AuthorizedRoute| async move {
            let sse = rustfs_gateway_core::sse::enforce(body_meta, connection, &body_service.inner.sse)
                .map_err(|rejection| from_sse(rejection, response_kind))?;
            if let Some(refusal) = view_policy.refusal_before_decode(operation, &body_wire.headers()) {
                return Err(from_handler(refusal, response_kind, ConnectionIntent::MayKeepAlive));
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

            let body_deadlines = state.config.config().request_body_deadlines();
            let (body, body_monitor) = match accepted_body {
                // Released unpolled, where it would have been read: no claim about it is judged
                // and no byte of it is held (`builder/bodyless_bodies.rs`).
                AcceptedBody::Ordinary(sealed) if view_policy.bodyless_bodies.leaves_unread(request_body_mode) => {
                    drop(sealed);
                    (rustfs_gateway_core::RequestBody::None, None)
                }
                AcceptedBody::Ordinary(sealed) => {
                    let ceilings =
                        BodyCeilings::for_mode(request_body_mode, operation, state.config.config().max_buffered_body_bytes());
                    let body_quota = state.config.body_quota();
                    // The accepted head, not the pre-filter copy: it is the map the codec binds from.
                    let integrity = crate::integrity::resolve_in(body_meta, &body_wire.headers(), body_wire.method(), operation)?;
                    let object_ceiling = crate::gate::object_ceiling_for(request_body_mode, operation, state.config.config());
                    let sealed = sealed.with_object_ceiling(object_ceiling);
                    let (framed, lengths) = (ingest.is_some(), view_policy.buffered_lengths);
                    if let Some(refusal) =
                        lengths.before_read(request_body_mode, framed, signed_length, declared_length, transport_length)
                    {
                        return Err(refusal);
                    }
                    let handed = sealed
                        .handoff(
                            &metadata_admission,
                            (request_body_mode, ceilings, body_deadlines, body_quota),
                            ingest,
                            body_digest,
                            integrity,
                        )
                        .await?;
                    if let (rustfs_gateway_core::RequestBody::Buffered(bytes), _) = &handed
                        && let Some(refusal) = lengths.after_read(request_body_mode, framed, declared_length, bytes)
                    {
                        return Err(refusal);
                    }
                    handed
                }
                AcceptedBody::PostObject(post) => (*post).handoff(&metadata_admission)?,
            };
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
        let input_verdict = &verdict;
        let input_wire = &wire;
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
            let input_subject = deciding.subject;
            let route_request = AuthzRequest {
                operation,
                action: deciding.action,
                resource: requirement.resource,
                bucket: input_meta.bucket(),
                key: input_effective_key,
                copy_source_identity: None,
                version_id: None,
                route_action: deciding.action,
                route_bucket: input_meta.bucket(),
                route_key: input_effective_key,
                identity: input_verdict.identity(),
                target_origin,
                subject: input_subject,
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
                    route_action: deciding.action,
                    route_bucket: input_meta.bucket(),
                    route_key: input_effective_key,
                    identity: input_verdict.identity(),
                    target_origin,
                    subject: input_subject,
                });
            }
            let input_request = InputAuthzRequest::new(&route_request, &input_resources);
            let authz_context = RequestContext::from_request(
                now,
                state.policy.as_ref(),
                auth_scheme,
                input_verdict.verified_scope(),
                server_extensions,
                input_wire.headers(),
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
            crate::ext::emit_input_safely(
                input_runtime.authz_audit.as_ref(),
                &AuthzAuditEvent {
                    request_id,
                    stage: AuthzStage::Input,
                    operation,
                    action: requirement.action,
                    resource: requirement.resource,
                    bucket: input_meta.bucket(),
                    key: input_effective_key,
                    resources: &audited_resources,
                    auth_scheme,
                    identity: input_verdict.identity(),
                    target_origin,
                    policy_snapshot: Some(state.policy.id()),
                    decision: input_decision,
                    elapsed: elapsed_since(input_service.inner.authz_clock.as_ref(), input_started),
                },
                input_request.visibility().zip(visibility),
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
            let config = config.with_missing_object_visibility(visibility).authorized();
            let map = |error| from_handler(error, response_kind, ConnectionIntent::MayKeepAlive);
            let sse = config.sse().cloned().map_err(map)?;
            let context = RequestContextView::from_pipeline(operation, input_wire, addressed, input_verdict, caller_secret)
                .map(|context| context.with_path_params(path_params).with_subjects(input_subjects.cloned()));
            let context = context.ok_or_else(|| map(HandlerError::internal_error("a rejected request reached its handler")))?;
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
            Err(StaticDispatchError::OperationMismatch { .. }) => {
                return outcome.refuse_handler(HandlerError::internal_error(
                    "the static operation set did not match the routed operation",
                ));
            }
            Err(StaticDispatchError::Route(error)) | Err(StaticDispatchError::Input(error)) => return outcome.refuse(error),
            Err(StaticDispatchError::Body(error)) => {
                let refused = Refused::reading_the_body(&error);
                return outcome.refuse_as(refused, self.inner.view_policy.body_refusal(error));
            }
            Err(StaticDispatchError::Codec(error)) => {
                let refusal = from_codec(error, response_kind);
                return outcome.refuse_as(Refused::reading_the_input(&refusal), refusal);
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
            StaticDispatchOutcome::Settled(mut encoded) => {
                if let Some(response) = post_response
                    && let Err(error) = response.apply(&mut encoded, connection, wire.host().as_str(), target_origin)
                {
                    return outcome.refuse_handler(error);
                }
                self.inner.view_policy.settle(operation, &mut encoded);
                into_response(encoded)
            }
            StaticDispatchOutcome::Committed { status, response } => {
                let host_bucket = match bound_bucket {
                    Some(bucket) => Some(bucket),
                    None if service_level => None,
                    None => resolved.bucket().cloned(),
                };
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
}

/// What the observer is told, accumulated as the pipeline learns it.
///
/// Borrows the request's [`RequestTrace`] rather than owning a source, which is what makes the one
/// identifier per request a property of the type: every refusal below renders through
/// [`Outcome::refuse`], and `refuse` has exactly one trace it can render with.
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
    credential_sentences: CredentialSentences,
    /// The stage that refused the request, when the gateway refused it; reported once, at the end
    /// (`crate::logging::request_refused`).
    refused: Option<Refused>,
}

impl<'a> Outcome<'a> {
    /// An outcome that knows nothing yet, except which request it is about.
    fn new(trace: &'a RequestTrace, method: &Method, credential_sentences: CredentialSentences) -> Self {
        Self {
            trace,
            operation: None,
            identity: None,
            error: None,
            cors: None,
            credential_sentences,
            refused: None,
            response_kind: if *method == Method::HEAD {
                ResponseKind::Head
            } else {
                ResponseKind::Other
            },
        }
    }

    /// Renders a refusal and records its code, so every early return goes through one place.
    fn refuse(&mut self, error: S3Error) -> Response<Body> {
        let error = self.credential_sentences.restyle(error);
        self.error = error.code().cloned();
        render(&error, self.trace)
    }

    fn refuse_handler(&mut self, error: HandlerError) -> Response<Body> {
        self.refuse(from_handler(error, self.response_kind, ConnectionIntent::MayKeepAlive))
    }

    /// [`Outcome::refuse`], remembering which stage refused, for the request's refusal event.
    fn refuse_at(&mut self, refused: Refused, error: S3Error) -> Response<Body> {
        self.refuse_as(Some(refused), error)
    }

    /// [`Outcome::refuse_at`] for a refusal whose stage is read off the refusal itself, and which
    /// may be no refusal of the gateway's at all (`None`).
    fn refuse_as(&mut self, refused: Option<Refused>, error: S3Error) -> Response<Body> {
        self.refused = refused;
        self.refuse(error)
    }

    /// [`Outcome::refuse_handler`], remembering which stage refused.
    fn refuse_handler_at(&mut self, refused: Refused, error: HandlerError) -> Response<Body> {
        self.refused = Some(refused);
        self.refuse_handler(error)
    }

    /// The one refusal a preflight can receive.
    ///
    /// `preflight_refusal_for` erases the typed cause before rendering. The closed contextual
    /// resolver remains the only authority for `AccessForbidden`; the non-contextual branch makes
    /// the refusal-profile mutation observable without opening another public construction seam.
    /// `Vary: Origin` rides along because the refusal is still
    /// an answer that depends on the `Origin` header: a shared cache that stored it under the URL
    /// alone would serve it to an origin that would have been allowed.
    ///
    /// A malformed preflight is a head the gateway could not read, and is reported as one; a
    /// preflight the bucket's CORS configuration does not allow is that configuration's answer.
    fn refuse_preflight(&mut self, cause: PreflightRefusalCause) -> Response<Body> {
        if cause == PreflightRefusalCause::Malformed {
            self.refused = Some(Refused::Wire);
        }
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
        self.refuse_handler_at(
            Refused::Governor,
            HandlerError::new(ErrorCode::SLOW_DOWN, "the service is not accepting this request right now"),
        )
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

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
