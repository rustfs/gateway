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
//!
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
//!
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
//!
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

use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use rustfs_gateway_core::cors::{
    CorsHeaders, CorsPolicy, PreflightClass, PreflightOutcome, PreflightRequest, VARY, VARY_ORIGIN, answer_actual,
    answer_preflight, classify, preflight_refusal,
};
use rustfs_gateway_core::{
    Decision, EncodedResponse, MetaView, ResourceShape, ResponseBody, RouteRequestParts, Router, SseConfig, TargetKind,
    TransportSecurity,
    dispatch::{NO_ROUTE_MESSAGE, NOT_REGISTERED_MESSAGE},
};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{
    Admission, PayloadMode, RawQuery, RequestNow, SecurityFloor, TrailerSet, Verdict, WireView, detect_credentials,
};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::{ErrorCode, NamePolicy};

use crate::clock::{Clock, ClockPosture};
use crate::dispatch::{DispatchTable, ErasedAnswer, target_of};
use crate::ext::{
    Authentication, Authenticator, Authorizer, AuthzRequest, CORS_PREFLIGHT, CachedCorsSource, ClassKind, ClientAddr, Governor,
    GovernorRequest, HostQuery, HostResolver, Observer, PolicySource, RequestContext, RequestEvent, ResolvedHost, ResponseView,
    RoutedView, StageFilter, WireHead,
};
use crate::gate::{Authenticated, BodyCeilings, SealedBody};
use crate::render::{S3Error, render};
use crate::trace::{RequestTrace, TraceSource};

/// Everything an assembled service holds. Behind one `Arc`, so cloning the service is one
/// refcount bump and a connection may hold its own clone.
pub(crate) struct Inner {
    pub(crate) router: Router,
    pub(crate) dispatch: DispatchTable,
    /// The deployment's stage filters, in registration order. Empty for almost every deployment,
    /// and the emptiness is checked before any of the three seams does any work.
    pub(crate) filters: Arc<[Arc<dyn StageFilter>]>,
    pub(crate) floor: SecurityFloor,
    pub(crate) limits: Limits,
    pub(crate) names: NamePolicy,
    pub(crate) max_buffered_body_bytes: u64,
    pub(crate) authorizer: Arc<dyn Authorizer>,
    pub(crate) authenticator: Arc<dyn Authenticator>,
    pub(crate) policy_source: Arc<dyn PolicySource>,
    pub(crate) host_resolver: Arc<dyn HostResolver>,
    pub(crate) governor: Arc<dyn Governor>,
    pub(crate) observer: Arc<dyn Observer>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) clock_posture: ClockPosture,
    pub(crate) traces: Arc<dyn TraceSource>,
    pub(crate) cors: Arc<CachedCorsSource>,
    pub(crate) cors_policy: CorsPolicy,
    pub(crate) sse: SseConfig,
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
        // One minting and one reading of the clock, at the top, side by side. Everything below is
        // handed both values; nothing below holds either source, so neither a second identifier nor
        // a second instant can be produced — which is what lets the `Date` header and the skew
        // window name the same moment.
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
        let mut outcome = Outcome::new(&trace);
        let mut response = self.run(request, &mut outcome, now, connection, client_addr).await;
        // The CORS decoration for an ordinary request, applied here because it belongs on
        // **every** answer the pipeline produced once authorisation was granted — the `404` and
        // the `500` included. A browser cannot read a response it was not granted access to, so
        // an error without these headers reaches the page as an opaque network failure and the
        // status the operator is looking at is invisible to the client. Nothing is applied when
        // `run` never got as far as authorising: see `Outcome::cors`.
        if let Some(cors) = outcome.cors.take() {
            let headers = response.headers_mut();
            for (name, value) in cors.iter() {
                headers.insert(name, value.clone());
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
                    response = outcome.refuse(error);
                    break;
                }
            }
        }
        // The one place the body invariants run, on both paths: the body is chosen and nothing has
        // been written. A refusal never reaches an encoder, so this is the only position from which
        // "a `HEAD` response has no content" can cover it.
        crate::invariants::enforce(&mut response, &method);
        // The one stamping site, on both paths, and the last writer on either. `render` has already
        // written the identifiers on the refusal path and writes the identical bytes, so this is an
        // overwrite with the same value there; on the success path it is the only writer, including
        // over an encoder that wrote its own.
        crate::stamp::stamp(response.headers_mut(), &trace, now);
        self.inner.observer.on_response(&RequestEvent {
            request_id: trace.request_id(),
            operation: outcome.operation,
            status: response.status().as_u16(),
            identity: outcome.identity.as_ref(),
            error: outcome.error.as_ref(),
        });
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

    async fn run<B>(
        &self,
        request: Request<B>,
        outcome: &mut Outcome<'_>,
        now: RequestNow,
        connection: TransportSecurity,
        client_addr: Option<ClientAddr>,
    ) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
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
                    return outcome.refuse(error);
                }
            }
        }

        let wire = match WireRequest::accept(Request::from_parts(parts, body), &self.inner.limits) {
            Ok(wire) => wire,
            Err(reject) => return outcome.refuse(S3Error::from(reject)),
        };

        let resolved = self.inner.host_resolver.resolve(&HostQuery {
            host: wire.host(),
            path: wire.raw_path().as_str(),
            method: wire.method(),
        });

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
        // Nothing below this point runs for a preflight: no security floor, no authenticator, no
        // authorizer, no handler. That is not a shortcut, it is the protocol — a browser sends no
        // credentials on a preflight, so requiring a signature here would switch CORS off.
        match classify(wire.method(), &wire.headers()) {
            PreflightClass::NotPreflight => {}
            PreflightClass::Malformed => return outcome.refuse_preflight(),
            PreflightClass::Preflight(preflight) => {
                return self
                    .serve_preflight(wire.raw_path().as_str(), resolved, &preflight, outcome, now, client_addr)
                    .await;
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
                    Some(hint) if error.message() == NO_ROUTE_MESSAGE => {
                        S3Error::new(error.code().clone(), hint.message()).with_status(error.status())
                    }
                    _ => S3Error::from(error),
                };
                return outcome.refuse(refusal);
            }
        };
        let operation = dispatched.spec.name;
        let target = target_of(dispatched.entry);
        outcome.operation = Some(operation);

        let Some(op) = self.inner.dispatch.get(operation) else {
            // Unreachable through `build`, which refuses an operation the router knows and this
            // crate has no codec for. Answered rather than panicked.
            return outcome.refuse(S3Error::new(ErrorCode::NOT_IMPLEMENTED, NOT_REGISTERED_MESSAGE));
        };
        let op = op.clone();
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
        let meta = match MetaView::addressed_with(&wire, target, resolved.bucket().cloned(), &self.inner.names) {
            Ok(meta) => meta,
            Err(error) => return outcome.refuse(S3Error::from(error)),
        };

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
                    return outcome.refuse(error);
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
        if self
            .inner
            .governor
            .try_acquire(&GovernorRequest::new(operation, meta.bucket(), declared_length, None, client_addr, class))
            .await
            .is_err()
        {
            return outcome.refuse_for_load();
        }

        // Sealed here and read at the bottom. Between the two lies every stage that can refuse
        // this request for a reason decidable from its head, and none of them can reach the bytes:
        // `SealedBody::read` needs an `Authenticated`, which does not exist yet.
        let sealed = SealedBody::seal(pending, declared_length);

        let chunk_sink = crate::ext::ChunkSink::new();
        // Kept out of the `match` so the read at the bottom can consult it: for an anonymous or
        // custom admission there is no payload mode and therefore no framed body to decode.
        let mut framing_mode: Option<PayloadMode> = None;
        let verdict = match self.inner.floor.admit(view, op.floor(), now) {
            Ok(Admission::Anonymous(evidence)) => Verdict::anonymous(evidence),
            Ok(Admission::Sealed(sealed)) => {
                let payload = match payload_mode(&headers) {
                    Ok(payload) => payload,
                    Err(error) => return outcome.refuse(error),
                };
                framing_mode = Some(payload.clone());
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
                match self.inner.authenticator.authenticate(&question).await {
                    Ok(verdict) => verdict,
                    Err(_) => {
                        return outcome.refuse(S3Error::new(ErrorCode::INTERNAL_ERROR, "the request could not be authenticated"));
                    }
                }
            }
            // A registered custom scheme reaches here. This assembly wires no verifier for one, and
            // answering it with the AWS path would be a downgrade rather than a compatibility
            // measure, so it is refused in the open.
            Ok(Admission::Custom(_)) => {
                return outcome.refuse(S3Error::new(
                    ErrorCode::NOT_IMPLEMENTED,
                    "this deployment registered a custom authentication scheme and installed no verifier for it",
                ));
            }
            // `Admission` is `#[non_exhaustive]`: a variant added later must not be answered by a
            // wildcard that falls through to "authenticated". Refused, loudly.
            Ok(_) => {
                return outcome.refuse(S3Error::new(
                    ErrorCode::NOT_IMPLEMENTED,
                    "the security floor admitted this request in a way this assembly does not handle",
                ));
            }
            Err(error) => Verdict::reject(error),
        };
        // H4's run-time half: a receipt minted for another request cannot be attached to this one.
        let verdict = SecurityFloor::seal_verdict(verdict, presence);
        if let Some(error) = verdict.rejection() {
            return outcome.refuse(S3Error::from(error));
        }
        // The proof, minted from the verdict that has just been checked. The `else` arm is
        // unreachable — `rejection()` was `None` one line ago — and is refused rather than
        // unwrapped, because "the signature was fine, take my word for it" is exactly the sentence
        // this type exists to make unspellable.
        let Some(authenticated) = Authenticated::of(&verdict) else {
            return outcome.refuse(S3Error::new(
                ErrorCode::INTERNAL_ERROR,
                "the request could not be shown to have been authenticated",
            ));
        };
        outcome.identity = verdict.identity().cloned();

        let Some(requirement) = op.auth() else {
            // Registration refuses an operation with no authorisation action, so this is a defect
            // rather than a configuration. Refused, never permitted: rustfs/rustfs#4845 is what a
            // permissive answer here looks like in production.
            return outcome.refuse(S3Error::new(ErrorCode::INTERNAL_ERROR, "this operation declares no authorisation action"));
        };
        let policy = match self.inner.policy_source.snapshot(verdict.identity()).await {
            Ok(policy) => policy,
            Err(_) => return outcome.refuse(S3Error::new(ErrorCode::ACCESS_DENIED, "access denied")),
        };
        let authz_context = RequestContext::new(now, &policy);
        if self
            .inner
            .authorizer
            .authorize(
                &authz_context,
                &AuthzRequest {
                    operation,
                    action: requirement.action,
                    resource: requirement.resource,
                    bucket: meta.bucket(),
                    key: meta.key(),
                    copy_source_identity: None,
                    version_id: None,
                    route_action: requirement.action,
                    route_bucket: meta.bucket(),
                    route_key: meta.key(),
                    identity: verdict.identity(),
                },
            )
            .await
            != Decision::Allow
        {
            return outcome.refuse(S3Error::new(ErrorCode::ACCESS_DENIED, "access denied"));
        }

        // Authorised, so the configuration read below is one an authenticated and permitted
        // caller paid for — which is what keeps an ordinary `GET` carrying an `Origin` from
        // becoming a second unauthenticated path to the store. Everything from here on carries
        // the headers, including every refusal: `crate::S3Service::call` applies them.
        outcome.cors = self.actual_cors(&headers, meta.bucket(), wire.method(), now).await;

        // Head-decidable and body-free: two different `x-amz-checksum-*` headers are two integrity
        // claims, and no body byte can settle which one the caller meant. `checksum_spec` is the
        // one place that rule lives — the generated decoders call the same function — and this is
        // the earliest position from which it can be applied to every operation at once, which is
        // what keeps a rejected upload from costing the whole transfer.
        if let Err(error) = rustfs_gateway_core::codec::value::refuse_contradictory_checksums(&meta) {
            return outcome.refuse(S3Error::from(error));
        }

        // The server-side-encryption family, on the same terms and in the same position, and for
        // **every** operation rather than the ones whose model happens to bind the headers. Three
        // reasons this is here and not in a codec:
        //
        // *Head-decidable*, so it costs the response and never the transfer — a customer-provided
        // key on a cleartext connection is refused before a byte of the object is read.
        // *Unconditional*, so a backend cannot decline the gate by not implementing it; the
        // refusal is the framework's, exactly as the checksum contradiction above is.
        // *Before the key can be handed anywhere*, which is the whole of the hygiene argument: once
        // a decoded input carrying the key exists, keeping it out of a log is somebody else's care.
        //
        // **Stated over `meta`, which is the head the wire seam produced — not the snapshot.**
        // There are two heads from `StageFilter::on_wire` onwards, and the choice is load-bearing
        // in both directions. Reading the snapshot would let a filter that *adds* the trio hand a
        // key to a handler over cleartext that this gate never looked at; it would also refuse a
        // request whose key a filter had *removed*, which is a wrong answer rather than a
        // protection. The invariant is that the gate and every consumer of the key read one head,
        // with no window between them — the decoder builds its input from this same `meta`.
        // `tests/sse_runtime.rs` pins both directions with a filter that adds the trio and one
        // that removes it. The signature is the deliberate exception and reads the pre-seam
        // `headers` snapshot, which is P6-01's isolation property and is not this rule's business.
        //
        // `SseEnforced` is dropped here. `Req<O>` carries a decoded input and nothing else, so
        // there is no seat on it for a proof — see the module docs of
        // `rustfs_gateway_core::sse` and the note in `crates/gateway/MAP.md`. A backend that needs
        // the fingerprint calls `rustfs_gateway_core::sse::presented_customer_key` from its own
        // decoder, which has the `MetaView`; it is the same code path this gate ran.
        if let Err(rejection) = rustfs_gateway_core::sse::enforce(&meta, connection, &self.inner.sse) {
            return outcome.refuse(S3Error::from(rejection));
        }

        // Whether the `aws-chunked` parser runs, decided from `x-amz-content-sha256` and from
        // nothing else, and decided here — after the verifier, because a signed chunk chain is
        // seeded by the request signature, and before the read, because every check it performs is
        // one the head already answers.
        let ingest = match framing_mode.as_ref() {
            Some(payload) => {
                let seed = crate::chunked::presented_signature_hex(&headers, wire.query().as_str());
                match crate::chunked::ChunkIngest::prepare(
                    payload,
                    &headers,
                    wire.framing(),
                    &chunk_sink,
                    seed.as_deref(),
                    // The documented defaults. `Limits` carries no `ChunkLimits` today, so there
                    // is no assembly-level knob to read; the defaults are the ones
                    // `rustfs_gateway_http::ChunkLimits` argues for, and a deployment that needs
                    // to move them needs a builder field first.
                    rustfs_gateway_http::ChunkLimits::default(),
                ) {
                    Ok(ingest) => ingest,
                    Err(error) => return outcome.refuse(error),
                }
            }
            None => None,
        };

        // The bytes, at last, and only now. Two ceilings, both enforced as the body arrives, and
        // both counted on the wire bytes rather than the decoded ones.
        let ceilings = BodyCeilings::of(operation, self.inner.max_buffered_body_bytes);
        let body = match sealed.read(&authenticated, ceilings, ingest).await {
            Ok(body) => body,
            Err(error) => return outcome.refuse(error),
        };

        let decoded = match op.decode(&meta, body) {
            Ok(decoded) => decoded,
            Err(error) => return outcome.refuse(S3Error::from(error)),
        };
        let resources = match op.resources(&decoded) {
            Ok(resources) => resources,
            Err(error) => return outcome.refuse(S3Error::from(error)),
        };
        let mut decisions = Vec::with_capacity(resources.len());
        let mut refused = false;
        for resource in &resources {
            let shape = if resource.key().is_some() {
                ResourceShape::Object
            } else if resource.bucket().is_some() {
                ResourceShape::Bucket
            } else {
                ResourceShape::Service
            };
            let decision = self
                .inner
                .authorizer
                .authorize(
                    &authz_context,
                    &AuthzRequest {
                        operation,
                        action: resource.action(),
                        resource: shape,
                        bucket: resource.bucket().or_else(|| meta.bucket()),
                        key: resource.key(),
                        copy_source_identity: resource.identity(),
                        version_id: resource.version_id(),
                        route_action: requirement.action,
                        route_bucket: meta.bucket(),
                        route_key: meta.key(),
                        identity: verdict.identity(),
                    },
                )
                .await;
            refused |= decision != Decision::Allow;
            decisions.push(decision);
        }
        if refused {
            return outcome.refuse(S3Error::new(ErrorCode::ACCESS_DENIED, "access denied"));
        }
        let authorized = match op.authorize(decoded, &decisions) {
            Ok(authorized) => authorized,
            Err(_) => return outcome.refuse(S3Error::new(ErrorCode::ACCESS_DENIED, "access denied")),
        };
        let invocation = match op.invoke(authorized) {
            Ok(invocation) => invocation,
            Err(error) => return outcome.refuse(S3Error::from(error)),
        };
        let (answer, status) = match invocation.await {
            Ok(answer) => answer,
            Err(error) => return outcome.refuse(S3Error::from(error)),
        };
        let output = match answer {
            ErasedAnswer::Settled(output) => output,
            // The head is committed from here on. Every exit below answers `status`, and none of
            // them can answer anything else: the continuation's `Err` is a `HandlerError`, which
            // carries a code and a message and no status of its own.
            ErasedAnswer::Committed(work) => {
                let committed = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
                return match work.await {
                    Ok(output) => match op.encode(output, &meta, status) {
                        Ok(encoded) => crate::commit::answered(encoded, committed),
                        Err(error) => outcome.refuse_after_commit(S3Error::from(error), committed),
                    },
                    Err(error) => outcome.refuse_after_commit(S3Error::from(error), committed),
                };
            }
        };
        match op.encode(output, &meta, status) {
            Ok(encoded) => into_response(encoded),
            Err(error) => outcome.refuse(S3Error::from(error)),
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
            None => None,
        };
        match answer_preflight(&self.inner.cors_policy, document.as_deref(), preflight) {
            PreflightOutcome::Allowed(headers) => preflight_response(&headers),
            PreflightOutcome::Refused => outcome.refuse_preflight(),
        }
    }

    /// The CORS decoration an ordinary response should carry, if any.
    ///
    /// Called once, after authorisation. `None` for a request with no usable `Origin`, for a path
    /// that names no bucket, and for an origin no rule admits — the last of which is not an error:
    /// the request is served and the browser is the one that withholds the answer from the page.
    async fn actual_cors(
        &self,
        headers: &http::HeaderMap,
        bucket: Option<&rustfs_gateway_types::BucketName>,
        method: &http::Method,
        now: RequestNow,
    ) -> Option<CorsHeaders> {
        let view = rustfs_gateway_http::HeaderView::new(headers);
        // Exactly one line, and one this runtime would be willing to echo. Two `Origin` lines are
        // refused here as they are on a preflight, and for the same cache-poisoning reason.
        let origin = (view.count(&rustfs_gateway_core::cors::ORIGIN) == 1)
            .then(|| view.get_str(&rustfs_gateway_core::cors::ORIGIN))
            .flatten()
            .filter(|origin| rustfs_gateway_core::cors::is_plausible_origin(origin))?;
        let document = self.inner.cors.get(bucket?, now).await?;
        answer_actual(&self.inner.cors_policy, Some(&document), origin, method.as_str())
    }
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
    if let Some(bucket) = resolved.bucket() {
        return Some(bucket.clone());
    }
    if !matches!(resolved.target, TargetKind::Bucket | TargetKind::Object) {
        return None;
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
struct Outcome<'a> {
    trace: &'a RequestTrace,
    operation: Option<&'static str>,
    identity: Option<rustfs_gateway_sig::Identity>,
    error: Option<ErrorCode>,
    /// The CORS decoration for an ordinary response, set once authorisation has been granted and
    /// applied by [`S3Service::call`] to whatever the pipeline produced afterwards. `None` for
    /// every request that never got that far, which is what keeps a pre-authentication refusal
    /// from costing a configuration read.
    cors: Option<CorsHeaders>,
}

impl<'a> Outcome<'a> {
    /// An outcome that knows nothing yet, except which request it is about.
    const fn new(trace: &'a RequestTrace) -> Self {
        Self {
            trace,
            operation: None,
            identity: None,
            error: None,
            cors: None,
        }
    }

    /// Renders a refusal and records its code, so every early return goes through one place.
    fn refuse(&mut self, error: S3Error) -> Response<Body> {
        self.error = Some(error.code().clone());
        render(&error, self.trace)
    }

    /// The one refusal a preflight can receive.
    ///
    /// Built from `rustfs_gateway_core::cors::preflight_refusal`, which takes no arguments — so
    /// the "no rule matched", "no document", "no bucket" and "illegal name" paths cannot render
    /// different bytes, whatever a future edit does to any one of them. `Vary: Origin` rides
    /// along because the refusal is still an answer that depends on the `Origin` header: a shared
    /// cache that stored it under the URL alone would serve it to an origin that would have been
    /// allowed.
    fn refuse_preflight(&mut self) -> Response<Body> {
        let error = S3Error::from(preflight_refusal());
        self.error = Some(error.code().clone());
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
        self.refuse(S3Error::new(ErrorCode::SLOW_DOWN, "the service is not accepting this request right now"))
    }

    /// The same, for a refusal that arrived after the head had gone out.
    ///
    /// The observer is told the code either way — a `200` whose body carries `<Code>InvalidPart</Code>`
    /// is a failed request, and an audit trail that recorded it as a success is the exact mistake the
    /// status line invites. What differs is the status, which is the committed one and no longer
    /// this refusal's to choose.
    fn refuse_after_commit(&mut self, error: S3Error, committed: StatusCode) -> Response<Body> {
        self.error = Some(error.code().clone());
        crate::commit::refused(&error, self.trace, committed)
    }
}

/// What `x-amz-content-sha256` said about the body.
///
/// An absent header is [`PayloadMode::Empty`], whose canonical token is the digest of the empty
/// payload — what SDKs sign for a body-less request.
///
/// The trailer set is read from `x-amz-trailer` and handed to `PayloadMode::parse` together with
/// the digest value, because the two are only valid in specific combinations and a mode that could
/// be half-built could be observed half-built. It used to be [`TrailerSet::None`] unconditionally,
/// which refused every trailered upload here as an unreadable header — the wrong stage and the
/// wrong sentence for a request that is well-formed and merely asks for something this assembly
/// has not finished. `crate::chunked` is where that refusal now happens, as a `501`.
fn payload_mode(headers: &http::HeaderMap) -> Result<PayloadMode, S3Error> {
    let Some(value) = headers.get("x-amz-content-sha256") else {
        return Ok(PayloadMode::Empty);
    };
    let Ok(text) = value.to_str() else {
        return Err(S3Error::new(
            ErrorCode::INVALID_REQUEST,
            "the x-amz-content-sha256 header is not a readable value",
        ));
    };
    PayloadMode::parse(text, declared_trailers(headers)?).map_err(|_| {
        S3Error::new(
            ErrorCode::INVALID_REQUEST,
            "the x-amz-content-sha256 header is not a value this service accepts",
        )
    })
}

/// The trailer set `x-amz-trailer` declared.
///
/// Every name is validated by `rustfs_gateway_sig::TrailerName`, and the set by
/// `DeclaredTrailers::new`, which refuses an empty declaration, too many names and duplicates. None
/// of those checks is repeated here: this function splits a list and nothing else, so there is one
/// place a trailer name is judged.
///
/// `signed` is `false`. `x-amz-trailer-signature` is a value that appears *after* the terminal
/// chunk rather than a name a client declares in this header, so nothing readable from the head can
/// set it; the signed-trailer form is refused downstream along with every other trailered mode.
fn declared_trailers(headers: &http::HeaderMap) -> Result<TrailerSet, S3Error> {
    let Some(value) = headers.get("x-amz-trailer") else {
        return Ok(TrailerSet::None);
    };
    let malformed = || S3Error::new(ErrorCode::INVALID_REQUEST, "the x-amz-trailer header is not one this service can read");
    let text = value.to_str().map_err(|_| malformed())?;
    let mut names = Vec::new();
    for name in text.split(',').map(str::trim).filter(|name| !name.is_empty()) {
        names.push(rustfs_gateway_sig::TrailerName::new(name).map_err(|_| malformed())?);
    }
    rustfs_gateway_sig::DeclaredTrailers::new(names, false)
        .map(TrailerSet::Declared)
        .map_err(|_| malformed())
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
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Positive — cloning the service is one pointer's worth of work, which is what makes cloning
    /// it per connection the right thing for a server to do.
    #[test]
    fn the_service_is_one_pointer_wide() {
        assert_eq!(core::mem::size_of::<S3Service>(), core::mem::size_of::<usize>());
    }

    /// Negative — an absent `x-amz-content-sha256` is the empty payload, not "unsigned". Treating
    /// it as unsigned would let a client drop the header to remove the body from the signature.
    #[test]
    fn an_absent_content_sha256_is_the_empty_payload() {
        assert_eq!(payload_mode(&http::HeaderMap::new()).expect("no header"), PayloadMode::Empty);
    }

    /// Negative — a request nobody annotated is cleartext, so the customer-key gate is closed by
    /// default rather than open by default.
    #[test]
    fn an_unannotated_request_is_cleartext() {
        assert_eq!(connection_security(&http::Extensions::new()), TransportSecurity::Plaintext);
    }

    /// Negative — and the other direction, so the reader is not simply stuck on one answer. A
    /// function that returned `Plaintext` unconditionally satisfies every test above.
    #[test]
    fn n_a_transport_that_declares_tls_is_believed_and_one_that_declares_cleartext_is_too() {
        let mut encrypted = http::Extensions::new();
        encrypted.insert(TransportSecurity::Encrypted);
        assert_eq!(connection_security(&encrypted), TransportSecurity::Encrypted);
        let mut plaintext = http::Extensions::new();
        plaintext.insert(TransportSecurity::Plaintext);
        assert_eq!(connection_security(&plaintext), TransportSecurity::Plaintext);
    }

    /// Negative — a value this assembly cannot frame is refused rather than admitted and then
    /// mis-decoded.
    #[test]
    fn an_unframeable_payload_declaration_is_refused() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::HeaderName::from_static("x-amz-content-sha256"),
            http::HeaderValue::from_static("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"),
        );
        assert!(payload_mode(&headers).is_err());
    }
}
