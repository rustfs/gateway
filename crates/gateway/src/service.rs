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
//!   accept        every wire-level ambiguity refused; no body byte read
//!   resolve host  what the path addresses, and which endpoint family
//!   route         which operation — decided before anything is authenticated
//!   govern        the deployment's chance to refuse: routed, so it has a bucket; before the body
//!   admit         the seven unconditional rules, outside every replaceable verifier
//!   authenticate  who the caller is, from a request the floor has already cleared
//!   authorize     whether that caller may do this — identity known, operation known
//!   contradict    the head-decidable contradictions, refused while the body is still outside
//!   read body     bounded by the assembly's ceiling and by the operation's own cap
//!   decode        the request head and body into the operation's input
//!   dispatch      the backend
//!   encode        the answer, plus the RFC 9110 body invariants
//! ```
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
use rustfs_gateway_core::{
    EncodedResponse, MetaView, ResponseBody, RouteRequestParts, Router,
    dispatch::{NO_ROUTE_MESSAGE, NOT_REGISTERED_MESSAGE},
};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{
    Admission, PayloadMode, RawQuery, RequestNow, SecurityFloor, TrailerSet, Verdict, WireView, detect_credentials,
};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::{ErrorCode, NamePolicy};

use crate::clock::Clock;
use crate::dispatch::{DispatchTable, ErasedAnswer, target_of};
use crate::ext::{
    Authentication, Authenticator, Authorizer, AuthzRequest, Governor, GovernorRequest, HostQuery, HostResolver, Observer,
    RequestEvent,
};
use crate::gate::{Authenticated, BodyCeilings, SealedBody};
use crate::render::{S3Error, render};
use crate::trace::{RequestTrace, TraceSource};

/// Everything an assembled service holds. Behind one `Arc`, so cloning the service is one
/// refcount bump and a connection may hold its own clone.
pub(crate) struct Inner {
    pub(crate) router: Router,
    pub(crate) dispatch: DispatchTable,
    pub(crate) floor: SecurityFloor,
    pub(crate) limits: Limits,
    pub(crate) names: NamePolicy,
    pub(crate) max_buffered_body_bytes: u64,
    pub(crate) authorizer: Arc<dyn Authorizer>,
    pub(crate) authenticator: Arc<dyn Authenticator>,
    pub(crate) host_resolver: Arc<dyn HostResolver>,
    pub(crate) governor: Arc<dyn Governor>,
    pub(crate) observer: Arc<dyn Observer>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) traces: Arc<dyn TraceSource>,
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
        let mut outcome = Outcome::new(&trace);
        let mut response = self.run(request, &mut outcome, now).await;
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

    async fn run<B>(&self, request: Request<B>, outcome: &mut Outcome<'_>, now: RequestNow) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // `WireRequest` publishes no way back to the header map — that is the boundary it exists to
        // draw — while `SecurityFloor` and the canonical request are defined over the raw map. The
        // copy is taken before acceptance and used only after it has succeeded, so what is held is
        // an accepted map. Removing the copy needs a signing accessor on `WireRequest` itself.
        let headers = request.headers().clone();

        let wire = match WireRequest::accept(request, &self.inner.limits) {
            Ok(wire) => wire,
            Err(reject) => return outcome.refuse(S3Error::from(reject)),
        };

        let resolved = self.inner.host_resolver.resolve(&HostQuery {
            host: wire.host(),
            path: wire.raw_path().as_str(),
            method: wire.method(),
        });

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

        // Routed, so there is a bucket to limit on; before the body, so a refusal costs the
        // response and nothing else.
        if self
            .inner
            .governor
            .try_acquire(&GovernorRequest {
                operation,
                bucket: meta.bucket(),
                declared_body_bytes: declared_length,
                identity: None,
            })
            .await
            .is_err()
        {
            return outcome.refuse(S3Error::new(ErrorCode::SLOW_DOWN, "the service is not accepting this request right now"));
        }

        // Sealed here and read at the bottom. Between the two lies every stage that can refuse
        // this request for a reason decidable from its head, and none of them can reach the bytes:
        // `SealedBody::read` needs an `Authenticated`, which does not exist yet.
        let sealed = SealedBody::seal(pending, declared_length);

        let query = RawQuery::new(wire.query().as_str());
        let view = WireView::new(&headers, query);
        let presence = detect_credentials(&view);
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
        if let Err(denial) = self
            .inner
            .authorizer
            .authorize(&AuthzRequest {
                operation,
                action: requirement.action,
                resource: requirement.resource,
                bucket: meta.bucket(),
                key: meta.key(),
                identity: verdict.identity(),
            })
            .await
        {
            return outcome.refuse(S3Error::from(denial));
        }

        // Head-decidable and body-free: two different `x-amz-checksum-*` headers are two integrity
        // claims, and no body byte can settle which one the caller meant. `checksum_spec` is the
        // one place that rule lives — the generated decoders call the same function — and this is
        // the earliest position from which it can be applied to every operation at once, which is
        // what keeps a rejected upload from costing the whole transfer.
        if let Err(error) = rustfs_gateway_core::codec::value::refuse_contradictory_checksums(&meta) {
            return outcome.refuse(S3Error::from(error));
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

        let invocation = match op.invoke(&meta, body) {
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
}

impl<'a> Outcome<'a> {
    /// An outcome that knows nothing yet, except which request it is about.
    const fn new(trace: &'a RequestTrace) -> Self {
        Self {
            trace,
            operation: None,
            identity: None,
            error: None,
        }
    }

    /// Renders a refusal and records its code, so every early return goes through one place.
    fn refuse(&mut self, error: S3Error) -> Response<Body> {
        self.error = Some(error.code().clone());
        render(&error, self.trace)
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
