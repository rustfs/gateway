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
//!   read body     bounded by the assembly's buffered ceiling
//!   admit         the seven unconditional rules, outside every replaceable verifier
//!   authenticate  who the caller is, from a request the floor has already cleared
//!   decode        the request head and body into the operation's input
//!   authorize     whether that caller may do this — identity known, operation known
//!   dispatch      the backend
//!   encode        the answer, plus the RFC 9110 body invariants
//! ```
//!
//! Two positions would be defects if moved. **Govern before the body** is the difference between
//! refusing a gibibyte upload and paying for it first. **Authorize after decode** is what gives the
//! authorizer the bucket and key the path actually named, rather than a second parse of the path.
//!
//! # Why the clock is read once
//!
//! At the top, before acceptance, and never again. Two readings inside one request let the skew
//! check and the expiry check straddle a second boundary, so a presigned URL can be inside its
//! window when it is admitted and outside it when its lifetime is computed.
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
use rustfs_gateway_core::{EncodedResponse, MetaView, ResponseBody, RouteRequestParts, Router, dispatch::NOT_REGISTERED_MESSAGE};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_sig::{Admission, PayloadMode, RawQuery, SecurityFloor, TrailerSet, Verdict, WireView, detect_credentials};
use rustfs_gateway_stream::Body;
use rustfs_gateway_types::ErrorCode;

use crate::clock::Clock;
use crate::dispatch::{DispatchTable, target_of};
use crate::ext::{
    Authentication, Authenticator, Authorizer, AuthzRequest, Governor, GovernorRequest, HostQuery, HostResolver, Observer,
    RequestEvent,
};
use crate::render::{S3Error, render};

/// Everything an assembled service holds. Behind one `Arc`, so cloning the service is one
/// refcount bump and a connection may hold its own clone.
pub(crate) struct Inner {
    pub(crate) router: Router,
    pub(crate) dispatch: DispatchTable,
    pub(crate) floor: SecurityFloor,
    pub(crate) limits: Limits,
    pub(crate) max_buffered_body_bytes: u64,
    pub(crate) authorizer: Arc<dyn Authorizer>,
    pub(crate) authenticator: Arc<dyn Authenticator>,
    pub(crate) host_resolver: Arc<dyn HostResolver>,
    pub(crate) governor: Arc<dyn Governor>,
    pub(crate) observer: Arc<dyn Observer>,
    pub(crate) clock: Arc<dyn Clock>,
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
        let mut outcome = Outcome::default();
        let response = self.run(request, &mut outcome).await;
        self.inner.observer.on_response(&RequestEvent {
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

    async fn run<B>(&self, request: Request<B>, outcome: &mut Outcome) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // One reading, at the top. Nothing below reads the clock again.
        let now = self.inner.clock.now();

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
            Err(error) => return outcome.refuse(S3Error::from(error)),
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

        let meta = match MetaView::of(&wire, target) {
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

        let body = match read_body(pending, declared_length, self.inner.max_buffered_body_bytes).await {
            Ok(body) => body,
            Err(error) => return outcome.refuse(error),
        };

        let query = RawQuery::new(wire.query().as_str());
        let view = WireView::new(&headers, query);
        let presence = detect_credentials(&view);
        let verdict = match self.inner.floor.admit(view, op.floor(), now) {
            Ok(Admission::Anonymous(evidence)) => Verdict::anonymous(evidence),
            Ok(Admission::Sealed(sealed)) => {
                let payload = match payload_mode(&headers) {
                    Ok(payload) => payload,
                    Err(error) => return outcome.refuse(error),
                };
                let question = Authentication::new(
                    &sealed,
                    wire.method(),
                    wire.raw_path().as_str(),
                    wire.host().raw_for_signing(),
                    &payload,
                    declared_length,
                );
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

        let invocation = match op.invoke(&meta, body) {
            Ok(invocation) => invocation,
            Err(error) => return outcome.refuse(S3Error::from(error)),
        };
        let (output, status) = match invocation.await {
            Ok(answer) => answer,
            Err(error) => return outcome.refuse(S3Error::from(error)),
        };
        match op.encode(output, &meta, status) {
            Ok(encoded) => into_response(encoded),
            Err(error) => outcome.refuse(S3Error::from(error)),
        }
    }
}

/// What the observer is told, accumulated as the pipeline learns it.
#[derive(Default)]
struct Outcome {
    operation: Option<&'static str>,
    identity: Option<rustfs_gateway_sig::Identity>,
    error: Option<ErrorCode>,
}

impl Outcome {
    /// Renders a refusal and records its code, so every early return goes through one place.
    fn refuse(&mut self, error: S3Error) -> Response<Body> {
        self.error = Some(error.code().clone());
        render(&error)
    }
}

/// What `x-amz-content-sha256` said about the body.
///
/// An absent header is [`PayloadMode::Empty`], whose canonical token is the digest of the empty
/// payload — what SDKs sign for a body-less request. `aws-chunked` framing is not decoded by this
/// assembly, so a streaming value that declares trailers is refused by `PayloadMode::parse` rather
/// than being admitted and then mis-framed.
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
    PayloadMode::parse(text, TrailerSet::None).map_err(|_| {
        S3Error::new(
            ErrorCode::INVALID_REQUEST,
            "the x-amz-content-sha256 header is not a value this service accepts",
        )
    })
}

/// Reads the request body, bounded twice: once by what it announced, once by what it delivers.
///
/// The announced check comes first so that a body claiming more than the ceiling is refused
/// without being read at all, and the delivered check is what catches a body that announced
/// nothing.
async fn read_body<B>(body: Option<B>, declared_length: Option<u64>, ceiling: u64) -> Result<Bytes, S3Error>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use http_body_util::BodyExt;

    let Some(body) = body else {
        return Ok(Bytes::new());
    };
    if declared_length.is_some_and(|length| length > ceiling) {
        return Err(S3Error::new(
            ErrorCode::ENTITY_TOO_LARGE,
            "the declared request body is larger than this service will hold",
        )
        .with_status(StatusCode::PAYLOAD_TOO_LARGE));
    }
    let limit = usize::try_from(ceiling).unwrap_or(usize::MAX);
    match http_body_util::Limited::new(body, limit).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        // One code for "it stopped early" and "it went on too long": both mean the body that
        // arrived is not the body that was announced, and distinguishing them tells a caller which
        // ceiling it hit.
        Err(_) => Err(S3Error::new(
            ErrorCode::INCOMPLETE_BODY,
            "the request body did not arrive as it was framed",
        )),
    }
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

    /// Negative — a body that announces more than the ceiling is refused before it is read, so the
    /// refusal costs nothing.
    #[tokio::test]
    async fn an_oversized_declared_body_is_refused_without_being_read() {
        let body = http_body_util::Full::new(Bytes::from_static(b"x"));
        let error = read_body(Some(body), Some(1 << 30), 1024)
            .await
            .expect_err("over the ceiling");
        assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.code(), &ErrorCode::ENTITY_TOO_LARGE);
    }

    /// Negative — a body that announces nothing and then exceeds the ceiling is still refused; a
    /// limit that only fires on a declared length is one a client removes by not declaring it.
    #[tokio::test]
    async fn an_undeclared_oversized_body_is_still_refused() {
        let body = http_body_util::Full::new(Bytes::from(vec![0_u8; 4096]));
        let error = read_body(Some(body), None, 1024).await.expect_err("over the ceiling");
        assert_eq!(error.code(), &ErrorCode::INCOMPLETE_BODY);
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

    /// Positive — an absent body reads as empty rather than as an error.
    #[tokio::test]
    async fn an_absent_body_reads_as_empty() {
        let body: Option<http_body_util::Full<Bytes>> = None;
        assert!(read_body(body, None, 1024).await.expect("no body").is_empty());
    }
}
