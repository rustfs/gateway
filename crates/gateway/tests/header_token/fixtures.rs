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

//! The fixtures of the header token suites (ADR-0050, rustfs/gateway#1586).
//!
//! Responsible for: the fixture host verifier and what it answers; recorders for both
//! authorization stages, the handler context, the audit and observer events, the governor's class
//! and the authenticator's credential lookups; and the assembled service every case drives, with
//! `request_context_runtime.rs`'s privileged vendor probe, whose floor refuses the scheme.
//! NOT responsible for: any assertion but [`Fixture::refused_before_any_verifier`], which names
//! the one refusal shape both suites hold a request to.
//! Upstream: `rustfs_gateway::ServiceBuilder`, `support`. Downstream: `header_token.rs` and
//! `header_token_secrecy.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::dto::{ListBuckets, ListBucketsOutput};
use rustfs_gateway::sig::{Identity, SecurityFloor};
use rustfs_gateway::{
    AuthSchemeRef, Authorizer, AuthzAuditEvent, AuthzAuditSink, AuthzRequest, BoxFuture, ClassKind, CredentialLookup,
    CredentialProvider, Credentials, Decision, Governor, GovernorRequest, Handler, HandlerContext, HandlerResult,
    HeaderTokenClaim, HeaderTokenRefused, HeaderTokenRequest, HeaderTokenVerifier, InputAuthzRequest, InputDecisions, Lease,
    Observer, ProviderError, RegionSet, Req, RequestContext, RequestContextView, RequestEvent, Resp, S3Service, ServiceBuilder,
    SigV4Authenticator, StaticCredentials,
};

pub(crate) use crate::request_context_runtime::PROBE_PATH;
use crate::request_context_runtime::{SecretProbe, probe_dialect};
use crate::support::{self, Ping, PingOutput};

pub(crate) const HEADER: &str = "x-auth-token";
/// The token every case presents. A sentinel, so "nothing holds it" is a search for bytes.
pub(crate) const TOKEN: &str = "gAAAAABheader-token-SENTINEL";
/// The principal the fixture host reports.
pub(crate) const PRINCIPAL: &str = "KEYSTONEUSER";
/// The access key the signed fixtures sign with (`support::signed`).
pub(crate) const SIGNED_PRINCIPAL: &str = "AKIDEXAMPLE";

pub(crate) fn claim() -> HeaderTokenClaim {
    HeaderTokenClaim::new(HEADER).expect("a legal claim")
}

// ── the host's verifier ────────────────────────────────────────────────────────────────────────

/// What a host's outer layer leaves in the request for its verifier to report.
#[derive(Clone)]
pub(crate) struct Established(pub(crate) &'static str);

/// What the fixture host answers when asked.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Answer {
    /// Reports [`PRINCIPAL`].
    Accepts,
    Refuses,
    /// Panics the first time it is asked, and accepts afterwards.
    PanicsOnce,
    /// Reports the identity its outer layer installed in this request, and refuses without one.
    ReportsInstalled,
}

/// The fixture host. It counts every call, so "the verifier was never asked" is a measurement.
struct Host {
    answer: Answer,
    calls: Arc<AtomicUsize>,
}

impl HeaderTokenVerifier for Host {
    fn verify(&self, request: &HeaderTokenRequest<'_>) -> Result<Identity, HeaderTokenRefused> {
        let asked = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let principal = match self.answer {
            Answer::Accepts => PRINCIPAL,
            Answer::Refuses => return Err(HeaderTokenRefused),
            Answer::PanicsOnce => {
                assert_ne!(asked, 1, "the fixture host's own failure");
                PRINCIPAL
            }
            Answer::ReportsInstalled => request.server_state::<Established>().ok_or(HeaderTokenRefused)?.0,
        };
        Identity::new(principal).map_err(|_| HeaderTokenRefused)
    }
}

// ── recorders ──────────────────────────────────────────────────────────────────────────────────

pub(crate) type Lines = Vec<(String, Vec<u8>)>;

/// One named request shape, rebuilt for every service it is sent to.
pub(crate) type RequestCase = (&'static str, Box<dyn Fn() -> http::Request<Bytes>>);

/// One authorization stage, as the recording authorizer was asked it.
#[derive(Clone, Debug)]
pub(crate) struct Asked {
    pub(crate) stage: &'static str,
    pub(crate) scheme: AuthSchemeRef,
    pub(crate) identity: Option<String>,
    pub(crate) headers: Lines,
    pub(crate) rendered: String,
}

/// Allows everything and records what each stage was handed.
#[derive(Default)]
pub(crate) struct Stages(Mutex<Vec<Asked>>);

impl Stages {
    fn record(&self, stage: &'static str, context: &RequestContext<'_>, identity: Option<&Identity>) {
        let headers = context.headers().map_or_else(Vec::new, |view| {
            view.iter_raw()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect()
        });
        self.0.lock().expect("not poisoned").push(Asked {
            stage,
            scheme: context.auth_scheme(),
            identity: identity.map(|identity| identity.access_key_id().to_owned()),
            headers,
            rendered: format!("{context:?}"),
        });
    }

    pub(crate) fn take(&self) -> Vec<Asked> {
        std::mem::take(&mut *self.0.lock().expect("not poisoned"))
    }
}

impl Authorizer for Stages {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        self.record("route", context, request.identity);
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        self.record("input", context, request.route().identity);
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// What one handler read from its request's context.
#[derive(Clone, Debug)]
pub(crate) struct Handed {
    pub(crate) operation: &'static str,
    pub(crate) header_token: Option<String>,
    pub(crate) signed: Option<String>,
    pub(crate) anonymous: bool,
    pub(crate) headers: Lines,
    pub(crate) rendered: String,
}

/// Serves every operation these suites route, and records what each handler was handed.
#[derive(Default)]
pub(crate) struct Backend(Mutex<Vec<Handed>>);

impl Backend {
    fn record(&self, context: &RequestContextView) {
        self.0.lock().expect("not poisoned").push(Handed {
            operation: context.operation(),
            header_token: context
                .header_token_principal()
                .map(|identity| identity.access_key_id().to_owned()),
            signed: context.principal().map(|principal| principal.access_key_id().to_owned()),
            anonymous: context.is_anonymous(),
            headers: context
                .headers()
                .iter_raw()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
            rendered: format!("{context:?}"),
        });
    }

    pub(crate) fn take(&self) -> Vec<Handed> {
        std::mem::take(&mut *self.0.lock().expect("not poisoned"))
    }
}

impl Handler<ListBuckets> for Backend {
    async fn call(&self, request: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
        self.record(request.context());
        Ok(Resp::new(ListBucketsOutput::default()))
    }

    async fn call_with_context(&self, request: Req<ListBuckets>, _context: HandlerContext) -> HandlerResult<ListBuckets> {
        self.record(request.context());
        Ok(Resp::new(ListBucketsOutput::default()))
    }
}

impl Handler<Ping> for Backend {
    async fn call(&self, request: Req<Ping>) -> HandlerResult<Ping> {
        self.record(request.context());
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }

    async fn call_with_context(&self, request: Req<Ping>, _context: HandlerContext) -> HandlerResult<Ping> {
        self.record(request.context());
        Ok(Resp::new(PingOutput {
            message: "pong".to_owned(),
        }))
    }
}

/// The audit and observer events of each request: the scheme and principal an audit event named,
/// the principal an observer event named, and every event's own rendering.
#[derive(Default)]
pub(crate) struct Events {
    pub(crate) audited: Mutex<Vec<(AuthSchemeRef, Option<String>)>>,
    pub(crate) observed: Mutex<Vec<(u16, Option<String>)>>,
    pub(crate) rendered: Mutex<Vec<String>>,
}

impl AuthzAuditSink for Events {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        let identity = event.identity.map(|identity| identity.access_key_id().to_owned());
        self.rendered.lock().expect("not poisoned").push(format!(
            "{:?} {:?} {:?} {:?} {:?}",
            event.auth_scheme, identity, event.operation, event.action, event.resources
        ));
        self.audited.lock().expect("not poisoned").push((event.auth_scheme, identity));
    }
}

impl Observer for Events {
    fn on_response(&self, event: &RequestEvent<'_>) {
        self.rendered.lock().expect("not poisoned").push(format!("{event:?}"));
        self.observed
            .lock()
            .expect("not poisoned")
            .push((event.status, event.identity.map(|identity| identity.access_key_id().to_owned())));
    }
}

/// Admits everything and records the class each request was governed under.
#[derive(Default)]
pub(crate) struct Classes(pub(crate) Mutex<Vec<ClassKind>>);

impl Governor for Classes {
    fn try_acquire<'a>(&'a self, request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        self.0.lock().expect("not poisoned").push(request.kind());
        Box::pin(async { Ok(Lease::admit()) })
    }
}

/// The fixture credential store, counting every lookup the authenticator makes.
struct CountedCredentials {
    store: StaticCredentials,
    lookups: Arc<AtomicUsize>,
}

impl CredentialProvider for CountedCredentials {
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        self.store.lookup(access_key_id)
    }
}

// ── a privileged vendor operation, which refuses the scheme ────────────────────────────────────
//
// `request_context_runtime.rs`'s `HEAD /example/admin/probe`: a third-party operation that kept its
// privileged default. Reused here rather than declared a second time.

impl Handler<SecretProbe> for Backend {
    async fn call(&self, request: Req<SecretProbe>) -> HandlerResult<SecretProbe> {
        self.record(request.context());
        Ok(Resp::new(()))
    }

    async fn call_with_context(&self, request: Req<SecretProbe>, _context: HandlerContext) -> HandlerResult<SecretProbe> {
        self.record(request.context());
        Ok(Resp::new(()))
    }
}

// ── the assembly ───────────────────────────────────────────────────────────────────────────────

/// Everything one assembled service records.
pub(crate) struct Recorders {
    /// How often the host's verifier was asked.
    pub(crate) verifier_calls: Arc<AtomicUsize>,
    /// How often the authenticator looked a credential up.
    pub(crate) lookups: Arc<AtomicUsize>,
    pub(crate) stages: Arc<Stages>,
    pub(crate) backend: Arc<Backend>,
    pub(crate) events: Arc<Events>,
    pub(crate) classes: Arc<Classes>,
}

/// One assembled service and its recorders.
pub(crate) struct Fixture {
    pub(crate) service: S3Service,
    recorders: Recorders,
}

impl core::ops::Deref for Fixture {
    type Target = Recorders;

    fn deref(&self) -> &Recorders {
        &self.recorders
    }
}

impl Fixture {
    pub(crate) fn of(builder: ServiceBuilder, recorders: Recorders) -> Self {
        Self {
            service: builder.build().expect("a complete assembly"),
            recorders,
        }
    }

    pub(crate) async fn exchange(&self, request: http::Request<Bytes>) -> rustfs_gateway::WireResponse {
        support::exchange_wire(&self.service, request).await
    }

    /// `403 AccessDenied`, and nothing behind the floor ran.
    pub(crate) fn refused_before_any_verifier(&self, response: &rustfs_gateway::WireResponse, at: &str) {
        let body = String::from_utf8_lossy(response.body()).into_owned();
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN, "{at}: {body}");
        assert_eq!(support::element_text(&body, "Code"), Some("AccessDenied"), "{at}: {body}");
        self.nothing_ran(at);
    }

    /// Nothing behind the floor ran: no verifier, no credential lookup, no authorizer question and
    /// no handler.
    pub(crate) fn nothing_ran(&self, at: &str) {
        assert_eq!(self.verifier_calls.load(Ordering::SeqCst), 0, "{at}: the host's verifier was asked");
        assert_eq!(self.lookups.load(Ordering::SeqCst), 0, "{at}: a credential was looked up");
        assert!(self.stages.take().is_empty(), "{at}: the authorizer was asked");
        assert!(self.backend.take().is_empty(), "{at}: a handler ran");
    }
}

/// The builder every suite starts from: the signed fixtures' clock, a fixed trace so two answers
/// can be compared byte for byte, and every recorder installed.
pub(crate) fn builder(floor: SecurityFloor) -> (ServiceBuilder, Recorders) {
    let lookups = Arc::new(AtomicUsize::new(0));
    let store = StaticCredentials::new().with(Credentials::new(SIGNED_PRINCIPAL, b"secret").expect("a valid access key id"));
    let credentials = Arc::new(CountedCredentials {
        store,
        lookups: Arc::clone(&lookups),
    });
    let recorders = Recorders {
        verifier_calls: Arc::new(AtomicUsize::new(0)),
        lookups,
        stages: Arc::new(Stages::default()),
        backend: Arc::new(Backend::default()),
        events: Arc::new(Events::default()),
        classes: Arc::new(Classes::default()),
    };
    let builder = ServiceBuilder::new()
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
        .authorizer(Arc::clone(&recorders.stages))
        .authz_audit(Arc::clone(&recorders.events))
        .observer(Arc::clone(&recorders.events))
        .governor(Arc::clone(&recorders.classes))
        .security_floor(floor)
        .trace_source(rustfs_gateway::FixedTrace::at(0x0123_4567_89AB_CDEF, 0))
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<ListBuckets, _>(Arc::clone(&recorders.backend))
        .register::<Ping, _>(Arc::clone(&recorders.backend))
        .register::<SecretProbe, _>(Arc::clone(&recorders.backend))
        .dialect(&support::ping_dialect())
        .dialect(&probe_dialect());
    (builder, recorders)
}

/// The service behind `floor`, with the header token claim installed when `opt_in` names what the
/// host answers, and absent otherwise.
pub(crate) fn assemble_on(floor: SecurityFloor, opt_in: Option<Answer>) -> Fixture {
    let (builder, recorders) = builder(floor);
    let builder = match opt_in {
        Some(answer) => builder.host_verified_header_token(
            claim(),
            Host {
                answer,
                calls: Arc::clone(&recorders.verifier_calls),
            },
        ),
        None => builder,
    };
    Fixture::of(builder, recorders)
}

pub(crate) fn assemble(opt_in: Option<Answer>) -> Fixture {
    assemble_on(SecurityFloor::new(), opt_in)
}

/// The default floor and the RustFS profile's reading of which requests are signed. Every refusal
/// beside an AWS surface holds under both.
pub(crate) fn floors() -> [(&'static str, SecurityFloor); 2] {
    [
        ("default", SecurityFloor::new()),
        (
            "rustfs-profile",
            SecurityFloor::new()
                .delegate_anonymous_to_authorizer_after_listing_in_the_posture_report()
                .enable_sigv2_presigned_compatibility()
                .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
                .recognize_signatures_as_legacy_rustfs(),
        ),
    ]
}

/// `request` with the token header added beside whatever it already carries.
pub(crate) fn with_token(mut request: http::Request<Bytes>) -> http::Request<Bytes> {
    request.headers_mut().insert(HEADER, http::HeaderValue::from_static(TOKEN));
    request
}

/// A request whose only credential is the token.
pub(crate) fn token_only(method: http::Method, uri: &str) -> http::Request<Bytes> {
    with_token(support::plain(method, uri))
}

pub(crate) fn status_and_code(response: &rustfs_gateway::WireResponse) -> (u16, Option<String>) {
    let body = String::from_utf8_lossy(response.body()).into_owned();
    (response.status().as_u16(), support::element_text(&body, "Code").map(str::to_owned))
}
