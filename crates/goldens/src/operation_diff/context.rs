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

//! Harness for the request-context diff against the pinned s3s oracle.
//!
//! Responsible for: building one raw request — optionally SigV4-signed by the gateway's client
//! signer, optionally addressed to a virtual host — and sending the same bytes through (a) a real
//! assembled gateway service whose backend, like the RustFS ring-2 adapter, turns its handler's
//! request context into an `s3s::S3Request` context and records it, and (b) the pinned s3s service
//! with the matching auth and host configuration, whose handler records the `S3Request` it was
//! handed. Then comparing every context member of the two requests.
//! NOT responsible for: the input members (the sibling decode diff), body consumption, RustFS
//! extensions, or production wiring. Only exists under `cfg(test)` (rustfs/backlog#1762, second
//! slice; rustfs/backlog#1752).
//! Upstream: `rustfs-gateway` (service assembly, authenticator, host resolvers, the handler request
//! context), `rustfs-gateway-sig` (floor, signer), `compat::request_context`.
//! Downstream: the per-operation context proofs beside it.
//!
//! # What the gateway side reads, and from where
//!
//! Every context value comes from `Req::context()` inside the gateway handler (ADR-0022), and from
//! nothing else — the same single source the RustFS adapter has: the method and raw target, every
//! accepted header line through `iter_raw` (so an unrelated value that is not UTF-8 crosses
//! unchanged), the host region from the routed addressing, and the principal, its verified scope
//! and the secret the authenticator handed over. Nothing here re-runs a signature check or looks a
//! secret up a second time. The accepted `WireRequest` and the host classification are still built
//! beside the service, for the input decode the GetBucketLocation proof compares.

mod adapter_request;
mod admin_request;
mod answers;
mod body_parity;
mod error_parity;
mod get_bucket_location;
mod put_object;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method, Uri};
use rustfs_gateway::dto;
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Handler, HandlerContext, HandlerResult, HostQuery, HostResolver,
    InputAuthzRequest, InputDecisions, PathStyleOnly, Req, RequestContext, RequestContextView, ResolvedHost, Resp, S3Service,
    ServiceBuilder, SigV4Authenticator, StaticCredentials, VirtualHostStyle,
};
use rustfs_gateway_http::{Limits, RawHost, WireRequest};
use rustfs_gateway_sig::{
    AmzDate, PayloadMode, RegionSet, RequestNow, SecurityFloor, SigService, SigV4Signer, SigningCredentials, SigningRequest,
    SigningScope,
};

use self::adapter_request::adapter_request;
use self::answers::answers;
use super::{HOST, block_on, oracle, s3s};

/// The one credential both stacks' stores hold.
pub(crate) const ACCESS_KEY: &str = "AKIDCONTEXTDIFF";
pub(crate) const SECRET_KEY: &str = "context-diff-secret-key";
/// A secret neither store holds: a forged signature on the shared access key.
const FORGED_SECRET: &str = "not-the-context-diff-secret";
/// An access key neither store holds.
const UNKNOWN_ACCESS_KEY: &str = "AKIDNOTINANYSTORE";
/// The regions the gateway serves. Two, so a region that is merely the first is not a pass.
pub(crate) const REGIONS: [&str; 2] = ["us-east-1", "eu-west-1"];
/// The base domain both stacks are told when a request is virtual-hosted.
pub(crate) const BASE_DOMAIN: &str = "example.test";
/// A path-style authority, shared with the decode diff.
pub(crate) const PATH_HOST: &str = HOST;

/// An extension a transport layer put on the request before either stack saw it.
#[derive(Clone, Debug)]
pub(crate) struct TransportMarker;

/// One raw request, exactly as both stacks receive it.
#[derive(Clone, Debug)]
pub(crate) struct ContextRequest {
    method: Method,
    host: String,
    /// Percent-encoded path, starting at `/`.
    path: String,
    /// Query without its `?`; empty for none.
    query: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    pub(crate) body: Bytes,
    signing_region: Option<&'static str>,
    virtual_hosting: bool,
    transport_extension: bool,
    absolute_form: bool,
    empty_query_marker: bool,
    /// Whether the gateway authenticator hands the caller's secret to the handler (ADR-0022).
    secret_hand_off: bool,
    /// The access key the request is signed with.
    access_key: &'static str,
    /// The secret the request is signed with.
    secret_key: &'static str,
    /// Whether the gateway authenticator verifies any scope region (ADR-0023).
    any_region: bool,
}

impl ContextRequest {
    fn new(method: Method, host: &str, path: &str, query: &str, body: &[u8]) -> Self {
        Self {
            method,
            host: host.to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            headers: Vec::new(),
            body: Bytes::copy_from_slice(body),
            signing_region: None,
            virtual_hosting: false,
            transport_extension: false,
            absolute_form: false,
            empty_query_marker: false,
            secret_hand_off: true,
            access_key: ACCESS_KEY,
            secret_key: SECRET_KEY,
            any_region: false,
        }
    }

    /// A `PUT` of `body` to `path` on `host`.
    pub(crate) fn put(host: &str, path: &str, body: &[u8]) -> Self {
        Self::new(Method::PUT, host, path, "", body)
    }

    /// A bodiless `POST` of `path?query` on `host`.
    #[allow(
        dead_code,
        reason = "only the RustFS admin proof sends one, through the s3s_f3e17541 compilation"
    )]
    pub(crate) fn post(host: &str, path: &str, query: &str) -> Self {
        Self::new(Method::POST, host, path, query, b"")
    }

    /// A bodiless `DELETE` of `path?query` on `host`.
    #[allow(
        dead_code,
        reason = "only the RustFS admin dialect sends one, through the s3s_f3e17541 compilation"
    )]
    pub(crate) fn delete(host: &str, path: &str, query: &str) -> Self {
        Self::new(Method::DELETE, host, path, query, b"")
    }

    /// A bodiless `GET` of `path?query` on `host`.
    pub(crate) fn get(host: &str, path: &str, query: &str) -> Self {
        Self::new(Method::GET, host, path, query, b"")
    }

    /// Header-signs the request with the shared credential, scoped to `region`.
    pub(crate) fn signed(mut self, region: &'static str) -> Self {
        self.signing_region = Some(region);
        self
    }

    /// Tells both stacks about [`BASE_DOMAIN`].
    pub(crate) fn virtual_hosted(mut self) -> Self {
        self.virtual_hosting = true;
        self
    }

    /// Leaves the gateway authenticator at its default, which keeps the caller's secret to itself.
    pub(crate) fn without_secret_hand_off(mut self) -> Self {
        self.secret_hand_off = false;
        self
    }

    /// Signs with the shared access key and a secret neither store holds.
    pub(crate) fn forged(mut self) -> Self {
        self.secret_key = FORGED_SECRET;
        self
    }

    /// Signs with an access key neither store holds.
    pub(crate) fn unknown_key(mut self) -> Self {
        self.access_key = UNKNOWN_ACCESS_KEY;
        self
    }

    /// Gives the gateway authenticator the RustFS profile of rd-loc-0004 (ADR-0023): any scope
    /// region in the configured-name grammar is verified. s3s needs no switch; it never checks.
    pub(crate) fn rustfs_profile(mut self) -> Self {
        self.any_region = true;
        self
    }

    /// Adds one header line; the value may be any bytes a field value can hold.
    pub(crate) fn header(mut self, name: &str, value: &[u8]) -> Self {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("a fixture header name");
        let value = HeaderValue::from_bytes(value).expect("a fixture header value");
        self.headers.push((name, value));
        self
    }

    /// Puts a [`TransportMarker`] in the request extensions both stacks receive.
    pub(crate) fn with_transport_extension(mut self) -> Self {
        self.transport_extension = true;
        self
    }

    /// Sends the request target in absolute form (`http://host/path`).
    pub(crate) fn absolute_form(mut self) -> Self {
        self.absolute_form = true;
        self
    }

    /// Ends a query-less target with a bare `?`.
    pub(crate) fn empty_query_marker(mut self) -> Self {
        self.empty_query_marker = true;
        self
    }

    fn target(&self) -> String {
        let mut target = String::new();
        if self.absolute_form {
            target.push_str("http://");
            target.push_str(&self.host);
        }
        target.push_str(&self.path);
        if !self.query.is_empty() {
            target.push('?');
            target.push_str(&self.query);
        } else if self.empty_query_marker {
            target.push('?');
        }
        target
    }

    /// The header lines on the wire, signed at `now` when the request is signed.
    pub(crate) fn wire_headers(&self, now: RequestNow) -> Result<HeaderMap, String> {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_str(&self.host).map_err(|error| error.to_string())?);
        if self.method == Method::PUT {
            headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(self.body.len()));
        }
        for (name, value) in &self.headers {
            headers.append(name.clone(), value.clone());
        }
        let Some(region) = self.signing_region else {
            return Ok(headers);
        };
        let stamp = AmzDate::parse(&amz_date(now.unix_seconds())).map_err(|error| format!("stamp: {error:?}"))?;
        let scope = SigningScope::new(stamp.day(), region, SigService::S3).map_err(|error| format!("scope: {error:?}"))?;
        let credentials = SigningCredentials::new(self.access_key, self.secret_key.as_bytes())
            .map_err(|error| format!("credentials: {error:?}"))?;
        let mut signer = SigV4Signer::new(credentials, scope);
        let raw_host = RawHost::from_host_header(self.host.as_bytes()).map_err(|error| format!("host: {error:?}"))?;
        let mut signing =
            SigningRequest::new(&self.method, &self.path, &self.query, &headers, &raw_host, PayloadMode::Unsigned, stamp);
        if self.method == Method::PUT {
            signing = signing.with_wire_content_length(self.body.len() as u64);
        }
        let signed = signer.sign_headers(&signing).map_err(|error| format!("signing: {error:?}"))?;
        Ok(signed.headers().clone())
    }

    pub(crate) fn http_head(&self, headers: &HeaderMap) -> http::request::Builder {
        let mut builder = http::Request::builder().method(self.method.clone()).uri(self.target());
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if self.transport_extension {
            builder = builder.extension(TransportMarker);
        }
        builder
    }
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time. Both verifiers compare the stamp against their own clock,
/// so the fixture is signed now rather than at a fixed instant.
pub(crate) fn amz_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let second_of_day = unix.rem_euclid(86_400);
    // Civil-from-days (proleptic Gregorian), days counted from 1970-01-01.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        second_of_day / 3_600,
        second_of_day % 3_600 / 60,
        second_of_day % 60
    )
}

// ── the gateway side ──────────────────────────────────────────────────────────────────────────

/// What the gateway handler saw, and what it converted that into.
pub(crate) struct GatewaySide {
    /// The operation the handler was registered for, from its request context.
    pub(crate) operation: &'static str,
    /// The s3s request context the handler built from its request context alone, or why not.
    pub(crate) converted: Result<s3s::S3Request<()>, String>,
    /// The bucket the handler's request context names.
    pub(crate) bucket: Option<String>,
    /// The key the handler's request context names.
    pub(crate) key: Option<String>,
    /// The accepted request, for an input decode.
    pub(crate) wire: WireRequest<()>,
    /// The host classification, for an input decode.
    pub(crate) resolved: ResolvedHost,
}

/// What one handler call recorded.
struct Recorded {
    operation: &'static str,
    converted: Result<s3s::S3Request<()>, String>,
    bucket: Option<String>,
    key: Option<String>,
}

/// A gateway backend that records, for the one call it gets, what [`adapter_request`] made of the
/// handler's request context.
struct AdapterBackend {
    recorded: Arc<Mutex<Option<Recorded>>>,
}

impl AdapterBackend {
    fn record(&self, context: &RequestContextView) {
        let recorded = Recorded {
            operation: context.operation(),
            converted: adapter_request(context),
            bucket: context.bucket().map(|bucket| bucket.as_str().to_owned()),
            key: context.key().map(|key| key.as_str().to_owned()),
        };
        if let Ok(mut slot) = self.recorded.lock() {
            *slot = Some(recorded);
        }
    }
}

impl Handler<dto::PutObject> for AdapterBackend {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        self.record(request.context());
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }

    async fn call_with_context(&self, request: Req<dto::PutObject>, _context: HandlerContext) -> HandlerResult<dto::PutObject> {
        self.record(request.context());
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

impl Handler<dto::GetBucketLocation> for AdapterBackend {
    async fn call(&self, request: Req<dto::GetBucketLocation>) -> HandlerResult<dto::GetBucketLocation> {
        self.record(request.context());
        Ok(Resp::new(dto::GetBucketLocationOutput::default()))
    }

    async fn call_with_context(
        &self,
        request: Req<dto::GetBucketLocation>,
        _context: HandlerContext,
    ) -> HandlerResult<dto::GetBucketLocation> {
        self.record(request.context());
        Ok(Resp::new(dto::GetBucketLocationOutput::default()))
    }
}

/// Allows both stages: this diff is about what a handler sees, not about policy. RustFS's own
/// access check is the ring-2 authorizer's.
struct AllowEveryStage;

impl Authorizer for AllowEveryStage {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// The account that owns every fixture bucket.
pub(crate) const BUCKET_OWNER: &str = "111122223333";

/// Answers [`BUCKET_OWNER`] for every bucket. The gateway checks `x-amz-expected-bucket-owner` at
/// route authorization, before the handler, where RustFS checks it inside its own handler; a
/// deployment whose owner lookup agrees is the one in which both stacks reach their handler.
struct FixtureOwner;

impl rustfs_gateway::BucketOwnerSource for FixtureOwner {
    fn owner<'a>(
        &'a self,
        _bucket: &'a rustfs_gateway_types::BucketName,
    ) -> BoxFuture<'a, Result<Arc<str>, rustfs_gateway::BucketOwnerError>> {
        Box::pin(async { Ok(Arc::from(BUCKET_OWNER)) })
    }
}

/// The assembled gateway: the built-in SigV4 authenticator over the shared credential, the
/// virtual-host resolver when the request is virtual-hosted, [`FixtureOwner`], and anonymous
/// admission delegated to the authorizer (ADR-0021), because RustFS admits every anonymous request
/// to its access hook.
fn gateway_service(request: &ContextRequest, recorded: &Arc<Mutex<Option<Recorded>>>) -> Result<S3Service, String> {
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).map_err(|error| format!("credential: {error:?}"))?;
    let regions = RegionSet::new(REGIONS).map_err(|error| format!("regions: {error:?}"))?;
    let mut authenticator = SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(credentials)), regions);
    if request.secret_hand_off {
        authenticator = authenticator.hand_caller_secret_to_handlers();
    }
    if request.any_region {
        authenticator = authenticator.accept_any_signing_region();
    }
    let backend = Arc::new(AdapterBackend {
        recorded: Arc::clone(recorded),
    });
    let mut builder = ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(AllowEveryStage)
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .bucket_owner_source(FixtureOwner)
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::GetBucketLocation, _>(backend);
    // The seam fills s3s's `Credentials` for every handler it wraps and refuses to invent the
    // secret, so the migration adapter widens the hand-off to every operation (ADR-0024).
    if request.secret_hand_off {
        builder = builder.hand_caller_secret_to_every_operation_after_listing_in_the_posture_report();
    }
    if request.virtual_hosting {
        builder = builder.host_resolver(VirtualHostStyle::new([BASE_DOMAIN]).map_err(|error| format!("base domain: {error:?}"))?);
    }
    builder.build().map_err(|error| format!("assembly: {error:?}"))
}

fn resolve(request: &ContextRequest, wire: &WireRequest<()>) -> Result<ResolvedHost, String> {
    let query = HostQuery {
        host: wire.host(),
        path: wire.raw_path().as_str(),
        method: wire.method(),
    };
    if request.virtual_hosting {
        let resolver = VirtualHostStyle::new([BASE_DOMAIN]).map_err(|error| format!("base domain: {error:?}"))?;
        Ok(resolver.resolve(&query))
    } else {
        Ok(PathStyleOnly.resolve(&query))
    }
}

/// Sends `request` through the assembled gateway and returns what its handler saw.
///
/// # Errors
///
/// The stage that refused, and why. A refusal before the handler comes back with its status.
pub(crate) fn gateway_side(request: &ContextRequest, headers: &HeaderMap) -> Result<GatewaySide, String> {
    let head = request
        .http_head(headers)
        .body(())
        .map_err(|error| format!("fixture head: {error}"))?;
    let wire = WireRequest::accept(head, &Limits::default()).map_err(|error| format!("wire refusal: {error:?}"))?;
    let resolved = resolve(request, &wire)?;

    let recorded = Arc::new(Mutex::new(None));
    let service = gateway_service(request, &recorded)?;
    let http_request = request
        .http_head(headers)
        .body(request.body.clone())
        .map_err(|error| format!("fixture head: {error}"))?;
    let status = block_on(service.call_bytes(http_request)).status().as_u16();
    let Recorded {
        operation,
        converted,
        bucket,
        key,
    } = recorded
        .lock()
        .map_err(|_| "the recording slot is poisoned".to_owned())?
        .take()
        .ok_or_else(|| format!("the gateway refused before its handler with status {status}"))?;
    Ok(GatewaySide {
        operation,
        converted,
        bucket,
        key,
        wire,
        resolved,
    })
}

// ── the s3s side ──────────────────────────────────────────────────────────────────────────────

/// The input an s3s handler was handed, for whichever operation it was.
pub(crate) enum CapturedInput {
    Put(Box<oracle::PutObjectInput>),
    Location(oracle::GetBucketLocationInput),
}

/// The whole request an s3s handler was handed.
pub(crate) type OracleRequest = s3s::S3Request<CapturedInput>;

/// An s3s backend that records the request of the one call it gets.
struct ContextS3 {
    captured: Arc<Mutex<Option<OracleRequest>>>,
}

impl ContextS3 {
    fn record(&self, request: OracleRequest) {
        if let Ok(mut slot) = self.captured.lock() {
            *slot = Some(request);
        }
    }
}

type Answer<'a, T> = Pin<Box<dyn Future<Output = s3s::S3Result<s3s::S3Response<T>>> + Send + 'a>>;

impl s3s::S3 for ContextS3 {
    // The pinned trait is declared with `#[async_trait]`; these are the signatures that attribute
    // expands a `&self` method to, spelled out so the harness needs no proc-macro dependency.
    fn put_object<'life0, 'future>(
        &'life0 self,
        request: s3s::S3Request<oracle::PutObjectInput>,
    ) -> Answer<'future, oracle::PutObjectOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record(request.map_input(|input| CapturedInput::Put(Box::new(input))));
        Box::pin(async { Ok(s3s::S3Response::new(oracle::PutObjectOutput::default())) })
    }

    fn get_bucket_location<'life0, 'future>(
        &'life0 self,
        request: s3s::S3Request<oracle::GetBucketLocationInput>,
    ) -> Answer<'future, oracle::GetBucketLocationOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        self.record(request.map_input(CapturedInput::Location));
        Box::pin(async { Ok(s3s::S3Response::new(oracle::GetBucketLocationOutput::default())) })
    }
}

/// Sends `request` with `headers` through the pinned s3s service, configured with the shared
/// credential when the request is signed and with [`BASE_DOMAIN`] when it is virtual-hosted.
///
/// # Errors
///
/// A harness failure. A refusal comes back as a status with no recorded request.
pub(crate) fn s3s_side(request: &ContextRequest, headers: &HeaderMap) -> Result<(u16, Option<OracleRequest>), String> {
    let (status, _body, recorded) = s3s_answer(request, headers)?;
    Ok((status, recorded))
}

/// [`s3s_side`], with the response body.
fn s3s_answer(request: &ContextRequest, headers: &HeaderMap) -> Result<(u16, Vec<u8>, Option<OracleRequest>), String> {
    let captured = Arc::new(Mutex::new(None));
    let mut builder = s3s::service::S3ServiceBuilder::new(ContextS3 {
        captured: Arc::clone(&captured),
    });
    if request.signing_region.is_some() {
        builder.set_auth(s3s::auth::SimpleAuth::from_single(ACCESS_KEY, SECRET_KEY));
    }
    if request.virtual_hosting {
        builder.set_host(s3s::host::MultiDomain::new([BASE_DOMAIN]).map_err(|error| format!("base domain: {error:?}"))?);
    }
    let service = builder.build();
    let body = if request.body.is_empty() {
        s3s::Body::empty()
    } else {
        s3s::Body::from(request.body.clone())
    };
    let http_request = request
        .http_head(headers)
        .body(body)
        .map_err(|error| format!("fixture head: {error}"))?;
    let response = block_on(service.call(http_request)).map_err(|error| format!("s3s service failed: {error:?}"))?;
    let (parts, mut body) = response.into_parts();
    let body = block_on(body.store_all_limited(1 << 20)).map_err(|error| format!("s3s response body: {error}"))?;
    let recorded = captured
        .lock()
        .map_err(|_| "the recording slot is poisoned".to_owned())?
        .take();
    Ok((parts.status.as_u16(), body.to_vec(), recorded))
}

// ── both ──────────────────────────────────────────────────────────────────────────────────────

/// One request through both stacks.
pub(crate) struct Exchange {
    pub(crate) gateway: GatewaySide,
    pub(crate) oracle_status: u16,
    pub(crate) oracle: Option<OracleRequest>,
}

/// Signs `request` once, then sends the same bytes to both stacks.
///
/// # Errors
///
/// The first stage on either side that refused.
pub(crate) fn exchange(request: &ContextRequest) -> Result<Exchange, String> {
    let now = RequestNow::capture();
    let headers = request.wire_headers(now)?;
    let gateway = gateway_side(request, &headers)?;
    let (oracle_status, oracle) = s3s_side(request, &headers)?;
    Ok(Exchange {
        gateway,
        oracle_status,
        oracle,
    })
}

/// Both requests, once the gateway handler has built its s3s context.
pub(crate) struct Compared {
    pub(crate) operation: &'static str,
    pub(crate) converted: s3s::S3Request<()>,
    pub(crate) oracle: OracleRequest,
    pub(crate) bucket: Option<String>,
    pub(crate) key: Option<String>,
    pub(crate) wire: WireRequest<()>,
    pub(crate) resolved: ResolvedHost,
}

/// [`exchange`], requiring both stacks to have reached their handler and the gateway handler's
/// conversion to have succeeded.
///
/// # Errors
///
/// A refusal on either side, or a conversion refusal.
pub(crate) fn compare(request: &ContextRequest) -> Result<Compared, String> {
    let Exchange {
        gateway,
        oracle_status,
        oracle,
    } = exchange(request)?;
    let GatewaySide {
        operation,
        converted,
        bucket,
        key,
        wire,
        resolved,
    } = gateway;
    let converted = converted?;
    let oracle = oracle.ok_or_else(|| format!("s3s refused before its handler with status {oracle_status}"))?;
    Ok(Compared {
        operation,
        converted,
        oracle,
        bucket,
        key,
        wire,
        resolved,
    })
}

// ── the comparison ────────────────────────────────────────────────────────────────────────────

/// Declares the compared members once and derives the comparison and the census from it.
///
/// The pattern names every member of the pinned `S3Request` with no `..`, so an s3s re-pin that
/// adds a context member is a compile error here rather than a member nobody compares.
macro_rules! context_members {
    ($($member:ident => $same:path),+ $(,)?) => {
        /// Every context member the diff compares, in s3s declaration order.
        pub(crate) const COMPARED_MEMBERS: &[&str] = &[$(stringify!($member)),+];

        /// The context members on which two s3s requests disagree. Inputs are compared by the
        /// decode diff, not here; secrets are compared without being printed.
        pub(crate) fn differing_context<A, B>(left: &s3s::S3Request<A>, right: &s3s::S3Request<B>) -> Vec<&'static str> {
            let s3s::S3Request { input: _, $($member: _),+ } = left;
            let mut differing = Vec::new();
            $( if !$same(&left.$member, &right.$member) { differing.push(stringify!($member)); } )+
            differing
        }
    };
}

context_members!(
    method => same_method,
    uri => same_uri,
    headers => same_headers,
    extensions => same_extensions,
    credentials => same_credentials,
    region => same_region,
    service => same_service,
    trailing_headers => same_trailers,
);

fn same_method(left: &Method, right: &Method) -> bool {
    left == right
}

fn same_uri(left: &Uri, right: &Uri) -> bool {
    left == right
}

/// Same names, and per name the same values in the same order.
fn same_headers(left: &HeaderMap, right: &HeaderMap) -> bool {
    left == right
}

/// Extensions are type-keyed and opaque; the count is what both sides can be held to, and every
/// equal case in the diff has zero on both.
fn same_extensions(left: &Extensions, right: &Extensions) -> bool {
    left.len() == right.len()
}

fn same_credentials(left: &Option<s3s::auth::Credentials>, right: &Option<s3s::auth::Credentials>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.access_key == right.access_key
                && same_secret(left.secret_key.expose().as_bytes(), right.secret_key.expose().as_bytes())
        }
        _ => false,
    }
}

/// No early exit on the first differing byte, so even the harness never models a short-circuiting
/// comparison of key material.
fn same_secret(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).fold(0_u8, |acc, (l, r)| acc | (l ^ r)) == 0
}

fn same_region(left: &Option<s3s::region::Region>, right: &Option<s3s::region::Region>) -> bool {
    left.as_ref().map(s3s::region::Region::as_str) == right.as_ref().map(s3s::region::Region::as_str)
}

fn same_service(left: &Option<String>, right: &Option<String>) -> bool {
    left == right
}

/// The handle is opaque; whether one was delivered is what an app body branches on.
fn same_trailers(left: &Option<s3s::TrailingHeaders>, right: &Option<s3s::TrailingHeaders>) -> bool {
    left.is_some() == right.is_some()
}

/// The access key of a request's credentials, if it has any.
pub(crate) fn access_key<T>(request: &s3s::S3Request<T>) -> Option<&str> {
    request
        .credentials
        .as_ref()
        .map(|credentials| credentials.access_key.as_str())
}

/// The region of a request, if it has one.
pub(crate) fn region_of<T>(request: &s3s::S3Request<T>) -> Option<&str> {
    request.region.as_ref().map(s3s::region::Region::as_str)
}
