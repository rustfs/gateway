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
//! signer, optionally addressed to a virtual host — and sending the same bytes through (a) the
//! gateway's real acceptance, host resolution, route table, security floor and SigV4
//! authenticator, from whose results it assembles a `GatewayRequestContext`, and (b) the pinned
//! s3s service with the matching auth and host configuration, whose handler records the
//! `S3Request` it was handed. Then comparing every context member of the two requests.
//! NOT responsible for: the input members (the sibling decode diff), body consumption, RustFS
//! extensions, or production wiring. Only exists under `cfg(test)` (rustfs/backlog#1762, second
//! slice; rustfs/backlog#1752).
//! Upstream: `rustfs-gateway` (authenticator, host resolvers), `rustfs-gateway-sig` (floor, scope,
//! signer), `rustfs-gateway-core` (route table, meta view), `compat::request_context`.
//! Downstream: the per-operation context proofs beside it.
//!
//! # What the gateway side assembles, and from where
//!
//! Every value comes from a gateway component that already computed it for this request: the
//! method, raw path and raw query from `WireRequest`; the headers from its text view (the wire
//! layer publishes no header map); the host region from the resolver; the principal from the
//! authenticator's verdict. One value does **not** survive the gateway pipeline: the verified
//! credential scope. `Verdict::Authenticated` carries the identity and the scheme, not the region
//! or service the signature was scoped to, so the harness re-runs the signature crate's own
//! `enforce_scope` on the same header — the check the authenticator ran — and a production adapter
//! would need the gateway to expose that value first.

mod get_bucket_location;
mod put_object;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{Extensions, HeaderMap, HeaderName, HeaderValue, Method, Uri};
use rustfs_gateway::{
    Addressing, Authentication, Authenticator, Credentials, HostQuery, HostResolver, PathStyleOnly, ResolvedHost,
    SigV4Authenticator, StaticCredentials, VirtualHostStyle,
};
use rustfs_gateway_core::codec::MetaView;
use rustfs_gateway_core::route::RouteRequestParts;
use rustfs_gateway_http::{Limits, RawHost, WireRequest};
use rustfs_gateway_sig::{
    Admission, AmzDate, ExpectedScope, OperationFloor, PayloadMode, RawQuery, RegionSet, RequestNow, SecurityFloor, SigService,
    SigV4Authorization, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, SkewWindow, TrailerSet, WireView,
    enforce_clock_skew, enforce_scope,
};
use rustfs_gateway_types::compat::request_context::{GatewayRequestContext, Principal, VerifiedScope, request_to_s3s};

use super::{HOST, block_on, oracle, route_table, s3s};

/// The one credential both stacks' stores hold.
pub(crate) const ACCESS_KEY: &str = "AKIDCONTEXTDIFF";
const SECRET_KEY: &str = "context-diff-secret-key";
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
    body: Bytes,
    signing_region: Option<&'static str>,
    virtual_hosting: bool,
    transport_extension: bool,
    absolute_form: bool,
    empty_query_marker: bool,
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
        }
    }

    /// A `PUT` of `body` to `path` on `host`.
    pub(crate) fn put(host: &str, path: &str, body: &[u8]) -> Self {
        Self::new(Method::PUT, host, path, "", body)
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
    fn wire_headers(&self, now: RequestNow) -> Result<HeaderMap, String> {
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
        let credentials =
            SigningCredentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).map_err(|error| format!("credentials: {error:?}"))?;
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

    fn http_head(&self, headers: &HeaderMap) -> http::request::Builder {
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
fn amz_date(unix: i64) -> String {
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

/// What the gateway pipeline knows about one request once it is routed and authenticated.
pub(crate) struct GatewaySide {
    /// The operation the route table chose.
    pub(crate) operation: &'static str,
    /// The facts the context conversion takes.
    pub(crate) context: GatewayRequestContext,
    /// The bucket the one meta view decided, from the host or the path.
    pub(crate) bucket: Option<String>,
    /// The key the one meta view decided.
    pub(crate) key: Option<String>,
    /// The accepted request, for an input decode.
    pub(crate) wire: WireRequest<()>,
    /// The host classification the meta view was built from.
    pub(crate) resolved: ResolvedHost,
}

fn authenticator() -> SigV4Authenticator {
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("a valid fixture credential");
    SigV4Authenticator::new(
        Arc::new(StaticCredentials::new().with(credentials)),
        RegionSet::new(REGIONS).expect("a non-empty region set"),
    )
}

/// The secret the shared store holds for `access_key` — the same store the authenticator and the
/// s3s auth were built from.
fn stored_secret(access_key: &str) -> Result<s3s::auth::SecretKey, String> {
    if access_key == ACCESS_KEY {
        Ok(SECRET_KEY.into())
    } else {
        Err(format!("no stored credential for {access_key}"))
    }
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

/// Runs the security floor and, for a sealed request, the built-in SigV4 authenticator.
fn authenticate(
    wire: &WireRequest<()>,
    headers: &HeaderMap,
    operation: &'static str,
    now: RequestNow,
) -> Result<Option<Principal>, String> {
    let view = WireView::new(headers, RawQuery::new(wire.query().as_str()));
    // The gateway admits an anonymous caller only for an operation a deployment opted in for;
    // RustFS admits every anonymous request to its access hook and decides there. The harness
    // makes that opt-in explicitly so an anonymous request reaches the same point on both stacks.
    let floor = OperationFloor::builtin(operation, SigService::S3).allow_anonymous_after_listing_in_the_posture_report();
    let sealed = match SecurityFloor::new().admit(view, &floor, now) {
        Ok(Admission::Anonymous(_)) => return Ok(None),
        Ok(Admission::Sealed(sealed)) => sealed,
        Ok(_) => return Err("the floor admitted a scheme this harness does not drive".to_owned()),
        Err(error) => return Err(format!("floor refusal: {error:?}")),
    };
    let token = header_text(headers, "x-amz-content-sha256")?;
    let payload = PayloadMode::parse(token, TrailerSet::None).map_err(|error| format!("payload mode: {error:?}"))?;
    let question = Authentication::new(
        &sealed,
        wire.method(),
        wire.raw_path().as_str(),
        wire.host().raw_for_signing(),
        &payload,
        wire.framing().declared_length(),
    );
    let outcome = block_on(authenticator().authenticate(&question)).map_err(|_| "credential store outage".to_owned())?;
    let identity = outcome
        .verdict()
        .identity()
        .ok_or_else(|| format!("authentication refused: {:?}", outcome.verdict().rejection()))?;

    // The verdict names who, not the scope. Re-derive the verified scope with the check the
    // authenticator itself ran; see the module documentation.
    let authorization =
        SigV4Authorization::parse(header_text(headers, "authorization")?).map_err(|error| format!("authorization: {error:?}"))?;
    let signed_at = AmzDate::parse(header_text(headers, "x-amz-date")?).map_err(|error| format!("x-amz-date: {error:?}"))?;
    let clock = enforce_clock_skew(&signed_at, now, SkewWindow::DEFAULT).map_err(|error| format!("clock: {error:?}"))?;
    let regions = RegionSet::new(REGIONS).map_err(|error| format!("regions: {error:?}"))?;
    let verified = enforce_scope(authorization.scope(), clock, &ExpectedScope::new(SigService::S3, &regions))
        .map_err(|error| format!("scope: {error:?}"))?;
    Ok(Some(Principal {
        access_key: identity.access_key_id().to_owned(),
        secret_key: stored_secret(identity.access_key_id())?,
        scope: Some(VerifiedScope {
            region: verified.region().to_owned(),
            service: verified.service().to_owned(),
        }),
    }))
}

fn header_text<'h>(headers: &'h HeaderMap, name: &str) -> Result<&'h str, String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| format!("the signed fixture has no readable {name}"))
}

/// Accepts, resolves, routes and authenticates `request` as the gateway pipeline does, and
/// assembles the context the conversion takes from what those stages produced.
///
/// # Errors
///
/// The stage that refused, and why.
pub(crate) fn gateway_side(request: &ContextRequest, headers: &HeaderMap, now: RequestNow) -> Result<GatewaySide, String> {
    let head = request
        .http_head(headers)
        .body(())
        .map_err(|error| format!("fixture head: {error}"))?;
    let wire = WireRequest::accept(head, &Limits::default()).map_err(|error| format!("wire refusal: {error:?}"))?;
    let resolved = resolve(request, &wire)?;
    let operation = route_table()
        .resolve(&RouteRequestParts {
            method: wire.method(),
            path: wire.raw_path().as_str(),
            target: resolved.target,
            host_class: resolved.host_class,
            arn_form: resolved.arn_form,
            query: wire.query(),
            headers: wire.headers(),
        })
        .map(|entry| entry.op_name)
        .ok_or_else(|| "the route table names no operation".to_owned())?;
    let (bucket, key) = {
        let meta = MetaView::addressed(&wire, resolved.target, resolved.bucket().cloned())
            .map_err(|error| format!("meta view: {}", error.code().as_str()))?;
        (
            meta.bucket().map(|bucket| bucket.as_str().to_owned()),
            meta.key().map(|key| key.as_str().to_owned()),
        )
    };
    let principal = authenticate(&wire, headers, operation, now)?;
    let mut readable = HeaderMap::new();
    for (name, text) in wire.headers().iter_text() {
        let value = HeaderValue::from_bytes(text.as_bytes()).map_err(|error| error.to_string())?;
        readable.append(name.clone(), value);
    }
    let host_region = match &resolved.addressing {
        Addressing::VirtualHosted { region, .. } => region.as_deref().map(str::to_owned),
        Addressing::Path => None,
    };
    let declares_trailers = wire.headers().get_bytes(&HeaderName::from_static("x-amz-trailer")).is_some();
    let context = GatewayRequestContext {
        method: wire.method().clone(),
        raw_path: wire.raw_path().as_str().to_owned(),
        raw_query: wire.query().as_str().to_owned(),
        headers: readable,
        principal,
        host_region,
        declares_trailers,
    };
    Ok(GatewaySide {
        operation,
        context,
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
    let recorded = captured
        .lock()
        .map_err(|_| "the recording slot is poisoned".to_owned())?
        .take();
    Ok((response.status().as_u16(), recorded))
}

// ── both ──────────────────────────────────────────────────────────────────────────────────────

/// One request through both stacks, before any conversion.
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
    let gateway = gateway_side(request, &headers, now)?;
    let (oracle_status, oracle) = s3s_side(request, &headers)?;
    Ok(Exchange {
        gateway,
        oracle_status,
        oracle,
    })
}

/// Both requests, once the gateway side has gone through the context conversion.
pub(crate) struct Compared {
    pub(crate) operation: &'static str,
    pub(crate) converted: s3s::S3Request<()>,
    pub(crate) oracle: OracleRequest,
    pub(crate) bucket: Option<String>,
    pub(crate) key: Option<String>,
    pub(crate) wire: WireRequest<()>,
    pub(crate) resolved: ResolvedHost,
}

/// [`exchange`], then the conversion, requiring both stacks to have reached their handler.
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
    let oracle = oracle.ok_or_else(|| format!("s3s refused before its handler with status {oracle_status}"))?;
    let GatewaySide {
        operation,
        context,
        bucket,
        key,
        wire,
        resolved,
    } = gateway;
    let converted = request_to_s3s(context, ()).map_err(|error| format!("conversion refused: {error}"))?;
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
