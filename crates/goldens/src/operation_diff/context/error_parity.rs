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

//! Harness for the error-document parity diff: what the gateway and the s3s service write when
//! they refuse the same raw request (rustfs/backlog#1762, error-document slice).
//!
//! Responsible for: signing one raw request once — by header, by presigned query, at a skewed
//! clock, with its `Content-Length` exact, declared or omitted — and sending the same bytes through
//! (a) an assembled gateway whose backend answers the way the RustFS ring-2 adapter does, by
//! mapping the RustFS body's `s3s::S3Error` through `compat::error::refusal_from_s3s`, and (b) the
//! s3s service with authentication configured, whose handler returns that same error; then reading
//! each answer's status, head, `<Error>` elements and connection verdict.
//! NOT responsible for: any assertion (`matrix` and `divergences` beside it), the handler context
//! (the parent), or RustFS storage: "what the RustFS body answers" is a scripted s3s error.
//! Upstream: the parent (request, credential, owner source), `compat::error`.
//! Downstream: `error_parity::matrix`, `error_parity::divergences`.
//!
//! # What each side stands in for
//!
//! Both stacks reach the same scripted body only after their own refusals had their chance, so a
//! refusal before the handler is the stack's own, and one after it is the body's as each stack
//! renders it. The s3s side writes no `Content-Length`: hyper frames a complete body from its exact
//! length, and [`Reply::wire_length`] models exactly that. It writes no request id either: RustFS
//! adds `x-amz-request-id` in a tower layer outside s3s (`rustfs/src/server/layer.rs`), which the
//! divergence register records.

mod divergences;
mod facts;
mod mapping;
mod matrix;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use http::{HeaderMap, HeaderValue, Method};
use rustfs_gateway::dto;
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Handler, HandlerError, HandlerErrorContext, HandlerResult,
    InputAuthzRequest, InputDecisions, MissingObject, Req, RequestContext, RequestContextView, ResourceVisibility, Resp,
    S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials, connection_intent_of,
};
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{
    AmzDate, PayloadMode, RegionSet, RequestNow, SecurityFloor, SigService, SigV4Signer, SigningCredentials, SigningRequest,
    SigningScope,
};

use super::super::seam::error::{Refusal, refusal_from_s3s};
use super::{ACCESS_KEY, Answer, ContextRequest, FixtureOwner, REGIONS, SECRET_KEY, amz_date, block_on, oracle, s3s};

/// What the RustFS app body answers once a request reaches it, on either stack.
#[derive(Clone, Copy)]
pub(crate) enum AppBody {
    /// The operation's default output.
    Succeeds,
    /// This error: s3s writes it, the gateway adapter maps it through the seam.
    Refuses(fn() -> s3s::S3Error),
}

/// How the request's `Content-Length` is written.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Length {
    /// The body's length on a `PUT`, none otherwise.
    Exact,
    /// No header, whatever the body.
    Omitted,
    /// This value, whatever the body.
    Declared(u64),
}

/// One refusal scenario: the raw request, how it is signed, and what the app body answers.
#[derive(Clone)]
pub(crate) struct Scenario {
    request: ContextRequest,
    presign_expiry: Option<u64>,
    clock_offset_seconds: i64,
    length: Length,
    body: AppBody,
}

impl Scenario {
    /// `request`, header-signed when it was built signed, whose app body succeeds.
    pub(crate) fn new(request: ContextRequest) -> Self {
        Self {
            request,
            presign_expiry: None,
            clock_offset_seconds: 0,
            length: Length::Exact,
            body: AppBody::Succeeds,
        }
    }

    /// Signs by presigned query, valid for `seconds`, instead of by header.
    pub(crate) fn presigned(mut self, seconds: u64) -> Self {
        self.presign_expiry = Some(seconds);
        self
    }

    /// Signs at the present moved by `seconds`; both verifiers still read their own clock.
    pub(crate) fn signed_at_offset(mut self, seconds: i64) -> Self {
        self.clock_offset_seconds = seconds;
        self
    }

    /// Writes `Content-Length` as `length` says.
    pub(crate) fn length(mut self, length: Length) -> Self {
        self.length = length;
        self
    }

    /// The RustFS body answers with this error on both stacks.
    pub(crate) fn app_refuses(mut self, error: fn() -> s3s::S3Error) -> Self {
        self.body = AppBody::Refuses(error);
        self
    }

    fn wire_length(&self) -> Option<u64> {
        match self.length {
            Length::Exact if self.request.method == Method::PUT => Some(self.request.body.len() as u64),
            Length::Exact | Length::Omitted => None,
            Length::Declared(value) => Some(value),
        }
    }

    /// The request target and header lines on the wire, signed at `now` moved by the offset.
    fn wire(&self, now: RequestNow) -> Result<(String, HeaderMap), String> {
        let request = &self.request;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::HOST,
            HeaderValue::from_str(&request.host).map_err(|error| error.to_string())?,
        );
        if let Some(length) = self.wire_length() {
            headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(length));
        }
        for (name, value) in &request.headers {
            headers.append(name.clone(), value.clone());
        }
        let target = request.target();
        let Some(region) = request.signing_region else {
            return Ok((target, headers));
        };
        let stamp = AmzDate::parse(&amz_date(now.unix_seconds() + self.clock_offset_seconds))
            .map_err(|error| format!("stamp: {error:?}"))?;
        let scope = SigningScope::new(stamp.day(), region, SigService::S3).map_err(|error| format!("scope: {error:?}"))?;
        let credentials = SigningCredentials::new(request.access_key, request.secret_key.as_bytes())
            .map_err(|error| format!("credentials: {error:?}"))?;
        let mut signer = SigV4Signer::new(credentials, scope);
        let raw_host = RawHost::from_host_header(request.host.as_bytes()).map_err(|error| format!("host: {error:?}"))?;
        let mut signing = SigningRequest::new(
            &request.method,
            &request.path,
            &request.query,
            &headers,
            &raw_host,
            PayloadMode::Unsigned,
            stamp,
        );
        if let Some(length) = self.wire_length() {
            signing = signing.with_wire_content_length(length);
        }
        let signed = match self.presign_expiry {
            None => signer.sign_headers(&signing),
            Some(seconds) => signer.presign(&signing, seconds),
        }
        .map_err(|error| format!("signing: {error:?}"))?;
        Ok((signed.target(), signed.headers().clone()))
    }
}

/// What one stack answered.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    /// Lowercase name to every value line, in arrival order.
    pub(crate) headers: BTreeMap<String, Vec<String>>,
    pub(crate) body: String,
    /// Whether the app body ran.
    pub(crate) reached: bool,
    /// The gateway's connection verdict. `None` on s3s, whose service states none and leaves the
    /// connection to hyper.
    pub(crate) closes: Option<bool>,
}

impl Reply {
    /// The only value of one header.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        match self.headers.get(name).map(Vec::as_slice) {
            Some([value]) => Some(value),
            _ => None,
        }
    }

    /// The text of one `<Error>` child element.
    pub(crate) fn element(&self, name: &str) -> Option<&str> {
        let open = format!("<{name}>");
        let start = self.body.find(&open)? + open.len();
        let end = self.body.get(start..)?.find(&format!("</{name}>"))? + start;
        self.body.get(start..end)
    }

    pub(crate) fn code(&self) -> Option<&str> {
        self.element("Code")
    }

    pub(crate) fn message(&self) -> Option<&str> {
        self.element("Message")
    }

    /// The names of the `<Error>` children, in document order.
    pub(crate) fn elements(&self) -> Vec<&str> {
        let Some(start) = self.body.find("<Error") else {
            return Vec::new();
        };
        let Some(open_end) = self.body[start..].find('>') else {
            return Vec::new();
        };
        let mut rest = &self.body[start + open_end + 1..];
        let mut names = Vec::new();
        while let Some(open) = rest.find('<') {
            rest = &rest[open + 1..];
            if rest.starts_with('/') {
                break;
            }
            let Some(name_end) = rest.find(['>', ' ', '/']) else { break };
            let name = &rest[..name_end];
            names.push(name);
            let close = format!("</{name}>");
            let Some(after) = rest.find(&close) else { break };
            rest = &rest[after + close.len()..];
        }
        names
    }

    /// `Content-Length` as the client receives it: the header the stack wrote, else the exact
    /// length hyper frames a complete body with. A bodyless status gets neither.
    pub(crate) fn wire_length(&self) -> Option<usize> {
        if let Some(value) = self.header("content-length") {
            return value.parse().ok();
        }
        let bodyless = matches!(self.status, 100..=199 | 204 | 304);
        (!bodyless).then_some(self.body.len())
    }
}

fn header_lines(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut lines: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        lines
            .entry(name.as_str().to_owned())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    lines
}

/// Both answers to one scenario.
#[derive(Debug)]
pub(crate) struct Pair {
    pub(crate) gateway: Reply,
    pub(crate) oracle: Reply,
}

/// Signs `scenario` once and sends the same bytes to both stacks.
///
/// # Errors
///
/// A harness failure; every refusal is a [`Reply`].
pub(crate) fn both(scenario: &Scenario) -> Result<Pair, String> {
    let (target, headers) = scenario.wire(RequestNow::capture())?;
    Ok(Pair {
        gateway: gateway_reply(scenario, &target, &headers)?,
        oracle: s3s_reply(scenario, &target, &headers)?,
    })
}

fn head(scenario: &Scenario, target: &str, headers: &HeaderMap) -> http::request::Builder {
    let mut builder = http::Request::builder().method(scenario.request.method.clone()).uri(target);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder
}

// ── the gateway side ──────────────────────────────────────────────────────────────────────────

/// The adapter's own `500` when the seam refuses an error: distinct from the gateway's resolution
/// of a bare contextual code, so a pin can tell which of the two refused.
pub(crate) const SEAM_REFUSED: &str = "the handler error has no gateway rendering";

/// The RustFS ring-2 adapter's error half: the gateway refusal for the RustFS body's s3s error, one
/// seam verdict to one gateway constructor. The adapter supplies what only the request holds: the
/// key, and the `Range` a `416` names.
pub(crate) fn adapter_error(error: &s3s::S3Error, context: &RequestContextView) -> HandlerError {
    let missing = |kind| match context.key() {
        Some(key) => HandlerErrorContext::missing_object_for(key.clone(), kind, ResourceVisibility::Visible),
        None => HandlerErrorContext::missing_object(kind, ResourceVisibility::Visible),
    };
    let refused = || HandlerError::internal_error(SEAM_REFUSED);
    match refusal_from_s3s(error) {
        Ok(Refusal::Ordinary { code, message }) => HandlerError::new(code, message),
        Ok(Refusal::MissingBucket) => HandlerErrorContext::missing_bucket().into(),
        Ok(Refusal::MissingKey) => missing(MissingObject::Key).into(),
        Ok(Refusal::MissingVersion) => missing(MissingObject::Version).into(),
        Ok(Refusal::NotModified { etag }) => HandlerErrorContext::not_modified(etag).into(),
        Ok(Refusal::UnsatisfiableRange { complete_length }) => match context.headers().get_str(&http::header::RANGE) {
            Some(range) => HandlerError::unsatisfiable_range(range.to_owned(), complete_length),
            None => refused(),
        },
        Ok(Refusal::CurrentDeleteMarker {
            version_id,
            last_modified,
        }) => HandlerErrorContext::current_delete_marker(
            ResourceVisibility::Visible,
            context.key().cloned(),
            &version_id,
            last_modified,
        )
        .map_or_else(|_| refused(), Into::into),
        Ok(Refusal::VersionedDeleteMarker {
            version_id,
            last_modified,
        }) => HandlerErrorContext::versioned_delete_marker(&version_id, last_modified).map_or_else(|_| refused(), Into::into),
        Err(_) => refused(),
    }
}

/// A gateway backend that answers every operation the scenario can reach as the adapter would.
struct ParityBackend {
    body: AppBody,
    reached: Arc<AtomicBool>,
}

impl ParityBackend {
    fn answer<O: rustfs_gateway::Operation>(&self, request: &Req<O>) -> HandlerResult<O>
    where
        O::Output: Default,
    {
        self.reached.store(true, Ordering::SeqCst);
        match self.body {
            AppBody::Succeeds => Ok(Resp::new(O::Output::default())),
            AppBody::Refuses(error) => Err(adapter_error(&error(), request.context())),
        }
    }
}

macro_rules! parity_handlers {
    ($($operation:ident),+ $(,)?) => {$(
        impl Handler<dto::$operation> for ParityBackend {
            async fn call(&self, request: Req<dto::$operation>) -> HandlerResult<dto::$operation> {
                self.answer(&request)
            }
        }
    )+};
}

parity_handlers!(PutObject, GetBucketLocation, GetObject, HeadObject, PutBucketVersioning, UploadPart);

/// Refuses an anonymous caller at the route stage, as RustFS's access hook refuses one on a private
/// bucket, and allows every signed one.
struct DenyAnonymous;

impl Authorizer for DenyAnonymous {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, _request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = if context.verified_scope().is_some() {
            Decision::Allow
        } else {
            Decision::Deny
        };
        Box::pin(async move { decision })
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

fn gateway_service(scenario: &Scenario, reached: &Arc<AtomicBool>) -> Result<S3Service, String> {
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).map_err(|error| format!("credential: {error:?}"))?;
    let regions = RegionSet::new(REGIONS).map_err(|error| format!("regions: {error:?}"))?;
    let authenticator = SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(credentials)), regions);
    let backend = Arc::new(ParityBackend {
        body: scenario.body,
        reached: Arc::clone(reached),
    });
    ServiceBuilder::new()
        .authenticator(authenticator)
        .authorizer(DenyAnonymous)
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .bucket_owner_source(FixtureOwner)
        .register::<dto::PutObject, _>(Arc::clone(&backend))
        .register::<dto::GetBucketLocation, _>(Arc::clone(&backend))
        .register::<dto::GetObject, _>(Arc::clone(&backend))
        .register::<dto::HeadObject, _>(Arc::clone(&backend))
        .register::<dto::PutBucketVersioning, _>(Arc::clone(&backend))
        .register::<dto::UploadPart, _>(backend)
        .build()
        .map_err(|error| format!("assembly: {error:?}"))
}

fn gateway_reply(scenario: &Scenario, target: &str, headers: &HeaderMap) -> Result<Reply, String> {
    let reached = Arc::new(AtomicBool::new(false));
    let service = gateway_service(scenario, &reached)?;
    let request = head(scenario, target, headers)
        .body(scenario.request.body.clone())
        .map_err(|error| format!("fixture head: {error}"))?;
    let response = block_on(service.call_bytes(request));
    let closes = connection_intent_of(&response).map(rustfs_gateway::ConnectionIntent::must_close);
    let (parts, body) = response.into_parts();
    let body = block_on(http_body_util::BodyExt::collect(body))
        .map_err(|error| format!("gateway body: {error:?}"))?
        .to_bytes();
    Ok(Reply {
        status: parts.status.as_u16(),
        headers: header_lines(&parts.headers),
        body: String::from_utf8_lossy(&body).into_owned(),
        reached: reached.load(Ordering::SeqCst),
        closes,
    })
}

// ── the s3s side ──────────────────────────────────────────────────────────────────────────────

/// An s3s backend whose every handler the scenario can reach answers the app body's result.
struct ParityS3 {
    body: AppBody,
    reached: Arc<AtomicBool>,
}

impl ParityS3 {
    fn answer<T: Default + Send + 'static>(&self) -> Answer<'static, T> {
        self.reached.store(true, Ordering::SeqCst);
        let result = match self.body {
            AppBody::Succeeds => Ok(s3s::S3Response::new(T::default())),
            AppBody::Refuses(error) => Err(error()),
        };
        Box::pin(async move { result })
    }
}

macro_rules! parity_s3s_handlers {
    ($($method:ident: $input:ident => $output:ident),+ $(,)?) => {
        impl s3s::S3 for ParityS3 {
            // The pinned trait is declared with `#[async_trait]`; these are the signatures that
            // attribute expands a `&self` method to, spelled out as the parent does.
            $(fn $method<'life0, 'future>(
                &'life0 self,
                _request: s3s::S3Request<oracle::$input>,
            ) -> Answer<'future, oracle::$output>
            where
                'life0: 'future,
                Self: 'future,
            {
                self.answer()
            })+
        }
    };
}

parity_s3s_handlers!(
    put_object: PutObjectInput => PutObjectOutput,
    get_bucket_location: GetBucketLocationInput => GetBucketLocationOutput,
    get_object: GetObjectInput => GetObjectOutput,
    head_object: HeadObjectInput => HeadObjectOutput,
    put_bucket_versioning: PutBucketVersioningInput => PutBucketVersioningOutput,
    upload_part: UploadPartInput => UploadPartOutput,
);

fn s3s_reply(scenario: &Scenario, target: &str, headers: &HeaderMap) -> Result<Reply, String> {
    let reached = Arc::new(AtomicBool::new(false));
    let mut builder = s3s::service::S3ServiceBuilder::new(ParityS3 {
        body: scenario.body,
        reached: Arc::clone(&reached),
    });
    // Authentication is always configured, so an anonymous request meets the default access check
    // RustFS's own access hook stands in for.
    builder.set_auth(s3s::auth::SimpleAuth::from_single(ACCESS_KEY, SECRET_KEY));
    let service = builder.build();
    let body = if scenario.request.body.is_empty() {
        s3s::Body::empty()
    } else {
        s3s::Body::from(scenario.request.body.clone())
    };
    let request = head(scenario, target, headers)
        .body(body)
        .map_err(|error| format!("fixture head: {error}"))?;
    let response = block_on(service.call(request)).map_err(|error| format!("s3s service failed: {error:?}"))?;
    let (parts, mut body) = response.into_parts();
    let body = block_on(body.store_all_limited(1 << 20)).map_err(|error| format!("s3s response body: {error}"))?;
    Ok(Reply {
        status: parts.status.as_u16(),
        headers: header_lines(&parts.headers),
        body: String::from_utf8_lossy(&body).into_owned(),
        reached: reached.load(Ordering::SeqCst),
        closes: None,
    })
}
