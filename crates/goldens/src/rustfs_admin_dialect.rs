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

//! The generated RustFS admin dialect (rustfs/backlog#1744) through a real assembled service, and
//! bound back to the recorded inventory it was generated from.
//!
//! Responsible for: an assembled service with the facade's SigV4 authenticator (handing the
//! caller's secret over, so each operation's own opt-in decides who holds it), a recording
//! authorizer answering by policy, the `rustfs` dialect, and one generic handler registered for
//! every generated operation through `fold_every_operation` that records its path parameters
//! and whether it holds the secret; and the requests the tests send — signed, unsigned,
//! presigned, with a concrete or a malformed parameter value, with or without the bucket a
//! query-bound operation names — for any row of any operation.
//! NOT responsible for: the assertions (`tests.rs`, `subject_tests.rs`, `bucket_tests.rs`), routing without a service (the dialect
//! crate's own tests), the generator's rules (xtask's), or the hand-written proof
//! (`rustfs_admin_proof`).
//! Upstream: `rustfs-gateway-dialect-rustfs-admin`, the facade, `operation_diff::context`'s
//! signer and credential. Downstream: `tests.rs`.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderValue, Method, Request};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Governor, GovernorRates, GovernorRequest, Handler,
    HandlerContext, HandlerResult, InputAuthzRequest, InputDecisions, Lease, Rate, Req, RequestContext, RequestContextView, Resp,
    S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials,
};
use rustfs_gateway_core::dialect::BucketParam;
use rustfs_gateway_core::{Subject, SubjectRule, Subjects};
use rustfs_gateway_dialect_rustfs_admin::{
    AdminOperation, AdminResponse, OperationFold, ROUTES, RouteRecord, fold_every_operation, rustfs_admin_dialect,
};
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{
    AmzDate, PayloadMode, RegionSet, RequestNow, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope,
};

use crate::operation_diff::s3s_0_17_0::context::{ACCESS_KEY, ContextRequest, PATH_HOST, REGIONS, SECRET_KEY, amz_date};
use crate::operation_diff::s3s_0_17_0::harness::block_on;
use crate::rustfs_admin_proof::same_bytes;

const REGION: &str = "us-east-1";

/// One question the authorizer was asked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Asked {
    /// `route`, `input` or `resource`.
    pub(crate) stage: &'static str,
    pub(crate) operation: String,
    pub(crate) action: String,
    pub(crate) caller: Option<String>,
    pub(crate) bucket: Option<String>,
    pub(crate) key: Option<String>,
    /// Whose account the question is about: `None` for no account, `Some(None)` for the caller,
    /// `Some(Some(name))` for a named one.
    pub(crate) subject: Option<Option<String>>,
}

type Policy = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Records every question and answers it with `policy(operation, action)`.
struct RecordingAuthorizer {
    policy: Policy,
    asked: Arc<Mutex<Vec<Asked>>>,
}

impl RecordingAuthorizer {
    fn decide(&self, stage: &'static str, request: &AuthzRequest<'_>) -> Decision {
        self.asked.lock().expect("uncontended").push(Asked {
            stage,
            operation: request.operation.to_owned(),
            action: request.action.to_owned(),
            caller: request.identity.map(|identity| identity.access_key_id().to_owned()),
            bucket: request.bucket.map(|bucket| bucket.as_str().to_owned()),
            key: request.key.map(|key| key.as_str().to_owned()),
            subject: request.subject.map(|subject| subject.name().map(str::to_owned)),
        });
        if (self.policy)(request.operation, request.action) {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

impl Authorizer for RecordingAuthorizer {
    fn authorize_route<'a>(&'a self, _context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        let decision = self.decide("route", request);
        Box::pin(async move { decision })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let stage = self.decide("input", request.route());
        let decisions = request.decide_all(stage, |resource| self.decide("resource", resource));
        Box::pin(async move { decisions })
    }
}

/// Admits every request. The default governor throttles a client after a burst of failed
/// signatures, which is its job; these tests send a burst of them on purpose and measure
/// authentication and authorisation, not admission.
struct AdmitAll;

impl Governor for AdmitAll {
    fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        Box::pin(async { Ok(Lease::admit()) })
    }
}

/// What one handler was handed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Handed {
    pub(crate) operation: &'static str,
    /// The decoded path parameters, in path order.
    pub(crate) params: Vec<(String, String)>,
    pub(crate) holds_secret: bool,
    pub(crate) secret_is_the_callers: bool,
    /// The accounts the context carries: `none`, `caller`, `named:<name>`, `each:<a>,<b>` or
    /// `everyone`.
    pub(crate) subjects: String,
    /// Whether `RequestContextView::subject()` holds one account, which it must only for a
    /// single-subject request.
    pub(crate) has_one_subject: bool,
    /// The bucket the context carries: the bound one (ADR-0030), or none for a service-level
    /// operation.
    pub(crate) bucket: Option<String>,
}

/// The accounts a context carries, spelled as [`Handed::subjects`] records them.
fn subjects_of(context: &RequestContextView) -> String {
    match context.subjects() {
        None => "none".to_owned(),
        Some(Subjects::One(Subject::Caller)) => "caller".to_owned(),
        Some(Subjects::One(subject)) => format!("named:{}", subject.name().unwrap_or_default()),
        Some(Subjects::Each(each)) => format!("each:{}", each.iter().filter_map(Subject::name).collect::<Vec<_>>().join(",")),
        Some(Subjects::Everyone) => "everyone".to_owned(),
    }
}

impl Handed {
    fn of(context: &RequestContextView) -> Self {
        let secret = context
            .principal()
            .and_then(|principal| principal.secret_key_from_authenticator_lookup());
        Self {
            subjects: subjects_of(context),
            has_one_subject: context.subject().is_some(),
            bucket: context.bucket().map(|bucket| bucket.as_str().to_owned()),
            operation: context.operation(),
            params: context
                .path_params()
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            holds_secret: secret.is_some(),
            secret_is_the_callers: secret.is_some_and(|secret| same_bytes(secret.expose_secret(), SECRET_KEY.as_bytes())),
        }
    }
}

/// One generic handler for every generated operation: it records what it was handed and answers
/// that operation's name as JSON.
#[derive(Default)]
struct Admin {
    handed: Mutex<Vec<Handed>>,
}

impl Admin {
    fn serve<O: AdminOperation>(&self, request: &Req<O>) -> HandlerResult<O> {
        self.handed.lock().expect("uncontended").push(Handed::of(request.context()));
        Ok(Resp::new(AdminResponse::json(format!("{{\"operation\":\"{}\"}}", O::NAME))))
    }
}

impl<O: AdminOperation> Handler<O> for Admin {
    async fn call(&self, request: Req<O>) -> HandlerResult<O> {
        self.serve(&request)
    }

    async fn call_with_context(&self, request: Req<O>, _context: HandlerContext) -> HandlerResult<O> {
        self.serve(&request)
    }
}

/// Registers the one handler for every operation, as a deployment with a generic handler would.
struct Register(Arc<Admin>);

impl OperationFold for Register {
    type Carry = ServiceBuilder;

    fn step<O: AdminOperation>(&mut self, carry: ServiceBuilder) -> ServiceBuilder {
        carry.register::<O, _>(Arc::clone(&self.0))
    }
}

/// What one request produced.
#[derive(Debug)]
pub(crate) struct Exchange {
    pub(crate) status: u16,
    pub(crate) body: String,
    pub(crate) asked: Vec<Asked>,
    pub(crate) reached: Vec<&'static str>,
    pub(crate) handed: Vec<Handed>,
}

/// The assembled service and what it records.
pub(crate) struct Assembled {
    service: S3Service,
    admin: Arc<Admin>,
    asked: Arc<Mutex<Vec<Asked>>>,
}

impl Assembled {
    /// Sends one request; returns what it produced and forgets it, so the next starts clean.
    pub(crate) fn exchange(&self, request: Request<Bytes>) -> Exchange {
        let response = block_on(self.service.call_bytes(request));
        let collected = block_on(rustfs_gateway::collect(response)).expect("an in-memory body");
        let handed = std::mem::take(&mut *self.admin.handed.lock().expect("uncontended"));
        Exchange {
            status: collected.status().as_u16(),
            body: String::from_utf8_lossy(collected.body()).into_owned(),
            asked: std::mem::take(&mut *self.asked.lock().expect("uncontended")),
            reached: handed.iter().map(|handed| handed.operation).collect(),
            handed,
        }
    }
}

/// The facade's SigV4 authenticator over the shared credential, handing the caller's secret over
/// under the assembly's default opted-in scope (ADR-0024), an authorizer answering with
/// `policy(operation, action)`, the `rustfs` dialect, and the generic handler for every operation.
pub(crate) fn assemble(policy: impl Fn(&str, &str) -> bool + Send + Sync + 'static) -> Assembled {
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("a fixture credential");
    let regions = RegionSet::new(REGIONS).expect("fixture regions");
    let authenticator =
        SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(credentials)), regions).hand_caller_secret_to_handlers();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let admin = Arc::new(Admin::default());
    let dialect = rustfs_admin_dialect().expect("the generated record and declarations agree");
    // The mandatory framework governor stays in force, with room for every row at once: each test
    // sends all 310 rows from one address-less client back to back, past the default burst of 256.
    let rates = GovernorRates {
        per_ip: Rate::new(8_192, 4_096),
        credential_lookup: Rate::new(8_192, 4_096),
        unauthenticated: Rate::new(8_192, 4_096),
        aggregate: Rate::new(16_384, 8_192),
        ..GovernorRates::default()
    };
    let builder = ServiceBuilder::new()
        .framework_governor_rates(rates)
        .authenticator(authenticator)
        .governor(AdmitAll)
        .authorizer(RecordingAuthorizer {
            policy: Box::new(policy),
            asked: Arc::clone(&asked),
        })
        .dialect(&dialect);
    let builder = fold_every_operation(&mut Register(Arc::clone(&admin)), builder);
    Assembled {
        service: builder.build().expect("a complete assembly"),
        admin,
        asked,
    }
}

/// How many services a refusal test spreads its rows across.
const LANES: usize = 8;

/// Runs `check` on every item, split across [`LANES`] threads that each assemble their own service
/// under `policy`. Every refusal holds the security floor's uniform failure latency, which is the
/// contract under test and is not lowered here, so a test that refuses all 442 rows one after
/// another waits out 442 floors. The lanes wait them out side by side instead. One service per
/// lane keeps every exchange's recorded questions its own. A panic in any lane fails the test with
/// that lane's own message, and the lanes together must have checked every item they were handed.
pub(crate) fn in_lanes<P, T: Sync>(policy: P, items: &[T], check: impl Fn(&Assembled, &T) + Sync)
where
    P: Fn(&str, &str) -> bool + Copy + Send + Sync + 'static,
{
    let per_lane = items.len().div_ceil(LANES).max(1);
    let checked: usize = std::thread::scope(|scope| {
        let lanes: Vec<_> = items
            .chunks(per_lane)
            .map(|lane| {
                let check = &check;
                scope.spawn(move || {
                    let assembled = assemble(policy);
                    let mut done = 0;
                    for item in lane {
                        check(&assembled, item);
                        done += 1;
                    }
                    done
                })
            })
            .collect();
        lanes
            .into_iter()
            .map(|lane| lane.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic)))
            .sum()
    });
    assert_eq!(checked, items.len(), "the lanes checked every item they were handed");
}

/// The actions a record's rule asks about a named account, in order: the rendered rule without
/// its ` about …` subject.
pub(crate) fn actions(record: &RouteRecord) -> Vec<&'static str> {
    let rule = record.action.split(" about ").next().unwrap_or(record.action);
    rule.strip_prefix("anyOf(")
        .and_then(|listed| listed.strip_suffix(')'))
        .map_or_else(|| vec![rule], |listed| listed.split(", ").collect())
}

/// The account every well-formed request for a named-account or set operation names.
pub(crate) const ACCOUNT: &str = "account-1";

/// The bucket every well-formed request for a bucket-bound operation names: the value the
/// `{bucket}` parameter is given ([`value_of`]), and the value a query-bound operation's `bucket`
/// parameter is given.
pub(crate) const BUCKET: &str = "bucket-1";

/// The query parameter a record's bucket binding reads, if it is a query one.
pub(crate) const fn bucket_query_param(record: &RouteRecord) -> Option<&'static str> {
    match record.bucket {
        Some(BucketParam::Query(param)) => Some(param),
        Some(BucketParam::Path(_)) | None => None,
    }
}

/// The bucket a well-formed request for `record` is authorised on and hands its handler, as
/// [`Asked::bucket`] and [`Handed::bucket`] record it: the value its template parameter is given
/// (`bucket-1` or `warehouse-1`), or [`BUCKET`] for a query binding.
pub(crate) fn expected_bucket(record: &RouteRecord) -> Option<String> {
    match record.bucket {
        Some(BucketParam::Path(param)) => Some(value_of(param)),
        Some(BucketParam::Query(_)) => Some(BUCKET.to_owned()),
        None => None,
    }
}

/// The query parameter a record's subject rule reads, if any.
pub(crate) const fn subject_param(record: &RouteRecord) -> Option<&'static str> {
    match record.subject {
        Some(SubjectRule::Query { param, .. } | SubjectRule::Set { param, .. }) => Some(param),
        Some(SubjectRule::Caller) | None => None,
    }
}

/// Whose account a well-formed request for `record` is about, as [`Asked::subject`] records it.
pub(crate) fn expected_subject(record: &RouteRecord) -> Option<Option<String>> {
    match record.subject {
        None => None,
        Some(SubjectRule::Caller) => Some(None),
        Some(_) => Some(Some(ACCOUNT.to_owned())),
    }
}

/// The accounts a well-formed request for `record` hands its handler, as [`Handed::subjects`]
/// records them.
pub(crate) fn expected_subjects(record: &RouteRecord) -> String {
    match record.subject {
        None => "none".to_owned(),
        Some(SubjectRule::Caller) => "caller".to_owned(),
        Some(SubjectRule::Query { .. }) => format!("named:{ACCOUNT}"),
        Some(SubjectRule::Set { .. }) => format!("each:{ACCOUNT}"),
    }
}

/// Allows an operation exactly the actions its own record names.
pub(crate) fn declared(operation: &str, action: &str) -> bool {
    ROUTES
        .iter()
        .any(|record| record.operation == operation && actions(record).contains(&action))
}

/// Every template a record's operation is served at: the canonical one, then the alias.
pub(crate) fn templates(record: &RouteRecord) -> Vec<&'static str> {
    std::iter::once(record.path).chain(record.alias).collect()
}

/// The parameter a template segment names, if it is one.
pub(crate) fn param(segment: &str) -> Option<&str> {
    segment.strip_prefix('{').and_then(|inner| inner.strip_suffix('}'))
}

/// The value every parameter is given in a well-formed request: its name then `-1`.
pub(crate) fn value_of(name: &str) -> String {
    format!("{name}-1")
}

/// `template` with its `index`-th segment spelled `raw`, and every other parameter given its
/// well-formed value.
pub(crate) fn with_segment(template: &str, index: Option<usize>, raw: &str) -> String {
    template
        .split('/')
        .enumerate()
        .map(|(at, segment)| match (Some(at) == index, param(segment)) {
            (true, _) => raw.to_owned(),
            (false, Some(name)) => value_of(name),
            (false, None) => segment.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// `template` with every parameter given its well-formed value.
pub(crate) fn concrete(template: &str) -> String {
    with_segment(template, None, "")
}

/// Every concrete path a record's operation is served at: the canonical one, then the alias.
pub(crate) fn paths(record: &RouteRecord) -> Vec<String> {
    templates(record).into_iter().map(concrete).collect()
}

/// A well-formed query for a record's operation: the value that selects it, the account its
/// subject rule reads, and the bucket its query binding reads, when it has any of them.
pub(crate) fn query(record: &RouteRecord) -> String {
    record
        .query
        .map(|(key, value)| format!("{key}={value}"))
        .into_iter()
        .chain(subject_param(record).map(|param| format!("{param}={ACCOUNT}")))
        .chain(bucket_query_param(record).map(|param| format!("{param}={BUCKET}")))
        .collect::<Vec<_>>()
        .join("&")
}

/// A request for a record's operation at `path`, signed with the shared credential.
pub(crate) fn signed(record: &RouteRecord, path: &str) -> ContextRequest {
    signed_with(record, path, &query(record))
}

/// A request for a record's operation at `path?query`, signed with the shared credential.
pub(crate) fn signed_with(record: &RouteRecord, path: &str, query: &str) -> ContextRequest {
    let request = match record.method {
        "GET" => ContextRequest::get(PATH_HOST, path, query),
        "HEAD" => ContextRequest::head(PATH_HOST, path, query),
        "POST" => ContextRequest::post(PATH_HOST, path, query),
        "DELETE" => ContextRequest::delete(PATH_HOST, path, query),
        "PUT" => ContextRequest::put_with_query(PATH_HOST, path, query, b"{}"),
        other => panic!("{}: no signed fixture for {other}", record.operation),
    };
    request.signed(REGION)
}

/// A signed request as it goes on the wire, signed now.
pub(crate) fn wire(request: &ContextRequest) -> Request<Bytes> {
    let headers = request.wire_headers(RequestNow::capture()).expect("fixture headers");
    request
        .http_head(&headers)
        .body(request.body.clone())
        .expect("a fixture request")
}

/// The same request with no credentials at all.
pub(crate) fn unsigned(record: &RouteRecord, path: &str) -> Request<Bytes> {
    unsigned_with(record, path, &query(record))
}

/// A request for a record's operation at `path?query`, with no credentials at all.
pub(crate) fn unsigned_with(record: &RouteRecord, path: &str, query: &str) -> Request<Bytes> {
    let uri = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    Request::builder()
        .method(record.method)
        .uri(uri)
        .header("host", PATH_HOST)
        .body(Bytes::new())
        .expect("a fixture request")
}

/// The request presigned in the query with the shared credential, now, its account included.
/// Only for a record whose operation no query selects.
pub(crate) fn presigned(record: &RouteRecord, path: &str) -> Request<Bytes> {
    assert!(record.query.is_none(), "{}", record.operation);
    let query = query(record);
    let method = Method::from_bytes(record.method.as_bytes()).expect("a method");
    let stamp = AmzDate::parse(&amz_date(RequestNow::capture().unix_seconds())).expect("a stamp");
    let scope = SigningScope::new(stamp.day(), REGION, SigService::S3).expect("a scope");
    let credentials = SigningCredentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("credentials");
    let mut signer = SigV4Signer::new(credentials, scope);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_str(PATH_HOST).expect("a host"));
    let host = RawHost::from_host_header(PATH_HOST.as_bytes()).expect("an acceptable host");
    let signing = SigningRequest::new(&method, path, &query, &headers, &host, PayloadMode::Unsigned, stamp);
    let signed = signer.presign(&signing, 900).expect("a presignable request");
    let mut builder = Request::builder().method(method).uri(format!("{path}?{}", signed.query()));
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("a request")
}

mod bucket_tests;
mod subject_tests;
mod tests;
