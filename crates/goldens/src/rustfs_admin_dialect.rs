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
//! Responsible for: an assembled service with the facade's SigV4 authenticator, a recording
//! authorizer answering by policy, the `rustfs` dialect, and one generic handler registered for
//! every generated operation through `fold_every_operation`; and the requests the tests send —
//! signed, unsigned, presigned — for any row of any operation.
//! NOT responsible for: the assertions (`tests.rs`), routing without a service (the dialect
//! crate's own tests), the generator's rules (xtask's), or the hand-written proof
//! (`rustfs_admin_proof`).
//! Upstream: `rustfs-gateway-dialect-rustfs-admin`, the facade, `operation_diff::context`'s
//! signer and credential. Downstream: `tests.rs`.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderValue, Method, Request};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Governor, GovernorRequest, Handler, HandlerContext,
    HandlerResult, InputAuthzRequest, InputDecisions, Lease, Req, RequestContext, Resp, S3Service, ServiceBuilder,
    SigV4Authenticator, StaticCredentials,
};
use rustfs_gateway_dialect_rustfs_admin::{
    AdminOperation, AdminResponse, OperationFold, ROUTES, RouteRecord, fold_every_operation, rustfs_admin_dialect,
};
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{
    AmzDate, PayloadMode, RegionSet, RequestNow, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope,
};

use crate::operation_diff::s3s_f3e17541::context::{ACCESS_KEY, ContextRequest, PATH_HOST, REGIONS, SECRET_KEY, amz_date};
use crate::operation_diff::s3s_f3e17541::harness::block_on;

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
    pub(crate) about_an_account: bool,
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
            about_an_account: request.subject.is_some(),
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

/// One generic handler for every generated operation: it records which operation it served and
/// answers that operation's name as JSON.
#[derive(Default)]
struct Admin {
    reached: Mutex<Vec<&'static str>>,
}

impl Admin {
    fn serve<O: AdminOperation>(&self, request: &Req<O>) -> HandlerResult<O> {
        self.reached.lock().expect("uncontended").push(request.context().operation());
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
        Exchange {
            status: collected.status().as_u16(),
            body: String::from_utf8_lossy(collected.body()).into_owned(),
            asked: std::mem::take(&mut *self.asked.lock().expect("uncontended")),
            reached: std::mem::take(&mut *self.admin.reached.lock().expect("uncontended")),
        }
    }
}

/// The facade's SigV4 authenticator over the shared credential, an authorizer answering with
/// `policy(operation, action)`, the `rustfs` dialect, and the generic handler for every operation.
pub(crate) fn assemble(policy: impl Fn(&str, &str) -> bool + Send + Sync + 'static) -> Assembled {
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("a fixture credential");
    let regions = RegionSet::new(REGIONS).expect("fixture regions");
    let authenticator = SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(credentials)), regions);
    let asked = Arc::new(Mutex::new(Vec::new()));
    let admin = Arc::new(Admin::default());
    let dialect = rustfs_admin_dialect().expect("the generated record and declarations agree");
    let builder = ServiceBuilder::new()
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

/// The actions a record's rule names, in order.
pub(crate) fn actions(record: &RouteRecord) -> Vec<&'static str> {
    record
        .action
        .strip_prefix("anyOf(")
        .and_then(|listed| listed.strip_suffix(')'))
        .map_or_else(|| vec![record.action], |listed| listed.split(", ").collect())
}

/// Allows an operation exactly the actions its own record names.
pub(crate) fn declared(operation: &str, action: &str) -> bool {
    ROUTES
        .iter()
        .any(|record| record.operation == operation && actions(record).contains(&action))
}

/// Every path a record's operation is served at: the canonical one, then the alias.
pub(crate) fn paths(record: &RouteRecord) -> Vec<&'static str> {
    std::iter::once(record.path).chain(record.alias).collect()
}

fn query(record: &RouteRecord) -> String {
    record.query.map_or_else(String::new, |(key, value)| format!("{key}={value}"))
}

/// A request for a record's operation at `path`, signed with the shared credential.
pub(crate) fn signed(record: &RouteRecord, path: &str) -> ContextRequest {
    let request = match record.method {
        "GET" => ContextRequest::get(PATH_HOST, path, &query(record)),
        "POST" => ContextRequest::post(PATH_HOST, path, &query(record)),
        "PUT" if record.query.is_none() => ContextRequest::put(PATH_HOST, path, b"{}"),
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
    let query = query(record);
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

/// The request presigned in the query with the shared credential, now. Only for a record whose
/// operation no query selects.
pub(crate) fn presigned(record: &RouteRecord, path: &str) -> Request<Bytes> {
    assert!(record.query.is_none(), "{}", record.operation);
    let method = Method::from_bytes(record.method.as_bytes()).expect("a method");
    let stamp = AmzDate::parse(&amz_date(RequestNow::capture().unix_seconds())).expect("a stamp");
    let scope = SigningScope::new(stamp.day(), REGION, SigService::S3).expect("a scope");
    let credentials = SigningCredentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("credentials");
    let mut signer = SigV4Signer::new(credentials, scope);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, HeaderValue::from_str(PATH_HOST).expect("a host"));
    let host = RawHost::from_host_header(PATH_HOST.as_bytes()).expect("an acceptable host");
    let signing = SigningRequest::new(&method, path, "", &headers, &host, PayloadMode::Unsigned, stamp);
    let signed = signer.presign(&signing, 900).expect("a presignable request");
    let mut builder = Request::builder().method(method).uri(format!("{path}?{}", signed.query()));
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    builder.body(Bytes::new()).expect("a request")
}

mod tests;
