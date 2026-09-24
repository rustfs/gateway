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

//! Responsible for: headerless OPTIONS rejection at the assembled gateway boundary.
//! NOT responsible for: signed-query OPTIONS or changing other preflight refusals.
//! Upstream: the unsigned AWS observation in issue #875; downstream: CORS regression coverage.

use super::*;
use bytes::Bytes;
use rustfs_gateway::{Authentication, AuthenticationOutcome, Authenticator, Unavailable};

#[derive(Clone, Default)]
struct Calls {
    host: Arc<AtomicUsize>,
    authentication: Arc<AtomicUsize>,
    authorization: Arc<AtomicUsize>,
    handler: Arc<AtomicUsize>,
    source: Arc<AtomicUsize>,
}

struct CountingHost(Arc<AtomicUsize>);

impl rustfs_gateway::HostResolver for CountingHost {
    fn resolve(&self, query: &rustfs_gateway::HostQuery<'_>) -> rustfs_gateway::ResolvedHost {
        self.0.fetch_add(1, Ordering::SeqCst);
        rustfs_gateway::HostResolver::resolve(&rustfs_gateway::PathStyleOnly, query)
    }
}

struct CountingAuthentication {
    calls: Arc<AtomicUsize>,
    inner: SigV4Authenticator,
}

impl Authenticator for CountingAuthentication {
    fn authenticate<'a>(&'a self, request: &'a Authentication<'a>) -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.authenticate(request)
    }
}

struct CountingRead(Arc<AtomicUsize>);

impl Handler<rustfs_gateway::dto::GetObject> for CountingRead {
    async fn call(&self, _request: Req<rustfs_gateway::dto::GetObject>) -> HandlerResult<rustfs_gateway::dto::GetObject> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(rustfs_gateway::dto::GetObjectOutput::default()))
    }
}

impl Handler<rustfs_gateway::dto::HeadObject> for CountingRead {
    async fn call(&self, _request: Req<rustfs_gateway::dto::HeadObject>) -> HandlerResult<rustfs_gateway::dto::HeadObject> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(rustfs_gateway::dto::HeadObjectOutput::default()))
    }
}

fn observed_service() -> (S3Service, Calls) {
    let calls = Calls::default();
    let authz = Arc::clone(&calls.authorization);
    let backend = Arc::new(CountingRead(Arc::clone(&calls.handler)));
    let credentials = Credentials::new("AKIDEXAMPLE", b"secret").expect("fixture credentials");
    let service = ServiceBuilder::new()
        .host_resolver(CountingHost(Arc::clone(&calls.host)))
        .register::<rustfs_gateway::dto::GetObject, _>(Arc::clone(&backend))
        .register::<rustfs_gateway::dto::HeadObject, _>(backend)
        .authenticator(CountingAuthentication {
            calls: Arc::clone(&calls.authentication),
            inner: SigV4Authenticator::new(
                Arc::new(StaticCredentials::new().with(credentials)),
                RegionSet::new(["us-east-1"]).expect("fixture region"),
            ),
        })
        .authorizer(allow_when(move |_| {
            authz.fetch_add(1, Ordering::SeqCst);
            true
        }))
        .clock_with_skew_ack(
            crate::support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .cors_source(CountingSource::new(&calls.source, &[NAMED], &["GET"]))
        .build()
        .expect("complete fixture");
    (service, calls)
}

fn assert_bad_request(response: &WireResponse) {
    assert_eq!(response.status().as_u16(), 400);
    assert!(String::from_utf8_lossy(response.body()).contains("<Code>BadRequest</Code>"));
    for name in [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-credentials",
    ] {
        assert_eq!(header(response, name), None, "a rejected OPTIONS granted {name}");
    }
}

#[tokio::test]
async fn headerless_options_returns_the_observed_bad_request() {
    let (service, _) = observed_service();
    let response = send(&service, "OPTIONS", PREFLIGHT, &[]).await;
    assert_bad_request(&response);
}

#[tokio::test]
async fn headerless_options_reads_no_cors_configuration() {
    let (service, calls) = observed_service();
    let response = send(&service, "OPTIONS", PREFLIGHT, &[]).await;
    assert_eq!(calls.source.load(Ordering::SeqCst), 0);
    assert_bad_request(&response);
}

#[tokio::test]
async fn headerless_options_reaches_no_authentication_authorization_or_handler() {
    let (service, calls) = observed_service();
    let response = send(&service, "OPTIONS", PREFLIGHT, &[]).await;
    assert_eq!(calls.authentication.load(Ordering::SeqCst), 0);
    assert_eq!(calls.authorization.load(Ordering::SeqCst), 0);
    assert_eq!(calls.handler.load(Ordering::SeqCst), 0);
    assert_bad_request(&response);
}

struct PollBody(Arc<AtomicUsize>);

impl http_body::Body for PollBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(None)
    }
}

#[tokio::test]
async fn headerless_options_does_not_poll_the_request_body() {
    let (service, _) = observed_service();
    let polls = Arc::new(AtomicUsize::new(0));
    let request = http::Request::builder()
        .method("OPTIONS")
        .uri(PREFLIGHT)
        .header("host", "host.invalid")
        .header("content-length", "1")
        .body(PollBody(Arc::clone(&polls)))
        .expect("request");
    let response = collect(service.call(request).await).await.expect("response");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_bad_request(&response);
}

#[tokio::test]
async fn headerless_options_waits_for_the_security_failure_floor() {
    let (service, _) = observed_service();
    let mut future = Box::pin(send(&service, "OPTIONS", PREFLIGHT, &[]));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert_bad_request(&future.await);
}

#[tokio::test]
async fn headerless_options_does_not_override_wire_rejection() {
    let (service, calls) = observed_service();
    let response = send(
        &service,
        "OPTIONS",
        PREFLIGHT,
        &[("content-length", "1"), ("transfer-encoding", "chunked")],
    )
    .await;
    assert_eq!(response.status().as_u16(), 400);
    assert!(!String::from_utf8_lossy(response.body()).contains("<Code>BadRequest</Code>"));
    assert_eq!(calls.source.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn headerless_options_change_preserves_other_malformed_preflights() {
    let (service, _) = observed_service();
    for headers in [
        vec![("origin", NAMED)],
        vec![("access-control-request-method", "GET")],
        vec![("origin", NAMED), ("origin", NAMED), ("access-control-request-method", "GET")],
        vec![("origin", ""), ("access-control-request-method", "GET")],
    ] {
        let response = send(&service, "OPTIONS", PREFLIGHT, &headers).await;
        assert_eq!(response.status().as_u16(), 403);
        assert!(String::from_utf8_lossy(response.body()).contains("<Code>AccessForbidden</Code>"));
    }
}

#[tokio::test]
async fn headerless_options_change_preserves_unsigned_read_refusal() {
    let (service, calls) = observed_service();
    for method in ["GET", "HEAD"] {
        assert_eq!(send(&service, method, PREFLIGHT, &[]).await.status().as_u16(), 403);
    }
    assert_eq!(calls.handler.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn headerless_options_observers_measure_real_preflight_and_signed_reads() {
    let (service, calls) = observed_service();
    let preflight = send(
        &service,
        "OPTIONS",
        PREFLIGHT,
        &[("origin", NAMED), ("access-control-request-method", "GET")],
    )
    .await;
    assert_eq!(preflight.status().as_u16(), 200);
    assert_eq!(calls.source.load(Ordering::SeqCst), 1);
    assert_eq!(calls.authentication.load(Ordering::SeqCst), 0);
    assert_eq!(calls.handler.load(Ordering::SeqCst), 0);
    for method in [http::Method::GET, http::Method::HEAD] {
        let response = service.call_bytes(crate::support::signed(method, PREFLIGHT)).await;
        assert_eq!(response.status().as_u16(), 200);
    }
    assert_eq!(calls.authentication.load(Ordering::SeqCst), 2);
    assert!(calls.authorization.load(Ordering::SeqCst) >= 2);
    assert_eq!(calls.handler.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn headerless_options_change_does_not_reclassify_requested_headers_alone() {
    let (service, _) = observed_service();
    let response = send(&service, "OPTIONS", PREFLIGHT, &[("access-control-request-headers", "x-example")]).await;
    assert_eq!(response.status().as_u16(), 501);
}

#[tokio::test]
async fn headerless_options_runs_host_resolution_before_refusal() {
    let (service, calls) = observed_service();
    assert_bad_request(&send(&service, "OPTIONS", PREFLIGHT, &[]).await);
    assert_eq!(calls.host.load(Ordering::SeqCst), 1);
}
