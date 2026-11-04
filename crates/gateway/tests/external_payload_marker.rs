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

//! Reserved external-data markers cannot reach ordinary empty-body handlers.
//!
//! Responsible for: proving default and feature-enabled service rejection before backend effects.
//! NOT responsible for: external transport execution or signature implementation.
//! Upstream: the real service entry and signed test requests. Downstream: the test harness.

use crate::support;
use http::{Method, StatusCode};
use rustfs_gateway::{Handler, HandlerResult, Req, Resp, S3Service, dto};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Backend(Arc<AtomicUsize>);
impl Handler<dto::PutObject> for Backend {
    async fn call(&self, _request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}
fn service() -> (S3Service, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = support::wired_at_signed_time()
        .register::<dto::PutObject, _>(Arc::new(Backend(calls.clone())))
        .build()
        .expect("valid assembly");
    (service, calls)
}
#[tokio::test]
async fn required_marker_is_rejected_without_backend_effects() {
    let (service, calls) = service();
    let request = support::signed_with(
        Method::PUT,
        "/bucket/object",
        &[("content-length", "0"), ("x-rustfs-rdma-required", "true")],
    );
    let (status, body) = support::exchange(&service, request).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("NotImplemented"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn an_orphan_transfer_marker_is_rejected() {
    let (service, calls) = service();
    let request = support::signed_with(
        Method::PUT,
        "/bucket/object",
        &[("content-length", "0"), ("x-rustfs-rdma-transfer", "transfer")],
    );
    let (status, _) = support::exchange(&service, request).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn a_false_required_marker_cannot_select_ordinary_upload() {
    let (service, calls) = service();
    let request = support::signed_with(
        Method::PUT,
        "/bucket/object",
        &[("content-length", "0"), ("x-rustfs-rdma-required", "false")],
    );
    let (status, _) = support::exchange(&service, request).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn ordinary_empty_put_keeps_its_existing_path() {
    let (service, calls) = service();
    let (status, _) =
        support::exchange(&service, support::signed_with(Method::PUT, "/bucket/object", &[("content-length", "0")])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "external-payload")]
mod execution {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue};
    use http_body_util::Full;
    use rustfs_gateway::external_payload::{
        ExternalPayload, ExternalPayloadBinding, ExternalPayloadContext, ExternalPayloadControl, ExternalPayloadError,
        ExternalPayloadExchange, ExternalPayloadHandler, ExternalPayloadProvider, ExternalRequest, PayloadProtection,
    };
    use rustfs_gateway::{BoxFuture, ByteStream, HandlerContext, HandlerError, TransportSecurity, collect};

    mod request_trace {
        use super::*;
        use rustfs_gateway::external_payload::{ExternalGetResponse, ExternalResponseConsumer, ExternalResponseResult};
        use rustfs_gateway::{HostId, HostRequestId, Observer, RequestEvent, RequestId, RequestTrace, TraceSource};
        use std::sync::Mutex;

        const HOST_REQUEST_ID: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

        #[derive(Default)]
        struct Traces {
            minted: AtomicUsize,
            observed: Mutex<Vec<String>>,
        }
        impl TraceSource for Traces {
            fn mint(&self) -> RequestTrace {
                let ordinal = self.minted.fetch_add(1, Ordering::SeqCst) + 1;
                RequestTrace::new(RequestId::from_bits(ordinal as u64), HostId::from_bits(17))
            }
        }
        impl Observer for Traces {
            fn on_response(&self, event: &RequestEvent<'_>) {
                self.observed.lock().unwrap().push(event.request_id.as_str().to_owned());
            }
        }
        fn builder(legacy: bool, traces: &Arc<Traces>) -> rustfs_gateway::ServiceBuilder {
            let builder = support::wired_at_signed_time()
                .trace_source(traces.clone())
                .observer(traces.clone());
            if legacy { builder.rustfs_profile() } else { builder }
        }
        fn identify(request: &mut http::Request<Full<Bytes>>, host: bool) -> String {
            if host {
                request.extensions_mut().insert(HostRequestId::new(HOST_REQUEST_ID).unwrap());
                HOST_REQUEST_ID.to_owned()
            } else {
                RequestId::from_bits(1).as_str().to_owned()
            }
        }
        fn assert_head(headers: &HeaderMap, legacy: bool, expected: &str) {
            let value = |name: &str| headers.get(name).map(|value| value.to_str().unwrap().to_owned());
            assert_eq!(
                (value("x-amz-request-id"), value("x-request-id"), value("x-amz-id-2")),
                (
                    Some(expected.to_owned()),
                    legacy.then(|| expected.to_owned()),
                    (!legacy).then(|| HostId::from_bits(17).as_str().to_owned()),
                ),
            );
        }
        async fn assert_error(response: http::Response<rustfs_gateway::Body>, legacy: bool, expected: &str) {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_head(response.headers(), legacy, expected);
            let response = collect(response).await.unwrap();
            let xml = std::str::from_utf8(response.body()).unwrap();
            assert!(xml.contains(&format!("<RequestId>{expected}</RequestId>")));
            assert_eq!(xml.contains("<HostId>"), !legacy);
        }
        async fn invalid_binding(control: bool) {
            for legacy in [false, true] {
                for host in [false, true] {
                    let traces = Arc::new(Traces::default());
                    let service = builder(legacy, &traces)
                        .register_external_payload::<dto::PutObject, _>(Arc::new(VerifiedBackend(Arc::default())))
                        .build()
                        .unwrap();
                    let mut request = request(&[]);
                    let expected = identify(&mut request, host);
                    request.extensions_mut().remove::<TransportSecurity>();
                    let response = if control {
                        service
                            .call_with_external_control_bound(request, binding(), Box::new(Query(Arc::default())))
                            .await
                    } else {
                        service
                            .call_with_external_payload_bound(request, binding(), exchange(Arc::default(), b"object"))
                            .await
                            .into_parts()
                            .0
                    };
                    assert_error(response, legacy, &expected).await;
                    assert_eq!(traces.observed.lock().unwrap().as_slice(), std::slice::from_ref(&expected));
                    assert_eq!(traces.minted.load(Ordering::SeqCst), 1);
                }
            }
        }
        #[tokio::test]
        async fn payload_binding_refusal_preserves_request_identity() {
            invalid_binding(false).await;
        }
        #[tokio::test]
        async fn control_binding_refusal_preserves_request_identity() {
            invalid_binding(true).await;
        }

        struct Get;
        impl Handler<dto::GetObject> for Get {
            async fn call(&self, _: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
                Ok(Resp::new(dto::GetObjectOutput {
                    body: Some(ByteStream::from_bytes(Bytes::from_static(b"object"))),
                    content_length: Some(6),
                    ..Default::default()
                }))
            }
        }
        struct Consumer {
            fail: bool,
            head: Arc<Mutex<Option<HeaderMap>>>,
        }
        impl ExternalResponseConsumer for Consumer {
            fn protection(&self) -> PayloadProtection {
                PayloadProtection::ConfidentialAuthenticated
            }
            fn consume(
                self: Box<Self>,
                response: ExternalGetResponse,
            ) -> BoxFuture<'static, Result<ExternalResponseResult, ExternalPayloadError>> {
                Box::pin(async move {
                    let (_, _, headers, body, _) = response.into_parts();
                    *self.head.lock().unwrap() = Some(headers);
                    if self.fail {
                        return Err(ExternalPayloadError::Transport);
                    }
                    let response = collect(http::Response::new(body.into_body())).await.unwrap();
                    Ok(ExternalResponseResult::new(
                        response.body().len() as u64,
                        rustfs_gateway_stream::TrailingHeaders::empty(),
                    ))
                })
            }
        }
        async fn download(fail: bool) {
            for legacy in [false, true] {
                for host in [false, true] {
                    let traces = Arc::new(Traces::default());
                    let service = builder(legacy, &traces)
                        .register::<dto::GetObject, _>(Arc::new(Get))
                        .build()
                        .unwrap();
                    let mut request = get_query_request();
                    let expected = identify(&mut request, host);
                    let head = Arc::new(Mutex::new(None));
                    let (response, _) = service
                        .call_with_external_payload_bound(
                            request,
                            binding(),
                            ExternalPayloadExchange::Download(Box::new(Consumer {
                                fail,
                                head: head.clone(),
                            })),
                        )
                        .await
                        .into_parts();
                    if head.lock().unwrap().is_none() {
                        let response = collect(response).await.unwrap();
                        panic!("consumer was not called: {}", String::from_utf8_lossy(response.body()));
                    }
                    assert_head(head.lock().unwrap().as_ref().unwrap(), legacy, &expected);
                    assert_eq!(traces.observed.lock().unwrap().as_slice(), std::slice::from_ref(&expected));
                    if fail {
                        assert_error(response, legacy, &expected).await;
                    } else {
                        assert_head(response.headers(), legacy, &expected);
                        assert_eq!(response.status(), StatusCode::OK);
                    }
                    assert_eq!(traces.minted.load(Ordering::SeqCst), 1);
                }
            }
        }
        #[tokio::test]
        async fn download_failure_preserves_the_observed_request_identity() {
            download(true).await;
        }
        #[tokio::test]
        async fn download_success_uses_one_request_identity() {
            download(false).await;
        }
    }

    struct Query(Arc<AtomicUsize>);
    impl rustfs_gateway::external_payload::ExternalControlQuery for Query {
        fn query(
            self: Box<Self>,
            request: ExternalRequest,
        ) -> BoxFuture<'static, Result<rustfs_gateway::external_payload::ExternalControlResponse, HandlerError>> {
            Box::pin(async move {
                assert!(matches!(request.context().operation(), "PutObject" | "GetObject"));
                assert!(request.context().principal().is_some());
                assert_eq!(request.binding_digest(), &[3; 32]);
                self.0.fetch_add(1, Ordering::SeqCst);
                rustfs_gateway::external_payload::ExternalControlResponse::new(
                    StatusCode::OK,
                    HeaderMap::new(),
                    b"original-result".to_vec(),
                )
                .map_err(|_| HandlerError::internal_error("control output is invalid"))
            })
        }
    }
    struct QueryGetBackend(Arc<AtomicUsize>);
    impl Handler<dto::GetObject> for QueryGetBackend {
        async fn call(&self, _: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Resp::new(dto::GetObjectOutput::default()))
        }
    }
    fn get_query_request() -> http::Request<Full<Bytes>> {
        let request = support::signed_external(Method::GET, "/bucket/object", &[("x-rustfs-rdma-binding", "opaque")]);
        let (mut parts, body) = request.into_parts();
        parts.extensions.insert(TransportSecurity::Encrypted);
        http::Request::from_parts(parts, Full::new(body))
    }
    struct QueryGate {
        route: bool,
        input: bool,
        route_calls: Arc<AtomicUsize>,
        input_calls: Arc<AtomicUsize>,
    }
    impl rustfs_gateway::Authorizer for QueryGate {
        fn authorize_route<'a>(
            &'a self,
            _: &'a rustfs_gateway::RequestContext<'a>,
            _: &'a rustfs_gateway::AuthzRequest<'a>,
        ) -> BoxFuture<'a, rustfs_gateway::Decision> {
            self.route_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if self.route {
                    rustfs_gateway::Decision::Allow
                } else {
                    rustfs_gateway::Decision::Deny
                }
            })
        }
        fn authorize_input<'a>(
            &'a self,
            _: &'a rustfs_gateway::RequestContext<'a>,
            request: &'a rustfs_gateway::InputAuthzRequest<'a>,
        ) -> BoxFuture<'a, rustfs_gateway::InputDecisions> {
            self.input_calls.fetch_add(1, Ordering::SeqCst);
            let decision = if self.input {
                rustfs_gateway::Decision::Allow
            } else {
                rustfs_gateway::Decision::Deny
            };
            let decisions = request.decide_all(decision, |_| decision);
            Box::pin(async move { decisions })
        }
    }
    #[tokio::test]
    async fn authorized_control_query_observes_without_executing_the_backend() {
        let calls = Arc::new(AtomicUsize::new(0));
        let queries = Arc::new(AtomicUsize::new(0));
        let service = support::wired_at_signed_time()
            .register_external_payload::<dto::PutObject, _>(Arc::new(VerifiedBackend(calls.clone())))
            .build()
            .unwrap();
        let response = service
            .call_with_external_control_bound(request(&[]), binding(), Box::new(Query(queries.clone())))
            .await;
        let response = collect(response).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{:?}", response.body());
        assert_eq!(response.body().as_ref(), b"original-result");
        assert_eq!(queries.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn authorized_get_control_query_observes_without_executing_the_backend() {
        let calls = Arc::new(AtomicUsize::new(0));
        let queries = Arc::new(AtomicUsize::new(0));
        let service = support::wired_at_signed_time()
            .register::<dto::GetObject, _>(Arc::new(QueryGetBackend(calls.clone())))
            .build()
            .unwrap();
        let response = service
            .call_with_external_control_bound(get_query_request(), binding(), Box::new(Query(queries.clone())))
            .await;
        let response = collect(response).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{:?}", response.body());
        assert_eq!(response.body().as_ref(), b"original-result");
        assert_eq!(queries.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn get_control_query_cannot_bypass_either_authorization_stage() {
        for (route, input) in [(false, true), (true, false)] {
            let calls = Arc::new(AtomicUsize::new(0));
            let queries = Arc::new(AtomicUsize::new(0));
            let route_calls = Arc::new(AtomicUsize::new(0));
            let input_calls = Arc::new(AtomicUsize::new(0));
            let service = support::wired_at_signed_time()
                .authorizer(QueryGate {
                    route,
                    input,
                    route_calls: route_calls.clone(),
                    input_calls: input_calls.clone(),
                })
                .register::<dto::GetObject, _>(Arc::new(QueryGetBackend(calls.clone())))
                .build()
                .unwrap();
            let response = service
                .call_with_external_control_bound(get_query_request(), binding(), Box::new(Query(queries.clone())))
                .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(route_calls.load(Ordering::SeqCst) > 0);
            assert_eq!(input_calls.load(Ordering::SeqCst) > 0, route);
            assert_eq!(queries.load(Ordering::SeqCst), 0);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn control_query_cannot_bypass_either_authorization_stage() {
        for (route, input) in [(false, true), (true, false)] {
            let calls = Arc::new(AtomicUsize::new(0));
            let queries = Arc::new(AtomicUsize::new(0));
            let route_calls = Arc::new(AtomicUsize::new(0));
            let input_calls = Arc::new(AtomicUsize::new(0));
            let service = support::wired_at_signed_time()
                .authorizer(QueryGate {
                    route,
                    input,
                    route_calls: route_calls.clone(),
                    input_calls: input_calls.clone(),
                })
                .register_external_payload::<dto::PutObject, _>(Arc::new(VerifiedBackend(calls.clone())))
                .build()
                .unwrap();
            let response = service
                .call_with_external_control_bound(request(&[]), binding(), Box::new(Query(queries.clone())))
                .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(route_calls.load(Ordering::SeqCst) > 0);
            assert_eq!(input_calls.load(Ordering::SeqCst) > 0, route);
            assert_eq!(queries.load(Ordering::SeqCst), 0);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn control_query_cannot_bypass_signature_or_binding() {
        for signature in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let queries = Arc::new(AtomicUsize::new(0));
            let service = support::wired_at_signed_time()
                .register_external_payload::<dto::PutObject, _>(Arc::new(VerifiedBackend(calls.clone())))
                .build()
                .unwrap();
            let mut request = request(&[]);
            if signature {
                request
                    .headers_mut()
                    .insert("x-amz-date", HeaderValue::from_static("20200101T000000Z"));
            } else {
                // A valid signature over a different value isolates the expected-binding guard.
                let signed = support::signed_external(
                    Method::PUT,
                    "/bucket/object",
                    &[("content-length", "0"), ("x-rustfs-rdma-binding", "different")],
                );
                let (mut parts, body) = signed.into_parts();
                parts.extensions.insert(TransportSecurity::Encrypted);
                request = http::Request::from_parts(parts, Full::new(body));
            }
            let response = service
                .call_with_external_control_bound(request, binding(), Box::new(Query(queries.clone())))
                .await;
            assert!(!response.status().is_success());
            assert_eq!(queries.load(Ordering::SeqCst), 0);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
    struct Control;
    impl ExternalPayloadControl for Control {
        fn accept(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
            Box::pin(async { Ok(()) })
        }
        fn wait_verified(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
            Box::pin(async { Ok(()) })
        }
        fn cancel(&self) {}
        fn protection(&self) -> PayloadProtection {
            PayloadProtection::Authenticated
        }
    }
    struct Provider(Arc<AtomicUsize>, Bytes);
    impl ExternalPayloadProvider for Provider {
        fn prepare(
            self: Box<Self>,
            request: ExternalRequest,
        ) -> BoxFuture<'static, Result<ExternalPayload, ExternalPayloadError>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                ExternalPayload::new(ByteStream::from_bytes(self.1), Arc::new(Control), *request.binding_digest())
            })
        }
    }
    struct VerifiedBackend(Arc<AtomicUsize>);
    impl Handler<dto::PutObject> for VerifiedBackend {
        async fn call(&self, _request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
            self.0.fetch_add(100, Ordering::SeqCst);
            Ok(Resp::new(dto::PutObjectOutput::default()))
        }
    }
    impl ExternalPayloadHandler<dto::PutObject> for VerifiedBackend {
        fn call_with_external_payload<'a>(
            &'a self,
            request: Req<dto::PutObject>,
            _: HandlerContext,
            payload: ExternalPayloadContext,
        ) -> BoxFuture<'a, HandlerResult<dto::PutObject>> {
            Box::pin(async move {
                payload.accept_after_admission().await?;
                let input = request.into_input();
                let body = collect(http::Response::new(
                    input
                        .body
                        .ok_or_else(|| HandlerError::internal_error("missing external input"))?
                        .into_body(),
                ))
                .await
                .map_err(|_| HandlerError::internal_error("logical body failed"))?;
                if body.body().as_ref() != b"object" {
                    return Err(HandlerError::internal_error("unexpected object"));
                }
                payload.verify_before_publish().await?;
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Resp::new(dto::PutObjectOutput::default()))
            })
        }
    }
    fn binding() -> ExternalPayloadBinding {
        let mut headers = HeaderMap::new();
        headers.insert("x-rustfs-rdma-binding", HeaderValue::from_static("opaque"));
        ExternalPayloadBinding::new([3; 32], 6, headers).unwrap()
    }
    fn request(extra: &[(&str, &str)]) -> http::Request<Full<Bytes>> {
        let mut fields = vec![("content-length", "0"), ("x-rustfs-rdma-binding", "opaque")];
        fields.extend_from_slice(extra);
        let request = support::signed_external(Method::PUT, "/bucket/object", &fields);
        let (mut parts, body) = request.into_parts();
        parts.extensions.insert(TransportSecurity::Encrypted);
        http::Request::from_parts(parts, Full::new(body))
    }
    fn exchange(prepared: Arc<AtomicUsize>, bytes: &'static [u8]) -> ExternalPayloadExchange {
        ExternalPayloadExchange::Upload(Box::new(Provider(prepared, Bytes::from_static(bytes))))
    }
    #[tokio::test]
    async fn signed_external_upload_reuses_s3_dispatch_and_verified_publication() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prepared = Arc::new(AtomicUsize::new(0));
        let service = support::wired_at_signed_time()
            .register_external_payload::<dto::PutObject, _>(Arc::new(VerifiedBackend(calls.clone())))
            .build()
            .unwrap();
        let result = service
            .call_with_external_payload_bound(request(&[]), binding(), exchange(prepared.clone(), b"object"))
            .await;
        let response = collect(result.into_parts().0).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{:?}", response.body());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(prepared.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn ordinary_handler_is_rejected_before_any_backend_effect() {
        let (service, calls) = service();
        let prepared = Arc::new(AtomicUsize::new(0));
        let result = service
            .call_with_external_payload_bound(request(&[]), binding(), exchange(prepared.clone(), b"object"))
            .await;
        assert_eq!(result.response().status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(prepared.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn invalid_signature_does_not_prepare_an_external_peer() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prepared = Arc::new(AtomicUsize::new(0));
        let service = support::wired_at_signed_time()
            .register_external_payload::<dto::PutObject, _>(Arc::new(VerifiedBackend(calls.clone())))
            .build()
            .unwrap();
        let mut request = request(&[]);
        *request.uri_mut() = "/bucket/tampered".parse().unwrap();
        let result = service
            .call_with_external_payload_bound(request, binding(), exchange(prepared.clone(), b"object"))
            .await;
        assert_eq!(result.response().status(), StatusCode::FORBIDDEN);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(prepared.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn logical_checksum_mismatch_prevents_publication() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prepared = Arc::new(AtomicUsize::new(0));
        let service = support::wired_at_signed_time()
            .register_external_payload::<dto::PutObject, _>(Arc::new(VerifiedBackend(calls.clone())))
            .build()
            .unwrap();
        let result = service
            .call_with_external_payload_bound(
                request(&[("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")]),
                binding(),
                exchange(prepared, b"object"),
            )
            .await;
        assert_eq!(result.response().status(), StatusCode::BAD_REQUEST);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    struct FailedProducer(Option<rustfs_gateway_stream::StreamError>);
    impl rustfs_gateway_stream::PayloadStream for FailedProducer {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<rustfs_gateway_stream::PayloadRead, rustfs_gateway_stream::StreamError>> {
            std::task::Poll::Ready(Err(self.get_mut().0.take().unwrap()))
        }
        fn caps(&self) -> rustfs_gateway_stream::PayloadCaps {
            rustfs_gateway_stream::PayloadCaps::PUSH | rustfs_gateway_stream::PayloadCaps::KNOWN_LENGTH
        }
        fn len_hint(&self) -> Option<u64> {
            Some(6)
        }
    }
    struct FailedProvider(ExternalPayloadError);
    impl ExternalPayloadProvider for FailedProvider {
        fn prepare(
            self: Box<Self>,
            request: ExternalRequest,
        ) -> BoxFuture<'static, Result<ExternalPayload, ExternalPayloadError>> {
            Box::pin(async move {
                let body = ByteStream::new(Box::pin(FailedProducer(Some(self.0.into_stream_error())))).unwrap();
                ExternalPayload::new(body, Arc::new(Control), *request.binding_digest())
            })
        }
    }
    struct ObserveFailure(Arc<std::sync::Mutex<Option<String>>>);
    impl Handler<dto::PutObject> for ObserveFailure {
        async fn call(&self, _: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
            Err(HandlerError::internal_error("ordinary handler cannot observe external failure"))
        }
    }
    impl ExternalPayloadHandler<dto::PutObject> for ObserveFailure {
        fn call_with_external_payload<'a>(
            &'a self,
            request: Req<dto::PutObject>,
            _: HandlerContext,
            payload: ExternalPayloadContext,
        ) -> BoxFuture<'a, HandlerResult<dto::PutObject>> {
            Box::pin(async move {
                payload.accept_after_admission().await?;
                let body = request.into_input().body.unwrap().into_body();
                assert!(collect(http::Response::new(body)).await.is_err());
                let error = payload.verify_before_publish().await.unwrap_err();
                *self.0.lock().unwrap() = Some(error.message().to_owned());
                Err(error)
            })
        }
    }
    #[tokio::test]
    async fn producer_failure_classes_survive_the_complete_s3_body_pipeline() {
        for expected in [
            ExternalPayloadError::Cancelled,
            ExternalPayloadError::Unavailable,
            ExternalPayloadError::Transport,
        ] {
            let observed = Arc::new(std::sync::Mutex::new(None));
            let service = support::wired_at_signed_time()
                .register_external_payload::<dto::PutObject, _>(Arc::new(ObserveFailure(observed.clone())))
                .build()
                .unwrap();
            let result = service
                .call_with_external_payload_bound(
                    request(&[]),
                    binding(),
                    ExternalPayloadExchange::Upload(Box::new(FailedProvider(expected))),
                )
                .await;
            assert!(!result.response().status().is_success());
            assert_eq!(observed.lock().unwrap().as_deref(), Some(expected.to_string().as_str()));
        }
    }
}
