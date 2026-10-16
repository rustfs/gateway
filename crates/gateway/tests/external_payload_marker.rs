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
