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

//! Verified external uploads through the real filesystem publication boundary.
//!
//! Responsible for: persisted objects and parts, rejection without publication and selected GET bytes.
//! NOT responsible for: native devices or private control encoding.
//! Upstream: ordinary S3 dispatch and external input ports. Downstream: the consolidated CRUD harness.

use super::*;
use rustfs_gateway::external_payload::{
    ExternalGetResponse, ExternalPayload, ExternalPayloadBinding, ExternalPayloadControl, ExternalPayloadError,
    ExternalPayloadExchange, ExternalPayloadProvider, ExternalRequest, ExternalResponseConsumer, ExternalResponseResult,
    PayloadProtection,
};
use rustfs_gateway::sig::{PayloadMode, SigService};
use rustfs_gateway::{BoxFuture, TransportSecurity};
use std::sync::Mutex;

struct Control {
    accepted: Arc<Mutex<usize>>,
    fail: bool,
}
impl ExternalPayloadControl for Control {
    fn accept(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
        Box::pin(async move {
            *self.accepted.lock().unwrap() += 1;
            Ok(())
        })
    }
    fn wait_verified(&self) -> BoxFuture<'_, Result<(), ExternalPayloadError>> {
        Box::pin(async move {
            if self.fail {
                Err(ExternalPayloadError::Transport)
            } else {
                Ok(())
            }
        })
    }
    fn cancel(&self) {}
    fn protection(&self) -> PayloadProtection {
        PayloadProtection::Authenticated
    }
}
struct Provider {
    bytes: Bytes,
    accepted: Arc<Mutex<usize>>,
    fail: bool,
}
impl ExternalPayloadProvider for Provider {
    fn prepare(self: Box<Self>, request: ExternalRequest) -> BoxFuture<'static, Result<ExternalPayload, ExternalPayloadError>> {
        Box::pin(async move {
            ExternalPayload::new(
                rustfs_gateway::ByteStream::from_bytes(self.bytes),
                Arc::new(Control {
                    accepted: self.accepted,
                    fail: self.fail,
                }),
                *request.binding_digest(),
            )
        })
    }
}
fn external_service(root: &TestRoot) -> S3Service {
    let backend =
        Arc::new(FsBackend::open_with_clock(&root.0, Arc::new(FixedClock::at_unix_seconds(SIGNED_AT_SECONDS))).unwrap());
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret").unwrap()));
    backend
        .register_with_external_payload(
            rustfs_gateway::ServiceBuilder::new()
                .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).unwrap()))
                .authorizer(allow_when(|_| true))
                .clock_with_skew_ack(
                    FixedClock::at_unix_seconds(SIGNED_AT_SECONDS),
                    ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
                ),
        )
        .build()
        .unwrap()
}
fn binding(length: u64) -> ExternalPayloadBinding {
    let mut fields = http::HeaderMap::new();
    fields.insert("x-rustfs-rdma-binding", http::HeaderValue::from_static("opaque"));
    ExternalPayloadBinding::new([3; 32], length, fields).unwrap()
}
fn external_request(method: http::Method, target: &str, extra: &[(&str, &str)]) -> http::Request<http_body_util::Full<Bytes>> {
    use rustfs_gateway::sig::{AmzDate, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
    let mut headers = http::HeaderMap::new();
    headers.insert("host", http::HeaderValue::from_static("s3.example.com"));
    headers.insert("content-length", http::HeaderValue::from_static("0"));
    headers.insert("x-rustfs-rdma-binding", http::HeaderValue::from_static("opaque"));
    for (name, value) in extra {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::HeaderValue::from_str(value).unwrap(),
        );
    }
    let probe = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .unwrap();
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).unwrap();
    let stamp = AmzDate::parse(SIGNED_AT).unwrap();
    let mut signer = SigV4Signer::new(
        SigningCredentials::new("AKIDEXAMPLE", b"secret").unwrap(),
        SigningScope::new(stamp.day(), "us-east-1", SigService::S3).unwrap(),
    );
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let request = SigningRequest::new(
        &method,
        path,
        query,
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::Unsigned,
        stamp,
    )
    .with_wire_content_length(0);
    let signed = signer.sign_headers(&request).unwrap();
    let mut result = http::Request::builder()
        .method(method)
        .uri(target)
        .body(http_body_util::Full::new(Bytes::new()))
        .unwrap();
    for (name, value) in signed.headers() {
        result.headers_mut().append(name.clone(), value.clone());
    }
    result.extensions_mut().insert(TransportSecurity::Encrypted);
    result
}
async fn upload(
    service: &S3Service,
    target: &str,
    bytes: &'static [u8],
    extra: &[(&str, &str)],
    fail: bool,
) -> (rustfs_gateway::WireResponse, usize) {
    let accepted = Arc::new(Mutex::new(0));
    let provider = Provider {
        bytes: Bytes::from_static(bytes),
        accepted: accepted.clone(),
        fail,
    };
    let result = service
        .call_with_external_payload_bound(
            external_request(http::Method::PUT, target, extra),
            binding(bytes.len() as u64),
            ExternalPayloadExchange::Upload(Box::new(provider)),
        )
        .await;
    (collect(result.into_parts().0).await.unwrap(), *accepted.lock().unwrap())
}
#[tokio::test]
async fn external_put_publishes_the_received_object_and_preserves_default_get() {
    let root = TestRoot::new();
    let service = external_service(&root);
    create_bucket(&service, "bucket").await;
    let (result, accepted) = upload(&service, "/bucket/object", b"object", &[], false).await;
    assert_eq!(result.status(), 200, "{}", String::from_utf8_lossy(result.body()));
    assert_eq!(accepted, 1);
    let get = exchange(&service, signed(http::Method::GET, "/bucket/object", Bytes::new())).await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.body().as_ref(), b"object");
}
#[tokio::test]
async fn empty_external_put_still_requires_admission_and_transport_verification() {
    let root = TestRoot::new();
    let service = external_service(&root);
    create_bucket(&service, "bucket").await;
    let (result, accepted) = upload(&service, "/bucket/empty", b"", &[], false).await;
    assert_eq!(result.status(), 200, "{}", String::from_utf8_lossy(result.body()));
    assert_eq!(accepted, 1);
    let get = exchange(&service, signed(http::Method::GET, "/bucket/empty", Bytes::new())).await;
    assert_eq!(get.status(), 200);
    assert!(get.body().is_empty());
    let (failed, accepted) = upload(&service, "/bucket/failed-empty", b"", &[], true).await;
    assert_eq!(failed.status(), 500);
    assert_eq!(accepted, 1);
    let get = exchange(&service, signed(http::Method::GET, "/bucket/failed-empty", Bytes::new())).await;
    assert_eq!(get.status(), 404);
}
#[tokio::test]
async fn failed_transport_verification_cannot_publish_a_version() {
    let root = TestRoot::new();
    let service = external_service(&root);
    create_bucket(&service, "bucket").await;
    let (result, accepted) = upload(&service, "/bucket/object", b"object", &[], true).await;
    assert_eq!(result.status(), http::StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(accepted, 1);
    let get = exchange(&service, signed(http::Method::GET, "/bucket/object", Bytes::new())).await;
    assert_eq!(get.status(), 404);
}
#[tokio::test]
async fn checksum_failure_cannot_publish_a_version() {
    let root = TestRoot::new();
    let service = external_service(&root);
    create_bucket(&service, "bucket").await;
    let (result, _) = upload(
        &service,
        "/bucket/object",
        b"object",
        &[("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")],
        false,
    )
    .await;
    assert_eq!(result.status(), 400);
    let get = exchange(&service, signed(http::Method::GET, "/bucket/object", Bytes::new())).await;
    assert_eq!(get.status(), 404);
}
#[tokio::test]
async fn missing_bucket_refuses_before_native_admission() {
    let root = TestRoot::new();
    let service = external_service(&root);
    let (result, accepted) = upload(&service, "/missing/object", b"object", &[], false).await;
    assert_eq!(result.status(), 404);
    assert_eq!(accepted, 0);
}
#[tokio::test]
async fn external_part_uses_existing_multipart_completion() {
    let root = TestRoot::new();
    let service = external_service(&root);
    create_bucket(&service, "bucket").await;
    let id = initiate(&service, "bucket", "object").await;
    let target = format!("/bucket/object?partNumber=1&uploadId={id}");
    let (result, accepted) = upload(&service, &target, b"object", &[], false).await;
    assert_eq!(result.status(), 200);
    assert_eq!(accepted, 1);
    let etag = header(&result, "etag").unwrap().to_str().unwrap();
    let done = complete(&service, "bucket", "object", &id, &[(1, etag)]).await;
    assert_eq!(done.status(), 200);
    let get = exchange(&service, signed(http::Method::GET, "/bucket/object", Bytes::new())).await;
    assert_eq!(get.body().as_ref(), b"object");
}
#[tokio::test]
async fn unknown_upload_refuses_before_native_admission() {
    let root = TestRoot::new();
    let service = external_service(&root);
    create_bucket(&service, "bucket").await;
    let (result, accepted) = upload(&service, "/bucket/object?partNumber=1&uploadId=unknown", b"object", &[], false).await;
    assert_eq!(result.status(), 404);
    assert_eq!(accepted, 0);
}
struct Consumer {
    bytes: Arc<Mutex<Vec<u8>>>,
    skip: bool,
}
impl ExternalResponseConsumer for Consumer {
    fn protection(&self) -> PayloadProtection {
        PayloadProtection::Authenticated
    }
    fn consume(
        self: Box<Self>,
        response: ExternalGetResponse,
    ) -> BoxFuture<'static, Result<ExternalResponseResult, ExternalPayloadError>> {
        Box::pin(async move {
            let (request, _, _, body, _) = response.into_parts();
            let length = request.logical_length();
            if self.skip {
                return Ok(ExternalResponseResult::new(length, rustfs_gateway::TrailingHeaders::empty()));
            }
            let collected = collect(http::Response::new(body.into_body()))
                .await
                .map_err(|_| ExternalPayloadError::Transport)?;
            *self.bytes.lock().unwrap() = collected.body().to_vec();
            Ok(ExternalResponseResult::new(length, rustfs_gateway::TrailingHeaders::empty()))
        })
    }
}
#[tokio::test]
async fn external_get_uses_the_selected_final_representation() {
    let root = TestRoot::new();
    let service = external_service(&root);
    create_bucket(&service, "bucket").await;
    exchange(&service, signed(http::Method::PUT, "/bucket/object", Bytes::from_static(b"object"))).await;
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let result = service
        .call_with_external_payload_bound(
            external_request(http::Method::GET, "/bucket/object", &[]),
            binding(64),
            ExternalPayloadExchange::Download(Box::new(Consumer {
                bytes: bytes.clone(),
                skip: false,
            })),
        )
        .await;
    assert_eq!(result.response().status(), 200);
    assert_eq!(*bytes.lock().unwrap(), b"object");
    assert_eq!(result.into_parts().1.unwrap().bytes_transferred(), 6);
}
#[tokio::test]
async fn a_download_consumer_cannot_claim_eof_without_reading() {
    let root = TestRoot::new();
    let service = external_service(&root);
    create_bucket(&service, "bucket").await;
    exchange(&service, signed(http::Method::PUT, "/bucket/object", Bytes::from_static(b"object"))).await;
    let result = service
        .call_with_external_payload_bound(
            external_request(http::Method::GET, "/bucket/object", &[]),
            binding(64),
            ExternalPayloadExchange::Download(Box::new(Consumer {
                bytes: Arc::new(Mutex::new(Vec::new())),
                skip: true,
            })),
        )
        .await;
    assert_eq!(result.response().status(), 400);
    assert!(result.into_parts().1.is_none());
}
