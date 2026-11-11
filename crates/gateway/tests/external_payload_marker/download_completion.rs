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

//! Checks the outcome of a bound GetObject at the gateway service boundary.
//!
//! Responsible for: verifying EOF trailers, response filtering and the final request event.
//! NOT responsible for: host transport framing.
//! Upstream: signed GetObject fixtures and the real response stream.
//! Downstream: the returned S3 response and the observer selected for the request.

use super::{execution::binding, support};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::Full;
use rustfs_gateway::external_payload::{
    ExternalGetResponse, ExternalPayloadError, ExternalPayloadExchange, ExternalResponseConsumer, ExternalResponseResult,
    PayloadProtection,
};
use rustfs_gateway::{
    AssemblyUpdate, BoxFuture, BucketName, ByteStream, CorsSource, CorsSourceError, Handler, HandlerResult, Observer, Req,
    RequestEvent, Resp, TransportSecurity, allow_when, collect, dto, response_filter,
};
use rustfs_gateway_stream::{PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

const ORIGIN: &str = "https://app.example.test";
const CHECKSUM: &str = "x-amz-checksum-crc32";

struct Source(Option<Bytes>);
impl PayloadStream for Source {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        Poll::Ready(Ok(match self.0.take() {
            Some(chunk) => PayloadRead::Chunk(chunk),
            None => {
                let mut trailer = HeaderMap::new();
                trailer.insert(CHECKSUM, HeaderValue::from_static("Nks/tw=="));
                PayloadRead::Eof {
                    trailers: TrailingHeaders::from_header_map(trailer),
                }
            }
        }))
    }
    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH
    }
    fn len_hint(&self) -> Option<u64> {
        Some(self.0.as_ref().map_or(0, |chunk| chunk.len() as u64))
    }
}
struct Get;
impl Handler<dto::GetObject> for Get {
    async fn call(&self, _: Req<dto::GetObject>) -> HandlerResult<dto::GetObject> {
        Ok(Resp::new(dto::GetObjectOutput {
            body: Some(ByteStream::new(Box::pin(Source(Some(Bytes::from_static(b"data"))))).unwrap()),
            content_length: Some(4),
            ..Default::default()
        }))
    }
}
impl CorsSource for Get {
    fn load<'a>(&'a self, _: &'a BucketName) -> BoxFuture<'a, Result<Option<dto::CorsConfiguration>, CorsSourceError>> {
        Box::pin(async {
            Ok(Some(dto::CorsConfiguration {
                cors_rules: vec![dto::CorsRule {
                    allowed_methods: vec!["GET".to_owned()],
                    allowed_origins: vec![ORIGIN.to_owned()],
                    ..Default::default()
                }],
            }))
        })
    }
}
struct Consumer {
    receipt: Result<HeaderMap, ExternalPayloadError>,
    selected_head: Arc<Mutex<Option<HeaderMap>>>,
    before_completion: Box<dyn FnOnce() + Send>,
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
            let (_, _, headers, mut body, _) = response.into_parts();
            *self.selected_head.lock().unwrap() = Some(headers);
            let mut data = Vec::new();
            loop {
                match std::future::poll_fn(|cx| Pin::new(&mut body).poll_read(cx)).await.unwrap() {
                    PayloadRead::Chunk(chunk) => data.extend_from_slice(&chunk),
                    PayloadRead::Eof { trailers } => {
                        assert_eq!(trailers.as_header_map()[CHECKSUM], "Nks/tw==");
                        break;
                    }
                }
            }
            assert_eq!(data, b"data");
            (self.before_completion)();
            Ok(ExternalResponseResult::new(
                data.len() as u64,
                TrailingHeaders::from_header_map(self.receipt?),
            ))
        })
    }
}

#[derive(Default)]
struct Events(Mutex<Vec<(u16, Option<String>)>>);
impl Observer for Events {
    fn on_response(&self, event: &RequestEvent<'_>) {
        self.0
            .lock()
            .unwrap()
            .push((event.status, event.error.map(|code| code.as_str().to_owned())));
    }
}

async fn download(receipt: Result<HeaderMap, ExternalPayloadError>, expected: StatusCode) {
    let events = Arc::new(Events::default());
    let next_events = Arc::new(Events::default());
    let filters = Arc::new(Mutex::new(Vec::new()));
    let selected_head = Arc::new(Mutex::new(None));
    let recorded = filters.clone();
    let service = support::wired_at_signed_time()
        .register::<dto::GetObject, _>(Arc::new(Get))
        .cors_source(Get)
        .stage_filter(response_filter(move |_, response| {
            recorded.lock().unwrap().push(response.status());
            let status = response.status();
            if expected == StatusCode::FORBIDDEN {
                return Err(rustfs_gateway::HandlerError::new(
                    rustfs_gateway::ErrorCode::ACCESS_DENIED,
                    "filtered object",
                ));
            }
            response
                .headers_mut()
                .insert("x-tested-filter", HeaderValue::from(status.as_u16()));
            Ok(())
        }))
        .observer(events.clone())
        .build()
        .unwrap();
    let before_completion = {
        let service = service.clone();
        let events = events.clone();
        let next_events = next_events.clone();
        Box::new(move || {
            assert!(events.0.lock().unwrap().is_empty());
            service
                .replace_assembly(
                    AssemblyUpdate::new()
                        .register::<dto::GetObject, _>(Arc::new(Get))
                        .authorizer(allow_when(|_| true))
                        .observer(next_events),
                )
                .unwrap();
        })
    };
    let (mut parts, body) =
        support::signed_external(Method::GET, "/bucket/object", &[("origin", ORIGIN), ("x-rustfs-rdma-binding", "opaque")])
            .into_parts();
    parts.extensions.insert(TransportSecurity::Encrypted);
    let (response, output) = service
        .call_with_external_payload_bound(
            http::Request::from_parts(parts, Full::new(body)),
            binding(),
            ExternalPayloadExchange::Download(Box::new(Consumer {
                receipt,
                selected_head: selected_head.clone(),
                before_completion,
            })),
        )
        .await
        .into_parts();
    assert_eq!(response.status(), expected);
    if expected == StatusCode::FORBIDDEN {
        assert_eq!(*filters.lock().unwrap(), [StatusCode::OK]);
        assert!(selected_head.lock().unwrap().is_none());
        assert!(output.is_none());
        assert_eq!(*events.0.lock().unwrap(), [(403, Some("AccessDenied".to_owned()))]);
        return;
    }
    let filtered = if expected.is_success() {
        vec![StatusCode::OK]
    } else {
        vec![StatusCode::OK, expected]
    };
    assert_eq!(*filters.lock().unwrap(), filtered);
    assert_eq!(response.headers()["x-tested-filter"], HeaderValue::from(expected.as_u16()));
    assert_eq!(response.headers()["access-control-allow-origin"], ORIGIN);
    assert!(response.headers().contains_key(http::header::DATE));
    let code = (expected == StatusCode::BAD_REQUEST).then(|| "InvalidRequest".to_owned());
    assert_eq!(*events.0.lock().unwrap(), [(expected.as_u16(), code)]);
    assert!(next_events.0.lock().unwrap().is_empty());
    let next = service
        .call_bytes(support::signed_with(Method::GET, "/bucket/object", &[]))
        .await;
    assert_eq!(next.status(), StatusCode::OK);
    assert_eq!(*next_events.0.lock().unwrap(), [(200, None)]);
    if let Some(output) = output {
        assert_eq!(expected, StatusCode::OK);
        assert_eq!(selected_head.lock().unwrap().as_ref().unwrap(), response.headers());
        assert_eq!(output.trailers().as_header_map()[CHECKSUM], "Nks/tw==");
    } else {
        assert_eq!(expected, StatusCode::BAD_REQUEST);
        assert!(
            std::str::from_utf8(collect(response).await.unwrap().body())
                .unwrap()
                .contains("<Code>InvalidRequest</Code>")
        );
    }
}

#[tokio::test]
async fn download_accepts_the_exact_trailers_observed_at_eof() {
    let mut trailer = HeaderMap::new();
    trailer.insert(CHECKSUM, HeaderValue::from_static("Nks/tw=="));
    download(Ok(trailer), StatusCode::OK).await;
}

#[tokio::test]
async fn download_refuses_missing_changed_or_invented_completion_trailers() {
    let mut changed = HeaderMap::new();
    changed.insert(CHECKSUM, HeaderValue::from_static("changed"));
    let mut oversized = HeaderMap::new();
    oversized.insert(CHECKSUM, HeaderValue::from_bytes(&vec![b'x'; 65_537]).unwrap());
    for receipt in [HeaderMap::new(), changed, oversized] {
        download(Ok(receipt), StatusCode::BAD_REQUEST).await;
    }
}

#[tokio::test]
async fn failed_transfer_decorates_the_refusal_and_reports_it_once() {
    download(Err(ExternalPayloadError::Transport), StatusCode::BAD_REQUEST).await;
}

#[tokio::test]
async fn response_filter_refusal_keeps_bytes_away_from_the_download_consumer() {
    download(Err(ExternalPayloadError::Transport), StatusCode::FORBIDDEN).await;
}
