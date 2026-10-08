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

//! The live-socket streaming fixture both gateway test targets assemble against.
//!
//! Responsible for: a streaming vendor operation and its dialect, a backend that drains the body,
//! the assembly and loopback server the socket suites drive, and a signed `aws-chunked` upload.
//! NOT responsible for: asserting anything; every assertion lives in the suite that makes it.
//! Upstream: `rustfs-gateway` and the generic server runtime. Downstream: the socket-timing suites
//! in `tests/socket_timing.rs` and the streaming suites that stay in `tests/integration.rs`.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    AuthRequirement, ByteStream, CodecError, EncodedResponse, Handler, HandlerDeadlineClass, HandlerResult, MetaView, NoDerived,
    Operation, OperationCodec, OperationFloor, OperationSpec, Predicate, Req, RequestBody, RequestBodyDeadlineConfig,
    RequestBodyMode, ResourceShape, Resp, ResponseBody, S3Service, ServiceConfig, SigService, TargetKind,
};
use rustfs_gateway_core::{Dialect, DialectOverlay, DialectRoute, OverlayRow};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, ShutdownReport};

pub struct StreamingPut;

pub struct StreamingInput {
    pub body: ByteStream,
}

pub struct StreamingOutput;

static STREAMING_SPEC: OperationSpec = OperationSpec::builder("example:StreamingPut", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("example:StreamingPut", ResourceShape::Service))
    .build();

static STREAMING_FLOOR: OperationFloor =
    OperationFloor::custom("example:StreamingPut", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

static STREAMING_PREDICATES: &[Predicate] = &[Predicate::Method(http::Method::PUT), Predicate::Target(TargetKind::Service)];

static STREAMING_OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-streaming-test",
    vendor: "example",
    claims: &[],
    operations: &[OverlayRow {
        name: "example:StreamingPut",
        precedence: 50,
        selector: "Method(PUT) ∧ Target(Service)",
        action: "example:StreamingPut",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: true,
        evidence: &["https://github.com/rustfs/gateway/issues/37"],
    }],
};

impl Operation for StreamingPut {
    const NAME: &'static str = "example:StreamingPut";

    type Input = StreamingInput;
    type Output = StreamingOutput;
    type DerivedResources = NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway::DerivedResourceError> {
        Ok(NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &STREAMING_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &STREAMING_FLOOR
    }
}

impl OperationCodec for StreamingPut {
    const REQUEST_BODY: RequestBodyMode = RequestBodyMode::Streaming;

    fn decode(_request: &MetaView<'_>, body: RequestBody) -> Result<Self::Input, CodecError> {
        body.into_stream()
            .map(|body| StreamingInput { body })
            .ok_or_else(|| CodecError::internal("the streaming operation was not handed a live body"))
    }

    fn encode(_output: Self::Output, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut response = EncodedResponse::of(status);
        response.body = ResponseBody::Complete(b"ok".to_vec());
        Ok(response)
    }
}

pub fn streaming_dialect() -> Dialect {
    Dialect::assemble(&STREAMING_OVERLAY)
        .declare::<StreamingPut>(DialectRoute {
            precedence: 50,
            selector: STREAMING_PREDICATES,
            path_shape: "/",
            shadows: &[],
        })
        .build()
        .expect("the streaming overlay and codec declaration must agree")
}

pub struct SwallowingBackend;

impl Handler<StreamingPut> for SwallowingBackend {
    async fn call(&self, request: Req<StreamingPut>) -> HandlerResult<StreamingPut> {
        let mut body = request.into_input().body.into_body();
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                break;
            }
        }
        Ok(Resp::new(StreamingOutput))
    }
}

pub fn service_with_deadlines<B>(backend: Arc<B>, deadlines: RequestBodyDeadlineConfig) -> S3Service
where
    B: Handler<StreamingPut>,
{
    let (builder, _handle) = super::wired()
        .clock_with_skew_ack(
            super::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<StreamingPut, _>(backend)
        .dialect(&streaming_dialect())
        .config(ServiceConfig::new(1024 * 1024).with_request_body_deadlines(deadlines));
    builder.build().expect("a complete streaming assembly")
}

pub fn live_server(service: S3Service) -> RunningServer {
    let service = tower::service_fn(move |request| {
        let mut service = service.clone();
        async move {
            let response = <S3Service as tower::Service<_>>::call(&mut service, request)
                .await
                .expect("the adapter is infallible");
            let collected = rustfs_gateway::collect(response).await.expect("the response is finite");
            let (status, headers, body, _trailers) = collected.into_parts();
            let mut response = http::Response::new(Full::new(body));
            *response.status_mut() = status;
            for (name, value) in headers {
                response.headers_mut().append(name, value);
            }
            Ok::<_, Infallible>(response)
        }
    });
    Server::new(
        ServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plaintext: true,
            so_rcvbuf: Some(8 * 1024),
            lingering_close_time: Duration::from_millis(20),
            ..ServerConfig::default()
        },
        service,
    )
    .serve()
    .expect("the loopback server starts")
}

pub async fn stop(running: RunningServer) {
    assert_eq!(
        running.shutdown.trigger(Duration::from_secs(1)).await,
        ShutdownReport { drained: 0, aborted: 0 }
    );
    assert!(running.task.await.expect("the server task joins").is_ok());
}

pub const SIGNED_CHUNK_BYTES: usize = 256;

pub fn signed_chunked_request(decoded_len: usize) -> (Vec<u8>, Vec<u8>) {
    signed_chunked_request_with_chunk_bytes(decoded_len, SIGNED_CHUNK_BYTES)
}

pub fn signed_chunked_request_with_chunk_bytes(decoded_len: usize, chunk_bytes: usize) -> (Vec<u8>, Vec<u8>) {
    let decoded: Vec<u8> = (0..decoded_len).map(|index| (index % 251) as u8).collect();
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(super::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);
    let probe = http::Request::builder()
        .method(http::Method::PUT)
        .uri("/")
        .header("host", "localhost")
        .body(())
        .expect("a valid request");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("an acceptable host");
    let wire_len = decoded
        .chunks(chunk_bytes)
        .map(|chunk| chunk.len() + format!("{:x}", chunk.len()).len() + 17 + 64 + 4)
        .sum::<usize>()
        + 1
        + 17
        + 64
        + 4;
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("localhost"));
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&wire_len.to_string()).expect("a digit run"),
    );
    let signing = SigningRequest::new(
        &http::Method::PUT,
        "/",
        "",
        &headers,
        accepted.host().raw_for_signing(),
        PayloadMode::StreamingSigned {
            trailer: rustfs_gateway::sig::TrailerSet::None,
        },
        stamp,
    )
    .with_wire_content_length(wire_len as u64)
    .with_decoded_content_length(decoded_len as u64);
    let signed = signer.sign_headers(&signing).expect("a signable request");
    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let mut wire = Vec::with_capacity(wire_len);
    for chunk in decoded.chunks(chunk_bytes) {
        wire.extend_from_slice(&chain.encode_chunk(chunk));
    }
    wire.extend_from_slice(&chain.encode_chunk(b""));
    assert_eq!(wire.len(), wire_len, "the signed wire length must be the one that was signed");

    let mut head = b"PUT / HTTP/1.1\r\n".to_vec();
    for (name, value) in signed.headers() {
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    (head, wire)
}
