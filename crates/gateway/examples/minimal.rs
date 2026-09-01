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

// a-asm-0003: this complete assembly is compiled and line-counted by its guard.

//! The smallest backend that proves the assembly path carries a request through a real listener.
//!
//! Responsible for: showing what a deployment writes — a handler, a builder, and the P7-02 server
//! listener — with explicit plaintext opt-in and graceful shutdown.
//! NOT responsible for: storing anything, TLS configuration, or production backend error handling.
//! Upstream: `rustfs-gateway` and `rustfs-gateway-server`. Downstream: a TCP S3 client.
//!
//! # Why the reachable operation is a third-party one
//!
//! Every AWS operation ships with `AllowedSchemes::HEADER_ONLY`, so reaching one means presenting
//! a SigV4 signature — and `rustfs-gateway-sig` verifies signatures without being able to produce
//! one. Until `rustfs_gateway::sig::Signer` lands there is no way for an example to sign a
//! request, so the operation this example drives to completion declares itself anonymously
//! reachable, in the one method whose name says what it costs. The `ListBuckets` request below is
//! what a standard operation does with an unsigned request, and it is asserted too.
//!
//! Run it with `cargo run -p rustfs-gateway --example minimal -- --host 127.0.0.1 --port 9000`.

use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustfs_gateway::dto::{Bucket, ListBuckets, ListBucketsOutput};
use rustfs_gateway::{
    AuthRequirement, BucketName, CodecError, Credentials, EncodedResponse, Handler, HandlerResult, MetaView, Operation,
    OperationCodec, OperationFloor, OperationSpec, Predicate, RegionSet, Req, RequestBody, ResourceShape, Resp, ServiceBuilder,
    SigService, SigV4Authenticator, StaticCredentials, TargetKind, allow_when,
};
use rustfs_gateway_core::{Dialect, DialectOverlay, DialectRoute, HandlerDeadlineClass, OverlayRow};
use rustfs_gateway_server::{RunningServer, Server, ServerConfig, ServerError};

// ── the vendor operation, which is what a dialect or an admin API looks like ────────────────────

/// A vendor operation with no input, no body, and a namespaced name.
pub struct Ping;

/// What `example:Ping` decodes to. It reads nothing from the request.
pub struct PingInput;

/// What `example:Ping` answers with.
pub struct PingOutput {
    /// The text the handler chose.
    pub message: String,
}

static PING_SPEC: OperationSpec = OperationSpec::builder("example:Ping", 200, None)
    .handler_deadline_class(HandlerDeadlineClass::Standard)
    .required_params(&[])
    .auth(AuthRequirement::new("example:Ping", ResourceShape::Service))
    .build();

/// Anonymously reachable, which is a deliberate widening and is spelled as one.
static PING_FLOOR: OperationFloor =
    OperationFloor::custom("example:Ping", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

/// `POST /`, which no AWS operation claims: the three standard `POST` routes address a bucket or
/// an object, so this selector overlaps none of them. That matters — the route table refuses a
/// third-party entry that shadows a standard one without a declaration, and the refusal is what
/// stops a vendor operation from quietly standing in front of `ListBuckets`.
static PING_PREDICATES: &[Predicate] = &[Predicate::Method(http::Method::POST), Predicate::Target(TargetKind::Service)];

static PING_OVERLAY: DialectOverlay = DialectOverlay {
    name: "example-minimal",
    vendor: "example",
    operations: &[OverlayRow {
        name: "example:Ping",
        precedence: 50,
        selector: "Method(POST) ∧ Target(Service)",
        action: "example:Ping",
        resource: ResourceShape::Service,
        success_status: 200,
        anonymous: true,
        evidence: &["https://github.com/rustfs/gateway/issues/37"],
    }],
};

impl Operation for Ping {
    const NAME: &'static str = "example:Ping";

    type Input = PingInput;
    type Output = PingOutput;
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &PING_SPEC
    }

    fn floor() -> &'static OperationFloor {
        &PING_FLOOR
    }
}

impl OperationCodec for Ping {
    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<PingInput, CodecError> {
        Ok(PingInput)
    }

    fn encode(output: PingOutput, _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        let mut encoded = EncodedResponse::of(status);
        encoded.set_header("content-type", "application/xml");
        encoded.body = rustfs_gateway::ResponseBody::Complete(format!("<Ping>{}</Ping>", output.message).into_bytes());
        Ok(encoded)
    }
}

// ── the backend ────────────────────────────────────────────────────────────────────────────────

/// A backend that owns two bucket names and nothing else.
struct InMemory {
    buckets: Vec<BucketName>,
}

impl Handler<Ping> for InMemory {
    fn call(&self, _request: Req<Ping>) -> impl core::future::Future<Output = HandlerResult<Ping>> + Send {
        let message = format!("{} buckets", self.buckets.len());
        async move { Ok(Resp::new(PingOutput { message })) }
    }

    fn call_with_context(
        &self,
        _request: Req<Ping>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<Ping>> + Send {
        let message = format!("{} buckets", self.buckets.len());
        async move { Ok(Resp::new(PingOutput { message })) }
    }
}

impl Handler<ListBuckets> for InMemory {
    fn call(&self, _request: Req<ListBuckets>) -> impl core::future::Future<Output = HandlerResult<ListBuckets>> + Send {
        let buckets: Vec<Bucket> = self
            .buckets
            .iter()
            .map(|name| Bucket {
                name: name.clone(),
                ..Bucket::default()
            })
            .collect();
        async move {
            Ok(Resp::new(ListBucketsOutput {
                buckets,
                ..ListBucketsOutput::default()
            }))
        }
    }

    fn call_with_context(
        &self,
        _request: Req<ListBuckets>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<ListBuckets>> + Send {
        let buckets: Vec<Bucket> = self
            .buckets
            .iter()
            .map(|name| Bucket {
                name: name.clone(),
                ..Bucket::default()
            })
            .collect();
        async move {
            Ok(Resp::new(ListBucketsOutput {
                buckets,
                ..ListBucketsOutput::default()
            }))
        }
    }
}

// ── the assembly ───────────────────────────────────────────────────────────────────────────────

fn build_service() -> Result<rustfs_gateway::S3Service, Box<dyn std::error::Error>> {
    // BEGIN MINIMAL ASSEMBLY
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret")?));
    let backend = Arc::new(InMemory {
        buckets: vec![BucketName::new("alpha")?, BucketName::new("beta")?],
    });
    let dialect = Dialect::assemble(&PING_OVERLAY)
        .declare::<Ping>(DialectRoute {
            precedence: 50,
            selector: PING_PREDICATES,
            path_shape: "/",
            shadows: &[],
        })
        .build()
        .map_err(|errors| io::Error::other(format!("invalid example dialect: {errors:?}")))?;
    let service = ServiceBuilder::new()
        .register::<Ping, _>(Arc::clone(&backend))
        .register::<ListBuckets, _>(backend)
        .dialect(&dialect)
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"])?))
        .authorizer(allow_when(|request| request.operation == "example:Ping"))
        .build()?;
    // END MINIMAL ASSEMBLY
    Ok(service)
}

// BEGIN MINIMAL LISTENER
fn server_config_from<I, S>(arguments: I) -> Result<ServerConfig, Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut host = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut port = 9000_u16;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_ref() {
            "--host" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--host requires an IP address"))?;
                host = value.as_ref().parse()?;
            }
            "--port" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--port requires a number"))?;
                port = value.as_ref().parse()?;
            }
            unknown => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown argument: {unknown}")).into());
            }
        }
    }
    Ok(ServerConfig {
        bind_addr: SocketAddr::new(host, port),
        plaintext: true,
        ..ServerConfig::default()
    })
}

fn start_server(config: ServerConfig, service: rustfs_gateway::S3Service) -> Result<RunningServer, ServerError> {
    Server::new(config, service).serve()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = start_server(server_config_from(env::args().skip(1))?, build_service()?)?;
    println!("listening on http://{}", running.local_addr);
    tokio::signal::ctrl_c().await?;
    let report = running.shutdown.trigger(Duration::from_secs(30)).await;
    println!("shutdown: drained={}, aborted={}", report.drained, report.aborted);
    running.task.await??;
    Ok(())
}
// END MINIMAL LISTENER

#[cfg(test)]
async fn tcp_exchange(address: SocketAddr, request: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(address).await?;
    stream.write_all(request).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8(response)?)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{build_service, server_config_from, start_server, tcp_exchange};

    #[test]
    fn cli_refuses_missing_port_value() {
        assert!(server_config_from(["--port"]).is_err());
    }

    #[test]
    fn cli_refuses_unknown_argument() {
        assert!(server_config_from(["--listen-everywhere"]).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn listener_observes_positive_and_negative_wire_paths() -> Result<(), Box<dyn Error>> {
        let config = server_config_from(["--host", "127.0.0.1", "--port", "0"])?;
        let running = start_server(config, build_service()?)?;

        let answered = tcp_exchange(
            running.local_addr,
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await?;
        assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
        assert!(answered.contains("<Ping>2 buckets</Ping>"), "{answered}");

        let refused = tcp_exchange(running.local_addr, b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await?;
        assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
        assert!(refused.contains("<Code>AccessDenied</Code>"), "{refused}");

        let _report = running.shutdown.trigger(std::time::Duration::from_secs(1)).await;
        tokio::time::timeout(std::time::Duration::from_secs(1), running.task).await???;
        Ok(())
    }
}
