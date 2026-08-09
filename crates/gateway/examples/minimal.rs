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

//! The smallest backend that proves the assembly path carries a request end to end.
//!
//! Responsible for: showing what a deployment writes — a handler, a builder, one request — and
//! asserting two outcomes that together cover the whole pipeline: a request that reaches the
//! handler and comes back encoded, and a request that is stopped by the security floor.
//! NOT responsible for: storing anything, listening on a socket (P7-02), or being a template for a
//! real backend's error handling.
//! Upstream: `rustfs-gateway`. Downstream: nothing; this is a leaf.
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
//! Run it with `cargo run -p rustfs-gateway --example minimal`.

use std::sync::Arc;

use rustfs_gateway::dto::{Bucket, ListBuckets, ListBucketsOutput};
use rustfs_gateway::{
    AuthRequirement, BucketName, CodecError, Credentials, EncodedResponse, Handler, HandlerResult, MetaView, Operation,
    OperationCodec, OperationFloor, OperationSpec, Predicate, RegionSet, Req, RequestBody, ResourceShape, Resp, RouteEntry,
    RouteSelector, ServiceBuilder, SigService, SigV4Authenticator, StaticCredentials, TargetKind, allow_when,
};

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

static PING_SPEC: OperationSpec = OperationSpec {
    name: "example:Ping",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("example:Ping", ResourceShape::Service)),
};

/// Anonymously reachable, which is a deliberate widening and is spelled as one.
static PING_FLOOR: OperationFloor =
    OperationFloor::custom("example:Ping", SigService::S3).allow_anonymous_after_listing_in_the_posture_report();

/// `POST /`, which no AWS operation claims: the three standard `POST` routes address a bucket or
/// an object, so this selector overlaps none of them. That matters — the route table refuses a
/// third-party entry that shadows a standard one without a declaration, and the refusal is what
/// stops a vendor operation from quietly standing in front of `ListBuckets`.
static PING_PREDICATES: &[Predicate] = &[Predicate::Method(http::Method::POST), Predicate::Target(TargetKind::Service)];

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
}

// ── the assembly ───────────────────────────────────────────────────────────────────────────────

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // BEGIN MINIMAL ASSEMBLY
    let credentials = Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", b"secret")?));
    let backend = Arc::new(InMemory {
        buckets: vec![BucketName::new("alpha")?, BucketName::new("beta")?],
    });
    let service = ServiceBuilder::new()
        .register::<Ping, _>(Arc::clone(&backend))
        .register::<ListBuckets, _>(backend)
        .route(RouteEntry {
            precedence: 50,
            selector: RouteSelector::new(PING_PREDICATES),
            op_name: "example:Ping",
            path_shape: "/",
        })
        .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"])?))
        .authorizer(allow_when(|request| request.operation == "example:Ping"))
        .build()?;
    // END MINIMAL ASSEMBLY

    // The whole pipeline, end to end: accepted, resolved, routed, governed, admitted, decoded,
    // authorised, dispatched, encoded.
    let answered = exchange(&service, http::Method::POST, "/").await?;
    println!("POST /  -> {} {}", answered.0, answered.1);
    assert_eq!(answered.0, http::StatusCode::OK, "the handler must have answered: {}", answered.1);
    assert!(answered.1.contains("<Ping>2 buckets</Ping>"), "{}", answered.1);

    // The same assembly, one stage earlier: an AWS operation with no signature never reaches the
    // handler, because its allow-list does not admit an anonymous request.
    let refused = exchange(&service, http::Method::GET, "/").await?;
    println!("GET  /  -> {} {}", refused.0, refused.1);
    assert_eq!(refused.0, http::StatusCode::FORBIDDEN, "{}", refused.1);
    assert!(refused.1.contains("<Code>AccessDenied</Code>"), "{}", refused.1);

    Ok(())
}

/// One request in, one status and body out.
async fn exchange(
    service: &rustfs_gateway::S3Service,
    method: http::Method,
    uri: &str,
) -> Result<(http::StatusCode, String), Box<dyn std::error::Error>> {
    let request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "s3.example.com")
        .body(bytes::Bytes::new())?;
    let response = rustfs_gateway::collect(service.call_bytes(request).await).await?;
    let body = String::from_utf8(response.body().to_vec())?;
    Ok((response.status(), body))
}
