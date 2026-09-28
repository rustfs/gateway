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

//! The gateway side of the decode diff: a real assembled service whose backend records what it
//! was handed.
//!
//! Responsible for: assembling the service the way the RustFS ring-2 adapter will (SigV4
//! authenticator, allow-every-stage authorizer, anonymous admission delegated to it, a fixed
//! bucket owner), registering one recording handler for every diffed operation, and reporting for
//! one request the operation the service routed to (from its own observer, refusals included),
//! what the handler was handed, and the refusal when the handler was never reached.
//! NOT responsible for: comparing (`decode.rs`), spelling members (`project/*.rs`), or host
//! classification (`resolver.rs`).
//! Upstream: `rustfs-gateway` (assembly, observer). Downstream: `decode.rs`.

use std::sync::{Arc, Mutex};

use http_body_util::BodyExt;
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, Handler, HandlerError, HandlerResult, InputAuthzRequest,
    InputDecisions, Observer, Req, RequestContext, RequestEvent, S3Service, ServiceBuilder, SigV4Authenticator,
    StaticCredentials,
};
use rustfs_gateway_sig::{RegionSet, SecurityFloor};
use rustfs_gateway_stream::{ByteStream, PayloadRead, PayloadStream};
use rustfs_gateway_types::ErrorCode;

use crate::decode::{Answer, BodySeen, Fault};
use crate::fields::Fields;
use crate::probe::{ProbeBody, block_on};
use crate::project::{Projected, Projection};
use crate::request::RawRequest;
use crate::resolver::Resolver;

/// The one credential the gateway store holds. The diff sends no signed request today — recorded
/// signatures are redacted — but the authenticator is the one a deployment runs.
const ACCESS_KEY: &str = "AKIDDIFFTEST";
const SECRET_KEY: &str = "difftest-secret-key";

/// What one gateway handler call recorded.
pub(crate) struct Handed {
    pub(crate) operation: &'static str,
    pub(crate) fields: Fields,
    pub(crate) body: BodySeen,
}

type Slot = Arc<Mutex<Option<Handed>>>;
type Routed = Arc<Mutex<Option<Option<String>>>>;

/// A backend whose every handler records its input and refuses, so no output is ever encoded.
pub(crate) struct Recorder {
    slot: Slot,
    /// [`Fault::GatewayDecoderEatsOneByte`]: the handler sees the body with its first byte gone.
    eats_one_byte: bool,
}

impl<O> Handler<O> for Recorder
where
    O: Projected,
{
    async fn call(&self, request: Req<O>) -> HandlerResult<O> {
        let operation = request.context().operation();
        let Projection { fields, body } = O::gateway(request);
        let body = match body {
            None => BodySeen::NoBody,
            Some(stream) => drain(stream, self.eats_one_byte).await,
        };
        if let Ok(mut slot) = self.slot.lock() {
            *slot = Some(Handed { operation, fields, body });
        }
        Err(HandlerError::new(ErrorCode::NOT_IMPLEMENTED, "recorded by the decode diff"))
    }
}

/// Reads a live gateway body to its end, as a handler that stores it would.
async fn drain(mut stream: ByteStream, eats_one_byte: bool) -> BodySeen {
    let mut bytes = Vec::new();
    let outcome = std::future::poll_fn(|cx| {
        loop {
            match std::pin::Pin::new(&mut stream).poll_read(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => bytes.extend_from_slice(&chunk),
                std::task::Poll::Ready(Ok(PayloadRead::Eof { .. })) => return std::task::Poll::Ready(Ok(())),
                std::task::Poll::Ready(Err(_)) => return std::task::Poll::Ready(Err(())),
            }
        }
    })
    .await;
    if eats_one_byte && !bytes.is_empty() {
        // The injected defect: a decoder that took one byte more than its framing said.
        bytes.remove(0);
    }
    match outcome {
        Ok(()) => BodySeen::Read(bytes),
        Err(()) => BodySeen::Failed { read: bytes },
    }
}

/// Records the operation the service routed to, for every request it answers — refusals before
/// the handler included, and `None` when routing chose none.
struct RouteObserver {
    routed: Routed,
}

impl Observer for RouteObserver {
    fn on_response(&self, event: &RequestEvent<'_>) {
        if let Ok(mut routed) = self.routed.lock() {
            *routed = Some(event.operation.map(str::to_owned));
        }
    }
}

/// Allows both stages: the diff is about decoding, not policy.
struct AllowEveryStage;

impl Authorizer for AllowEveryStage {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// The account that owns every bucket, so `x-amz-expected-bucket-owner` reaches the handler when
/// it names this account, as it does in a RustFS deployment whose owner lookup agrees.
pub(crate) const BUCKET_OWNER: &str = "111122223333";

struct FixtureOwner;

impl rustfs_gateway::BucketOwnerSource for FixtureOwner {
    fn owner<'a>(
        &'a self,
        _bucket: &'a rustfs_gateway_types::BucketName,
    ) -> BoxFuture<'a, Result<Arc<str>, rustfs_gateway::BucketOwnerError>> {
        Box::pin(async { Ok(Arc::from(BUCKET_OWNER)) })
    }
}

/// The assembled gateway and its recording slots.
pub(crate) struct GatewayStack {
    service: S3Service,
    slot: Slot,
    routed: Routed,
}

impl GatewayStack {
    pub(crate) fn new(fault: &Fault) -> Result<Self, String> {
        let credentials =
            Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).map_err(|error| format!("credential: {error:?}"))?;
        let regions = RegionSet::new(["us-east-1"]).map_err(|error| format!("regions: {error:?}"))?;
        let authenticator = SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(credentials)), regions);
        let slot: Slot = Arc::new(Mutex::new(None));
        let routed: Routed = Arc::new(Mutex::new(None));
        let recorder = Arc::new(Recorder {
            slot: Arc::clone(&slot),
            eats_one_byte: *fault == Fault::GatewayDecoderEatsOneByte,
        });
        let builder = ServiceBuilder::new()
            .authenticator(authenticator)
            .authorizer(AllowEveryStage)
            .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
            .bucket_owner_source(FixtureOwner)
            .host_resolver(Resolver::new(*fault == Fault::GatewayMisroutesObjects))
            .observer(RouteObserver {
                routed: Arc::clone(&routed),
            });
        let service = crate::project::register(builder, &recorder)
            .build()
            .map_err(|error| format!("assembly: {error:?}"))?;
        Ok(Self { service, slot, routed })
    }

    /// Sends `request` and reports what the gateway made of it.
    pub(crate) fn send(&self, request: &RawRequest) -> Result<(Option<String>, Answer<Handed>), String> {
        *self.slot.lock().map_err(|_| "the recording slot is poisoned".to_owned())? = None;
        *self
            .routed
            .lock()
            .map_err(|_| "the routed-operation slot is poisoned".to_owned())? = None;
        let mut head = request.http_head()?;
        if request.secure {
            head = head.extension(rustfs_gateway::TransportSecurity::Encrypted);
        }
        let http_request = head
            .body(ProbeBody::new(&request.body))
            .map_err(|error| format!("request head: {error}"))?;
        let response = block_on(self.service.call(http_request));
        let (parts, body) = response.into_parts();
        let body = block_on(body.collect())
            .map_err(|_| "the gateway response body failed".to_owned())?
            .to_bytes();
        let routed = self
            .routed
            .lock()
            .map_err(|_| "the routed-operation slot is poisoned".to_owned())?
            .take()
            .ok_or_else(|| "the gateway answered without reporting the request to its observer".to_owned())?;
        let handed = self
            .slot
            .lock()
            .map_err(|_| "the recording slot is poisoned".to_owned())?
            .take();
        match handed {
            Some(handed) if routed.as_deref() != Some(handed.operation) => {
                Err(format!("the service reported {routed:?} and the {} handler was called", handed.operation))
            }
            Some(handed) => Ok((routed, Answer::Handed(handed))),
            None => Ok((routed, Answer::refused(parts.status.as_u16(), &body))),
        }
    }
}
