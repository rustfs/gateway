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

//! The sealed generic operation path shared with the facade.
//!
//! Responsible for: public entries that preserve route authorization, body read, input
//! authorization, concrete handler invocation and encoding order without stored callbacks.
//! NOT responsible for: routing, assembly, extension implementations or rendering refusals.
//! Upstream: the core codec, authorization and handler types. Downstream: the facade's
//! monomorphic operation-set branch.

use core::future::Future;
use core::marker::PhantomData;
use core::task::{Context, Poll};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use http::HeaderMap;
use rustfs_gateway_stream::ByteStream;

use crate::authz::{Decoded, authorize_input, prepare_input_under};
use crate::{
    Answer, CodecError, Decision, Denied, DerivedResourceSet, EncodedResponse, Handler, HandlerCancellationSource, HandlerError,
    MetaView, OperationCodec, OwnedResource, RequestBody,
};

/// The result of a static operation whose response head was not committed early.
#[derive(Debug)]
pub enum StaticDispatchOutcome {
    /// A fully encoded ordinary response.
    Settled(EncodedResponse),
    /// A response whose status was committed before its continuation completed.
    Committed {
        /// The already committed status.
        status: u16,
        /// The frozen operation headers and unresolved detached work.
        response: StaticCommittedResponse,
    },
    /// An already framed event stream.
    EventStream {
        /// The operation's success status.
        status: u16,
        /// The frames to write without an output-document encoder.
        stream: ByteStream,
    },
}

/// A failure after a response status was committed.
#[derive(Debug)]
pub enum StaticCommittedError {
    /// The handler continuation failed.
    Handler(HandlerError),
    /// The completed output could not be encoded.
    Codec(CodecError),
}

trait ErasedCommittedWork: Send {
    fn poll_resolve(
        &mut self,
        context: &mut Context<'_>,
        meta: &MetaView<'_>,
        status: u16,
        head: &HeaderMap,
    ) -> Poll<Result<EncodedResponse, StaticCommittedError>>;
}

struct TypedCommittedWork<O: OperationCodec> {
    work: Option<crate::CommitWork<O>>,
    response_headers: &'static [&'static str],
    response_header_prefixes: &'static [&'static str],
}

impl<O: OperationCodec> ErasedCommittedWork for TypedCommittedWork<O> {
    fn poll_resolve(
        &mut self,
        context: &mut Context<'_>,
        meta: &MetaView<'_>,
        status: u16,
        head: &HeaderMap,
    ) -> Poll<Result<EncodedResponse, StaticCommittedError>> {
        let output = match poll_committed_work(&mut self.work, context) {
            Poll::Ready(Ok(output)) => output,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(StaticCommittedError::Handler(error))),
            Poll::Pending => return Poll::Pending,
        };
        let encoded = match encode::<O>(output, meta, status) {
            Ok(encoded) => encoded,
            Err(error) => return Poll::Ready(Err(StaticCommittedError::Codec(error))),
        };
        let terminal_headers = operation_headers(&encoded.headers, self.response_headers, self.response_header_prefixes);
        if terminal_headers != *head {
            return Poll::Ready(Err(StaticCommittedError::Codec(CodecError::internal(
                "the committed output headers differ from the frozen response head",
            ))));
        }
        Poll::Ready(Ok(encoded))
    }
}

/// A committed response whose typed operation has been erased but whose work has not started.
///
/// The facade receives this value before spawning. It can therefore finish response filters,
/// invariants, and framework headers while the backend work remains unpolled.
pub struct StaticCommittedResponse {
    head: HeaderMap,
    work: Box<dyn ErasedCommittedWork>,
}

impl StaticCommittedResponse {
    /// Erases one generated operation's committed response for the facade boundary.
    #[doc(hidden)]
    pub fn erase<O: OperationCodec>(committed: crate::CommittedResponse<O>) -> Self {
        let (head, work, response_headers, response_header_prefixes) = committed.into_dispatch_parts();
        Self {
            head: head.into_headers(),
            work: Box::new(TypedCommittedWork::<O> {
                work: Some(work),
                response_headers,
                response_header_prefixes,
            }),
        }
    }

    /// The validated operation headers that leave before the work starts.
    #[must_use]
    pub const fn head(&self) -> &HeaderMap {
        &self.head
    }

    /// Drives and encodes the detached work against a rebuilt request view.
    ///
    /// # Errors
    ///
    /// [`StaticCommittedError`] when the handler fails, panics, cannot encode its output, or
    /// produces operation headers different from the frozen head.
    pub async fn resolve(self, meta: &MetaView<'_>, status: u16) -> Result<EncodedResponse, StaticCommittedError> {
        let Self { head, mut work } = self;
        core::future::poll_fn(move |context| work.poll_resolve(context, meta, status, &head)).await
    }
}

impl core::fmt::Debug for StaticCommittedResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticCommittedResponse")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

fn operation_headers(headers: &HeaderMap, exact: &[&str], prefixes: &[&str]) -> HeaderMap {
    let mut operation = HeaderMap::new();
    for (name, value) in headers {
        if exact.contains(&name.as_str()) || prefixes.iter().any(|prefix| name.as_str().starts_with(prefix)) {
            operation.append(name.clone(), value.clone());
        }
    }
    operation
}

/// A refusal from the sealed static operation entry.
#[derive(Debug)]
pub enum StaticDispatchError<E> {
    /// The type-level branch did not match the operation chosen by the router.
    OperationMismatch {
        /// The operation name the router chose.
        routed: String,
        /// The operation type the branch attempted to run.
        expected: &'static str,
    },
    /// Route authorization refused or failed.
    Route(E),
    /// The authorized body gate refused or failed.
    Body(E),
    /// The operation codec refused the request.
    Codec(CodecError),
    /// Input authorization refused or failed.
    Input(E),
    /// The input decisions did not authorize every derived resource.
    Denied(Denied),
    /// The concrete handler failed before committing a response.
    Handler(HandlerError),
}

/// One operation's generic codec and concrete-handler path.
///
/// This type has no public constructor and no public stage methods. Its two dispatch entries keep
/// decode and both authorization passes sealed; the facade-only variant injects handler policy
/// after authorization without exposing any earlier stage.
pub struct StaticOperation<O>(PhantomData<fn() -> O>);

impl<O> StaticOperation<O>
where
    O: OperationCodec,
{
    /// Runs one routed operation without storing codec or handler callbacks.
    ///
    /// The callback order is fixed: `authorize_route`, `read_body`, `authorize_input`, then the
    /// concrete [`Handler<O>`]. The routed identity is checked before any callback.
    ///
    /// # Errors
    ///
    /// [`StaticDispatchError`] identifies the stage that refused. A committed continuation uses
    /// [`StaticDispatchOutcome::Committed`] because its status can no longer change.
    pub async fn dispatch<B, S, T, G, E, Route, RouteFuture, Read, ReadFuture, Input, InputFuture>(
        routed_operation: &str,
        meta: &MetaView<'_>,
        backend: Arc<B>,
        authorize_route: Route,
        read_body: Read,
        authorize_input_callback: Input,
    ) -> Result<StaticDispatchOutcome, StaticDispatchError<E>>
    where
        B: Handler<O>,
        Route: FnOnce() -> RouteFuture,
        RouteFuture: Future<Output = Result<S, E>>,
        Read: FnOnce(S) -> ReadFuture,
        ReadFuture: Future<Output = Result<(T, RequestBody), E>>,
        Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture,
        InputFuture: Future<Output = Result<(Vec<Decision>, G, crate::SseEnforced, crate::RequestContextView), E>>,
    {
        Self::dispatch_with_handler(
            routed_operation,
            meta,
            backend,
            authorize_route,
            read_body,
            authorize_input_callback,
            |backend, request, _request_guard| async move {
                let (_cancellation, context) = HandlerCancellationSource::pair();
                backend
                    .call_with_context(request, context)
                    .await
                    .map_err(StaticDispatchError::Handler)
            },
        )
        .await
    }

    /// Runs one routed operation while allowing the facade to wrap only the concrete handler call.
    ///
    /// Route authorization, body read, decoding, input authorization, and encoding remain in this
    /// sealed order. The callback receives the authorized request and the state returned by input
    /// authorization, which lets the facade apply request-snapshot policy without erasing the
    /// concrete handler type.
    ///
    /// # Errors
    ///
    /// [`StaticDispatchError`] identifies the stage that refused. A committed continuation uses
    /// [`StaticDispatchOutcome::Committed`] because its status can no longer change.
    #[doc(hidden)]
    pub async fn dispatch_with_handler<
        B,
        S,
        T,
        G,
        E,
        Route,
        RouteFuture,
        Read,
        ReadFuture,
        Input,
        InputFuture,
        Invoke,
        InvokeFuture,
    >(
        routed_operation: &str,
        meta: &MetaView<'_>,
        backend: Arc<B>,
        authorize_route: Route,
        read_body: Read,
        authorize_input_callback: Input,
        invoke_handler: Invoke,
    ) -> Result<StaticDispatchOutcome, StaticDispatchError<E>>
    where
        B: Handler<O>,
        Route: FnOnce() -> RouteFuture,
        RouteFuture: Future<Output = Result<S, E>>,
        Read: FnOnce(S) -> ReadFuture,
        ReadFuture: Future<Output = Result<(T, RequestBody), E>>,
        Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture,
        InputFuture: Future<Output = Result<(Vec<Decision>, G, crate::SseEnforced, crate::RequestContextView), E>>,
        Invoke: FnOnce(Arc<B>, crate::Req<O>, G) -> InvokeFuture,
        InvokeFuture: Future<Output = Result<crate::Resp<O>, StaticDispatchError<E>>>,
    {
        if routed_operation != O::NAME {
            return Err(StaticDispatchError::OperationMismatch {
                routed: routed_operation.to_owned(),
                expected: O::NAME,
            });
        }
        let route_state = authorize_route().await.map_err(StaticDispatchError::Route)?;
        let (body_state, body) = read_body(route_state).await.map_err(StaticDispatchError::Body)?;
        let decoded = decode::<O>(meta, body).map_err(StaticDispatchError::Codec)?;
        let resources = resources::<O>(&decoded).map_err(StaticDispatchError::Codec)?;
        let (decisions, request_guard, sse, context) = authorize_input_callback(body_state, resources)
            .await
            .map_err(StaticDispatchError::Input)?;
        let authorized = authorize::<O>(decoded, &decisions).map_err(StaticDispatchError::Denied)?;
        let response = invoke_handler(backend, authorized.into_request(sse, context), request_guard).await?;
        let (answer, status, extra_headers) = response.into_parts();
        if !extra_headers.is_empty() && !matches!(answer, Answer::Settled(_)) {
            return Err(StaticDispatchError::Codec(CodecError::internal(
                "extra response headers apply only to a settled answer",
            )));
        }
        match answer {
            Answer::Settled(output) => encode::<O>(output, meta, status)
                .and_then(|mut encoded| encoded.append_extra_headers(extra_headers).map(|()| encoded))
                .map(StaticDispatchOutcome::Settled)
                .map_err(StaticDispatchError::Codec),
            Answer::Committed(committed) => Ok(StaticDispatchOutcome::Committed {
                status,
                response: StaticCommittedResponse::erase(committed),
            }),
            Answer::EventStream(stream) => Ok(StaticDispatchOutcome::EventStream { status, stream }),
        }
    }
}

fn poll_committed_work<T>(
    work: &mut Option<crate::BoxFuture<'static, Result<T, HandlerError>>>,
    context: &mut Context<'_>,
) -> Poll<Result<T, HandlerError>> {
    let polled = match work.as_mut() {
        Some(work) => catch_unwind(AssertUnwindSafe(|| work.as_mut().poll(context))),
        None => return Poll::Ready(Err(HandlerError::internal_error("the handler failed"))),
    };
    match polled {
        Ok(Poll::Ready(result)) => {
            let completed = work.take();
            match catch_unwind(AssertUnwindSafe(|| drop(completed))) {
                Ok(()) => Poll::Ready(result),
                Err(_) => Poll::Ready(Err(HandlerError::internal_error("the handler failed"))),
            }
        }
        Ok(Poll::Pending) => Poll::Pending,
        Err(_) => {
            let abandoned = work.take();
            let _ = catch_unwind(AssertUnwindSafe(|| drop(abandoned)));
            Poll::Ready(Err(HandlerError::internal_error("the handler failed")))
        }
    }
}

pub(crate) fn decode<O: OperationCodec>(meta: &MetaView<'_>, body: RequestBody) -> Result<Decoded<O>, CodecError> {
    let input = O::decode(meta, body)?;
    prepare_input_under::<O>(input, meta.names()).map_err(|error| CodecError::new(error.code().clone(), error.message()))
}

pub(crate) fn resources<O: OperationCodec>(decoded: &Decoded<O>) -> Result<Vec<OwnedResource>, CodecError> {
    let mut resources = Vec::with_capacity(decoded.resources().len());
    decoded
        .resources()
        .visit(&mut |resource| resources.push(OwnedResource::from_ref(resource)));
    Ok(resources)
}

pub(crate) fn authorize<O: OperationCodec>(decoded: Decoded<O>, decisions: &[Decision]) -> Result<crate::Authorized<O>, Denied> {
    let mut decisions = decisions.iter().copied();
    let authorized = authorize_input(decoded, |_| decisions.next().unwrap_or(Decision::Indeterminate))?;
    if decisions.next().is_some() {
        return Err(Denied::indeterminate());
    }
    Ok(authorized)
}

pub(crate) fn encode<O: OperationCodec>(
    output: O::Output,
    meta: &MetaView<'_>,
    status: u16,
) -> Result<EncodedResponse, CodecError> {
    let mut encoded = O::encode(output, meta, status)?;
    encoded.apply_response_overrides(meta, O::RESPONSE_OVERRIDES);
    encoded.enforce_http_invariants(meta.method());
    Ok(encoded)
}
