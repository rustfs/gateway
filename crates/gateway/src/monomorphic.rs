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

//! The concrete-backend service and its explicit type-level operation set.
//!
//! Responsible for: selecting one operation type without stored codec or handler callbacks.
//! NOT responsible for: any protocol stage; [`rustfs_gateway_core::StaticOperation`] owns their
//! fixed order and [`crate::S3Service`] owns the surrounding request pipeline.
//! Upstream: [`crate::ServiceBuilder`]. Downstream: deployments choosing static dispatch.

use core::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response};
use rustfs_gateway_stream::Body;

use crate::S3Service;

/// The end of a monomorphic operation list.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperationSetEnd;

/// One operation followed by the rest of a monomorphic operation list.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperationSetNode<O, Tail>(PhantomData<fn() -> (O, Tail)>);

/// A sealed type-level set whose every operation is handled by one concrete backend type.
pub trait MonomorphicOperationSet<H>: sealed::Set<H> {}

impl<H, T> MonomorphicOperationSet<H> for T where T: sealed::Set<H> {}

/// An assembled service whose operation codec and handler selection are statically dispatched.
pub struct MonomorphicService<H, Operations> {
    pub(crate) service: S3Service,
    pub(crate) backend: Arc<H>,
    pub(crate) operations: PhantomData<fn() -> Operations>,
}

impl<H, Operations> Clone for MonomorphicService<H, Operations> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            backend: Arc::clone(&self.backend),
            operations: PhantomData,
        }
    }
}

impl<H, Operations> core::fmt::Debug for MonomorphicService<H, Operations> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MonomorphicService")
            .field("operations", &self.service.operations().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl<H, Operations> MonomorphicService<H, Operations>
where
    H: Send + Sync + 'static,
    Operations: MonomorphicOperationSet<H>,
{
    /// Answers one request through the sealed static operation entry.
    pub async fn call<B>(&self, request: Request<B>) -> Response<Body>
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.service
            .call_monomorphic::<B, H, Operations>(request, Arc::clone(&self.backend))
            .await
    }

    /// Answers one request whose body is already in memory.
    pub async fn call_bytes(&self, request: Request<Bytes>) -> Response<Body> {
        let (parts, body) = request.into_parts();
        self.call(Request::from_parts(parts, http_body_util::Full::new(body))).await
    }

    /// The operations this service answers, sorted.
    pub fn operations(&self) -> impl Iterator<Item = &'static str> {
        self.service.operations()
    }
}

pub(crate) mod sealed {
    use core::future::Future;
    use std::time::Duration;

    use rustfs_gateway_core::{
        AuthRequirement, BoxFuture, Decision, Handler, HandlerCancellationSource, HandlerError, MetaView, OperationCodec,
        OwnedResource, StaticDispatchError, StaticDispatchOutcome, StaticOperation,
    };
    use rustfs_gateway_sig::OperationFloor;

    use super::*;
    use crate::request_config::{InputAuthorized, RequestConfig};
    use crate::request_deadline::{HandlerDeadlineOutcome, handler_with_deadline};

    pub trait HandlerDeadlinePolicy: Send {
        fn handler_deadline(&self, class: rustfs_gateway_core::HandlerDeadlineClass) -> Duration;

        fn handler_cleanup_grace(&self) -> Duration;
    }

    impl HandlerDeadlinePolicy for RequestConfig<InputAuthorized> {
        fn handler_deadline(&self, class: rustfs_gateway_core::HandlerDeadlineClass) -> Duration {
            self.config().handler_deadline(class)
        }

        fn handler_cleanup_grace(&self) -> Duration {
            self.config().handler_cleanup_grace()
        }
    }

    pub trait Set<H>: Send + Sync + 'static {
        fn names(output: &mut Vec<&'static str>);

        fn floor(operation: &str) -> Option<&'static OperationFloor>;

        fn auth(operation: &str) -> Option<Option<AuthRequirement>>;

        fn dispatch<'a, S, T, G, E, Route, RouteFuture, Read, ReadFuture, Input, InputFuture>(
            operation: &'a str,
            meta: &'a MetaView<'a>,
            backend: Arc<H>,
            authorize_route: Route,
            read_body: Read,
            authorize_input: Input,
        ) -> BoxFuture<'a, Result<StaticDispatchOutcome, StaticDispatchError<E>>>
        where
            S: Send + 'a,
            T: Send + 'a,
            G: HandlerDeadlinePolicy + Send + 'a,
            E: Send + 'a,
            Route: FnOnce() -> RouteFuture + Send + 'a,
            RouteFuture: Future<Output = Result<S, E>> + Send + 'a,
            Read: FnOnce(S) -> ReadFuture + Send + 'a,
            ReadFuture: Future<Output = Result<(T, Bytes), E>> + Send + 'a,
            Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture + Send + 'a,
            InputFuture: Future<Output = Result<(Vec<Decision>, G), E>> + Send + 'a;
    }

    impl<H> Set<H> for OperationSetEnd
    where
        H: Send + Sync + 'static,
    {
        fn names(_output: &mut Vec<&'static str>) {}

        fn floor(_operation: &str) -> Option<&'static OperationFloor> {
            None
        }

        fn auth(_operation: &str) -> Option<Option<AuthRequirement>> {
            None
        }

        fn dispatch<'a, S, T, G, E, Route, RouteFuture, Read, ReadFuture, Input, InputFuture>(
            operation: &'a str,
            _meta: &'a MetaView<'a>,
            _backend: Arc<H>,
            _authorize_route: Route,
            _read_body: Read,
            _authorize_input: Input,
        ) -> BoxFuture<'a, Result<StaticDispatchOutcome, StaticDispatchError<E>>>
        where
            S: Send + 'a,
            T: Send + 'a,
            G: HandlerDeadlinePolicy + Send + 'a,
            E: Send + 'a,
            Route: FnOnce() -> RouteFuture + Send + 'a,
            RouteFuture: Future<Output = Result<S, E>> + Send + 'a,
            Read: FnOnce(S) -> ReadFuture + Send + 'a,
            ReadFuture: Future<Output = Result<(T, Bytes), E>> + Send + 'a,
            Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture + Send + 'a,
            InputFuture: Future<Output = Result<(Vec<Decision>, G), E>> + Send + 'a,
        {
            Box::pin(async move {
                Err(StaticDispatchError::OperationMismatch {
                    routed: operation.to_owned(),
                    expected: "<operation-set-end>",
                })
            })
        }
    }

    impl<H, O, Tail> Set<H> for OperationSetNode<O, Tail>
    where
        H: Handler<O>,
        O: OperationCodec,
        Tail: Set<H>,
    {
        fn names(output: &mut Vec<&'static str>) {
            output.push(O::NAME);
            Tail::names(output);
        }

        fn floor(operation: &str) -> Option<&'static OperationFloor> {
            if operation == O::NAME {
                Some(O::floor())
            } else {
                Tail::floor(operation)
            }
        }

        fn auth(operation: &str) -> Option<Option<AuthRequirement>> {
            if operation == O::NAME {
                Some(O::spec().auth)
            } else {
                Tail::auth(operation)
            }
        }

        fn dispatch<'a, S, T, G, E, Route, RouteFuture, Read, ReadFuture, Input, InputFuture>(
            operation: &'a str,
            meta: &'a MetaView<'a>,
            backend: Arc<H>,
            authorize_route: Route,
            read_body: Read,
            authorize_input: Input,
        ) -> BoxFuture<'a, Result<StaticDispatchOutcome, StaticDispatchError<E>>>
        where
            S: Send + 'a,
            T: Send + 'a,
            G: HandlerDeadlinePolicy + Send + 'a,
            E: Send + 'a,
            Route: FnOnce() -> RouteFuture + Send + 'a,
            RouteFuture: Future<Output = Result<S, E>> + Send + 'a,
            Read: FnOnce(S) -> ReadFuture + Send + 'a,
            ReadFuture: Future<Output = Result<(T, Bytes), E>> + Send + 'a,
            Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture + Send + 'a,
            InputFuture: Future<Output = Result<(Vec<Decision>, G), E>> + Send + 'a,
        {
            if operation == O::NAME {
                Box::pin(StaticOperation::<O>::dispatch_with_handler(
                    operation,
                    meta,
                    backend,
                    authorize_route,
                    read_body,
                    authorize_input,
                    |backend, request, request_config| async move {
                        let Some(deadline_class) = O::spec().deadline_class() else {
                            return Err(HandlerError::internal_error("handler deadline class is missing"));
                        };
                        let deadline = request_config.handler_deadline(deadline_class);
                        let cleanup_grace = request_config.handler_cleanup_grace();
                        let (deadline_cancellation, context) = HandlerCancellationSource::pair();
                        let call: BoxFuture<'static, _> =
                            Box::pin(async move { backend.call_with_context(request, context).await });
                        match handler_with_deadline(call, deadline_cancellation, deadline, cleanup_grace).await {
                            HandlerDeadlineOutcome::Completed(response) => response,
                            HandlerDeadlineOutcome::Expired { cleanup_completed: true } => {
                                Err(HandlerError::internal_error("handler deadline exceeded after cleanup completed"))
                            }
                            HandlerDeadlineOutcome::Expired {
                                cleanup_completed: false,
                            } => Err(HandlerError::internal_error("handler deadline exceeded before cleanup completed")),
                        }
                    },
                ))
            } else {
                Tail::dispatch(operation, meta, backend, authorize_route, read_body, authorize_input)
            }
        }
    }
}
