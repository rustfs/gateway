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

//! Operation selection behind the common request pipeline.
//!
//! Responsible for: adapting either the existing erased table or a type-level operation set to
//! the one internal dispatch interface consumed by `service`.
//! NOT responsible for: routing, authorization policy, body gates or response rendering.
//! Upstream: `dispatch` and `monomorphic`. Downstream: `service`.

use core::future::Future;
use core::task::Poll;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use bytes::Bytes;
use rustfs_gateway_core::{
    AuthRequirement, BoxFuture, Decision, HandlerError, MetaView, OwnedResource, StaticCommittedError, StaticDispatchError,
    StaticDispatchOutcome,
};

use crate::dispatch::{DispatchTable, ErasedAnswer};
use crate::monomorphic::sealed::Set as StaticSet;
use crate::request_config::{InputAuthorized, RequestConfig};

pub(crate) trait OperationMode {
    type Entry: Send;

    fn entry(&self, operation: &str) -> Option<Self::Entry>;

    fn floor(entry: &Self::Entry) -> &'static rustfs_gateway_sig::OperationFloor;

    fn auth(entry: &Self::Entry) -> Option<AuthRequirement>;

    fn dispatch<'a, S, T, E, Route, RouteFuture, Read, ReadFuture, Input, InputFuture>(
        &'a self,
        _entry: Self::Entry,
        operation: &'a str,
        meta: &'a MetaView<'a>,
        authorize_route: Route,
        read_body: Read,
        authorize_input: Input,
    ) -> BoxFuture<'a, Result<StaticDispatchOutcome, StaticDispatchError<E>>>
    where
        S: Send + 'a,
        T: Send + 'a,
        E: Send + 'a,
        Route: FnOnce() -> RouteFuture + Send + 'a,
        RouteFuture: Future<Output = Result<S, E>> + Send + 'a,
        Read: FnOnce(S) -> ReadFuture + Send + 'a,
        ReadFuture: Future<Output = Result<(T, Bytes), E>> + Send + 'a,
        Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture + Send + 'a,
        InputFuture: Future<Output = Result<(Vec<Decision>, RequestConfig<InputAuthorized>), E>> + Send + 'a;
}

pub(crate) struct DynamicMode<'a> {
    pub(crate) dispatch: &'a DispatchTable,
}

impl OperationMode for DynamicMode<'_> {
    type Entry = crate::dispatch::OperationDispatch;

    fn entry(&self, operation: &str) -> Option<Self::Entry> {
        self.dispatch.get(operation).cloned()
    }

    fn floor(entry: &Self::Entry) -> &'static rustfs_gateway_sig::OperationFloor {
        entry.floor()
    }

    fn auth(entry: &Self::Entry) -> Option<AuthRequirement> {
        entry.auth()
    }

    fn dispatch<'a, S, T, E, Route, RouteFuture, Read, ReadFuture, Input, InputFuture>(
        &'a self,
        entry: Self::Entry,
        _operation: &'a str,
        meta: &'a MetaView<'a>,
        authorize_route: Route,
        read_body: Read,
        authorize_input_callback: Input,
    ) -> BoxFuture<'a, Result<StaticDispatchOutcome, StaticDispatchError<E>>>
    where
        S: Send + 'a,
        T: Send + 'a,
        E: Send + 'a,
        Route: FnOnce() -> RouteFuture + Send + 'a,
        RouteFuture: Future<Output = Result<S, E>> + Send + 'a,
        Read: FnOnce(S) -> ReadFuture + Send + 'a,
        ReadFuture: Future<Output = Result<(T, Bytes), E>> + Send + 'a,
        Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture + Send + 'a,
        InputFuture: Future<Output = Result<(Vec<Decision>, RequestConfig<InputAuthorized>), E>> + Send + 'a,
    {
        Box::pin(async move {
            let route_state = authorize_route().await.map_err(StaticDispatchError::Route)?;
            let (body_state, body) = read_body(route_state).await.map_err(StaticDispatchError::Body)?;
            let decoded = entry.decode(meta, body).map_err(StaticDispatchError::Codec)?;
            let resources = entry.resources(&decoded).map_err(StaticDispatchError::Codec)?;
            let (decisions, request_config) = authorize_input_callback(body_state, resources)
                .await
                .map_err(StaticDispatchError::Input)?;
            let authorized = entry.authorize(decoded, &decisions).map_err(StaticDispatchError::Denied)?;
            let invocation = entry
                .invoke(authorized, request_config)
                .map_err(StaticDispatchError::Handler)?;
            let (answer, status) = invocation.await.map_err(StaticDispatchError::Handler)?;
            match answer {
                ErasedAnswer::Settled(output) => entry
                    .encode(output, meta, status)
                    .map(StaticDispatchOutcome::Settled)
                    .map_err(StaticDispatchError::Codec),
                ErasedAnswer::Committed(work) => {
                    let result = match contain_committed_work(work).await {
                        Ok(output) => entry.encode(output, meta, status).map_err(StaticCommittedError::Codec),
                        Err(error) => Err(StaticCommittedError::Handler(error)),
                    };
                    Ok(StaticDispatchOutcome::Committed { status, result })
                }
                ErasedAnswer::EventStream(stream) => Ok(StaticDispatchOutcome::EventStream { status, stream }),
            }
        })
    }
}

async fn contain_committed_work<T>(work: BoxFuture<'static, Result<T, HandlerError>>) -> Result<T, HandlerError> {
    let mut work = Some(work);
    core::future::poll_fn(move |context| {
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
    })
    .await
}

pub(crate) struct MonomorphicMode<H, Operations> {
    pub(crate) backend: Arc<H>,
    pub(crate) operations: core::marker::PhantomData<fn() -> Operations>,
}

pub(crate) struct MonomorphicEntry {
    floor: &'static rustfs_gateway_sig::OperationFloor,
    auth: Option<AuthRequirement>,
}

impl<H, Operations> OperationMode for MonomorphicMode<H, Operations>
where
    H: Send + Sync + 'static,
    Operations: StaticSet<H>,
{
    type Entry = MonomorphicEntry;

    fn entry(&self, operation: &str) -> Option<Self::Entry> {
        Some(MonomorphicEntry {
            floor: Operations::floor(operation)?,
            auth: Operations::auth(operation)?,
        })
    }

    fn floor(entry: &Self::Entry) -> &'static rustfs_gateway_sig::OperationFloor {
        entry.floor
    }

    fn auth(entry: &Self::Entry) -> Option<AuthRequirement> {
        entry.auth
    }

    fn dispatch<'a, S, T, E, Route, RouteFuture, Read, ReadFuture, Input, InputFuture>(
        &'a self,
        _entry: Self::Entry,
        operation: &'a str,
        meta: &'a MetaView<'a>,
        authorize_route: Route,
        read_body: Read,
        authorize_input: Input,
    ) -> BoxFuture<'a, Result<StaticDispatchOutcome, StaticDispatchError<E>>>
    where
        S: Send + 'a,
        T: Send + 'a,
        E: Send + 'a,
        Route: FnOnce() -> RouteFuture + Send + 'a,
        RouteFuture: Future<Output = Result<S, E>> + Send + 'a,
        Read: FnOnce(S) -> ReadFuture + Send + 'a,
        ReadFuture: Future<Output = Result<(T, Bytes), E>> + Send + 'a,
        Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture + Send + 'a,
        InputFuture: Future<Output = Result<(Vec<Decision>, RequestConfig<InputAuthorized>), E>> + Send + 'a,
    {
        Operations::dispatch(operation, meta, Arc::clone(&self.backend), authorize_route, read_body, authorize_input)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use core::pin::Pin;
    use core::task::Context;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustfs_gateway_core::{StaticDispatchError, TargetKind};
    use rustfs_gateway_http::{Limits, WireRequest};

    use super::*;

    type Operations = crate::OperationSetNode<crate::dto::ListBuckets, crate::OperationSetEnd>;

    fn meta() -> MetaView<'static> {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("/")
            .header("host", "s3.example.com")
            .body(Bytes::new())
            .expect("a valid request");
        let wire = Box::leak(Box::new(WireRequest::accept(request, &Limits::default()).expect("an accepted request")));
        MetaView::of(wire, TargetKind::Service).expect("service metadata")
    }

    struct ReadyThenDropPanics;

    impl Future for ReadyThenDropPanics {
        type Output = Result<(), HandlerError>;

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(Ok(()))
        }
    }

    impl Drop for ReadyThenDropPanics {
        fn drop(&mut self) {
            panic!("dynamic committed continuation drop panic fixture");
        }
    }

    #[tokio::test]
    async fn dynamic_committed_ready_contains_a_destructor_panic() {
        let result = contain_committed_work(Box::pin(ReadyThenDropPanics)).await;
        assert!(result.is_err(), "a destructor panic escaped as a successful committed body");
    }

    /// a-asm-0007. Even if an internal cache hands dispatch metadata selected for ListBuckets to
    /// a different routed identity, the facade refuses before route, body or input callbacks.
    #[tokio::test]
    async fn selected_entry_and_runtime_route_mismatch_is_fail_closed() {
        let mode = MonomorphicMode::<_, Operations> {
            backend: Arc::new(crate::tests::NoBackend),
            operations: core::marker::PhantomData,
        };
        let selected = mode.entry("ListBuckets").expect("the selected static entry");
        let callbacks = Arc::new(AtomicUsize::new(0));
        let route_callbacks = Arc::clone(&callbacks);
        let body_callbacks = Arc::clone(&callbacks);
        let input_callbacks = Arc::clone(&callbacks);

        let result = mode
            .dispatch(
                selected,
                "GetObject",
                &meta(),
                move || {
                    route_callbacks.fetch_add(1, Ordering::SeqCst);
                    async { Ok::<_, &'static str>(()) }
                },
                move |()| {
                    body_callbacks.fetch_add(1, Ordering::SeqCst);
                    async { Ok::<_, &'static str>(((), Bytes::new())) }
                },
                move |(), _| {
                    input_callbacks.fetch_add(1, Ordering::SeqCst);
                    async {
                        Ok::<_, &'static str>((
                            Vec::new(),
                            RequestConfig::enter(Arc::new(crate::ServiceConfig::new(1)))
                                .accepted()
                                .routed()
                                .governed()
                                .authenticated()
                                .route_authorized()
                                .body_read()
                                .decoded()
                                .input_authorized(),
                        ))
                    }
                },
            )
            .await;

        assert!(matches!(result, Err(StaticDispatchError::OperationMismatch { .. })));
        assert_eq!(callbacks.load(Ordering::SeqCst), 0, "a callback ran before identity refusal");
    }
}
