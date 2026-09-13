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
use std::sync::Arc;

use rustfs_gateway_core::{
    AuthRequirement, BoxFuture, Decision, MetaView, OwnedResource, RequestBody, RequestBodyMode, StaticDispatchError,
    StaticDispatchOutcome,
};

use crate::dispatch::{DispatchTable, ErasedAnswer};
use crate::monomorphic::sealed::Set as StaticSet;
use crate::render::S3Error;
use crate::request_config::{Authorized, RequestConfig};
use crate::request_deadline::{BodyMonitoredOutcome, handler_with_body_monitor};

pub(crate) trait OperationMode {
    type Entry: Send;

    fn entry(&self, operation: &str) -> Option<Self::Entry>;

    fn floor(entry: &Self::Entry) -> &'static rustfs_gateway_sig::OperationFloor;

    fn auth(entry: &Self::Entry) -> Option<AuthRequirement>;

    fn request_body_mode(entry: &Self::Entry) -> RequestBodyMode;

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
        E: From<S3Error> + Send + 'a,
        Route: FnOnce() -> RouteFuture + Send + 'a,
        RouteFuture: Future<Output = Result<S, E>> + Send + 'a,
        Read: FnOnce(S) -> ReadFuture + Send + 'a,
        ReadFuture: Future<Output = Result<(T, RequestBody), E>> + Send + 'a,
        Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture + Send + 'a,
        InputFuture: Future<
                Output = Result<
                    (
                        Vec<Decision>,
                        RequestConfig<Authorized>,
                        rustfs_gateway_core::SseEnforced,
                        rustfs_gateway_core::RequestContextView,
                    ),
                    E,
                >,
            > + Send
            + 'a;
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

    fn request_body_mode(entry: &Self::Entry) -> RequestBodyMode {
        entry.request_body_mode()
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
        E: From<S3Error> + Send + 'a,
        Route: FnOnce() -> RouteFuture + Send + 'a,
        RouteFuture: Future<Output = Result<S, E>> + Send + 'a,
        Read: FnOnce(S) -> ReadFuture + Send + 'a,
        ReadFuture: Future<Output = Result<(T, RequestBody), E>> + Send + 'a,
        Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture + Send + 'a,
        InputFuture: Future<
                Output = Result<
                    (
                        Vec<Decision>,
                        RequestConfig<Authorized>,
                        rustfs_gateway_core::SseEnforced,
                        rustfs_gateway_core::RequestContextView,
                    ),
                    E,
                >,
            > + Send
            + 'a,
    {
        Box::pin(async move {
            let route_state = authorize_route().await.map_err(StaticDispatchError::Route)?;
            let (body_state, body) = read_body(route_state).await.map_err(StaticDispatchError::Body)?;
            let decoded = entry.decode(meta, body).map_err(StaticDispatchError::Codec)?;
            let resources = entry.resources(&decoded).map_err(StaticDispatchError::Codec)?;
            let (decisions, mut request_config, _sse, request_context) = authorize_input_callback(body_state, resources)
                .await
                .map_err(StaticDispatchError::Input)?;
            let authorized = entry.authorize(decoded, &decisions).map_err(StaticDispatchError::Denied)?;
            let hide_missing_object = request_config.hide_missing_object();
            let body_monitor = request_config.take_body_monitor();
            let cleanup_grace = request_config.config().handler_cleanup_grace();
            let invocation = entry
                .invoke(authorized, request_config, request_context)
                .map_err(StaticDispatchError::Handler)?;
            let body_cancellation = invocation.cancellation_source();
            let answer =
                match handler_with_body_monitor(Box::pin(invocation), body_cancellation, cleanup_grace, body_monitor).await {
                    BodyMonitoredOutcome::Completed(answer) => answer,
                    BodyMonitoredOutcome::Failed(error) => return Err(StaticDispatchError::Body(E::from(error))),
                };
            let (answer, status) = answer
                .map_err(|error| {
                    if hide_missing_object {
                        error.hide_missing_object()
                    } else {
                        error
                    }
                })
                .map_err(StaticDispatchError::Handler)?;
            match answer {
                ErasedAnswer::Settled(output) => entry
                    .encode(output, meta, status)
                    .map(StaticDispatchOutcome::Settled)
                    .map_err(StaticDispatchError::Codec),
                ErasedAnswer::Committed(response) => Ok(StaticDispatchOutcome::Committed { status, response }),
                ErasedAnswer::EventStream(stream) => Ok(StaticDispatchOutcome::EventStream { status, stream }),
            }
        })
    }
}

pub(crate) struct MonomorphicMode<H, Operations> {
    pub(crate) backend: Arc<H>,
    pub(crate) operations: core::marker::PhantomData<fn() -> Operations>,
}

pub(crate) struct MonomorphicEntry {
    floor: &'static rustfs_gateway_sig::OperationFloor,
    auth: Option<AuthRequirement>,
    request_body: RequestBodyMode,
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
            request_body: Operations::request_body_mode(operation)?,
        })
    }

    fn floor(entry: &Self::Entry) -> &'static rustfs_gateway_sig::OperationFloor {
        entry.floor
    }

    fn auth(entry: &Self::Entry) -> Option<AuthRequirement> {
        entry.auth
    }

    fn request_body_mode(entry: &Self::Entry) -> RequestBodyMode {
        entry.request_body
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
        E: From<S3Error> + Send + 'a,
        Route: FnOnce() -> RouteFuture + Send + 'a,
        RouteFuture: Future<Output = Result<S, E>> + Send + 'a,
        Read: FnOnce(S) -> ReadFuture + Send + 'a,
        ReadFuture: Future<Output = Result<(T, RequestBody), E>> + Send + 'a,
        Input: FnOnce(T, Vec<OwnedResource>) -> InputFuture + Send + 'a,
        InputFuture: Future<
                Output = Result<
                    (
                        Vec<Decision>,
                        RequestConfig<Authorized>,
                        rustfs_gateway_core::SseEnforced,
                        rustfs_gateway_core::RequestContextView,
                    ),
                    E,
                >,
            > + Send
            + 'a,
    {
        Operations::dispatch(operation, meta, Arc::clone(&self.backend), authorize_route, read_body, authorize_input)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
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
                    async { Ok::<_, S3Error>(()) }
                },
                move |()| {
                    body_callbacks.fetch_add(1, Ordering::SeqCst);
                    async { Ok::<_, S3Error>(((), RequestBody::None)) }
                },
                move |(), _| {
                    input_callbacks.fetch_add(1, Ordering::SeqCst);
                    async {
                        let sse = crate::request_config::sse_proof_for_test();
                        let config = RequestConfig::enter(Arc::new(crate::ServiceConfig::new(1)))
                            .wire()
                            .targeted()
                            .routed()
                            .governed(crate::Lease::admit())
                            .meta_auth()
                            .route_authorized()
                            .guarded(sse.clone())
                            .decoded()
                            .authorized();
                        let context = rustfs_gateway_core::RequestContextView::detached("ListBuckets");
                        Ok::<_, S3Error>((Vec::new(), config, sse, context))
                    }
                },
            )
            .await;

        assert!(matches!(result, Err(StaticDispatchError::OperationMismatch { .. })));
        assert_eq!(callbacks.load(Ordering::SeqCst), 0, "a callback ran before identity refusal");
    }
}
