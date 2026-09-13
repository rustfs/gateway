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

//! The one place a backend type disappears, and the only file in this crate that awaits.
//!
//! Responsible for: [`erase`] — turning `(O, B)` into a closure that mentions neither — the
//! [`HandlerTable`] those closures live in, and [`Invocation`], the typed future that hands the
//! answer back without a second heap allocation.
//! NOT responsible for: erasing the codec (`super::codecs`), deciding whether a registration is
//! allowed (`super::reject`), route conflicts (`crate::route`), or any pre-authentication
//! decision. Nothing here runs before the security floor has admitted the request.
//! Upstream: `crate::handler`, `crate::op`. Downstream: [`super::Registry`], and the pipeline,
//! which reaches a handler by name through [`HandlerTable::invoke_erased`] with the payload the
//! entry's own decoder produced.
//!
//! # What is erased, and what is not
//!
//! The backend type is erased; the operation type is not. A registry entry has to be able to call
//! `B::call`, so it has to know `B` — which is exactly why `inventory`-style collection cannot
//! work here (measured `error[E0117]`, ADR-0003). Erasing `B` inside a closure at registration
//! time is what keeps `Router` and, above it, the service non-generic: one process can hold two
//! routers over two different backends, which RustFS already does in its end-to-end tests.
//!
//! The payload stays `Box<dyn Any + Send>`, and it is a `Req<O>` on the way in and a `Resp<O>` on
//! the way back. What produces and consumes those boxes is the codec erased from the *same*
//! registration, held in the same entry here (`super::codecs`), so "which type is in this box" has
//! one answer per operation and it was fixed at registration.
//!
//! # Why the codec lives in this table rather than beside it
//!
//! Two maps keyed by the same name are two maps that can disagree: an entry in one and not the
//! other is a handler that routes and cannot be read, or a decoder whose answer nothing will
//! receive. One entry holding both makes that state unrepresentable — [`HandlerTable::insert`]
//! takes them together, and there is no method that adds either half to an entry that exists.
//!
//! # One `Box::pin` per invocation
//!
//! [`erase`] pins once. [`HandlerTable::invoke`] does not pin again — it wraps the pinned future
//! in [`Invocation`], which downcasts in `poll`. That keeps the framework's per-request boxing
//! count at one, which is the same count s3s pays today for its `#[async_trait]` dispatch.

use std::any::Any;
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::Authorized;
use crate::HandlerContext;
use crate::RequestContextView;
use crate::SseEnforced;
use crate::handler::{BoxFuture, Handler, HandlerError, Resp};
use crate::op::Operation;
use crate::registry::codecs::{ErasedCodec, ErasedDecode, ErasedEncode};

/// An authorized request whose operation type the registry has forgotten.
///
/// The payload stays private so erasure cannot become a public constructor for
/// [`Authorized<O>`]. It can only be consumed by the registered typed dispatch.
pub struct ErasedRequest(Box<dyn Any + Send>);

impl ErasedRequest {
    pub(crate) fn authorized<O: Operation>(request: Authorized<O>) -> Self {
        Self(Box::new(request))
    }

    fn into_inner(self) -> Box<dyn Any + Send> {
        self.0
    }
}

/// A `Resp<O>` whose `O` the registry has forgotten.
pub type ErasedResponse = Box<dyn Any + Send>;

/// A registered handler with its backend type erased.
///
/// `Arc` rather than `Box` so that [`super::Registry`] stays `Clone`: a router is cheap to hand to
/// another task, and a registry that could not be cloned would push that cost onto everything
/// holding one.
pub type ErasedHandler = Arc<dyn Fn(ErasedRequest, SseEnforced, RequestContextView) -> ErasedFuture + Send + Sync>;

/// The future an erased handler returns.
type ErasedFuture = BoxFuture<'static, Result<ErasedResponse, HandlerError>>;

/// Erases an operation and a backend into one closure.
///
/// This is the whole registration mechanism. The returned closure knows how to call `B` for `O`
/// and mentions neither in its type. The SSE proof and the request context travel beside the
/// erased payload and become part of the `Req<O>` the backend receives (ADR-0017, ADR-0022).
pub fn erase_authorized_handler<O, B>(implementation: Arc<B>) -> ErasedHandler
where
    O: Operation,
    B: Handler<O>,
{
    Arc::new(move |request: ErasedRequest, sse: SseEnforced, request_context: RequestContextView| {
        let implementation = Arc::clone(&implementation);
        erase_request::<O, B>(implementation, request, sse, request_context, None)
    })
}

/// Erases an operation and backend while preserving one caller-created handler context.
///
/// This is the bounded ADR-0011 migration entry used by the facade. The original
/// [`erase_authorized_handler`] remains source-compatible until every handler implementation and
/// the monomorphic path have migrated.
pub fn erase_authorized_handler_with_context<O, B>(
    implementation: Arc<B>,
) -> Arc<impl Fn(ErasedRequest, HandlerContext, SseEnforced, RequestContextView) -> ErasedFuture + Send + Sync>
where
    O: Operation,
    B: Handler<O>,
{
    Arc::new(
        move |request: ErasedRequest,
              context: HandlerContext,
              sse: SseEnforced,
              request_context: RequestContextView|
              -> BoxFuture<'static, Result<ErasedResponse, HandlerError>> {
            let implementation = Arc::clone(&implementation);
            erase_request::<O, B>(implementation, request, sse, request_context, Some(context))
        },
    )
}

fn erase_request<O, B>(
    implementation: Arc<B>,
    request: ErasedRequest,
    sse: SseEnforced,
    request_context: RequestContextView,
    context: Option<HandlerContext>,
) -> BoxFuture<'static, Result<ErasedResponse, HandlerError>>
where
    O: Operation,
    B: Handler<O>,
{
    Box::pin(async move {
        let authorized = request
            .into_inner()
            .downcast::<Authorized<O>>()
            .map_err(|_| mismatch::<O>())?;
        let request = authorized.into_request(sse, request_context);
        match context {
            Some(context) => dispatch_with_context::<O, B>(implementation, request, context).await,
            None => dispatch::<O, B>(implementation, request).await,
        }
    })
}

/// The only typed transition from authorization into a backend call.
async fn dispatch<O, B>(implementation: Arc<B>, request: crate::Req<O>) -> Result<ErasedResponse, HandlerError>
where
    O: Operation,
    B: Handler<O>,
{
    let response = implementation.call(request).await?;
    Ok(Box::new(response) as ErasedResponse)
}

async fn dispatch_with_context<O, B>(
    implementation: Arc<B>,
    request: crate::Req<O>,
    context: HandlerContext,
) -> Result<ErasedResponse, HandlerError>
where
    O: Operation,
    B: Handler<O>,
{
    let response = implementation.call_with_context(request, context).await?;
    Ok(Box::new(response) as ErasedResponse)
}

/// The error for a payload that is not the type the entry was registered with.
///
/// Unreachable through [`HandlerTable::invoke`], which looks the entry up by `O::NAME` and refuses
/// duplicate names, so the entry it finds was registered for the same operation. It is reachable
/// through [`HandlerTable::invoke_erased`], where the caller chose the box. Answered rather than
/// panicked: a pipeline bug must not be able to take the process down.
fn mismatch<O: Operation>() -> HandlerError {
    HandlerError::internal_error(format!(
        "the registered handler for {} was called with a payload of another operation's type",
        O::NAME
    ))
}

/// The typed future the handler table's internal invoke path returns.
///
/// Wraps the already-pinned erased future and downcasts its answer in `poll`, so the typed path
/// costs no allocation over the erased one. Every field is `Unpin`, so the projection needs no
/// `unsafe` — which matters, because the crate forbids it.
pub struct Invocation<O: Operation> {
    inner: BoxFuture<'static, Result<ErasedResponse, HandlerError>>,
    operation: PhantomData<fn() -> O>,
}

impl<O: Operation> Future for Invocation<O> {
    type Output = Result<Resp<O>, HandlerError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.inner.as_mut().poll(context).map(|result| {
            result.and_then(|response| {
                response
                    .downcast::<Resp<O>>()
                    .map(|boxed| *boxed)
                    .map_err(|_| mismatch::<O>())
            })
        })
    }
}

impl<O: Operation> fmt::Debug for Invocation<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invocation").field("operation", &O::NAME).finish()
    }
}

/// One registration: the erased handler, and the erased codec it was registered with.
///
/// Private, and there is no constructor that takes one half — the only way to make one is the
/// single [`HandlerTable::insert`] call inside `super::Registry`, which is what makes the pair
/// inseparable.
#[derive(Clone)]
struct Entry {
    handler: ErasedHandler,
    codec: Option<ErasedCodec>,
}

/// The erased handlers of one backend, with their codecs, by operation name.
#[derive(Clone, Default)]
pub struct HandlerTable {
    entries: BTreeMap<&'static str, Entry>,
}

impl HandlerTable {
    /// An empty table: every operation is unhandled, and therefore a 501.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores one erased handler together with the codec it was registered with.
    ///
    /// The two arrive in one call because they must: an entry can hold a handler with a codec or a
    /// handler without one, and there is no third state and no later call that could produce one.
    /// `None` is the operation whose wire form this crate does not define — a dialect operation
    /// registered through `super::Registry::register_handler_without_codec`.
    ///
    /// Returns whether the name was free. The caller decides what a taken name means; the registry
    /// treats it as [`super::RegistryError::Duplicate`], never as an overwrite.
    pub(crate) fn insert(&mut self, name: &'static str, handler: ErasedHandler, codec: Option<ErasedCodec>) -> bool {
        if self.entries.contains_key(name) {
            return false;
        }
        self.entries.insert(name, Entry { handler, codec });
        true
    }

    /// Whether an operation has a handler.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// The erased handler registered under a name.
    #[must_use]
    pub fn handler(&self, name: &str) -> Option<&ErasedHandler> {
        self.entries.get(name).map(|entry| &entry.handler)
    }

    /// The codec registered with that handler, when the operation has one.
    #[must_use]
    pub fn codec(&self, name: &str) -> Option<&ErasedCodec> {
        self.entries.get(name)?.codec.as_ref()
    }

    /// Both halves of one entry, in one lookup.
    ///
    /// What [`super::Registry::wire`] is built on: asking for the handler and then for the codec
    /// would search the map twice for an answer it already had, on the path every request takes.
    pub(crate) fn pair(&self, name: &str) -> Option<(&ErasedHandler, Option<&ErasedCodec>)> {
        let entry = self.entries.get(name)?;
        Some((&entry.handler, entry.codec.as_ref()))
    }

    /// The decoder registered with that handler, when the operation has one.
    #[must_use]
    pub fn decoder(&self, name: &str) -> Option<&ErasedDecode> {
        Some(self.codec(name)?.decoder())
    }

    /// The encoder registered with that handler, when the operation has one.
    #[must_use]
    pub fn encoder(&self, name: &str) -> Option<&ErasedEncode> {
        Some(self.codec(name)?.encoder())
    }

    /// Every registered operation that has no codec, sorted.
    ///
    /// One call, so that an assembly-time check for "this operation would route and then have
    /// nothing able to read it" is a loop somebody wrote once rather than a rule each caller
    /// reimplements over [`HandlerTable::names`].
    pub fn names_without_codec(&self) -> impl Iterator<Item = &'static str> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.codec.is_none())
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// How many operations have handlers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no operation has one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every operation with a handler, sorted.
    pub fn names(&self) -> impl Iterator<Item = &'static str> {
        self.entries.keys().copied().collect::<Vec<_>>().into_iter()
    }

    /// Calls the handler registered for `O`.
    ///
    /// `None` when nothing is registered under [`Operation::NAME`] — the caller answers that with
    /// a 501, which is what makes a partial backend legal without a single default method.
    #[must_use]
    pub(crate) fn invoke<O: Operation>(
        &self,
        request: Authorized<O>,
        sse: SseEnforced,
        context: crate::RequestContextView,
    ) -> Option<Invocation<O>> {
        let handler = self.handler(O::NAME)?;
        Some(Invocation {
            inner: handler(ErasedRequest::authorized(request), sse, context),
            operation: PhantomData,
        })
    }

    /// Calls the handler registered under a name, with a payload the caller boxed and the request
    /// context the caller's pipeline produced for the same request.
    ///
    /// The entry point the pipeline uses: it has a name from the route table and no operation type
    /// in hand.
    #[must_use]
    pub fn invoke_erased(
        &self,
        name: &str,
        request: ErasedRequest,
        sse: SseEnforced,
        context: crate::RequestContextView,
    ) -> Option<BoxFuture<'static, Result<ErasedResponse, HandlerError>>> {
        let handler = self.handler(name)?;
        Some(handler(request, sse, context))
    }
}

impl fmt::Debug for HandlerTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandlerTable")
            .field("operations", &self.names().collect::<Vec<_>>())
            .field("without_codec", &self.names_without_codec().collect::<Vec<_>>())
            .finish()
    }
}
