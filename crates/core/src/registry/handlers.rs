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
//! NOT responsible for: deciding whether a registration is allowed (`super::reject`), route
//! conflicts (`crate::route`), or any pre-authentication decision. Nothing here runs before the
//! security floor has admitted the request.
//! Upstream: `crate::handler`, `crate::op`. Downstream: [`super::Registry`], and P4-04's pipeline,
//! which is what will call [`HandlerTable::invoke_erased`] with a wire request once the generated
//! codecs exist.
//!
//! # What is erased, and what is not
//!
//! The backend type is erased; the operation type is not. A registry entry has to be able to call
//! `B::call`, so it has to know `B` — which is exactly why `inventory`-style collection cannot
//! work here (measured `error[E0117]`, ADR-0003). Erasing `B` inside a closure at registration
//! time is what keeps `Router` and, above it, the service non-generic: one process can hold two
//! routers over two different backends, which RustFS already does in its end-to-end tests.
//!
//! The payload is `Box<dyn Any + Send>` for one reason and it is temporary: the erased closure
//! should take a wire request and return a wire response, but `Operation::decode` and
//! `Operation::encode` arrive with the generated codecs. Until then the pipeline hands over an
//! already-decoded `Req<O>` in a box, and the closure hands back a `Resp<O>` in a box. The
//! signature changes when the codecs land; [`crate::handler::Handler`] and the macro do not.
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

use crate::handler::{BoxFuture, Handler, HandlerError, Req, Resp};
use crate::op::Operation;

/// A `Req<O>` whose `O` the registry has forgotten.
pub type ErasedRequest = Box<dyn Any + Send>;

/// A `Resp<O>` whose `O` the registry has forgotten.
pub type ErasedResponse = Box<dyn Any + Send>;

/// A registered handler with its backend type erased.
///
/// `Arc` rather than `Box` so that [`super::Registry`] stays `Clone`: a router is cheap to hand to
/// another task, and a registry that could not be cloned would push that cost onto everything
/// holding one.
pub type ErasedHandler = Arc<dyn Fn(ErasedRequest) -> BoxFuture<'static, Result<ErasedResponse, HandlerError>> + Send + Sync>;

/// Erases an operation and a backend into one closure.
///
/// This is the whole registration mechanism. The returned closure knows how to call `B` for `O`
/// and mentions neither in its type.
pub(crate) fn erase<O, B>(implementation: Arc<B>) -> ErasedHandler
where
    O: Operation,
    B: Handler<O>,
{
    Arc::new(move |request: ErasedRequest| {
        let implementation = Arc::clone(&implementation);
        Box::pin(async move {
            let request = request.downcast::<Req<O>>().map_err(|_| mismatch::<O>())?;
            let response = implementation.call(*request).await?;
            Ok(Box::new(response) as ErasedResponse)
        })
    })
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

/// The typed future [`HandlerTable::invoke`] returns.
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

/// The erased handlers of one backend, by operation name.
#[derive(Clone, Default)]
pub struct HandlerTable {
    entries: BTreeMap<&'static str, ErasedHandler>,
}

impl HandlerTable {
    /// An empty table: every operation is unhandled, and therefore a 501.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores one erased handler.
    ///
    /// Returns whether the name was free. The caller decides what a taken name means; the registry
    /// treats it as [`super::RegistryError::Duplicate`], never as an overwrite.
    pub(crate) fn insert(&mut self, name: &'static str, handler: ErasedHandler) -> bool {
        if self.entries.contains_key(name) {
            return false;
        }
        self.entries.insert(name, handler);
        true
    }

    /// Whether an operation has a handler.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
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
    pub fn invoke<O: Operation>(&self, request: Req<O>) -> Option<Invocation<O>> {
        let handler = self.entries.get(O::NAME)?;
        Some(Invocation {
            inner: handler(Box::new(request)),
            operation: PhantomData,
        })
    }

    /// Calls the handler registered under a name, with a payload the caller boxed.
    ///
    /// The entry point the pipeline uses: it has a name from the route table and no operation type
    /// in hand.
    #[must_use]
    pub fn invoke_erased(
        &self,
        name: &str,
        request: ErasedRequest,
    ) -> Option<BoxFuture<'static, Result<ErasedResponse, HandlerError>>> {
        let handler = self.entries.get(name)?;
        Some(handler(request))
    }
}

impl fmt::Debug for HandlerTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandlerTable")
            .field("operations", &self.names().collect::<Vec<_>>())
            .finish()
    }
}
