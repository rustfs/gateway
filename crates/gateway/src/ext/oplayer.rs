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

//! The innermost of the three levels: middleware around one operation, with its types intact.
//!
//! Responsible for: [`OpLayer`], the continuation [`Next`] it is handed, the closure adapter
//! [`op_layer`], and [`OpLayerSlot`] — the typed box that lets a per-operation layer be collected
//! in a registry that is not generic over the operation.
//! NOT responsible for: running them. `crate::dispatch` builds the chain, because that is the one
//! place in this crate that still knows `O`. Nor for anything between stages, which is
//! [`crate::StageFilter`] one level out.
//! Upstream: `rustfs-gateway-core`'s `Operation`, `Req`, `Resp`. Downstream: `crate::builder`,
//! `crate::dispatch`.
//!
//! # Why this level exists at all
//!
//! RustFS carries a tower layer today whose whole job is to correct one field of one operation's
//! response. Because a tower layer sees bytes, it has to parse the response XML, edit the element
//! and serialise it back — for a value the server itself produced from a struct one stack frame
//! earlier. With a typed `Output` the same correction is three statements, and it cannot break the
//! document's shape, because it never touches the document.
//!
//! # Why it cannot skip authorisation
//!
//! An [`OpLayer`] runs **inside** dispatch. By the time one is called the request has passed the
//! security floor, the authenticator and the authorizer; the layer's argument is a `Req<O>` that
//! only the decoder can produce, and there is no constructor anywhere that turns a layer's own
//! value into an authorised request. Not calling [`Next::run`] therefore skips the *handler*, never
//! the authorisation — which is the difference between a legitimate cache and rustfs/rustfs#4845.
//!
//! # Why `Next::run` takes `self`
//!
//! It consumes the continuation, so "call `next` twice" is not a runtime error to be reported: it
//! is a value that has been moved, and the second call does not compile. A runtime one-shot guard
//! would have been the weaker half of the same property, with a branch nothing can reach.
//!
//! # Why the future is hand-written
//!
//! ADR-0002: this trait is held as `Arc<dyn OpLayer<O>>`, and RPITIT is measurably not dyn
//! compatible. `Handler<O>` and `Operation` are the only two traits in the workspace exempt, and
//! neither of them is this one.

use std::any::Any;
use std::sync::Arc;

use rustfs_gateway_core::{BoxFuture, HandlerResult, Operation, Req};

/// The innermost end of one operation's layer chain: the backend call itself.
///
/// A crate-private trait rather than a type parameter on [`Next`], because `Next` is public and
/// must not grow a parameter for the backend — a deployment writing a layer would then have to name
/// the backend's type in the layer's signature. It is also not a `dyn Fn`: tying the returned future
/// to `&self` rather than to a second lifetime parameter is what keeps the chain's borrows
/// intelligible.
pub(crate) trait Terminal<O: Operation>: Send + Sync {
    /// Calls the backend.
    fn call(&self, request: Req<O>) -> BoxFuture<'_, HandlerResult<O>>;
}

/// The rest of the chain, exactly once.
///
/// [`Next::run`] takes `self`, so a layer either delegates or answers, and cannot do both. See the
/// module documentation for why that is stronger than a one-shot guard.
pub struct Next<'a, O: Operation> {
    remaining: &'a [Arc<dyn OpLayer<O>>],
    terminal: &'a dyn Terminal<O>,
}

impl<'a, O: Operation> Next<'a, O> {
    /// Builds the outermost continuation. Crate-private: a layer receives one, never mints one, so
    /// nothing outside this crate can start a chain that skipped its own beginning.
    pub(crate) fn new(remaining: &'a [Arc<dyn OpLayer<O>>], terminal: &'a dyn Terminal<O>) -> Self {
        Self { remaining, terminal }
    }

    /// Runs the next layer, or the backend when this was the innermost one.
    pub fn run(self, request: Req<O>) -> BoxFuture<'a, HandlerResult<O>> {
        match self.remaining.split_first() {
            Some((next, remaining)) => next.wrap(
                request,
                Self {
                    remaining,
                    terminal: self.terminal,
                },
            ),
            None => self.terminal.call(request),
        }
    }

    /// How many layers are still inside this one, the backend excluded.
    ///
    /// For an assertion, and for a layer that wants to know whether it is the innermost.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.remaining.len()
    }
}

impl<O: Operation> core::fmt::Debug for Next<'_, O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Next")
            .field("operation", &O::NAME)
            .field("depth", &self.remaining.len())
            .finish()
    }
}

/// Middleware around one operation, holding that operation's decoded input and typed output.
///
/// Registered with [`crate::ServiceBuilder::op_layer`], which refuses at assembly time if the
/// operation has no handler. Multiple layers on one operation nest outer to inner in registration
/// order.
///
/// **This is the level for a rewrite that needs a DTO.** A rewrite that does not is a
/// [`crate::StageFilter`]; observation is a [`crate::Observer`].
pub trait OpLayer<O: Operation>: Send + Sync + 'static {
    /// Wraps one call.
    ///
    /// Call `next.run(request)` to reach the rest of the chain, or answer without it. What cannot
    /// be done from here is reaching the handler *twice*, or reaching it having skipped a stage:
    /// authentication and authorisation happened before dispatch, and there is nothing here that
    /// can undo them.
    fn wrap<'a>(&'a self, request: Req<O>, next: Next<'a, O>) -> BoxFuture<'a, HandlerResult<O>>;
}

impl<O: Operation, T: OpLayer<O> + ?Sized> OpLayer<O> for Arc<T> {
    fn wrap<'a>(&'a self, request: Req<O>, next: Next<'a, O>) -> BoxFuture<'a, HandlerResult<O>> {
        (**self).wrap(request, next)
    }
}

/// An [`OpLayer`] from a closure, so that supplying one function does not require declaring a
/// struct (ADR-0002's consequence).
///
/// ```
/// use rustfs_gateway::{BoxFuture, HandlerResult, Next, Req, op_layer};
/// use rustfs_gateway::dto::GetObjectAttributes;
///
/// let layer = op_layer(|request: Req<GetObjectAttributes>, next: Next<'_, GetObjectAttributes>| {
///     Box::pin(async move {
///         let mut response = next.run(request).await?;
///         if let Some(output) = response.output_mut() {
///             output.e_tag = None;
///         }
///         Ok(response)
///     }) as BoxFuture<'_, HandlerResult<GetObjectAttributes>>
/// });
/// # let _ = layer;
/// ```
pub fn op_layer<O, F>(f: F) -> impl OpLayer<O>
where
    O: Operation,
    F: for<'a> Fn(Req<O>, Next<'a, O>) -> BoxFuture<'a, HandlerResult<O>> + Send + Sync + 'static,
{
    struct FromFn<F, O> {
        f: F,
        operation: core::marker::PhantomData<fn() -> O>,
    }

    // `PhantomData<fn() -> O>` is `Send + Sync` whatever `O` is, so the bounds come from `F` alone.
    impl<O, F> OpLayer<O> for FromFn<F, O>
    where
        O: Operation,
        F: for<'a> Fn(Req<O>, Next<'a, O>) -> BoxFuture<'a, HandlerResult<O>> + Send + Sync + 'static,
    {
        fn wrap<'a>(&'a self, request: Req<O>, next: Next<'a, O>) -> BoxFuture<'a, HandlerResult<O>> {
            (self.f)(request, next)
        }
    }

    FromFn {
        f,
        operation: core::marker::PhantomData,
    }
}

/// One registered layer, in the one shape a registry that has forgotten `O` can hold.
///
/// The builder collects `Arc<dyn Any + Send + Sync>`, keyed by operation name. `Arc<dyn OpLayer<O>>`
/// is itself unsized and cannot be downcast to; wrapping it in this concrete, `O`-parameterised
/// struct gives `Any` something with a single `TypeId` to match on. Assembly then downcasts each
/// slot back inside the one closure that still knows `O` — the same closure-erasure shape
/// `rustfs_gateway_core::registry` uses for handlers, and the reason neither needs `inventory`
/// (ADR-0003).
pub(crate) struct OpLayerSlot<O: Operation> {
    layer: Arc<dyn OpLayer<O>>,
}

impl<O: Operation> OpLayerSlot<O> {
    /// Boxes one layer for storage.
    ///
    /// Deliberately not called `new`: it returns the erased handle rather than a `Self`, and the
    /// erasure is the whole point of the type.
    pub(crate) fn erase(layer: Arc<dyn OpLayer<O>>) -> Arc<dyn Any + Send + Sync> {
        Arc::new(Self { layer })
    }

    /// Takes the layer back out.
    pub(crate) fn into_layer(self: Arc<Self>) -> Arc<dyn OpLayer<O>> {
        Arc::clone(&self.layer)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_core::{HandlerError, Resp};
    use rustfs_gateway_types::dto::ListBuckets;

    /// The backend end of a chain, for the tests below: it refuses, so reaching it is visible.
    struct Refusing;

    impl Terminal<ListBuckets> for Refusing {
        fn call(&self, _request: Req<ListBuckets>) -> BoxFuture<'_, HandlerResult<ListBuckets>> {
            Box::pin(async { Err(HandlerError::not_implemented("the terminal")) })
        }
    }

    /// Positive — an empty chain reaches the terminal, which is the shape every request takes when
    /// no layer is registered.
    #[tokio::test]
    async fn an_empty_chain_reaches_the_terminal() {
        let call = Refusing;
        let empty: [Arc<dyn OpLayer<ListBuckets>>; 0] = [];
        let next = Next::new(&empty, &call);
        assert_eq!(next.depth(), 0);
        let error = next
            .run(Req::new(Default::default()))
            .await
            .expect_err("the terminal refuses");
        assert_eq!(error.message(), "the terminal");
    }

    /// Positive — the depth a layer sees counts the layers still inside it, so the outermost of two
    /// sees one and the innermost sees none.
    #[tokio::test]
    async fn each_layer_sees_the_depth_still_inside_it() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let make = |seen: &Arc<std::sync::Mutex<Vec<usize>>>| {
            let seen = Arc::clone(seen);
            let layer: Arc<dyn OpLayer<ListBuckets>> = Arc::new(op_layer(move |request, next: Next<'_, ListBuckets>| {
                if let Ok(mut seen) = seen.lock() {
                    seen.push(next.depth());
                }
                next.run(request)
            }));
            layer
        };
        let layers = [make(&seen), make(&seen)];
        let call = Refusing;
        let _ = Next::new(&layers, &call).run(Req::new(Default::default())).await;
        assert_eq!(seen.lock().expect("not poisoned").as_slice(), [1, 0]);
    }

    /// Negative — a layer that does not delegate stops the chain, so nothing inside it runs.
    #[tokio::test]
    async fn a_layer_that_does_not_delegate_stops_the_chain() {
        let inner_ran = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&inner_ran);
        let outer: Arc<dyn OpLayer<ListBuckets>> = Arc::new(op_layer(|_request, _next: Next<'_, ListBuckets>| {
            Box::pin(async { Ok(Resp::new(Default::default())) }) as BoxFuture<'_, HandlerResult<ListBuckets>>
        }));
        let inner: Arc<dyn OpLayer<ListBuckets>> = Arc::new(op_layer(move |request, next: Next<'_, ListBuckets>| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            next.run(request)
        }));
        let layers = [outer, inner];
        let call = Refusing;
        let response = Next::new(&layers, &call)
            .run(Req::new(Default::default()))
            .await
            .expect("the outer layer answered");
        assert_eq!(response.status(), 200);
        assert_eq!(inner_ran.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// Negative — a slot hands back the very layer it was given, so the registry cannot substitute
    /// one operation's layer for another's on the way through `Any`.
    #[test]
    fn a_slot_round_trips_its_layer() {
        let layer: Arc<dyn OpLayer<ListBuckets>> = Arc::new(op_layer(|request, next: Next<'_, ListBuckets>| next.run(request)));
        let erased = OpLayerSlot::<ListBuckets>::erase(Arc::clone(&layer));
        let slot = erased
            .downcast::<OpLayerSlot<ListBuckets>>()
            .map_err(|_| "the slot did not carry its own type")
            .expect("a slot");
        assert!(Arc::ptr_eq(&slot.into_layer(), &layer));
    }
}
