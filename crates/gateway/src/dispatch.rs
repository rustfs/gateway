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

//! Where the operation type disappears, and the only file in this crate that is generic over one.
//!
//! Responsible for: [`OperationDispatch`] — the codec-aware erasure of one `(O, B)` pair — and
//! [`DispatchTable`], the per-operation lookup the service performs after routing.
//! NOT responsible for: deciding which operation a request names (`rustfs_gateway_core::route`),
//! whether a registration is allowed (`rustfs_gateway_core::registry`), or anything a codec does.
//! Upstream: `rustfs-gateway-core`'s `OperationCodec` and `Handler`. Downstream: `crate::service`.
//!
//! # Why this is not `rustfs_gateway_core::registry`'s erasure
//!
//! That one erases the *backend* and stops there: its closure takes an already-decoded `Req<O>` in
//! a `Box<dyn Any>`, which means a caller must know `O` to build the argument. The facade never
//! knows `O` — it has a name from the route table — so it needs a closure that starts one step
//! earlier, at the wire. `crate::registry`'s own module documentation says as much: the payload is
//! `Any` "for one reason and it is temporary", until the generated codecs exist. They exist now,
//! and this is the shape that consumes them. Registration still goes through `RouterBuilder`, so
//! every registration-time refusal is unchanged; this table is what the request actually reaches.
//!
//! # Why the body is offered as a stream first
//!
//! `OperationSpec` does not carry the IR's `payload.request.buffering`, so the facade cannot ask
//! an operation whether its decoder wants `RequestBody::Stream` or `RequestBody::Buffered`. Two
//! wrong answers are available and only one of them is loud: handing a buffered body to a
//! streaming decoder makes `into_stream()` return `None` and the upload silently vanishes, while
//! handing a stream to a buffered decoder is refused by `RequestBody::into_buffered` with a
//! `500 InternalError` that says exactly what happened. So the stream is offered first and the
//! documented refusal is what selects the other shape. The retry costs one extra decode pass for
//! the buffered operations, whose bodies are small XML documents, and none for the streaming ones.
//!
//! A field on `OperationSpec` would remove the retry entirely; that is a `-core` change and a
//! regeneration, and it is recorded here rather than guessed at.
//!
//! # Where `OpLayer<O>` joins, and what it costs when nobody registered one
//!
//! The layer chain is built here because this is the last place `O` exists. The layers arrive as
//! `Option<Arc<[Arc<dyn OpLayer<O>>]>>`, and the `None` is load-bearing: with no layer registered
//! the invocation calls `backend.call(..)` directly, so there is no continuation, no `Terminal`
//! closure and no second `Box::pin`. `GET /b/key` is the overwhelming majority of data-plane
//! traffic and pays nothing for a level it does not use.
//!
//! That property is asserted rather than described. [`layered_invocations`] counts the times the
//! chain was entered, and the unit tests below drive one invocation with no layers and one with a
//! layer: the first must not move the counter and the second must. It is a count of *chain
//! entries*, not of allocations — a counting allocator needs `unsafe impl GlobalAlloc` and the
//! workspace forbids `unsafe` — so what it proves is that the code path holding the allocations was
//! not taken.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use rustfs_gateway_core::registry::erase_authorized_handler_with_context;
use rustfs_gateway_core::{
    Answer as CoreAnswer, AuthRequirement, BoxFuture, CodecError, Decision, Denied, EncodedResponse, ErasedCodec, ErasedDecoded,
    ErasedRequest, Handler, HandlerCancellationSource, HandlerContext, HandlerError, MetaView, OperationCodec, OwnedResource,
    Req, RequestBody, Resp, RouteEntry, TargetKind,
};
use rustfs_gateway_sig::OperationFloor;
use rustfs_gateway_stream::ByteStream;
use rustfs_gateway_types::ErrorCode;

use crate::ext::{Next, OpLayer, Terminal};
use crate::request_config::{InputAuthorized, RequestConfig};
use crate::request_deadline::{HandlerCancellationOutcome, commit_with_progress_deadline, handler_with_request_cancellation};

/// A `Resp<O>`'s output whose `O` this table has forgotten.
type ErasedOutput = Box<dyn std::any::Any + Send>;

/// The continuation of a committed response, with `O` forgotten.
pub(crate) type ErasedCommitWork = BoxFuture<'static, Result<ErasedOutput, HandlerError>>;

/// What a backend answered with, once the operation type is gone.
///
/// The distinction survives erasure on purpose: it is the difference between a response whose head
/// has not been written and one whose head is already on the wire, and the facade writes the two
/// differently.
pub(crate) enum ErasedAnswer {
    /// The output is here; the response can be encoded whole.
    Settled(ErasedOutput),
    /// The status is committed and the outcome is still running.
    Committed(ErasedCommitWork),
    /// An already framed event stream, with no generated output document to encode.
    EventStream(ByteStream),
}

/// The answer a backend produced, and the status it goes out with.
type Answer = Result<(ErasedAnswer, u16), HandlerError>;

/// A backend call in flight and the framework-owned half of its cancellation signal.
pub(crate) struct Invocation {
    inner: BoxFuture<'static, Answer>,
    _cancellation: HandlerCancellationSource,
}

impl Invocation {
    /// Signals this handler invocation once.
    #[cfg(test)]
    pub(crate) fn cancel(&self, reason: rustfs_gateway_core::HandlerCancellation) -> bool {
        self._cancellation.cancel(reason)
    }
}

impl Future for Invocation {
    type Output = Answer;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(context)
    }
}

/// Call the backend with input that carries the authorization proof.
type Invoke = Arc<dyn Fn(ErasedRequest, RequestConfig<InputAuthorized>) -> Result<Invocation, HandlerError> + Send + Sync>;

/// Write the answer back to the wire.
type Encode = Arc<dyn Fn(ErasedOutput, &MetaView<'_>, u16) -> Result<EncodedResponse, CodecError> + Send + Sync>;

/// Everything the service needs about one registered operation, with `O` erased.
#[derive(Clone)]
pub(crate) struct OperationDispatch {
    codec: ErasedCodec,
    invoke: Invoke,
    encode: Encode,
    floor: &'static OperationFloor,
    auth: Option<AuthRequirement>,
}

impl OperationDispatch {
    /// Erases one `(O, B)` pair with no middleware around it.
    #[cfg(test)]
    pub(crate) fn of<O, B>(backend: Arc<B>) -> Self
    where
        O: OperationCodec,
        B: Handler<O>,
    {
        Self::layered::<O, B>(backend, Vec::new())
    }

    /// Erases one `(O, B)` pair and the layers registered around it. The only generic function in
    /// this crate's request path.
    ///
    /// `layers` is in registration order, outermost first.
    pub(crate) fn layered<O, B>(backend: Arc<B>, layers: Vec<Arc<dyn OpLayer<O>>>) -> Self
    where
        O: OperationCodec,
        B: Handler<O>,
    {
        // `None` rather than an empty slice, so the hot path's test is a discriminant check and the
        // per-request work for an unlayered operation is exactly what it was before this level
        // existed.
        let layers: Option<Arc<[Arc<dyn OpLayer<O>>]>> = (!layers.is_empty()).then(|| Arc::from(layers));

        let codec = ErasedCodec::for_operation::<O>();

        let handler = erase_authorized_handler_with_context::<O, _>(Arc::new(LayeredBackend {
            backend,
            layers,
            operation: core::marker::PhantomData,
        }));
        let invoke: Invoke = Arc::new(move |request: ErasedRequest, request_config: RequestConfig<InputAuthorized>| {
            let (cancellation, context) = HandlerCancellationSource::pair();
            let call = handler(request, context);
            let deadline_class = O::spec()
                .deadline_class()
                .ok_or_else(|| HandlerError::internal_error("registered operation is missing its handler deadline class"))?;
            let deadline = request_config.config().handler_deadline(deadline_class);
            let cleanup_grace = request_config.config().handler_cleanup_grace();
            let commit_progress = request_config.config().commit_progress_deadline();
            let request_cancellation = request_config.request_cancellation();
            let deadline_cancellation = cancellation.clone();
            Ok(Invocation {
                _cancellation: cancellation,
                inner: Box::pin(async move {
                    // Keep the request's one configuration snapshot alive through the backend call.
                    // No dispatch implementation can load or substitute another snapshot.
                    let _request_config = request_config;
                    let response = match handler_with_request_cancellation(
                        call,
                        deadline_cancellation,
                        deadline,
                        cleanup_grace,
                        request_cancellation,
                    )
                    .await
                    {
                        HandlerCancellationOutcome::Completed(response) => response?,
                        HandlerCancellationOutcome::Expired { cleanup_completed: true } => {
                            _request_config.record_handler_deadline(true);
                            return Err(HandlerError::internal_error("handler deadline exceeded after cleanup completed"));
                        }
                        HandlerCancellationOutcome::Expired {
                            cleanup_completed: false,
                        } => {
                            _request_config.record_handler_deadline(false);
                            return Err(HandlerError::internal_error("handler deadline exceeded before cleanup completed"));
                        }
                        HandlerCancellationOutcome::RequestAborted { cleanup_completed } => {
                            let message = if cleanup_completed {
                                "request ended after handler cleanup completed"
                            } else {
                                "request ended before handler cleanup completed"
                            };
                            return Err(HandlerError::internal_error(message));
                        }
                    };
                    let response = response.downcast::<Resp<O>>().map_err(|_| {
                        HandlerError::internal_error("the registered dispatch received another operation's response")
                    })?;
                    let (answer, status) = response.into_parts();
                    let answer = match answer {
                        CoreAnswer::Settled(output) => ErasedAnswer::Settled(Box::new(output) as ErasedOutput),
                        // Bounded here rather than after the erasure, so that the deadline wraps
                        // the backend's own future and not a layer of `Box<dyn Any>` around it.
                        CoreAnswer::Committed(work) => {
                            let work = commit_with_progress_deadline(work, commit_progress);
                            ErasedAnswer::Committed(Box::pin(
                                async move { work.await.map(|output| Box::new(output) as ErasedOutput) },
                            ))
                        }
                        CoreAnswer::EventStream(stream) => ErasedAnswer::EventStream(stream),
                    };
                    Ok((answer, status))
                }),
            })
        });

        let encode: Encode = Arc::new(|output: ErasedOutput, meta: &MetaView<'_>, status: u16| {
            // Unreachable through the service, which looks the entry up by the same name it
            // invoked. Answered rather than panicked: a table bug must not take the process down.
            let output = output
                .downcast::<O::Output>()
                .map_err(|_| CodecError::internal("the registered codec was handed another operation's output"))?;
            let mut encoded = O::encode(*output, meta, status)?;
            encoded.apply_response_overrides(meta, O::RESPONSE_OVERRIDES);
            encoded.enforce_http_invariants(meta.method());
            Ok(encoded)
        });

        Self {
            codec,
            invoke,
            encode,
            floor: O::floor(),
            auth: O::spec().auth,
        }
    }

    /// What this operation tells the security floor about itself.
    pub(crate) const fn floor(&self) -> &'static OperationFloor {
        self.floor
    }

    /// The action this operation is authorised against.
    ///
    /// `Option` because `OperationSpec` carries it as one; registration has already refused every
    /// operation whose value is `None`, so the service treats a `None` reaching it as a refusal
    /// rather than as permission.
    pub(crate) const fn auth(&self) -> Option<AuthRequirement> {
        self.auth
    }

    /// Decodes the request without making it dispatchable.
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the request could not be read. A handler failure is inside the future.
    pub(crate) fn decode(&self, meta: &MetaView<'_>, body: Bytes) -> Result<ErasedDecoded, CodecError> {
        let streamed = RequestBody::Stream(ByteStream::from_bytes(body.clone()));
        match self.codec.decode(meta, streamed) {
            Ok(decoded) => Ok(decoded),
            Err(error) if error.code() == &ErrorCode::INTERNAL_ERROR => self.codec.decode(meta, RequestBody::Buffered(body)),
            Err(error) => Err(error),
        }
    }

    /// The normalized resources that require the second authorization stage.
    pub(crate) fn resources(&self, decoded: &ErasedDecoded) -> Result<Vec<OwnedResource>, CodecError> {
        self.codec.derived_resources(decoded)
    }

    /// Consumes decoded input and produces the only payload dispatch accepts.
    pub(crate) fn authorize(&self, decoded: ErasedDecoded, decisions: &[Decision]) -> Result<ErasedRequest, Denied> {
        self.codec.authorize(decoded, decisions)
    }

    /// Calls the backend with authorized input.
    pub(crate) fn invoke(
        &self,
        request: ErasedRequest,
        config: RequestConfig<InputAuthorized>,
    ) -> Result<Invocation, HandlerError> {
        (self.invoke)(request, config)
    }

    /// Encodes the answer.
    ///
    /// # Errors
    ///
    /// [`CodecError::internal`] for an output with no wire form. Nothing a caller sends reaches it.
    pub(crate) fn encode(&self, output: ErasedOutput, meta: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        (self.encode)(output, meta, status)
    }
}

impl core::fmt::Debug for OperationDispatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OperationDispatch")
            .field("action", &self.auth.map(|auth| auth.action))
            .finish_non_exhaustive()
    }
}

// How many times the layer chain has been entered on this thread.
//
// Test-only, and the whole of the zero-registration assertion: an invocation with no layer must
// not move it. See the module documentation for what this measures and what it does not.
//
// Thread-local rather than a process-wide atomic, because the test harness runs test functions
// concurrently and a `#[tokio::test]` drives its future on the thread that started it. A shared
// counter made the two assertions below observe each other's invocations, which is a flake in
// exactly the direction that reads like a real defect.
#[cfg(test)]
thread_local! {
    static LAYERED_INVOCATIONS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// The current value of the chain-entry counter, for this thread.
#[cfg(test)]
pub(crate) fn layered_invocations() -> u64 {
    LAYERED_INVOCATIONS.with(core::cell::Cell::get)
}

/// The typed backend registered behind core's opaque authorized dispatch.
struct LayeredBackend<O, B>
where
    O: OperationCodec,
    B: Handler<O>,
{
    backend: Arc<B>,
    layers: Option<Arc<[Arc<dyn OpLayer<O>>]>>,
    operation: core::marker::PhantomData<fn() -> O>,
}

impl<O, B> Handler<O> for LayeredBackend<O, B>
where
    O: OperationCodec,
    B: Handler<O>,
{
    async fn call(&self, request: Req<O>) -> rustfs_gateway_core::HandlerResult<O> {
        match &self.layers {
            None => self.backend.call(request).await,
            Some(layers) => {
                let (_source, context) = HandlerCancellationSource::pair();
                run_layered::<O, B>(&self.backend, layers, request, context).await
            }
        }
    }

    async fn call_with_context(&self, request: Req<O>, context: HandlerContext) -> rustfs_gateway_core::HandlerResult<O> {
        match &self.layers {
            None => self.backend.call_with_context(request, context).await,
            Some(layers) => run_layered::<O, B>(&self.backend, layers, request, context).await,
        }
    }
}

/// Runs one operation's layer chain, outermost first, with the backend as the terminal.
///
/// Reached only when at least one layer is registered; see [`OperationDispatch::layered`].
async fn run_layered<O, B>(
    backend: &B,
    layers: &[Arc<dyn OpLayer<O>>],
    request: Req<O>,
    context: HandlerContext,
) -> Result<Resp<O>, HandlerError>
where
    O: OperationCodec,
    B: Handler<O>,
{
    #[cfg(test)]
    LAYERED_INVOCATIONS.with(|entries| entries.set(entries.get().saturating_add(1)));
    let terminal = BackendTerminal::<O, B> {
        backend,
        context,
        operation: core::marker::PhantomData,
    };
    Next::new(layers, &terminal).run(request).await
}

/// The innermost link of a chain: the registered backend, in the shape `Next` calls.
struct BackendTerminal<'a, O, B> {
    backend: &'a B,
    context: HandlerContext,
    operation: core::marker::PhantomData<fn() -> O>,
}

impl<O, B> Terminal<O> for BackendTerminal<'_, O, B>
where
    O: OperationCodec,
    B: Handler<O>,
{
    fn call(&self, request: Req<O>) -> BoxFuture<'_, rustfs_gateway_core::HandlerResult<O>> {
        Box::pin(self.backend.call_with_context(request, self.context.clone()))
    }
}

/// The registered operations, by name.
#[derive(Clone, Debug, Default)]
pub(crate) struct DispatchTable {
    entries: BTreeMap<&'static str, OperationDispatch>,
}

impl DispatchTable {
    /// Stores one erased operation. Reports whether the name was free; the builder treats a taken
    /// name as a duplicate, exactly as the core registry does, and never as an overwrite.
    pub(crate) fn insert(&mut self, name: &'static str, dispatch: OperationDispatch) -> bool {
        if self.entries.contains_key(name) {
            return false;
        }
        self.entries.insert(name, dispatch);
        true
    }

    /// The entry for an operation, when one is registered.
    pub(crate) fn get(&self, name: &str) -> Option<&OperationDispatch> {
        self.entries.get(name)
    }

    /// Whether an operation has an entry.
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// How many operations are registered.
    ///
    /// Test-only since assembly moved to a deferred registration map: `build` counts the pending
    /// registrations, because that is the set that exists before the erasure runs.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Every registered name, sorted.
    pub(crate) fn names(&self) -> impl Iterator<Item = &'static str> {
        self.entries.keys().copied().collect::<Vec<_>>().into_iter()
    }

    /// Every registered operation floor, for the one startup posture report.
    pub(crate) fn floors(&self) -> impl Iterator<Item = &'static OperationFloor> + '_ {
        self.entries.values().map(OperationDispatch::floor)
    }
}

/// What the path of a routed request addresses.
///
/// Read from the entry's own selector, which is where the route table records it, with the path
/// shape as the fallback for a hand-written entry that omitted the predicate. Deriving it from the
/// path a second time would be a second component answering the [`crate::HostResolver`]'s
/// question.
pub(crate) fn target_of(entry: &RouteEntry) -> TargetKind {
    for predicate in entry.selector.predicates() {
        if let rustfs_gateway_core::Predicate::Target(kind) = predicate {
            return *kind;
        }
    }
    match entry.path_shape.matches('/').count() {
        0 => TargetKind::Service,
        1 if entry.path_shape == "/" => TargetKind::Service,
        1 => TargetKind::Bucket,
        _ => TargetKind::Object,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_core::{Predicate, RouteSelector};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn entry(predicates: &'static [Predicate], path_shape: &'static str) -> RouteEntry {
        RouteEntry {
            precedence: 100,
            selector: RouteSelector::new(predicates),
            op_name: "vendor:Probe",
            path_shape,
        }
    }

    /// Positive — the selector is the source, so an entry that declares its target is read rather
    /// than guessed at.
    #[test]
    fn the_target_comes_from_the_selector() {
        static PREDICATES: &[Predicate] = &[Predicate::Target(TargetKind::Object)];
        assert_eq!(target_of(&entry(PREDICATES, "/")), TargetKind::Object);
    }

    /// Negative — an entry with no target predicate falls back to its path shape rather than
    /// defaulting to `Object`, which would make every service-level path decode a bucket label out
    /// of nothing.
    #[test]
    fn an_entry_without_a_target_predicate_falls_back_to_its_shape() {
        static NONE: &[Predicate] = &[];
        assert_eq!(target_of(&entry(NONE, "/")), TargetKind::Service);
        assert_eq!(target_of(&entry(NONE, "/{Bucket}")), TargetKind::Bucket);
        assert_eq!(target_of(&entry(NONE, "/{Bucket}/{Key+}")), TargetKind::Object);
    }

    /// Negative — a second registration under one name is refused, never an overwrite. An
    /// overwrite would let a later `register` call silently take over an operation.
    #[test]
    fn a_duplicate_name_is_refused_rather_than_overwritten() {
        let mut table = DispatchTable::default();
        let dispatch = OperationDispatch::of::<rustfs_gateway_types::dto::ListBuckets, _>(Arc::new(NoBackend));
        assert!(table.insert("ListBuckets", dispatch.clone()));
        assert!(!table.insert("ListBuckets", dispatch));
        assert_eq!(table.len(), 1);
    }

    /// Negative — a name nobody registered is absent, which is what the service turns into a 501.
    #[test]
    fn an_unregistered_name_is_absent() {
        let table = DispatchTable::default();
        assert!(!table.contains("GetObject"));
        assert!(table.get("GetObject").is_none());
        assert_eq!(table.names().count(), 0);
    }

    /// Negative — with no layer registered the chain is never entered, so nothing on the hot path
    /// builds a continuation, a terminal or a second boxed future.
    ///
    /// This is a count of chain entries and not of allocations: a counting global allocator needs
    /// `unsafe impl GlobalAlloc` and the workspace forbids `unsafe`. What it proves is that the
    /// branch holding those allocations was not taken — break `layered` so that it always chooses
    /// the chain and this goes red, which is the mutation that says the assertion is worth having.
    #[tokio::test]
    async fn an_unlayered_operation_never_enters_the_chain() {
        let before = layered_invocations();
        let dispatch = OperationDispatch::layered::<rustfs_gateway_types::dto::ListBuckets, _>(Arc::new(NoBackend), Vec::new());
        let _ = invoke_once(&dispatch).await;
        assert_eq!(layered_invocations(), before, "an unlayered operation entered the layer chain");
    }

    /// Positive — the erased dynamic path must preserve the handler context rather than silently
    /// falling back to the legacy one-argument call. The deadline owner cannot signal a context
    /// that disappears at registration-time erasure.
    #[tokio::test]
    async fn dynamic_dispatch_reaches_the_context_aware_handler_entry() {
        let observed = Arc::new(AtomicBool::new(false));
        let backend = Arc::new(ContextAwareBackend {
            observed: Arc::clone(&observed),
            behavior: ContextBehavior::ObserveCancellation,
        });

        let dispatch = OperationDispatch::of::<rustfs_gateway_types::dto::ListBuckets, _>(Arc::clone(&backend));
        let invocation = invocation_once(&dispatch).expect("dispatchable");
        assert!(invocation.cancel(rustfs_gateway_core::HandlerCancellation::Deadline));
        let _ = invocation.await;
        assert!(observed.swap(false, Ordering::AcqRel), "the erased path discarded HandlerContext");

        let layer: Arc<dyn OpLayer<rustfs_gateway_types::dto::ListBuckets>> =
            Arc::new(crate::ext::op_layer(|request, next: Next<'_, rustfs_gateway_types::dto::ListBuckets>| {
                next.run(request)
            }));
        let dispatch = OperationDispatch::layered::<rustfs_gateway_types::dto::ListBuckets, _>(backend, vec![layer]);
        let invocation = invocation_once(&dispatch).expect("dispatchable");
        assert!(invocation.cancel(rustfs_gateway_core::HandlerCancellation::Deadline));
        let _ = invocation.await;
        assert!(observed.swap(false, Ordering::AcqRel), "the operation layer discarded HandlerContext");
    }

    /// Negative — a handler that cooperates with the deadline may finish cleanup, but its late
    /// success must never become the response.
    #[tokio::test]
    async fn handler_deadline_signals_cleanup_and_discards_the_late_result() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let dispatch = OperationDispatch::of::<rustfs_gateway_types::dto::ListBuckets, _>(Arc::new(ContextAwareBackend {
            observed: Arc::clone(&cleaned),
            behavior: ContextBehavior::Cleanup,
        }));
        let invocation =
            invocation_with_deadline(&dispatch, Duration::from_millis(20), Duration::from_millis(100)).expect("dispatchable");

        let result = tokio::time::timeout(Duration::from_secs(1), invocation)
            .await
            .expect("the handler deadline is bounded");
        let Err(error) = result else {
            panic!("a success completed after the deadline");
        };
        assert_eq!(error.message(), "handler deadline exceeded after cleanup completed");
        assert!(cleaned.load(Ordering::Acquire), "the handler did not observe the deadline signal");
    }

    /// Negative — an uncooperative handler remains pending through the cleanup grace, then the
    /// invocation returns without waiting for the backend forever.
    #[tokio::test]
    async fn handler_deadline_bounds_an_uncooperative_handler() {
        let dispatch = OperationDispatch::of::<rustfs_gateway_types::dto::ListBuckets, _>(Arc::new(ContextAwareBackend {
            observed: Arc::new(AtomicBool::new(false)),
            behavior: ContextBehavior::NeverCompletes,
        }));
        let invocation =
            invocation_with_deadline(&dispatch, Duration::from_millis(20), Duration::from_millis(40)).expect("dispatchable");

        let result = tokio::time::timeout(Duration::from_secs(1), invocation)
            .await
            .expect("deadline plus cleanup grace is bounded");
        let Err(error) = result else {
            panic!("an uncooperative handler produced a response");
        };
        assert_eq!(error.message(), "handler deadline exceeded before cleanup completed");
    }

    /// Positive — a handler that completes before its class deadline keeps its ordinary response.
    #[tokio::test]
    async fn handler_result_before_deadline_is_preserved() {
        let dispatch = OperationDispatch::of::<rustfs_gateway_types::dto::ListBuckets, _>(Arc::new(ContextAwareBackend {
            observed: Arc::new(AtomicBool::new(false)),
            behavior: ContextBehavior::Immediate,
        }));
        let invocation =
            invocation_with_deadline(&dispatch, Duration::from_millis(100), Duration::from_millis(20)).expect("dispatchable");

        let result = invocation.await;
        assert!(matches!(result, Ok((ErasedAnswer::Settled(_), 200))));
    }

    /// Positive — the other direction. One registered layer does enter the chain, so the counter
    /// above is a measurement of the branch rather than of a code path nothing ever reaches.
    #[tokio::test]
    async fn a_layered_operation_enters_the_chain_exactly_once() {
        let layer: Arc<dyn OpLayer<rustfs_gateway_types::dto::ListBuckets>> =
            Arc::new(crate::ext::op_layer(|request, next: Next<'_, rustfs_gateway_types::dto::ListBuckets>| {
                next.run(request)
            }));
        let dispatch = OperationDispatch::layered::<rustfs_gateway_types::dto::ListBuckets, _>(Arc::new(NoBackend), vec![layer]);
        let before = layered_invocations();
        let _ = invoke_once(&dispatch).await;
        assert_eq!(layered_invocations(), before + 1);
    }

    /// Drives one invocation of an already-erased operation, with an empty body.
    async fn invoke_once(dispatch: &OperationDispatch) -> Result<(ErasedAnswer, u16), HandlerError> {
        invocation_once(dispatch)?.await
    }

    fn invocation_once(dispatch: &OperationDispatch) -> Result<Invocation, HandlerError> {
        invocation_with_config(dispatch, crate::ServiceConfig::new(1))
    }

    fn invocation_with_deadline(
        dispatch: &OperationDispatch,
        deadline: Duration,
        cleanup_grace: Duration,
    ) -> Result<Invocation, HandlerError> {
        let deadlines = crate::HandlerDeadlineConfig::new(deadline, deadline)
            .expect("non-zero deadlines")
            .try_with_cleanup_grace(cleanup_grace)
            .expect("a non-zero cleanup grace");
        invocation_with_config(dispatch, crate::ServiceConfig::new(1).with_handler_deadlines(deadlines))
    }

    fn invocation_with_config(dispatch: &OperationDispatch, config: crate::ServiceConfig) -> Result<Invocation, HandlerError> {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("/")
            .header("host", "s3.example.com")
            .body(Bytes::new())
            .expect("a valid request");
        let wire = rustfs_gateway_http::WireRequest::accept(request, &rustfs_gateway_http::Limits::default())
            .expect("an acceptable request");
        let meta = MetaView::of(&wire, TargetKind::Service).expect("a service-level view");
        let decoded = dispatch.decode(&meta, Bytes::new()).expect("a decodable request");
        let resources = dispatch.resources(&decoded).expect("derived resources");
        let decisions = vec![Decision::Allow; resources.len()];
        let authorized = dispatch.authorize(decoded, &decisions).expect("authorized");
        let config = RequestConfig::enter(Arc::new(config))
            .accepted()
            .routed()
            .governed()
            .authenticated()
            .route_authorized()
            .body_read()
            .decoded()
            .input_authorized();
        dispatch.invoke(authorized, config)
    }

    struct NoBackend;

    struct ContextAwareBackend {
        observed: Arc<AtomicBool>,
        behavior: ContextBehavior,
    }

    enum ContextBehavior {
        ObserveCancellation,
        Cleanup,
        NeverCompletes,
        Immediate,
    }

    impl Handler<rustfs_gateway_types::dto::ListBuckets> for ContextAwareBackend {
        async fn call(
            &self,
            _request: Req<rustfs_gateway_types::dto::ListBuckets>,
        ) -> rustfs_gateway_core::HandlerResult<rustfs_gateway_types::dto::ListBuckets> {
            Err(HandlerError::internal_error("the legacy handler entry was used"))
        }

        async fn call_with_context(
            &self,
            _request: Req<rustfs_gateway_types::dto::ListBuckets>,
            context: rustfs_gateway_core::HandlerContext,
        ) -> rustfs_gateway_core::HandlerResult<rustfs_gateway_types::dto::ListBuckets> {
            match &self.behavior {
                ContextBehavior::NeverCompletes => return std::future::pending().await,
                ContextBehavior::Immediate => return Ok(Resp::new(Default::default())),
                ContextBehavior::ObserveCancellation | ContextBehavior::Cleanup => {
                    assert_eq!(context.cancelled().await, rustfs_gateway_core::HandlerCancellation::Deadline);
                }
            }
            self.observed.store(true, Ordering::Release);
            match self.behavior {
                ContextBehavior::ObserveCancellation => {
                    Err(HandlerError::not_implemented("the context-aware handler entry was used"))
                }
                ContextBehavior::Cleanup => Ok(Resp::new(Default::default())),
                ContextBehavior::NeverCompletes | ContextBehavior::Immediate => {
                    Err(HandlerError::internal_error("the context-aware test backend used the wrong behavior"))
                }
            }
        }
    }

    impl Handler<rustfs_gateway_types::dto::ListBuckets> for NoBackend {
        async fn call(
            &self,
            _request: Req<rustfs_gateway_types::dto::ListBuckets>,
        ) -> rustfs_gateway_core::HandlerResult<rustfs_gateway_types::dto::ListBuckets> {
            Err(HandlerError::not_implemented("this backend answers nothing"))
        }

        async fn call_with_context(
            &self,
            _request: Req<rustfs_gateway_types::dto::ListBuckets>,
            _context: rustfs_gateway_core::HandlerContext,
        ) -> rustfs_gateway_core::HandlerResult<rustfs_gateway_types::dto::ListBuckets> {
            Err(HandlerError::not_implemented("this backend answers nothing"))
        }
    }
}
