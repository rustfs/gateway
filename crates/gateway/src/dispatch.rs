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

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use rustfs_gateway_core::{
    Answer as CoreAnswer, AuthRequirement, BoxFuture, CodecError, EncodedResponse, Handler, HandlerError, MetaView,
    OperationCodec, Req, RequestBody, Resp, RouteEntry, TargetKind,
};
use rustfs_gateway_sig::OperationFloor;
use rustfs_gateway_stream::ByteStream;
use rustfs_gateway_types::ErrorCode;

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
}

/// The answer a backend produced, and the status it goes out with.
type Answer = Result<(ErasedAnswer, u16), HandlerError>;

/// A backend call in flight.
pub(crate) type Invocation = BoxFuture<'static, Answer>;

/// Decode the wire, then call the backend.
type Invoke = Arc<dyn Fn(&MetaView<'_>, Bytes) -> Result<Invocation, CodecError> + Send + Sync>;

/// Write the answer back to the wire.
type Encode = Arc<dyn Fn(ErasedOutput, &MetaView<'_>, u16) -> Result<EncodedResponse, CodecError> + Send + Sync>;

/// Everything the service needs about one registered operation, with `O` erased.
#[derive(Clone)]
pub(crate) struct OperationDispatch {
    invoke: Invoke,
    encode: Encode,
    floor: &'static OperationFloor,
    auth: Option<AuthRequirement>,
}

impl OperationDispatch {
    /// Erases one `(O, B)` pair. The only generic function in this crate's request path.
    pub(crate) fn of<O, B>(backend: Arc<B>) -> Self
    where
        O: OperationCodec,
        B: Handler<O>,
    {
        let invoke: Invoke = Arc::new(move |meta: &MetaView<'_>, bytes: Bytes| {
            let input = decode::<O>(meta, bytes)?;
            let backend = Arc::clone(&backend);
            Ok(Box::pin(async move {
                let response: Resp<O> = backend.call(Req::<O>::new(input)).await?;
                let (answer, status) = response.into_parts();
                let answer = match answer {
                    CoreAnswer::Settled(output) => ErasedAnswer::Settled(Box::new(output) as ErasedOutput),
                    // The continuation is re-boxed rather than driven here, because driving it is
                    // what the head has already been committed against: this closure returns as
                    // soon as the status is known, and the facade writes the head before awaiting
                    // what is inside.
                    CoreAnswer::Committed(work) => {
                        ErasedAnswer::Committed(Box::pin(
                            async move { work.await.map(|output| Box::new(output) as ErasedOutput) },
                        ))
                    }
                };
                Ok((answer, status))
            }) as Invocation)
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

    /// Decodes the request and calls the backend.
    ///
    /// # Errors
    ///
    /// [`CodecError`] when the request could not be read. A handler failure is inside the future.
    pub(crate) fn invoke(&self, meta: &MetaView<'_>, body: Bytes) -> Result<Invocation, CodecError> {
        (self.invoke)(meta, body)
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

/// Decodes one operation's input, offering the body as a stream first.
///
/// See the module documentation for why the order is this way round and not the other.
fn decode<O: OperationCodec>(meta: &MetaView<'_>, bytes: Bytes) -> Result<O::Input, CodecError> {
    let streamed = RequestBody::Stream(ByteStream::from_bytes(bytes.clone()));
    match O::decode(meta, streamed) {
        Ok(input) => Ok(input),
        // The one documented refusal `RequestBody::into_buffered` produces. Every other failure is
        // a statement about the request and is returned untouched.
        Err(error) if error.code() == &ErrorCode::INTERNAL_ERROR => O::decode(meta, RequestBody::Buffered(bytes)),
        Err(error) => Err(error),
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
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Every registered name, sorted.
    pub(crate) fn names(&self) -> impl Iterator<Item = &'static str> {
        self.entries.keys().copied().collect::<Vec<_>>().into_iter()
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

    struct NoBackend;

    impl Handler<rustfs_gateway_types::dto::ListBuckets> for NoBackend {
        async fn call(
            &self,
            _request: Req<rustfs_gateway_types::dto::ListBuckets>,
        ) -> rustfs_gateway_core::HandlerResult<rustfs_gateway_types::dto::ListBuckets> {
            Err(HandlerError::not_implemented("this backend answers nothing"))
        }
    }
}
