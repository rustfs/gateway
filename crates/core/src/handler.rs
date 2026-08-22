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

//! What a backend implements for one operation, and the two wrappers that call carries.
//!
//! Responsible for: [`Handler`] — one obligation per operation — [`Req`] and [`Resp`],
//! [`HandlerError`] (the error an *authenticated* request may receive, so unlike
//! [`crate::PreAuthError`] it may carry text, response headers and extra document elements), and
//! the [`BoxFuture`] alias every other extension point returns by hand.
//! NOT responsible for: registering anything (`crate::registry`), erasing anything (that is
//! `crate::registry`'s closure, and the only file in this crate that awaits), routing,
//! authentication, or deciding which headers and elements a refusal may carry — that closed set is
//! [`crate::fault`]'s.
//! Upstream: `crate::op`, `crate::fault`. Downstream: `crate::registry`, and every backend that
//! implements an operation.
//!
//! # Why this trait may use RPITIT when nothing else may
//!
//! ADR-0002 fixes the spelling of async in traits: every extension point held as `Arc<dyn _>`
//! writes `-> BoxFuture<'_, T>` by hand, because RPITIT is measurably not dyn compatible
//! (`error[E0038]`). [`Handler`] and [`crate::op::Operation`] are the two exceptions, and the
//! reason is structural rather than stylistic: registration wraps a `Handler` implementation in a
//! closure and stores the closure, so `dyn Handler` never has to exist. If that ever changes, the
//! exception dies with it and ADR-0002 has to be superseded rather than quietly edited.
//!
//! # Why there is no bundle trait
//!
//! `trait ObjectApi: Handler<GetObject> + Handler<PutObject> + ...` was measured and rejected: a
//! backend missing one implementation produced 73 separate `E0277` errors, and the bundle was not
//! dyn compatible either. Completeness is asserted at run time instead, by
//! [`crate::registry::RouterBuilder::require`], whose failure is one sentence naming what is
//! missing.
//!
//! # The third thing a handler can say: "the status is settled and the outcome is not"
//!
//! `CompleteMultipartUpload` and `CopyObject` are documented by AWS as flushing a `200` before they
//! know whether they succeeded, because assembling the parts can outlast a client's timeout. A
//! `Result<Resp<O>, HandlerError>` cannot express that: choosing `Err` gives up the head, and
//! choosing `Ok` gives up the right to fail.
//!
//! [`Resp::commit`] is the third choice, and the shape of the pipeline's own `wire → targeted →
//! routed → …` type states is what it copies. `Resp<O>` is the state in which the status is still
//! being chosen — every constructor takes or reads one. [`Answer::Committed`] is the state after it
//! has been chosen, and what it holds is a [`CommitWork`] whose output is a [`CommitOutcome`]: an
//! `O::Output` or a [`HandlerError`], and **neither carries a status**. So "change the status after
//! committing" is not a rule anything checks at run time — after the transition there is no value a
//! status could be written into, and `Resp` has no setter to write one with either. The framework
//! reads the status from the `Resp` that committed it and from nowhere else.
//!
//! What a committed response *looks like* on the wire — the prologue, the keep-alive bytes that hold
//! the connection while the work runs, and the fact that the trailing document carries no XML
//! declaration of its own — is the facade's, not a backend's. A backend that could choose the
//! keep-alive cadence would be choosing an observable contract that clients time out against.
//!
//! # The fourth thing a handler can say: "the answer is a framed stream"
//!
//! [`Resp::event_stream`] carries a [`ByteStream`] whose messages are already framed. It is not a
//! committed XML answer: an error after the `200` head is an exception frame inside the same
//! stream, and the generated `O::Output` encoder must never see it. [`Answer::EventStream`] keeps
//! that distinction through registration-time erasure so the facade supplies the event-stream
//! content type and writes the body through its ordinary service exit.

use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use rustfs_gateway_stream::ByteStream;
use rustfs_gateway_types::ErrorCode;

use crate::error_resolution::{ErrorContext, HandlerErrorContext, ResponseKind, resolve};
use crate::fault::{ErrorDetail, ErrorHeader, PRECONDITION_FAILED_MESSAGE, RANGE_NOT_SATISFIABLE_MESSAGE};
use crate::op::Operation;

pub(crate) use crate::committed::deferred_sealed;
pub use crate::committed::{CommitOutcome, CommitWork, CommittedResponse, DeferredOperation, HeadPart, HeadPartError};

/// The return type every extension point in this workspace writes by hand.
///
/// Re-exported by the `rustfs-gateway` facade so that a downstream crate implementing an extension
/// point does not have to depend on `futures` for one alias. This is a public API commitment
/// (ADR-0002).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The result a handler returns.
pub type HandlerResult<O> = Result<Resp<O>, HandlerError>;

/// A decoded request on its way to the operation that will answer it.
///
/// A wrapper around the input rather than the input itself, because this is where the pipeline
/// (P4-04) adds what a handler is allowed to know about the caller — identity, region, request id.
/// Adding those to a struct is a minor change; adding them to a bare `O::Input` parameter is a
/// signature change in every handler that exists.
///
/// The input is boxed once when authorization becomes a handler request. Generated DTOs keep
/// their public fields, `Default`, and functional-update construction, while `Req<O>` stays one
/// pointer plus its authorization proofs even for large operations such as `PutObject`. Keeping
/// the DTO inline here made every async handler future carry the whole request layout across each
/// suspension point.
pub struct Req<O: Operation> {
    input: Box<O::Input>,
    resources: O::DerivedResources,
    read: crate::AuthorizedRead,
}

impl<O: Operation> Req<O> {
    /// Converts the framework's authorization proof into a handler request.
    pub(crate) fn from_authorized(authorized: crate::Authorized<O>) -> Self {
        let (input, resources, read) = authorized.into_parts();
        Self {
            input: Box::new(input),
            resources,
            read,
        }
    }

    /// The decoded input.
    pub const fn input(&self) -> &O::Input {
        &self.input
    }

    /// Resources derived from this exact input and allowed by the input authorization pass.
    pub const fn resources(&self) -> &O::DerivedResources {
        &self.resources
    }

    /// Proof that every resource in [`Self::resources`] was allowed.
    pub const fn read_proof(&self) -> &crate::AuthorizedRead {
        &self.read
    }

    /// The decoded input, mutably.
    pub const fn input_mut(&mut self) -> &mut O::Input {
        &mut self.input
    }

    /// Takes the input out.
    pub fn into_input(self) -> O::Input {
        *self.input
    }

    /// The operation this request names.
    #[must_use]
    pub const fn operation_name(&self) -> &'static str {
        O::NAME
    }
}

impl<O> Req<O>
where
    O: Operation<DerivedResources = crate::NoDerived>,
{
    /// Builds a request for direct handler and middleware tests of an operation that explicitly
    /// derives no second-stage resources.
    ///
    /// Registry and wire dispatch still require [`crate::Authorized<O>`]; this constructor cannot
    /// be used for copy, batch-delete, or any future operation with derived resources.
    #[must_use]
    pub fn new(input: O::Input) -> Self {
        Self {
            input: Box::new(input),
            resources: crate::NoDerived,
            read: crate::AuthorizedRead::empty(),
        }
    }
}

impl<O: Operation> fmt::Debug for Req<O>
where
    O::Input: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Req")
            .field("operation", &O::NAME)
            .field("input", &self.input)
            .finish()
    }
}

/// The content half of a [`Resp`]: known now, or committed and still running.
///
/// Not `#[non_exhaustive]`: the facade matches on it exhaustively and a third arm is a change to how
/// every response is written, which is precisely the review a compile error should force.
pub enum Answer<O: Operation> {
    /// The status and the content were decided together.
    Settled(O::Output),
    /// The status is decided; the content is not, and the head has gone out on the strength of it.
    Committed(CommittedResponse<O>),
    /// A sequence of already framed event-stream messages.
    ///
    /// Unlike [`Self::Committed`], errors after the head are frames inside this stream rather than
    /// a trailing XML document. The facade therefore sends this body without invoking the
    /// operation's generated output encoder.
    EventStream(ByteStream),
}

impl<O: Operation> fmt::Debug for Answer<O>
where
    O::Output: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Settled(output) => f.debug_tuple("Settled").field(output).finish(),
            Self::Committed(_) => f.write_str("Committed(..)"),
            Self::EventStream(stream) => f.debug_tuple("EventStream").field(stream).finish(),
        }
    }
}

/// An answer on its way back to the wire.
pub struct Resp<O: Operation> {
    answer: Answer<O>,
    status: u16,
}

impl<O: Operation> Resp<O> {
    /// The answer, with the operation's declared success status.
    ///
    /// The status comes from the spec rather than from a constant here, because `204` for the
    /// delete family and `303` for a POST Object redirect are per-operation facts the IR already
    /// carries.
    pub fn new(output: O::Output) -> Self {
        Self {
            answer: Answer::Settled(output),
            status: O::spec().success_status,
        }
    }

    /// The answer with a status other than the declared one — `206` for a ranged read, `200` for a
    /// delete that reports per-key results.
    pub const fn with_status(output: O::Output, status: u16) -> Self {
        Self {
            answer: Answer::Settled(output),
            status,
        }
    }

    /// Answers with an `application/vnd.amazon.event-stream` frame sequence.
    ///
    /// The stream is already framed: a backend uses the exported event-stream encoder to produce
    /// `Records`, `Stats`, `Progress`, `Cont`, `End`, or an in-band exception. The facade supplies
    /// the response content type and sends the operation's declared success status; no generated
    /// document encoder is involved.
    #[must_use]
    pub fn event_stream(stream: ByteStream) -> Self {
        Self {
            answer: Answer::EventStream(stream),
            status: O::spec().success_status,
        }
    }

    /// The output, when there already is one.
    ///
    /// `None` for a committed answer, whose output does not exist yet. An accessor that could not
    /// say so would have to invent one.
    pub const fn output(&self) -> Option<&O::Output> {
        match &self.answer {
            Answer::Settled(output) => Some(output),
            Answer::Committed(_) | Answer::EventStream(_) => None,
        }
    }

    /// The output, mutably, when there already is one.
    ///
    /// This is what makes a per-operation middleware (`rustfs_gateway::OpLayer`) three statements
    /// instead of a tower layer that parses the response XML, edits an element and serialises it
    /// back. `None` for a committed answer, whose output does not exist yet — and a caller that
    /// treats the `None` as "nothing to change" is correct: a committed response's content is
    /// decided inside its own continuation, where no layer of this kind can reach it.
    ///
    /// The status is deliberately not settable through this: it belongs to the constructor that
    /// chose it, and a middleware that could change it after the fact would be able to contradict a
    /// head that has already gone out.
    pub const fn output_mut(&mut self) -> Option<&mut O::Output> {
        match &mut self.answer {
            Answer::Settled(output) => Some(output),
            Answer::Committed(_) | Answer::EventStream(_) => None,
        }
    }

    /// Whether the head is committed and the outcome still pending.
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        matches!(self.answer, Answer::Committed(_))
    }

    /// Whether the answer is an event-stream frame sequence.
    #[must_use]
    pub const fn is_event_stream(&self) -> bool {
        matches!(self.answer, Answer::EventStream(_))
    }

    /// The status this answer goes out with.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Takes the output out, when there already is one.
    pub fn into_output(self) -> Option<O::Output> {
        match self.answer {
            Answer::Settled(output) => Some(output),
            Answer::Committed(_) | Answer::EventStream(_) => None,
        }
    }

    /// Takes the content and the status.
    pub fn into_parts(self) -> (Answer<O>, u16) {
        (self.answer, self.status)
    }

    /// Wraps a committed continuation, leaving every other answer and the status untouched.
    ///
    /// The framework's one way to put something around the work a backend committed to — a
    /// progress bound, an observer — without taking the answer apart and putting it back together.
    /// Rebuilding it at the call site is what this exists to prevent: `Answer` has three variants
    /// and only one of the three has a constructor that can carry an arbitrary status, so a call
    /// site that destructured and reassembled would silently move an event stream's status back to
    /// the operation's declared one.
    ///
    /// `f` is not called for a settled or event-stream answer, which is the other half of the
    /// contract: a wrapper meant for a continuation must not become a wrapper on everything.
    #[must_use]
    pub fn map_commit_work(self, f: impl FnOnce(CommitWork<O>) -> CommitWork<O>) -> Self {
        let Self { answer, status } = self;
        let answer = match answer {
            Answer::Committed(committed) => Answer::Committed(committed.map_work(f)),
            settled_or_stream => settled_or_stream,
        };
        Self { answer, status }
    }
}

impl<O: DeferredOperation> Resp<O> {
    /// Commits the operation's declared success status before the outcome is known.
    ///
    /// The generated deferred-operation marker limits this constructor to operations whose IR
    /// permits an error document after `200`. `head` contains every operation header known before
    /// the detached work starts; `work` can produce only an output or a [`HandlerError`], never a
    /// second status.
    #[must_use]
    pub fn commit(head: HeadPart<O>, work: CommitWork<O>) -> Self {
        Self {
            answer: Answer::Committed(CommittedResponse::new(head, work, O::RESPONSE_HEADERS, O::RESPONSE_HEADER_PREFIXES)),
            status: O::spec().success_status,
        }
    }

    /// [`Self::commit`] with a status other than the operation's declared success status.
    #[must_use]
    pub fn commit_with_status(head: HeadPart<O>, work: CommitWork<O>, status: u16) -> Self {
        Self {
            answer: Answer::Committed(CommittedResponse::new(head, work, O::RESPONSE_HEADERS, O::RESPONSE_HEADER_PREFIXES)),
            status,
        }
    }
}

impl<O: Operation> fmt::Debug for Resp<O>
where
    O::Output: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resp")
            .field("operation", &O::NAME)
            .field("status", &self.status)
            .field("answer", &self.answer)
            .finish()
    }
}

/// What a handler failed with.
///
/// Deliberately unlike [`crate::PreAuthError`], which holds a `&'static str` so that an
/// unidentified caller cannot make the service echo its own bytes back. By the time a handler
/// runs, the caller has been authenticated and authorised, so a message may name what went wrong.
/// The two types exist separately so that this distinction is visible in the signature rather than
/// remembered.
///
/// A code and a message alone cannot express several refusals the protocol defines: a `416` is
/// required to carry `Content-Range`, and the `416` and `412` documents carry elements no other
/// document has. So this also holds two lists — [`ErrorHeader`] and [`ErrorDetail`], both closed
/// sets, for the reasons in [`crate::fault`] — and each list holds at most one entry per header and
/// per element name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlerError {
    code: ErrorCode,
    message: Cow<'static, str>,
    headers: Vec<ErrorHeader>,
    details: Vec<ErrorDetail>,
    context: Option<Box<HandlerErrorContext>>,
}

impl HandlerError {
    /// An error with a code and a message.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            message: message.into(),
            headers: Vec::new(),
            details: Vec::new(),
            context: None,
        }
    }

    /// `500 InternalError`: the gateway itself is at fault, not the caller.
    #[must_use]
    pub fn internal_error(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::INTERNAL_ERROR, message)
    }

    /// `501 NotImplemented`: this backend does not answer this operation.
    #[must_use]
    pub fn not_implemented(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::NOT_IMPLEMENTED, message)
    }

    /// `416 InvalidRange`, whole: the code, the message AWS pins, the `Content-Range` RFC 9110
    /// §14.4 requires on one, and the two elements the document carries.
    ///
    /// One call rather than four because the length appears three times on the wire — in the
    /// header, in `<ActualObjectSize>`, and by implication in the client's next request — and three
    /// call sites for one number is three chances for the header and the document to disagree about
    /// how long the object is. Here they cannot: they are the same argument.
    #[must_use]
    pub fn unsatisfiable_range(requested: impl Into<Cow<'static, str>>, complete_length: u64) -> Self {
        let requested = requested.into();
        let error = Self::new(ErrorCode::INVALID_RANGE, RANGE_NOT_SATISFIABLE_MESSAGE)
            .with_header(ErrorHeader::UnsatisfiedRange { complete_length })
            .with_detail(ErrorDetail::RangeRequested(requested));
        if matches!(
            crate::contracts::UNSATISFIABLE_ACTUAL_SIZE_DETAIL_POLICY,
            crate::contracts::UnsatisfiableActualSizeDetailPolicy::Include
        ) {
            error.with_detail(ErrorDetail::ActualObjectSize(complete_length))
        } else {
            error
        }
    }

    /// `412 PreconditionFailed`, naming the request header whose condition did not hold.
    ///
    /// The name is the header's — `If-Match`, `If-None-Match`, `If-Modified-Since`,
    /// `If-Unmodified-Since` — because that is what the client can act on, and it is the only part
    /// of the document that says which of four conditions failed.
    #[must_use]
    pub fn precondition_failed(condition: impl Into<Cow<'static, str>>) -> Self {
        let error = Self::new(ErrorCode::PRECONDITION_FAILED, PRECONDITION_FAILED_MESSAGE);
        if crate::contracts::include_condition_failure_detail() {
            error.with_detail(ErrorDetail::Condition(condition.into()))
        } else {
            error
        }
    }

    /// Adds a header to the refusal's head, replacing any earlier one of the same name.
    ///
    /// Replacing rather than appending: a response carrying two `Content-Range` headers is one an
    /// intermediary may pick either half of, and "the last writer wins" is the rule the rest of the
    /// response head already follows.
    #[must_use]
    pub fn with_header(mut self, header: ErrorHeader) -> Self {
        if self.context.is_some() {
            return self;
        }
        let name = header.name();
        self.headers.retain(|existing| existing.name() != name);
        self.headers.push(header);
        self
    }

    /// Adds an element to the error document, replacing any earlier one of the same name.
    ///
    /// The list is kept in [`crate::fault::ELEMENT_ORDER`], so the document's element order is a
    /// function of which elements it carries and never of the order they were added in. A handler
    /// cannot produce a document whose elements are in an order no case asserted.
    #[must_use]
    pub fn with_detail(mut self, detail: ErrorDetail) -> Self {
        if self.context.is_some() {
            return self;
        }
        let element = detail.element();
        self.details.retain(|existing| existing.element() != element);
        self.details.push(detail);
        self.details.sort_by_key(ErrorDetail::position);
        self
    }

    /// The headers this refusal adds to its own head, in no particular order.
    #[must_use]
    pub fn headers(&self) -> &[ErrorHeader] {
        &self.headers
    }

    /// The extra elements of the error document, in the order they will be written.
    #[must_use]
    pub fn details(&self) -> &[ErrorDetail] {
        &self.details
    }

    /// The error code.
    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// The message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn into_context(mut self) -> Result<ErrorContext, Self> {
        match self.context.take() {
            Some(context) => Ok(context.into_error_context()),
            None => Err(self),
        }
    }
}

impl From<HandlerErrorContext> for HandlerError {
    fn from(context: HandlerErrorContext) -> Self {
        let resolution = resolve(context.clone().into_error_context(), ResponseKind::Other);
        Self {
            code: resolution.code().cloned().unwrap_or(ErrorCode::INTERNAL_ERROR),
            message: resolution
                .message()
                .map_or(Cow::Borrowed("the operation completed without an error document"), |message| {
                    Cow::Owned(message.to_owned())
                }),
            headers: resolution.headers().to_vec(),
            details: resolution.details().to_vec(),
            context: Some(Box::new(context)),
        }
    }
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for HandlerError {}

/// A backend's answer to one operation.
///
/// Implement it once per operation, in `ops/<snake_name>.rs`, or generate the implementations from
/// an inherent `impl` block with `#[rustfs_gateway_macros::handlers]`. The macro is optional sugar
/// and produces exactly this trait implementation; the hand-written form is always available and
/// is documented beside it.
#[diagnostic::on_unimplemented(
    message = "backend `{Self}` does not handle the S3 operation `{O}`",
    label = "no `impl Handler<{O}>` for `{Self}`",
    note = "write `impl Handler<{O}> for {Self}` in its own `ops/<snake_name>.rs`, or put \
            `#[rustfs_gateway_macros::handlers]` on an inherent impl block whose method name is \
            the snake_case spelling of `{O}`",
    note = "an operation with no handler is answered with 501; a backend that must be complete \
            should assert it with `RouterBuilder::require(OperationSet::aws_full())`"
)]
pub trait Handler<O: Operation>: Send + Sync + 'static {
    /// Answers one request.
    ///
    /// RPITIT is permitted here and in [`Operation`] alone (ADR-0002): registration erases the
    /// implementation behind a closure, so this trait is never used as a trait object.
    fn call(&self, request: Req<O>) -> impl Future<Output = HandlerResult<O>> + Send;

    /// Answers one request with request-scoped execution signals.
    ///
    /// This temporary migration entry keeps existing backends source-compatible while handler
    /// implementations move to the ADR-0011 signature in bounded batches. The default deliberately
    /// ignores the context and must be removed when backlog#1861 completes. Dynamic framework
    /// dispatch already calls this entry; the monomorphic path is the next bounded migration slice.
    fn call_with_context(
        &self,
        request: Req<O>,
        _context: crate::HandlerContext,
    ) -> impl Future<Output = HandlerResult<O>> + Send {
        self.call(request)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::StatusCode;
    use rustfs_gateway_stream::ByteStream;
    use rustfs_gateway_types::dto::SelectObjectContent;

    /// Positive — an event stream carries the operation's declared success status and no typed
    /// output. Treating the stream as a settled empty output is the defect this response shape
    /// exists to make impossible.
    #[test]
    fn an_event_stream_is_a_third_answer_shape() {
        let response = Resp::<SelectObjectContent>::event_stream(ByteStream::from_bytes(Bytes::from_static(b"frame")));
        assert_eq!(response.status(), 200);
        assert!(response.is_event_stream());
        assert!(!response.is_committed());
        assert!(response.output().is_none());
        assert!(response.into_output().is_none());
    }

    /// Negative — erasing an event stream must not turn it into a settled output. The facade's
    /// dispatch matches this exact variant to bypass the generated document encoder.
    #[test]
    fn an_event_stream_survives_into_parts() {
        let response = Resp::<SelectObjectContent>::event_stream(ByteStream::from_bytes(Bytes::from_static(b"frame")));
        let (answer, status) = response.into_parts();
        assert_eq!(status, 200);
        assert!(matches!(answer, Answer::EventStream(_)));
    }

    /// Negative — a plain error carries no headers and no elements, so nothing this file added can
    /// change the shape of a document that did not ask for it.
    #[test]
    fn a_plain_error_adds_nothing_to_the_document_or_the_head() {
        let error = HandlerError::internal_error("no");
        assert!(error.headers().is_empty());
        assert!(error.details().is_empty());
    }

    /// Negative — adding the same header twice leaves one, so a response cannot carry two
    /// `Content-Range` values for an intermediary to choose between.
    #[test]
    fn a_repeated_header_replaces_rather_than_appends() {
        let error = HandlerError::internal_error("no")
            .with_header(ErrorHeader::UnsatisfiedRange { complete_length: 1 })
            .with_header(ErrorHeader::UnsatisfiedRange { complete_length: 2 });
        assert_eq!(error.headers(), [ErrorHeader::UnsatisfiedRange { complete_length: 2 }]);
    }

    /// Negative — the same for elements: a document with two `<Condition>` elements names two
    /// conditions, and only one of them failed.
    #[test]
    fn a_repeated_element_replaces_rather_than_appends() {
        let error = HandlerError::internal_error("no")
            .with_detail(ErrorDetail::Condition(Cow::Borrowed("If-Match")))
            .with_detail(ErrorDetail::Condition(Cow::Borrowed("If-None-Match")));
        assert_eq!(error.details().len(), 1);
        assert_eq!(error.details()[0].text(), "If-None-Match");
    }

    /// Negative — the elements come out in the declared order whatever order they went in. This is
    /// the assertion behind "a handler cannot get the document order wrong".
    #[test]
    fn elements_are_written_in_the_declared_order_not_the_order_they_were_added() {
        let error = HandlerError::internal_error("no")
            .with_detail(ErrorDetail::ActualObjectSize(10))
            .with_detail(ErrorDetail::Condition(Cow::Borrowed("If-Match")))
            .with_detail(ErrorDetail::RangeRequested(Cow::Borrowed("bytes=20-30")))
            .with_detail(ErrorDetail::Key(Cow::Borrowed("k")));
        let names: Vec<&str> = error.details().iter().map(ErrorDetail::element).collect();
        assert_eq!(names, ["Key", "Condition", "RangeRequested", "ActualObjectSize"]);
    }

    /// Negative — the two facts a `416` states about the object's length come from one argument, so
    /// the header and the document cannot disagree. A client that trusted one and retried against
    /// the other would loop.
    #[test]
    fn the_range_refusal_states_one_length_in_both_places() {
        let error = HandlerError::unsatisfiable_range("bytes=20-30", 10);
        assert_eq!(error.code().default_status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(error.headers(), [ErrorHeader::UnsatisfiedRange { complete_length: 10 }]);
        assert_eq!(error.headers()[0].value(), "bytes */10");
        let sizes: Vec<String> = error
            .details()
            .iter()
            .filter(|detail| detail.element() == "ActualObjectSize")
            .map(|detail| detail.text().into_owned())
            .collect();
        assert_eq!(sizes, ["10"]);
    }

    /// Negative — a zero-length object is still a length, not an absent one: `bytes */0` is what
    /// tells a client that no range of it is satisfiable.
    #[test]
    fn a_zero_length_object_still_states_its_length() {
        let error = HandlerError::unsatisfiable_range("bytes=0-0", 0);
        assert_eq!(error.headers()[0].value(), "bytes */0");
        assert_eq!(error.details().last().expect("a size").text(), "0");
    }

    /// Positive — the range refusal's message and element order are the ones the wire pins.
    #[test]
    fn the_range_refusal_carries_the_pinned_message_and_order() {
        let error = HandlerError::unsatisfiable_range("bytes=20-30", 10);
        assert_eq!(error.message(), RANGE_NOT_SATISFIABLE_MESSAGE);
        let names: Vec<&str> = error.details().iter().map(ErrorDetail::element).collect();
        assert_eq!(names, ["RangeRequested", "ActualObjectSize"]);
    }

    /// Positive — the precondition refusal names the header that failed and adds no header of its
    /// own; a `412` has nothing to put in its head.
    #[test]
    fn the_precondition_refusal_names_the_header_that_failed() {
        let error = HandlerError::precondition_failed("If-None-Match");
        assert_eq!(error.code().default_status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(error.message(), PRECONDITION_FAILED_MESSAGE);
        assert!(error.headers().is_empty());
        assert_eq!(error.details()[0].element(), "Condition");
        assert_eq!(error.details()[0].text(), "If-None-Match");
    }
}
