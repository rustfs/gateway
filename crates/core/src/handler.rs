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
//! [`crate::PreAuthError`] it may carry text), and the [`BoxFuture`] alias every other extension
//! point returns by hand.
//! NOT responsible for: registering anything (`crate::registry`), erasing anything (that is
//! `crate::registry`'s closure, and the only file in this crate that awaits), routing, or
//! authentication.
//! Upstream: `crate::op`. Downstream: `crate::registry`, and every backend that implements an
//! operation.
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

use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use http::StatusCode;
use rustfs_gateway_types::{ErrorCode, ErrorContext, status_of};

use crate::op::Operation;

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
pub struct Req<O: Operation> {
    input: O::Input,
}

impl<O: Operation> Req<O> {
    /// Wraps a decoded input.
    pub const fn new(input: O::Input) -> Self {
        Self { input }
    }

    /// The decoded input.
    pub const fn input(&self) -> &O::Input {
        &self.input
    }

    /// The decoded input, mutably.
    pub const fn input_mut(&mut self) -> &mut O::Input {
        &mut self.input
    }

    /// Takes the input out.
    pub fn into_input(self) -> O::Input {
        self.input
    }

    /// The operation this request names.
    #[must_use]
    pub const fn operation_name(&self) -> &'static str {
        O::NAME
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

/// An answer on its way back to the wire.
pub struct Resp<O: Operation> {
    output: O::Output,
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
            output,
            status: O::spec().success_status,
        }
    }

    /// The answer with a status other than the declared one — `206` for a ranged read, `200` for a
    /// delete that reports per-key results.
    pub const fn with_status(output: O::Output, status: u16) -> Self {
        Self { output, status }
    }

    /// The output.
    pub const fn output(&self) -> &O::Output {
        &self.output
    }

    /// The status this answer goes out with.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Takes the output out.
    pub fn into_output(self) -> O::Output {
        self.output
    }

    /// Takes the output and the status.
    pub fn into_parts(self) -> (O::Output, u16) {
        (self.output, self.status)
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
            .field("output", &self.output)
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlerError {
    code: ErrorCode,
    message: Cow<'static, str>,
}

impl HandlerError {
    /// An error with a code and a message.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            message: message.into(),
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

    /// The status this error goes out with, in the default context.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        status_of(&self.code, &ErrorContext::default())
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
}
