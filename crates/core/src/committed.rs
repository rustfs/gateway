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

//! The typed response head and detached work for operations that may fail after `200`.
//!
//! Responsible for: sealing the codegen-owned deferred-operation capability, validating the
//! operation-owned headers frozen before work begins, and carrying that head with statusless work.
//! NOT responsible for: selecting a response status, encoding the terminal document, starting a
//! task, or writing keep-alive bytes.
//! Upstream: generated codec modules and `crate::handler`. Downstream: static and dynamic dispatch.

use std::fmt;
use std::marker::PhantomData;

use http::HeaderMap;

use crate::handler::{BoxFuture, HandlerError};
use crate::op::Operation;

/// What a committed operation eventually produced: the answer, or the refusal.
///
/// Deliberately statusless. The status went out with the head, so a value that could carry a second
/// one would be a value that can contradict the wire — and the contradiction would be discovered by
/// the client, not by a test.
pub type CommitOutcome<O> = Result<<O as Operation>::Output, HandlerError>;

/// The work that decides a committed response, handed to the framework to drive.
///
/// Boxed rather than generic because the registry erases the operation and the backend, and a
/// continuation that stayed generic would have to be named by every layer it passes through.
pub type CommitWork<O> = BoxFuture<'static, CommitOutcome<O>>;

/// The codegen-owned capability to commit an operation response before its work completes.
///
/// This trait is sealed and implemented only by generated codec modules whose IR carries
/// `allows_error_after_200 = true`. A backend can use the capability but cannot add it to another
/// operation by hand.
pub trait DeferredOperation: Operation + deferred_sealed::Sealed {
    /// Exact response-header bindings this operation may freeze before starting its work.
    const RESPONSE_HEADERS: &'static [&'static str];

    /// Prefix response-header bindings this operation may freeze before starting its work.
    const RESPONSE_HEADER_PREFIXES: &'static [&'static str];
}

pub(crate) mod deferred_sealed {
    /// The private half of [`super::DeferredOperation`].
    pub trait Sealed {}
}

/// Why a backend-provided committed response head was not safe to freeze.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadPartError {
    /// The header is owned by HTTP framing or by the gateway framework.
    FrameworkOwned,
    /// The operation's generated response bindings do not name the header.
    Unbound,
    /// One header name carries more than one value.
    Duplicate,
}

impl fmt::Display for HeadPartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FrameworkOwned => "a committed response head contains a framework-owned header",
            Self::Unbound => "a committed response head contains an unbound operation header",
            Self::Duplicate => "a committed response head contains a duplicate operation header",
        })
    }
}

impl std::error::Error for HeadPartError {}

/// The operation-owned headers known before committed work starts.
///
/// Names and values are already parsed HTTP types. Construction also checks the generated
/// response binding set, so a backend cannot smuggle framing headers or invent a late header.
pub struct HeadPart<O: Operation> {
    headers: HeaderMap,
    operation: PhantomData<fn() -> O>,
}

impl<O: DeferredOperation> HeadPart<O> {
    /// Validates and freezes one operation's response headers.
    ///
    /// # Errors
    ///
    /// [`HeadPartError`] when a header is framework-owned, is not a generated response binding,
    /// or has more than one value.
    pub fn new(headers: HeaderMap) -> Result<Self, HeadPartError> {
        for name in headers.keys() {
            if framework_owns_committed_header(name.as_str()) {
                return Err(HeadPartError::FrameworkOwned);
            }
            if headers.get_all(name).iter().count() != 1 {
                return Err(HeadPartError::Duplicate);
            }
            let bound = O::RESPONSE_HEADERS.contains(&name.as_str())
                || O::RESPONSE_HEADER_PREFIXES
                    .iter()
                    .any(|prefix| name.as_str().starts_with(prefix));
            if !bound {
                return Err(HeadPartError::Unbound);
            }
        }
        Ok(Self {
            headers,
            operation: PhantomData,
        })
    }
}

impl<O: Operation> HeadPart<O> {
    /// The validated operation headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Takes the validated operation headers.
    #[must_use]
    pub fn into_headers(self) -> HeaderMap {
        self.headers
    }
}

impl<O: Operation> fmt::Debug for HeadPart<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeadPart")
            .field("operation", &O::NAME)
            .field("headers", &self.headers)
            .finish()
    }
}

fn framework_owns_committed_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "content-length"
            | "content-type"
            | "date"
            | "server"
            | "trailer"
            | "transfer-encoding"
            | "x-amz-id-2"
            | "x-amz-request-id"
    )
}

/// A frozen committed head and the detached work that will finish its document.
pub struct CommittedResponse<O: Operation> {
    head: HeadPart<O>,
    work: CommitWork<O>,
    response_headers: &'static [&'static str],
    response_header_prefixes: &'static [&'static str],
}

impl<O: Operation> CommittedResponse<O> {
    pub(crate) fn new(
        head: HeadPart<O>,
        work: CommitWork<O>,
        response_headers: &'static [&'static str],
        response_header_prefixes: &'static [&'static str],
    ) -> Self {
        Self {
            head,
            work,
            response_headers,
            response_header_prefixes,
        }
    }

    /// The operation headers that must leave before the work starts.
    #[must_use]
    pub const fn head(&self) -> &HeadPart<O> {
        &self.head
    }

    /// Takes the frozen head and the work for framework dispatch.
    #[must_use]
    pub fn into_parts(self) -> (HeadPart<O>, CommitWork<O>) {
        (self.head, self.work)
    }

    pub(crate) fn map_work(self, f: impl FnOnce(CommitWork<O>) -> CommitWork<O>) -> Self {
        Self {
            head: self.head,
            work: f(self.work),
            response_headers: self.response_headers,
            response_header_prefixes: self.response_header_prefixes,
        }
    }

    pub(crate) fn into_dispatch_parts(self) -> (HeadPart<O>, CommitWork<O>, &'static [&'static str], &'static [&'static str]) {
        (self.head, self.work, self.response_headers, self.response_header_prefixes)
    }
}
