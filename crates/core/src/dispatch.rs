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

//! The three questions asked in order, and the different answer each one has when it fails.
//!
//! Responsible for: [`Router`] — routing, then registration, then parameter validation — and the
//! two textually different `501`s.
//! NOT responsible for: authentication, decoding, or anything after `Ok`.
//! Upstream: `crate::route`, `crate::registry`, `crate::error`. Downstream: the pipeline (P4-04).
//!
//! ```text
//! route table
//!   ├─ no entry                    -> 501, "this request shape names no operation"
//!   └─ entry
//!        ├─ not registered         -> 501, "this backend does not handle that operation"
//!        ├─ required param missing -> the operation's own code, normally 400 InvalidArgument
//!        └─ ok                     -> the pipeline's routed stage
//! ```
//!
//! # Why the two `501`s must read differently
//!
//! They call for opposite actions. The first means the request did not look like any S3 operation
//! — overwhelmingly because the gateway was never told which domain it serves, so a
//! virtual-hosted request arrived as a path-style one addressing a bucket that is really a host.
//! The operator's fix is configuration, and a bare "not implemented" sends them looking for a
//! missing feature instead. The second means routing worked and no handler is installed: the fix
//! is code. One string for both hides which of the two happened.
//!
//! # Why both routers are kept
//!
//! [`Router::resolve`] answers from the compiled table; [`Router::resolve_readable`] answers from
//! the readable one. Both are public and both are exercised by the same cases, because a fast
//! implementation of a pre-authentication security decision is only allowed to exist while
//! something is continuously proving it agrees with the implementation a person can read.

use crate::error::PreAuthError;
use crate::registry::{OperationSpec, Registry, check_required};
use crate::route::{
    CompileError, CompiledRouter, PROVISIONAL_SHADOWING, RouteBuildError, RouteEntry, RouteRequestParts, RouteTable, RowError,
    generated_entries,
};

/// The message a request that names no operation receives.
///
/// Actionable on purpose: the overwhelmingly common cause is an unconfigured virtual-host domain,
/// and it contains nothing derived from the request.
pub const NO_ROUTE_MESSAGE: &str = "This request does not name any S3 operation. If clients address buckets as virtual hosts, \
     check that the gateway has been configured with the domain it serves; otherwise the method, \
     path or query is not one this service defines.";

/// The message a routed but unhandled operation receives.
pub const NOT_REGISTERED_MESSAGE: &str = "This operation is defined by S3 but is not handled by this backend.";

/// A request that has been routed, registered and validated.
#[derive(Clone, Copy, Debug)]
pub struct Dispatch<'a> {
    /// The route entry that won.
    pub entry: &'a RouteEntry,
    /// The registered operation.
    pub spec: &'a OperationSpec,
}

/// Why a router could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouterBuildError {
    /// A generated row could not be read.
    Row(RowError),
    /// The table refused to be built.
    Route(RouteBuildError),
    /// The table could not be compiled.
    Compile(CompileError),
}

impl std::fmt::Display for RouterBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Row(error) => write!(f, "{error}"),
            Self::Route(error) => write!(f, "{error}"),
            Self::Compile(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for RouterBuildError {}

impl From<RowError> for RouterBuildError {
    fn from(error: RowError) -> Self {
        Self::Row(error)
    }
}

impl From<RouteBuildError> for RouterBuildError {
    fn from(error: RouteBuildError) -> Self {
        Self::Route(error)
    }
}

impl From<CompileError> for RouterBuildError {
    fn from(error: CompileError) -> Self {
        Self::Compile(error)
    }
}

/// The route table, its compiled form, and the operations this backend handles.
#[derive(Clone, Debug)]
pub struct Router {
    table: RouteTable,
    compiled: CompiledRouter,
    registry: Registry,
}

impl Router {
    /// Builds a router over an already-built table.
    ///
    /// Not `async`, and it takes no store, connection or repository — see the invariant in
    /// [`crate::route`].
    ///
    /// # Errors
    ///
    /// [`RouterBuildError::Compile`] when the table cannot be compiled.
    pub fn new(table: RouteTable, registry: Registry) -> Result<Self, RouterBuildError> {
        let compiled = CompiledRouter::compile(&table)?;
        Ok(Self {
            table,
            compiled,
            registry,
        })
    }

    /// Builds a router over the generated route table and its shadowing declarations.
    ///
    /// # Errors
    ///
    /// [`RouterBuildError`] — an unreadable generated row, a table the build-time checks refuse,
    /// or a table that will not compile.
    pub fn from_generated(registry: Registry) -> Result<Self, RouterBuildError> {
        let entries = generated_entries()?;
        let table = RouteTable::build(entries, &PROVISIONAL_SHADOWING)?;
        Self::new(table, registry)
    }

    /// The route table.
    #[must_use]
    pub fn table(&self) -> &RouteTable {
        &self.table
    }

    /// The compiled table.
    #[must_use]
    pub fn compiled(&self) -> &CompiledRouter {
        &self.compiled
    }

    /// The registry.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Which operation this request names, answered from the compiled table.
    ///
    /// Not `async`, holds nothing, allocates nothing.
    #[must_use]
    pub fn resolve(&self, request: &RouteRequestParts<'_>) -> Option<&RouteEntry> {
        let op = self.compiled.resolve(request)?;
        self.table.entries().get(usize::from(op))
    }

    /// The same answer from the readable table. Kept as the reference implementation.
    #[must_use]
    pub fn resolve_readable(&self, request: &RouteRequestParts<'_>) -> Option<&RouteEntry> {
        self.table.resolve(request)
    }

    /// Routes, checks registration, then checks required parameters.
    ///
    /// # Errors
    ///
    /// [`PreAuthError`]: `501` with [`NO_ROUTE_MESSAGE`] when nothing matched, `501` with
    /// [`NOT_REGISTERED_MESSAGE`] when the operation is not handled here, and otherwise the
    /// operation's own code for the first missing required parameter.
    pub fn dispatch(&self, request: &RouteRequestParts<'_>) -> Result<Dispatch<'_>, PreAuthError> {
        let Some(entry) = self.resolve(request) else {
            return Err(PreAuthError::not_implemented(NO_ROUTE_MESSAGE));
        };
        let Some(spec) = self.registry.get(entry.op_name) else {
            return Err(PreAuthError::not_implemented(NOT_REGISTERED_MESSAGE).about(entry.op_name));
        };
        check_required(spec, request)?;
        Ok(Dispatch { entry, spec })
    }
}
