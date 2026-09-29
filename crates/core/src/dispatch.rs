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
    ClaimLookup, ClaimedEntry, ClaimedTable, CompileError, CompiledRouter, LegacySelection, RouteBuildError, RouteEntry,
    RouteRequestParts, RouteTable, RowError, SHADOWING, Selection, generated_entries, legacy_rustfs_selection,
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

/// The message a request inside a dialect's path-prefix claim receives when no claimed row accepts
/// it (ADR-0024).
///
/// Separate from [`NO_ROUTE_MESSAGE`] because the cause and the fix differ: the request is not a
/// misaddressed S3 request, it is inside a namespace S3 routing never considers.
pub const NO_CLAIMED_ROUTE_MESSAGE: &str = "This request is inside a path prefix an installed dialect claims, and names none of the \
     operations that dialect serves there.";

/// The message a request whose `x-id` is repeated, or names no operation of its method and target,
/// receives under [`Selection::RustfsLegacy`] (rustfs/gateway#1127).
pub const UNDECLARED_OPERATION_MESSAGE: &str =
    "The operation named by x-id is unknown, named more than once, or does not match this request.";

/// A request that has been routed, registered and validated.
#[derive(Clone, Copy, Debug)]
pub struct Dispatch<'a> {
    /// The route entry that won.
    pub entry: &'a RouteEntry,
    /// The registered operation.
    pub spec: &'a OperationSpec,
    /// The claimed row that accepted the request, when a dialect's path-prefix claim covered it;
    /// `None` for an S3-table row. Its template is what path parameters are extracted with.
    pub claimed: Option<&'a ClaimedEntry>,
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

/// The route table, its compiled form, the claimed rows, and the operations this backend handles.
#[derive(Clone, Debug)]
pub struct Router {
    table: RouteTable,
    compiled: CompiledRouter,
    claims: ClaimedTable,
    registry: Registry,
    selection: Selection,
}

impl Router {
    /// Builds a router over an already-built table, with no path-prefix claim.
    ///
    /// Not `async`, and it takes no store, connection or repository — see the invariant in
    /// [`crate::route`].
    ///
    /// # Errors
    ///
    /// [`RouterBuildError::Compile`] when the table cannot be compiled.
    pub fn new(table: RouteTable, registry: Registry) -> Result<Self, RouterBuildError> {
        Self::with_claims(table, ClaimedTable::default(), registry)
    }

    /// Builds a router over an already-built S3 table and an already-built claimed table.
    ///
    /// # Errors
    ///
    /// [`RouterBuildError::Compile`] when the S3 table cannot be compiled.
    pub fn with_claims(table: RouteTable, claims: ClaimedTable, registry: Registry) -> Result<Self, RouterBuildError> {
        let compiled = CompiledRouter::compile(&table)?;
        Ok(Self {
            table,
            compiled,
            claims,
            registry,
            selection: Selection::Table,
        })
    }

    /// The same router, choosing among the operations a request outside every claim names by
    /// `selection` — [`Selection::RustfsLegacy`] for a deployment fronting RustFS
    /// (rustfs/gateway#1127).
    #[must_use]
    pub const fn selecting(mut self, selection: Selection) -> Self {
        self.selection = selection;
        self
    }

    /// How this router chooses among the operations a request names.
    #[must_use]
    pub const fn selection(&self) -> Selection {
        self.selection
    }

    /// The path-prefix claims and the rows inside them.
    #[must_use]
    pub fn claims(&self) -> &ClaimedTable {
        &self.claims
    }

    /// Builds a router over the generated route table and its shadowing declarations.
    ///
    /// # Errors
    ///
    /// [`RouterBuildError`] — an unreadable generated row, a table the build-time checks refuse,
    /// or a table that will not compile.
    pub fn from_generated(registry: Registry) -> Result<Self, RouterBuildError> {
        let entries = generated_entries()?;
        let table = RouteTable::build(entries, &SHADOWING)?;
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

    /// Which operation this request names: the claimed row when a path-prefix claim covers the
    /// request, and otherwise the compiled S3 table's answer. A request inside a claim that no
    /// claimed row accepts names nothing; it is never handed to the S3 table.
    ///
    /// Not `async`, holds nothing, allocates nothing.
    #[must_use]
    pub fn resolve(&self, request: &RouteRequestParts<'_>) -> Option<&RouteEntry> {
        match self.claims.lookup(request) {
            ClaimLookup::Outside => self.select(request).ok().flatten(),
            ClaimLookup::Inside { entry, .. } => entry.map(ClaimedEntry::entry),
        }
    }

    /// The S3-table row a request outside every claim names, under this router's [`Selection`].
    ///
    /// `Ok(None)` when it names none. An `Err` is a refusal [`Selection::RustfsLegacy`] makes
    /// before the table is asked: a legacy RustFS operation this table does not define, or an
    /// `x-id` it does not accept.
    fn select(&self, request: &RouteRequestParts<'_>) -> Result<Option<&RouteEntry>, PreAuthError> {
        let from_table = || {
            self.compiled
                .resolve(request)
                .and_then(|op| self.table.entries().get(usize::from(op)))
        };
        if self.selection == Selection::Table {
            return Ok(from_table());
        }
        match legacy_rustfs_selection(request) {
            LegacySelection::Table => Ok(from_table()),
            LegacySelection::Unknown => Ok(None),
            LegacySelection::Undeclared => Err(PreAuthError::invalid_request(UNDECLARED_OPERATION_MESSAGE)),
            LegacySelection::Selected(name) => match self.table.entries().iter().find(|entry| entry.op_name == name) {
                Some(entry) => Ok(Some(entry)),
                None => Err(PreAuthError::not_implemented(NOT_REGISTERED_MESSAGE).about(name)),
            },
        }
    }

    /// The same answer from the readable S3 table. Kept as the reference implementation.
    #[must_use]
    pub fn resolve_readable(&self, request: &RouteRequestParts<'_>) -> Option<&RouteEntry> {
        match self.claims.lookup(request) {
            ClaimLookup::Outside => self.table.resolve(request),
            ClaimLookup::Inside { entry, .. } => entry.map(ClaimedEntry::entry),
        }
    }

    /// Routes, checks registration, then checks required parameters.
    ///
    /// # Errors
    ///
    /// [`PreAuthError`]: `501` with [`NO_ROUTE_MESSAGE`] when nothing matched, `501` with
    /// [`NO_CLAIMED_ROUTE_MESSAGE`] when a claim covers the request and no claimed row accepts it,
    /// `501` with [`NOT_REGISTERED_MESSAGE`] when the operation is not handled here, and otherwise
    /// the operation's own code for the first missing required parameter.
    pub fn dispatch(&self, request: &RouteRequestParts<'_>) -> Result<Dispatch<'_>, PreAuthError> {
        let (entry, claimed) = match self.claims.lookup(request) {
            ClaimLookup::Outside => {
                let Some(entry) = self.select(request)? else {
                    return Err(PreAuthError::not_implemented(NO_ROUTE_MESSAGE));
                };
                (entry, None)
            }
            ClaimLookup::Inside {
                entry: Some(claimed), ..
            } => (claimed.entry(), Some(claimed)),
            ClaimLookup::Inside { entry: None, .. } => {
                return Err(PreAuthError::not_implemented(NO_CLAIMED_ROUTE_MESSAGE));
            }
        };
        let Some(spec) = self.registry.get(entry.op_name) else {
            return Err(PreAuthError::not_implemented(NOT_REGISTERED_MESSAGE).about(entry.op_name));
        };
        check_required(spec, request)?;
        Ok(Dispatch { entry, spec, claimed })
    }
}
