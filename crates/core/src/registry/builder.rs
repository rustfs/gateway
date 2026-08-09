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

//! Assembly: the routes, the handlers, the completeness assertion, and one router or one error.
//!
//! Responsible for: [`RouterBuilder`] — the only supported way to install handlers — and
//! [`BuildError`], the single answer to "why did this service refuse to start".
//! NOT responsible for: what a registration must satisfy (`super::reject`), erasing it
//! (`super::handlers`), route overlap (`crate::route::RouteTable::build`, reached from here), or
//! anything per request.
//! Upstream: `crate::route`, `crate::op`, `super`. Downstream: `crate::dispatch::Router`, and the
//! `rustfs-gateway` facade's service builder.
//!
//! # Why `handle` returns `Self` and the errors come out of `build`
//!
//! Seventy-three chained `?` on a builder is not a nicer failure than one: every one of them is a
//! separate place to write the wrong thing, and the natural way to write the chain — collecting
//! into a `Result` per call — reports the first refusal and hides the rest. So refusals accumulate
//! and [`RouterBuilder::build`] reports all of them at once. Assembly happens on start-up, so the
//! cost of holding a `Vec` of errors is nothing and the benefit is that a backend fixing its
//! registrations sees the whole list.
//!
//! # Why a failed build cannot degrade a running service
//!
//! [`RouterBuilder::build`] either returns a complete [`Router`] or returns an error and produces
//! nothing. There is no partially built router and no fallback to an empty table — "the new
//! configuration failed to validate, so we served everything with no routes" is how a reload turns
//! into an outage or, worse, into a permissive default. A caller reloading configuration keeps the
//! router it already has.

use std::sync::Arc;

use crate::codec::OperationCodec;
use crate::dialect::Dialect;
use crate::dispatch::{Router, RouterBuildError};
use crate::handler::Handler;
use crate::op::{Operation, is_standard_operation_name};
use crate::registry::Registry;
use crate::registry::opset::{MissingHandlers, OperationSet};
use crate::registry::reject::RegistryError;
use crate::route::{PROVISIONAL_SHADOWING, RouteEntry, RouteTable, ShadowingDecl, ShadowingDecls, generated_entries};

/// Why a router refused to be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// One or more registrations were refused. Never empty.
    Registration(Vec<RegistryError>),
    /// A third-party route entry claims an AWS operation name.
    ///
    /// Separate from [`RegistryError::NameCollidesWithStandard`] because it is about the route
    /// table rather than about the handler: an added entry that says `op_name: "GetObject"` would
    /// send requests that AWS defines to a handler nobody reviewed, whatever it is registered as.
    RouteClaimsStandardName {
        /// The name the added entry claimed.
        op_name: &'static str,
    },
    /// The route table or its compiled form refused to be built.
    ///
    /// This is where a third-party entry overlapping an AWS one at the same precedence lands: the
    /// route table's own conflict decision refuses it, and the error carries a request that
    /// reaches both.
    Route(RouterBuildError),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration(errors) => {
                write!(f, "{} registration(s) refused:", errors.len())?;
                for error in errors {
                    write!(f, "\n  {error}")?;
                }
                Ok(())
            }
            Self::RouteClaimsStandardName { op_name } => write!(
                f,
                "an added route entry claims the AWS operation name {op_name}; a third-party entry \
                 may not stand in front of a standard operation"
            ),
            Self::Route(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<RouterBuildError> for BuildError {
    fn from(error: RouterBuildError) -> Self {
        Self::Route(error)
    }
}

/// Collects handlers and extra routes, and turns them into a [`Router`].
///
/// The backend type is erased by [`RouterBuilder::handle`], so neither this builder nor the router
/// it produces is generic over it. That is the whole reason the service above can stay one
/// non-generic type while a process holds several routers over different backends.
#[derive(Debug, Default)]
pub struct RouterBuilder {
    registry: Registry,
    entries: Vec<RouteEntry>,
    /// One group per installed dialect, folded onto [`PROVISIONAL_SHADOWING`] at build time.
    shadowing: Vec<&'static [ShadowingDecl]>,
    errors: Vec<RegistryError>,
}

impl RouterBuilder {
    /// A builder over the generated route table, with nothing registered.
    ///
    /// Building it as it stands yields a router that routes every AWS request and answers all of
    /// them with `501`, which is the correct behaviour for a backend that has implemented nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `implementation` as the handler for `O`, together with `O`'s wire codec.
    ///
    /// The `(O, B)` pair is erased here into a closure, and `O`'s [`OperationCodec`] into two
    /// more. Refusals are collected and reported by [`RouterBuilder::build`].
    #[must_use]
    pub fn handle<O, B>(mut self, implementation: Arc<B>) -> Self
    where
        O: OperationCodec,
        B: Handler<O>,
    {
        if let Err(error) = self.registry.register_handler::<O, B>(implementation) {
            self.errors.push(error);
        }
        self
    }

    /// Registers `implementation` as the handler for an operation with no wire codec.
    ///
    /// See [`Registry::register_handler_without_codec`]: the operation routes and dispatches, and
    /// nothing here can read it off the wire. Spelled differently from [`RouterBuilder::handle`]
    /// so that a backend cannot reach that state by accident, and so `grep` finds every place it
    /// was chosen.
    #[must_use]
    pub fn handle_without_codec<O, B>(mut self, implementation: Arc<B>) -> Self
    where
        O: Operation,
        B: Handler<O>,
    {
        if let Err(error) = self.registry.register_handler_without_codec::<O, B>(implementation) {
            self.errors.push(error);
        }
        self
    }

    /// Adds a route entry for an operation this crate does not define.
    ///
    /// The entry joins the generated ones and is subject to the same build-time overlap decision,
    /// so a third-party selector that collides with an AWS one at the same precedence refuses the
    /// build rather than winning by sort order.
    #[must_use]
    pub fn route(mut self, entry: RouteEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Installs a dialect: one route row per operation it adds, and the overlaps those rows
    /// declare.
    ///
    /// The rows join the generated ones and face the same build-time decision, so a dialect
    /// selector that collides with an AWS one at the same precedence refuses the build, and one
    /// that stands in front of an AWS row at a different precedence needs a declaration. The
    /// declarations a dialect brings are *appended* to the reviewed record for the generated table
    /// — [`ShadowingDecls::and`] — so a dialect can account for the overlaps its own placement
    /// creates and cannot rewrite anybody else's.
    ///
    /// Handlers are a separate call. See the module docs of [`crate::dialect`] for why: a route
    /// with no handler answers `501`, which is the correct answer for an operation a backend has
    /// not implemented, and making installation implicit is the link-time collection ADR-0003
    /// bans.
    #[must_use]
    pub fn dialect(mut self, dialect: &Dialect) -> Self {
        for operation in dialect.operations() {
            self.entries.push(operation.entry().clone());
            if !operation.shadows().is_empty() {
                self.shadowing.push(operation.shadows());
            }
        }
        self
    }

    /// Asserts that every operation in `set` has a handler.
    ///
    /// This replaces a compile-time completeness check. See [`MissingHandlers`] for why one
    /// sentence beats 73 `E0277` errors.
    ///
    /// # Errors
    ///
    /// [`MissingHandlers`], naming what is missing and how much of the set that is.
    pub fn require(self, set: &OperationSet) -> Result<Self, MissingHandlers> {
        match set.missing(|name| self.registry.handlers().contains(name)) {
            Some(missing) => Err(missing),
            None => Ok(self),
        }
    }

    /// The operations registered so far, sorted. For assertions and for a start-up report.
    pub fn registered(&self) -> impl Iterator<Item = &'static str> {
        self.registry.handler_names()
    }

    /// Builds the router, or reports every reason it cannot be built.
    ///
    /// # Errors
    ///
    /// [`BuildError::Registration`] with every refused registration,
    /// [`BuildError::RouteClaimsStandardName`] for an added entry wearing an AWS name, or
    /// [`BuildError::Route`] when the table itself refuses — an overlap at one precedence,
    /// undeclared shadowing, or a generated row this crate cannot read.
    pub fn build(self) -> Result<Router, BuildError> {
        if !self.errors.is_empty() {
            return Err(BuildError::Registration(self.errors));
        }
        for entry in &self.entries {
            if is_standard_operation_name(entry.op_name) {
                return Err(BuildError::RouteClaimsStandardName { op_name: entry.op_name });
            }
        }
        let mut entries = generated_entries().map_err(RouterBuildError::from)?;
        entries.extend(self.entries);
        let mut shadowing: ShadowingDecls = PROVISIONAL_SHADOWING;
        for group in self.shadowing {
            shadowing = shadowing.and(group);
        }
        let table = RouteTable::build(entries, &shadowing).map_err(RouterBuildError::from)?;
        Ok(Router::new(table, self.registry)?)
    }
}
