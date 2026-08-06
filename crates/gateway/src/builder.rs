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

//! Assembly: the operations, the extension points, and one service or one refusal.
//!
//! Responsible for: [`ServiceBuilder`] — the only supported way to build an [`S3Service`] — and
//! the assembly-time checks whose failure is an [`AssemblyError`].
//! NOT responsible for: registration rules, which are
//! `rustfs_gateway_core::RouterBuilder::build`'s and are surfaced unchanged; route conflicts,
//! which the route table decides; or anything per request (`crate::service`).
//! Upstream: `rustfs-gateway-core`, `crate::ext`. Downstream: `crate::service`.
//!
//! # Why every refusal comes out of `build` and none out of the setters
//!
//! A setter that returned `Result` puts a `?` on every line of an assembly that is written once
//! and read often, and the natural way to write that chain reports the first refusal and hides the
//! rest. `rustfs_gateway_core::RouterBuilder` already made this choice for registration, and
//! reversing it one layer up would mean two builders with two different shapes. So refusals
//! accumulate and `build` reports them; assembly happens at start-up and a `Vec` of errors costs
//! nothing there.
//!
//! # Why the missing-extension-point check is a run-time refusal and not a type-state
//!
//! Both are permitted, and the property that matters is that *no* [`S3Service`] can exist without
//! an [`Authorizer`] and an [`Authenticator`]. This crate spends that budget on the refusal rather
//! than on the type parameters because two required and five optional extension points give a
//! type-state builder four public states and four rustdoc pages, and every one of them is a place
//! a future extension point has to be threaded through. The invariant is the same either way:
//! `build` is the only constructor, and it returns `Err` rather than a permissive default.

use std::sync::Arc;

use rustfs_gateway_core::{Handler, MissingHandlers, OperationCodec, OperationSet, RouterBuilder};
use rustfs_gateway_http::Limits;
use rustfs_gateway_sig::SecurityFloor;

use crate::assembly::{AssemblyError, RuleRef};
use crate::clock::{Clock, system_clock};
use crate::dispatch::{DispatchTable, OperationDispatch};
use crate::ext::{Authenticator, Authorizer, Governor, HostResolver, NoObserver, Observer, PathStyleOnly, Unlimited};
use crate::service::{Inner, S3Service};

/// The ceiling on a request body this assembly will hold in memory.
///
/// 64 MiB, which is far below `Limits::max_body_bytes` and deliberately so: this facade reads a
/// request body into memory before decoding it, so the streaming ingest path is not yet wired
/// through it. Until it is, the honest ceiling is the one this service can actually survive, and a
/// larger body is refused with `413` rather than accepted and buffered.
pub const DEFAULT_MAX_BUFFERED_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// Collects operations and extension points, and turns them into an [`S3Service`].
///
/// Nothing here is generic over the backend: `register` erases the `(operation, backend)` pair
/// into a closure, exactly as `rustfs_gateway_core::RouterBuilder::handle` does, which is what
/// lets one process hold several services over different backends without a type parameter
/// reaching the caller.
pub struct ServiceBuilder {
    router: RouterBuilder,
    dispatch: DispatchTable,
    floor: SecurityFloor,
    limits: Limits,
    max_buffered_body_bytes: u64,
    authorizer: Option<Arc<dyn Authorizer>>,
    authenticator: Option<Arc<dyn Authenticator>>,
    host_resolver: Arc<dyn HostResolver>,
    governor: Arc<dyn Governor>,
    observer: Arc<dyn Observer>,
    clock: Arc<dyn Clock>,
}

impl core::fmt::Debug for ServiceBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServiceBuilder")
            .field("operations", &self.dispatch.names().collect::<Vec<_>>())
            .field("has_authorizer", &self.authorizer.is_some())
            .field("has_authenticator", &self.authenticator.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for ServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceBuilder {
    /// A builder over the generated route table with nothing registered and no extension point
    /// installed.
    ///
    /// Building it as it stands is refused twice over — no operation, no authorizer — which is the
    /// correct answer for a service nobody has configured.
    #[must_use]
    pub fn new() -> Self {
        Self {
            router: RouterBuilder::new(),
            dispatch: DispatchTable::default(),
            floor: SecurityFloor::new(),
            limits: Limits::default(),
            max_buffered_body_bytes: DEFAULT_MAX_BUFFERED_BODY_BYTES,
            authorizer: None,
            authenticator: None,
            host_resolver: Arc::new(PathStyleOnly),
            governor: Arc::new(Unlimited),
            observer: Arc::new(NoObserver),
            clock: Arc::new(system_clock()),
        }
    }

    /// Registers `backend` as the handler for one operation.
    ///
    /// The registration goes to `rustfs_gateway_core::RouterBuilder` as well as to this crate's
    /// wire table, so every registration-time refusal — a duplicate, an un-namespaced third-party
    /// name, a name colliding with an AWS one, an operation with no authorisation action — is the
    /// core's answer and not a second implementation of it. Refusals surface from
    /// [`ServiceBuilder::build`].
    #[must_use]
    pub fn register<O, B>(mut self, backend: Arc<B>) -> Self
    where
        O: OperationCodec,
        B: Handler<O>,
    {
        self.router = self.router.handle::<O, B>(Arc::clone(&backend));
        // A taken name is already a `RegistryError::Duplicate` from the line above, which `build`
        // reports. Inserting over it here would leave the two tables disagreeing about which
        // backend answers the operation.
        let _ = self.dispatch.insert(O::NAME, OperationDispatch::of::<O, B>(backend));
        self
    }

    /// Adds a route entry for an operation this workspace does not define.
    ///
    /// The entry joins the generated ones and is subject to the same build-time overlap decision,
    /// so a third-party selector that collides with an AWS one at the same precedence refuses the
    /// build rather than winning by sort order. An entry wearing an AWS operation name is refused
    /// outright.
    #[must_use]
    pub fn route(mut self, entry: rustfs_gateway_core::RouteEntry) -> Self {
        self.router = self.router.route(entry);
        self
    }

    /// Asserts that every operation in `set` has a handler.
    ///
    /// # Errors
    ///
    /// [`MissingHandlers`], naming what is missing. A deployment that must be complete says so
    /// here; one that implements a subset does not call this, and its unimplemented operations are
    /// answered `501`.
    pub fn require(mut self, set: &OperationSet) -> Result<Self, MissingHandlers> {
        self.router = self.router.require(set)?;
        Ok(self)
    }

    /// Installs the authorizer. Required: there is no default.
    #[must_use]
    pub fn authorizer(mut self, authorizer: impl Authorizer) -> Self {
        self.authorizer = Some(Arc::new(authorizer));
        self
    }

    /// Installs the authenticator. Required: there is no default.
    #[must_use]
    pub fn authenticator(mut self, authenticator: impl Authenticator) -> Self {
        self.authenticator = Some(Arc::new(authenticator));
        self
    }

    /// Installs a host resolver. Defaults to [`PathStyleOnly`].
    #[must_use]
    pub fn host_resolver(mut self, resolver: impl HostResolver) -> Self {
        self.host_resolver = Arc::new(resolver);
        self
    }

    /// Installs a governor. Defaults to [`Unlimited`].
    #[must_use]
    pub fn governor(mut self, governor: impl Governor) -> Self {
        self.governor = Arc::new(governor);
        self
    }

    /// Installs an observer. Defaults to [`NoObserver`].
    #[must_use]
    pub fn observer(mut self, observer: impl Observer) -> Self {
        self.observer = Arc::new(observer);
        self
    }

    /// Installs the clock. Defaults to the system one.
    ///
    /// One reading is taken per request, at the top of the pipeline. See [`crate::clock`].
    #[must_use]
    pub fn clock(mut self, clock: impl Clock) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Narrows the security floor.
    ///
    /// `SecurityFloor` can be narrowed and cannot be widened: its skew window is capped, its
    /// presigned ceiling is a constant, and its two switches only add scheme surface. There is no
    /// way to hand this method a floor that enforces less than the default does.
    #[must_use]
    pub fn security_floor(mut self, floor: SecurityFloor) -> Self {
        self.floor = floor;
        self
    }

    /// Sets the acceptance-layer ceilings.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Sets the ceiling on a request body this service will hold in memory.
    ///
    /// See [`DEFAULT_MAX_BUFFERED_BODY_BYTES`] for why this exists and why it is far below
    /// `Limits::max_body_bytes`.
    #[must_use]
    pub const fn max_buffered_body_bytes(mut self, bytes: u64) -> Self {
        self.max_buffered_body_bytes = bytes;
        self
    }

    /// The operations registered so far, sorted. For an assertion and for a start-up report.
    pub fn registered(&self) -> impl Iterator<Item = &'static str> {
        self.dispatch.names()
    }

    /// Builds the service, or reports why it refused.
    ///
    /// # Errors
    ///
    /// [`AssemblyError`], one variant per rule and every one of them carrying its [`RuleRef`]:
    /// a refused registration or route, an empty registry, a missing authorizer, a missing
    /// authenticator, or an operation the router knows and this crate has no codec for. Nothing
    /// here degrades to a warning.
    pub fn build(self) -> Result<S3Service, AssemblyError> {
        if self.dispatch.len() == 0 {
            return Err(AssemblyError::EmptyRegistry {
                rule: RuleRef::EMPTY_REGISTRY,
            });
        }
        let Some(authorizer) = self.authorizer else {
            return Err(AssemblyError::MissingAuthorizer {
                rule: RuleRef::MISSING_AUTHORIZER,
            });
        };
        let Some(authenticator) = self.authenticator else {
            return Err(AssemblyError::MissingAuthenticator {
                rule: RuleRef::MISSING_AUTHENTICATOR,
            });
        };

        let router = self.router.build()?;

        // The two tables are populated by the same call and can only disagree through a defect
        // here. Checked anyway, because the failure mode is a request that routes and then reaches
        // nothing able to read it, which looks like a codec bug rather than an assembly one.
        for name in router.registry().names() {
            if !self.dispatch.contains(name) {
                return Err(AssemblyError::MissingCodec {
                    operation: name,
                    rule: RuleRef::MISSING_CODEC,
                });
            }
        }

        Ok(S3Service::from_inner(Inner {
            router,
            dispatch: self.dispatch,
            floor: self.floor,
            limits: self.limits,
            max_buffered_body_bytes: self.max_buffered_body_bytes,
            authorizer,
            authenticator,
            host_resolver: self.host_resolver,
            governor: self.governor,
            observer: self.observer,
            clock: self.clock,
        }))
    }
}
