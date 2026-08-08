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

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use rustfs_gateway_core::{Handler, MissingHandlers, Operation, OperationCodec, OperationSet, RouterBuilder, SseConfig};
use rustfs_gateway_http::Limits;
use rustfs_gateway_sig::SecurityFloor;
use rustfs_gateway_types::{NamePolicy, NameValidator, SlashPolicy};

use crate::assembly::{AssemblyError, RuleRef};
use crate::clock::{Clock, system_clock};
use crate::dispatch::{DispatchTable, OperationDispatch};
use crate::ext::{
    Authenticator, Authorizer, CachedCorsSource, CorsCacheConfig, CorsSource, Governor, HostResolver, NoCors, NoObserver,
    Observer, OpLayer, OpLayerSlot, PathStyleOnly, StageFilter, Unlimited,
};
use crate::service::{Inner, S3Service};
use crate::trace::{MintedTraces, TraceSource};
use rustfs_gateway_core::cors::CorsPolicy;

/// One registered layer, with its operation type forgotten.
type ErasedOpLayer = Arc<dyn Any + Send + Sync>;

/// One registration, held until `build` knows which layers belong to it.
///
/// The closure is what still knows `O` and `B`, so it is also the only thing able to turn the
/// erased layers back into `Arc<dyn OpLayer<O>>`. That is the same closure-erasure shape
/// `rustfs_gateway_core::registry` uses, and the reason registration stays explicit and greppable
/// rather than reaching for `inventory` (ADR-0003).
type PendingRegistration = Box<dyn FnOnce(Vec<ErasedOpLayer>) -> Result<OperationDispatch, AssemblyError> + Send>;

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
    /// One entry per `register` call, keyed by operation name, in name order. Deferred rather than
    /// erased on the spot because `op_layer` may arrive after `register` and the erasure has to see
    /// both.
    pending: BTreeMap<&'static str, PendingRegistration>,
    /// The layers registered per operation, in registration order.
    op_layers: BTreeMap<&'static str, Vec<ErasedOpLayer>>,
    /// The stage filters, in registration order.
    filters: Vec<Arc<dyn StageFilter>>,
    floor: SecurityFloor,
    limits: Limits,
    names: NamePolicy,
    max_buffered_body_bytes: u64,
    authorizer: Option<Arc<dyn Authorizer>>,
    authenticator: Option<Arc<dyn Authenticator>>,
    host_resolver: Arc<dyn HostResolver>,
    governor: Arc<dyn Governor>,
    observer: Arc<dyn Observer>,
    clock: Arc<dyn Clock>,
    traces: Arc<dyn TraceSource>,
    cors_source: Arc<dyn CorsSource>,
    cors_cache: CorsCacheConfig,
    cors_policy: CorsPolicy,
    sse: SseConfig,
}

impl core::fmt::Debug for ServiceBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServiceBuilder")
            .field("operations", &self.registered().collect::<Vec<_>>())
            .field("has_authorizer", &self.authorizer.is_some())
            .field("has_authenticator", &self.authenticator.is_some())
            .field("stage_filters", &self.filters.len())
            .field("op_layers", &self.op_layers.values().map(Vec::len).sum::<usize>())
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
            pending: BTreeMap::new(),
            op_layers: BTreeMap::new(),
            filters: Vec::new(),
            floor: SecurityFloor::new(),
            limits: Limits::default(),
            names: NamePolicy::default(),
            max_buffered_body_bytes: DEFAULT_MAX_BUFFERED_BODY_BYTES,
            authorizer: None,
            authenticator: None,
            host_resolver: Arc::new(PathStyleOnly),
            governor: Arc::new(Unlimited),
            observer: Arc::new(NoObserver),
            clock: Arc::new(system_clock()),
            traces: Arc::new(MintedTraces::new()),
            cors_source: Arc::new(NoCors),
            cors_cache: CorsCacheConfig::default(),
            cors_policy: CorsPolicy::default(),
            sse: SseConfig::strict(),
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
        self.pending.entry(O::NAME).or_insert_with(|| {
            Box::new(move |erased: Vec<ErasedOpLayer>| {
                let mut layers: Vec<Arc<dyn OpLayer<O>>> = Vec::with_capacity(erased.len());
                for slot in erased {
                    // Unreachable through `op_layer`, which keys the slot by the very `O::NAME` the
                    // registration is under. Refused rather than unwrapped: two operation types
                    // sharing one name is an assembly defect, and answering it with a panic would
                    // take a process down at start-up for a reason the message never states.
                    let slot = slot
                        .downcast::<OpLayerSlot<O>>()
                        .map_err(|_| AssemblyError::OpLayerTypeMismatch {
                            operation: O::NAME,
                            rule: RuleRef::OP_LAYER_TYPE,
                        })?;
                    layers.push(slot.into_layer());
                }
                Ok(OperationDispatch::layered::<O, B>(backend, layers))
            })
        });
        self
    }

    /// Installs a [`StageFilter`]. Every seam it implements runs in registration order.
    ///
    /// A filter may observe, may rewrite and may refuse; it may not answer, may not affect a
    /// signature, may not choose the target, and may not defeat a response invariant. The reasons
    /// are on the trait, and the decision tree for "which of the three levels is this" is
    /// `docs/middleware.md`.
    #[must_use]
    pub fn stage_filter(mut self, filter: impl StageFilter) -> Self {
        self.filters.push(Arc::new(filter));
        self
    }

    /// Installs an [`OpLayer`] around one operation. Layers nest outer to inner in registration
    /// order.
    ///
    /// The operation must have a handler by the time [`ServiceBuilder::build`] runs, or the build
    /// is refused with [`RuleRef::OP_LAYER_UNATTACHED`]. Ignoring an unattached layer would leave a
    /// deployment believing a rewrite is in force while nothing runs it.
    #[must_use]
    pub fn op_layer<O, L>(mut self, layer: L) -> Self
    where
        O: Operation,
        L: OpLayer<O>,
    {
        self.op_layers
            .entry(O::NAME)
            .or_default()
            .push(OpLayerSlot::<O>::erase(Arc::new(layer)));
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

    /// Installs a naming policy: the slash rule and the validator.
    ///
    /// Defaults to [`NamePolicy::default`] — AWS slash semantics and the AWS bucket naming rules.
    /// Whatever is installed here, the safety floor underneath it does not move: a validator has
    /// no variant with which to permit what the floor refused.
    #[must_use]
    pub fn name_policy(mut self, names: NamePolicy) -> Self {
        self.names = names;
        self
    }

    /// Installs a name validator, keeping the slash policy already set.
    ///
    /// It may refuse more than the built-in `AwsNameValidator` does, and it cannot refuse less
    /// than the floor: the framework runs the floor first and ANDs the two answers.
    #[must_use]
    pub fn name_validator(mut self, validator: impl NameValidator) -> Self {
        self.names = self.names.with_validator(Arc::new(validator));
        self
    }

    /// Chooses what happens to a run of slashes in an object key.
    ///
    /// **Persistence-affecting.** [`SlashPolicy::Collapse`] makes `a//b` and `a/b` the same object;
    /// switching it on a deployment that has data renames every object whose key held an empty
    /// segment. [`SlashPolicy::rewrites_keys`] is what a start-up posture report reads.
    #[must_use]
    pub fn slash_policy(mut self, slash: SlashPolicy) -> Self {
        self.names = self.names.with_slash_policy(slash);
        self
    }

    /// Installs a host resolver. Defaults to [`PathStyleOnly`].
    ///
    /// A deployment that serves `bucket.example.com` installs
    /// [`VirtualHostStyle`](crate::VirtualHostStyle) here with the base domains it answers for;
    /// the default takes the bucket from the path and never from the host, so those requests would
    /// otherwise be routed by their path.
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

    /// Installs the source of bucket CORS documents. Defaults to [`NoCors`], under which no
    /// preflight is ever allowed.
    ///
    /// The source is wrapped in [`CachedCorsSource`] here and stored wrapped, which is the whole
    /// of the "no un-cached call path" property: this is the only setter, it takes a bare source,
    /// and nothing hands the inner one back. See `crate::ext::cors` for why an unauthenticated
    /// read that reaches storage once per request is an amplifier.
    #[must_use]
    pub fn cors_source(mut self, source: impl CorsSource) -> Self {
        self.cors_source = Arc::new(source);
        self
    }

    /// Tunes the mandatory CORS cache. Defaults to [`CorsCacheConfig::default`].
    #[must_use]
    pub const fn cors_cache(mut self, config: CorsCacheConfig) -> Self {
        self.cors_cache = config;
        self
    }

    /// Installs the deployment's credential posture for CORS.
    ///
    /// Defaults to "any origin the bucket's rules admit, no credentials". A policy that would
    /// pair a reflected origin with credentials cannot be constructed at all, so there is nothing
    /// for this setter to refuse — see `rustfs_gateway_core::cors::CorsPolicy::new`.
    #[must_use]
    pub fn cors_policy(mut self, policy: CorsPolicy) -> Self {
        self.cors_policy = policy;
        self
    }

    /// Installs the deployment's server-side-encryption posture.
    ///
    /// Defaults to [`SseConfig::strict`], under which a customer-provided encryption key on a
    /// cleartext connection is refused with `400 InvalidRequest` before the request body is read.
    /// The only way to relax that is
    /// [`SseConfig::allowing_customer_keys_over_plaintext`][relaxed], which takes a witness whose
    /// name has to be typed out — and a deployment that reaches for it should first ask whether
    /// its transport can declare [`rustfs_gateway_core::TransportSecurity::Encrypted`] instead,
    /// because that states the fact per connection rather than asserting it about all of them.
    ///
    /// This setter cannot refuse anything: the witness is the refusal, and it is a compile-time
    /// one.
    ///
    /// [relaxed]: rustfs_gateway_core::SseConfig::allowing_customer_keys_over_plaintext
    #[must_use]
    pub const fn sse_config(mut self, config: SseConfig) -> Self {
        self.sse = config;
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

    /// Installs the source of the per-request identifiers. Defaults to [`MintedTraces`].
    ///
    /// One trace is minted per request, at the top of the pipeline, and the same value reaches the
    /// `x-amz-request-id` header, the `<RequestId>` element of an error document and the audit
    /// event. See [`crate::trace`] for why a source cannot echo anything the caller sent, and read
    /// the security note on [`crate::FixedTrace`] before installing that one.
    #[must_use]
    pub fn trace_source(mut self, traces: impl TraceSource) -> Self {
        self.traces = Arc::new(traces);
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
        self.pending.keys().copied().collect::<Vec<_>>().into_iter()
    }

    /// Builds the service, or reports why it refused.
    ///
    /// # Errors
    ///
    /// [`AssemblyError`], one variant per rule and every one of them carrying its [`RuleRef`]:
    /// a refused registration or route, an empty registry, a missing authorizer, a missing
    /// authenticator, an [`OpLayer`] on an operation nobody registered, or an operation the router
    /// knows and this crate has no codec for. Nothing here degrades to a warning.
    pub fn build(mut self) -> Result<S3Service, AssemblyError> {
        if self.pending.is_empty() {
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

        // Before the erasure, so the refusal names the operation the deployment asked for rather
        // than whatever the erasure happens to reach first.
        if let Some((operation, _)) = self
            .op_layers
            .iter()
            .find(|(operation, _)| !self.pending.contains_key(*operation))
        {
            return Err(AssemblyError::UnattachedOpLayer {
                operation,
                rule: RuleRef::OP_LAYER_UNATTACHED,
            });
        }

        let mut dispatch = DispatchTable::default();
        for (name, finalise) in core::mem::take(&mut self.pending) {
            let layers = self.op_layers.remove(name).unwrap_or_default();
            // `pending` is a map, so the name is unique by construction and the insert cannot
            // report a duplicate. Checked anyway rather than discarded: a silently dropped
            // registration is a request that routes and reaches nothing.
            if !dispatch.insert(name, finalise(layers)?) {
                return Err(AssemblyError::MissingCodec {
                    operation: name,
                    rule: RuleRef::MISSING_CODEC,
                });
            }
        }

        let router = self.router.build()?;

        // The two tables are populated by the same call and can only disagree through a defect
        // here. Checked anyway, because the failure mode is a request that routes and then reaches
        // nothing able to read it, which looks like a codec bug rather than an assembly one.
        for name in router.registry().names() {
            if !dispatch.contains(name) {
                return Err(AssemblyError::MissingCodec {
                    operation: name,
                    rule: RuleRef::MISSING_CODEC,
                });
            }
        }

        Ok(S3Service::from_inner(Inner {
            router,
            dispatch,
            filters: Arc::from(self.filters),
            floor: self.floor,
            limits: self.limits,
            names: self.names,
            max_buffered_body_bytes: self.max_buffered_body_bytes,
            authorizer,
            authenticator,
            host_resolver: self.host_resolver,
            governor: self.governor,
            observer: self.observer,
            clock: self.clock,
            traces: self.traces,
            cors: Arc::new(CachedCorsSource::new(self.cors_source, self.cors_cache)),
            cors_policy: self.cors_policy,
            sse: self.sse,
        }))
    }
}
