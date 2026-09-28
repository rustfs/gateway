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
#[cfg(feature = "dangerous-allow-all-authorizer")]
use std::any::TypeId;
use std::collections::BTreeMap;
use std::sync::Arc;

use rustfs_gateway_core::{
    Dialect, Handler, MissingHandlers, Operation, OperationCodec, OperationSet, RedirectTarget, RouterBuilder, SseConfig,
};
use rustfs_gateway_http::Limits;
#[cfg(feature = "dangerous-replace-signature-verifier")]
use rustfs_gateway_sig::{AwsSignatureVerifier, DangerAck};
use rustfs_gateway_sig::{SecurityFloor, SignatureVerifier};
use rustfs_gateway_types::{NamePolicy, NameValidator, SlashPolicy};

use crate::assembly::{AssemblyError, RuleRef};
use crate::clock::{Clock, ClockPosture, ClockSkewAck, MAX_CLOCK_SKEW_SECONDS, SystemMonotonic, skew_from_system, system_clock};
use crate::config::{AssemblySnapshot, ConfigHandle, ConfigStore, ServiceConfig};
use crate::dispatch::{DispatchTable, OperationDispatch};
use crate::ext::{
    Authenticator, Authorizer, AuthzAuditSink, BucketOwnerSource, CachedCorsSource, CorsCacheConfig, CorsSource, DefaultGovernor,
    Governor, GovernorRates, HostResolver, LayeredGovernor, NoAuthzAudit, NoBucketOwner, NoCors, NoObserver, NoPolicy, Observer,
    OpLayer, OpLayerSlot, PathStyleOnly, PolicySource, PolicyTimeout, StageFilter,
};
use crate::posture::{SecurityPosture, log_dialect_posture, log_startup_posture};
use crate::routing::{RoutingSnapshot, RuntimeAssembly};

mod assembly_update;
mod client_quirks;
mod secret_scope;
pub use self::assembly_update::AssemblyUpdate;
pub(crate) use self::client_quirks::ChecksumWaiver;
pub use self::client_quirks::MINIO_CLIENT_CHECKSUM_OPTIONAL_OPERATIONS;
use crate::service::{Inner, S3Service};
use crate::trace::{MintedTraces, TraceSource};
use crate::{MonomorphicOperationSet, MonomorphicService};
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
/// into a closure, as `rustfs_gateway_core::RouterBuilder::handle` does, so one process can hold
/// several services over different backends without a type parameter reaching the caller.
pub struct ServiceBuilder {
    router: RouterBuilder,
    /// One entry per `register` call, keyed by name; deferred so a later `op_layer` is seen too.
    pending: BTreeMap<&'static str, PendingRegistration>,
    /// The layers registered per operation, in registration order.
    op_layers: BTreeMap<&'static str, Vec<ErasedOpLayer>>,
    /// The stage filters, in registration order.
    filters: Vec<Arc<dyn StageFilter>>,
    floor: SecurityFloor,
    limits: Limits,
    names: NamePolicy,
    config: ConfigStore,
    authorizer: Option<Arc<dyn Authorizer>>,
    dangerous_allow_all_authorizer: bool,
    /// ADR-0024: a handed-over caller secret reaches every operation, not only opted-in ones.
    caller_secret_every_operation: bool,
    checksum_waiver: client_quirks::ChecksumWaiver,
    authenticator: Option<Arc<dyn Authenticator>>,
    custom_signature_verifier: Option<Arc<dyn SignatureVerifier>>,
    #[cfg(feature = "dangerous-replace-signature-verifier")]
    dangerously_replaced_signature_verifier: Option<Arc<dyn AwsSignatureVerifier>>,
    policy_source: Arc<dyn PolicySource>,
    policy_timeout: PolicyTimeout,
    authz_audit: Arc<dyn AuthzAuditSink>,
    bucket_owner_source: Arc<dyn BucketOwnerSource>,
    host_resolver: Arc<dyn HostResolver>,
    governor_rates: GovernorRates,
    governor: Option<Arc<dyn Governor>>,
    observer: Arc<dyn Observer>,
    clock: Arc<dyn Clock>,
    clock_posture: ClockPosture,
    traces: Arc<dyn TraceSource>,
    cors_source: Arc<dyn CorsSource>,
    cors_cache: CorsCacheConfig,
    cors_policy: CorsPolicy,
    sse: SseConfig,
    temporary_redirect_targets: Vec<RedirectTarget>,
}

impl core::fmt::Debug for ServiceBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServiceBuilder")
            .field("operations", &self.registered().collect::<Vec<_>>())
            .field("has_authorizer", &self.authorizer.is_some())
            .field("has_authenticator", &self.authenticator.is_some())
            .field("has_custom_signature_verifier", &self.custom_signature_verifier.is_some())
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
    /// A builder over the generated route table with nothing registered and no extension point.
    ///
    /// Building it as it stands is refused twice over (no operation, no authorizer).
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
            config: Arc::new(arc_swap::ArcSwap::from_pointee(AssemblySnapshot::unassembled(ServiceConfig::new(
                DEFAULT_MAX_BUFFERED_BODY_BYTES,
            )))),
            authorizer: None,
            dangerous_allow_all_authorizer: false,
            caller_secret_every_operation: false,
            checksum_waiver: client_quirks::ChecksumWaiver::default(),
            authenticator: None,
            custom_signature_verifier: None,
            #[cfg(feature = "dangerous-replace-signature-verifier")]
            dangerously_replaced_signature_verifier: None,
            policy_source: Arc::new(NoPolicy),
            policy_timeout: PolicyTimeout::default(),
            authz_audit: Arc::new(NoAuthzAudit),
            bucket_owner_source: Arc::new(NoBucketOwner),
            host_resolver: Arc::new(PathStyleOnly),
            governor_rates: GovernorRates::default(),
            governor: None,
            observer: Arc::new(NoObserver),
            clock: Arc::new(system_clock()),
            clock_posture: ClockPosture::System,
            traces: Arc::new(MintedTraces::new()),
            cors_source: Arc::new(NoCors),
            cors_cache: CorsCacheConfig::default(),
            cors_policy: CorsPolicy::default(),
            sse: SseConfig::strict(),
            temporary_redirect_targets: Vec::new(),
        }
    }

    /// Allows one exact `Location` value on a `307 Temporary Redirect` response.
    ///
    /// The list is fixed into the service at assembly time. A handler or response filter may
    /// select one of these values, but cannot introduce a request-derived endpoint later.
    #[must_use]
    pub fn allow_temporary_redirect_target(mut self, target: RedirectTarget) -> Self {
        self.temporary_redirect_targets.push(target);
        self
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

    /// Installs an [`OpLayer`] around one operation; layers nest outer to inner in order.
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

    /// Stages a raw route entry for an operation this workspace does not define.
    ///
    /// A route-only operation with no wire codec remains usable by the core router. A route paired
    /// with a public wire codec must also be the exact row installed by [`ServiceBuilder::dialect`]
    /// or the build fails closed. This method cannot acknowledge dialect evidence, anonymous
    /// reachability, or reserved host classes on its own.
    #[must_use]
    pub fn route(mut self, entry: rustfs_gateway_core::RouteEntry) -> Self {
        self.router = self.router.route(entry);
        self
    }

    /// Installs the exact route rows carried by one validated [`Dialect`] proof.
    ///
    /// Registration remains explicit and greppable through [`ServiceBuilder::register`], while
    /// [`ServiceBuilder::build`] commits the route table and its handler table together. A raw row
    /// paired with a codec is refused unless this proof contains that exact row, so callers cannot
    /// route around the overlay's evidence and security acknowledgements.
    #[must_use]
    pub fn dialect(mut self, dialect: &Dialect) -> Self {
        self.router = self.router.dialect(dialect);
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
    pub fn authorizer<A: Authorizer>(mut self, authorizer: A) -> Self {
        #[cfg(feature = "dangerous-allow-all-authorizer")]
        {
            self.dangerous_allow_all_authorizer = TypeId::of::<A>() == TypeId::of::<crate::AllowAllAuthorizer>();
        }
        self.authorizer = Some(Arc::new(authorizer));
        self
    }

    /// Installs the authenticator. Required: there is no default.
    #[must_use]
    pub fn authenticator(mut self, authenticator: impl Authenticator) -> Self {
        self.authenticator = Some(Arc::new(authenticator));
        self
    }

    /// Installs the verifier for registered non-AWS authentication schemes.
    ///
    /// The security floor decides whether a request is custom before this verifier runs. Requests
    /// carrying any AWS credential marker remain sealed to the built-in [`Authenticator`] path.
    #[must_use]
    pub fn custom_signature_verifier(mut self, verifier: impl SignatureVerifier) -> Self {
        self.custom_signature_verifier = Some(Arc::new(verifier));
        self
    }

    /// Replaces the built-in AWS signature computation after the unconditional security floor.
    ///
    /// This feature-gated escape hatch emits a start-up warning and is recorded in
    /// [`SecurityPosture`]. It does not bypass H1..H7: malformed, expired, duplicated, skewed, or
    /// privileged presigned requests are refused before `verifier` receives a sealed request.
    #[cfg(feature = "dangerous-replace-signature-verifier")]
    #[must_use]
    pub fn with_dangerously_replaced_signature_verifier(
        mut self,
        verifier: impl AwsSignatureVerifier,
        _acknowledgement: DangerAck,
    ) -> Self {
        self.dangerously_replaced_signature_verifier = Some(Arc::new(verifier));
        self
    }

    /// Installs the source read exactly once for each request's authorization stages.
    #[must_use]
    pub fn policy_source(mut self, source: impl PolicySource) -> Self {
        self.policy_source = Arc::new(source);
        self
    }

    /// Sets the validated hard limit for the one policy read per request.
    #[must_use]
    pub const fn policy_timeout(mut self, timeout: PolicyTimeout) -> Self {
        self.policy_timeout = timeout;
        self
    }

    /// Installs the read-only authorization audit sink.
    #[must_use]
    pub fn authz_audit(mut self, sink: impl AuthzAuditSink) -> Self {
        self.authz_audit = Arc::new(sink);
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

    /// Installs the source used to enforce `x-amz-expected-bucket-owner`.
    ///
    /// The default [`NoBucketOwner`] makes a presented assertion fail closed. Requests that do not
    /// carry the header never call this source and retain their existing path.
    #[must_use]
    pub fn bucket_owner_source(mut self, source: impl BucketOwnerSource) -> Self {
        self.bucket_owner_source = Arc::new(source);
        self
    }

    /// Tunes the mandatory framework governor.
    #[must_use]
    pub const fn framework_governor_rates(mut self, rates: GovernorRates) -> Self {
        self.governor_rates = rates;
        self
    }

    /// Installs a deployment governor after the mandatory framework governor.
    ///
    /// The default is [`DefaultGovernor`] at [`GovernorRates::default`](crate::GovernorRates), not
    /// an unlimited one, and the difference matters: three of this service's paths — a preflight,
    /// a credential lookup, and any request that reaches the body — do work for a caller who has
    /// not authenticated, so a limit that has to be configured before it applies is a limit that
    /// is missing from every deployment nobody has read the documentation for.
    ///
    /// Both must admit. Installing [`Unlimited`](crate::Unlimited) therefore means the deployment
    /// adds no quota of its own; it does not remove the framework's pre-authentication limits.
    #[must_use]
    pub fn governor(mut self, governor: impl Governor) -> Self {
        self.governor = Some(Arc::new(governor));
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
    /// One reading is taken per request, at the top of the pipeline. See the crate's clock module.
    #[must_use]
    pub fn clock(mut self, clock: impl Clock) -> Self {
        self.clock = Arc::new(clock);
        self.clock_posture = ClockPosture::CustomChecked;
        self
    }

    /// Installs a deliberately skewed clock with an explicit replay-risk acknowledgement.
    #[must_use]
    pub fn clock_with_skew_ack(mut self, clock: impl Clock, _ack: ClockSkewAck) -> Self {
        self.clock = Arc::new(clock);
        self.clock_posture = ClockPosture::CustomAcknowledged;
        self
    }

    /// Installs the source of the per-request identifiers. Defaults to [`MintedTraces`].
    ///
    /// One trace is minted per request, at the top of the pipeline, and the same value reaches the
    /// `x-amz-request-id` header, the `<RequestId>` element of an error document and the audit
    /// event. See the crate's trace module for why a source cannot echo anything the caller sent, and read
    /// the security note on [`crate::FixedTrace`] before installing that one.
    #[must_use]
    pub fn trace_source(mut self, traces: impl TraceSource) -> Self {
        self.traces = Arc::new(traces);
        self
    }

    /// Narrows the security floor.
    ///
    /// `SecurityFloor` can be narrowed and cannot be widened: its skew window is capped, its
    /// presigned ceiling is a constant, and its switches only add scheme surface. There is no way
    /// to hand this method a floor that enforces less than the default does.
    ///
    /// One of those switches is
    /// `SecurityFloor::delegate_anonymous_to_authorizer_after_listing_in_the_posture_report`, for
    /// a deployment whose own access check decides every request (ADR-0021). It lets a request
    /// that presented nothing reach every non-privileged operation's authorization stages, and
    /// the installed `Authorizer` then decides. The default stays per operation.
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

    /// Installs hot service configuration and returns the handle that may replace it.
    ///
    /// A request loads one immutable snapshot at entry. Calling [`ConfigHandle::store`] affects
    /// later requests and cannot change the settings an in-flight request already observes.
    #[must_use]
    pub fn config(self, config: ServiceConfig) -> (Self, ConfigHandle) {
        let handle = ConfigHandle::new(&self.config);
        handle.store(config);
        (self, handle)
    }

    /// Sets the ceiling on a request body this service will hold in memory.
    ///
    /// See [`DEFAULT_MAX_BUFFERED_BODY_BYTES`] for why this exists and why it is far below
    /// `Limits::max_body_bytes`.
    #[must_use]
    pub fn max_buffered_body_bytes(self, bytes: u64) -> Self {
        ConfigHandle::new(&self.config).store(ServiceConfig::new(bytes));
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
    pub fn build(self) -> Result<S3Service, AssemblyError> {
        let authorizer = self.validate_assembly()?;
        let Some(authenticator) = self.authenticator else {
            return Err(AssemblyError::MissingAuthenticator {
                rule: RuleRef::MISSING_AUTHENTICATOR,
            });
        };

        if self.clock_posture == ClockPosture::CustomChecked {
            let skew_seconds = skew_from_system(self.clock.as_ref());
            if skew_seconds > MAX_CLOCK_SKEW_SECONDS {
                return Err(AssemblyError::ClockSkew {
                    skew_seconds,
                    rule: RuleRef::CLOCK_SKEW,
                });
            }
        }

        let routing = assemble_routing(self.router, self.pending, self.op_layers)?;

        if self.dangerous_allow_all_authorizer {
            eprintln!("WARN: dangerous allow-all authorizer disables authorization for every request");
        }

        #[cfg(feature = "dangerous-replace-signature-verifier")]
        let dangerously_replaced_signature_verifier = self.dangerously_replaced_signature_verifier.is_some();
        #[cfg(not(feature = "dangerous-replace-signature-verifier"))]
        let dangerously_replaced_signature_verifier = false;
        if dangerously_replaced_signature_verifier {
            eprintln!(
                "WARN: the built-in AWS signature verifier is dangerously replaced; the H1..H7 security floor remains enforced"
            );
        }

        let framework_governor = DefaultGovernor::with_rates(self.governor_rates);
        let custom_signature_verifier = self.custom_signature_verifier.is_some();
        let security_posture = SecurityPosture::new(
            authenticator.credential_guard_config(),
            self.governor_rates.per_ip,
            custom_signature_verifier,
            dangerously_replaced_signature_verifier,
        );
        log_startup_posture(
            routing.dispatch.floors(),
            &self.floor,
            custom_signature_verifier,
            dangerously_replaced_signature_verifier,
        );
        log_dialect_posture(&routing.router, self.caller_secret_every_operation);
        let governor: Arc<dyn Governor> = match self.governor {
            Some(user) => Arc::new(LayeredGovernor::new(framework_governor, user)),
            None => Arc::new(framework_governor),
        };

        let runtime = Arc::new(RuntimeAssembly {
            routing: Arc::new(routing),
            filters: Arc::from(self.filters),
            authorizer,
            policy_source: self.policy_source,
            policy_timeout: self.policy_timeout,
            authz_audit: self.authz_audit,
            observer: self.observer,
        });
        self.config.rcu(|current| {
            Arc::new(AssemblySnapshot {
                config: Arc::clone(&current.config),
                runtime: Some(Arc::clone(&runtime)),
            })
        });
        Ok(S3Service::from_inner(Inner {
            floor: self.floor,
            limits: self.limits,
            names: self.names,
            config: self.config,
            authenticator,
            custom_signature_verifier: self.custom_signature_verifier,
            #[cfg(feature = "dangerous-replace-signature-verifier")]
            dangerously_replaced_signature_verifier: self.dangerously_replaced_signature_verifier,
            authz_clock: Arc::new(SystemMonotonic::new()),
            bucket_owner_source: self.bucket_owner_source,
            host_resolver: self.host_resolver,
            governor,
            clock: self.clock,
            clock_posture: self.clock_posture,
            security_posture,
            traces: self.traces,
            cors: Arc::new(CachedCorsSource::new(self.cors_source, self.cors_cache)),
            cors_policy: self.cors_policy,
            sse: self.sse,
            response_body_corrections: std::sync::atomic::AtomicU64::new(0),
            temporary_redirect_targets: Arc::from(self.temporary_redirect_targets),
            caller_secret_every_operation: self.caller_secret_every_operation,
            checksum_waiver: self.checksum_waiver,
        }))
    }

    /// Consumes only the inputs that define a replaceable routing generation.
    pub(crate) fn into_routing(self) -> Result<RoutingSnapshot, AssemblyError> {
        assemble_routing(self.router, self.pending, self.op_layers)
    }

    /// Builds a service that selects operation codecs and one concrete backend statically.
    ///
    /// `Operations` must name exactly the operations registered on this builder. Operation layers
    /// are refused because their dynamic continuation chain would contradict this path's dispatch
    /// contract; stage-level extension points remain the object-safe forms required by ADR-0002.
    ///
    /// # Errors
    ///
    /// [`AssemblyError`] when ordinary assembly fails, the type-level operation set differs from
    /// registration, or an operation layer was installed.
    pub fn build_monomorphic<H, Operations>(self, backend: Arc<H>) -> Result<MonomorphicService<H, Operations>, AssemblyError>
    where
        H: Send + Sync + 'static,
        Operations: MonomorphicOperationSet<H>,
    {
        if !self.op_layers.is_empty() {
            return Err(AssemblyError::MonomorphicSet {
                reason: "operation layers require dynamic per-operation continuations".to_owned(),
                rule: RuleRef::MONOMORPHIC_SET,
            });
        }

        let registered: Vec<&'static str> = self.pending.keys().copied().collect();
        let mut declared = Vec::new();
        <Operations as crate::monomorphic::sealed::Set<H>>::names(&mut declared);
        declared.sort_unstable();
        declared.dedup();
        if registered != declared {
            return Err(AssemblyError::MonomorphicSet {
                reason: format!("registered operations {registered:?} differ from declared static operations {declared:?}"),
                rule: RuleRef::MONOMORPHIC_SET,
            });
        }

        let service = self.build()?;
        Ok(MonomorphicService {
            service,
            backend,
            operations: core::marker::PhantomData,
        })
    }
}

fn assemble_routing(
    router: RouterBuilder,
    pending: BTreeMap<&'static str, PendingRegistration>,
    mut op_layers: BTreeMap<&'static str, Vec<ErasedOpLayer>>,
) -> Result<RoutingSnapshot, AssemblyError> {
    if pending.is_empty() {
        return Err(AssemblyError::EmptyRegistry {
            rule: RuleRef::EMPTY_REGISTRY,
        });
    }

    // Before the erasure, so the refusal names the operation the deployment asked for rather
    // than whatever the erasure happens to reach first.
    if let Some((operation, _)) = op_layers.iter().find(|(operation, _)| !pending.contains_key(*operation)) {
        return Err(AssemblyError::UnattachedOpLayer {
            operation,
            rule: RuleRef::OP_LAYER_UNATTACHED,
        });
    }

    let mut dispatch = DispatchTable::default();
    for (name, finalise) in pending {
        let layers = op_layers.remove(name).unwrap_or_default();
        // `pending` is a map, so the name is unique by construction and the insert cannot report
        // a duplicate. Checked anyway rather than discarded: a silently dropped registration is
        // a request that routes and reaches nothing.
        if !dispatch.insert(name, finalise(layers)?) {
            return Err(AssemblyError::MissingCodec {
                operation: name,
                rule: RuleRef::MISSING_CODEC,
            });
        }
    }

    let router = router.build()?;
    // The two tables are populated by the same call and can only disagree through a defect here.
    // Checked anyway, because a mismatch would route a request to no codec.
    for name in router.registry().names() {
        if !dispatch.contains(name) {
            return Err(AssemblyError::MissingCodec {
                operation: name,
                rule: RuleRef::MISSING_CODEC,
            });
        }
    }

    Ok(RoutingSnapshot { router, dispatch })
}
