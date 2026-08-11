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

//! The extension points a deployment mounts on the assembled service.
//!
//! Responsible for: mounting one module per extension point, and stating the rule that binds all
//! of them.
//! NOT responsible for: assembling them (`crate::builder`), calling them in order
//! (`crate::service`), or any protocol behaviour.
//! Upstream: `rustfs-gateway-core`'s `BoxFuture` alias. Downstream: `crate::builder`.
//!
//! # The two rules every extension point here follows
//!
//! 1. **Asynchronous methods are hand-written `-> BoxFuture<'_, T>`** (ADR-0002). Every trait here
//!    is held as `Arc<dyn _>` by the assembled service, and RPITIT is measurably not dyn
//!    compatible. `Handler<O>` and `Operation` are the only two exceptions in the workspace, and
//!    neither of them is here.
//! 2. **A synchronous extension point must justify itself in its own module docs.** Two of them
//!    are synchronous — [`HostResolver`] and [`Observer`] — and both justifications are about
//!    where they run rather than about convenience.
//!
//! # Which of these have a default, and what the default costs
//!
//! | Extension point | Default | What the default means |
//! | --- | --- | --- |
//! | [`Authorizer`] | none — [`crate::ServiceBuilder::build`] refuses | there is no safe default: allow-all is a hole, deny-all is a service nobody can use |
//! | [`Authenticator`] | none — `build` refuses | the same asymmetry, one stage earlier |
//! | [`HostResolver`] | [`PathStyleOnly`] | a virtual-hosted request is routed by its path, so `Host: bucket.example.com` addressing `/key` is not understood; install [`VirtualHostStyle`] to understand it |
//! | [`Governor`] | [`DefaultGovernor`] | aggregate, per-client, and three pre-authentication class ceilings are in force at [`GovernorRates::default`]; no per-identity quota, because this hook has no identity |
//! | [`Observer`] | [`NoObserver`] | nothing is recorded; a rejection leaves no trace outside the response |
//! | [`CorsSource`] | [`NoCors`] | no bucket has a CORS document, so no preflight is ever allowed and no `Access-Control-*` header is ever written |
//! | [`StageFilter`] | none installed | the three seams run nothing, and the pipeline allocates nothing for them |
//! | [`OpLayer`] | none installed | dispatch calls the backend directly, with no continuation and no chain |
//!
//! Every default above is safe in the sense that it cannot widen access. [`NoObserver`] is the
//! one that removes a defence rather than opening a door: a deployment that ships with it has no
//! audit trail. The [`Governor`] row used to be the second such default — it was [`Unlimited`] —
//! and it is not any more, because the three unauthenticated paths this service exposes are
//! amplifiers whose only mitigation is a limit that is already on. [`Unlimited`] still exists as
//! a deployment governor that adds no quota, but it cannot remove the framework default.
//!
//! # The three middleware levels, and which requirement belongs to which
//!
//! `docs/middleware.md` is the decision tree, and it is also the acceptance list for deleting the
//! nine tower patch layers RustFS carries around s3s today. The short form:
//!
//! | The shape of the requirement | The level |
//! | --- | --- |
//! | Connection-wide, no S3 semantics: panic capture, tracing, accept back-pressure | a tower `Layer` outside the whole service — nothing here |
//! | See or rewrite the HTTP shape, or a finished response; no typed input needed | [`StageFilter`] |
//! | One operation, and it needs the decoded input or the typed output | [`OpLayer`] |
//! | Only watching: logs, metrics, audit | [`Observer`], which is read-only and always will be |

mod authenticator;
mod authorizer;
mod authz_audit;
mod cors;
mod credential_guard;
mod credentials;
mod filter;
mod governor;
mod host;
mod observer;
mod oplayer;
mod policy;
mod vhost;

pub use self::authenticator::{
    Authentication, AuthenticationOutcome, Authenticator, ChunkSink, ChunkVerification, SigV4Authenticator, Unavailable,
};
#[cfg(feature = "dangerous-allow-all-authorizer")]
pub use self::authorizer::{AllowAllAuthorizer, DangerAck};
pub use self::authorizer::{
    AuthSchemeRef, Authorizer, AuthzRequest, Decision, Denial, DenyAllAuthorizer, InputAuthzRequest, InputDecisions,
    RequestContext, ServerExtensions, allow_when, decide_with,
};
pub(crate) use self::authz_audit::emit_safely;
pub use self::authz_audit::{AuthzAuditEvent, AuthzAuditSink, AuthzStage, NoAuthzAudit};
pub use self::cors::{CORS_PREFLIGHT, CachedCorsSource, CorsCacheConfig, CorsSource, CorsSourceError, NoCors};
pub use self::credential_guard::{CredentialGuardConfig, GuardedCredentialProvider, ProviderMetrics};
pub use self::credentials::{
    Credential, CredentialLookup, CredentialProvider, CredentialRefusal, Credentials, CredentialsError, ProviderError,
    SessionBinding, SessionBindingError, StaticCredentials, fn_credential_provider,
};
pub use self::filter::{
    FROZEN_WIRE_HEADERS, FrozenHeader, ResponseView, RoutedView, StageFilter, WireHead, response_filter, routed_filter,
    wire_filter,
};
pub use self::governor::{
    ClassKind, ClientAddr, DefaultGovernor, Governor, GovernorRates, GovernorRequest, LayeredGovernor, Lease, Rate, Unlimited,
};
pub use self::host::{Addressing, HostQuery, HostResolver, PathStyleOnly, ResolvedHost, TargetOrigin, VhostHint};
pub use self::observer::{NoObserver, Observer, RequestEvent};
pub use self::oplayer::{Next, OpLayer, op_layer};
pub(crate) use self::oplayer::{OpLayerSlot, Terminal};
pub use self::policy::{
    DEFAULT_POLICY_SNAPSHOT_TIMEOUT, MAX_POLICY_SNAPSHOT_TIMEOUT, NoPolicy, PolicyError, PolicySnapshot, PolicySource,
    PolicyTimeout, PolicyTimeoutError, SnapshotId, policy_from,
};
pub use self::vhost::{BaseDomain, DomainError, MAX_BASE_DOMAIN_BYTES, VirtualHostStyle};
