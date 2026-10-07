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

//! Whether an authenticated caller may perform the operation routing already chose.
//!
//! Responsible for: the two-stage [`Authorizer`] contract, the requests it is asked about
//! ([`AuthzRequest`] and [`InputAuthzRequest`]), the [`RequestContext`] both stages share — its
//! clock, policy, [`AuthSchemeRef`], verified scope, headers, raw query and [`ClientFacts`] — with
//! the typed [`ServerExtensions`] read path onto the accepted request's transport bag, and the
//! closure adapters ADR-0002 requires every `BoxFuture` extension point to ship ([`allow_when`]
//! and [`decide_with`]).
//! NOT responsible for: authentication (`super::authenticator`), deciding which operation was
//! named (`rustfs_gateway_core::route`), or the action-to-resource mapping, which is
//! `OperationSpec::auth` and is registered rather than computed here.
//! Upstream: `rustfs-gateway-core`, `rustfs-gateway-sig`. Downstream: `crate::service`.
//!
//! # Why there is no default implementation
//!
//! An `Option<Arc<dyn Authorizer>>` that falls back to allow-all is a fail-open default wearing an
//! ergonomics argument, and it is the exact shape of rustfs/rustfs#4845: a route that reached a
//! handler without ever reaching an authorisation check. A fall back to deny-all is not better —
//! it makes every misassembled deployment fail identically to a correctly assembled one under a
//! restrictive policy, so the mistake is discovered by a user rather than by the build. So there is
//! no default at all: [`crate::ServiceBuilder::build`] refuses without one.
//!
//! # Why the refusal is one variant
//!
//! [`Denial`] carries a decision and nothing derived from the request. An authorisation refusal is
//! answered to a caller whose identity is known but whose permission is not, and a refusal that
//! explained which condition failed would let that caller map the policy one request at a time.

use rustfs_gateway_core::{BoxFuture, ResourceIdentity, ResourceShape, Subject};
use rustfs_gateway_http::{TransportExtensions, WireRequest};
use rustfs_gateway_sig::{AuthScheme, Identity, RequestNow, SigFamily, SigLocation, Verdict, VerifiedScope};
use rustfs_gateway_types::{BucketName, ObjectKey};

pub use rustfs_gateway_core::{Decision, Denied as Denial};

use super::{ClientFacts, PolicySnapshot, TargetOrigin};

/// How the request was authenticated, as far as a policy may branch on it: the signature family
/// and where it was carried, never the session token or the signature itself.
///
/// Read off the verdict's own scheme by [`AuthSchemeRef::of_scheme`]; nothing here verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthSchemeRef {
    /// The request presented no authentication material, and that was confirmed.
    Anonymous,
    /// `AWS4-HMAC-SHA256` in the `Authorization` header.
    SigV4Header,
    /// `AWS4-HMAC-SHA256` in the query: a presigned URL.
    SigV4Presigned,
    /// SigV2 in the `Authorization` header.
    SigV2Header,
    /// SigV2 in the query: a presigned URL.
    SigV2Presigned,
    /// A signed POST policy in a browser form field, of either family.
    PostPolicy,
    /// Verified by a family this enum has no spelling for — SigV4a, or one the signing crate adds
    /// later. Its own answer rather than the nearest SigV4 variant, so a policy that names a
    /// scheme never admits one it did not name.
    OtherSigned,
}

impl AuthSchemeRef {
    /// The scheme a verdict's [`AuthScheme`] spells, read from its family and its location.
    #[must_use]
    pub fn of_scheme(scheme: &AuthScheme) -> Self {
        match (scheme.family, scheme.location) {
            (SigFamily::V4 | SigFamily::V2, SigLocation::FormField) => Self::PostPolicy,
            (SigFamily::V4, SigLocation::Header) => Self::SigV4Header,
            (SigFamily::V4, SigLocation::Query) => Self::SigV4Presigned,
            (SigFamily::V2, SigLocation::Header) => Self::SigV2Header,
            (SigFamily::V2, SigLocation::Query) => Self::SigV2Presigned,
            _ => Self::OtherSigned,
        }
    }

    /// The scheme a settled verdict carries: `None` for a rejected verdict, and for any variant
    /// added later, so that a caller refuses rather than reports "presented nothing".
    #[must_use]
    pub fn of_verdict(verdict: &Verdict) -> Option<Self> {
        match verdict {
            Verdict::Authenticated { scheme, .. } => Some(Self::of_scheme(scheme)),
            Verdict::Anonymous(_) => Some(Self::Anonymous),
            _ => None,
        }
    }

    /// Whether a signature was verified: everything but [`Self::Anonymous`].
    #[must_use]
    pub const fn is_authenticated(self) -> bool {
        !matches!(self, Self::Anonymous)
    }

    /// Whether the signature was carried in the query, so the URL itself is the credential.
    #[must_use]
    pub const fn is_presigned(self) -> bool {
        matches!(self, Self::SigV4Presigned | Self::SigV2Presigned)
    }
}

/// Server-derived request state available to an authorizer: the values the transport and the
/// host installed in the request before acceptance, read by type.
///
/// This type has no public constructor or mutation API. It borrows the accepted request's
/// [`TransportExtensions`] — the same bag `RequestContextView::transport_extensions` hands a
/// handler — so a value is installed once and read by both. Client request headers are a
/// different thing and are not reachable through here: nothing on the wire can put a value in
/// this bag.
#[derive(Clone, Copy, Debug)]
pub struct ServerExtensions<'a> {
    transport: Option<&'a TransportExtensions>,
}

/// The immutable values every authorization stage in one request must share.
pub struct RequestContext<'a> {
    now: RequestNow,
    policy: &'a PolicySnapshot,
    auth_scheme: AuthSchemeRef,
    verified_scope: Option<&'a VerifiedScope>,
    server_extensions: ServerExtensions<'a>,
    headers: Option<rustfs_gateway_http::HeaderView<'a>>,
    raw_query: Option<&'a str>,
}

impl std::fmt::Debug for RequestContext<'_> {
    /// Prints the query's length and never the query: a presigned query is a credential.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestContext")
            .field("now", &self.now)
            .field("policy", &self.policy)
            .field("auth_scheme", &self.auth_scheme)
            .field("verified_scope", &self.verified_scope)
            .field("server_extensions", &self.server_extensions)
            .field("headers_available", &self.headers.is_some())
            .field("raw_query_bytes", &self.raw_query.map(str::len))
            .field("client", &self.client())
            .finish()
    }
}

impl<'a> RequestContext<'a> {
    /// Builds the immutable context shared by both stages.
    ///
    /// A context built here is anonymous and has no [`VerifiedScope`]: there is no parameter
    /// through which one could be supplied, because only the pipeline holds a verdict.
    #[must_use]
    pub const fn new(now: RequestNow, policy: &'a PolicySnapshot) -> Self {
        Self {
            now,
            policy,
            auth_scheme: AuthSchemeRef::Anonymous,
            verified_scope: None,
            server_extensions: ServerExtensions::none(),
            headers: None,
            raw_query: None,
        }
    }

    /// The context both stages share, read off the accepted request: its transport bag, its
    /// headers after the wire seam, and its query exactly as it arrived.
    pub(crate) fn from_request<B>(
        now: RequestNow,
        policy: &'a PolicySnapshot,
        auth_scheme: AuthSchemeRef,
        verified_scope: Option<&'a VerifiedScope>,
        wire: &'a WireRequest<B>,
    ) -> Self {
        Self {
            now,
            policy,
            auth_scheme,
            verified_scope,
            server_extensions: ServerExtensions::of(wire.transport_extensions()),
            headers: Some(wire.headers()),
            raw_query: Some(wire.query().as_str()),
        }
    }

    /// Accepted request headers after wire filters, borrowed read-only, when available.
    ///
    /// These are the header facts the operation consumes, not the original signing input.
    /// Filters may rewrite them; use [`Self::auth_scheme`] and [`Self::verified_scope`] for
    /// authentication evidence instead of deriving it from a header.
    ///
    /// `None` identifies a manually constructed context whose request headers are unknown;
    /// it does not prove that a particular header was absent. Pipeline contexts return `Some`
    /// in both authorization stages, even when the observed header map is empty.
    #[must_use]
    pub fn headers(&self) -> Option<rustfs_gateway_http::HeaderView<'a>> {
        self.headers
    }

    /// The query exactly as it arrived, without its `?`: `Some("")` for a pipeline request that
    /// had none, `None` for a manually constructed context whose request is unknown.
    ///
    /// A presigned query carries the signature, so this is for a policy's own condition keys and
    /// not for a log line; this context's `Debug` prints the length only.
    #[must_use]
    pub const fn raw_query(&self) -> Option<&'a str> {
        self.raw_query
    }

    /// What the transport knew about the client: the socket peer, whether the transport was
    /// secure, and the client address a host attested (rustfs/backlog#2752).
    ///
    /// `None` when nothing was installed — a context built by hand, or a request that reached the
    /// service without a listener's connection value, a host's `TransportSecurity` or
    /// `ClientAddr`, and without a `WireHead::set_client_facts` override. `None` is "unknown",
    /// never "cleartext from nowhere", and no field of a `Some` leans towards allow.
    #[must_use]
    pub fn client(&self) -> Option<&'a ClientFacts> {
        self.server_extensions.get::<ClientFacts>()
    }

    /// The credential scope this request's signature was verified under (ADR-0020).
    ///
    /// Borrowed from the verdict the pipeline checked, never re-derived from a header. `None` for
    /// an anonymous request and for a scheme without a credential scope (SigV2, a custom scheme).
    #[must_use]
    pub const fn verified_scope(&self) -> Option<&'a VerifiedScope> {
        self.verified_scope
    }

    /// The single clock reading captured for this request.
    #[must_use]
    pub const fn now(&self) -> RequestNow {
        self.now
    }

    /// The single policy reading captured for this request.
    #[must_use]
    pub const fn policy(&self) -> &'a PolicySnapshot {
        self.policy
    }

    /// Whether this request was authenticated, with anonymous represented explicitly.
    #[must_use]
    pub const fn auth_scheme(&self) -> AuthSchemeRef {
        self.auth_scheme
    }

    /// Server-derived extensions, read by type. Client-controlled request headers are not
    /// exposed here.
    #[must_use]
    pub const fn server_extensions(&self) -> ServerExtensions<'a> {
        self.server_extensions
    }
}

impl<'a> ServerExtensions<'a> {
    /// A context built by hand has no bag to read.
    const fn none() -> Self {
        Self { transport: None }
    }

    /// A view onto the accepted request's bag. Borrowed, so reading one costs nothing.
    pub(crate) const fn of(transport: &'a TransportExtensions) -> Self {
        Self {
            transport: Some(transport),
        }
    }

    /// Borrows the value of type `T` the transport or the host installed before acceptance, when
    /// one was.
    #[must_use]
    pub fn get<T: Send + Sync + 'static>(self) -> Option<&'a T> {
        self.transport.and_then(TransportExtensions::get::<T>)
    }
}

/// What an [`Authorizer`] is asked about.
///
/// Borrowed throughout: the whole value lives for one call and copying an object key per request
/// to hand it to a policy engine is a per-request allocation the engine does not need.
#[derive(Clone, Copy, Debug)]
pub struct AuthzRequest<'a> {
    /// The operation routing chose, by its `Operation::NAME`.
    pub operation: &'a str,
    /// The IAM action the operation declares, in its wire spelling: `s3:GetObject`.
    pub action: &'a str,
    /// What the action is about.
    pub resource: ResourceShape,
    /// The bucket the path addressed, when it addressed one.
    pub bucket: Option<&'a BucketName>,
    /// The object key the path addressed, when it addressed one.
    pub key: Option<&'a ObjectKey>,
    /// The addressing identity of a derived copy source, when this is its second-stage check.
    pub copy_source_identity: Option<&'a ResourceIdentity>,
    /// The exact object version for a derived version action, when any.
    pub version_id: Option<&'a str>,
    /// The route-level destination action for the same request.
    pub route_action: &'a str,
    /// The route-level destination bucket for the same request.
    pub route_bucket: Option<&'a BucketName>,
    /// The route-level destination key for the same request.
    pub route_key: Option<&'a ObjectKey>,
    /// Who the request runs as. `None` for an anonymous request, which is a request that presented
    /// nothing and was confirmed to have presented nothing — never a request whose verification
    /// failed.
    pub identity: Option<&'a Identity>,
    /// Whether the bucket name came from the host or the path.
    pub target_origin: TargetOrigin,
    /// Whose account the request acts on, when the operation declares a subject rule (ADR-0025);
    /// `None` otherwise. Decoded once, before authentication, and handed unchanged to both stages
    /// and to the handler. Whether a named subject is the caller, or one of the caller's service
    /// accounts, is this authorizer's decision: only it can look that up. The facade never asks
    /// about a subject for an anonymous caller.
    ///
    /// A set rule (ADR-0026) is asked one question per named account and action, every account in
    /// turn, and is allowed only when every account is. A request for every account is asked
    /// about no subject (`None`), under the operation's actions and the rule's broader action, so
    /// no own-account relaxation can answer it.
    pub subject: Option<&'a Subject>,
}

impl AuthzRequest<'_> {
    /// Whether the caller is anonymous.
    ///
    /// A convenience over `identity.is_none()`, spelled out so that a policy that treats anonymity
    /// specially says so at the call site.
    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        self.identity.is_none()
    }
}

/// The second-stage question, after decoding and derived-resource normalization.
///
/// `resources` contains every derived resource and no raw header or body representation. The
/// framework checks the complete returned decision batch before it can ask the core to create
/// `Authorized<O>`.
#[derive(Debug)]
pub struct InputAuthzRequest<'a> {
    route: &'a AuthzRequest<'a>,
    resources: &'a [AuthzRequest<'a>],
    visibility: Option<AuthzRequest<'a>>,
}

impl<'a> InputAuthzRequest<'a> {
    pub(crate) fn new(route: &'a AuthzRequest<'a>, resources: &'a [AuthzRequest<'a>]) -> Self {
        let visibility = (route.operation == "GetObject").then_some(AuthzRequest {
            action: "s3:ListBucket",
            resource: ResourceShape::Bucket,
            copy_source_identity: None,
            version_id: None,
            ..*route
        });
        Self {
            route,
            resources,
            visibility,
        }
    }

    /// The route-level destination already admitted by the first stage.
    #[must_use]
    pub const fn route(&self) -> &'a AuthzRequest<'a> {
        self.route
    }

    /// Every normalized body/header-derived resource that must be judged.
    #[must_use]
    pub const fn resources(&self) -> &'a [AuthzRequest<'a>] {
        self.resources
    }

    /// The non-gating bucket-list capability that controls missing-object disclosure, when this
    /// operation can report an absent object.
    #[must_use]
    pub const fn visibility(&self) -> Option<&AuthzRequest<'a>> {
        self.visibility.as_ref()
    }

    /// Visits every derived resource and builds a complete decision batch.
    #[must_use]
    pub fn decide_all<F>(&self, stage: Decision, mut decide: F) -> InputDecisions
    where
        F: FnMut(&AuthzRequest<'_>) -> Decision,
    {
        let decisions = self.resources.iter().map(&mut decide).collect();
        let visibility = self.visibility.as_ref().map(&mut decide);
        InputDecisions {
            stage,
            decisions,
            visibility,
        }
    }
}

/// Decisions bound to one complete second-stage resource batch.
///
/// Fields and constructors are private. An implementation obtains this only through
/// [`InputAuthzRequest::decide_all`], which visits the entire batch.
#[derive(Debug)]
pub struct InputDecisions {
    stage: Decision,
    decisions: Vec<Decision>,
    visibility: Option<Decision>,
}

impl InputDecisions {
    pub(crate) const fn stage(&self) -> Decision {
        self.stage
    }

    pub(crate) fn as_slice(&self) -> &[Decision] {
        &self.decisions
    }

    pub(crate) const fn visibility(&self) -> Option<Decision> {
        self.visibility
    }
}

/// Decides whether one authenticated caller may perform one already-routed operation.
///
/// Held as `Arc<dyn Authorizer>`, so the async method is a hand-written [`BoxFuture`] (ADR-0002).
///
/// The framework runs this **after** the security floor has admitted the request and after the
/// signature has been verified, and **before** the handler is invoked. An implementation therefore
/// cannot be reached by a request whose signature did not verify, and cannot be skipped by one
/// whose did.
pub trait Authorizer: Send + Sync + 'static {
    /// Decides the routed action and destination before the body is read.
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision>;

    /// Decides the decoded input and every normalized resource derived from it.
    ///
    /// There is deliberately no default body: omitting the second stage is a compile error.
    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions>;
}

impl<T: Authorizer + ?Sized> Authorizer for std::sync::Arc<T> {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        (**self).authorize_route(context, request)
    }

    fn authorize_input<'a>(
        &'a self,
        context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        (**self).authorize_input(context, request)
    }
}

/// The only built-in authorizer: both stages refuse every request.
pub struct DenyAllAuthorizer;

impl Authorizer for DenyAllAuthorizer {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Deny })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Deny, |_| Decision::Deny);
        Box::pin(async move { decisions })
    }
}

/// Explicit acknowledgement required to construct the dangerous allow-all authorizer.
#[cfg(feature = "dangerous-allow-all-authorizer")]
pub struct DangerAck {
    _private: (),
}

#[cfg(feature = "dangerous-allow-all-authorizer")]
impl DangerAck {
    /// Acknowledges that every routed and derived resource will be authorized.
    #[must_use]
    pub const fn i_understand_this_disables_authorization() -> Self {
        Self { _private: () }
    }
}

/// An explicit, feature-gated authorizer for deployments that intentionally disable authorization.
#[cfg(feature = "dangerous-allow-all-authorizer")]
pub struct AllowAllAuthorizer(DangerAck);

#[cfg(feature = "dangerous-allow-all-authorizer")]
impl AllowAllAuthorizer {
    /// Constructs the dangerous authorizer after an explicit acknowledgement.
    #[must_use]
    pub fn new(acknowledgement: DangerAck) -> Self {
        crate::logging::dangerous_assembly(
            "allow_all_authorizer_constructed",
            "constructing an allow-all authorizer disables authorization for every request",
        );
        Self(acknowledgement)
    }
}

#[cfg(feature = "dangerous-allow-all-authorizer")]
impl Authorizer for AllowAllAuthorizer {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// The closure adapter for [`Authorizer`].
///
/// ADR-0002 makes shipping one a completion condition of every `BoxFuture` extension point:
/// requiring a user to declare a struct in order to supply one synchronous predicate is the real
/// ergonomic cost of the dyn policy, and this is what pays it back.
///
/// The predicate is synchronous on purpose. An authorizer that needs to await — one that consults
/// a policy store — is exactly the case that deserves a named type, because its failure modes and
/// its caching are things a reviewer must be able to find.
#[must_use]
pub fn allow_when<F>(predicate: F) -> impl Authorizer
where
    F: Fn(&AuthzRequest<'_>) -> bool + Send + Sync + 'static,
{
    decide_with(move |request| if predicate(request) { Decision::Allow } else { Decision::Deny })
}

/// Adapts one synchronous three-state decision function to both authorization stages.
#[must_use]
pub fn decide_with<F>(decide: F) -> impl Authorizer
where
    F: Fn(&AuthzRequest<'_>) -> Decision + Send + Sync + 'static,
{
    struct FnAuthorizer<F>(F);

    impl<F> Authorizer for FnAuthorizer<F>
    where
        F: Fn(&AuthzRequest<'_>) -> Decision + Send + Sync + 'static,
    {
        fn authorize_route<'a>(
            &'a self,
            _context: &'a RequestContext<'a>,
            request: &'a AuthzRequest<'a>,
        ) -> BoxFuture<'a, Decision> {
            let decision = (self.0)(request);
            Box::pin(async move { decision })
        }

        fn authorize_input<'a>(
            &'a self,
            _context: &'a RequestContext<'a>,
            request: &'a InputAuthzRequest<'a>,
        ) -> BoxFuture<'a, InputDecisions> {
            let stage = (self.0)(request.route());
            let decisions = request.decide_all(stage, |resource| (self.0)(resource));
            Box::pin(async move { decisions })
        }
    }

    FnAuthorizer(decide)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[path = "authorizer_tests.rs"]
mod tests;
