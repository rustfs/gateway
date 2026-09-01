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
//! ([`AuthzRequest`] and [`InputAuthzRequest`]), and the closure adapters ADR-0002 requires every
//! `BoxFuture` extension point to ship ([`allow_when`] and [`decide_with`]).
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

use rustfs_gateway_core::{BoxFuture, ResourceIdentity, ResourceShape};
use rustfs_gateway_sig::{Identity, RequestNow};
use rustfs_gateway_types::{BucketName, ObjectKey};

pub use rustfs_gateway_core::{Decision, Denied as Denial};

use super::{PolicySnapshot, TargetOrigin};

/// The authentication scheme exposed to authorization without exposing session-token material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthSchemeRef {
    /// The request presented no authentication material.
    Anonymous,
    /// The request carried a signature that was verified.
    Authenticated,
}

/// Server-derived request state available to an authorizer.
///
/// This type has no public constructor or mutation API. Client request extensions are deliberately
/// a different type and are not reachable through [`RequestContext`].
#[derive(Debug)]
pub struct ServerExtensions {
    _private: (),
}

static EMPTY_SERVER_EXTENSIONS: ServerExtensions = ServerExtensions { _private: () };

/// The immutable values every authorization stage in one request must share.
#[derive(Debug)]
pub struct RequestContext<'a> {
    now: RequestNow,
    policy: &'a PolicySnapshot,
    auth_scheme: AuthSchemeRef,
    server_extensions: &'a ServerExtensions,
}

impl<'a> RequestContext<'a> {
    /// Builds the immutable context shared by both stages.
    #[must_use]
    pub const fn new(now: RequestNow, policy: &'a PolicySnapshot) -> Self {
        Self {
            now,
            policy,
            auth_scheme: AuthSchemeRef::Anonymous,
            server_extensions: &EMPTY_SERVER_EXTENSIONS,
        }
    }

    pub(crate) const fn from_request(
        now: RequestNow,
        policy: &'a PolicySnapshot,
        auth_scheme: AuthSchemeRef,
        server_extensions: &'a ServerExtensions,
    ) -> Self {
        Self {
            now,
            policy,
            auth_scheme,
            server_extensions,
        }
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

    /// Server-derived extensions. Client-controlled request extensions are not exposed here.
    #[must_use]
    pub const fn server_extensions(&self) -> &'a ServerExtensions {
        self.server_extensions
    }
}

impl ServerExtensions {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
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
        eprintln!("WARN: constructing an allow-all authorizer disables authorization for every request");
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
mod tests {
    use super::*;

    fn request<'a>(operation: &'a str, identity: Option<&'a Identity>) -> AuthzRequest<'a> {
        AuthzRequest {
            operation,
            action: "s3:GetObject",
            resource: ResourceShape::Object,
            bucket: None,
            key: None,
            copy_source_identity: None,
            version_id: None,
            route_action: "s3:GetObject",
            route_bucket: None,
            route_key: None,
            identity,
            target_origin: TargetOrigin::Path,
        }
    }

    /// Negative — the closure adapter refuses when the predicate is false, and the refusal is the
    /// ordinary 403 rather than something a caller can mistake for a routing failure.
    #[tokio::test]
    async fn a_false_predicate_refuses_with_access_denied() {
        let authorizer = allow_when(|request| request.operation == "ListBuckets");
        let policy = PolicySnapshot::empty();
        let context = RequestContext::new(RequestNow::from_unix_seconds(0), &policy);
        assert_eq!(authorizer.authorize_route(&context, &request("GetObject", None)).await, Decision::Deny);
    }

    /// Negative — a denial renders nothing about the request, so it cannot become a policy oracle.
    #[test]
    fn a_denial_carries_nothing_from_the_request() {
        let rendered = format!("{:?}", Denial::access_denied());
        assert!(!rendered.contains("GetObject"), "{rendered}");
    }

    /// Negative — an anonymous request is the one with no identity, and nothing else may produce
    /// that answer.
    #[test]
    fn anonymity_is_the_absence_of_an_identity() {
        let identity = Identity::new("AKIDEXAMPLE").expect("a valid access key id");
        assert!(request("GetObject", None).is_anonymous());
        assert!(!request("GetObject", Some(&identity)).is_anonymous());
    }

    /// Positive — a true predicate permits, and the adapter is usable behind `Arc<dyn _>`, which
    /// is the property ADR-0002 exists to protect.
    #[tokio::test]
    async fn the_adapter_is_dyn_compatible() {
        let authorizer: std::sync::Arc<dyn Authorizer> = std::sync::Arc::new(allow_when(|_| true));
        let policy = PolicySnapshot::empty();
        let context = RequestContext::new(RequestNow::from_unix_seconds(0), &policy);
        let route = request("GetObject", None);
        assert_eq!(authorizer.authorize_route(&context, &route).await, Decision::Allow);
        let resources = [request("GetObject", None), request("HeadObject", None)];
        let input = InputAuthzRequest::new(&route, &resources);
        let decisions = authorizer.authorize_input(&context, &input).await;
        assert_eq!(decisions.stage(), Decision::Allow);
        assert_eq!(decisions.as_slice(), [Decision::Allow, Decision::Allow]);
        assert_eq!(decisions.visibility(), Some(Decision::Allow));
    }

    /// Negative — the disclosure check is a separate, non-gating ListBucket decision and retains
    /// the addressed key so a prefix-scoped policy can decide the exact read target.
    #[tokio::test]
    async fn n_get_object_asks_for_its_missing_key_visibility_without_gating_the_read() {
        let bucket = BucketName::new("example-bucket").expect("a valid bucket name");
        let key = ObjectKey::new("private/report.txt").expect("a valid object key");
        let route = AuthzRequest {
            bucket: Some(&bucket),
            key: Some(&key),
            route_bucket: Some(&bucket),
            route_key: Some(&key),
            ..request("GetObject", None)
        };
        let input = InputAuthzRequest::new(&route, &[]);
        let visibility = input.visibility().expect("GetObject asks the auxiliary question");
        assert_eq!(visibility.action, "s3:ListBucket");
        assert_eq!(visibility.resource, ResourceShape::Bucket);
        assert_eq!(visibility.key.map(ObjectKey::as_str), Some("private/report.txt"));
        assert_eq!(visibility.route_action, "s3:GetObject");

        let decisions = input.decide_all(Decision::Allow, |request| {
            if request.action == "s3:ListBucket" {
                Decision::Deny
            } else {
                Decision::Allow
            }
        });
        assert_eq!(decisions.stage(), Decision::Allow);
        assert!(decisions.as_slice().is_empty());
        assert_eq!(decisions.visibility(), Some(Decision::Deny));
    }

    /// Negative — an operation that happens to reuse the GetObject IAM action does not silently
    /// inherit this operation-specific error transition without its own end-to-end contract.
    #[test]
    fn n_a_sibling_operation_does_not_inherit_get_objects_visibility_transition() {
        let route = request("GetObjectAttributes", None);
        assert!(InputAuthzRequest::new(&route, &[]).visibility().is_none());
    }

    #[cfg(feature = "dangerous-allow-all-authorizer")]
    #[tokio::test]
    async fn the_dangerous_authorizer_requires_acknowledgement_and_allows_both_stages() {
        let acknowledgement = DangerAck::i_understand_this_disables_authorization();
        let authorizer = AllowAllAuthorizer::new(acknowledgement);
        let policy = PolicySnapshot::empty();
        let context = RequestContext::new(RequestNow::from_unix_seconds(0), &policy);
        let route = request("GetObject", None);
        assert_eq!(authorizer.authorize_route(&context, &route).await, Decision::Allow);
        let input = InputAuthzRequest::new(&route, &[]);
        let decisions = authorizer.authorize_input(&context, &input).await;
        assert_eq!(decisions.stage(), Decision::Allow);
        assert!(decisions.as_slice().is_empty());
    }
}
