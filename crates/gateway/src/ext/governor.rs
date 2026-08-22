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

//! Whether this deployment will spend resources on this request at all.
//!
//! Responsible for: [`Governor`], the question it is asked ([`GovernorRequest`]), the permit it
//! hands back ([`Lease`]), the lease's optional [`BodyQuota`], the limiter a deployment gets
//! without asking ([`DefaultGovernor`], in `governor/default.rs`), and [`Unlimited`], which adds no
//! deployment-specific limit.
//! NOT responsible for: connection-level back-pressure and idle timeouts, which belong to the
//! server (P7-02) and not here; authorisation, which is a different question with a different
//! answer; or counting anything, which is the implementation's business.
//! Upstream: `rustfs-gateway-core`. Downstream: `crate::service`.
//!
//! # Where the framework calls this, and why it is exactly there
//!
//! **After routing, before a single body byte is read.** Both halves are load-bearing.
//!
//! Earlier than routing, the call has no resolved bucket or operation. The framework waits for
//! those authoritative routing results, but still keys the default per-client meter from a
//! transport-supplied [`ClientAddr`] rather than re-deriving either fact from request text.
//!
//! Later than the first body byte, the request has already cost what it was going to cost: a
//! gibibyte `PutObject` that is refused after its body has been read has been paid for in full.
//! `crate::service` reads the body only after this returns a [`Lease`], so a refusal costs the
//! response and nothing else.
//!
//! # Why it is not a tower layer
//!
//! A `tower::Layer` wrapping the service sees an `http::Request` that has not been routed. It can
//! see the path, but "which bucket is this" is the [`crate::HostResolver`]'s answer and not the
//! path's, and a layer that re-derived it would be a second component deciding the same question.

mod default;
mod meter;
mod rates;

pub use self::default::{DefaultGovernor, LayeredGovernor};
pub use self::rates::{GovernorRates, Rate};

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::Identity;
use rustfs_gateway_types::BucketName;

/// The framework-owned pre-authentication class of one request.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClassKind {
    /// A request that presented credential material and can drive a credential lookup.
    CredentialLookup,
    /// A browser CORS preflight.
    CorsPreflight,
    /// A request that presented no credential material.
    Unauthenticated,
    /// A request whose caller is already known.
    ///
    /// The current pre-body hook cannot produce this variant. It remains part of the vocabulary
    /// for deployments that reuse a governor after authentication; [`DefaultGovernor`] admits it
    /// without charging the framework's pre-authentication buckets.
    Authenticated,
}

/// The peer address supplied by the transport.
///
/// The service reads this value only from [`http::Request::extensions`]. It never parses
/// `X-Forwarded-For` or another caller-controlled header, so a proxy must validate its trust
/// boundary before inserting one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientAddr(IpAddr);

impl ClientAddr {
    /// Records the address observed by the listener or a trusted-proxy adapter.
    #[must_use]
    pub const fn from_peer(address: IpAddr) -> Self {
        Self(address)
    }

    /// The address as supplied by the transport.
    #[must_use]
    pub const fn ip(self) -> IpAddr {
        self.0
    }

    pub(super) fn rate_key(self) -> IpAddr {
        match self.0 {
            IpAddr::V4(address) => IpAddr::V4(address),
            IpAddr::V6(address) => {
                let prefix = u128::from(address) & (u128::MAX << 64);
                IpAddr::V6(Ipv6Addr::from(prefix))
            }
        }
    }
}

/// What a [`Governor`] is asked about.
///
/// The identity is `None` here for every request, and that is not an oversight: this runs before
/// authentication, because the point of a limit is to stop work being done, and verifying a
/// signature is work. A deployment that wants a per-identity quota applies it in its
/// [`crate::Authorizer`], which runs after the identity is known.
#[derive(Debug)]
pub struct GovernorRequest<'a> {
    /// The operation routing chose, by its `Operation::NAME`.
    operation: &'a str,
    /// The bucket the path addressed, when it addressed one.
    bucket: Option<&'a BucketName>,
    /// The body length the request head declared, when HTTP framing gave one.
    ///
    /// `None` for a chunked body. A limit that only fires on a declared length is a limit a client
    /// removes by switching to `Transfer-Encoding: chunked`, so an implementation that cares must
    /// handle the `None` case rather than admitting it.
    declared_body_bytes: Option<u64>,
    /// Always `None`. Reserved so that adding the identity later is not a signature change.
    identity: Option<&'a Identity>,
    /// The peer address supplied by the transport, or `None` when the transport supplied none.
    client_addr: Option<ClientAddr>,
    /// The framework-owned pre-authentication class.
    kind: ClassKind,
}

impl<'a> GovernorRequest<'a> {
    pub(crate) const fn new(
        operation: &'a str,
        bucket: Option<&'a BucketName>,
        declared_body_bytes: Option<u64>,
        identity: Option<&'a Identity>,
        client_addr: Option<ClientAddr>,
        kind: ClassKind,
    ) -> Self {
        Self {
            operation,
            bucket,
            declared_body_bytes,
            identity,
            client_addr,
            kind,
        }
    }

    /// The routed operation name.
    #[must_use]
    pub const fn operation(&self) -> &'a str {
        self.operation
    }

    /// The bucket from the framework's resolved target.
    #[must_use]
    pub const fn bucket(&self) -> Option<&'a BucketName> {
        self.bucket
    }

    /// The declared body length, when the framing supplied one.
    #[must_use]
    pub const fn declared_body_bytes(&self) -> Option<u64> {
        self.declared_body_bytes
    }

    /// The authenticated identity, when this hook is reused after authentication.
    #[must_use]
    pub const fn identity(&self) -> Option<&'a Identity> {
        self.identity
    }

    /// The transport-supplied peer address.
    #[must_use]
    pub const fn client_addr(&self) -> Option<ClientAddr> {
        self.client_addr
    }

    /// The framework-owned class.
    #[must_use]
    pub const fn kind(&self) -> ClassKind {
        self.kind
    }
}

/// Verified body progress presented to a lease's optional streaming quota.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedBodyProgress {
    verified_bytes: u64,
    newly_verified_bytes: u64,
}

impl VerifiedBodyProgress {
    pub(crate) const fn new(verified_bytes: u64, newly_verified_bytes: u64) -> Self {
        Self {
            verified_bytes,
            newly_verified_bytes,
        }
    }

    /// Cumulative bytes verified before delivery to the handler.
    #[must_use]
    pub const fn verified_bytes(self) -> u64 {
        self.verified_bytes
    }

    /// Newly verified bytes awaiting delivery to the handler.
    #[must_use]
    pub const fn newly_verified_bytes(self) -> u64 {
        self.newly_verified_bytes
    }
}

/// The opaque refusal returned by a streaming body quota.
///
/// # Security
///
/// Default construction is fail-closed: it represents refusal and carries no request data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BodyQuotaExceeded(());

impl BodyQuotaExceeded {
    /// Refuses further verified body progress.
    #[must_use]
    pub const fn new() -> Self {
        Self(())
    }
}

/// An optional synchronous quota attached to one admitted request.
///
/// The gateway invokes this once for each newly verified run, before exposing that run to the
/// handler. Refusal is terminal; the gateway does not poll or drain the remaining request body.
pub trait BodyQuota: Send + Sync + 'static {
    /// Admits or refuses the next verified run.
    ///
    /// This runs in the body poll path and must return promptly without blocking. A panic is
    /// contained and treated as a refusal.
    fn check(&self, progress: VerifiedBodyProgress) -> Result<(), BodyQuotaExceeded>;
}

impl<T: BodyQuota + ?Sized> BodyQuota for Arc<T> {
    fn check(&self, progress: VerifiedBodyProgress) -> Result<(), BodyQuotaExceeded> {
        (**self).check(progress)
    }
}

/// Permission to proceed, with at most one streaming body quota.
#[must_use = "a lease that is dropped immediately admits the request without limiting it"]
pub struct Lease {
    body_quota: Option<Arc<dyn BodyQuota>>,
}

impl fmt::Debug for Lease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Lease")
            .field("has_body_quota", &self.body_quota.is_some())
            .finish()
    }
}

impl Lease {
    /// Admits the request.
    pub const fn admit() -> Self {
        Self { body_quota: None }
    }

    /// Attaches the only streaming body quota for this request.
    pub fn with_body_quota(mut self, quota: impl BodyQuota) -> Self {
        self.body_quota = Some(Arc::new(quota));
        self
    }

    pub(crate) fn body_quota(&self) -> Option<Arc<dyn BodyQuota>> {
        self.body_quota.clone()
    }
}

/// Decides whether the deployment will do the work this request asks for.
///
/// Held as `Arc<dyn Governor>`, so the async method is a hand-written [`BoxFuture`] (ADR-0002).
/// Asynchronous because a real limiter consults shared state; an implementation that awaits a
/// remote store on this path is buying an availability risk on every request and should say so in
/// its own documentation.
pub trait Governor: Send + Sync + 'static {
    /// Decides one routed request.
    ///
    /// `Err(())` refuses it, and the framework answers `503 SlowDown`. There is no way to return a
    /// different code: a limiter that could choose the status would be able to answer `403`, and
    /// the difference between "you may not" and "not right now" is the one thing a client's retry
    /// logic branches on.
    fn try_acquire<'a>(&'a self, request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>>;
}

impl<T: Governor + ?Sized> Governor for std::sync::Arc<T> {
    fn try_acquire<'a>(&'a self, request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        (**self).try_acquire(request)
    }
}

/// A deployment governor that adds no limit of its own.
///
/// **Not the framework default and not a bypass.** [`crate::ServiceBuilder`] installs
/// [`DefaultGovernor`] first and ANDs a deployment governor after it. Installing this type leaves
/// the mandatory aggregate, per-client, and per-class limits in force.
///
/// # Security
///
/// It is safe only in the narrow sense that it cannot remove the framework governor. It still
/// means the deployment added no authenticated or tenant-specific quota.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unlimited;

impl Governor for Unlimited {
    fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        Box::pin(async { Ok(Lease::admit()) })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RefuseEverything;

    impl Governor for RefuseEverything {
        fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
            Box::pin(async { Err(()) })
        }
    }

    fn request() -> GovernorRequest<'static> {
        GovernorRequest::new("PutObject", None, Some(1 << 30), None, None, ClassKind::Unauthenticated)
    }

    /// Negative — a refusal is expressible, and it is the only failure shape there is.
    #[tokio::test]
    async fn a_governor_can_refuse() {
        assert!(RefuseEverything.try_acquire(&request()).await.is_err());
    }

    /// Negative — the request carries no identity, so a governor cannot be written against one and
    /// then silently see `None` for every caller.
    #[test]
    fn the_question_carries_no_identity() {
        assert!(request().identity().is_none());
    }

    /// Negative — the trait is usable behind `Arc<dyn _>`; that is what ADR-0002's hand-written
    /// `BoxFuture` buys, and an RPITIT method here would not compile.
    #[tokio::test]
    async fn the_trait_is_dyn_compatible() {
        let governor: std::sync::Arc<dyn Governor> = std::sync::Arc::new(Unlimited);
        assert!(governor.try_acquire(&request()).await.is_ok());
    }

    struct CountingQuota(Arc<AtomicUsize>);

    impl BodyQuota for CountingQuota {
        fn check(&self, _progress: VerifiedBodyProgress) -> Result<(), BodyQuotaExceeded> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    /// Negative — replacing a quota cannot create a callback chain that grows with configuration.
    #[test]
    fn a_lease_holds_exactly_one_body_quota() {
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        let lease = Lease::admit()
            .with_body_quota(CountingQuota(Arc::clone(&first)))
            .with_body_quota(CountingQuota(Arc::clone(&second)));

        lease
            .body_quota()
            .expect("the replacement quota")
            .check(VerifiedBodyProgress::new(1, 1))
            .expect("the replacement admits");

        assert_eq!(first.load(Ordering::Relaxed), 0);
        assert_eq!(second.load(Ordering::Relaxed), 1);
    }

    /// Positive — the governor named after admitting everything admits everything.
    #[tokio::test]
    async fn the_unlimited_governor_admits() {
        assert!(Unlimited.try_acquire(&request()).await.is_ok());
    }
}
