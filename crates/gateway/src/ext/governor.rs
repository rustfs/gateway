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
//! hands back ([`Lease`]), and the default [`Unlimited`].
//! NOT responsible for: connection-level back-pressure and idle timeouts, which belong to the
//! server (P7-02) and not here; authorisation, which is a different question with a different
//! answer; or counting anything, which is the implementation's business.
//! Upstream: `rustfs-gateway-core`. Downstream: `crate::service`.
//!
//! # Where the framework calls this, and why it is exactly there
//!
//! **After routing, before a single body byte is read.** Both halves are load-bearing.
//!
//! Earlier than routing, the call has no bucket and no operation, so the only limit expressible is
//! per-connection or per-IP — which `tower`'s own rate-limit layer already does and which is not
//! the dimension an object store needs.
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

use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::Identity;
use rustfs_gateway_types::BucketName;

/// What a [`Governor`] is asked about.
///
/// The identity is `None` here for every request, and that is not an oversight: this runs before
/// authentication, because the point of a limit is to stop work being done, and verifying a
/// signature is work. A deployment that wants a per-identity quota applies it in its
/// [`crate::Authorizer`], which runs after the identity is known.
#[derive(Debug)]
pub struct GovernorRequest<'a> {
    /// The operation routing chose, by its `Operation::NAME`.
    pub operation: &'a str,
    /// The bucket the path addressed, when it addressed one.
    pub bucket: Option<&'a BucketName>,
    /// The body length the request head declared, when HTTP framing gave one.
    ///
    /// `None` for a chunked body. A limit that only fires on a declared length is a limit a client
    /// removes by switching to `Transfer-Encoding: chunked`, so an implementation that cares must
    /// handle the `None` case rather than admitting it.
    pub declared_body_bytes: Option<u64>,
    /// Always `None`. Reserved so that adding the identity later is not a signature change.
    pub identity: Option<&'a Identity>,
}

/// Permission to proceed.
///
/// An opaque token rather than `()` so that the admit path reads as an acquisition. It releases
/// nothing on drop today; when a concurrency limiter needs that, the release goes here and every
/// call site already holds the value it has to hold.
#[derive(Debug)]
#[must_use = "a lease that is dropped immediately admits the request without limiting it"]
pub struct Lease(());

impl Lease {
    /// Admits the request.
    pub const fn admit() -> Self {
        Self(())
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

/// The default governor: every request is admitted.
///
/// # Security
///
/// This default removes a defence rather than opening a door. Assembled with it, the service has
/// no per-bucket and no per-operation quota, so a single caller can occupy every worker the server
/// runs. Connection-level limits are the server's (P7-02) and do not substitute for this: a
/// thousand cheap requests and one expensive one look the same to an accept loop.
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

    struct RefuseEverything;

    impl Governor for RefuseEverything {
        fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
            Box::pin(async { Err(()) })
        }
    }

    fn request() -> GovernorRequest<'static> {
        GovernorRequest {
            operation: "PutObject",
            bucket: None,
            declared_body_bytes: Some(1 << 30),
            identity: None,
        }
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
        assert!(request().identity.is_none());
    }

    /// Negative — the trait is usable behind `Arc<dyn _>`; that is what ADR-0002's hand-written
    /// `BoxFuture` buys, and an RPITIT method here would not compile.
    #[tokio::test]
    async fn the_trait_is_dyn_compatible() {
        let governor: std::sync::Arc<dyn Governor> = std::sync::Arc::new(Unlimited);
        assert!(governor.try_acquire(&request()).await.is_ok());
    }

    /// Positive — the default admits.
    #[tokio::test]
    async fn the_default_admits() {
        assert!(Unlimited.try_acquire(&request()).await.is_ok());
    }
}
