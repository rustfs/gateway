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
//! Responsible for: [`Authorizer`], the request it is asked about ([`AuthzRequest`]), the one
//! refusal it may produce ([`Denial`]), and the closure adapter ADR-0002 requires every
//! `BoxFuture` extension point to ship ([`allow_when`]).
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
//! [`Denial`] carries a code and nothing derived from the request. An authorisation refusal is
//! answered to a caller whose identity is known but whose permission is not, and a refusal that
//! explained which condition failed would let that caller map the policy one request at a time.

use rustfs_gateway_core::{BoxFuture, ResourceShape};
use rustfs_gateway_sig::Identity;
use rustfs_gateway_types::{BucketName, ErrorCode, ObjectKey};

/// What an [`Authorizer`] is asked about.
///
/// Borrowed throughout: the whole value lives for one call and copying an object key per request
/// to hand it to a policy engine is a per-request allocation the engine does not need.
#[derive(Debug)]
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
    /// Who the request runs as. `None` for an anonymous request, which is a request that presented
    /// nothing and was confirmed to have presented nothing — never a request whose verification
    /// failed.
    pub identity: Option<&'a Identity>,
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

/// Why an authorizer refused.
///
/// Two codes, and the choice between them is the one distinction S3 clients act on: `AccessDenied`
/// means "you are known and this is not allowed", `NoSuchBucket` is the answer a policy may prefer
/// for a bucket whose existence the caller is not allowed to learn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial {
    code: ErrorCode,
}

impl Denial {
    /// `403 AccessDenied`. The ordinary refusal.
    #[must_use]
    pub fn access_denied() -> Self {
        Self {
            code: ErrorCode::ACCESS_DENIED,
        }
    }

    /// A refusal with a code the deployment chose.
    ///
    /// Provided because hiding a bucket's existence behind `404 NoSuchBucket` is a legitimate
    /// policy outcome and not an error. It carries no message: see the module documentation.
    #[must_use]
    pub fn with_code(code: ErrorCode) -> Self {
        Self { code }
    }

    /// The code this refusal is answered with.
    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }
}

impl Default for Denial {
    fn default() -> Self {
        Self::access_denied()
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
    /// Decides one request.
    ///
    /// Returning `Ok(())` permits it. Any error refuses it; there is no third answer, because
    /// "abstain" would have to mean either allow or deny and whichever it meant would be invisible
    /// at the call site.
    fn authorize<'a>(&'a self, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Result<(), Denial>>;
}

impl<T: Authorizer + ?Sized> Authorizer for std::sync::Arc<T> {
    fn authorize<'a>(&'a self, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Result<(), Denial>> {
        (**self).authorize(request)
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
    struct FnAuthorizer<F>(F);

    impl<F> Authorizer for FnAuthorizer<F>
    where
        F: Fn(&AuthzRequest<'_>) -> bool + Send + Sync + 'static,
    {
        fn authorize<'a>(&'a self, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Result<(), Denial>> {
            let outcome = if (self.0)(request) {
                Ok(())
            } else {
                Err(Denial::access_denied())
            };
            Box::pin(async move { outcome })
        }
    }

    FnAuthorizer(predicate)
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
            identity,
        }
    }

    /// Negative — the closure adapter refuses when the predicate is false, and the refusal is the
    /// ordinary 403 rather than something a caller can mistake for a routing failure.
    #[tokio::test]
    async fn a_false_predicate_refuses_with_access_denied() {
        let authorizer = allow_when(|request| request.operation == "ListBuckets");
        let denial = authorizer
            .authorize(&request("GetObject", None))
            .await
            .expect_err("the predicate is false");
        assert_eq!(denial.code(), &ErrorCode::ACCESS_DENIED);
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
        assert!(authorizer.authorize(&request("GetObject", None)).await.is_ok());
    }
}
