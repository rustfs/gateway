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

//! What the request path addresses, and which endpoint family it arrived on.
//!
//! Responsible for: [`HostResolver`] — the one component that classifies a request into the
//! [`TargetKind`], [`HostClass`] and [`ArnForm`] the route table matches on — the question it is
//! asked ([`HostQuery`]), its answer ([`ResolvedHost`]), and the default [`PathStyleOnly`].
//! NOT responsible for: deciding the effective host, which `rustfs-gateway-http` did once at
//! acceptance and which this consumes; matching any route predicate
//! (`rustfs_gateway_core::route`); or percent-decoding anything.
//! Upstream: `rustfs-gateway-http`, `rustfs-gateway-core`. Downstream: `crate::service`.
//!
//! # Why this one is synchronous when ADR-0002 makes extension points asynchronous
//!
//! It runs on the pre-authentication path, before the security floor. `rustfs-gateway-core`'s
//! `tests/purity_guard.rs` asserts over its own source that nothing on that path awaits, holds a
//! store handle or allocates per request, and the reason is not tidiness: a resolver that could
//! await turns an unauthenticated request into work the deployment does on the caller's behalf,
//! which is an amplifier. So the answer is computed from the head, in constant time, with no I/O.
//! A deployment whose host-to-bucket mapping genuinely lives in a database must snapshot it into
//! the resolver at assembly time.
//!
//! # What the default cannot do, and what that costs
//!
//! [`PathStyleOnly`] reads the path and ignores the host entirely. A virtual-hosted request —
//! `Host: bucket.example.com`, `GET /key` — is therefore classified as a *bucket* named `key`, and
//! routes to whatever operation that shape names. That is not a security hole, because every
//! decision downstream is made about the bucket the resolver named; it is a functional gap, and it
//! is why `rustfs_gateway_core::dispatch::NO_ROUTE_MESSAGE` tells an operator to check the
//! configured domain first.

use http::Method;
use rustfs_gateway_core::{ArnForm, HostClass, TargetKind};
use rustfs_gateway_http::EffectiveHost;

/// What a [`HostResolver`] is asked about.
///
/// Every field is borrowed and every one of them was already determined at acceptance. There is
/// deliberately no body, no header map and no query: a resolver that read a header would be a
/// second place where routing is decided.
#[derive(Debug)]
pub struct HostQuery<'a> {
    /// The one effective host, decided once by `rustfs-gateway-http`.
    pub host: &'a EffectiveHost,
    /// The request path, still percent-encoded.
    pub path: &'a str,
    /// The request method.
    pub method: &'a Method,
}

/// How a request was classified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedHost {
    /// What the path addresses.
    pub target: TargetKind,
    /// Which endpoint family the request arrived on.
    pub host_class: HostClass,
    /// The ARN shape in the bucket position, when there is one.
    pub arn_form: Option<ArnForm>,
}

impl ResolvedHost {
    /// A request on the ordinary REST endpoint with no ARN in the bucket position.
    #[must_use]
    pub const fn standard(target: TargetKind) -> Self {
        Self {
            target,
            host_class: HostClass::Standard,
            arn_form: None,
        }
    }
}

/// Classifies one request into the dimensions the route table matches on.
///
/// Synchronous; see the module documentation for why. Held as `Arc<dyn HostResolver>` so that a
/// deployment can install its own without the service becoming generic over it.
pub trait HostResolver: Send + Sync + 'static {
    /// Classifies one request.
    ///
    /// Infallible on purpose. A host this deployment does not serve is still a request that has to
    /// be answered, and answering it is routing's job: a resolver that could refuse would be a
    /// second rejection surface in front of the route table, with its own status code and its own
    /// message, for a decision the table already makes.
    fn resolve(&self, query: &HostQuery<'_>) -> ResolvedHost;
}

impl<T: HostResolver + ?Sized> HostResolver for std::sync::Arc<T> {
    fn resolve(&self, query: &HostQuery<'_>) -> ResolvedHost {
        (**self).resolve(query)
    }
}

/// The default resolver: the path decides, and the host is not consulted.
///
/// # Security
///
/// This default cannot widen access — every downstream decision, authorisation included, is made
/// about the bucket and key it names. What it does is fail to understand virtual-hosted addressing,
/// so a deployment that serves `bucket.example.com` and installs nothing will route those requests
/// by their path and answer many of them `501`. See the module documentation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathStyleOnly;

impl HostResolver for PathStyleOnly {
    fn resolve(&self, query: &HostQuery<'_>) -> ResolvedHost {
        ResolvedHost::standard(target_of_path(query.path))
    }
}

/// Which kind of resource a path-style request target addresses.
///
/// `/` is the service, `/bucket` and `/bucket/` are a bucket, and anything with a non-empty
/// segment after the first slash is an object. The trailing-slash case matters: `/bucket/` and
/// `/bucket` are the same request to S3, and classifying the first as an object named the empty
/// string would route it to an operation whose key cannot be decoded.
#[must_use]
fn target_of_path(path: &str) -> TargetKind {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    match trimmed.split_once('/') {
        None if trimmed.is_empty() => TargetKind::Service,
        None => TargetKind::Bucket,
        Some((bucket, key)) if key.is_empty() && !bucket.is_empty() => TargetKind::Bucket,
        Some(("", _)) => TargetKind::Service,
        Some(_) => TargetKind::Object,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn resolve(path: &str) -> TargetKind {
        target_of_path(path)
    }

    /// Positive — the three shapes the route table's `Target` predicate distinguishes.
    #[test]
    fn the_three_target_shapes_are_classified() {
        assert_eq!(resolve("/"), TargetKind::Service);
        assert_eq!(resolve("/bucket"), TargetKind::Bucket);
        assert_eq!(resolve("/bucket/key"), TargetKind::Object);
    }

    /// Negative — `/bucket/` is a bucket, not an object whose key is empty. An object target here
    /// would route to an operation whose key decode then fails with a 400 the caller cannot fix.
    #[test]
    fn a_trailing_slash_does_not_invent_an_object() {
        assert_eq!(resolve("/bucket/"), TargetKind::Bucket);
    }

    /// Negative — a doubled leading slash names no bucket, so it must not be classified as one.
    #[test]
    fn a_doubled_leading_slash_is_not_a_bucket() {
        assert_eq!(resolve("//"), TargetKind::Service);
        assert_eq!(resolve("//key"), TargetKind::Service);
    }

    /// Negative — a deep path is one object, not a nested bucket: only the first segment is a
    /// bucket label and everything after it is the key.
    #[test]
    fn a_deep_path_is_still_one_object() {
        assert_eq!(resolve("/bucket/a/b/c"), TargetKind::Object);
    }

    /// Negative — the default ignores the host, which is the documented gap rather than a bug to
    /// be discovered later. A virtual-hosted spelling classifies by its path.
    #[test]
    fn the_default_resolver_does_not_read_the_host() {
        let request = http::Request::builder()
            .method(Method::GET)
            .uri("/key")
            .header("host", "bucket.example.com")
            .body(())
            .expect("a valid request");
        let host = rustfs_gateway_http::effective_host(&request).expect("a valid host");
        let resolved = PathStyleOnly.resolve(&HostQuery {
            host: &host,
            path: "/key",
            method: &Method::GET,
        });
        assert_eq!(resolved.target, TargetKind::Bucket);
        assert_eq!(resolved.host_class, HostClass::Standard);
    }
}
