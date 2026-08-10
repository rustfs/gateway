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
//! asked ([`HostQuery`]), its answer ([`ResolvedHost`]) with the [`Addressing`] that says whether
//! the bucket came from the host or from the path, the [`VhostHint`] a misaddressed request earns,
//! and the default [`PathStyleOnly`].
//! NOT responsible for: matching a host against a configured base domain, which is
//! [`crate::VirtualHostStyle`]'s; deciding the effective host, which `rustfs-gateway-http` did once
//! at acceptance and which this consumes; matching any route predicate
//! (`rustfs_gateway_core::route`); or percent-decoding anything.
//! Upstream: `rustfs-gateway-http`, `rustfs-gateway-core`. Downstream: `crate::service`,
//! `crate::ext::vhost`.
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
//! [`PathStyleOnly`] takes the bucket from the path and never from the host. A virtual-hosted
//! request — `Host: bucket.example.com`, `GET /key` — is therefore classified as a *bucket* named
//! `key`, and routes to whatever operation that shape names. That is not a security hole, because
//! every decision downstream is made about the bucket the resolver named; it is a functional gap,
//! and [`crate::VirtualHostStyle`] is what a deployment installs to close it.
//!
//! The default does read the host for one thing, and only one: raising a [`VhostHint`] when a
//! request that plainly meant to be virtual-hosted arrives at a deployment that understands no
//! such domain. The hint is a sentence, never an input — [`ResolvedHost::addressing`] is decided
//! before it is computed and is not revisited afterwards.

use http::Method;
use rustfs_gateway_core::{ArnForm, HostClass, TargetKind};
use rustfs_gateway_http::EffectiveHost;
use rustfs_gateway_types::BucketName;

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

/// Where the bucket a request addresses was read from.
///
/// Recorded rather than inferred later, because "this bucket name came out of the `Host` header"
/// is the single most useful fact in an audit trail of a routing dispute: the path is visible in
/// every access log, and the host that reinterpreted it usually is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TargetOrigin {
    /// The bucket came from the host, virtual-hosted style.
    Host,
    /// The bucket came from the path, or there is no bucket.
    Path,
}

impl TargetOrigin {
    /// A short, stable label for logs and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Path => "path",
        }
    }
}

/// How the request named its bucket.
///
/// There is no `bucket` field beside a `style` flag, and no `origin` field beside either: a value
/// that can say "path-style" while carrying a host-derived bucket is a value two readers will
/// disagree about. [`ResolvedHost::origin`] is computed from this, so it cannot drift from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addressing {
    /// The bucket, if any, is the first path segment.
    Path,
    /// The host named the bucket, so the whole path is the object key.
    VirtualHosted {
        /// The bucket the host named. Always a name [`BucketName`] accepts.
        bucket: BucketName,
        /// The region label the host carried, when it carried one.
        ///
        /// A `&str` rather than a typed region: this crate has no region vocabulary, and the one
        /// in `rustfs-gateway-sig` is the set a deployment *signs* for, which is a different
        /// question from the one a host answers.
        region: Option<Box<str>>,
    },
}

/// A readable reason a request that looks virtual-hosted did not resolve as one.
///
/// Rendered into an error message and into logs, and into nothing else. Every variant's text is a
/// **constant**: this value is produced before the request has been authenticated, so a message
/// built from it must not carry one byte the caller chose. Naming the host back at an unauthenticated
/// peer is how a refusal becomes a reflection primitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VhostHint {
    /// The host's first label is a legal bucket name, the path names no bucket, and no configured
    /// base domain matched — so the caller almost certainly meant virtual-hosted addressing and
    /// this deployment does not serve that domain.
    LooksLikeVhostButNotConfigured,
}

impl VhostHint {
    /// The fixed sentence this hint renders as.
    ///
    /// Fixed in the strong sense: it takes no arguments, so there is no interpolation site for a
    /// later change to widen.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::LooksLikeVhostButNotConfigured => {
                "This request addresses a bucket as a virtual host, and this gateway serves no base \
                 domain that the host of the request belongs to. Configure the virtual-hosted base \
                 domains this deployment answers for, or address the bucket in the request path."
            }
        }
    }

    /// A short, stable label for logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LooksLikeVhostButNotConfigured => "vhost-not-configured",
        }
    }
}

/// How a request was classified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedHost {
    /// What the path addresses.
    pub target: TargetKind,
    /// Which endpoint family the request arrived on.
    pub host_class: HostClass,
    /// The ARN shape in the bucket position, when there is one.
    pub arn_form: Option<ArnForm>,
    /// Whether the bucket came from the host or from the path.
    pub addressing: Addressing,
    /// A readable reason, when the classification is likely not what the caller wanted.
    ///
    /// Consumed by `crate::service` for the message of a request that then failed to route, and by
    /// nothing that decides anything.
    pub diagnostic: Option<VhostHint>,
}

impl ResolvedHost {
    /// A path-style request on the ordinary REST endpoint with no ARN in the bucket position.
    #[must_use]
    pub const fn standard(target: TargetKind) -> Self {
        Self {
            target,
            host_class: HostClass::Standard,
            arn_form: None,
            addressing: Addressing::Path,
            diagnostic: None,
        }
    }

    /// A virtual-hosted request whose bucket the host named.
    #[must_use]
    pub const fn virtual_hosted(target: TargetKind, bucket: BucketName, region: Option<Box<str>>) -> Self {
        Self {
            target,
            host_class: HostClass::Standard,
            arn_form: None,
            addressing: Addressing::VirtualHosted { bucket, region },
            diagnostic: None,
        }
    }

    /// The same classification carrying a hint.
    #[must_use]
    pub fn with_diagnostic(mut self, hint: Option<VhostHint>) -> Self {
        self.diagnostic = hint;
        self
    }

    /// Where the bucket came from. Read off [`ResolvedHost::addressing`], never stored beside it.
    #[must_use]
    pub const fn origin(&self) -> TargetOrigin {
        match self.addressing {
            Addressing::Path => TargetOrigin::Path,
            Addressing::VirtualHosted { .. } => TargetOrigin::Host,
        }
    }

    /// The bucket the *host* named, when the host named one.
    ///
    /// `None` for every path-style request, including the ones whose path does name a bucket:
    /// splitting a path is `rustfs_gateway_core::MetaView`'s job and this is not a second copy of
    /// the answer.
    #[must_use]
    pub const fn bucket(&self) -> Option<&BucketName> {
        match &self.addressing {
            Addressing::Path => None,
            Addressing::VirtualHosted { bucket, .. } => Some(bucket),
        }
    }

    /// The region label the host carried, when it carried one.
    #[must_use]
    pub fn region(&self) -> Option<&str> {
        match &self.addressing {
            Addressing::Path => None,
            Addressing::VirtualHosted { region, .. } => region.as_deref(),
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

/// The default resolver: the path decides which bucket, and the host names none.
///
/// # Security
///
/// This default cannot widen access — every downstream decision, authorisation included, is made
/// about the bucket and key it names. What it does is fail to understand virtual-hosted addressing,
/// so a deployment that serves `bucket.example.com` and installs nothing will route those requests
/// by their path and answer many of them `501` — with [`VhostHint`]'s sentence rather than a bare
/// "no such operation", which is the whole of what the host is read for here. See the module
/// documentation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathStyleOnly;

impl HostResolver for PathStyleOnly {
    fn resolve(&self, query: &HostQuery<'_>) -> ResolvedHost {
        // No domain is configured at all, so every host is an unmatched one and the hint's
        // preconditions are the only thing left to check.
        ResolvedHost::standard(target_of_path(query.path)).with_diagnostic(vhost_hint(query))
    }
}

/// Whether an unmatched host and a path with no bucket in it look like a virtual-hosted request
/// that arrived at a deployment which serves no such domain.
///
/// Four conditions, all required, and each of them is there to keep the hint from being noise:
///
/// * the path names no bucket — `/` and nothing else, because a caller who wrote a bucket into the
///   path meant path style;
/// * the method is one that addresses a bucket root — `PUT` creates one, `DELETE` removes one,
///   `GET` lists or reads a bucket sub-resource. `POST` and `HEAD` on `/` are not that request;
/// * the host has a label in front of something — one bare label has no bucket position;
/// * that first label is a name a bucket could actually have.
///
/// It is deliberately computed from the same [`HostQuery`] the resolution was, and deliberately
/// returns a value rather than a message: the caller decides whether a sentence is even rendered,
/// and the sentence itself is a constant.
pub(crate) fn vhost_hint(query: &HostQuery<'_>) -> Option<VhostHint> {
    if query.path != "/" {
        return None;
    }
    if !matches!(*query.method, Method::PUT | Method::DELETE | Method::GET) {
        return None;
    }
    let host = query.host.host_without_port();
    // An address is never a virtual host, so a request to one is not a misconfiguration.
    if host.starts_with('[') || is_ipv4_literal(host) {
        return None;
    }
    let (first, rest) = host.split_once('.')?;
    if rest.is_empty() {
        return None;
    }
    BucketName::new(first).ok().map(|_| VhostHint::LooksLikeVhostButNotConfigured)
}

/// Whether a host is four dot-separated runs of decimal digits — an IPv4 address, written out.
///
/// Shared with [`crate::ext::vhost`], where it is a security rule rather than a hint suppressor:
/// s3s#147/#150 are the case of an address being read as a virtual host and producing a bucket the
/// client never named.
pub(crate) fn is_ipv4_literal(host: &str) -> bool {
    let mut octets = 0usize;
    for part in host.split('.') {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        octets = octets.saturating_add(1);
    }
    octets == 4
}

/// Which kind of resource a path-style request target addresses.
///
/// `/` is the service, `/bucket` and `/bucket/` are a bucket, and anything with a non-empty
/// segment after the first slash is an object. The trailing-slash case matters: `/bucket/` and
/// `/bucket` are the same request to S3, and classifying the first as an object named the empty
/// string would route it to an operation whose key cannot be decoded.
#[must_use]
pub(crate) fn target_of_path(path: &str) -> TargetKind {
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

    /// a-asm-0005. Negative — the default ignores the host, which is the documented gap rather than a bug to
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
