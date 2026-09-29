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

//! Reading a bucket out of a host, on a label boundary, or not at all.
//!
//! Responsible for: [`VirtualHostStyle`] — the [`HostResolver`](crate::HostResolver) that matches
//! a request's host against a configured set of base domains and, when one matches on a **label
//! boundary**, reads the bucket and the region out of the prefix; the [`BaseDomain`] configuration
//! grammar and the [`DomainError`] that refuses a base domain nobody could mean one thing by; and
//! the unconditional path-style fallback for every host that matched nothing.
//! NOT responsible for: deciding the effective host (`rustfs-gateway-http`, once, at acceptance),
//! canonicalising anything for a signature (`rustfs-gateway-sig`, over the raw bytes and never
//! over a value from here), splitting a path (`rustfs_gateway_core::MetaView`), or knowing whether
//! the bucket it named exists — that needs a storage read, which this layer is barred from by
//! being synchronous and holding no handle.
//! Upstream: `crate::ext::host`. Downstream: `crate::service`, and any deployment that installs
//! this through [`ServiceBuilder::host_resolver`](crate::ServiceBuilder::host_resolver).
//!
//! # Why the boundary is the whole point
//!
//! SigV4 covers the `Host` header, and it does not cover *which part of it is the bucket*. So a
//! request can be perfectly signed and still be delivered to a bucket the client never named, if
//! the resolver reads the host wrongly — the signature says nothing about the interpretation.
//!
//! The concrete defect, still open upstream as s3s#648, is matching a configured base domain with
//! `ends_with` and no boundary check. With `mys3.com` configured, `evilnotmys3.com` ends with it,
//! so the characters in front become a bucket name; the attacker picks those characters. Here the
//! character immediately before the suffix must be a `.`, and the negative cases in
//! `crates/gateway/tests/vhost_resolution.rs` are the ones that matter: they assert that a
//! dozen near-miss hosts name **no** bucket at all.
//!
//! # Look-alikes are refused, never guessed
//!
//! Every shape that is not exactly one of the four in the table below falls back to path style.
//! That is not politeness — a resolver that guesses at an unfamiliar prefix is a resolver whose
//! guess an attacker can arrange. `s3s#147`/`#150` decided the same thing for a host that matches
//! nothing: it is path-style, unconditionally, and `s3s#643` is what happens when that fallback is
//! written as an afterthought and stops working the moment any domain is configured.
//!
//! | prefix in front of the base domain | reading |
//! |---|---|
//! | empty | path style — this is `GET /bucket/key` on the endpoint itself |
//! | one label that is a legal bucket name | bucket, no region |
//! | `<bucket>.s3` | bucket, no region |
//! | `<bucket>.s3.<region>` | bucket, and the region label |
//! | anything else | path style |
//!
//! # What this deliberately does not do
//!
//! * **No IDN or punycode mapping.** A host arrives as ASCII (`rustfs-gateway-http` refuses
//!   anything else) and is compared as ASCII. Mapping an A-label to a U-label would give one
//!   bucket two host spellings while the signature covers only the one that was sent, which is the
//!   same many-to-one hazard normalisation causes everywhere else on this path. `xn--` is a
//!   reserved bucket prefix in any case, so an A-label never survives [`BucketName`].
//! * **No forwarded headers.** [`HostQuery`] carries the effective host, the path and the method.
//!   There is no header map, so `X-Forwarded-Host` cannot reach a bucket decision at all; a
//!   deployment that wants to trust a proxy has to say so where the effective host is determined,
//!   not here.
//! * **No normalised value reaches a signature.** This module reads
//!   [`EffectiveHost::host_without_port`], which is lower-cased, root-dot-stripped and port-free.
//!   The canonical request reads `EffectiveHost::raw_for_signing`, which is none of those things.
//!   The two are different types precisely so that the derived value cannot be signed: were it
//!   signed, `b.mys3.com`, `B.MyS3.CoM.` and `b.mys3.com:443` would share one signature (and a
//!   presigned URL on a non-default port would be refused, s3s#438).

use rustfs_gateway_core::TargetKind;
use rustfs_gateway_types::BucketName;

use crate::ext::host::{HostQuery, HostResolver, ResolvedHost, is_ipv4_literal, target_of_path, vhost_hint};

/// The longest base domain this resolver will hold, in bytes.
///
/// 253 is the DNS name ceiling without the root dot. A base domain longer than a whole host name
/// could never match anything, so accepting one would be storing a configuration error.
pub const MAX_BASE_DOMAIN_BYTES: usize = 253;

/// The label that separates a bucket from a region inside a virtual-hosted prefix.
const SERVICE_LABEL: &str = "s3";

/// The longest region label read out of a host.
const MAX_REGION_BYTES: usize = 32;

/// Why a base domain cannot be configured.
///
/// A configuration mistake is refused when the resolver is built, never absorbed at request time:
/// a domain that is silently dropped turns every virtual-hosted request into a path-style one,
/// which is a `501` per request and a green start-up log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DomainError {
    /// The domain was the empty string.
    Empty,
    /// The domain is longer than [`MAX_BASE_DOMAIN_BYTES`].
    TooLong,
    /// The domain holds a byte that may not appear in a host name.
    ///
    /// Non-ASCII, whitespace, a control character, a slash, an `@`, a `:` — anything that would
    /// make this string parse as something other than a bare domain. Ports belong here too: a base
    /// domain is matched against a host whose port has already been removed, so a configured port
    /// could never match and keeping it would be a silent never-match.
    NotADomain,
    /// The domain begins with a dot, ends with one, or holds an empty label.
    ///
    /// `.mys3.com`, `mys3.com.` and `a..b` each have more than one reading across resolvers, and
    /// the reading this one picks would not be the one the operator had in mind.
    EmptyLabel,
    /// The domain is an IP address literal.
    ///
    /// An address has no subdomains, so configuring one can only produce virtual-hosted readings
    /// of hosts that are addresses — which is exactly the defect s3s#147/#150 fixed.
    AddressLiteral,
}

impl DomainError {
    /// A short, constant reason. Carries no byte of the offending configuration.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Empty => "a virtual-hosted base domain may not be empty",
            Self::TooLong => "a virtual-hosted base domain is longer than a host name may be",
            Self::NotADomain => "a virtual-hosted base domain may hold only the bytes a host name may hold, and no port",
            Self::EmptyLabel => "a virtual-hosted base domain may not begin or end with a dot, or hold an empty label",
            Self::AddressLiteral => "a virtual-hosted base domain may not be an IP address literal",
        }
    }
}

impl core::fmt::Display for DomainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.reason())
    }
}

impl core::error::Error for DomainError {}

/// One configured base domain, validated and lower-cased once at assembly.
///
/// Lower-cased here rather than at every comparison: the host side is already normalised by
/// `rustfs-gateway-http`, so doing the same to the configuration means the match is a plain byte
/// comparison and there is no per-request casing to get subtly wrong under a hot path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BaseDomain(Box<str>);

impl BaseDomain {
    /// Validates and normalises one base domain.
    ///
    /// # Errors
    ///
    /// [`DomainError`], one variant per way a domain cannot mean one thing.
    pub fn new(domain: &str) -> Result<Self, DomainError> {
        if domain.is_empty() {
            return Err(DomainError::Empty);
        }
        if domain.len() > MAX_BASE_DOMAIN_BYTES {
            return Err(DomainError::TooLong);
        }
        // The byte set is the DNS one, plus the underscore hosts in the wild carry. Notably absent:
        // `:` (a port never matches, because the host side has already had its port removed), `[`
        // and `]` (a bracketed literal is an address), `/`, `@`, whitespace and every control
        // character.
        if !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
        {
            return Err(DomainError::NotADomain);
        }
        if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
            return Err(DomainError::EmptyLabel);
        }
        if is_ipv4_literal(domain) {
            return Err(DomainError::AddressLiteral);
        }
        Ok(Self(domain.to_ascii_lowercase().into_boxed_str()))
    }

    /// The normalised domain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The part of `host` that sits in front of this domain, when `host` is a subdomain of it.
    ///
    /// `Some("")` when the host *is* the domain — an endpoint request, not a virtual host. `None`
    /// when the domain is not a suffix of the host **on a label boundary**, which is the s3s#648
    /// rule: `evilnotmys3.com` ends with `mys3.com` and is a different domain entirely.
    #[must_use]
    fn prefix_of<'a>(&self, host: &'a str) -> Option<&'a str> {
        if host == self.as_str() {
            return Some("");
        }
        let boundary = host.len().checked_sub(self.as_str().len())?.checked_sub(1)?;
        let (prefix, suffix) = host.split_at_checked(boundary)?;
        // `suffix` starts at the boundary byte, so this single comparison asserts both halves of
        // the rule: the byte in front of the domain is a dot, and what follows it is the domain.
        let rest = suffix.strip_prefix('.')?;
        if rest == self.as_str() { Some(prefix) } else { None }
    }
}

/// Resolves virtual-hosted addressing against a configured set of base domains.
///
/// Holds nothing but the domains: no store, no client, no cache, no clock. That is a type-level
/// property this crate's `tests/purity_guard`-equivalent, `scripts/check_resolver_pure.sh`,
/// asserts over the source — a resolver that could consult a store would let an unauthenticated
/// request drive a storage read, which is both an amplifier and a private-bucket enumeration
/// oracle.
///
/// # Example
///
/// ```
/// use rustfs_gateway::{ServiceBuilder, VirtualHostStyle};
///
/// let resolver = VirtualHostStyle::new(["s3.example.com", "s3.us-east-1.example.com"])?;
/// let builder = ServiceBuilder::new().host_resolver(resolver);
/// # let _ = builder;
/// # Ok::<(), rustfs_gateway::DomainError>(())
/// ```
///
/// # Security
///
/// The default has no trusted base domains, so no unauthenticated `Host` value can select a
/// bucket; requests remain path-style.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VirtualHostStyle {
    /// Sorted longest first, so the first match is the longest one and the answer does not depend
    /// on the order the operator listed them in. With `example.com` and `foo.example.com` both
    /// configured, `b.s3.foo.example.com` is bucket `b` — under the shorter domain the same host
    /// would read `foo` as a region.
    domains: Box<[BaseDomain]>,
}

impl VirtualHostStyle {
    /// Builds a resolver for one or more base domains.
    ///
    /// An empty set is legal and produces a resolver that answers every request path-style, with
    /// the [`VhostHint`](crate::VhostHint) a misaddressed request earns — the same behaviour as
    /// [`PathStyleOnly`](crate::PathStyleOnly), reached deliberately rather than by an empty
    /// configuration file going unnoticed.
    ///
    /// # Errors
    ///
    /// [`DomainError`] for the first domain that is not usable. Refused here, so that a typo is a
    /// start-up failure rather than a per-request `501`.
    pub fn new<I, S>(domains: I) -> Result<Self, DomainError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut parsed = domains
            .into_iter()
            .map(|domain| BaseDomain::new(domain.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        // Longest first, then lexicographic, so two configurations listing the same domains in
        // different orders are the same resolver.
        parsed.sort_by(|left, right| {
            right
                .as_str()
                .len()
                .cmp(&left.as_str().len())
                .then_with(|| left.as_str().cmp(right.as_str()))
        });
        parsed.dedup();
        Ok(Self {
            domains: parsed.into_boxed_slice(),
        })
    }

    /// The configured base domains, longest first.
    pub fn domains(&self) -> impl Iterator<Item = &str> {
        self.domains.iter().map(BaseDomain::as_str)
    }
}

impl HostResolver for VirtualHostStyle {
    fn resolve(&self, query: &HostQuery<'_>) -> ResolvedHost {
        // The normalised host: lower-case, no port, no root dot. Never the bytes a signature was
        // computed over — see the module documentation.
        let host = query.host.host_without_port();

        // An address is not a virtual host, whatever the configuration says. This is checked before
        // the domains rather than left to the domain grammar, because a legal base domain can be a
        // label-boundary suffix of an address: `168.1.1` is not an address, and `192.168.1.1` ends
        // with `.168.1.1`.
        if !host.starts_with('[') && !is_ipv4_literal(host) {
            for domain in &self.domains {
                let Some(prefix) = domain.prefix_of(host) else {
                    continue;
                };
                if let Some((bucket, region)) = split_prefix(prefix) {
                    return ResolvedHost::virtual_hosted(target_of_vhost_path(query.path), bucket, region);
                }
                // The domain matched and the prefix said nothing usable — including the empty
                // prefix, which is the endpoint addressed directly. A shorter configured domain
                // must not get a second, looser reading of the same host, so the search stops.
                return ResolvedHost::standard(target_of_path(query.path));
            }
        }

        // s3s#643: configuring domains must leave every other host exactly as usable as it was.
        ResolvedHost::standard(target_of_path(query.path)).with_diagnostic(vhost_hint(query))
    }
}

/// Reads a bucket and an optional region out of the labels in front of a base domain.
///
/// `None` for every shape not in the module's table, which is what "does not guess" means here.
fn split_prefix(prefix: &str) -> Option<(BucketName, Option<Box<str>>)> {
    if prefix.is_empty() {
        return None;
    }
    let mut labels = prefix.split('.');
    let candidate = labels.next()?;
    let region = match (labels.next(), labels.next(), labels.next()) {
        // `<bucket>`
        (None, _, _) => None,
        // `<bucket>.s3`
        (Some(SERVICE_LABEL), None, _) => None,
        // `<bucket>.s3.<region>`
        (Some(SERVICE_LABEL), Some(region), None) if is_region_label(region) => Some(region),
        // Anything else, including a fourth label and a middle label that is not `s3`.
        _ => return None,
    };
    // `candidate` came out of a `split('.')`, so it holds no dot and `BucketName::is_vhost_safe`
    // is true of everything that gets this far. A dotted bucket name is refused one level up, by
    // the shape table: `mine.dotted.bucket` is three labels whose middle one is not `s3`, so it
    // never reaches here at all. No second predicate is written for it, because a check that
    // cannot fail reads exactly like one that passed.
    let bucket = BucketName::new(candidate).ok()?;
    Some((bucket, region.map(|region| region.to_owned().into_boxed_str())))
}

/// Whether a label could be a region name.
///
/// Deliberately a shape check and not a list: a deployment names its own regions, and a resolver
/// holding an allow-list of AWS region strings would refuse every private one. What it does refuse
/// is a label that is not a plausible name at all, which keeps `a.s3.b_c.example.com` from
/// producing a region nothing downstream can use.
fn is_region_label(label: &str) -> bool {
    if label.is_empty() || label.len() > MAX_REGION_BYTES {
        return false;
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return false;
    }
    let alphanumeric = |byte: Option<u8>| byte.is_some_and(|byte| byte.is_ascii_alphanumeric());
    alphanumeric(label.bytes().next()) && alphanumeric(label.bytes().next_back())
}

/// What a virtual-hosted request's path addresses, given that the bucket came from the host.
///
/// `/` is the bucket itself, and everything else is an object key — the *whole* path, not its
/// first segment. This is the half of the rule that makes `(bucket, key)` have one source:
/// `GET /b2/key` on `bucket.mys3.com` is the object `b2/key` in `bucket`, and never the bucket
/// `b2`.
pub(crate) fn target_of_vhost_path(path: &str) -> TargetKind {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        TargetKind::Bucket
    } else {
        TargetKind::Object
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn domain(text: &str) -> BaseDomain {
        BaseDomain::new(text).expect("the fixture domain is well formed")
    }

    /// Positive — the host is the domain, one label in front of it, and several.
    #[test]
    fn the_prefix_is_everything_in_front_of_the_boundary_dot() {
        let base = domain("mys3.com");
        assert_eq!(base.prefix_of("mys3.com"), Some(""));
        assert_eq!(base.prefix_of("b.mys3.com"), Some("b"));
        assert_eq!(base.prefix_of("b.s3.us-west-2.mys3.com"), Some("b.s3.us-west-2"));
    }

    /// Negative — s3s#648, at the level the bug lives at. Each of these ends with `mys3.com` under
    /// `str::ends_with` and is a different domain.
    #[test]
    fn n_a_suffix_without_a_label_boundary_is_not_a_subdomain() {
        let base = domain("mys3.com");
        for host in [
            "notmys3.com",
            "xmys3.com",
            "amys3.com",
            "evil-notmys3.com",
            // The domain is present here as a whole label sequence, in the middle of the host,
            // where it means nothing. A resolver matching on containment rather than on a suffix
            // boundary reads `victim-bucket` out of this one — the same defect from the other end.
            "victim-bucket.mys3.com.evil.io",
            "mys3.com.evil.io",
        ] {
            assert_eq!(base.prefix_of(host), None, "host {host}");
        }
    }

    /// Negative — a host shorter than the domain, and the empty host, must not index out of range
    /// or wrap around into a match.
    #[test]
    fn n_a_host_shorter_than_the_domain_never_matches() {
        let base = domain("mys3.com");
        for host in ["", ".", "com", "s3.com", "ys3.com"] {
            assert_eq!(base.prefix_of(host), None, "host {host}");
        }
    }

    /// Negative — the prefix table refuses every shape it does not recognise, rather than picking
    /// a label.
    #[test]
    fn n_an_unrecognised_prefix_shape_yields_no_bucket() {
        for prefix in [
            "",
            "ab",
            "_bad_",
            "a.b",
            "a.b.c",
            "bucket.s3.us-west-2.extra",
            "bucket.s3.bad_region",
            "bucket.s3.",
            ".bucket",
            "mine.dotted.bucket",
        ] {
            assert!(split_prefix(prefix).is_none(), "prefix {prefix}");
        }
    }

    /// Positive — the three shapes that do resolve, and the region that comes with the third.
    #[test]
    fn the_three_recognised_prefix_shapes_resolve() {
        let (bucket, region) = split_prefix("conf-host").expect("one label is a bucket");
        assert_eq!(bucket.as_str(), "conf-host");
        assert_eq!(region, None);

        let (bucket, region) = split_prefix("conf-host.s3").expect("the s3 infix form is a bucket");
        assert_eq!(bucket.as_str(), "conf-host");
        assert_eq!(region, None);

        let (bucket, region) = split_prefix("conf-host.s3.us-west-2").expect("the region form is a bucket");
        assert_eq!(bucket.as_str(), "conf-host");
        assert_eq!(region.as_deref(), Some("us-west-2"));
    }

    /// Negative — a region label that is not a plausible name is not carried out as one.
    #[test]
    fn n_an_implausible_region_label_is_refused() {
        for label in [
            "",
            "-lead",
            "trail-",
            "UPPER",
            "under_score",
            &"x".repeat(MAX_REGION_BYTES + 1),
        ] {
            assert!(!is_region_label(label), "label {label}");
        }
    }

    /// Positive — the labels a private deployment actually uses.
    #[test]
    fn plausible_region_labels_are_accepted() {
        for label in ["us-west-2", "eu-central-1", "local", "r1"] {
            assert!(is_region_label(label), "label {label}");
        }
    }

    /// Negative — configuration is validated once, and a mistake is an error rather than a domain
    /// that quietly matches nothing.
    #[test]
    fn n_configuration_mistakes_are_refused() {
        assert_eq!(BaseDomain::new(""), Err(DomainError::Empty));
        assert_eq!(BaseDomain::new(&"a.".repeat(200)), Err(DomainError::TooLong));
        assert_eq!(BaseDomain::new("mys3.com:9000"), Err(DomainError::NotADomain));
        assert_eq!(BaseDomain::new("[2001:db8::1]"), Err(DomainError::NotADomain));
        assert_eq!(BaseDomain::new("my s3.com"), Err(DomainError::NotADomain));
        assert_eq!(BaseDomain::new(".mys3.com"), Err(DomainError::EmptyLabel));
        assert_eq!(BaseDomain::new("mys3.com."), Err(DomainError::EmptyLabel));
        assert_eq!(BaseDomain::new("mys3..com"), Err(DomainError::EmptyLabel));
        assert_eq!(BaseDomain::new("192.168.1.1"), Err(DomainError::AddressLiteral));
    }

    /// Positive — the domains are held longest-first, whatever order they were listed in.
    #[test]
    fn the_domains_are_ordered_longest_first() {
        let one = VirtualHostStyle::new(["example.com", "foo.example.com"]).expect("both are well formed");
        let other = VirtualHostStyle::new(["foo.example.com", "example.com"]).expect("both are well formed");
        assert_eq!(one.domains().collect::<Vec<_>>(), ["foo.example.com", "example.com"]);
        assert_eq!(one, other);
    }

    /// Negative — a path on a virtual host is all key, and `/` is the bucket. A first segment read
    /// as a bucket here would be the second source of truth this whole module exists to remove.
    #[test]
    fn n_a_virtual_hosted_path_is_never_split_for_a_bucket() {
        assert_eq!(target_of_vhost_path("/"), TargetKind::Bucket);
        assert_eq!(target_of_vhost_path(""), TargetKind::Bucket);
        assert_eq!(target_of_vhost_path("/key"), TargetKind::Object);
        assert_eq!(target_of_vhost_path("/b2/key"), TargetKind::Object);
        assert_eq!(target_of_vhost_path("//"), TargetKind::Object);
    }
}
