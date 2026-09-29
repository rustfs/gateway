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

//! Virtual-hosted addressing as legacy RustFS reads it (rustfs/gateway#1136): RustFS's domain list,
//! matched with ports ignored, the whole prefix as the bucket, and the CNAME-style fallback.
//!
//! Responsible for: [`LegacyRustfsVirtualHosts`], the RustFS profile's
//! [`HostResolver`](crate::HostResolver), and [`LegacyDomainError`], the start-up refusal of a
//! domain list RustFS itself would refuse.
//! NOT responsible for: the default resolvers ([`crate::VirtualHostStyle`],
//! [`crate::PathStyleOnly`]), the path split, or where a refusal is answered
//! (`crate::legacy_addressing`).
//! Upstream: `crate::ext::host`. Downstream: a RustFS-profile assembly's host resolver.
//!
//! # What legacy RustFS does, measured on a legacy build
//!
//! RustFS keeps each configured domain as written, a listener port included, and drops a later
//! entry whose name without its port repeats an earlier one's (`rustfs/src/server/http.rs:175-192`
//! on rustfs/rustfs `e870a6d25b`, rustfs/rustfs#7051); a domain that is not one, or that equals or
//! is a subdomain of another, stops it at start-up. A host that is an IP address or a socket
//! address is read path-style. Otherwise, with the port ignored on both sides, a host equal to a
//! domain is read path-style, and a host ending in `.` and a domain names the bucket in front of
//! it — the whole prefix, dots and case kept, judged by the bucket rules afterwards. A host no
//! domain matches is refused `400 InvalidRequest` unless it is a domain (labels of letters, digits
//! and `-`, an optional port); a domain that, lower-cased, is a bucket name is that bucket
//! (CNAME-style addressing), and any other is read path-style — `localhost:9000` among them,
//! because a port is never part of a bucket name. With no domain configured, every host is read
//! path-style, exactly as [`crate::PathStyleOnly`] reads it.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rustfs_gateway_types::{BucketName, LegacyRustfsNameValidator, NamePolicy};

use crate::ext::host::{HostQuery, HostRefusal, HostResolver, ResolvedHost, target_of_path, vhost_hint};
use crate::ext::vhost::target_of_vhost_path;

/// Why a domain list cannot be what legacy RustFS reads hosts against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LegacyDomainError {
    /// An entry is not a domain: an empty label, a byte other than a letter, a digit, `-` or `.`,
    /// or a port that is not a 16-bit number.
    NotADomain,
    /// Two entries name the same host, or one is a subdomain of another, once ports are ignored.
    Overlapping,
}

impl std::fmt::Display for LegacyDomainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NotADomain => "a server domain must be a domain name, with an optional port",
            Self::Overlapping => "two server domains name the same host, or one is a subdomain of another",
        })
    }
}

impl std::error::Error for LegacyDomainError {}

/// Reads virtual-hosted addressing as legacy RustFS reads it, for a deployment in front of RustFS.
///
/// Built from the same list RustFS reads `RUSTFS_SERVER_DOMAINS` into; see the module
/// documentation for what it reads, and [`crate::HostResolver::refusal`] for the two refusals it
/// makes. A bucket a host names is held to legacy RustFS's bucket rules
/// ([`LegacyRustfsNameValidator`]).
///
/// Legacy-compat (rustfs/backlog#2684): the whole prefix in front of a domain as the bucket, and
/// any bucket-shaped host outside every domain as a bucket of its own, let a host select a bucket
/// its owner never configured, and give one bucket as many spellings as it has dotted names. Kept
/// so a RustFS client's host reaches the bucket it reaches today; the intended future behaviour is
/// [`crate::VirtualHostStyle`], whose reading is label-exact and has no fallback.
#[derive(Clone, Debug)]
pub struct LegacyRustfsVirtualHosts {
    /// As configured, ports kept, in order, a later repeat of a name dropped.
    domains: Box<[Box<str>]>,
    /// Legacy RustFS's bucket rules, which a host-named bucket is materialised under.
    names: NamePolicy,
}

/// How legacy RustFS reads one host.
enum Reading<'a> {
    /// Path-style: the bucket, if any, is the path's.
    Path,
    /// The host names this bucket, not yet judged.
    Bucket(Cow<'a, str>),
    /// The host is no domain: `400 InvalidRequest`.
    Unusable,
}

impl LegacyRustfsVirtualHosts {
    /// Builds the reading of one RustFS domain list.
    ///
    /// # Errors
    ///
    /// [`LegacyDomainError`] for an entry legacy RustFS would refuse at start-up.
    pub fn new<I, S>(domains: I) -> Result<Self, LegacyDomainError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = BTreeSet::new();
        let mut kept: Vec<Box<str>> = Vec::new();
        for domain in domains {
            let domain = domain.as_ref();
            if seen.insert(strip_port(domain).to_owned()) {
                kept.push(domain.into());
            }
        }
        for (index, domain) in kept.iter().enumerate() {
            if !is_domain(domain) {
                return Err(LegacyDomainError::NotADomain);
            }
            if kept.iter().take(index).any(|earlier| overlaps(domain, earlier)) {
                return Err(LegacyDomainError::Overlapping);
            }
        }
        Ok(Self {
            domains: kept.into_boxed_slice(),
            names: NamePolicy::default().with_validator(Arc::new(LegacyRustfsNameValidator)),
        })
    }

    /// The configured domains, as kept.
    pub fn domains(&self) -> impl Iterator<Item = &str> {
        self.domains.iter().map(AsRef::as_ref)
    }

    fn read<'a>(&self, host: &'a str) -> Reading<'a> {
        if self.domains.is_empty() || host.parse::<SocketAddr>().is_ok() || host.parse::<IpAddr>().is_ok() {
            return Reading::Path;
        }
        let bare = strip_port(host);
        for domain in &self.domains {
            let base = strip_port(domain);
            if bare == base {
                return Reading::Path;
            }
            if let Some(bucket) = bare.strip_suffix(base).and_then(|prefix| prefix.strip_suffix('.')) {
                return Reading::Bucket(Cow::Borrowed(bucket));
            }
        }
        if !is_domain(host) {
            return Reading::Unusable;
        }
        let lower = host.to_ascii_lowercase();
        if BucketName::materialize(&lower, &self.names).is_ok() {
            Reading::Bucket(Cow::Owned(lower))
        } else {
            Reading::Path
        }
    }
}

impl HostResolver for LegacyRustfsVirtualHosts {
    fn resolve(&self, query: &HostQuery<'_>) -> ResolvedHost {
        match self.read(query.host.raw_for_signing().as_str()) {
            Reading::Bucket(label) => match BucketName::materialize(&label, &self.names) {
                Ok(bucket) => ResolvedHost::virtual_hosted(target_of_vhost_path(query.path), bucket, None),
                // Refused by `refusal`, before this reading is routed.
                Err(_) => ResolvedHost::standard(target_of_path(query.path)),
            },
            Reading::Unusable => ResolvedHost::standard(target_of_path(query.path)),
            // With no domain configured legacy RustFS's hint for a misaddressed request applies,
            // as it does to `PathStyleOnly`; with one, it does not.
            Reading::Path if self.domains.is_empty() => {
                ResolvedHost::standard(target_of_path(query.path)).with_diagnostic(vhost_hint(query))
            }
            Reading::Path => ResolvedHost::standard(target_of_path(query.path)),
        }
    }

    fn refusal(&self, query: &HostQuery<'_>) -> Option<HostRefusal> {
        match self.read(query.host.raw_for_signing().as_str()) {
            Reading::Unusable => Some(HostRefusal::UnusableHost),
            Reading::Bucket(label) if BucketName::materialize(&label, &self.names).is_err() => Some(HostRefusal::RefusedBucket),
            Reading::Bucket(_) | Reading::Path => None,
        }
    }
}

/// `host` without a trailing `:<port>` that is a 16-bit number; a bracketed address is kept whole.
fn strip_port(host: &str) -> &str {
    if host.ends_with(']') {
        return host;
    }
    match host.rsplit_once(':') {
        Some((name, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) && port.parse::<u16>().is_ok() =>
        {
            name
        }
        _ => host,
    }
}

/// Whether `text` is a domain as legacy RustFS reads one: dot-separated non-empty labels of ASCII
/// letters, digits and `-`, and at most one `:` followed by a 16-bit port.
fn is_domain(text: &str) -> bool {
    let name = match text.split_once(':') {
        Some((name, port)) if !port.is_empty() && port.parse::<u16>().is_ok() => name,
        Some(_) => return false,
        None => text,
    };
    !name.is_empty()
        && name
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
}

/// Whether two domains compete for one host: equal once ports are ignored, or one a subdomain of
/// the other on a label boundary.
fn overlaps(one: &str, other: &str) -> bool {
    let (one, other) = (strip_port(one), strip_port(other));
    let under = |host: &str, base: &str| host.strip_suffix(base).is_some_and(|prefix| prefix.ends_with('.'));
    one == other || under(one, other) || under(other, one)
}

#[cfg(test)]
#[path = "legacy_vhost_tests.rs"]
mod tests;
