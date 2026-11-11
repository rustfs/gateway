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

//! A host-verified header token claim (ADR-0051, rustfs/gateway#1586).
//!
//! Responsible for: [`HeaderTokenClaim`] (the service-level opt-in: one lowercase header name,
//! and the alias names of it that are refused wherever they appear),
//! [`HeaderTokenAdmission`] (the sealed result of the floor admitting a request by that claim),
//! the host's [`HeaderTokenVerifier`] trust boundary and the [`HeaderTokenReceipt`] only a
//! verification produces.
//! NOT responsible for: validating the token, its replay policy, expiry or revocation — the
//! host's outer layer did that before the gateway ran, and the verifier only reports the identity
//! that layer established — or authorization, which still runs on the receipt's principal.
//! Upstream: [`crate::SecurityFloor::admit`], the only producer of a [`HeaderTokenAdmission`].
//! Downstream: [`crate::Verdict::HeaderToken`], and the facade, which installs the claim and the
//! verifier together and removes the claimed header from the request head before acceptance.
//!
//! # Why a claim and not an anonymous request
//!
//! A host whose outer layer authenticated a non-AWS token (OpenStack Keystone's `X-Auth-Token`)
//! serves the request as that token's user. Admitting the request as anonymous would have the
//! governor, both authorization stages and the audit record judge it as nobody. The claim instead
//! admits it only as far as the host's verifier, and the verdict names the principal the host
//! established.
//!
//! # The token never enters this module
//!
//! The floor checks that the claimed header is present exactly once and well shaped, and copies
//! nothing: [`HeaderTokenAdmission`] holds no token, and the verifier is handed only what the
//! host's outer layer left in this request's own state, and the clock.
//!
//! # The identity is the one this request carries
//!
//! A verifier names a type, [`HeaderTokenVerifier::Established`], and the admission reads the
//! value of that type from the accepted request's own transport values, which no client can
//! write. With no such value the verifier is not called and the request is refused; with one, the
//! verifier is handed that value and nothing else of the request. A verifier therefore cannot
//! report an identity for a request whose outer layer established none, and the implementation
//! that needs no other state is the correct one. The reported name is marked
//! [`crate::IdentityOrigin::HostToken`], which host code cannot set, so nothing downstream takes
//! it for an access key and no access key passes for it.
//!
//! ```compile_fail,E0624
//! use rustfs_gateway_sig::Identity;
//! fn launder(identity: Identity) -> Identity {
//!     identity.host_reported()
//! }
//! ```
//!
//! # What cannot be forged
//!
//! [`HeaderTokenAdmission`] and [`HeaderTokenReceipt`] have private fields, no `Clone`, no
//! `Default` and no public constructor: the first comes only from the floor, the second only from
//! [`HeaderTokenAdmission::verify`], which calls the installed verifier.
//!
//! ```compile_fail,E0451
//! use rustfs_gateway_sig::{HeaderTokenAdmission, RequestNow};
//! fn forge(now: RequestNow) -> HeaderTokenAdmission {
//!     HeaderTokenAdmission { now }
//! }
//! ```
//!
//! ```compile_fail,E0624
//! use rustfs_gateway_sig::{HeaderTokenAdmission, RequestNow};
//! fn conjure(now: RequestNow) -> HeaderTokenAdmission {
//!     HeaderTokenAdmission::new(now)
//! }
//! ```
//!
//! ```compile_fail,E0277
//! use rustfs_gateway_sig::HeaderTokenAdmission;
//! fn copy(admission: &HeaderTokenAdmission) -> HeaderTokenAdmission {
//!     Clone::clone(admission)
//! }
//! ```
//!
//! ```compile_fail,E0599
//! use rustfs_gateway_sig::HeaderTokenAdmission;
//! fn conjure() -> HeaderTokenAdmission {
//!     HeaderTokenAdmission::default()
//! }
//! ```
//!
//! ```compile_fail,E0451
//! use rustfs_gateway_sig::{HeaderTokenReceipt, Identity};
//! fn forge(identity: Identity) -> HeaderTokenReceipt {
//!     HeaderTokenReceipt { identity }
//! }
//! ```
//!
//! ```compile_fail,E0277
//! use rustfs_gateway_sig::HeaderTokenReceipt;
//! fn copy(receipt: &HeaderTokenReceipt) -> HeaderTokenReceipt {
//!     Clone::clone(receipt)
//! }
//! ```
//!
//! ```compile_fail,E0599
//! use rustfs_gateway_sig::HeaderTokenReceipt;
//! fn conjure() -> HeaderTokenReceipt {
//!     HeaderTokenReceipt::default()
//! }
//! ```
//!
//! Host code cannot wrap a receipt into a verdict itself; only [`HeaderTokenAdmission::verify`]
//! does:
//!
//! ```compile_fail,E0624
//! use rustfs_gateway_sig::{HeaderTokenReceipt, Verdict};
//! fn launder(receipt: HeaderTokenReceipt) -> Verdict {
//!     Verdict::header_token(receipt)
//! }
//! ```
//!
//! Nor build the variant directly:
//!
//! ```compile_fail,E0603
//! use rustfs_gateway_sig::{HeaderTokenReceipt, Verdict};
//! fn launder(receipt: HeaderTokenReceipt) -> Verdict {
//!     Verdict::HeaderToken(receipt)
//! }
//! ```
//!
//! Each probe above fails for the one reason it names and no other. Stable `rustdoc` does not
//! compare the error code, so the code is a record of what was measured, and the guarantee is
//! that a probe compiles the moment the thing it forbids exists.

use core::fmt;

use http::HeaderMap;
use rustfs_gateway_http::TransportExtensions;

use crate::clock::RequestNow;
use crate::verdict::{AuthError, Identity};

/// The prefix every claimable header carries: an extension header, never a standard one.
const EXTENSION_PREFIX: &str = "x-";

/// Extension names that already mean something to the gateway, a dialect or a proxy in front of
/// either. The facade removes a claimed header before acceptance, so claiming one of these would
/// change what signing, routing or decoding see.
const RESERVED_PREFIXES: [&str; 5] = ["x-amz-", "x-minio-", "x-rustfs-", "x-forwarded-", "x-http-method"];

/// Whole names reserved for the same reason.
const RESERVED_NAMES: [&str; 2] = ["x-request-id", "x-real-ip"];

/// Whether `header` may be claimed or refused as an alias: `x-` followed by lowercase ASCII
/// letters, digits and `-`, under no reserved prefix and not a reserved name.
fn claimable(header: &str) -> bool {
    header.strip_prefix(EXTENSION_PREFIX).is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) && !RESERVED_PREFIXES.iter().any(|prefix| header.starts_with(prefix))
        && !RESERVED_NAMES.contains(&header)
}

/// A service's opt-in to admission by one header token, which its host verifies.
///
/// The claim names the header, lowercase, and any aliases of it that the service refuses. It is
/// service-level: the floor that carries it reads those headers on every request, and
/// [`crate::SecurityFloor::admits_header_token`] decides which operations admit the scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HeaderTokenClaim {
    header: &'static str,
    refused_aliases: &'static [&'static str],
}

impl HeaderTokenClaim {
    /// The longest token the floor reads. The facade removes the claimed header before acceptance
    /// counts the request head, so the floor bounds the value itself.
    pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

    /// A claim on `header`, from a literal in the host's own build code.
    ///
    /// # Errors
    ///
    /// [`InvalidHeaderTokenClaim`] unless the name is `x-` followed by lowercase ASCII letters,
    /// digits and `-`, under none of the prefixes that already carry meaning (`x-amz-`,
    /// `x-minio-`, `x-rustfs-`, `x-forwarded-`, `x-http-method`), and neither `x-request-id`
    /// nor `x-real-ip`.
    /// The facade removes the claimed header before the request is accepted, so the grammar
    /// admits no header HTTP, the signature path, a dialect or a proxy gives a meaning to.
    pub fn new(header: &'static str) -> Result<Self, InvalidHeaderTokenClaim> {
        if !claimable(header) {
            return Err(InvalidHeaderTokenClaim);
        }
        Ok(Self {
            header,
            refused_aliases: &[],
        })
    }

    /// This claim, refusing every request that carries one of `aliases`.
    ///
    /// For a host whose outer layer reads the token under a second name (RustFS reads
    /// `x-storage-token` as well as `x-auth-token`). The gateway claims one header; a request
    /// that carried only the other would be anonymous, or its signer, to the gateway while the
    /// host acted as the token's user. A refused alias closes that: the request is answered
    /// `403 AccessDenied` before any verifier of any scheme is asked, whatever else it carries
    /// and whatever its operation, and the alias is removed with the claimed header.
    ///
    /// # Errors
    ///
    /// [`InvalidHeaderTokenClaim`] when an alias fails the grammar of [`Self::new`] or repeats
    /// the claimed header.
    pub fn refusing_aliases(mut self, aliases: &'static [&'static str]) -> Result<Self, InvalidHeaderTokenClaim> {
        if aliases.iter().any(|alias| !claimable(alias) || *alias == self.header) {
            return Err(InvalidHeaderTokenClaim);
        }
        self.refused_aliases = aliases;
        Ok(self)
    }

    /// The claimed header's name, lowercase.
    #[must_use]
    pub const fn header(&self) -> &'static str {
        self.header
    }

    /// The alias names this claim refuses, lowercase.
    #[must_use]
    pub const fn refused_aliases(&self) -> &'static [&'static str] {
        self.refused_aliases
    }

    /// Whether `headers` carries the claimed header or a refused alias at all, however often and
    /// whatever its value: the requests this claim alone decides.
    #[must_use]
    pub fn presented(&self, headers: &HeaderMap) -> bool {
        headers.contains_key(self.header) || self.alias_presented(headers)
    }

    /// Whether `headers` carries a refused alias.
    pub(crate) fn alias_presented(&self, headers: &HeaderMap) -> bool {
        self.refused_aliases.iter().any(|alias| headers.contains_key(*alias))
    }

    /// Whether `headers` carries the claimed header exactly once, as one token: 1 to
    /// [`Self::MAX_TOKEN_BYTES`] bytes, every one ASCII graphic and none a comma. A repeated line
    /// has no occurrence to prefer, a comma is how repeated lines are joined into one, and
    /// interior whitespace, a control byte or a non-ASCII byte is no part of a token.
    pub(crate) fn well_formed(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(self.header).iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return false;
        };
        let token = value.as_bytes();
        !token.is_empty()
            && token.len() <= Self::MAX_TOKEN_BYTES
            && token.iter().all(|byte| byte.is_ascii_graphic() && *byte != b',')
    }
}

/// A header name that cannot be a [`HeaderTokenClaim`] or one of its refused aliases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidHeaderTokenClaim;

impl fmt::Display for InvalidHeaderTokenClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a header token claim names lowercase `x-` headers under no reserved prefix, each once")
    }
}

impl core::error::Error for InvalidHeaderTokenClaim {}

/// A request the floor admitted by its [`HeaderTokenClaim`], not yet verified.
///
/// Holding one means the request carried the claimed header exactly once and well formed, beside
/// no other credential surface and no refused alias, on an operation that admits the scheme. It
/// holds no token. There is no public constructor: [`crate::SecurityFloor::admit`] builds it.
#[derive(Debug)]
pub struct HeaderTokenAdmission {
    now: RequestNow,
}

impl HeaderTokenAdmission {
    pub(crate) const fn new(now: RequestNow) -> Self {
        Self { now }
    }

    /// Reads what the host's outer layer established in `server_state`, asks `verifier` which
    /// identity that is, and answers with the verdict: [`crate::Verdict::HeaderToken`] naming it,
    /// or `AccessDenied` when nothing was established or the verifier refuses. This is the only
    /// way a header-token verdict is built, and it is never anonymous.
    ///
    /// `server_state` is the accepted request's own transport values. A request that holds no
    /// [`HeaderTokenVerifier::Established`] value is refused without the verifier being called.
    #[must_use]
    pub fn verify<V: HeaderTokenVerifier>(self, verifier: &V, server_state: &TransportExtensions) -> crate::Verdict {
        let Some(established) = server_state.get::<V::Established>() else {
            return crate::Verdict::reject(AuthError::AccessDenied);
        };
        match verifier.identity(established, self.now) {
            Ok(identity) => crate::Verdict::header_token(HeaderTokenReceipt {
                identity: identity.host_reported(),
            }),
            Err(HeaderTokenRefused) => crate::Verdict::reject(AuthError::AccessDenied),
        }
    }
}

/// A verifier's refusal: the host will not vouch for what it established in this request.
/// Deliberately carries nothing, and is always answered `403 AccessDenied`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderTokenRefused;

/// The host's reading of the identity its outer layer established: the declared trust boundary of
/// a [`HeaderTokenClaim`].
///
/// # What the kernel does
///
/// It admits a request that carries the claimed header exactly once and well formed, beside no
/// other credential surface and no refused alias, on an operation that admits the scheme. It
/// then takes the [`Self::Established`] value from that request's own state and calls the
/// verifier once with it. A request that holds none is refused and the verifier is not called.
/// The kernel never gives the verifier the token and never reads it itself, and it marks the
/// reported name [`crate::IdentityOrigin::HostToken`].
///
/// # What the host must do
///
/// * Validate the token in a layer that runs before the gateway, on every request, and insert
///   what it established into **that request's own extensions** as a value of type
///   [`Self::Established`]; insert nothing when it established nothing.
/// * Answer from the value it is handed. **A thread-local, a global, a "last authenticated" slot
///   or a cache keyed on the connection is forbidden as the source of the identity.** Each of
///   them outlives one request: requests share a thread, HTTP/2 multiplexes callers behind a
///   proxy onto one connection, and a keep-alive connection carries one caller after another, so
///   such a source hands one request the identity another request earned.
/// * Establish an identity from the claimed header only, and leave the header in place: the
///   gateway consumes it. A host whose outer layer also reads the token under another name
///   lists that name in [`HeaderTokenClaim::refusing_aliases`], or renames it to the claimed
///   header before the gateway.
/// * Keep its name space apart from access keys where the two are different principals. The
///   kernel marks the origin; a policy source or authorizer that looks a principal up by the
///   bare name must branch on [`Identity::origin`].
/// * Own replay, expiry and revocation. The kernel keeps no token state.
///
/// # Calling contract
///
/// Called synchronously on the request path, before authorization, under the same contract as
/// [`crate::BearerTokenVerifier`]: **must not block, sleep or do I/O**, and **must not panic** —
/// the facade contains a panic and refuses the request with `403`, but the host's own state is
/// whatever the panic left it in.
pub trait HeaderTokenVerifier: Send + Sync + 'static {
    /// What the host's outer layer inserts into a request's extensions once it has validated the
    /// token: a type of the host's own, so nothing else in the process can supply one.
    type Established: Send + Sync + 'static;

    /// Names the principal `established` stands for, at the request's one clock reading.
    ///
    /// # Errors
    ///
    /// [`HeaderTokenRefused`] when the host does not accept it here: it expired, or it cannot be
    /// named.
    fn identity(&self, established: &Self::Established, now: RequestNow) -> Result<Identity, HeaderTokenRefused>;
}

/// The receipt of one header-token verification: the principal the host reported.
///
/// A private field, no `Clone`, no `Default`, no public constructor.
#[derive(Debug)]
pub struct HeaderTokenReceipt {
    identity: Identity,
}

impl HeaderTokenReceipt {
    /// The principal the host established for the request.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }
}
