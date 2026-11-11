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

//! A host-verified header token claim (ADR-0050, rustfs/gateway#1586).
//!
//! Responsible for: [`HeaderTokenClaim`] (the service-level opt-in: one lowercase header name),
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
//! nothing: [`HeaderTokenAdmission`] holds no token, and [`HeaderTokenRequest`] has no accessor
//! for one. The verifier answers from the request's own server-side state.
//!
//! ```compile_fail,E0599
//! fn peek<'a>(request: &'a rustfs_gateway_sig::HeaderTokenRequest<'_>) -> &'a str {
//!     request.token()
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
use crate::signed_headers::AMZ_HEADER_PREFIX;
use crate::verdict::{AuthError, Identity};

/// The prefix every claimable header carries: an extension header, never a standard one.
const EXTENSION_PREFIX: &str = "x-";

/// A service's opt-in to admission by one header token, which its host verifies.
///
/// The claim names the header, lowercase. It is service-level: the floor that carries it reads
/// the header on every request, and [`crate::SecurityFloor::admits_header_token`] decides which
/// operations admit the scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HeaderTokenClaim {
    header: &'static str,
}

impl HeaderTokenClaim {
    /// The longest token the floor reads. The facade removes the claimed header before acceptance
    /// counts the request head, so the floor bounds the value itself.
    pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

    /// A claim on `header`, from a literal in the host's own build code.
    ///
    /// # Errors
    ///
    /// [`InvalidHeaderTokenClaim`] unless the name is an extension header outside the AWS
    /// namespace: `x-` followed by lowercase ASCII letters, digits and `-`, and not `x-amz-`.
    /// The facade removes the claimed header before the request is accepted, so the grammar
    /// admits no header HTTP or the signature path gives a meaning to — `authorization`, `host`,
    /// `content-length`, an HTTP/2 pseudo-header — and no `x-amz-` name.
    pub fn new(header: &'static str) -> Result<Self, InvalidHeaderTokenClaim> {
        let extension = header.strip_prefix(EXTENSION_PREFIX).is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
        if !extension || header.starts_with(AMZ_HEADER_PREFIX) {
            return Err(InvalidHeaderTokenClaim);
        }
        Ok(Self { header })
    }

    /// The claimed header's name, lowercase.
    #[must_use]
    pub const fn header(&self) -> &'static str {
        self.header
    }

    /// Whether `headers` carries the claimed header at all, however often and whatever its value.
    #[must_use]
    pub fn presented(&self, headers: &HeaderMap) -> bool {
        headers.contains_key(self.header)
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

/// A header name that cannot be a [`HeaderTokenClaim`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidHeaderTokenClaim;

impl fmt::Display for InvalidHeaderTokenClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a header token claim names one lowercase `x-` header outside `x-amz-`")
    }
}

impl core::error::Error for InvalidHeaderTokenClaim {}

/// A request the floor admitted by its [`HeaderTokenClaim`], not yet verified.
///
/// Holding one means the request carried the claimed header exactly once and well formed, beside
/// no other credential surface, on an operation that admits the scheme. It holds no token. There
/// is no public constructor: [`crate::SecurityFloor::admit`] builds it.
#[derive(Debug)]
pub struct HeaderTokenAdmission {
    now: RequestNow,
}

impl HeaderTokenAdmission {
    pub(crate) const fn new(now: RequestNow) -> Self {
        Self { now }
    }

    /// Asks `verifier` which identity the host established for this request, and answers with the
    /// verdict: [`crate::Verdict::HeaderToken`] naming it, or `AccessDenied` when the verifier
    /// refuses. This is the only way a header-token verdict is built, and it is never anonymous.
    ///
    /// `server_state` is the accepted request's own transport values, where a host's outer layer
    /// leaves what it established.
    #[must_use]
    pub fn verify(self, verifier: &dyn HeaderTokenVerifier, server_state: &TransportExtensions) -> crate::Verdict {
        let request = HeaderTokenRequest {
            now: self.now,
            server_state,
        };
        match verifier.verify(&request) {
            Ok(identity) => crate::Verdict::header_token(HeaderTokenReceipt { identity }),
            Err(HeaderTokenRefused) => crate::Verdict::reject(AuthError::AccessDenied),
        }
    }
}

/// What a [`HeaderTokenVerifier`] is asked: the admission's one clock reading and the request's
/// server-side state. Deliberately not the token.
#[derive(Debug)]
pub struct HeaderTokenRequest<'a> {
    now: RequestNow,
    server_state: &'a TransportExtensions,
}

impl<'a> HeaderTokenRequest<'a> {
    /// The request's single clock reading, for a host that holds its identity to an expiry.
    #[must_use]
    pub const fn now(&self) -> RequestNow {
        self.now
    }

    /// The value of type `T` the host installed in this request before the gateway accepted it,
    /// when one was. Nothing a client sends reaches this state.
    #[must_use]
    pub fn server_state<T: Send + Sync + 'static>(&self) -> Option<&'a T> {
        self.server_state.get::<T>()
    }
}

/// A verifier's refusal: the host established no identity for this request, or will not vouch for
/// it. Deliberately carries nothing, and is always answered `403 AccessDenied`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderTokenRefused;

/// The host's report of the identity its outer layer established: the declared trust boundary of
/// a [`HeaderTokenClaim`].
///
/// # What the kernel does
///
/// It admits a request that carries the claimed header exactly once and well formed, beside no
/// other credential surface, on an operation that admits the scheme, and calls the verifier once.
/// It never gives the verifier the token and never reads it itself.
///
/// # What the host must do
///
/// * Validate the token in a layer that runs before the gateway, on every request, and leave the
///   identity it established in that request's own state. Report that identity here, and refuse
///   when there is none: an absent identity is a refusal, never an anonymous request.
/// * Establish an identity from the claimed header only, and leave the header in place: the
///   gateway consumes it. An identity established from any other header reaches a request the
///   gateway treats as anonymous, or as its signer. A host that accepts an alias of the header
///   renames it to the claimed one in its outer layer, or refuses it there.
/// * Report an identity its policy source and audit trail can tell from an access key, unless
///   the two are meant to be one principal: the identity is the only thing they are handed. A
///   [`crate::SessionBinding`] naming the issuer is one way to mark it.
/// * Own replay, expiry and revocation. The kernel keeps no token state.
///
/// # Calling contract
///
/// Called synchronously on the request path, before authorization, under the same contract as
/// [`crate::BearerTokenVerifier`]: **must not block, sleep or do I/O**, and **must not panic** —
/// the facade contains a panic and refuses the request with `403`, but the host's own state is
/// whatever the panic left it in.
pub trait HeaderTokenVerifier: Send + Sync + 'static {
    /// Reports the identity the host established for one request.
    ///
    /// # Errors
    ///
    /// [`HeaderTokenRefused`] when the host established none, or does not accept it here.
    fn verify(&self, request: &HeaderTokenRequest<'_>) -> Result<Identity, HeaderTokenRefused>;
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
