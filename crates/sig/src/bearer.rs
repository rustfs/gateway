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

//! A route-bound query bearer claim (ADR-0042, rustfs/gateway#1400).
//!
//! Responsible for: [`QueryBearerClaim`] (the opt-in an operation's floor declares: one query
//! parameter and one literal path suffix), [`BearerAdmission`] (the sealed result of the floor
//! admitting a request by that claim), the host's [`BearerTokenVerifier`] trust boundary and the
//! [`BearerReceipt`] only a verification produces.
//! NOT responsible for: the token's cryptography, its expiry or the download it names — the host
//! verifier owns all three — or authorization, which still runs on the receipt's principal.
//! Upstream: [`crate::SecurityFloor::admit`], the only producer of a [`BearerAdmission`].
//! Downstream: [`crate::Verdict::Bearer`], and the facade, which installs the verifier and strips
//! the token from every context after verification.
//!
//! # Why a claim and not an anonymous route
//!
//! The URL a RustFS zip download mints carries no signature, only `?token=`. Admitting it
//! anonymously would attribute a stored principal's download to nobody (ADR-0026 (g)). The claim
//! instead admits the request only as far as the host's verifier, and the verdict it produces names
//! the principal the token was issued to, so the governor, both authorization stages, audit and the
//! handler all see that principal.
//!
//! # What cannot be forged
//!
//! [`BearerAdmission`] and [`BearerReceipt`] have private fields, no `Clone`, no `Default` and no
//! public constructor: the first comes only from the floor, the second only from
//! [`BearerAdmission::verify`] or [`BearerAdmission::verify_alongside`], which call the installed
//! verifier on that admission's own token, operation and download. The verifier's
//! [`BearerGrant`] is constructible — the verifier is the declared trust boundary — but a grant is
//! not a receipt, and nothing turns one into the other without a verification.
//!
//! ```compile_fail,E0451
//! use rustfs_gateway_sig::BearerReceipt;
//! fn forge(identity: rustfs_gateway_sig::Identity) -> BearerReceipt {
//!     BearerReceipt { identity, operation: "op", resource: Box::from("id"), state: todo!() }
//! }
//! ```
//!
//! ```compile_fail,E0599
//! use rustfs_gateway_sig::BearerReceipt;
//! fn copy(receipt: &BearerReceipt) -> BearerReceipt {
//!     receipt.clone()
//! }
//! ```

use core::fmt;
use std::any::Any;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::clock::RequestNow;
use crate::floor::WireView;
use crate::query::query_name_matches;
use crate::verdict::{AuthError, Identity};

/// An operation's opt-in to admission by one query bearer parameter.
///
/// The claim names the parameter (case-sensitive, matched on its decoded name) and the literal
/// suffix the request path's last raw segment must end with. The bound resource is that segment
/// with the suffix removed, never decoded or normalized: the verifier compares it with the
/// resource its token names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QueryBearerClaim {
    param: &'static str,
    path_suffix: &'static str,
}

impl QueryBearerClaim {
    /// A claim read from `param`, bound to a last path segment that ends with `path_suffix`.
    #[must_use]
    pub const fn new(param: &'static str, path_suffix: &'static str) -> Self {
        Self { param, path_suffix }
    }

    /// The query parameter that carries the token.
    #[must_use]
    pub const fn param(&self) -> &'static str {
        self.param
    }

    /// The literal suffix the last raw path segment must carry.
    #[must_use]
    pub const fn path_suffix(&self) -> &'static str {
        self.path_suffix
    }

    /// The resource this claim binds a request to: the last raw path segment with the one literal
    /// suffix removed. `None` when the segment lacks the suffix or nothing precedes it.
    #[must_use]
    pub fn bound_resource<'p>(&self, raw_path: &'p str) -> Option<&'p str> {
        let segment = raw_path.rsplit_once('/').map_or(raw_path, |(_, last)| last);
        let resource = segment.strip_suffix(self.path_suffix)?;
        (!resource.is_empty()).then_some(resource)
    }

    /// Whether `view`'s query carries this claim's parameter at all, however often.
    #[must_use]
    pub fn presented(&self, view: &WireView<'_>) -> bool {
        view.query_contains(self.param)
    }

    /// `raw_query` with every component whose decoded name is this claim's parameter removed, so a
    /// context handed to an authorizer or a handler never holds the token.
    ///
    /// A component whose name cannot be decoded is compared on its wire bytes, so a broken spelling
    /// cannot keep the token in place.
    #[must_use]
    pub fn strip_from(&self, raw_query: &str) -> String {
        raw_query
            .split('&')
            .filter(|component| {
                let raw_key = component.split_once('=').map_or(*component, |(key, _)| key);
                let named = query_name_matches(raw_key, self.param);
                !component.is_empty() && !named
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    /// The token this claim reads from `view`: `Ok(None)` when the parameter is absent.
    ///
    /// # Errors
    ///
    /// [`AuthError::AccessDenied`] for a repeated parameter (no occurrence is chosen over another),
    /// an undecodable or non-UTF-8 value, and an empty one.
    pub(crate) fn read_token(&self, view: &WireView<'_>) -> Result<Option<Zeroizing<String>>, AuthError> {
        match view.count_query_param(self.param) {
            0 => return Ok(None),
            1 => {}
            _ => return Err(AuthError::AccessDenied),
        }
        let token = view
            .query()
            .decoded_value(self.param)
            .map_err(|_| AuthError::AccessDenied)?
            .map(Zeroizing::new)
            .ok_or(AuthError::AccessDenied)?;
        if token.is_empty() {
            return Err(AuthError::AccessDenied);
        }
        Ok(Some(token))
    }
}

/// A request the floor admitted by an operation's [`QueryBearerClaim`], not yet verified.
///
/// There is no public constructor: [`crate::SecurityFloor::admit`] builds one for a request that
/// presented no AWS credential surface, and [`crate::SecurityFloor::bearer_alongside_signature`]
/// for a signed request on the same operation.
pub struct BearerAdmission {
    operation: &'static str,
    claim: QueryBearerClaim,
    token: Zeroizing<String>,
    now: RequestNow,
}

impl BearerAdmission {
    pub(crate) const fn new(operation: &'static str, claim: QueryBearerClaim, token: Zeroizing<String>, now: RequestNow) -> Self {
        Self {
            operation,
            claim,
            token,
            now,
        }
    }

    /// The operation whose claim admitted the request.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// The claim that admitted the request.
    #[must_use]
    pub const fn claim(&self) -> QueryBearerClaim {
        self.claim
    }

    /// Verifies a request that presented only the bearer token.
    ///
    /// # Errors
    ///
    /// [`AuthError::AccessDenied`] when `raw_path` does not end with the claim's suffix after a
    /// non-empty resource, and whenever the verifier refuses.
    pub fn verify(self, verifier: &dyn BearerTokenVerifier, raw_path: &str) -> Result<BearerReceipt, AuthError> {
        let resource = self.claim.bound_resource(raw_path).ok_or(AuthError::AccessDenied)?;
        let request = BearerTokenRequest {
            operation: self.operation,
            resource,
            token: self.token.as_str(),
            now: self.now,
        };
        let grant = verifier.verify(&request).map_err(|BearerRefused| AuthError::AccessDenied)?;
        Ok(BearerReceipt {
            identity: grant.identity,
            operation: self.operation,
            resource: Box::from(resource),
            state: grant.state,
        })
    }

    /// Verifies the token of a request whose signature already authenticated `signed`, and
    /// requires the token to have been issued to that same principal.
    ///
    /// # Errors
    ///
    /// Everything [`Self::verify`] refuses, and [`AuthError::AccessDenied`] when the token names
    /// another principal than the signature.
    pub fn verify_alongside(
        self,
        verifier: &dyn BearerTokenVerifier,
        raw_path: &str,
        signed: &Identity,
    ) -> Result<BearerReceipt, AuthError> {
        let receipt = self.verify(verifier, raw_path)?;
        if receipt.identity.access_key_id() != signed.access_key_id() {
            return Err(AuthError::AccessDenied);
        }
        Ok(receipt)
    }
}

impl fmt::Debug for BearerAdmission {
    /// Never the token.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerAdmission")
            .field("operation", &self.operation)
            .field("claim", &self.claim)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// What a [`BearerTokenVerifier`] is asked: one admission's token, operation, bound resource and
/// the one clock reading the whole admission uses.
pub struct BearerTokenRequest<'a> {
    operation: &'static str,
    resource: &'a str,
    token: &'a str,
    now: RequestNow,
}

impl<'a> BearerTokenRequest<'a> {
    /// The routed operation.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// The resource the request path names: its last raw segment without the claim's suffix,
    /// neither decoded nor normalized. The verifier refuses a token issued for another.
    #[must_use]
    pub const fn resource(&self) -> &'a str {
        self.resource
    }

    /// The decoded token. A credential: never log it.
    #[must_use]
    pub const fn token(&self) -> &'a str {
        self.token
    }

    /// The request's single clock reading. A token whose `expires_at <= now` must be refused.
    #[must_use]
    pub const fn now(&self) -> RequestNow {
        self.now
    }
}

impl fmt::Debug for BearerTokenRequest<'_> {
    /// Never the token.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerTokenRequest")
            .field("operation", &self.operation)
            .field("resource", &self.resource)
            .field("token", &"<redacted>")
            .field("now", &self.now)
            .finish()
    }
}

/// Read-only access to the host's request-bound verified value, indexed by its concrete type.
/// The host must keep any interior-mutable state consistent with the verified decision.
#[derive(Clone)]
pub struct VerifiedBearerState(http::Extensions);

impl VerifiedBearerState {
    fn new<T: Any + Send + Sync>(value: Arc<T>) -> Self {
        let mut state = http::Extensions::new();
        state.insert(value);
        Self(state)
    }

    /// Returns the verified value only when the host asks for its original type.
    #[must_use]
    pub fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.0.get::<Arc<T>>().map(Arc::as_ref)
    }
}

/// The host's answer to a token it verified: the principal it was issued to and the host's own
/// verified state, which the handler reads instead of decoding the token again.
pub struct BearerGrant {
    identity: Identity,
    state: VerifiedBearerState,
}

impl BearerGrant {
    /// The verified principal and the host state that travels to the handler.
    #[must_use]
    pub fn new<T: Any + Send + Sync>(identity: Identity, state: Arc<T>) -> Self {
        Self {
            identity,
            state: VerifiedBearerState::new(state),
        }
    }
}

impl fmt::Debug for BearerGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerGrant")
            .field("identity", &self.identity)
            .field("state", &"<opaque>")
            .finish()
    }
}

/// A verifier's refusal. Deliberately carries nothing: which check failed is not something the
/// caller of an unsigned URL needs, and every refusal is answered `403 AccessDenied`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BearerRefused;

/// The host's token verification: the declared trust boundary of a [`QueryBearerClaim`].
///
/// The host authenticates the token's ciphertext, checks that it names
/// [`BearerTokenRequest::resource`] and refuses `expires_at <= now` against
/// [`BearerTokenRequest::now`]. Nothing is installed by default, and a claim with no verifier
/// refuses every token.
pub trait BearerTokenVerifier: Send + Sync + 'static {
    /// Verifies one request's token.
    ///
    /// # Errors
    ///
    /// [`BearerRefused`] for any token the host does not accept for this request.
    fn verify(&self, request: &BearerTokenRequest<'_>) -> Result<BearerGrant, BearerRefused>;
}

/// The receipt of one bearer verification, bound to its admission's operation and resource.
///
/// Private fields, no `Clone`, no `Default`, no public constructor.
pub struct BearerReceipt {
    identity: Identity,
    operation: &'static str,
    resource: Box<str>,
    state: VerifiedBearerState,
}

impl BearerReceipt {
    /// The principal the verified token was issued to.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The operation whose claim admitted the request.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// The resource the request was bound to.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// The host's verified state, shared read-only with the handler of this request.
    #[must_use]
    pub fn state(&self) -> &VerifiedBearerState {
        &self.state
    }
}

impl fmt::Debug for BearerReceipt {
    /// Names the principal and the operation; never the token, which the receipt does not hold,
    /// nor the host's state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerReceipt")
            .field("identity", &self.identity)
            .field("operation", &self.operation)
            .field("state", &"<opaque>")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    #[test]
    fn verified_state_preserves_type_and_original_value() {
        let value = std::sync::Arc::new(String::from("verified"));
        let state = super::VerifiedBearerState::new(value.clone());
        assert!(std::ptr::eq(state.get::<String>().expect("matching type"), value.as_ref()));
        assert!(state.get::<u64>().is_none());
    }
    use http::HeaderMap;

    use super::*;
    use crate::query::RawQuery;

    const CLAIM: QueryBearerClaim = QueryBearerClaim::new("token", ".zip");

    fn token_of(query: &str) -> Result<Option<String>, AuthError> {
        let headers = HeaderMap::new();
        let view = WireView::new(&headers, RawQuery::new(query));
        CLAIM
            .read_token(&view)
            .map(|token| token.map(|token| token.as_str().to_owned()))
    }

    #[test]
    fn the_bound_resource_is_the_raw_segment_without_its_one_literal_suffix() {
        assert_eq!(CLAIM.bound_resource("/rustfs/admin/v3/object-zip-downloads/abc.zip"), Some("abc"));
        assert_eq!(CLAIM.bound_resource("/x/a%2Eb.zip"), Some("a%2Eb"), "never decoded");
        assert_eq!(CLAIM.bound_resource("/x/abc.zip.zip"), Some("abc.zip"), "only one suffix is removed");
    }

    #[test]
    fn n_a_segment_without_the_suffix_or_without_a_resource_binds_nothing() {
        for path in ["/x/abc", "/x/abc.tar", "/x/abc%2Ezip", "/x/.zip", "/x/abc.ZIP", "/x/"] {
            assert_eq!(CLAIM.bound_resource(path), None, "{path}");
        }
    }

    #[test]
    fn one_literal_token_is_read_and_decoded_once() {
        assert_eq!(token_of("token=a%2Bb").expect("readable"), Some("a+b".to_owned()));
        assert_eq!(token_of("note=x&token=t").expect("readable"), Some("t".to_owned()));
        assert_eq!(token_of("note=x").expect("readable"), None);
    }

    #[test]
    fn n_repeated_empty_or_undecodable_tokens_are_refused() {
        for query in [
            "token=a&token=b",
            "token=a&token=",
            "token=",
            "token",
            "token=%zz",
            "token=%ff",
        ] {
            assert_eq!(token_of(query), Err(AuthError::AccessDenied), "{query}");
        }
    }

    #[test]
    fn n_the_token_is_stripped_and_every_other_parameter_kept() {
        assert_eq!(CLAIM.strip_from("note=a+b&token=secret&z=1"), "note=a+b&z=1");
        assert_eq!(CLAIM.strip_from("token=secret"), "");
        assert_eq!(CLAIM.strip_from("%74oken=secret&Token=kept"), "Token=kept");
    }

    #[test]
    fn n_debug_never_prints_the_token() {
        let admission =
            BearerAdmission::new("op", CLAIM, Zeroizing::new("sentinel-token".to_owned()), RequestNow::from_unix_seconds(0));
        assert!(!format!("{admission:?}").contains("sentinel-token"));
        let request = BearerTokenRequest {
            operation: "op",
            resource: "abc",
            token: "sentinel-token",
            now: RequestNow::from_unix_seconds(0),
        };
        assert!(!format!("{request:?}").contains("sentinel-token"));
    }
}
