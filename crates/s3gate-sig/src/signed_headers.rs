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

//! The client's `SignedHeaders` allow-list, and the completeness rules it must satisfy.
//!
//! Responsible for: [`SignedHeaderSet`] — parsing the semicolon-separated list, and enforcing the
//! six rules that turn it from "a hint about what to hash" into "a promise about what the client
//! actually covered"; plus [`UNSIGNED_HEADER_EXEMPTIONS`], the closed list of headers AWS lets a
//! client leave unsigned.
//! NOT responsible for: computing anything. This module never hashes, never compares a signature
//! and never sees a secret; it decides which header names the canonical request is allowed to
//! contain, and in which order.
//! Upstream: [`crate::AuthError`], `http`'s `HeaderMap`. Downstream: [`crate::canonical`], which
//! will not build a canonical request without one of these.
//!
//! # The rule this whole module exists for
//!
//! **Every `x-amz-*` header that arrived must appear in the list.** Without it, a header the
//! client never signed still reaches the operation, and the operation trusts it. The reachable set
//! is not obscure: `x-amz-copy-source` redirects a copy at its source,
//! `x-amz-server-side-encryption-customer-key` substitutes the encryption key,
//! `x-amz-metadata-directive` decides whether metadata is replaced, `x-amz-object-lock-*` weakens
//! retention, `x-amz-acl` and `x-amz-tagging` change who may read the object afterwards, and
//! `x-amz-security-token` changes which identity the request runs as. Any intermediary — or
//! anything that can inject one header into a request in flight — turns an unsigned `x-amz-*` into
//! an unsigned instruction.
//!
//! The complement of the rule matters too: the canonical request is built from **this list**, never
//! from "every header except a deny-list". `aws-sigv4` 1.5.1 walks the whole `HeaderMap` and
//! subtracts an excluded set, which means an unanticipated header from a reverse proxy silently
//! joins the hash and every such request fails with `SignatureDoesNotMatch`. Worse, the complement
//! is attacker-reachable: what the deny-list forgets, the attacker supplies.

use http::HeaderMap;
use http::header::{CONTENT_LENGTH, HOST, HeaderName};

use crate::verdict::AuthError;

/// The header-name prefix whose members must always be signed.
pub const AMZ_HEADER_PREFIX: &str = "x-amz-";

/// The headers a client may leave out of `SignedHeaders`.
///
/// Hop-by-hop metadata that a proxy is entitled to rewrite, plus `user-agent`, which some SDKs
/// sign and some do not. The list is fixed, written out here, and asserted in the test suite to
/// contain nothing beginning with `x-amz-` — a single `x-amz-*` entry would reopen the whole
/// injection surface this module exists to close.
///
/// Note where the exemption applies: these headers may be *absent* from the list. Nothing here
/// lets a header that the client *did* declare be missing from the request, and nothing here
/// exempts anything from being hashed once it is declared.
pub const UNSIGNED_HEADER_EXEMPTIONS: [&str; 6] = [
    "connection",
    "expect",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "user-agent",
];

/// The client's `SignedHeaders` allow-list, with every completeness rule already enforced.
///
/// The field is private and there is no constructor other than
/// [`SignedHeaderSet::parse_and_enforce`], so a set in hand has been through all six rules. A
/// public `Vec<HeaderName>` would let a caller assemble precisely the states the rules exist to
/// reject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHeaderSet {
    names: Vec<HeaderName>,
}

impl SignedHeaderSet {
    /// Parses the list and enforces every rule, or refuses.
    ///
    /// The rules, in the order they are checked:
    ///
    /// 1. **Syntax.** Names are non-empty lowercase HTTP tokens separated by `;`. Uppercase is
    ///    rejected rather than folded: the list is a signed string, so two casings are two strings.
    /// 2. **Non-empty.** An empty list covers nothing at all.
    /// 3. **Strictly ascending.** Byte order, no repeats. This is what AWS emits, and it removes
    ///    the question of what a repeated or out-of-order name would mean.
    /// 4. **`host` is present.** The host is the request's destination; a signature that does not
    ///    cover it is valid for every host the gateway answers on.
    /// 5. **Everything declared was sent.** Except `host`: an HTTP/2 request legitimately carries
    ///    its host in `:authority` and no `host` header, so `host` is supplied by
    ///    [`crate::effective_host`] rather than by the header map.
    /// 6. **Everything `x-amz-*` that was sent is declared**, and, when `content-length` is
    ///    declared, its header value matches the length the wire layer actually decided on.
    ///
    /// `wire_content_length` is the length the wire layer settled on, which is not always the
    /// header: under aws-chunked framing the header covers the encoded body. Pass `None` when the
    /// request has no body length; declaring `content-length` then is a rejection.
    ///
    /// # Errors
    ///
    /// * [`AuthError::AuthorizationHeaderMalformed`] for rules 1 and 3 — the list itself is
    ///   ill-formed, which is a `400`-shaped fault in the client.
    /// * [`AuthError::SignatureDoesNotMatch`] for rules 2, 4, 5 and 6 — the list is well-formed but
    ///   does not cover what it must, which is indistinguishable, to the client, from having signed
    ///   the wrong thing.
    pub fn parse_and_enforce(raw: &str, headers: &HeaderMap, wire_content_length: Option<u64>) -> Result<Self, AuthError> {
        if raw.is_empty() {
            return Err(AuthError::SignatureDoesNotMatch);
        }

        let mut names: Vec<HeaderName> = Vec::new();
        for token in raw.split(';') {
            if !is_lowercase_token(token) {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            if let Some(previous) = names.last() {
                // Strictly ascending: equality is a duplicate, and a duplicate is an ambiguity.
                if previous.as_str().as_bytes() >= token.as_bytes() {
                    return Err(AuthError::AuthorizationHeaderMalformed);
                }
            }
            let name = HeaderName::from_bytes(token.as_bytes()).map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
            names.push(name);
        }

        let set = Self { names };

        if !set.contains(&HOST) {
            return Err(AuthError::SignatureDoesNotMatch);
        }

        for name in &set.names {
            // `host` is exempt: RFC 9113 §8.3.1 lets an h2 request carry `:authority` and no
            // `host` header, and `effective_host` is what supplies the value in that case.
            if name == HOST {
                continue;
            }
            if !headers.contains_key(name) {
                return Err(AuthError::SignatureDoesNotMatch);
            }
        }

        for name in headers.keys() {
            if name.as_str().starts_with(AMZ_HEADER_PREFIX) && !set.contains(name) {
                return Err(AuthError::SignatureDoesNotMatch);
            }
        }

        if set.contains(&CONTENT_LENGTH) {
            set.check_content_length(headers, wire_content_length)?;
        }

        Ok(set)
    }

    fn check_content_length(&self, headers: &HeaderMap, wire_content_length: Option<u64>) -> Result<(), AuthError> {
        let mut values = headers.get_all(CONTENT_LENGTH).iter();
        let declared = values.next().ok_or(AuthError::SignatureDoesNotMatch)?;
        if values.next().is_some() {
            // Two lengths is the classic smuggling shape; it is not this module's job to pick one.
            return Err(AuthError::SignatureDoesNotMatch);
        }
        let declared: u64 = declared
            .to_str()
            .map_err(|_| AuthError::SignatureDoesNotMatch)?
            .parse()
            .map_err(|_| AuthError::SignatureDoesNotMatch)?;
        if wire_content_length != Some(declared) {
            return Err(AuthError::SignatureDoesNotMatch);
        }
        Ok(())
    }

    /// Whether a header name is covered.
    #[must_use]
    pub fn contains(&self, name: &HeaderName) -> bool {
        self.names.iter().any(|candidate| candidate == name)
    }

    /// The covered names, ascending. This is the order the canonical request uses.
    #[must_use]
    pub fn names(&self) -> &[HeaderName] {
        &self.names
    }

    /// How many headers are covered. Never zero.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Always `false`: the empty list is rejected at construction.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The `SignedHeaders` line of the canonical request: names joined with `;`.
    #[must_use]
    pub fn canonical_list(&self) -> String {
        let mut out = String::new();
        for (index, name) in self.names.iter().enumerate() {
            if index > 0 {
                out.push(';');
            }
            out.push_str(name.as_str());
        }
        out
    }

    /// Whether a header may be left unsigned. See [`UNSIGNED_HEADER_EXEMPTIONS`].
    #[must_use]
    pub fn is_exempt_from_signing(name: &str) -> bool {
        !name.starts_with(AMZ_HEADER_PREFIX) && UNSIGNED_HEADER_EXEMPTIONS.contains(&name)
    }
}

fn is_lowercase_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    token.bytes().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'^' | b'`' | b'|' | b'~'
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            let name = HeaderName::from_bytes(name.as_bytes()).expect("test header name");
            map.append(name, value.parse().expect("test header value"));
        }
        map
    }

    #[test]
    fn a_minimal_well_formed_list_is_accepted() {
        let map = headers(&[("x-amz-date", "20150830T123600Z")]);
        let set = SignedHeaderSet::parse_and_enforce("host;x-amz-date", &map, None).expect("valid");
        assert_eq!(set.canonical_list(), "host;x-amz-date");
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn host_need_not_be_in_the_header_map() {
        // An h2 request that carried `:authority` and no `host` header.
        let map = headers(&[("x-amz-date", "20150830T123600Z")]);
        assert!(SignedHeaderSet::parse_and_enforce("host;x-amz-date", &map, None).is_ok());
    }

    #[test]
    fn an_unsigned_amz_header_is_refused() {
        let map = headers(&[("x-amz-date", "20150830T123600Z"), ("x-amz-copy-source", "/other/key")]);
        assert_eq!(
            SignedHeaderSet::parse_and_enforce("host;x-amz-date", &map, None),
            Err(AuthError::SignatureDoesNotMatch)
        );
    }

    #[test]
    fn the_exemption_list_never_covers_an_amz_header() {
        for exempt in UNSIGNED_HEADER_EXEMPTIONS {
            assert!(!exempt.starts_with(AMZ_HEADER_PREFIX), "{exempt} must not be exempt");
            assert!(SignedHeaderSet::is_exempt_from_signing(exempt));
        }
        assert!(!SignedHeaderSet::is_exempt_from_signing("x-amz-copy-source"));
    }

    #[test]
    fn ill_formed_lists_are_refused() {
        let map = headers(&[("x-amz-date", "d"), ("content-type", "text/plain")]);
        // Out of order, duplicated, uppercase, empty token, empty list.
        for bad in [
            "x-amz-date;host",
            "host;host;x-amz-date",
            "Host;x-amz-date",
            "host;;x-amz-date",
            "",
        ] {
            assert!(SignedHeaderSet::parse_and_enforce(bad, &map, None).is_err(), "must reject {bad:?}");
        }
        // No host at all.
        assert_eq!(
            SignedHeaderSet::parse_and_enforce("content-type;x-amz-date", &map, None),
            Err(AuthError::SignatureDoesNotMatch)
        );
        // Declared but never sent.
        assert_eq!(
            SignedHeaderSet::parse_and_enforce("host;x-amz-date;x-amz-nonexistent", &map, None),
            Err(AuthError::SignatureDoesNotMatch)
        );
    }

    #[test]
    fn a_signed_content_length_must_match_the_wire_length() {
        let map = headers(&[("content-length", "13"), ("x-amz-date", "d")]);
        assert!(SignedHeaderSet::parse_and_enforce("content-length;host;x-amz-date", &map, Some(13)).is_ok());
        assert_eq!(
            SignedHeaderSet::parse_and_enforce("content-length;host;x-amz-date", &map, Some(14)),
            Err(AuthError::SignatureDoesNotMatch)
        );
        assert_eq!(
            SignedHeaderSet::parse_and_enforce("content-length;host;x-amz-date", &map, None),
            Err(AuthError::SignatureDoesNotMatch)
        );
    }
}
