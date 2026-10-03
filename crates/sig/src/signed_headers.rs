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
//! actually covered"; the RustFS profile's verbatim reading of a list AWS would call malformed
//! ([`SignedHeaderSet::parse_and_enforce_as_legacy_rustfs`], canonicalised by
//! `crate::signed_headers_legacy`); plus [`UNSIGNED_HEADER_EXEMPTIONS`], the closed list of
//! headers AWS lets a client leave unsigned.
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
use http::header::{CONTENT_LENGTH, DATE, HOST, HeaderName};
use smallvec::SmallVec;

use crate::verdict::AuthError;

/// The SigV4 timestamp header; when it is absent, `Date` supplies the timestamp and must be signed.
const X_AMZ_DATE: HeaderName = HeaderName::from_static("x-amz-date");

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
///
/// The original list is retained for allocation-free canonical writing. Up to eight parsed names
/// stay inline, so the usual request still pays one heap allocation rather than adding a second
/// one for the borrowed HTTP writer's input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHeaderSet {
    raw: String,
    names: SmallVec<[HeaderName; 8]>,
    reading: ListReading,
}

/// How the canonical request reads the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListReading {
    /// Lowercase and strictly ascending, as AWS emits it: the list is canonical as it stands.
    Aws,
    /// Verbatim, as legacy RustFS reads a list AWS would call malformed (rustfs/gateway#1130):
    /// every name in the order and the case the client wrote it (`crate::signed_headers_legacy`).
    LegacyRustfs,
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

        let mut names: SmallVec<[HeaderName; 8]> = SmallVec::new();
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

        let set = Self {
            raw: raw.to_owned(),
            names,
            reading: ListReading::Aws,
        };
        set.enforce(headers, wire_content_length)?;
        Ok(set)
    }

    /// [`Self::parse_and_enforce`], except that a list AWS would call malformed — a name in
    /// uppercase, out of order, repeated or empty — is read as legacy RustFS reads it, for the
    /// RustFS profile (rustfs/gateway#1130): each name as written, in the order written, looked up
    /// case-insensitively, and written into the canonical request that way
    /// (`crate::signed_headers_legacy`). A list AWS emits is read exactly as
    /// [`Self::parse_and_enforce`] reads it.
    ///
    /// The completeness rules hold for both readings, case-insensitively: `host` must be named,
    /// every name must have been sent, every `x-amz-*` header sent must be named, a `Date` that
    /// supplies the timestamp must be named, and a named `content-length` must be the wire's.
    /// What changes is only how the covered headers are spelled in the string the client signed.
    ///
    /// # Errors
    ///
    /// As [`Self::parse_and_enforce`]; a name that is not a header name is a header the request
    /// did not send, [`AuthError::SignatureDoesNotMatch`], as legacy RustFS answers it.
    pub fn parse_and_enforce_as_legacy_rustfs(
        raw: &str,
        headers: &HeaderMap,
        wire_content_length: Option<u64>,
    ) -> Result<Self, AuthError> {
        match Self::parse_and_enforce(raw, headers, wire_content_length) {
            Err(AuthError::AuthorizationHeaderMalformed) => {}
            read => return read,
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads a list AWS would call
        // malformed (a name in uppercase, out of order, repeated) and canonicalises it as
        // written, normalising values by Unicode whitespace; two signers of one request can
        // disagree on that string, and a repeated name is hashed twice. Kept: the reading, only
        // for such a list. The intended future behaviour is AWS's: lowercase, ascending, once
        // each, refused otherwise.
        let mut names: SmallVec<[HeaderName; 8]> = SmallVec::new();
        for token in raw.split(';') {
            let name = HeaderName::from_bytes(token.as_bytes()).map_err(|_| AuthError::SignatureDoesNotMatch)?;
            // Rule 5 here rather than after the loop: a name the request did not send ends the
            // reading at once, so the distinct names kept are never more than the headers sent.
            if name != HOST && !headers.contains_key(&name) {
                return Err(AuthError::SignatureDoesNotMatch);
            }
            if !names.contains(&name) {
                names.push(name);
            }
        }
        let set = Self {
            raw: raw.to_owned(),
            names,
            reading: ListReading::LegacyRustfs,
        };
        set.enforce(headers, wire_content_length)?;
        Ok(set)
    }

    /// Rules 4 to 6, and the `Date` and `content-length` rules, over the parsed names.
    fn enforce(&self, headers: &HeaderMap, wire_content_length: Option<u64>) -> Result<(), AuthError> {
        let set = self;
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

        // A request with no `x-amz-date` is dated by its `Date` header (rustfs/gateway#809), so
        // that header is the timestamp the skew check judged, and it must be covered: left
        // unsigned, a captured request could be replayed forever under a fresh `Date`. With
        // `x-amz-date` present, `Date` is an ordinary header and may be left unsigned.
        if !headers.contains_key(X_AMZ_DATE) && headers.contains_key(DATE) && !set.contains(&DATE) {
            return Err(AuthError::SignatureDoesNotMatch);
        }

        if set.contains(&CONTENT_LENGTH) {
            set.check_content_length(headers, wire_content_length)?;
        }

        Ok(())
    }

    /// Whether the canonical request writes the list verbatim, as legacy RustFS does.
    pub(crate) fn reads_verbatim(&self) -> bool {
        self.reading == ListReading::LegacyRustfs
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

    /// The covered names, lowercase: ascending, the order the canonical request uses, for a list
    /// AWS emits; in the order first written, each once, for one read verbatim.
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

    /// The validated `SignedHeaders` line exactly as supplied.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// An owned `SignedHeaders` line for callers that need to retain it independently.
    #[must_use]
    pub fn canonical_list(&self) -> String {
        self.raw.clone()
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
        let canonical: &str = set.as_str();
        assert_eq!(canonical, "host;x-amz-date");
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

    /// Negative — with no `x-amz-date`, the `Date` header supplies the timestamp and must be signed
    /// (rustfs/gateway#809); left out of the list it is a `SignatureDoesNotMatch`, like an unsigned
    /// `x-amz-*` header.
    #[test]
    fn n_a_date_that_supplies_the_timestamp_must_be_signed() {
        let map = headers(&[("date", "Mon, 14 Sep 2026 03:16:56 GMT")]);
        assert_eq!(
            SignedHeaderSet::parse_and_enforce("host", &map, None).err(),
            Some(AuthError::SignatureDoesNotMatch)
        );
        assert!(SignedHeaderSet::parse_and_enforce("date;host", &map, None).is_ok());
    }

    /// Positive — the legacy RustFS reading reads a list AWS emits exactly as the AWS reading does,
    /// and reads verbatim a list AWS would call malformed: uppercase, out of order, repeated.
    #[test]
    fn the_legacy_reading_reads_what_legacy_rustfs_reads() {
        let map = headers(&[("x-amz-date", "d"), ("x-amz-content-sha256", "UNSIGNED-PAYLOAD")]);
        let aws = "host;x-amz-content-sha256;x-amz-date";
        assert_eq!(
            SignedHeaderSet::parse_and_enforce_as_legacy_rustfs(aws, &map, None),
            SignedHeaderSet::parse_and_enforce(aws, &map, None)
        );
        assert!(
            !SignedHeaderSet::parse_and_enforce_as_legacy_rustfs(aws, &map, None)
                .expect("valid")
                .reads_verbatim()
        );
        for verbatim in [
            "HOST;X-AMZ-CONTENT-SHA256;X-AMZ-DATE",
            "x-amz-date;host;x-amz-content-sha256",
            "host;host;x-amz-content-sha256;x-amz-date",
            "Host;host;x-amz-content-sha256;x-amz-date",
        ] {
            let set = SignedHeaderSet::parse_and_enforce_as_legacy_rustfs(verbatim, &map, None).expect(verbatim);
            assert!(set.reads_verbatim(), "{verbatim}");
            assert_eq!(set.as_str(), verbatim);
            assert_eq!(set.len(), 3, "{verbatim}: each header once");
        }
    }

    /// Negative — the legacy RustFS reading keeps every completeness rule, case-insensitively:
    /// `host` named, every name sent (a name that is not a header name included), every `x-amz-*`
    /// sent named, and a named `content-length` the wire's.
    #[test]
    fn n_the_legacy_reading_keeps_every_completeness_rule() {
        let map = headers(&[("x-amz-date", "d"), ("content-length", "3")]);
        for list in [
            "X-AMZ-DATE",
            "HOST;X-AMZ-DATE;X-AMZ-META-GONE",
            "x-amz-date;host;x-amz-meta-gone",
            "HOST",
            "host;;x-amz-date",
            "x-amz-date;host; x-amz-date",
            "CONTENT-LENGTH;HOST;X-AMZ-DATE",
        ] {
            assert_eq!(
                SignedHeaderSet::parse_and_enforce_as_legacy_rustfs(list, &map, Some(4)),
                Err(AuthError::SignatureDoesNotMatch),
                "{list}"
            );
        }
        assert!(SignedHeaderSet::parse_and_enforce_as_legacy_rustfs("CONTENT-LENGTH;HOST;X-AMZ-DATE", &map, Some(3)).is_ok());
    }

    /// Positive — with `x-amz-date` present, `Date` is an ordinary header: it may be signed or
    /// left unsigned, because the timestamp is read from `x-amz-date` either way.
    #[test]
    fn a_date_beside_x_amz_date_may_stay_unsigned() {
        let map = headers(&[("x-amz-date", "20260914T031656Z"), ("date", "Mon, 14 Sep 2026 03:16:56 GMT")]);
        assert!(SignedHeaderSet::parse_and_enforce("host;x-amz-date", &map, None).is_ok());
        assert!(SignedHeaderSet::parse_and_enforce("date;host;x-amz-date", &map, None).is_ok());
    }
}
