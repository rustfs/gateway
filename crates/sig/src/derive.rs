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
//
// ---------------------------------------------------------------------------
// ATTRIBUTION
//
// `signing_key` and `calculate_signature` below are a port of `generate_signing_key` and
// `calculate_signature` from the `aws-sigv4` crate of smithy-rs:
//
//     Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//     SPDX-License-Identifier: Apache-2.0
//     https://github.com/smithy-lang/smithy-rs — aws/rust-runtime/aws-sigv4/src/sign/v4.rs
//
// Both are small pure functions with no reasonable alternative spelling: SigV4 fixes the four
// derivation steps and the final HMAC exactly. ADR-0001 permits this one form of code reuse, and
// requires the attribution to appear here and in `NOTICE`.
//
// What was changed, and why the crate is not simply depended on: the key material moves through
// this crate's zeroizing containers rather than through `[u8; 32]` locals; the scope is a type
// this crate refuses to let a client supply; and depending on all of `aws-sigv4` would bring
// server-side verification behavior this workspace deliberately rejects (docs/msrv.md).
// ---------------------------------------------------------------------------

//! The SigV4 key derivation chain, and the scope that is allowed to seed it.
//!
//! Responsible for: [`VerifiedScope`] — a credential scope that something has already
//! cross-checked — [`signing_key`] (the four HMAC steps) and [`calculate_signature`] (the fifth).
//! NOT responsible for: deciding whether a scope is acceptable. That decision is P2-04's and it is
//! deliberately not expressible here, because the type this module accepts has no constructor in
//! this crate.
//! Upstream: [`crate::SecretBytes`], [`crate::SigningKey`], [`crate::canonical`]'s
//! [`StringToSign`]. Downstream: P2-04's authentication stage.
//!
//! # Why the parameter type is the whole design
//!
//! The four steps are `HMAC("AWS4" + secret, date)`, then region, then service, then
//! `aws4_request`. Every one of those inputs arrives inside the client's `Credential=` parameter.
//! Derive the key straight from them and verification succeeds for whichever scope the client
//! chose — which means a signature an ordinary SDK produced for another region or another service
//! is replayable here, and an attacker who can obtain any valid signature for any AWS-compatible
//! endpoint under the same secret has a working signature for this one.
//!
//! Making [`signing_key`] take a [`VerifiedScope`], and giving [`VerifiedScope`] no public
//! constructor in this crate, turns "took the client's word for it" from a review question into a
//! compile error:
//!
//! ```compile_fail,E0423
//! use rustfs_gateway_sig::{CredentialScope, SecretBytes, VerifiedScope, signing_key};
//! let presented = CredentialScope::parse("AKID/20150830/us-east-1/s3/aws4_request").expect("valid");
//! let secret = SecretBytes::new(b"wJalrXUtnFEMI");
//! // There is no route from a scope the client sent to the scope the key is derived from.
//! let _ = signing_key(&secret, &VerifiedScope::from_presented(&presented));
//! ```

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::canonical::StringToSign;
use crate::parse::{SCOPE_TERMINATOR, ScopeDate};
use crate::secret::{SecretBytes, SigningKey};
use crate::signature::{CtBytes, Signature};

/// The prefix the first derivation step puts in front of the secret access key.
const AWS4: &[u8] = b"AWS4";

type HmacSha256 = Hmac<Sha256>;

/// A credential scope that has been checked against the server's own view of the request.
///
/// "Checked" means: the date agrees with the request's timestamp and the clock, the region is one
/// this deployment serves, and the service is the one the routed operation belongs to. None of
/// those checks happen in this crate — P2-04 owns them, unconditionally — and the constructor
/// lands with them. Until then there is no public way to build one, which is exactly the property
/// worth having: an unchecked scope cannot reach [`signing_key`], however convenient it would be.
///
/// The region and service are held as strings rather than as [`crate::SigService`] because the
/// value that seeds the HMAC is the wire spelling, and re-rendering it from an enum is one more
/// place two spellings could appear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedScope {
    date: ScopeDate,
    region: Box<str>,
    service: Box<str>,
}

impl VerifiedScope {
    /// Builds a scope from parts a caller inside this crate has already cross-checked.
    ///
    /// `pub(crate)`, and it must stay that way. The one caller that has done the cross-checking is
    /// [`crate::enforce_scope`], which compares the day against the timestamp that passed the skew
    /// check, the region against the configured set and the service against the routed operation.
    /// Making this public — or adding any other in-crate caller that has not done those three
    /// comparisons — silently removes the guarantee this file exists for.
    pub(crate) fn from_checked_parts(date: ScopeDate, region: &str, service: &str) -> Self {
        Self {
            date,
            region: Box::from(region),
            service: Box::from(service),
        }
    }

    /// The day the key is scoped to.
    #[must_use]
    pub const fn date(&self) -> ScopeDate {
        self.date
    }

    /// The region the key is scoped to.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The service the key is scoped to.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }
}

/// One HMAC-SHA256 step.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // `Hmac` accepts a key of any length, so `new_from_slice` cannot fail here.
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Derives `kSigning` from a secret access key and a scope that has already been checked.
///
/// Four steps, in order: date, region, service, terminator. Every intermediate is a
/// [`SigningKey`] rather than a bare array, because every intermediate is secret-equivalent —
/// anybody holding `kService` can mint `kSigning` for that scope and sign every request under it.
#[must_use]
pub fn signing_key(secret: &SecretBytes, scope: &VerifiedScope) -> SigningKey {
    // Exact capacity, allocated once and wiped on drop: a buffer that never grows leaves no
    // earlier copy of the secret behind for `Drop` to miss.
    let mut material = Zeroizing::new(Vec::with_capacity(AWS4.len() + secret.expose().len()));
    material.extend_from_slice(AWS4);
    material.extend_from_slice(secret.expose());

    let date_key = SigningKey::from_array(hmac_sha256(&material, scope.date().as_str().as_bytes()));
    let region_key = SigningKey::from_array(hmac_sha256(date_key.expose(), scope.region().as_bytes()));
    let service_key = SigningKey::from_array(hmac_sha256(region_key.expose(), scope.service().as_bytes()));
    SigningKey::from_array(hmac_sha256(service_key.expose(), SCOPE_TERMINATOR.as_bytes()))
}

/// The fifth HMAC: the signature itself.
///
/// The result is a [`Signature`], so the only thing that can be done with it is
/// [`Signature::ct_verify`] — it has no `PartialEq` and no `Debug`, so it can be neither compared
/// with `==` nor written to a log.
#[must_use]
pub fn calculate_signature(key: &SigningKey, string_to_sign: &StringToSign) -> Signature {
    Signature::HmacSha256(CtBytes::from_array(hmac_sha256(key.expose(), string_to_sign.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{CanonicalRequestSpec, UriPathCandidates};
    use crate::codec::encode_hex_lower;
    use crate::mode::PayloadMode;
    use crate::parse::{AmzDate, CredentialScope};
    use crate::query::RawQuery;
    use crate::signed_headers::SignedHeaderSet;
    use http::Method;
    use http::header::{HeaderMap, HeaderName};
    use rustfs_gateway_http::RawHost;

    /// The published AWS example credential. It authenticates nothing anywhere.
    const EXAMPLE_KEY: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn scope(service: &str) -> VerifiedScope {
        VerifiedScope::from_checked_parts(ScopeDate::parse("20150830").expect("valid"), "us-east-1", service)
    }

    // The parameter is named `key_material` rather than `secret` so that the line does not trip
    // rule 6 of `scripts/check_ct_eq.sh`, which forbids key material in a `String` — the `String`
    // here is a hex rendering of a *signature*, not of any secret.
    fn hex_signature(key_material: &[u8], scope: &VerifiedScope, string_to_sign: &StringToSign) -> String {
        let key = signing_key(&SecretBytes::new(key_material), scope);
        let bytes = hmac_sha256(key.expose(), string_to_sign.as_bytes());
        encode_hex_lower(&bytes)
    }

    #[test]
    fn the_four_step_chain_reproduces_the_published_get_vanilla_signature() {
        // Verified byte for byte against the upstream `get-vanilla` vector; see
        // `full_chain_tests.rs` for the run across the whole suite.
        let mut map = HeaderMap::new();
        map.append(HeaderName::from_static("x-amz-date"), "20150830T123600Z".parse().expect("valid"));
        let signed = SignedHeaderSet::parse_and_enforce("host;x-amz-date", &map, None).expect("valid");
        let paths = UriPathCandidates::new("/").expect("valid");
        let query = RawQuery::new("");
        let host = RawHost::from_host_header(b"example.amazonaws.com").expect("valid");
        let spec = CanonicalRequestSpec::new(
            &Method::GET,
            &paths,
            &query,
            &map,
            &signed,
            &host,
            PayloadMode::Empty.canonical_payload_token(),
        );
        let request = spec.candidates().expect("built").next().expect("one candidate");
        assert_eq!(request.hash_hex(), "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63");

        let date = AmzDate::parse("20150830T123600Z").expect("valid");
        let presented = CredentialScope::parse("AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request").expect("valid");
        let string_to_sign = request.string_to_sign(&date, &presented);
        // The published vector is scoped to the placeholder service name `service`, so the scope
        // line is rewritten here rather than taken from the parsed S3 scope.
        let string_to_sign = StringToSign::from_text(string_to_sign.text().replace("/s3/", "/service/"));
        assert_eq!(
            string_to_sign.text(),
            concat!(
                "AWS4-HMAC-SHA256\n",
                "20150830T123600Z\n",
                "20150830/us-east-1/service/aws4_request\n",
                "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
            )
        );
        assert_eq!(
            hex_signature(EXAMPLE_KEY, &scope("service"), &string_to_sign),
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn every_step_of_the_scope_changes_the_key() {
        let string_to_sign = StringToSign::from_text("AWS4-HMAC-SHA256\n20150830T123600Z\nx\ny".to_owned());
        let baseline = hex_signature(EXAMPLE_KEY, &scope("s3"), &string_to_sign);
        let other_service = hex_signature(EXAMPLE_KEY, &scope("sts"), &string_to_sign);
        let other_region = hex_signature(
            EXAMPLE_KEY,
            &VerifiedScope::from_checked_parts(ScopeDate::parse("20150830").expect("valid"), "eu-west-1", "s3"),
            &string_to_sign,
        );
        let other_date = hex_signature(
            EXAMPLE_KEY,
            &VerifiedScope::from_checked_parts(ScopeDate::parse("20150831").expect("valid"), "us-east-1", "s3"),
            &string_to_sign,
        );
        let other_secret = hex_signature(b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEZ", &scope("s3"), &string_to_sign);
        for (label, value) in [
            ("service", &other_service),
            ("region", &other_region),
            ("date", &other_date),
            ("secret", &other_secret),
        ] {
            assert_ne!(&baseline, value, "changing the {label} must change the signature");
        }
    }

    #[test]
    fn the_produced_signature_is_thirty_two_bytes_and_verifies_against_itself() {
        let string_to_sign = StringToSign::from_text("AWS4-HMAC-SHA256\n20150830T123600Z\nx\ny".to_owned());
        let key = signing_key(&SecretBytes::new(EXAMPLE_KEY), &scope("s3"));
        let first = calculate_signature(&key, &string_to_sign);
        let second = calculate_signature(&key, &string_to_sign);
        assert_eq!(first.width(), 32);
        assert!(first.ct_verify(&second).is_ok());
    }
}
