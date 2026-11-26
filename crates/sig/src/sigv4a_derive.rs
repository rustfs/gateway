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

//! SigV4a ECDSA P-256 keypair derivation (NIST SP 800-108 + FIPS 186-4 B.4.2) and verification.
//!
//! Responsible for: deriving the deterministic P-256 public verifying key [`SigV4aVerifyingKey`]
//! from `(AccessKeyId, SecretBytes)` while wiping all secret intermediates immediately, and
//! verifying ASN.1 DER ECDSA P-256 signatures to mint [`SignatureMatch`].
//! NOT responsible for: parsing `Authorization` or query parameters ([`crate::sigv4a`]),
//! canonicalizing requests ([`crate::canonical`]), or streaming chunk framing
//! (`rustfs-gateway-http`).
//! Upstream: `hmac`, `sha2`, `p256`, `zeroize`, [`crate::SecretBytes`], [`crate::sigv4a`].
//! Downstream: `rustfs-gateway`'s `SigV4Authenticator` and [`crate::sigv4a_signer`].

use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::signature::Verifier;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::canonical::StringToSign;
use crate::error::SigParseError;
use crate::scheme::ALGORITHM_SIGV4A;
use crate::secret::SecretBytes;
use crate::signature::{SignatureMatch, VerifyRejection, ecdsa_signature_match};
use crate::sigv4a::{EcdsaDerSignature, VerifiedSigV4aScope};
use crate::verdict::Identity;

type HmacSha256 = Hmac<Sha256>;

/// The prefix prepended to the secret access key for the SigV4a SP 800-108 KDF.
const AWS4A_PREFIX: &[u8] = b"AWS4A";

/// Fixed 32-bit big-endian iteration counter `i = 1` in SP 800-108 counter mode.
const KDF_ITERATION_BE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// Fixed 32-bit big-endian output bit length `L = 256` in SP 800-108 counter mode.
const KDF_LENGTH_BITS_BE: [u8; 4] = [0x00, 0x00, 0x01, 0x00];

/// P-256 group order minus two (`n - 2`), big-endian, for FIPS 186-4 B.4.2 scalar testing.
///
/// `n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`.
const P256_N_MINUS_2_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7,
    0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f,
];

/// Derived P-256 public verifying key for a SigV4a credential pair.
///
/// Holds only the public curve point — never the private scalar, which is wiped before this value
/// is constructed. Safe to hand as 33-byte compressed SEC1 bytes across the streaming chunk
/// verification boundary without expanding the secret exposure surface.
#[derive(Clone, Copy)]
pub struct SigV4aVerifyingKey {
    inner: p256::ecdsa::VerifyingKey,
}

impl SigV4aVerifyingKey {
    /// Derives the deterministic SigV4a P-256 public verifying key from `access_key_id` and
    /// `secret`.
    ///
    /// Implements the AWS SigV4a counter-mode KDF (NIST SP 800-108 over HMAC-SHA256 with key
    /// `"AWS4A" || secret` and input `0x00000001 || "AWS4-ECDSA-P256-SHA256" || 0x00 ||
    /// access_key_id || counter || 0x00000100`, `counter = 1..=254`) combined with FIPS 186-4
    /// B.4.2 (`c <= n - 2`, `d = c + 1`). Every secret intermediate and the ephemeral P-256
    /// private scalar are zeroized on drop before returning.
    ///
    /// # Errors
    ///
    /// [`SigParseError::InvalidAccessKeyId`] if `access_key_id` is not a valid access key id, or
    /// if the KDF counter exhausts `1..=254` without producing an in-range scalar.
    pub fn derive(access_key_id: &str, secret: &SecretBytes) -> Result<Self, SigParseError> {
        let ephemeral = derive_p256_signing_key(access_key_id, secret)?;
        let inner = *ephemeral.verifying_key();
        drop(ephemeral);
        Ok(Self { inner })
    }

    /// Exports the 33-byte SEC1 compressed public key encoding for downstream chunk verification.
    #[must_use]
    pub fn compressed_sec1(&self) -> [u8; 33] {
        let point = self.inner.to_sec1_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Exports the uncompressed affine `(X, Y)` coordinates as 32-byte big-endian arrays.
    #[cfg(test)]
    pub(crate) fn uncompressed_xy(&self) -> ([u8; 32], [u8; 32]) {
        let point = self.inner.to_sec1_point(false);
        let bytes = point.as_bytes();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        (x, y)
    }
}

/// Allocates the exact-size `"AWS4A" || raw` KDF key once in a `Box<[u8]>` so it never grows.
fn build_kdf_key(raw: &[u8]) -> Zeroizing<Box<[u8]>> {
    let mut buf = vec![0u8; AWS4A_PREFIX.len() + raw.len()].into_boxed_slice();
    buf[..AWS4A_PREFIX.len()].copy_from_slice(AWS4A_PREFIX);
    buf[AWS4A_PREFIX.len()..].copy_from_slice(raw);
    Zeroizing::new(buf)
}

/// Evaluates `lhs <= rhs` for 256-bit unsigned big-endian integers without secret-dependent early
/// exit.
fn be_u256_le(lhs: &[u8; 32], rhs: &[u8; 32]) -> bool {
    let mut borrow: u16 = 0;
    let mut index = 32usize;
    while index > 0 {
        index -= 1;
        let diff = u16::from(rhs[index]).wrapping_sub(u16::from(lhs[index])).wrapping_sub(borrow);
        borrow = (diff >> 15) & 1;
    }
    borrow == 0
}

/// Computes `value + 1` on a 256-bit unsigned big-endian integer (caller guarantees `value <= n-2`).
fn be_u256_add_one(value: &[u8; 32]) -> [u8; 32] {
    let mut out = *value;
    let mut carry: u16 = 1;
    let mut index = 32usize;
    while index > 0 {
        index -= 1;
        let sum = u16::from(out[index]) + carry;
        out[index] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    out
}

/// Derives the ephemeral P-256 `SigningKey` (`ZeroizeOnDrop`). Crate-private so private scalars
/// never leak across the crate boundary; verification callers use [`SigV4aVerifyingKey::derive`].
pub(crate) fn derive_p256_signing_key(
    access_key_id: &str,
    key_material: &SecretBytes,
) -> Result<p256::ecdsa::SigningKey, SigParseError> {
    let _ = Identity::new(access_key_id)?;
    let kdf_key = build_kdf_key(key_material.expose());
    let akid = access_key_id.as_bytes();

    for counter in 1u8..=254u8 {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&kdf_key).expect("HMAC-SHA256 accepts any key length");
        mac.update(&KDF_ITERATION_BE);
        mac.update(ALGORITHM_SIGV4A.as_bytes());
        mac.update(&[0x00]);
        mac.update(akid);
        mac.update(&[counter]);
        mac.update(&KDF_LENGTH_BITS_BE);
        let candidate: Zeroizing<[u8; 32]> = Zeroizing::new(mac.finalize().into_bytes().into());

        if be_u256_le(&candidate, &P256_N_MINUS_2_BE) {
            let scalar = Zeroizing::new(be_u256_add_one(&candidate));
            if let Ok(ephemeral) = p256::ecdsa::SigningKey::from_bytes((&*scalar).into()) {
                return Ok(ephemeral);
            }
        }
    }
    Err(SigParseError::InvalidAccessKeyId)
}

/// Verifies an ASN.1 DER ECDSA P-256 signature over `string_to_sign` and mints [`SignatureMatch`]
/// on success.
///
/// Requires a [`VerifiedSigV4aScope`] (which only [`crate::enforce_sigv4a_scope`] constructs),
/// enforcing at compile time that H5 date, region-set, and service checks completed before
/// verification. Valid AWS SigV4a signatures with high-S (`s > n/2`) are normalized before
/// verification because AWS signers do not enforce low-S.
///
/// # Errors
///
/// [`VerifyRejection::Mismatch`] if the DER signature does not verify against `verifying_key`
/// and `string_to_sign`.
pub fn verify_sigv4a_signature(
    verifying_key: &SigV4aVerifyingKey,
    _scope: &VerifiedSigV4aScope,
    string_to_sign: &StringToSign,
    presented: &EcdsaDerSignature,
) -> Result<SignatureMatch, VerifyRejection> {
    verify_der_message(&verifying_key.inner, string_to_sign.as_bytes(), presented.as_der_bytes())
        .map(|()| ecdsa_signature_match())
        .map_err(|()| VerifyRejection::Mismatch)
}

/// Normalizes an ASN.1 DER ECDSA P-256 signature to canonical low-S DER so `(r, s)` and
/// `(r, n - s)` produce identical bytes (preventing presigned replay-fingerprint malleability).
pub(crate) fn canonical_low_s_der(der_bytes: &[u8]) -> Option<p256::ecdsa::DerSignature> {
    let parsed = p256::ecdsa::Signature::from_der(der_bytes).ok()?;
    Some(parsed.normalize_s().to_der())
}

/// Verifies raw ASN.1 DER bytes against a P-256 verifying key, accepting compliant high-S values.
pub(crate) fn verify_der_message(verifying_key: &p256::ecdsa::VerifyingKey, message: &[u8], der_bytes: &[u8]) -> Result<(), ()> {
    let parsed = p256::ecdsa::Signature::from_der(der_bytes).map_err(|_| ())?;
    let normalized = parsed.normalize_s();
    verifying_key.verify(message, &normalized).map_err(|_| ())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use http::{HeaderMap, Method};

    use super::*;
    use crate::{
        Admission, AmzDate, CanonicalRequestSpec, ExpectedScope, OperationFloor, PayloadMode, RawHost, RawQuery, RegionSet,
        RequestNow, ScopeDate, SecurityFloor, SigService, SigV4aPresignedParams, SigV4aSigner, SignedHeaderSet,
        SigningCredentials, SigningRequest, UriPathCandidates, WireView, enforce_sigv4a_scope,
    };

    /// Flips ECDSA P-256 DER `(r, s)` to its malleable twin `(r, n - s)` in canonical minimal DER.
    fn flip_p256_der_s(der_hex: &str) -> String {
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa,
            0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ];
        let der: Vec<u8> = (0..der_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&der_hex[i..i + 2], 16).expect("hex"))
            .collect();
        let r_len = usize::from(der[3]);
        let r = &der[4..4 + r_len];
        let s_off = 4 + r_len;
        let s_len = usize::from(der[s_off + 1]);
        let s_raw = &der[s_off + 2..s_off + 2 + s_len];
        let s_trim = s_raw.strip_prefix(&[0]).unwrap_or(s_raw);
        let mut s_be = [0u8; 32];
        s_be[32 - s_trim.len()..].copy_from_slice(s_trim);
        let (mut s_neg, mut borrow) = ([0u8; 32], 0i16);
        for i in (0..32).rev() {
            let diff = i16::from(N[i]) - i16::from(s_be[i]) - borrow;
            s_neg[i] = if diff < 0 {
                borrow = 1;
                (diff + 256) as u8
            } else {
                borrow = 0;
                diff as u8
            };
        }
        let first = s_neg.iter().position(|&b| b != 0).unwrap_or(31);
        let mut s_enc = Vec::with_capacity(33);
        if s_neg[first] & 0x80 != 0 {
            s_enc.push(0);
        }
        s_enc.extend_from_slice(&s_neg[first..]);
        let mut out = vec![0x30, (4 + r.len() + s_enc.len()) as u8, 0x02, r.len() as u8];
        out.extend_from_slice(r);
        out.extend_from_slice(&[0x02, s_enc.len() as u8]);
        out.extend_from_slice(&s_enc);
        out.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Negative — presigned SigV4a `ReplayFingerprint` normalizes ECDSA `(r, s)` and `(r, n - s)`
    /// to the same canonical low-S DER digest so single-use replay protection cannot be bypassed.
    #[test]
    fn n_sigv4a_presigned_replay_fingerprint_is_invariant_to_high_s_malleability() {
        const AKID: &str = "AKIDEXAMPLE";
        const SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let day = ScopeDate::parse("20150830").expect("day");
        let stamp = AmzDate::parse("20150830T123600Z").expect("stamp");
        let now = RequestNow::from_unix_seconds(1_440_938_160);
        let host = RawHost::from_host_header(b"example.amazonaws.com").expect("host");
        let signer = SigV4aSigner::new(SigningCredentials::new(AKID, SECRET).expect("creds"), day, SigService::S3, "us-east-1")
            .expect("signer");
        let empty = HeaderMap::new();
        let req = SigningRequest::new(&Method::GET, "/b/k", "", &empty, &host, PayloadMode::Unsigned, stamp);
        let signed = signer.presign(&req, 300).expect("presigns");
        let twin_hex = flip_p256_der_s(signed.signature_hex());
        assert_ne!(signed.signature_hex(), twin_hex);
        let twin_query = signed.query().replace(signed.signature_hex(), &twin_hex);

        let floor = SecurityFloor::new();
        let op = OperationFloor::builtin_presigned("GetObject", SigService::S3);
        let Admission::Sealed(s1) = floor
            .admit(WireView::new(signed.headers(), RawQuery::new(signed.query())), &op, now)
            .expect("admit orig")
        else {
            panic!("expected Sealed");
        };
        let Admission::Sealed(s2) = floor
            .admit(WireView::new(signed.headers(), RawQuery::new(&twin_query)), &op, now)
            .expect("admit twin")
        else {
            panic!("expected Sealed");
        };
        assert_eq!(s1.replay_fingerprint().expect("orig fp"), s2.replay_fingerprint().expect("twin fp"));

        let params_twin = SigV4aPresignedParams::parse(&RawQuery::new(&twin_query)).expect("twin parses");
        let regions = RegionSet::new(["us-east-1"]).expect("regions");
        let verified = enforce_sigv4a_scope(
            params_twin.scope(),
            params_twin.region_set(),
            s2.clock(),
            &ExpectedScope::new(SigService::S3, &regions),
        )
        .expect("scope ok");
        let sh = SignedHeaderSet::parse_and_enforce(params_twin.signed_headers(), signed.headers(), None).expect("sh");
        let paths = UriPathCandidates::new("/b/k").expect("path");
        let rq = RawQuery::new(&twin_query);
        let cand = CanonicalRequestSpec::new(
            &Method::GET,
            &paths,
            &rq,
            signed.headers(),
            &sh,
            &host,
            PayloadMode::Unsigned.canonical_payload_token(),
        )
        .presigned()
        .candidates()
        .expect("cands")
        .next()
        .expect("one");
        let vk = SigV4aVerifyingKey::derive(AKID, &SecretBytes::new(SECRET)).expect("vk");
        verify_sigv4a_signature(
            &vk,
            &verified,
            &cand.string_to_sign_v4a(&stamp, params_twin.scope()),
            params_twin.signature(),
        )
        .expect("malleable twin still authenticates");

        let bad_query = signed.query().replace(signed.signature_hex(), "deadbeef");
        let Admission::Sealed(s_bad) = floor
            .admit(WireView::new(signed.headers(), RawQuery::new(&bad_query)), &op, now)
            .expect("admit malformed")
        else {
            panic!("expected Sealed");
        };
        assert_eq!(s_bad.replay_fingerprint(), None);
    }
}
