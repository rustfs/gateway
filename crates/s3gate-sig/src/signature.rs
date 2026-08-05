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

//! The signature value, its fixed-width container, and the only way to compare two of them.
//!
//! Responsible for: [`CtBytes`] (fixed-width, unprintable, uncomparable bytes), [`Signature`]
//! (one variant per algorithm width), the single constant-time comparison entry point, and
//! [`SignatureMatch`] — the proof token that makes "authenticated without comparing" fail to
//! compile.
//! NOT responsible for: deriving signing keys, building the canonical request or the
//! string-to-sign (P2-02/P2-03), or deciding what an authenticated identity may do (that is
//! authorization, in `s3gate-core`).
//! Upstream: `subtle`, [`crate::codec`]. Downstream: P2-02's verifier and `s3gate-core`'s authn
//! stage, which can only build its `Authenticated` verdict by presenting a [`SignatureMatch`].

use subtle::ConstantTimeEq;

/// Fixed-width bytes that can only be compared in constant time.
///
/// # Why fixed width
///
/// `subtle`'s slice comparison short-circuits when the two slices differ in length (documented in
/// `subtle` 2.6.1). Comparing attacker-influenced `&[u8]` would therefore leak the expected
/// length. A `CtBytes<N>` can only be compared against another `CtBytes<N>`, so the lengths are
/// equal by construction and the comparison is total.
///
/// # Why it has no `PartialEq` and no `Debug`
///
/// A derived `PartialEq` is a byte-wise comparison that stops at the first difference — a timing
/// oracle that recovers the expected signature one byte at a time. A derived `Debug` is how the
/// expected signature ends up in a log. Both are absent, so both mistakes are compile errors:
///
/// ```compile_fail,E0369
/// use s3gate_sig::CtBytes;
/// let a = CtBytes::<32>::from_array([0u8; 32]);
/// let b = CtBytes::<32>::from_array([0u8; 32]);
/// let _ = a == b; // no PartialEq: does not compile
/// ```
///
/// ```compile_fail,E0277
/// use s3gate_sig::CtBytes;
/// let a = CtBytes::<32>::from_array([0u8; 32]);
/// println!("{a:?}"); // no Debug: does not compile
/// ```
#[derive(Clone)]
pub struct CtBytes<const N: usize>([u8; N]);

impl<const N: usize> CtBytes<N> {
    /// Wraps bytes that have already been strictly decoded to their exact width.
    ///
    /// The caller is responsible for having used [`crate::codec::decode_hex_lower`] or an
    /// equivalent length-exact decoder: those fail rather than truncate or zero-pad, which is
    /// what keeps a client from choosing how many bytes the comparison covers.
    #[must_use]
    pub fn from_array(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrows the bytes, for the constant-time comparison in this crate only.
    pub(crate) fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    /// The width in bytes. Public because the width is algorithm metadata, not key material.
    #[must_use]
    pub const fn width(&self) -> usize {
        N
    }
}

/// A computed or presented signature.
///
/// This is an enum and not a `[u8; 32]` because SigV2 signs with HMAC-SHA1 and produces **20**
/// bytes. A 32-byte-only type would force a second signature type to appear later, and the second
/// type is the one nobody remembers to keep `PartialEq`-free.
///
/// Like [`CtBytes`], it has no `PartialEq` and no `Debug`:
///
/// ```compile_fail,E0369
/// use s3gate_sig::{CtBytes, Signature};
/// let a = Signature::HmacSha256(CtBytes::from_array([0u8; 32]));
/// let b = Signature::HmacSha256(CtBytes::from_array([0u8; 32]));
/// let _ = a == b; // does not compile; use `Signature::ct_verify`
/// ```
#[non_exhaustive]
#[derive(Clone)]
pub enum Signature {
    /// SigV4 — header, presigned query, POST policy, chunk and trailer signatures.
    HmacSha256(CtBytes<32>),
    /// SigV2 — HMAC-SHA1, 20 bytes.
    HmacSha1(CtBytes<20>),
    /// SigV4a — ECDSA P-256, reserved. Verification is not implemented in this phase.
    EcdsaP256(CtBytes<64>),
}

/// Proof that two signatures were compared in constant time and were equal.
///
/// The type is a zero-sized token with a private field, so the only way to obtain one is
/// [`Signature::ct_verify`]. Downstream, an authenticated verdict is expected to be shaped as
/// `Verdict::Authenticated { identity, proof: SignatureMatch }` — which means a code path that
/// never compared anything cannot construct the verdict, and "forgot to verify" becomes a
/// compile error rather than a CVE (the shape of MinIO CVE-2025-31489).
///
/// It has no `Debug` and no `PartialEq`: it carries nothing to print and nothing to compare.
#[derive(Clone, Copy)]
pub struct SignatureMatch(());

/// Why a signature comparison did not produce a [`SignatureMatch`].
///
/// Both variants are safe to log — they say nothing about the expected value. `AlgorithmMismatch`
/// in particular exists so that a 20-byte SigV2 signature can never be compared against a 32-byte
/// SigV4 signature by truncating or zero-padding either one.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerifyRejection {
    /// The two signatures are of different algorithms; they are not comparable at all.
    AlgorithmMismatch,
    /// Same algorithm, different value.
    Mismatch,
}

impl Signature {
    /// The single comparison entry point for signature material.
    ///
    /// Same-algorithm signatures are compared over their whole fixed width in constant time.
    /// Different algorithms are rejected outright rather than coerced: truncating a 32-byte value
    /// to 20, or zero-extending a 20-byte value to 32, would let an attacker pick the comparison
    /// width.
    ///
    /// # Errors
    ///
    /// [`VerifyRejection::AlgorithmMismatch`] if the variants differ, [`VerifyRejection::Mismatch`]
    /// if the bytes differ.
    pub fn ct_verify(&self, expected: &Self) -> Result<SignatureMatch, VerifyRejection> {
        let equal = match (self, expected) {
            (Self::HmacSha256(lhs), Self::HmacSha256(rhs)) => lhs.as_array().ct_eq(rhs.as_array()),
            (Self::HmacSha1(lhs), Self::HmacSha1(rhs)) => lhs.as_array().ct_eq(rhs.as_array()),
            (Self::EcdsaP256(lhs), Self::EcdsaP256(rhs)) => lhs.as_array().ct_eq(rhs.as_array()),
            _ => return Err(VerifyRejection::AlgorithmMismatch),
        };
        if bool::from(equal) {
            Ok(SignatureMatch(()))
        } else {
            Err(VerifyRejection::Mismatch)
        }
    }

    /// The signature width in bytes. Algorithm metadata, not key material.
    #[must_use]
    pub const fn width(&self) -> usize {
        match self {
            Self::HmacSha256(_) => 32,
            Self::HmacSha1(_) => 20,
            Self::EcdsaP256(_) => 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_signatures_produce_a_match() {
        let lhs = Signature::HmacSha256(CtBytes::from_array([7u8; 32]));
        let rhs = Signature::HmacSha256(CtBytes::from_array([7u8; 32]));
        assert!(lhs.ct_verify(&rhs).is_ok());
    }

    #[test]
    fn one_differing_byte_is_a_mismatch() {
        let mut bytes = [7u8; 32];
        bytes[31] ^= 0x01;
        let lhs = Signature::HmacSha256(CtBytes::from_array([7u8; 32]));
        let rhs = Signature::HmacSha256(CtBytes::from_array(bytes));
        // `assert_eq!` is unavailable on purpose: the Ok side carries `SignatureMatch`, which has
        // neither `Debug` nor `PartialEq`.
        assert!(matches!(lhs.ct_verify(&rhs), Err(VerifyRejection::Mismatch)));
    }

    #[test]
    fn widths_are_reported_per_algorithm() {
        assert_eq!(Signature::HmacSha1(CtBytes::from_array([0u8; 20])).width(), 20);
        assert_eq!(Signature::EcdsaP256(CtBytes::from_array([0u8; 64])).width(), 64);
    }
}
