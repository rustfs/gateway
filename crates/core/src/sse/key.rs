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

//! The customer-provided key: decoded, checked against its digest, and then gone.
//!
//! Responsible for: [`KeyFingerprint`], the sixteen-byte digest a request's SSE-C headers reduce
//! to, and [`fingerprint_of`], the one function that decodes a key, agrees it with the digest the
//! caller sent, and returns the digest alone.
//! NOT responsible for: encrypting anything, storing a key, or handing one to a backend. A
//! backend that must encrypt reads the key off its own decoded operation input, where the
//! generated dto already carries a hand-written redacting `Debug`; nothing in this module will
//! give it one.
//! Upstream: [`super::base64`]. Downstream: [`super::enforce`], [`super::consistency`].
//!
//! # The raw key does not outlive this file's stack frame
//!
//! There is deliberately no type here that holds a customer key. The bytes exist inside
//! [`fingerprint_of`], in a [`Zeroizing`] stack array, for exactly as long as it takes to hash
//! them; the value that comes out is the digest AWS itself echoes in a response header. That is a
//! stronger guarantee than a redacting `Debug`, because a field that is never stored cannot be
//! printed, serialised, cloned into a log record, or captured by a future `#[derive]` — the four
//! ways `crates/sig`'s `SecretBytes` is careful about, answered by the value not being there.
//!
//! `SecretBytes` was the other candidate. It is the right carrier for a secret a process must
//! *keep* — a signing key, a session token — and it is a heap `Box<[u8]>`, which for a value that
//! lives four statements is a heap allocation whose zeroization is one more thing to be right
//! about. A fixed-width stack array is what `check_ct_eq.sh`'s rule 6 argues for on the same
//! grounds it argues against `Vec<u8>`.
//!
//! # Why the digest comparison is constant time when the digest is not a secret
//!
//! AWS returns `x-amz-server-side-encryption-customer-key-MD5` on every SSE-C response, so the
//! value is not confidential and no attacker learns anything from it that the protocol does not
//! already hand out. The comparison is constant time anyway, for two reasons that do not depend
//! on that: its left-hand side is *derived from key material*, and AGENTS.md's rule on comparing
//! key material admits no exception; and [`KeyFingerprint::matches`] is also the multipart
//! consistency comparison, where the two sides come from two different requests and an early exit
//! would say how many leading bytes of a bound upload's digest a guess got right.

use zeroize::Zeroizing;

use super::base64::{Base64Error, decode_exact};

/// The width of the key a client provides: AES-256, so 256 bits.
pub const CUSTOMER_KEY_BYTES: usize = 32;

/// The width of its MD5 digest.
pub const KEY_DIGEST_BYTES: usize = 16;

/// The MD5 of a customer-provided key.
///
/// No `Debug`, no `Display`, no `PartialEq` — the first two because this repository's rule for
/// anything derived from key material is that it does not render itself, and the third because a
/// derived `PartialEq` is a byte-wise comparison that stops at the first difference. The only
/// comparison is [`KeyFingerprint::matches`]. `Clone` and `Copy` are present: sixteen bytes of a
/// value AWS publishes are cheap to move and awkward to thread by reference through a multipart
/// binding a backend has to store.
#[derive(Clone, Copy)]
pub struct KeyFingerprint([u8; KEY_DIGEST_BYTES]);

impl KeyFingerprint {
    /// Wraps a digest that has already been decoded to its exact width.
    ///
    /// The width is in the type, so there is no length for a caller to get wrong. This is how a
    /// backend rebuilds a fingerprint it stored against an upload id.
    #[must_use]
    pub const fn from_array(bytes: [u8; KEY_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    /// The digest bytes, for a backend that must persist the binding.
    ///
    /// Public because this value is echoed to every SSE-C caller by AWS itself; it is metadata,
    /// not key material. What is **not** public is any route back to the key that produced it.
    #[must_use]
    pub const fn as_array(&self) -> &[u8; KEY_DIGEST_BYTES] {
        &self.0
    }

    /// Whether two fingerprints are the same, compared in constant time.
    ///
    /// The only comparison this type has. See the module documentation for why it is constant
    /// time even though the value is not confidential.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        // The one `subtle::Choice`-to-`bool` conversion in this module, mirroring
        // `crates/sig/src/signature.rs`'s single site. `scripts/check_sse_key_never_leaks.sh`
        // asserts it stays the only one: a second lets `a.ct_eq(&b).into() && other()` be
        // written, and `&&` short-circuits.
        bool::from(self.0.ct_eq(&other.0))
    }
}

/// Decodes a customer key and its digest, agrees them, and returns the digest.
///
/// Both values are decoded strictly ([`super::base64`]) to their exact widths before anything is
/// compared, so a caller cannot choose the comparison width by sending a short key. The key bytes
/// live in a [`Zeroizing`] array that is wiped when this function returns, whichever way it
/// returns.
///
/// # Errors
///
/// [`KeyRejection`] naming which of the three rules fired. The caller is expected to collapse
/// every variant into one client-visible sentence: see [`super::SseRejection`].
pub fn fingerprint_of(key_base64: &str, digest_base64: &str) -> Result<KeyFingerprint, KeyRejection> {
    let key: Zeroizing<[u8; CUSTOMER_KEY_BYTES]> =
        Zeroizing::new(decode_exact::<CUSTOMER_KEY_BYTES>(key_base64).map_err(KeyRejection::Key)?);
    let presented = KeyFingerprint(decode_exact::<KEY_DIGEST_BYTES>(digest_base64).map_err(KeyRejection::Digest)?);
    let computed = KeyFingerprint(md5_of(&key));
    if computed.matches(&presented) {
        Ok(computed)
    } else {
        Err(KeyRejection::Disagree)
    }
}

/// The MD5 of a customer key.
///
/// MD5 is not a choice this implementation makes — it is the digest the header is defined over,
/// and the value is a checksum of a key the client already knows, never an authentication token.
fn md5_of(key: &[u8; CUSTOMER_KEY_BYTES]) -> [u8; KEY_DIGEST_BYTES] {
    use md5::{Digest as _, Md5};
    Md5::digest(key).into()
}

/// Why a customer key and its digest were refused.
///
/// Three variants, one client-visible sentence. The split exists so this module's tests can say
/// which rule fired; see [`super::SseRejection::CustomerKeyMalformed`] for why the answer a client
/// receives does not make the distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRejection {
    /// The key is not canonical base64 of exactly thirty-two bytes.
    Key(Base64Error),
    /// The digest is not canonical base64 of exactly sixteen bytes.
    Digest(Base64Error),
    /// Both decoded, and the digest is not the digest of the key.
    Disagree,
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `ops/shared/encryption.rs`.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A 32-byte key of `0x00..0x1f`, and its true MD5.
    const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const MD5_A: &str = "tP/LI3N87DFaSk0aoqYgzg==";
    /// A different 32-byte key, and its true MD5.
    const KEY_B: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    const MD5_B: &str = "v2HomVYPq94vbXb0BabrcA==";

    /// [`KeyFingerprint`] has neither `Debug` nor `PartialEq` on purpose, so `expect` and
    /// `assert_eq!` cannot be used on a `Result` carrying one. These two are the replacement:
    /// the absence of the derives is the property, not an inconvenience to work around by adding
    /// them "just for tests".
    fn agreed(result: Result<KeyFingerprint, KeyRejection>) -> KeyFingerprint {
        match result {
            Ok(fingerprint) => fingerprint,
            Err(rejection) => panic!("the pair was refused: {rejection:?}"),
        }
    }

    fn refused(result: Result<KeyFingerprint, KeyRejection>) -> KeyRejection {
        match result {
            Ok(_) => panic!("the pair was accepted"),
            Err(rejection) => rejection,
        }
    }

    /// The digest constants above are asserted rather than trusted: a wrong constant would make
    /// every case below assert something other than what its name says.
    #[test]
    fn the_fixture_digests_are_the_digests_of_the_fixture_keys() {
        let key_a = super::super::base64::decode_exact::<32>(KEY_A).expect("canonical");
        let key_b = super::super::base64::decode_exact::<32>(KEY_B).expect("canonical");
        let md5_a = super::super::base64::decode_exact::<16>(MD5_A).expect("canonical");
        let md5_b = super::super::base64::decode_exact::<16>(MD5_B).expect("canonical");
        assert_eq!(md5_of(&key_a), md5_a);
        assert_eq!(md5_of(&key_b), md5_b);
        assert_ne!(md5_a, md5_b);
    }

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_key_with_its_own_digest_produces_that_digest() {
        let fingerprint = agreed(fingerprint_of(KEY_A, MD5_A));
        let expected = super::super::base64::decode_exact::<16>(MD5_A).expect("canonical");
        assert_eq!(fingerprint.as_array(), &expected);
    }

    #[test]
    fn a_fingerprint_matches_itself_and_an_equal_one() {
        let one = agreed(fingerprint_of(KEY_A, MD5_A));
        let same = agreed(fingerprint_of(KEY_A, MD5_A));
        assert!(one.matches(&same));
        assert!(one.matches(&one));
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn n_two_different_keys_do_not_share_a_fingerprint() {
        let a = agreed(fingerprint_of(KEY_A, MD5_A));
        let b = agreed(fingerprint_of(KEY_B, MD5_B));
        assert!(!a.matches(&b), "distinct keys must not compare equal");
        assert!(!b.matches(&a), "the comparison is symmetric");
    }

    #[test]
    fn n_a_digest_that_belongs_to_another_key_is_refused() {
        assert_eq!(refused(fingerprint_of(KEY_A, MD5_B)), KeyRejection::Disagree);
    }

    /// Negative — the two ways to get the pair wrong are one refusal.
    ///
    /// "The right key with somebody else's digest" and "somebody else's key with the right digest"
    /// are the same mistake seen from two sides, and a service that answered them differently
    /// would tell a caller which half it had guessed correctly. The assertion is on the rejection
    /// value, because that is what decides both the code and the sentence downstream.
    #[test]
    fn n_a_wrong_digest_and_a_wrong_key_are_indistinguishable() {
        let wrong_digest = refused(fingerprint_of(KEY_A, MD5_B));
        let wrong_key = refused(fingerprint_of(KEY_B, MD5_A));
        assert_eq!(wrong_digest, KeyRejection::Disagree);
        assert_eq!(wrong_key, KeyRejection::Disagree);
        assert_eq!(wrong_digest, wrong_key);
    }

    #[test]
    fn n_a_key_of_the_wrong_width_is_refused_before_anything_is_compared() {
        // 31 bytes and 33 bytes, each with a well-formed 16-byte digest beside it.
        for spelling in [
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g",
        ] {
            assert!(
                matches!(refused(fingerprint_of(spelling, MD5_A)), KeyRejection::Key(_)),
                "accepted a key of the wrong width: {spelling:?}"
            );
        }
    }

    #[test]
    fn n_a_digest_of_the_wrong_width_is_refused() {
        // Fifteen bytes and seventeen bytes.
        for spelling in ["AAECAwQFBgcICQoLDA0O", "AAECAwQFBgcICQoLDA0ODxA="] {
            assert!(
                matches!(refused(fingerprint_of(KEY_A, spelling)), KeyRejection::Digest(_)),
                "accepted a digest of the wrong width: {spelling:?}"
            );
        }
    }

    #[test]
    fn n_a_leniently_spelled_key_is_refused_rather_than_normalised() {
        for spelling in [
            KEY_A.trim_end_matches('='),
            " AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "--__AwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ] {
            assert!(
                matches!(refused(fingerprint_of(spelling, MD5_A)), KeyRejection::Key(_)),
                "accepted a lenient spelling: {spelling:?}"
            );
        }
    }

    #[test]
    fn n_an_empty_key_or_digest_is_refused() {
        assert!(matches!(refused(fingerprint_of("", MD5_A)), KeyRejection::Key(_)));
        assert!(matches!(refused(fingerprint_of(KEY_A, "")), KeyRejection::Digest(_)));
    }

    /// Negative — the key is decoded before the digest, so a request that gets both wrong is
    /// refused for the key. Stated because the order is what makes the refusal deterministic:
    /// two runs of one malformed request must not report different rules.
    #[test]
    fn n_the_key_is_judged_before_the_digest() {
        assert!(matches!(refused(fingerprint_of("!!!!", "!!!!")), KeyRejection::Key(_)));
    }

    /// Negative — a single flipped bit anywhere in the digest is refused.
    ///
    /// The comparison covers all sixteen bytes. A comparison that stopped early, or covered a
    /// prefix, would accept a digest that agrees on its first byte and differs later.
    #[test]
    fn n_every_single_byte_of_the_digest_is_covered_by_the_comparison() {
        let truth = super::super::base64::decode_exact::<16>(MD5_A).expect("canonical");
        for index in 0..KEY_DIGEST_BYTES {
            let mut altered = truth;
            if let Some(slot) = altered.get_mut(index) {
                *slot ^= 0x01;
            }
            let presented = KeyFingerprint::from_array(altered);
            let computed = KeyFingerprint::from_array(truth);
            assert!(!computed.matches(&presented), "byte {index} is outside the comparison");
        }
    }
}
