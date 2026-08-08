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

//! One multipart upload, one customer key, on every part.
//!
//! Responsible for: [`check_part`] — the comparison between the key an upload was created with
//! and the key a part presents — and [`PartRejection`], the four answers it can give.
//! NOT responsible for: *storing* the binding. This framework holds no upload state, so which
//! fingerprint an upload id is bound to is the backend's to remember; what is held here is the
//! rule, so that two backends cannot refuse different requests. Nor for the transport gate or the
//! per-request header rules ([`super::enforce`]), which have already run by the time a part
//! reaches a handler.
//! Upstream: [`super::key::KeyFingerprint`]. Downstream: a backend's `UploadPart` and
//! `UploadPartCopy` handlers.
//!
//! # Why this is a cross-request rule and therefore the one most likely to be skipped
//!
//! Every other SSE rule is decidable from one request head, so the framework applies it in the
//! pipeline and a backend cannot forget. This one needs a value from a request that finished
//! minutes ago, which only the backend has. What the framework can do is make the rule a single
//! function with an unignorable result: [`check_part`] returns a `Result`, which is `#[must_use]`
//! by definition, and `KeyFingerprint` has no public constructor other than
//! [`super::key::fingerprint_of`] and [`super::key::KeyFingerprint::from_array`] — so a handler
//! cannot arrive at a value to compare without having gone through the validation that produced
//! it.
//!
//! # What the fingerprint is, and what it is not
//!
//! The bound value is `MD5(key)`, never the key. A backend that persists an upload's binding is
//! persisting the same sixteen bytes AWS puts in every SSE-C response header, so a store that
//! leaks is a store that leaked a value the protocol already published. Persisting the key
//! instead would turn every multipart upload in progress into key material at rest, which is the
//! whole reason customer-provided keys exist.
//!
//! # `CompleteMultipartUpload` does not take part
//!
//! AWS's completion carries no customer-key headers, and one that arrives takes no part in this
//! comparison. It is still subject to the transport gate — a key on a plaintext wire is a
//! disclosure whatever operation carried it — which is [`super::enforce`]'s, not this module's.

use super::key::KeyFingerprint;

/// Why a part was refused.
///
/// Three variants, and a backend is expected to answer all three with one sentence: telling a
/// caller *which* disagreement it made is telling it something about a key it did not send. The
/// split is for the backend's own diagnostics and for this module's tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartRejection {
    /// The upload was created with a customer-provided key and the part presents none.
    MissingOnEncryptedUpload,
    /// The upload was created without one and the part presents one.
    PresentOnPlainUpload,
    /// Both present one, and they are different keys.
    DifferentKey,
}

/// Compares the key a part presents against the one its upload was created with.
///
/// `bound` is what the backend stored when it answered `CreateMultipartUpload`; `presented` is
/// what this part's headers reduced to, which is [`super::SseEnforced::customer_key_fingerprint`]
/// for an `UploadPart` and the copy-source fingerprint's sibling rule for an `UploadPartCopy`.
///
/// The result is a `Result`, which Rust already forbids discarding silently. That is the whole of
/// the enforcement available to a framework that holds no upload state, and it is deliberately
/// not a `bool`: `if !check_part(..) { }` and `if check_part(..) { }` are one keystroke apart and
/// both compile.
///
/// # Errors
///
/// [`PartRejection`] naming which of the three disagreements this is.
pub fn check_part(bound: Option<&KeyFingerprint>, presented: Option<&KeyFingerprint>) -> Result<(), PartRejection> {
    match (bound, presented) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(PartRejection::MissingOnEncryptedUpload),
        (None, Some(_)) => Err(PartRejection::PresentOnPlainUpload),
        // Constant time, for `KeyFingerprint::matches`'s reason: the two sides come from two
        // different requests, so an early exit says how many leading bytes a guess got right.
        (Some(bound), Some(presented)) => {
            if bound.matches(presented) {
                Ok(())
            } else {
                Err(PartRejection::DifferentKey)
            }
        }
    }
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `ops/shared/encryption.rs`.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fingerprint(seed: u8) -> KeyFingerprint {
        KeyFingerprint::from_array([seed; 16])
    }

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_part_repeating_the_upload_s_key_is_accepted() {
        assert_eq!(check_part(Some(&fingerprint(7)), Some(&fingerprint(7))), Ok(()));
    }

    #[test]
    fn an_unencrypted_part_of_an_unencrypted_upload_is_accepted() {
        assert_eq!(check_part(None, None), Ok(()));
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn n_a_part_encrypted_with_a_different_key_is_refused() {
        assert_eq!(check_part(Some(&fingerprint(7)), Some(&fingerprint(8))), Err(PartRejection::DifferentKey));
    }

    #[test]
    fn n_an_unencrypted_part_of_an_encrypted_upload_is_refused() {
        assert_eq!(check_part(Some(&fingerprint(7)), None), Err(PartRejection::MissingOnEncryptedUpload));
    }

    #[test]
    fn n_an_encrypted_part_of_an_unencrypted_upload_is_refused() {
        assert_eq!(check_part(None, Some(&fingerprint(7))), Err(PartRejection::PresentOnPlainUpload));
    }

    /// Negative — the two "one side only" refusals are distinct values, so a future edit that
    /// collapsed the match into a catch-all would be visible here rather than in nothing at all.
    #[test]
    fn n_the_two_asymmetric_refusals_are_not_the_same_answer() {
        assert_ne!(
            check_part(Some(&fingerprint(7)), None),
            check_part(None, Some(&fingerprint(7))),
            "a part that dropped the headers and a part that added them are different mistakes"
        );
    }

    /// Negative — every byte of the bound fingerprint takes part.
    ///
    /// A comparison over a prefix would accept a part whose key digest agrees on its first byte,
    /// which is one guess away from uploading a part under a key the upload was not created with.
    #[test]
    fn n_a_single_differing_byte_anywhere_refuses_the_part() {
        let bound = KeyFingerprint::from_array([0x5a; 16]);
        for index in 0..16 {
            let mut bytes = [0x5a_u8; 16];
            if let Some(slot) = bytes.get_mut(index) {
                *slot ^= 0xff;
            }
            let presented = KeyFingerprint::from_array(bytes);
            assert_eq!(
                check_part(Some(&bound), Some(&presented)),
                Err(PartRejection::DifferentKey),
                "byte {index} is outside the comparison"
            );
        }
    }
}
