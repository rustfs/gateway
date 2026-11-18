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

//! How an assembly answers a request whose server-side-encryption headers the shared gate
//! (`rustfs_gateway_core::sse::enforce`) refused: in whose words.
//!
//! Responsible for: [`ServiceBuilder::answer_customer_key_refusals_as_legacy_rustfs`] and
//! [`SseRefusals::error`], the one renderer of an [`SseRejection`] into the error a client is
//! answered with; and [`ServiceBuilder::defer_encryption_header_refusals_to_handlers`] with
//! [`SseRefusals::settle`], which decides whether that error is answered now or by the handler.
//! NOT responsible for: the rules or their order (`rustfs_gateway_core::sse`, which this module
//! reads the verdict of and never re-judges), the cleartext gate before routing
//! (`super::plaintext_customer_keys`), or the managed channel's sentences, which stay the core's.
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::render::from_sse`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS answers
//!
//! Legacy RustFS judges a customer key in its storage layer (rustfs/rustfs
//! `rustfs/src/storage/sse.rs`, `validate_ssec_params`, `:4490-4526`, and the write-header check
//! `validate_sse_headers_for_write`, `:633-694`) and answers every refusal `400 InvalidRequest`,
//! one sentence per rule, where the gateway answers `400 InvalidArgument` with one sentence for
//! every key fault. The RustFS e2e suite pins the width and digest sentences
//! (`kms_edge_cases_test.rs`, `test_kms_invalid_key_scenarios`) and the code for a missing and an
//! unsupported algorithm (`select_sse_response_test.rs`).
//!
//! The width sentence states the length the key decoded to, as legacy RustFS's does. That is the
//! one request-derived value any of these sentences carries: a count, never a key byte, the digest
//! the caller sent or the digest of the key it sent.

use std::borrow::Cow;

use rustfs_gateway_core::{HandlerError, KeyRejection, ResponseKind, SseEnforced, SseRejection};
use rustfs_gateway_types::ErrorCode;

use super::ServiceBuilder;
use crate::render::{S3Error, from_sse};

/// Legacy RustFS's sentence for one or two of a customer-key trio's three headers.
const MISSING_PARAMETERS: &str = "Missing SSE-C parameters. Algorithm, customer key and customer key MD5 are all required.";
/// Legacy RustFS's sentence for a customer algorithm other than `AES256`.
const UNSUPPORTED_ALGORITHM: &str = "Unsupported SSE-C algorithm. Only AES256 is supported.";
/// Legacy RustFS's sentence for a key that is not base64.
const NOT_BASE64: &str = "Invalid SSE-C key: not valid Base64.";
/// Legacy RustFS's sentence for a key digest that is not the key's.
const DIGEST_DISAGREES: &str = "The calculated MD5 hash of the key did not match the hash that was provided.";

/// Whose words an SSE refusal is answered in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SseRefusals {
    /// Whether a customer-key refusal is answered as legacy RustFS answered it.
    legacy_customer_keys: bool,
    /// Whether a value refusal of a header-carried request is handed to the handler.
    deferred_to_handlers: bool,
}

impl SseRefusals {
    /// Whether customer-key refusals are answered in legacy RustFS's code and words.
    pub(crate) const fn legacy_customer_keys(self) -> bool {
        self.legacy_customer_keys
    }

    /// Whether value refusals are handed to the handler
    /// ([`ServiceBuilder::defer_encryption_header_refusals_to_handlers`]).
    pub(crate) const fn deferred_to_handlers(self) -> bool {
        self.deferred_to_handlers
    }

    /// Settles the gate's refusal of a request: answered now, or — under
    /// [`ServiceBuilder::defer_encryption_header_refusals_to_handlers`], for a request whose SSE
    /// members are all headers (`headers_only`) — handed to the handler as a proof carrying it, in
    /// this assembly's words. The cleartext refusal is always answered now.
    pub(crate) fn settle(
        self,
        rejection: SseRejection,
        headers_only: bool,
        response: ResponseKind,
    ) -> Result<SseEnforced, S3Error> {
        if !(self.deferred_to_handlers && headers_only) {
            return Err(from_sse(&rejection, response, self));
        }
        let error = self.error(&rejection);
        rejection.defer(error).map_err(|kept| from_sse(&kept, response, self))
    }

    /// The error `rejection` is answered with: legacy RustFS's code and sentence for a customer-key
    /// refusal under [`ServiceBuilder::answer_customer_key_refusals_as_legacy_rustfs`], the core's
    /// code and constant sentence otherwise.
    pub(crate) fn error(self, rejection: &SseRejection) -> HandlerError {
        match self.legacy_customer_keys.then(|| legacy_rustfs_sentence(rejection)).flatten() {
            Some(sentence) => HandlerError::new(ErrorCode::INVALID_REQUEST, sentence),
            None => HandlerError::new(rejection.code(), rejection.reason()),
        }
    }
}

/// Legacy RustFS's sentence for a customer-key refusal, on either key position; `None` for a
/// refusal that is not about a customer key.
fn legacy_rustfs_sentence(rejection: &SseRejection) -> Option<Cow<'static, str>> {
    let sentence = match rejection {
        SseRejection::CustomerTrioIncomplete(_) => MISSING_PARAMETERS.into(),
        SseRejection::CustomerAlgorithmUnknown(_) => UNSUPPORTED_ALGORITHM.into(),
        SseRejection::CustomerKeyMalformed(_, KeyRejection::Key(_)) => NOT_BASE64.into(),
        SseRejection::CustomerKeyMalformed(_, KeyRejection::KeyWidth(width)) => {
            format!("SSE-C key must be 32 bytes (256 bits), got {width} bytes.").into()
        }
        SseRejection::CustomerKeyMalformed(_, KeyRejection::Digest(_) | KeyRejection::Disagree) => DIGEST_DISAGREES.into(),
        SseRejection::PlaintextCustomerKey | SseRejection::ChannelsContradict | SseRejection::ManagedChannelInvalid(_) => {
            return None;
        }
    };
    Some(sentence)
}

impl ServiceBuilder {
    /// Answers a refused customer-provided key as legacy RustFS answers it: `400 InvalidRequest`,
    /// with one sentence per rule — an incomplete trio, an algorithm other than `AES256`, a key that
    /// is not base64, a key of the wrong width (naming the width), and a digest that is not the
    /// key's — on the target's and the copy source's position alike.
    ///
    /// Off by default: the gateway answers every key fault `400 InvalidArgument` with one sentence,
    /// so a caller is not told which half of the pair it got wrong. The rules, their order and the
    /// requests refused are the same either way; only the answer differs.
    #[must_use]
    pub fn answer_customer_key_refusals_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.sse_refusals.legacy_customer_keys = true;
        self
    }

    /// Hands a value refusal of the SSE headers to the handler instead of answering it before the
    /// handler runs: the handler receives a proof whose
    /// [`rustfs_gateway_core::SseEnforced::deferred_refusal`] carries the rule and the error this
    /// assembly answers it with, and owes that error once it has authorized the request.
    ///
    /// For a host that authorizes inside its handler, as the RustFS bridge does: legacy RustFS asks
    /// its bucket policy before it judges an SSE header, so a policy that denies the header's value
    /// is answered `403` there and `400` by a gate in front of the handler. Not part of
    /// [`ServiceBuilder::rustfs_profile`]: a host whose authorizer decides before the body is read,
    /// as the reference launcher's does, already authorizes first, and a handler that does not read
    /// the deferred refusal would serve a request the gate refused. The cleartext refusal
    /// (`refuse_plaintext_customer_keys_before_routing`, and the gate's own) is never deferred, and
    /// a POST Object form's fields are judged before the handler as before. Off by default.
    #[must_use]
    pub fn defer_encryption_header_refusals_to_handlers(mut self) -> Self {
        self.view_policy.sse_refusals.deferred_to_handlers = true;
        self
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use rustfs_gateway_core::KeySide;
    use rustfs_gateway_core::sse::base64::Base64Error;
    use rustfs_gateway_core::sse::{ManagedRejection, SSEC_ALGORITHM, SSEC_KEY, SSEC_KEY_MD5};

    use super::*;

    const LEGACY: SseRefusals = SseRefusals {
        legacy_customer_keys: true,
        deferred_to_handlers: false,
    };
    const DEFERRING: SseRefusals = SseRefusals {
        legacy_customer_keys: true,
        deferred_to_handlers: true,
    };

    /// Negative — without the deferral every refusal is answered now, in this assembly's words.
    #[test]
    fn n_without_the_deferral_every_refusal_is_answered_now() {
        for headers_only in [true, false] {
            let Err(refusal) =
                LEGACY.settle(SseRejection::CustomerTrioIncomplete(KeySide::Target), headers_only, ResponseKind::Other)
            else {
                panic!("deferred without the switch");
            };
            assert_eq!(refusal.message(), Some(MISSING_PARAMETERS));
        }
    }

    /// Negative — under the deferral the cleartext refusal and a form-carried refusal are still
    /// answered now.
    #[test]
    fn n_the_deferral_never_takes_the_cleartext_refusal_or_a_form() {
        let Err(cleartext) = DEFERRING.settle(SseRejection::PlaintextCustomerKey, true, ResponseKind::Other) else {
            panic!("the cleartext refusal was deferred");
        };
        assert_eq!(cleartext.code(), Some(&ErrorCode::INVALID_REQUEST));
        assert!(
            DEFERRING
                .settle(SseRejection::ChannelsContradict, false, ResponseKind::Other)
                .is_err(),
            "a form-carried refusal was deferred"
        );
    }

    /// Negative — under the deferral a header refusal reaches the handler carrying the error this
    /// assembly answers it with.
    #[test]
    fn n_a_deferred_refusal_carries_the_assembly_words() {
        let rejection = SseRejection::CustomerKeyMalformed(KeySide::Target, KeyRejection::KeyWidth(5));
        let Ok(proof) = DEFERRING.settle(rejection.clone(), true, ResponseKind::Other) else {
            panic!("not deferred");
        };
        let Some(deferred) = proof.deferred_refusal() else {
            panic!("the proof lost the refusal");
        };
        assert_eq!(deferred.rejection(), &rejection);
        assert_eq!(
            answered(LEGACY, &rejection),
            (deferred.error().code().clone(), deferred.error().message().to_owned())
        );
    }

    fn answered(refusals: SseRefusals, rejection: &SseRejection) -> (ErrorCode, String) {
        let error = refusals.error(rejection);
        (error.code().clone(), error.message().to_owned())
    }

    /// Every rejection the shared gate builds about a customer key, with legacy RustFS's sentence.
    fn customer_key_rejections() -> Vec<(SseRejection, String)> {
        let mut rows = Vec::new();
        for side in [KeySide::Target, KeySide::CopySource] {
            rows.extend([
                (SseRejection::CustomerTrioIncomplete(side), MISSING_PARAMETERS.to_owned()),
                (SseRejection::CustomerAlgorithmUnknown(side), UNSUPPORTED_ALGORITHM.to_owned()),
                (
                    SseRejection::CustomerKeyMalformed(side, KeyRejection::Key(Base64Error::Alphabet)),
                    NOT_BASE64.to_owned(),
                ),
                (
                    SseRejection::CustomerKeyMalformed(side, KeyRejection::KeyWidth(5)),
                    "SSE-C key must be 32 bytes (256 bits), got 5 bytes.".to_owned(),
                ),
                (
                    SseRejection::CustomerKeyMalformed(side, KeyRejection::Digest(Base64Error::TooShort)),
                    DIGEST_DISAGREES.to_owned(),
                ),
                (
                    SseRejection::CustomerKeyMalformed(side, KeyRejection::Disagree),
                    DIGEST_DISAGREES.to_owned(),
                ),
            ]);
        }
        rows
    }

    /// Negative — under the switch every customer-key refusal, on either position, is
    /// `InvalidRequest` with legacy RustFS's sentence for its rule.
    #[test]
    fn n_every_customer_key_refusal_is_answered_in_legacy_rustfs_words() {
        for (rejection, sentence) in customer_key_rejections() {
            assert_eq!(answered(LEGACY, &rejection), (ErrorCode::INVALID_REQUEST, sentence), "{rejection:?}");
        }
    }

    /// Negative — without the switch the same refusals keep the core's code and sentence, byte for
    /// byte: the default does not move.
    #[test]
    fn n_without_the_switch_every_customer_key_refusal_keeps_the_core_answer() {
        for (rejection, _) in customer_key_rejections() {
            assert_eq!(
                answered(SseRefusals::default(), &rejection),
                (rejection.code(), rejection.reason().to_owned()),
                "{rejection:?}"
            );
            assert_eq!(rejection.code(), ErrorCode::INVALID_ARGUMENT, "{rejection:?}");
        }
    }

    /// Negative — what is not about a customer key keeps the core's answer under the switch too:
    /// the cleartext gate, the contradiction and the managed channel.
    #[test]
    fn n_refusals_that_are_not_about_a_customer_key_keep_the_core_answer() {
        for rejection in [
            SseRejection::PlaintextCustomerKey,
            SseRejection::ChannelsContradict,
            SseRejection::ManagedChannelInvalid(ManagedRejection::BucketKeyNotABoolean),
        ] {
            assert_eq!(
                answered(LEGACY, &rejection),
                (rejection.code(), rejection.reason().to_owned()),
                "{rejection:?}"
            );
        }
    }

    /// Negative — the sentences come from the gate's verdict on real headers, and none of them
    /// carries the key, the digest the caller sent, or the digest of the key it sent.
    #[test]
    fn n_no_legacy_sentence_carries_a_key_or_a_digest() {
        // `short`, base64 and its true MD5; KEY_A's MD5; and a 32-byte key with another's digest.
        let (short, short_md5) = ("c2hvcnQ=", "TwnaqdlbyxZqMCQHoOC6vg==");
        let (key_a, md5_a, md5_b) = (
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "tP/LI3N87DFaSk0aoqYgzg==",
            "v2HomVYPq94vbXb0BabrcA==",
        );
        for (key, digest) in [
            (short, short_md5),
            (key_a, md5_b),
            ("!!!!", md5_a),
            (key_a, "AAECAwQFBgcICQoLDA0O"),
        ] {
            let lookup = |name: &str| match name {
                SSEC_ALGORITHM => Some(Cow::Borrowed("AES256")),
                SSEC_KEY => Some(Cow::Borrowed(key)),
                SSEC_KEY_MD5 => Some(Cow::Borrowed(digest)),
                _ => None,
            };
            let Err(rejection) = rustfs_gateway_core::sse::enforce_with(
                lookup,
                rustfs_gateway_core::TransportSecurity::Encrypted,
                &rustfs_gateway_core::SseConfig::strict(),
            ) else {
                panic!("{key:?} with {digest:?} was served");
            };
            let (_, sentence) = answered(LEGACY, &rejection);
            assert!(legacy_rustfs_sentence(&rejection).is_some(), "{rejection:?}");
            for secret in [key, digest, md5_a, md5_b, short_md5, "short", key.trim_end_matches('=')] {
                assert!(!sentence.contains(secret), "{sentence:?} carries {secret:?}");
            }
        }
    }
}
