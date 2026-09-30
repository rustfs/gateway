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

//! The RustFS-profile switch that answers the two credential refusals with the sentences legacy
//! RustFS writes for them (rustfs/gateway#1120).
//!
//! Responsible for: [`ServiceBuilder::answer_credential_refusals_with_legacy_rustfs_sentences`],
//! the two sentences, and [`CredentialSentences::restyle`], which the pipeline applies to every
//! refusal it renders.
//! NOT responsible for: choosing a refusal's code, status or connection verdict (the
//! authenticator and `crate::close`), or rendering it (`crate::render`).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`'s `Outcome`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS writes
//!
//! Observed against a legacy RustFS build (rustfs/rustfs `e870a6d25b`) over raw sockets: a
//! signature that does not match answers `403 SignatureDoesNotMatch` with
//! [`RUSTFS_SIGNATURE_DOES_NOT_MATCH`] for a header-signed SigV4 request, a presigned SigV4 URL, a
//! header-signed SigV2 request and a presigned SigV2 URL alike; an access key nobody issued answers
//! `403 InvalidAccessKeyId` with [`RUSTFS_INVALID_ACCESS_KEY_ID`], the sentence RustFS's credential
//! lookup refuses it with (`rustfs/src/auth.rs:271-274`). RustFS added
//! `S3ErrorMessageCompatLayer` (`rustfs/src/server/layer.rs:809`, `:1942-1954`, rustfs/rustfs#2596)
//! so a `SignatureDoesNotMatch` document never went out without a `<Message>`; the legacy stack's
//! protocol library now supplies its own default sentence for the code, which is the one on the
//! wire, so that is the sentence kept here.
//!
//! The gateway's own answer is one sentence for both codes, so that a message logged without its
//! code does not say which half of the credential was wrong. The codes already say it on the wire;
//! the RustFS profile keeps RustFS's wording for them and changes nothing else.

use std::borrow::Cow;

use rustfs_gateway_types::ErrorCode;

use super::ServiceBuilder;
use crate::render::S3Error;

/// Legacy RustFS's sentence for `SignatureDoesNotMatch`.
pub(crate) const RUSTFS_SIGNATURE_DOES_NOT_MATCH: &str = "The request signature we calculated does not match the signature you \
     provided. Check your AWS secret access key and signing method. For more information, see REST Authentication and SOAP \
     Authentication for details.";

/// Legacy RustFS's sentence for `InvalidAccessKeyId`.
pub(crate) const RUSTFS_INVALID_ACCESS_KEY_ID: &str = "The Access Key Id you provided does not exist in our records.";

/// Which sentences an assembly answers a credential refusal with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CredentialSentences {
    /// This gateway's one sentence for both codes.
    #[default]
    Gateway,
    /// Legacy RustFS's sentence for each.
    LegacyRustfs,
}

impl CredentialSentences {
    /// `refusal`, carrying legacy RustFS's sentence when this assembly answers with those and the
    /// refusal is `SignatureDoesNotMatch` or `InvalidAccessKeyId`. Only the message changes: the
    /// code, the status, the connection verdict, the unread-body proof and any diagnostic element
    /// the refusing stage attached are the refusal's own.
    pub(crate) fn restyle(self, mut refusal: S3Error) -> S3Error {
        if self == Self::Gateway {
            return refusal;
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS words the two credential refusals
        // differently, so a message recorded without its code still says whether the key or the
        // signature was wrong. The wire code says so already; the intended future behaviour is the
        // gateway's one sentence for both, which keeps logs from carrying the distinction too.
        let sentence = match refusal.code() {
            Some(code) if *code == ErrorCode::SIGNATURE_DOES_NOT_MATCH => RUSTFS_SIGNATURE_DOES_NOT_MATCH,
            Some(code) if *code == ErrorCode::INVALID_ACCESS_KEY_ID => RUSTFS_INVALID_ACCESS_KEY_ID,
            _ => return refusal,
        };
        refusal.message = Some(Cow::Borrowed(sentence));
        refusal
    }
}

impl ServiceBuilder {
    /// Answers `403 SignatureDoesNotMatch` and `403 InvalidAccessKeyId` with the sentences legacy
    /// RustFS writes for them, as RustFS does today (rustfs/gateway#1120).
    ///
    /// Off by default: the gateway answers both with one sentence, so the message alone never says
    /// which half of a credential was wrong. Only the `<Message>` changes — the code, the status,
    /// the connection verdict and the point the request is refused at stay the authenticator's —
    /// and no refusal of any other code is touched.
    #[must_use]
    pub fn answer_credential_refusals_with_legacy_rustfs_sentences(mut self) -> Self {
        self.view_policy.credential_sentences = CredentialSentences::LegacyRustfs;
        self
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use crate::close::ConnectionIntent;
    use crate::render::{from_auth, from_handler};
    use rustfs_gateway_core::{HandlerError, ResponseKind};
    use rustfs_gateway_sig::AuthError;

    fn message_of(error: &S3Error) -> &str {
        error.message().unwrap_or_default()
    }

    /// Positive — each of the two credential refusals carries its own legacy sentence, and nothing
    /// else about it moves: code, status and connection verdict, for a body still owed and not.
    #[test]
    fn the_legacy_sentences_replace_only_the_message_of_the_two_credential_refusals() {
        for (error, code, sentence) in [
            (
                AuthError::SignatureDoesNotMatch,
                ErrorCode::SIGNATURE_DOES_NOT_MATCH,
                RUSTFS_SIGNATURE_DOES_NOT_MATCH,
            ),
            (
                AuthError::InvalidAccessKeyId,
                ErrorCode::INVALID_ACCESS_KEY_ID,
                RUSTFS_INVALID_ACCESS_KEY_ID,
            ),
        ] {
            for body_owed in [false, true] {
                let original = from_auth(error, ResponseKind::Other, body_owed);
                let restyled = CredentialSentences::LegacyRustfs.restyle(original.clone());
                assert_eq!(message_of(&restyled), sentence, "{error:?}");
                assert_eq!(restyled.code(), Some(&code), "{error:?}");
                assert_eq!(restyled.status(), original.status(), "{error:?}");
                assert_eq!(restyled.connection_intent(), original.connection_intent(), "{error:?} {body_owed}");
                assert_ne!(message_of(&original), sentence, "the control already carried the legacy sentence");
            }
        }
    }

    /// Negative — off by default, and the default leaves both credential refusals exactly as the
    /// gateway renders them.
    #[test]
    fn n_the_gateway_default_keeps_its_one_sentence() {
        assert_eq!(CredentialSentences::default(), CredentialSentences::Gateway);
        for error in [AuthError::SignatureDoesNotMatch, AuthError::InvalidAccessKeyId] {
            let original = from_auth(error, ResponseKind::Other, false);
            assert_eq!(CredentialSentences::Gateway.restyle(original.clone()), original, "{error:?}");
        }
    }

    /// Negative — every other authentication refusal keeps the gateway's sentence under the
    /// switch; the switch is about the two credential codes and nothing else.
    #[test]
    fn n_every_other_authentication_refusal_keeps_its_sentence() {
        for error in [
            AuthError::AccessDenied,
            AuthError::RequestExpired,
            AuthError::RequestTimeTooSkewed,
            AuthError::AuthorizationQueryParametersError,
            AuthError::AuthorizationHeaderMalformed,
            AuthError::InvalidCredentialRegion,
        ] {
            let original = from_auth(error, ResponseKind::Other, false);
            assert_eq!(CredentialSentences::LegacyRustfs.restyle(original.clone()), original, "{error:?}");
        }
    }

    /// Negative — a refusal of another code keeps its sentence, even one whose sentence happens to
    /// be the gateway's credential sentence, and a refusal without a code is left alone.
    #[test]
    fn n_a_refusal_of_another_code_keeps_its_sentence() {
        for code in [
            ErrorCode::ACCESS_DENIED,
            ErrorCode::NO_SUCH_BUCKET,
            ErrorCode::INVALID_REQUEST,
            ErrorCode::BAD_DIGEST,
        ] {
            let original = from_handler(
                HandlerError::new(code.clone(), "the request was not authenticated"),
                ResponseKind::Other,
                ConnectionIntent::MayKeepAlive,
            );
            assert_eq!(CredentialSentences::LegacyRustfs.restyle(original.clone()), original, "{code:?}");
        }
    }

    /// Negative — a `HEAD` refusal keeps its body policy; only the message it would have carried
    /// changes, and a `HEAD` answer carries none on the wire either way.
    #[test]
    fn n_a_head_refusal_keeps_its_shape() {
        let original = from_auth(AuthError::SignatureDoesNotMatch, ResponseKind::Head, false);
        let restyled = CredentialSentences::LegacyRustfs.restyle(original.clone());
        assert_eq!(restyled.status(), original.status());
        assert_eq!(restyled.connection_intent(), original.connection_intent());
        assert_eq!(message_of(&restyled), RUSTFS_SIGNATURE_DOES_NOT_MATCH);
    }
}
