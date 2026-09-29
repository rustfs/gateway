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

//! The RustFS-profile switch that answers a request-body refusal with the sentence legacy RustFS
//! writes for its code (rustfs/gateway#1099).
//!
//! Responsible for: [`ServiceBuilder::answer_body_refusals_with_legacy_rustfs_sentences`], the
//! three sentences, and [`BodySentences::restyle`], which the pipeline applies to a refusal of the
//! request body and to a refusal of the request head's declared length.
//! NOT responsible for: choosing a refusal's code (the refusing stage, and `crate::integrity` for
//! the RustFS profile's `BadDigest`) or rendering it (`crate::render`).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS writes
//!
//! RustFS's API layer answers a body that failed verification, or arrived short, with one fixed
//! sentence per code, whatever the cause (rustfs/rustfs `e870a6d25b`, `rustfs/src/error.rs:301-339`
//! for the sentences; applied to a mismatched digest at `:545-561` and `:714-730`, and to a short
//! body at `:595-609` and `:762-782`; rustfs/rustfs#6564, #6578, #6842, #7052, #7635, #7659). A
//! declared upload length above RustFS's 5 GiB single-request ceiling (`rustfs/src/server/http.rs:170`)
//! is refused before the body is read with a third sentence. Each was observed against a legacy
//! RustFS build: a tampered signed payload, a mismatched or unreadable `x-amz-checksum-*` value, a
//! mismatched trailer checksum and a mismatched `Content-MD5` all answer the `BadDigest` sentence; a
//! body cut short, a truncated aws-chunked body and a decoded-length mismatch answer the
//! `IncompleteBody` one; a 5 GiB + 1 `PutObject` or `UploadPart` answers the `EntityTooLarge` one.
//!
//! The codes themselves are not this module's: `BadDigest` for a checksum failure is
//! [`ServiceBuilder::answer_checksum_failures_with_bad_digest`]'s, and the other two are the core's
//! already. A refusal of any other code, and a `413` from the buffered ceiling, keep this gateway's
//! sentence.

use http::StatusCode;
use rustfs_gateway_core::HandlerError;
use rustfs_gateway_types::ErrorCode;

use super::ServiceBuilder;
use crate::render::{S3Error, from_transport_limit};

/// Legacy RustFS's sentence for `BadDigest`.
pub(crate) const RUSTFS_BAD_DIGEST: &str = "The Content-Md5 you specified did not match what we received.";

/// Legacy RustFS's sentence for `IncompleteBody`.
pub(crate) const RUSTFS_INCOMPLETE_BODY: &str =
    "You did not provide the number of bytes specified by the Content-Length HTTP header.";

/// Legacy RustFS's sentence for an upload declared larger than its single-request ceiling.
pub(crate) const RUSTFS_UPLOAD_TOO_LARGE: &str = "Request body exceeds the configured maximum object size.";

/// Which sentences an assembly answers a request-body refusal with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum BodySentences {
    /// This gateway's own sentences.
    #[default]
    Gateway,
    /// Legacy RustFS's, for the three codes it answers with a fixed sentence.
    LegacyRustfs,
}

impl BodySentences {
    /// `refusal`, with legacy RustFS's sentence when this assembly answers with those and the
    /// refusal's code is one RustFS answers with a fixed sentence. Everything else about the refusal
    /// — code, status, connection, the unread-body proof — is kept. A refusal of these three codes
    /// carries no headers or document elements to keep: the error-resolution authority admits none
    /// for them.
    pub(crate) fn restyle(self, refusal: S3Error) -> S3Error {
        if self == Self::Gateway {
            return refusal;
        }
        let Some(code) = refusal.code().cloned() else {
            return refusal;
        };
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS answers every verification failure of
        // a body with the `Content-MD5` sentence — a mismatched `x-amz-content-sha256`, a wrong
        // CRC32 — and every short body with the `Content-Length` one, so the message names a header
        // the client may never have sent. Kept so RustFS clients read what they read today; the
        // intended future behaviour is this gateway's sentences, which name what was checked.
        let sentence = if code == ErrorCode::BAD_DIGEST {
            RUSTFS_BAD_DIGEST
        } else if code == ErrorCode::INCOMPLETE_BODY {
            RUSTFS_INCOMPLETE_BODY
        } else if code == ErrorCode::ENTITY_TOO_LARGE && refusal.status() == StatusCode::BAD_REQUEST {
            RUSTFS_UPLOAD_TOO_LARGE
        } else {
            return refusal;
        };
        let mut restyled = from_transport_limit(HandlerError::new(code, sentence), refusal.status(), refusal.connection_intent());
        restyled.body_unfinished = refusal.body_unfinished;
        restyled
    }
}

impl ServiceBuilder {
    /// Answers a refusal of the request body — `BadDigest`, `IncompleteBody`, and a `400
    /// EntityTooLarge` for a declared length above the ceiling — with the fixed sentence legacy
    /// RustFS writes for that code, as RustFS does today (rustfs/gateway#1099).
    ///
    /// Off by default: the core's sentences name what was checked. Only the `<Message>` changes; the
    /// code, the status, the connection and the point the request is refused at are the refusing
    /// stage's, so a body that failed verification is still never handed on as complete.
    #[must_use]
    pub fn answer_body_refusals_with_legacy_rustfs_sentences(mut self) -> Self {
        self.view_policy.body_sentences = BodySentences::LegacyRustfs;
        self
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use crate::close::ConnectionIntent;

    fn refusal(code: ErrorCode, message: &'static str, status: StatusCode, connection: ConnectionIntent) -> S3Error {
        from_transport_limit(HandlerError::new(code, message), status, connection)
    }

    fn message_of(error: &S3Error) -> &str {
        error.message().unwrap_or_default()
    }

    #[test]
    fn the_legacy_sentences_replace_only_the_message_of_the_three_codes() {
        for (code, status, connection, sentence) in [
            (
                ErrorCode::BAD_DIGEST,
                StatusCode::BAD_REQUEST,
                ConnectionIntent::MayKeepAlive,
                RUSTFS_BAD_DIGEST,
            ),
            (
                ErrorCode::INCOMPLETE_BODY,
                StatusCode::BAD_REQUEST,
                ConnectionIntent::Close,
                RUSTFS_INCOMPLETE_BODY,
            ),
            (
                ErrorCode::ENTITY_TOO_LARGE,
                StatusCode::BAD_REQUEST,
                ConnectionIntent::Close,
                RUSTFS_UPLOAD_TOO_LARGE,
            ),
        ] {
            let original = refusal(code.clone(), "the gateway's own sentence", status, connection);
            let restyled = BodySentences::LegacyRustfs.restyle(original.clone());
            assert_eq!(message_of(&restyled), sentence, "{code:?}");
            assert_eq!(restyled.code(), Some(&code));
            assert_eq!(restyled.status(), status, "{code:?}");
            assert_eq!(restyled.connection_intent(), connection, "{code:?}");
            assert_eq!(BodySentences::Gateway.restyle(original.clone()), original, "{code:?}");
        }
    }

    #[test]
    fn n_every_other_refusal_keeps_its_sentence() {
        for (code, status) in [
            (ErrorCode::ENTITY_TOO_LARGE, StatusCode::PAYLOAD_TOO_LARGE),
            (ErrorCode::X_AMZ_CONTENT_SHA256_MISMATCH, StatusCode::BAD_REQUEST),
            (ErrorCode::X_AMZ_CONTENT_CHECKSUM_MISMATCH, StatusCode::BAD_REQUEST),
            (ErrorCode::INVALID_DIGEST, StatusCode::BAD_REQUEST),
            (ErrorCode::INVALID_REQUEST, StatusCode::BAD_REQUEST),
            (ErrorCode::SIGNATURE_DOES_NOT_MATCH, StatusCode::FORBIDDEN),
            (ErrorCode::MISSING_CONTENT_LENGTH, StatusCode::LENGTH_REQUIRED),
            (ErrorCode::REQUEST_TIMEOUT, StatusCode::BAD_REQUEST),
        ] {
            let original = refusal(code.clone(), "the gateway's own sentence", status, ConnectionIntent::Close);
            assert_eq!(BodySentences::LegacyRustfs.restyle(original.clone()), original, "{code:?} {status}");
        }
    }

    /// The unread-body proof a ceiling refusal carries survives the new sentence, so the
    /// connection is still closed on a body nobody read.
    #[test]
    fn the_unread_body_proof_survives_the_sentence() {
        let body = http_body_util::Full::new(bytes::Bytes::from_static(b"unread"));
        let proof = crate::wire_read::WireProgress::for_body(crate::gate::BodyDigestObligation::None, Some(&body))
            .request_body_unfinished();
        assert!(proof.is_some());
        let mut original = refusal(
            ErrorCode::INCOMPLETE_BODY,
            "the gateway's own sentence",
            StatusCode::BAD_REQUEST,
            ConnectionIntent::Close,
        );
        original.body_unfinished = proof;
        let restyled = BodySentences::LegacyRustfs.restyle(original.clone());
        assert_eq!(restyled.body_unfinished, original.body_unfinished);
        assert_eq!(message_of(&restyled), RUSTFS_INCOMPLETE_BODY);
    }

    #[test]
    fn the_sentences_are_legacy_rustfs_s_byte_for_byte() {
        assert_eq!(RUSTFS_BAD_DIGEST, "The Content-Md5 you specified did not match what we received.");
        assert_eq!(
            RUSTFS_INCOMPLETE_BODY,
            "You did not provide the number of bytes specified by the Content-Length HTTP header."
        );
        assert_eq!(RUSTFS_UPLOAD_TOO_LARGE, "Request body exceeds the configured maximum object size.");
        assert_eq!(BodySentences::default(), BodySentences::Gateway);
    }
}
