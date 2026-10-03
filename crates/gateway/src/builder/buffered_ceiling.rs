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

//! The RustFS-profile switch that bounds every buffered request body at legacy RustFS's 20 MiB
//! (rustfs/gateway#1173).
//!
//! Responsible for: [`ServiceBuilder::bound_buffered_bodies_as_legacy_rustfs`] and
//! [`BufferedCeiling`]: the ceilings a buffered body is read under, the XML document ceiling the
//! view carries, and the refusal a body past the ceiling is answered with.
//! NOT responsible for: enforcing the ceiling (`crate::gate` before the read and
//! `crate::wire_read` frame by frame), a claimed route's body (`super::claimed_bodies`), or any
//! streamed, unread or POST body.
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS does
//!
//! Legacy RustFS buffers the body of every operation it decodes whole (every configuration write,
//! `DeleteObjects`, `CompleteMultipartUpload`, `RestoreObject`, `SelectObjectContent`, ...) up to
//! 20 MiB, the legacy stack's default ceiling, which RustFS does not change
//! (`rustfs/src/server/http.rs:166-173` on rustfs/rustfs `3268c42e00`); it has no per-operation
//! ceiling of its own, and its XML reader has no size bound beyond that one. Observed against a
//! legacy RustFS build: a `PutBucketTagging` of 1.5 MiB and of 20 MiB less 200 bytes is stored, a
//! `DeleteObjects` padded to 3 MiB and to 20 MiB less 300 bytes deletes its keys, and a
//! `CompleteMultipartUpload` of 10,000 parts each carrying a CRC32C (1.32 MiB from aws-sdk-go-v2,
//! 1.24 MiB from botocore) reaches its handler. The core reads an XML document of at most 1 MiB
//! and a `DeleteObjects` body of at most 2 MiB, so it refused all four.
//!
//! Past 20 MiB legacy RustFS answers `500 InternalError` once it has read 20 MiB: its read ends in
//! an error its own mapping does not recognise, which is a bug rather than a decision. The profile
//! answers `400 MaxMessageLengthExceeded`, the code that mapping names, and answers it as soon as
//! the declared length or the arriving frames cross the ceiling (rd-err-0014).

use http::StatusCode;
use rustfs_gateway_core::{HandlerError, MetaView, RequestBodyMode};
use rustfs_gateway_types::ErrorCode;

use super::ServiceBuilder;
use crate::gate::BodyCeilings;
use crate::render::{S3Error, from_transport_limit};

/// Legacy RustFS's ceiling on a buffered request body: 20 MiB.
pub(crate) const LEGACY_RUSTFS_BUFFERED_BODY_BYTES: u64 = 20 * 1024 * 1024;

/// The sentence a buffered body past the ceiling is answered with.
const PAST_THE_CEILING: &str = "the request body is larger than the 20 MiB this operation reads";

/// Which ceiling a buffered request body is read under.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum BufferedCeiling {
    /// The assembly's buffered ceiling, the operation's declared cap and the XML reader's 1 MiB.
    #[default]
    Model,
    /// Legacy RustFS's 20 MiB for every buffered body, and nothing below it.
    LegacyRustfs,
}

/// Whether `mode` is read whole before it is decoded, on a route legacy RustFS reads as an S3
/// operation rather than its admin surface.
const fn buffered(mode: RequestBodyMode, claimed: bool) -> bool {
    !claimed && matches!(mode, RequestBodyMode::Full | RequestBodyMode::Deferred)
}

impl BufferedCeiling {
    /// The ceilings a body of `mode` is read under: `model`, or under the switch, for a buffered
    /// body, legacy RustFS's 20 MiB on the whole body and no operation cap below it.
    pub(crate) const fn ceilings(self, mode: RequestBodyMode, claimed: bool, model: BodyCeilings) -> BodyCeilings {
        match self {
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads every buffered body up to
            // 20 MiB whatever the operation, so a tag set, a versioning or a CORS document of 20 MiB
            // is read and decoded. That is questionable: none of those documents can legitimately
            // come near 1 MiB, and any signed client can make the server hold 20 MiB per request.
            // The intended behaviour is a ceiling per operation, sized to the largest document it
            // can carry (a 10,000-part completion with checksums included), refused from the head.
            Self::LegacyRustfs if buffered(mode, claimed) => BodyCeilings {
                buffered: LEGACY_RUSTFS_BUFFERED_BODY_BYTES,
                whole_body: true,
                declared: None,
            },
            _ => model,
        }
    }

    /// `meta`, reading an XML request document under legacy RustFS's ceiling under the switch.
    pub(crate) const fn apply<'a>(self, meta: MetaView<'a>) -> MetaView<'a> {
        match self {
            // The ceiling is on the body before decoding and a document is at most that body, so a
            // document never meets a bound tighter than the one the body passed.
            #[allow(clippy::cast_possible_truncation)] // 20 MiB fits every target's `usize`.
            Self::LegacyRustfs => meta.with_document_body_ceiling(LEGACY_RUSTFS_BUFFERED_BODY_BYTES as usize),
            Self::Model => meta,
        }
    }

    /// The refusal of a buffered body of `mode`, answered as this switch says: the ceiling's `413`
    /// becomes `400 MaxMessageLengthExceeded`, its connection verdict and unread-body proof kept.
    pub(crate) fn refusal(self, mode: RequestBodyMode, claimed: bool, refusal: S3Error) -> S3Error {
        let past_ceiling = refusal.status() == StatusCode::PAYLOAD_TOO_LARGE
            && refusal.code().is_some_and(|code| *code == ErrorCode::ENTITY_TOO_LARGE);
        if self != Self::LegacyRustfs || !buffered(mode, claimed) || !past_ceiling {
            return refusal;
        }
        // Legacy RustFS reads 20 MiB and then answers `500 InternalError`, a read error its own
        // mapping does not recognise: a legacy bug, not a decision. The profile answers the code that
        // mapping names, as soon as the declared length or a frame crosses the ceiling (rd-err-0014).
        let mut answered = from_transport_limit(
            HandlerError::new(ErrorCode::MAX_MESSAGE_LENGTH_EXCEEDED, PAST_THE_CEILING),
            StatusCode::BAD_REQUEST,
            refusal.connection_intent(),
        );
        answered.body_unfinished = refusal.body_unfinished;
        answered
    }
}

impl ServiceBuilder {
    /// Reads every buffered request body under legacy RustFS's 20 MiB ceiling
    /// (rustfs/gateway#1173): an XML document, a batch delete and a multipart completion up to
    /// 20 MiB are read and decoded, and a body past it is refused `400 MaxMessageLengthExceeded`
    /// before it is buffered — from its declared length, or at the frame that crosses the ceiling.
    ///
    /// Off by default: the core reads an XML document of at most 1 MiB, a `DeleteObjects` body of
    /// at most 2 MiB, and any buffered body up to the assembly's buffered ceiling (`413` past it).
    /// A claimed route, an upload, a POST form and a body-less operation are unchanged.
    #[must_use]
    pub fn bound_buffered_bodies_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.buffered_ceiling = BufferedCeiling::LegacyRustfs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODEL: BodyCeilings = BodyCeilings {
        buffered: 64 * 1024 * 1024,
        whole_body: true,
        declared: Some(2 * 1024 * 1024),
    };

    /// Positive — under the switch a buffered body is bounded at 20 MiB with no cap below it.
    #[test]
    fn the_switch_bounds_a_buffered_body_at_twenty_mebibytes() {
        for mode in [RequestBodyMode::Full, RequestBodyMode::Deferred] {
            let ceilings = BufferedCeiling::LegacyRustfs.ceilings(mode, false, MODEL);
            assert_eq!(ceilings.buffered, 20 * 1024 * 1024, "{mode:?}");
            assert!(ceilings.whole_body, "{mode:?}");
            assert_eq!(ceilings.declared, None, "{mode:?}");
        }
    }

    /// Negative — a claimed route, every other body mode and the default keep the model ceilings.
    #[test]
    fn n_a_claimed_route_other_modes_and_the_default_keep_the_model() {
        assert_eq!(BufferedCeiling::LegacyRustfs.ceilings(RequestBodyMode::Full, true, MODEL), MODEL);
        for mode in [RequestBodyMode::None, RequestBodyMode::Streaming, RequestBodyMode::PostObject] {
            assert_eq!(BufferedCeiling::LegacyRustfs.ceilings(mode, false, MODEL), MODEL, "{mode:?}");
        }
        assert_eq!(BufferedCeiling::Model.ceilings(RequestBodyMode::Full, false, MODEL), MODEL);
        assert_eq!(BufferedCeiling::default(), BufferedCeiling::Model);
    }

    fn ceiling_refusal() -> S3Error {
        crate::gate::past_buffered_ceiling(None)
    }

    /// Positive — under the switch the ceiling's refusal of a buffered body is `400
    /// MaxMessageLengthExceeded`, closing as the ceiling closed.
    #[test]
    fn the_ceiling_refusal_of_a_buffered_body_is_max_message_length_exceeded() {
        let answered = BufferedCeiling::LegacyRustfs.refusal(RequestBodyMode::Full, false, ceiling_refusal());
        assert_eq!(answered.status(), StatusCode::BAD_REQUEST);
        assert_eq!(answered.code(), Some(&ErrorCode::MAX_MESSAGE_LENGTH_EXCEEDED));
        assert_eq!(answered.connection_intent(), ceiling_refusal().connection_intent());
    }

    /// Negative — any other refusal, a claimed route, an unbuffered body and the default are
    /// answered as they came.
    #[test]
    fn n_other_refusals_and_bodies_are_answered_as_they_came() {
        let legacy = BufferedCeiling::LegacyRustfs;
        let other = crate::gate::incomplete();
        assert_eq!(
            legacy.refusal(RequestBodyMode::Full, false, other).code(),
            Some(&ErrorCode::INCOMPLETE_BODY)
        );
        assert_eq!(
            legacy.refusal(RequestBodyMode::Full, true, ceiling_refusal()).status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            legacy.refusal(RequestBodyMode::Streaming, false, ceiling_refusal()).status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            BufferedCeiling::Model
                .refusal(RequestBodyMode::Full, false, ceiling_refusal())
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
