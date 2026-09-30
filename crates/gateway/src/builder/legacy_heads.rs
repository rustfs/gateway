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

//! The RustFS-profile switch that writes a successful answer's status and headers as legacy RustFS
//! writes them (rustfs/gateway#1148).
//!
//! Responsible for: [`ServiceBuilder::answer_heads_as_legacy_rustfs`] and [`AnswerHeads::settle`],
//! which the pipeline applies to a settled answer after its encoder and before the framework
//! stamps it: `HeadBucket` without a region the backend left unnamed, `PutBucketPolicy` as `204`,
//! `RestoreObject` as `200`, and `GetBucketPolicy` without a `Content-Type`.
//! NOT responsible for: the document an answer carries (its layout is rustfs/gateway#1078's), an
//! error answer (`crate::render`), or a committed answer, whose head left before its outcome was
//! known.
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS writes
//!
//! Its writer answers each of these with a fixed head, whatever the backend meant
//! (rustfs/rustfs `e870a6d25b` pins the legacy stack whose writers these are): `HeadBucket` writes
//! `x-amz-bucket-region` only when the output names one, and RustFS's handler names none
//! (`rustfs/src/app/bucket_usecase.rs:1520-1536`, `HeadBucketOutput::default()`); `PutBucketPolicy`
//! answers `204 No Content`; `RestoreObject` answers `200` for every restore, a first retrieval
//! included; `GetBucketPolicy` writes the policy as the body and sets no `Content-Type`. RustFS
//! overrides none of these statuses (it sets one only on `DeleteObject`, `DeleteBucketEncryption`
//! and `DeletePublicAccessBlock`, all `204` in the model too). Each was observed on a legacy RustFS
//! build: a `HeadBucket` of an existing bucket answers `200` with no `x-amz-bucket-region`.
//!
//! Legacy-compat (rustfs/backlog#2684): the region a client uses to follow a bucket to its endpoint,
//! the `202` that tells a restore poller "come back later" from the `200` that says "it is here",
//! and the type of the policy document are all missing or flattened. Kept so RustFS clients see what
//! they see today; the intended future behaviour is the model's heads, which the core writes by
//! default.

use http::StatusCode;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use rustfs_gateway_core::{EncodedResponse, ResponseBody};

use super::ServiceBuilder;

/// The header `HeadBucket` names the bucket's region in.
const BUCKET_REGION: &str = "x-amz-bucket-region";

/// Which heads an assembly writes a successful answer with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum AnswerHeads {
    /// The model's: the status and headers the operation declares.
    #[default]
    Model,
    /// Legacy RustFS's, for the four operations whose heads its writer spells otherwise.
    LegacyRustfs,
}

impl AnswerHeads {
    /// `encoded`, the settled answer to `operation`, with legacy RustFS's head when this assembly
    /// writes those. Nothing is added: a status is lowered to the one legacy RustFS writes, and a
    /// header it does not write is removed. Every other operation, and every answer under the
    /// model's heads, is left as its encoder wrote it.
    pub(crate) fn settle(self, operation: &str, encoded: &mut EncodedResponse) {
        if self == Self::Model {
            return;
        }
        match operation {
            // An empty region is how the migration seam hands over a legacy output that named none:
            // a region is never empty, so nothing a backend meant is lost.
            "HeadBucket" if encoded.headers.get(BUCKET_REGION).is_some_and(|region| region.is_empty()) => {
                encoded.headers.remove(BUCKET_REGION);
            }
            "PutBucketPolicy" if encoded.status == StatusCode::OK => {
                encoded.status = StatusCode::NO_CONTENT;
                encoded.body = ResponseBody::Empty;
                encoded.headers.remove(CONTENT_LENGTH);
                encoded.headers.remove(CONTENT_TYPE);
            }
            "RestoreObject" if encoded.status == StatusCode::ACCEPTED => encoded.status = StatusCode::OK,
            "GetBucketPolicy" => {
                encoded.headers.remove(CONTENT_TYPE);
            }
            _ => {}
        }
    }
}

impl ServiceBuilder {
    /// Writes a successful answer's status and headers as legacy RustFS writes them, as RustFS
    /// does today (rustfs/gateway#1148): `HeadBucket` without an `x-amz-bucket-region` the backend
    /// left empty, `PutBucketPolicy` as `204 No Content`, `RestoreObject` as `200` whatever the
    /// retrieval's state, and `GetBucketPolicy` without a `Content-Type`.
    ///
    /// Off by default: the core writes the model's heads — `200` for a policy write, `202` for a
    /// restore it started, the JSON type for a policy and the region on every `HeadBucket`. Only the
    /// head changes; the body, and every answer to any other operation, is what the encoder wrote.
    #[must_use]
    pub fn answer_heads_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.answer_heads = AnswerHeads::LegacyRustfs;
        self
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn answer(status: StatusCode, headers: &[(&'static str, &str)], body: &[u8]) -> EncodedResponse {
        let mut encoded = EncodedResponse::of(status.as_u16());
        encoded.status = status;
        for (name, value) in headers {
            encoded.set_header(name, value);
        }
        if !body.is_empty() {
            encoded.body = ResponseBody::Complete(body.to_vec());
        }
        encoded
    }

    fn settled(heads: AnswerHeads, operation: &str, mut encoded: EncodedResponse) -> EncodedResponse {
        heads.settle(operation, &mut encoded);
        encoded
    }

    fn header<'a>(encoded: &'a EncodedResponse, name: &str) -> Option<&'a str> {
        encoded.headers.get(name).and_then(|value| value.to_str().ok())
    }

    #[test]
    fn the_legacy_heads_are_written_for_the_four_operations() {
        let unnamed = settled(
            AnswerHeads::LegacyRustfs,
            "HeadBucket",
            answer(StatusCode::OK, &[(BUCKET_REGION, "")], b""),
        );
        assert_eq!((unnamed.status, header(&unnamed, BUCKET_REGION)), (StatusCode::OK, None));
        let policy_write = settled(AnswerHeads::LegacyRustfs, "PutBucketPolicy", answer(StatusCode::OK, &[], b""));
        assert_eq!(policy_write.status, StatusCode::NO_CONTENT);
        assert!(matches!(policy_write.body, ResponseBody::Empty));
        let restore = settled(AnswerHeads::LegacyRustfs, "RestoreObject", answer(StatusCode::ACCEPTED, &[], b""));
        assert_eq!(restore.status, StatusCode::OK);
        let policy = settled(
            AnswerHeads::LegacyRustfs,
            "GetBucketPolicy",
            answer(StatusCode::OK, &[("content-type", "application/json")], b"{}"),
        );
        assert_eq!((policy.status, header(&policy, "content-type")), (StatusCode::OK, None));
        assert!(matches!(policy.body, ResponseBody::Complete(ref bytes) if bytes == b"{}"));
    }

    /// Negative — the model's heads are the default: nothing is rewritten.
    #[test]
    fn n_the_model_heads_are_kept_by_default() {
        let unnamed = settled(AnswerHeads::default(), "HeadBucket", answer(StatusCode::OK, &[(BUCKET_REGION, "")], b""));
        assert_eq!(header(&unnamed, BUCKET_REGION), Some(""));
        let policy_write = settled(AnswerHeads::default(), "PutBucketPolicy", answer(StatusCode::OK, &[], b""));
        assert_eq!(policy_write.status, StatusCode::OK);
        let restore = settled(AnswerHeads::default(), "RestoreObject", answer(StatusCode::ACCEPTED, &[], b""));
        assert_eq!(restore.status, StatusCode::ACCEPTED);
        let policy = settled(
            AnswerHeads::default(),
            "GetBucketPolicy",
            answer(StatusCode::OK, &[("content-type", "application/json")], b"{}"),
        );
        assert_eq!(header(&policy, "content-type"), Some("application/json"));
    }

    /// Negative — a region the backend named is written, and no other answer is touched.
    #[test]
    fn n_a_named_region_and_every_other_answer_are_left_as_encoded() {
        let named = settled(
            AnswerHeads::LegacyRustfs,
            "HeadBucket",
            answer(StatusCode::OK, &[(BUCKET_REGION, "us-east-1")], b""),
        );
        assert_eq!(header(&named, BUCKET_REGION), Some("us-east-1"));
        for operation in ["GetBucketLocation", "PutBucketTagging", "HeadObject", "GetObject"] {
            let other = settled(
                AnswerHeads::LegacyRustfs,
                operation,
                answer(StatusCode::OK, &[("content-type", "application/json"), (BUCKET_REGION, "")], b"x"),
            );
            assert_eq!(
                (other.status, header(&other, "content-type"), header(&other, BUCKET_REGION)),
                (StatusCode::OK, Some("application/json"), Some("")),
                "{operation}"
            );
        }
    }

    /// Negative — only the status legacy RustFS replaces is lowered: a restore of an object already
    /// restored stays `200`, and no other status of either operation is rewritten.
    #[test]
    fn n_only_the_replaced_status_is_rewritten() {
        let restored = settled(AnswerHeads::LegacyRustfs, "RestoreObject", answer(StatusCode::OK, &[], b""));
        assert_eq!(restored.status, StatusCode::OK);
        let created = settled(AnswerHeads::LegacyRustfs, "PutBucketPolicy", answer(StatusCode::CREATED, &[], b""));
        assert_eq!(created.status, StatusCode::CREATED);
        let other = settled(AnswerHeads::LegacyRustfs, "RestoreObject", answer(StatusCode::CREATED, &[], b""));
        assert_eq!(other.status, StatusCode::CREATED);
    }
}
