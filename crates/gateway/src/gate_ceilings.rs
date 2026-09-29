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

//! The per-operation body cap table and the ceiling on an upload's object, split out of
//! `crate::gate` at the 800-line limit.
//!
//! Responsible for: [`declared_body_cap`], the per-operation cap table `crate::gate::BodyCeilings`
//! reads; [`object_ceiling_for`], which operations an assembly's upload-object ceiling reaches;
//! [`max_framed_upload_bytes`], the wire length an aws-chunked upload of a given object can have
//! and still pass the chunk decoder; and [`past_object_ceiling`], the refusal of an upload whose
//! object is past the ceiling.
//! NOT responsible for: enforcing them (`crate::wire_read` frame by frame, `crate::request_body`
//! before the first frame) or the other refusals (`crate::gate`).
//! Upstream: `crate::config::ServiceConfig`. Downstream: `crate::gate`, which re-exports them.

use http::StatusCode;
use rustfs_gateway_core::{HandlerError, RequestBodyMode};
use rustfs_gateway_types::ErrorCode;

use crate::render::{S3Error, from_transport_limit};
use crate::wire_read::RequestBodyUnfinished;

/// How large a well-formed body for this operation can be, when the operation bounds one.
///
/// **This table is in the wrong crate and is here for a boundary reason, not a design one.** The
/// bound belongs beside the operation — `rustfs_gateway_core::Operation` is where a per-operation
/// constant should be declared, so that a new operation with a bounded body cannot be added
/// without stating its bound. Until that constant exists, an assembly that enforces nothing is
/// strictly worse than an assembly that enforces the documented number from one greppable place.
///
/// `DeleteObjects` is the only entry: AWS documents the request as carrying at most one thousand
/// key entries, and a thousand entries of the maximum key length plus their version ids fit inside
/// two mebibytes with room to spare. Everything else is `None` and falls back to the assembly's
/// buffered ceiling.
pub(crate) const fn declared_body_cap(operation: &str) -> Option<u64> {
    match operation.as_bytes() {
        b"DeleteObjects" => Some(MAX_DELETE_OBJECTS_BODY_BYTES),
        _ => None,
    }
}

/// The `DeleteObjects` request-body cap, in bytes.
const MAX_DELETE_OBJECTS_BODY_BYTES: u64 = 2 * 1024 * 1024;

/// The object ceiling `config` sets for `operation` read in `mode`: RustFS applies its own to a
/// streamed `PutObject` and `UploadPart` only, and so does this; every other operation, and a
/// `PostObject` file (bounded by its form limits), has none.
pub(crate) fn object_ceiling_for(mode: RequestBodyMode, operation: &str, config: &crate::config::ServiceConfig) -> Option<u64> {
    let upload = matches!(mode, RequestBodyMode::Streaming) && matches!(operation, "PutObject" | "UploadPart");
    config.upload_object_ceiling().filter(|_| upload)
}

/// Framing slack beyond the chunk decoder's overhead ratio: the last chunk-size line and CRLFs the
/// ratio counts after its last check, and the trailer section, which it does not count at all.
const FRAMING_SLACK: u64 = 64 * 1024;

/// The largest wire length an aws-chunked upload of `object` bytes can have and still be accepted
/// by this crate's chunk decoder: the object, the framing overhead `ChunkLimits::default()` admits
/// for it, and slack for the final chunk line and the trailer section.
///
/// An assembly that sets `ServiceConfig::with_upload_object_ceiling` near `Limits::max_body_bytes`
/// raises the latter to this, so an upload whose object fits is not refused at the wire for its
/// framing: the wire length of an aws-chunked body counts its chunk lines, and legacy RustFS
/// applies its 5 GiB ceiling to the decoded object alone (rustfs/rustfs#7635).
#[must_use]
pub fn max_framed_upload_bytes(object: u64) -> u64 {
    let limits = rustfs_gateway_http::ChunkLimits::default();
    let ratio = object.saturating_mul(u64::from(limits.max_overhead_permille())) / 1000;
    object
        .saturating_add(ratio.max(limits.overhead_ratio_floor_bytes()))
        .saturating_add(FRAMING_SLACK)
}

/// The refusal for an upload whose object is larger than the assembly's ceiling on one
/// (`ServiceConfig::with_upload_object_ceiling`): `400 EntityTooLarge`, as S3 and RustFS answer an
/// upload past their single-request limit, before a body byte is read. Closes the connection on
/// the body nobody read, for `crate::gate::past_declared_cap`'s reason.
pub(crate) fn past_object_ceiling(proof: Option<RequestBodyUnfinished>) -> S3Error {
    let mut refusal = from_transport_limit(
        HandlerError::new(ErrorCode::ENTITY_TOO_LARGE, "Your proposed upload exceeds the maximum allowed size."),
        StatusCode::BAD_REQUEST,
        crate::close::after_body_ceiling(),
    );
    refusal.body_unfinished = proof;
    refusal
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The helper admits the decoder's whole overhead allowance and nothing unbounded.
    #[test]
    fn the_framed_bound_is_the_object_plus_the_decoders_overhead_allowance() {
        let five_gib = 5 * 1024 * 1024 * 1024;
        assert_eq!(max_framed_upload_bytes(five_gib), five_gib + five_gib / 20 + FRAMING_SLACK);
        assert_eq!(max_framed_upload_bytes(0), 4096 + FRAMING_SLACK, "the ratio floor");
        assert_eq!(max_framed_upload_bytes(u64::MAX), u64::MAX, "saturates rather than wraps");
    }

    /// Positive — a configured ceiling reaches a streamed `PutObject` and `UploadPart`.
    #[test]
    fn the_object_ceiling_reaches_the_streamed_uploads() {
        let config = crate::config::ServiceConfig::new(1024).with_upload_object_ceiling(10);
        for operation in ["PutObject", "UploadPart"] {
            assert_eq!(
                object_ceiling_for(RequestBodyMode::Streaming, operation, &config),
                Some(10),
                "{operation}"
            );
        }
    }

    /// Negative — no ceiling unless configured, and none for any other operation or body mode.
    #[test]
    fn n_the_object_ceiling_is_the_uploads_alone() {
        let unset = crate::config::ServiceConfig::new(1024);
        for operation in ["PutObject", "UploadPart"] {
            assert_eq!(object_ceiling_for(RequestBodyMode::Streaming, operation, &unset), None, "{operation}");
        }
        let config = crate::config::ServiceConfig::new(1024).with_upload_object_ceiling(10);
        for operation in [
            "PostObject",
            "PutBucketPolicy",
            "CompleteMultipartUpload",
            "UploadPartCopy",
            "putobject",
        ] {
            for mode in [RequestBodyMode::Streaming, RequestBodyMode::PostObject, RequestBodyMode::Full] {
                assert_eq!(object_ceiling_for(mode, operation, &config), None, "{operation} {mode:?}");
            }
        }
        for mode in [
            RequestBodyMode::PostObject,
            RequestBodyMode::Full,
            RequestBodyMode::None,
            RequestBodyMode::Deferred,
        ] {
            assert_eq!(object_ceiling_for(mode, "PutObject", &config), None, "{mode:?}");
        }
    }
}
