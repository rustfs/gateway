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

//! The RustFS-profile reading of a request's checksum-algorithm declaration: legacy RustFS's two
//! refusals of it, before decode (rustfs/gateway#1349).
//!
//! Responsible for: [`ServiceBuilder::read_checksum_declarations_as_legacy_rustfs`], the closed set
//! of operations it covers ([`LEGACY_CHECKSUM_DECLARATION_OPERATIONS`]), and the refusal an assembly
//! under it answers before decode with, in legacy RustFS's code and sentence.
//! NOT responsible for: arbitrating or verifying a checksum claim (`rustfs_gateway_http::BodyIntegrity`),
//! framing a trailer section (`rustfs_gateway_http::TrailerDeclaration`), or any operation outside
//! the set, whose declaration legacy RustFS never reads.
//! Upstream: `crate::builder::ServiceBuilder`. Downstream: `super::ViewPolicy`, which the service
//! asks for the refusal on the accepted head, after authorization and before decode.
//!
//! # What legacy RustFS answers, and where
//!
//! Legacy RustFS reads one checksum-algorithm member on exactly the operations in
//! [`LEGACY_CHECKSUM_DECLARATION_OPERATIONS`], when it decodes the request: after it has verified
//! the signature, before its per-operation access check and handler. It reads
//! `x-amz-checksum-algorithm` first and, only when that is absent or empty, the checksum names an
//! `x-amz-trailer` declaration lists. Two answers come of it (rustfs/rustfs `95268a3b9` builds its
//! S3 front on a protocol library whose `parse_checksum_algorithm_header` and
//! `get_optional_header` decide them):
//!
//! * `x-amz-checksum-algorithm` on two field lines is `400 InvalidRequest` `duplicate header:
//!   x-amz-checksum-algorithm`, whatever they hold, on every operation in the set; a gateway
//!   operation that does not bind the header (`PutObject` and `UploadPart` bind
//!   `x-amz-sdk-checksum-algorithm`, `kd-decode-0001`) would otherwise serve it;
//! * an `x-amz-trailer` declaration naming a second checksum header — two different ones, or one
//!   twice — is `400 InvalidArgument` `invalid header: x-amz-trailer: <value>`, the value written
//!   as the declaration's text in Rust debug form. Names that are not checksum headers, and empty
//!   names between commas, are skipped; the checksum names are compared without regard to case.
//!
//! The gateway's own answer to the second is `400 InvalidRequest`, from the integrity arbitration
//! or the trailer framing, whichever reads it first: the same refusal under another code, which
//! the RustFS profile answers with legacy's instead. A declaration naming two checksums beside an
//! `x-amz-checksum-algorithm` value passes legacy's decoder and reaches its storage reader, which
//! answers `500 InternalError`; the gateway keeps its `400` there, as it keeps the other legacy
//! `500`s it answers as client errors (`rd-err-0012`).

use rustfs_gateway_core::HandlerError;
use rustfs_gateway_http::HeaderView;
use rustfs_gateway_types::ErrorCode;

use crate::builder::ServiceBuilder;

/// The operations whose checksum-algorithm declaration legacy RustFS reads, and no others: every
/// operation of its S3 front whose input carries the member.
pub const LEGACY_CHECKSUM_DECLARATION_OPERATIONS: [&str; 33] = [
    "CopyObject",
    "CreateBucketMetadataConfiguration",
    "CreateBucketMetadataTableConfiguration",
    "CreateMultipartUpload",
    "DeleteObjects",
    "PutBucketAbac",
    "PutBucketAccelerateConfiguration",
    "PutBucketAcl",
    "PutBucketCors",
    "PutBucketEncryption",
    "PutBucketLifecycleConfiguration",
    "PutBucketLogging",
    "PutBucketOwnershipControls",
    "PutBucketPolicy",
    "PutBucketReplication",
    "PutBucketRequestPayment",
    "PutBucketTagging",
    "PutBucketVersioning",
    "PutBucketWebsite",
    "PutObject",
    "PutObjectAcl",
    "PutObjectAnnotation",
    "PutObjectLegalHold",
    "PutObjectLockConfiguration",
    "PutObjectRetention",
    "PutObjectTagging",
    "PutPublicAccessBlock",
    "RestoreObject",
    "UpdateBucketMetadataAnnotationTableConfiguration",
    "UpdateBucketMetadataInventoryTableConfiguration",
    "UpdateBucketMetadataJournalTableConfiguration",
    "UpdateObjectEncryption",
    "UploadPart",
];

/// The checksum headers legacy RustFS recognises in an `x-amz-trailer` declaration.
const LEGACY_TRAILER_CHECKSUMS: [&str; 10] = [
    "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c",
    "x-amz-checksum-sha1",
    "x-amz-checksum-sha256",
    "x-amz-checksum-crc64nvme",
    "x-amz-checksum-sha512",
    "x-amz-checksum-md5",
    "x-amz-checksum-xxhash64",
    "x-amz-checksum-xxhash3",
    "x-amz-checksum-xxhash128",
];

const CHECKSUM_ALGORITHM: &str = "x-amz-checksum-algorithm";
const TRAILER: &str = "x-amz-trailer";

/// The refusal legacy RustFS answers `operation`'s checksum-algorithm declaration with, if any.
///
/// `headers` is the accepted head the codec binds from.
pub(crate) fn refusal(operation: &str, headers: &HeaderView<'_>) -> Option<HandlerError> {
    if !LEGACY_CHECKSUM_DECLARATION_OPERATIONS.contains(&operation) {
        return None;
    }
    let mut algorithms = headers
        .iter_raw()
        .filter(|(name, _)| name.as_str() == CHECKSUM_ALGORITHM)
        .map(|(_, value)| value);
    if let Some(algorithm) = algorithms.next() {
        if algorithms.next().is_some() {
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS refuses an
            // `x-amz-checksum-algorithm` sent on two lines even when both name the same algorithm,
            // where RFC 9110 §5.3 lets a recipient combine repeated lines of a list-valued field;
            // the header is not list-valued, so the refusal itself is reasonable, but it lands
            // after the signature check on some operations and not others. The intended future
            // behaviour is one refusal of a repeated singleton header for every operation, before
            // the body is read.
            return Some(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                format!("duplicate header: {CHECKSUM_ALGORITHM}"),
            ));
        }
        if !algorithm.is_empty() {
            return None;
        }
    }
    // The wire layer refuses a repeated or non-text `x-amz-trailer` before routing, so one text
    // line is all that can reach here.
    let declared = headers
        .iter_raw()
        .find(|(name, _)| name.as_str() == TRAILER)
        .and_then(|(_, value)| value.to_str().ok())?;
    let checksums = declared
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .filter(|name| LEGACY_TRAILER_CHECKSUMS.iter().any(|known| name.eq_ignore_ascii_case(known)))
        .count();
    (checksums > 1).then(|| HandlerError::new(ErrorCode::INVALID_ARGUMENT, format!("invalid header: {TRAILER}: {declared:?}")))
}

impl ServiceBuilder {
    /// Reads a request's checksum-algorithm declaration on exactly
    /// [`LEGACY_CHECKSUM_DECLARATION_OPERATIONS`] as legacy RustFS does: an
    /// `x-amz-checksum-algorithm` on two lines is `400 InvalidRequest`, and an `x-amz-trailer`
    /// declaration naming a second checksum header is `400 InvalidArgument`, each with legacy
    /// RustFS's sentence, after authorization and before the body is read (rustfs/gateway#1349).
    ///
    /// Off by default: the core reads only the headers each operation's model binds, so a repeated
    /// `x-amz-checksum-algorithm` on an upload binding `x-amz-sdk-checksum-algorithm` is served, and
    /// a declaration naming two checksums is `400 InvalidRequest`. Nothing is served under the
    /// switch that is refused without it: it only refuses earlier, or under legacy's code.
    #[must_use]
    pub fn read_checksum_declarations_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.legacy_checksum_declarations = true;
        self
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use http::{HeaderMap, HeaderName, HeaderValue};

    fn head(lines: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in lines {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                HeaderValue::from_str(value).expect("a header value"),
            );
        }
        map
    }

    fn answer(operation: &str, lines: &[(&str, &str)]) -> Option<(ErrorCode, String)> {
        let map = head(lines);
        refusal(operation, &HeaderView::new(&map)).map(|error| (error.code().clone(), error.message().to_owned()))
    }

    /// Negative — a repeated algorithm is legacy's duplicate-header refusal on every covered
    /// operation, the same algorithm twice included.
    #[test]
    fn n_a_repeated_algorithm_is_a_duplicate_header() {
        for operation in LEGACY_CHECKSUM_DECLARATION_OPERATIONS {
            for (first, second) in [("CRC32", "CRC32"), ("CRC32", "SHA256"), ("", "CRC32")] {
                assert_eq!(
                    answer(operation, &[(CHECKSUM_ALGORITHM, first), (CHECKSUM_ALGORITHM, second)]),
                    Some((ErrorCode::INVALID_REQUEST, "duplicate header: x-amz-checksum-algorithm".to_owned())),
                    "{operation} {first:?} {second:?}"
                );
            }
        }
    }

    /// Negative — a declaration naming a second checksum is legacy's invalid-header refusal,
    /// quoting the declaration: two different names, one name twice, in any case and spacing.
    #[test]
    fn n_a_declaration_naming_two_checksums_is_an_invalid_header() {
        for declared in [
            "x-amz-checksum-crc32,x-amz-checksum-sha256",
            "x-amz-checksum-crc32, x-amz-checksum-crc32",
            "X-Amz-Checksum-CRC32C ,, x-amz-meta-a, x-amz-checksum-xxhash3",
            "x-amz-checksum-md5,x-amz-checksum-crc64nvme",
        ] {
            assert_eq!(
                answer("PutObject", &[(TRAILER, declared)]),
                Some((ErrorCode::INVALID_ARGUMENT, format!("invalid header: x-amz-trailer: {declared:?}"))),
                "{declared}"
            );
        }
    }

    /// Negative — an empty algorithm is the header not sent, so the declaration is read.
    #[test]
    fn n_an_empty_algorithm_leaves_the_declaration_read() {
        assert_eq!(
            answer(
                "UploadPart",
                &[
                    (CHECKSUM_ALGORITHM, ""),
                    (TRAILER, "x-amz-checksum-crc32,x-amz-checksum-sha1")
                ]
            )
            .map(|(code, _)| code),
            Some(ErrorCode::INVALID_ARGUMENT)
        );
    }

    /// Negative — an operation legacy RustFS reads no declaration on is never refused here.
    #[test]
    fn n_an_operation_outside_the_set_is_not_read() {
        for operation in ["GetObject", "CompleteMultipartUpload", "UploadPartCopy", "HeadObject"] {
            assert_eq!(
                answer(
                    operation,
                    &[
                        (CHECKSUM_ALGORITHM, "CRC32"),
                        (CHECKSUM_ALGORITHM, "CRC32"),
                        (TRAILER, "x-amz-checksum-crc32,x-amz-checksum-sha256"),
                    ]
                ),
                None,
                "{operation}"
            );
        }
    }

    /// Positive — what legacy reads without refusing passes: one algorithm (whatever the
    /// declaration beside it says), one declared checksum, names that are not checksums, nothing.
    #[test]
    fn what_legacy_reads_without_refusing_passes() {
        for lines in [
            &[][..],
            &[(CHECKSUM_ALGORITHM, "CRC32")][..],
            &[
                (CHECKSUM_ALGORITHM, "CRC32"),
                (TRAILER, "x-amz-checksum-crc32,x-amz-checksum-sha256"),
            ][..],
            &[(TRAILER, "x-amz-checksum-crc32")][..],
            &[(TRAILER, "x-amz-checksum-crc32, x-amz-meta-a, x-amz-checksum-blake3")][..],
            &[(TRAILER, " , ")][..],
        ] {
            assert_eq!(answer("PutObject", lines), None, "{lines:?}");
        }
    }
}
