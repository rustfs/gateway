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

//! The RustFS-profile switch that reads a request's checksum declarations as legacy RustFS does
//! (rustfs/gateway#1349).
//!
//! Responsible for: [`ServiceBuilder::read_checksums_as_legacy_rustfs`], which operations it
//! covers, and which of them read `x-amz-checksum-algorithm`.
//! NOT responsible for: the reading itself (`rustfs_gateway_types::legacy_rustfs_request_checksum`),
//! the body verification (`rustfs-gateway-http`), or the binder (`rustfs-gateway-core`).
//! Upstream: `crate::builder::ServiceBuilder`. Downstream: `super::ViewPolicy`, which marks the view
//! of every covered operation, and `crate::integrity`, which reads the mark.

use crate::builder::ServiceBuilder;

/// The upload operations whose legacy storage reader reads `x-amz-checksum-algorithm`.
const ALGORITHM_HEADER_OPERATIONS: [&str; 2] = ["PutObject", "UploadPart"];

/// Whether `operation`'s checksum claims are read as legacy RustFS reads them: every operation
/// whose `x-amz-checksum-*` header describes the request body. `CompleteMultipartUpload`'s describes
/// the assembled object and keeps its own reading.
pub(super) fn covers(operation: &str) -> bool {
    operation != "CompleteMultipartUpload"
}

/// Whether `operation`'s legacy storage reader reads `x-amz-checksum-algorithm`.
pub(super) fn reads_algorithm_header(operation: &str) -> bool {
    ALGORITHM_HEADER_OPERATIONS.contains(&operation)
}

impl ServiceBuilder {
    /// Reads a request's checksum declarations as legacy RustFS reads them (rustfs/gateway#1349).
    ///
    /// Off by default: the core refuses an `x-amz-sdk-checksum-algorithm` without its value header
    /// or naming another algorithm than the value header, and an `x-amz-checksum-type` it cannot
    /// read. Under the switch, as legacy RustFS (rustfs/rustfs `95268a3b9`, measured on a native
    /// build): `x-amz-sdk-checksum-algorithm` is not read, and an `x-amz-checksum-type` legacy
    /// RustFS ignores is ignored; a full-object type on an algorithm that cannot be combined is
    /// refused; and on `PutObject` and `UploadPart` an `x-amz-checksum-algorithm` naming an
    /// algorithm legacy RustFS does not know, or a type it cannot apply beside one, is refused —
    /// each refusal a checksum mismatch, `BadDigest` with
    /// [`ServiceBuilder::answer_checksum_failures_with_bad_digest`].
    ///
    /// Stricter than legacy RustFS, deliberately: the value header present is always compared
    /// (legacy RustFS skips it when `x-amz-checksum-algorithm` names another algorithm), and two
    /// value headers of different algorithms stay refused, since the input carries one claim.
    #[must_use]
    pub fn read_checksums_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.legacy_checksums = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Negative — the completion's checksum describes the assembled object and is not read here;
    /// only the two uploads read the algorithm header.
    #[test]
    fn n_only_the_uploads_read_the_algorithm_header_and_the_completion_is_not_covered() {
        assert!(!covers("CompleteMultipartUpload"));
        for operation in ["PutObject", "UploadPart"] {
            assert!(covers(operation) && reads_algorithm_header(operation), "{operation}");
        }
        for operation in ["PutObjectTagging", "DeleteObjects", "CopyObject", "PutBucketCors"] {
            assert!(covers(operation) && !reads_algorithm_header(operation), "{operation}");
        }
    }
}
