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

//! The checksum a CopyObject result reports for the object it copied.
//!
//! Responsible for: mapping a checksum the copied object was written with to the one result member
//! S3 names for its algorithm.
//! Not responsible for: deciding whether the object's checksum was supplied (the copy handler reads
//! `StoredObject::checksum_supplied`) or the copy itself.
//! Upstream: the CopyObject handler. Downstream: the generated CopyObject encoder.

use super::*;

/// The copy result's checksum member for a checksum the copied object was written with: S3 reports
/// that algorithm, and none for an object written without one (`c-copy-0044`, `c-copy-0010`).
pub(super) fn copy_result_checksum(checksum: Option<&ChecksumSpec>) -> dto::CopyObjectOutput {
    let mut output = dto::CopyObjectOutput::default();
    let Some(checksum) = checksum else { return output };
    let value = Some(checksum.render_base64().to_owned());
    match checksum.algorithm() {
        ChecksumAlgorithm::Crc32 => output.checksum_crc32 = value,
        ChecksumAlgorithm::Crc32c => output.checksum_crc32c = value,
        ChecksumAlgorithm::Crc64Nvme => output.checksum_crc64nvme = value,
        ChecksumAlgorithm::Sha1 => output.checksum_sha1 = value,
        ChecksumAlgorithm::Sha256 => output.checksum_sha256 = value,
        ChecksumAlgorithm::Sha512 => output.checksum_sha512 = value,
        ChecksumAlgorithm::Md5 => output.checksum_md5 = value,
        ChecksumAlgorithm::XxHash64 => output.checksum_xxhash64 = value,
        ChecksumAlgorithm::XxHash3 => output.checksum_xxhash3 = value,
        ChecksumAlgorithm::XxHash128 => output.checksum_xxhash128 = value,
        // An algorithm added after these ten has no result member to report it in yet.
        _ => {}
    }
    output
}
