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

//! Checksum projection into the three object-response DTOs with separate checksum fields.
//!
//! Responsible for: mapping one typed checksum to its named response field.
//! NOT responsible for: checksum computation, persistence or request-mode decisions.
//! Upstream: the filesystem read/copy handlers. Downstream: the response codecs.

macro_rules! set_object_checksum {
    ($output:expr, $checksum:expr) => {{
        if let Some(checksum) = $checksum {
            let output = &mut $output;
            let slot = match checksum.algorithm() {
                rustfs_gateway::ChecksumAlgorithm::Crc32 => &mut output.checksum_crc32,
                rustfs_gateway::ChecksumAlgorithm::Crc32c => &mut output.checksum_crc32c,
                rustfs_gateway::ChecksumAlgorithm::Crc64Nvme => &mut output.checksum_crc64nvme,
                rustfs_gateway::ChecksumAlgorithm::Sha1 => &mut output.checksum_sha1,
                rustfs_gateway::ChecksumAlgorithm::Sha256 => &mut output.checksum_sha256,
                rustfs_gateway::ChecksumAlgorithm::Sha512 => &mut output.checksum_sha512,
                rustfs_gateway::ChecksumAlgorithm::Md5 => &mut output.checksum_md5,
                rustfs_gateway::ChecksumAlgorithm::XxHash64 => &mut output.checksum_xxhash64,
                rustfs_gateway::ChecksumAlgorithm::XxHash3 => &mut output.checksum_xxhash3,
                rustfs_gateway::ChecksumAlgorithm::XxHash128 => &mut output.checksum_xxhash128,
                _ => return Err(crate::storage_error()),
            };
            *slot = Some(checksum.render_base64().to_owned());
        }
    }};
}
