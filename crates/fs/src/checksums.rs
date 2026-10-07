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

//! Stored checksum attributes and their projection into object responses.
//!
//! Responsible for: keeping a checksum's explicit type marker and mapping both into response fields.
//! NOT responsible for: checksum computation, the record grammar or request-mode decisions.
//! Upstream: the filesystem record and write handlers. Downstream: read/copy handlers and response codecs.

use rustfs_gateway::{ChecksumSpec, ChecksumType, dto};

/// A checksum and whether its stored representation explicitly reports its type.
///
/// Plain PUT reports no type; multipart completion does, even for FULL_OBJECT values whose
/// bytes alone are indistinguishable from a plain PUT checksum.
#[derive(Clone, Copy, Debug)]
pub(super) struct StoredChecksum {
    pub(super) value: ChecksumSpec,
    pub(super) report_type: bool,
}

impl StoredChecksum {
    pub(super) fn plain(value: ChecksumSpec) -> Self {
        Self {
            value,
            report_type: false,
        }
    }

    pub(super) fn multipart(value: ChecksumSpec) -> Self {
        Self {
            value,
            report_type: true,
        }
    }

    pub(super) fn dto_type(self) -> Option<dto::ChecksumType> {
        self.report_type.then(|| match self.value.checksum_type() {
            ChecksumType::Composite => dto::ChecksumType::COMPOSITE,
            ChecksumType::FullObject => dto::ChecksumType::FULL_OBJECT,
        })
    }
}

macro_rules! set_object_checksum {
    ($output:expr, $checksum:expr) => {{
        if let Some(checksum) = $checksum {
            let output = &mut $output;
            let slot = match checksum.value.algorithm() {
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
            *slot = Some(checksum.value.render_base64().to_owned());
        }
    }};
}
