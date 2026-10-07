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

//! How a view's `x-amz-checksum-*` headers are read: the model's reading, an unknown algorithm
//! ignored, or legacy RustFS's reading of the declarations (rustfs/gateway#1349).
//!
//! Responsible for: [`ChecksumReading`], [`MetaView::with_legacy_rustfs_checksums`] and
//! [`MetaView::legacy_rustfs_checksum_reading`], the mark the assembly's body verification reads.
//! NOT responsible for: verifying a claim (`rustfs-gateway-http`'s `BodyIntegrity`), or the binder
//! (`crate::codec::value::checksum_spec`), which binds the one value header under every reading.
//! Upstream: the assembly that builds the view. Downstream: the assembly's body verification.

use super::MetaView;

/// How a view's decoder reads `x-amz-checksum-*` headers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum ChecksumReading {
    /// The model's reading: one claim, an unknown algorithm refused.
    #[default]
    Model,
    /// The model's reading, a header naming an unknown algorithm ignored.
    UnknownIgnored,
    /// Legacy RustFS's reading (which ignores an unknown algorithm too); `reads_algorithm_header`
    /// when the operation's legacy storage reader reads `x-amz-checksum-algorithm`.
    LegacyRustfs { reads_algorithm_header: bool },
}

impl ChecksumReading {
    /// This reading with an unknown algorithm ignored: the legacy reading already ignores one.
    pub(super) const fn ignoring_unknown(self) -> Self {
        match self {
            Self::Model => Self::UnknownIgnored,
            other => other,
        }
    }
}

impl MetaView<'_> {
    /// This view, for a deployment that reads checksum declarations as legacy RustFS does
    /// (rustfs/gateway#1349); `reads_algorithm_header` when the operation's legacy storage reader
    /// reads `x-amz-checksum-algorithm`. A header naming an unknown algorithm is ignored, and the
    /// decoder binds the one value header as under every reading.
    #[must_use]
    pub const fn with_legacy_rustfs_checksums(mut self, reads_algorithm_header: bool) -> Self {
        self.checksum_reading = ChecksumReading::LegacyRustfs { reads_algorithm_header };
        self
    }

    /// `Some(reads_algorithm_header)` when the view reads checksum headers as legacy RustFS does.
    #[must_use]
    pub const fn legacy_rustfs_checksum_reading(&self) -> Option<bool> {
        match self.checksum_reading {
            ChecksumReading::LegacyRustfs { reads_algorithm_header } => Some(reads_algorithm_header),
            ChecksumReading::Model | ChecksumReading::UnknownIgnored => None,
        }
    }
}
