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

//! The RustFS-profile readings an assembly applies to the view every codec reads
//! (rustfs/backlog#1677): the switches that make a RustFS deployment answer a request the way
//! RustFS answers it today, where the core keeps the AWS-model answer as its default.
//!
//! Responsible for: [`ServiceBuilder::clamp_oversized_max_keys`], the closed set of listings it
//! covers, and the per-request decision the assembly applies to the routed view, the client
//! checksum waivers of `super::client_quirks` included.
//! NOT responsible for: reading the parameter ([`rustfs_gateway_core::MetaView::query`]) or the
//! modelled range the default refuses outside of (the generated codec).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, which applies [`ViewPolicy`]
//! to the view every decoder reads.
//!
//! # Why an oversized `max-keys` is clamped, and on exactly these listings
//!
//! Legacy RustFS takes `max-keys` as any 32-bit integer, refuses a negative one with
//! `InvalidArgument`, and lowers anything above 1000 to 1000 before it lists or echoes it
//! (rustfs/rustfs@1e7065101d `rustfs/src/storage/s3_api/bucket.rs:40-42` `normalize_max_keys`,
//! `:121-145` and `:147-165`, the two `parse_list_*_params` functions; the clamped value is the
//! one listed and echoed, `rustfs/src/app/bucket_usecase.rs:1071` and `:1160`). `ListObjects`
//! goes through the same ListObjectsV2 path (`bucket_usecase.rs:3109-3119`). Hadoop S3A pages
//! at 5000 by default, and the RustFS e2e suite pages ListObjectsV2 at 1001.
//!
//! The core keeps `q-max-keys-0073` as the default: ListObjectsV2 refuses a value above the ceiling
//! (`c-list-0028`). The RustFS profile clamps it instead, and clamps the other two listings too,
//! which the core hands to the backend as sent, so the page a backend serves and the
//! `<MaxKeys>` it echoes are the ones RustFS serves and echoes.
//!
//! `max-uploads` and `max-parts` are deliberately not here: RustFS refuses a value outside
//! `1..=1000` for both (`rustfs/src/storage/s3_api/multipart.rs`, `parse_list_parts_params` and
//! `parse_list_multipart_uploads_params`) after its access check, and the core hands both to the
//! backend as sent, so a RustFS backend already gives RustFS's answer in RustFS's order. Clamping
//! them here would serve a page RustFS refuses.

use super::ServiceBuilder;
use super::client_quirks::ChecksumWaiver;
use rustfs_gateway_core::{MetaView, PageSizeCeiling};

/// The page size RustFS lowers an oversized `max-keys` to (`S3_MAX_KEYS`).
pub const RUSTFS_MAX_KEYS_CEILING: i32 = 1000;

/// The listings whose `max-keys` the RustFS profile clamps, and no others.
pub const CLAMPED_MAX_KEYS_OPERATIONS: [&str; 3] = ["ListObjects", "ListObjectVersions", "ListObjectsV2"];

/// The `max-keys` ceiling, as the view applies it.
const MAX_KEYS: PageSizeCeiling = PageSizeCeiling::new("max-keys", RUSTFS_MAX_KEYS_CEILING);

/// Which RustFS-profile readings this assembly applies to a routed view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ViewPolicy {
    /// The client checksum waivers (`super::client_quirks`).
    pub(super) checksum_waiver: ChecksumWaiver,
    clamp_max_keys: bool,
}

impl ViewPolicy {
    /// The routed view of `operation`, with this assembly's readings applied to it.
    pub(crate) fn apply<'a>(self, operation: &str, meta: MetaView<'a>) -> MetaView<'a> {
        let meta = self.checksum_waiver.apply(operation, meta);
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS silently lowers an oversized
        // `max-keys` to 1000 on every listing instead of refusing it, so a client asking for more
        // cannot tell a short page from its own mistake. Kept so RustFS clients (Hadoop S3A pages
        // at 5000) see no change; the intended future behaviour is the core default, a
        // `400 InvalidArgument` for a page size outside the modelled range (`q-max-keys-0073`).
        if self.clamp_max_keys && CLAMPED_MAX_KEYS_OPERATIONS.contains(&operation) {
            meta.with_page_size_ceiling(MAX_KEYS)
        } else {
            meta
        }
    }
}

impl ServiceBuilder {
    /// Clamps a `max-keys` above [`RUSTFS_MAX_KEYS_CEILING`] to it on exactly
    /// [`CLAMPED_MAX_KEYS_OPERATIONS`], as RustFS does, instead of refusing it (ListObjectsV2's
    /// modelled range) or handing it to the backend as sent (the other two).
    ///
    /// Off by default: the core answers ListObjectsV2's modelled range, `400 InvalidArgument` for a
    /// page size above a thousand (`c-list-0028`). The RustFS profile turns it on so that Hadoop
    /// S3A's 5000-key pages and every other client RustFS serves today keep working. A negative or
    /// unparseable value is still refused, as RustFS refuses it.
    #[must_use]
    pub fn clamp_oversized_max_keys(mut self) -> Self {
        self.view_policy.clamp_max_keys = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_is_off_by_default_and_its_set_is_closed() {
        assert!(!ViewPolicy::default().clamp_max_keys);
        for operation in ["ListMultipartUploads", "ListParts", "ListBuckets", "GetObject", "PutObject"] {
            assert!(!CLAMPED_MAX_KEYS_OPERATIONS.contains(&operation), "{operation}");
        }
        assert_eq!(MAX_KEYS.parameter(), "max-keys");
        assert_eq!(MAX_KEYS.ceiling(), 1000);
    }
}
