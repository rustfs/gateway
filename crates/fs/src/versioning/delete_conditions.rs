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

//! `If-Match` on `DeleteObject`, read and judged as legacy RustFS reads and judges it
//! (rustfs/gateway#1191).
//!
//! Responsible for: reading the header value as legacy RustFS reads it, and the verdict against
//! what a delete targets — an object version's tag, a delete marker, or nothing — including legacy
//! RustFS's one exception, a versioned bucket's key that holds no version at all, left unjudged.
//! NOT responsible for: whether the rule is on (`crate::rustfs_parity`), selecting the target or
//! deleting it (`super`'s `delete_object_version_if`, which holds the version lock from this
//! verdict to the delete), or the RFC 9110 conditions of reads and writes (`crate::conditions`).
//! Upstream: the `DeleteObject` handler. Downstream: nothing.

use rustfs_gateway::{ErrorCode, HandlerError, PRECONDITION_FAILED_MESSAGE};

use super::super::records::{RecordKind, VersionRecord};
use super::super::{FsBackend, etag};
use super::{VersioningState, newest_for_key};

/// A delete's `If-Match` value, trimmed and never blank.
pub(super) struct DeleteIfMatch(String);

impl DeleteIfMatch {
    /// Refuses the delete unless `e_tag` — the stored tag of the targeted object version, `None`
    /// for a delete marker or for nothing — satisfies the condition.
    fn guard(&self, e_tag: Option<&str>) -> Result<(), HandlerError> {
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS strips every surrounding double quote
        // from both tags and compares what is left as a string (`etag_matches`,
        // `crates/storage-api/src/object.rs:750` on rustfs/rustfs 3268c42e00), so `"*"` is the
        // wildcard, `""<tag>""` matches, and a list or a weak tag never does. That is not RFC
        // 9110's strong comparison, under which a quoted `*` is an ordinary entity tag and a
        // malformed value is refused rather than half read. Intended: the RFC 9110 parse and
        // strong comparison the backend's other conditions use (`crate::conditions`).
        let wanted = self.0.trim_matches('"');
        let holds = e_tag.is_some_and(|e_tag| wanted == "*" || e_tag.trim_matches('"') == wanted);
        if holds {
            Ok(())
        } else {
            Err(HandlerError::new(ErrorCode::PRECONDITION_FAILED, PRECONDITION_FAILED_MESSAGE))
        }
    }
}

/// The stored tag of `record`, or `None` for a delete marker.
fn object_tag(record: &VersionRecord) -> Option<&str> {
    matches!(record.kind, RecordKind::Object).then_some(record.e_tag.as_str())
}

impl FsBackend {
    /// The condition a delete's `If-Match` carries, read only when the deployment asked for legacy
    /// RustFS's rule ([`FsBackend::evaluating_delete_if_match`]); otherwise the header is unread.
    /// Absent or blank is no condition, as legacy RustFS reads it
    /// (`crates/storage-api/src/object.rs:746` on rustfs/rustfs 3268c42e00).
    pub(super) fn delete_condition(&self, value: Option<&str>) -> Option<DeleteIfMatch> {
        let value = value.filter(|_| self.rustfs_parity.delete_if_match)?.trim();
        (!value.is_empty()).then(|| DeleteIfMatch(value.to_owned()))
    }

    /// The tag of the object file a key held before version records existed, or `None`.
    async fn plain_object_tag(&self, bucket: &str, key: &str) -> Result<Option<String>, HandlerError> {
        match self.read_object_if_present(bucket, key).await? {
            Some((bytes, _)) => Ok(Some(etag(&bytes)?.opaque_tag().to_owned())),
            None => Ok(None),
        }
    }

    /// Judges a delete of the version named `version_id`: `record` when one is stored, else the
    /// plain object file when the name is `null`. A name nothing answers to is not judged — the
    /// delete removes nothing either way, as legacy RustFS's does.
    pub(super) async fn judge_named(
        &self,
        condition: &DeleteIfMatch,
        bucket: &str,
        key: &str,
        version_id: &str,
        record: Option<&VersionRecord>,
    ) -> Result<(), HandlerError> {
        match record {
            Some(record) => condition.guard(object_tag(record)),
            None if version_id == "null" => match self.plain_object_tag(bucket, key).await? {
                Some(e_tag) => condition.guard(Some(&e_tag)),
                None => Ok(()),
            },
            None => Ok(()),
        }
    }

    /// Judges a delete of the key's current version under the delete's versioning `state`.
    pub(super) async fn judge_current(
        &self,
        condition: &DeleteIfMatch,
        bucket: &str,
        key: &str,
        state: VersioningState,
        records: &[VersionRecord],
    ) -> Result<(), HandlerError> {
        if let Some(record) = newest_for_key(records, key) {
            return condition.guard(object_tag(record));
        }
        if let Some(e_tag) = self.plain_object_tag(bucket, key).await? {
            return condition.guard(Some(&e_tag));
        }
        if matches!(state, VersioningState::Never) {
            return condition.guard(None);
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS does not judge the condition when a
        // versioned or suspended bucket's key holds no version at all; it writes a delete marker
        // instead (`should_force_delete_marker_for_missing_version`,
        // `crates/ecstore/src/set_disk/mod.rs:5980`, and `crates/ecstore/src/set_disk/ops/object.rs:8943-8951`
        // on rustfs/rustfs 3268c42e00), so `If-Match: *` on a key that does not exist succeeds.
        // The condition names a representation that is not there, which RFC 9110 says fails it,
        // and an unversioned bucket already answers `412`. Intended: `412` with no marker written.
        Ok(())
    }
}
