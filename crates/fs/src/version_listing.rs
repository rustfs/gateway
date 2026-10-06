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

//! `ListObjectVersions`: the version census as one paged, delimiter-aware listing.
//!
//! Responsible for: ordering every version and delete marker under a prefix, rolling the keys
//! below a delimiter into `CommonPrefixes` exactly as `ListObjects` does, paging the merged
//! sequence by `max-keys`, and resuming from the key and version markers.
//! NOT responsible for: reading or writing version records (`versioning`), or the ordinary object
//! listing (`listing`), whose rollup rule this module shares.
//! Upstream: `versioning::version_records`. Downstream: the production `ListObjectVersions` route.
//!
//! # Why the delimiter is applied here and not echoed
//!
//! The API reference says of `Delimiter`: all keys that contain the same string between the prefix
//! and the first occurrence of the delimiter are grouped under a single `CommonPrefixes` element,
//! and those keys are not returned elsewhere in the response. An earlier version of this handler
//! echoed the delimiter and returned every version of every key regardless, so `aws s3api
//! list-object-versions --delimiter /` walked a tree it was told had been rolled up, and its page
//! boundaries were wrong. A common prefix counts against `max-keys` and is a position a key marker
//! can resume from, as it is for `ListObjects`.

use std::collections::{BTreeMap, BTreeSet};

use rustfs_gateway::dto::{DeleteMarkerEntry, ListObjectVersions, ListObjectVersionsOutput, ObjectVersion};
use rustfs_gateway::{ErrorCode, Handler, HandlerError, HandlerResult, ObjectKey, Req, Resp, Timestamp};

use super::listing::rolled_up_prefix;
use super::records::{RecordKind, VersionRecord};
use super::{FsBackend, storage_error};

/// One position in the listing: a version or delete marker, or a rolled-up prefix.
enum Entry<'a> {
    Version(&'a VersionRecord),
    CommonPrefix(String),
}

impl Entry<'_> {
    fn name(&self) -> &str {
        match self {
            Self::Version(record) => &record.key,
            Self::CommonPrefix(prefix) => prefix,
        }
    }

    fn version_id(&self) -> Option<&str> {
        match self {
            Self::Version(record) => Some(&record.version_id),
            Self::CommonPrefix(_) => None,
        }
    }
}

/// The listing's positions in wire order: by name, a key's versions newest first, and a common
/// prefix where its keys would have been.
fn entries<'a>(records: &'a [VersionRecord], prefix: &str, delimiter: Option<&str>) -> Vec<Entry<'a>> {
    let mut entries = Vec::with_capacity(records.len());
    let mut common_prefixes = BTreeSet::new();
    for record in records {
        match rolled_up_prefix(&record.key, prefix, delimiter) {
            Some(common_prefix) => {
                common_prefixes.insert(common_prefix);
            }
            None => entries.push(Entry::Version(record)),
        }
    }
    entries.extend(common_prefixes.into_iter().map(Entry::CommonPrefix));
    // A stable sort keeps a key's versions in the newest-first order the records arrived in; a
    // common prefix never shares a name with a listed key, because such a key rolled up into it.
    entries.sort_by(|left, right| left.name().as_bytes().cmp(right.name().as_bytes()));
    entries
}

impl Handler<ListObjectVersions> for FsBackend {
    async fn call(&self, request: Req<ListObjectVersions>) -> HandlerResult<ListObjectVersions> {
        let input = request.input();
        // The version cursor resumes within the key the key cursor names; alone it names nothing,
        // and answering page one would repeat what the client already has (`c-list-0034`). An
        // empty key marker names no key either (`c-list-0046`).
        if input.version_id_marker.is_some() && input.key_marker.as_deref().is_none_or(str::is_empty) {
            return Err(HandlerError::new(
                ErrorCode::INVALID_ARGUMENT,
                "a version-id-marker requires a key-marker",
            ));
        }
        let _guard = self.version_lock.lock().await;
        self.require_readable_versioning(input.bucket.as_str()).await?;
        let prefix = input.prefix.as_deref().unwrap_or_default();
        let mut records = self.version_records(input.bucket.as_str()).await?;
        records.retain(|record| record.key.starts_with(prefix));
        records.sort_by(|left, right| left.key.cmp(&right.key).then_with(|| right.sequence.cmp(&left.sequence)));
        let mut latest = BTreeMap::new();
        for record in &records {
            latest.entry(record.key.as_str()).or_insert(record.sequence);
        }
        let entries = entries(&records, prefix, input.delimiter.as_deref());
        let start = match input.key_marker.as_deref() {
            None => 0,
            Some(key) if input.version_id_marker.is_none() => entries.partition_point(|entry| entry.name() <= key),
            Some(key) => {
                let marker = input
                    .version_id_marker
                    .as_ref()
                    .map(|value| value.as_str())
                    .unwrap_or_default();
                // The pair is a position, not a reference (`c-list-0045`, rustfs/gateway#807): a
                // cleanup deletes each page before asking for the next, so the named version is
                // usually gone. Version ids are opaque digests, so a vanished version's place
                // within its key cannot be recovered; the key's surviving versions are listed
                // again rather than skipped, because a repeat is harmless to a walker and a skip
                // silently strands the versions behind the cursor.
                entries
                    .iter()
                    .position(|entry| entry.name() == key && entry.version_id() == Some(marker))
                    .map_or_else(|| entries.partition_point(|entry| entry.name() < key), |position| position + 1)
            }
        };
        let max_keys = input.max_keys.unwrap_or(1000);
        let limit = usize::try_from(max_keys)
            .map_err(|_| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "max-keys must be a non-negative integer"))?;
        let selected = entries.iter().skip(start).take(limit).collect::<Vec<_>>();
        // A page of zero is a page of nothing, not a page that ran out: `ListObjects` answers
        // `max-keys=0` with `IsTruncated=false` and no cursor (`c-list-0027`), and a `true` with no
        // `NextKeyMarker` to act on sends a paginating client back for the same nothing forever.
        let is_truncated = limit > 0 && start.saturating_add(selected.len()) < entries.len();
        let mut versions = Vec::new();
        let mut delete_markers = Vec::new();
        let mut common_prefixes = Vec::new();
        for entry in &selected {
            let record = match entry {
                Entry::Version(record) => record,
                Entry::CommonPrefix(common_prefix) => {
                    common_prefixes.push(rustfs_gateway::dto::CommonPrefix {
                        prefix: common_prefix.clone(),
                    });
                    continue;
                }
            };
            let is_latest = latest.get(record.key.as_str()).copied() == Some(record.sequence);
            match record.kind {
                RecordKind::Object => versions.push(ObjectVersion {
                    key: ObjectKey::new(record.key.clone()).map_err(|_| storage_error())?,
                    version_id: record.version_id.clone().into(),
                    is_latest,
                    last_modified: Timestamp::from_secs(record.modified),
                    e_tag: rustfs_gateway::ETag::new(record.e_tag.clone()).map_err(|_| storage_error())?,
                    size: record.size,
                    storage_class: record.storage_class.clone(),
                    owner: self.reported_owner().cloned(),
                    ..ObjectVersion::default()
                }),
                RecordKind::DeleteMarker => delete_markers.push(DeleteMarkerEntry {
                    key: ObjectKey::new(record.key.clone()).map_err(|_| storage_error())?,
                    version_id: record.version_id.clone().into(),
                    is_latest,
                    last_modified: Timestamp::from_secs(record.modified),
                    owner: self.reported_owner().cloned(),
                }),
            }
        }
        let next = is_truncated.then(|| selected.last()).flatten();
        Ok(Resp::new(ListObjectVersionsOutput {
            name: input.bucket.clone(),
            prefix: prefix.to_owned(),
            delimiter: input.delimiter.clone(),
            encoding_type: input.encoding_type.clone(),
            key_marker: input.key_marker.clone().unwrap_or_default(),
            version_id_marker: input.version_id_marker.clone().unwrap_or_default(),
            next_key_marker: next.map(|entry| entry.name().to_owned()),
            next_version_id_marker: next.and_then(|entry| entry.version_id()).map(|id| id.to_owned().into()),
            max_keys,
            is_truncated,
            versions,
            delete_markers,
            common_prefixes,
            ..ListObjectVersionsOutput::default()
        }))
    }
}
